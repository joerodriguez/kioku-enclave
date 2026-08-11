#![allow(
    dead_code,
    reason = "inactive ADR-0022 checkpoint/WAL shadow primitives are compiled and tested before authority wiring"
)]

//! Bounded checkpoint-manifest and SQLite WAL-segment formats for ADR-0022.
//!
//! This module has no production authority and performs no filesystem, GCS,
//! witness, or SQLite VFS I/O. It makes the immutable journal payloads and
//! their fail-closed validation independently testable before shadow wiring.

use crate::archive_v3::{
    ArchiveCipher, ArchiveRoot, ArchiveV3Error, CiphertextEnvelope, ImmutableReference,
    LogicalLocation, ObjectContext, ObjectId, ObjectRole, Result, ARCHIVE_FORMAT_VERSION,
    SQLITE_PAGE_SIZE,
};
use zeroize::Zeroizing;

const CHECKPOINT_MANIFEST_MAGIC: &[u8; 8] = b"KACMv3\0\0";
const WAL_SEGMENT_MAGIC: &[u8; 8] = b"KAWLv3\0\0";
const SQLITE_WAL_MAGIC_LE_CHECKSUM: u32 = 0x377f_0682;
const SQLITE_WAL_MAGIC_BE_CHECKSUM: u32 = 0x377f_0683;
const SQLITE_WAL_FORMAT_VERSION: u32 = 3_007_000;
const SQLITE_WAL_HEADER_BYTES: usize = 32;
const SQLITE_WAL_FRAME_HEADER_BYTES: usize = 24;

/// Checkpoints use page-aligned, independently authenticated chunks. A
/// 32-GiB database therefore never enters one allocation or AEAD operation.
pub const CHECKPOINT_CHUNK_BYTES: u32 = 1_048_576;
/// Each manifest node is bounded independent of database size; larger
/// checkpoints add tree levels rather than entries to one root object.
pub const MAX_CHECKPOINT_MANIFEST_FANOUT: usize = 256;
pub const MAX_CHECKPOINT_MANIFEST_BYTES: usize = 32 * 1024;
/// The encoded WAL segment must fit the generic archive-v3 envelope after
/// framing. At 4-KiB pages this permits 254 frames per immutable segment.
pub const MAX_WAL_SEGMENT_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointChunkEntry {
    pub chunk_index: u32,
    pub logical_offset: u64,
    pub logical_byte_len: u32,
    pub plaintext_hash: [u8; 32],
    pub reference: ImmutableReference,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointManifestChild {
    pub range_start: u32,
    pub range_end: u32,
    pub reference: ImmutableReference,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointManifestEntries {
    Chunks(Vec<CheckpointChunkEntry>),
    Children(Vec<CheckpointManifestChild>),
}

/// One node in a persistent bounded checkpoint-manifest tree. Every node binds
/// the complete checkpoint descriptor so subtree substitution fails even
/// before its archive-v3 AEAD context is checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointManifestNode {
    pub checkpoint_id: ObjectId,
    pub level: u8,
    pub range_start: u32,
    pub range_end: u32,
    pub total_chunks: u32,
    pub logical_file_length: u64,
    pub sqlite_page_size: u32,
    pub database_plaintext_hash: [u8; 32],
    pub entries: CheckpointManifestEntries,
}

impl CheckpointManifestNode {
    pub fn validate(&self) -> Result<()> {
        if self.sqlite_page_size != SQLITE_PAGE_SIZE {
            return Err(ArchiveV3Error::Malformed("checkpoint page size"));
        }
        if self.logical_file_length == 0
            || !self
                .logical_file_length
                .is_multiple_of(u64::from(self.sqlite_page_size))
        {
            return Err(ArchiveV3Error::Malformed("checkpoint file length"));
        }
        let expected_total = self
            .logical_file_length
            .div_ceil(u64::from(CHECKPOINT_CHUNK_BYTES));
        if expected_total == 0
            || expected_total > u64::from(u32::MAX)
            || self.total_chunks != expected_total as u32
        {
            return Err(ArchiveV3Error::Malformed("checkpoint chunk count"));
        }
        if self.range_start >= self.range_end || self.range_end > self.total_chunks {
            return Err(ArchiveV3Error::Malformed("checkpoint manifest range"));
        }

        match &self.entries {
            CheckpointManifestEntries::Chunks(chunks) => {
                if self.level != 0 {
                    return Err(ArchiveV3Error::Malformed("checkpoint leaf level"));
                }
                validate_fanout(chunks.len())?;
                if chunks.len() != (self.range_end - self.range_start) as usize {
                    return Err(ArchiveV3Error::Malformed("checkpoint leaf coverage"));
                }
                for (expected_index, chunk) in (self.range_start..self.range_end).zip(chunks) {
                    let expected_offset = u64::from(expected_index)
                        .checked_mul(u64::from(CHECKPOINT_CHUNK_BYTES))
                        .ok_or(ArchiveV3Error::Malformed("checkpoint offset overflow"))?;
                    let remaining = self
                        .logical_file_length
                        .checked_sub(expected_offset)
                        .ok_or(ArchiveV3Error::Malformed("checkpoint chunk offset"))?;
                    let expected_length = remaining.min(u64::from(CHECKPOINT_CHUNK_BYTES)) as u32;
                    if chunk.chunk_index != expected_index
                        || chunk.logical_offset != expected_offset
                        || chunk.logical_byte_len != expected_length
                        || !chunk.logical_byte_len.is_multiple_of(self.sqlite_page_size)
                    {
                        return Err(ArchiveV3Error::Malformed("checkpoint chunk descriptor"));
                    }
                }
            }
            CheckpointManifestEntries::Children(children) => {
                if self.level == 0 {
                    return Err(ArchiveV3Error::Malformed("checkpoint internal level"));
                }
                validate_fanout(children.len())?;
                let mut next = self.range_start;
                for child in children {
                    if child.range_start != next
                        || child.range_end <= child.range_start
                        || child.range_end > self.range_end
                    {
                        return Err(ArchiveV3Error::Malformed("checkpoint child coverage"));
                    }
                    next = child.range_end;
                }
                if next != self.range_end {
                    return Err(ArchiveV3Error::Malformed("checkpoint child coverage"));
                }
            }
        }
        Ok(())
    }

    pub fn is_complete_root(&self) -> bool {
        self.range_start == 0 && self.range_end == self.total_chunks
    }

    pub fn validate_for_context(&self, context: &ObjectContext) -> Result<()> {
        self.validate()?;
        if context.role() != ObjectRole::CheckpointManifestV3
            || !matches!(
                context.location(),
                LogicalLocation::CheckpointManifest {
                    checkpoint_id,
                    level,
                    range_start,
                    range_end,
                } if *checkpoint_id == self.checkpoint_id
                    && *level == self.level
                    && *range_start == self.range_start
                    && *range_end == self.range_end
            )
        {
            return Err(ArchiveV3Error::InvalidContext);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let (kind, count, entry_size) = match &self.entries {
            CheckpointManifestEntries::Chunks(values) => (1u8, values.len(), 96usize),
            CheckpointManifestEntries::Children(values) => (2u8, values.len(), 56usize),
        };
        let length = 85usize
            .checked_add(
                count
                    .checked_mul(entry_size)
                    .ok_or(ArchiveV3Error::TooLarge("checkpoint manifest"))?,
            )
            .ok_or(ArchiveV3Error::TooLarge("checkpoint manifest"))?;
        if length > MAX_CHECKPOINT_MANIFEST_BYTES {
            return Err(ArchiveV3Error::TooLarge("checkpoint manifest"));
        }
        let mut out = Vec::with_capacity(length);
        out.extend_from_slice(CHECKPOINT_MANIFEST_MAGIC);
        out.push(ARCHIVE_FORMAT_VERSION);
        out.extend_from_slice(self.checkpoint_id.as_bytes());
        out.push(kind);
        out.push(self.level);
        push_u32(&mut out, self.range_start);
        push_u32(&mut out, self.range_end);
        push_u32(&mut out, self.total_chunks);
        push_u64(&mut out, self.logical_file_length);
        push_u32(&mut out, self.sqlite_page_size);
        out.extend_from_slice(&self.database_plaintext_hash);
        push_u16(&mut out, count as u16);
        match &self.entries {
            CheckpointManifestEntries::Chunks(chunks) => {
                for chunk in chunks {
                    push_u32(&mut out, chunk.chunk_index);
                    push_u64(&mut out, chunk.logical_offset);
                    push_u32(&mut out, chunk.logical_byte_len);
                    out.extend_from_slice(&chunk.plaintext_hash);
                    encode_reference(&mut out, &chunk.reference);
                }
            }
            CheckpointManifestEntries::Children(children) => {
                for child in children {
                    push_u32(&mut out, child.range_start);
                    push_u32(&mut out, child.range_end);
                    encode_reference(&mut out, &child.reference);
                }
            }
        }
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_CHECKPOINT_MANIFEST_BYTES {
            return Err(ArchiveV3Error::TooLarge("checkpoint manifest"));
        }
        if input.len() < 85
            || &input[..8] != CHECKPOINT_MANIFEST_MAGIC
            || input[8] != ARCHIVE_FORMAT_VERSION
        {
            return Err(ArchiveV3Error::Malformed("checkpoint manifest header"));
        }
        let mut offset = 9;
        let checkpoint_id = ObjectId::from_bytes(take_array(take(input, &mut offset, 16)?)?);
        let kind = take(input, &mut offset, 1)?[0];
        let level = take(input, &mut offset, 1)?[0];
        let range_start = take_u32(input, &mut offset)?;
        let range_end = take_u32(input, &mut offset)?;
        let total_chunks = take_u32(input, &mut offset)?;
        let logical_file_length = take_u64(input, &mut offset)?;
        let sqlite_page_size = take_u32(input, &mut offset)?;
        let database_plaintext_hash = take_array(take(input, &mut offset, 32)?)?;
        let count = usize::from(take_u16(input, &mut offset)?);
        validate_fanout(count)?;
        let entries = match kind {
            1 => {
                let mut chunks = Vec::with_capacity(count);
                for _ in 0..count {
                    chunks.push(CheckpointChunkEntry {
                        chunk_index: take_u32(input, &mut offset)?,
                        logical_offset: take_u64(input, &mut offset)?,
                        logical_byte_len: take_u32(input, &mut offset)?,
                        plaintext_hash: take_array(take(input, &mut offset, 32)?)?,
                        reference: decode_reference(input, &mut offset)?,
                    });
                }
                CheckpointManifestEntries::Chunks(chunks)
            }
            2 => {
                let mut children = Vec::with_capacity(count);
                for _ in 0..count {
                    children.push(CheckpointManifestChild {
                        range_start: take_u32(input, &mut offset)?,
                        range_end: take_u32(input, &mut offset)?,
                        reference: decode_reference(input, &mut offset)?,
                    });
                }
                CheckpointManifestEntries::Children(children)
            }
            _ => return Err(ArchiveV3Error::Malformed("checkpoint manifest kind")),
        };
        if offset != input.len() {
            return Err(ArchiveV3Error::Malformed("checkpoint manifest length"));
        }
        let node = Self {
            checkpoint_id,
            level,
            range_start,
            range_end,
            total_chunks,
            logical_file_length,
            sqlite_page_size,
            database_plaintext_hash,
            entries,
        };
        node.validate()?;
        Ok(node)
    }
}

fn validate_fanout(count: usize) -> Result<()> {
    if count == 0 {
        return Err(ArchiveV3Error::Malformed("empty checkpoint manifest"));
    }
    if count > MAX_CHECKPOINT_MANIFEST_FANOUT {
        return Err(ArchiveV3Error::TooLarge("checkpoint manifest fanout"));
    }
    Ok(())
}

/// One bounded part of a single SQLite commit. A commit may span multiple
/// immutable segments; only its final segment contains the commit frame. The
/// witnessed root names the exact final segment and the authenticated
/// predecessor links make the whole commit atomic without an unbounded object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalSegment {
    pub root_seq: u64,
    pub wal_generation: u64,
    pub segment_index: u32,
    pub segment_count: u32,
    pub previous_segment: Option<ImmutableReference>,
    pub first_frame_no: u64,
    pub checksum_before: [u32; 2],
    pub wal_header: [u8; SQLITE_WAL_HEADER_BYTES],
    pub frames: Vec<u8>,
}

impl WalSegment {
    pub fn is_final(&self) -> bool {
        self.segment_index.checked_add(1) == Some(self.segment_count)
    }

    pub fn frame_count(&self) -> Result<u32> {
        let frame_bytes = SQLITE_WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize;
        if self.frames.is_empty() || !self.frames.len().is_multiple_of(frame_bytes) {
            return Err(ArchiveV3Error::Malformed("WAL frame length"));
        }
        u32::try_from(self.frames.len() / frame_bytes)
            .map_err(|_| ArchiveV3Error::TooLarge("WAL frame count"))
    }

    pub fn validate(&self) -> Result<()> {
        if self.root_seq == 0
            || self.wal_generation == 0
            || self.first_frame_no == 0
            || self.segment_count == 0
            || self.segment_index >= self.segment_count
        {
            return Err(ArchiveV3Error::Malformed("WAL sequence"));
        }
        if (self.segment_index == 0) != self.previous_segment.is_none() {
            return Err(ArchiveV3Error::Malformed("WAL predecessor"));
        }
        let magic = read_be_u32(&self.wal_header[0..4])?;
        let checksum_order = match magic {
            SQLITE_WAL_MAGIC_LE_CHECKSUM => ChecksumOrder::Little,
            SQLITE_WAL_MAGIC_BE_CHECKSUM => ChecksumOrder::Big,
            _ => return Err(ArchiveV3Error::Malformed("WAL magic")),
        };
        if read_be_u32(&self.wal_header[4..8])? != SQLITE_WAL_FORMAT_VERSION
            || read_be_u32(&self.wal_header[8..12])? != SQLITE_PAGE_SIZE
        {
            return Err(ArchiveV3Error::Malformed("WAL header"));
        }
        let header_checksum = wal_checksum(checksum_order, &self.wal_header[..24], [0, 0])?;
        let stored_header_checksum = [
            read_be_u32(&self.wal_header[24..28])?,
            read_be_u32(&self.wal_header[28..32])?,
        ];
        if header_checksum != stored_header_checksum {
            return Err(ArchiveV3Error::Malformed("WAL header checksum"));
        }
        if self.first_frame_no == 1 && self.checksum_before != stored_header_checksum {
            return Err(ArchiveV3Error::Malformed("WAL initial checksum"));
        }
        if self.frames.len() > MAX_WAL_SEGMENT_BYTES {
            return Err(ArchiveV3Error::TooLarge("WAL segment"));
        }
        let frame_count = self.frame_count()?;
        let frame_bytes = SQLITE_WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize;
        let salts = (&self.wal_header[16..20], &self.wal_header[20..24]);
        let mut checksum = self.checksum_before;
        let mut last_commit_size = 0;
        for frame_index in 0..frame_count as usize {
            let start = frame_index * frame_bytes;
            let frame = &self.frames[start..start + frame_bytes];
            if read_be_u32(&frame[0..4])? == 0
                || &frame[8..12] != salts.0
                || &frame[12..16] != salts.1
            {
                return Err(ArchiveV3Error::Malformed("WAL frame header"));
            }
            checksum = wal_checksum(checksum_order, &frame[..8], checksum)?;
            checksum = wal_checksum(checksum_order, &frame[24..], checksum)?;
            let stored = [read_be_u32(&frame[16..20])?, read_be_u32(&frame[20..24])?];
            if checksum != stored {
                return Err(ArchiveV3Error::Malformed("WAL frame checksum"));
            }
            let commit_size = read_be_u32(&frame[4..8])?;
            let is_last_frame = frame_index + 1 == frame_count as usize;
            if commit_size != 0 && !(self.is_final() && is_last_frame) {
                return Err(ArchiveV3Error::Malformed("WAL commit placement"));
            }
            last_commit_size = commit_size;
        }
        if self.is_final() != (last_commit_size != 0) {
            return Err(ArchiveV3Error::Malformed("WAL segment not commit bounded"));
        }
        Ok(())
    }

    pub fn validate_for_context(&self, context: &ObjectContext) -> Result<()> {
        self.validate()?;
        if context.role() != ObjectRole::WalSegmentV3
            || !matches!(
                context.location(),
                LogicalLocation::Wal {
                    root_seq,
                    wal_generation,
                    segment_index,
                } if *root_seq == self.root_seq
                    && *wal_generation == self.wal_generation
                    && *segment_index == self.segment_index
            )
            || context.parent().is_some()
        {
            return Err(ArchiveV3Error::InvalidContext);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let frame_count = self.frame_count()?;
        let length = 90usize
            .checked_add(self.previous_segment.as_ref().map_or(0, |_| 48))
            .and_then(|value| value.checked_add(self.frames.len()))
            .ok_or(ArchiveV3Error::TooLarge("WAL segment"))?;
        if length > MAX_WAL_SEGMENT_BYTES {
            return Err(ArchiveV3Error::TooLarge("WAL segment"));
        }
        let mut out = Vec::with_capacity(length);
        out.extend_from_slice(WAL_SEGMENT_MAGIC);
        out.push(ARCHIVE_FORMAT_VERSION);
        push_u64(&mut out, self.root_seq);
        push_u64(&mut out, self.wal_generation);
        push_u32(&mut out, self.segment_index);
        push_u32(&mut out, self.segment_count);
        encode_optional_reference(&mut out, &self.previous_segment);
        push_u64(&mut out, self.first_frame_no);
        push_u32(&mut out, self.checksum_before[0]);
        push_u32(&mut out, self.checksum_before[1]);
        out.extend_from_slice(&self.wal_header);
        push_u32(&mut out, frame_count);
        push_u32(&mut out, self.frames.len() as u32);
        out.extend_from_slice(&self.frames);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_WAL_SEGMENT_BYTES {
            return Err(ArchiveV3Error::TooLarge("WAL segment"));
        }
        if input.len() < 90
            || &input[..8] != WAL_SEGMENT_MAGIC
            || input[8] != ARCHIVE_FORMAT_VERSION
        {
            return Err(ArchiveV3Error::Malformed("WAL segment header"));
        }
        let mut offset = 9;
        let root_seq = take_u64(input, &mut offset)?;
        let wal_generation = take_u64(input, &mut offset)?;
        let segment_index = take_u32(input, &mut offset)?;
        let segment_count = take_u32(input, &mut offset)?;
        let previous_segment = decode_optional_reference(input, &mut offset)?;
        let first_frame_no = take_u64(input, &mut offset)?;
        let checksum_before = [take_u32(input, &mut offset)?, take_u32(input, &mut offset)?];
        let wal_header = take_array(take(input, &mut offset, SQLITE_WAL_HEADER_BYTES)?)?;
        let encoded_frame_count = take_u32(input, &mut offset)?;
        let frame_length = take_u32(input, &mut offset)? as usize;
        let frames = take(input, &mut offset, frame_length)?.to_vec();
        if offset != input.len() {
            return Err(ArchiveV3Error::Malformed("WAL segment length"));
        }
        let segment = Self {
            root_seq,
            wal_generation,
            segment_index,
            segment_count,
            previous_segment,
            first_frame_no,
            checksum_before,
            wal_header,
            frames,
        };
        if segment.frame_count()? != encoded_frame_count {
            return Err(ArchiveV3Error::Malformed("WAL frame count"));
        }
        segment.validate()?;
        Ok(segment)
    }

    fn terminal_checksum(&self) -> Result<[u32; 2]> {
        let frame_bytes = SQLITE_WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize;
        let frame_count = self.frame_count()? as usize;
        let last = &self.frames[(frame_count - 1) * frame_bytes..frame_count * frame_bytes];
        Ok([read_be_u32(&last[16..20])?, read_be_u32(&last[20..24])?])
    }
}

/// A segment that has been resolved from the expected object ID and actual
/// ciphertext envelope, hash-checked, AEAD-opened under its exact context, and
/// payload-validated. Private fields prevent callers from bypassing that proof.
#[derive(Clone)]
pub struct ResolvedWalSegment {
    reference: ImmutableReference,
    segment: WalSegment,
}

impl ResolvedWalSegment {
    /// Both values are available only after the envelope hash, AEAD context,
    /// encoded segment, and segment context have been verified together.
    pub(crate) fn reference(&self) -> &ImmutableReference {
        &self.reference
    }

    pub(crate) fn segment(&self) -> &WalSegment {
        &self.segment
    }
}

pub fn resolve_wal_segment(
    cipher: &ArchiveCipher,
    context: ObjectContext,
    expected_reference: ImmutableReference,
    envelope: CiphertextEnvelope,
) -> Result<ResolvedWalSegment> {
    if context.object_id() != expected_reference.object_id
        || envelope.hash() != expected_reference.envelope_hash
    {
        return Err(ArchiveV3Error::Authentication);
    }
    // `WalSegment::decode` copies the authenticated frame bytes into its
    // bounded owned representation. Keep the transient AEAD plaintext
    // zeroized even when decoding or context validation rejects it.
    let plaintext = Zeroizing::new(cipher.open(&context, &envelope)?);
    let segment = WalSegment::decode(plaintext.as_slice())?;
    segment.validate_for_context(&context)?;
    Ok(ResolvedWalSegment {
        reference: expected_reference,
        segment,
    })
}

/// The verified archive cipher is the production-shaped cipher boundary. Keep
/// this twin of [`resolve_wal_segment`] explicit rather than allowing callers
/// to reach inside `VerifiedArchiveCipher` for its raw DEK.
pub fn resolve_verified_wal_segment(
    cipher: &crate::archive_v3::VerifiedArchiveCipher,
    context: ObjectContext,
    expected_reference: ImmutableReference,
    envelope: CiphertextEnvelope,
) -> Result<ResolvedWalSegment> {
    if context.object_id() != expected_reference.object_id
        || envelope.hash() != expected_reference.envelope_hash
    {
        return Err(ArchiveV3Error::Authentication);
    }
    // See `resolve_wal_segment`: the raw AEAD plaintext has no reason to
    // survive after the validated segment owns its bounded frame copy.
    let plaintext = Zeroizing::new(cipher.open(&context, &envelope)?);
    let segment = WalSegment::decode(plaintext.as_slice())?;
    segment.validate_for_context(&context)?;
    Ok(ResolvedWalSegment {
        reference: expected_reference,
        segment,
    })
}

/// Verify one complete SQLite commit against the exact root that nominates it.
/// This is deliberately independent of prefix enumeration and accepts no
/// locally valid orphan candidate.
pub fn validate_wal_commit_chain(root: &ArchiveRoot, entries: &[ResolvedWalSegment]) -> Result<()> {
    root.validate()?;
    let final_reference = root
        .wal_chain_root
        .as_ref()
        .ok_or(ArchiveV3Error::Malformed("root has no WAL chain"))?;
    if entries.is_empty()
        || entries.len() != root.wal_segment_count as usize
        || entries.last().map(|entry| &entry.reference) != Some(final_reference)
    {
        return Err(ArchiveV3Error::Malformed("WAL root chain"));
    }

    let first = &entries[0].segment;
    let mut expected_frame = first.first_frame_no;
    let mut expected_checksum = first.checksum_before;
    let mut previous_reference: Option<&ImmutableReference> = None;
    let expected_header = first.wal_header;
    for (index, entry) in entries.iter().enumerate() {
        let segment = &entry.segment;
        segment.validate()?;
        if segment.root_seq != root.root_seq
            || segment.wal_generation != root.wal_generation
            || segment.segment_count != root.wal_segment_count
            || segment.segment_index as usize != index
            || segment.first_frame_no != expected_frame
            || segment.checksum_before != expected_checksum
            || segment.wal_header != expected_header
            || segment.previous_segment.as_ref() != previous_reference
        {
            return Err(ArchiveV3Error::Malformed("WAL chain continuity"));
        }
        expected_frame = expected_frame
            .checked_add(u64::from(segment.frame_count()?))
            .ok_or(ArchiveV3Error::Malformed("WAL frame sequence overflow"))?;
        expected_checksum = segment.terminal_checksum()?;
        previous_reference = Some(&entry.reference);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ChecksumOrder {
    Little,
    Big,
}

fn wal_checksum(order: ChecksumOrder, input: &[u8], mut state: [u32; 2]) -> Result<[u32; 2]> {
    if !input.len().is_multiple_of(8) {
        return Err(ArchiveV3Error::Malformed("WAL checksum length"));
    }
    for words in input.chunks_exact(8) {
        let first = match order {
            ChecksumOrder::Little => u32::from_le_bytes(take_array(&words[..4])?),
            ChecksumOrder::Big => u32::from_be_bytes(take_array(&words[..4])?),
        };
        let second = match order {
            ChecksumOrder::Little => u32::from_le_bytes(take_array(&words[4..])?),
            ChecksumOrder::Big => u32::from_be_bytes(take_array(&words[4..])?),
        };
        state[0] = state[0].wrapping_add(first).wrapping_add(state[1]);
        state[1] = state[1].wrapping_add(second).wrapping_add(state[0]);
    }
    Ok(state)
}

fn encode_reference(out: &mut Vec<u8>, reference: &ImmutableReference) {
    out.extend_from_slice(reference.object_id.as_bytes());
    out.extend_from_slice(&reference.envelope_hash);
}

fn encode_optional_reference(out: &mut Vec<u8>, reference: &Option<ImmutableReference>) {
    match reference {
        Some(reference) => {
            out.push(1);
            encode_reference(out, reference);
        }
        None => out.push(0),
    }
}

fn decode_reference(input: &[u8], offset: &mut usize) -> Result<ImmutableReference> {
    Ok(ImmutableReference {
        object_id: ObjectId::from_bytes(take_array(take(input, offset, 16)?)?),
        envelope_hash: take_array(take(input, offset, 32)?)?,
    })
}

fn decode_optional_reference(
    input: &[u8],
    offset: &mut usize,
) -> Result<Option<ImmutableReference>> {
    match take(input, offset, 1)?[0] {
        0 => Ok(None),
        1 => Ok(Some(decode_reference(input, offset)?)),
        _ => Err(ArchiveV3Error::Malformed("WAL predecessor flag")),
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or(ArchiveV3Error::Malformed("overflow"))?;
    let value = input
        .get(*offset..end)
        .ok_or(ArchiveV3Error::Malformed("truncated"))?;
    *offset = end;
    Ok(value)
}
fn take_array<const N: usize>(input: &[u8]) -> Result<[u8; N]> {
    input
        .try_into()
        .map_err(|_| ArchiveV3Error::Malformed("integer"))
}
fn take_u16(input: &[u8], offset: &mut usize) -> Result<u16> {
    Ok(u16::from_be_bytes(take_array(take(input, offset, 2)?)?))
}
fn take_u32(input: &[u8], offset: &mut usize) -> Result<u32> {
    Ok(u32::from_be_bytes(take_array(take(input, offset, 4)?)?))
}
fn take_u64(input: &[u8], offset: &mut usize) -> Result<u64> {
    Ok(u64::from_be_bytes(take_array(take(input, offset, 8)?)?))
}
fn read_be_u32(input: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(take_array(input)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3::{
        ArchiveCipher, ArchiveDek, ArchiveId, DatabaseEpoch, KeyEpoch, ParentReference,
    };
    use sha2::{Digest, Sha256};

    fn reference(value: u8) -> ImmutableReference {
        ImmutableReference {
            object_id: ObjectId::from_bytes([value; 16]),
            envelope_hash: [value; 32],
        }
    }

    fn leaf() -> CheckpointManifestNode {
        let length = u64::from(CHECKPOINT_CHUNK_BYTES) + u64::from(SQLITE_PAGE_SIZE);
        CheckpointManifestNode {
            checkpoint_id: ObjectId::from_bytes([7; 16]),
            level: 0,
            range_start: 0,
            range_end: 2,
            total_chunks: 2,
            logical_file_length: length,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            database_plaintext_hash: [8; 32],
            entries: CheckpointManifestEntries::Chunks(vec![
                CheckpointChunkEntry {
                    chunk_index: 0,
                    logical_offset: 0,
                    logical_byte_len: CHECKPOINT_CHUNK_BYTES,
                    plaintext_hash: [1; 32],
                    reference: reference(1),
                },
                CheckpointChunkEntry {
                    chunk_index: 1,
                    logical_offset: u64::from(CHECKPOINT_CHUNK_BYTES),
                    logical_byte_len: SQLITE_PAGE_SIZE,
                    plaintext_hash: [2; 32],
                    reference: reference(2),
                },
            ]),
        }
    }

    fn manifest_context(node: &CheckpointManifestNode) -> ObjectContext {
        ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::CheckpointManifestV3,
            LogicalLocation::CheckpointManifest {
                checkpoint_id: node.checkpoint_id,
                level: node.level,
                range_start: node.range_start,
                range_end: node.range_end,
            },
            ObjectId::from_bytes([4; 16]),
            None,
        )
        .unwrap()
    }

    #[test]
    fn bounded_checkpoint_leaf_round_trips_and_binds_context() {
        let node = leaf();
        assert!(node.is_complete_root());
        assert_eq!(
            CheckpointManifestNode::decode(&node.encode().unwrap()).unwrap(),
            node
        );
        assert_eq!(node.validate_for_context(&manifest_context(&node)), Ok(()));

        let mut wrong = manifest_context(&node);
        wrong = ObjectContext::new(
            wrong.archive_id(),
            wrong.database_epoch(),
            wrong.key_epoch(),
            ObjectRole::CheckpointManifestV3,
            LogicalLocation::CheckpointManifest {
                checkpoint_id: ObjectId::from_bytes([9; 16]),
                level: 0,
                range_start: 0,
                range_end: 2,
            },
            wrong.object_id(),
            None,
        )
        .unwrap();
        assert_eq!(
            node.validate_for_context(&wrong),
            Err(ArchiveV3Error::InvalidContext)
        );
    }

    #[test]
    fn checkpoint_manifest_rejects_gaps_substitution_and_unbounded_input() {
        let mut node = leaf();
        if let CheckpointManifestEntries::Chunks(chunks) = &mut node.entries {
            chunks[1].chunk_index = 3;
        }
        assert_eq!(
            node.encode(),
            Err(ArchiveV3Error::Malformed("checkpoint chunk descriptor"))
        );

        let internal = CheckpointManifestNode {
            checkpoint_id: ObjectId::from_bytes([7; 16]),
            level: 1,
            range_start: 0,
            range_end: 4,
            total_chunks: 4,
            logical_file_length: 4 * u64::from(CHECKPOINT_CHUNK_BYTES),
            sqlite_page_size: SQLITE_PAGE_SIZE,
            database_plaintext_hash: [8; 32],
            entries: CheckpointManifestEntries::Children(vec![
                CheckpointManifestChild {
                    range_start: 0,
                    range_end: 2,
                    reference: reference(1),
                },
                CheckpointManifestChild {
                    range_start: 3,
                    range_end: 4,
                    reference: reference(2),
                },
            ]),
        };
        assert_eq!(
            internal.encode(),
            Err(ArchiveV3Error::Malformed("checkpoint child coverage"))
        );
        assert_eq!(
            CheckpointManifestNode::decode(&vec![0; MAX_CHECKPOINT_MANIFEST_BYTES + 1]),
            Err(ArchiveV3Error::TooLarge("checkpoint manifest"))
        );
    }

    #[test]
    fn thirty_two_gib_checkpoint_root_is_bounded_and_chunks_are_exact_length() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let total_chunks = (32 * GIB / u64::from(CHECKPOINT_CHUNK_BYTES)) as u32;
        let children = (0..total_chunks)
            .step_by(MAX_CHECKPOINT_MANIFEST_FANOUT)
            .map(|start| CheckpointManifestChild {
                range_start: start,
                range_end: (start + MAX_CHECKPOINT_MANIFEST_FANOUT as u32).min(total_chunks),
                reference: reference((start / MAX_CHECKPOINT_MANIFEST_FANOUT as u32) as u8),
            })
            .collect();
        let root = CheckpointManifestNode {
            checkpoint_id: ObjectId::from_bytes([7; 16]),
            level: 1,
            range_start: 0,
            range_end: total_chunks,
            total_chunks,
            logical_file_length: 32 * GIB,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            database_plaintext_hash: [8; 32],
            entries: CheckpointManifestEntries::Children(children),
        };
        let encoded = root.encode().unwrap();
        assert!(root.is_complete_root());
        assert!(encoded.len() <= MAX_CHECKPOINT_MANIFEST_BYTES);
        assert_eq!(CheckpointManifestNode::decode(&encoded).unwrap(), root);

        let context = ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::CheckpointChunkV3,
            LogicalLocation::CheckpointChunk {
                checkpoint_id: root.checkpoint_id,
                chunk_index: 0,
                logical_offset: 0,
                byte_len: CHECKPOINT_CHUNK_BYTES,
            },
            ObjectId::from_bytes([4; 16]),
            None,
        )
        .unwrap();
        let cipher = ArchiveCipher::new(ArchiveDek::from_bytes([9; 32]));
        assert_eq!(
            cipher.seal(&context, &[0; SQLITE_PAGE_SIZE as usize]),
            Err(ArchiveV3Error::InvalidContext)
        );
        assert!(context.object_key().as_str().contains("/checkpoints/"));
    }

    fn fixture_wal_frames(
        frame_count: usize,
    ) -> ([u8; SQLITE_WAL_HEADER_BYTES], Vec<u8>, [u32; 2]) {
        let order = ChecksumOrder::Little;
        let mut wal_header = [0u8; SQLITE_WAL_HEADER_BYTES];
        wal_header[0..4].copy_from_slice(&SQLITE_WAL_MAGIC_LE_CHECKSUM.to_be_bytes());
        wal_header[4..8].copy_from_slice(&SQLITE_WAL_FORMAT_VERSION.to_be_bytes());
        wal_header[8..12].copy_from_slice(&SQLITE_PAGE_SIZE.to_be_bytes());
        wal_header[12..16].copy_from_slice(&1u32.to_be_bytes());
        wal_header[16..20].copy_from_slice(&[11, 12, 13, 14]);
        wal_header[20..24].copy_from_slice(&[21, 22, 23, 24]);
        let header_checksum = wal_checksum(order, &wal_header[..24], [0, 0]).unwrap();
        wal_header[24..28].copy_from_slice(&header_checksum[0].to_be_bytes());
        wal_header[28..32].copy_from_slice(&header_checksum[1].to_be_bytes());

        let frame_bytes = SQLITE_WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize;
        let mut frames = vec![0u8; frame_bytes * frame_count];
        let mut checksum = header_checksum;
        for index in 0..frame_count {
            let frame = &mut frames[index * frame_bytes..(index + 1) * frame_bytes];
            frame[0..4].copy_from_slice(&(index as u32 + 1).to_be_bytes());
            frame[4..8].copy_from_slice(
                &(if index + 1 == frame_count {
                    frame_count as u32
                } else {
                    0u32
                })
                .to_be_bytes(),
            );
            frame[8..16].copy_from_slice(&wal_header[16..24]);
            frame[24..].fill(index as u8);
            checksum = wal_checksum(order, &frame[..8], checksum).unwrap();
            checksum = wal_checksum(order, &frame[24..], checksum).unwrap();
            frame[16..20].copy_from_slice(&checksum[0].to_be_bytes());
            frame[20..24].copy_from_slice(&checksum[1].to_be_bytes());
        }
        (wal_header, frames, header_checksum)
    }

    fn fixture_wal_segment() -> WalSegment {
        let (wal_header, frames, header_checksum) = fixture_wal_frames(2);
        WalSegment {
            root_seq: 1,
            wal_generation: 1,
            segment_index: 0,
            segment_count: 1,
            previous_segment: None,
            first_frame_no: 1,
            checksum_before: header_checksum,
            wal_header,
            frames,
        }
    }

    #[test]
    fn wal_segment_round_trips_only_at_a_verified_commit_boundary() {
        let segment = fixture_wal_segment();
        let wire = segment.encode().unwrap();
        assert_eq!(WalSegment::decode(&wire).unwrap(), segment);
        let context = ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::WalSegmentV3,
            LogicalLocation::Wal {
                root_seq: 1,
                wal_generation: 1,
                segment_index: 0,
            },
            ObjectId::from_bytes([4; 16]),
            None,
        )
        .unwrap();
        assert_eq!(segment.validate_for_context(&context), Ok(()));
    }

    #[test]
    fn wal_segment_rejects_tamper_truncation_wrong_salt_and_noncommit_tail() {
        let segment = fixture_wal_segment();
        let mut tampered = segment.clone();
        *tampered.frames.last_mut().unwrap() ^= 1;
        assert_eq!(
            tampered.validate(),
            Err(ArchiveV3Error::Malformed("WAL frame checksum"))
        );
        let mut wrong_salt = segment.clone();
        wrong_salt.frames[8] ^= 1;
        assert_eq!(
            wrong_salt.validate(),
            Err(ArchiveV3Error::Malformed("WAL frame header"))
        );
        let mut no_commit = segment.clone();
        let frame_bytes = SQLITE_WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize;
        let mut checksum = [
            read_be_u32(&no_commit.frames[16..20]).unwrap(),
            read_be_u32(&no_commit.frames[20..24]).unwrap(),
        ];
        let last = &mut no_commit.frames[frame_bytes..2 * frame_bytes];
        last[4..8].fill(0);
        checksum = wal_checksum(ChecksumOrder::Little, &last[..8], checksum).unwrap();
        checksum = wal_checksum(ChecksumOrder::Little, &last[24..], checksum).unwrap();
        last[16..20].copy_from_slice(&checksum[0].to_be_bytes());
        last[20..24].copy_from_slice(&checksum[1].to_be_bytes());
        assert_eq!(
            no_commit.validate(),
            Err(ArchiveV3Error::Malformed("WAL segment not commit bounded"))
        );
        assert_eq!(
            WalSegment::decode(&segment.encode().unwrap()[..89]),
            Err(ArchiveV3Error::Malformed("WAL segment header"))
        );
        assert_ne!(
            Sha256::digest(segment.encode().unwrap()),
            Sha256::digest(tampered.frames)
        );
    }

    #[test]
    fn a_255_frame_transaction_spans_two_bounded_segments_and_is_atomic_at_the_root() {
        let (wal_header, frames, header_checksum) = fixture_wal_frames(255);
        let frame_bytes = SQLITE_WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize;
        let first_frames = frames[..254 * frame_bytes].to_vec();
        let second_frames = frames[254 * frame_bytes..].to_vec();
        let cipher = ArchiveCipher::new(ArchiveDek::from_bytes([9; 32]));
        let first = WalSegment {
            root_seq: 7,
            wal_generation: 3,
            segment_index: 0,
            segment_count: 2,
            previous_segment: None,
            first_frame_no: 1,
            checksum_before: header_checksum,
            wal_header,
            frames: first_frames,
        };
        let first_context = ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::WalSegmentV3,
            LogicalLocation::Wal {
                root_seq: 7,
                wal_generation: 3,
                segment_index: 0,
            },
            ObjectId::from_bytes([41; 16]),
            None,
        )
        .unwrap();
        let first_envelope = cipher
            .seal(&first_context, &first.encode().unwrap())
            .unwrap();
        let first_reference = ImmutableReference {
            object_id: first_context.object_id(),
            envelope_hash: first_envelope.hash(),
        };
        let second = WalSegment {
            root_seq: 7,
            wal_generation: 3,
            segment_index: 1,
            segment_count: 2,
            previous_segment: Some(first_reference.clone()),
            first_frame_no: 255,
            checksum_before: first.terminal_checksum().unwrap(),
            wal_header,
            frames: second_frames,
        };
        let second_context = ObjectContext::new(
            ArchiveId::from_bytes([1; 16]),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectRole::WalSegmentV3,
            LogicalLocation::Wal {
                root_seq: 7,
                wal_generation: 3,
                segment_index: 1,
            },
            ObjectId::from_bytes([42; 16]),
            None,
        )
        .unwrap();
        let second_envelope = cipher
            .seal(&second_context, &second.encode().unwrap())
            .unwrap();
        let final_reference = ImmutableReference {
            object_id: second_context.object_id(),
            envelope_hash: second_envelope.hash(),
        };
        assert!(first.encode().unwrap().len() <= MAX_WAL_SEGMENT_BYTES);
        assert!(second.encode().unwrap().len() <= MAX_WAL_SEGMENT_BYTES);
        let root = ArchiveRoot {
            root_seq: 7,
            parent: Some(ParentReference {
                object_id: ObjectId::from_bytes([9; 16]),
                envelope_hash: [9; 32],
            }),
            database_epoch: DatabaseEpoch::from_bytes([2; 16]),
            key_epoch: KeyEpoch::from_bytes([3; 16]),
            owner_fencing_epoch: 11,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: 255 * u64::from(SQLITE_PAGE_SIZE),
            user_schema_version: 4,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 3,
            wal_segment_count: 2,
            checkpoint_root: Some(reference(40)),
            extent_tree_root: None,
            wal_chain_root: Some(final_reference.clone()),
        };
        let resolved_first = resolve_wal_segment(
            &cipher,
            first_context.clone(),
            first_reference.clone(),
            first_envelope.clone(),
        )
        .unwrap();
        let resolved_second = resolve_wal_segment(
            &cipher,
            second_context,
            final_reference.clone(),
            second_envelope,
        )
        .unwrap();
        let entries = [resolved_first.clone(), resolved_second.clone()];
        assert_eq!(validate_wal_commit_chain(&root, &entries), Ok(()));

        let mut wrong_hash = first_reference.clone();
        wrong_hash.envelope_hash[0] ^= 1;
        assert!(matches!(
            resolve_wal_segment(&cipher, first_context, wrong_hash, first_envelope,),
            Err(ArchiveV3Error::Authentication)
        ));

        let mut wrong_sequence = second.clone();
        wrong_sequence.first_frame_no = 256;
        let wrong_entries = [
            resolved_first,
            ResolvedWalSegment {
                reference: final_reference,
                segment: wrong_sequence,
            },
        ];
        assert_eq!(
            validate_wal_commit_chain(&root, &wrong_entries),
            Err(ArchiveV3Error::Malformed("WAL chain continuity"))
        );
        let wrong_root = ArchiveRoot {
            wal_chain_root: Some(reference(99)),
            ..root
        };
        assert_eq!(
            validate_wal_commit_chain(&wrong_root, &entries),
            Err(ArchiveV3Error::Malformed("WAL root chain"))
        );
    }
}
