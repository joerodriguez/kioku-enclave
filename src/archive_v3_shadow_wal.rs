#![allow(
    dead_code,
    reason = "inactive ADR-0022 WAL publication/recovery is compiled and tested before authority wiring"
)]

//! Inactive, bounded ADR-0022 captured-WAL publication and recovery.
//!
//! This is deliberately below the publication coordinator: it turns one
//! already-validated [`CapturedWalCommit`] into sealed immutable segments,
//! reads every created segment back under its exact context, and composes the
//! checkpoint-plus-WAL portion of a future root. Recovery starts at the one
//! exact root named by a [`RecoveryRoot`] and follows predecessor references
//! backwards; it never lists objects or accepts a caller-selected WAL object.
//!
//! No runtime installs a VFS, drains a capture, invokes these functions from a
//! `Store`, truncates a local WAL, or gives this module witness authority.

use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    archive_v3::{
        ArchiveId, ArchiveRoot, ArchiveV3Error, DatabaseEpoch, ImmutableObjectBackend,
        ImmutableReference, LogicalLocation, ObjectContext, ObjectId, ObjectRole, ParentReference,
        VerifiedArchiveCipher, ARCHIVE_FORMAT_VERSION, SQLITE_PAGE_SIZE,
    },
    archive_v3_journal::{
        resolve_verified_wal_segment, validate_wal_commit_chain, ResolvedWalSegment, WalSegment,
        MAX_WAL_SEGMENT_BYTES,
    },
    archive_v3_shadow::CapturedWalCommit,
    archive_v3_witness::{RecoveryRoot, RootReference},
};

const SQLITE_WAL_HEADER_BYTES: usize = 32;
const SQLITE_WAL_FRAME_HEADER_BYTES: usize = 24;
const SQLITE_WAL_FRAME_BYTES: usize = SQLITE_WAL_FRAME_HEADER_BYTES + SQLITE_PAGE_SIZE as usize;
// The largest encoded predecessor-bearing `WalSegment` fixed prefix is 138
// bytes. Keep this independent of the encoder's allocation strategy.
const MAX_WAL_SEGMENT_FIXED_BYTES: usize = 138;
const MAX_WAL_FRAMES_PER_SEGMENT: usize =
    (MAX_WAL_SEGMENT_BYTES - MAX_WAL_SEGMENT_FIXED_BYTES) / SQLITE_WAL_FRAME_BYTES;

/// A VFS capture has its own 8-MiB ceiling. This independent publication cap
/// makes recovery allocation and object fanout explicit even if that capture
/// implementation changes later.
pub const MAX_WAL_SEGMENTS_PER_COMMIT: u32 = 16;

#[derive(Debug, Error)]
pub enum ShadowWalError {
    #[error(transparent)]
    Archive(#[from] ArchiveV3Error),
    #[error("the exact immutable WAL object is absent")]
    MissingObject,
    #[error("the witnessed root has no checkpoint-plus-WAL recovery state")]
    MissingCheckpointOrWal,
    #[error("WAL recovery sink rejected output")]
    Sink,
}

pub type Result<T> = std::result::Result<T, ShadowWalError>;

/// Opaque description of immutable objects that were sealed and then read
/// back successfully. It has no authority until a separately authenticated
/// root names `final_segment` and that root is witnessed.
#[derive(Clone, PartialEq, Eq)]
pub struct UploadedWalCommit {
    root_seq: u64,
    wal_generation: u64,
    segment_count: u32,
    effective_logical_file_length: u64,
    final_segment: ImmutableReference,
}

impl UploadedWalCommit {
    pub(crate) fn root_seq(&self) -> u64 {
        self.root_seq
    }

    pub(crate) fn wal_generation(&self) -> u64 {
        self.wal_generation
    }

    pub(crate) fn segment_count(&self) -> u32 {
        self.segment_count
    }

    pub(crate) fn effective_logical_file_length(&self) -> u64 {
        self.effective_logical_file_length
    }

    pub(crate) fn final_segment(&self) -> &ImmutableReference {
        &self.final_segment
    }
}

impl std::fmt::Debug for UploadedWalCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UploadedWalCommit(<opaque>)")
    }
}

/// Upload one capture-bound SQLite commit as predecessor-linked immutable
/// segments. The caller cannot substitute raw WAL bytes: the capture has
/// already validated complete `xSync`-durable commit boundaries, rolling
/// checksums, salts, and frame order. Each newly sealed object is immediately
/// fetched, hash-checked, AEAD-opened, and decoded before the next object is
/// created.
pub(crate) async fn upload_captured_wal_commit(
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    root_seq: u64,
    capture: &CapturedWalCommit,
) -> Result<UploadedWalCommit> {
    if cipher.archive_id() != archive_id || root_seq == 0 {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let effective_logical_file_length = capture.effective_logical_file_length(root_seq)?;
    let frames = capture.replay_frames();
    if frames.is_empty() || !frames.len().is_multiple_of(SQLITE_WAL_FRAME_BYTES) {
        return Err(ArchiveV3Error::Malformed("captured WAL frames").into());
    }
    let frame_count = frames.len() / SQLITE_WAL_FRAME_BYTES;
    let segment_count = frame_count.div_ceil(MAX_WAL_FRAMES_PER_SEGMENT);
    let segment_count =
        u32::try_from(segment_count).map_err(|_| ArchiveV3Error::TooLarge("WAL segment count"))?;
    if segment_count == 0 || segment_count > MAX_WAL_SEGMENTS_PER_COMMIT {
        return Err(ArchiveV3Error::TooLarge("WAL commit segments").into());
    }

    let mut previous_segment = None;
    for segment_index in 0..segment_count {
        let start_frame = segment_index as usize * MAX_WAL_FRAMES_PER_SEGMENT;
        let end_frame = (start_frame + MAX_WAL_FRAMES_PER_SEGMENT).min(frame_count);
        let frame_start = start_frame * SQLITE_WAL_FRAME_BYTES;
        let frame_end = end_frame * SQLITE_WAL_FRAME_BYTES;
        let checksum_before = if segment_index == 0 {
            capture.replay_checksum_before()
        } else {
            let checksum_offset = frame_start
                .checked_sub(SQLITE_WAL_FRAME_BYTES)
                .and_then(|offset| offset.checked_add(16))
                .ok_or(ArchiveV3Error::Malformed("WAL checksum offset"))?;
            [
                u32::from_be_bytes(
                    frames[checksum_offset..checksum_offset + 4]
                        .try_into()
                        .map_err(|_| ArchiveV3Error::Malformed("WAL checksum"))?,
                ),
                u32::from_be_bytes(
                    frames[checksum_offset + 4..checksum_offset + 8]
                        .try_into()
                        .map_err(|_| ArchiveV3Error::Malformed("WAL checksum"))?,
                ),
            ]
        };
        let segment = WalSegment {
            root_seq,
            wal_generation: capture.wal_generation(),
            segment_index,
            segment_count,
            previous_segment: previous_segment.clone(),
            first_frame_no: capture
                .first_frame_no()
                .checked_add(start_frame as u64)
                .ok_or(ArchiveV3Error::Malformed("WAL frame sequence overflow"))?,
            checksum_before,
            wal_header: *capture.replay_header(),
            frames: frames[frame_start..frame_end].to_vec(),
        };
        let object_id = ObjectId::random();
        let context = wal_context(
            archive_id,
            database_epoch,
            cipher.key_epoch(),
            root_seq,
            capture.wal_generation(),
            segment_index,
            object_id,
        )?;
        // The encoded WAL object is plaintext until `seal` returns. Keep that
        // bounded transient zeroized on success, error, and cancellation.
        let encoded = Zeroizing::new(segment.encode()?);
        let envelope = cipher.seal(&context, encoded.as_slice())?;
        backend
            .create_if_absent(context.object_key(), envelope.clone())
            .await?;
        let reference = ImmutableReference {
            object_id,
            envelope_hash: envelope.hash(),
        };
        // Do not return a root-composable reference until the exact object is
        // proven readable and valid under the context derived above.
        let resolved = load_exact_wal_segment(backend, cipher, &context, &reference).await?;
        if resolved.reference() != &reference || resolved.segment() != &segment {
            return Err(ArchiveV3Error::Authentication.into());
        }
        previous_segment = Some(reference);
    }

    Ok(UploadedWalCommit {
        root_seq,
        wal_generation: capture.wal_generation(),
        segment_count,
        effective_logical_file_length,
        final_segment: previous_segment.ok_or(ArchiveV3Error::Malformed("empty WAL upload"))?,
    })
}

/// Compose the exact checkpoint-plus-WAL fields of a candidate root. It
/// intentionally rejects a base that already has a WAL chain: a future actor
/// must checkpoint or perform a separately reviewed multi-commit replay before
/// it can layer another commit. This prevents a root from silently omitting a
/// prior witnessed WAL chain.
pub(crate) fn compose_checkpoint_wal_root(
    base: &ArchiveRoot,
    root_seq: u64,
    parent: ParentReference,
    owner_fencing_epoch: u64,
    uploaded: &UploadedWalCommit,
) -> Result<ArchiveRoot> {
    base.validate()?;
    if base.checkpoint_root.is_none()
        || base.extent_tree_root.is_some()
        || base.wal_chain_root.is_some()
        || base.wal_generation != 0
        || base.wal_segment_count != 0
        || base.root_seq.checked_add(1) != Some(root_seq)
        || uploaded.root_seq != root_seq
        // ArchiveRoot presently has one logical length because it is also the
        // deterministic checkpoint-manifest context input. Do not publish a
        // WAL grow/shrink root until a new root format can bind both lengths.
        || uploaded.effective_logical_file_length != base.logical_file_length
        || owner_fencing_epoch == 0
    {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let root = ArchiveRoot {
        root_seq,
        parent: Some(parent),
        database_epoch: base.database_epoch,
        key_epoch: base.key_epoch,
        owner_fencing_epoch,
        sqlite_page_size: SQLITE_PAGE_SIZE,
        logical_file_length: base.logical_file_length,
        user_schema_version: base.user_schema_version,
        storage_format_version: ARCHIVE_FORMAT_VERSION,
        wal_generation: uploaded.wal_generation,
        wal_segment_count: uploaded.segment_count,
        checkpoint_root: base.checkpoint_root.clone(),
        extent_tree_root: None,
        wal_chain_root: Some(uploaded.final_segment.clone()),
    };
    root.validate()?;
    Ok(root)
}

/// A private staging adapter owns the local database's temporary `-wal`
/// sibling. It receives no bytes until the whole exact predecessor chain has
/// been authenticated and validated. It has no `finish`: a future reviewed
/// composite adapter must first join this staged WAL with checkpoint recovery,
/// then make both files visible atomically.
pub trait WalRecoverySink {
    fn write_wal_header(&mut self, header: &[u8; SQLITE_WAL_HEADER_BYTES]) -> Result<()>;
    fn write_wal_frames(&mut self, first_frame_no: u64, frames: &[u8]) -> Result<()>;
    fn abort(&mut self);
}

/// Opaque proof that the exact witnessed root had both a checkpoint reference
/// and a complete verified WAL chain. A future atomic staging adapter pairs
/// this with `recover_checkpoint_from_recovery_root` using the same
/// `RecoveryRoot`; this module deliberately does not expose a partially
/// recovered database by itself.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveredWitnessWal {
    checkpoint_root: ImmutableReference,
    root_seq: u64,
    wal_generation: u64,
    segment_count: u32,
}

impl std::fmt::Debug for RecoveredWitnessWal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveredWitnessWal(<opaque>)")
    }
}

/// Recover exactly the checkpoint-plus-WAL state nominated by an independently
/// obtained witness recovery record. It derives every root and WAL context
/// from that record and follows only authenticated predecessor references.
/// There is no prefix enumeration, orphan selection, or fallback to a newer
/// local WAL. The caller's checkpoint staging flow must use this *same*
/// `RecoveryRoot` before its composite sink publishes either temporary file.
pub(crate) async fn recover_witness_nominated_wal(
    recovery: &RecoveryRoot,
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    sink: &mut dyn WalRecoverySink,
) -> Result<RecoveredWitnessWal> {
    let result =
        recover_witness_nominated_wal_inner(recovery, backend, cipher, archive_id, sink).await;
    if result.is_err() {
        sink.abort();
    }
    result
}

async fn recover_witness_nominated_wal_inner(
    recovery: &RecoveryRoot,
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    sink: &mut dyn WalRecoverySink,
) -> Result<RecoveredWitnessWal> {
    if cipher.archive_id() != archive_id {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let commitment = recovery.root();
    let registry = recovery.registry();
    // The witness root names both a root commitment and the exact wrapped
    // registry that authorized its DEK. A key-epoch match alone would permit
    // a different same-epoch registry object to be substituted at this seam.
    if cipher.key_epoch() != commitment.key_epoch()
        || registry.key_epoch() != commitment.key_epoch()
        || registry.rotation_generation() != cipher.registry_rotation_generation()
        || registry.object_id() != cipher.registry_object_id()
        || registry.ciphertext_hash() != cipher.registry_ciphertext_hash()
    {
        return Err(ArchiveV3Error::Authentication.into());
    }
    let root = load_witness_root(
        backend,
        cipher,
        archive_id,
        commitment.root(),
        commitment.parent(),
        commitment.database_epoch(),
        commitment.key_epoch(),
        commitment.owner_fencing_epoch(),
    )
    .await?;
    recover_exact_root_wal(&root, backend, cipher, archive_id, sink).await
}

/// This private helper is deliberately reachable only after
/// `load_witness_root` has authenticated the root. Keeping the chain walker
/// separate makes that proof boundary auditable and testable without creating
/// a second root-selection API.
async fn recover_exact_root_wal(
    root: &ArchiveRoot,
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    sink: &mut dyn WalRecoverySink,
) -> Result<RecoveredWitnessWal> {
    root.validate()?;
    let checkpoint_root = root
        .checkpoint_root
        .clone()
        .ok_or(ShadowWalError::MissingCheckpointOrWal)?;
    let final_reference = root
        .wal_chain_root
        .clone()
        .ok_or(ShadowWalError::MissingCheckpointOrWal)?;
    if root.wal_generation == 0
        || root.wal_segment_count == 0
        || root.wal_segment_count > MAX_WAL_SEGMENTS_PER_COMMIT
    {
        return Err(ShadowWalError::MissingCheckpointOrWal);
    }

    // A chain is short by construction, so retaining it until its *entire*
    // topology validates prevents an output sink observing an authenticated
    // prefix that later proves disconnected.
    let mut reversed = Vec::with_capacity(root.wal_segment_count as usize);
    let mut expected_reference = Some(final_reference);
    for segment_index in (0..root.wal_segment_count).rev() {
        let reference = expected_reference
            .take()
            .ok_or(ArchiveV3Error::Malformed("WAL missing predecessor"))?;
        let context = wal_context(
            archive_id,
            root.database_epoch,
            root.key_epoch,
            root.root_seq,
            root.wal_generation,
            segment_index,
            reference.object_id,
        )?;
        let resolved = load_exact_wal_segment(backend, cipher, &context, &reference).await?;
        expected_reference = resolved.segment().previous_segment.clone();
        reversed.push(resolved);
    }
    if expected_reference.is_some() {
        return Err(ArchiveV3Error::Malformed("WAL first predecessor").into());
    }
    reversed.reverse();
    validate_wal_commit_chain(root, &reversed)?;

    sink.write_wal_header(&reversed[0].segment().wal_header)?;
    for entry in &reversed {
        sink.write_wal_frames(entry.segment().first_frame_no, &entry.segment().frames)?;
    }
    Ok(RecoveredWitnessWal {
        checkpoint_root,
        root_seq: root.root_seq,
        wal_generation: root.wal_generation,
        segment_count: root.wal_segment_count,
    })
}

fn wal_context(
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: crate::archive_v3::KeyEpoch,
    root_seq: u64,
    wal_generation: u64,
    segment_index: u32,
    object_id: ObjectId,
) -> std::result::Result<ObjectContext, ArchiveV3Error> {
    ObjectContext::new(
        archive_id,
        database_epoch,
        key_epoch,
        ObjectRole::WalSegmentV3,
        LogicalLocation::Wal {
            root_seq,
            wal_generation,
            segment_index,
        },
        object_id,
        None,
    )
}

async fn load_exact_wal_segment(
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    context: &ObjectContext,
    reference: &ImmutableReference,
) -> Result<ResolvedWalSegment> {
    if context.object_id() != reference.object_id {
        return Err(ArchiveV3Error::InvalidContext.into());
    }
    let envelope = backend
        .get(&context.object_key())
        .await?
        .ok_or(ShadowWalError::MissingObject)?;
    Ok(resolve_verified_wal_segment(
        cipher,
        context.clone(),
        reference.clone(),
        envelope,
    )?)
}

#[allow(clippy::too_many_arguments)]
async fn load_witness_root(
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    reference: RootReference,
    parent: Option<RootReference>,
    database_epoch: DatabaseEpoch,
    key_epoch: crate::archive_v3::KeyEpoch,
    owner_fencing_epoch: u64,
) -> Result<ArchiveRoot> {
    let parent = parent.map(|value| ParentReference {
        object_id: value.object_id(),
        envelope_hash: value.ciphertext_hash(),
    });
    let context = ObjectContext::new(
        archive_id,
        database_epoch,
        key_epoch,
        ObjectRole::RootV3,
        LogicalLocation::Root {
            root_seq: reference.sequence(),
        },
        reference.object_id(),
        parent,
    )?;
    let expected = ImmutableReference {
        object_id: reference.object_id(),
        envelope_hash: reference.ciphertext_hash(),
    };
    let envelope = backend
        .get(&context.object_key())
        .await?
        .ok_or(ShadowWalError::MissingObject)?;
    if envelope.hash() != expected.envelope_hash {
        return Err(ArchiveV3Error::Authentication.into());
    }
    let plaintext = Zeroizing::new(cipher.open(&context, &envelope)?);
    let root = ArchiveRoot::decode(plaintext.as_slice())?;
    root.validate_for_context(&context)?;
    if root.database_epoch != database_epoch
        || root.key_epoch != key_epoch
        || root.owner_fencing_epoch != owner_fencing_epoch
    {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        archive_v3::{
            resolve_archive_cipher, ArchiveDek, ArchivePrefix, CreateIfAbsent, EnumerationCursor,
            EnumerationLimit, EnumerationPage, ExactKeyRegistryProvider, InMemoryImmutableBackend,
            KeyEpoch, KeyKind, KeyRegistryContext, KeyRegistryPlaintext, ObjectKey,
        },
        archive_v3_shadow::{ShadowSyncOutcome, WalCaptureState},
        archive_v3_witness::{
            InMemoryWitness, KeyRegistryReference, RootCommitment, Witness, WitnessBootstrap,
        },
    };

    const WRAPPED: &[u8] = b"shadow-wal-test-registry";

    struct RegistryProvider {
        plaintext: Vec<u8>,
    }

    /// A provider fault after an accepted immutable create. Publication must
    /// fail before a caller receives a root-composable reference.
    struct MissingReadbackBackend {
        inner: InMemoryImmutableBackend,
    }

    #[async_trait]
    impl ImmutableObjectBackend for MissingReadbackBackend {
        async fn create_if_absent(
            &self,
            key: ObjectKey,
            value: crate::archive_v3::CiphertextEnvelope,
        ) -> crate::archive_v3::Result<CreateIfAbsent> {
            self.inner.create_if_absent(key, value).await
        }

        async fn get(
            &self,
            _key: &ObjectKey,
        ) -> crate::archive_v3::Result<Option<crate::archive_v3::CiphertextEnvelope>> {
            Ok(None)
        }

        async fn enumerate(
            &self,
            prefix: &ArchivePrefix,
            cursor: Option<&EnumerationCursor>,
            limit: EnumerationLimit,
        ) -> crate::archive_v3::Result<EnumerationPage> {
            self.inner.enumerate(prefix, cursor, limit).await
        }

        async fn delete_exact(&self, key: &ObjectKey) -> crate::archive_v3::Result<bool> {
            self.inner.delete_exact(key).await
        }
    }

    #[async_trait]
    impl ExactKeyRegistryProvider for RegistryProvider {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            _object_id: ObjectId,
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            destination[..WRAPPED.len()].copy_from_slice(WRAPPED);
            Ok(WRAPPED.len())
        }

        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            _wrapped: &[u8],
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            Ok(self.plaintext.len())
        }
    }

    async fn test_cipher(archive: ArchiveId, key: KeyEpoch) -> VerifiedArchiveCipher {
        let context = KeyRegistryContext::new(archive, KeyKind::Archive, key);
        let plaintext =
            KeyRegistryPlaintext::encode_archive(&context, &ArchiveDek::from_bytes([7; 32]))
                .unwrap()
                .to_vec();
        resolve_archive_cipher(
            &context,
            ObjectId::from_bytes([9; 16]),
            Sha256::digest(WRAPPED).into(),
            &RegistryProvider { plaintext },
        )
        .await
        .unwrap()
    }

    fn checksum(input: &[u8], mut state: [u32; 2]) -> [u32; 2] {
        for pair in input.chunks_exact(8) {
            let first = u32::from_le_bytes(pair[..4].try_into().unwrap());
            let second = u32::from_le_bytes(pair[4..].try_into().unwrap());
            state[0] = state[0].wrapping_add(first).wrapping_add(state[1]);
            state[1] = state[1].wrapping_add(second).wrapping_add(state[0]);
        }
        state
    }

    fn captured_commit(frames: usize) -> CapturedWalCommit {
        captured_commit_with_page_count(frames, 1)
    }

    fn captured_commit_with_page_count(frames: usize, page_count: u32) -> CapturedWalCommit {
        let mut header = [0u8; SQLITE_WAL_HEADER_BYTES];
        header[..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        header[4..8].copy_from_slice(&3_007_000u32.to_be_bytes());
        header[8..12].copy_from_slice(&SQLITE_PAGE_SIZE.to_be_bytes());
        header[12..16].copy_from_slice(&1u32.to_be_bytes());
        header[16..20].copy_from_slice(&[11, 12, 13, 14]);
        header[20..24].copy_from_slice(&[21, 22, 23, 24]);
        let header_checksum = checksum(&header[..24], [0, 0]);
        header[24..28].copy_from_slice(&header_checksum[0].to_be_bytes());
        header[28..32].copy_from_slice(&header_checksum[1].to_be_bytes());

        let mut all_frames = vec![0; frames * SQLITE_WAL_FRAME_BYTES];
        let mut rolling = header_checksum;
        for frame_index in 0..frames {
            let frame = &mut all_frames
                [frame_index * SQLITE_WAL_FRAME_BYTES..(frame_index + 1) * SQLITE_WAL_FRAME_BYTES];
            frame[..4].copy_from_slice(&(frame_index as u32 + 1).to_be_bytes());
            if frame_index + 1 == frames {
                frame[4..8].copy_from_slice(&page_count.to_be_bytes());
            }
            frame[8..16].copy_from_slice(&header[16..24]);
            frame[24..].fill((frame_index % 251) as u8);
            rolling = checksum(&frame[..8], rolling);
            rolling = checksum(&frame[24..], rolling);
            frame[16..20].copy_from_slice(&rolling[0].to_be_bytes());
            frame[20..24].copy_from_slice(&rolling[1].to_be_bytes());
        }
        let mut capture = WalCaptureState::new();
        capture.observe_write(0, &header);
        capture.observe_write(SQLITE_WAL_HEADER_BYTES as i64, &all_frames);
        assert_eq!(capture.observe_sync(true), ShadowSyncOutcome::Captured);
        capture.drain_completed().pop().unwrap()
    }

    struct RecordingSink {
        header: Option<[u8; SQLITE_WAL_HEADER_BYTES]>,
        frames: Vec<(u64, Vec<u8>)>,
        aborted: bool,
        reject: bool,
        reject_frame_write: bool,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                header: None,
                frames: Vec::new(),
                aborted: false,
                reject: false,
                reject_frame_write: false,
            }
        }
    }

    impl WalRecoverySink for RecordingSink {
        fn write_wal_header(&mut self, header: &[u8; SQLITE_WAL_HEADER_BYTES]) -> Result<()> {
            if self.reject {
                return Err(ShadowWalError::Sink);
            }
            self.header = Some(*header);
            Ok(())
        }

        fn write_wal_frames(&mut self, first_frame_no: u64, frames: &[u8]) -> Result<()> {
            if self.reject || self.reject_frame_write {
                return Err(ShadowWalError::Sink);
            }
            self.frames.push((first_frame_no, frames.to_vec()));
            Ok(())
        }

        fn abort(&mut self) {
            self.aborted = true;
        }
    }

    fn bootstrap_recovery(
        archive: ArchiveId,
        database: DatabaseEpoch,
        key: KeyEpoch,
        registry: KeyRegistryReference,
    ) -> crate::archive_v3_witness::RecoveryRoot {
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive,
                database,
                RootCommitment::genesis(
                    database,
                    key,
                    RootReference::new(0, ObjectId::from_bytes([31; 16]), [32; 32]),
                ),
                registry,
            ))
            .unwrap();
        witness.recovery_root(archive).unwrap()
    }

    #[tokio::test]
    async fn public_recovery_binds_the_exact_registry_and_aborts_its_sink() {
        let archive = ArchiveId::from_bytes([21; 16]);
        let database = DatabaseEpoch::from_bytes([22; 16]);
        let key = KeyEpoch::from_bytes([23; 16]);
        let cipher = test_cipher(archive, key).await;
        let wrong_registry = KeyRegistryReference::new(
            key,
            cipher.registry_rotation_generation().saturating_add(1),
            ObjectId::from_bytes([24; 16]),
            [25; 32],
        );
        let recovery = bootstrap_recovery(archive, database, key, wrong_registry);
        let backend = InMemoryImmutableBackend::new();
        let mut sink = RecordingSink::new();
        assert!(matches!(
            recover_witness_nominated_wal(&recovery, &backend, &cipher, archive, &mut sink).await,
            Err(ShadowWalError::Archive(ArchiveV3Error::Authentication))
        ));
        assert!(sink.aborted);
        assert!(sink.header.is_none() && sink.frames.is_empty());
    }

    #[tokio::test]
    async fn public_recovery_aborts_on_a_missing_witness_nominated_root() {
        let archive = ArchiveId::from_bytes([26; 16]);
        let database = DatabaseEpoch::from_bytes([27; 16]);
        let key = KeyEpoch::from_bytes([28; 16]);
        let cipher = test_cipher(archive, key).await;
        let registry = KeyRegistryReference::new(
            key,
            cipher.registry_rotation_generation(),
            cipher.registry_object_id(),
            cipher.registry_ciphertext_hash(),
        );
        let recovery = bootstrap_recovery(archive, database, key, registry);
        let backend = InMemoryImmutableBackend::new();
        let mut sink = RecordingSink::new();
        assert!(matches!(
            recover_witness_nominated_wal(&recovery, &backend, &cipher, archive, &mut sink).await,
            Err(ShadowWalError::MissingObject)
        ));
        assert!(sink.aborted);
        assert!(sink.header.is_none() && sink.frames.is_empty());
    }

    #[tokio::test]
    async fn upload_requires_exact_readback_before_returning_a_reference() {
        let archive = ArchiveId::from_bytes([41; 16]);
        let database = DatabaseEpoch::from_bytes([42; 16]);
        let key = KeyEpoch::from_bytes([43; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = MissingReadbackBackend {
            inner: InMemoryImmutableBackend::new(),
        };
        assert!(matches!(
            upload_captured_wal_commit(
                &backend,
                &cipher,
                archive,
                database,
                1,
                &captured_commit(1),
            )
            .await,
            Err(ShadowWalError::MissingObject)
        ));
    }

    #[tokio::test]
    async fn upload_readback_composes_bounded_checkpoint_wal_root_and_replays_on_restart() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let database = DatabaseEpoch::from_bytes([2; 16]);
        let key = KeyEpoch::from_bytes([3; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = InMemoryImmutableBackend::new();
        // 255 frames force two sealed predecessor-linked objects at 4-KiB
        // pages, exercising the boundary the bundled SQLite oracle produces.
        let capture = captured_commit(255);
        let uploaded =
            upload_captured_wal_commit(&backend, &cipher, archive, database, 1, &capture)
                .await
                .unwrap();
        assert_eq!(uploaded.segment_count(), 2);
        assert_eq!(
            uploaded.effective_logical_file_length(),
            SQLITE_PAGE_SIZE as u64
        );

        let checkpoint = ImmutableReference {
            object_id: ObjectId::from_bytes([4; 16]),
            envelope_hash: [5; 32],
        };
        let base = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: SQLITE_PAGE_SIZE as u64,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: Some(checkpoint),
            extent_tree_root: None,
            wal_chain_root: None,
        };
        let root = compose_checkpoint_wal_root(
            &base,
            1,
            ParentReference {
                object_id: ObjectId::from_bytes([6; 16]),
                envelope_hash: [7; 32],
            },
            1,
            &uploaded,
        )
        .unwrap();

        let mut first = RecordingSink::new();
        recover_exact_root_wal(&root, &backend, &cipher, archive, &mut first)
            .await
            .unwrap();
        let mut restarted = RecordingSink::new();
        recover_exact_root_wal(&root, &backend, &cipher, archive, &mut restarted)
            .await
            .unwrap();
        assert_eq!(first.header, restarted.header);
        assert_eq!(first.frames, restarted.frames);
        assert_eq!(first.frames.len(), 2);
    }

    #[tokio::test]
    async fn recovery_sink_failure_aborts_without_accepting_a_partial_chain() {
        let archive = ArchiveId::from_bytes([11; 16]);
        let database = DatabaseEpoch::from_bytes([12; 16]);
        let key = KeyEpoch::from_bytes([13; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = InMemoryImmutableBackend::new();
        let uploaded = upload_captured_wal_commit(
            &backend,
            &cipher,
            archive,
            database,
            1,
            &captured_commit(1),
        )
        .await
        .unwrap();
        let root = ArchiveRoot {
            root_seq: 1,
            parent: Some(ParentReference {
                object_id: ObjectId::from_bytes([14; 16]),
                envelope_hash: [15; 32],
            }),
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 1,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: SQLITE_PAGE_SIZE as u64,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: uploaded.wal_generation(),
            wal_segment_count: uploaded.segment_count(),
            checkpoint_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([16; 16]),
                envelope_hash: [17; 32],
            }),
            extent_tree_root: None,
            wal_chain_root: Some(uploaded.final_segment().clone()),
        };
        let mut sink = RecordingSink::new();
        sink.reject_frame_write = true;
        assert!(
            recover_exact_root_wal(&root, &backend, &cipher, archive, &mut sink)
                .await
                .is_err()
        );
        // The public witness entrypoint calls abort on this same error path;
        // direct walker tests establish that no complete chain is accepted.
    }

    #[test]
    fn composition_refuses_to_drop_an_existing_wal_or_extent_base() {
        let base = ArchiveRoot {
            root_seq: 1,
            parent: Some(ParentReference {
                object_id: ObjectId::from_bytes([1; 16]),
                envelope_hash: [1; 32],
            }),
            database_epoch: DatabaseEpoch::from_bytes([2; 16]),
            key_epoch: KeyEpoch::from_bytes([3; 16]),
            owner_fencing_epoch: 1,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: SQLITE_PAGE_SIZE as u64,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 1,
            wal_segment_count: 1,
            checkpoint_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([4; 16]),
                envelope_hash: [4; 32],
            }),
            extent_tree_root: None,
            wal_chain_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([5; 16]),
                envelope_hash: [5; 32],
            }),
        };
        let uploaded = UploadedWalCommit {
            root_seq: 2,
            wal_generation: 2,
            segment_count: 1,
            effective_logical_file_length: SQLITE_PAGE_SIZE as u64,
            final_segment: ImmutableReference {
                object_id: ObjectId::from_bytes([6; 16]),
                envelope_hash: [6; 32],
            },
        };
        assert!(compose_checkpoint_wal_root(
            &base,
            2,
            ParentReference {
                object_id: ObjectId::from_bytes([7; 16]),
                envelope_hash: [7; 32],
            },
            2,
            &uploaded,
        )
        .is_err());
    }

    #[tokio::test]
    async fn exact_254_frame_boundary_stays_one_segment_and_255_splits() {
        let archive = ArchiveId::from_bytes([51; 16]);
        let database = DatabaseEpoch::from_bytes([52; 16]);
        let key = KeyEpoch::from_bytes([53; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = InMemoryImmutableBackend::new();
        assert_eq!(
            upload_captured_wal_commit(
                &backend,
                &cipher,
                archive,
                database,
                1,
                &captured_commit(254),
            )
            .await
            .unwrap()
            .segment_count(),
            1
        );
        assert_eq!(
            upload_captured_wal_commit(
                &backend,
                &cipher,
                archive,
                database,
                2,
                &captured_commit(255),
            )
            .await
            .unwrap()
            .segment_count(),
            2
        );
    }

    #[tokio::test]
    async fn composition_rejects_wal_growth_and_shrink_until_root_format_binds_two_lengths() {
        let archive = ArchiveId::from_bytes([61; 16]);
        let database = DatabaseEpoch::from_bytes([62; 16]);
        let key = KeyEpoch::from_bytes([63; 16]);
        let cipher = test_cipher(archive, key).await;
        let backend = InMemoryImmutableBackend::new();
        let base = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: SQLITE_PAGE_SIZE as u64,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: Some(ImmutableReference {
                object_id: ObjectId::from_bytes([64; 16]),
                envelope_hash: [65; 32],
            }),
            extent_tree_root: None,
            wal_chain_root: None,
        };
        let grow = upload_captured_wal_commit(
            &backend,
            &cipher,
            archive,
            database,
            1,
            &captured_commit_with_page_count(1, 2),
        )
        .await
        .unwrap();
        assert!(compose_checkpoint_wal_root(
            &base,
            1,
            ParentReference {
                object_id: ObjectId::from_bytes([66; 16]),
                envelope_hash: [67; 32],
            },
            1,
            &grow,
        )
        .is_err());

        let shorter_base = ArchiveRoot {
            logical_file_length: 2 * u64::from(SQLITE_PAGE_SIZE),
            ..base
        };
        let shrink = upload_captured_wal_commit(
            &backend,
            &cipher,
            archive,
            database,
            1,
            &captured_commit(1),
        )
        .await
        .unwrap();
        assert!(compose_checkpoint_wal_root(
            &shorter_base,
            1,
            ParentReference {
                object_id: ObjectId::from_bytes([68; 16]),
                envelope_hash: [69; 32],
            },
            1,
            &shrink,
        )
        .is_err());
    }
}
