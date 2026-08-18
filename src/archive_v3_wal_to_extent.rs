#![allow(
    dead_code,
    reason = "inactive ADR-0022 WAL-to-extent converter is compiled and tested before runtime activation"
)]

//! Inactive ADR-0022 WAL-to-extent streaming converter.
//!
//! Converts a base database checkpoint stream plus a SQLite WAL into an initial sparse Merkle
//! extent tree epoch with bounded memory:
//! 1. Validates the WAL header: magic (`0x377f0682` / `0x377f0683`), file format (`3007000`),
//!    page size, sequence numbers, salts, and header checksum. All fields are decoded strictly
//!    as big-endian per the SQLite specification; the magic number determines only whether
//!    checksum words are interpreted as big-endian or little-endian.
//! 2. Validates SQLite checksum-chain consistency (format integrity, not cryptographic
//!    authentication) for every frame, plus salts, page numbers, and commit markers.
//! 3. Sealed index: [`ChecksumValidatedWalIndex`] fields are private and can only be minted via
//!    `parse`.
//! 4. RAII temporary staging: [`PrivateWalStagingFile`] guarantees `O_EXCL` creation with 0600
//!    permissions and unlinks the name immediately after opening, so no path persists while the
//!    plaintext WAL is staged.
//! 5. Bounded two-pass streaming: pass 1 checksum-validates frames into the bounded index;
//!    pass 2 streams 1 MiB extents.
//! 6. Builds the 256-fanout Merkle radix tree via
//!    [`upload_extent_tree`](crate::archive_v3_extent::upload_extent_tree).
//!
//! # Security boundary
//!
//! WAL and base-checkpoint bytes must arrive through the AEAD-authenticated archive envelope
//! path or an equally trusted source. The SQLite WAL checksum chain validated here is a
//! non-keyed rolling checksum: it detects torn or corrupted WALs, not adversarial substitution.
//! Salts bind frames to this WAL's header only. Nothing in this module provides cryptographic
//! authentication of WAL or base content.
//!
//! # Format policy (fail closed)
//!
//! - Page size: exactly 4096 ([`SQLITE_PAGE_SIZE`]). Any other page size is rejected; this is
//!   not a general WAL parser.
//! - Torn-tail policy (SQLite-conformant recovery semantics): header-level corruption (bad
//!   magic, wrong format version, wrong page size, header checksum mismatch, short header) is a
//!   hard error. Frame-level anomalies (salt mismatch, frame checksum mismatch, truncated
//!   trailing frame header or payload) end the log cleanly: scanning stops and previously
//!   committed transactions are kept, exactly as SQLite recovers a torn WAL tail.
//! - A checksum-consistent frame carrying an impossible page number (zero, or beyond the
//!   32 GiB database bound) is a hard error: such a WAL cannot describe a database this
//!   module can represent.
//!
//! # Availability limit
//!
//! At most [`MAX_WAL_FRAMES`] (65,536) frames are accepted, an explicit availability ceiling of
//! roughly 256 MiB of WAL page data ([`MAX_WAL_STREAM_BYTES`], about 258 MiB including frame
//! headers). Larger WAL streams are rejected before staging completes; callers must checkpoint
//! more frequently than this ceiling.
//!
//! # Plaintext staging
//!
//! The production entrypoint stages the plaintext WAL in the fixed directory `/tmp`, which is
//! SEV-encrypted tmpfs under the repository threat model: plaintext must never reach persistent
//! disk, and no environment variable is consulted when choosing the directory.

use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

use crate::archive_v3::{
    ArchiveId, ArchiveV3Error, DatabaseEpoch, ImmutableObjectBackend, SQLITE_PAGE_SIZE,
};
use crate::archive_v3_extent::{
    upload_extent_tree, ExtentCipher, ExtentObjectStaging, ExtentSource, ExtentTreeError,
    Result as ExtentResult, SourceExtent, UploadedExtentTree, EXTENT_BYTES,
};

pub const WAL_MAGIC_LE: u32 = 0x377f0682;
pub const WAL_MAGIC_BE: u32 = 0x377f0683;
pub const WAL_FILE_FORMAT_VERSION: u32 = 3007000;
pub const WAL_HEADER_BYTES: usize = 32;
pub const WAL_FRAME_HEADER_BYTES: usize = 24;
pub const WAL_FRAME_BYTES: usize = WAL_FRAME_HEADER_BYTES + (SQLITE_PAGE_SIZE as usize);
pub const MAX_WAL_FRAMES: usize = 65_536;
pub const MAX_UNCOMMITTED_FRAMES: usize = 8_192;

/// SQLite page size as a usize for buffer sizing. `SQLITE_PAGE_SIZE` is 4096, which fits every
/// supported target's usize.
const PAGE_BYTES: usize = SQLITE_PAGE_SIZE as usize;

/// Upper bound on the staged WAL stream: header plus the maximum number of frames. Streams
/// exceeding this are rejected before parsing (availability ceiling, roughly 256 MiB of page
/// data).
pub const MAX_WAL_STREAM_BYTES: u64 =
    (WAL_HEADER_BYTES as u64) + (MAX_WAL_FRAMES as u64) * (WAL_FRAME_BYTES as u64);

/// Largest page number representable within the 32 GiB database bound.
const MAX_WAL_PAGE_NO: u64 = crate::archive_v3::MAX_DATABASE_BYTES / (SQLITE_PAGE_SIZE as u64);

#[derive(Debug, thiserror::Error)]
pub enum WalToExtentError {
    #[error(transparent)]
    Extent(#[from] ExtentTreeError),
    #[error(transparent)]
    Archive(#[from] ArchiveV3Error),
    #[error("database length is zero")]
    ZeroLengthDatabase,
    #[error("database length is not a whole number of pages")]
    MisalignedDatabaseLength,
    #[error("database size exceeds maximum permitted for extent conversion")]
    DatabaseTooLarge,
    #[error("WAL stream exceeds maximum permitted size")]
    WalStreamTooLarge,
    #[error("WAL header truncated")]
    TruncatedWalHeader,
    #[error("invalid WAL header magic")]
    InvalidWalMagic,
    #[error("unsupported WAL file format version")]
    UnsupportedFileFormat,
    #[error("unsupported WAL page size; only 4096 is supported")]
    UnsupportedPageSize,
    #[error("invalid WAL header checksum")]
    HeaderChecksumMismatch,
    #[error("invalid page number in checksum-consistent WAL frame")]
    InvalidPageNumber,
    #[error("uncommitted frame count exceeded maximum allowed limit")]
    ExceededUncommittedFrameLimit,
    #[error("total WAL frames exceeded maximum cap")]
    ExceededTotalFrameLimit,
    #[error("checksum input length is not a multiple of 8 bytes")]
    MisalignedChecksumInput,
    #[error("integer conversion out of range during WAL conversion")]
    IntegerOutOfRange,
    #[error("I/O error reading staged WAL")]
    StagingIo(#[source] std::io::Error),
    #[error("I/O error during WAL stream conversion")]
    Io(#[from] std::io::Error),
}

/// Compute the SQLite WAL rolling checksum (running 32-bit pair s1, s2) over 32-bit words.
///
/// Per the SQLite specification, the magic number determines whether the 32-bit words are read
/// as big-endian (0x377f0683) or little-endian (0x377f0682). This is a non-keyed format
/// checksum, not a cryptographic MAC. Errors (without touching `s1`/`s2`) if `bytes` is not a
/// multiple of 8 bytes long.
pub(crate) fn wal_checksum_bytes(
    bytes: &[u8],
    checksum_is_big_endian: bool,
    s1: &mut u32,
    s2: &mut u32,
) -> Result<(), WalToExtentError> {
    if !bytes.len().is_multiple_of(8) {
        return Err(WalToExtentError::MisalignedChecksumInput);
    }
    for chunk in bytes.chunks_exact(8) {
        let (w1, w2) = if checksum_is_big_endian {
            (
                u32::from_be_bytes(chunk[0..4].try_into().unwrap()),
                u32::from_be_bytes(chunk[4..8].try_into().unwrap()),
            )
        } else {
            (
                u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
                u32::from_le_bytes(chunk[4..8].try_into().unwrap()),
            )
        };
        *s1 = s1.wrapping_add(w1).wrapping_add(*s2);
        *s2 = s2.wrapping_add(w2).wrapping_add(*s1);
    }
    Ok(())
}

/// Checksum-validated WAL header metadata. Fields are private and can only be minted by
/// [`ChecksumValidatedWalIndex::parse`]; accessors expose read-only copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedWalHeader {
    checksum_is_big_endian: bool,
    page_size: u32,
    checkpoint_seq: u32,
    salt1: u32,
    salt2: u32,
    checksum1: u32,
    checksum2: u32,
}

impl ValidatedWalHeader {
    pub fn checksum_is_big_endian(&self) -> bool {
        self.checksum_is_big_endian
    }

    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    pub fn checkpoint_seq(&self) -> u32 {
        self.checkpoint_seq
    }

    pub fn salt1(&self) -> u32 {
        self.salt1
    }

    pub fn salt2(&self) -> u32 {
        self.salt2
    }

    pub fn checksum1(&self) -> u32 {
        self.checksum1
    }

    pub fn checksum2(&self) -> u32 {
        self.checksum2
    }
}

/// Lightweight, sealed index of checksum-validated, committed WAL frames.
///
/// The index validates SQLite checksum-chain consistency (format integrity, not cryptographic
/// authentication) and retains only committed transactions.
#[derive(Debug)]
pub struct ChecksumValidatedWalIndex {
    header: ValidatedWalHeader,
    final_db_size_pages: u32,
    committed_frame_offsets: HashMap<u32, u64>, // page_no (1-indexed) -> byte offset in WAL stream
}

impl ChecksumValidatedWalIndex {
    /// Parse a WAL stream, validating the SQLite checksum chain of every frame and retaining
    /// only committed transactions.
    ///
    /// Torn-tail policy (SQLite-conformant): header-level corruption is a hard error;
    /// frame-level anomalies (salt mismatch, frame checksum mismatch, truncated trailing frame
    /// header or payload) end the log cleanly, keeping previously committed transactions. A
    /// checksum-consistent frame with an impossible page number (zero or beyond the 32 GiB
    /// bound) is a hard error. Genuine I/O errors while scanning are reported as
    /// [`WalToExtentError::StagingIo`], distinct from end-of-log.
    pub fn parse<R: Read + Seek>(mut reader: R) -> Result<Self, WalToExtentError> {
        let mut header_buf = [0u8; WAL_HEADER_BYTES];
        reader.read_exact(&mut header_buf).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                WalToExtentError::TruncatedWalHeader
            } else {
                WalToExtentError::StagingIo(error)
            }
        })?;

        // All fields in the SQLite WAL header are strictly big-endian.
        let magic = u32::from_be_bytes(header_buf[0..4].try_into().unwrap());
        let checksum_is_big_endian = match magic {
            WAL_MAGIC_BE => true,
            WAL_MAGIC_LE => false,
            _ => return Err(WalToExtentError::InvalidWalMagic),
        };

        let file_format = u32::from_be_bytes(header_buf[4..8].try_into().unwrap());
        if file_format != WAL_FILE_FORMAT_VERSION {
            return Err(WalToExtentError::UnsupportedFileFormat);
        }

        let page_size = u32::from_be_bytes(header_buf[8..12].try_into().unwrap());
        if page_size != SQLITE_PAGE_SIZE {
            return Err(WalToExtentError::UnsupportedPageSize);
        }

        let checkpoint_seq = u32::from_be_bytes(header_buf[12..16].try_into().unwrap());
        let salt1 = u32::from_be_bytes(header_buf[16..20].try_into().unwrap());
        let salt2 = u32::from_be_bytes(header_buf[20..24].try_into().unwrap());
        let expected_checksum1 = u32::from_be_bytes(header_buf[24..28].try_into().unwrap());
        let expected_checksum2 = u32::from_be_bytes(header_buf[28..32].try_into().unwrap());

        // Validate the WAL header checksum over the first 24 bytes.
        let mut running_s1 = 0u32;
        let mut running_s2 = 0u32;
        wal_checksum_bytes(
            &header_buf[0..24],
            checksum_is_big_endian,
            &mut running_s1,
            &mut running_s2,
        )?;
        if running_s1 != expected_checksum1 || running_s2 != expected_checksum2 {
            return Err(WalToExtentError::HeaderChecksumMismatch);
        }

        let header = ValidatedWalHeader {
            checksum_is_big_endian,
            page_size,
            checkpoint_seq,
            salt1,
            salt2,
            checksum1: expected_checksum1,
            checksum2: expected_checksum2,
        };

        let mut committed_frame_offsets = HashMap::new();
        let mut uncommitted_batch = Vec::new();
        let mut final_db_size_pages = 0;
        let mut frame_idx = 0;

        let mut frame_header_buf = [0u8; WAL_FRAME_HEADER_BYTES];
        // Frame payloads are plaintext database pages; zeroize on drop.
        let mut page_data_buf = Zeroizing::new([0u8; PAGE_BYTES]);

        loop {
            // Distinguish genuine zero-byte EOF, a torn trailing frame header (clean
            // end-of-log), and genuine I/O errors.
            let mut header_read = 0;
            while header_read < WAL_FRAME_HEADER_BYTES {
                match reader.read(&mut frame_header_buf[header_read..]) {
                    Ok(0) => break,
                    Ok(n) => header_read += n,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(WalToExtentError::StagingIo(error)),
                }
            }

            if header_read == 0 {
                // Genuine zero-byte EOF.
                break;
            }
            if header_read < WAL_FRAME_HEADER_BYTES {
                // Torn trailing frame header: clean end-of-log, keep prior commits.
                break;
            }

            // A full additional frame is present beyond the availability ceiling: fail
            // closed. Exactly MAX_WAL_FRAMES frames are accepted.
            if frame_idx >= MAX_WAL_FRAMES {
                return Err(WalToExtentError::ExceededTotalFrameLimit);
            }

            let frame_offset = reader.stream_position()? - (WAL_FRAME_HEADER_BYTES as u64);
            let page_no = u32::from_be_bytes(frame_header_buf[0..4].try_into().unwrap());
            let commit_page_count = u32::from_be_bytes(frame_header_buf[4..8].try_into().unwrap());
            let frame_salt1 = u32::from_be_bytes(frame_header_buf[8..12].try_into().unwrap());
            let frame_salt2 = u32::from_be_bytes(frame_header_buf[12..16].try_into().unwrap());
            let frame_expected_c1 =
                u32::from_be_bytes(frame_header_buf[16..20].try_into().unwrap());
            let frame_expected_c2 =
                u32::from_be_bytes(frame_header_buf[20..24].try_into().unwrap());

            if frame_salt1 != salt1 || frame_salt2 != salt2 {
                // Salt mismatch terminates the valid WAL sequence cleanly.
                break;
            }

            // Read the frame page payload; a torn trailing payload is clean end-of-log, any
            // other read failure is a genuine staging I/O error.
            if let Err(error) = reader.read_exact(page_data_buf.as_mut_slice()) {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(WalToExtentError::StagingIo(error));
            }

            // Compute the frame checksum: 8 bytes of frame header + 4096 bytes of page data.
            wal_checksum_bytes(
                &frame_header_buf[0..8],
                checksum_is_big_endian,
                &mut running_s1,
                &mut running_s2,
            )?;
            wal_checksum_bytes(
                page_data_buf.as_slice(),
                checksum_is_big_endian,
                &mut running_s1,
                &mut running_s2,
            )?;

            if running_s1 != frame_expected_c1 || running_s2 != frame_expected_c2 {
                // Frame checksum mismatch: clean end-of-log, keep prior commits. The running
                // checksum state is now stale, but scanning stops here so it is never reused.
                break;
            }

            // Only checksum-consistent frames reach the page-number checks, so a torn tail
            // with garbage page numbers still ends the log cleanly above, while a valid frame
            // carrying an impossible page number is a hard error: committed frames beyond the
            // 32 GiB bound must never enter the index.
            if page_no == 0 || u64::from(page_no) > MAX_WAL_PAGE_NO {
                return Err(WalToExtentError::InvalidPageNumber);
            }

            // Enforce the uncommitted-transaction bound exactly: the batch never holds more
            // than MAX_UNCOMMITTED_FRAMES frames, including the commit frame.
            if uncommitted_batch.len() >= MAX_UNCOMMITTED_FRAMES {
                return Err(WalToExtentError::ExceededUncommittedFrameLimit);
            }
            uncommitted_batch.push((page_no, frame_offset + (WAL_FRAME_HEADER_BYTES as u64)));

            if commit_page_count > 0 {
                // Commit marker found: commit this transaction batch.
                final_db_size_pages = commit_page_count;
                for (p_no, p_off) in uncommitted_batch.drain(..) {
                    committed_frame_offsets.insert(p_no, p_off);
                }
            }
            frame_idx += 1;
        }

        Ok(Self {
            header,
            final_db_size_pages,
            committed_frame_offsets,
        })
    }

    pub fn header(&self) -> &ValidatedWalHeader {
        &self.header
    }

    pub fn final_db_size_pages(&self) -> u32 {
        self.final_db_size_pages
    }

    pub fn committed_page_count(&self) -> usize {
        self.committed_frame_offsets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.committed_frame_offsets.is_empty()
    }
}

/// RAII-guarded private 0600 temporary staging file.
///
/// The file is created with `O_EXCL` and a random name, then unlinked immediately after
/// opening (POSIX semantics keep the open descriptor usable), so no name persists on the
/// filesystem during conversion. The `Drop` `remove_file` is a no-op fallback covering the
/// unlikely window where the immediate unlink failed.
pub(crate) struct PrivateWalStagingFile {
    file: File,
    path: PathBuf,
}

impl PrivateWalStagingFile {
    /// Create a private 0600 staging file in the specified directory and immediately unlink
    /// its name. Tests may pass a `tempfile` directory; production code must use
    /// `create_private`.
    pub(crate) fn create_in(dir: &Path) -> std::io::Result<Self> {
        use rand::{rngs::OsRng, RngCore};
        let mut rand_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut rand_bytes);
        let mut hex_name = String::with_capacity(32);
        for b in rand_bytes {
            use std::fmt::Write;
            let _ = write!(&mut hex_name, "{:02x}", b);
        }
        let unique_name = format!("kioku-wal-stage-{}.tmp", hex_name);
        let path = dir.join(unique_name);

        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;

        // Unlink the name immediately while keeping the descriptor: no path persists during
        // conversion. On failure, Drop retries as a best-effort fallback.
        let _ = std::fs::remove_file(&path);

        Ok(Self { file, path })
    }

    /// Create a private staging file in the fixed directory `/tmp`, which is SEV-encrypted
    /// tmpfs under the repository threat model (plaintext must never reach persistent disk).
    /// No environment variable is consulted when choosing the directory.
    fn create_private() -> std::io::Result<Self> {
        Self::create_in(Path::new("/tmp"))
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// The path the file was created at. The name is unlinked immediately after creation, so
    /// this path normally no longer exists on the filesystem.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Read for PrivateWalStagingFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for PrivateWalStagingFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for PrivateWalStagingFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

impl Drop for PrivateWalStagingFile {
    fn drop(&mut self) {
        // No-op fallback: the name was already unlinked at creation in the normal case.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Copy at most `max_bytes` from `reader` into `writer`; fail closed with
/// [`WalToExtentError::WalStreamTooLarge`] if the stream holds even one more byte.
fn copy_bounded<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    max_bytes: u64,
) -> Result<u64, WalToExtentError> {
    let mut limited = reader.take(max_bytes.saturating_add(1));
    let copied = std::io::copy(&mut limited, writer)?;
    if copied > max_bytes {
        return Err(WalToExtentError::WalStreamTooLarge);
    }
    Ok(copied)
}

/// Lazily pulled base-checkpoint state: at most one pending base extent is buffered.
struct BaseSourceState {
    source: Box<dyn ExtentSource>,
    /// The base source's own declared logical length; every pulled extent is validated
    /// against it.
    base_len: u64,
    base_slots: u64,
    last_pulled_extent_no: Option<u64>,
    pending: Option<SourceExtent>,
    /// Plaintext scratch for the pending extent; zeroized on drop.
    pending_data: Zeroizing<Vec<u8>>,
    exhausted: bool,
}

impl BaseSourceState {
    /// Pull the next base extent into the pending slot if it is empty. Base extents at or
    /// beyond `total_extents` are dropped when the WAL committed a (possibly smaller) database
    /// size, and are a contract violation otherwise.
    async fn pull(&mut self, wal_defined_length: bool, total_extents: u64) -> ExtentResult<()> {
        if self.exhausted || self.pending.is_some() {
            return Ok(());
        }
        self.pending_data.fill(0);
        let Some(item) = self
            .source
            .next_extent(self.pending_data.as_mut_slice())
            .await?
        else {
            self.exhausted = true;
            return Ok(());
        };
        // Validate the extent against the base source's own declared length: strictly
        // increasing extent numbers and the exact per-extent byte length.
        if self
            .last_pulled_extent_no
            .is_some_and(|previous| item.extent_no <= previous)
            || item.extent_no >= self.base_slots
        {
            return Err(ExtentTreeError::Source);
        }
        let offset = item
            .extent_no
            .checked_mul(u64::from(EXTENT_BYTES))
            .ok_or(ExtentTreeError::Source)?;
        let expected_len = self
            .base_len
            .checked_sub(offset)
            .ok_or(ExtentTreeError::Source)?
            .min(u64::from(EXTENT_BYTES));
        if item.logical_byte_len == 0 || u64::from(item.logical_byte_len) != expected_len {
            return Err(ExtentTreeError::Source);
        }
        self.last_pulled_extent_no = Some(item.extent_no);
        if item.extent_no >= total_extents {
            if wal_defined_length {
                // dbsize-after-commit truncation: this and every later base extent lies at or
                // beyond the new logical end and is dropped (extent numbers are strictly
                // increasing, so nothing further can be in range).
                self.pending_data.fill(0);
                self.exhausted = true;
                return Ok(());
            }
            // Without a WAL-committed length the merged length is the base's own claimed
            // length; a base extent beyond it violates the source contract.
            return Err(ExtentTreeError::Source);
        }
        self.pending = Some(item);
        Ok(())
    }
}

/// Bounded streaming extent source merging a base database checkpoint with committed,
/// checksum-validated WAL frames.
///
/// The base source may omit extents (sparse holes per the [`ExtentSource`] contract); omitted
/// base extents merge as zeros. Merged extents that are entirely zero are themselves emitted
/// as holes (skipped), which the extent tree reconstructs as zeros; the logical file length is
/// preserved exactly regardless of trailing holes. A database whose merged content is entirely
/// zero yields no extents and is rejected by the uploader (an all-hole file has no root),
/// which cannot occur for a well-formed SQLite database because page 1 carries the header.
pub struct StreamingWalExtentSource<R: Read + Seek> {
    wal_reader: R,
    committed_frame_offsets: HashMap<u32, u64>,
    logical_file_length: u64,
    total_extents: u64,
    current_extent_no: u64,
    /// True when the logical length came from a WAL commit record (authoritative, may
    /// truncate the base); false when it fell back to the base length.
    wal_defined_length: bool,
    base: Option<BaseSourceState>,
}

impl<R: Read + Seek> StreamingWalExtentSource<R> {
    pub fn new(
        wal_reader: R,
        index: ChecksumValidatedWalIndex,
        base_source: Option<Box<dyn ExtentSource>>,
        fallback_base_len: u64,
    ) -> Result<Self, WalToExtentError> {
        let wal_defined_length = index.final_db_size_pages > 0;
        let logical_file_length = if wal_defined_length {
            u64::from(index.final_db_size_pages) * u64::from(SQLITE_PAGE_SIZE)
        } else {
            fallback_base_len
        };

        if logical_file_length == 0 {
            return Err(WalToExtentError::ZeroLengthDatabase);
        }
        if !logical_file_length.is_multiple_of(u64::from(SQLITE_PAGE_SIZE)) {
            return Err(WalToExtentError::MisalignedDatabaseLength);
        }
        if logical_file_length > crate::archive_v3::MAX_DATABASE_BYTES {
            return Err(WalToExtentError::DatabaseTooLarge);
        }

        let total_extents = logical_file_length.div_ceil(u64::from(EXTENT_BYTES));
        let base = match base_source {
            Some(source) => {
                let base_len = source.logical_file_length()?;
                Some(BaseSourceState {
                    source,
                    base_len,
                    base_slots: base_len.div_ceil(u64::from(EXTENT_BYTES)),
                    last_pulled_extent_no: None,
                    pending: None,
                    // EXTENT_BYTES (1 MiB) fits usize on all supported targets.
                    pending_data: Zeroizing::new(vec![0u8; EXTENT_BYTES as usize]),
                    exhausted: base_len == 0,
                })
            }
            None => None,
        };

        Ok(Self {
            wal_reader,
            committed_frame_offsets: index.committed_frame_offsets,
            logical_file_length,
            total_extents,
            current_extent_no: 0,
            wal_defined_length,
            base,
        })
    }
}

#[async_trait::async_trait]
impl<R: Read + Seek + Send> ExtentSource for StreamingWalExtentSource<R> {
    fn logical_file_length(&self) -> ExtentResult<u64> {
        Ok(self.logical_file_length)
    }

    async fn next_extent(&mut self, destination: &mut [u8]) -> ExtentResult<Option<SourceExtent>> {
        let wal_defined_length = self.wal_defined_length;
        let total_extents = self.total_extents;

        loop {
            if self.current_extent_no >= total_extents {
                // Fail closed: without a WAL-committed (possibly truncating) length, a base
                // source yielding anything beyond the merged length violates its contract.
                // With a WAL-committed truncation, remaining base extents are legitimately
                // dropped without being pulled.
                if let Some(state) = self.base.as_mut() {
                    if !wal_defined_length && !state.exhausted {
                        state.pending_data.fill(0);
                        if state
                            .source
                            .next_extent(state.pending_data.as_mut_slice())
                            .await?
                            .is_some()
                        {
                            return Err(ExtentTreeError::Source);
                        }
                        state.exhausted = true;
                    }
                }
                return Ok(None);
            }

            let extent_no = self.current_extent_no;
            self.current_extent_no += 1;

            let extent_start_byte = extent_no
                .checked_mul(u64::from(EXTENT_BYTES))
                .ok_or(ExtentTreeError::Source)?;
            let extent_end_byte = (extent_start_byte.saturating_add(u64::from(EXTENT_BYTES)))
                .min(self.logical_file_length);
            // Bounded by EXTENT_BYTES (1 MiB), so both conversions always succeed; checked
            // anyway per the no-unchecked-cast policy.
            let logical_byte_len = u32::try_from(extent_end_byte - extent_start_byte)
                .map_err(|_| ExtentTreeError::Source)?;
            let logical_byte_len_usize =
                usize::try_from(logical_byte_len).map_err(|_| ExtentTreeError::Source)?;

            destination[..logical_byte_len_usize].fill(0);

            // Merge the base checkpoint extent, if the base covers this extent number.
            // Omitted base extent numbers are sparse holes (zeros).
            if let Some(state) = self.base.as_mut() {
                state.pull(wal_defined_length, total_extents).await?;
                match state.pending {
                    Some(pending) if pending.extent_no < extent_no => {
                        // The uploader consumes strictly increasing extents, so a pending
                        // base extent below the current output extent is unreachable unless
                        // the base violated its ordering contract.
                        return Err(ExtentTreeError::Source);
                    }
                    Some(pending) if pending.extent_no == extent_no => {
                        let copy_len = if pending.logical_byte_len > logical_byte_len {
                            // The base extends past the merged logical end inside this
                            // extent. Legitimate only under WAL dbsize truncation: trim the
                            // final extent to the final logical length.
                            if !wal_defined_length {
                                return Err(ExtentTreeError::Source);
                            }
                            logical_byte_len_usize
                        } else {
                            usize::try_from(pending.logical_byte_len)
                                .map_err(|_| ExtentTreeError::Source)?
                        };
                        destination[..copy_len].copy_from_slice(&state.pending_data[..copy_len]);
                        state.pending = None;
                    }
                    // Pending extent beyond the current one, or base exhausted: this output
                    // extent is a base hole (zeros).
                    _ => {}
                }
            }

            // Overlay committed WAL frames. The MAX_DATABASE_BYTES validation in `new`
            // guarantees extent_start_byte / page size and every derived page number fit in
            // u32; conversions are checked anyway.
            let start_page = u32::try_from(extent_start_byte / u64::from(SQLITE_PAGE_SIZE))
                .map_err(|_| ExtentTreeError::Source)?;
            let num_pages_in_extent = logical_byte_len_usize.div_ceil(PAGE_BYTES);

            for p_idx in 0..num_pages_in_extent {
                let page_no = start_page
                    .checked_add(u32::try_from(p_idx).map_err(|_| ExtentTreeError::Source)?)
                    .and_then(|value| value.checked_add(1)) // 1-indexed SQLite page
                    .ok_or(ExtentTreeError::Source)?;
                if let Some(&frame_data_offset) = self.committed_frame_offsets.get(&page_no) {
                    let dest_offset = p_idx
                        .checked_mul(PAGE_BYTES)
                        .ok_or(ExtentTreeError::Source)?;
                    self.wal_reader
                        .seek(SeekFrom::Start(frame_data_offset))
                        .map_err(|_| ExtentTreeError::Source)?;
                    self.wal_reader
                        .read_exact(&mut destination[dest_offset..dest_offset + PAGE_BYTES])
                        .map_err(|_| ExtentTreeError::Source)?;
                }
            }

            // Emit an entirely zero merged extent as a sparse hole: skip it. The extent tree
            // treats omitted extent numbers as all-zero holes, and the logical file length is
            // carried by `logical_file_length()`, so trailing holes preserve exact length.
            if destination[..logical_byte_len_usize]
                .iter()
                .all(|&b| b == 0)
            {
                continue;
            }

            return Ok(Some(SourceExtent {
                extent_no,
                logical_byte_len,
            }));
        }
    }
}

/// Convert a WAL-authoritative archive snapshot into a verified extent tree root.
///
/// The plaintext WAL is staged in a private, immediately unlinked 0600 file in the fixed
/// directory `/tmp` (SEV-encrypted tmpfs under the repository threat model; no environment
/// variable is consulted). The incoming stream is capped at [`MAX_WAL_STREAM_BYTES`]; larger
/// streams fail closed before parsing. The base source, when present, may omit extents as
/// sparse holes, and a base longer than a WAL-truncated database is dropped/trimmed to the
/// final logical length.
#[allow(clippy::too_many_arguments)]
pub async fn convert_wal_stream_to_extent_tree<R, C, S>(
    backend: &dyn ImmutableObjectBackend,
    cipher: &C,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    mut wal_stream: R,
    base_source: Option<Box<dyn ExtentSource>>,
    fallback_base_len: u64,
    staging: S,
) -> Result<UploadedExtentTree, WalToExtentError>
where
    R: Read + Send,
    C: ExtentCipher,
    S: ExtentObjectStaging,
{
    let mut staging_file = PrivateWalStagingFile::create_private()?;
    copy_bounded(&mut wal_stream, &mut staging_file, MAX_WAL_STREAM_BYTES)?;
    staging_file.seek(SeekFrom::Start(0))?;

    let index = ChecksumValidatedWalIndex::parse(&mut staging_file)?;
    staging_file.seek(SeekFrom::Start(0))?;

    let mut source =
        StreamingWalExtentSource::new(staging_file, index, base_source, fallback_base_len)?;

    let tree = upload_extent_tree(
        backend,
        cipher,
        archive_id,
        database_epoch,
        &mut source,
        staging,
    )
    .await?;

    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3::{InMemoryImmutableBackend, KeyEpoch};
    use crate::archive_v3_extent::tests::{NonWalTestStaging, TestCipher};
    use std::io::Cursor;

    /// Incremental builder for synthetic, checksum-chain-consistent WAL streams.
    struct WalBuilder {
        bytes: Vec<u8>,
        s1: u32,
        s2: u32,
        checksum_is_big_endian: bool,
        salt1: u32,
        salt2: u32,
    }

    impl WalBuilder {
        fn with_header_fields(magic: u32, file_format: u32, page_size: u32) -> Self {
            let checksum_is_big_endian = magic == WAL_MAGIC_BE;
            let salt1 = 0x11223344u32;
            let salt2 = 0x55667788u32;

            let mut header_prefix = Vec::new();
            header_prefix.extend_from_slice(&magic.to_be_bytes());
            header_prefix.extend_from_slice(&file_format.to_be_bytes());
            header_prefix.extend_from_slice(&page_size.to_be_bytes());
            header_prefix.extend_from_slice(&1u32.to_be_bytes()); // checkpoint seq
            header_prefix.extend_from_slice(&salt1.to_be_bytes());
            header_prefix.extend_from_slice(&salt2.to_be_bytes());

            let mut s1 = 0u32;
            let mut s2 = 0u32;
            wal_checksum_bytes(&header_prefix, checksum_is_big_endian, &mut s1, &mut s2)
                .expect("header prefix is checksum-aligned");

            let mut bytes = header_prefix;
            bytes.extend_from_slice(&s1.to_be_bytes());
            bytes.extend_from_slice(&s2.to_be_bytes());
            Self {
                bytes,
                s1,
                s2,
                checksum_is_big_endian,
                salt1,
                salt2,
            }
        }

        fn new(magic: u32) -> Self {
            Self::with_header_fields(magic, WAL_FILE_FORMAT_VERSION, SQLITE_PAGE_SIZE)
        }

        fn push_frame(&mut self, page_no: u32, commit_page_count: u32, page: &[u8; PAGE_BYTES]) {
            let mut frame_hdr = Vec::new();
            frame_hdr.extend_from_slice(&page_no.to_be_bytes());
            frame_hdr.extend_from_slice(&commit_page_count.to_be_bytes());
            frame_hdr.extend_from_slice(&self.salt1.to_be_bytes());
            frame_hdr.extend_from_slice(&self.salt2.to_be_bytes());
            wal_checksum_bytes(
                &frame_hdr[0..8],
                self.checksum_is_big_endian,
                &mut self.s1,
                &mut self.s2,
            )
            .expect("frame header prefix is checksum-aligned");
            wal_checksum_bytes(
                page,
                self.checksum_is_big_endian,
                &mut self.s1,
                &mut self.s2,
            )
            .expect("page payload is checksum-aligned");
            self.bytes.extend_from_slice(&frame_hdr);
            self.bytes.extend_from_slice(&self.s1.to_be_bytes());
            self.bytes.extend_from_slice(&self.s2.to_be_bytes());
            self.bytes.extend_from_slice(page);
        }

        fn frame(mut self, page_no: u32, commit_page_count: u32, fill: u8) -> Self {
            self.push_frame(page_no, commit_page_count, &[fill; PAGE_BYTES]);
            self
        }

        fn build(self) -> Vec<u8> {
            self.bytes
        }
    }

    fn make_test_wal_stream(magic: u32) -> Vec<u8> {
        WalBuilder::new(magic)
            .frame(1, 0, 0x11)
            .frame(2, 2, 0x22)
            .build()
    }

    /// Test base source yielding the listed `(extent_no, fill)` extents against a declared
    /// logical length; omitted extent numbers are sparse holes.
    struct TestBaseSource {
        base_len: u64,
        extents: Vec<(u64, u8)>,
        next: usize,
    }

    #[async_trait::async_trait]
    impl ExtentSource for TestBaseSource {
        fn logical_file_length(&self) -> ExtentResult<u64> {
            Ok(self.base_len)
        }

        async fn next_extent(
            &mut self,
            destination: &mut [u8],
        ) -> ExtentResult<Option<SourceExtent>> {
            let Some(&(extent_no, fill)) = self.extents.get(self.next) else {
                return Ok(None);
            };
            self.next += 1;
            let offset = extent_no * u64::from(EXTENT_BYTES);
            let logical_byte_len =
                u32::try_from((self.base_len - offset).min(u64::from(EXTENT_BYTES)))
                    .expect("extent length fits u32");
            destination[..logical_byte_len as usize].fill(fill);
            Ok(Some(SourceExtent {
                extent_no,
                logical_byte_len,
            }))
        }
    }

    /// Test base source streaming real bytes as dense sequential extents.
    struct BufBaseSource {
        data: Vec<u8>,
        next_extent_no: u64,
    }

    #[async_trait::async_trait]
    impl ExtentSource for BufBaseSource {
        fn logical_file_length(&self) -> ExtentResult<u64> {
            Ok(self.data.len() as u64)
        }

        async fn next_extent(
            &mut self,
            destination: &mut [u8],
        ) -> ExtentResult<Option<SourceExtent>> {
            let offset = (self.next_extent_no * u64::from(EXTENT_BYTES)) as usize;
            if offset >= self.data.len() {
                return Ok(None);
            }
            let extent_no = self.next_extent_no;
            self.next_extent_no += 1;
            let len = (self.data.len() - offset).min(EXTENT_BYTES as usize);
            destination[..len].copy_from_slice(&self.data[offset..offset + len]);
            Ok(Some(SourceExtent {
                extent_no,
                logical_byte_len: u32::try_from(len).expect("extent length fits u32"),
            }))
        }
    }

    /// Drive an extent source to completion, assembling the merged logical image (holes stay
    /// zero) and recording which extent numbers were yielded.
    async fn merge_to_image(source: &mut dyn ExtentSource) -> (Vec<u8>, Vec<u64>) {
        let logical_len = usize::try_from(source.logical_file_length().expect("logical length"))
            .expect("length fits usize");
        let mut image = vec![0u8; logical_len];
        let mut buffer = vec![0u8; EXTENT_BYTES as usize];
        let mut yielded = Vec::new();
        loop {
            buffer.fill(0);
            let Some(item) = source.next_extent(&mut buffer).await.expect("next extent") else {
                break;
            };
            yielded.push(item.extent_no);
            let offset = usize::try_from(item.extent_no * u64::from(EXTENT_BYTES))
                .expect("offset fits usize");
            let len = item.logical_byte_len as usize;
            image[offset..offset + len].copy_from_slice(&buffer[..len]);
        }
        (image, yielded)
    }

    fn parse_index(wal: &[u8]) -> ChecksumValidatedWalIndex {
        ChecksumValidatedWalIndex::parse(Cursor::new(wal.to_vec())).expect("parses WAL")
    }

    #[test]
    fn test_wal_checksum_validation_be_and_le_magic() {
        for magic in [WAL_MAGIC_BE, WAL_MAGIC_LE] {
            let wal_bytes = make_test_wal_stream(magic);
            let index = ChecksumValidatedWalIndex::parse(Cursor::new(wal_bytes))
                .expect("parses checksum-consistent WAL");

            assert_eq!(index.final_db_size_pages(), 2);
            assert_eq!(index.committed_page_count(), 2);
            assert_eq!(index.header().page_size(), 4096);
        }

        // A bit flip in the first frame makes its checksum chain inconsistent. Per the
        // SQLite-conformant torn-tail policy this is a clean end-of-log before any commit,
        // not a hard error.
        let mut bad_wal = make_test_wal_stream(WAL_MAGIC_BE);
        bad_wal[35] ^= 0xff;
        let index = ChecksumValidatedWalIndex::parse(Cursor::new(bad_wal))
            .expect("torn tail is a clean end-of-log");
        assert!(index.is_empty());
        assert_eq!(index.final_db_size_pages(), 0);
    }

    #[test]
    fn test_header_level_corruption_hard_errors() {
        // Invalid magic.
        let wal =
            WalBuilder::with_header_fields(0xdead_beef, WAL_FILE_FORMAT_VERSION, 4096).build();
        assert!(matches!(
            ChecksumValidatedWalIndex::parse(Cursor::new(wal)),
            Err(WalToExtentError::InvalidWalMagic)
        ));

        // Wrong file format version (header checksum itself is consistent).
        let wal = WalBuilder::with_header_fields(WAL_MAGIC_BE, 3007001, 4096).build();
        assert!(matches!(
            ChecksumValidatedWalIndex::parse(Cursor::new(wal)),
            Err(WalToExtentError::UnsupportedFileFormat)
        ));

        // Wrong page size (header checksum itself is consistent).
        let wal =
            WalBuilder::with_header_fields(WAL_MAGIC_BE, WAL_FILE_FORMAT_VERSION, 8192).build();
        assert!(matches!(
            ChecksumValidatedWalIndex::parse(Cursor::new(wal)),
            Err(WalToExtentError::UnsupportedPageSize)
        ));

        // Header checksum mismatch.
        let mut wal = WalBuilder::new(WAL_MAGIC_BE).build();
        wal[30] ^= 0xff;
        assert!(matches!(
            ChecksumValidatedWalIndex::parse(Cursor::new(wal)),
            Err(WalToExtentError::HeaderChecksumMismatch)
        ));

        // Short header.
        let wal = WalBuilder::new(WAL_MAGIC_BE).build();
        assert!(matches!(
            ChecksumValidatedWalIndex::parse(Cursor::new(wal[..16].to_vec())),
            Err(WalToExtentError::TruncatedWalHeader)
        ));
    }

    #[test]
    fn test_wal_truncation_is_end_of_log() {
        let wal_bytes = make_test_wal_stream(WAL_MAGIC_BE);

        // Truncated frame header (10 bytes of frame after the 32-byte WAL header): clean
        // end-of-log with no commits.
        let index = ChecksumValidatedWalIndex::parse(Cursor::new(wal_bytes[..42].to_vec()))
            .expect("torn trailing frame header ends the log cleanly");
        assert!(index.is_empty());

        // Truncated frame payload: clean end-of-log with no commits.
        let index = ChecksumValidatedWalIndex::parse(Cursor::new(wal_bytes[..100].to_vec()))
            .expect("torn trailing frame payload ends the log cleanly");
        assert!(index.is_empty());
    }

    #[test]
    fn test_torn_tail_preserves_prior_commits() {
        let committed = WalBuilder::new(WAL_MAGIC_BE).frame(1, 1, 0xAA).build();

        // Torn trailing frame header after a committed transaction.
        let mut torn_header = committed.clone();
        torn_header.extend_from_slice(&2u32.to_be_bytes());
        torn_header.extend_from_slice(&[0u8; 6]); // 10 bytes of a would-be frame header
        let index = parse_index(&torn_header);
        assert_eq!(index.final_db_size_pages(), 1);
        assert_eq!(index.committed_page_count(), 1);

        // Torn trailing frame payload (valid salts, full header, partial page).
        let full = WalBuilder::new(WAL_MAGIC_BE)
            .frame(1, 1, 0xAA)
            .frame(2, 2, 0xBB)
            .build();
        let torn_payload = full[..committed.len() + WAL_FRAME_HEADER_BYTES + 100].to_vec();
        let index = parse_index(&torn_payload);
        assert_eq!(index.final_db_size_pages(), 1);
        assert_eq!(index.committed_page_count(), 1);
    }

    #[test]
    fn test_frame_checksum_mismatch_is_clean_end_of_log() {
        let mut wal = WalBuilder::new(WAL_MAGIC_BE)
            .frame(1, 1, 0xAA)
            .frame(2, 2, 0xBB)
            .build();
        // Corrupt one payload byte of the second frame.
        let second_frame_payload = WAL_HEADER_BYTES + WAL_FRAME_BYTES + WAL_FRAME_HEADER_BYTES;
        wal[second_frame_payload + 50] ^= 0xff;

        let index = parse_index(&wal);
        assert_eq!(index.final_db_size_pages(), 1, "first commit preserved");
        assert_eq!(index.committed_page_count(), 1);
    }

    #[test]
    fn test_wal_salt_mismatch_clean_termination() {
        let mut wal_bytes = make_test_wal_stream(WAL_MAGIC_BE);
        // Append a frame with mismatched salts.
        let mut rogue_hdr = Vec::new();
        rogue_hdr.extend_from_slice(&3u32.to_be_bytes());
        rogue_hdr.extend_from_slice(&3u32.to_be_bytes());
        rogue_hdr.extend_from_slice(&0x99999999u32.to_be_bytes()); // wrong salt
        rogue_hdr.extend_from_slice(&0x88888888u32.to_be_bytes());
        rogue_hdr.extend_from_slice(&0u32.to_be_bytes());
        rogue_hdr.extend_from_slice(&0u32.to_be_bytes());
        rogue_hdr.extend_from_slice(&[0u8; 4096]);
        wal_bytes.extend_from_slice(&rogue_hdr);

        let index = ChecksumValidatedWalIndex::parse(Cursor::new(wal_bytes))
            .expect("cleanly terminates on salt change");
        assert_eq!(index.final_db_size_pages(), 2);
    }

    #[test]
    fn test_post_commit_uncommitted_trailing_frames_dropped() {
        let wal = WalBuilder::new(WAL_MAGIC_BE)
            .frame(1, 1, 0xAA)
            .frame(2, 0, 0xBB) // valid frame after the last commit: never committed
            .build();
        let index = parse_index(&wal);
        assert_eq!(index.final_db_size_pages(), 1);
        assert_eq!(
            index.committed_page_count(),
            1,
            "trailing uncommitted frame dropped"
        );
    }

    #[test]
    fn test_invalid_page_numbers_hard_error() {
        // Page number zero in a checksum-consistent frame.
        let wal = WalBuilder::new(WAL_MAGIC_BE).frame(0, 1, 0xAA).build();
        assert!(matches!(
            ChecksumValidatedWalIndex::parse(Cursor::new(wal)),
            Err(WalToExtentError::InvalidPageNumber)
        ));

        // Page number beyond the 32 GiB database bound.
        let beyond = u32::try_from(MAX_WAL_PAGE_NO + 1).expect("bound fits u32");
        let wal = WalBuilder::new(WAL_MAGIC_BE).frame(beyond, 1, 0xAA).build();
        assert!(matches!(
            ChecksumValidatedWalIndex::parse(Cursor::new(wal)),
            Err(WalToExtentError::InvalidPageNumber)
        ));

        // Largest in-bound page number is accepted.
        let at_bound = u32::try_from(MAX_WAL_PAGE_NO).expect("bound fits u32");
        let wal = WalBuilder::new(WAL_MAGIC_BE)
            .frame(at_bound, 1, 0xAA)
            .build();
        assert!(ChecksumValidatedWalIndex::parse(Cursor::new(wal)).is_ok());
    }

    fn build_single_transaction_wal(frame_count: usize) -> Vec<u8> {
        let mut builder = WalBuilder::new(WAL_MAGIC_BE);
        let page = [0x42u8; PAGE_BYTES];
        for i in 0..frame_count {
            let page_no = u32::try_from(i + 1).expect("page number fits u32");
            let commit = if i + 1 == frame_count {
                u32::try_from(frame_count).expect("commit size fits u32")
            } else {
                0
            };
            builder.push_frame(page_no, commit, &page);
        }
        builder.build()
    }

    #[test]
    fn test_uncommitted_frame_limit_boundary() {
        // Exactly MAX_UNCOMMITTED_FRAMES frames in one transaction is accepted.
        let wal = build_single_transaction_wal(MAX_UNCOMMITTED_FRAMES);
        let index = parse_index(&wal);
        assert_eq!(index.committed_page_count(), MAX_UNCOMMITTED_FRAMES);

        // One more frame in the same transaction fails closed.
        let wal = build_single_transaction_wal(MAX_UNCOMMITTED_FRAMES + 1);
        assert!(matches!(
            ChecksumValidatedWalIndex::parse(Cursor::new(wal)),
            Err(WalToExtentError::ExceededUncommittedFrameLimit)
        ));
    }

    #[test]
    fn test_checksum_input_alignment() {
        let mut s1 = 0u32;
        let mut s2 = 0u32;
        assert!(matches!(
            wal_checksum_bytes(&[0u8; 7], true, &mut s1, &mut s2),
            Err(WalToExtentError::MisalignedChecksumInput)
        ));
        assert_eq!((s1, s2), (0, 0), "state untouched on misaligned input");
        wal_checksum_bytes(&[0u8; 8], true, &mut s1, &mut s2).expect("aligned input");
    }

    #[test]
    fn test_copy_bounded_cap() {
        let mut out = Vec::new();
        let copied =
            copy_bounded(&mut Cursor::new(vec![7u8; 10]), &mut out, 10).expect("within cap");
        assert_eq!(copied, 10);
        assert_eq!(out.len(), 10);

        let mut out = Vec::new();
        assert!(matches!(
            copy_bounded(&mut Cursor::new(vec![7u8; 11]), &mut out, 10),
            Err(WalToExtentError::WalStreamTooLarge)
        ));
    }

    #[test]
    fn test_private_wal_staging_file_unlinked_at_create() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut staging = PrivateWalStagingFile::create_in(dir.path()).expect("create");
        assert!(
            !staging.path().exists(),
            "staging file name must be unlinked immediately after creation"
        );
        staging.write_all(b"SECRET_WAL_DATA").expect("write via fd");
        staging.seek(SeekFrom::Start(0)).expect("seek via fd");
        let mut readback = Vec::new();
        staging.read_to_end(&mut readback).expect("read via fd");
        assert_eq!(readback, b"SECRET_WAL_DATA");
    }

    #[test]
    fn test_database_length_validation_split() {
        // Header-only WAL: no commits, so the fallback length governs.
        let wal = WalBuilder::new(WAL_MAGIC_BE).build();

        assert!(matches!(
            StreamingWalExtentSource::new(Cursor::new(wal.clone()), parse_index(&wal), None, 0),
            Err(WalToExtentError::ZeroLengthDatabase)
        ));
        assert!(matches!(
            StreamingWalExtentSource::new(Cursor::new(wal.clone()), parse_index(&wal), None, 4097),
            Err(WalToExtentError::MisalignedDatabaseLength)
        ));
        let too_large = crate::archive_v3::MAX_DATABASE_BYTES + u64::from(SQLITE_PAGE_SIZE);
        assert!(matches!(
            StreamingWalExtentSource::new(
                Cursor::new(wal.clone()),
                parse_index(&wal),
                None,
                too_large
            ),
            Err(WalToExtentError::DatabaseTooLarge)
        ));
    }

    #[tokio::test]
    async fn test_zero_frame_wal_falls_back_to_base_length() {
        let wal = WalBuilder::new(WAL_MAGIC_BE).build();
        let index = parse_index(&wal);
        assert!(index.is_empty());
        assert_eq!(index.final_db_size_pages(), 0);

        let base = TestBaseSource {
            base_len: 8192,
            extents: vec![(0, 0x33)],
            next: 0,
        };
        let mut source =
            StreamingWalExtentSource::new(Cursor::new(wal), index, Some(Box::new(base)), 8192)
                .expect("falls back to base length");
        assert_eq!(source.logical_file_length().expect("length"), 8192);
        let (image, yielded) = merge_to_image(&mut source).await;
        assert_eq!(yielded, vec![0]);
        assert_eq!(image, vec![0x33u8; 8192]);
    }

    #[tokio::test]
    async fn test_duplicate_page_later_commit_wins() {
        let wal = WalBuilder::new(WAL_MAGIC_BE)
            .frame(1, 1, 0xAA)
            .frame(1, 1, 0xBB)
            .build();
        let index = parse_index(&wal);
        assert_eq!(index.committed_page_count(), 1);

        let mut source = StreamingWalExtentSource::new(Cursor::new(wal), index, None, 0)
            .expect("source over duplicate-page WAL");
        let (image, yielded) = merge_to_image(&mut source).await;
        assert_eq!(yielded, vec![0]);
        assert_eq!(image, vec![0xBBu8; 4096], "later committed frame wins");
    }

    #[tokio::test]
    async fn test_dbsize_truncation_drops_pages_beyond_final_size() {
        // First commit grows the database to 3 pages; the second commit truncates it to 2.
        let wal = WalBuilder::new(WAL_MAGIC_BE)
            .frame(1, 0, 0x01)
            .frame(2, 0, 0x02)
            .frame(3, 3, 0x03)
            .frame(1, 2, 0x04)
            .build();
        let index = parse_index(&wal);
        assert_eq!(index.final_db_size_pages(), 2);

        let mut source = StreamingWalExtentSource::new(Cursor::new(wal), index, None, 0)
            .expect("source over truncating WAL");
        assert_eq!(source.logical_file_length().expect("length"), 8192);
        let (image, _) = merge_to_image(&mut source).await;
        assert_eq!(
            image.len(),
            8192,
            "logical length matches the final commit size"
        );
        assert_eq!(&image[..4096], &[0x04u8; 4096][..]);
        assert_eq!(
            &image[4096..],
            &[0x02u8; 4096][..],
            "page beyond final size dropped"
        );
    }

    const MIB: usize = EXTENT_BYTES as usize;

    fn truncating_overlay_wal() -> Vec<u8> {
        // Page 300 lives in extent 1; the commit truncates the database to 640 pages
        // (2.5 MiB), so extent 2 is a partially covered final extent.
        WalBuilder::new(WAL_MAGIC_BE)
            .frame(300, 0, 0x77)
            .frame(1, 640, 0x55)
            .build()
    }

    #[tokio::test]
    async fn test_base_overlay_sparse_hole_trim_and_drop() {
        // Base: 4 MiB with extent 1 omitted (sparse hole) and extent 3 beyond the truncated
        // logical end (dropped without being consumed).
        let wal = truncating_overlay_wal();
        let base = TestBaseSource {
            base_len: 4 * MIB as u64,
            extents: vec![(0, 0xA1), (2, 0xC3), (3, 0xD4)],
            next: 0,
        };
        let mut source = StreamingWalExtentSource::new(
            Cursor::new(wal.clone()),
            parse_index(&wal),
            Some(Box::new(base)),
            0,
        )
        .expect("merged source");

        let logical_len = 640usize * PAGE_BYTES; // 2.5 MiB
        assert_eq!(
            source.logical_file_length().expect("length"),
            logical_len as u64
        );
        let (image, yielded) = merge_to_image(&mut source).await;
        assert_eq!(yielded, vec![0, 1, 2]);

        let mut expected = vec![0u8; logical_len];
        expected[..MIB].fill(0xA1); // base extent 0
        expected[..PAGE_BYTES].fill(0x55); // WAL page 1 overlays base
        let page_300 = 299 * PAGE_BYTES;
        expected[page_300..page_300 + PAGE_BYTES].fill(0x77); // WAL page in base hole
        expected[2 * MIB..].fill(0xC3); // base extent 2 trimmed to 512 KiB
        assert_eq!(image, expected);
    }

    #[tokio::test]
    async fn test_base_beyond_truncated_length_dropped_and_tail_hole_skipped() {
        // Base extent 3 is pulled and buffered while scanning extent 1, then dropped because
        // the WAL truncated the database to 2.5 MiB. Extent 2 merges to all zeros and is
        // emitted as a hole, while the exact logical length is preserved.
        let wal = truncating_overlay_wal();
        let base = TestBaseSource {
            base_len: 4 * MIB as u64,
            extents: vec![(0, 0xA1), (3, 0xD4)],
            next: 0,
        };
        let mut source = StreamingWalExtentSource::new(
            Cursor::new(wal.clone()),
            parse_index(&wal),
            Some(Box::new(base)),
            0,
        )
        .expect("merged source");

        let logical_len = 640usize * PAGE_BYTES;
        assert_eq!(
            source.logical_file_length().expect("length"),
            logical_len as u64
        );
        let (image, yielded) = merge_to_image(&mut source).await;
        assert_eq!(yielded, vec![0, 1], "all-zero extent 2 emitted as a hole");

        let mut expected = vec![0u8; logical_len];
        expected[..MIB].fill(0xA1);
        expected[..PAGE_BYTES].fill(0x55);
        let page_300 = 299 * PAGE_BYTES;
        expected[page_300..page_300 + PAGE_BYTES].fill(0x77);
        assert_eq!(image, expected);
    }

    #[tokio::test]
    async fn test_base_beyond_fallback_length_fails_closed() {
        // Header-only WAL: the merged length is the 1 MiB fallback, so a base yielding a
        // second extent violates the contract instead of being silently dropped.
        let wal = WalBuilder::new(WAL_MAGIC_BE).build();
        let base = TestBaseSource {
            base_len: 2 * MIB as u64,
            extents: vec![(0, 0xA1), (1, 0xB2)],
            next: 0,
        };
        let mut source = StreamingWalExtentSource::new(
            Cursor::new(wal.clone()),
            parse_index(&wal),
            Some(Box::new(base)),
            MIB as u64,
        )
        .expect("merged source");

        let mut buffer = vec![0u8; MIB];
        let first = source.next_extent(&mut buffer).await.expect("first extent");
        assert_eq!(first.map(|e| e.extent_no), Some(0));
        buffer.fill(0);
        assert!(
            source.next_extent(&mut buffer).await.is_err(),
            "base extent beyond non-truncated merged length must fail closed"
        );
    }

    #[tokio::test]
    async fn test_base_intra_extent_trim_under_truncation() {
        // Base of 3 pages, WAL commit truncates to 2 pages inside the same extent: the base
        // extent is trimmed to the final logical length.
        let wal = WalBuilder::new(WAL_MAGIC_BE).frame(1, 2, 0x66).build();
        let base = TestBaseSource {
            base_len: 3 * PAGE_BYTES as u64,
            extents: vec![(0, 0xB2)],
            next: 0,
        };
        let mut source = StreamingWalExtentSource::new(
            Cursor::new(wal.clone()),
            parse_index(&wal),
            Some(Box::new(base)),
            0,
        )
        .expect("merged source");
        assert_eq!(source.logical_file_length().expect("length"), 8192);
        let (image, yielded) = merge_to_image(&mut source).await;
        assert_eq!(yielded, vec![0]);
        assert_eq!(&image[..PAGE_BYTES], &[0x66u8; PAGE_BYTES][..]);
        assert_eq!(
            &image[PAGE_BYTES..],
            &[0xB2u8; PAGE_BYTES][..],
            "trimmed base tail"
        );

        // Without a WAL-committed length the same overhang is a contract violation.
        let wal = WalBuilder::new(WAL_MAGIC_BE).build();
        let base = TestBaseSource {
            base_len: 3 * PAGE_BYTES as u64,
            extents: vec![(0, 0xB2)],
            next: 0,
        };
        let mut source = StreamingWalExtentSource::new(
            Cursor::new(wal.clone()),
            parse_index(&wal),
            Some(Box::new(base)),
            2 * PAGE_BYTES as u64,
        )
        .expect("merged source");
        let mut buffer = vec![0u8; MIB];
        assert!(
            source.next_extent(&mut buffer).await.is_err(),
            "base claiming bytes past a non-truncated logical end must fail closed"
        );
    }

    #[tokio::test]
    async fn test_all_zero_tail_extent_round_trips_exact_length() {
        // A single committed page-1 write with a 512-page (2 MiB) database size: extent 1 is
        // entirely zero, uploads as a hole, and the exact logical length is preserved.
        let wal = WalBuilder::new(WAL_MAGIC_BE).frame(1, 512, 0x5A).build();

        let backend = InMemoryImmutableBackend::default();
        let archive_id = ArchiveId::random();
        let database_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let cipher = TestCipher::new(archive_id, key_epoch);
        let staging = NonWalTestStaging::in_memory();

        let uploaded_tree = convert_wal_stream_to_extent_tree(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            Cursor::new(wal.clone()),
            None,
            0,
            staging,
        )
        .await
        .expect("converts WAL with all-zero tail extent");
        assert_eq!(
            uploaded_tree.extent_count(),
            1,
            "tail extent uploaded as a hole"
        );
        assert_eq!(uploaded_tree.logical_file_length(), 2 * MIB as u64);

        let mut source =
            StreamingWalExtentSource::new(Cursor::new(wal.clone()), parse_index(&wal), None, 0)
                .expect("source");
        let (image, yielded) = merge_to_image(&mut source).await;
        assert_eq!(yielded, vec![0]);
        assert_eq!(image.len(), 2 * MIB);
        assert_eq!(&image[..PAGE_BYTES], &[0x5Au8; PAGE_BYTES][..]);
        assert!(image[PAGE_BYTES..].iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn test_wal_to_extent_streaming_conversion() {
        let wal_bytes = make_test_wal_stream(WAL_MAGIC_BE);
        let reader = Cursor::new(wal_bytes);

        let backend = InMemoryImmutableBackend::default();
        let archive_id = ArchiveId::random();
        let database_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let cipher = TestCipher::new(archive_id, key_epoch);
        let staging = NonWalTestStaging::in_memory();

        let uploaded_tree = convert_wal_stream_to_extent_tree(
            &backend,
            &cipher,
            archive_id,
            database_epoch,
            reader,
            None,
            0,
            staging,
        )
        .await
        .expect("converts WAL stream into uploaded extent tree");

        assert_eq!(uploaded_tree.extent_count(), 1);
        assert_eq!(uploaded_tree.logical_file_length(), 8192);
    }

    #[tokio::test]
    async fn test_known_answer_real_sqlite_wal_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("known_answer.sqlite3");
        let wal_path = dir.path().join("known_answer.sqlite3-wal");

        let conn = rusqlite::Connection::open(&db_path).expect("open database");
        conn.execute_batch("PRAGMA page_size=4096;")
            .expect("set page size");
        let mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .expect("enable WAL");
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        let _autocheckpoint: i64 = conn
            .query_row("PRAGMA wal_autocheckpoint=0", [], |row| row.get(0))
            .expect("disable auto-checkpoint");
        let page_size: i64 = conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .expect("read page size");
        assert_eq!(page_size, 4096);

        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB);")
            .expect("create table");
        for i in 0..64i64 {
            conn.execute(
                "INSERT INTO t (id, v) VALUES (?1, ?2)",
                rusqlite::params![i, vec![0xC7u8; 512]],
            )
            .expect("insert row");
        }

        // Snapshot the pre-checkpoint base file and the WAL while the connection is open
        // (closing the last connection would checkpoint and reset the WAL).
        let base_bytes = std::fs::read(&db_path).expect("read base database");
        let wal_bytes = std::fs::read(&wal_path).expect("read WAL");
        assert!(wal_bytes.len() > WAL_HEADER_BYTES, "WAL must be non-empty");

        let index = ChecksumValidatedWalIndex::parse(Cursor::new(wal_bytes.clone()))
            .expect("parses a real SQLite WAL");
        assert!(index.committed_page_count() > 0);
        assert!(index.final_db_size_pages() > 0);
        let final_len = u64::from(index.final_db_size_pages()) * u64::from(SQLITE_PAGE_SIZE);

        // Checkpoint through a second connection, then compare the checkpointed database
        // image against this module's merge of base + WAL.
        let conn2 = rusqlite::Connection::open(&db_path).expect("open second connection");
        let _busy: i64 = conn2
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .expect("checkpoint");
        drop(conn2);
        drop(conn);
        let db_after = std::fs::read(&db_path).expect("read checkpointed database");
        assert_eq!(
            db_after.len() as u64,
            final_len,
            "commit dbsize matches checkpoint"
        );

        let base: Option<Box<dyn ExtentSource>> = if base_bytes.is_empty() {
            None
        } else {
            Some(Box::new(BufBaseSource {
                data: base_bytes.clone(),
                next_extent_no: 0,
            }))
        };
        let mut source = StreamingWalExtentSource::new(
            Cursor::new(wal_bytes),
            index,
            base,
            base_bytes.len() as u64,
        )
        .expect("merged source over real WAL");
        let (image, _) = merge_to_image(&mut source).await;
        assert_eq!(&image[..16], &b"SQLite format 3\0"[..]);
        assert_eq!(image, db_after, "merge matches SQLite's own checkpoint");
    }
}
