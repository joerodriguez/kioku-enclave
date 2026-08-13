//! Private, inactive bridge from a legacy SQLite plaintext stream to dense
//! archive-v3 extents.
//!
//! This adapter is intentionally only a provisional byte source. It does not
//! finish the parent second pass, verify its binding, stage an object, create a
//! candidate, or expose a completion token. A later reviewed coordinator must
//! own those actions and the required witness re-read before any authority can
//! be created.

use crate::{
    archive_v3::{MAX_DATABASE_BYTES, SQLITE_PAGE_SIZE},
    archive_v3_extent::{
        ExtentSource, ExtentTreeError, Result as ExtentResult, SourceExtent, EXTENT_BYTES,
    },
};
use zeroize::Zeroize;

use super::{AuthenticatedLegacySource, LegacySourceState, PinnedLegacyRangeReader};

// This composition remains a child of `legacy_gcm`: it alone may consume the
// parent source's provisional pull and one-shot completion without broadening
// either capability to archive-v3 callers.
mod coordinator;

const SQLITE_HEADER_BYTES: usize = 100;
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Facts extracted from an already validated first SQLite header. This remains
/// private until a later child coordinator can bind it to a finished source
/// and an independently re-read witness.
#[derive(Clone, Copy, PartialEq, Eq)]
struct LegacySqliteHeader {
    user_version: [u8; 4],
}

/// Dense, sequential provisional extents from one authenticated legacy
/// source. It has no public constructor and no production authority.
struct LegacySqliteExtentSource<'source, 'reader, R: PinnedLegacyRangeReader> {
    source: &'source mut AuthenticatedLegacySource<'reader, R>,
    plaintext_len: u64,
    next_extent_no: u64,
    header: Option<LegacySqliteHeader>,
    state: ExtentSourceState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtentSourceState {
    Reading,
    EofReturned,
    Failed,
}

/// Marks a cancelled adapter pull terminal. The parent source has its own
/// operation guard, so both retained cryptographic state and the adapter's
/// stream state fail closed across every await boundary.
struct ExtentSourceOperationGuard<'operation, 'source, 'reader, R: PinnedLegacyRangeReader> {
    source: &'operation mut LegacySqliteExtentSource<'source, 'reader, R>,
    completed: bool,
}

impl<'operation, 'source, 'reader, R: PinnedLegacyRangeReader>
    ExtentSourceOperationGuard<'operation, 'source, 'reader, R>
{
    fn new(source: &'operation mut LegacySqliteExtentSource<'source, 'reader, R>) -> Self {
        Self {
            source,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl<R: PinnedLegacyRangeReader> Drop for ExtentSourceOperationGuard<'_, '_, '_, R> {
    fn drop(&mut self) {
        if !self.completed {
            self.source.fail();
        }
    }
}

impl<'source, 'reader, R: PinnedLegacyRangeReader> LegacySqliteExtentSource<'source, 'reader, R> {
    fn new(source: &'source mut AuthenticatedLegacySource<'reader, R>) -> ExtentResult<Self> {
        let plaintext_len = source.plaintext_len();
        validate_plaintext_len(plaintext_len)?;
        Ok(Self {
            source,
            plaintext_len,
            next_extent_no: 0,
            header: None,
            state: ExtentSourceState::Reading,
        })
    }

    fn header(&self) -> Option<LegacySqliteHeader> {
        self.header
    }

    fn fail(&mut self) {
        self.state = ExtentSourceState::Failed;
        self.source.state = LegacySourceState::Failed;
        self.source.scrub();
    }

    async fn next_extent_inner(
        &mut self,
        destination: &mut [u8],
    ) -> ExtentResult<Option<SourceExtent>> {
        destination.zeroize();
        if destination.len() != EXTENT_BYTES as usize {
            self.fail();
            return Err(ExtentTreeError::Source);
        }
        let Some(logical_byte_len) = extent_len(self.plaintext_len, self.next_extent_no) else {
            self.state = ExtentSourceState::EofReturned;
            return Ok(None);
        };

        // Always pass the complete caller-owned extent buffer to the parent.
        // Besides enforcing the one-MiB pull bound, this preserves the
        // parent's clear-before-read ownership contract for a short final
        // extent.
        let provisional = match self.source.read_provisional(destination).await {
            Ok(provisional) => provisional,
            Err(_) => {
                destination.zeroize();
                self.fail();
                return Err(ExtentTreeError::Source);
            }
        };
        if provisional.len() != logical_byte_len as usize {
            destination.zeroize();
            self.fail();
            return Err(ExtentTreeError::Source);
        }
        if self.next_extent_no == 0 {
            let header = match validate_sqlite_header(
                &destination[..SQLITE_HEADER_BYTES],
                self.plaintext_len,
            ) {
                Ok(header) => header,
                Err(error) => {
                    destination.zeroize();
                    self.fail();
                    return Err(error);
                }
            };
            self.header = Some(header);
        }
        let item = SourceExtent {
            extent_no: self.next_extent_no,
            logical_byte_len,
        };
        self.next_extent_no = match self.next_extent_no.checked_add(1) {
            Some(next_extent_no) => next_extent_no,
            None => {
                destination.zeroize();
                self.fail();
                return Err(ExtentTreeError::Source);
            }
        };
        Ok(Some(item))
    }
}

#[async_trait::async_trait]
impl<R: PinnedLegacyRangeReader> ExtentSource for LegacySqliteExtentSource<'_, '_, R> {
    fn logical_file_length(&self) -> ExtentResult<u64> {
        if self.state == ExtentSourceState::Failed {
            return Err(ExtentTreeError::Source);
        }
        Ok(self.plaintext_len)
    }

    async fn next_extent(&mut self, destination: &mut [u8]) -> ExtentResult<Option<SourceExtent>> {
        destination.zeroize();
        if self.state != ExtentSourceState::Reading {
            self.fail();
            return Err(ExtentTreeError::Source);
        }
        let mut operation = ExtentSourceOperationGuard::new(self);
        let result = operation.source.next_extent_inner(destination).await;
        if result.is_ok() {
            operation.complete();
        }
        result
    }
}

fn validate_plaintext_len(plaintext_len: u64) -> ExtentResult<()> {
    if plaintext_len == 0
        || plaintext_len < u64::from(SQLITE_PAGE_SIZE)
        || plaintext_len > MAX_DATABASE_BYTES
        || !plaintext_len.is_multiple_of(u64::from(SQLITE_PAGE_SIZE))
    {
        return Err(ExtentTreeError::Source);
    }
    Ok(())
}

fn extent_len(plaintext_len: u64, extent_no: u64) -> Option<u32> {
    let offset = extent_no.checked_mul(u64::from(EXTENT_BYTES))?;
    if offset >= plaintext_len {
        return None;
    }
    let remaining = plaintext_len.checked_sub(offset)?;
    u32::try_from(remaining.min(u64::from(EXTENT_BYTES))).ok()
}

fn validate_sqlite_header(header: &[u8], plaintext_len: u64) -> ExtentResult<LegacySqliteHeader> {
    if header.len() != SQLITE_HEADER_BYTES
        || header[..16] != SQLITE_MAGIC[..]
        || header[16..18] != (SQLITE_PAGE_SIZE as u16).to_be_bytes()[..]
        || !matches!(header[18], 1 | 2)
        || !matches!(header[19], 1 | 2)
        || header[21..24] != [64, 32, 32]
        || !header[72..92].iter().all(|byte| *byte == 0)
    {
        return Err(ExtentTreeError::Source);
    }

    let change_counter =
        u32::from_be_bytes(header[24..28].try_into().expect("SQLite header slice"));
    let page_count = u32::from_be_bytes(header[28..32].try_into().expect("SQLite header slice"));
    let freelist_trunk =
        u32::from_be_bytes(header[32..36].try_into().expect("SQLite header slice"));
    let freelist_pages =
        u32::from_be_bytes(header[36..40].try_into().expect("SQLite header slice"));
    let schema_format = u32::from_be_bytes(header[44..48].try_into().expect("SQLite header slice"));
    let largest_root = u32::from_be_bytes(header[52..56].try_into().expect("SQLite header slice"));
    let text_encoding = u32::from_be_bytes(header[56..60].try_into().expect("SQLite header slice"));
    let incremental_vacuum =
        u32::from_be_bytes(header[64..68].try_into().expect("SQLite header slice"));
    let version_valid_for =
        u32::from_be_bytes(header[92..96].try_into().expect("SQLite header slice"));
    let authenticated_pages = plaintext_len / u64::from(SQLITE_PAGE_SIZE);
    if schema_format > 4
        || !(1..=3).contains(&text_encoding)
        || (freelist_trunk == 0 && freelist_pages != 0)
        || (freelist_trunk != 0
            && (freelist_pages == 0
                || freelist_trunk < 2
                || u64::from(freelist_trunk) > authenticated_pages))
        || u64::from(freelist_pages) >= authenticated_pages
        || (largest_root == 0 && incremental_vacuum != 0)
        || (largest_root != 0 && u64::from(largest_root) > authenticated_pages)
    {
        return Err(ExtentTreeError::Source);
    }
    if change_counter == version_valid_for
        && page_count != 0
        && u64::from(page_count) != authenticated_pages
    {
        return Err(ExtentTreeError::Source);
    }

    Ok(LegacySqliteHeader {
        user_version: header[60..64].try_into().expect("SQLite header slice"),
    })
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    use zeroize::Zeroize;

    use super::super::{
        authenticate_legacy_source, crypto_error, sealed, LegacyEmptyAad, LegacyGcmAad,
        LegacyGeneration, LegacyRangeReceipt, LegacySourceIdentity, PinnedLegacyObject,
    };
    use super::*;
    use crate::crypto::Dek;

    struct FakeReader {
        bytes: Vec<u8>,
        identity: LegacySourceIdentity,
        generation: LegacyGeneration,
        fail_after_reads: Option<usize>,
        reads: usize,
    }

    impl FakeReader {
        fn new(bytes: Vec<u8>, identity: LegacySourceIdentity) -> Self {
            Self {
                bytes,
                identity,
                generation: LegacyGeneration::new(1).unwrap(),
                fail_after_reads: None,
                reads: 0,
            }
        }
    }

    impl sealed::RangeReader for FakeReader {}

    #[async_trait::async_trait]
    impl PinnedLegacyRangeReader for FakeReader {
        async fn pin_legacy_object(&mut self) -> crate::error::Result<PinnedLegacyObject> {
            Ok(PinnedLegacyObject::new(
                &self.identity,
                self.generation,
                self.bytes.len() as u64,
            ))
        }

        async fn read_pinned_exact(
            &mut self,
            object: &PinnedLegacyObject,
            offset: u64,
            destination: &mut [u8],
        ) -> crate::error::Result<LegacyRangeReceipt> {
            self.reads += 1;
            if self
                .fail_after_reads
                .is_some_and(|limit| self.reads > limit)
            {
                return Err(crypto_error("test range mutation"));
            }
            let start = usize::try_from(offset).map_err(|_| crypto_error("test offset"))?;
            let end = start
                .checked_add(destination.len())
                .ok_or_else(|| crypto_error("test range overflow"))?;
            if end > self.bytes.len() {
                return Err(crypto_error("test range unavailable"));
            }
            destination.copy_from_slice(&self.bytes[start..end]);
            Ok(LegacyRangeReceipt::new(
                object.clone(),
                offset,
                destination.len() as u64,
            ))
        }
    }

    fn dek() -> Dek {
        Dek([0; 32])
    }

    fn identity() -> LegacySourceIdentity {
        LegacySourceIdentity::new(b"legacy-sqlite-extent-test-source").unwrap()
    }

    fn envelope(plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&dek().0).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&[7; 12]),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .unwrap();
        let mut result = vec![7; 12];
        result.extend_from_slice(&encrypted);
        result
    }

    fn sqlite_plaintext(length: usize) -> Vec<u8> {
        assert!(length >= SQLITE_HEADER_BYTES);
        let mut plaintext = vec![0; length];
        plaintext[..16].copy_from_slice(SQLITE_MAGIC);
        plaintext[16..18].copy_from_slice(&(SQLITE_PAGE_SIZE as u16).to_be_bytes());
        plaintext[18] = 1;
        plaintext[19] = 1;
        plaintext[21..24].copy_from_slice(&[64, 32, 32]);
        let pages = u32::try_from(length / SQLITE_PAGE_SIZE as usize).unwrap();
        plaintext[24..28].copy_from_slice(&9u32.to_be_bytes());
        plaintext[28..32].copy_from_slice(&pages.to_be_bytes());
        plaintext[44..48].copy_from_slice(&4u32.to_be_bytes());
        plaintext[56..60].copy_from_slice(&1u32.to_be_bytes());
        plaintext[92..96].copy_from_slice(&9u32.to_be_bytes());
        plaintext
    }

    async fn legacy_source<'a>(
        reader: &'a mut FakeReader,
        identity: &LegacySourceIdentity,
    ) -> AuthenticatedLegacySource<'a, FakeReader> {
        authenticate_legacy_source(
            reader,
            &dek(),
            LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            identity,
        )
        .await
        .unwrap()
    }

    #[test]
    fn plaintext_length_is_bounded_before_any_pull() {
        for invalid in [
            0,
            u64::from(SQLITE_PAGE_SIZE) - 1,
            u64::from(SQLITE_PAGE_SIZE) + 1,
            MAX_DATABASE_BYTES + u64::from(SQLITE_PAGE_SIZE),
        ] {
            assert!(validate_plaintext_len(invalid).is_err());
        }
        assert!(validate_plaintext_len(u64::from(SQLITE_PAGE_SIZE)).is_ok());
        assert!(validate_plaintext_len(MAX_DATABASE_BYTES).is_ok());
    }

    #[tokio::test]
    async fn invalid_first_header_is_rejected_before_the_first_extent() {
        for mutation in 0..13 {
            let pages = if matches!(mutation, 11 | 12) { 2 } else { 1 };
            let mut plaintext = sqlite_plaintext(pages * SQLITE_PAGE_SIZE as usize);
            match mutation {
                0 => plaintext[0] ^= 1,
                1 => plaintext[16..18].copy_from_slice(&1024u16.to_be_bytes()),
                2 => plaintext[18] = 0,
                3 => plaintext[19] = 3,
                4 => plaintext[21] = 63,
                5 => plaintext[44..48].copy_from_slice(&5u32.to_be_bytes()),
                6 => plaintext[56..60].copy_from_slice(&4u32.to_be_bytes()),
                7 => plaintext[72] = 1,
                8 => plaintext[64..68].copy_from_slice(&1u32.to_be_bytes()),
                9 => plaintext[36..40].copy_from_slice(&1u32.to_be_bytes()),
                10 => plaintext[52..56].copy_from_slice(&2u32.to_be_bytes()),
                11 => {
                    plaintext[32..36].copy_from_slice(&1u32.to_be_bytes());
                    plaintext[36..40].copy_from_slice(&1u32.to_be_bytes());
                }
                12 => {
                    plaintext[32..36].copy_from_slice(&2u32.to_be_bytes());
                    plaintext[36..40].copy_from_slice(&2u32.to_be_bytes());
                }
                _ => unreachable!("fixed header mutation set"),
            }
            let identity = identity();
            let mut reader = FakeReader::new(envelope(&plaintext), identity.clone());
            let mut legacy = legacy_source(&mut reader, &identity).await;
            let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
            let mut output = vec![0; EXTENT_BYTES as usize];
            assert!(source.next_extent(&mut output).await.is_err());
            assert!(matches!(source.state, ExtentSourceState::Failed));
            assert!(matches!(source.source.state, LegacySourceState::Failed));
            assert!(output.iter().all(|byte| *byte == 0));
            assert!(source.next_extent(&mut output).await.is_err());
            output.zeroize();
        }
    }

    #[tokio::test]
    async fn extension_reserve_and_empty_schema_format_are_accepted() {
        for fixture in 0..2 {
            let mut plaintext = sqlite_plaintext(SQLITE_PAGE_SIZE as usize);
            match fixture {
                0 => plaintext[20] = u8::MAX,
                1 => plaintext[44..48].copy_from_slice(&0u32.to_be_bytes()),
                _ => unreachable!("fixed valid header fixture set"),
            }
            let identity = identity();
            let mut reader = FakeReader::new(envelope(&plaintext), identity.clone());
            let mut legacy = legacy_source(&mut reader, &identity).await;
            let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
            let mut output = vec![0; EXTENT_BYTES as usize];
            assert_eq!(
                source.next_extent(&mut output).await.unwrap(),
                Some(SourceExtent {
                    extent_no: 0,
                    logical_byte_len: SQLITE_PAGE_SIZE,
                })
            );
            output.zeroize();
        }
    }

    #[tokio::test]
    async fn coherent_page_count_must_match_but_stale_count_is_accepted() {
        let mut coherent_wrong = sqlite_plaintext(SQLITE_PAGE_SIZE as usize);
        coherent_wrong[28..32].copy_from_slice(&2u32.to_be_bytes());
        let coherent_identity = identity();
        let mut reader = FakeReader::new(envelope(&coherent_wrong), coherent_identity.clone());
        let mut legacy = legacy_source(&mut reader, &coherent_identity).await;
        let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
        let mut output = vec![0; EXTENT_BYTES as usize];
        assert!(source.next_extent(&mut output).await.is_err());
        output.zeroize();

        let mut stale = sqlite_plaintext(SQLITE_PAGE_SIZE as usize);
        stale[28..32].copy_from_slice(&2u32.to_be_bytes());
        stale[92..96].copy_from_slice(&10u32.to_be_bytes());
        let stale_identity = identity();
        let mut stale_reader = FakeReader::new(envelope(&stale), stale_identity.clone());
        let mut legacy = legacy_source(&mut stale_reader, &stale_identity).await;
        let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
        let mut output = vec![0; EXTENT_BYTES as usize];
        assert_eq!(
            source.next_extent(&mut output).await.unwrap(),
            Some(SourceExtent {
                extent_no: 0,
                logical_byte_len: SQLITE_PAGE_SIZE,
            })
        );
        output.zeroize();
    }

    #[tokio::test]
    async fn header_user_version_and_dense_extent_geometry_are_retained_privately() {
        let length = EXTENT_BYTES as usize + SQLITE_PAGE_SIZE as usize;
        let mut plaintext = sqlite_plaintext(length);
        plaintext[60..64].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        let identity = identity();
        let mut reader = FakeReader::new(envelope(&plaintext), identity.clone());
        let mut legacy = legacy_source(&mut reader, &identity).await;
        let mut output = vec![0; EXTENT_BYTES as usize];
        {
            let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
            assert_eq!(
                source.next_extent(&mut output).await.unwrap(),
                Some(SourceExtent {
                    extent_no: 0,
                    logical_byte_len: EXTENT_BYTES,
                })
            );
            assert_eq!(
                source.header().unwrap().user_version,
                0x1122_3344u32.to_be_bytes()
            );
            assert_eq!(
                source.next_extent(&mut output).await.unwrap(),
                Some(SourceExtent {
                    extent_no: 1,
                    logical_byte_len: SQLITE_PAGE_SIZE,
                })
            );
            assert_eq!(source.next_extent(&mut output).await.unwrap(), None);
        }
        output.zeroize();
        assert_eq!(legacy.finish().await.unwrap().plaintext_len, length as u64);
    }

    #[tokio::test]
    async fn one_full_extent_is_followed_by_one_eof() {
        let identity = identity();
        let plaintext = sqlite_plaintext(EXTENT_BYTES as usize);
        let mut reader = FakeReader::new(envelope(&plaintext), identity.clone());
        let mut legacy = legacy_source(&mut reader, &identity).await;
        let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
        let mut output = vec![0; EXTENT_BYTES as usize];
        assert_eq!(
            source.next_extent(&mut output).await.unwrap(),
            Some(SourceExtent {
                extent_no: 0,
                logical_byte_len: EXTENT_BYTES,
            })
        );
        assert_eq!(source.next_extent(&mut output).await.unwrap(), None);
        assert!(source.next_extent(&mut output).await.is_err());
        output.zeroize();
    }

    #[tokio::test]
    async fn scoped_adapter_leaves_parent_completion_for_later_coordinator() {
        let buffer_identity = identity();
        let plaintext = sqlite_plaintext(SQLITE_PAGE_SIZE as usize);
        let mut reader = FakeReader::new(envelope(&plaintext), buffer_identity.clone());
        let mut legacy = legacy_source(&mut reader, &buffer_identity).await;
        let pre_staging_binding = legacy.binding();
        {
            let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
            let mut output = vec![0; EXTENT_BYTES as usize];
            assert_eq!(
                source.next_extent(&mut output).await.unwrap(),
                Some(SourceExtent {
                    extent_no: 0,
                    logical_byte_len: SQLITE_PAGE_SIZE,
                })
            );
            assert_eq!(source.next_extent(&mut output).await.unwrap(), None);
            output.zeroize();
        }
        let completion = legacy.finish().await.unwrap();
        assert_eq!(
            completion.verify_binding(pre_staging_binding).unwrap(),
            pre_staging_binding
        );
    }

    #[tokio::test]
    async fn all_zero_extents_are_not_omitted() {
        let length = EXTENT_BYTES as usize + SQLITE_PAGE_SIZE as usize;
        let identity = identity();
        let plaintext = sqlite_plaintext(length);
        let mut reader = FakeReader::new(envelope(&plaintext), identity.clone());
        let mut legacy = legacy_source(&mut reader, &identity).await;
        let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
        let mut output = vec![0xa5; EXTENT_BYTES as usize];
        assert!(source.next_extent(&mut output).await.unwrap().is_some());
        assert_eq!(
            source.next_extent(&mut output).await.unwrap(),
            Some(SourceExtent {
                extent_no: 1,
                logical_byte_len: SQLITE_PAGE_SIZE,
            })
        );
        assert!(output.iter().all(|byte| *byte == 0));
        output.zeroize();
    }

    #[test]
    fn max_geometry_needs_no_maximum_database_allocation() {
        assert_eq!(
            MAX_DATABASE_BYTES / u64::from(EXTENT_BYTES),
            crate::archive_v3::MAX_DATABASE_EXTENT_SLOTS
        );
        assert_eq!(extent_len(MAX_DATABASE_BYTES, 0), Some(EXTENT_BYTES));
        assert_eq!(
            extent_len(
                MAX_DATABASE_BYTES,
                crate::archive_v3::MAX_DATABASE_EXTENT_SLOTS - 1
            ),
            Some(EXTENT_BYTES)
        );
        assert_eq!(
            extent_len(
                MAX_DATABASE_BYTES,
                crate::archive_v3::MAX_DATABASE_EXTENT_SLOTS
            ),
            None
        );
    }

    #[tokio::test]
    async fn source_error_and_buffer_misuse_are_terminal_without_completion() {
        let buffer_identity = identity();
        let plaintext = sqlite_plaintext(SQLITE_PAGE_SIZE as usize);
        let mut reader = FakeReader::new(envelope(&plaintext), buffer_identity.clone());
        let mut legacy = legacy_source(&mut reader, &buffer_identity).await;
        let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
        let mut wrong_buffer = vec![0xa5; EXTENT_BYTES as usize - 1];
        assert!(source.next_extent(&mut wrong_buffer).await.is_err());
        assert!(wrong_buffer.iter().all(|byte| *byte == 0));
        assert!(matches!(source.state, ExtentSourceState::Failed));
        assert!(matches!(source.source.state, LegacySourceState::Failed));
        wrong_buffer.zeroize();

        let fault_identity = identity();
        let plaintext = sqlite_plaintext(SQLITE_PAGE_SIZE as usize);
        let mut reader = FakeReader::new(envelope(&plaintext), fault_identity.clone());
        // First-pass authentication uses nonce, tag, then ciphertext; fail the
        // first second-pass range before provisional plaintext can escape.
        reader.fail_after_reads = Some(3);
        let mut legacy = legacy_source(&mut reader, &fault_identity).await;
        let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
        let mut output = vec![0; EXTENT_BYTES as usize];
        assert!(source.next_extent(&mut output).await.is_err());
        assert!(matches!(source.state, ExtentSourceState::Failed));
        assert!(matches!(source.source.state, LegacySourceState::Failed));
        output.zeroize();

        let mismatch_identity = identity();
        let plaintext = sqlite_plaintext(SQLITE_PAGE_SIZE as usize);
        let mut reader = FakeReader::new(envelope(&plaintext), mismatch_identity.clone());
        let mut legacy = legacy_source(&mut reader, &mismatch_identity).await;
        let mut source = LegacySqliteExtentSource::new(&mut legacy).unwrap();
        // This private fixture makes the parent underfill after it has
        // decrypted a nonzero prefix, exercising the adapter's local error
        // cleanup rather than a range-reader failure.
        source.source.ciphertext_len -= 1;
        let mut output = vec![0xa5; EXTENT_BYTES as usize];
        assert!(source.next_extent(&mut output).await.is_err());
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(matches!(source.state, ExtentSourceState::Failed));
        assert!(matches!(source.source.state, LegacySourceState::Failed));
        output.zeroize();
    }

    #[test]
    fn adapter_and_header_stay_private_and_cannot_finish_the_parent() {
        let source = include_str!("extent_candidate.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production adapter precedes its tests");
        for forbidden in [
            "pub struct LegacySqliteExtentSource",
            "pub(crate) struct LegacySqliteExtentSource",
            "pub(super) struct LegacySqliteExtentSource",
            "pub struct LegacySqliteHeader",
            "pub(crate) struct LegacySqliteHeader",
            "pub(super) struct LegacySqliteHeader",
            ".finish(",
            "verify_binding",
            "LegacyGcmCompletion",
        ] {
            assert!(
                !production.contains(forbidden),
                "private adapter gained {forbidden}"
            );
        }
    }
}
