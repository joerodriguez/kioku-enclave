#![allow(
    dead_code,
    reason = "inactive ADR-0022 export parity contract is compiled and fake-tested before authenticated walking and canonical-query parity exist"
)]

//! Inactive, fail-closed archive-v3 export parity seam.
//!
//! The live /api/export route remains the legacy Store export. Archive-v3
//! does not yet have (a) one complete authenticated checkpoint/WAL/extent
//! walker, (b) a cancellation-aware exact witness plus deletion-safe
//! publication admission, or (c) an admitted adapter for the live route's
//! canonical query, ordering, JSON, and content semantics. Those boundaries
//! are sealed here with implementations only in deterministic tests.
//!
//! This module has no Store, route, startup, environment, credential, logging,
//! or provider-I/O wiring. It accepts only an opaque ArchiveId and the exact
//! active witness record read for that archive. It never accepts user IDs,
//! prefixes, provider object names, discovery cursors, or list-all selectors.

use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use thiserror::Error;

use crate::{
    archive_v3::{ArchiveId, SQLITE_PAGE_SIZE},
    archive_v3_witness::{DeletionState, MigrationState, WitnessRecord},
};

pub const MAX_EXPORT_SNAPSHOT_BYTES: u64 = 32 * 1024 * 1024 * 1024;
pub const MAX_EXPORT_PAGES: u64 = MAX_EXPORT_SNAPSHOT_BYTES / SQLITE_PAGE_SIZE as u64;
pub const MAX_EXPORT_CURSOR_BYTES: usize = 256;
pub const MAX_EXPORT_SINK_CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_EXPORT_OUTPUT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_EXPORT_WRITE_OPERATIONS: u64 = 65_536;
pub const MAX_EXPORT_DEADLINE_TICKS: u32 = 600;
const FIXED_PAGE_BYTES: usize = SQLITE_PAGE_SIZE as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ArchiveV3ExportError {
    #[error("archive-v3 export is unavailable")]
    Unavailable,
    #[error("archive-v3 export request was rejected")]
    Rejected,
    #[error("archive-v3 export snapshot changed")]
    Unstable,
    #[error("archive-v3 export was cancelled or its sink failed")]
    Cancelled,
}

type Result<T> = std::result::Result<T, ArchiveV3ExportError>;

/// Bounded operation control passed into every potentially blocking witness,
/// source, canonical-adapter, sink, and publication boundary. Implementations
/// must apply the finite deadline budget to their own I/O and honor cancellation
/// internally. Outer checks do not claim to interrupt an implementation that
/// blocks without honoring this control.
pub(crate) struct ExportOperationControl {
    cancelled: AtomicBool,
    deadline_expired: AtomicBool,
    deadline_budget_ticks: u32,
}

impl ExportOperationControl {
    pub(crate) fn new(deadline_budget_ticks: u32) -> Result<Self> {
        if deadline_budget_ticks == 0 || deadline_budget_ticks > MAX_EXPORT_DEADLINE_TICKS {
            return Err(ArchiveV3ExportError::Rejected);
        }
        Ok(Self {
            cancelled: AtomicBool::new(false),
            deadline_expired: AtomicBool::new(false),
            deadline_budget_ticks,
        })
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn expire_deadline(&self) {
        self.deadline_expired.store(true, Ordering::Release);
    }

    pub(crate) const fn deadline_budget_ticks(&self) -> u32 {
        self.deadline_budget_ticks
    }

    fn is_stopped(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || self.deadline_expired.load(Ordering::Acquire)
    }

    fn check(&self) -> Result<()> {
        if self.is_stopped() {
            Err(ArchiveV3ExportError::Cancelled)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ExportOperationControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportOperationControl(<opaque>)")
    }
}

/// A fixed-capacity opaque continuation. The provider cannot return an
/// allocation before the caller checks the length. Sequence validation rejects
/// repeats and cycles without retaining an unbounded set of earlier cursors.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SnapshotCursor {
    sequence: u64,
    len: u16,
    token: [u8; MAX_EXPORT_CURSOR_BYTES],
}

impl SnapshotCursor {
    fn valid_for(&self, expected_sequence: u64) -> bool {
        self.sequence == expected_sequence
            && usize::from(self.len) <= MAX_EXPORT_CURSOR_BYTES
            && self.len != 0
    }
}

impl fmt::Debug for SnapshotCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SnapshotCursor(<opaque>)")
    }
}

#[cfg(test)]
impl SnapshotCursor {
    fn test_new(sequence: u64, token: &[u8]) -> Self {
        let mut fixed = [0u8; MAX_EXPORT_CURSOR_BYTES];
        let copied = token.len().min(MAX_EXPORT_CURSOR_BYTES);
        fixed[..copied].copy_from_slice(&token[..copied]);
        Self {
            sequence,
            len: token.len().min(usize::from(u16::MAX)) as u16,
            token: fixed,
        }
    }

    fn test_with_declared_len(sequence: u64, len: u16) -> Self {
        Self {
            sequence,
            len,
            token: [1u8; MAX_EXPORT_CURSOR_BYTES],
        }
    }

    fn test_sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SnapshotDescriptor {
    total_pages: u64,
}

#[cfg(test)]
impl SnapshotDescriptor {
    fn test_new(total_pages: u64) -> Self {
        Self { total_pages }
    }
}

/// Fixed metadata for one pull. Page bytes use caller-owned storage.
pub(crate) struct SnapshotPull {
    page_number: u64,
    bytes_written: u32,
    extent_count: u8,
    next_cursor: Option<SnapshotCursor>,
}

mod witness_seal {
    pub trait Sealed {}
}

/// Cancellation/deadline-aware witness boundary. No live adapter exists; the
/// ordinary witness trait is insufficient because outer polling cannot bound
/// or interrupt a blocked provider read.
pub(crate) trait ExactExportWitness: witness_seal::Sealed + Send + Sync {
    fn read_current(
        &self,
        archive_id: ArchiveId,
        control: &ExportOperationControl,
    ) -> std::result::Result<Option<WitnessRecord>, ()>;
}

mod source_seal {
    pub trait Sealed {}
}

/// Sealed blocker for the missing authenticated checkpoint/WAL/extent walker.
pub(crate) trait AuthenticatedArchiveSnapshotSource:
    source_seal::Sealed + Send + Sync
{
    fn open_exact(
        &self,
        archive_id: ArchiveId,
        expected: &WitnessRecord,
        control: &ExportOperationControl,
    ) -> std::result::Result<Box<dyn AuthenticatedArchiveSnapshot>, ()>;
}

pub(crate) trait AuthenticatedArchiveSnapshot: source_seal::Sealed + Send {
    fn descriptor(
        &self,
        control: &ExportOperationControl,
    ) -> std::result::Result<SnapshotDescriptor, ()>;

    fn pull_page(
        &mut self,
        cursor: Option<&SnapshotCursor>,
        destination: &mut [u8; FIXED_PAGE_BYTES],
        control: &ExportOperationControl,
    ) -> std::result::Result<SnapshotPull, ()>;
}

mod publication_seal {
    pub trait Sealed {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactPublicationError {
    Stale,
    Sink,
}

/// Deletion-aware exact-record admission. Acquisition atomically compares the
/// full active witness record and pins it. All witness transitions serialize
/// with active admissions; deletion closes new admissions and wins or drains
/// existing admissions before tombstoning.
pub(crate) trait ExactExportPublication: publication_seal::Sealed + Send + Sync {
    fn acquire_exact(
        &self,
        archive_id: ArchiveId,
        expected: &WitnessRecord,
        control: &ExportOperationControl,
    ) -> std::result::Result<Box<dyn ExactExportAdmission>, ()>;
}

/// Only a sealed admission can conditionally publish. If deletion closure
/// wins, commit fails while output remains abortable and unpublished.
pub(crate) trait ExactExportAdmission: publication_seal::Sealed + Send {
    fn commit_if_exact_active(
        &mut self,
        sink: &mut dyn ArchiveV3TransactionalExportSink,
        control: &ExportOperationControl,
    ) -> std::result::Result<(), ExactPublicationError>;
}

mod canonical_adapter_seal {
    pub trait Sealed {}
}

/// Sealed blocker for the live route's exact schema/query/content semantics.
pub(crate) trait CanonicalArchiveExportAdapter:
    canonical_adapter_seal::Sealed + Send
{
    fn encode(
        &mut self,
        pages: &mut dyn AuthenticatedExportPageReader,
        output: &mut dyn CanonicalExportOutput,
        control: &ExportOperationControl,
    ) -> Result<()>;
}

pub(crate) trait AuthenticatedExportPageReader {
    fn next_page(&mut self) -> Result<Option<&[u8]>>;
}

pub(crate) trait CanonicalExportOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
}

/// Trusted transactional output boundary. Begin and write implementations must
/// honor the finite control internally. Begin failure leaves no transaction;
/// writes remain invisible; abort discards them; failed commit stays abortable.
/// Only the sealed admission may invoke conditional commit. A dishonest sink
/// implementation is explicitly outside this code proof.
pub(crate) trait ArchiveV3TransactionalExportSink {
    fn begin(&mut self, control: &ExportOperationControl) -> std::result::Result<(), ()>;
    fn write_uncommitted(
        &mut self,
        bytes: &[u8],
        control: &ExportOperationControl,
    ) -> std::result::Result<(), ()>;
    fn commit_if_not_stopped(
        &mut self,
        control: &ExportOperationControl,
    ) -> std::result::Result<(), ()>;
    fn abort(&mut self);
}

/// Inactive, no-I/O composition.
pub(crate) struct ArchiveV3ExportSeam<'a> {
    witness: &'a dyn ExactExportWitness,
    source: &'a dyn AuthenticatedArchiveSnapshotSource,
    publication: &'a dyn ExactExportPublication,
}

impl<'a> ArchiveV3ExportSeam<'a> {
    pub(crate) fn new(
        witness: &'a dyn ExactExportWitness,
        source: &'a dyn AuthenticatedArchiveSnapshotSource,
        publication: &'a dyn ExactExportPublication,
    ) -> Self {
        Self {
            witness,
            source,
            publication,
        }
    }

    pub(crate) fn export(
        &self,
        archive_id: ArchiveId,
        adapter: &mut dyn CanonicalArchiveExportAdapter,
        sink: &mut dyn ArchiveV3TransactionalExportSink,
        control: &ExportOperationControl,
    ) -> Result<()> {
        let expected = self.read_start_record(archive_id, control)?;

        control.check()?;
        let admission_result = self
            .publication
            .acquire_exact(archive_id, &expected, control);
        control.check()?;
        let mut admission = admission_result.map_err(|_| ArchiveV3ExportError::Rejected)?;

        control.check()?;
        let snapshot_result = self.source.open_exact(archive_id, &expected, control);
        control.check()?;
        let mut snapshot = snapshot_result.map_err(|_| ArchiveV3ExportError::Unavailable)?;

        control.check()?;
        let descriptor_result = snapshot.descriptor(control);
        control.check()?;
        let descriptor = descriptor_result.map_err(|_| ArchiveV3ExportError::Unavailable)?;
        validate_descriptor(descriptor)?;
        let mut pages = BoundedPageReader::new(snapshot.as_mut(), descriptor, control);
        let mut transaction = TransactionGuard::begin(sink, control)?;

        let output_complete = {
            let mut output = BoundedTransactionalOutput::new(&mut transaction, control);
            control.check()?;
            let encode_result = adapter.encode(&mut pages, &mut output, control);
            control.check()?;
            encode_result?;
            output.is_complete()
        };
        if !pages.is_complete() || !output_complete {
            return Err(ArchiveV3ExportError::Rejected);
        }

        let final_record = self.read_final_record(archive_id, control)?;
        if final_record != expected {
            return Err(ArchiveV3ExportError::Unstable);
        }

        transaction.commit(admission.as_mut(), control)
    }

    fn read_start_record(
        &self,
        archive_id: ArchiveId,
        control: &ExportOperationControl,
    ) -> Result<WitnessRecord> {
        control.check()?;
        let read_result = self.witness.read_current(archive_id, control);
        control.check()?;
        let record = read_result
            .map_err(|_| ArchiveV3ExportError::Unavailable)?
            .ok_or(ArchiveV3ExportError::Rejected)?;
        if !active_exact_archive(&record, archive_id) {
            return Err(ArchiveV3ExportError::Rejected);
        }
        Ok(record)
    }

    fn read_final_record(
        &self,
        archive_id: ArchiveId,
        control: &ExportOperationControl,
    ) -> Result<WitnessRecord> {
        control.check()?;
        let read_result = self.witness.read_current(archive_id, control);
        control.check()?;
        let record = read_result
            .map_err(|_| ArchiveV3ExportError::Unavailable)?
            .ok_or(ArchiveV3ExportError::Unstable)?;
        if !active_exact_archive(&record, archive_id) {
            return Err(ArchiveV3ExportError::Unstable);
        }
        Ok(record)
    }
}

fn active_exact_archive(record: &WitnessRecord, archive_id: ArchiveId) -> bool {
    record.archive_id() == archive_id
        && record.deletion() == DeletionState::Active
        && !matches!(
            record.migration(),
            MigrationState::Deleting | MigrationState::Deleted
        )
}

fn validate_descriptor(descriptor: SnapshotDescriptor) -> Result<()> {
    let bytes = descriptor
        .total_pages
        .checked_mul(u64::from(SQLITE_PAGE_SIZE))
        .ok_or(ArchiveV3ExportError::Rejected)?;
    if descriptor.total_pages == 0
        || descriptor.total_pages > MAX_EXPORT_PAGES
        || bytes > MAX_EXPORT_SNAPSHOT_BYTES
    {
        return Err(ArchiveV3ExportError::Rejected);
    }
    Ok(())
}

struct BoundedPageReader<'a> {
    snapshot: &'a mut dyn AuthenticatedArchiveSnapshot,
    control: &'a ExportOperationControl,
    total_pages: u64,
    emitted_pages: u64,
    cursor: Option<SnapshotCursor>,
    terminal: bool,
    page: [u8; FIXED_PAGE_BYTES],
}

impl<'a> BoundedPageReader<'a> {
    fn new(
        snapshot: &'a mut dyn AuthenticatedArchiveSnapshot,
        descriptor: SnapshotDescriptor,
        control: &'a ExportOperationControl,
    ) -> Self {
        Self {
            snapshot,
            control,
            total_pages: descriptor.total_pages,
            emitted_pages: 0,
            cursor: None,
            terminal: false,
            page: [0u8; FIXED_PAGE_BYTES],
        }
    }

    fn is_complete(&self) -> bool {
        self.terminal && self.emitted_pages == self.total_pages
    }
}

impl AuthenticatedExportPageReader for BoundedPageReader<'_> {
    fn next_page(&mut self) -> Result<Option<&[u8]>> {
        if self.terminal {
            return if self.emitted_pages == self.total_pages {
                Ok(None)
            } else {
                Err(ArchiveV3ExportError::Rejected)
            };
        }
        if self.emitted_pages >= self.total_pages {
            return Err(ArchiveV3ExportError::Rejected);
        }
        if let Some(cursor) = &self.cursor {
            if !cursor.valid_for(self.emitted_pages) {
                return Err(ArchiveV3ExportError::Rejected);
            }
        }

        self.control.check()?;
        let pull_result =
            self.snapshot
                .pull_page(self.cursor.as_ref(), &mut self.page, self.control);
        self.control.check()?;
        let pulled = pull_result.map_err(|_| ArchiveV3ExportError::Unavailable)?;

        if pulled.extent_count != 1
            || pulled.page_number != self.emitted_pages
            || pulled.bytes_written != SQLITE_PAGE_SIZE
        {
            return Err(ArchiveV3ExportError::Rejected);
        }
        let next_emitted = self
            .emitted_pages
            .checked_add(1)
            .ok_or(ArchiveV3ExportError::Rejected)?;
        match &pulled.next_cursor {
            Some(cursor) => {
                if !cursor.valid_for(next_emitted) || next_emitted >= self.total_pages {
                    return Err(ArchiveV3ExportError::Rejected);
                }
            }
            None if next_emitted != self.total_pages => {
                return Err(ArchiveV3ExportError::Rejected);
            }
            None => {}
        }
        self.emitted_pages = next_emitted;
        self.terminal = pulled.next_cursor.is_none();
        self.cursor = pulled.next_cursor;
        Ok(Some(&self.page))
    }
}

struct TransactionGuard<'a> {
    sink: &'a mut dyn ArchiveV3TransactionalExportSink,
    active: bool,
}

impl<'a> TransactionGuard<'a> {
    fn begin(
        sink: &'a mut dyn ArchiveV3TransactionalExportSink,
        control: &ExportOperationControl,
    ) -> Result<Self> {
        control.check()?;
        sink.begin(control)
            .map_err(|_| ArchiveV3ExportError::Cancelled)?;
        let guard = Self { sink, active: true };
        control.check()?;
        Ok(guard)
    }

    fn write(&mut self, bytes: &[u8], control: &ExportOperationControl) -> Result<()> {
        control.check()?;
        let write_result = self.sink.write_uncommitted(bytes, control);
        control.check()?;
        write_result.map_err(|_| ArchiveV3ExportError::Cancelled)
    }

    fn commit(
        mut self,
        admission: &mut dyn ExactExportAdmission,
        control: &ExportOperationControl,
    ) -> Result<()> {
        control.check()?;
        let commit_result = admission.commit_if_exact_active(self.sink, control);
        match commit_result {
            Ok(()) => {
                let _stopped_after_commit = control.is_stopped();
                self.active = false;
                Ok(())
            }
            Err(error) => {
                control.check()?;
                Err(match error {
                    ExactPublicationError::Stale => ArchiveV3ExportError::Unstable,
                    ExactPublicationError::Sink => ArchiveV3ExportError::Cancelled,
                })
            }
        }
    }
}

impl Drop for TransactionGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            self.sink.abort();
            self.active = false;
        }
    }
}

struct BoundedTransactionalOutput<'a, 'b> {
    transaction: &'a mut TransactionGuard<'b>,
    control: &'a ExportOperationControl,
    written: u64,
    write_operations: u64,
}

impl<'a, 'b> BoundedTransactionalOutput<'a, 'b> {
    fn new(transaction: &'a mut TransactionGuard<'b>, control: &'a ExportOperationControl) -> Self {
        Self {
            transaction,
            control,
            written: 0,
            write_operations: 0,
        }
    }

    fn is_complete(&self) -> bool {
        self.written != 0
    }
}

impl CanonicalExportOutput for BoundedTransactionalOutput<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_EXPORT_SINK_CHUNK_BYTES {
            return Err(ArchiveV3ExportError::Rejected);
        }
        self.write_operations = self
            .write_operations
            .checked_add(1)
            .filter(|operations| *operations <= MAX_EXPORT_WRITE_OPERATIONS)
            .ok_or(ArchiveV3ExportError::Rejected)?;
        self.written = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|written| *written <= MAX_EXPORT_OUTPUT_BYTES)
            .ok_or(ArchiveV3ExportError::Rejected)?;
        self.transaction.write(bytes, self.control)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use super::*;
    use crate::{
        archive_v3::{DatabaseEpoch, KeyEpoch, ObjectId},
        archive_v3_witness::{
            InMemoryWitness, KeyRegistryReference, RootCommitment, RootReference, WitnessBootstrap,
        },
    };

    const REVIEWED_FAKE_EXPORT: &[u8] = b"reviewed-test-canonical-export";
    const TEST_DEADLINE_TICKS: u32 = 30;

    #[derive(Clone, Copy)]
    enum StopKind {
        Cancel,
        Deadline,
    }

    impl StopKind {
        fn stop(self, control: &ExportOperationControl) {
            match self {
                Self::Cancel => control.cancel(),
                Self::Deadline => control.expire_deadline(),
            }
        }
    }

    struct FakeWitness {
        records: Mutex<VecDeque<Option<WitnessRecord>>>,
        reads: AtomicUsize,
        controls: Arc<Mutex<Vec<u32>>>,
        stop_on_read: Option<(usize, StopKind)>,
    }

    impl FakeWitness {
        fn new(records: impl IntoIterator<Item = Option<WitnessRecord>>) -> Self {
            Self {
                records: Mutex::new(records.into_iter().collect()),
                reads: AtomicUsize::new(0),
                controls: Arc::new(Mutex::new(Vec::new())),
                stop_on_read: None,
            }
        }

        fn stopping_on_read(
            records: impl IntoIterator<Item = Option<WitnessRecord>>,
            read: usize,
            stop: StopKind,
        ) -> Self {
            Self {
                records: Mutex::new(records.into_iter().collect()),
                reads: AtomicUsize::new(0),
                controls: Arc::new(Mutex::new(Vec::new())),
                stop_on_read: Some((read, stop)),
            }
        }
    }

    impl witness_seal::Sealed for FakeWitness {}

    impl ExactExportWitness for FakeWitness {
        fn read_current(
            &self,
            _: ArchiveId,
            control: &ExportOperationControl,
        ) -> std::result::Result<Option<WitnessRecord>, ()> {
            self.controls
                .lock()
                .unwrap()
                .push(control.deadline_budget_ticks());
            let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            let record = self.records.lock().unwrap().pop_front().unwrap_or(None);
            if let Some((stop_read, stop)) = self.stop_on_read {
                if stop_read == read {
                    stop.stop(control);
                }
            }
            Ok(record)
        }
    }

    struct FakePull {
        page_number: u64,
        bytes_written: u32,
        extent_count: u8,
        fill: u8,
        next_cursor: Option<SnapshotCursor>,
    }

    impl FakePull {
        fn page(page_number: u64, next_cursor: Option<SnapshotCursor>) -> Self {
            Self {
                page_number,
                bytes_written: SQLITE_PAGE_SIZE,
                extent_count: 1,
                fill: page_number as u8,
                next_cursor,
            }
        }
    }

    type PullArguments = Arc<Mutex<Vec<(Option<u64>, u32)>>>;

    struct FakeSnapshot {
        descriptor: SnapshotDescriptor,
        pulls: VecDeque<FakePull>,
        arguments: PullArguments,
        stop_on_pull: Option<(usize, StopKind)>,
        pull_count: usize,
    }

    impl source_seal::Sealed for FakeSnapshot {}

    impl AuthenticatedArchiveSnapshot for FakeSnapshot {
        fn descriptor(
            &self,
            _control: &ExportOperationControl,
        ) -> std::result::Result<SnapshotDescriptor, ()> {
            Ok(self.descriptor)
        }

        fn pull_page(
            &mut self,
            cursor: Option<&SnapshotCursor>,
            destination: &mut [u8; FIXED_PAGE_BYTES],
            control: &ExportOperationControl,
        ) -> std::result::Result<SnapshotPull, ()> {
            self.arguments.lock().unwrap().push((
                cursor.map(SnapshotCursor::test_sequence),
                control.deadline_budget_ticks(),
            ));
            self.pull_count += 1;
            let pull = self.pulls.pop_front().ok_or(())?;
            let fill_len = usize::try_from(pull.bytes_written)
                .unwrap_or(usize::MAX)
                .min(destination.len());
            destination[..fill_len].fill(pull.fill);
            if let Some((stop_pull, stop)) = self.stop_on_pull {
                if stop_pull == self.pull_count {
                    stop.stop(control);
                }
            }
            Ok(SnapshotPull {
                page_number: pull.page_number,
                bytes_written: pull.bytes_written,
                extent_count: pull.extent_count,
                next_cursor: pull.next_cursor,
            })
        }
    }

    struct FakeSource {
        snapshots: Mutex<VecDeque<FakeSnapshot>>,
        opens: AtomicUsize,
        controls: Arc<Mutex<Vec<u32>>>,
        stop_on_open: Option<StopKind>,
    }

    impl FakeSource {
        fn new(snapshots: impl IntoIterator<Item = FakeSnapshot>) -> Self {
            Self {
                snapshots: Mutex::new(snapshots.into_iter().collect()),
                opens: AtomicUsize::new(0),
                controls: Arc::new(Mutex::new(Vec::new())),
                stop_on_open: None,
            }
        }
    }

    impl source_seal::Sealed for FakeSource {}

    impl AuthenticatedArchiveSnapshotSource for FakeSource {
        fn open_exact(
            &self,
            _: ArchiveId,
            _: &WitnessRecord,
            control: &ExportOperationControl,
        ) -> std::result::Result<Box<dyn AuthenticatedArchiveSnapshot>, ()> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.controls
                .lock()
                .unwrap()
                .push(control.deadline_budget_ticks());
            if let Some(stop) = self.stop_on_open {
                stop.stop(control);
            }
            self.snapshots
                .lock()
                .unwrap()
                .pop_front()
                .map(|snapshot| Box::new(snapshot) as Box<dyn AuthenticatedArchiveSnapshot>)
                .ok_or(())
        }
    }

    struct PublicationState {
        current: WitnessRecord,
        deletion_closing: bool,
        admissions: usize,
    }

    struct FakePublication {
        state: Arc<Mutex<PublicationState>>,
        acquisitions: AtomicUsize,
        controls: Arc<Mutex<Vec<u32>>>,
        close_at_commit: bool,
    }

    impl FakePublication {
        fn new(current: WitnessRecord) -> Self {
            Self {
                state: Arc::new(Mutex::new(PublicationState {
                    current,
                    deletion_closing: false,
                    admissions: 0,
                })),
                acquisitions: AtomicUsize::new(0),
                controls: Arc::new(Mutex::new(Vec::new())),
                close_at_commit: false,
            }
        }

        fn closing_at_commit(current: WitnessRecord) -> Self {
            let mut publication = Self::new(current);
            publication.close_at_commit = true;
            publication
        }
    }

    impl publication_seal::Sealed for FakePublication {}

    impl ExactExportPublication for FakePublication {
        fn acquire_exact(
            &self,
            archive_id: ArchiveId,
            expected: &WitnessRecord,
            control: &ExportOperationControl,
        ) -> std::result::Result<Box<dyn ExactExportAdmission>, ()> {
            self.acquisitions.fetch_add(1, Ordering::SeqCst);
            self.controls
                .lock()
                .unwrap()
                .push(control.deadline_budget_ticks());
            control.check().map_err(|_| ())?;
            let mut state = self.state.lock().unwrap();
            if state.deletion_closing
                || &state.current != expected
                || !active_exact_archive(&state.current, archive_id)
            {
                return Err(());
            }
            state.admissions += 1;
            drop(state);
            Ok(Box::new(FakeAdmission {
                state: self.state.clone(),
                expected: expected.clone(),
                close_at_commit: self.close_at_commit,
                released: false,
            }))
        }
    }

    struct FakeAdmission {
        state: Arc<Mutex<PublicationState>>,
        expected: WitnessRecord,
        close_at_commit: bool,
        released: bool,
    }

    impl publication_seal::Sealed for FakeAdmission {}

    impl ExactExportAdmission for FakeAdmission {
        fn commit_if_exact_active(
            &mut self,
            sink: &mut dyn ArchiveV3TransactionalExportSink,
            control: &ExportOperationControl,
        ) -> std::result::Result<(), ExactPublicationError> {
            control.check().map_err(|_| ExactPublicationError::Sink)?;
            let mut state = self.state.lock().unwrap();
            if self.close_at_commit {
                state.deletion_closing = true;
            }
            if state.deletion_closing
                || state.current != self.expected
                || !active_exact_archive(&state.current, self.expected.archive_id())
            {
                return Err(ExactPublicationError::Stale);
            }
            sink.commit_if_not_stopped(control)
                .map_err(|_| ExactPublicationError::Sink)?;
            let _stopped_after_commit = control.is_stopped();
            Ok(())
        }
    }

    impl Drop for FakeAdmission {
        fn drop(&mut self) {
            if !self.released {
                let mut state = self.state.lock().unwrap();
                state.admissions = state.admissions.saturating_sub(1);
                self.released = true;
            }
        }
    }

    struct ReviewedFakeCanonicalAdapter {
        stop_after_pages: Option<usize>,
        writes: u64,
        write_empty: bool,
        fail_after_first_write: bool,
        controls: Vec<u32>,
        stop_during_encode: Option<StopKind>,
    }

    impl ReviewedFakeCanonicalAdapter {
        fn complete() -> Self {
            Self {
                stop_after_pages: None,
                writes: 1,
                write_empty: false,
                fail_after_first_write: false,
                controls: Vec::new(),
                stop_during_encode: None,
            }
        }
    }

    impl canonical_adapter_seal::Sealed for ReviewedFakeCanonicalAdapter {}

    impl CanonicalArchiveExportAdapter for ReviewedFakeCanonicalAdapter {
        fn encode(
            &mut self,
            pages: &mut dyn AuthenticatedExportPageReader,
            output: &mut dyn CanonicalExportOutput,
            control: &ExportOperationControl,
        ) -> Result<()> {
            self.controls.push(control.deadline_budget_ticks());
            if let Some(stop) = self.stop_during_encode {
                stop.stop(control);
                control.check()?;
            }
            let mut consumed = 0usize;
            while pages.next_page()?.is_some() {
                consumed += 1;
                if self.stop_after_pages == Some(consumed) {
                    break;
                }
            }
            if self.write_empty {
                output.write(&[])?;
            }
            for write_index in 0..self.writes {
                output.write(REVIEWED_FAKE_EXPORT)?;
                if self.fail_after_first_write && write_index == 0 {
                    return Err(ArchiveV3ExportError::Cancelled);
                }
            }
            Ok(())
        }
    }

    struct FakeSink {
        begun: bool,
        pending: Vec<Vec<u8>>,
        committed: Vec<Vec<u8>>,
        aborts: usize,
        fail_write_after: Option<usize>,
        fail_commit: bool,
        begin_controls: Vec<u32>,
        write_controls: Vec<u32>,
        stop_during_begin: Option<StopKind>,
        stop_during_write: Option<StopKind>,
        stop_after_commit: Option<(Arc<ExportOperationControl>, StopKind)>,
    }

    impl FakeSink {
        fn new() -> Self {
            Self {
                begun: false,
                pending: Vec::new(),
                committed: Vec::new(),
                aborts: 0,
                fail_write_after: None,
                fail_commit: false,
                begin_controls: Vec::new(),
                write_controls: Vec::new(),
                stop_during_begin: None,
                stop_during_write: None,
                stop_after_commit: None,
            }
        }
    }

    impl ArchiveV3TransactionalExportSink for FakeSink {
        fn begin(&mut self, control: &ExportOperationControl) -> std::result::Result<(), ()> {
            self.begin_controls.push(control.deadline_budget_ticks());
            if self.begun {
                return Err(());
            }
            self.begun = true;
            if let Some(stop) = self.stop_during_begin {
                stop.stop(control);
            }
            Ok(())
        }

        fn write_uncommitted(
            &mut self,
            bytes: &[u8],
            control: &ExportOperationControl,
        ) -> std::result::Result<(), ()> {
            self.write_controls.push(control.deadline_budget_ticks());
            if self.fail_write_after == Some(self.pending.len()) {
                return Err(());
            }
            self.pending.push(bytes.to_vec());
            if let Some(stop) = self.stop_during_write {
                stop.stop(control);
            }
            Ok(())
        }

        fn commit_if_not_stopped(
            &mut self,
            control: &ExportOperationControl,
        ) -> std::result::Result<(), ()> {
            if control.is_stopped() || self.fail_commit {
                return Err(());
            }
            self.committed = std::mem::take(&mut self.pending);
            self.begun = false;
            if let Some((stopped, kind)) = &self.stop_after_commit {
                kind.stop(stopped);
            }
            Ok(())
        }

        fn abort(&mut self) {
            self.pending.clear();
            self.begun = false;
            self.aborts += 1;
        }
    }

    fn record(archive: ArchiveId, root_byte: u8, registry_byte: u8) -> WitnessRecord {
        let database = DatabaseEpoch::from_bytes([2; 16]);
        let key = KeyEpoch::from_bytes([3; 16]);
        let root = RootCommitment::genesis(
            database,
            key,
            RootReference::new(0, ObjectId::from_bytes([root_byte; 16]), [4; 32]),
        );
        let registry =
            KeyRegistryReference::new(key, 0, ObjectId::from_bytes([registry_byte; 16]), [5; 32]);
        InMemoryWitness::new()
            .bootstrap(WitnessBootstrap::new(archive, database, root, registry))
            .unwrap()
    }

    fn control() -> Arc<ExportOperationControl> {
        Arc::new(ExportOperationControl::new(TEST_DEADLINE_TICKS).unwrap())
    }

    fn cursor(sequence: u64) -> SnapshotCursor {
        SnapshotCursor::test_new(sequence, &[sequence as u8])
    }

    fn snapshot(
        total_pages: u64,
        pulls: impl IntoIterator<Item = FakePull>,
    ) -> (FakeSnapshot, PullArguments) {
        let arguments = Arc::new(Mutex::new(Vec::new()));
        (
            FakeSnapshot {
                descriptor: SnapshotDescriptor::test_new(total_pages),
                pulls: pulls.into_iter().collect(),
                arguments: arguments.clone(),
                stop_on_pull: None,
                pull_count: 0,
            },
            arguments,
        )
    }

    fn export_with(
        archive: ArchiveId,
        witness: &FakeWitness,
        source: &FakeSource,
        publication: &FakePublication,
        adapter: &mut ReviewedFakeCanonicalAdapter,
        sink: &mut FakeSink,
        control: &ExportOperationControl,
    ) -> Result<()> {
        ArchiveV3ExportSeam::new(witness, source, publication)
            .export(archive, adapter, sink, control)
    }

    #[test]
    fn constructor_performs_no_io() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        let witness = FakeWitness::new([Some(current.clone())]);
        let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
        let source = FakeSource::new([snapshot]);
        let publication = FakePublication::new(current);
        let _seam = ArchiveV3ExportSeam::new(&witness, &source, &publication);
        assert_eq!(source.opens.load(Ordering::SeqCst), 0);
        assert_eq!(witness.reads.load(Ordering::SeqCst), 0);
        assert_eq!(publication.acquisitions.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn deadline_budget_is_finite_and_nonzero() {
        assert!(matches!(
            ExportOperationControl::new(0),
            Err(ArchiveV3ExportError::Rejected)
        ));
        assert!(matches!(
            ExportOperationControl::new(MAX_EXPORT_DEADLINE_TICKS + 1),
            Err(ArchiveV3ExportError::Rejected)
        ));
        assert_eq!(
            ExportOperationControl::new(MAX_EXPORT_DEADLINE_TICKS)
                .unwrap()
                .deadline_budget_ticks(),
            MAX_EXPORT_DEADLINE_TICKS
        );
    }

    #[test]
    fn zero_page_snapshot_is_rejected() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        let witness = FakeWitness::new([Some(current.clone())]);
        let (snapshot, _) = snapshot(0, []);
        let source = FakeSource::new([snapshot]);
        let publication = FakePublication::new(current);
        let mut adapter = ReviewedFakeCanonicalAdapter::complete();
        let mut sink = FakeSink::new();
        let control = control();
        assert_eq!(
            export_with(
                archive,
                &witness,
                &source,
                &publication,
                &mut adapter,
                &mut sink,
                control.as_ref(),
            ),
            Err(ArchiveV3ExportError::Rejected)
        );
        assert!(!sink.begun);
        assert!(sink.committed.is_empty());
    }

    #[test]
    fn one_page_terminal_never_pulls_again_with_none() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        let witness = FakeWitness::new([Some(current.clone()), Some(current.clone())]);
        let (snapshot, arguments) = snapshot(1, [FakePull::page(0, None)]);
        let source = FakeSource::new([snapshot]);
        let publication = FakePublication::new(current);
        let mut adapter = ReviewedFakeCanonicalAdapter::complete();
        let mut sink = FakeSink::new();
        let control = control();

        assert_eq!(
            export_with(
                archive,
                &witness,
                &source,
                &publication,
                &mut adapter,
                &mut sink,
                control.as_ref(),
            ),
            Ok(())
        );
        assert_eq!(
            *arguments.lock().unwrap(),
            vec![(None, TEST_DEADLINE_TICKS)]
        );
        assert_eq!(sink.committed, vec![REVIEWED_FAKE_EXPORT.to_vec()]);
        assert_eq!(sink.aborts, 0);
        assert_eq!(adapter.controls, vec![TEST_DEADLINE_TICKS]);
        assert_eq!(sink.begin_controls, vec![TEST_DEADLINE_TICKS]);
        assert_eq!(sink.write_controls, vec![TEST_DEADLINE_TICKS]);
    }

    #[test]
    fn multi_page_terminal_uses_exact_cursor_arguments_and_stops() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        let witness = FakeWitness::new([Some(current.clone()), Some(current.clone())]);
        let (snapshot, arguments) = snapshot(
            3,
            [
                FakePull::page(0, Some(cursor(1))),
                FakePull::page(1, Some(cursor(2))),
                FakePull::page(2, None),
            ],
        );
        let source = FakeSource::new([snapshot]);
        let publication = FakePublication::new(current);
        let mut adapter = ReviewedFakeCanonicalAdapter::complete();
        let mut sink = FakeSink::new();
        let control = control();

        assert_eq!(
            export_with(
                archive,
                &witness,
                &source,
                &publication,
                &mut adapter,
                &mut sink,
                control.as_ref(),
            ),
            Ok(())
        );
        assert_eq!(
            *arguments.lock().unwrap(),
            vec![
                (None, TEST_DEADLINE_TICKS),
                (Some(1), TEST_DEADLINE_TICKS),
                (Some(2), TEST_DEADLINE_TICKS),
            ]
        );
    }

    #[test]
    fn early_terminal_and_incomplete_adapter_abort() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        for (pulls, stop_after) in [
            (vec![FakePull::page(0, None)], None),
            (
                vec![FakePull::page(0, Some(cursor(1))), FakePull::page(1, None)],
                Some(1),
            ),
        ] {
            let witness = FakeWitness::new([Some(current.clone())]);
            let (snapshot, _) = snapshot(2, pulls);
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = ReviewedFakeCanonicalAdapter {
                stop_after_pages: stop_after,
                ..ReviewedFakeCanonicalAdapter::complete()
            };
            let mut sink = FakeSink::new();
            let control = control();
            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Rejected)
            );
            assert!(sink.committed.is_empty());
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn tombstoned_deleting_or_deleted_before_start_never_opens_source() {
        let archive = ArchiveId::from_bytes([1; 16]);
        for rejected in [
            record(archive, 6, 7).with_deletion_for_test(DeletionState::Tombstoned),
            record(archive, 6, 7).with_migration_for_test(MigrationState::Deleting),
            record(archive, 6, 7).with_migration_for_test(MigrationState::Deleted),
        ] {
            let witness = FakeWitness::new([Some(rejected.clone())]);
            let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(rejected);
            let mut adapter = ReviewedFakeCanonicalAdapter::complete();
            let mut sink = FakeSink::new();
            let control = control();
            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Rejected)
            );
            assert_eq!(source.opens.load(Ordering::SeqCst), 0);
            assert_eq!(publication.acquisitions.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn final_witness_change_aborts_uncommitted_output() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        for changed in [
            current.with_deletion_for_test(DeletionState::Tombstoned),
            record(archive, 8, 7),
            record(archive, 6, 9),
        ] {
            let witness = FakeWitness::new([Some(current.clone()), Some(changed)]);
            let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = ReviewedFakeCanonicalAdapter::complete();
            let mut sink = FakeSink::new();
            let control = control();
            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Unstable)
            );
            assert!(sink.pending.is_empty());
            assert!(sink.committed.is_empty());
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn concurrent_tombstone_closure_at_commit_prevents_publication() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        let witness = FakeWitness::new([Some(current.clone()), Some(current.clone())]);
        let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
        let source = FakeSource::new([snapshot]);
        let publication = FakePublication::closing_at_commit(current);
        let mut adapter = ReviewedFakeCanonicalAdapter::complete();
        let mut sink = FakeSink::new();
        let control = control();

        assert_eq!(
            export_with(
                archive,
                &witness,
                &source,
                &publication,
                &mut adapter,
                &mut sink,
                control.as_ref(),
            ),
            Err(ArchiveV3ExportError::Unstable)
        );
        let mut state = publication.state.lock().unwrap();
        assert!(state.deletion_closing);
        assert_eq!(state.admissions, 0);
        let tombstoned = state
            .current
            .with_deletion_for_test(DeletionState::Tombstoned);
        state.current = tombstoned;
        assert_eq!(state.current.deletion(), DeletionState::Tombstoned);
        assert!(sink.pending.is_empty());
        assert!(sink.committed.is_empty());
        assert_eq!(sink.aborts, 1);
    }

    #[test]
    fn page_total_and_cursor_bounds_reject_before_use() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        let cases = [
            snapshot(MAX_EXPORT_PAGES + 1, []).0,
            snapshot(
                1,
                [FakePull {
                    page_number: 1,
                    ..FakePull::page(0, None)
                }],
            )
            .0,
            snapshot(
                1,
                [FakePull {
                    bytes_written: 1,
                    ..FakePull::page(0, None)
                }],
            )
            .0,
            snapshot(
                1,
                [FakePull {
                    extent_count: 2,
                    ..FakePull::page(0, None)
                }],
            )
            .0,
            snapshot(
                2,
                [FakePull::page(
                    0,
                    Some(SnapshotCursor::test_with_declared_len(
                        1,
                        (MAX_EXPORT_CURSOR_BYTES + 1) as u16,
                    )),
                )],
            )
            .0,
            snapshot(
                2,
                [
                    FakePull::page(0, Some(cursor(1))),
                    FakePull::page(1, Some(cursor(1))),
                ],
            )
            .0,
        ];

        for bad_snapshot in cases {
            let witness = FakeWitness::new([Some(current.clone())]);
            let source = FakeSource::new([bad_snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = ReviewedFakeCanonicalAdapter::complete();
            let mut sink = FakeSink::new();
            let control = control();
            assert!(matches!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Rejected)
            ));
            assert!(sink.committed.is_empty());
        }
    }

    #[test]
    fn cancellation_and_deadline_are_passed_into_blocking_boundaries() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        for stop in [StopKind::Cancel, StopKind::Deadline] {
            let witness = FakeWitness::new([Some(current.clone())]);
            let (mut snapshot, arguments) = snapshot(1, [FakePull::page(0, None)]);
            snapshot.stop_on_pull = Some((1, stop));
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = ReviewedFakeCanonicalAdapter::complete();
            let mut sink = FakeSink::new();
            let control = control();
            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Cancelled)
            );
            assert_eq!(*witness.controls.lock().unwrap(), vec![TEST_DEADLINE_TICKS]);
            assert_eq!(*source.controls.lock().unwrap(), vec![TEST_DEADLINE_TICKS]);
            assert_eq!(
                *publication.controls.lock().unwrap(),
                vec![TEST_DEADLINE_TICKS]
            );
            assert_eq!(
                *arguments.lock().unwrap(),
                vec![(None, TEST_DEADLINE_TICKS)]
            );
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn deadline_expiring_inside_source_open_stops_before_transaction() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        let witness = FakeWitness::new([Some(current.clone())]);
        let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
        let mut source = FakeSource::new([snapshot]);
        source.stop_on_open = Some(StopKind::Deadline);
        let publication = FakePublication::new(current);
        let mut adapter = ReviewedFakeCanonicalAdapter::complete();
        let mut sink = FakeSink::new();
        let control = control();

        assert_eq!(
            export_with(
                archive,
                &witness,
                &source,
                &publication,
                &mut adapter,
                &mut sink,
                control.as_ref(),
            ),
            Err(ArchiveV3ExportError::Cancelled)
        );
        assert_eq!(*source.controls.lock().unwrap(), vec![TEST_DEADLINE_TICKS]);
        assert!(!sink.begun);
        assert!(sink.committed.is_empty());
    }

    #[test]
    fn cancellation_or_deadline_after_final_witness_read_aborts_output() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        for stop in [StopKind::Cancel, StopKind::Deadline] {
            let witness = FakeWitness::stopping_on_read(
                [Some(current.clone()), Some(current.clone())],
                2,
                stop,
            );
            let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = ReviewedFakeCanonicalAdapter::complete();
            let mut sink = FakeSink::new();
            let control = control();
            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Cancelled)
            );
            assert!(sink.pending.is_empty());
            assert!(sink.committed.is_empty());
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn cancellation_and_deadline_are_honored_inside_adapter() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        for stop in [StopKind::Cancel, StopKind::Deadline] {
            let witness = FakeWitness::new([Some(current.clone())]);
            let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = ReviewedFakeCanonicalAdapter {
                stop_during_encode: Some(stop),
                ..ReviewedFakeCanonicalAdapter::complete()
            };
            let mut sink = FakeSink::new();
            let control = control();

            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Cancelled)
            );
            assert_eq!(adapter.controls, vec![TEST_DEADLINE_TICKS]);
            assert_eq!(sink.begin_controls, vec![TEST_DEADLINE_TICKS]);
            assert!(sink.write_controls.is_empty());
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn cancellation_and_deadline_are_honored_inside_sink_begin() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        for stop in [StopKind::Cancel, StopKind::Deadline] {
            let witness = FakeWitness::new([Some(current.clone())]);
            let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = ReviewedFakeCanonicalAdapter::complete();
            let mut sink = FakeSink::new();
            sink.stop_during_begin = Some(stop);
            let control = control();

            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Cancelled)
            );
            assert_eq!(sink.begin_controls, vec![TEST_DEADLINE_TICKS]);
            assert!(adapter.controls.is_empty());
            assert!(sink.write_controls.is_empty());
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn fully_consumed_zero_total_output_is_rejected_before_final_witness() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        let witness = FakeWitness::new([Some(current.clone())]);
        let (snapshot, arguments) = snapshot(1, [FakePull::page(0, None)]);
        let source = FakeSource::new([snapshot]);
        let publication = FakePublication::new(current);
        let mut adapter = ReviewedFakeCanonicalAdapter {
            writes: 0,
            write_empty: false,
            ..ReviewedFakeCanonicalAdapter::complete()
        };
        let mut sink = FakeSink::new();
        let control = control();

        assert_eq!(
            export_with(
                archive,
                &witness,
                &source,
                &publication,
                &mut adapter,
                &mut sink,
                control.as_ref(),
            ),
            Err(ArchiveV3ExportError::Rejected)
        );
        assert_eq!(witness.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            *arguments.lock().unwrap(),
            vec![(None, TEST_DEADLINE_TICKS)]
        );
        assert_eq!(adapter.controls, vec![TEST_DEADLINE_TICKS]);
        assert_eq!(sink.begin_controls, vec![TEST_DEADLINE_TICKS]);
        assert!(sink.write_controls.is_empty());
        assert!(sink.pending.is_empty());
        assert!(sink.committed.is_empty());
        assert_eq!(sink.aborts, 1);
    }

    #[test]
    fn empty_output_and_write_operation_overflow_are_rejected() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        for adapter in [
            ReviewedFakeCanonicalAdapter {
                write_empty: true,
                ..ReviewedFakeCanonicalAdapter::complete()
            },
            ReviewedFakeCanonicalAdapter {
                writes: MAX_EXPORT_WRITE_OPERATIONS + 1,
                ..ReviewedFakeCanonicalAdapter::complete()
            },
        ] {
            let witness = FakeWitness::new([Some(current.clone())]);
            let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = adapter;
            let mut sink = FakeSink::new();
            let control = control();
            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Rejected)
            );
            assert!(sink.pending.is_empty());
            assert!(sink.committed.is_empty());
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn partial_write_adapter_and_commit_failures_abort() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        for (fail_write_after, fail_adapter, fail_commit) in [
            (Some(1), false, false),
            (None, true, false),
            (None, false, true),
        ] {
            let witness = FakeWitness::new([Some(current.clone()), Some(current.clone())]);
            let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = ReviewedFakeCanonicalAdapter {
                writes: 2,
                fail_after_first_write: fail_adapter,
                ..ReviewedFakeCanonicalAdapter::complete()
            };
            let mut sink = FakeSink::new();
            sink.fail_write_after = fail_write_after;
            sink.fail_commit = fail_commit;
            let control = control();
            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Cancelled)
            );
            assert!(sink.pending.is_empty());
            assert!(sink.committed.is_empty());
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn cancellation_and_deadline_are_honored_inside_output_write() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        for stop in [StopKind::Cancel, StopKind::Deadline] {
            let witness = FakeWitness::new([Some(current.clone())]);
            let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
            let source = FakeSource::new([snapshot]);
            let publication = FakePublication::new(current.clone());
            let mut adapter = ReviewedFakeCanonicalAdapter::complete();
            let control = control();
            let mut sink = FakeSink::new();
            sink.stop_during_write = Some(stop);

            assert_eq!(
                export_with(
                    archive,
                    &witness,
                    &source,
                    &publication,
                    &mut adapter,
                    &mut sink,
                    control.as_ref(),
                ),
                Err(ArchiveV3ExportError::Cancelled)
            );
            assert_eq!(adapter.controls, vec![TEST_DEADLINE_TICKS]);
            assert_eq!(sink.begin_controls, vec![TEST_DEADLINE_TICKS]);
            assert_eq!(sink.write_controls, vec![TEST_DEADLINE_TICKS]);
            assert!(sink.pending.is_empty());
            assert!(sink.committed.is_empty());
            assert_eq!(sink.aborts, 1);
        }
    }

    #[test]
    fn stop_racing_after_atomic_conditional_commit_does_not_revoke_success() {
        let archive = ArchiveId::from_bytes([1; 16]);
        let current = record(archive, 6, 7);
        let witness = FakeWitness::new([Some(current.clone()), Some(current.clone())]);
        let (snapshot, _) = snapshot(1, [FakePull::page(0, None)]);
        let source = FakeSource::new([snapshot]);
        let publication = FakePublication::new(current);
        let mut adapter = ReviewedFakeCanonicalAdapter::complete();
        let control = control();
        let mut sink = FakeSink::new();
        sink.stop_after_commit = Some((control.clone(), StopKind::Deadline));

        assert_eq!(
            export_with(
                archive,
                &witness,
                &source,
                &publication,
                &mut adapter,
                &mut sink,
                control.as_ref(),
            ),
            Ok(())
        );
        assert_eq!(sink.committed, vec![REVIEWED_FAKE_EXPORT.to_vec()]);
        assert_eq!(sink.aborts, 0);
    }
}
