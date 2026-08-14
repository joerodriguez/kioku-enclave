#![allow(
    dead_code,
    reason = "inactive ADR-0022 logical-write gate is compiled before a WAL publication owner exists"
)]

//! Inactive, fail-closed logical-operation idempotency gate for a future
//! archive-v3 WAL writer.
//!
//! Any future replay rows are permanent within their exact owning operation
//! domain. A caller cannot use a universal receipt table: it must hold a
//! module-sealed domain plan whose distinct, bounded ledger fixes the request
//! fingerprint, indexed resolver, and exact replay-result policy. Only a
//! bounded test exemplar implements that contract in this slice. This module
//! performs only local SQLite transactions. It has no Store connection,
//! publisher, capture, root, witness, provider, route, worker, or startup path.
//!
//! The future owner order is deliberately documented but not implemented:
//! derive stable ID/fingerprint before actor admission; reconcile any pending
//! attempt; enter `BEGIN IMMEDIATE`; resolve-or-apply the domain mutation and
//! exact result atomically; capture the same ID/fingerprint; publish and exact-
//! read back immutable objects; CAS/reconcile the witness; settle publication;
//! only then expose the retained result. Cancellation after a local commit but
//! before settlement must poison that actor until durable reconciliation.

use rusqlite::{Connection, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{fmt, sync::atomic::AtomicBool};
use thiserror::Error;
use zeroize::Zeroizing;

const WAL_IDEMPOTENCY_FORMAT_V1: u16 = 1;
const REQUEST_FINGERPRINT_DOMAIN: &[u8] = b"kioku/archive-v3/wal-logical-request-fingerprint/v1\0";
const REPLAY_RESULT_DOMAIN: &[u8] = b"kioku/archive-v3/wal-logical-replay-result/v1\0";
const MAX_CANONICAL_WAL_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_CANONICAL_REPLAY_RESULT_BYTES: usize = 4096;
const MAX_ENCODED_REPLAY_RESULT_BYTES: usize = MAX_CANONICAL_REPLAY_RESULT_BYTES + 9;
const RESULT_UNIT: u8 = 1;
const RESULT_CANONICAL_RESPONSE: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum WalIdempotencyError {
    #[error("WAL logical operation input is malformed")]
    Malformed,
    #[error("WAL logical operation exceeded a fixed bound")]
    Limit,
    #[error("WAL logical operation state is corrupt or unsupported")]
    Corrupt,
    #[error("WAL logical operation ID was reused for a different request")]
    FingerprintConflict,
    #[error("WAL logical operation domain rejected the replay result")]
    ResultUnsupported,
    #[error("WAL logical operation transaction is unavailable")]
    Unavailable,
}

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// Stable portable domains approved for future conversion. Attempt counters,
/// wall-clock retry bookkeeping, auto-ID creation, arbitrary SQL, purge, and
/// account deletion deliberately have no variant and remain disabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub(crate) enum WalOperationKind {
    MediaCaptureEvent = 1,
    CaptureSessionFinish = 2,
    SelectedScreenshot = 3,
    FinalizationQueue = 4,
    FinalizationCommit = 5,
    DeterministicMediaWorkResult = 6,
    VertexUsage = 7,
    WebhookDelivery = 8,
    EmailDelivery = 9,
    PushDelivery = 10,
    Retention = 11,
    ReviewerBackfill = 12,
}

impl WalOperationKind {
    fn decode(value: i64) -> Result<Self> {
        match value {
            1 => Ok(Self::MediaCaptureEvent),
            2 => Ok(Self::CaptureSessionFinish),
            3 => Ok(Self::SelectedScreenshot),
            4 => Ok(Self::FinalizationQueue),
            5 => Ok(Self::FinalizationCommit),
            6 => Ok(Self::DeterministicMediaWorkResult),
            7 => Ok(Self::VertexUsage),
            8 => Ok(Self::WebhookDelivery),
            9 => Ok(Self::EmailDelivery),
            10 => Ok(Self::PushDelivery),
            11 => Ok(Self::Retention),
            12 => Ok(Self::ReviewerBackfill),
            _ => Err(WalIdempotencyError::Corrupt),
        }
    }

    const fn codec_version(self) -> u16 {
        match self {
            Self::MediaCaptureEvent
            | Self::CaptureSessionFinish
            | Self::SelectedScreenshot
            | Self::FinalizationQueue
            | Self::FinalizationCommit
            | Self::DeterministicMediaWorkResult
            | Self::VertexUsage
            | Self::WebhookDelivery
            | Self::EmailDelivery
            | Self::PushDelivery
            | Self::Retention
            | Self::ReviewerBackfill => 1,
        }
    }

    const fn permits_canonical_response(self) -> bool {
        matches!(
            self,
            Self::MediaCaptureEvent | Self::CaptureSessionFinish | Self::SelectedScreenshot
        )
    }
}

/// Nonzero stable ID supplied by the portable domain, never allocated after a
/// mutation begins.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WalLogicalOperationId([u8; 16]);

impl WalLogicalOperationId {
    pub(crate) fn from_bytes(value: [u8; 16]) -> Result<Self> {
        value
            .iter()
            .any(|byte| *byte != 0)
            .then_some(Self(value))
            .ok_or(WalIdempotencyError::Malformed)
    }

    const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for WalLogicalOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalLogicalOperationId(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalRequestFingerprint([u8; 32]);

impl WalRequestFingerprint {
    fn derive(kind: WalOperationKind, canonical_request: &[u8]) -> Result<Self> {
        if canonical_request.is_empty() {
            return Err(WalIdempotencyError::Malformed);
        }
        if canonical_request.len() > MAX_CANONICAL_WAL_REQUEST_BYTES {
            return Err(WalIdempotencyError::Limit);
        }
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_FINGERPRINT_DOMAIN);
        hasher.update(WAL_IDEMPOTENCY_FORMAT_V1.to_be_bytes());
        hasher.update((kind as u16).to_be_bytes());
        hasher.update(kind.codec_version().to_be_bytes());
        hasher.update((canonical_request.len() as u32).to_be_bytes());
        hasher.update(canonical_request);
        let fingerprint: [u8; 32] = hasher.finalize().into();
        if fingerprint == [0; 32] {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(Self(fingerprint))
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for WalRequestFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalRequestFingerprint(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
enum WalReplayResult {
    UnitApplied,
    CanonicalResponse(Zeroizing<Vec<u8>>),
}

impl WalReplayResult {
    fn unit() -> Self {
        Self::UnitApplied
    }

    fn canonical_response(kind: WalOperationKind, bytes: Vec<u8>) -> Result<Self> {
        if !kind.permits_canonical_response() {
            return Err(WalIdempotencyError::ResultUnsupported);
        }
        if bytes.is_empty() {
            return Err(WalIdempotencyError::Malformed);
        }
        if bytes.len() > MAX_CANONICAL_REPLAY_RESULT_BYTES {
            return Err(WalIdempotencyError::Limit);
        }
        Ok(Self::CanonicalResponse(Zeroizing::new(bytes)))
    }

    fn encode(&self, kind: WalOperationKind) -> Result<Zeroizing<Vec<u8>>> {
        let mut encoded = Zeroizing::new(Vec::new());
        encoded.extend_from_slice(&WAL_IDEMPOTENCY_FORMAT_V1.to_be_bytes());
        encoded.extend_from_slice(&(kind as u16).to_be_bytes());
        match self {
            Self::UnitApplied => {
                encoded.push(RESULT_UNIT);
                encoded.extend_from_slice(&0u32.to_be_bytes());
            }
            Self::CanonicalResponse(bytes) => {
                if !kind.permits_canonical_response() || bytes.is_empty() {
                    return Err(WalIdempotencyError::ResultUnsupported);
                }
                if bytes.len() > MAX_CANONICAL_REPLAY_RESULT_BYTES {
                    return Err(WalIdempotencyError::Limit);
                }
                encoded.push(RESULT_CANONICAL_RESPONSE);
                encoded.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                encoded.extend_from_slice(bytes);
            }
        }
        Ok(encoded)
    }

    fn decode(kind: WalOperationKind, encoded: &[u8]) -> Result<Self> {
        if encoded.len() < 9 || encoded.len() > MAX_CANONICAL_REPLAY_RESULT_BYTES + 9 {
            return Err(WalIdempotencyError::Corrupt);
        }
        let version = u16::from_be_bytes([encoded[0], encoded[1]]);
        let stored_kind = u16::from_be_bytes([encoded[2], encoded[3]]);
        let length = u32::from_be_bytes([encoded[5], encoded[6], encoded[7], encoded[8]]) as usize;
        if version != WAL_IDEMPOTENCY_FORMAT_V1
            || stored_kind != kind as u16
            || encoded.len() != 9 + length
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        match encoded[4] {
            RESULT_UNIT if length == 0 => Ok(Self::UnitApplied),
            RESULT_CANONICAL_RESPONSE
                if kind.permits_canonical_response()
                    && (1..=MAX_CANONICAL_REPLAY_RESULT_BYTES).contains(&length) =>
            {
                Ok(Self::CanonicalResponse(Zeroizing::new(
                    encoded[9..].to_vec(),
                )))
            }
            _ => Err(WalIdempotencyError::ResultUnsupported),
        }
    }

    fn commitment(&self, kind: WalOperationKind) -> Result<[u8; 32]> {
        let encoded = self.encode(kind)?;
        let mut hasher = Sha256::new();
        hasher.update(REPLAY_RESULT_DOMAIN);
        hasher.update((encoded.len() as u32).to_be_bytes());
        hasher.update(encoded.as_slice());
        let commitment: [u8; 32] = hasher.finalize().into();
        Ok(commitment)
    }
}

impl fmt::Debug for WalReplayResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnitApplied => formatter.write_str("WalReplayResult::UnitApplied"),
            Self::CanonicalResponse(bytes) => formatter
                .debug_tuple("WalReplayResult::CanonicalResponse")
                .field(&format_args!("<redacted:{} bytes>", bytes.len()))
                .finish(),
        }
    }
}

mod sealed {
    pub trait DomainLedger {}
    pub trait DomainPlan {}
}

/// Each supported domain owns request canonicalization, mutation SQL, and
/// exact replay validation. No generic closure or arbitrary SQL reaches the
/// permanent ledger surface.
trait WalLogicalDomainPlan: sealed::DomainPlan + Send + Sized {
    type Ledger: WalLogicalDomainLedger<Self>;

    fn kind(&self) -> WalOperationKind;
    fn operation_id(&self) -> WalLogicalOperationId;
    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>>;
    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult>;
    fn validate_replay(&self, result: &WalReplayResult) -> Result<()>;
}

/// Every portable domain owns a distinct, permanently retained, bounded row
/// family and its exact indexed resolver. The shared gate deliberately has no
/// universal table or table-name selector.
trait WalLogicalDomainLedger<P: WalLogicalDomainPlan>: sealed::DomainLedger + Send {
    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<P>,
    ) -> Result<LogicalMutationDisposition>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DomainLedgerBounds {
    max_rows: u32,
    max_result_bytes: u64,
}

impl DomainLedgerBounds {
    const fn new(max_rows: u32, max_result_bytes: u64) -> Self {
        Self {
            max_rows,
            max_result_bytes,
        }
    }

    fn admit(self, rows: u32, result_bytes: u64, next_result_bytes: usize) -> Result<()> {
        let next_result_bytes =
            u64::try_from(next_result_bytes).map_err(|_| WalIdempotencyError::Limit)?;
        if self.max_rows == 0
            || self.max_result_bytes == 0
            || rows >= self.max_rows
            || result_bytes
                .checked_add(next_result_bytes)
                .is_none_or(|total| total > self.max_result_bytes)
        {
            return Err(WalIdempotencyError::Limit);
        }
        Ok(())
    }
}

/// Opaque plan produced before actor entry. Only this module's future owner
/// may consume it; callers cannot obtain its ID, fingerprint, SQL, or result.
struct PreparedLogicalMutation<P: WalLogicalDomainPlan> {
    plan: P,
    operation_id: WalLogicalOperationId,
    request_fingerprint: WalRequestFingerprint,
}

impl<P: WalLogicalDomainPlan> PreparedLogicalMutation<P> {
    fn prepare(plan: P) -> Result<Self> {
        let operation_id = plan.operation_id();
        let canonical_request = plan.canonical_request()?;
        let request_fingerprint = WalRequestFingerprint::derive(plan.kind(), &canonical_request)?;
        Ok(Self {
            plan,
            operation_id,
            request_fingerprint,
        })
    }
}

impl<P: WalLogicalDomainPlan> fmt::Debug for PreparedLogicalMutation<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedLogicalMutation(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogicalMutationDisposition {
    Applied,
    Replayed,
}

fn execute_prepared<P: WalLogicalDomainPlan>(
    connection: &mut Connection,
    prepared: PreparedLogicalMutation<P>,
) -> Result<LogicalMutationDisposition> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let disposition = P::Ledger::resolve_or_apply(&transaction, &prepared)?;
    transaction
        .commit()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    Ok(disposition)
}

/// Process-local cancellation guard for the future actor owner. Dropping a
/// pre-commit attempt is harmless; dropping after local commit and before
/// durable publication settlement poisons the actor. This has no publisher or
/// authority transition.
struct LocalMutationCancellationGuard<'a> {
    actor_poisoned: &'a AtomicBool,
    local_committed: bool,
    settled: bool,
}

impl<'a> LocalMutationCancellationGuard<'a> {
    fn new(actor_poisoned: &'a AtomicBool) -> Self {
        Self {
            actor_poisoned,
            local_committed: false,
            settled: false,
        }
    }

    fn mark_local_committed(&mut self) {
        self.local_committed = true;
    }

    fn mark_settled(&mut self) {
        self.settled = true;
    }
}

impl Drop for LocalMutationCancellationGuard<'_> {
    fn drop(&mut self) {
        if self.local_committed && !self.settled {
            self.actor_poisoned
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, OptionalExtension};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    };
    use std::time::Duration;

    #[derive(Clone)]
    struct TestDomain {
        kind: WalOperationKind,
        id: WalLogicalOperationId,
        request: Vec<u8>,
        result: WalReplayResult,
        apply_count: Arc<AtomicUsize>,
        lookup_count: Arc<AtomicUsize>,
        fail_after_sql: bool,
    }

    struct TestMediaCaptureLedger;

    impl sealed::DomainPlan for TestDomain {}
    impl sealed::DomainLedger for TestMediaCaptureLedger {}

    const TEST_LEDGER_BOUNDS: DomainLedgerBounds =
        DomainLedgerBounds::new(64, (64 * MAX_ENCODED_REPLAY_RESULT_BYTES) as u64);

    impl WalLogicalDomainLedger<TestDomain> for TestMediaCaptureLedger {
        fn resolve_or_apply(
            transaction: &Transaction<'_>,
            prepared: &PreparedLogicalMutation<TestDomain>,
        ) -> Result<LogicalMutationDisposition> {
            if prepared.plan.kind() != WalOperationKind::MediaCaptureEvent {
                return Err(WalIdempotencyError::ResultUnsupported);
            }
            prepared.plan.lookup_count.fetch_add(1, Ordering::SeqCst);
            let row = transaction
                .query_row(
                    "SELECT format_version,codec_version,request_fingerprint,
                            result_bytes,result_commitment
                     FROM test_wal_media_capture_operations WHERE operation_id=?1",
                    [prepared.operation_id.as_bytes().as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if let Some((format, codec, fingerprint, encoded, commitment)) = row {
                if format != i64::from(WAL_IDEMPOTENCY_FORMAT_V1)
                    || codec != i64::from(WalOperationKind::MediaCaptureEvent.codec_version())
                    || fingerprint.len() != 32
                    || commitment.len() != 32
                {
                    return Err(WalIdempotencyError::Corrupt);
                }
                if fingerprint.as_slice() != prepared.request_fingerprint.as_bytes() {
                    return Err(WalIdempotencyError::FingerprintConflict);
                }
                let result =
                    WalReplayResult::decode(WalOperationKind::MediaCaptureEvent, &encoded)?;
                if commitment.as_slice()
                    != result
                        .commitment(WalOperationKind::MediaCaptureEvent)?
                        .as_slice()
                {
                    return Err(WalIdempotencyError::Corrupt);
                }
                prepared.plan.validate_replay(&result)?;
                return Ok(LogicalMutationDisposition::Replayed);
            }

            let (rows, result_bytes) = transaction
                .query_row(
                    "SELECT row_count,result_bytes
                     FROM test_wal_media_capture_ledger_state WHERE singleton=1",
                    [],
                    |row| Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(|_| WalIdempotencyError::Corrupt)?;
            let result_bytes =
                u64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
            // Reserve the domain codec's maximum encoded result before any
            // mutation SQL, so a full ledger cannot execute caller work and
            // then rely on rollback for safety.
            TEST_LEDGER_BOUNDS.admit(rows, result_bytes, MAX_ENCODED_REPLAY_RESULT_BYTES)?;
            let result = prepared.plan.apply(transaction)?;
            prepared.plan.validate_replay(&result)?;
            let encoded = result.encode(WalOperationKind::MediaCaptureEvent)?;
            let commitment = result.commitment(WalOperationKind::MediaCaptureEvent)?;
            transaction
                .execute(
                    "INSERT INTO test_wal_media_capture_operations
                     (operation_id,format_version,codec_version,request_fingerprint,
                      result_bytes,result_commitment)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![
                        prepared.operation_id.as_bytes().as_slice(),
                        i64::from(WAL_IDEMPOTENCY_FORMAT_V1),
                        i64::from(WalOperationKind::MediaCaptureEvent.codec_version()),
                        prepared.request_fingerprint.as_bytes().as_slice(),
                        encoded.as_slice(),
                        commitment.as_slice(),
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            transaction
                .execute(
                    "UPDATE test_wal_media_capture_ledger_state
                     SET row_count=row_count+1,result_bytes=result_bytes+?1
                     WHERE singleton=1",
                    [i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            Ok(LogicalMutationDisposition::Applied)
        }
    }

    impl WalLogicalDomainPlan for TestDomain {
        type Ledger = TestMediaCaptureLedger;

        fn kind(&self) -> WalOperationKind {
            self.kind
        }

        fn operation_id(&self) -> WalLogicalOperationId {
            self.id
        }

        fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(self.request.clone()))
        }

        fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
            self.apply_count.fetch_add(1, Ordering::SeqCst);
            transaction
                .execute(
                    "INSERT INTO domain_values(value) VALUES (?1)",
                    [self.request.as_slice()],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if self.fail_after_sql {
                return Err(WalIdempotencyError::Unavailable);
            }
            Ok(self.result.clone())
        }

        fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
            if result == &self.result {
                Ok(())
            } else {
                Err(WalIdempotencyError::ResultUnsupported)
            }
        }
    }

    fn initialize_test_ledger(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE domain_values(value BLOB NOT NULL);
                 CREATE TABLE test_wal_media_capture_operations (
                    operation_id BLOB PRIMARY KEY NOT NULL,
                    format_version INTEGER NOT NULL,
                    codec_version INTEGER NOT NULL,
                    request_fingerprint BLOB NOT NULL,
                    result_bytes BLOB NOT NULL,
                    result_commitment BLOB NOT NULL,
                    CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                    CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                    CHECK(length(result_bytes) BETWEEN 9 AND 4105),
                    CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                 ) WITHOUT ROWID;
                 CREATE TABLE test_wal_media_capture_ledger_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 64),
                    result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 262720)
                 );
                 INSERT INTO test_wal_media_capture_ledger_state
                    (singleton,row_count,result_bytes) VALUES (1,0,0);",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        initialize_test_ledger(&connection);
        connection
    }

    fn domain(
        kind: WalOperationKind,
        id: u8,
        request: &[u8],
        result: WalReplayResult,
        count: Arc<AtomicUsize>,
    ) -> TestDomain {
        TestDomain {
            kind,
            id: WalLogicalOperationId::from_bytes([id; 16]).unwrap(),
            request: request.to_vec(),
            result,
            apply_count: count,
            lookup_count: Arc::new(AtomicUsize::new(0)),
            fail_after_sql: false,
        }
    }

    #[test]
    fn ids_fingerprints_domains_versions_and_bounds_are_strict() {
        assert!(WalLogicalOperationId::from_bytes([0; 16]).is_err());
        let id = WalLogicalOperationId::from_bytes([1; 16]).unwrap();
        assert_eq!(format!("{id:?}"), "WalLogicalOperationId(<opaque>)");
        assert!(WalRequestFingerprint::derive(WalOperationKind::MediaCaptureEvent, &[]).is_err());
        assert!(WalRequestFingerprint::derive(
            WalOperationKind::MediaCaptureEvent,
            &vec![1; MAX_CANONICAL_WAL_REQUEST_BYTES + 1]
        )
        .is_err());
        let one = WalRequestFingerprint::derive(WalOperationKind::MediaCaptureEvent, b"x").unwrap();
        let two =
            WalRequestFingerprint::derive(WalOperationKind::CaptureSessionFinish, b"x").unwrap();
        assert_ne!(one.as_bytes(), two.as_bytes());
        assert!(WalOperationKind::decode(0).is_err());
        assert!(WalOperationKind::decode(13).is_err());
        assert!(
            WalReplayResult::canonical_response(WalOperationKind::FinalizationCommit, vec![1])
                .is_err()
        );
        assert!(WalReplayResult::canonical_response(
            WalOperationKind::MediaCaptureEvent,
            vec![1; MAX_CANONICAL_REPLAY_RESULT_BYTES + 1]
        )
        .is_err());
    }

    #[test]
    fn exact_replay_does_not_reapply_domain_closure_or_write_rows() {
        let mut connection = connection();
        let count = Arc::new(AtomicUsize::new(0));
        let first = domain(
            WalOperationKind::MediaCaptureEvent,
            1,
            b"request",
            WalReplayResult::canonical_response(
                WalOperationKind::MediaCaptureEvent,
                b"response".to_vec(),
            )
            .unwrap(),
            count.clone(),
        );
        assert_eq!(
            execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(first).unwrap()
            )
            .unwrap(),
            LogicalMutationDisposition::Applied
        );
        let changes = connection.total_changes();
        let replay = domain(
            WalOperationKind::MediaCaptureEvent,
            1,
            b"request",
            WalReplayResult::canonical_response(
                WalOperationKind::MediaCaptureEvent,
                b"response".to_vec(),
            )
            .unwrap(),
            count.clone(),
        );
        assert_eq!(
            execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(replay).unwrap()
            )
            .unwrap(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(connection.total_changes(), changes);
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM domain_values", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn same_domain_and_id_with_different_fingerprint_conflicts() {
        let mut connection = connection();
        let count = Arc::new(AtomicUsize::new(0));
        let first = domain(
            WalOperationKind::MediaCaptureEvent,
            2,
            b"first",
            WalReplayResult::unit(),
            count.clone(),
        );
        execute_prepared(
            &mut connection,
            PreparedLogicalMutation::prepare(first).unwrap(),
        )
        .unwrap();
        let conflict = domain(
            WalOperationKind::MediaCaptureEvent,
            2,
            b"second",
            WalReplayResult::unit(),
            count,
        );
        assert_eq!(
            execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(conflict).unwrap()
            )
            .unwrap_err(),
            WalIdempotencyError::FingerprintConflict
        );
    }

    #[test]
    fn domain_sql_and_result_row_rollback_together() {
        let mut connection = connection();
        let count = Arc::new(AtomicUsize::new(0));
        let mut failing = domain(
            WalOperationKind::MediaCaptureEvent,
            3,
            b"rollback",
            WalReplayResult::unit(),
            count,
        );
        failing.fail_after_sql = true;
        assert!(execute_prepared(
            &mut connection,
            PreparedLogicalMutation::prepare(failing).unwrap()
        )
        .is_err());
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM domain_values", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM test_wal_media_capture_operations",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn result_tamper_unknown_version_and_codec_fail_closed() {
        for corruption in ["result", "version", "codec"] {
            let mut connection = connection();
            let count = Arc::new(AtomicUsize::new(0));
            let plan = domain(
                WalOperationKind::MediaCaptureEvent,
                4,
                b"request",
                WalReplayResult::canonical_response(
                    WalOperationKind::MediaCaptureEvent,
                    b"response".to_vec(),
                )
                .unwrap(),
                count.clone(),
            );
            execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            )
            .unwrap();
            match corruption {
                "result" => {
                    connection
                        .execute(
                            "UPDATE test_wal_media_capture_operations SET result_bytes=?1",
                            [vec![0xff; 9]],
                        )
                        .unwrap();
                }
                "version" => {
                    connection
                        .execute(
                            "UPDATE test_wal_media_capture_operations SET format_version=99",
                            [],
                        )
                        .unwrap();
                }
                "codec" => {
                    connection
                        .execute(
                            "UPDATE test_wal_media_capture_operations SET codec_version=99",
                            [],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let replay = domain(
                WalOperationKind::MediaCaptureEvent,
                4,
                b"request",
                WalReplayResult::canonical_response(
                    WalOperationKind::MediaCaptureEvent,
                    b"response".to_vec(),
                )
                .unwrap(),
                count,
            );
            assert!(execute_prepared(
                &mut connection,
                PreparedLogicalMutation::prepare(replay).unwrap()
            )
            .is_err());
        }
    }

    #[test]
    fn restart_distinguishes_absent_from_exact_committed_replay() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("logical.db");
        let count = Arc::new(AtomicUsize::new(0));
        {
            let mut connection = Connection::open(&path).unwrap();
            initialize_test_ledger(&connection);
            let plan = domain(
                WalOperationKind::MediaCaptureEvent,
                5,
                b"commit",
                WalReplayResult::unit(),
                count.clone(),
            );
            assert_eq!(
                execute_prepared(
                    &mut connection,
                    PreparedLogicalMutation::prepare(plan).unwrap()
                )
                .unwrap(),
                LogicalMutationDisposition::Applied
            );
        }
        let mut reopened = Connection::open(&path).unwrap();
        let replay = domain(
            WalOperationKind::MediaCaptureEvent,
            5,
            b"commit",
            WalReplayResult::unit(),
            count.clone(),
        );
        assert_eq!(
            execute_prepared(
                &mut reopened,
                PreparedLogicalMutation::prepare(replay).unwrap()
            )
            .unwrap(),
            LogicalMutationDisposition::Replayed
        );
        let absent = domain(
            WalOperationKind::MediaCaptureEvent,
            6,
            b"new",
            WalReplayResult::unit(),
            count.clone(),
        );
        assert_eq!(
            execute_prepared(
                &mut reopened,
                PreparedLogicalMutation::prepare(absent).unwrap()
            )
            .unwrap(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_same_operation_serializes_to_one_apply_and_one_replay() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("serialized.db");
        {
            let connection = Connection::open(&path).unwrap();
            initialize_test_ledger(&connection);
        }
        let barrier = Arc::new(Barrier::new(2));
        let count = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let count = Arc::clone(&count);
            workers.push(std::thread::spawn(move || {
                let mut connection = Connection::open(path).unwrap();
                connection.busy_timeout(Duration::from_secs(5)).unwrap();
                barrier.wait();
                let plan = domain(
                    WalOperationKind::MediaCaptureEvent,
                    7,
                    b"same-request",
                    WalReplayResult::unit(),
                    count,
                );
                execute_prepared(
                    &mut connection,
                    PreparedLogicalMutation::prepare(plan).unwrap(),
                )
                .unwrap()
            }));
        }
        let mut dispositions = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        dispositions.sort_by_key(|disposition| match disposition {
            LogicalMutationDisposition::Applied => 0,
            LogicalMutationDisposition::Replayed => 1,
        });
        assert_eq!(
            dispositions,
            vec![
                LogicalMutationDisposition::Applied,
                LogicalMutationDisposition::Replayed,
            ]
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let connection = Connection::open(&path).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM domain_values", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn domain_row_and_byte_caps_reject_before_apply_and_lookup_work_is_constant() {
        let mut full_ledger = connection();
        let apply_count = Arc::new(AtomicUsize::new(0));
        for id in 1..=64 {
            let plan = domain(
                WalOperationKind::MediaCaptureEvent,
                id,
                &[id],
                WalReplayResult::unit(),
                Arc::clone(&apply_count),
            );
            let lookup_count = Arc::clone(&plan.lookup_count);
            assert_eq!(
                execute_prepared(
                    &mut full_ledger,
                    PreparedLogicalMutation::prepare(plan).unwrap(),
                )
                .unwrap(),
                LogicalMutationDisposition::Applied
            );
            assert_eq!(lookup_count.load(Ordering::SeqCst), 1);
        }
        let over_row_cap = domain(
            WalOperationKind::MediaCaptureEvent,
            65,
            b"over-row-cap",
            WalReplayResult::unit(),
            Arc::clone(&apply_count),
        );
        assert_eq!(
            execute_prepared(
                &mut full_ledger,
                PreparedLogicalMutation::prepare(over_row_cap).unwrap(),
            )
            .unwrap_err(),
            WalIdempotencyError::Limit
        );
        assert_eq!(apply_count.load(Ordering::SeqCst), 64);

        let replay = domain(
            WalOperationKind::MediaCaptureEvent,
            32,
            &[32],
            WalReplayResult::unit(),
            Arc::clone(&apply_count),
        );
        let replay_lookup_count = Arc::clone(&replay.lookup_count);
        assert_eq!(
            execute_prepared(
                &mut full_ledger,
                PreparedLogicalMutation::prepare(replay).unwrap(),
            )
            .unwrap(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(replay_lookup_count.load(Ordering::SeqCst), 1);
        assert_eq!(apply_count.load(Ordering::SeqCst), 64);

        let mut byte_limited = connection();
        byte_limited
            .execute(
                "UPDATE test_wal_media_capture_ledger_state SET result_bytes=?1",
                [i64::try_from(TEST_LEDGER_BOUNDS.max_result_bytes - 8).unwrap()],
            )
            .unwrap();
        let byte_apply_count = Arc::new(AtomicUsize::new(0));
        let over_byte_cap = domain(
            WalOperationKind::MediaCaptureEvent,
            66,
            b"over-byte-cap",
            WalReplayResult::unit(),
            Arc::clone(&byte_apply_count),
        );
        assert_eq!(
            execute_prepared(
                &mut byte_limited,
                PreparedLogicalMutation::prepare(over_byte_cap).unwrap(),
            )
            .unwrap_err(),
            WalIdempotencyError::Limit
        );
        assert_eq!(byte_apply_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancellation_before_commit_is_safe_and_after_commit_poisons_until_settled() {
        let poisoned = AtomicBool::new(false);
        drop(LocalMutationCancellationGuard::new(&poisoned));
        assert!(!poisoned.load(Ordering::Acquire));
        {
            let mut guard = LocalMutationCancellationGuard::new(&poisoned);
            guard.mark_local_committed();
        }
        assert!(poisoned.load(Ordering::Acquire));
        poisoned.store(false, Ordering::Release);
        {
            let mut guard = LocalMutationCancellationGuard::new(&poisoned);
            guard.mark_local_committed();
            guard.mark_settled();
        }
        assert!(!poisoned.load(Ordering::Acquire));
    }

    #[test]
    fn source_has_no_runtime_or_public_universal_receipt_surface() {
        let source = include_str!("archive_v3_wal_idempotency.rs");
        for forbidden in [
            concat!("crate::store::", "Store"),
            concat!("std::", "env"),
            concat!("Gcs", "Client"),
            concat!("Witness::", "advance"),
            concat!("tokio::", "spawn"),
            concat!("pub struct ", "PreparedLogicalMutation"),
            concat!("pub(crate) struct ", "PreparedLogicalMutation"),
            concat!("OperationKind::", "AccountDelete"),
            concat!("OperationKind::", "EpisodeDelete"),
            concat!("archive_v3_wal_", "logical_operations"),
            concat!("ORDER BY operation_", "kind"),
        ] {
            assert!(!source.contains(forbidden), "found forbidden {forbidden}");
        }
    }
}
