#![allow(
    dead_code,
    reason = "inactive ADR-0022 production domain codec is reviewed before launcher or route ownership"
)]

//! Inactive WAL logical-operation codecs owned by Cloud Capture.
//!
//! The parent converts capture-session finish into one closed request/result
//! codec and distinct permanent ledger. Private children separately cover the
//! local receipt for an already durable canonical-media upload, first-writer-
//! wins installation of a future KMS-supplied media DEK, and the deterministic
//! metadata-only screen-reference batch. None has Store, route, launcher,
//! provider, KMS, task, or acknowledgement authority.

mod capture_event;
mod media_dek;
mod reference_batch;
mod reference_event;
pub(crate) use capture_event::{CanonicalCaptureEventLedger, CanonicalCaptureEventPlan};
pub(in crate::cp) use media_dek::{authenticate_media_dek_install_receipt, MediaDekInstallReceipt};
pub(crate) use media_dek::{MediaDekInstallLedger, MediaDekInstallPlan};
pub(crate) use reference_batch::{MediaReferenceBatchLedger, MediaReferenceBatchPlan};
pub(crate) use reference_event::{MediaReferenceEventLedger, MediaReferenceEventPlan};

use std::sync::{Arc, OnceLock};

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult, MAX_ENCODED_REPLAY_RESULT_BYTES,
};
use crate::error::{CaptureReferenceFailureReason, EnclaveError};

/// ADR-0022: the rebase-required reason a reference write observed *inside*
/// `apply()`, carried out of band so the route can still answer with it.
///
/// Why a side channel and not the error type: `WalIdempotencyError` is a
/// payload-free `Copy` enum, and `Store::wal_authoritative_submit` deliberately
/// narrows every owner refusal to a content-free `Conflict` or `Store`. A
/// reference refusal that reaches the submit boundary therefore arrives with
/// nothing but "conflict", and the route answers `409`/`500` instead of the
/// documented `400 {"error":"screen_reference_rebase_required","reason":...}`.
/// That is a real wedge, not a cosmetic one: the Mac client's outbox is
/// durable, a 409/500 is retryable to it, and the one thing that can clear the
/// refusal is a *rebase* it never learns it needs — so it re-posts the same
/// unrebasable event forever and its stream never advances.
///
/// The preflight read the routes run first catches the ordinary case. This
/// carries the race window between that read and the submit, which is exactly
/// where the refusal is both possible and invisible.
///
/// Recording is strictly additive: `apply()` still returns the same
/// `WalIdempotencyError::Precondition` it returned before, the transaction
/// still rolls back, and a route that ignores the sink behaves exactly as it
/// did. Only the FIRST refusal is retained (`OnceLock`), which matches the
/// batch loop's own abort-on-first-item semantics.
#[derive(Clone, Default)]
pub(in crate::cp::media) struct RebaseRefusalSink(Arc<OnceLock<RebaseRefusal>>);

#[derive(Clone, Copy)]
struct RebaseRefusal {
    reason: CaptureReferenceFailureReason,
    /// `Some((index, sequence))` for a batch item, mirroring the legacy
    /// `record_reference_batch` framing byte for byte; `None` for the
    /// single-event route, whose legacy branch reports the bare reason.
    batch_position: Option<(usize, i64)>,
}

impl RebaseRefusalSink {
    fn record(&self, reason: CaptureReferenceFailureReason, batch_position: Option<(usize, i64)>) {
        let _ = self.0.set(RebaseRefusal {
            reason,
            batch_position,
        });
    }

    /// The exact error the legacy branch would have returned, if `apply()`
    /// observed a rebase-required refusal. `None` means the submit failed for
    /// some other reason and the caller must keep its own error.
    pub(in crate::cp::media) fn observed(&self) -> Option<EnclaveError> {
        self.0.get().map(|refusal| match refusal.batch_position {
            Some((index, sequence)) => EnclaveError::CaptureReferenceBatch {
                reason: refusal.reason,
                index,
                sequence,
            },
            None => EnclaveError::CaptureReference(refusal.reason),
        })
    }
}

/// The byte length beyond which a carried commit stamp is refused. It matches
/// `media_worker::wal::claim`'s and `media_worker::wal::failure`'s own
/// `MAX_TIMESTAMP_BYTES`, because those are the bounds a stamp written by this
/// module is later measured against.
///
/// The round-trip check below already implies it — the canonical rendering is
/// always exactly 24 bytes — so this is a redundant explicit bound, kept
/// because it names the downstream constant this module has to agree with and
/// would survive a change to `format_epoch_millis` that the round trip alone
/// would silently follow.
pub(super) const MAX_COMMIT_STAMP_BYTES: usize = 64;

/// ADR-0022: the exact shape a carried commit stamp must have before any
/// family here may bind it in place of a live-clock column DEFAULT.
///
/// The stamp must be the canonical UTC rendering `YYYY-MM-DDTHH:MM:SS.mmmZ`
/// that `isotime::format_epoch_millis` — and therefore `media_worker::now_iso`
/// — produces. It is checked by ROUND TRIP rather than by pattern, so the
/// predicate cannot drift away from the renderer it is supposed to agree with.
///
/// This is not cosmetic, and it is not a re-validation of something the
/// manifest already checked. `media_worker::wal::claim::MediaWorkClaimPlan::new`
/// refuses to construct whenever a member's `latest_observed_timestamp()` —
/// which is `media_processing_jobs.updated_at` while `lease_until` is NULL,
/// and it is NULL for every `pending` job — string-compares GREATER than the
/// enclave-generated `committed_at` it carries. `enumerate_claimable` bounds
/// `updated_at` only in its `retry_wait` arm; `state='pending'` is
/// unconditional. So a single job row carrying a stamp that sorts above
/// `now_iso()` is re-enumerated by every sweep, deterministically re-selected
/// by `media_planner::plan_first`, and refused again at construction — with no
/// attempt cap, no terminalization path for a `pending` job and no
/// user-visible error. `media_objects.processing_state` stays `'queued'`
/// forever, so `summarizer::session_tail_is_settled` never holds and the
/// summarizer's forward-only cursor never advances: no episodes, ever.
///
/// Because the comparison is a RAW STRING compare, two shapes wedge the lane
/// with no clock skew whatsoever:
///
///   * an offset-bearing `2026-08-21T21:00:00+09:00`, which `parse_epoch_millis`
///     accepts as a PAST instant and which sorts above every `now_iso()` for
///     the next nine hours;
///   * more than three fractional digits — `parse_epoch_millis` ignores the
///     rest, and once the string passes 64 bytes it also fails
///     `ClaimMember::resolve`'s `MAX_TIMESTAMP_BYTES` bound.
///
/// Round-tripping through the canonical renderer rejects both, and every other
/// shape that is not byte-comparable against `now_iso()`.
pub(super) fn is_canonical_commit_stamp(value: &str) -> bool {
    value.len() <= MAX_COMMIT_STAMP_BYTES
        && super::super::isotime::parse_epoch_millis(value)
            .is_some_and(|millis| super::super::isotime::format_epoch_millis(millis) == value)
}

const CAPTURE_SESSION_FINISH_REQUEST_V1: u16 = 1;
const CAPTURE_SESSION_FINISH_RESULT_V1: u16 = 1;
const RESULT_FINISHED: u8 = 1;
const MAX_ENDED_AT_BYTES: usize = 64;
const CAPTURE_SESSION_FINISH_SCHEMA_TABLE: &str = "archive_v3_wal_capture_session_finish_schema";
const CAPTURE_SESSION_FINISH_LEDGER_TABLE: &str =
    "archive_v3_wal_capture_session_finish_operations";
const CAPTURE_SESSION_FINISH_STATE_TABLE: &str = "archive_v3_wal_capture_session_finish_state";
const MAX_CAPTURE_SESSION_FINISH_ROWS: u32 = 65_536;
const MAX_CAPTURE_SESSION_FINISH_RESULT_BYTES: u64 = 128 * 1024 * 1024;
const CAPTURE_SESSION_FINISH_BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(
    MAX_CAPTURE_SESSION_FINISH_ROWS,
    MAX_CAPTURE_SESSION_FINISH_RESULT_BYTES,
);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// Exact logical result retained across publication and replay. The route may
/// separately load its ordinary live status view after this receipt settles;
/// mutable later worker state is deliberately not embedded in this result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CaptureSessionFinishOutcome {
    ended_at: String,
}

impl CaptureSessionFinishOutcome {
    pub(super) fn ended_at(&self) -> &str {
        &self.ended_at
    }

    /// Test-only crate-visible accessor for the cross-module WAL launch
    /// end-to-end tests.
    #[cfg(test)]
    pub(crate) fn ended_at_for_wal_e2e(&self) -> &str {
        &self.ended_at
    }
}

/// Caller-stable capture-session finish plan. Its operation ID is derived
/// only from the validated session ID under the fixed operation-kind domain.
pub(crate) struct CaptureSessionFinishPlan {
    operation_id: WalLogicalOperationId,
    capture_session_id: String,
}

impl CaptureSessionFinishPlan {
    pub(super) fn new(capture_session_id: String) -> Result<Self> {
        super::validate_id("capture_session_id", &capture_session_id)
            .map_err(|_| WalIdempotencyError::Malformed)?;
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::CaptureSessionFinish,
            capture_session_id.as_bytes(),
        )?;
        Ok(Self {
            operation_id,
            capture_session_id,
        })
    }

    /// Test-only crate-visible constructor for the cross-module WAL launch
    /// end-to-end tests; production construction stays sealed to this
    /// domain's routes.
    #[cfg(test)]
    pub(crate) fn new_for_wal_e2e(capture_session_id: String) -> Result<Self> {
        Self::new(capture_session_id)
    }

    #[cfg(test)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        capture_session_id: &str,
    ) -> Result<Self> {
        super::validate_id("capture_session_id", capture_session_id)
            .map_err(|_| WalIdempotencyError::Malformed)?;
        Ok(Self {
            operation_id,
            capture_session_id: capture_session_id.to_owned(),
        })
    }
}

pub(crate) struct CaptureSessionFinishLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for CaptureSessionFinishPlan {
    type Ledger = CaptureSessionFinishLedger;
    type Output = CaptureSessionFinishOutcome;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::CaptureSessionFinish
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let id_bytes = self.capture_session_id.as_bytes();
        let id_length = u16::try_from(id_bytes.len()).map_err(|_| WalIdempotencyError::Limit)?;
        let mut request = Zeroizing::new(Vec::with_capacity(4 + id_bytes.len()));
        request.extend_from_slice(&CAPTURE_SESSION_FINISH_REQUEST_V1.to_be_bytes());
        request.extend_from_slice(&id_length.to_be_bytes());
        request.extend_from_slice(id_bytes);
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let existing = transaction
            .query_row(
                "SELECT ended_at FROM capture_sessions WHERE id=?1",
                [&self.capture_session_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let ended_at = match existing {
            None => return Err(WalIdempotencyError::Precondition),
            Some(Some(ended_at)) => ended_at,
            Some(None) => {
                let changed = transaction
                    .execute(
                        "UPDATE capture_sessions
                         SET ended_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                         WHERE id=?1 AND ended_at IS NULL",
                        [&self.capture_session_id],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if changed != 1 {
                    return Err(WalIdempotencyError::Corrupt);
                }
                transaction
                    .query_row(
                        "SELECT ended_at FROM capture_sessions WHERE id=?1",
                        [&self.capture_session_id],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?
                    .ok_or(WalIdempotencyError::Corrupt)?
            }
        };
        encode_outcome(&CaptureSessionFinishOutcome { ended_at })
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        decode_outcome(result).map(|_| ())
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        decode_outcome(result)
    }
}

impl WalLogicalDomainLedger<CaptureSessionFinishPlan> for CaptureSessionFinishLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<CaptureSessionFinishPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,
                        result_bytes,result_commitment
                 FROM archive_v3_wal_capture_session_finish_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
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
        let Some((format, codec, fingerprint, encoded, commitment)) = row else {
            return Ok(None);
        };
        let kind = WalOperationKind::CaptureSessionFinish;
        if format != i64::from(WalOperationKind::format_version())
            || codec != i64::from(kind.codec_version())
            || fingerprint.len() != 32
            || commitment.len() != 32
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        if fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        let result = WalReplayResult::decode(kind, &encoded)?;
        if commitment.as_slice() != result.commitment(kind)?.as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<CaptureSessionFinishPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }

        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        CAPTURE_SESSION_FINISH_BOUNDS.admit(
            row_count,
            result_bytes,
            MAX_ENCODED_REPLAY_RESULT_BYTES,
        )?;

        let kind = WalOperationKind::CaptureSessionFinish;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_capture_session_finish_operations
                 (operation_id,format_version,codec_version,request_fingerprint,
                  result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let encoded_length =
            i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?;
        let previous_result_bytes =
            i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_capture_session_finish_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![encoded_length, i64::from(row_count), previous_result_bytes],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

fn require_kind(prepared: &PreparedLogicalMutation<CaptureSessionFinishPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::CaptureSessionFinish)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn encode_outcome(outcome: &CaptureSessionFinishOutcome) -> Result<WalReplayResult> {
    let mut bytes = Vec::with_capacity(5 + MAX_ENDED_AT_BYTES);
    bytes.extend_from_slice(&CAPTURE_SESSION_FINISH_RESULT_V1.to_be_bytes());
    validate_ended_at(&outcome.ended_at)?;
    bytes.push(RESULT_FINISHED);
    let length = u16::try_from(outcome.ended_at.len()).map_err(|_| WalIdempotencyError::Limit)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(outcome.ended_at.as_bytes());
    WalReplayResult::canonical_response(WalOperationKind::CaptureSessionFinish, bytes)
}

fn decode_outcome(result: &WalReplayResult) -> Result<CaptureSessionFinishOutcome> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    if bytes.len() < 3
        || u16::from_be_bytes([bytes[0], bytes[1]]) != CAPTURE_SESSION_FINISH_RESULT_V1
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    match bytes[2] {
        RESULT_FINISHED if bytes.len() >= 5 => {
            let length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
            if length == 0
                || length > MAX_ENDED_AT_BYTES
                || bytes.len() != 5usize.saturating_add(length)
            {
                return Err(WalIdempotencyError::Corrupt);
            }
            let ended_at = std::str::from_utf8(&bytes[5..])
                .map_err(|_| WalIdempotencyError::Corrupt)?
                .to_owned();
            validate_ended_at(&ended_at)?;
            Ok(CaptureSessionFinishOutcome { ended_at })
        }
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn validate_ended_at(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ENDED_AT_BYTES
        || super::super::isotime::parse_epoch_millis(value).is_none()
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3)",
            params![
                CAPTURE_SESSION_FINISH_SCHEMA_TABLE,
                CAPTURE_SESSION_FINISH_LEDGER_TABLE,
                CAPTURE_SESSION_FINISH_STATE_TABLE,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(LedgerSchemaState::Absent),
        3 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_capture_session_finish_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_capture_session_finish_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes) BETWEEN 9 AND 4105),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_capture_session_finish_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 134217728)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_capture_session_finish_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_capture_session_finish_state
                        (singleton,row_count,result_bytes) VALUES (1,0,0);",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            validate_schema_marker(transaction)
        }
    }
}

fn validate_schema_marker(connection: &Connection) -> Result<()> {
    let marker = connection
        .query_row(
            "SELECT format_version,codec_version
             FROM archive_v3_wal_capture_session_finish_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::CaptureSessionFinish.codec_version()),
        ))
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let _ = load_ledger_state(connection)?;
    Ok(())
}

fn load_ledger_state(connection: &Connection) -> Result<(u32, u64)> {
    let state = connection
        .query_row(
            "SELECT row_count,result_bytes
             FROM archive_v3_wal_capture_session_finish_state WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let row_count = u32::try_from(state.0).map_err(|_| WalIdempotencyError::Corrupt)?;
    let result_bytes = u64::try_from(state.1).map_err(|_| WalIdempotencyError::Corrupt)?;
    if row_count > MAX_CAPTURE_SESSION_FINISH_ROWS
        || result_bytes > MAX_CAPTURE_SESSION_FINISH_RESULT_BYTES
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok((row_count, result_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use rusqlite::Connection;

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE capture_sessions (
                    id TEXT PRIMARY KEY NOT NULL,
                    ended_at TEXT
                 ) STRICT;",
            )
            .unwrap();
        connection
    }

    fn id(value: u8) -> WalLogicalOperationId {
        WalLogicalOperationId::from_bytes([value; 16]).unwrap()
    }

    fn plan(value: u8, session: &str) -> CaptureSessionFinishPlan {
        CaptureSessionFinishPlan::with_operation_id(id(value), session).unwrap()
    }

    #[test]
    fn stable_source_derives_stable_kind_scoped_operation_id_and_request() {
        let one = CaptureSessionFinishPlan::new("session-1".to_owned()).unwrap();
        let replay = CaptureSessionFinishPlan::new("session-1".to_owned()).unwrap();
        let other = CaptureSessionFinishPlan::new("session-2".to_owned()).unwrap();
        assert_eq!(one.operation_id(), replay.operation_id());
        assert_ne!(one.operation_id(), other.operation_id());
        assert_ne!(
            one.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::MediaCaptureEvent,
                b"session-1"
            )
            .unwrap()
        );
        assert_eq!(
            one.canonical_request().unwrap().as_slice(),
            b"\0\x01\0\tsession-1"
        );
        assert!(CaptureSessionFinishPlan::new(String::new()).is_err());
    }

    #[test]
    fn applies_once_and_replays_exact_finished_time() {
        let mut connection = connection();
        connection
            .execute(
                "INSERT INTO capture_sessions(id,ended_at) VALUES (?1,NULL)",
                ["session-1"],
            )
            .unwrap();
        let first = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(1, "session-1")).unwrap(),
        )
        .unwrap();
        assert_eq!(first.disposition(), LogicalMutationDisposition::Applied);
        let first_result = first.into_validated_result().release().unwrap();
        let ended_at = first_result.ended_at;
        let changes = connection.total_changes();
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(1, "session-1")).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(
            replay.into_validated_result().release().unwrap(),
            CaptureSessionFinishOutcome {
                ended_at: ended_at.clone()
            }
        );
        assert_eq!(connection.total_changes(), changes);
        assert_eq!(
            connection
                .query_row(
                    "SELECT ended_at FROM capture_sessions WHERE id='session-1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            ended_at
        );
    }

    #[test]
    fn absent_session_does_not_consume_identity_and_later_retry_can_apply() {
        let mut connection = connection();
        let first_error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(2, "missing")).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(first_error, WalIdempotencyError::Precondition);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name='archive_v3_wal_capture_session_finish_operations'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "failed domain work must roll back its lazily-created ledger schema"
        );
        connection
            .execute(
                "INSERT INTO capture_sessions(id,ended_at) VALUES ('missing',NULL)",
                [],
            )
            .unwrap();
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(2, "missing")).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Applied);
        let outcome = replay.into_validated_result().release().unwrap();
        validate_ended_at(outcome.ended_at()).unwrap();
        assert!(connection
            .query_row(
                "SELECT ended_at FROM capture_sessions WHERE id='missing'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn same_operation_id_with_another_session_conflicts_before_domain_sql() {
        let mut connection = connection();
        connection
            .execute_batch(
                "INSERT INTO capture_sessions(id,ended_at) VALUES ('one',NULL);
                 INSERT INTO capture_sessions(id,ended_at) VALUES ('two',NULL);",
            )
            .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(3, "one")).unwrap(),
        )
        .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(3, "two")).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::FingerprintConflict);
        assert!(connection
            .query_row(
                "SELECT ended_at FROM capture_sessions WHERE id='two'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn row_cap_rejects_before_session_mutation_but_committed_replay_survives() {
        let mut connection = connection();
        connection
            .execute_batch(
                "INSERT INTO capture_sessions(id,ended_at) VALUES ('first',NULL);
                 INSERT INTO capture_sessions(id,ended_at) VALUES ('blocked',NULL);",
            )
            .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(4, "first")).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_capture_session_finish_state
                 SET row_count=?1",
                [i64::from(MAX_CAPTURE_SESSION_FINISH_ROWS)],
            )
            .unwrap();
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(4, "first")).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(5, "blocked")).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Limit);
        assert!(connection
            .query_row(
                "SELECT ended_at FROM capture_sessions WHERE id='blocked'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn result_byte_cap_rejects_before_session_mutation_but_replay_survives() {
        let mut connection = connection();
        connection
            .execute_batch(
                "INSERT INTO capture_sessions(id,ended_at) VALUES ('first-byte',NULL);
                 INSERT INTO capture_sessions(id,ended_at) VALUES ('blocked-byte',NULL);",
            )
            .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(10, "first-byte")).unwrap(),
        )
        .unwrap();
        let insufficient_capacity = MAX_CAPTURE_SESSION_FINISH_RESULT_BYTES
            - u64::try_from(MAX_ENCODED_REPLAY_RESULT_BYTES).unwrap()
            + 1;
        connection
            .execute(
                "UPDATE archive_v3_wal_capture_session_finish_state
                 SET result_bytes=?1",
                [i64::try_from(insufficient_capacity).unwrap()],
            )
            .unwrap();
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(10, "first-byte")).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(11, "blocked-byte")).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Limit);
        assert!(connection
            .query_row(
                "SELECT ended_at FROM capture_sessions WHERE id='blocked-byte'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn late_ledger_failure_rolls_back_the_session_update() {
        let mut connection = connection();
        connection
            .execute(
                "INSERT INTO capture_sessions(id,ended_at) VALUES ('rollback',NULL)",
                [],
            )
            .unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        ensure_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_capture_finish_ledger
                 BEFORE INSERT ON archive_v3_wal_capture_session_finish_operations
                 BEGIN SELECT RAISE(ABORT,'reject'); END;",
            )
            .unwrap();
        assert!(execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(6, "rollback")).unwrap(),
        )
        .is_err());
        assert!(connection
            .query_row(
                "SELECT ended_at FROM capture_sessions WHERE id='rollback'",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn reopened_database_exactly_replays_without_another_update() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture-finish.db");
        let ended_at = {
            let mut connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE capture_sessions (
                        id TEXT PRIMARY KEY NOT NULL,
                        ended_at TEXT
                     ) STRICT;
                     INSERT INTO capture_sessions(id,ended_at) VALUES ('restart',NULL);",
                )
                .unwrap();
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(9, "restart")).unwrap(),
            )
            .unwrap()
            .into_validated_result()
            .release()
            .unwrap()
            .ended_at
        };
        let mut reopened = Connection::open(&path).unwrap();
        let changes = reopened.total_changes();
        let replay = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(plan(9, "restart")).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(
            replay.into_validated_result().release().unwrap().ended_at(),
            ended_at
        );
        assert_eq!(reopened.total_changes(), changes);
    }

    #[test]
    fn partial_schema_and_tampered_result_fail_closed() {
        let mut partial = connection();
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_capture_session_finish_schema (
                    singleton INTEGER PRIMARY KEY,
                    format_version INTEGER,
                    codec_version INTEGER
                 );",
            )
            .unwrap();
        let partial_error = execute_prepared_for_owner(
            &mut partial,
            PreparedLogicalMutation::prepare(plan(7, "partial")).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(partial_error, WalIdempotencyError::Corrupt);

        let mut tampered = connection();
        tampered
            .execute(
                "INSERT INTO capture_sessions(id,ended_at) VALUES ('missing',NULL)",
                [],
            )
            .unwrap();
        execute_prepared_for_owner(
            &mut tampered,
            PreparedLogicalMutation::prepare(plan(8, "missing")).unwrap(),
        )
        .unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_capture_session_finish_operations
                 SET result_bytes=zeroblob(9)",
                [],
            )
            .unwrap();
        assert!(execute_prepared_for_owner(
            &mut tampered,
            PreparedLogicalMutation::prepare(plan(8, "missing")).unwrap(),
        )
        .is_err());
    }
}
