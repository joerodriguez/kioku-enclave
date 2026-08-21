//! Inactive metadata-only screen-reference batch WAL domain.
//!
//! The batch ID is derived by the existing cross-language route contract before
//! actor admission. This child can mutate only the exact validated reference
//! rows and its own bounded replay ledger. It cannot upload canonical media,
//! obtain a media DEK, call Store, launch a task, or acknowledge a request.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult, MAX_ENCODED_REPLAY_RESULT_BYTES,
};
use crate::error::EnclaveError;

use super::super::{
    CaptureEventManifest, RecordOutcome, ScreenReferenceBatchRequest, MAX_REFERENCE_BATCH_BYTES,
};
use super::RebaseRefusalSink;

const REQUEST_V1: u16 = 1;
const REQUEST_REFERENCE_BATCH: u8 = 1;
const OPERATION_SOURCE_DOMAIN: &[u8] = b"reference-batch-v1\0";
const RESULT_V1: u16 = 1;
const RESULT_REFERENCE_BATCH: u8 = 1;
const SCHEMA_TABLE: &str = "archive_v3_wal_media_reference_batch_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_media_reference_batch_operations";
const STATE_TABLE: &str = "archive_v3_wal_media_reference_batch_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 512 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MediaReferenceBatchOutcome {
    batch_id: String,
    stream_id: String,
    first_sequence: i64,
    last_sequence: i64,
    new_count: u16,
    duplicate_count: u16,
    committed_through_sequence: i64,
}

impl MediaReferenceBatchOutcome {
    pub(in crate::cp::media) fn batch_id(&self) -> &str {
        &self.batch_id
    }

    pub(in crate::cp::media) fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub(in crate::cp::media) const fn first_sequence(&self) -> i64 {
        self.first_sequence
    }

    pub(in crate::cp::media) const fn last_sequence(&self) -> i64 {
        self.last_sequence
    }

    pub(in crate::cp::media) const fn new_count(&self) -> u16 {
        self.new_count
    }

    pub(in crate::cp::media) const fn duplicate_count(&self) -> u16 {
        self.duplicate_count
    }

    pub(in crate::cp::media) const fn committed_through_sequence(&self) -> i64 {
        self.committed_through_sequence
    }
}

pub(crate) struct MediaReferenceBatchPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    batch_id: String,
    events: Vec<CaptureEventManifest>,
    manifest_digests: Vec<String>,
    stream_id: String,
    first_sequence: i64,
    last_sequence: i64,
    refusal: RebaseRefusalSink,
}

impl MediaReferenceBatchPlan {
    pub(in crate::cp::media) fn new(
        account_id: String,
        batch_id: String,
        events: Vec<CaptureEventManifest>,
    ) -> Result<Self> {
        Self::build(None, account_id, batch_id, events)
    }

    /// Handle on the rebase-required reason `apply()` refused with, taken by
    /// the route before `prepare` consumes the plan. See
    /// [`RebaseRefusalSink`].
    pub(in crate::cp::media) fn refusal_sink(&self) -> RebaseRefusalSink {
        self.refusal.clone()
    }

    fn build(
        operation_id: Option<WalLogicalOperationId>,
        account_id: String,
        batch_id: String,
        events: Vec<CaptureEventManifest>,
    ) -> Result<Self> {
        super::super::validate_id("account_id", &account_id)
            .map_err(|_| WalIdempotencyError::Malformed)?;
        let request = ScreenReferenceBatchRequest {
            schema_version: 1,
            batch_id: batch_id.clone(),
            events,
        };
        let validated = super::super::validate_reference_batch(&request)
            .map_err(|_| WalIdempotencyError::Malformed)?;
        let operation_id = match operation_id {
            Some(value) => value,
            None => {
                let mut stable_source = Vec::with_capacity(
                    OPERATION_SOURCE_DOMAIN.len().saturating_add(batch_id.len()),
                );
                stable_source.extend_from_slice(OPERATION_SOURCE_DOMAIN);
                stable_source.extend_from_slice(batch_id.as_bytes());
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::MediaCaptureEvent,
                    &stable_source,
                )?
            }
        };
        Ok(Self {
            operation_id,
            account_id,
            batch_id,
            events: request.events,
            manifest_digests: validated.manifest_digests,
            stream_id: validated.stream_id,
            first_sequence: validated.first_sequence,
            last_sequence: validated.last_sequence,
            refusal: RebaseRefusalSink::default(),
        })
    }

    #[cfg(test)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        account_id: &str,
        batch_id: String,
        events: Vec<CaptureEventManifest>,
    ) -> Result<Self> {
        Self::build(Some(operation_id), account_id.to_owned(), batch_id, events)
    }
}

pub(crate) struct MediaReferenceBatchLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for MediaReferenceBatchPlan {
    type Ledger = MediaReferenceBatchLedger;
    type Output = MediaReferenceBatchOutcome;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::MediaCaptureEvent
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let account_length =
            u16::try_from(self.account_id.len()).map_err(|_| WalIdempotencyError::Limit)?;
        let event_count =
            u16::try_from(self.events.len()).map_err(|_| WalIdempotencyError::Limit)?;
        let mut request = Zeroizing::new(Vec::new());
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        request.push(REQUEST_REFERENCE_BATCH);
        request.extend_from_slice(&account_length.to_be_bytes());
        request.extend_from_slice(self.account_id.as_bytes());
        request.extend_from_slice(self.batch_id.as_bytes());
        request.extend_from_slice(&event_count.to_be_bytes());
        for event in &self.events {
            let normalized =
                serde_json::to_vec(event).map_err(|_| WalIdempotencyError::Malformed)?;
            let length = u32::try_from(normalized.len()).map_err(|_| WalIdempotencyError::Limit)?;
            request.extend_from_slice(&length.to_be_bytes());
            request.extend_from_slice(&normalized);
        }
        if request.len() > MAX_REFERENCE_BATCH_BYTES {
            return Err(WalIdempotencyError::Limit);
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let mut new_count = 0u16;
        let mut duplicate_count = 0u16;
        for (index, (event, digest)) in self.events.iter().zip(&self.manifest_digests).enumerate() {
            let outcome = match super::super::record_reference_event_in_transaction(
                transaction,
                &self.account_id,
                event,
                digest,
                // Each event stamps its own rows with its own `source_wall_at`
                // instead of firing the live-clock DEFAULTs inside `apply()`.
                // See `super::reference_event` for the full argument.
                Some(&event.source_wall_at),
            ) {
                Ok(outcome) => outcome,
                Err(EnclaveError::CaptureReference(reason)) => {
                    // The refusal still collapses to `Precondition` below --
                    // no failure handler is weakened and the transaction still
                    // rolls back. The reason is recorded first so the route can
                    // answer the documented 400 instead of a content-free
                    // conflict the client would retry forever. The framing
                    // mirrors the legacy `record_reference_batch` branch
                    // exactly: the failing item's index and sequence.
                    self.refusal.record(reason, Some((index, event.sequence)));
                    return Err(map_domain_error(EnclaveError::CaptureReference(reason)));
                }
                Err(error) => return Err(map_domain_error(error)),
            };
            match outcome {
                RecordOutcome::Created => {
                    new_count = new_count.checked_add(1).ok_or(WalIdempotencyError::Limit)?;
                }
                RecordOutcome::Duplicate => {
                    duplicate_count = duplicate_count
                        .checked_add(1)
                        .ok_or(WalIdempotencyError::Limit)?;
                }
            }
        }
        let committed_through_sequence =
            super::super::committed_through_sequence(transaction, &self.stream_id)
                .map_err(map_domain_error)?;
        encode_outcome(&MediaReferenceBatchOutcome {
            batch_id: self.batch_id.clone(),
            stream_id: self.stream_id.clone(),
            first_sequence: self.first_sequence,
            last_sequence: self.last_sequence,
            new_count,
            duplicate_count,
            committed_through_sequence,
        })
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        let outcome = decode_outcome(result)?;
        let observed_count = usize::from(outcome.new_count)
            .checked_add(usize::from(outcome.duplicate_count))
            .ok_or(WalIdempotencyError::Corrupt)?;
        if outcome.batch_id != self.batch_id
            || outcome.stream_id != self.stream_id
            || outcome.first_sequence != self.first_sequence
            || outcome.last_sequence != self.last_sequence
            || observed_count != self.events.len()
            || outcome.committed_through_sequence < -1
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(())
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        let outcome = decode_outcome(result)?;
        self.validate_replay(result)?;
        Ok(outcome)
    }
}

impl WalLogicalDomainLedger<MediaReferenceBatchPlan> for MediaReferenceBatchLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<MediaReferenceBatchPlan>,
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
                 FROM archive_v3_wal_media_reference_batch_operations
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
        let kind = WalOperationKind::MediaCaptureEvent;
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
        prepared: &PreparedLogicalMutation<MediaReferenceBatchPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, MAX_ENCODED_REPLAY_RESULT_BYTES)?;

        let kind = WalOperationKind::MediaCaptureEvent;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_media_reference_batch_operations
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
                "UPDATE archive_v3_wal_media_reference_batch_state
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

fn require_kind(prepared: &PreparedLogicalMutation<MediaReferenceBatchPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::MediaCaptureEvent)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn map_domain_error(error: EnclaveError) -> WalIdempotencyError {
    match error {
        EnclaveError::CaptureReference(_)
        | EnclaveError::CaptureReferenceBatch { .. }
        | EnclaveError::Conflict(_)
        | EnclaveError::NotFound => WalIdempotencyError::Precondition,
        EnclaveError::InvalidRequest(_) | EnclaveError::Json(_) => WalIdempotencyError::Corrupt,
        EnclaveError::Db(_)
        | EnclaveError::Crypto(_)
        | EnclaveError::Store(_)
        | EnclaveError::Kms(_)
        | EnclaveError::Gcs(_)
        | EnclaveError::Http(_)
        | EnclaveError::Io(_)
        | EnclaveError::Attestation(_)
        | EnclaveError::Auth(_)
        | EnclaveError::Embedding(_)
        | EnclaveError::Config(_)
        | EnclaveError::SignupLimited
        | EnclaveError::DeletionPending(_)
        // ADR-0022 D4: a deferred domain is unavailable, never corrupt and
        // never a definitive precondition failure -- it stays retryable.
        | EnclaveError::WalDomainUnmigrated(_) => WalIdempotencyError::Unavailable,
    }
}

fn encode_outcome(outcome: &MediaReferenceBatchOutcome) -> Result<WalReplayResult> {
    let batch_length =
        u16::try_from(outcome.batch_id.len()).map_err(|_| WalIdempotencyError::Limit)?;
    let stream_length =
        u16::try_from(outcome.stream_id.len()).map_err(|_| WalIdempotencyError::Limit)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(RESULT_REFERENCE_BATCH);
    bytes.extend_from_slice(&batch_length.to_be_bytes());
    bytes.extend_from_slice(outcome.batch_id.as_bytes());
    bytes.extend_from_slice(&stream_length.to_be_bytes());
    bytes.extend_from_slice(outcome.stream_id.as_bytes());
    bytes.extend_from_slice(&outcome.first_sequence.to_be_bytes());
    bytes.extend_from_slice(&outcome.last_sequence.to_be_bytes());
    bytes.extend_from_slice(&outcome.new_count.to_be_bytes());
    bytes.extend_from_slice(&outcome.duplicate_count.to_be_bytes());
    bytes.extend_from_slice(&outcome.committed_through_sequence.to_be_bytes());
    WalReplayResult::canonical_response(WalOperationKind::MediaCaptureEvent, bytes)
}

fn decode_outcome(result: &WalReplayResult) -> Result<MediaReferenceBatchOutcome> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    let mut reader = ResultReader::new(bytes);
    if reader.take_u16()? != RESULT_V1 || reader.take_u8()? != RESULT_REFERENCE_BATCH {
        return Err(WalIdempotencyError::Corrupt);
    }
    let batch_id = reader.take_string()?;
    let stream_id = reader.take_string()?;
    let first_sequence = reader.take_i64()?;
    let last_sequence = reader.take_i64()?;
    let new_count = reader.take_u16()?;
    let duplicate_count = reader.take_u16()?;
    let committed_through_sequence = reader.take_i64()?;
    if !reader.is_empty()
        || batch_id.len() != 64
        || !batch_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || super::super::validate_id("stream_id", &stream_id).is_err()
        || first_sequence < 0
        || last_sequence < first_sequence
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(MediaReferenceBatchOutcome {
        batch_id,
        stream_id,
        first_sequence,
        last_sequence,
        new_count,
        duplicate_count,
        committed_through_sequence,
    })
}

struct ResultReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ResultReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WalIdempotencyError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(WalIdempotencyError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(WalIdempotencyError::Corrupt)
    }

    fn take_u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn take_i64(&mut self) -> Result<i64> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn take_string(&mut self) -> Result<String> {
        let length = usize::from(self.take_u16()?);
        let value =
            std::str::from_utf8(self.take(length)?).map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(value.to_owned())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3)",
            params![SCHEMA_TABLE, LEDGER_TABLE, STATE_TABLE],
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
                    "CREATE TABLE archive_v3_wal_media_reference_batch_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_media_reference_batch_operations (
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
                     CREATE TABLE archive_v3_wal_media_reference_batch_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 536870912)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_media_reference_batch_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_media_reference_batch_state
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
             FROM archive_v3_wal_media_reference_batch_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::MediaCaptureEvent.codec_version()),
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
             FROM archive_v3_wal_media_reference_batch_state WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let row_count = u32::try_from(state.0).map_err(|_| WalIdempotencyError::Corrupt)?;
    let result_bytes = u64::try_from(state.1).map_err(|_| WalIdempotencyError::Corrupt)?;
    if row_count > MAX_ROWS || result_bytes > MAX_RESULT_BYTES {
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
    use crate::cp::media::{MediaDisposition, ScreenReferenceDescriptor};
    use rusqlite::Connection;
    use serde_json::json;

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        super::super::super::init_schema(&connection).unwrap();
        connection
    }

    fn operation_id(value: u8) -> WalLogicalOperationId {
        WalLogicalOperationId::from_bytes([value; 16]).unwrap()
    }

    fn canonical_manifest() -> CaptureEventManifest {
        serde_json::from_value(json!({
            "schema_version": 2,
            "event_id": "screen-event-0",
            "device_id": "device-1",
            "install_id": "install-1",
            "capture_session_id": "session-1",
            "stream_id": "screen-1",
            "stream_kind": "mac_screen",
            "sequence": 0,
            "source_wall_at": "2026-07-31T18:00:00.000Z",
            "source_monotonic_ns": 9_000_000_000_u64,
            "started_at": "2026-07-31T18:00:00.000Z",
            "ended_at": "2026-07-31T18:00:02.000Z",
            "timezone_id": "America/New_York",
            "utc_offset_minutes": -240,
            "clock_uncertainty_ms": 24,
            "media": {
                "asset_id": "screen-asset-0",
                "mime_type": "image/jpeg",
                "codec": "jpeg",
                "byte_length": 12,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "width": 1280,
                "height": 720
            },
            "context": {
                "capture_status": "stable",
                "active_app": "Google Chrome",
                "primary_bundle_id": "com.google.Chrome",
                "primary_window_id": 9,
                "window_title": "Weekly planning",
                "display_id": 42,
                "active_url": "https://meet.google.com/abc-defg-hij?authuser=0",
                "active_url_title": "Weekly planning",
                "browser_permission_status": "granted",
                "visible_windows": [{"bundle_id":"com.google.Chrome","window_id":9}],
                "visible_windows_truncated": false
            }
        }))
        .unwrap()
    }

    fn reference_to(
        canonical: &CaptureEventManifest,
        sequence: i64,
        event_id: &str,
    ) -> CaptureEventManifest {
        let mut reference = canonical.clone();
        let media = canonical.media.as_ref().unwrap();
        let context = canonical.context.as_ref().unwrap();
        reference.event_id = event_id.to_owned();
        reference.sequence = sequence;
        reference.source_monotonic_ns = reference
            .source_monotonic_ns
            .checked_add(u64::try_from(sequence).unwrap() + 1)
            .unwrap();
        reference.media_disposition = MediaDisposition::Reference;
        reference.media = None;
        reference.reference = Some(ScreenReferenceDescriptor {
            canonical_event_id: canonical.event_id.clone(),
            canonical_asset_id: media.asset_id.clone(),
            canonical_media_sha256: media.sha256.clone(),
            perceptual_hash: "0123456789abcdef".to_owned(),
            hamming_distance: 2,
            pixel_change_ratio: 0.004,
            context_fingerprint: super::super::super::semantic_context_fingerprint(context, 1)
                .unwrap(),
            dedupe_version: 1,
        });
        reference
    }

    fn insert_canonical(connection: &Connection, canonical: &CaptureEventManifest) {
        super::super::super::record_source_event(
            connection,
            "account-1",
            canonical,
            &super::super::super::manifest_digest(canonical).unwrap(),
            "object-0",
        )
        .unwrap();
    }

    fn plan(events: Vec<CaptureEventManifest>) -> MediaReferenceBatchPlan {
        let batch_id = super::super::super::reference_batch_id(&events).unwrap();
        MediaReferenceBatchPlan::new("account-1".to_owned(), batch_id, events).unwrap()
    }

    fn forced_plan(value: u8, events: Vec<CaptureEventManifest>) -> MediaReferenceBatchPlan {
        let batch_id = super::super::super::reference_batch_id(&events).unwrap();
        MediaReferenceBatchPlan::with_operation_id(
            operation_id(value),
            "account-1",
            batch_id,
            events,
        )
        .unwrap()
    }

    #[test]
    fn stable_batch_identity_is_kind_scoped_and_request_covers_normalized_manifests() {
        let canonical = canonical_manifest();
        let events = vec![
            reference_to(&canonical, 1, "screen-event-1"),
            reference_to(&canonical, 2, "screen-event-2"),
        ];
        let one = plan(events.clone());
        let replay = plan(events.clone());
        assert_eq!(one.operation_id(), replay.operation_id());
        assert_eq!(
            one.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(
            one.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::CaptureSessionFinish,
                one.batch_id.as_bytes(),
            )
            .unwrap()
        );
        assert_ne!(
            one.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::MediaCaptureEvent,
                one.batch_id.as_bytes(),
            )
            .unwrap(),
            "the batch subtype must not collide with a future singular capture event"
        );

        let mut changed = events;
        changed[1].context.as_mut().unwrap().window_title = Some("Changed".to_owned());
        changed[1].reference.as_mut().unwrap().context_fingerprint =
            super::super::super::semantic_context_fingerprint(
                changed[1].context.as_ref().unwrap(),
                1,
            )
            .unwrap();
        let changed = plan(changed);
        assert_eq!(one.operation_id(), changed.operation_id());
        assert_ne!(
            one.canonical_request().unwrap(),
            changed.canonical_request().unwrap()
        );
    }

    #[test]
    fn normalized_batch_request_is_bounded_before_actor_admission() {
        let canonical = canonical_manifest();
        let mut events = Vec::new();
        for sequence in 1..=9 {
            let mut event = reference_to(&canonical, sequence, &format!("screen-event-{sequence}"));
            event.context.as_mut().unwrap().visible_windows = Some(json!("x".repeat(120_000)));
            event.reference.as_mut().unwrap().context_fingerprint =
                super::super::super::semantic_context_fingerprint(
                    event.context.as_ref().unwrap(),
                    1,
                )
                .unwrap();
            events.push(event);
        }
        let error = PreparedLogicalMutation::prepare(plan(events))
            .err()
            .unwrap();
        assert_eq!(error, WalIdempotencyError::Limit);
    }

    #[test]
    fn applies_mixed_batch_once_and_replays_exact_response_without_writes() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let first = reference_to(&canonical, 1, "screen-event-1");
        let second = reference_to(&canonical, 2, "screen-event-2");
        super::super::super::record_reference_event(
            &connection,
            "account-1",
            &first,
            &super::super::super::manifest_digest(&first).unwrap(),
        )
        .unwrap();
        let events = vec![first, second];
        let batch_id = super::super::super::reference_batch_id(&events).unwrap();
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(events.clone())).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        let outcome = applied.into_validated_result().release().unwrap();
        assert_eq!(outcome.batch_id(), batch_id);
        assert_eq!(outcome.stream_id(), "screen-1");
        assert_eq!((outcome.first_sequence(), outcome.last_sequence()), (1, 2));
        assert_eq!((outcome.new_count(), outcome.duplicate_count()), (1, 1));
        assert_eq!(outcome.committed_through_sequence(), 2);

        let changes = connection.total_changes();
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(events)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(replay.into_validated_result().release().unwrap(), outcome);
        assert_eq!(connection.total_changes(), changes);
    }

    #[test]
    fn missing_canonical_rolls_back_schema_and_later_same_identity_applies() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        let events = vec![reference_to(&canonical, 1, "screen-event-1")];
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(events.clone())).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name=?1",
                    [LEDGER_TABLE],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        insert_canonical(&connection, &canonical);
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(events)).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
    }

    #[test]
    fn same_stable_batch_id_with_changed_manifest_conflicts_before_event_sql() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let first = vec![reference_to(&canonical, 1, "screen-event-1")];
        let mut changed = first.clone();
        changed[0].context.as_mut().unwrap().window_title = Some("Changed".to_owned());
        changed[0].reference.as_mut().unwrap().context_fingerprint =
            super::super::super::semantic_context_fingerprint(
                changed[0].context.as_ref().unwrap(),
                1,
            )
            .unwrap();
        assert_eq!(
            super::super::super::reference_batch_id(&first).unwrap(),
            super::super::super::reference_batch_id(&changed).unwrap()
        );
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(first)).unwrap(),
        )
        .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(changed)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::FingerprintConflict);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE media_disposition='reference'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn row_cap_rejects_before_batch_mutation_but_committed_replay_survives() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let first = vec![reference_to(&canonical, 1, "screen-event-1")];
        let blocked = vec![reference_to(&canonical, 2, "screen-event-2")];
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(8, first.clone())).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_media_reference_batch_state SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(8, first)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(9, blocked)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Limit);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='screen-event-2'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn result_byte_cap_rejects_before_batch_mutation() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let first = vec![reference_to(&canonical, 1, "screen-event-1")];
        let blocked = vec![reference_to(&canonical, 2, "screen-event-2")];
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(10, first)).unwrap(),
        )
        .unwrap();
        let insufficient_capacity =
            MAX_RESULT_BYTES - u64::try_from(MAX_ENCODED_REPLAY_RESULT_BYTES).unwrap() + 1;
        connection
            .execute(
                "UPDATE archive_v3_wal_media_reference_batch_state SET result_bytes=?1",
                [i64::try_from(insufficient_capacity).unwrap()],
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(11, blocked)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Limit);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE event_id='screen-event-2'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_every_reference_and_ack_advance() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let transaction = connection.unchecked_transaction().unwrap();
        ensure_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_reference_batch_ledger
                 BEFORE INSERT ON archive_v3_wal_media_reference_batch_operations
                 BEGIN SELECT RAISE(ABORT,'reject'); END;",
            )
            .unwrap();
        let events = vec![
            reference_to(&canonical, 1, "screen-event-1"),
            reference_to(&canonical, 2, "screen-event-2"),
        ];
        assert!(execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(12, events)).unwrap(),
        )
        .is_err());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE media_disposition='reference'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            super::super::super::committed_through_sequence(&connection, "screen-1").unwrap(),
            0
        );
    }

    #[test]
    fn invalid_middle_reference_rolls_back_prefix_without_consuming_identity() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let first = reference_to(&canonical, 1, "screen-event-1");
        let mut invalid = reference_to(&canonical, 2, "screen-event-2");
        invalid.reference.as_mut().unwrap().canonical_event_id = "missing-event".to_owned();
        let events = vec![first, invalid];
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(13, events)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM capture_events WHERE media_disposition='reference'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name=?1",
                    [LEDGER_TABLE],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn reopened_database_replays_exact_batch_and_admits_next_batch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reference-batch.db");
        let canonical = canonical_manifest();
        let first = vec![reference_to(&canonical, 1, "screen-event-1")];
        let expected = {
            let mut connection = Connection::open(&path).unwrap();
            super::super::super::init_schema(&connection).unwrap();
            insert_canonical(&connection, &canonical);
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(forced_plan(14, first.clone())).unwrap(),
            )
            .unwrap()
            .into_validated_result()
            .release()
            .unwrap()
        };
        let mut reopened = Connection::open(&path).unwrap();
        let changes = reopened.total_changes();
        let replay = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(forced_plan(14, first)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(replay.into_validated_result().release().unwrap(), expected);
        assert_eq!(reopened.total_changes(), changes);

        let next = vec![reference_to(&canonical, 2, "screen-event-2")];
        let applied = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(forced_plan(15, next)).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        assert_eq!(
            applied
                .into_validated_result()
                .release()
                .unwrap()
                .committed_through_sequence(),
            2
        );
    }

    #[test]
    fn partial_schema_and_tampered_result_fail_closed() {
        let mut partial = connection();
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_media_reference_batch_schema (
                    singleton INTEGER PRIMARY KEY,
                    format_version INTEGER,
                    codec_version INTEGER
                 );",
            )
            .unwrap();
        let canonical = canonical_manifest();
        let events = vec![reference_to(&canonical, 1, "screen-event-1")];
        let error = execute_prepared_for_owner(
            &mut partial,
            PreparedLogicalMutation::prepare(forced_plan(16, events)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Corrupt);

        let mut tampered = connection();
        insert_canonical(&tampered, &canonical);
        let events = vec![reference_to(&canonical, 1, "screen-event-1")];
        execute_prepared_for_owner(
            &mut tampered,
            PreparedLogicalMutation::prepare(forced_plan(17, events.clone())).unwrap(),
        )
        .unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_media_reference_batch_operations
                 SET result_bytes=zeroblob(9)",
                [],
            )
            .unwrap();
        assert!(execute_prepared_for_owner(
            &mut tampered,
            PreparedLogicalMutation::prepare(forced_plan(17, events)).unwrap(),
        )
        .is_err());
    }

    /// The pre-existing wedge on the MERGED batch path: a rebase-required
    /// refusal used to collapse into a content-free `Precondition`, the submit
    /// narrowed that to a bare conflict, and the route answered 409 instead of
    /// the documented `400 screen_reference_rebase_required`. The Mac client's
    /// outbox treats a 409 as retryable, so it re-posted an event only a rebase
    /// could fix -- forever. The preflight read the route runs first catches
    /// the ordinary case; this carries the race window between that read and
    /// the submit, which is exactly where the refusal is both possible and
    /// invisible.
    ///
    /// The batch framing (failing item index and sequence) mirrors the legacy
    /// `record_reference_batch` branch byte for byte, so the WAL and legacy
    /// responses for the same refusal are the same response.
    ///
    /// Falsifiability, checked by sabotage: deleting the `self.refusal.record`
    /// call leaves `observed()` as `None` and every assertion after the
    /// `Precondition` one fails -- which is why the `Precondition` assertion
    /// alone was never enough to catch this.
    #[test]
    fn a_rebase_required_refusal_reaches_the_route_with_its_index_and_sequence() {
        use crate::error::CaptureReferenceFailureReason;

        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let good = reference_to(&canonical, 1, "screen-event-1");
        let mut bad = reference_to(&canonical, 2, "screen-event-2");
        bad.reference.as_mut().unwrap().canonical_media_sha256 = "b".repeat(64);

        let plan = plan(vec![good, bad]);
        let refusal = plan.refusal_sink();
        let prepared = PreparedLogicalMutation::prepare(plan).unwrap();
        let error = execute_prepared_for_owner(&mut connection, prepared)
            .err()
            .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);

        let observed = refusal.observed().expect("the reason must reach the route");
        match observed {
            EnclaveError::CaptureReferenceBatch {
                reason,
                index,
                sequence,
            } => {
                assert_eq!(reason, CaptureReferenceFailureReason::TargetMismatch);
                assert_eq!(index, 1, "the failing item's position");
                assert_eq!(sequence, 2, "the failing item's sequence");
            }
            other => panic!("expected a batch rebase refusal, got {other:?}"),
        }
        let response = axum::response::IntoResponse::into_response(
            refusal.observed().expect("still recorded"),
        );
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

        let rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM capture_events WHERE media_disposition='reference'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0, "the refused batch must roll back entirely");
    }

    /// Each event in a batch stamps its OWN rows, so the committed pages stay a
    /// function of the request rather than of wall time.
    #[test]
    fn each_batch_item_binds_its_own_source_wall_at_instead_of_the_live_clock() {
        let mut connection = connection();
        let canonical = canonical_manifest();
        insert_canonical(&connection, &canonical);
        let mut first = reference_to(&canonical, 1, "screen-event-1");
        first.source_wall_at = "2026-07-31T18:00:01.000Z".to_owned();
        let mut second = reference_to(&canonical, 2, "screen-event-2");
        second.source_wall_at = "2026-07-31T18:00:02.000Z".to_owned();

        let prepared = PreparedLogicalMutation::prepare(plan(vec![first, second])).unwrap();
        execute_prepared_for_owner(&mut connection, prepared).unwrap();

        let stamps: Vec<String> = connection
            .prepare(
                "SELECT received_at FROM capture_events \
                 WHERE media_disposition='reference' ORDER BY sequence",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            stamps,
            vec![
                "2026-07-31T18:00:01.000Z".to_owned(),
                "2026-07-31T18:00:02.000Z".to_owned()
            ]
        );
    }
}
