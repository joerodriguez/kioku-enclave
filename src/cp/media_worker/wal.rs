#![allow(
    dead_code,
    reason = "inactive ADR-0022 media-worker codecs are reviewed before their external boundaries, launcher, or worker ownership"
)]

//! Inactive media-worker WAL domains.
//!
//! A future deletion boundary must authenticate and settle the exact retained
//! provider object before constructing this plan. The plan can only mark the
//! matching local media row pruned and retain a permanent exact replay receipt.
//! It cannot read, list, delete, or otherwise reach a provider, call Store,
//! launch work, or acknowledge retention completion. Private B children fix
//! stable screen and audio Vertex attempt identity and billing intent before
//! provider I/O; the private production-facing result children cover only
//! screen storyboards without person evidence and audio-window transcripts
//! without identity rows, each reauthenticating its exact binding before its
//! local mutation. Every person/identity/voice mutation remains unsupported
//! — the audio transcript subtype has no constructor slot for speaker names,
//! person facts, or quality flags and never writes voice tables.

pub(super) mod attempt;
pub(super) mod audio_attempt;
pub(super) mod audio_result;
pub(super) mod reservation;
pub(super) mod result;
pub(super) mod resurrection;
pub(super) mod usage;
pub(crate) use attempt::{ScreenStoryboardAttemptLedger, ScreenStoryboardAttemptPlan};
pub(crate) use audio_attempt::{AudioWindowAttemptLedger, AudioWindowAttemptPlan};
pub(crate) use audio_result::{AudioWindowTranscriptLedger, AudioWindowTranscriptPlan};
pub(crate) use reservation::{MediaWorkReservationLedger, MediaWorkReservationPlan};
pub(crate) use result::{ScreenStoryboardResultLedger, ScreenStoryboardResultPlan};
pub(crate) use resurrection::{MediaJobResurrectionLedger, MediaJobResurrectionPlan};
pub(crate) use usage::{MediaUsageSettlementLedger, MediaUsageSettlementPlan};

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const STATE_READY: u8 = 1;
const STATE_FAILED: u8 = 2;
const BACKEND_UNSPECIFIED: u8 = 0;
const BACKEND_CURRENT: u8 = 1;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_ID_BYTES: usize = 128;
const MAX_OBJECT_KEY_BYTES: usize = 512;
const MAX_TIMESTAMP_BYTES: usize = 64;
const SCHEMA_TABLE: &str = "archive_v3_wal_retention_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_retention_operations";
const STATE_TABLE: &str = "archive_v3_wal_retention_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedProcessingState {
    Ready,
    Failed,
}

impl ExpectedProcessingState {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "ready" => Ok(Self::Ready),
            "failed" => Ok(Self::Failed),
            _ => Err(WalIdempotencyError::Malformed),
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Ready => STATE_READY,
            Self::Failed => STATE_FAILED,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectBackend {
    Unspecified,
    Current,
}

impl ObjectBackend {
    fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None => Ok(Self::Unspecified),
            Some("current") => Ok(Self::Current),
            Some(_) => Err(WalIdempotencyError::Malformed),
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Unspecified => BACKEND_UNSPECIFIED,
            Self::Current => BACKEND_CURRENT,
        }
    }

    const fn as_option(self) -> Option<&'static str> {
        match self {
            Self::Unspecified => None,
            Self::Current => Some("current"),
        }
    }
}

/// Exact local receipt for one provider-settled raw-media retention deletion.
/// The stable account/event identity is fixed before actor admission; all
/// provider facts and the terminal timestamp are part of the fingerprint.
pub(crate) struct RetentionSettlementPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    event_id: String,
    object_key: String,
    object_generation: Option<i64>,
    object_backend: ObjectBackend,
    sha256: String,
    retain_until: String,
    expected_state: ExpectedProcessingState,
    deleted_at: String,
}

impl RetentionSettlementPlan {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        account_id: String,
        event_id: String,
        object_key: String,
        object_generation: Option<i64>,
        object_backend: Option<String>,
        sha256: String,
        retain_until: String,
        expected_state: String,
        deleted_at: String,
    ) -> Result<Self> {
        Self::build(
            None,
            account_id,
            event_id,
            object_key,
            object_generation,
            object_backend,
            sha256,
            retain_until,
            expected_state,
            deleted_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        operation_id: Option<WalLogicalOperationId>,
        account_id: String,
        event_id: String,
        object_key: String,
        object_generation: Option<i64>,
        object_backend: Option<String>,
        sha256: String,
        retain_until: String,
        expected_state: String,
        deleted_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        validate_id(&event_id)?;
        validate_object_key(&account_id, &object_key)?;
        if object_generation.is_some_and(|value| value <= 0) || !valid_lower_hex(&sha256, 64) {
            return Err(WalIdempotencyError::Malformed);
        }
        let object_backend = ObjectBackend::parse(object_backend.as_deref())?;
        if object_backend == ObjectBackend::Current && object_generation.is_none() {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_timestamp(&retain_until)?;
        validate_timestamp(&deleted_at)?;
        if retain_until > deleted_at {
            return Err(WalIdempotencyError::Precondition);
        }
        let expected_state = ExpectedProcessingState::parse(&expected_state)?;
        let operation_id = match operation_id {
            Some(value) => value,
            None => {
                let mut source = Vec::with_capacity(account_id.len() + event_id.len() + 1);
                source.extend_from_slice(account_id.as_bytes());
                source.push(0);
                source.extend_from_slice(event_id.as_bytes());
                WalLogicalOperationId::from_stable_source(WalOperationKind::Retention, &source)?
            }
        };
        Ok(Self {
            operation_id,
            account_id,
            event_id,
            object_key,
            object_generation,
            object_backend,
            sha256,
            retain_until,
            expected_state,
            deleted_at,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        account_id: &str,
        event_id: &str,
        object_key: &str,
        object_generation: Option<i64>,
        object_backend: Option<&str>,
        sha256: &str,
        retain_until: &str,
        expected_state: &str,
        deleted_at: &str,
    ) -> Result<Self> {
        Self::build(
            Some(operation_id),
            account_id.to_owned(),
            event_id.to_owned(),
            object_key.to_owned(),
            object_generation,
            object_backend.map(str::to_owned),
            sha256.to_owned(),
            retain_until.to_owned(),
            expected_state.to_owned(),
            deleted_at.to_owned(),
        )
    }
}

pub(crate) struct RetentionSettlementLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for RetentionSettlementPlan {
    type Ledger = RetentionSettlementLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::Retention
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(1_024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.event_id)?;
        encode_string(&mut request, &self.object_key)?;
        encode_optional_i64(&mut request, self.object_generation)?;
        request.push(self.object_backend.tag());
        request.extend_from_slice(self.sha256.as_bytes());
        encode_string(&mut request, &self.retain_until)?;
        request.push(self.expected_state.tag());
        encode_string(&mut request, &self.deleted_at)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let Some(stored) = load_media_row(transaction, &self.event_id)? else {
            return Err(WalIdempotencyError::Precondition);
        };
        if stored.matches_terminal(self) {
            return Ok(WalReplayResult::unit());
        }
        if !stored.matches_pending(self) {
            return Err(WalIdempotencyError::Precondition);
        }
        let changed = transaction
            .execute(
                "UPDATE media_objects
                 SET processing_state='pruned',deleted_at=?1
                 WHERE event_id=?2 AND object_key=?3
                   AND object_generation IS ?4 AND object_backend IS ?5
                   AND sha256=?6 AND retain_until=?7
                   AND processing_state=?8 AND deleted_at IS NULL",
                params![
                    self.deleted_at,
                    self.event_id,
                    self.object_key,
                    self.object_generation,
                    self.object_backend.as_option(),
                    self.sha256,
                    self.retain_until,
                    self.expected_state.as_str(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(WalReplayResult::unit())
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        match result {
            WalReplayResult::UnitApplied => Ok(()),
            WalReplayResult::CanonicalResponse(_) => Err(WalIdempotencyError::ResultUnsupported),
        }
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)
    }
}

impl WalLogicalDomainLedger<RetentionSettlementPlan> for RetentionSettlementLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<RetentionSettlementPlan>,
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
                 FROM archive_v3_wal_retention_operations
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
        let kind = WalOperationKind::Retention;
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
        prepared: &PreparedLogicalMutation<RetentionSettlementPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::Retention;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_retention_operations
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
        let previous_result_bytes =
            i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_retention_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    previous_result_bytes,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct StoredMediaRow {
    object_key: String,
    object_generation: Option<i64>,
    object_backend: Option<String>,
    sha256: String,
    retain_until: String,
    processing_state: String,
    deleted_at: Option<String>,
}

impl StoredMediaRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            object_key: row.get(0)?,
            object_generation: row.get(1)?,
            object_backend: row.get(2)?,
            sha256: row.get(3)?,
            retain_until: row.get(4)?,
            processing_state: row.get(5)?,
            deleted_at: row.get(6)?,
        })
    }

    fn matches_identity(&self, plan: &RetentionSettlementPlan) -> bool {
        self.object_key == plan.object_key
            && self.object_generation == plan.object_generation
            && self.object_backend.as_deref() == plan.object_backend.as_option()
            && self.sha256 == plan.sha256
            && self.retain_until == plan.retain_until
    }

    fn matches_pending(&self, plan: &RetentionSettlementPlan) -> bool {
        self.matches_identity(plan)
            && self.processing_state == plan.expected_state.as_str()
            && self.deleted_at.is_none()
    }

    fn matches_terminal(&self, plan: &RetentionSettlementPlan) -> bool {
        self.matches_identity(plan)
            && self.processing_state == "pruned"
            && self.deleted_at.as_deref() == Some(plan.deleted_at.as_str())
    }
}

fn load_media_row(connection: &Connection, event_id: &str) -> Result<Option<StoredMediaRow>> {
    connection
        .query_row(
            "SELECT object_key,object_generation,object_backend,sha256,
                    retain_until,processing_state,deleted_at
             FROM media_objects WHERE event_id=?1",
            [event_id],
            StoredMediaRow::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn require_kind(prepared: &PreparedLogicalMutation<RetentionSettlementPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::Retention)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn validate_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_object_key(account_id: &str, value: &str) -> Result<()> {
    let prefix = format!("raw/{account_id}/");
    let asset_id = value
        .strip_prefix(&prefix)
        .and_then(|suffix| suffix.strip_suffix(".enc"));
    if value.len() > MAX_OBJECT_KEY_BYTES
        || value.contains("..")
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        || asset_id.is_none_or(|asset_id| validate_id(asset_id).is_err())
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TIMESTAMP_BYTES {
        return Err(WalIdempotencyError::Malformed);
    }
    let millis =
        super::super::isotime::parse_epoch_millis(value).ok_or(WalIdempotencyError::Malformed)?;
    if super::super::isotime::format_epoch_millis(millis) != value {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u16::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    if length == 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_optional_i64(output: &mut Vec<u8>, value: Option<i64>) -> Result<()> {
    match value {
        None => output.push(0),
        Some(value) if value > 0 => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        Some(_) => return Err(WalIdempotencyError::Malformed),
    }
    Ok(())
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
                    "CREATE TABLE archive_v3_wal_retention_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_retention_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes)=9),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_retention_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_retention_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_retention_state
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
             FROM archive_v3_wal_retention_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::Retention.codec_version()),
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
             FROM archive_v3_wal_retention_state WHERE singleton=1",
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
    use tempfile::tempdir;

    const ACCOUNT: &str = "retention-user";
    const EVENT: &str = "event-0001";
    const KEY: &str = "raw/retention-user/asset-0001.enc";
    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RETAIN_UNTIL: &str = "2026-08-01T00:00:00.000Z";
    const DELETED_AT: &str = "2026-08-14T12:00:00.000Z";

    fn install_domain_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE media_objects (
                    event_id TEXT PRIMARY KEY,
                    object_key TEXT NOT NULL,
                    object_generation INTEGER,
                    object_backend TEXT,
                    sha256 TEXT NOT NULL,
                    retain_until TEXT NOT NULL,
                    processing_state TEXT NOT NULL,
                    deleted_at TEXT
                 ) STRICT;",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_domain_schema(&connection);
        connection
    }

    fn insert_media(connection: &Connection, event_id: &str, state: &str) {
        connection
            .execute(
                "INSERT INTO media_objects
                 (event_id,object_key,object_generation,object_backend,sha256,
                  retain_until,processing_state)
                 VALUES (?1,?2,7,'current',?3,?4,?5)",
                params![event_id, KEY, HASH, RETAIN_UNTIL, state],
            )
            .unwrap();
    }

    fn plan(event_id: &str, state: &str) -> RetentionSettlementPlan {
        RetentionSettlementPlan::new(
            ACCOUNT.into(),
            event_id.into(),
            KEY.into(),
            Some(7),
            Some("current".into()),
            HASH.into(),
            RETAIN_UNTIL.into(),
            state.into(),
            DELETED_AT.into(),
        )
        .unwrap()
    }

    fn explicit_id(value: u8) -> WalLogicalOperationId {
        WalLogicalOperationId::from_bytes([value; 16]).unwrap()
    }

    #[test]
    fn stable_identity_is_kind_scoped_and_request_binds_every_deletion_fact() {
        let first = plan(EVENT, "ready");
        let replay = plan(EVENT, "ready");
        assert_eq!(first.operation_id(), replay.operation_id());
        assert_eq!(
            first.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(
            first.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::VertexUsage,
                format!("{ACCOUNT}\0{EVENT}").as_bytes(),
            )
            .unwrap()
        );
        let changed = RetentionSettlementPlan::new(
            ACCOUNT.into(),
            EVENT.into(),
            KEY.into(),
            Some(8),
            Some("current".into()),
            HASH.into(),
            RETAIN_UNTIL.into(),
            "ready".into(),
            DELETED_AT.into(),
        )
        .unwrap();
        assert_ne!(
            first.canonical_request().unwrap(),
            changed.canonical_request().unwrap()
        );
        assert!(RetentionSettlementPlan::new(
            ACCOUNT.into(),
            EVENT.into(),
            "raw/other/asset.enc".into(),
            Some(7),
            Some("current".into()),
            HASH.into(),
            RETAIN_UNTIL.into(),
            "ready".into(),
            DELETED_AT.into(),
        )
        .is_err());
        assert_eq!(
            RetentionSettlementPlan::new(
                ACCOUNT.into(),
                EVENT.into(),
                KEY.into(),
                Some(7),
                Some("current".into()),
                HASH.into(),
                "2026-08-15T00:00:00.000Z".into(),
                "ready".into(),
                DELETED_AT.into(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
        assert!(RetentionSettlementPlan::new(
            ACCOUNT.into(),
            EVENT.into(),
            "raw/retention-user/nested/asset.enc".into(),
            Some(7),
            Some("current".into()),
            HASH.into(),
            RETAIN_UNTIL.into(),
            "ready".into(),
            DELETED_AT.into(),
        )
        .is_err());
        assert!(RetentionSettlementPlan::new(
            ACCOUNT.into(),
            EVENT.into(),
            KEY.into(),
            None,
            Some("current".into()),
            HASH.into(),
            RETAIN_UNTIL.into(),
            "ready".into(),
            DELETED_AT.into(),
        )
        .is_err());
        assert!(RetentionSettlementPlan::new(
            ACCOUNT.into(),
            EVENT.into(),
            KEY.into(),
            Some(7),
            Some("legacy".into()),
            HASH.into(),
            RETAIN_UNTIL.into(),
            "ready".into(),
            DELETED_AT.into(),
        )
        .is_err());
    }

    #[test]
    fn exact_ready_settlement_applies_once_and_replays_without_rewriting() {
        let mut connection = connection();
        insert_media(&connection, EVENT, "ready");
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        applied.into_validated_result().release().unwrap();
        let stored = load_media_row(&connection, EVENT).unwrap().unwrap();
        assert_eq!(stored.processing_state, "pruned");
        assert_eq!(stored.deleted_at.as_deref(), Some(DELETED_AT));

        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(load_ledger_state(&connection).unwrap(), (1, 9));
    }

    #[test]
    fn failed_media_is_an_explicit_supported_predecessor() {
        let mut connection = connection();
        insert_media(&connection, EVENT, "failed");
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(EVENT, "failed")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            load_media_row(&connection, EVENT)
                .unwrap()
                .unwrap()
                .processing_state,
            "pruned"
        );
    }

    #[test]
    fn missing_precondition_rolls_back_schema_and_same_identity_can_later_apply() {
        let mut connection = connection();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name LIKE 'archive_v3_wal_retention_%'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        insert_media(&connection, EVENT, "ready");
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn substituted_or_ineligible_media_fails_closed() {
        for mutation in [
            "UPDATE media_objects SET object_key='raw/retention-user/other.enc'",
            "UPDATE media_objects SET object_generation=8",
            "UPDATE media_objects SET object_backend=NULL",
            "UPDATE media_objects SET sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
            "UPDATE media_objects SET retain_until='2026-08-02T00:00:00.000Z'",
            "UPDATE media_objects SET processing_state='processing'",
        ] {
            let mut connection = connection();
            insert_media(&connection, EVENT, "ready");
            connection.execute(mutation, []).unwrap();
            assert_eq!(
                execute_prepared_for_owner(
                    &mut connection,
                    PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
                )
                .err()
                .unwrap(),
                WalIdempotencyError::Precondition
            );
        }
    }

    #[test]
    fn exact_preexisting_terminal_is_adopted_but_another_timestamp_is_rejected() {
        let mut adopted = connection();
        insert_media(&adopted, EVENT, "ready");
        adopted
            .execute(
                "UPDATE media_objects SET processing_state='pruned',deleted_at=?1",
                [DELETED_AT],
            )
            .unwrap();
        let result = execute_prepared_for_owner(
            &mut adopted,
            PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
        )
        .unwrap();
        assert_eq!(result.disposition(), LogicalMutationDisposition::Applied);

        let mut conflict = connection();
        insert_media(&conflict, EVENT, "ready");
        conflict
            .execute(
                "UPDATE media_objects SET processing_state='pruned',
                 deleted_at='2026-08-14T12:00:01.000Z'",
                [],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut conflict,
                PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
    }

    #[test]
    fn row_and_byte_caps_precede_domain_mutation_but_existing_replay_survives() {
        let mut connection = connection();
        insert_media(&connection, EVENT, "ready");
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_retention_state SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        let next_event = "event-0002";
        insert_media(&connection, next_event, "ready");
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(next_event, "ready")).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            load_media_row(&connection, next_event)
                .unwrap()
                .unwrap()
                .processing_state,
            "ready"
        );
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );

        connection
            .execute(
                "UPDATE archive_v3_wal_retention_state
                 SET row_count=1,result_bytes=?1",
                [i64::try_from(MAX_RESULT_BYTES).unwrap()],
            )
            .unwrap();
        let third_event = "event-0003";
        insert_media(&connection, third_event, "failed");
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(third_event, "failed")).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Limit
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_retention_settlement() {
        let mut connection = connection();
        {
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_retention_wal_insert
                 BEFORE INSERT ON archive_v3_wal_retention_operations
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        insert_media(&connection, EVENT, "ready");
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Unavailable
        );
        let stored = load_media_row(&connection, EVENT).unwrap().unwrap();
        assert_eq!(stored.processing_state, "ready");
        assert_eq!(stored.deleted_at, None);
        assert_eq!(load_ledger_state(&connection).unwrap(), (0, 0));
    }

    #[test]
    fn changed_same_attempt_conflicts_and_tampered_result_fails_closed() {
        let mut connection = connection();
        insert_media(&connection, EVENT, "ready");
        let fixed = || {
            RetentionSettlementPlan::with_operation_id(
                explicit_id(9),
                ACCOUNT,
                EVENT,
                KEY,
                Some(7),
                Some("current"),
                HASH,
                RETAIN_UNTIL,
                "ready",
                DELETED_AT,
            )
            .unwrap()
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(fixed()).unwrap(),
        )
        .unwrap();
        let changed = RetentionSettlementPlan::with_operation_id(
            explicit_id(9),
            ACCOUNT,
            EVENT,
            KEY,
            Some(7),
            Some("current"),
            HASH,
            RETAIN_UNTIL,
            "ready",
            "2026-08-14T12:00:01.000Z",
        )
        .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(changed).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::FingerprintConflict
        );
        connection
            .execute(
                "UPDATE archive_v3_wal_retention_operations SET result_commitment=?1",
                [[7u8; 32].as_slice()],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(fixed()).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn close_reopen_replays_exactly_and_admits_new_retention_row() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("retention.sqlite");
        {
            let mut connection = Connection::open(&path).unwrap();
            install_domain_schema(&connection);
            insert_media(&connection, EVENT, "ready");
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
            )
            .unwrap();
        }
        let mut reopened = Connection::open(&path).unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut reopened,
                PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        let next_event = "event-0004";
        insert_media(&reopened, next_event, "failed");
        assert_eq!(
            execute_prepared_for_owner(
                &mut reopened,
                PreparedLogicalMutation::prepare(plan(next_event, "failed")).unwrap(),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(load_ledger_state(&reopened).unwrap(), (2, 18));
    }

    #[test]
    fn partial_schema_is_rejected() {
        let mut connection = connection();
        connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_retention_schema (
                    singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        insert_media(&connection, EVENT, "ready");
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan(EVENT, "ready")).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );
    }
}
