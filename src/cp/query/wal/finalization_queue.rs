//! Inactive exact finalization-queue WAL domain.
//!
//! A future owner supplies a caller-stable queue request plus the complete
//! authenticated predecessor row. This child can only reset that exact
//! eligible episode to `queued` in the same transaction as permanent replay.
//! It cannot allocate an identity, schedule or launch finalization, mutate a
//! retry after the queue transition, call Store, or acknowledge a request.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"finalization-queue-v1";
// Codec v1 is permanently bound to finalization v5. A later product version
// must receive an explicit codec review instead of silently changing replay.
const TARGET_VERSION: i32 = 5;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const MAX_UUID_BYTES: usize = 36;
const MAX_QUEUE_ID_BYTES: usize = 32;
const MAX_ERROR_CHARS: usize = 1_000;
const MAX_ERROR_BYTES: usize = MAX_ERROR_CHARS * 4;
const MAX_TIMESTAMP_BYTES: usize = 64;
const SCHEMA_TABLE: &str = "archive_v3_wal_finalization_queue_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_finalization_queue_operations";
const STATE_TABLE: &str = "archive_v3_wal_finalization_queue_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum EligibleStatus {
    PendingHorizon,
    PendingCursor,
    PendingWatermark,
    RetryWait,
    BudgetWait,
    FailedTerminal,
    Complete,
}

impl EligibleStatus {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending_horizon" => Ok(Self::PendingHorizon),
            "pending_cursor" => Ok(Self::PendingCursor),
            "pending_watermark" => Ok(Self::PendingWatermark),
            "retry_wait" => Ok(Self::RetryWait),
            "budget_wait" => Ok(Self::BudgetWait),
            "failed_terminal" => Ok(Self::FailedTerminal),
            "complete" => Ok(Self::Complete),
            _ => Err(WalIdempotencyError::Precondition),
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::PendingHorizon => 1,
            Self::PendingCursor => 2,
            Self::PendingWatermark => 3,
            Self::RetryWait => 4,
            Self::BudgetWait => 5,
            Self::FailedTerminal => 6,
            Self::Complete => 7,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::PendingHorizon => "pending_horizon",
            Self::PendingCursor => "pending_cursor",
            Self::PendingWatermark => "pending_watermark",
            Self::RetryWait => "retry_wait",
            Self::BudgetWait => "budget_wait",
            Self::FailedTerminal => "failed_terminal",
            Self::Complete => "complete",
        }
    }
}

/// Complete exact predecessor for one user-requested queue transition.
/// Content-bearing error text stays private and is retained only in the
/// transient canonical request buffer and its fixed digest.
pub(super) struct FinalizationQueuePredecessor {
    substance: String,
    finalized_at: Option<String>,
    finalization_version: Option<i32>,
    status: EligibleStatus,
    error: Option<String>,
    attempted_at: Option<String>,
    attempt_count: i64,
    next_attempt_at: Option<String>,
    updated_at: Option<String>,
}

impl FinalizationQueuePredecessor {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        substance: String,
        finalized_at: Option<String>,
        finalization_version: Option<i32>,
        status: String,
        error: Option<String>,
        attempted_at: Option<String>,
        attempt_count: i64,
        next_attempt_at: Option<String>,
        updated_at: Option<String>,
    ) -> Result<Self> {
        if !matches!(substance.as_str(), "low" | "normal")
            || finalization_version.is_some_and(|version| version <= 0)
            || attempt_count < 0
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if let Some(value) = finalized_at.as_deref() {
            validate_timestamp(value)?;
        }
        if let Some(value) = error.as_deref() {
            validate_error(value)?;
        }
        for value in [
            attempted_at.as_deref(),
            next_attempt_at.as_deref(),
            updated_at.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_timestamp(value)?;
        }
        let status = EligibleStatus::parse(&status)?;
        if finalized_at.is_some() && finalization_version.unwrap_or(1) >= TARGET_VERSION {
            return Err(WalIdempotencyError::Precondition);
        }
        Ok(Self {
            substance,
            finalized_at,
            finalization_version,
            status,
            error,
            attempted_at,
            attempt_count,
            next_attempt_at,
            updated_at,
        })
    }
}

/// One caller-stable queue request. The request ID is fixed outside this child
/// before actor admission and may never be generated from a clock, retry
/// counter, random source, or database lookup here.
pub(crate) struct FinalizationQueuePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    queue_request_id: String,
    episode_id: i64,
    queued_at: String,
    predecessor: FinalizationQueuePredecessor,
}

impl FinalizationQueuePlan {
    pub(super) fn new(
        account_id: String,
        queue_request_id: String,
        episode_id: i64,
        queued_at: String,
        predecessor: FinalizationQueuePredecessor,
    ) -> Result<Self> {
        validate_uuid(&account_id)?;
        if !valid_lower_hex(&queue_request_id, MAX_QUEUE_ID_BYTES) || episode_id <= 0 {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_canonical_timestamp(&queued_at)?;
        let queued_millis = timestamp_millis(&queued_at)?;
        for predecessor_time in [
            predecessor.finalized_at.as_deref(),
            predecessor.attempted_at.as_deref(),
            predecessor.updated_at.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if timestamp_millis(predecessor_time)? > queued_millis {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        let mut source =
            Vec::with_capacity(SUBTYPE.len() + account_id.len() + queue_request_id.len() + 2);
        source.extend_from_slice(SUBTYPE);
        source.push(0);
        source.extend_from_slice(account_id.as_bytes());
        source.push(0);
        source.extend_from_slice(queue_request_id.as_bytes());
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::FinalizationQueue,
            &source,
        )?;
        Ok(Self {
            operation_id,
            account_id,
            queue_request_id,
            episode_id,
            queued_at,
            predecessor,
        })
    }
}

pub(crate) struct FinalizationQueueLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for FinalizationQueuePlan {
    type Ledger = FinalizationQueueLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::FinalizationQueue
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(2_048));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.queue_request_id)?;
        request.extend_from_slice(&self.episode_id.to_be_bytes());
        request.extend_from_slice(&TARGET_VERSION.to_be_bytes());
        encode_string(&mut request, &self.queued_at)?;
        encode_string(&mut request, &self.predecessor.substance)?;
        encode_optional_string(&mut request, self.predecessor.finalized_at.as_deref())?;
        encode_optional_i32(&mut request, self.predecessor.finalization_version);
        request.push(self.predecessor.status.tag());
        encode_optional_text(&mut request, self.predecessor.error.as_deref())?;
        encode_optional_string(&mut request, self.predecessor.attempted_at.as_deref())?;
        request.extend_from_slice(&self.predecessor.attempt_count.to_be_bytes());
        encode_optional_string(&mut request, self.predecessor.next_attempt_at.as_deref())?;
        encode_optional_string(&mut request, self.predecessor.updated_at.as_deref())?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let Some(stored) = load_episode_row(transaction, self.episode_id)? else {
            return Err(WalIdempotencyError::Precondition);
        };
        if !stored.matches_predecessor(&self.predecessor) {
            return Err(WalIdempotencyError::Precondition);
        }
        let changed = transaction
            .execute(
                "UPDATE episodes
                 SET finalization_status='queued',finalization_error=NULL,
                     finalization_attempt_count=0,finalization_next_attempt_at=NULL,
                     updated_at=?11
                 WHERE id=?1 AND substance=?2 AND finalized_at IS ?3
                   AND finalization_version IS ?4 AND finalization_status=?5
                   AND finalization_error IS ?6 AND finalization_attempted_at IS ?7
                   AND finalization_attempt_count=?8
                   AND finalization_next_attempt_at IS ?9 AND updated_at IS ?10",
                params![
                    self.episode_id,
                    self.predecessor.substance,
                    self.predecessor.finalized_at,
                    self.predecessor.finalization_version,
                    self.predecessor.status.as_str(),
                    self.predecessor.error,
                    self.predecessor.attempted_at,
                    self.predecessor.attempt_count,
                    self.predecessor.next_attempt_at,
                    self.predecessor.updated_at,
                    self.queued_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        let queued =
            load_episode_row(transaction, self.episode_id)?.ok_or(WalIdempotencyError::Corrupt)?;
        if !queued.matches_queued(&self.predecessor, &self.queued_at) {
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

impl WalLogicalDomainLedger<FinalizationQueuePlan> for FinalizationQueueLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<FinalizationQueuePlan>,
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
                 FROM archive_v3_wal_finalization_queue_operations
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
        let kind = WalOperationKind::FinalizationQueue;
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
        prepared: &PreparedLogicalMutation<FinalizationQueuePlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::FinalizationQueue;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_finalization_queue_operations
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
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_finalization_queue_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

struct StoredEpisodeRow {
    substance: String,
    finalized_at: Option<String>,
    finalization_version: Option<i32>,
    status: String,
    error: Option<String>,
    attempted_at: Option<String>,
    attempt_count: i64,
    next_attempt_at: Option<String>,
    updated_at: Option<String>,
}

impl StoredEpisodeRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            substance: row.get(0)?,
            finalized_at: row.get(1)?,
            finalization_version: row.get(2)?,
            status: row.get(3)?,
            error: row.get(4)?,
            attempted_at: row.get(5)?,
            attempt_count: row.get(6)?,
            next_attempt_at: row.get(7)?,
            updated_at: row.get(8)?,
        })
    }

    fn matches_predecessor(&self, predecessor: &FinalizationQueuePredecessor) -> bool {
        self.substance == predecessor.substance
            && self.finalized_at == predecessor.finalized_at
            && self.finalization_version == predecessor.finalization_version
            && self.status == predecessor.status.as_str()
            && self.error == predecessor.error
            && self.attempted_at == predecessor.attempted_at
            && self.attempt_count == predecessor.attempt_count
            && self.next_attempt_at == predecessor.next_attempt_at
            && self.updated_at == predecessor.updated_at
    }

    fn matches_queued(&self, predecessor: &FinalizationQueuePredecessor, queued_at: &str) -> bool {
        self.substance == predecessor.substance
            && self.finalized_at == predecessor.finalized_at
            && self.finalization_version == predecessor.finalization_version
            && self.status == "queued"
            && self.error.is_none()
            && self.attempted_at == predecessor.attempted_at
            && self.attempt_count == 0
            && self.next_attempt_at.is_none()
            && self.updated_at.as_deref() == Some(queued_at)
    }
}

fn load_episode_row(connection: &Connection, episode_id: i64) -> Result<Option<StoredEpisodeRow>> {
    connection
        .query_row(
            "SELECT substance,finalized_at,finalization_version,finalization_status,
                    finalization_error,finalization_attempted_at,
                    finalization_attempt_count,finalization_next_attempt_at,updated_at
             FROM episodes WHERE id=?1",
            [episode_id],
            StoredEpisodeRow::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn require_kind(prepared: &PreparedLogicalMutation<FinalizationQueuePlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::FinalizationQueue)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn valid_lower_hex(value: &str, exact_length: usize) -> bool {
    value.len() == exact_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_uuid(value: &str) -> Result<()> {
    if value.len() != MAX_UUID_BYTES
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_error(value: &str) -> Result<()> {
    if value.chars().count() > MAX_ERROR_CHARS
        || value.len() > MAX_ERROR_BYTES
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn valid_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TIMESTAMP_BYTES
        && !value.bytes().any(|byte| byte == 0)
        && super::super::super::isotime::parse_epoch_millis(value).is_some()
}

fn timestamp_millis(value: &str) -> Result<i64> {
    super::super::super::isotime::parse_epoch_millis(value).ok_or(WalIdempotencyError::Malformed)
}

fn validate_timestamp(value: &str) -> Result<()> {
    valid_timestamp(value)
        .then_some(())
        .ok_or(WalIdempotencyError::Malformed)
}

fn validate_canonical_timestamp(value: &str) -> Result<()> {
    validate_timestamp(value)?;
    let millis = timestamp_millis(value)?;
    if super::super::super::isotime::format_epoch_millis(millis) != value {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u16::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    if length == 0 {
        return Err(WalIdempotencyError::Malformed);
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    encode_bytes(output, value.as_bytes())
}

fn encode_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            encode_string(output, value)?;
        }
    }
    Ok(())
}

fn encode_optional_text(output: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            let length = u16::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(value.as_bytes());
        }
    }
    Ok(())
}

fn encode_optional_i32(output: &mut Vec<u8>, value: Option<i32>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
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
                    "CREATE TABLE archive_v3_wal_finalization_queue_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_finalization_queue_operations (
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
                     CREATE TABLE archive_v3_wal_finalization_queue_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_finalization_queue_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_finalization_queue_state
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
             FROM archive_v3_wal_finalization_queue_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::FinalizationQueue.codec_version()),
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
             FROM archive_v3_wal_finalization_queue_state WHERE singleton=1",
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

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const ACCOUNT_TWO: &str = "22222222-2222-4222-8222-222222222222";
    const QUEUE_ONE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const QUEUE_TWO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ATTEMPTED_AT: &str = "2026-08-15T12:00:00.000Z";
    const NEXT_AT: &str = "2026-08-15T13:00:00.000Z";
    const UPDATED_AT: &str = "2026-08-15T12:01:00.000Z";
    const QUEUED_AT: &str = "2026-08-15T12:02:00.000Z";

    fn install_domain_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE episodes (
                    id INTEGER PRIMARY KEY,
                    substance TEXT NOT NULL,
                    finalized_at TEXT,
                    finalization_version INTEGER,
                    finalization_status TEXT NOT NULL,
                    finalization_error TEXT,
                    finalization_attempted_at TEXT,
                    finalization_attempt_count INTEGER NOT NULL,
                    finalization_next_attempt_at TEXT,
                    updated_at TEXT
                 ) STRICT;",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_domain_schema(&connection);
        connection
    }

    #[allow(clippy::too_many_arguments)]
    fn seed(
        connection: &Connection,
        id: i64,
        substance: &str,
        finalized_at: Option<&str>,
        version: Option<i32>,
        status: &str,
        error: Option<&str>,
        attempted_at: Option<&str>,
        attempt_count: i64,
        next_attempt_at: Option<&str>,
        updated_at: Option<&str>,
    ) {
        connection
            .execute(
                "INSERT INTO episodes
                 (id,substance,finalized_at,finalization_version,
                  finalization_status,finalization_error,finalization_attempted_at,
                  finalization_attempt_count,finalization_next_attempt_at,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    id,
                    substance,
                    finalized_at,
                    version,
                    status,
                    error,
                    attempted_at,
                    attempt_count,
                    next_attempt_at,
                    updated_at,
                ],
            )
            .unwrap();
    }

    fn seed_default(connection: &Connection, id: i64) {
        seed(
            connection,
            id,
            "normal",
            None,
            None,
            "retry_wait",
            Some("provider unavailable"),
            Some(ATTEMPTED_AT),
            2,
            Some(NEXT_AT),
            Some(UPDATED_AT),
        );
    }

    fn predecessor(status: &str) -> FinalizationQueuePredecessor {
        FinalizationQueuePredecessor::new(
            "normal".into(),
            None,
            None,
            status.into(),
            Some("provider unavailable".into()),
            Some(ATTEMPTED_AT.into()),
            2,
            Some(NEXT_AT.into()),
            Some(UPDATED_AT.into()),
        )
        .unwrap()
    }

    fn plan(
        queue_id: &str,
        episode_id: i64,
        predecessor: FinalizationQueuePredecessor,
    ) -> FinalizationQueuePlan {
        FinalizationQueuePlan::new(
            ACCOUNT.into(),
            queue_id.into(),
            episode_id,
            QUEUED_AT.into(),
            predecessor,
        )
        .unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: FinalizationQueuePlan,
    ) -> std::result::Result<
        crate::archive_v3_wal_idempotency::ExecutedLogicalMutation<FinalizationQueuePlan>,
        WalIdempotencyError,
    > {
        execute_prepared_for_owner(connection, PreparedLogicalMutation::prepare(plan).unwrap())
    }

    #[test]
    fn stable_identity_is_account_and_caller_request_bound() {
        let first = plan(QUEUE_ONE, 1, predecessor("retry_wait"));
        let replay = plan(QUEUE_ONE, 1, predecessor("retry_wait"));
        assert_eq!(first.operation_id(), replay.operation_id());
        assert_eq!(
            first.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(
            first.operation_id(),
            plan(QUEUE_TWO, 1, predecessor("retry_wait")).operation_id()
        );
        let changed_time = FinalizationQueuePlan::new(
            ACCOUNT.into(),
            QUEUE_ONE.into(),
            1,
            "2026-08-15T12:03:00.000Z".into(),
            predecessor("retry_wait"),
        )
        .unwrap();
        assert_eq!(first.operation_id(), changed_time.operation_id());
        assert_ne!(
            first.canonical_request().unwrap(),
            changed_time.canonical_request().unwrap()
        );
        let other_account = FinalizationQueuePlan::new(
            ACCOUNT_TWO.into(),
            QUEUE_ONE.into(),
            1,
            QUEUED_AT.into(),
            predecessor("retry_wait"),
        )
        .unwrap();
        assert_ne!(first.operation_id(), other_account.operation_id());
    }

    #[test]
    fn codec_target_version_is_the_reviewed_current_finalization_version() {
        assert_eq!(TARGET_VERSION, crate::store::EPISODE_FINALIZATION_VERSION);
    }

    #[test]
    fn exact_queue_applies_once_and_replays_without_rewrite() {
        let mut connection = connection();
        seed_default(&connection, 1);
        assert_eq!(
            execute(
                &mut connection,
                plan(QUEUE_ONE, 1, predecessor("retry_wait")),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Applied
        );
        let queued = load_episode_row(&connection, 1).unwrap().unwrap();
        assert_eq!(queued.status, "queued");
        assert!(queued.error.is_none());
        assert_eq!(queued.attempt_count, 0);
        assert!(queued.next_attempt_at.is_none());
        let queued_at = queued.updated_at;
        assert_eq!(queued_at.as_deref(), Some(QUEUED_AT));
        assert_eq!(
            execute(
                &mut connection,
                plan(QUEUE_ONE, 1, predecessor("retry_wait")),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(
            load_episode_row(&connection, 1)
                .unwrap()
                .unwrap()
                .updated_at,
            queued_at
        );
        assert_eq!(load_ledger_state(&connection).unwrap(), (1, 9));
    }

    #[test]
    fn every_predecessor_fact_is_authenticated_before_queueing() {
        for mutation in [
            "UPDATE episodes SET substance='none' WHERE id=1",
            "UPDATE episodes SET finalized_at='2026-08-15T11:00:00.000Z',finalization_version=5 WHERE id=1",
            "UPDATE episodes SET finalization_version=4 WHERE id=1",
            "UPDATE episodes SET finalization_status='budget_wait' WHERE id=1",
            "UPDATE episodes SET finalization_error='different' WHERE id=1",
            "UPDATE episodes SET finalization_attempted_at=NULL WHERE id=1",
            "UPDATE episodes SET finalization_attempt_count=1 WHERE id=1",
            "UPDATE episodes SET finalization_next_attempt_at=NULL WHERE id=1",
            "UPDATE episodes SET updated_at=NULL WHERE id=1",
        ] {
            let mut connection = connection();
            seed_default(&connection, 1);
            connection.execute(mutation, []).unwrap();
            assert_eq!(
                execute(
                    &mut connection,
                    plan(QUEUE_ONE, 1, predecessor("retry_wait")),
                )
                .err()
                .unwrap(),
                WalIdempotencyError::Precondition
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE name LIKE 'archive_v3_wal_finalization_queue_%'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn every_current_eligible_status_and_old_version_regeneration_queue() {
        for (index, status) in [
            "pending_horizon",
            "pending_cursor",
            "pending_watermark",
            "retry_wait",
            "budget_wait",
            "failed_terminal",
        ]
        .into_iter()
        .enumerate()
        {
            let mut connection = connection();
            let id = i64::try_from(index + 1).unwrap();
            seed(
                &connection,
                id,
                "normal",
                None,
                None,
                status,
                Some("provider unavailable"),
                Some(ATTEMPTED_AT),
                2,
                Some(NEXT_AT),
                Some(UPDATED_AT),
            );
            execute(&mut connection, plan(QUEUE_ONE, id, predecessor(status))).unwrap();
        }

        let mut regeneration = connection();
        seed(
            &regeneration,
            7,
            "low",
            Some("2026-08-15T11:00:00.000Z"),
            Some(TARGET_VERSION - 1),
            "complete",
            None,
            Some(ATTEMPTED_AT),
            0,
            None,
            Some(UPDATED_AT),
        );
        let old = FinalizationQueuePredecessor::new(
            "low".into(),
            Some("2026-08-15T11:00:00.000Z".into()),
            Some(TARGET_VERSION - 1),
            "complete".into(),
            None,
            Some(ATTEMPTED_AT.into()),
            0,
            None,
            Some(UPDATED_AT.into()),
        )
        .unwrap();
        execute(&mut regeneration, plan(QUEUE_ONE, 7, old)).unwrap();

        let mut empty_error = connection();
        seed(
            &empty_error,
            8,
            "normal",
            None,
            None,
            "failed_terminal",
            Some(""),
            Some(ATTEMPTED_AT),
            3,
            None,
            Some(UPDATED_AT),
        );
        let empty = FinalizationQueuePredecessor::new(
            "normal".into(),
            None,
            None,
            "failed_terminal".into(),
            Some(String::new()),
            Some(ATTEMPTED_AT.into()),
            3,
            None,
            Some(UPDATED_AT.into()),
        )
        .unwrap();
        execute(&mut empty_error, plan(QUEUE_ONE, 8, empty)).unwrap();
    }

    #[test]
    fn same_queue_identity_with_changed_request_conflicts() {
        let mut connection = connection();
        seed_default(&connection, 1);
        execute(
            &mut connection,
            plan(QUEUE_ONE, 1, predecessor("retry_wait")),
        )
        .unwrap();
        let changed = FinalizationQueuePredecessor::new(
            "normal".into(),
            None,
            None,
            "retry_wait".into(),
            Some("another error".into()),
            Some(ATTEMPTED_AT.into()),
            2,
            Some(NEXT_AT.into()),
            Some(UPDATED_AT.into()),
        )
        .unwrap();
        assert_eq!(
            execute(&mut connection, plan(QUEUE_ONE, 1, changed))
                .err()
                .unwrap(),
            WalIdempotencyError::FingerprintConflict
        );
    }

    #[test]
    fn capacity_is_reserved_before_queue_mutation_but_replay_survives() {
        let mut connection = connection();
        seed_default(&connection, 1);
        execute(
            &mut connection,
            plan(QUEUE_ONE, 1, predecessor("retry_wait")),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_finalization_queue_state SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        assert_eq!(
            execute(
                &mut connection,
                plan(QUEUE_ONE, 1, predecessor("retry_wait")),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        seed_default(&connection, 2);
        assert_eq!(
            execute(
                &mut connection,
                plan(QUEUE_TWO, 2, predecessor("retry_wait")),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            load_episode_row(&connection, 2).unwrap().unwrap().status,
            "retry_wait"
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_queue_transition() {
        let mut connection = connection();
        seed_default(&connection, 1);
        {
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_finalization_queue_ledger
                 BEFORE INSERT ON archive_v3_wal_finalization_queue_operations
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        assert_eq!(
            execute(
                &mut connection,
                plan(QUEUE_ONE, 1, predecessor("retry_wait")),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Unavailable
        );
        let row = load_episode_row(&connection, 1).unwrap().unwrap();
        assert_eq!(row.status, "retry_wait");
        assert_eq!(row.error.as_deref(), Some("provider unavailable"));
        assert_eq!(row.attempt_count, 2);
    }

    #[test]
    fn missing_precondition_rolls_back_schema_and_same_identity_can_retry() {
        let mut connection = connection();
        assert_eq!(
            execute(
                &mut connection,
                plan(QUEUE_ONE, 1, predecessor("retry_wait")),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            schema_state(&connection).unwrap(),
            LedgerSchemaState::Absent
        );
        seed_default(&connection, 1);
        execute(
            &mut connection,
            plan(QUEUE_ONE, 1, predecessor("retry_wait")),
        )
        .unwrap();
    }

    #[test]
    fn partial_schema_and_result_tamper_fail_closed() {
        let mut partial = connection();
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_finalization_queue_schema(
                    singleton INTEGER PRIMARY KEY,format_version INTEGER,codec_version INTEGER
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            execute(&mut partial, plan(QUEUE_ONE, 1, predecessor("retry_wait")),)
                .err()
                .unwrap(),
            WalIdempotencyError::Corrupt
        );

        let mut tampered = connection();
        seed_default(&tampered, 1);
        execute(&mut tampered, plan(QUEUE_ONE, 1, predecessor("retry_wait"))).unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_finalization_queue_operations
                 SET result_commitment=?1",
                [[9u8; 32].as_slice()],
            )
            .unwrap();
        assert_eq!(
            execute(&mut tampered, plan(QUEUE_ONE, 1, predecessor("retry_wait")),)
                .err()
                .unwrap(),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn close_reopen_replays_then_accepts_a_new_explicit_queue_request() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("archive.sqlite");
        {
            let mut connection = Connection::open(&path).unwrap();
            install_domain_schema(&connection);
            seed_default(&connection, 1);
            execute(
                &mut connection,
                plan(QUEUE_ONE, 1, predecessor("retry_wait")),
            )
            .unwrap();
        }
        let mut connection = Connection::open(&path).unwrap();
        assert_eq!(
            execute(
                &mut connection,
                plan(QUEUE_ONE, 1, predecessor("retry_wait")),
            )
            .unwrap()
            .disposition(),
            LogicalMutationDisposition::Replayed
        );
        connection
            .execute(
                "UPDATE episodes
                 SET finalization_status='failed_terminal',
                     finalization_error='model rejected',
                     finalization_attempt_count=3,
                     finalization_next_attempt_at=NULL,
                     updated_at=?1 WHERE id=1",
                [UPDATED_AT],
            )
            .unwrap();
        let next = FinalizationQueuePredecessor::new(
            "normal".into(),
            None,
            None,
            "failed_terminal".into(),
            Some("model rejected".into()),
            Some(ATTEMPTED_AT.into()),
            3,
            None,
            Some(UPDATED_AT.into()),
        )
        .unwrap();
        execute(&mut connection, plan(QUEUE_TWO, 1, next)).unwrap();
        assert_eq!(
            load_episode_row(&connection, 1).unwrap().unwrap().status,
            "queued"
        );
    }

    #[test]
    fn constructors_reject_unstable_or_ineligible_inputs() {
        assert!(FinalizationQueuePlan::new(
            "bad".into(),
            QUEUE_ONE.into(),
            1,
            QUEUED_AT.into(),
            predecessor("retry_wait"),
        )
        .is_err());
        assert!(FinalizationQueuePlan::new(
            ACCOUNT.into(),
            "not-hex".into(),
            1,
            QUEUED_AT.into(),
            predecessor("retry_wait"),
        )
        .is_err());
        assert!(FinalizationQueuePlan::new(
            ACCOUNT.into(),
            QUEUE_ONE.into(),
            0,
            QUEUED_AT.into(),
            predecessor("retry_wait"),
        )
        .is_err());
        assert!(FinalizationQueuePlan::new(
            ACCOUNT.into(),
            QUEUE_ONE.into(),
            1,
            "2026-08-15T12:00:00.000Z".into(),
            predecessor("retry_wait"),
        )
        .is_err());
        assert!(FinalizationQueuePlan::new(
            ACCOUNT.into(),
            QUEUE_ONE.into(),
            1,
            "2026-08-15T12:02:00Z".into(),
            predecessor("retry_wait"),
        )
        .is_err());
        assert!(FinalizationQueuePredecessor::new(
            "none".into(),
            None,
            None,
            "retry_wait".into(),
            None,
            None,
            0,
            None,
            None,
        )
        .is_err());
        assert!(FinalizationQueuePredecessor::new(
            "normal".into(),
            None,
            None,
            "queued".into(),
            None,
            None,
            0,
            None,
            None,
        )
        .is_err());
        assert!(FinalizationQueuePredecessor::new(
            "normal".into(),
            Some("2026-08-15T11:00:00.000Z".into()),
            Some(TARGET_VERSION),
            "complete".into(),
            None,
            None,
            0,
            None,
            None,
        )
        .is_err());
        assert!(FinalizationQueuePredecessor::new(
            "normal".into(),
            None,
            None,
            "retry_wait".into(),
            Some("x".repeat(MAX_ERROR_CHARS + 1)),
            None,
            0,
            None,
            None,
        )
        .is_err());
    }
}
