#![allow(
    dead_code,
    reason = "inactive ADR-0022 screen-attempt boundary is reviewed before provider or launcher ownership"
)]

//! Inactive pre-provider identity for one leased screen-storyboard attempt.
//!
//! The caller fixes one canonical attempt time and supplies the exact
//! authenticated leased-work commitment before actor admission. The domain
//! derives a stable Vertex event ID, records the exact billing intent and
//! monthly coverage, and retains a complete attempt-to-work binding plus a
//! bounded typed receipt in one SQLite transaction. It cannot read media, call
//! Vertex, allocate a clock/random ID, use Store, launch work, retry, or
//! acknowledge anything.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

use super::result::current_screen_work_attempt_commitments;

const REQUEST_V1: u16 = 1;
const REQUEST_SCREEN_STORYBOARD_ATTEMPT: u8 = 1;
const RESULT_V1: u16 = 1;
const RESULT_SCREEN_STORYBOARD_ATTEMPT: u8 = 1;
const EVENT_ID_DOMAIN: &[u8] = b"archive-v3-screen-storyboard-vertex-event-v1\0";
const OPERATION_SOURCE_DOMAIN: &[u8] = b"screen-storyboard-vertex-attempt-v1\0";
const BINDING_DOMAIN: &[u8] = b"archive-v3-screen-storyboard-vertex-binding-v1\0";
const MAX_ID_BYTES: usize = 128;
const MAX_MODEL_BYTES: usize = 128;
const MAX_LOCATION_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const EVENT_ID_BYTES: usize = 68;
const ENCODED_RESULT_BYTES: usize = 114;
const SCHEMA_TABLE: &str = "archive_v3_wal_screen_vertex_attempt_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_screen_vertex_attempt_operations";
const STATE_TABLE: &str = "archive_v3_wal_screen_vertex_attempt_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 128 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScreenStoryboardAttemptReceipt {
    event_id: String,
    binding_commitment: [u8; 32],
}

impl ScreenStoryboardAttemptReceipt {
    pub(in crate::cp::media_worker) fn event_id(&self) -> &str {
        &self.event_id
    }

    pub(in crate::cp::media_worker) const fn binding_commitment(&self) -> [u8; 32] {
        self.binding_commitment
    }
}

/// Stable pre-provider billing and work binding for a screen storyboard.
/// The attempt commitment is minted from the complete currently leased work
/// topology by the private helper in the reviewed result child.
pub(crate) struct ScreenStoryboardAttemptPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    work_unit_id: String,
    predecessor_commitment: [u8; 32],
    attempt_commitment: [u8; 32],
    requested_model: String,
    location: String,
    observed_at: String,
    receipt: ScreenStoryboardAttemptReceipt,
}

impl ScreenStoryboardAttemptPlan {
    pub(in crate::cp::media_worker) fn new(
        account_id: String,
        work_unit_id: String,
        predecessor_commitment: [u8; 32],
        attempt_commitment: [u8; 32],
        requested_model: String,
        location: String,
        observed_at: String,
    ) -> Result<Self> {
        Self::build(
            None,
            account_id,
            work_unit_id,
            predecessor_commitment,
            attempt_commitment,
            requested_model,
            location,
            observed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        operation_id: Option<WalLogicalOperationId>,
        account_id: String,
        work_unit_id: String,
        predecessor_commitment: [u8; 32],
        attempt_commitment: [u8; 32],
        requested_model: String,
        location: String,
        observed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if !valid_lower_hex(&work_unit_id, 64)
            || predecessor_commitment == [0; 32]
            || attempt_commitment == [0; 32]
            || requested_model.is_empty()
            || requested_model.len() > MAX_MODEL_BYTES
            || !super::super::super::vertex_model_name_is_billing_safe(&requested_model)
            || !valid_location(&location)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_canonical_timestamp(&observed_at)?;
        let event_id = derive_event_id(&account_id, &work_unit_id, &attempt_commitment)?;
        let binding_commitment = derive_binding_commitment(
            &event_id,
            &account_id,
            &work_unit_id,
            &predecessor_commitment,
            &attempt_commitment,
            &requested_model,
            &location,
            &observed_at,
        )?;
        let operation_id = match operation_id {
            Some(value) => value,
            None => {
                let mut source = Vec::with_capacity(
                    OPERATION_SOURCE_DOMAIN.len().saturating_add(event_id.len()),
                );
                source.extend_from_slice(OPERATION_SOURCE_DOMAIN);
                source.extend_from_slice(event_id.as_bytes());
                WalLogicalOperationId::from_stable_source(WalOperationKind::VertexUsage, &source)?
            }
        };
        Ok(Self {
            operation_id,
            account_id,
            work_unit_id,
            predecessor_commitment,
            attempt_commitment,
            requested_model,
            location,
            observed_at,
            receipt: ScreenStoryboardAttemptReceipt {
                event_id,
                binding_commitment,
            },
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        account_id: &str,
        work_unit_id: &str,
        predecessor_commitment: [u8; 32],
        attempt_commitment: [u8; 32],
        requested_model: &str,
        location: &str,
        observed_at: &str,
    ) -> Result<Self> {
        Self::build(
            Some(operation_id),
            account_id.to_owned(),
            work_unit_id.to_owned(),
            predecessor_commitment,
            attempt_commitment,
            requested_model.to_owned(),
            location.to_owned(),
            observed_at.to_owned(),
        )
    }
}

pub(crate) struct ScreenStoryboardAttemptLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for ScreenStoryboardAttemptPlan {
    type Ledger = ScreenStoryboardAttemptLedger;
    type Output = ScreenStoryboardAttemptReceipt;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::VertexUsage
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(512));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        request.push(REQUEST_SCREEN_STORYBOARD_ATTEMPT);
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.work_unit_id)?;
        request.extend_from_slice(&self.predecessor_commitment);
        request.extend_from_slice(&self.attempt_commitment);
        encode_string(&mut request, &self.requested_model)?;
        encode_string(&mut request, &self.location)?;
        encode_string(&mut request, &self.observed_at)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let current = current_screen_work_attempt_commitments(
            transaction,
            &self.work_unit_id,
            &self.observed_at,
        )?;
        if current.predecessor() != self.predecessor_commitment
            || current.attempt() != self.attempt_commitment
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let existing = transaction
            .query_row(
                "SELECT COUNT(*) FROM vertex_usage_events WHERE event_id=?1",
                [&self.receipt.event_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if existing != 0 {
            return Err(WalIdempotencyError::Precondition);
        }
        transaction
            .execute(
                "INSERT INTO vertex_usage_events
                 (event_id,operation,requested_model,returned_model,location,traffic_type,
                  http_status,prompt_tokens,input_text_tokens,input_audio_tokens,
                  input_image_tokens,cached_input_tokens,cached_input_text_tokens,
                  cached_input_audio_tokens,cached_input_image_tokens,output_text_tokens,
                  thought_tokens,total_tokens,outcome,delivery_state,delivery_attempt_count,
                  observed_at,updated_at)
                 VALUES (?1,'screen_understanding',?2,NULL,?3,'on_demand',
                         NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
                         'started','pending',0,?4,?4)",
                params![
                    self.receipt.event_id,
                    self.requested_model,
                    self.location,
                    self.observed_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        refresh_coverage(transaction, &self.observed_at)?;
        validate_started_event(transaction, self)?;
        validate_bound_event(transaction, self)?;
        encode_receipt(&self.receipt)
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        (decode_receipt(result)? == self.receipt)
            .then_some(())
            .ok_or(WalIdempotencyError::Corrupt)
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        let receipt = decode_receipt(result)?;
        (receipt == self.receipt)
            .then_some(receipt)
            .ok_or(WalIdempotencyError::Corrupt)
    }
}

impl WalLogicalDomainLedger<ScreenStoryboardAttemptPlan> for ScreenStoryboardAttemptLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<ScreenStoryboardAttemptPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,
                        event_id,account_id,work_unit_id,predecessor_commitment,attempt_commitment,
                        requested_model,location,observed_at,binding_commitment,
                        result_bytes,result_commitment
                 FROM archive_v3_wal_screen_vertex_attempt_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                StoredLedgerRow::from_row,
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let plan = prepared.plan_for_domain_ledger();
        if row.format_version != i64::from(WalOperationKind::format_version())
            || row.codec_version != i64::from(WalOperationKind::VertexUsage.codec_version())
            || row.request_fingerprint.len() != 32
            || row.result_commitment.len() != 32
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        if row.request_fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        if !row.matches_plan(plan) {
            return Err(WalIdempotencyError::Corrupt);
        }
        let stored_predecessor: [u8; 32] = row
            .predecessor_commitment
            .as_slice()
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let stored_attempt: [u8; 32] = row
            .attempt_commitment
            .as_slice()
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let expected_binding = derive_binding_commitment(
            &row.event_id,
            &row.account_id,
            &row.work_unit_id,
            &stored_predecessor,
            &stored_attempt,
            &row.requested_model,
            &row.location,
            &row.observed_at,
        )?;
        if row.binding_commitment.as_slice() != expected_binding.as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        let result = WalReplayResult::decode(WalOperationKind::VertexUsage, &row.result_bytes)?;
        if row.result_bytes.len() != ENCODED_RESULT_BYTES
            || row.result_commitment.as_slice()
                != result.commitment(WalOperationKind::VertexUsage)?.as_slice()
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        plan.validate_replay(&result)?;
        validate_bound_event(connection, plan)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<ScreenStoryboardAttemptPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_RESULT_BYTES)?;
        let plan = prepared.plan_for_domain_ledger();
        let result = plan.apply(transaction)?;
        plan.validate_replay(&result)?;
        let encoded = result.encode(WalOperationKind::VertexUsage)?;
        if encoded.len() != ENCODED_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let result_commitment = result.commitment(WalOperationKind::VertexUsage)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_screen_vertex_attempt_operations
                 (operation_id,format_version,codec_version,request_fingerprint,
                  event_id,account_id,work_unit_id,predecessor_commitment,attempt_commitment,
                  requested_model,location,observed_at,binding_commitment,result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(WalOperationKind::VertexUsage.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    plan.receipt.event_id,
                    plan.account_id,
                    plan.work_unit_id,
                    plan.predecessor_commitment.as_slice(),
                    plan.attempt_commitment.as_slice(),
                    plan.requested_model,
                    plan.location,
                    plan.observed_at,
                    plan.receipt.binding_commitment.as_slice(),
                    encoded.as_slice(),
                    result_commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_screen_vertex_attempt_state
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
        let Some(stored) = Self::lookup(transaction, prepared)? else {
            return Err(WalIdempotencyError::Corrupt);
        };
        if stored != result {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

struct StoredLedgerRow {
    format_version: i64,
    codec_version: i64,
    request_fingerprint: Vec<u8>,
    event_id: String,
    account_id: String,
    work_unit_id: String,
    predecessor_commitment: Vec<u8>,
    attempt_commitment: Vec<u8>,
    requested_model: String,
    location: String,
    observed_at: String,
    binding_commitment: Vec<u8>,
    result_bytes: Vec<u8>,
    result_commitment: Vec<u8>,
}

impl StoredLedgerRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            format_version: row.get(0)?,
            codec_version: row.get(1)?,
            request_fingerprint: row.get(2)?,
            event_id: row.get(3)?,
            account_id: row.get(4)?,
            work_unit_id: row.get(5)?,
            predecessor_commitment: row.get(6)?,
            attempt_commitment: row.get(7)?,
            requested_model: row.get(8)?,
            location: row.get(9)?,
            observed_at: row.get(10)?,
            binding_commitment: row.get(11)?,
            result_bytes: row.get(12)?,
            result_commitment: row.get(13)?,
        })
    }

    fn matches_plan(&self, plan: &ScreenStoryboardAttemptPlan) -> bool {
        self.event_id == plan.receipt.event_id
            && self.account_id == plan.account_id
            && self.work_unit_id == plan.work_unit_id
            && self.predecessor_commitment.as_slice() == plan.predecessor_commitment.as_slice()
            && self.attempt_commitment.as_slice() == plan.attempt_commitment.as_slice()
            && self.requested_model == plan.requested_model
            && self.location == plan.location
            && self.observed_at == plan.observed_at
            && self.binding_commitment.as_slice() == plan.receipt.binding_commitment.as_slice()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredCoverage {
    sequence: i64,
    pending_events: i64,
    lost_events: i64,
    delivery_state: String,
    updated_at: String,
}

fn refresh_coverage(transaction: &Transaction<'_>, observed_at: &str) -> Result<()> {
    let period = observed_at.get(..7).ok_or(WalIdempotencyError::Malformed)?;
    let pending_events = transaction
        .query_row(
            "SELECT COUNT(*) FROM vertex_usage_events
             WHERE delivery_state='pending' AND substr(observed_at,1,7)=?1",
            [period],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if pending_events <= 0 {
        return Err(WalIdempotencyError::Corrupt);
    }
    let prior = load_coverage(transaction, period)?;
    let expected = match prior {
        None => {
            transaction
                .execute(
                    "INSERT INTO vertex_usage_coverage
                     (period,sequence,pending_events,lost_events,delivery_state,updated_at)
                     VALUES (?1,1,?2,0,'pending',?3)",
                    params![period, pending_events, observed_at],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            StoredCoverage {
                sequence: 1,
                pending_events,
                lost_events: 0,
                delivery_state: "pending".to_owned(),
                updated_at: observed_at.to_owned(),
            }
        }
        Some(prior) => {
            validate_coverage(&prior)?;
            if timestamp_millis(&prior.updated_at)? > timestamp_millis(observed_at)? {
                return Err(WalIdempotencyError::Precondition);
            }
            let next_sequence = prior
                .sequence
                .checked_add(1)
                .ok_or(WalIdempotencyError::Limit)?;
            let changed = transaction
                .execute(
                    "UPDATE vertex_usage_coverage
                     SET sequence=?1,pending_events=?2,lost_events=?3,
                         delivery_state='pending',updated_at=?4
                     WHERE period=?5 AND sequence=?6 AND pending_events=?7
                       AND lost_events=?8 AND delivery_state=?9 AND updated_at=?10",
                    params![
                        next_sequence,
                        pending_events,
                        prior.lost_events,
                        observed_at,
                        period,
                        prior.sequence,
                        prior.pending_events,
                        prior.lost_events,
                        prior.delivery_state,
                        prior.updated_at,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
            StoredCoverage {
                sequence: next_sequence,
                pending_events,
                lost_events: prior.lost_events,
                delivery_state: "pending".to_owned(),
                updated_at: observed_at.to_owned(),
            }
        }
    };
    if load_coverage(transaction, period)? != Some(expected) {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn load_coverage(connection: &Connection, period: &str) -> Result<Option<StoredCoverage>> {
    connection
        .query_row(
            "SELECT sequence,pending_events,lost_events,delivery_state,updated_at
             FROM vertex_usage_coverage WHERE period=?1",
            [period],
            |row| {
                Ok(StoredCoverage {
                    sequence: row.get(0)?,
                    pending_events: row.get(1)?,
                    lost_events: row.get(2)?,
                    delivery_state: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn validate_coverage(coverage: &StoredCoverage) -> Result<()> {
    if coverage.sequence <= 0
        || coverage.pending_events < 0
        || coverage.lost_events < 0
        || !matches!(coverage.delivery_state.as_str(), "pending" | "delivered")
        || !valid_canonical_timestamp(&coverage.updated_at)
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn validate_bound_event(connection: &Connection, plan: &ScreenStoryboardAttemptPlan) -> Result<()> {
    let row = connection
        .query_row(
            "SELECT event_id,operation,requested_model,location,observed_at
             FROM vertex_usage_events WHERE event_id=?1",
            [&plan.receipt.event_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if row
        != Some((
            plan.receipt.event_id.clone(),
            "screen_understanding".to_owned(),
            plan.requested_model.clone(),
            plan.location.clone(),
            plan.observed_at.clone(),
        ))
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn validate_started_event(
    connection: &Connection,
    plan: &ScreenStoryboardAttemptPlan,
) -> Result<()> {
    let exact = connection
        .query_row(
            "SELECT COUNT(*) FROM vertex_usage_events
             WHERE event_id=?1 AND operation='screen_understanding'
               AND requested_model=?2 AND returned_model IS NULL
               AND location=?3 AND traffic_type='on_demand'
               AND http_status IS NULL AND prompt_tokens IS NULL
               AND input_text_tokens IS NULL AND input_audio_tokens IS NULL
               AND input_image_tokens IS NULL AND cached_input_tokens IS NULL
               AND cached_input_text_tokens IS NULL AND cached_input_audio_tokens IS NULL
               AND cached_input_image_tokens IS NULL AND output_text_tokens IS NULL
               AND thought_tokens IS NULL AND total_tokens IS NULL
               AND outcome='started' AND delivery_state='pending'
               AND delivery_attempt_count=0 AND observed_at=?4 AND updated_at=?4",
            params![
                plan.receipt.event_id,
                plan.requested_model,
                plan.location,
                plan.observed_at,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if exact != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn require_kind(prepared: &PreparedLogicalMutation<ScreenStoryboardAttemptPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::VertexUsage)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
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
                    "CREATE TABLE archive_v3_wal_screen_vertex_attempt_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_screen_vertex_attempt_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        event_id TEXT NOT NULL UNIQUE,
                        account_id TEXT NOT NULL,
                        work_unit_id TEXT NOT NULL,
                        predecessor_commitment BLOB NOT NULL,
                        attempt_commitment BLOB NOT NULL,
                        requested_model TEXT NOT NULL,
                        location TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        binding_commitment BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(event_id)=68),
                        CHECK(length(account_id) BETWEEN 1 AND 128),
                        CHECK(length(work_unit_id)=64),
                        CHECK(length(predecessor_commitment)=32 AND predecessor_commitment<>zeroblob(32)),
                        CHECK(length(attempt_commitment)=32 AND attempt_commitment<>zeroblob(32)),
                        CHECK(length(requested_model) BETWEEN 1 AND 128),
                        CHECK(length(location) BETWEEN 1 AND 128),
                        CHECK(length(observed_at) BETWEEN 1 AND 64),
                        CHECK(length(binding_commitment)=32 AND binding_commitment<>zeroblob(32)),
                        CHECK(length(result_bytes)=114),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_screen_vertex_attempt_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 134217728)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_screen_vertex_attempt_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_screen_vertex_attempt_state
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
             FROM archive_v3_wal_screen_vertex_attempt_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::VertexUsage.codec_version()),
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
             FROM archive_v3_wal_screen_vertex_attempt_state WHERE singleton=1",
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

#[allow(clippy::too_many_arguments)]
fn derive_binding_commitment(
    event_id: &str,
    account_id: &str,
    work_unit_id: &str,
    predecessor_commitment: &[u8; 32],
    attempt_commitment: &[u8; 32],
    requested_model: &str,
    location: &str,
    observed_at: &str,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hash_field(&mut hasher, event_id.as_bytes())?;
    hash_field(&mut hasher, account_id.as_bytes())?;
    hash_field(&mut hasher, work_unit_id.as_bytes())?;
    hash_field(&mut hasher, predecessor_commitment)?;
    hash_field(&mut hasher, attempt_commitment)?;
    hash_field(&mut hasher, requested_model.as_bytes())?;
    hash_field(&mut hasher, location.as_bytes())?;
    hash_field(&mut hasher, observed_at.as_bytes())?;
    let commitment: [u8; 32] = hasher.finalize().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn derive_event_id(
    account_id: &str,
    work_unit_id: &str,
    attempt_commitment: &[u8; 32],
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(EVENT_ID_DOMAIN);
    hash_field(&mut hasher, account_id.as_bytes())?;
    hash_field(&mut hasher, work_unit_id.as_bytes())?;
    hash_field(&mut hasher, attempt_commitment)?;
    let event_id = format!("vtx_{:x}", hasher.finalize());
    if event_id.len() != EVENT_ID_BYTES {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(event_id)
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) -> Result<()> {
    hasher.update(
        u32::try_from(value.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    hasher.update(value);
    Ok(())
}

fn encode_receipt(receipt: &ScreenStoryboardAttemptReceipt) -> Result<WalReplayResult> {
    let mut bytes = Vec::with_capacity(105);
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(RESULT_SCREEN_STORYBOARD_ATTEMPT);
    encode_string(&mut bytes, &receipt.event_id)?;
    bytes.extend_from_slice(&receipt.binding_commitment);
    WalReplayResult::canonical_response(WalOperationKind::VertexUsage, bytes)
}

fn decode_receipt(result: &WalReplayResult) -> Result<ScreenStoryboardAttemptReceipt> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    let mut reader = Reader::new(bytes);
    if reader.take_u16()? != RESULT_V1 || reader.take_u8()? != RESULT_SCREEN_STORYBOARD_ATTEMPT {
        return Err(WalIdempotencyError::Corrupt);
    }
    let event_id = reader.take_string(MAX_ID_BYTES)?;
    let binding_commitment = reader.take_array_32()?;
    if !reader.is_empty()
        || event_id.len() != EVENT_ID_BYTES
        || !event_id
            .strip_prefix("vtx_")
            .is_some_and(|suffix| valid_lower_hex(suffix, 64))
        || binding_commitment == [0; 32]
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(ScreenStoryboardAttemptReceipt {
        event_id,
        binding_commitment,
    })
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

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if self.remaining.len() < length {
            return Err(WalIdempotencyError::Corrupt);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn take_array_32(&mut self) -> Result<[u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)
    }

    fn take_string(&mut self, maximum: usize) -> Result<String> {
        let length: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 || length > maximum {
            return Err(WalIdempotencyError::Corrupt);
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| WalIdempotencyError::Corrupt)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_location(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LOCATION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn timestamp_millis(value: &str) -> Result<i64> {
    super::super::super::isotime::parse_epoch_millis(value).ok_or(WalIdempotencyError::Malformed)
}

fn valid_canonical_timestamp(value: &str) -> bool {
    timestamp_millis(value).is_ok_and(|millis| {
        value.len() <= MAX_TIMESTAMP_BYTES
            && !value.contains('\0')
            && super::super::super::isotime::format_epoch_millis(millis) == value
    })
}

fn validate_canonical_timestamp(value: &str) -> Result<()> {
    valid_canonical_timestamp(value)
        .then_some(())
        .ok_or(WalIdempotencyError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use crate::cp::media_worker::wal::result::tests::{
        install_schema, seed_work, ACCOUNT, LEASE_UNTIL, MODEL, UPDATED_AT, WORK_ONE,
    };
    use tempfile::tempdir;

    const SEED_VERTEX: &str =
        "vtx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ATTEMPTED_AT: &str = "2026-08-15T15:00:03.000Z";
    const NEXT_ATTEMPTED_AT: &str = "2026-08-15T15:01:01.000Z";

    fn install_coverage_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE vertex_usage_coverage (
                    period TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    pending_events INTEGER NOT NULL,
                    lost_events INTEGER NOT NULL,
                    delivery_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                 ) STRICT;",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        install_coverage_schema(&connection);
        connection
    }

    fn reserved_usage(work: &str, count: usize) -> String {
        serde_json::json!({
            "work_unit_id": work,
            "work_class": "screen",
            "member_count": count,
            "reservation_state": "reserved",
            "reserved_output_tokens": 1024,
            "processor_version": 1,
        })
        .to_string()
    }

    fn seed_reserved_work(connection: &Connection, work: &str, base: i64, count: usize) {
        seed_work(connection, work, SEED_VERTEX, base, count);
        connection
            .execute(
                "DELETE FROM vertex_usage_events WHERE event_id=?1",
                [SEED_VERTEX],
            )
            .unwrap();
        let usage = reserved_usage(work, count);
        connection
            .execute(
                "UPDATE media_work_units SET usage_json=?1,updated_at=?2 WHERE id=?3",
                params![usage, UPDATED_AT, work],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE media_processing_jobs SET usage_json=?1,updated_at=?2
                 WHERE id IN (SELECT job_id FROM media_work_members WHERE work_unit_id=?3)",
                params![usage, UPDATED_AT, work],
            )
            .unwrap();
    }

    fn plan_at(
        connection: &Connection,
        work: &str,
        model: &str,
        location: &str,
        observed_at: &str,
    ) -> ScreenStoryboardAttemptPlan {
        let commitments =
            current_screen_work_attempt_commitments(connection, work, observed_at).unwrap();
        ScreenStoryboardAttemptPlan::new(
            ACCOUNT.to_owned(),
            work.to_owned(),
            commitments.predecessor(),
            commitments.attempt(),
            model.to_owned(),
            location.to_owned(),
            observed_at.to_owned(),
        )
        .unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: ScreenStoryboardAttemptPlan,
    ) -> std::result::Result<
        crate::archive_v3_wal_idempotency::ExecutedLogicalMutation<ScreenStoryboardAttemptPlan>,
        WalIdempotencyError,
    > {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared)
    }

    fn execute_error(
        connection: &mut Connection,
        plan: ScreenStoryboardAttemptPlan,
    ) -> WalIdempotencyError {
        match execute(connection, plan) {
            Ok(_) => panic!("mutation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    fn advance_attempt(connection: &Connection, work: &str) {
        let usage = reserved_usage(work, 1);
        connection
            .execute(
                "UPDATE media_work_units
                 SET attempt_count=attempt_count+1,usage_json=?1,updated_at='2026-08-15T15:01:00.000Z'
                 WHERE id=?2",
                params![usage, work],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE media_processing_jobs
                 SET attempt_count=attempt_count+1,lease_until='2026-08-15T15:06:00.000Z',
                     usage_json=?1,updated_at='2026-08-15T15:01:00.000Z'
                 WHERE id IN (SELECT job_id FROM media_work_members WHERE work_unit_id=?2)",
                params![usage, work],
            )
            .unwrap();
    }

    #[test]
    fn exact_attempt_applies_once_and_replays_typed_receipt_without_rewrite() {
        let mut connection = connection();
        seed_reserved_work(&connection, WORK_ONE, 1, 1);
        let replay = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        let first = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        let operation_id = first.operation_id();
        let applied = execute(&mut connection, first).unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        let receipt = applied.into_validated_result().release().unwrap();
        assert_eq!(receipt.event_id.len(), EVENT_ID_BYTES);
        assert_ne!(receipt.binding_commitment(), [0; 32]);
        assert_ne!(
            operation_id,
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::VertexUsage,
                receipt.event_id.as_bytes(),
            )
            .unwrap()
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM vertex_usage_events
                     WHERE event_id=?1 AND operation='screen_understanding'
                       AND requested_model=?2 AND returned_model IS NULL
                       AND location='us-central1' AND traffic_type='on_demand'
                       AND http_status IS NULL AND prompt_tokens IS NULL
                       AND input_text_tokens IS NULL AND input_audio_tokens IS NULL
                       AND input_image_tokens IS NULL AND cached_input_tokens IS NULL
                       AND cached_input_text_tokens IS NULL AND cached_input_audio_tokens IS NULL
                       AND cached_input_image_tokens IS NULL AND output_text_tokens IS NULL
                       AND thought_tokens IS NULL AND total_tokens IS NULL
                       AND outcome='started' AND delivery_state='pending'
                       AND delivery_attempt_count=0 AND observed_at=?3 AND updated_at=?3",
                    params![receipt.event_id(), MODEL, ATTEMPTED_AT],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            load_coverage(&connection, "2026-08").unwrap(),
            Some(StoredCoverage {
                sequence: 1,
                pending_events: 1,
                lost_events: 0,
                delivery_state: "pending".to_owned(),
                updated_at: ATTEMPTED_AT.to_owned(),
            })
        );
        connection
            .execute_batch(
                "CREATE TRIGGER reject_vertex_rewrite BEFORE UPDATE ON vertex_usage_events
                 BEGIN SELECT RAISE(ABORT,'no rewrite'); END;
                 CREATE TRIGGER reject_coverage_rewrite BEFORE UPDATE ON vertex_usage_coverage
                 BEGIN SELECT RAISE(ABORT,'no rewrite'); END;",
            )
            .unwrap();
        let replayed = execute(&mut connection, replay).unwrap();
        assert_eq!(replayed.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(replayed.operation_id(), operation_id);
        assert_eq!(replayed.into_validated_result().release().unwrap(), receipt);
        assert_eq!(load_ledger_state(&connection).unwrap(), (1, 114));
    }

    #[test]
    fn stable_attempt_rejects_changed_request_but_retry_gets_a_new_identity() {
        let mut connection = connection();
        seed_reserved_work(&connection, WORK_ONE, 1, 1);
        let changed = plan_at(
            &connection,
            WORK_ONE,
            "gemini-3.5-pro",
            "us-central1",
            ATTEMPTED_AT,
        );
        let first = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        assert_eq!(first.operation_id(), changed.operation_id());
        let first_event = first.receipt.event_id.clone();
        execute(&mut connection, first).unwrap();
        assert_eq!(
            execute_error(&mut connection, changed),
            WalIdempotencyError::FingerprintConflict
        );

        advance_attempt(&connection, WORK_ONE);
        let retry = plan_at(
            &connection,
            WORK_ONE,
            MODEL,
            "us-central1",
            NEXT_ATTEMPTED_AT,
        );
        assert_ne!(retry.receipt.event_id, first_event);
        assert_eq!(
            execute(&mut connection, retry).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
    }

    #[test]
    fn exact_work_stage_and_attempt_window_are_required_before_any_write() {
        for mutation in [
            "work",
            "job",
            "usage",
            "equivalent-usage",
            "work-time",
            "early",
            "short",
            "expired",
        ] {
            let mut connection = connection();
            seed_reserved_work(&connection, WORK_ONE, 1, 1);
            let commitments =
                current_screen_work_attempt_commitments(&connection, WORK_ONE, ATTEMPTED_AT)
                    .unwrap();
            let observed_at = match mutation {
                "early" => "2026-08-15T14:59:58.000Z",
                "short" => "2026-08-15T15:03:01.000Z",
                "expired" => "2026-08-15T15:05:01.000Z",
                _ => ATTEMPTED_AT,
            };
            match mutation {
                "work" => {
                    connection
                        .execute("UPDATE media_work_units SET attempt_count=2", [])
                        .unwrap();
                }
                "job" => {
                    connection
                        .execute("UPDATE media_processing_jobs SET attempt_count=2", [])
                        .unwrap();
                }
                "usage" => {
                    connection
                        .execute(
                            "UPDATE media_work_units SET usage_json=json_set(usage_json,'$.outcome','model_returned')",
                            [],
                        )
                        .unwrap();
                }
                "equivalent-usage" => {
                    let reordered = format!(
                        "{{\"processor_version\":1,\"reserved_output_tokens\":1024,\"reservation_state\":\"reserved\",\"member_count\":1,\"work_class\":\"screen\",\"work_unit_id\":\"{WORK_ONE}\"}}"
                    );
                    connection
                        .execute(
                            "UPDATE media_work_units SET usage_json=?1 WHERE id=?2",
                            params![&reordered, WORK_ONE],
                        )
                        .unwrap();
                    connection
                        .execute(
                            "UPDATE media_processing_jobs SET usage_json=?1",
                            [&reordered],
                        )
                        .unwrap();
                }
                "work-time" => {
                    connection
                        .execute(
                            "UPDATE media_work_units SET updated_at='2026-08-15T15:00:02.500Z'",
                            [],
                        )
                        .unwrap();
                }
                "early" | "short" | "expired" => {}
                _ => unreachable!(),
            }
            let plan = ScreenStoryboardAttemptPlan::new(
                ACCOUNT.to_owned(),
                WORK_ONE.to_owned(),
                commitments.predecessor(),
                commitments.attempt(),
                MODEL.to_owned(),
                "us-central1".to_owned(),
                observed_at.to_owned(),
            )
            .unwrap();
            assert_eq!(
                execute_error(&mut connection, plan),
                WalIdempotencyError::Precondition,
                "mutation {mutation}"
            );
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM vertex_usage_events", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                schema_state(&connection).unwrap(),
                LedgerSchemaState::Absent
            );
        }
        assert_eq!(LEASE_UNTIL, "2026-08-15T15:05:00.000Z");
    }

    #[test]
    fn unledgered_event_is_never_adopted() {
        let mut connection = connection();
        seed_reserved_work(&connection, WORK_ONE, 1, 1);
        let plan = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        connection
            .execute(
                "INSERT INTO vertex_usage_events
                 (event_id,operation,requested_model,returned_model,location,traffic_type,
                  http_status,prompt_tokens,input_text_tokens,input_audio_tokens,input_image_tokens,
                  cached_input_tokens,cached_input_text_tokens,cached_input_audio_tokens,
                  cached_input_image_tokens,output_text_tokens,thought_tokens,total_tokens,outcome,
                  delivery_state,delivery_attempt_count,observed_at,updated_at)
                 VALUES (?1,'screen_understanding',?2,NULL,'us-central1','on_demand',
                         NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
                         'started','pending',0,?3,?3)",
                params![plan.receipt.event_id, MODEL, ATTEMPTED_AT],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, plan),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            schema_state(&connection).unwrap(),
            LedgerSchemaState::Absent
        );
    }

    #[test]
    fn post_insert_domain_rewrite_rolls_back_instead_of_minting_a_receipt() {
        let mut connection = connection();
        seed_reserved_work(&connection, WORK_ONE, 1, 1);
        let plan = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        connection
            .execute_batch(
                "CREATE TRIGGER rewrite_started_event AFTER INSERT ON vertex_usage_events
                 BEGIN
                   UPDATE vertex_usage_events SET outcome='ambiguous'
                   WHERE event_id=NEW.event_id;
                 END;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, plan),
            WalIdempotencyError::Corrupt
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM vertex_usage_events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(load_coverage(&connection, "2026-08").unwrap().is_none());
        assert_eq!(
            schema_state(&connection).unwrap(),
            LedgerSchemaState::Absent
        );
    }

    #[test]
    fn existing_coverage_is_full_tuple_advanced_and_preserves_loss() {
        let mut connection = connection();
        seed_reserved_work(&connection, WORK_ONE, 1, 1);
        connection
            .execute(
                "INSERT INTO vertex_usage_events
                 (event_id,operation,requested_model,returned_model,location,traffic_type,
                  http_status,prompt_tokens,input_text_tokens,input_audio_tokens,input_image_tokens,
                  cached_input_tokens,cached_input_text_tokens,cached_input_audio_tokens,
                  cached_input_image_tokens,output_text_tokens,thought_tokens,total_tokens,outcome,
                  delivery_state,delivery_attempt_count,observed_at,updated_at)
                 VALUES (?1,'episode_finalization',?2,NULL,'us-central1','on_demand',
                         NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
                         'ambiguous','pending',0,'2026-08-15T14:00:00.000Z','2026-08-15T14:00:00.000Z')",
                params![format!("vtx_{}", "f".repeat(64)), MODEL],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO vertex_usage_coverage
                 (period,sequence,pending_events,lost_events,delivery_state,updated_at)
                 VALUES ('2026-08',7,1,3,'delivered','2026-08-15T14:00:00.000Z')",
                [],
            )
            .unwrap();
        let plan = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        execute(&mut connection, plan).unwrap();
        assert_eq!(
            load_coverage(&connection, "2026-08").unwrap(),
            Some(StoredCoverage {
                sequence: 8,
                pending_events: 2,
                lost_events: 3,
                delivery_state: "pending".to_owned(),
                updated_at: ATTEMPTED_AT.to_owned(),
            })
        );
    }

    #[test]
    fn capacity_and_late_failure_never_leak_event_or_coverage_rows() {
        let mut connection = connection();
        seed_reserved_work(&connection, WORK_ONE, 1, 1);
        let replay = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        let first = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        execute(&mut connection, first).unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_screen_vertex_attempt_state
                 SET row_count=1048576,result_bytes=134217728",
                [],
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );
        advance_attempt(&connection, WORK_ONE);
        let blocked = plan_at(
            &connection,
            WORK_ONE,
            MODEL,
            "us-central1",
            NEXT_ATTEMPTED_AT,
        );
        let blocked_event = blocked.receipt.event_id.clone();
        assert_eq!(
            execute_error(&mut connection, blocked),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM vertex_usage_events WHERE event_id=?1",
                    [&blocked_event],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        connection
            .execute(
                "UPDATE archive_v3_wal_screen_vertex_attempt_state
                 SET row_count=1,result_bytes=114",
                [],
            )
            .unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_late_state BEFORE UPDATE
                 ON archive_v3_wal_screen_vertex_attempt_state
                 BEGIN SELECT RAISE(ABORT,'late failure'); END;",
            )
            .unwrap();
        let late = plan_at(
            &connection,
            WORK_ONE,
            MODEL,
            "us-central1",
            NEXT_ATTEMPTED_AT,
        );
        assert_eq!(
            execute_error(&mut connection, late),
            WalIdempotencyError::Unavailable
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM vertex_usage_events WHERE observed_at=?1",
                    [NEXT_ATTEMPTED_AT],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            load_coverage(&connection, "2026-08")
                .unwrap()
                .unwrap()
                .sequence,
            1
        );
    }

    #[test]
    fn partial_schema_and_binding_or_domain_tamper_fail_closed() {
        let mut partial = connection();
        seed_reserved_work(&partial, WORK_ONE, 1, 1);
        let plan = plan_at(&partial, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_screen_vertex_attempt_schema (
                    singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut partial, plan),
            WalIdempotencyError::Corrupt
        );

        let mut tampered = connection();
        seed_reserved_work(&tampered, WORK_ONE, 1, 1);
        let replay = plan_at(&tampered, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        let first = plan_at(&tampered, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        execute(&mut tampered, first).unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_screen_vertex_attempt_operations
                 SET binding_commitment=?1",
                [[7_u8; 32].as_slice()],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut tampered, replay),
            WalIdempotencyError::Corrupt
        );

        let mut domain_tamper = connection();
        seed_reserved_work(&domain_tamper, WORK_ONE, 1, 1);
        let replay = plan_at(&domain_tamper, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        let first = plan_at(&domain_tamper, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
        let event_id = first.receipt.event_id.clone();
        execute(&mut domain_tamper, first).unwrap();
        domain_tamper
            .execute(
                "UPDATE vertex_usage_events SET requested_model='gemini-3.5-pro'
                 WHERE event_id=?1",
                [&event_id],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut domain_tamper, replay),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn close_reopen_replays_then_accepts_a_later_attempt() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("screen-attempt.sqlite");
        let (replay, first_event) = {
            let mut connection = Connection::open(&path).unwrap();
            install_schema(&connection);
            install_coverage_schema(&connection);
            seed_reserved_work(&connection, WORK_ONE, 1, 1);
            let replay = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
            let first = plan_at(&connection, WORK_ONE, MODEL, "us-central1", ATTEMPTED_AT);
            let event = first.receipt.event_id.clone();
            execute(&mut connection, first).unwrap();
            (replay, event)
        };
        let mut reopened = Connection::open(&path).unwrap();
        assert_eq!(
            execute(&mut reopened, replay).unwrap().disposition(),
            LogicalMutationDisposition::Replayed
        );
        advance_attempt(&reopened, WORK_ONE);
        let next = plan_at(&reopened, WORK_ONE, MODEL, "us-central1", NEXT_ATTEMPTED_AT);
        assert_ne!(next.receipt.event_id, first_event);
        assert_eq!(
            execute(&mut reopened, next).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(load_ledger_state(&reopened).unwrap(), (2, 228));
    }

    #[test]
    fn constructors_reject_unstable_or_malformed_boundary_inputs() {
        assert!(ScreenStoryboardAttemptPlan::new(
            ACCOUNT.to_owned(),
            WORK_ONE.to_owned(),
            [0; 32],
            [1; 32],
            MODEL.to_owned(),
            "us-central1".to_owned(),
            ATTEMPTED_AT.to_owned(),
        )
        .is_err());
        assert!(ScreenStoryboardAttemptPlan::new(
            ACCOUNT.to_owned(),
            WORK_ONE.to_owned(),
            [1; 32],
            [1; 32],
            MODEL.to_owned(),
            "US Central".to_owned(),
            ATTEMPTED_AT.to_owned(),
        )
        .is_err());
        assert!(ScreenStoryboardAttemptPlan::with_operation_id(
            WalLogicalOperationId::from_bytes([9; 16]).unwrap(),
            ACCOUNT,
            WORK_ONE,
            [1; 32],
            [1; 32],
            MODEL,
            "us-central1",
            "not-a-time",
        )
        .is_err());
    }
}
