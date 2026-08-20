#![allow(
    dead_code,
    reason = "inactive ADR-0022 production domain codec is reviewed before launcher or worker ownership"
)]

//! Inactive WAL logical-operation codecs owned by the Vertex usage ledger.
//!
//! This production A-domain terminalizes one already-created Vertex invocation
//! under its caller-stable event ID. Invocation creation remains a disabled B
//! dependency. This child has no Store, worker, launcher, provider, task,
//! delivery, or acknowledgement authority.

pub(super) mod coverage;
pub(super) mod delivery;
pub(super) mod invocation;
pub(super) mod reconcile;
pub(in crate::cp) use coverage::{CoveragePredecessor, CoverageTransition};
pub(crate) use coverage::{VertexCoverageLedgerLedger, VertexCoverageLedgerPlan};
pub(in crate::cp) use delivery::{DeliveryEventPredecessor, DeliveryOutcome};
pub(crate) use delivery::{VertexUsageDeliveryLedger, VertexUsageDeliveryPlan};
pub(in crate::cp) use invocation::{
    derive_event_id, read_lane_sequence, request_commitment, VertexInvocationLane,
};
pub(crate) use invocation::{VertexInvocationBeginLedger, VertexInvocationBeginPlan};
pub(in crate::cp) use reconcile::{PoisonIntent, StaleIntent};
pub(crate) use reconcile::{VertexIntentReconcileLedger, VertexIntentReconcilePlan};

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

const VERTEX_USAGE_REQUEST_V1: u16 = 1;
const TERMINAL_RESPONSE: u8 = 1;
const TERMINAL_AMBIGUOUS: u8 = 2;
const TERMINAL_NOT_BILLED: u8 = 3;
const RESPONSE_USAGE_MISSING: u8 = 1;
const RESPONSE_METERED: u8 = 2;
const TRAFFIC_ON_DEMAND: u8 = 1;
const TRAFFIC_BATCH: u8 = 2;
const TRAFFIC_PROVISIONED: u8 = 3;
const MAX_EVENT_ID_BYTES: usize = 68;
const MAX_RETURNED_MODEL_BYTES: usize = 256;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const VERTEX_USAGE_SCHEMA_TABLE: &str = "archive_v3_wal_vertex_usage_schema";
const VERTEX_USAGE_LEDGER_TABLE: &str = "archive_v3_wal_vertex_usage_operations";
const VERTEX_USAGE_STATE_TABLE: &str = "archive_v3_wal_vertex_usage_state";
const MAX_VERTEX_USAGE_ROWS: u32 = 1_048_576;
const MAX_VERTEX_USAGE_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const VERTEX_USAGE_BOUNDS: DomainLedgerBounds =
    DomainLedgerBounds::new(MAX_VERTEX_USAGE_ROWS, MAX_VERTEX_USAGE_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrafficType {
    OnDemand,
    Batch,
    ProvisionedThroughput,
}

impl TrafficType {
    fn from_normalized(value: &str) -> Result<Self> {
        match value {
            "on_demand" => Ok(Self::OnDemand),
            "batch" => Ok(Self::Batch),
            "provisioned_throughput" => Ok(Self::ProvisionedThroughput),
            _ => Err(WalIdempotencyError::Malformed),
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::OnDemand => TRAFFIC_ON_DEMAND,
            Self::Batch => TRAFFIC_BATCH,
            Self::ProvisionedThroughput => TRAFFIC_PROVISIONED,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::OnDemand => "on_demand",
            Self::Batch => "batch",
            Self::ProvisionedThroughput => "provisioned_throughput",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResponseFields {
    metered: bool,
    returned_model: Option<String>,
    traffic_type: TrafficType,
    prompt_tokens: Option<i64>,
    input_text_tokens: Option<i64>,
    input_audio_tokens: Option<i64>,
    input_image_tokens: Option<i64>,
    cached_input_tokens: Option<i64>,
    cached_input_text_tokens: Option<i64>,
    cached_input_audio_tokens: Option<i64>,
    cached_input_image_tokens: Option<i64>,
    output_text_tokens: Option<i64>,
    thought_tokens: Option<i64>,
    total_tokens: Option<i64>,
}

impl ResponseFields {
    fn from_metadata(metadata: &super::super::vertex::VertexMetadata) -> Result<Self> {
        let (returned_model, normalized) = super::normalized_billable_response(metadata);
        let metered = normalized.is_some();
        let usage = normalized.unwrap_or_default();
        let traffic_type = TrafficType::from_normalized(&super::normalized_traffic_type(
            metadata.traffic_type.as_deref(),
        ))?;
        let fields = Self {
            metered,
            returned_model,
            traffic_type,
            prompt_tokens: super::to_i64(usage.prompt_tokens),
            input_text_tokens: super::to_i64(usage.input_text_tokens),
            input_audio_tokens: super::to_i64(usage.input_audio_tokens),
            input_image_tokens: super::to_i64(usage.input_image_tokens),
            cached_input_tokens: super::to_i64(usage.cached_input_tokens),
            cached_input_text_tokens: super::to_i64(usage.cached_input_text_tokens),
            cached_input_audio_tokens: super::to_i64(usage.cached_input_audio_tokens),
            cached_input_image_tokens: super::to_i64(usage.cached_input_image_tokens),
            output_text_tokens: super::to_i64(usage.output_tokens),
            thought_tokens: super::to_i64(usage.thought_tokens),
            total_tokens: super::to_i64(usage.total_tokens),
        };
        fields.validate()?;
        Ok(fields)
    }

    fn validate(&self) -> Result<()> {
        if self.metered && self.returned_model.is_none() {
            return Err(WalIdempotencyError::Malformed);
        }
        if let Some(model) = &self.returned_model {
            if model.is_empty()
                || model.len() > MAX_RETURNED_MODEL_BYTES
                || !super::super::vertex_model_name_is_billing_safe(model)
            {
                return Err(WalIdempotencyError::Malformed);
            }
        }
        for value in self.token_values().into_iter().flatten() {
            if value < 0 {
                return Err(WalIdempotencyError::Malformed);
            }
        }
        Ok(())
    }

    const fn token_values(&self) -> [Option<i64>; 11] {
        [
            self.prompt_tokens,
            self.input_text_tokens,
            self.input_audio_tokens,
            self.input_image_tokens,
            self.cached_input_tokens,
            self.cached_input_text_tokens,
            self.cached_input_audio_tokens,
            self.cached_input_image_tokens,
            self.output_text_tokens,
            self.thought_tokens,
            self.total_tokens,
        ]
    }

    const fn outcome(&self) -> &'static str {
        if self.metered {
            "metered"
        } else {
            "usage_missing"
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TerminalOutcome {
    Response(Box<ResponseFields>),
    Ambiguous { http_status: Option<u16> },
    NotBilled { http_status: u16 },
}

impl TerminalOutcome {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Response(fields) => fields.validate(),
            Self::Ambiguous { .. } | Self::NotBilled { .. } => Ok(()),
        }
    }
}

/// Stable terminal outcome for one pre-existing Vertex invocation. The event
/// ID is allocated and durably saved by the separately reviewed B boundary
/// before any provider request leaves the enclave.
pub(crate) struct VertexUsageOutcomePlan {
    operation_id: WalLogicalOperationId,
    event_id: String,
    outcome: TerminalOutcome,
}

impl VertexUsageOutcomePlan {
    pub(super) fn response(
        event_id: String,
        metadata: &super::super::vertex::VertexMetadata,
    ) -> Result<Self> {
        Self::new(
            event_id,
            TerminalOutcome::Response(Box::new(ResponseFields::from_metadata(metadata)?)),
        )
    }

    pub(super) fn ambiguous(event_id: String, http_status: Option<u16>) -> Result<Self> {
        Self::new(event_id, TerminalOutcome::Ambiguous { http_status })
    }

    pub(super) fn not_billed(event_id: String, http_status: u16) -> Result<Self> {
        Self::new(event_id, TerminalOutcome::NotBilled { http_status })
    }

    fn new(event_id: String, outcome: TerminalOutcome) -> Result<Self> {
        validate_event_id(&event_id)?;
        outcome.validate()?;
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::VertexUsage,
            event_id.as_bytes(),
        )?;
        Ok(Self {
            operation_id,
            event_id,
            outcome,
        })
    }

    #[cfg(test)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        event_id: &str,
        outcome: TerminalOutcome,
    ) -> Result<Self> {
        validate_event_id(event_id)?;
        outcome.validate()?;
        Ok(Self {
            operation_id,
            event_id: event_id.to_owned(),
            outcome,
        })
    }
}

pub(crate) struct VertexUsageOutcomeLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for VertexUsageOutcomePlan {
    type Ledger = VertexUsageOutcomeLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::VertexUsage
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.outcome.validate()?;
        let event_bytes = self.event_id.as_bytes();
        let event_length =
            u16::try_from(event_bytes.len()).map_err(|_| WalIdempotencyError::Limit)?;
        let mut request = Zeroizing::new(Vec::with_capacity(512));
        request.extend_from_slice(&VERTEX_USAGE_REQUEST_V1.to_be_bytes());
        request.extend_from_slice(&event_length.to_be_bytes());
        request.extend_from_slice(event_bytes);
        match &self.outcome {
            TerminalOutcome::Response(fields) => {
                request.push(TERMINAL_RESPONSE);
                request.push(if fields.metered {
                    RESPONSE_METERED
                } else {
                    RESPONSE_USAGE_MISSING
                });
                encode_optional_string(&mut request, fields.returned_model.as_deref())?;
                request.push(fields.traffic_type.tag());
                for value in fields.token_values() {
                    encode_optional_i64(&mut request, value)?;
                }
            }
            TerminalOutcome::Ambiguous { http_status } => {
                request.push(TERMINAL_AMBIGUOUS);
                encode_optional_u16(&mut request, *http_status);
            }
            TerminalOutcome::NotBilled { http_status } => {
                request.push(TERMINAL_NOT_BILLED);
                request.extend_from_slice(&http_status.to_be_bytes());
            }
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let Some(stored) = load_stored_outcome(transaction, &self.event_id)? else {
            return Err(WalIdempotencyError::Precondition);
        };
        if stored.outcome != "started" {
            return if stored.matches(&self.outcome) {
                Ok(WalReplayResult::unit())
            } else {
                Err(WalIdempotencyError::Precondition)
            };
        }
        if !stored.is_exact_started() {
            return Err(WalIdempotencyError::Precondition);
        }
        let changed = apply_started_outcome(transaction, &self.event_id, &self.outcome)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        super::refresh_coverage_conn(transaction).map_err(|_| WalIdempotencyError::Unavailable)?;
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

impl WalLogicalDomainLedger<VertexUsageOutcomePlan> for VertexUsageOutcomeLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<VertexUsageOutcomePlan>,
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
                 FROM archive_v3_wal_vertex_usage_operations
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
        let kind = WalOperationKind::VertexUsage;
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
        prepared: &PreparedLogicalMutation<VertexUsageOutcomePlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        VERTEX_USAGE_BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::VertexUsage;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_vertex_usage_operations
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
                "UPDATE archive_v3_wal_vertex_usage_state
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

fn apply_started_outcome(
    transaction: &Transaction<'_>,
    event_id: &str,
    outcome: &TerminalOutcome,
) -> Result<usize> {
    match outcome {
        TerminalOutcome::Response(fields) => transaction.execute(
            "UPDATE vertex_usage_events SET returned_model=?1,traffic_type=?2,
             http_status=200,prompt_tokens=?3,input_text_tokens=?4,input_audio_tokens=?5,
             input_image_tokens=?6,cached_input_tokens=?7,cached_input_text_tokens=?8,
             cached_input_audio_tokens=?9,cached_input_image_tokens=?10,
             output_text_tokens=?11,thought_tokens=?12,total_tokens=?13,outcome=?14,
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE event_id=?15 AND outcome='started'",
            params![
                fields.returned_model,
                fields.traffic_type.as_str(),
                fields.prompt_tokens,
                fields.input_text_tokens,
                fields.input_audio_tokens,
                fields.input_image_tokens,
                fields.cached_input_tokens,
                fields.cached_input_text_tokens,
                fields.cached_input_audio_tokens,
                fields.cached_input_image_tokens,
                fields.output_text_tokens,
                fields.thought_tokens,
                fields.total_tokens,
                fields.outcome(),
                event_id,
            ],
        ),
        TerminalOutcome::Ambiguous { http_status } => transaction.execute(
            "UPDATE vertex_usage_events SET outcome='ambiguous',http_status=?1,
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE event_id=?2 AND outcome='started'",
            params![http_status, event_id],
        ),
        TerminalOutcome::NotBilled { http_status } => transaction.execute(
            "UPDATE vertex_usage_events SET outcome='not_billed',
             delivery_state='delivered',http_status=?1,
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE event_id=?2 AND outcome='started'",
            params![http_status, event_id],
        ),
    }
    .map_err(|_| WalIdempotencyError::Unavailable)
}

#[derive(Debug, PartialEq, Eq)]
struct StoredOutcome {
    returned_model: Option<String>,
    traffic_type: String,
    http_status: Option<i64>,
    tokens: [Option<i64>; 11],
    outcome: String,
    delivery_state: String,
    delivery_attempt_count: i64,
}

impl StoredOutcome {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            returned_model: row.get(0)?,
            traffic_type: row.get(1)?,
            http_status: row.get(2)?,
            tokens: [
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
            ],
            outcome: row.get(14)?,
            delivery_state: row.get(15)?,
            delivery_attempt_count: row.get(16)?,
        })
    }

    fn is_exact_started(&self) -> bool {
        self.returned_model.is_none()
            && self.traffic_type == "on_demand"
            && self.http_status.is_none()
            && self.tokens == [None; 11]
            && self.outcome == "started"
            && self.delivery_state == "pending"
            && self.delivery_attempt_count == 0
    }

    fn delivery_state_is_valid(&self) -> bool {
        matches!(self.delivery_state.as_str(), "pending" | "delivered")
            && self.delivery_attempt_count >= 0
    }

    fn matches(&self, expected: &TerminalOutcome) -> bool {
        match expected {
            TerminalOutcome::Response(fields) => {
                self.returned_model == fields.returned_model
                    && self.traffic_type == fields.traffic_type.as_str()
                    && self.http_status == Some(200)
                    && self.tokens == fields.token_values()
                    && self.outcome == fields.outcome()
                    && self.delivery_state_is_valid()
            }
            TerminalOutcome::Ambiguous { http_status } => {
                self.returned_model.is_none()
                    && self.traffic_type == "on_demand"
                    && self.http_status == http_status.map(i64::from)
                    && self.tokens == [None; 11]
                    && self.outcome == "ambiguous"
                    && self.delivery_state_is_valid()
            }
            TerminalOutcome::NotBilled { http_status } => {
                self.returned_model.is_none()
                    && self.traffic_type == "on_demand"
                    && self.http_status == Some(i64::from(*http_status))
                    && self.tokens == [None; 11]
                    && self.outcome == "not_billed"
                    && self.delivery_state == "delivered"
                    && self.delivery_attempt_count >= 0
            }
        }
    }
}

fn load_stored_outcome(connection: &Connection, event_id: &str) -> Result<Option<StoredOutcome>> {
    connection
        .query_row(
            "SELECT returned_model,traffic_type,http_status,prompt_tokens,
                    input_text_tokens,input_audio_tokens,input_image_tokens,
                    cached_input_tokens,cached_input_text_tokens,cached_input_audio_tokens,
                    cached_input_image_tokens,output_text_tokens,thought_tokens,total_tokens,outcome,
                    delivery_state,delivery_attempt_count
             FROM vertex_usage_events WHERE event_id=?1",
            [event_id],
            StoredOutcome::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn require_kind(prepared: &PreparedLogicalMutation<VertexUsageOutcomePlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::VertexUsage)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn validate_event_id(value: &str) -> Result<()> {
    let Some(suffix) = value.strip_prefix("vtx_") else {
        return Err(WalIdempotencyError::Malformed);
    };
    if value.len() != MAX_EVENT_ID_BYTES
        || suffix.len() != 64
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn encode_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => output.extend_from_slice(&0u16.to_be_bytes()),
        Some(value) => {
            let length = u16::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
            if length == 0 {
                return Err(WalIdempotencyError::Malformed);
            }
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(value.as_bytes());
        }
    }
    Ok(())
}

fn encode_optional_i64(output: &mut Vec<u8>, value: Option<i64>) -> Result<()> {
    match value {
        None => output.push(0),
        Some(value) if value >= 0 => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        Some(_) => return Err(WalIdempotencyError::Malformed),
    }
    Ok(())
}

fn encode_optional_u16(output: &mut Vec<u8>, value: Option<u16>) {
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
            params![
                VERTEX_USAGE_SCHEMA_TABLE,
                VERTEX_USAGE_LEDGER_TABLE,
                VERTEX_USAGE_STATE_TABLE,
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
                    "CREATE TABLE archive_v3_wal_vertex_usage_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_vertex_usage_operations (
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
                     CREATE TABLE archive_v3_wal_vertex_usage_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_vertex_usage_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_vertex_usage_state
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
             FROM archive_v3_wal_vertex_usage_schema WHERE singleton=1",
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
             FROM archive_v3_wal_vertex_usage_state WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let row_count = u32::try_from(state.0).map_err(|_| WalIdempotencyError::Corrupt)?;
    let result_bytes = u64::try_from(state.1).map_err(|_| WalIdempotencyError::Corrupt)?;
    if row_count > MAX_VERTEX_USAGE_ROWS || result_bytes > MAX_VERTEX_USAGE_RESULT_BYTES {
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
    use crate::cp::vertex::{VertexMetadata, VertexUsage};
    use tempfile::tempdir;

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_domain_schema(&connection);
        connection
    }

    fn install_domain_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE vertex_usage_events (
                    event_id TEXT PRIMARY KEY,
                    returned_model TEXT,
                    traffic_type TEXT NOT NULL DEFAULT 'on_demand',
                    http_status INTEGER,
                    prompt_tokens INTEGER,
                    input_text_tokens INTEGER,
                    input_audio_tokens INTEGER,
                    input_image_tokens INTEGER,
                    cached_input_tokens INTEGER,
                    cached_input_text_tokens INTEGER,
                    cached_input_audio_tokens INTEGER,
                    cached_input_image_tokens INTEGER,
                    output_text_tokens INTEGER,
                    thought_tokens INTEGER,
                    total_tokens INTEGER,
                    outcome TEXT NOT NULL,
                    delivery_state TEXT NOT NULL DEFAULT 'pending',
                    delivery_attempt_count INTEGER NOT NULL DEFAULT 0,
                    observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                 ) STRICT;
                 CREATE TABLE vertex_usage_coverage (
                    period TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    pending_events INTEGER NOT NULL,
                    lost_events INTEGER NOT NULL,
                    delivery_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                 ) STRICT;",
            )
            .unwrap();
    }

    fn event(byte: char) -> String {
        format!("vtx_{}", byte.to_string().repeat(64))
    }

    fn insert_started(connection: &Connection, event_id: &str) {
        connection
            .execute(
                "INSERT INTO vertex_usage_events(event_id,outcome) VALUES (?1,'started')",
                [event_id],
            )
            .unwrap();
    }

    fn explicit_id(value: u8) -> WalLogicalOperationId {
        WalLogicalOperationId::from_bytes([value; 16]).unwrap()
    }

    fn complete_metadata() -> VertexMetadata {
        VertexMetadata {
            model_version: Some("gemini-3.5-flash-001".into()),
            traffic_type: Some("PROVISIONED_THROUGHPUT".into()),
            usage: Some(VertexUsage {
                prompt_details_present: true,
                cache_details_present: true,
                prompt_tokens: Some(12),
                input_text_tokens: Some(10),
                input_audio_tokens: Some(2),
                input_image_tokens: Some(0),
                cached_input_tokens: Some(3),
                cached_input_text_tokens: Some(3),
                cached_input_audio_tokens: Some(0),
                cached_input_image_tokens: Some(0),
                output_tokens: Some(4),
                thought_tokens: Some(0),
                total_tokens: Some(16),
                ..VertexUsage::default()
            }),
        }
    }

    fn coverage_sequence(connection: &Connection) -> Option<i64> {
        connection
            .query_row("SELECT sequence FROM vertex_usage_coverage", [], |row| {
                row.get(0)
            })
            .optional()
            .unwrap()
    }

    #[test]
    fn stable_event_identity_is_kind_scoped_and_request_distinguishes_outcomes() {
        let event_id = event('a');
        let first = VertexUsageOutcomePlan::ambiguous(event_id.clone(), Some(503)).unwrap();
        let replay = VertexUsageOutcomePlan::ambiguous(event_id.clone(), Some(503)).unwrap();
        let other_outcome = VertexUsageOutcomePlan::not_billed(event_id.clone(), 429).unwrap();
        assert_eq!(first.operation_id(), replay.operation_id());
        assert_eq!(first.operation_id(), other_outcome.operation_id());
        assert_eq!(
            first.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(
            first.canonical_request().unwrap(),
            other_outcome.canonical_request().unwrap()
        );
        assert_ne!(
            first.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::CaptureSessionFinish,
                event_id.as_bytes(),
            )
            .unwrap()
        );
        assert!(VertexUsageOutcomePlan::ambiguous("vtx_short".into(), None).is_err());
        assert!(VertexUsageOutcomePlan::not_billed(event('A'), 400).is_err());
    }

    #[test]
    fn metered_response_applies_once_and_replay_does_not_refresh_coverage() {
        let mut connection = connection();
        let event_id = event('b');
        insert_started(&connection, &event_id);
        let first = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(
                VertexUsageOutcomePlan::response(event_id.clone(), &complete_metadata()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(first.disposition(), LogicalMutationDisposition::Applied);
        first.into_validated_result().release().unwrap();
        let stored = load_stored_outcome(&connection, &event_id)
            .unwrap()
            .unwrap();
        assert!(stored.matches(
            &VertexUsageOutcomePlan::response(event_id.clone(), &complete_metadata())
                .unwrap()
                .outcome
        ));
        assert_eq!(coverage_sequence(&connection), Some(1));

        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(
                VertexUsageOutcomePlan::response(event_id, &complete_metadata()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        replay.into_validated_result().release().unwrap();
        assert_eq!(coverage_sequence(&connection), Some(1));
        assert_eq!(
            connection
                .query_row(
                    "SELECT row_count FROM archive_v3_wal_vertex_usage_state",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn missing_event_rolls_back_schema_and_same_identity_can_later_apply() {
        let mut connection = connection();
        let event_id = event('c');
        let plan = || VertexUsageOutcomePlan::ambiguous(event_id.clone(), None).unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan()).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name LIKE 'archive_v3_wal_vertex_usage_%'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        insert_started(&connection, &event_id);
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan()).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
    }

    #[test]
    fn all_terminal_variants_are_exact_and_conflicts_fail_closed() {
        let mut connection = connection();
        let ambiguous_id = event('d');
        insert_started(&connection, &ambiguous_id);
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(
                VertexUsageOutcomePlan::ambiguous(ambiguous_id.clone(), Some(504)).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    VertexUsageOutcomePlan::not_billed(ambiguous_id.clone(), 429).unwrap(),
                )
                .unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::FingerprintConflict
        );

        let not_billed_id = event('e');
        insert_started(&connection, &not_billed_id);
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(
                VertexUsageOutcomePlan::not_billed(not_billed_id.clone(), 400).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let state = connection
            .query_row(
                "SELECT outcome,delivery_state,http_status
                 FROM vertex_usage_events WHERE event_id=?1",
                [&not_billed_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(state, ("not_billed".into(), "delivered".into(), 400));

        let missing_usage_id = event('f');
        insert_started(&connection, &missing_usage_id);
        let metadata = VertexMetadata {
            model_version: Some("gemini-3.5-flash-001".into()),
            usage: None,
            traffic_type: None,
        };
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(
                VertexUsageOutcomePlan::response(missing_usage_id.clone(), &metadata).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT outcome FROM vertex_usage_events WHERE event_id=?1",
                    [&missing_usage_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "usage_missing"
        );
    }

    #[test]
    fn exact_terminal_adoption_succeeds_but_substitution_does_not() {
        let mut connection = connection();
        let adopted_id = event('1');
        connection
            .execute(
                "INSERT INTO vertex_usage_events(event_id,outcome,http_status)
                 VALUES (?1,'ambiguous',503)",
                [&adopted_id],
            )
            .unwrap();
        let adopted = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(
                VertexUsageOutcomePlan::ambiguous(adopted_id, Some(503)).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(adopted.disposition(), LogicalMutationDisposition::Applied);
        assert_eq!(coverage_sequence(&connection), None);

        let conflict_id = event('2');
        connection
            .execute(
                "INSERT INTO vertex_usage_events(event_id,outcome,http_status,delivery_state)
                 VALUES (?1,'not_billed',400,'delivered')",
                [&conflict_id],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    VertexUsageOutcomePlan::ambiguous(conflict_id, Some(400)).unwrap(),
                )
                .unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );

        let corrupt_started_id = event('0');
        connection
            .execute(
                "INSERT INTO vertex_usage_events(event_id,outcome,traffic_type)
                 VALUES (?1,'started','batch')",
                [&corrupt_started_id],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    VertexUsageOutcomePlan::not_billed(corrupt_started_id, 400).unwrap(),
                )
                .unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
    }

    #[test]
    fn row_cap_precedes_domain_mutation_while_committed_replay_survives() {
        let mut connection = connection();
        let first_id = event('3');
        insert_started(&connection, &first_id);
        let first_plan = || VertexUsageOutcomePlan::not_billed(first_id.clone(), 400).unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(first_plan()).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_vertex_usage_state SET row_count=?1",
                [i64::from(MAX_VERTEX_USAGE_ROWS)],
            )
            .unwrap();
        let next_id = event('4');
        insert_started(&connection, &next_id);
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    VertexUsageOutcomePlan::not_billed(next_id.clone(), 401).unwrap(),
                )
                .unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT outcome FROM vertex_usage_events WHERE event_id=?1",
                    [&next_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "started"
        );
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(first_plan()).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
    }

    #[test]
    fn byte_cap_precedes_domain_mutation_while_committed_replay_survives() {
        let mut connection = connection();
        let first_id = event('a');
        insert_started(&connection, &first_id);
        let first_plan = || VertexUsageOutcomePlan::ambiguous(first_id.clone(), Some(500)).unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(first_plan()).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_vertex_usage_state SET result_bytes=?1",
                [i64::try_from(MAX_VERTEX_USAGE_RESULT_BYTES).unwrap()],
            )
            .unwrap();
        let next_id = event('b');
        insert_started(&connection, &next_id);
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    VertexUsageOutcomePlan::not_billed(next_id.clone(), 401).unwrap(),
                )
                .unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT outcome FROM vertex_usage_events WHERE event_id=?1",
                    [&next_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "started"
        );
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(first_plan()).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
    }

    #[test]
    fn late_ledger_failure_rolls_back_terminal_row_and_coverage() {
        let mut connection = connection();
        {
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_vertex_wal_insert
                 BEFORE INSERT ON archive_v3_wal_vertex_usage_operations
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();
        let event_id = event('5');
        insert_started(&connection, &event_id);
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    VertexUsageOutcomePlan::not_billed(event_id.clone(), 400).unwrap(),
                )
                .unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Unavailable
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT outcome FROM vertex_usage_events WHERE event_id=?1",
                    [&event_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "started"
        );
        assert_eq!(coverage_sequence(&connection), None);
        assert_eq!(load_ledger_state(&connection).unwrap(), (0, 0));
    }

    #[test]
    fn close_reopen_replays_exactly_and_admits_new_event() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("vertex-usage.sqlite");
        let first_id = event('6');
        {
            let mut connection = Connection::open(&path).unwrap();
            install_domain_schema(&connection);
            insert_started(&connection, &first_id);
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(
                    VertexUsageOutcomePlan::ambiguous(first_id.clone(), Some(500)).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        }
        let mut reopened = Connection::open(&path).unwrap();
        let replay = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(
                VertexUsageOutcomePlan::ambiguous(first_id, Some(500)).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(coverage_sequence(&reopened), Some(1));

        let next_id = event('7');
        insert_started(&reopened, &next_id);
        let next = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(
                VertexUsageOutcomePlan::not_billed(next_id, 404).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(next.disposition(), LogicalMutationDisposition::Applied);
        assert_eq!(coverage_sequence(&reopened), Some(2));
    }

    #[test]
    fn partial_schema_and_ledger_tamper_fail_closed() {
        let mut partial = connection();
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_vertex_usage_schema (
                    singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        let partial_id = event('8');
        insert_started(&partial, &partial_id);
        assert_eq!(
            execute_prepared_for_owner(
                &mut partial,
                PreparedLogicalMutation::prepare(
                    VertexUsageOutcomePlan::ambiguous(partial_id, None).unwrap(),
                )
                .unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );

        let mut tampered = connection();
        let event_id = event('9');
        insert_started(&tampered, &event_id);
        let plan = || {
            VertexUsageOutcomePlan::with_operation_id(
                explicit_id(9),
                &event_id,
                TerminalOutcome::Ambiguous {
                    http_status: Some(502),
                },
            )
            .unwrap()
        };
        execute_prepared_for_owner(
            &mut tampered,
            PreparedLogicalMutation::prepare(plan()).unwrap(),
        )
        .unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_vertex_usage_operations
                 SET result_commitment=zeroblob(32)",
                [],
            )
            .err()
            .unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_vertex_usage_operations
                 SET result_commitment=?1",
                [[7u8; 32].as_slice()],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut tampered,
                PreparedLogicalMutation::prepare(plan()).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );
    }
}
