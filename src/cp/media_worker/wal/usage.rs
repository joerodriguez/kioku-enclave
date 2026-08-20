//! Terminal media work usage settlement as a sealed WAL plan (ADR-0022,
//! the missing family surfaced by the storyboard wiring).
//!
//! `persist_actual_media_usage` stamps the returned provider usage onto the
//! work unit and every member job after the paid media call returns. The
//! bound storyboard result plan **requires** this terminal usage before it
//! can apply, so this family sits between the provider return and the
//! result settle on the screen lane (the audio lane shares the owner).
//!
//! Identity follows F6 (the reservation family) exactly — R3 case 3: the
//! work unit's `attempt_count`, advanced durably by the claim path before
//! any settle, anchors the attempt. The same attempt retried derives the
//! same id; a re-claimed unit derives a new one, which is why the observed
//! predecessors and the commit stamp are safely fingerprinted. `apply()`
//! carries the same adopt ladder: everything-already-target converges as a
//! lost-ack replay, anything that is neither target nor the observed
//! predecessor fails closed.
//!
//! The target usage json is built INSIDE the plan from carried provider
//! facts with the same `json!` literal the legacy writer uses, so the two
//! populations' rows cannot drift textually.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-media-usage-settlement-v1";
const PROCESSOR_VERSION: i64 = 1;
const MAX_ID_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_JOBS: usize = 256;
const MAX_USAGE_BYTES: usize = 8 * 1024;
const MAX_TEXT_BYTES: usize = 256;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_media_usage_settlement_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_media_usage_settlement_operations";
const STATE_TABLE: &str = "archive_v3_wal_media_usage_settlement_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 1_048_576 * 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// The provider facts one settled media generation carries — exactly the
/// values the legacy writer embeds, so the target json stays byte-identical.
pub(in crate::cp) struct MediaUsageFacts {
    pub(in crate::cp) reserved_output_tokens: u32,
    pub(in crate::cp) prompt_tokens: Option<u64>,
    pub(in crate::cp) input_text_tokens: Option<u64>,
    pub(in crate::cp) input_audio_tokens: Option<u64>,
    pub(in crate::cp) input_image_tokens: Option<u64>,
    pub(in crate::cp) cached_input_tokens: Option<u64>,
    pub(in crate::cp) output_tokens: Option<u64>,
    pub(in crate::cp) thought_tokens: Option<u64>,
    pub(in crate::cp) total_tokens: Option<u64>,
    pub(in crate::cp) returned_model: Option<String>,
    pub(in crate::cp) traffic_type: Option<String>,
    pub(in crate::cp) latency_ms: u64,
}

pub(crate) struct MediaUsageSettlementPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    work_unit_id: String,
    work_class: String,
    attempt_count: i64,
    job_ids: Vec<i64>,
    committed_at: String,
    predecessor_retained: i64,
    predecessor_unit_usage: Option<String>,
    predecessor_job_usage: Vec<Option<String>>,
    target_usage: String,
}

impl MediaUsageSettlementPlan {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp) fn new(
        account_id: String,
        work_unit_id: String,
        work_class: String,
        attempt_count: i64,
        job_ids: Vec<i64>,
        facts: MediaUsageFacts,
        committed_at: String,
        predecessor_retained: i64,
        predecessor_unit_usage: Option<String>,
        predecessor_job_usage: Vec<Option<String>>,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if work_unit_id.is_empty()
            || work_unit_id.len() > MAX_ID_BYTES
            || !matches!(work_class.as_str(), "audio" | "screen")
            || attempt_count <= 0
            || job_ids.is_empty()
            || job_ids.len() > MAX_JOBS
            || predecessor_job_usage.len() != job_ids.len()
            || committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if !job_ids.windows(2).all(|pair| pair[0] < pair[1]) || job_ids[0] <= 0 {
            return Err(WalIdempotencyError::Malformed);
        }
        if !matches!(predecessor_retained, 0 | 1) {
            return Err(WalIdempotencyError::Malformed);
        }
        for usage in predecessor_job_usage
            .iter()
            .chain(std::iter::once(&predecessor_unit_usage))
            .flatten()
        {
            if usage.len() > MAX_USAGE_BYTES || usage.contains('\0') {
                return Err(WalIdempotencyError::Malformed);
            }
        }
        for value in [
            facts.returned_model.as_deref(),
            facts.traffic_type.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
                return Err(WalIdempotencyError::Malformed);
            }
        }
        // Byte-identical to the legacy writer: the same `json!` literal.
        let target_usage = json!({
            "work_unit_id": work_unit_id,
            "work_class": work_class,
            "member_count": job_ids.len(),
            "reservation_state": "reserved",
            "reserved_output_tokens": facts.reserved_output_tokens,
            "actual_prompt_tokens": facts.prompt_tokens,
            "actual_input_text_tokens": facts.input_text_tokens,
            "actual_input_audio_tokens": facts.input_audio_tokens,
            "actual_input_image_tokens": facts.input_image_tokens,
            "actual_cached_input_tokens": facts.cached_input_tokens,
            "actual_output_tokens": facts.output_tokens,
            "actual_thought_tokens": facts.thought_tokens,
            "actual_total_tokens": facts.total_tokens,
            "returned_model": facts.returned_model.as_deref(),
            "traffic_type": facts.traffic_type.as_deref(),
            "latency_ms": facts.latency_ms,
            "processor_version": PROCESSOR_VERSION,
            "outcome": "model_returned",
        })
        .to_string();
        if target_usage.len() > MAX_USAGE_BYTES {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut jobs_digest = Sha256::new();
        for id in &job_ids {
            jobs_digest.update(id.to_be_bytes());
        }
        let jobs_digest: [u8; 32] = jobs_digest.finalize().into();
        let source = stable_operation_source(
            SUBTYPE,
            &[
                account_id.as_bytes(),
                work_unit_id.as_bytes(),
                &attempt_count.to_be_bytes(),
                &jobs_digest,
                &PROCESSOR_VERSION.to_be_bytes(),
            ],
        )?;
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::DeterministicMediaWorkResult,
            &source,
        )?;
        Ok(Self {
            operation_id,
            account_id,
            work_unit_id,
            work_class,
            attempt_count,
            job_ids,
            committed_at,
            predecessor_retained,
            predecessor_unit_usage,
            predecessor_job_usage,
            target_usage,
        })
    }

    fn adopt_state(&self, transaction: &Transaction<'_>) -> Result<AdoptState> {
        let unit = load_unit(transaction, &self.work_unit_id)?;
        if unit.work_class != self.work_class || unit.attempt_count != self.attempt_count {
            // A later claim advanced the attempt ladder: this settlement
            // belongs to an attempt that no longer exists.
            return Err(WalIdempotencyError::Precondition);
        }
        let mut all_converged = unit.usage_json.as_deref() == Some(&self.target_usage);
        let mut all_predecessor = unit.reservation_retained == self.predecessor_retained
            && unit.usage_json == self.predecessor_unit_usage;
        for (job_id, predecessor) in self.job_ids.iter().zip(&self.predecessor_job_usage) {
            let usage = load_job_usage(transaction, *job_id)?;
            if usage.as_deref() != Some(&self.target_usage) {
                all_converged = false;
            }
            if usage != *predecessor {
                all_predecessor = false;
            }
        }
        Ok(AdoptState {
            all_converged,
            all_predecessor,
        })
    }
}

struct AdoptState {
    all_converged: bool,
    all_predecessor: bool,
}

struct UnitRow {
    work_class: String,
    attempt_count: i64,
    reservation_retained: i64,
    usage_json: Option<String>,
}

fn load_unit(transaction: &Transaction<'_>, work_unit_id: &str) -> Result<UnitRow> {
    transaction
        .query_row(
            "SELECT work_class,attempt_count,reservation_retained,usage_json
             FROM media_work_units WHERE id=?1",
            [work_unit_id],
            |row| {
                Ok(UnitRow {
                    work_class: row.get(0)?,
                    attempt_count: row.get(1)?,
                    reservation_retained: row.get(2)?,
                    usage_json: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)
}

fn load_job_usage(transaction: &Transaction<'_>, job_id: i64) -> Result<Option<String>> {
    transaction
        .query_row(
            "SELECT usage_json FROM media_processing_jobs WHERE id=?1",
            [job_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)
}

pub(crate) struct MediaUsageSettlementLedger;

impl WalLogicalDomainPlan for MediaUsageSettlementPlan {
    type Ledger = MediaUsageSettlementLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::DeterministicMediaWorkResult
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(4 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.work_unit_id)?;
        encode_string(&mut request, &self.work_class)?;
        request.extend_from_slice(&self.attempt_count.to_be_bytes());
        encode_len(&mut request, self.job_ids.len())?;
        for (job_id, predecessor) in self.job_ids.iter().zip(&self.predecessor_job_usage) {
            request.extend_from_slice(&job_id.to_be_bytes());
            encode_optional_string(&mut request, predecessor.as_deref())?;
        }
        encode_string(&mut request, &self.committed_at)?;
        request.push(
            u8::try_from(self.predecessor_retained).map_err(|_| WalIdempotencyError::Malformed)?,
        );
        encode_optional_string(&mut request, self.predecessor_unit_usage.as_deref())?;
        encode_string(&mut request, &self.target_usage)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let adopt = self.adopt_state(transaction)?;
        if adopt.all_converged {
            // Lost-ack convergence: everything already equals the target.
            return Ok(WalReplayResult::unit());
        }
        if !adopt.all_predecessor {
            // Neither the settled target nor the observed predecessor:
            // something else moved these rows. Fail closed; the caller
            // re-derives against fresh state as a NEW operation.
            return Err(WalIdempotencyError::Precondition);
        }
        for (job_id, predecessor) in self.job_ids.iter().zip(&self.predecessor_job_usage) {
            let changed = transaction
                .execute(
                    "UPDATE media_processing_jobs SET usage_json=?1
                     WHERE id=?2 AND usage_json IS ?3",
                    params![self.target_usage, job_id, predecessor.as_deref()],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        let changed = transaction
            .execute(
                "UPDATE media_work_units
                 SET usage_json=?1,updated_at=?2
                 WHERE id=?3 AND reservation_retained=?4 AND usage_json IS ?5
                   AND attempt_count=?6",
                params![
                    self.target_usage,
                    self.committed_at,
                    self.work_unit_id,
                    self.predecessor_retained,
                    self.predecessor_unit_usage.as_deref(),
                    self.attempt_count,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Precondition);
        }
        if !self.adopt_state(transaction)?.all_converged {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<MediaUsageSettlementPlan> for MediaUsageSettlementLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<MediaUsageSettlementPlan>,
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
                 FROM archive_v3_wal_media_usage_settlement_operations
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
        let kind = WalOperationKind::DeterministicMediaWorkResult;
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
        prepared: &PreparedLogicalMutation<MediaUsageSettlementPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::DeterministicMediaWorkResult;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_media_usage_settlement_operations
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
                "UPDATE archive_v3_wal_media_usage_settlement_state
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

fn require_kind(prepared: &PreparedLogicalMutation<MediaUsageSettlementPlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::DeterministicMediaWorkResult {
        return Err(WalIdempotencyError::Corrupt);
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
                    "CREATE TABLE archive_v3_wal_media_usage_settlement_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_media_usage_settlement_operations (
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
                     CREATE TABLE archive_v3_wal_media_usage_settlement_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 9437184)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_media_usage_settlement_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_media_usage_settlement_state
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
             FROM archive_v3_wal_media_usage_settlement_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::DeterministicMediaWorkResult.codec_version()),
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
             FROM archive_v3_wal_media_usage_settlement_state WHERE singleton=1",
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

fn encode_len(request: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| WalIdempotencyError::Limit)?;
    request.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn encode_bytes(request: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    encode_len(request, value.len())?;
    request.extend_from_slice(value);
    Ok(())
}

fn encode_string(request: &mut Vec<u8>, value: &str) -> Result<()> {
    encode_bytes(request, value.as_bytes())
}

fn encode_optional_string(request: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => {
            request.push(0);
            Ok(())
        }
        Some(value) => {
            request.push(1);
            encode_string(request, value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const WORK: &str = "work-1";
    const COMMITTED_AT: &str = "2026-08-20T21:00:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE media_work_units (
                    id TEXT PRIMARY KEY,
                    work_class TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    reservation_retained INTEGER NOT NULL,
                    usage_json TEXT,
                    updated_at TEXT NOT NULL DEFAULT ''
                 );
                 CREATE TABLE media_processing_jobs (
                    id INTEGER PRIMARY KEY,
                    usage_json TEXT
                 );
                 INSERT INTO media_work_units VALUES ('work-1','screen',2,1,'{\"r\":1}','');
                 INSERT INTO media_processing_jobs VALUES (10,'{\"r\":1}'),(11,'{\"r\":1}');",
            )
            .unwrap();
    }

    fn facts() -> MediaUsageFacts {
        MediaUsageFacts {
            reserved_output_tokens: 4096,
            prompt_tokens: Some(120),
            input_text_tokens: Some(20),
            input_audio_tokens: None,
            input_image_tokens: Some(100),
            cached_input_tokens: None,
            output_tokens: Some(64),
            thought_tokens: None,
            total_tokens: Some(184),
            returned_model: Some("gemini-2.5-flash".into()),
            traffic_type: Some("on_demand".into()),
            latency_ms: 902,
        }
    }

    fn build(attempt_count: i64, committed_at: &str) -> MediaUsageSettlementPlan {
        MediaUsageSettlementPlan::new(
            ACCOUNT.into(),
            WORK.into(),
            "screen".into(),
            attempt_count,
            vec![10, 11],
            facts(),
            committed_at.into(),
            1,
            Some("{\"r\":1}".into()),
            vec![Some("{\"r\":1}".into()), Some("{\"r\":1}".into())],
        )
        .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: MediaUsageSettlementPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn terminal_usage_settles_replays_and_adopts_a_lost_ack() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        assert!(matches!(
            settle(&mut connection, build(2, COMMITTED_AT)).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let (unit_usage, updated): (String, String) = connection
            .query_row(
                "SELECT usage_json,updated_at FROM media_work_units WHERE id='work-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(unit_usage.contains("\"outcome\":\"model_returned\""));
        assert!(unit_usage.contains("\"actual_total_tokens\":184"));
        assert_eq!(updated, COMMITTED_AT);
        let job_usage: String = connection
            .query_row(
                "SELECT usage_json FROM media_processing_jobs WHERE id=11",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(job_usage, unit_usage);
        // Exact replay resolves from the ledger.
        assert!(matches!(
            settle(&mut connection, build(2, COMMITTED_AT)).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        // Same-attempt re-derivation with a fresh stamp shares the identity
        // but not the fingerprint: the ledger refuses it. This mirrors F6 —
        // the real retry path is a re-claim, which advances the attempt
        // anchor and derives a NEW operation; within one attempt the owner
        // constructs exactly once.
        assert!(matches!(
            settle(&mut connection, build(2, "2026-08-20T21:05:00.000Z")),
            Err(WalIdempotencyError::FingerprintConflict)
        ));
    }

    #[test]
    fn a_replayed_apply_over_settled_rows_adopts_as_converged() {
        // Segment-replay shape: the rows already carry the target (a prior
        // apply landed; the ledger row is absent in this fresh store), and
        // the carried predecessors describe the pre-state. The adopt ladder
        // must converge as a unit result instead of failing the CAS.
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let target = build(2, COMMITTED_AT).target_usage.clone();
        connection
            .execute(
                "UPDATE media_work_units SET usage_json=?1 WHERE id='work-1'",
                [&target],
            )
            .unwrap();
        connection
            .execute("UPDATE media_processing_jobs SET usage_json=?1", [&target])
            .unwrap();
        assert!(matches!(
            settle(&mut connection, build(2, COMMITTED_AT)).unwrap(),
            LogicalMutationDisposition::Applied
        ));
    }

    #[test]
    fn a_moved_row_fails_closed_and_a_new_attempt_is_a_new_operation() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
            .execute(
                "UPDATE media_processing_jobs SET usage_json='{\"other\":1}' WHERE id=11",
                [],
            )
            .unwrap();
        assert!(matches!(
            settle(&mut connection, build(2, COMMITTED_AT)),
            Err(WalIdempotencyError::Precondition)
        ));
        // Identity: the attempt anchor separates operations; the commit
        // stamp does not.
        assert_eq!(
            build(2, COMMITTED_AT).operation_id(),
            build(2, "2026-08-20T22:00:00.000Z").operation_id()
        );
        assert_ne!(
            build(2, COMMITTED_AT).operation_id(),
            build(3, COMMITTED_AT).operation_id()
        );
    }

    #[test]
    fn a_stale_attempt_and_malformed_inputs_are_refused() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
            .execute(
                "UPDATE media_work_units SET attempt_count=3 WHERE id='work-1'",
                [],
            )
            .unwrap();
        assert!(matches!(
            settle(&mut connection, build(2, COMMITTED_AT)),
            Err(WalIdempotencyError::Precondition)
        ));
        assert!(MediaUsageSettlementPlan::new(
            ACCOUNT.into(),
            WORK.into(),
            "video".into(),
            2,
            vec![10, 11],
            facts(),
            COMMITTED_AT.into(),
            1,
            None,
            vec![None, None],
        )
        .is_err());
        assert!(MediaUsageSettlementPlan::new(
            ACCOUNT.into(),
            WORK.into(),
            "screen".into(),
            0,
            vec![10],
            facts(),
            COMMITTED_AT.into(),
            1,
            None,
            vec![None],
        )
        .is_err());
    }
}
