//! Media work-unit output reservation as a sealed WAL plan (ADR-0022 F6).
//!
//! `reserve_media_output` reserves Vertex output spend for **every** outbound
//! attempt, retries included: a prior attempt may have completed billable
//! work even when Kioku timed out or rejected its response, so reusing a
//! reservation would let retry spend exceed the configured hard ceiling. The
//! Control-side quota verdict stays where it is; this plan settles only the
//! archive half — the per-job `usage_json` stamps and the work unit's
//! `reservation_retained=1` — under the WAL owner's lease.
//!
//! Identity anchors on `media_work_units.attempt_count`, which the claim path
//! advanced durably *before* this plan is constructed (R3 case 3): the same
//! attempt retried derives the same id, a new claim derives a new one.
//!
//! The predecessor CAS pins the **observed** `reservation_retained`, never a
//! literal `0`: the flag is one-way (nothing resets it), so on a retry the
//! observed predecessor is `1`, and a hard-coded `0` would wedge every media
//! retry — a total media outage sitting in the Tier-0 prerequisite chain.

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
const SUBTYPE: &[u8] = b"adr-0022-media-work-reservation-v1";
const PROCESSOR_VERSION: i64 = 1;
const MAX_ID_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_JOBS: usize = 256;
const MAX_USAGE_BYTES: usize = 4 * 1024;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_media_work_reservation_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_media_work_reservation_operations";
const STATE_TABLE: &str = "archive_v3_wal_media_work_reservation_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

pub(crate) struct MediaWorkReservationPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    work_unit_id: String,
    work_class: String,
    attempt_count: i64,
    job_ids: Vec<i64>,
    requested_output_tokens: i64,
    committed_at: String,
    predecessor_retained: i64,
    predecessor_unit_usage: Option<String>,
    predecessor_job_usage: Vec<Option<String>>,
    target_usage: String,
}

impl MediaWorkReservationPlan {
    /// `predecessor_*` are the values a routed read observed immediately
    /// before construction. The plan is constructed once per reservation and
    /// re-submitted verbatim on conflict (R5); it is never rebuilt from a
    /// fresh read of the rows it is about to change.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn new(
        account_id: String,
        work_unit_id: String,
        work_class: String,
        attempt_count: i64,
        job_ids: Vec<i64>,
        requested_output_tokens: i64,
        committed_at: String,
        predecessor_retained: i64,
        predecessor_unit_usage: Option<String>,
        predecessor_job_usage: Vec<Option<String>>,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        validate_id(&work_unit_id)?;
        if work_class != "audio" && work_class != "screen" {
            return Err(WalIdempotencyError::Malformed);
        }
        if attempt_count < 1
            || requested_output_tokens <= 0
            || job_ids.is_empty()
            || job_ids.len() > MAX_JOBS
            || job_ids.len() != predecessor_job_usage.len()
            || !job_ids.windows(2).all(|pair| pair[0] < pair[1])
            || job_ids.iter().any(|id| *id <= 0)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
            || committed_at.contains('\0')
        {
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
        // Byte-identical to the legacy writer: the same `json!` literal, so
        // the two populations' rows cannot drift textually.
        let target_usage = json!({
            "work_unit_id": work_unit_id,
            "work_class": work_class,
            "member_count": job_ids.len(),
            "reservation_state": "reserved",
            "reserved_output_tokens": requested_output_tokens,
            "processor_version": PROCESSOR_VERSION,
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
                &requested_output_tokens.to_be_bytes(),
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
            requested_output_tokens,
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
            // A later claim advanced the attempt ladder (or the unit was
            // rebuilt): this reservation belongs to an attempt that no longer
            // exists, and applying it would stamp stale spend bookkeeping.
            return Err(WalIdempotencyError::Precondition);
        }
        let mut all_converged = unit.reservation_retained == 1
            && unit.usage_json.as_deref() == Some(&self.target_usage);
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

pub(crate) struct MediaWorkReservationLedger;

impl WalLogicalDomainPlan for MediaWorkReservationPlan {
    type Ledger = MediaWorkReservationLedger;
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
        request.extend_from_slice(&self.requested_output_tokens.to_be_bytes());
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
                 SET reservation_retained=1,usage_json=?1,updated_at=?2
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
        // The settled state must be exactly the target before the ledger row
        // becomes durable.
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

impl WalLogicalDomainLedger<MediaWorkReservationPlan> for MediaWorkReservationLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<MediaWorkReservationPlan>,
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
                 FROM archive_v3_wal_media_work_reservation_operations
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
        prepared: &PreparedLogicalMutation<MediaWorkReservationPlan>,
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
                "INSERT INTO archive_v3_wal_media_work_reservation_operations
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
                "UPDATE archive_v3_wal_media_work_reservation_state
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

struct StoredUnit {
    work_class: String,
    reservation_retained: i64,
    attempt_count: i64,
    usage_json: Option<String>,
}

fn load_unit(transaction: &Transaction<'_>, work_unit_id: &str) -> Result<StoredUnit> {
    transaction
        .query_row(
            "SELECT work_class,reservation_retained,attempt_count,usage_json
             FROM media_work_units WHERE id=?1",
            [work_unit_id],
            |row| {
                Ok(StoredUnit {
                    work_class: row.get(0)?,
                    reservation_retained: row.get(1)?,
                    attempt_count: row.get(2)?,
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

fn require_kind(prepared: &PreparedLogicalMutation<MediaWorkReservationPlan>) -> Result<()> {
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
                    "CREATE TABLE archive_v3_wal_media_work_reservation_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_media_work_reservation_operations (
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
                     CREATE TABLE archive_v3_wal_media_work_reservation_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_media_work_reservation_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_media_work_reservation_state
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
             FROM archive_v3_wal_media_work_reservation_schema WHERE singleton=1",
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
             FROM archive_v3_wal_media_work_reservation_state WHERE singleton=1",
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

fn validate_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.contains('\0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
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
    const WORK: &str = "work-unit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const COMMITTED_AT: &str = "2026-08-20T12:00:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE media_processing_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    job_kind TEXT NOT NULL,
                    input_revision TEXT NOT NULL,
                    processor_version INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    lease_until TEXT,
                    error_code TEXT,
                    model_id TEXT,
                    prompt_version INTEGER,
                    schema_version INTEGER,
                    usage_json TEXT,
                    updated_at TEXT NOT NULL DEFAULT ''
                 );
                 CREATE TABLE media_work_units (
                    id TEXT PRIMARY KEY,
                    work_class TEXT NOT NULL,
                    processor_version INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT NOT NULL,
                    reserved_output_tokens INTEGER NOT NULL,
                    reservation_retained INTEGER NOT NULL DEFAULT 0,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    error_code TEXT,
                    usage_json TEXT,
                    created_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT ''
                 );",
            )
            .unwrap();
    }

    fn seed_claimed_attempt(connection: &Connection, attempt: i64) -> Vec<i64> {
        connection
            .execute(
                "INSERT INTO media_work_units
                 (id,work_class,processor_version,state,started_at,ended_at,
                  reserved_output_tokens,reservation_retained,attempt_count)
                 VALUES (?1,'screen',1,'processing','a','b',512,0,?2)
                 ON CONFLICT(id) DO UPDATE SET attempt_count=?2",
                params![WORK, attempt],
            )
            .unwrap();
        let mut ids = Vec::new();
        for suffix in ["one", "two"] {
            connection
                .execute(
                    "INSERT INTO media_processing_jobs
                     (event_id,job_kind,input_revision,processor_version,state)
                     VALUES (?1,'screen_describe','rev',1,'processing')
                     ON CONFLICT DO NOTHING",
                    [format!("evt-{suffix}")],
                )
                .unwrap();
            let id: i64 = connection
                .query_row(
                    "SELECT id FROM media_processing_jobs WHERE event_id=?1",
                    [format!("evt-{suffix}")],
                    |row| row.get(0),
                )
                .unwrap();
            ids.push(id);
        }
        ids.sort_unstable();
        ids
    }

    fn observed(
        connection: &Connection,
        ids: &[i64],
    ) -> (i64, Option<String>, Vec<Option<String>>) {
        let (retained, unit_usage): (i64, Option<String>) = connection
            .query_row(
                "SELECT reservation_retained,usage_json FROM media_work_units WHERE id=?1",
                [WORK],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let job_usage = ids
            .iter()
            .map(|id| {
                connection
                    .query_row(
                        "SELECT usage_json FROM media_processing_jobs WHERE id=?1",
                        [id],
                        |row| row.get(0),
                    )
                    .unwrap()
            })
            .collect();
        (retained, unit_usage, job_usage)
    }

    fn plan_for(connection: &Connection, ids: &[i64], attempt: i64) -> MediaWorkReservationPlan {
        let (retained, unit_usage, job_usage) = observed(connection, ids);
        MediaWorkReservationPlan::new(
            ACCOUNT.into(),
            WORK.into(),
            "screen".into(),
            attempt,
            ids.to_vec(),
            512,
            COMMITTED_AT.into(),
            retained,
            unit_usage,
            job_usage,
        )
        .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: MediaWorkReservationPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn first_attempt_reserves_and_replays_without_double_apply() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let ids = seed_claimed_attempt(&connection, 1);
        let plan = plan_for(&connection, &ids, 1);
        let replay = plan_for(&connection, &ids, 1);
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let (retained, unit_usage, job_usage) = observed(&connection, &ids);
        assert_eq!(retained, 1);
        let target = unit_usage.clone().unwrap();
        assert!(target.contains("\"reservation_state\":\"reserved\""));
        assert!(job_usage
            .iter()
            .all(|usage| usage.as_deref() == Some(target.as_str())));
        // Same attempt, identical plan: replays from the ledger, no second
        // application.
        assert!(matches!(
            settle(&mut connection, replay).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        assert_eq!(observed(&connection, &ids).0, 1);
    }

    #[test]
    fn retry_attempt_pins_the_observed_retained_one_and_does_not_wedge() {
        // THE trap this family exists to avoid: reservation_retained is
        // one-way, so a second attempt observes 1 and must succeed. A plan
        // that hard-coded predecessor 0 would return Precondition here and
        // every media retry would wedge.
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let ids = seed_claimed_attempt(&connection, 1);
        let first = plan_for(&connection, &ids, 1);
        assert!(matches!(
            settle(&mut connection, first).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        // The claim advances the durable attempt ladder; the reservation for
        // attempt 2 observes retained=1 and the prior usage as predecessor.
        seed_claimed_attempt(&connection, 2);
        let (retained, _, _) = observed(&connection, &ids);
        assert_eq!(retained, 1, "the flag is one-way by construction");
        let retry = plan_for(&connection, &ids, 2);
        assert!(matches!(
            settle(&mut connection, retry).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        // Distinct attempts derive distinct operations (property B).
        let first = plan_for(&connection, &ids, 2).operation_id;
        seed_claimed_attempt(&connection, 3);
        let second = plan_for(&connection, &ids, 3).operation_id;
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn stale_attempt_and_moved_rows_fail_closed() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let ids = seed_claimed_attempt(&connection, 1);
        let stale = plan_for(&connection, &ids, 1);
        // A later claim advances the ladder before the stale plan settles.
        seed_claimed_attempt(&connection, 2);
        assert!(matches!(
            settle(&mut connection, stale),
            Err(WalIdempotencyError::Precondition)
        ));
        // Rows moved under a current-attempt plan: neither converged nor at
        // the observed predecessor.
        let plan = plan_for(&connection, &ids, 2);
        connection
            .execute(
                "UPDATE media_processing_jobs SET usage_json='{\"moved\":true}' WHERE id=?1",
                [ids[0]],
            )
            .unwrap();
        assert!(matches!(
            settle(&mut connection, plan),
            Err(WalIdempotencyError::Precondition)
        ));
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        for (attempt, ids, tokens, class) in [
            (0i64, vec![1i64, 2], 512i64, "screen"),
            (1, vec![], 512, "screen"),
            (1, vec![2, 1], 512, "screen"),
            (1, vec![1, 1], 512, "screen"),
            (1, vec![1, 2], 0, "screen"),
            (1, vec![1, 2], 512, "video"),
        ] {
            let predecessors = vec![None; ids.len()];
            assert!(MediaWorkReservationPlan::new(
                ACCOUNT.into(),
                WORK.into(),
                class.into(),
                attempt,
                ids,
                tokens,
                COMMITTED_AT.into(),
                0,
                None,
                predecessors,
            )
            .is_err());
        }
    }

    #[test]
    fn ledger_fingerprint_conflict_is_detected() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let ids = seed_claimed_attempt(&connection, 1);
        let plan = plan_for(&connection, &ids, 1);
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        // Same identity fields, different carried timestamp: same operation
        // id, different fingerprint. The ledger must refuse, not replay.
        let (retained, unit_usage, job_usage) = observed(&connection, &ids);
        let conflicting = MediaWorkReservationPlan::new(
            ACCOUNT.into(),
            WORK.into(),
            "screen".into(),
            1,
            ids.clone(),
            512,
            "2026-08-20T13:00:00.000Z".into(),
            retained,
            unit_usage,
            job_usage,
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, conflicting),
            Err(WalIdempotencyError::FingerprintConflict)
        ));
    }
}
