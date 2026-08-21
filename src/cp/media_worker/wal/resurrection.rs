//! Terminal-failure job resurrection as a sealed WAL plan (ADR-0022 F7).
//!
//! The live sweep enumerates a bounded eligible set and flips each job (and
//! its failed media objects) back onto the retry ladder. The identity is the
//! **resolved eligible set** — the ordered `(job_id, event_id, predecessor
//! state, attempt_count, updated_at)` tuples — never the clock: the sweep
//! bounds (`stale_before`, `window_start`) and the carried commit stamp enter
//! only the fingerprinted canonical request. A retry after a failed settle
//! re-derives the same identity; a retry after a lost ack re-enumerates a
//! set whose predecessors have advanced and derives a new one.
//!
//! `apply()` re-runs the identical bounded eligibility query — shared with
//! the owner by construction, not by convention — and requires the observed
//! ordered set to equal the carried set exactly before writing, so a stale
//! enumeration fails closed instead of resurrecting rows it never admitted.
//!
//! Kind 6 (`DeterministicMediaWorkResult`) is reused: this is the media
//! job/work bookkeeping family that ordinal 6 already owns. The subtype keeps
//! the ledgers disjoint.
//!
//! ## Why the eligibility WHERE clause could be widened after sealing
//!
//! The query below is shared by construction between the owner and `apply`,
//! so changing it changes replay semantics for every committed operation —
//! normally forbidden. Slice 10i adds
//! `AND j.error_code IS NOT 'transcript_target_conflict'`, and that is safe
//! for exactly one reason: `transcript_target_conflict` is a brand-new error
//! code that **cannot exist in any archive written before this slice ships**,
//! so the added predicate is a no-op over all existing WAL history and every
//! committed operation replays identically. The exclusion and the owner code
//! that can produce the code therefore ship in the SAME change — never the
//! producer first. Re-check this argument before widening the clause again.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-media-job-resurrection-v1";
const PREDECESSOR_STATE: &str = "failed_terminal";
const MAX_ID_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_SWEEP_LIMIT: i64 = 1_024;
const MAX_ATTEMPT_CAP: i64 = 64;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_media_job_resurrection_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_media_job_resurrection_operations";
const STATE_TABLE: &str = "archive_v3_wal_media_job_resurrection_state";
const MAX_ROWS: u32 = 65_536;
const MAX_RESULT_BYTES: u64 = 65_536 * 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// The identical bounded eligibility query the owner enumerates with and
/// `apply()` revalidates with. One definition — the "same query" requirement
/// holds by construction. Sweep parameters are carried in the plan (never
/// read from code constants inside `apply()`) so replay stays deterministic
/// across binary revisions.
pub(in crate::cp::media_worker) fn enumerate_resurrectable(
    connection: &Connection,
    processor_version: i64,
    attempt_cap: i64,
    stale_before: &str,
    window_start: &str,
    sweep_limit: i64,
) -> rusqlite::Result<Vec<(i64, String, i64, String)>> {
    let mut statement = connection.prepare(
        "SELECT j.id, j.event_id, j.attempt_count, j.updated_at \
         FROM media_processing_jobs j \
         JOIN capture_events e ON e.event_id = j.event_id \
         WHERE j.processor_version = ?1 AND j.state = 'failed_terminal' \
           AND j.error_code IS NOT 'media_integrity' \
           AND j.error_code IS NOT 'transcript_target_conflict' \
           AND j.attempt_count < ?2 \
           AND j.updated_at <= ?3 \
           AND e.started_at >= ?4 \
         ORDER BY j.id LIMIT ?5",
    )?;
    let rows = statement.query_map(
        params![
            processor_version,
            attempt_cap,
            stale_before,
            window_start,
            sweep_limit
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    rows.collect()
}

/// One enumerated terminally-failed job with its observed predecessor tuple.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::cp) struct ResurrectableJob {
    job_id: i64,
    event_id: String,
    attempt_count: i64,
    updated_at: String,
}

impl ResurrectableJob {
    pub(in crate::cp) fn new(
        job_id: i64,
        event_id: String,
        attempt_count: i64,
        updated_at: String,
    ) -> Result<Self> {
        if job_id <= 0
            || event_id.is_empty()
            || event_id.len() > MAX_ID_BYTES
            || attempt_count < 0
            || updated_at.is_empty()
            || updated_at.len() > MAX_TIMESTAMP_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            job_id,
            event_id,
            attempt_count,
            updated_at,
        })
    }
}

pub(crate) struct MediaJobResurrectionPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    jobs: Vec<ResurrectableJob>,
    processor_version: i64,
    attempt_cap: i64,
    sweep_limit: i64,
    stale_before: String,
    window_start: String,
    committed_at: String,
}

impl MediaJobResurrectionPlan {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp) fn new(
        account_id: String,
        jobs: Vec<ResurrectableJob>,
        processor_version: i64,
        attempt_cap: i64,
        sweep_limit: i64,
        stale_before: String,
        window_start: String,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if jobs.is_empty()
            || processor_version <= 0
            || !(1..=MAX_ATTEMPT_CAP).contains(&attempt_cap)
            || !(1..=MAX_SWEEP_LIMIT).contains(&sweep_limit)
            || jobs.len() > usize::try_from(sweep_limit).map_err(|_| WalIdempotencyError::Limit)?
            || stale_before.is_empty()
            || stale_before.len() > MAX_TIMESTAMP_BYTES
            || window_start.is_empty()
            || window_start.len() > MAX_TIMESTAMP_BYTES
            || committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if !jobs.windows(2).all(|pair| pair[0].job_id < pair[1].job_id) {
            return Err(WalIdempotencyError::Malformed);
        }
        if jobs.iter().any(|job| job.attempt_count >= attempt_cap) {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut payload = Sha256::new();
        for job in &jobs {
            hash_field(&mut payload, &job.job_id.to_be_bytes())?;
            hash_field(&mut payload, job.event_id.as_bytes())?;
            hash_field(&mut payload, PREDECESSOR_STATE.as_bytes())?;
            hash_field(&mut payload, &job.attempt_count.to_be_bytes())?;
            hash_field(&mut payload, job.updated_at.as_bytes())?;
        }
        let payload: [u8; 32] = payload.finalize().into();
        let source = stable_operation_source(SUBTYPE, &[account_id.as_bytes(), &payload])?;
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::DeterministicMediaWorkResult,
            &source,
        )?;
        Ok(Self {
            operation_id,
            account_id,
            jobs,
            processor_version,
            attempt_cap,
            sweep_limit,
            stale_before,
            window_start,
            committed_at,
        })
    }
}

pub(crate) struct MediaJobResurrectionLedger;

impl WalLogicalDomainPlan for MediaJobResurrectionPlan {
    type Ledger = MediaJobResurrectionLedger;
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
        request.extend_from_slice(&self.processor_version.to_be_bytes());
        request.extend_from_slice(&self.attempt_cap.to_be_bytes());
        request.extend_from_slice(&self.sweep_limit.to_be_bytes());
        encode_string(&mut request, &self.stale_before)?;
        encode_string(&mut request, &self.window_start)?;
        encode_string(&mut request, &self.committed_at)?;
        encode_len(&mut request, self.jobs.len())?;
        for job in &self.jobs {
            request.extend_from_slice(&job.job_id.to_be_bytes());
            encode_string(&mut request, &job.event_id)?;
            request.extend_from_slice(&job.attempt_count.to_be_bytes());
            encode_string(&mut request, &job.updated_at)?;
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        // Revalidate with the identical bounded query: the observed ordered
        // set must equal the carried set exactly. A row that advanced, left,
        // or newly entered eligibility means the scan is stale — refuse and
        // let the caller re-enumerate rather than write against a set this
        // identity never admitted.
        let observed = enumerate_resurrectable(
            transaction,
            self.processor_version,
            self.attempt_cap,
            &self.stale_before,
            &self.window_start,
            self.sweep_limit,
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
        if observed.len() != self.jobs.len()
            || !observed.iter().zip(&self.jobs).all(|(seen, job)| {
                seen.0 == job.job_id
                    && seen.1 == job.event_id
                    && seen.2 == job.attempt_count
                    && seen.3 == job.updated_at
            })
        {
            return Err(WalIdempotencyError::Precondition);
        }
        for job in &self.jobs {
            let changed = transaction
                .execute(
                    "UPDATE media_processing_jobs \
                     SET state='retry_wait',lease_until=NULL,updated_at=?1 \
                     WHERE id=?2 AND state='failed_terminal' \
                       AND attempt_count=?3 AND updated_at=?4",
                    params![
                        self.committed_at,
                        job.job_id,
                        job.attempt_count,
                        job.updated_at,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                // The row was observed in this very transaction; a CAS miss
                // here is not a race, it is corruption.
                return Err(WalIdempotencyError::Corrupt);
            }
            transaction
                .execute(
                    "UPDATE media_objects SET processing_state='retry_wait' \
                     WHERE event_id=?1 AND processing_state='failed'",
                    [&job.event_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
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

impl WalLogicalDomainLedger<MediaJobResurrectionPlan> for MediaJobResurrectionLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<MediaJobResurrectionPlan>,
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
                 FROM archive_v3_wal_media_job_resurrection_operations
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
        prepared: &PreparedLogicalMutation<MediaJobResurrectionPlan>,
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
                "INSERT INTO archive_v3_wal_media_job_resurrection_operations
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
                "UPDATE archive_v3_wal_media_job_resurrection_state
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

fn require_kind(prepared: &PreparedLogicalMutation<MediaJobResurrectionPlan>) -> Result<()> {
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
                    "CREATE TABLE archive_v3_wal_media_job_resurrection_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_media_job_resurrection_operations (
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
                     CREATE TABLE archive_v3_wal_media_job_resurrection_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 589824)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_media_job_resurrection_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_media_job_resurrection_state
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
             FROM archive_v3_wal_media_job_resurrection_schema WHERE singleton=1",
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
             FROM archive_v3_wal_media_job_resurrection_state WHERE singleton=1",
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

fn hash_field(hasher: &mut Sha256, value: &[u8]) -> Result<()> {
    hasher.update(
        u32::try_from(value.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    hasher.update(value);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const STALE_BEFORE: &str = "2026-08-20T18:00:00.000Z";
    const WINDOW_START: &str = "2026-08-13T19:00:00.000Z";
    const COMMITTED_AT: &str = "2026-08-20T19:00:00.000Z";
    const ATTEMPT_CAP: i64 = 9;
    const SWEEP_LIMIT: i64 = 16;

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE media_processing_jobs (
                    id INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    processor_version INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    error_code TEXT,
                    attempt_count INTEGER NOT NULL,
                    lease_until TEXT,
                    updated_at TEXT NOT NULL DEFAULT ''
                 );
                 CREATE TABLE capture_events (
                    event_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL
                 );
                 CREATE TABLE media_objects (
                    event_id TEXT NOT NULL,
                    processing_state TEXT NOT NULL
                 );
                 INSERT INTO capture_events VALUES
                    ('ev-a','2026-08-15T00:00:00.000Z'),
                    ('ev-old','2026-08-01T00:00:00.000Z');
                 INSERT INTO media_processing_jobs VALUES
                    (1,'ev-a',1,'failed_terminal',NULL,3,'lease','2026-08-20T10:00:00.000Z'),
                    (2,'ev-a',1,'failed_terminal','media_integrity',1,NULL,'2026-08-20T10:00:00.000Z'),
                    (3,'ev-a',1,'failed_terminal',NULL,9,NULL,'2026-08-20T10:00:00.000Z'),
                    (4,'ev-a',1,'failed_terminal',NULL,1,NULL,'2026-08-20T18:30:00.000Z'),
                    (5,'ev-old',1,'failed_terminal',NULL,1,NULL,'2026-08-20T10:00:00.000Z'),
                    (6,'ev-a',1,'done',NULL,1,NULL,'2026-08-20T10:00:00.000Z');
                 INSERT INTO media_objects VALUES
                    ('ev-a','failed'),
                    ('ev-a','done');",
            )
            .unwrap();
    }

    fn enumerated_jobs(connection: &Connection) -> Vec<ResurrectableJob> {
        enumerate_resurrectable(
            connection,
            1,
            ATTEMPT_CAP,
            STALE_BEFORE,
            WINDOW_START,
            SWEEP_LIMIT,
        )
        .unwrap()
        .into_iter()
        .map(|(job_id, event_id, attempt_count, updated_at)| {
            ResurrectableJob::new(job_id, event_id, attempt_count, updated_at).unwrap()
        })
        .collect()
    }

    fn build(jobs: Vec<ResurrectableJob>, committed_at: &str) -> MediaJobResurrectionPlan {
        MediaJobResurrectionPlan::new(
            ACCOUNT.into(),
            jobs,
            1,
            ATTEMPT_CAP,
            SWEEP_LIMIT,
            STALE_BEFORE.into(),
            WINDOW_START.into(),
            committed_at.into(),
        )
        .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: MediaJobResurrectionPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn resurrection_settles_the_exact_enumerated_set_and_replays() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let jobs = enumerated_jobs(&connection);
        assert_eq!(jobs.len(), 1, "only job 1 passes every eligibility bound");
        assert!(matches!(
            settle(&mut connection, build(jobs.clone(), COMMITTED_AT)).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let (state, lease, updated): (String, Option<String>, String) = connection
            .query_row(
                "SELECT state,lease_until,updated_at FROM media_processing_jobs WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, "retry_wait");
        assert_eq!(lease, None);
        assert_eq!(updated, COMMITTED_AT);
        let untouched: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM media_processing_jobs
                 WHERE id IN (2,3,4,5) AND state='failed_terminal'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(untouched, 4, "ineligible jobs stay terminal");
        let objects: Vec<String> = connection
            .prepare("SELECT processing_state FROM media_objects ORDER BY processing_state")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(objects, ["done", "retry_wait"]);
        assert!(matches!(
            settle(&mut connection, build(jobs, COMMITTED_AT)).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
    }

    #[test]
    fn a_newly_eligible_row_fails_the_stale_enumeration_closed() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let jobs = enumerated_jobs(&connection);
        connection
            .execute(
                "INSERT INTO media_processing_jobs VALUES
                 (7,'ev-a',1,'failed_terminal',NULL,2,NULL,'2026-08-20T09:00:00.000Z')",
                [],
            )
            .unwrap();
        assert!(matches!(
            settle(&mut connection, build(jobs, COMMITTED_AT)),
            Err(WalIdempotencyError::Precondition)
        ));
    }

    #[test]
    fn an_advanced_predecessor_fails_the_stale_enumeration_closed() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let jobs = enumerated_jobs(&connection);
        // An interleaved attempt advanced the carried row's predecessor.
        connection
            .execute(
                "UPDATE media_processing_jobs
                 SET attempt_count=4,updated_at='2026-08-20T11:00:00.000Z' WHERE id=1",
                [],
            )
            .unwrap();
        assert!(matches!(
            settle(&mut connection, build(jobs, COMMITTED_AT)),
            Err(WalIdempotencyError::Precondition)
        ));
    }

    #[test]
    fn the_clock_never_enters_the_identity_but_the_predecessor_does() {
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let jobs = enumerated_jobs(&connection);
        // A crash-retry re-mints the commit stamp: same set, same identity —
        // property A holds without a FingerprintConflict hazard because a
        // failed settle records nothing.
        let first = build(jobs.clone(), COMMITTED_AT);
        let reminted = build(jobs.clone(), "2026-08-20T19:05:00.000Z");
        assert_eq!(first.operation_id(), reminted.operation_id());
        // An advanced predecessor is a legitimately new operation (B).
        let advanced =
            vec![
                ResurrectableJob::new(1, "ev-a".into(), 4, "2026-08-20T11:00:00.000Z".into())
                    .unwrap(),
            ];
        assert_ne!(
            first.operation_id(),
            build(advanced, COMMITTED_AT).operation_id()
        );
    }

    #[test]
    fn the_transcript_conflict_exclusion_is_history_neutral() {
        // Widening a sealed family's shared eligibility query changes replay
        // semantics for every committed operation. It is safe here for
        // exactly one reason: `transcript_target_conflict` cannot exist in
        // any archive written before slice 10i, so the added predicate is a
        // no-op over all existing WAL history. This test is that argument.
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        for (id, code) in [
            (10_i64, "processing_error"),
            (11, "invalid_model_output"),
            (12, "vertex_quota"),
            (13, "vertex_daily_budget"),
        ] {
            connection
                .execute(
                    "INSERT INTO media_processing_jobs VALUES
                     (?1,'ev-a',1,'failed_terminal',?2,1,NULL,'2026-08-20T10:00:00.000Z')",
                    params![id, code],
                )
                .unwrap();
        }
        let baseline = enumerate_resurrectable(
            &connection,
            1,
            ATTEMPT_CAP,
            STALE_BEFORE,
            WINDOW_START,
            SWEEP_LIMIT,
        )
        .unwrap();
        assert_eq!(
            baseline.iter().map(|row| row.0).collect::<Vec<_>>(),
            vec![1, 10, 11, 12, 13],
            "every pre-existing error code is still resurrectable"
        );
        connection
            .execute(
                "UPDATE media_processing_jobs SET error_code='transcript_target_conflict' \
                 WHERE id=12",
                [],
            )
            .unwrap();
        let excluded = enumerate_resurrectable(
            &connection,
            1,
            ATTEMPT_CAP,
            STALE_BEFORE,
            WINDOW_START,
            SWEEP_LIMIT,
        )
        .unwrap();
        assert_eq!(
            excluded.iter().map(|row| row.0).collect::<Vec<_>>(),
            vec![1, 10, 11, 13],
            "a target conflict can never recover, so it is never resurrected"
        );
    }

    #[test]
    fn malformed_sets_are_rejected() {
        let job = |id: i64, attempts: i64| {
            ResurrectableJob::new(
                id,
                "ev-a".into(),
                attempts,
                "2026-08-20T10:00:00.000Z".into(),
            )
            .unwrap()
        };
        let build = |jobs: Vec<ResurrectableJob>, cap: i64, limit: i64| {
            MediaJobResurrectionPlan::new(
                ACCOUNT.into(),
                jobs,
                1,
                cap,
                limit,
                STALE_BEFORE.into(),
                WINDOW_START.into(),
                COMMITTED_AT.into(),
            )
        };
        assert!(build(vec![], ATTEMPT_CAP, SWEEP_LIMIT).is_err());
        assert!(build(vec![job(2, 1), job(1, 1)], ATTEMPT_CAP, SWEEP_LIMIT).is_err());
        assert!(
            build(vec![job(1, 9)], ATTEMPT_CAP, SWEEP_LIMIT).is_err(),
            "attempt count at the cap is not eligible"
        );
        assert!(build(vec![job(1, 1), job(2, 1)], ATTEMPT_CAP, 1).is_err());
        assert!(ResurrectableJob::new(0, "ev-a".into(), 1, "t".into()).is_err());
        assert!(ResurrectableJob::new(1, String::new(), 1, "t".into()).is_err());
    }
}
