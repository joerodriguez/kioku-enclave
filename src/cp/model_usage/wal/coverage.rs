//! Vertex coverage-ledger transitions as one sealed WAL plan (ADR-0022 F5).
//!
//! Four owners write `vertex_usage_coverage` outside the event-driven
//! refresh: the month rollover (terminalize prior pending periods + ensure
//! the current row), the snapshot persist, the delivered completion, and the
//! stale invalidation. Each becomes a tagged transition of this plan with a
//! full predecessor CAS and a terminal adopt arm; every increment is written
//! absolutely from the carried predecessor (R3), and the rollover carries the
//! enumerated prior-period set rather than an open `WHERE period < ?` (R6).

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-vertex-coverage-ledger-v1";
const MAX_PERIOD_BYTES: usize = 16;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_PRIOR_PERIODS: usize = 128;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_vertex_coverage_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_vertex_coverage_operations";
const STATE_TABLE: &str = "archive_v3_wal_vertex_coverage_state";
const MAX_ROWS: u32 = 65_536;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// The observed predecessor of one coverage row.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::cp) struct CoveragePredecessor {
    period: String,
    sequence: i64,
    pending_events: i64,
    lost_events: i64,
}

impl CoveragePredecessor {
    pub(in crate::cp) fn new(
        period: String,
        sequence: i64,
        pending_events: i64,
        lost_events: i64,
    ) -> Result<Self> {
        validate_period(&period)?;
        if sequence < 0 || pending_events < 0 || lost_events < 0 {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            period,
            sequence,
            pending_events,
            lost_events,
        })
    }

    pub(in crate::cp) fn sequence_for_caller(&self) -> i64 {
        self.sequence
    }
}

#[derive(Clone)]
pub(in crate::cp) enum CoverageTransition {
    /// Month rollover: terminalize the enumerated prior pending periods and
    /// ensure the current period's row exists.
    Rollover {
        current_period: String,
        prior_pending: Vec<CoveragePredecessor>,
    },
    /// Persist the Control-anchored snapshot back over the row.
    PersistSnapshot {
        predecessor: CoveragePredecessor,
        sequence: i64,
        pending_events: i64,
        lost_events: i64,
        observed_at: String,
    },
    /// Mark the exact (period, sequence) delivered.
    CompleteDelivered { predecessor: CoveragePredecessor },
    /// Bump the sequence past a stale snapshot and re-arm delivery.
    InvalidateStale { predecessor: CoveragePredecessor },
}

impl CoverageTransition {
    const fn tag(&self) -> u8 {
        match self {
            Self::Rollover { .. } => 1,
            Self::PersistSnapshot { .. } => 2,
            Self::CompleteDelivered { .. } => 3,
            Self::InvalidateStale { .. } => 4,
        }
    }
}

pub(crate) struct VertexCoverageLedgerPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    transition: CoverageTransition,
    committed_at: String,
}

impl VertexCoverageLedgerPlan {
    pub(in crate::cp) fn new(
        account_id: String,
        transition: CoverageTransition,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
            || committed_at.contains('\0')
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut payload = Sha256::new();
        match &transition {
            CoverageTransition::Rollover {
                current_period,
                prior_pending,
            } => {
                validate_period(current_period)?;
                if prior_pending.len() > MAX_PRIOR_PERIODS {
                    return Err(WalIdempotencyError::Malformed);
                }
                if !prior_pending
                    .windows(2)
                    .all(|pair| pair[0].period < pair[1].period)
                {
                    return Err(WalIdempotencyError::Malformed);
                }
                if prior_pending
                    .iter()
                    .any(|prior| prior.period.as_str() >= current_period.as_str())
                {
                    return Err(WalIdempotencyError::Malformed);
                }
                hash_field(&mut payload, current_period.as_bytes())?;
                for prior in prior_pending {
                    hash_predecessor(&mut payload, prior)?;
                }
            }
            CoverageTransition::PersistSnapshot {
                predecessor,
                sequence,
                pending_events,
                lost_events,
                observed_at,
            } => {
                if *sequence < 0
                    || *pending_events < 0
                    || *lost_events < 0
                    || observed_at.is_empty()
                    || observed_at.len() > MAX_TIMESTAMP_BYTES
                {
                    return Err(WalIdempotencyError::Malformed);
                }
                hash_predecessor(&mut payload, predecessor)?;
                hash_field(&mut payload, &sequence.to_be_bytes())?;
                hash_field(&mut payload, &pending_events.to_be_bytes())?;
                hash_field(&mut payload, &lost_events.to_be_bytes())?;
                hash_field(&mut payload, observed_at.as_bytes())?;
            }
            CoverageTransition::CompleteDelivered { predecessor }
            | CoverageTransition::InvalidateStale { predecessor } => {
                hash_predecessor(&mut payload, predecessor)?;
            }
        }
        let payload: [u8; 32] = payload.finalize().into();
        let source = stable_operation_source(
            SUBTYPE,
            &[account_id.as_bytes(), &[transition.tag()], &payload],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::VertexUsage, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            transition,
            committed_at,
        })
    }
}

fn hash_predecessor(hasher: &mut Sha256, predecessor: &CoveragePredecessor) -> Result<()> {
    hash_field(hasher, predecessor.period.as_bytes())?;
    hash_field(hasher, &predecessor.sequence.to_be_bytes())?;
    hash_field(hasher, &predecessor.pending_events.to_be_bytes())?;
    hash_field(hasher, &predecessor.lost_events.to_be_bytes())
}

pub(crate) struct VertexCoverageLedgerLedger;

impl WalLogicalDomainPlan for VertexCoverageLedgerPlan {
    type Ledger = VertexCoverageLedgerLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::VertexUsage
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(2 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        request.push(self.transition.tag());
        match &self.transition {
            CoverageTransition::Rollover {
                current_period,
                prior_pending,
            } => {
                encode_string(&mut request, current_period)?;
                encode_len(&mut request, prior_pending.len())?;
                for prior in prior_pending {
                    encode_predecessor(&mut request, prior)?;
                }
            }
            CoverageTransition::PersistSnapshot {
                predecessor,
                sequence,
                pending_events,
                lost_events,
                observed_at,
            } => {
                encode_predecessor(&mut request, predecessor)?;
                request.extend_from_slice(&sequence.to_be_bytes());
                request.extend_from_slice(&pending_events.to_be_bytes());
                request.extend_from_slice(&lost_events.to_be_bytes());
                encode_string(&mut request, observed_at)?;
            }
            CoverageTransition::CompleteDelivered { predecessor }
            | CoverageTransition::InvalidateStale { predecessor } => {
                encode_predecessor(&mut request, predecessor)?;
            }
        }
        // committed_at stays out of both the identity and the fingerprint
        // (clock; see the F2 precedent).
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        match &self.transition {
            CoverageTransition::Rollover {
                current_period,
                prior_pending,
            } => {
                for prior in prior_pending {
                    let target_lost = (prior.lost_events + prior.pending_events).max(1);
                    let row = load_row(transaction, &prior.period)?
                        .ok_or(WalIdempotencyError::Precondition)?;
                    if row.delivery_state == "delivered"
                        && row.pending_events == 0
                        && row.lost_events == target_lost
                    {
                        continue; // adopted
                    }
                    let changed = transaction
                        .execute(
                            "UPDATE vertex_usage_coverage
                             SET pending_events=0,lost_events=?1,
                                 delivery_state='delivered',updated_at=?2
                             WHERE period=?3 AND delivery_state='pending'
                               AND sequence=?4 AND pending_events=?5 AND lost_events=?6",
                            params![
                                target_lost,
                                self.committed_at,
                                prior.period,
                                prior.sequence,
                                prior.pending_events,
                                prior.lost_events
                            ],
                        )
                        .map_err(|_| WalIdempotencyError::Unavailable)?;
                    if changed != 1 {
                        return Err(WalIdempotencyError::Precondition);
                    }
                }
                // Ensure the current period's row; the pending count is a
                // pure function of this transaction's pre-state.
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO vertex_usage_coverage
                         (period,sequence,pending_events,lost_events,delivery_state,updated_at)
                         VALUES (
                            ?1,1,
                            (SELECT count(*) FROM vertex_usage_events
                             WHERE delivery_state='pending'
                               AND substr(observed_at,1,7)=?1),
                            0,'pending',?2)",
                        params![current_period, self.committed_at],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if load_row(transaction, current_period)?.is_none() {
                    return Err(WalIdempotencyError::Corrupt);
                }
            }
            CoverageTransition::PersistSnapshot {
                predecessor,
                sequence,
                pending_events,
                lost_events,
                observed_at,
            } => {
                let row = load_row(transaction, &predecessor.period)?
                    .ok_or(WalIdempotencyError::Precondition)?;
                if row.sequence == *sequence
                    && row.pending_events == *pending_events
                    && row.lost_events == *lost_events
                    && row.delivery_state == "pending"
                {
                    return Ok(WalReplayResult::unit()); // adopted
                }
                let changed = transaction
                    .execute(
                        "UPDATE vertex_usage_coverage
                         SET sequence=?1,pending_events=?2,lost_events=?3,
                             delivery_state='pending',updated_at=?4
                         WHERE period=?5 AND sequence=?6
                           AND pending_events=?7 AND lost_events=?8",
                        params![
                            sequence,
                            pending_events,
                            lost_events,
                            observed_at,
                            predecessor.period,
                            predecessor.sequence,
                            predecessor.pending_events,
                            predecessor.lost_events
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if changed != 1 {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
            CoverageTransition::CompleteDelivered { predecessor } => {
                let row = load_row(transaction, &predecessor.period)?
                    .ok_or(WalIdempotencyError::Precondition)?;
                if row.sequence == predecessor.sequence && row.delivery_state == "delivered" {
                    return Ok(WalReplayResult::unit()); // adopted
                }
                let changed = transaction
                    .execute(
                        "UPDATE vertex_usage_coverage SET delivery_state='delivered',
                         updated_at=?1
                         WHERE period=?2 AND sequence=?3 AND delivery_state='pending'",
                        params![self.committed_at, predecessor.period, predecessor.sequence],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if changed != 1 {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
            CoverageTransition::InvalidateStale { predecessor } => {
                let target_sequence = predecessor.sequence + 1;
                let target_lost = predecessor.lost_events.max(1);
                let row = load_row(transaction, &predecessor.period)?
                    .ok_or(WalIdempotencyError::Precondition)?;
                if row.sequence == target_sequence
                    && row.lost_events >= target_lost
                    && row.delivery_state == "pending"
                {
                    return Ok(WalReplayResult::unit()); // adopted
                }
                let changed = transaction
                    .execute(
                        "UPDATE vertex_usage_coverage
                         SET sequence=?1,lost_events=?2,delivery_state='pending',updated_at=?3
                         WHERE period=?4 AND sequence=?5 AND lost_events=?6",
                        params![
                            target_sequence,
                            target_lost,
                            self.committed_at,
                            predecessor.period,
                            predecessor.sequence,
                            predecessor.lost_events
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if changed != 1 {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
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

struct CoverageRow {
    sequence: i64,
    pending_events: i64,
    lost_events: i64,
    delivery_state: String,
}

fn load_row(transaction: &Transaction<'_>, period: &str) -> Result<Option<CoverageRow>> {
    transaction
        .query_row(
            "SELECT sequence,pending_events,lost_events,delivery_state
             FROM vertex_usage_coverage WHERE period=?1",
            [period],
            |row| {
                Ok(CoverageRow {
                    sequence: row.get(0)?,
                    pending_events: row.get(1)?,
                    lost_events: row.get(2)?,
                    delivery_state: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn validate_period(period: &str) -> Result<()> {
    if period.len() != 7
        || period.len() > MAX_PERIOD_BYTES
        || !period[..4].bytes().all(|byte| byte.is_ascii_digit())
        || period.as_bytes()[4] != b'-'
        || !period[5..].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn encode_predecessor(request: &mut Vec<u8>, predecessor: &CoveragePredecessor) -> Result<()> {
    encode_string(request, &predecessor.period)?;
    request.extend_from_slice(&predecessor.sequence.to_be_bytes());
    request.extend_from_slice(&predecessor.pending_events.to_be_bytes());
    request.extend_from_slice(&predecessor.lost_events.to_be_bytes());
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<VertexCoverageLedgerPlan> for VertexCoverageLedgerLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<VertexCoverageLedgerPlan>,
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
                 FROM archive_v3_wal_vertex_coverage_operations
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
        prepared: &PreparedLogicalMutation<VertexCoverageLedgerPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
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
                "INSERT INTO archive_v3_wal_vertex_coverage_operations
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
                "UPDATE archive_v3_wal_vertex_coverage_state
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

fn require_kind(prepared: &PreparedLogicalMutation<VertexCoverageLedgerPlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::VertexUsage {
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
                    "CREATE TABLE archive_v3_wal_vertex_coverage_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_vertex_coverage_operations (
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
                     CREATE TABLE archive_v3_wal_vertex_coverage_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_vertex_coverage_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_vertex_coverage_state
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
             FROM archive_v3_wal_vertex_coverage_schema WHERE singleton=1",
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
             FROM archive_v3_wal_vertex_coverage_state WHERE singleton=1",
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
    const COMMITTED_AT: &str = "2026-08-20T16:30:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE vertex_usage_events (
                    event_id TEXT PRIMARY KEY,
                    delivery_state TEXT NOT NULL DEFAULT 'pending',
                    observed_at TEXT NOT NULL DEFAULT '2026-08-20T15:00:00.000Z'
                 );
                 CREATE TABLE vertex_usage_coverage (
                    period TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    pending_events INTEGER NOT NULL,
                    lost_events INTEGER NOT NULL,
                    delivery_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT ''
                 );",
            )
            .unwrap();
    }

    fn seed_period(connection: &Connection, period: &str, sequence: i64, pending: i64, lost: i64) {
        connection
            .execute(
                "INSERT INTO vertex_usage_coverage
                 (period,sequence,pending_events,lost_events,delivery_state)
                 VALUES (?1,?2,?3,?4,'pending')",
                params![period, sequence, pending, lost],
            )
            .unwrap();
    }

    fn predecessor(connection: &Connection, period: &str) -> CoveragePredecessor {
        let (sequence, pending, lost): (i64, i64, i64) = connection
            .query_row(
                "SELECT sequence,pending_events,lost_events
                 FROM vertex_usage_coverage WHERE period=?1",
                [period],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        CoveragePredecessor::new(period.into(), sequence, pending, lost).unwrap()
    }

    fn coverage_row(connection: &Connection, period: &str) -> (i64, i64, i64, String, String) {
        connection
            .query_row(
                "SELECT sequence,pending_events,lost_events,delivery_state,updated_at
                 FROM vertex_usage_coverage WHERE period=?1",
                [period],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: VertexCoverageLedgerPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn rollover_terminalizes_enumerated_priors_and_ensures_the_current_row() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        seed_period(&connection, "2026-06", 2, 3, 1);
        seed_period(&connection, "2026-07", 1, 0, 0);
        let plan = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::Rollover {
                current_period: "2026-08".into(),
                prior_pending: vec![
                    predecessor(&connection, "2026-06"),
                    predecessor(&connection, "2026-07"),
                ],
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let (lost_june, state_june): (i64, String) = connection
            .query_row(
                "SELECT lost_events,delivery_state FROM vertex_usage_coverage WHERE period='2026-06'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(lost_june, 4);
        assert_eq!(state_june, "delivered");
        let (lost_july, _): (i64, String) = connection
            .query_row(
                "SELECT lost_events,delivery_state FROM vertex_usage_coverage WHERE period='2026-07'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            lost_july, 1,
            "an empty pending period still records one lost"
        );
        let current: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM vertex_usage_coverage WHERE period='2026-08'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current, 1);
    }

    #[test]
    fn snapshot_complete_and_invalidate_settle_with_full_predecessor_cas() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        seed_period(&connection, "2026-08", 3, 5, 0);
        // Persist a snapshot over the row.
        let plan = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::PersistSnapshot {
                predecessor: predecessor(&connection, "2026-08"),
                sequence: 4,
                pending_events: 2,
                lost_events: 1,
                observed_at: "2026-08-20T16:00:00.000Z".into(),
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        // Complete that exact sequence.
        let plan = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::CompleteDelivered {
                predecessor: predecessor(&connection, "2026-08"),
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let state: String = connection
            .query_row(
                "SELECT delivery_state FROM vertex_usage_coverage WHERE period='2026-08'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "delivered");
        // Invalidation bumps the sequence absolutely and re-arms delivery.
        connection
            .execute(
                "UPDATE vertex_usage_coverage SET delivery_state='pending' WHERE period='2026-08'",
                [],
            )
            .unwrap();
        let before = predecessor(&connection, "2026-08");
        let plan = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::InvalidateStale {
                predecessor: before,
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let (sequence, lost): (i64, i64) = connection
            .query_row(
                "SELECT sequence,lost_events FROM vertex_usage_coverage WHERE period='2026-08'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(sequence, 5);
        assert_eq!(lost, 1);
    }

    #[test]
    fn captured_completion_reapplies_after_recovery_without_creating_loss() {
        const RECOVERED_AT: &str = "2026-08-20T16:31:00.000Z";
        const REPLAYED_AT: &str = "2026-08-20T16:32:00.000Z";

        let mut first_process = Connection::open_in_memory().unwrap();
        install_schema(&first_process);
        seed_period(&first_process, "2026-08", 7, 0, 0);
        let first_plan = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::CompleteDelivered {
                predecessor: predecessor(&first_process, "2026-08"),
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        let operation_id = first_plan.operation_id;
        assert!(matches!(
            settle(&mut first_process, first_plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        assert_eq!(
            coverage_row(&first_process, "2026-08"),
            (7, 0, 0, "delivered".into(), COMMITTED_AT.into())
        );

        // Model a process loss after the SQLite WAL was captured but before
        // its candidate was witnessed: recovery opens the last witnessed
        // predecessor, not the first process's locally committed bytes. The
        // restart may carry a later clock value, but it must derive the same
        // operation and settle without inventing a coverage loss.
        let mut recovered_process = Connection::open_in_memory().unwrap();
        install_schema(&recovered_process);
        seed_period(&recovered_process, "2026-08", 7, 0, 0);
        let recovered_plan = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::CompleteDelivered {
                predecessor: predecessor(&recovered_process, "2026-08"),
            },
            RECOVERED_AT.into(),
        )
        .unwrap();
        assert_eq!(recovered_plan.operation_id, operation_id);
        assert!(matches!(
            settle(&mut recovered_process, recovered_plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        assert_eq!(
            coverage_row(&recovered_process, "2026-08"),
            (7, 0, 0, "delivered".into(), RECOVERED_AT.into())
        );

        let replay = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::CompleteDelivered {
                predecessor: CoveragePredecessor::new("2026-08".into(), 7, 0, 0).unwrap(),
            },
            REPLAYED_AT.into(),
        )
        .unwrap();
        assert_eq!(replay.operation_id, operation_id);
        assert!(matches!(
            settle(&mut recovered_process, replay).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        assert_eq!(
            coverage_row(&recovered_process, "2026-08"),
            (7, 0, 0, "delivered".into(), RECOVERED_AT.into())
        );
    }

    #[test]
    fn captured_rollback_marker_recovery_records_one_fail_closed_loss() {
        const ANCHORED_AT: &str = "2026-08-20T16:29:00.000Z";
        const RECOVERED_AT: &str = "2026-08-20T16:31:00.000Z";

        fn rollback_plan(connection: &Connection, committed_at: &str) -> VertexCoverageLedgerPlan {
            VertexCoverageLedgerPlan::new(
                ACCOUNT.into(),
                CoverageTransition::PersistSnapshot {
                    predecessor: predecessor(connection, "2026-08"),
                    sequence: 8,
                    pending_events: 0,
                    lost_events: 1,
                    observed_at: ANCHORED_AT.into(),
                },
                committed_at.into(),
            )
            .unwrap()
        }

        let mut first_process = Connection::open_in_memory().unwrap();
        install_schema(&first_process);
        seed_period(&first_process, "2026-08", 7, 0, 0);
        let first_plan = rollback_plan(&first_process, COMMITTED_AT);
        let operation_id = first_plan.operation_id;
        assert!(matches!(
            settle(&mut first_process, first_plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        assert_eq!(
            coverage_row(&first_process, "2026-08"),
            (8, 0, 1, "pending".into(), ANCHORED_AT.into())
        );

        // The captured attempt is absent from the last witnessed predecessor.
        // Re-preparing that exact marker after restart must reproduce one
        // conservative loss, never increment it again or clear it.
        let mut recovered_process = Connection::open_in_memory().unwrap();
        install_schema(&recovered_process);
        seed_period(&recovered_process, "2026-08", 7, 0, 0);
        let recovered_plan = rollback_plan(&recovered_process, RECOVERED_AT);
        assert_eq!(recovered_plan.operation_id, operation_id);
        assert!(matches!(
            settle(&mut recovered_process, recovered_plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        assert_eq!(
            coverage_row(&recovered_process, "2026-08"),
            (8, 0, 1, "pending".into(), ANCHORED_AT.into())
        );

        let replay = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::PersistSnapshot {
                predecessor: CoveragePredecessor::new("2026-08".into(), 7, 0, 0).unwrap(),
                sequence: 8,
                pending_events: 0,
                lost_events: 1,
                observed_at: ANCHORED_AT.into(),
            },
            RECOVERED_AT.into(),
        )
        .unwrap();
        assert_eq!(replay.operation_id, operation_id);
        assert!(matches!(
            settle(&mut recovered_process, replay).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        assert_eq!(
            coverage_row(&recovered_process, "2026-08"),
            (8, 0, 1, "pending".into(), ANCHORED_AT.into())
        );
    }

    #[test]
    fn moved_rows_fail_closed_and_replays_do_not_reapply() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        seed_period(&connection, "2026-08", 1, 2, 0);
        let stale = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::CompleteDelivered {
                predecessor: predecessor(&connection, "2026-08"),
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        let replay = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::CompleteDelivered {
                predecessor: predecessor(&connection, "2026-08"),
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, stale).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        assert!(matches!(
            settle(&mut connection, replay).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        // A DIFFERENT predecessor tuple is a new operation and fails closed
        // against the moved row (already delivered at sequence 1).
        let wrong = VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::InvalidateStale {
                predecessor: CoveragePredecessor::new("2026-08".into(), 9, 9, 9).unwrap(),
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, wrong),
            Err(WalIdempotencyError::Precondition)
        ));
    }

    #[test]
    fn malformed_transitions_are_rejected() {
        assert!(CoveragePredecessor::new("2026-8".into(), 0, 0, 0).is_err());
        assert!(CoveragePredecessor::new("2026-08".into(), -1, 0, 0).is_err());
        // Priors must be strictly ordered and strictly before current.
        let june = CoveragePredecessor::new("2026-06".into(), 1, 0, 0).unwrap();
        let august = CoveragePredecessor::new("2026-08".into(), 1, 0, 0).unwrap();
        assert!(VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::Rollover {
                current_period: "2026-08".into(),
                prior_pending: vec![august, june.clone()],
            },
            COMMITTED_AT.into(),
        )
        .is_err());
        assert!(VertexCoverageLedgerPlan::new(
            ACCOUNT.into(),
            CoverageTransition::Rollover {
                current_period: "2026-06".into(),
                prior_pending: vec![june],
            },
            COMMITTED_AT.into(),
        )
        .is_err());
    }
}
