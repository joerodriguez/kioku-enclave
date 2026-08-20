//! Finalization lifecycle transitions as a sealed WAL plan (ADR-0022 F10).
//!
//! `FinalizationCommitPlan` covers the happy-path terminal; the surrounding
//! lifecycle — status stamps, failure recording with the retry ladder, and
//! the budget deferral — stayed on the legacy path. Each becomes a tagged
//! transition here, writing the finalization columns only (a strict subset of
//! what the commit plan owns; no FTS trigger fires, `episodes_update_fts` is
//! scoped to the content columns).
//!
//! The identity carries the **full predecessor tuple** rather than a counter:
//! the same predecessor derives the same id (exact replay), an advanced
//! predecessor derives a new id (a legitimately new operation). R3 case 2
//! holds because each transition is caused by exactly one Vertex attempt.
//! Clock-derived *target* values (retry timestamps) are fingerprinted — safe
//! here, unlike F2's identity clock, because a successful settle advances the
//! predecessor, so a crash-retry re-reads a moved tuple and derives a fresh
//! operation instead of colliding with the stored fingerprint.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-finalization-lifecycle-v1";
const MAX_TEXT_BYTES: usize = 1_000;
const MAX_TIMESTAMP_BYTES: usize = 64;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_finalization_lifecycle_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_finalization_lifecycle_operations";
const STATE_TABLE: &str = "archive_v3_wal_finalization_lifecycle_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// The full observed predecessor of one episode's finalization columns.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::cp) struct FinalizationPredecessor {
    pub(in crate::cp) finalized_at: Option<String>,
    pub(in crate::cp) finalization_version: Option<i64>,
    pub(in crate::cp) status: String,
    pub(in crate::cp) error: Option<String>,
    pub(in crate::cp) attempted_at: Option<String>,
    pub(in crate::cp) attempt_count: i64,
    pub(in crate::cp) next_attempt_at: Option<String>,
    pub(in crate::cp) updated_at: String,
}

impl FinalizationPredecessor {
    fn validate(&self) -> Result<()> {
        if self.status.is_empty()
            || self.status.len() > 64
            || self.attempt_count < 0
            || self.updated_at.is_empty()
            || self.updated_at.len() > MAX_TIMESTAMP_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        for value in [
            &self.finalized_at,
            &self.error,
            &self.attempted_at,
            &self.next_attempt_at,
        ]
        .into_iter()
        .flatten()
        {
            if value.len() > MAX_TEXT_BYTES {
                return Err(WalIdempotencyError::Malformed);
            }
        }
        Ok(())
    }

    fn commitment(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hash_optional(&mut hasher, self.finalized_at.as_deref())?;
        match self.finalization_version {
            None => hasher.update([0]),
            Some(version) => {
                hasher.update([1]);
                hasher.update(version.to_be_bytes());
            }
        }
        hash_field(&mut hasher, self.status.as_bytes())?;
        hash_optional(&mut hasher, self.error.as_deref())?;
        hash_optional(&mut hasher, self.attempted_at.as_deref())?;
        hash_field(&mut hasher, &self.attempt_count.to_be_bytes())?;
        hash_optional(&mut hasher, self.next_attempt_at.as_deref())?;
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        let commitment: [u8; 32] = hasher.finalize().into();
        (commitment != [0; 32])
            .then_some(commitment)
            .ok_or(WalIdempotencyError::Corrupt)
    }
}

/// The transition targets, with every written value computed pre-submit.
#[derive(Clone)]
pub(in crate::cp) enum LifecycleTarget {
    /// `set_finalization_status`: stamp status/error, optionally marking the
    /// attempt time.
    SetStatus {
        status: String,
        error: Option<String>,
        attempted: bool,
    },
    /// `record_finalization_failure`: the retry ladder, with the attempt
    /// count and disposition computed in Rust from the pinned predecessor.
    RecordFailure {
        status: String,
        error: String,
        attempt_count: i64,
        next_attempt_at: Option<String>,
    },
    /// `defer_finalization_for_budget`.
    DeferBudget { next_attempt_at: String },
}

impl LifecycleTarget {
    const fn tag(&self) -> u8 {
        match self {
            Self::SetStatus { .. } => 1,
            Self::RecordFailure { .. } => 2,
            Self::DeferBudget { .. } => 3,
        }
    }
}

pub(crate) struct FinalizationLifecyclePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    episode_id: i64,
    predecessor: FinalizationPredecessor,
    target: LifecycleTarget,
    committed_at: String,
}

impl FinalizationLifecyclePlan {
    pub(in crate::cp) fn new(
        account_id: String,
        episode_id: i64,
        predecessor: FinalizationPredecessor,
        target: LifecycleTarget,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        predecessor.validate()?;
        if episode_id <= 0
            || committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
            || committed_at.contains('\0')
        {
            return Err(WalIdempotencyError::Malformed);
        }
        match &target {
            LifecycleTarget::SetStatus { status, error, .. } => {
                if status.is_empty()
                    || status.len() > 64
                    || error.as_deref().is_some_and(|e| e.len() > MAX_TEXT_BYTES)
                {
                    return Err(WalIdempotencyError::Malformed);
                }
            }
            LifecycleTarget::RecordFailure {
                status,
                error,
                attempt_count,
                next_attempt_at,
            } => {
                if status.is_empty()
                    || status.len() > 64
                    || error.len() > MAX_TEXT_BYTES
                    || *attempt_count != predecessor.attempt_count.saturating_add(1)
                    || next_attempt_at
                        .as_deref()
                        .is_some_and(|t| t.len() > MAX_TIMESTAMP_BYTES)
                {
                    return Err(WalIdempotencyError::Malformed);
                }
            }
            LifecycleTarget::DeferBudget { next_attempt_at } => {
                if next_attempt_at.is_empty() || next_attempt_at.len() > MAX_TIMESTAMP_BYTES {
                    return Err(WalIdempotencyError::Malformed);
                }
            }
        }
        let source = stable_operation_source(
            SUBTYPE,
            &[
                account_id.as_bytes(),
                &episode_id.to_be_bytes(),
                &[target.tag()],
                &predecessor.commitment()?,
            ],
        )?;
        let operation_id = WalLogicalOperationId::from_stable_source(
            WalOperationKind::FinalizationCommit,
            &source,
        )?;
        Ok(Self {
            operation_id,
            account_id,
            episode_id,
            predecessor,
            target,
            committed_at,
        })
    }

    fn load_current(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<Option<FinalizationPredecessor>> {
        transaction
            .query_row(
                "SELECT finalized_at,finalization_version,finalization_status,
                        finalization_error,finalization_attempted_at,
                        finalization_attempt_count,finalization_next_attempt_at,updated_at
                 FROM episodes WHERE id=?1",
                [self.episode_id],
                |row| {
                    Ok(FinalizationPredecessor {
                        finalized_at: row.get(0)?,
                        finalization_version: row.get(1)?,
                        status: row.get(2)?,
                        error: row.get(3)?,
                        attempted_at: row.get(4)?,
                        attempt_count: row.get(5)?,
                        next_attempt_at: row.get(6)?,
                        updated_at: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)
    }

    fn matches_target(&self, current: &FinalizationPredecessor) -> bool {
        match &self.target {
            LifecycleTarget::SetStatus {
                status,
                error,
                attempted,
            } => {
                current.status == *status
                    && current.error == *error
                    && (!attempted || current.attempted_at.as_deref() == Some(&self.committed_at))
            }
            LifecycleTarget::RecordFailure {
                status,
                error,
                attempt_count,
                next_attempt_at,
            } => {
                current.status == *status
                    && current.error.as_deref() == Some(error.as_str())
                    && current.attempt_count == *attempt_count
                    && current.next_attempt_at == *next_attempt_at
            }
            LifecycleTarget::DeferBudget { next_attempt_at } => {
                current.status == "budget_wait"
                    && current.next_attempt_at.as_deref() == Some(next_attempt_at.as_str())
            }
        }
    }
}

pub(crate) struct FinalizationLifecycleLedger;

impl WalLogicalDomainPlan for FinalizationLifecyclePlan {
    type Ledger = FinalizationLifecycleLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::FinalizationCommit
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(2 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        request.extend_from_slice(&self.episode_id.to_be_bytes());
        request.extend_from_slice(&self.predecessor.commitment()?);
        request.push(self.target.tag());
        match &self.target {
            LifecycleTarget::SetStatus {
                status,
                error,
                attempted,
            } => {
                encode_string(&mut request, status)?;
                encode_optional(&mut request, error.as_deref())?;
                request.push(u8::from(*attempted));
            }
            LifecycleTarget::RecordFailure {
                status,
                error,
                attempt_count,
                next_attempt_at,
            } => {
                encode_string(&mut request, status)?;
                encode_string(&mut request, error)?;
                request.extend_from_slice(&attempt_count.to_be_bytes());
                encode_optional(&mut request, next_attempt_at.as_deref())?;
            }
            LifecycleTarget::DeferBudget { next_attempt_at } => {
                encode_string(&mut request, next_attempt_at)?;
            }
        }
        // The commit stamp is a written target value, so unlike F2's identity
        // clock it IS fingerprinted; a crash-retry re-reads an advanced
        // predecessor and derives a fresh operation instead of colliding.
        encode_string(&mut request, &self.committed_at)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let current = self
            .load_current(transaction)?
            .ok_or(WalIdempotencyError::Precondition)?;
        if self.matches_target(&current) {
            // Lost-ack convergence.
            return Ok(WalReplayResult::unit());
        }
        if current != self.predecessor {
            return Err(WalIdempotencyError::Precondition);
        }
        let changed = match &self.target {
            LifecycleTarget::SetStatus {
                status,
                error,
                attempted,
            } => transaction
                .execute(
                    "UPDATE episodes
                     SET finalization_status=?1,
                         finalization_error=?2,
                         finalization_attempted_at=
                             CASE WHEN ?3=1 THEN ?4 ELSE finalization_attempted_at END,
                         updated_at=?4
                     WHERE id=?5 AND finalization_status=?6
                       AND finalization_attempt_count=?7 AND updated_at=?8",
                    params![
                        status,
                        error,
                        i64::from(*attempted),
                        self.committed_at,
                        self.episode_id,
                        self.predecessor.status,
                        self.predecessor.attempt_count,
                        self.predecessor.updated_at,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?,
            LifecycleTarget::RecordFailure {
                status,
                error,
                attempt_count,
                next_attempt_at,
            } => transaction
                .execute(
                    "UPDATE episodes
                     SET finalization_status=?1,
                         finalization_error=?2,
                         finalization_attempt_count=?3,
                         finalization_next_attempt_at=?4,
                         updated_at=?5
                     WHERE id=?6 AND finalization_status=?7
                       AND finalization_attempt_count=?8 AND updated_at=?9",
                    params![
                        status,
                        error,
                        attempt_count,
                        next_attempt_at,
                        self.committed_at,
                        self.episode_id,
                        self.predecessor.status,
                        self.predecessor.attempt_count,
                        self.predecessor.updated_at,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?,
            LifecycleTarget::DeferBudget { next_attempt_at } => transaction
                .execute(
                    "UPDATE episodes
                     SET finalization_status='budget_wait',
                         finalization_error='daily Vertex output-token budget exhausted',
                         finalization_next_attempt_at=?1,
                         updated_at=?2
                     WHERE id=?3 AND finalization_status=?4
                       AND finalization_attempt_count=?5 AND updated_at=?6",
                    params![
                        next_attempt_at,
                        self.committed_at,
                        self.episode_id,
                        self.predecessor.status,
                        self.predecessor.attempt_count,
                        self.predecessor.updated_at,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?,
        };
        if changed != 1 {
            return Err(WalIdempotencyError::Precondition);
        }
        let settled = self
            .load_current(transaction)?
            .ok_or(WalIdempotencyError::Corrupt)?;
        if !self.matches_target(&settled) {
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

impl WalLogicalDomainLedger<FinalizationLifecyclePlan> for FinalizationLifecycleLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<FinalizationLifecyclePlan>,
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
                 FROM archive_v3_wal_finalization_lifecycle_operations
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
        let kind = WalOperationKind::FinalizationCommit;
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
        prepared: &PreparedLogicalMutation<FinalizationLifecyclePlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::FinalizationCommit;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_finalization_lifecycle_operations
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
                "UPDATE archive_v3_wal_finalization_lifecycle_state
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

fn require_kind(prepared: &PreparedLogicalMutation<FinalizationLifecyclePlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::FinalizationCommit {
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
                    "CREATE TABLE archive_v3_wal_finalization_lifecycle_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_finalization_lifecycle_operations (
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
                     CREATE TABLE archive_v3_wal_finalization_lifecycle_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_finalization_lifecycle_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_finalization_lifecycle_state
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
             FROM archive_v3_wal_finalization_lifecycle_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::FinalizationCommit.codec_version()),
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
             FROM archive_v3_wal_finalization_lifecycle_state WHERE singleton=1",
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

fn hash_optional(hasher: &mut Sha256, value: Option<&str>) -> Result<()> {
    match value {
        None => {
            hasher.update([0]);
            Ok(())
        }
        Some(value) => {
            hasher.update([1]);
            hash_field(hasher, value.as_bytes())
        }
    }
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

fn encode_optional(request: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
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
    const COMMITTED_AT: &str = "2026-08-20T18:00:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE episodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finalized_at TEXT,
                    finalization_version INTEGER,
                    finalization_status TEXT NOT NULL DEFAULT 'pending_horizon',
                    finalization_error TEXT,
                    finalization_attempted_at TEXT,
                    finalization_attempt_count INTEGER NOT NULL DEFAULT 0,
                    finalization_next_attempt_at TEXT,
                    updated_at TEXT NOT NULL DEFAULT '2026-08-20T17:00:00.000Z'
                 );",
            )
            .unwrap();
        connection
            .execute("INSERT INTO episodes (id) VALUES (7)", [])
            .unwrap();
    }

    fn predecessor(connection: &Connection) -> FinalizationPredecessor {
        connection
            .query_row(
                "SELECT finalized_at,finalization_version,finalization_status,
                        finalization_error,finalization_attempted_at,
                        finalization_attempt_count,finalization_next_attempt_at,updated_at
                 FROM episodes WHERE id=7",
                [],
                |row| {
                    Ok(FinalizationPredecessor {
                        finalized_at: row.get(0)?,
                        finalization_version: row.get(1)?,
                        status: row.get(2)?,
                        error: row.get(3)?,
                        attempted_at: row.get(4)?,
                        attempt_count: row.get(5)?,
                        next_attempt_at: row.get(6)?,
                        updated_at: row.get(7)?,
                    })
                },
            )
            .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: FinalizationLifecyclePlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn failure_ladder_advances_once_and_predecessor_moves_derive_new_operations() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let before = predecessor(&connection);
        let failure = FinalizationLifecyclePlan::new(
            ACCOUNT.into(),
            7,
            before.clone(),
            LifecycleTarget::RecordFailure {
                status: "retry_wait".into(),
                error: "vertex timeout".into(),
                attempt_count: before.attempt_count + 1,
                next_attempt_at: Some("2026-08-20T19:00:00.000Z".into()),
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        let first_id = failure.operation_id().as_bytes().to_vec();
        assert!(matches!(
            settle(&mut connection, failure).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let (attempts, status): (i64, String) = connection
            .query_row(
                "SELECT finalization_attempt_count,finalization_status FROM episodes WHERE id=7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(attempts, 1);
        assert_eq!(status, "retry_wait");
        // The advanced predecessor derives a NEW id: the counter never
        // appears as a counter, but the tuple containing it does (R3 case 2).
        let after = predecessor(&connection);
        let second = FinalizationLifecyclePlan::new(
            ACCOUNT.into(),
            7,
            after.clone(),
            LifecycleTarget::RecordFailure {
                status: "retry_wait".into(),
                error: "vertex timeout".into(),
                attempt_count: after.attempt_count + 1,
                next_attempt_at: Some("2026-08-20T20:00:00.000Z".into()),
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert_ne!(second.operation_id().as_bytes().to_vec(), first_id);
        assert!(matches!(
            settle(&mut connection, second).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let attempts: i64 = connection
            .query_row(
                "SELECT finalization_attempt_count FROM episodes WHERE id=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attempts, 2);
    }

    #[test]
    fn set_status_defer_and_adopt_converge_without_rewrites() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let before = predecessor(&connection);
        let set = FinalizationLifecyclePlan::new(
            ACCOUNT.into(),
            7,
            before.clone(),
            LifecycleTarget::SetStatus {
                status: "in_progress".into(),
                error: None,
                attempted: true,
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        let replay = FinalizationLifecyclePlan::new(
            ACCOUNT.into(),
            7,
            before,
            LifecycleTarget::SetStatus {
                status: "in_progress".into(),
                error: None,
                attempted: true,
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, set).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let attempted_at: Option<String> = connection
            .query_row(
                "SELECT finalization_attempted_at FROM episodes WHERE id=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attempted_at.as_deref(), Some(COMMITTED_AT));
        assert!(matches!(
            settle(&mut connection, replay).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        // Budget deferral from the moved predecessor.
        let current = predecessor(&connection);
        let defer = FinalizationLifecyclePlan::new(
            ACCOUNT.into(),
            7,
            current,
            LifecycleTarget::DeferBudget {
                next_attempt_at: "2026-08-20T19:00:00.000Z".into(),
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, defer).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let status: String = connection
            .query_row(
                "SELECT finalization_status FROM episodes WHERE id=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "budget_wait");
    }

    #[test]
    fn stale_predecessors_and_malformed_targets_fail_closed() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let stale = predecessor(&connection);
        // Someone else advances the ladder first.
        connection
            .execute(
                "UPDATE episodes SET finalization_attempt_count=5 WHERE id=7",
                [],
            )
            .unwrap();
        let plan = FinalizationLifecyclePlan::new(
            ACCOUNT.into(),
            7,
            stale.clone(),
            LifecycleTarget::SetStatus {
                status: "in_progress".into(),
                error: None,
                attempted: false,
            },
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, plan),
            Err(WalIdempotencyError::Precondition)
        ));
        // The failure target must carry attempts = predecessor + 1 exactly.
        assert!(FinalizationLifecyclePlan::new(
            ACCOUNT.into(),
            7,
            stale.clone(),
            LifecycleTarget::RecordFailure {
                status: "retry_wait".into(),
                error: "e".into(),
                attempt_count: stale.attempt_count + 2,
                next_attempt_at: None,
            },
            COMMITTED_AT.into(),
        )
        .is_err());
        assert!(FinalizationLifecyclePlan::new(
            ACCOUNT.into(),
            0,
            stale,
            LifecycleTarget::DeferBudget {
                next_attempt_at: "t".into(),
            },
            COMMITTED_AT.into(),
        )
        .is_err());
    }
}
