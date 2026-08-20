//! Vertex intent reconciliation as a sealed WAL plan (ADR-0022 F3).
//!
//! `pending_events` performs three archive mutations in one transaction: the
//! stale-`started` sweep to `ambiguous`, the unsafe-model poison quarantine
//! (twelve token columns NULLed, `outcome='usage_missing'`,
//! `delivery_state='delivered'`), and the coverage `lost_events` accounting.
//! They are atomic today and stay atomic here: one plan, all three writes.
//!
//! R6 applies: the open `WHERE outcome='started' AND observed_at <= <clock>`
//! becomes a routed enumeration whose **resolved ordered set** is the
//! fingerprinted request; `apply()` re-validates that exact set and never
//! widens its predicate to catch up.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-vertex-intent-reconcile-v1";
const MAX_EVENTS: usize = 256;
const MAX_ID_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_PERIOD_BYTES: usize = 16;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_vertex_reconcile_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_vertex_reconcile_operations";
const STATE_TABLE: &str = "archive_v3_wal_vertex_reconcile_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// One enumerated stale `started` intent.
#[derive(Clone)]
pub(in crate::cp) struct StaleIntent {
    event_id: String,
    observed_at: String,
}

impl StaleIntent {
    pub(in crate::cp) fn new(event_id: String, observed_at: String) -> Result<Self> {
        validate_event_id(&event_id)?;
        if observed_at.is_empty()
            || observed_at.len() > MAX_TIMESTAMP_BYTES
            || observed_at.contains('\0')
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            event_id,
            observed_at,
        })
    }

    pub(in crate::cp) fn event_id_for_order(&self) -> &str {
        &self.event_id
    }
}

/// One enumerated unsafe-model event with its observed predecessor.
#[derive(Clone)]
pub(in crate::cp) struct PoisonIntent {
    event_id: String,
    outcome: String,
    delivery_state: String,
}

impl PoisonIntent {
    pub(in crate::cp) fn new(
        event_id: String,
        outcome: String,
        delivery_state: String,
    ) -> Result<Self> {
        validate_event_id(&event_id)?;
        if outcome.is_empty()
            || outcome.len() > 32
            || delivery_state.is_empty()
            || delivery_state.len() > 32
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            event_id,
            outcome,
            delivery_state,
        })
    }

    pub(in crate::cp) fn event_id_for_order(&self) -> &str {
        &self.event_id
    }
}

pub(crate) struct VertexIntentReconcilePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    stale: Vec<StaleIntent>,
    poison: Vec<PoisonIntent>,
    period: String,
    predecessor_lost_events: i64,
    committed_at: String,
}

impl VertexIntentReconcilePlan {
    pub(in crate::cp) fn new(
        account_id: String,
        stale: Vec<StaleIntent>,
        poison: Vec<PoisonIntent>,
        period: String,
        predecessor_lost_events: i64,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if stale.is_empty() && poison.is_empty() {
            // A clean scan submits nothing; constructing an empty
            // reconciliation is a caller bug.
            return Err(WalIdempotencyError::Malformed);
        }
        if stale.len() > MAX_EVENTS || poison.len() > MAX_EVENTS {
            return Err(WalIdempotencyError::Limit);
        }
        if !stale
            .windows(2)
            .all(|pair| pair[0].event_id < pair[1].event_id)
            || !poison
                .windows(2)
                .all(|pair| pair[0].event_id < pair[1].event_id)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if period.len() != 7
            || period.len() > MAX_PERIOD_BYTES
            || predecessor_lost_events < 0
            || committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
            || committed_at.contains('\0')
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut payload = Sha256::new();
        for intent in &stale {
            hash_field(&mut payload, intent.event_id.as_bytes())?;
            hash_field(&mut payload, intent.observed_at.as_bytes())?;
        }
        payload.update([0]);
        for intent in &poison {
            hash_field(&mut payload, intent.event_id.as_bytes())?;
            hash_field(&mut payload, intent.outcome.as_bytes())?;
            hash_field(&mut payload, intent.delivery_state.as_bytes())?;
        }
        payload.update([0]);
        hash_field(&mut payload, period.as_bytes())?;
        hash_field(&mut payload, &predecessor_lost_events.to_be_bytes())?;
        let payload: [u8; 32] = payload.finalize().into();
        let source = stable_operation_source(SUBTYPE, &[account_id.as_bytes(), &payload])?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::VertexUsage, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            stale,
            poison,
            period,
            predecessor_lost_events,
            committed_at,
        })
    }
}

pub(crate) struct VertexIntentReconcileLedger;

impl WalLogicalDomainPlan for VertexIntentReconcilePlan {
    type Ledger = VertexIntentReconcileLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::VertexUsage
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(8 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        encode_len(&mut request, self.stale.len())?;
        for intent in &self.stale {
            encode_string(&mut request, &intent.event_id)?;
            encode_string(&mut request, &intent.observed_at)?;
        }
        encode_len(&mut request, self.poison.len())?;
        for intent in &self.poison {
            encode_string(&mut request, &intent.event_id)?;
            encode_string(&mut request, &intent.outcome)?;
            encode_string(&mut request, &intent.delivery_state)?;
        }
        encode_string(&mut request, &self.period)?;
        request.extend_from_slice(&self.predecessor_lost_events.to_be_bytes());
        // committed_at stays out of identity and fingerprint (clock; F2
        // precedent).
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        for intent in &self.stale {
            let changed = transaction
                .execute(
                    "UPDATE vertex_usage_events SET outcome='ambiguous',updated_at=?1
                     WHERE event_id=?2 AND outcome='started' AND observed_at=?3",
                    params![self.committed_at, intent.event_id, intent.observed_at],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                let adopted: i64 = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM vertex_usage_events
                         WHERE event_id=?1 AND outcome!='started'",
                        [&intent.event_id],
                        |row| row.get(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if adopted != 1 {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
        }
        for intent in &self.poison {
            let changed = transaction
                .execute(
                    "UPDATE vertex_usage_events
                     SET returned_model=NULL,prompt_tokens=NULL,input_text_tokens=NULL,
                         input_audio_tokens=NULL,input_image_tokens=NULL,
                         cached_input_tokens=NULL,cached_input_text_tokens=NULL,
                         cached_input_audio_tokens=NULL,cached_input_image_tokens=NULL,
                         output_text_tokens=NULL,thought_tokens=NULL,total_tokens=NULL,
                         outcome='usage_missing',delivery_state='delivered',updated_at=?1
                     WHERE event_id=?2 AND outcome=?3 AND delivery_state=?4",
                    params![
                        self.committed_at,
                        intent.event_id,
                        intent.outcome,
                        intent.delivery_state
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                let adopted: i64 = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM vertex_usage_events
                         WHERE event_id=?1 AND outcome='usage_missing'
                           AND delivery_state='delivered'",
                        [&intent.event_id],
                        |row| row.get(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if adopted != 1 {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
        }
        // Coverage refresh (clock-free) plus the lost-events accounting under
        // a re-verified predecessor.
        transaction
            .execute(
                "INSERT INTO vertex_usage_coverage
                 (period,sequence,pending_events,lost_events,delivery_state,updated_at)
                 VALUES (
                    ?1,1,
                    (SELECT count(*) FROM vertex_usage_events
                     WHERE delivery_state='pending' AND substr(observed_at,1,7)=?1),
                    0,'pending',?2)
                 ON CONFLICT(period) DO UPDATE SET
                    sequence=vertex_usage_coverage.sequence+1,
                    pending_events=excluded.pending_events,
                    lost_events=vertex_usage_coverage.lost_events,
                    delivery_state='pending',
                    updated_at=?2",
                params![self.period, self.committed_at],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if !self.poison.is_empty() {
            let target =
                self.predecessor_lost_events + i64::try_from(self.poison.len()).unwrap_or(0);
            let changed = transaction
                .execute(
                    "UPDATE vertex_usage_coverage
                     SET lost_events=?1,delivery_state='pending'
                     WHERE period=?2 AND lost_events=?3",
                    params![target, self.period, self.predecessor_lost_events],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                let adopted: i64 = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM vertex_usage_coverage
                         WHERE period=?1 AND lost_events>=?2",
                        params![self.period, target],
                        |row| row.get(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if adopted != 1 {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<VertexIntentReconcilePlan> for VertexIntentReconcileLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<VertexIntentReconcilePlan>,
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
                 FROM archive_v3_wal_vertex_reconcile_operations
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
        prepared: &PreparedLogicalMutation<VertexIntentReconcilePlan>,
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
                "INSERT INTO archive_v3_wal_vertex_reconcile_operations
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
                "UPDATE archive_v3_wal_vertex_reconcile_state
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

fn require_kind(prepared: &PreparedLogicalMutation<VertexIntentReconcilePlan>) -> Result<()> {
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
                    "CREATE TABLE archive_v3_wal_vertex_reconcile_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_vertex_reconcile_operations (
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
                     CREATE TABLE archive_v3_wal_vertex_reconcile_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_vertex_reconcile_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_vertex_reconcile_state
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
             FROM archive_v3_wal_vertex_reconcile_schema WHERE singleton=1",
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
             FROM archive_v3_wal_vertex_reconcile_state WHERE singleton=1",
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

fn validate_event_id(value: &str) -> Result<()> {
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
    const COMMITTED_AT: &str = "2026-08-20T17:00:00.000Z";
    const OBSERVED: &str = "2026-08-20T16:00:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE vertex_usage_events (
                    event_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL DEFAULT 'episode_summarization',
                    requested_model TEXT NOT NULL DEFAULT 'm',
                    returned_model TEXT,
                    location TEXT NOT NULL DEFAULT 'l',
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
                    outcome TEXT NOT NULL DEFAULT 'started',
                    delivery_state TEXT NOT NULL DEFAULT 'pending',
                    delivery_attempt_count INTEGER NOT NULL DEFAULT 0,
                    observed_at TEXT NOT NULL DEFAULT '2026-08-20T16:00:00.000Z',
                    updated_at TEXT NOT NULL DEFAULT ''
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

    fn settle(
        connection: &mut Connection,
        plan: VertexIntentReconcilePlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn reconcile_settles_all_three_mutations_atomically_and_replays() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
            .execute(
                "INSERT INTO vertex_usage_events (event_id,outcome,total_tokens) VALUES
                 ('vtx_stale','started',NULL),
                 ('vtx_poison','metered',42)",
                [],
            )
            .unwrap();
        let build = || {
            VertexIntentReconcilePlan::new(
                ACCOUNT.into(),
                vec![StaleIntent::new("vtx_stale".into(), OBSERVED.into()).unwrap()],
                vec![
                    PoisonIntent::new("vtx_poison".into(), "metered".into(), "pending".into())
                        .unwrap(),
                ],
                "2026-08".into(),
                0,
                COMMITTED_AT.into(),
            )
            .unwrap()
        };
        assert!(matches!(
            settle(&mut connection, build()).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let (stale_outcome,): (String,) = connection
            .query_row(
                "SELECT outcome FROM vertex_usage_events WHERE event_id='vtx_stale'",
                [],
                |row| Ok((row.get(0)?,)),
            )
            .unwrap();
        assert_eq!(stale_outcome, "ambiguous");
        let (poison_outcome, poison_state, tokens): (String, String, Option<i64>) = connection
            .query_row(
                "SELECT outcome,delivery_state,total_tokens
                 FROM vertex_usage_events WHERE event_id='vtx_poison'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(poison_outcome, "usage_missing");
        assert_eq!(poison_state, "delivered");
        assert_eq!(tokens, None);
        let lost: i64 = connection
            .query_row(
                "SELECT lost_events FROM vertex_usage_coverage WHERE period='2026-08'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(lost, 1);
        // The identical plan replays; nothing re-applies.
        assert!(matches!(
            settle(&mut connection, build()).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        let lost: i64 = connection
            .query_row(
                "SELECT lost_events FROM vertex_usage_coverage WHERE period='2026-08'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(lost, 1, "the lost counter must not double-count on replay");
    }

    #[test]
    fn moved_rows_fail_closed_but_already_converged_rows_adopt() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
            .execute(
                "INSERT INTO vertex_usage_events (event_id,outcome) VALUES
                 ('vtx_a','started')",
                [],
            )
            .unwrap();
        let plan = VertexIntentReconcilePlan::new(
            ACCOUNT.into(),
            vec![StaleIntent::new("vtx_a".into(), OBSERVED.into()).unwrap()],
            vec![],
            "2026-08".into(),
            0,
            COMMITTED_AT.into(),
        )
        .unwrap();
        // The intent settled its outcome between scan and submit: the stale
        // sweep's target is gone, but the row is TERMINAL, which is what the
        // sweep wanted -- adopt, don't wedge.
        connection
            .execute(
                "UPDATE vertex_usage_events SET outcome='metered' WHERE event_id='vtx_a'",
                [],
            )
            .unwrap();
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let outcome: String = connection
            .query_row(
                "SELECT outcome FROM vertex_usage_events WHERE event_id='vtx_a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outcome, "metered", "an adopted terminal row is untouched");
    }

    #[test]
    fn empty_reconciliation_and_unordered_sets_are_rejected() {
        assert!(VertexIntentReconcilePlan::new(
            ACCOUNT.into(),
            vec![],
            vec![],
            "2026-08".into(),
            0,
            COMMITTED_AT.into(),
        )
        .is_err());
        let b = StaleIntent::new("vtx_b".into(), OBSERVED.into()).unwrap();
        let a = StaleIntent::new("vtx_a".into(), OBSERVED.into()).unwrap();
        assert!(VertexIntentReconcilePlan::new(
            ACCOUNT.into(),
            vec![b, a],
            vec![],
            "2026-08".into(),
            0,
            COMMITTED_AT.into(),
        )
        .is_err());
    }
}
