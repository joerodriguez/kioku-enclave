//! Vertex usage-delivery settlement as a sealed WAL plan (ADR-0022 F4).
//!
//! `complete_delivery` marks enumerated events delivered after the billing
//! plane accepted them; `note_delivery_failure` advances their attempt
//! counter after it refused. Both arms carry the full predecessor tuple per
//! event and write absolutely — the increment is computed as
//! `predecessor + 1` and written as a value, never `col = col + 1` (R3: no
//! read-then-increment inside apply).
//!
//! The outcome tag is part of the identity, so the two arms of one drain are
//! distinct operations: a drain that claims both simply produces two ids, and
//! only the arm whose predecessor CAS matches settles.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-vertex-usage-delivery-v1";
const MAX_EVENTS: usize = 256;
const MAX_ID_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_vertex_delivery_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_vertex_delivery_operations";
const STATE_TABLE: &str = "archive_v3_wal_vertex_delivery_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cp) enum DeliveryOutcome {
    Delivered = 1,
    AttemptFailed = 2,
}

/// One enumerated event with its observed predecessor tuple.
#[derive(Clone)]
pub(in crate::cp) struct DeliveryEventPredecessor {
    event_id: String,
    attempt_count: i64,
    updated_at: String,
}

impl DeliveryEventPredecessor {
    pub(in crate::cp) fn new(
        event_id: String,
        attempt_count: i64,
        updated_at: String,
    ) -> Result<Self> {
        if event_id.is_empty()
            || event_id.len() > MAX_ID_BYTES
            || event_id.contains('\0')
            || attempt_count < 0
            || updated_at.is_empty()
            || updated_at.len() > MAX_TIMESTAMP_BYTES
            || updated_at.contains('\0')
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            event_id,
            attempt_count,
            updated_at,
        })
    }
}

pub(crate) struct VertexUsageDeliveryPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    outcome: DeliveryOutcome,
    events: Vec<DeliveryEventPredecessor>,
    committed_at: String,
}

impl VertexUsageDeliveryPlan {
    pub(in crate::cp) fn new(
        account_id: String,
        outcome: DeliveryOutcome,
        events: Vec<DeliveryEventPredecessor>,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if events.is_empty()
            || events.len() > MAX_EVENTS
            || committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
            || committed_at.contains('\0')
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if !events
            .windows(2)
            .all(|pair| pair[0].event_id < pair[1].event_id)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut set = Sha256::new();
        for event in &events {
            hash_field(&mut set, event.event_id.as_bytes())?;
            hash_field(&mut set, &event.attempt_count.to_be_bytes())?;
            hash_field(&mut set, event.updated_at.as_bytes())?;
        }
        let set: [u8; 32] = set.finalize().into();
        let source =
            stable_operation_source(SUBTYPE, &[account_id.as_bytes(), &[outcome as u8], &set])?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::VertexUsage, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            outcome,
            events,
            committed_at,
        })
    }
}

pub(crate) struct VertexUsageDeliveryLedger;

impl WalLogicalDomainPlan for VertexUsageDeliveryPlan {
    type Ledger = VertexUsageDeliveryLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::VertexUsage
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(4 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        request.push(self.outcome as u8);
        encode_len(&mut request, self.events.len())?;
        for event in &self.events {
            encode_string(&mut request, &event.event_id)?;
            request.extend_from_slice(&event.attempt_count.to_be_bytes());
            encode_string(&mut request, &event.updated_at)?;
        }
        // committed_at is deliberately NOT here (nor in the identity): it is
        // a clock; see the F2 precedent. It is carried unfingerprinted and
        // written once by the first apply.
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        for event in &self.events {
            let row = transaction
                .query_row(
                    "SELECT delivery_state,delivery_attempt_count FROM vertex_usage_events
                     WHERE event_id=?1",
                    [&event.event_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let Some((state, attempts)) = row else {
                return Err(WalIdempotencyError::Precondition);
            };
            let adopted = match self.outcome {
                DeliveryOutcome::Delivered => state == "delivered",
                DeliveryOutcome::AttemptFailed => {
                    state == "pending" && attempts == event.attempt_count + 1
                }
            };
            if adopted {
                // Lost-ack convergence for this row; nothing to write.
                continue;
            }
            if state != "pending" || attempts != event.attempt_count {
                return Err(WalIdempotencyError::Precondition);
            }
            let changed = match self.outcome {
                DeliveryOutcome::Delivered => transaction
                    .execute(
                        "UPDATE vertex_usage_events
                         SET delivery_state='delivered',updated_at=?1
                         WHERE event_id=?2 AND delivery_state='pending'
                           AND delivery_attempt_count=?3",
                        params![self.committed_at, event.event_id, event.attempt_count],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?,
                DeliveryOutcome::AttemptFailed => transaction
                    .execute(
                        "UPDATE vertex_usage_events
                         SET delivery_attempt_count=?1,updated_at=?2
                         WHERE event_id=?3 AND delivery_state='pending'
                           AND delivery_attempt_count=?4",
                        params![
                            event.attempt_count + 1,
                            self.committed_at,
                            event.event_id,
                            event.attempt_count
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?,
            };
            if changed != 1 {
                return Err(WalIdempotencyError::Precondition);
            }
        }
        if self.outcome == DeliveryOutcome::Delivered {
            // Clock-free coverage refresh on the delivered arm, mirroring the
            // legacy refresh with the carried timestamp.
            let period = &self.committed_at[..7.min(self.committed_at.len())];
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
                    params![period, self.committed_at],
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

impl WalLogicalDomainLedger<VertexUsageDeliveryPlan> for VertexUsageDeliveryLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<VertexUsageDeliveryPlan>,
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
                 FROM archive_v3_wal_vertex_delivery_operations
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
        prepared: &PreparedLogicalMutation<VertexUsageDeliveryPlan>,
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
                "INSERT INTO archive_v3_wal_vertex_delivery_operations
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
                "UPDATE archive_v3_wal_vertex_delivery_state
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

fn require_kind(prepared: &PreparedLogicalMutation<VertexUsageDeliveryPlan>) -> Result<()> {
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
                    "CREATE TABLE archive_v3_wal_vertex_delivery_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_vertex_delivery_operations (
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
                     CREATE TABLE archive_v3_wal_vertex_delivery_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_vertex_delivery_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_vertex_delivery_state
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
             FROM archive_v3_wal_vertex_delivery_schema WHERE singleton=1",
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
             FROM archive_v3_wal_vertex_delivery_state WHERE singleton=1",
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
    const COMMITTED_AT: &str = "2026-08-20T16:00:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE vertex_usage_events (
                    event_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL DEFAULT 'episode_summarization',
                    requested_model TEXT NOT NULL DEFAULT 'm',
                    location TEXT NOT NULL DEFAULT 'l',
                    outcome TEXT NOT NULL DEFAULT 'metered',
                    delivery_state TEXT NOT NULL DEFAULT 'pending',
                    delivery_attempt_count INTEGER NOT NULL DEFAULT 0,
                    observed_at TEXT NOT NULL DEFAULT '2026-08-20T15:00:00.000Z',
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

    fn seed_event(connection: &Connection, event_id: &str, attempts: i64) {
        connection
            .execute(
                "INSERT INTO vertex_usage_events (event_id,delivery_attempt_count,updated_at)
                 VALUES (?1,?2,'2026-08-20T15:00:01.000Z')",
                params![event_id, attempts],
            )
            .unwrap();
    }

    fn predecessors(connection: &Connection, ids: &[&str]) -> Vec<DeliveryEventPredecessor> {
        let mut ids = ids.to_vec();
        ids.sort_unstable();
        ids.iter()
            .map(|id| {
                let (attempts, updated): (i64, String) = connection
                    .query_row(
                        "SELECT delivery_attempt_count,updated_at
                         FROM vertex_usage_events WHERE event_id=?1",
                        [id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                DeliveryEventPredecessor::new((*id).into(), attempts, updated).unwrap()
            })
            .collect()
    }

    fn settle(
        connection: &mut Connection,
        plan: VertexUsageDeliveryPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn delivered_arm_settles_replays_and_adopts_without_rewrites() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        seed_event(&connection, "vtx_a", 0);
        seed_event(&connection, "vtx_b", 2);
        let events = predecessors(&connection, &["vtx_a", "vtx_b"]);
        let plan = VertexUsageDeliveryPlan::new(
            ACCOUNT.into(),
            DeliveryOutcome::Delivered,
            events.clone(),
            COMMITTED_AT.into(),
        )
        .unwrap();
        let replay = VertexUsageDeliveryPlan::new(
            ACCOUNT.into(),
            DeliveryOutcome::Delivered,
            events,
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let delivered: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM vertex_usage_events WHERE delivery_state='delivered'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(delivered, 2);
        assert!(matches!(
            settle(&mut connection, replay).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
    }

    #[test]
    fn failure_arm_writes_the_absolute_increment_and_never_re_increments() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        seed_event(&connection, "vtx_a", 3);
        let events = predecessors(&connection, &["vtx_a"]);
        let plan = VertexUsageDeliveryPlan::new(
            ACCOUNT.into(),
            DeliveryOutcome::AttemptFailed,
            events.clone(),
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let attempts: i64 = connection
            .query_row(
                "SELECT delivery_attempt_count FROM vertex_usage_events WHERE event_id='vtx_a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attempts, 4);
        // A second submit of the identical plan replays from the ledger; the
        // adopt arm would also converge without touching the counter. Either
        // way the increment happens exactly once.
        let again = VertexUsageDeliveryPlan::new(
            ACCOUNT.into(),
            DeliveryOutcome::AttemptFailed,
            events,
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, again).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        let attempts: i64 = connection
            .query_row(
                "SELECT delivery_attempt_count FROM vertex_usage_events WHERE event_id='vtx_a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attempts, 4);
    }

    #[test]
    fn moved_predecessors_fail_closed_and_the_two_arms_are_distinct_operations() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        seed_event(&connection, "vtx_a", 0);
        let events = predecessors(&connection, &["vtx_a"]);
        let delivered = VertexUsageDeliveryPlan::new(
            ACCOUNT.into(),
            DeliveryOutcome::Delivered,
            events.clone(),
            COMMITTED_AT.into(),
        )
        .unwrap();
        let failed = VertexUsageDeliveryPlan::new(
            ACCOUNT.into(),
            DeliveryOutcome::AttemptFailed,
            events.clone(),
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert_ne!(
            delivered.operation_id().as_bytes(),
            failed.operation_id().as_bytes()
        );
        // Someone else advanced the counter between read and settle.
        connection
            .execute(
                "UPDATE vertex_usage_events SET delivery_attempt_count=9 WHERE event_id='vtx_a'",
                [],
            )
            .unwrap();
        assert!(matches!(
            settle(&mut connection, failed),
            Err(WalIdempotencyError::Precondition)
        ));
        assert!(matches!(
            settle(&mut connection, delivered),
            Err(WalIdempotencyError::Precondition)
        ));
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let event = DeliveryEventPredecessor::new("vtx_a".into(), 0, "t".into()).unwrap();
        // Unordered ids.
        let unordered = vec![
            DeliveryEventPredecessor::new("vtx_b".into(), 0, "t".into()).unwrap(),
            event.clone(),
        ];
        assert!(VertexUsageDeliveryPlan::new(
            ACCOUNT.into(),
            DeliveryOutcome::Delivered,
            unordered,
            COMMITTED_AT.into(),
        )
        .is_err());
        assert!(VertexUsageDeliveryPlan::new(
            ACCOUNT.into(),
            DeliveryOutcome::Delivered,
            vec![],
            COMMITTED_AT.into(),
        )
        .is_err());
        assert!(DeliveryEventPredecessor::new("".into(), 0, "t".into()).is_err());
        assert!(DeliveryEventPredecessor::new("vtx_a".into(), -1, "t".into()).is_err());
    }
}
