//! Webhook delivery settlement as a sealed WAL plan (ADR-0022 F14).
//!
//! Covers the cancelled/failed/retry arms of the webhook ladder. Identity:
//! subtype ‖ user ‖ event id ‖ episode ‖ subscription ‖ version ‖
//! predecessor commitment (R3 case 2). The live owner wrote `updated_at` as
//! an inline `strftime('now')` — hoisted here into the carried commit stamp
//! so `apply()` is deterministic.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-webhook-delivery-settlement-v1";
const MAX_ID_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_webhook_settlement_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_webhook_settlement_operations";
const STATE_TABLE: &str = "archive_v3_wal_webhook_settlement_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);
const STATES: &[&str] = &["pending", "sent", "retry", "cancelled", "failed"];

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// The observed predecessor of one webhook delivery row.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::cp) struct WebhookDeliveryPredecessor {
    pub(in crate::cp) state: String,
    pub(in crate::cp) attempt_count: i64,
    pub(in crate::cp) next_attempt_at: Option<String>,
    pub(in crate::cp) updated_at: String,
}

impl WebhookDeliveryPredecessor {
    fn validate(&self) -> Result<()> {
        if !STATES.contains(&self.state.as_str())
            || self.attempt_count < 0
            || self
                .next_attempt_at
                .as_deref()
                .is_some_and(|v| v.len() > MAX_TIMESTAMP_BYTES)
            || self.updated_at.is_empty()
            || self.updated_at.len() > MAX_TIMESTAMP_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(())
    }

    fn commitment(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, self.state.as_bytes())?;
        hash_field(&mut hasher, &self.attempt_count.to_be_bytes())?;
        match self.next_attempt_at.as_deref() {
            None => hasher.update([0]),
            Some(next) => {
                hasher.update([1]);
                hash_field(&mut hasher, next.as_bytes())?;
            }
        }
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        let commitment: [u8; 32] = hasher.finalize().into();
        (commitment != [0; 32])
            .then_some(commitment)
            .ok_or(WalIdempotencyError::Corrupt)
    }
}

pub(crate) struct WebhookDeliverySettlementPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    event_id: String,
    episode_id: i64,
    subscription_id: String,
    delivery_version: i64,
    predecessor: WebhookDeliveryPredecessor,
    state: String,
    attempt_count: i64,
    response_status: Option<i64>,
    error_code: Option<String>,
    next_attempt_at: Option<String>,
    committed_at: String,
}

impl WebhookDeliverySettlementPlan {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp) fn new(
        account_id: String,
        event_id: String,
        episode_id: i64,
        subscription_id: String,
        delivery_version: i64,
        predecessor: WebhookDeliveryPredecessor,
        state: String,
        attempt_count: i64,
        response_status: Option<i64>,
        error_code: Option<String>,
        next_attempt_at: Option<String>,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        predecessor.validate()?;
        if event_id.is_empty()
            || event_id.len() > MAX_ID_BYTES
            || episode_id <= 0
            || subscription_id.is_empty()
            || subscription_id.len() > MAX_ID_BYTES
            || delivery_version < 0
            || !STATES.contains(&state.as_str())
            || attempt_count < 0
            || error_code
                .as_deref()
                .is_some_and(|v| v.len() > MAX_TEXT_BYTES)
            || next_attempt_at
                .as_deref()
                .is_some_and(|v| v.is_empty() || v.len() > MAX_TIMESTAMP_BYTES)
            || committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let source = stable_operation_source(
            SUBTYPE,
            &[
                account_id.as_bytes(),
                event_id.as_bytes(),
                &episode_id.to_be_bytes(),
                subscription_id.as_bytes(),
                &delivery_version.to_be_bytes(),
                &predecessor.commitment()?,
            ],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::WebhookDelivery, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            event_id,
            episode_id,
            subscription_id,
            delivery_version,
            predecessor,
            state,
            attempt_count,
            response_status,
            error_code,
            next_attempt_at,
            committed_at,
        })
    }

    fn load_current(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<Option<(WebhookDeliveryPredecessor, Option<String>)>> {
        transaction
            .query_row(
                "SELECT state,attempt_count,next_attempt_at,updated_at,error_code
                 FROM webhook_deliveries
                 WHERE event_id=?1 AND episode_id=?2 AND subscription_id=?3
                   AND delivery_version=?4",
                params![
                    self.event_id,
                    self.episode_id,
                    self.subscription_id,
                    self.delivery_version
                ],
                |row| {
                    Ok((
                        WebhookDeliveryPredecessor {
                            state: row.get(0)?,
                            attempt_count: row.get(1)?,
                            next_attempt_at: row.get(2)?,
                            updated_at: row.get(3)?,
                        },
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)
    }

    fn matches_target(
        &self,
        current: &WebhookDeliveryPredecessor,
        error_code: &Option<String>,
    ) -> bool {
        current.state == self.state
            && current.attempt_count == self.attempt_count
            && *error_code == self.error_code
            && current.next_attempt_at == self.next_attempt_at
    }
}

pub(crate) struct WebhookDeliverySettlementLedger;

impl WalLogicalDomainPlan for WebhookDeliverySettlementPlan {
    type Ledger = WebhookDeliverySettlementLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::WebhookDelivery
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.event_id)?;
        request.extend_from_slice(&self.episode_id.to_be_bytes());
        encode_string(&mut request, &self.subscription_id)?;
        request.extend_from_slice(&self.delivery_version.to_be_bytes());
        request.extend_from_slice(&self.predecessor.commitment()?);
        encode_string(&mut request, &self.state)?;
        request.extend_from_slice(&self.attempt_count.to_be_bytes());
        match self.response_status {
            None => request.push(0),
            Some(status) => {
                request.push(1);
                request.extend_from_slice(&status.to_be_bytes());
            }
        }
        encode_optional(&mut request, self.error_code.as_deref())?;
        encode_optional(&mut request, self.next_attempt_at.as_deref())?;
        // Fingerprinted target clock: safe because the identity is the full
        // predecessor, which a successful settle advances (F10 precedent).
        encode_string(&mut request, &self.committed_at)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let Some((current, error_code)) = self.load_current(transaction)? else {
            return Err(WalIdempotencyError::Precondition);
        };
        if self.matches_target(&current, &error_code) {
            return Ok(WalReplayResult::unit());
        }
        if current != self.predecessor {
            return Err(WalIdempotencyError::Precondition);
        }
        let changed = transaction
            .execute(
                "UPDATE webhook_deliveries
                 SET state=?1,attempt_count=?2,response_status=?3,
                     error_code=?4,next_attempt_at=?5,updated_at=?6
                 WHERE event_id=?7 AND episode_id=?8 AND subscription_id=?9
                   AND delivery_version=?10
                   AND state=?11 AND attempt_count=?12 AND updated_at=?13",
                params![
                    self.state,
                    self.attempt_count,
                    self.response_status,
                    self.error_code,
                    self.next_attempt_at,
                    self.committed_at,
                    self.event_id,
                    self.episode_id,
                    self.subscription_id,
                    self.delivery_version,
                    self.predecessor.state,
                    self.predecessor.attempt_count,
                    self.predecessor.updated_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Precondition);
        }
        let Some((settled, error_code)) = self.load_current(transaction)? else {
            return Err(WalIdempotencyError::Corrupt);
        };
        if !self.matches_target(&settled, &error_code) {
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

impl WalLogicalDomainLedger<WebhookDeliverySettlementPlan> for WebhookDeliverySettlementLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<WebhookDeliverySettlementPlan>,
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
                 FROM archive_v3_wal_webhook_settlement_operations
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
        let kind = WalOperationKind::WebhookDelivery;
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
        prepared: &PreparedLogicalMutation<WebhookDeliverySettlementPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::WebhookDelivery;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_webhook_settlement_operations
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
                "UPDATE archive_v3_wal_webhook_settlement_state
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

fn require_kind(prepared: &PreparedLogicalMutation<WebhookDeliverySettlementPlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::WebhookDelivery {
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
                    "CREATE TABLE archive_v3_wal_webhook_settlement_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_webhook_settlement_operations (
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
                     CREATE TABLE archive_v3_wal_webhook_settlement_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_webhook_settlement_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_webhook_settlement_state
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
             FROM archive_v3_wal_webhook_settlement_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::WebhookDelivery.codec_version()),
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
             FROM archive_v3_wal_webhook_settlement_state WHERE singleton=1",
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
    const COMMITTED_AT: &str = "2026-08-20T20:00:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE webhook_deliveries (
                    episode_id INTEGER NOT NULL,
                    subscription_id TEXT NOT NULL,
                    delivery_version INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT NOT NULL,
                    response_status INTEGER,
                    error_code TEXT,
                    updated_at TEXT NOT NULL DEFAULT '2026-08-20T19:00:00.000Z',
                    PRIMARY KEY (episode_id, subscription_id, delivery_version)
                 );
                 INSERT INTO webhook_deliveries
                    (episode_id,subscription_id,delivery_version,event_id,state,next_attempt_at)
                 VALUES (5,'sub-a',1,'evt-a','pending','2026-08-20T19:30:00.000Z');",
            )
            .unwrap();
    }

    fn predecessor(connection: &Connection) -> WebhookDeliveryPredecessor {
        connection
            .query_row(
                "SELECT state,attempt_count,next_attempt_at,updated_at
                 FROM webhook_deliveries WHERE event_id='evt-a'",
                [],
                |row| {
                    Ok(WebhookDeliveryPredecessor {
                        state: row.get(0)?,
                        attempt_count: row.get(1)?,
                        next_attempt_at: row.get(2)?,
                        updated_at: row.get(3)?,
                    })
                },
            )
            .unwrap()
    }

    fn settle(
        connection: &mut Connection,
        plan: WebhookDeliverySettlementPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    fn build(
        connection: &Connection,
        state: &str,
        attempt_count: i64,
    ) -> WebhookDeliverySettlementPlan {
        WebhookDeliverySettlementPlan::new(
            ACCOUNT.into(),
            "evt-a".into(),
            5,
            "sub-a".into(),
            1,
            predecessor(connection),
            state.into(),
            attempt_count,
            Some(429),
            Some("throttled".into()),
            Some("2026-08-20T20:05:00.000Z".into()),
            COMMITTED_AT.into(),
        )
        .unwrap()
    }

    #[test]
    fn retry_arm_settles_replays_and_derives_new_operations_per_predecessor() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let plan = build(&connection, "retry", 1);
        let replay = build(&connection, "retry", 1);
        let first_id = plan.operation_id().as_bytes().to_vec();
        assert!(matches!(
            settle(&mut connection, plan).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let (state, attempts, next): (String, i64, Option<String>) = connection
            .query_row(
                "SELECT state,attempt_count,next_attempt_at FROM webhook_deliveries
                 WHERE event_id='evt-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((state.as_str(), attempts), ("retry", 1));
        assert_eq!(next.as_deref(), Some("2026-08-20T20:05:00.000Z"));
        assert!(matches!(
            settle(&mut connection, replay).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
        let second = build(&connection, "failed", 2);
        assert_ne!(second.operation_id().as_bytes().to_vec(), first_id);
        assert!(matches!(
            settle(&mut connection, second).unwrap(),
            LogicalMutationDisposition::Applied
        ));
    }

    #[test]
    fn moved_rows_and_malformed_inputs_fail_closed() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let plan = build(&connection, "retry", 1);
        connection
            .execute(
                "UPDATE webhook_deliveries SET attempt_count=9 WHERE event_id='evt-a'",
                [],
            )
            .unwrap();
        assert!(matches!(
            settle(&mut connection, plan),
            Err(WalIdempotencyError::Precondition)
        ));
        let predecessor = predecessor(&connection);
        assert!(WebhookDeliverySettlementPlan::new(
            ACCOUNT.into(),
            "evt-a".into(),
            5,
            "".into(),
            1,
            predecessor,
            "retry".into(),
            1,
            None,
            None,
            Some("t".into()),
            COMMITTED_AT.into(),
        )
        .is_err());
    }
}
