//! Webhook subscription cascade as a sealed WAL plan (ADR-0022 F15).
//!
//! The archive half of `DELETE /webhooks/{id}`: cancel the enumerated
//! pending/retry deliveries of exactly that subscription (R6 applied to the
//! live unbounded predicate; the inline `strftime('now')` is hoisted). The
//! authoritative subscription delete is Control-only and precedes this. If
//! this half never lands, `deliver_user_webhooks` cancels the orphans as
//! `subscription_inactive` — a benign convergence net, deliberately kept.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-webhook-subscription-cascade-v1";
const MAX_BATCH: usize = 256;
const MAX_ID_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_webhook_cascade_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_webhook_cascade_operations";
const STATE_TABLE: &str = "archive_v3_wal_webhook_cascade_state";
const MAX_ROWS: u32 = 65_536;
const MAX_RESULT_BYTES: u64 = 65_536 * 9;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// One enumerated pending/retry delivery to cancel.
#[derive(Clone)]
pub(in crate::cp) struct CascadeDelivery {
    event_id: String,
    episode_id: i64,
    delivery_version: i64,
    state: String,
}

impl CascadeDelivery {
    pub(in crate::cp) fn new(
        event_id: String,
        episode_id: i64,
        delivery_version: i64,
        state: String,
    ) -> Result<Self> {
        if event_id.is_empty()
            || event_id.len() > MAX_ID_BYTES
            || episode_id <= 0
            || delivery_version < 0
            || (state != "pending" && state != "retry")
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(Self {
            event_id,
            episode_id,
            delivery_version,
            state,
        })
    }
}

pub(crate) struct WebhookSubscriptionCascadePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    subscription_id: String,
    deliveries: Vec<CascadeDelivery>,
    committed_at: String,
}

impl WebhookSubscriptionCascadePlan {
    pub(in crate::cp) fn new(
        account_id: String,
        subscription_id: String,
        deliveries: Vec<CascadeDelivery>,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if subscription_id.is_empty()
            || subscription_id.len() > MAX_ID_BYTES
            || deliveries.is_empty()
            || deliveries.len() > MAX_BATCH
            || committed_at.is_empty()
            || committed_at.len() > MAX_TIMESTAMP_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        if !deliveries
            .windows(2)
            .all(|pair| pair[0].event_id < pair[1].event_id)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let mut payload = Sha256::new();
        hash_field(&mut payload, subscription_id.as_bytes())?;
        for delivery in &deliveries {
            hash_field(&mut payload, delivery.event_id.as_bytes())?;
            hash_field(&mut payload, &delivery.episode_id.to_be_bytes())?;
            hash_field(&mut payload, &delivery.delivery_version.to_be_bytes())?;
            hash_field(&mut payload, delivery.state.as_bytes())?;
        }
        let payload: [u8; 32] = payload.finalize().into();
        let source = stable_operation_source(SUBTYPE, &[account_id.as_bytes(), &payload])?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::WebhookDelivery, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            subscription_id,
            deliveries,
            committed_at,
        })
    }
}

pub(crate) struct WebhookSubscriptionCascadeLedger;

impl WalLogicalDomainPlan for WebhookSubscriptionCascadePlan {
    type Ledger = WebhookSubscriptionCascadeLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::WebhookDelivery
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(4 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_bytes(&mut request, SUBTYPE)?;
        encode_string(&mut request, &self.account_id)?;
        encode_string(&mut request, &self.subscription_id)?;
        encode_len(&mut request, self.deliveries.len())?;
        for delivery in &self.deliveries {
            encode_string(&mut request, &delivery.event_id)?;
            request.extend_from_slice(&delivery.episode_id.to_be_bytes());
            request.extend_from_slice(&delivery.delivery_version.to_be_bytes());
            encode_string(&mut request, &delivery.state)?;
        }
        encode_string(&mut request, &self.committed_at)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        for delivery in &self.deliveries {
            let changed = transaction
                .execute(
                    "UPDATE webhook_deliveries
                     SET state='cancelled',error_code='subscription_deleted',updated_at=?1
                     WHERE event_id=?2 AND episode_id=?3 AND subscription_id=?4
                       AND delivery_version=?5 AND state=?6",
                    params![
                        self.committed_at,
                        delivery.event_id,
                        delivery.episode_id,
                        self.subscription_id,
                        delivery.delivery_version,
                        delivery.state,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                // Terminal adopt: already cancelled counts as converged.
                let adopted: i64 = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM webhook_deliveries
                         WHERE event_id=?1 AND state='cancelled'",
                        [&delivery.event_id],
                        |row| row.get(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if adopted != 1 {
                    return Err(WalIdempotencyError::Precondition);
                }
            }
        }
        // The exact-bound assertion (R6): nothing outside the enumerated set
        // may still be pending/retry — otherwise the scan was stale and the
        // caller must re-enumerate rather than silently under-cancel.
        let residue: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM webhook_deliveries
                 WHERE subscription_id=?1 AND state IN ('pending','retry')",
                [&self.subscription_id],
                |row| row.get(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if residue != 0 {
            return Err(WalIdempotencyError::Precondition);
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

impl WalLogicalDomainLedger<WebhookSubscriptionCascadePlan> for WebhookSubscriptionCascadeLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<WebhookSubscriptionCascadePlan>,
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
                 FROM archive_v3_wal_webhook_cascade_operations
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
        prepared: &PreparedLogicalMutation<WebhookSubscriptionCascadePlan>,
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
                "INSERT INTO archive_v3_wal_webhook_cascade_operations
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
                "UPDATE archive_v3_wal_webhook_cascade_state
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

fn require_kind(prepared: &PreparedLogicalMutation<WebhookSubscriptionCascadePlan>) -> Result<()> {
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
                    "CREATE TABLE archive_v3_wal_webhook_cascade_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_webhook_cascade_operations (
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
                     CREATE TABLE archive_v3_wal_webhook_cascade_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 65536),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 589824)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_webhook_cascade_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_webhook_cascade_state
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
             FROM archive_v3_wal_webhook_cascade_schema WHERE singleton=1",
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
             FROM archive_v3_wal_webhook_cascade_state WHERE singleton=1",
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
    const COMMITTED_AT: &str = "2026-08-20T19:30:00.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE webhook_deliveries (
                    episode_id INTEGER NOT NULL,
                    subscription_id TEXT NOT NULL,
                    delivery_version INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    error_code TEXT,
                    updated_at TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (episode_id, subscription_id, delivery_version)
                 );
                 INSERT INTO webhook_deliveries VALUES
                    (1,'sub-a',1,'dlv-a','pending',NULL,''),
                    (2,'sub-a',1,'dlv-b','retry',NULL,''),
                    (3,'sub-b',1,'dlv-c','pending',NULL,'');",
            )
            .unwrap();
    }

    fn enumerate(connection: &Connection) -> Vec<CascadeDelivery> {
        let mut statement = connection
            .prepare(
                "SELECT event_id,episode_id,delivery_version,state
                 FROM webhook_deliveries
                 WHERE subscription_id='sub-a' AND state IN ('pending','retry')
                 ORDER BY event_id",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .unwrap()
            .map(|row| {
                let (id, episode, version, state) = row.unwrap();
                CascadeDelivery::new(id, episode, version, state).unwrap()
            })
            .collect()
    }

    fn settle(
        connection: &mut Connection,
        plan: WebhookSubscriptionCascadePlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|outcome| outcome.disposition())
    }

    #[test]
    fn cancellation_settles_the_exact_enumerated_set_and_replays() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let set = enumerate(&connection);
        assert_eq!(set.len(), 2);
        let build = |set: Vec<CascadeDelivery>| {
            WebhookSubscriptionCascadePlan::new(
                ACCOUNT.into(),
                "sub-a".into(),
                set,
                COMMITTED_AT.into(),
            )
            .unwrap()
        };
        assert!(matches!(
            settle(&mut connection, build(set.clone())).unwrap(),
            LogicalMutationDisposition::Applied
        ));
        let cancelled: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM webhook_deliveries WHERE state='cancelled'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cancelled, 2);
        let other: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM webhook_deliveries
                 WHERE subscription_id='sub-b' AND state='pending'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(other, 1, "another subscription's rows are untouched");
        assert!(matches!(
            settle(&mut connection, build(set)).unwrap(),
            LogicalMutationDisposition::Replayed
        ));
    }

    #[test]
    fn a_stale_enumeration_fails_closed_instead_of_under_cancelling() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let set = enumerate(&connection);
        // A new pending delivery lands between scan and settle: the exact
        // bound is violated and the plan refuses rather than leaving an
        // uncancelled orphan behind a "complete" cancellation.
        connection
            .execute(
                "INSERT INTO webhook_deliveries VALUES (9,'sub-a',1,'dlv-z','pending',NULL,'')",
                [],
            )
            .unwrap();
        let plan = WebhookSubscriptionCascadePlan::new(
            ACCOUNT.into(),
            "sub-a".into(),
            set,
            COMMITTED_AT.into(),
        )
        .unwrap();
        assert!(matches!(
            settle(&mut connection, plan),
            Err(WalIdempotencyError::Precondition)
        ));
    }

    #[test]
    fn malformed_sets_are_rejected() {
        assert!(WebhookSubscriptionCascadePlan::new(
            ACCOUNT.into(),
            "sub".into(),
            vec![],
            COMMITTED_AT.into(),
        )
        .is_err());
        let a = CascadeDelivery::new("a".into(), 1, 1, "pending".into()).unwrap();
        let b = CascadeDelivery::new("b".into(), 2, 1, "retry".into()).unwrap();
        assert!(WebhookSubscriptionCascadePlan::new(
            ACCOUNT.into(),
            "sub".into(),
            vec![b, a],
            COMMITTED_AT.into(),
        )
        .is_err());
        assert!(CascadeDelivery::new("a".into(), 1, 1, "accepted".into()).is_err());
    }
}
