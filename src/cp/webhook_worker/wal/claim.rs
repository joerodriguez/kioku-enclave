//! Durable, payload-bearing pre-send boundary for at-most-once webhook delivery.
//!
//! A fresh random claim id is persisted before provider I/O together with the
//! complete due-row snapshot and checked next attempt. Only the caller that
//! receives the first canonical `Authorized` result may send. A later caller
//! sees `Busy` and leaves a live lease untouched; it never replays provider
//! I/O. Only an expired lease may be recovered as ambiguous.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};
use crate::cp::isotime;

use super::exact::{
    load_delivery_snapshot, target_snapshot, WebhookDeliverySnapshot, WebhookSettlementKind,
    AMBIGUOUS_ERROR_CODE,
};

const REQUEST_V1: u16 = 1;
const RESULT_V1: u16 = 1;
const RESULT_AUTHORIZED: u8 = 1;
const RESULT_BUSY: u8 = 2;
const RESULT_DEFERRED_LIMIT: u8 = 3;
const RESULT_REQUEST_CAPACITY: u8 = 4;
const SUBTYPE: &[u8] = b"adr-0022-webhook-send-claim-v1";
const MAX_ATTEMPTS: i64 = 10;
const MAX_DEFERRED_CLAIMS_PER_ATTEMPT: i64 = 16;
#[cfg(not(test))]
pub(in crate::cp) const CLAIM_LEASE_MILLIS: i64 = 90_000;
#[cfg(test)]
pub(in crate::cp) const CLAIM_LEASE_MILLIS: i64 = 15_000;
#[cfg(not(test))]
pub(in crate::cp) const MIN_SEND_LEASE_MILLIS: i64 = 30_000;
#[cfg(test)]
pub(in crate::cp) const MIN_SEND_LEASE_MILLIS: i64 = 2_000;
const MAX_TEXT_BYTES: usize = 256;
const MAX_PROVIDER_ID_BYTES: usize = 512;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_SIGNING_SECRET_BYTES: usize = 256;
const MAX_EVENT_BODY_BYTES: usize = 512 * 1024;
const MAX_SUBSCRIPTION_ID_BYTES: usize = 36;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_CANONICAL_RESULT_BYTES: usize = 3;
const SCHEMA_TABLE: &str = "archive_v3_wal_webhook_claim_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_webhook_claim_operations";
const STATE_TABLE: &str = "archive_v3_wal_webhook_claim_state";
const FROZEN_REQUESTS_TABLE: &str = "archive_v3_wal_webhook_frozen_requests";
pub(super) const CLAIMS_TABLE: &str = "archive_v3_wal_webhook_send_claims";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FROZEN_REQUESTS: u32 = 65_536;
const MAX_FROZEN_REQUEST_BYTES: u64 = 1024 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WebhookClaimOutcome {
    Started,
    Accepted,
    Rejected,
    Deferred,
    Ambiguous,
    Cancelled,
    Failed,
}

impl WebhookClaimOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Deferred => "deferred",
            Self::Ambiguous => "ambiguous",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "started" => Ok(Self::Started),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "deferred" => Ok(Self::Deferred),
            "ambiguous" => Ok(Self::Ambiguous),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            _ => Err(WalIdempotencyError::Corrupt),
        }
    }
}

/// Exact request bytes frozen before provider I/O. A retry or crash recovery
/// can never rebuild a different destination, signing key, or body under the
/// same event id.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::cp) struct WebhookFrozenRequest {
    endpoint_url: String,
    signing_secret: String,
    event_body: String,
    subscription_id: String,
    event_id: String,
    include_content: bool,
}

impl std::fmt::Debug for WebhookFrozenRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebhookFrozenRequest(<redacted>)")
    }
}

impl WebhookFrozenRequest {
    pub(in crate::cp) fn new(
        endpoint_url: String,
        signing_secret: String,
        event_body: String,
        subscription_id: String,
        event_id: String,
        include_content: bool,
    ) -> Result<Self> {
        let request = Self {
            endpoint_url,
            signing_secret,
            event_body,
            subscription_id,
            event_id,
            include_content,
        };
        request.validate()?;
        Ok(request)
    }

    pub(in crate::cp) fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }

    pub(in crate::cp) fn signing_secret(&self) -> &str {
        &self.signing_secret
    }

    pub(in crate::cp) fn event_body(&self) -> &[u8] {
        self.event_body.as_bytes()
    }

    pub(in crate::cp) fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    pub(in crate::cp) fn event_id(&self) -> &str {
        &self.event_id
    }

    pub(in crate::cp) const fn include_content(&self) -> bool {
        self.include_content
    }

    fn validate(&self) -> Result<()> {
        if self.endpoint_url.is_empty()
            || self.endpoint_url.len() > MAX_ENDPOINT_BYTES
            || self.signing_secret.is_empty()
            || self.signing_secret.len() > MAX_SIGNING_SECRET_BYTES
            || self.event_body.is_empty()
            || self.event_body.len() > MAX_EVENT_BODY_BYTES
            || self.subscription_id.is_empty()
            || self.subscription_id.len() > MAX_SUBSCRIPTION_ID_BYTES
            || !valid_selected_event_id(&self.event_id)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(())
    }

    fn commitment(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, self.endpoint_url.as_bytes())?;
        hash_field(&mut hasher, self.signing_secret.as_bytes())?;
        hash_field(&mut hasher, self.event_body.as_bytes())?;
        hash_field(&mut hasher, self.subscription_id.as_bytes())?;
        hash_field(&mut hasher, self.event_id.as_bytes())?;
        hasher.update([u8::from(self.include_content)]);
        nonzero_digest(hasher)
    }

    fn encoded_bytes(&self) -> Result<u64> {
        self.validate()?;
        let payload = self
            .endpoint_url
            .len()
            .checked_add(self.signing_secret.len())
            .and_then(|value| value.checked_add(self.event_body.len()))
            .and_then(|value| value.checked_add(self.subscription_id.len()))
            .and_then(|value| value.checked_add(self.event_id.len()))
            .and_then(|value| value.checked_add(21))
            .ok_or(WalIdempotencyError::Limit)?;
        u64::try_from(payload).map_err(|_| WalIdempotencyError::Limit)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) struct WebhookSendClaim {
    claim_id: String,
    predecessor: WebhookDeliverySnapshot,
    request: WebhookFrozenRequest,
    send_attempt: i64,
    started_at: String,
    lease_expires_at: String,
}

impl WebhookSendClaim {
    pub(in crate::cp) fn claim_id(&self) -> &str {
        &self.claim_id
    }

    pub(in crate::cp) fn predecessor(&self) -> &WebhookDeliverySnapshot {
        &self.predecessor
    }

    pub(in crate::cp) fn request(&self) -> &WebhookFrozenRequest {
        &self.request
    }

    pub(in crate::cp) const fn send_attempt(&self) -> i64 {
        self.send_attempt
    }

    pub(in crate::cp) fn started_at(&self) -> &str {
        &self.started_at
    }

    pub(in crate::cp) fn lease_expires_at(&self) -> &str {
        &self.lease_expires_at
    }

    pub(in crate::cp) fn is_live_at(&self, now_millis: i64) -> Result<bool> {
        Ok(timestamp_millis(&self.lease_expires_at)? > now_millis)
    }

    pub(in crate::cp) fn admits_send_at(&self, now_millis: i64) -> Result<bool> {
        Ok(timestamp_millis(&self.lease_expires_at)?
            .checked_sub(now_millis)
            .is_some_and(|remaining| remaining >= MIN_SEND_LEASE_MILLIS))
    }

    pub(super) fn validate_for(&self, predecessor: &WebhookDeliverySnapshot) -> Result<()> {
        predecessor.validate_sendable()?;
        if !self.predecessor.same_stored_contents(predecessor)
            || self.request.event_id != predecessor.event_id
            || self.request.subscription_id != predecessor.subscription_id
            || !valid_uuid(&self.claim_id)
            || self.send_attempt
                != predecessor
                    .attempt_count
                    .checked_add(1)
                    .ok_or(WalIdempotencyError::Limit)?
            || !(1..=MAX_ATTEMPTS).contains(&self.send_attempt)
            || !valid_timestamp(&self.started_at)
            || !valid_timestamp(&self.lease_expires_at)
            || timestamp_millis(&self.started_at)? < timestamp_millis(&predecessor.updated_at)?
            || timestamp_millis(&self.lease_expires_at)?
                != timestamp_millis(&self.started_at)?
                    .checked_add(CLAIM_LEASE_MILLIS)
                    .ok_or(WalIdempotencyError::Limit)?
        {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(())
    }

    pub(super) fn commitment(&self) -> Result<[u8; 32]> {
        self.validate_for(&self.predecessor)?;
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, self.claim_id.as_bytes())?;
        hasher.update(self.predecessor.commitment()?);
        hasher.update(self.request.commitment()?);
        hasher.update(self.send_attempt.to_be_bytes());
        hash_field(&mut hasher, self.started_at.as_bytes())?;
        hash_field(&mut hasher, self.lease_expires_at.as_bytes())?;
        let digest: [u8; 32] = hasher.finalize().into();
        (digest != [0; 32])
            .then_some(digest)
            .ok_or(WalIdempotencyError::Corrupt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WebhookSendClaimDisposition {
    Authorized,
    Busy,
    DeferredLimit,
    RequestCapacity,
}

pub(crate) struct WebhookSendClaimPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    claim: WebhookSendClaim,
}

impl WebhookSendClaimPlan {
    pub(in crate::cp) fn new(
        account_id: String,
        claim_id: String,
        predecessor: WebhookDeliverySnapshot,
        request: WebhookFrozenRequest,
        started_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        let send_attempt = predecessor
            .attempt_count
            .checked_add(1)
            .ok_or(WalIdempotencyError::Limit)?;
        let claim = WebhookSendClaim {
            claim_id,
            predecessor,
            request,
            send_attempt,
            lease_expires_at: add_millis(&started_at, CLAIM_LEASE_MILLIS)?,
            started_at,
        };
        claim.validate_for(&claim.predecessor)?;
        let source = stable_operation_source(
            SUBTYPE,
            &[
                account_id.as_bytes(),
                claim.claim_id.as_bytes(),
                &claim.commitment()?,
            ],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::WebhookDelivery, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            claim,
        })
    }

    #[cfg(test)]
    pub(in crate::cp) fn apply_direct(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<WebhookSendClaimDisposition> {
        ensure_schema(transaction)?;
        decode_disposition(&self.apply(transaction)?)
    }

    fn apply_claim(&self, transaction: &Transaction<'_>) -> Result<WebhookSendClaimDisposition> {
        let current = load_delivery_snapshot(transaction, &self.claim.predecessor.event_id)?
            .ok_or(WalIdempotencyError::Precondition)?;
        if !current.same_stored_contents(&self.claim.predecessor) {
            return Err(WalIdempotencyError::Precondition);
        }
        if load_open_claim(transaction, &self.claim.predecessor.event_id)?.is_some() {
            return Ok(WebhookSendClaimDisposition::Busy);
        }
        if load_frozen_request(transaction, &self.claim.predecessor.event_id)?
            .is_some_and(|request| request != self.claim.request)
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if deferred_claim_count(
            transaction,
            &self.claim.predecessor.event_id,
            self.claim.send_attempt,
        )? >= MAX_DEFERRED_CLAIMS_PER_ATTEMPT
        {
            return Ok(WebhookSendClaimDisposition::DeferredLimit);
        }
        let request_commitment = self.claim.request.commitment()?;
        if !ensure_frozen_request(
            transaction,
            &self.claim.predecessor.event_id,
            &self.claim.request,
        )? {
            return Ok(WebhookSendClaimDisposition::RequestCapacity);
        }
        let predecessor = &self.claim.predecessor;
        let changed = transaction
            .execute(
                "INSERT INTO archive_v3_wal_webhook_send_claims
                 (claim_id,event_id,predecessor_rowid,episode_id,delivery_version,
                  predecessor_include_content,predecessor_state,predecessor_attempt_count,
                  predecessor_next_attempt_at,predecessor_provider_message_id,
                  predecessor_response_status,predecessor_error_code,predecessor_created_at,
                  predecessor_updated_at,request_commitment,send_attempt,started_at,
                  lease_expires_at,outcome,provider_status,provider_message_id,provider_error,settled_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,
                         ?18,'started',NULL,NULL,NULL,NULL)",
                params![
                    self.claim.claim_id,
                    predecessor.event_id,
                    predecessor.rowid,
                    predecessor.episode_id,
                    predecessor.delivery_version,
                    i64::from(predecessor.include_content),
                    predecessor.state,
                    predecessor.attempt_count,
                    predecessor.next_attempt_at,
                    predecessor.provider_message_id,
                    predecessor.response_status,
                    predecessor.error_code,
                    predecessor.created_at,
                    predecessor.updated_at,
                    request_commitment.as_slice(),
                    self.claim.send_attempt,
                    self.claim.started_at,
                    self.claim.lease_expires_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        require_started_claim(transaction, &self.claim)?;
        Ok(WebhookSendClaimDisposition::Authorized)
    }
}

pub(crate) struct WebhookSendClaimLedger;

impl WalLogicalDomainPlan for WebhookSendClaimPlan {
    type Ledger = WebhookSendClaimLedger;
    type Output = WebhookSendClaimDisposition;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::WebhookDelivery
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(128));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_string(&mut request, &self.account_id)?;
        request.extend_from_slice(&self.claim.commitment()?);
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        encode_disposition(self.apply_claim(transaction)?)
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        decode_disposition(result).map(|_| ())
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        decode_disposition(result)
    }
}

impl WalLogicalDomainLedger<WebhookSendClaimPlan> for WebhookSendClaimLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<WebhookSendClaimPlan>,
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
                 FROM archive_v3_wal_webhook_claim_operations WHERE operation_id=?1",
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
        prepared: &PreparedLogicalMutation<WebhookSendClaimPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let state = load_ledger_state(transaction)?;
        let kind = WalOperationKind::WebhookDelivery;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        BOUNDS.admit(state.row_count, state.result_bytes, encoded.len())?;
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_webhook_claim_operations
                 (operation_id,format_version,codec_version,request_fingerprint,
                  result_bytes,result_commitment) VALUES (?1,?2,?3,?4,?5,?6)",
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
                "UPDATE archive_v3_wal_webhook_claim_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(state.row_count),
                    i64::try_from(state.result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredClaim {
    claim: WebhookSendClaim,
    request_commitment: Vec<u8>,
    outcome: WebhookClaimOutcome,
    provider_status: Option<i64>,
    provider_message_id: Option<String>,
    provider_error: Option<String>,
    settled_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) enum WebhookClaimRecovery {
    Started(WebhookSendClaim),
    Accepted {
        claim: WebhookSendClaim,
        status: i64,
        settled_at: String,
    },
    Retry {
        claim: WebhookSendClaim,
        status: Option<i64>,
        code: String,
        retry_at: String,
        settled_at: String,
    },
    Deferred,
    Ambiguous {
        claim: WebhookSendClaim,
        settled_at: String,
    },
    Failed {
        claim: WebhookSendClaim,
        status: Option<i64>,
        code: String,
        settled_at: String,
    },
    Cancelled {
        claim: WebhookSendClaim,
        code: String,
        settled_at: String,
    },
}

impl StoredClaim {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let outcome: String = row.get(23)?;
        Ok(Self {
            claim: WebhookSendClaim {
                claim_id: row.get(0)?,
                predecessor: WebhookDeliverySnapshot {
                    event_id: row.get(1)?,
                    rowid: row.get(2)?,
                    episode_id: row.get(3)?,
                    subscription_id: row.get(17)?,
                    delivery_version: row.get(4)?,
                    include_content: row.get::<_, i64>(5)? != 0,
                    state: row.get(6)?,
                    attempt_count: row.get(7)?,
                    next_attempt_at: row.get(8)?,
                    provider_message_id: row.get(9)?,
                    response_status: row.get(10)?,
                    error_code: row.get(11)?,
                    created_at: row.get(12)?,
                    updated_at: row.get(13)?,
                },
                request: WebhookFrozenRequest {
                    endpoint_url: row.get(14)?,
                    signing_secret: row.get(15)?,
                    event_body: row.get(16)?,
                    subscription_id: row.get(17)?,
                    event_id: row.get(18)?,
                    include_content: row.get::<_, i64>(19)? != 0,
                },
                send_attempt: row.get(20)?,
                started_at: row.get(21)?,
                lease_expires_at: row.get(22)?,
            },
            request_commitment: row.get(28)?,
            outcome: WebhookClaimOutcome::parse(&outcome).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    23,
                    rusqlite::types::Type::Text,
                    "invalid webhook claim outcome".into(),
                )
            })?,
            provider_status: row.get(24)?,
            provider_message_id: row.get(25)?,
            provider_error: row.get(26)?,
            settled_at: row.get(27)?,
        })
    }

    fn validate(&self) -> Result<()> {
        self.claim.validate_for(&self.claim.predecessor)?;
        let expected = self.claim.request.commitment()?;
        if self.request_commitment.as_slice() != expected.as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(())
    }
}

const CLAIM_SELECT: &str =
    "SELECT c.claim_id,c.event_id,c.predecessor_rowid,c.episode_id,c.delivery_version,
            c.predecessor_include_content,c.predecessor_state,c.predecessor_attempt_count,
            c.predecessor_next_attempt_at,c.predecessor_provider_message_id,
            c.predecessor_response_status,c.predecessor_error_code,c.predecessor_created_at,
            c.predecessor_updated_at,f.endpoint_url,f.signing_secret,f.event_body,
            f.subscription_id,f.request_event_id,f.request_content_scope,
            c.send_attempt,c.started_at,c.lease_expires_at,c.outcome,c.provider_status,
            c.provider_message_id,c.provider_error,c.settled_at,c.request_commitment
     FROM archive_v3_wal_webhook_send_claims c
     JOIN archive_v3_wal_webhook_frozen_requests f ON f.event_id=c.event_id";

pub(in crate::cp) fn claim_table_present(connection: &Connection) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [CLAIMS_TABLE],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
}

pub(super) fn purge_sidecar_present(connection: &Connection) -> Result<bool> {
    match schema_state(connection)? {
        LedgerSchemaState::Absent => Ok(false),
        LedgerSchemaState::Present => {
            validate_schema_marker(connection)?;
            Ok(true)
        }
    }
}

pub(super) fn raw_live_claim_exists(connection: &Connection, event_id: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM archive_v3_wal_webhook_send_claims
               WHERE event_id=?1 AND outcome='started'
             )",
            [event_id],
            |row| row.get(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
}

pub(in crate::cp) fn load_open_claim(
    connection: &Connection,
    event_id: &str,
) -> Result<Option<WebhookSendClaim>> {
    if !claim_table_present(connection)? {
        return Ok(None);
    }
    let sql = format!(
        "{CLAIM_SELECT} WHERE c.event_id=?1 AND c.outcome='started'
         ORDER BY c.send_attempt LIMIT 1"
    );
    let stored = connection
        .query_row(&sql, [event_id], StoredClaim::from_row)
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    stored.validate()?;
    if stored.provider_status.is_some()
        || stored.provider_message_id.is_some()
        || stored.provider_error.is_some()
        || stored.settled_at.is_some()
        || stored.outcome != WebhookClaimOutcome::Started
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(Some(stored.claim))
}

/// Return the one request permanently bound to a delivery id. Claims carry a
/// fixed-size commitment to this single row rather than duplicating the body.
pub(in crate::cp) fn load_frozen_request(
    connection: &Connection,
    event_id: &str,
) -> Result<Option<WebhookFrozenRequest>> {
    if !claim_table_present(connection)? {
        return Ok(None);
    }
    let row = connection
        .query_row(
            "SELECT endpoint_url,signing_secret,event_body,subscription_id,
                    request_event_id,request_content_scope,request_commitment,
                    encoded_bytes
             FROM archive_v3_wal_webhook_frozen_requests WHERE event_id=?1",
            [event_id],
            |row| {
                Ok((
                    WebhookFrozenRequest {
                        endpoint_url: row.get(0)?,
                        signing_secret: row.get(1)?,
                        event_body: row.get(2)?,
                        subscription_id: row.get(3)?,
                        event_id: row.get(4)?,
                        include_content: row.get::<_, i64>(5)? != 0,
                    },
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some((request, commitment, encoded_bytes)) = row else {
        return Ok(None);
    };
    request.validate()?;
    if request.event_id != event_id
        || commitment.as_slice() != request.commitment()?.as_slice()
        || u64::try_from(encoded_bytes).map_err(|_| WalIdempotencyError::Corrupt)?
            != request.encoded_bytes()?
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(Some(request))
}

fn ensure_frozen_request(
    transaction: &Transaction<'_>,
    event_id: &str,
    request: &WebhookFrozenRequest,
) -> Result<bool> {
    if let Some(existing) = load_frozen_request(transaction, event_id)? {
        return (existing == *request)
            .then_some(true)
            .ok_or(WalIdempotencyError::Precondition);
    }
    let state = load_ledger_state(transaction)?;
    let encoded_bytes = request.encoded_bytes()?;
    let next_count = state
        .frozen_request_count
        .checked_add(1)
        .ok_or(WalIdempotencyError::Limit)?;
    let next_bytes = state
        .frozen_request_bytes
        .checked_add(encoded_bytes)
        .ok_or(WalIdempotencyError::Limit)?;
    if next_count > MAX_FROZEN_REQUESTS || next_bytes > MAX_FROZEN_REQUEST_BYTES {
        return Ok(false);
    }
    transaction
        .execute(
            "INSERT INTO archive_v3_wal_webhook_frozen_requests
             (event_id,endpoint_url,signing_secret,event_body,subscription_id,
              request_event_id,request_content_scope,request_commitment,encoded_bytes)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                event_id,
                request.endpoint_url,
                request.signing_secret,
                request.event_body,
                request.subscription_id,
                request.event_id,
                i64::from(request.include_content),
                request.commitment()?.as_slice(),
                i64::try_from(encoded_bytes).map_err(|_| WalIdempotencyError::Limit)?,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let changed = transaction
        .execute(
            "UPDATE archive_v3_wal_webhook_claim_state
             SET frozen_request_count=?1,frozen_request_bytes=?2
             WHERE singleton=1 AND frozen_request_count=?3 AND frozen_request_bytes=?4",
            params![
                i64::from(next_count),
                i64::try_from(next_bytes).map_err(|_| WalIdempotencyError::Limit)?,
                i64::from(state.frozen_request_count),
                i64::try_from(state.frozen_request_bytes)
                    .map_err(|_| WalIdempotencyError::Corrupt)?,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(true)
}

fn deferred_claim_count(connection: &Connection, event_id: &str, send_attempt: i64) -> Result<i64> {
    if !claim_table_present(connection)? {
        return Ok(0);
    }
    connection
        .query_row(
            "SELECT COUNT(*) FROM archive_v3_wal_webhook_send_claims
             WHERE event_id=?1 AND send_attempt=?2 AND outcome='deferred'",
            params![event_id, send_attempt],
            |row| row.get(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_claim_by_id(connection: &Connection, claim_id: &str) -> Result<Option<StoredClaim>> {
    if !claim_table_present(connection)? {
        return Ok(None);
    }
    let sql = format!("{CLAIM_SELECT} WHERE c.claim_id=?1");
    let stored = connection
        .query_row(&sql, [claim_id], StoredClaim::from_row)
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if let Some(stored) = stored.as_ref() {
        stored.validate()?;
    }
    Ok(stored)
}

pub(in crate::cp) fn load_claim_recovery(
    connection: &Connection,
    claim_id: &str,
) -> Result<Option<WebhookClaimRecovery>> {
    let Some(stored) = load_claim_by_id(connection, claim_id)? else {
        return Ok(None);
    };
    stored.claim.validate_for(&stored.claim.predecessor)?;
    let settled_at = || {
        stored
            .settled_at
            .clone()
            .ok_or(WalIdempotencyError::Corrupt)
    };
    let code = || {
        stored
            .provider_error
            .clone()
            .ok_or(WalIdempotencyError::Corrupt)
    };
    let current_target = || {
        load_delivery_snapshot(connection, &stored.claim.predecessor.event_id)?
            .ok_or(WalIdempotencyError::Corrupt)
    };
    let require_target = |kind: WebhookSettlementKind| {
        let settled_at = settled_at()?;
        let expected = target_snapshot(
            &stored.claim.predecessor,
            Some(&stored.claim),
            &kind,
            &settled_at,
        )?;
        current_target()?
            .same_stored_contents(&expected)
            .then_some(())
            .ok_or(WalIdempotencyError::Corrupt)
    };
    let recovery = match stored.outcome {
        WebhookClaimOutcome::Started => {
            if stored.provider_status.is_some()
                || stored.provider_message_id.is_some()
                || stored.provider_error.is_some()
                || stored.settled_at.is_some()
            {
                return Err(WalIdempotencyError::Corrupt);
            }
            WebhookClaimRecovery::Started(stored.claim)
        }
        WebhookClaimOutcome::Accepted => {
            let status = stored.provider_status.ok_or(WalIdempotencyError::Corrupt)?;
            if stored.provider_message_id.is_some() || stored.provider_error.is_some() {
                return Err(WalIdempotencyError::Corrupt);
            }
            require_target(WebhookSettlementKind::Accepted { status })?;
            WebhookClaimRecovery::Accepted {
                claim: stored.claim,
                status,
                settled_at: settled_at()?,
            }
        }
        WebhookClaimOutcome::Rejected => {
            if stored.provider_message_id.is_some() {
                return Err(WalIdempotencyError::Corrupt);
            }
            let target = current_target()?;
            let code = code()?;
            let retry_at = target
                .next_attempt_at
                .clone()
                .ok_or(WalIdempotencyError::Corrupt)?;
            require_target(WebhookSettlementKind::Retry {
                status: stored.provider_status,
                code: code.clone(),
                retry_at: retry_at.clone(),
            })?;
            WebhookClaimRecovery::Retry {
                claim: stored.claim,
                status: stored.provider_status,
                code,
                retry_at,
                settled_at: settled_at()?,
            }
        }
        WebhookClaimOutcome::Deferred => {
            let target = current_target()?;
            let code = code()?;
            if stored.provider_status.is_some() || stored.provider_message_id.is_some() {
                return Err(WalIdempotencyError::Corrupt);
            }
            let retry_at = target
                .next_attempt_at
                .clone()
                .ok_or(WalIdempotencyError::Corrupt)?;
            require_target(WebhookSettlementKind::Defer { code, retry_at })?;
            WebhookClaimRecovery::Deferred
        }
        WebhookClaimOutcome::Ambiguous => {
            if stored.provider_status.is_some()
                || stored.provider_message_id.is_some()
                || stored.provider_error.as_deref() != Some(AMBIGUOUS_ERROR_CODE)
            {
                return Err(WalIdempotencyError::Corrupt);
            }
            require_target(WebhookSettlementKind::Ambiguous)?;
            WebhookClaimRecovery::Ambiguous {
                claim: stored.claim,
                settled_at: settled_at()?,
            }
        }
        WebhookClaimOutcome::Cancelled => {
            let code = code()?;
            if stored.provider_status.is_some() || stored.provider_message_id.is_some() {
                return Err(WalIdempotencyError::Corrupt);
            }
            require_target(WebhookSettlementKind::Cancel { code: code.clone() })?;
            WebhookClaimRecovery::Cancelled {
                claim: stored.claim,
                code,
                settled_at: settled_at()?,
            }
        }
        WebhookClaimOutcome::Failed => {
            if stored.provider_message_id.is_some() {
                return Err(WalIdempotencyError::Corrupt);
            }
            let code = code()?;
            require_target(WebhookSettlementKind::Failed {
                status: stored.provider_status,
                code: code.clone(),
            })?;
            WebhookClaimRecovery::Failed {
                claim: stored.claim,
                status: stored.provider_status,
                code,
                settled_at: settled_at()?,
            }
        }
    };
    Ok(Some(recovery))
}

pub(in crate::cp) fn validate_live_send_authority(
    connection: &Connection,
    claim: &WebhookSendClaim,
    now_millis: i64,
) -> Result<()> {
    require_started_claim(connection, claim)?;
    let current = load_delivery_snapshot(connection, &claim.predecessor.event_id)?
        .ok_or(WalIdempotencyError::Precondition)?;
    if !current.same_stored_contents(&claim.predecessor) || !claim.admits_send_at(now_millis)? {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

pub(super) fn require_started_claim(
    connection: &Connection,
    claim: &WebhookSendClaim,
) -> Result<()> {
    let stored =
        load_claim_by_id(connection, &claim.claim_id)?.ok_or(WalIdempotencyError::Precondition)?;
    if stored.claim != *claim
        || stored.outcome != WebhookClaimOutcome::Started
        || stored.provider_status.is_some()
        || stored.provider_message_id.is_some()
        || stored.provider_error.is_some()
        || stored.settled_at.is_some()
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

pub(super) fn settle_claim(
    transaction: &Transaction<'_>,
    claim: &WebhookSendClaim,
    outcome: WebhookClaimOutcome,
    provider_status: Option<i64>,
    provider_message_id: Option<&str>,
    provider_error: Option<&str>,
    settled_at: &str,
) -> Result<()> {
    if outcome == WebhookClaimOutcome::Started
        || !valid_timestamp(settled_at)
        || provider_message_id.is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_PROVIDER_ID_BYTES
                || value
                    .bytes()
                    .any(|byte| byte == 0 || byte.is_ascii_control())
        })
        || !valid_optional_text(provider_error)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    require_started_claim(transaction, claim)?;
    let predecessor = &claim.predecessor;
    let changed = transaction
        .execute(
            "UPDATE archive_v3_wal_webhook_send_claims
             SET outcome=?1,provider_status=?2,provider_message_id=?3,provider_error=?4,settled_at=?5
             WHERE claim_id=?6 AND event_id=?7 AND predecessor_rowid=?8 AND episode_id=?9
               AND delivery_version=?10 AND predecessor_include_content=?11
               AND predecessor_state=?12 AND predecessor_attempt_count=?13
               AND predecessor_next_attempt_at IS ?14
               AND predecessor_provider_message_id IS ?15
               AND predecessor_response_status IS ?16 AND predecessor_error_code IS ?17
               AND predecessor_created_at=?18 AND predecessor_updated_at=?19
               AND request_commitment=?20
               AND send_attempt=?21 AND started_at=?22 AND lease_expires_at=?23
               AND outcome='started'
               AND provider_status IS NULL AND provider_message_id IS NULL
               AND provider_error IS NULL AND settled_at IS NULL",
            params![
                outcome.as_str(),
                provider_status,
                provider_message_id,
                provider_error,
                settled_at,
                claim.claim_id,
                predecessor.event_id,
                predecessor.rowid,
                predecessor.episode_id,
                predecessor.delivery_version,
                i64::from(predecessor.include_content),
                predecessor.state,
                predecessor.attempt_count,
                predecessor.next_attempt_at,
                predecessor.provider_message_id,
                predecessor.response_status,
                predecessor.error_code,
                predecessor.created_at,
                predecessor.updated_at,
                claim.request.commitment()?.as_slice(),
                claim.send_attempt,
                claim.started_at,
                claim.lease_expires_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Precondition);
    }
    require_settled_claim(
        transaction,
        claim,
        outcome,
        provider_status,
        provider_message_id,
        provider_error,
        settled_at,
    )
}

pub(super) fn require_settled_claim(
    connection: &Connection,
    claim: &WebhookSendClaim,
    outcome: WebhookClaimOutcome,
    provider_status: Option<i64>,
    provider_message_id: Option<&str>,
    provider_error: Option<&str>,
    settled_at: &str,
) -> Result<()> {
    let stored =
        load_claim_by_id(connection, &claim.claim_id)?.ok_or(WalIdempotencyError::Precondition)?;
    if stored.claim != *claim
        || stored.outcome != outcome
        || stored.provider_status != provider_status
        || stored.provider_message_id.as_deref() != provider_message_id
        || stored.provider_error.as_deref() != provider_error
        || stored.settled_at.as_deref() != Some(settled_at)
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn encode_disposition(disposition: WebhookSendClaimDisposition) -> Result<WalReplayResult> {
    let tag = match disposition {
        WebhookSendClaimDisposition::Authorized => RESULT_AUTHORIZED,
        WebhookSendClaimDisposition::Busy => RESULT_BUSY,
        WebhookSendClaimDisposition::DeferredLimit => RESULT_DEFERRED_LIMIT,
        WebhookSendClaimDisposition::RequestCapacity => RESULT_REQUEST_CAPACITY,
    };
    let mut bytes = Vec::with_capacity(MAX_CANONICAL_RESULT_BYTES);
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(tag);
    WalReplayResult::canonical_response(WalOperationKind::WebhookDelivery, bytes)
}

fn decode_disposition(result: &WalReplayResult) -> Result<WebhookSendClaimDisposition> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    if bytes.len() != MAX_CANONICAL_RESULT_BYTES
        || u16::from_be_bytes([bytes[0], bytes[1]]) != RESULT_V1
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    match bytes[2] {
        RESULT_AUTHORIZED => Ok(WebhookSendClaimDisposition::Authorized),
        RESULT_BUSY => Ok(WebhookSendClaimDisposition::Busy),
        RESULT_DEFERRED_LIMIT => Ok(WebhookSendClaimDisposition::DeferredLimit),
        RESULT_REQUEST_CAPACITY => Ok(WebhookSendClaimDisposition::RequestCapacity),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn require_kind(prepared: &PreparedLogicalMutation<WebhookSendClaimPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::WebhookDelivery)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3,?4,?5)",
            params![
                SCHEMA_TABLE,
                LEDGER_TABLE,
                STATE_TABLE,
                FROZEN_REQUESTS_TABLE,
                CLAIMS_TABLE
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(LedgerSchemaState::Absent),
        5 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_webhook_claim_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_webhook_claim_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes) BETWEEN 1 AND 32),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_webhook_claim_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432),
                        frozen_request_count INTEGER NOT NULL
                          CHECK(frozen_request_count BETWEEN 0 AND 65536),
                        frozen_request_bytes INTEGER NOT NULL
                          CHECK(frozen_request_bytes BETWEEN 0 AND 1073741824)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_webhook_frozen_requests (
                        event_id TEXT PRIMARY KEY NOT NULL
                          REFERENCES webhook_deliveries(event_id) ON DELETE CASCADE,
                        endpoint_url TEXT NOT NULL,
                        signing_secret TEXT NOT NULL,
                        event_body TEXT NOT NULL,
                        subscription_id TEXT NOT NULL,
                        request_event_id TEXT NOT NULL,
                        request_content_scope INTEGER NOT NULL CHECK(request_content_scope IN (0,1)),
                        request_commitment BLOB NOT NULL
                          CHECK(length(request_commitment)=32 AND request_commitment<>zeroblob(32)),
                        encoded_bytes INTEGER NOT NULL CHECK(encoded_bytes BETWEEN 1 AND 1073741824)
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_webhook_send_claims (
                        claim_id TEXT PRIMARY KEY NOT NULL,
                        event_id TEXT NOT NULL REFERENCES webhook_deliveries(event_id) ON DELETE CASCADE,
                        predecessor_rowid INTEGER NOT NULL,
                        episode_id INTEGER NOT NULL,
                        delivery_version INTEGER NOT NULL,
                        predecessor_include_content INTEGER NOT NULL CHECK(predecessor_include_content IN (0,1)),
                        predecessor_state TEXT NOT NULL CHECK(predecessor_state IN ('pending','retry')),
                        predecessor_attempt_count INTEGER NOT NULL CHECK(predecessor_attempt_count BETWEEN 0 AND 9),
                        predecessor_next_attempt_at TEXT,
                        predecessor_provider_message_id TEXT,
                        predecessor_response_status INTEGER,
                        predecessor_error_code TEXT,
                        predecessor_created_at TEXT NOT NULL,
                        predecessor_updated_at TEXT NOT NULL,
                        request_commitment BLOB NOT NULL
                          CHECK(length(request_commitment)=32 AND request_commitment<>zeroblob(32)),
                        send_attempt INTEGER NOT NULL CHECK(send_attempt BETWEEN 1 AND 10),
                        started_at TEXT NOT NULL,
                        lease_expires_at TEXT NOT NULL,
                        outcome TEXT NOT NULL CHECK(outcome IN ('started','accepted','rejected','deferred','ambiguous','cancelled','failed')),
                        provider_status INTEGER,
                        provider_message_id TEXT,
                        provider_error TEXT,
                        settled_at TEXT
                     ) STRICT;
                     CREATE UNIQUE INDEX archive_v3_wal_webhook_one_live_claim
                     ON archive_v3_wal_webhook_send_claims(event_id) WHERE outcome='started';
                     CREATE TRIGGER archive_v3_wal_webhook_live_claim_delete_guard
                     BEFORE DELETE ON webhook_deliveries
                     WHEN EXISTS(
                       SELECT 1 FROM archive_v3_wal_webhook_send_claims
                       WHERE event_id=OLD.event_id AND outcome='started'
                     )
                     BEGIN
                       SELECT RAISE(ABORT,'webhook delivery has a live send claim');
                     END;
                     CREATE TRIGGER archive_v3_wal_webhook_frozen_request_delete_accounting
                     AFTER DELETE ON archive_v3_wal_webhook_frozen_requests
                     BEGIN
                       UPDATE archive_v3_wal_webhook_claim_state
                       SET frozen_request_count=frozen_request_count-1,
                           frozen_request_bytes=frozen_request_bytes-OLD.encoded_bytes
                       WHERE singleton=1 AND frozen_request_count>0
                         AND frozen_request_bytes>=OLD.encoded_bytes;
                       SELECT CASE WHEN changes()<>1
                         THEN RAISE(ABORT,'webhook frozen request accounting corrupt') END;
                     END;
                     INSERT INTO archive_v3_wal_webhook_claim_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_webhook_claim_state
                        (singleton,row_count,result_bytes,frozen_request_count,frozen_request_bytes)
                        VALUES (1,0,0,0,0);",
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
             FROM archive_v3_wal_webhook_claim_schema WHERE singleton=1",
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
    let guards: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE \
             (type='index' AND name='archive_v3_wal_webhook_one_live_claim' \
               AND sql LIKE '%WHERE outcome=''started''%') OR \
             (type='trigger' AND name='archive_v3_wal_webhook_live_claim_delete_guard' \
               AND sql LIKE '%BEFORE DELETE ON webhook_deliveries%' \
               AND sql LIKE '%outcome=''started''%') OR \
             (type='trigger' AND name='archive_v3_wal_webhook_frozen_request_delete_accounting' \
               AND sql LIKE '%AFTER DELETE ON archive_v3_wal_webhook_frozen_requests%' \
               AND sql LIKE '%frozen_request_bytes=frozen_request_bytes-OLD.encoded_bytes%')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if guards != 3 {
        return Err(WalIdempotencyError::Corrupt);
    }
    let _ = load_ledger_state(connection)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LedgerState {
    row_count: u32,
    result_bytes: u64,
    frozen_request_count: u32,
    frozen_request_bytes: u64,
}

fn load_ledger_state(connection: &Connection) -> Result<LedgerState> {
    let state = connection
        .query_row(
            "SELECT row_count,result_bytes,frozen_request_count,frozen_request_bytes
             FROM archive_v3_wal_webhook_claim_state WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let state = LedgerState {
        row_count: u32::try_from(state.0).map_err(|_| WalIdempotencyError::Corrupt)?,
        result_bytes: u64::try_from(state.1).map_err(|_| WalIdempotencyError::Corrupt)?,
        frozen_request_count: u32::try_from(state.2).map_err(|_| WalIdempotencyError::Corrupt)?,
        frozen_request_bytes: u64::try_from(state.3).map_err(|_| WalIdempotencyError::Corrupt)?,
    };
    if state.row_count > MAX_ROWS
        || state.result_bytes > MAX_RESULT_BYTES
        || state.frozen_request_count > MAX_FROZEN_REQUESTS
        || state.frozen_request_bytes > MAX_FROZEN_REQUEST_BYTES
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(state)
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn valid_selected_event_id(value: &str) -> bool {
    value
        .strip_prefix(super::super::SELECTED_WEBHOOK_EVENT_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 64
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn valid_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TIMESTAMP_BYTES
        && isotime::parse_epoch_millis(value)
            .is_some_and(|millis| isotime::format_epoch_millis(millis) == value)
}

fn timestamp_millis(value: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value).ok_or(WalIdempotencyError::Malformed)
}

fn add_millis(timestamp: &str, millis: i64) -> Result<String> {
    let value = timestamp_millis(timestamp)?
        .checked_add(millis)
        .ok_or(WalIdempotencyError::Limit)?;
    Ok(isotime::format_epoch_millis(value))
}

fn valid_optional_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= MAX_TEXT_BYTES
            && !value
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
    })
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

fn nonzero_digest(hasher: Sha256) -> Result<[u8; 32]> {
    let digest: [u8; 32] = hasher.finalize().into();
    (digest != [0; 32])
        .then_some(digest)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const EVENT: &str = "w1_2222222222222222222222222222222222222222222222222222222222222222";
    const SUBSCRIPTION: &str = "33333333-3333-4333-8333-333333333333";
    const CLAIM_A: &str = "44444444-4444-4444-8444-444444444444";
    const CLAIM_B: &str = "55555555-5555-4555-8555-555555555555";
    const STARTED: &str = "2026-08-20T20:00:00.000Z";

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(&format!(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE webhook_deliveries (
                    episode_id INTEGER NOT NULL,subscription_id TEXT NOT NULL,
                    delivery_version INTEGER NOT NULL,event_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,attempt_count INTEGER NOT NULL,
                    next_attempt_at TEXT,response_status INTEGER,error_code TEXT,
                    created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
                    PRIMARY KEY(episode_id,subscription_id,delivery_version));
                 INSERT INTO webhook_deliveries VALUES (
                    5,'{SUBSCRIPTION}',1,'{EVENT}','pending',0,NULL,NULL,NULL,
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z');"
            ))
            .unwrap();
        connection
    }

    fn snapshot(connection: &Connection) -> WebhookDeliverySnapshot {
        load_delivery_snapshot(connection, EVENT).unwrap().unwrap()
    }

    fn request(endpoint: &str, body: &str) -> WebhookFrozenRequest {
        WebhookFrozenRequest::new(
            endpoint.into(),
            "whsec_test-secret".into(),
            body.into(),
            SUBSCRIPTION.into(),
            EVENT.into(),
            true,
        )
        .unwrap()
    }

    #[test]
    fn first_claim_freezes_exact_destination_and_body_and_competing_claim_is_busy() {
        let mut connection = connection();
        let predecessor = snapshot(&connection);
        let first = WebhookSendClaimPlan::new(
            ACCOUNT.into(),
            CLAIM_A.into(),
            predecessor.clone(),
            request("https://hooks.example.com/first", "{\"version\":1}"),
            STARTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            first.apply_direct(&transaction).unwrap(),
            WebhookSendClaimDisposition::Authorized
        );
        transaction.commit().unwrap();
        assert_eq!(
            load_frozen_request(&connection, EVENT).unwrap(),
            Some(request(
                "https://hooks.example.com/first",
                "{\"version\":1}"
            ))
        );

        let second = WebhookSendClaimPlan::new(
            ACCOUNT.into(),
            CLAIM_B.into(),
            predecessor,
            request("https://hooks.example.com/first", "{\"version\":1}"),
            "2026-08-20T20:00:01.000Z".into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            second.apply_direct(&transaction).unwrap(),
            WebhookSendClaimDisposition::Busy
        );
    }

    #[test]
    fn a_deferred_claim_cannot_change_endpoint_or_regenerated_body() {
        let mut connection = connection();
        let predecessor = snapshot(&connection);
        let first = WebhookSendClaimPlan::new(
            ACCOUNT.into(),
            CLAIM_A.into(),
            predecessor.clone(),
            request("https://hooks.example.com/first", "{\"version\":1}"),
            STARTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            first.apply_direct(&transaction).unwrap(),
            WebhookSendClaimDisposition::Authorized
        );
        let claim = load_open_claim(&transaction, EVENT).unwrap().unwrap();
        settle_claim(
            &transaction,
            &claim,
            WebhookClaimOutcome::Deferred,
            None,
            None,
            Some("control_unavailable"),
            "2026-08-20T20:00:01.000Z",
        )
        .unwrap();
        transaction.commit().unwrap();

        for changed in [
            request("https://other.example.com/hook", "{\"version\":1}"),
            request("https://hooks.example.com/first", "{\"version\":2}"),
        ] {
            let plan = WebhookSendClaimPlan::new(
                ACCOUNT.into(),
                CLAIM_B.into(),
                predecessor.clone(),
                changed,
                "2026-08-20T20:00:02.000Z".into(),
            )
            .unwrap();
            let transaction = connection.transaction().unwrap();
            assert_eq!(
                plan.apply_direct(&transaction),
                Err(WalIdempotencyError::Precondition)
            );
        }
    }
}
