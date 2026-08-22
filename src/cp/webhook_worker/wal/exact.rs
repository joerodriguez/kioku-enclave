//! Exact webhook-delivery settlement after a durable, payload-bearing send claim.
//!
//! The provider owner carries one complete due-row snapshot across the send.
//! It never substitutes a post-I/O reread, and every stored column participates
//! in adoption and CAS. Provider outcomes require the exact durable claim;
//! provider-free cancellation is allowed only when no live claim exists.

use rusqlite::{params, types::ValueRef, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};
use crate::cp::isotime;

use super::claim::{self, WebhookClaimOutcome, WebhookSendClaim};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-webhook-delivery-exact-settlement-v1";
const PURGE_SUBTYPE: &[u8] = b"adr-0022-webhook-delivery-exact-purge-v1";
const MAX_EVENT_ID_BYTES: usize = 68;
const MAX_SUBSCRIPTION_ID_BYTES: usize = 36;
const MAX_TEXT_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
pub(super) const MAX_ATTEMPTS: i64 = 10;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_webhook_exact_settlement_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_webhook_exact_settlement_operations";
const STATE_TABLE: &str = "archive_v3_wal_webhook_exact_settlement_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

pub(in crate::cp) const AMBIGUOUS_ERROR_CODE: &str = "provider_outcome_ambiguous_v1";

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) struct WebhookDeliverySnapshot {
    pub(in crate::cp) rowid: i64,
    pub(in crate::cp) episode_id: i64,
    pub(in crate::cp) subscription_id: String,
    pub(in crate::cp) delivery_version: i64,
    pub(in crate::cp) event_id: String,
    // Webhook rows do not carry content preference or a provider message id;
    // these constant aliases keep the shared complete-evidence framing small
    // while the claim ledger uses the event id as its sole durable identity.
    pub(super) include_content: bool,
    pub(super) provider_message_id: Option<String>,
    pub(in crate::cp) state: String,
    pub(in crate::cp) attempt_count: i64,
    pub(in crate::cp) next_attempt_at: Option<String>,
    pub(in crate::cp) response_status: Option<i64>,
    pub(in crate::cp) error_code: Option<String>,
    pub(in crate::cp) created_at: String,
    pub(in crate::cp) updated_at: String,
}

impl WebhookDeliverySnapshot {
    pub(in crate::cp) fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let event_id: String = row.get(4)?;
        Ok(Self {
            rowid: row.get(0)?,
            episode_id: row.get(1)?,
            subscription_id: row.get(2)?,
            delivery_version: row.get(3)?,
            event_id: event_id.clone(),
            include_content: false,
            provider_message_id: None,
            state: row.get(5)?,
            attempt_count: row.get(6)?,
            next_attempt_at: row.get(7)?,
            response_status: row.get(8)?,
            error_code: row.get(9)?,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
        })
    }

    fn validate_exact_evidence(&self) -> Result<()> {
        if self.rowid <= 0 || self.state.is_empty() {
            return Err(WalIdempotencyError::Malformed);
        }
        Ok(())
    }

    pub(super) fn validate_stored_predecessor(&self) -> Result<()> {
        self.validate_exact_evidence()?;
        matches!(self.state.as_str(), "pending" | "retry")
            .then_some(())
            .ok_or(WalIdempotencyError::Malformed)
    }

    pub(in crate::cp) fn send_admission_refusal(&self) -> Result<Option<&'static str>> {
        self.validate_stored_predecessor()?;
        if self.event_id.is_empty()
            || self.event_id.len() > MAX_EVENT_ID_BYTES
            || self.subscription_id.is_empty()
            || self.subscription_id.len() > MAX_SUBSCRIPTION_ID_BYTES
            || self.state.len() > MAX_TEXT_BYTES
            || self
                .next_attempt_at
                .as_deref()
                .is_some_and(|value| value.len() > MAX_TIMESTAMP_BYTES)
            || self.created_at.len() > MAX_TIMESTAMP_BYTES
            || self.updated_at.len() > MAX_TIMESTAMP_BYTES
            || self
                .error_code
                .as_deref()
                .is_some_and(|value| !valid_text(value, MAX_TEXT_BYTES))
        {
            return Ok(Some("delivery_malformed"));
        }
        if !valid_selected_event_id(&self.event_id) {
            return Ok(Some("activation_ineligible"));
        }
        if self.episode_id <= 0 || self.delivery_version <= 0 {
            return Ok(Some("delivery_malformed"));
        }
        if self.attempt_count < 0 {
            return Ok(Some("attempt_count_invalid"));
        }
        if self.attempt_count >= MAX_ATTEMPTS {
            return Ok(Some("attempt_cap"));
        }
        if self
            .next_attempt_at
            .as_deref()
            .is_some_and(|value| !valid_timestamp(value))
            || !valid_timestamp(&self.created_at)
            || !valid_timestamp(&self.updated_at)
            || self
                .response_status
                .is_some_and(|status| !(100..=599).contains(&status))
            || !valid_optional_text(self.error_code.as_deref(), MAX_TEXT_BYTES)
        {
            return Ok(Some("delivery_malformed"));
        }
        Ok(None)
    }

    pub(super) fn validate_sendable(&self) -> Result<()> {
        self.send_admission_refusal()?
            .is_none()
            .then_some(())
            .ok_or(WalIdempotencyError::Malformed)
    }

    pub(super) fn commitment(&self) -> Result<[u8; 32]> {
        self.validate_stored_predecessor()?;
        let mut hasher = Sha256::new();
        hash_i64(&mut hasher, self.episode_id);
        hash_field(&mut hasher, self.subscription_id.as_bytes())?;
        hash_i64(&mut hasher, self.delivery_version);
        hash_field(&mut hasher, self.event_id.as_bytes())?;
        hash_field(&mut hasher, self.state.as_bytes())?;
        hash_i64(&mut hasher, self.attempt_count);
        hash_optional_text(
            &mut hasher,
            self.next_attempt_at.as_deref(),
            MAX_TIMESTAMP_BYTES,
        )?;
        hash_optional_i64(&mut hasher, self.response_status);
        hash_optional_text(&mut hasher, self.error_code.as_deref(), MAX_TEXT_BYTES)?;
        hash_field(&mut hasher, self.created_at.as_bytes())?;
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        nonzero_digest(hasher)
    }

    pub(super) fn same_stored_contents(&self, other: &Self) -> bool {
        self.episode_id == other.episode_id
            && self.subscription_id == other.subscription_id
            && self.delivery_version == other.delivery_version
            && self.event_id == other.event_id
            && self.state == other.state
            && self.attempt_count == other.attempt_count
            && self.next_attempt_at == other.next_attempt_at
            && self.response_status == other.response_status
            && self.error_code == other.error_code
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
    }

    fn validate_purge_predecessor(&self) -> Result<()> {
        self.validate_exact_evidence()?;
        matches!(self.state.as_str(), "sent" | "failed" | "cancelled")
            .then_some(())
            .ok_or(WalIdempotencyError::Precondition)
    }

    fn raw_commitment(&self) -> Result<[u8; 32]> {
        self.validate_exact_evidence()?;
        let mut hasher = Sha256::new();
        hash_i64(&mut hasher, self.episode_id);
        hash_field(&mut hasher, self.subscription_id.as_bytes())?;
        hash_i64(&mut hasher, self.delivery_version);
        hash_field(&mut hasher, self.event_id.as_bytes())?;
        hash_field(&mut hasher, self.state.as_bytes())?;
        hash_i64(&mut hasher, self.attempt_count);
        hash_optional_raw_text(&mut hasher, self.next_attempt_at.as_deref())?;
        hash_optional_i64(&mut hasher, self.response_status);
        hash_optional_raw_text(&mut hasher, self.error_code.as_deref())?;
        hash_field(&mut hasher, self.created_at.as_bytes())?;
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        nonzero_digest(hasher)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) struct WebhookDeliveryPurgeEvidence {
    predecessor: WebhookDeliverySnapshot,
    subtree_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) enum WebhookSubscriptionPurgeCandidate {
    Active(WebhookDeliverySnapshot),
    Terminal(WebhookDeliveryPurgeEvidence),
}

pub(in crate::cp) fn load_subscription_purge_candidate(
    connection: &Connection,
    subscription_id: &str,
) -> Result<Option<WebhookSubscriptionPurgeCandidate>> {
    let predecessor = connection
        .query_row(
            "SELECT rowid,episode_id,subscription_id,delivery_version,event_id,state,
                    attempt_count,next_attempt_at,response_status,error_code,created_at,updated_at
             FROM webhook_deliveries WHERE subscription_id=?1
             ORDER BY created_at,event_id LIMIT 1",
            [subscription_id],
            WebhookDeliverySnapshot::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(predecessor) = predecessor else {
        return Ok(None);
    };
    if matches!(predecessor.state.as_str(), "pending" | "retry") {
        predecessor.validate_stored_predecessor()?;
        return Ok(Some(WebhookSubscriptionPurgeCandidate::Active(predecessor)));
    }
    predecessor.validate_purge_predecessor()?;
    let subtree_commitment = webhook_subtree_commitment(connection, &predecessor.event_id)?;
    Ok(Some(WebhookSubscriptionPurgeCandidate::Terminal(
        WebhookDeliveryPurgeEvidence {
            predecessor,
            subtree_commitment,
        },
    )))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) enum WebhookSettlementKind {
    Cancel {
        code: String,
    },
    Accepted {
        status: i64,
    },
    Retry {
        status: Option<i64>,
        code: String,
        retry_at: String,
    },
    Defer {
        code: String,
        retry_at: String,
    },
    Failed {
        status: Option<i64>,
        code: String,
    },
    Ambiguous,
}

impl WebhookSettlementKind {
    fn tag(&self) -> u8 {
        match self {
            Self::Cancel { .. } => 1,
            Self::Accepted { .. } => 2,
            Self::Retry { .. } => 3,
            Self::Defer { .. } => 4,
            Self::Failed { .. } => 5,
            Self::Ambiguous => 6,
        }
    }
}

pub(crate) struct ExactWebhookDeliverySettlementPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    predecessor: WebhookDeliverySnapshot,
    claim: Option<WebhookSendClaim>,
    kind: WebhookSettlementKind,
    target: WebhookDeliverySnapshot,
    committed_at: String,
}

impl ExactWebhookDeliverySettlementPlan {
    pub(in crate::cp) fn new(
        account_id: String,
        predecessor: WebhookDeliverySnapshot,
        claim: Option<WebhookSendClaim>,
        kind: WebhookSettlementKind,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        predecessor.validate_stored_predecessor()?;
        validate_timestamp(&committed_at)?;
        match (&claim, &kind) {
            (None, WebhookSettlementKind::Cancel { code }) => {
                validate_text(code, MAX_TEXT_BYTES)?;
                if valid_timestamp(&predecessor.updated_at)
                    && timestamp_millis(&committed_at)? < timestamp_millis(&predecessor.updated_at)?
                {
                    return Err(WalIdempotencyError::Malformed);
                }
            }
            (None, _) => return Err(WalIdempotencyError::Malformed),
            (Some(claim), kind) => {
                predecessor.validate_sendable()?;
                claim.validate_for(&predecessor)?;
                if timestamp_millis(&committed_at)? < timestamp_millis(claim.started_at())? {
                    return Err(WalIdempotencyError::Malformed);
                }
                match kind {
                    WebhookSettlementKind::Cancel { code }
                    | WebhookSettlementKind::Failed { code, .. } => {
                        validate_text(code, MAX_TEXT_BYTES)?
                    }
                    WebhookSettlementKind::Accepted { status } => {
                        if !(200..=299).contains(status) {
                            return Err(WalIdempotencyError::Malformed);
                        }
                    }
                    WebhookSettlementKind::Retry {
                        status,
                        code,
                        retry_at,
                    } => {
                        if claim.send_attempt() >= MAX_ATTEMPTS {
                            return Err(WalIdempotencyError::Limit);
                        }
                        validate_status(*status)?;
                        validate_text(code, MAX_TEXT_BYTES)?;
                        validate_timestamp(retry_at)?;
                        if timestamp_millis(retry_at)? < timestamp_millis(&committed_at)? {
                            return Err(WalIdempotencyError::Malformed);
                        }
                    }
                    WebhookSettlementKind::Defer { code, retry_at } => {
                        validate_text(code, MAX_TEXT_BYTES)?;
                        validate_timestamp(retry_at)?;
                        if timestamp_millis(retry_at)? < timestamp_millis(&committed_at)? {
                            return Err(WalIdempotencyError::Malformed);
                        }
                    }
                    WebhookSettlementKind::Ambiguous => {}
                }
                if let WebhookSettlementKind::Failed { status, .. } = kind {
                    validate_status(*status)?;
                }
            }
        }
        let target = target_snapshot(&predecessor, claim.as_ref(), &kind, &committed_at)?;
        let predecessor_commitment = predecessor.commitment()?;
        let claim_commitment = match &claim {
            Some(claim) => claim.commitment()?.to_vec(),
            None => Vec::new(),
        };
        let target_commitment = target.commitment_for_target()?;
        let source = stable_operation_source(
            SUBTYPE,
            &[
                account_id.as_bytes(),
                &predecessor.rowid.to_be_bytes(),
                &predecessor_commitment,
                &claim_commitment,
                &target_commitment,
            ],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::WebhookDelivery, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            predecessor,
            claim,
            kind,
            target,
            committed_at,
        })
    }

    #[cfg(test)]
    pub(in crate::cp) fn apply_direct(&self, transaction: &Transaction<'_>) -> Result<()> {
        self.apply(transaction).and_then(|result| {
            self.validate_replay(&result)?;
            Ok(())
        })
    }

    fn apply_exact(&self, transaction: &Transaction<'_>) -> Result<()> {
        let current = load_current_candidate(transaction, &self.predecessor, &self.target)?;
        if self.claim.is_none()
            && claim::load_open_claim(transaction, &self.predecessor.event_id)?.is_some()
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if current.same_stored_contents(&self.target) {
            if let Some(claim) = &self.claim {
                claim::require_settled_claim(
                    transaction,
                    claim,
                    claim_outcome(&self.kind),
                    self.target.response_status,
                    None,
                    self.target.error_code.as_deref(),
                    &self.committed_at,
                )?;
            }
            return Ok(());
        }
        if !current.same_stored_contents(&self.predecessor) {
            return Err(WalIdempotencyError::Precondition);
        }
        if let Some(claim) = &self.claim {
            claim::require_started_claim(transaction, claim)?;
        }
        let changed = transaction
            .execute(
                "UPDATE webhook_deliveries
                 SET state=?1,attempt_count=?2,next_attempt_at=?3,
                     response_status=?4,error_code=?5,updated_at=?6
                 WHERE rowid=?7 AND episode_id=?8 AND subscription_id=?9
                   AND delivery_version=?10 AND event_id=?11 AND state=?12
                   AND attempt_count=?13 AND next_attempt_at IS ?14
                   AND response_status IS ?15 AND error_code IS ?16
                   AND created_at=?17 AND updated_at=?18",
                params![
                    self.target.state,
                    self.target.attempt_count,
                    self.target.next_attempt_at,
                    self.target.response_status,
                    self.target.error_code,
                    self.target.updated_at,
                    current.rowid,
                    self.predecessor.episode_id,
                    self.predecessor.subscription_id,
                    self.predecessor.delivery_version,
                    self.predecessor.event_id,
                    self.predecessor.state,
                    self.predecessor.attempt_count,
                    self.predecessor.next_attempt_at,
                    self.predecessor.response_status,
                    self.predecessor.error_code,
                    self.predecessor.created_at,
                    self.predecessor.updated_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Precondition);
        }
        if let Some(claim) = &self.claim {
            claim::settle_claim(
                transaction,
                claim,
                claim_outcome(&self.kind),
                self.target.response_status,
                None,
                self.target.error_code.as_deref(),
                &self.committed_at,
            )?;
        }
        let settled = load_delivery_snapshot_by_rowid(transaction, current.rowid)?
            .ok_or(WalIdempotencyError::Corrupt)?;
        if !settled.same_stored_contents(&self.target) {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(())
    }
}

pub(crate) struct ExactWebhookDeliverySettlementLedger;

impl WalLogicalDomainPlan for ExactWebhookDeliverySettlementPlan {
    type Ledger = ExactWebhookDeliverySettlementLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::WebhookDelivery
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(512));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_string(&mut request, &self.account_id)?;
        request.extend_from_slice(&self.predecessor.rowid.to_be_bytes());
        request.extend_from_slice(&self.predecessor.commitment()?);
        match &self.claim {
            None => request.push(0),
            Some(claim) => {
                request.push(1);
                request.extend_from_slice(&claim.commitment()?);
            }
        }
        request.push(self.kind.tag());
        request.extend_from_slice(&self.target.commitment_for_target()?);
        encode_string(&mut request, &self.committed_at)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        self.apply_exact(transaction)?;
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

/// Exact, provider-free erasure of one terminal delivery and its sensitive
/// frozen-request/claim subtree. The permanent logical ledger stores only the
/// request fingerprint and a unit result; endpoint, secret, and body bytes are
/// committed here but never copied into the purge ledger.
pub(crate) struct ExactWebhookDeliveryPurgePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    evidence: WebhookDeliveryPurgeEvidence,
}

impl ExactWebhookDeliveryPurgePlan {
    pub(in crate::cp) fn new(
        account_id: String,
        evidence: WebhookDeliveryPurgeEvidence,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        evidence.predecessor.validate_purge_predecessor()?;
        let predecessor_commitment = evidence.predecessor.raw_commitment()?;
        let source = stable_operation_source(
            PURGE_SUBTYPE,
            &[
                account_id.as_bytes(),
                &predecessor_commitment,
                &evidence.subtree_commitment,
            ],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::WebhookDelivery, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            evidence,
        })
    }

    #[cfg(test)]
    pub(in crate::cp) fn apply_direct(&self, transaction: &Transaction<'_>) -> Result<()> {
        self.apply(transaction).and_then(|result| {
            self.validate_replay(&result)?;
            Ok(())
        })
    }

    fn apply_exact(&self, transaction: &Transaction<'_>) -> Result<()> {
        let predecessor = &self.evidence.predecessor;
        let current = load_delivery_snapshot(transaction, &predecessor.event_id)?;
        let Some(current) = current else {
            return webhook_subtree_absent(transaction, &predecessor.event_id)?
                .then_some(())
                .ok_or(WalIdempotencyError::Corrupt);
        };
        if !current.same_stored_contents(predecessor) {
            return Err(WalIdempotencyError::Precondition);
        }
        current.validate_purge_predecessor()?;
        if webhook_subtree_commitment(transaction, &current.event_id)?
            != self.evidence.subtree_commitment
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let changed = transaction
            .execute(
                "DELETE FROM webhook_deliveries
                 WHERE rowid=?1 AND episode_id=?2 AND subscription_id=?3
                   AND delivery_version=?4 AND event_id=?5 AND state=?6
                   AND attempt_count=?7 AND next_attempt_at IS ?8
                   AND response_status IS ?9 AND error_code IS ?10
                   AND created_at=?11 AND updated_at=?12",
                params![
                    current.rowid,
                    predecessor.episode_id,
                    predecessor.subscription_id,
                    predecessor.delivery_version,
                    predecessor.event_id,
                    predecessor.state,
                    predecessor.attempt_count,
                    predecessor.next_attempt_at,
                    predecessor.response_status,
                    predecessor.error_code,
                    predecessor.created_at,
                    predecessor.updated_at,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1
            || load_delivery_snapshot(transaction, &predecessor.event_id)?.is_some()
            || !webhook_subtree_absent(transaction, &predecessor.event_id)?
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(())
    }
}

pub(crate) struct ExactWebhookDeliveryPurgeLedger;

impl WalLogicalDomainPlan for ExactWebhookDeliveryPurgePlan {
    type Ledger = ExactWebhookDeliveryPurgeLedger;
    type Output = ();

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
        request.extend_from_slice(&self.evidence.predecessor.raw_commitment()?);
        request.extend_from_slice(&self.evidence.subtree_commitment);
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        self.apply_exact(transaction)?;
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

impl WalLogicalDomainLedger<ExactWebhookDeliverySettlementPlan>
    for ExactWebhookDeliverySettlementLedger
{
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<ExactWebhookDeliverySettlementPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,result_bytes,result_commitment
                 FROM archive_v3_wal_webhook_exact_settlement_operations WHERE operation_id=?1",
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
            || fingerprint.as_slice()
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
        prepared: &PreparedLogicalMutation<ExactWebhookDeliverySettlementPlan>,
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
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_webhook_exact_settlement_operations
                 (operation_id,format_version,codec_version,request_fingerprint,result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    prepared.request_fingerprint_for_owner().as_bytes().as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if transaction
            .execute(
                "UPDATE archive_v3_wal_webhook_exact_settlement_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            != 1
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

impl WalLogicalDomainLedger<ExactWebhookDeliveryPurgePlan> for ExactWebhookDeliveryPurgeLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<ExactWebhookDeliveryPurgePlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_purge_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,result_bytes,result_commitment
                 FROM archive_v3_wal_webhook_exact_settlement_operations WHERE operation_id=?1",
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
            || fingerprint.as_slice()
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
        prepared: &PreparedLogicalMutation<ExactWebhookDeliveryPurgePlan>,
    ) -> Result<LogicalMutationResult> {
        require_purge_kind(prepared)?;
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
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_webhook_exact_settlement_operations
                 (operation_id,format_version,codec_version,request_fingerprint,result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    prepared.request_fingerprint_for_owner().as_bytes().as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if transaction
            .execute(
                "UPDATE archive_v3_wal_webhook_exact_settlement_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?
            != 1
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

fn require_kind(
    prepared: &PreparedLogicalMutation<ExactWebhookDeliverySettlementPlan>,
) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::WebhookDelivery)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

fn require_purge_kind(
    prepared: &PreparedLogicalMutation<ExactWebhookDeliveryPurgePlan>,
) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::WebhookDelivery)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN (?1,?2,?3)",
            params![SCHEMA_TABLE, LEDGER_TABLE, STATE_TABLE],
            |row| row.get(0),
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
                    "CREATE TABLE archive_v3_wal_webhook_exact_settlement_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_webhook_exact_settlement_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
                        result_bytes BLOB NOT NULL CHECK(length(result_bytes)=9),
                        result_commitment BLOB NOT NULL CHECK(length(result_commitment)=32)
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_webhook_exact_settlement_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_webhook_exact_settlement_schema VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_webhook_exact_settlement_state VALUES (1,0,0);",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            validate_schema_marker(transaction)
        }
    }
}

fn validate_schema_marker(connection: &Connection) -> Result<()> {
    let marker = connection
        .query_row(
            "SELECT format_version,codec_version FROM archive_v3_wal_webhook_exact_settlement_schema
             WHERE singleton=1",
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
    let (rows, bytes): (i64, i64) = connection
        .query_row(
            "SELECT row_count,result_bytes FROM archive_v3_wal_webhook_exact_settlement_state
             WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let rows = u32::try_from(rows).map_err(|_| WalIdempotencyError::Corrupt)?;
    let bytes = u64::try_from(bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
    if rows > MAX_ROWS || bytes > MAX_RESULT_BYTES {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok((rows, bytes))
}

pub(super) fn target_snapshot(
    predecessor: &WebhookDeliverySnapshot,
    claim: Option<&WebhookSendClaim>,
    kind: &WebhookSettlementKind,
    committed_at: &str,
) -> Result<WebhookDeliverySnapshot> {
    let mut target = predecessor.clone();
    target.attempt_count = if matches!(
        kind,
        WebhookSettlementKind::Cancel { .. } | WebhookSettlementKind::Defer { .. }
    ) {
        predecessor.attempt_count
    } else {
        claim
            .map(WebhookSendClaim::send_attempt)
            .unwrap_or(predecessor.attempt_count)
    };
    target.updated_at = committed_at.to_owned();
    target.next_attempt_at = None;
    match kind {
        WebhookSettlementKind::Cancel { code } => {
            target.state = "cancelled".into();
            target.response_status = None;
            target.error_code = Some(code.clone());
        }
        WebhookSettlementKind::Accepted { status } => {
            target.state = "sent".into();
            target.response_status = Some(*status);
            target.error_code = None;
        }
        WebhookSettlementKind::Retry {
            status,
            code,
            retry_at,
        } => {
            target.state = "retry".into();
            target.response_status = *status;
            target.error_code = Some(code.clone());
            target.next_attempt_at = Some(retry_at.clone());
        }
        WebhookSettlementKind::Defer { code, retry_at } => {
            target.state = "retry".into();
            target.attempt_count = predecessor.attempt_count;
            target.response_status = None;
            target.error_code = Some(code.clone());
            target.next_attempt_at = Some(retry_at.clone());
        }
        WebhookSettlementKind::Failed { status, code } => {
            target.state = "failed".into();
            target.response_status = *status;
            target.error_code = Some(code.clone());
        }
        WebhookSettlementKind::Ambiguous => {
            target.state = "failed".into();
            target.response_status = None;
            target.error_code = Some(AMBIGUOUS_ERROR_CODE.into());
        }
    }
    target.validate_target()?;
    Ok(target)
}

impl WebhookDeliverySnapshot {
    fn validate_target(&self) -> Result<()> {
        self.validate_exact_evidence()?;
        if !matches!(
            self.state.as_str(),
            "retry" | "sent" | "cancelled" | "failed"
        ) || self.attempt_count < 0
            || self
                .next_attempt_at
                .as_deref()
                .is_some_and(|value| !valid_timestamp(value))
            || !valid_timestamp(&self.updated_at)
            || !valid_optional_text(self.error_code.as_deref(), MAX_TEXT_BYTES)
            || (self.state == "retry" && self.next_attempt_at.is_none())
            || (self.state != "retry" && self.next_attempt_at.is_some())
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_status(self.response_status)
    }

    fn commitment_for_target(&self) -> Result<[u8; 32]> {
        self.validate_target()?;
        let mut hasher = Sha256::new();
        hash_i64(&mut hasher, self.episode_id);
        hash_field(&mut hasher, self.subscription_id.as_bytes())?;
        hash_i64(&mut hasher, self.delivery_version);
        hash_field(&mut hasher, self.event_id.as_bytes())?;
        hash_field(&mut hasher, self.state.as_bytes())?;
        hash_i64(&mut hasher, self.attempt_count);
        hash_optional_text(
            &mut hasher,
            self.next_attempt_at.as_deref(),
            MAX_TIMESTAMP_BYTES,
        )?;
        hash_optional_i64(&mut hasher, self.response_status);
        hash_optional_text(&mut hasher, self.error_code.as_deref(), MAX_TEXT_BYTES)?;
        hash_field(&mut hasher, self.created_at.as_bytes())?;
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        nonzero_digest(hasher)
    }
}

fn claim_outcome(kind: &WebhookSettlementKind) -> WebhookClaimOutcome {
    match kind {
        WebhookSettlementKind::Cancel { .. } => WebhookClaimOutcome::Cancelled,
        WebhookSettlementKind::Accepted { .. } => WebhookClaimOutcome::Accepted,
        WebhookSettlementKind::Retry { .. } => WebhookClaimOutcome::Rejected,
        WebhookSettlementKind::Defer { .. } => WebhookClaimOutcome::Deferred,
        WebhookSettlementKind::Failed { .. } => WebhookClaimOutcome::Failed,
        WebhookSettlementKind::Ambiguous => WebhookClaimOutcome::Ambiguous,
    }
}

pub(super) fn load_delivery_snapshot(
    connection: &Connection,
    event_id: &str,
) -> Result<Option<WebhookDeliverySnapshot>> {
    connection
        .query_row(
            "SELECT rowid,episode_id,subscription_id,delivery_version,event_id,state,
                    attempt_count,next_attempt_at,response_status,error_code,created_at,updated_at
             FROM webhook_deliveries WHERE event_id=?1",
            [event_id],
            WebhookDeliverySnapshot::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_delivery_snapshot_by_rowid(
    connection: &Connection,
    rowid: i64,
) -> Result<Option<WebhookDeliverySnapshot>> {
    connection
        .query_row(
            "SELECT rowid,episode_id,subscription_id,delivery_version,event_id,state,
                    attempt_count,next_attempt_at,response_status,error_code,created_at,updated_at
             FROM webhook_deliveries WHERE rowid=?1",
            [rowid],
            WebhookDeliverySnapshot::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_current_candidate(
    connection: &Connection,
    predecessor: &WebhookDeliverySnapshot,
    target: &WebhookDeliverySnapshot,
) -> Result<WebhookDeliverySnapshot> {
    if let Some(current) = load_delivery_snapshot_by_rowid(connection, predecessor.rowid)? {
        if current.same_stored_contents(predecessor) || current.same_stored_contents(target) {
            return Ok(current);
        }
    }
    if let Some(current) = load_delivery_snapshot(connection, &predecessor.event_id)? {
        if current.same_stored_contents(predecessor) || current.same_stored_contents(target) {
            return Ok(current);
        }
    }
    Err(WalIdempotencyError::Precondition)
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

fn validate_text(value: &str, maximum: usize) -> Result<()> {
    valid_text(value, maximum)
        .then_some(())
        .ok_or(WalIdempotencyError::Malformed)
}

fn valid_optional_text(value: Option<&str>, maximum: usize) -> bool {
    value.is_none_or(|value| valid_text(value, maximum))
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

fn validate_timestamp(value: &str) -> Result<()> {
    valid_timestamp(value)
        .then_some(())
        .ok_or(WalIdempotencyError::Malformed)
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

fn validate_status(status: Option<i64>) -> Result<()> {
    status
        .is_none_or(|status| (100..=599).contains(&status))
        .then_some(())
        .ok_or(WalIdempotencyError::Malformed)
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

fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_be_bytes());
}

fn hash_optional_i64(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        None => hasher.update([0]),
        Some(value) => {
            hasher.update([1]);
            hash_i64(hasher, value);
        }
    }
}

fn hash_optional_text(hasher: &mut Sha256, value: Option<&str>, maximum: usize) -> Result<()> {
    if !valid_optional_text(value, maximum) {
        return Err(WalIdempotencyError::Malformed);
    }
    match value {
        None => hasher.update([0]),
        Some(value) => {
            hasher.update([1]);
            hash_field(hasher, value.as_bytes())?;
        }
    }
    Ok(())
}

fn hash_optional_raw_text(hasher: &mut Sha256, value: Option<&str>) -> Result<()> {
    match value {
        None => hasher.update([0]),
        Some(value) => {
            hasher.update([1]);
            hash_field(hasher, value.as_bytes())?;
        }
    }
    Ok(())
}

fn hash_sql_value(hasher: &mut Sha256, value: ValueRef<'_>) -> Result<()> {
    match value {
        ValueRef::Null => hasher.update([0]),
        ValueRef::Integer(value) => {
            hasher.update([1]);
            hash_i64(hasher, value);
        }
        ValueRef::Real(value) => {
            hasher.update([2]);
            hasher.update(value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => {
            hasher.update([3]);
            hash_field(hasher, value)?;
        }
        ValueRef::Blob(value) => {
            hasher.update([4]);
            hash_field(hasher, value)?;
        }
    }
    Ok(())
}

fn hash_query_rows(
    connection: &Connection,
    sql: &str,
    event_id: &str,
    hasher: &mut Sha256,
) -> Result<u64> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let column_count = statement.column_count();
    let mut rows = statement
        .query([event_id])
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let mut count = 0_u64;
    while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
        count = count.checked_add(1).ok_or(WalIdempotencyError::Limit)?;
        hasher.update([0x52]);
        for index in 0..column_count {
            hash_sql_value(
                hasher,
                row.get_ref(index)
                    .map_err(|_| WalIdempotencyError::Unavailable)?,
            )?;
        }
    }
    Ok(count)
}

fn webhook_subtree_commitment(connection: &Connection, event_id: &str) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"adr-0022-webhook-delivery-purge-subtree-v1");
    if !claim::purge_sidecar_present(connection)? {
        hasher.update(0_u64.to_be_bytes());
        hasher.update(0_u64.to_be_bytes());
        return nonzero_digest(hasher);
    }
    if claim::raw_live_claim_exists(connection, event_id)? {
        return Err(WalIdempotencyError::Precondition);
    }
    let frozen_count = hash_query_rows(
        connection,
        "SELECT endpoint_url,signing_secret,event_body,subscription_id,
                request_event_id,request_content_scope,request_commitment,encoded_bytes
         FROM archive_v3_wal_webhook_frozen_requests WHERE event_id=?1",
        event_id,
        &mut hasher,
    )?;
    hasher.update(frozen_count.to_be_bytes());
    let claim_count = hash_query_rows(
        connection,
        "SELECT claim_id,event_id,predecessor_rowid,episode_id,delivery_version,
                predecessor_include_content,predecessor_state,predecessor_attempt_count,
                predecessor_next_attempt_at,predecessor_provider_message_id,
                predecessor_response_status,predecessor_error_code,predecessor_created_at,
                predecessor_updated_at,request_commitment,send_attempt,started_at,
                lease_expires_at,outcome,provider_status,provider_message_id,provider_error,
                settled_at
         FROM archive_v3_wal_webhook_send_claims WHERE event_id=?1 ORDER BY claim_id",
        event_id,
        &mut hasher,
    )?;
    hasher.update(claim_count.to_be_bytes());
    nonzero_digest(hasher)
}

fn webhook_subtree_absent(connection: &Connection, event_id: &str) -> Result<bool> {
    if !claim::purge_sidecar_present(connection)? {
        return Ok(true);
    }
    connection
        .query_row(
            "SELECT
               NOT EXISTS(SELECT 1 FROM archive_v3_wal_webhook_frozen_requests WHERE event_id=?1)
               AND NOT EXISTS(SELECT 1 FROM archive_v3_wal_webhook_send_claims WHERE event_id=?1)",
            [event_id],
            |row| row.get(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn nonzero_digest(hasher: Sha256) -> Result<[u8; 32]> {
    let digest: [u8; 32] = hasher.finalize().into();
    (digest != [0; 32])
        .then_some(digest)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn encode_string(request: &mut Vec<u8>, value: &str) -> Result<()> {
    request.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    request.extend_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::webhook_worker::wal::claim::{
        WebhookFrozenRequest, WebhookSendClaimDisposition, WebhookSendClaimPlan,
    };
    use tempfile::tempdir;

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const EVENT: &str = "w1_2222222222222222222222222222222222222222222222222222222222222222";
    const SUBSCRIPTION: &str = "33333333-3333-4333-8333-333333333333";
    const CLAIM: &str = "44444444-4444-4444-8444-444444444444";
    const STARTED: &str = "2026-08-20T20:00:00.000Z";
    const COMMITTED: &str = "2026-08-20T20:00:01.000Z";

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

    fn claim(connection: &mut Connection) -> WebhookSendClaim {
        let plan = WebhookSendClaimPlan::new(
            ACCOUNT.into(),
            CLAIM.into(),
            snapshot(connection),
            WebhookFrozenRequest::new(
                "https://hooks.example.com/frozen".into(),
                "whsec_test-secret".into(),
                "{\"immutable\":true}".into(),
                SUBSCRIPTION.into(),
                EVENT.into(),
                true,
            )
            .unwrap(),
            STARTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            plan.apply_direct(&transaction).unwrap(),
            WebhookSendClaimDisposition::Authorized
        );
        transaction.commit().unwrap();
        claim::load_open_claim(connection, EVENT).unwrap().unwrap()
    }

    fn accepted_purge_plan(connection: &mut Connection) -> ExactWebhookDeliveryPurgePlan {
        let send_claim = claim(connection);
        let settlement = ExactWebhookDeliverySettlementPlan::new(
            ACCOUNT.into(),
            snapshot(connection),
            Some(send_claim),
            WebhookSettlementKind::Accepted { status: 204 },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        settlement.apply_direct(&transaction).unwrap();
        transaction.commit().unwrap();
        let WebhookSubscriptionPurgeCandidate::Terminal(evidence) =
            load_subscription_purge_candidate(connection, SUBSCRIPTION)
                .unwrap()
                .unwrap()
        else {
            panic!("accepted delivery must be terminal purge evidence");
        };
        ExactWebhookDeliveryPurgePlan::new(ACCOUNT.into(), evidence).unwrap()
    }

    fn execute_purge(
        connection: &mut Connection,
        prepared: &PreparedLogicalMutation<ExactWebhookDeliveryPurgePlan>,
    ) -> Result<LogicalMutationResult> {
        let transaction = connection
            .transaction()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let result = ExactWebhookDeliveryPurgeLedger::resolve_or_apply(&transaction, prepared)?;
        transaction
            .commit()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        Ok(result)
    }

    #[test]
    fn exact_claim_settles_acceptance_and_survives_rowid_relocation() {
        let mut connection = connection();
        let predecessor = snapshot(&connection);
        let claim = claim(&mut connection);
        connection
            .execute(
                "UPDATE webhook_deliveries SET rowid=rowid+100 WHERE event_id=?1",
                [EVENT],
            )
            .unwrap();
        let relocated = snapshot(&connection);
        assert_ne!(relocated.rowid, predecessor.rowid);
        assert!(relocated.same_stored_contents(&predecessor));
        let plan = ExactWebhookDeliverySettlementPlan::new(
            ACCOUNT.into(),
            relocated,
            Some(claim),
            WebhookSettlementKind::Accepted { status: 204 },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        plan.apply_direct(&transaction).unwrap();
        transaction.commit().unwrap();
        let settled = snapshot(&connection);
        assert_eq!(settled.state, "sent");
        assert_eq!(settled.attempt_count, 1);
        assert_eq!(settled.response_status, Some(204));
        assert!(matches!(
            claim::load_claim_recovery(&connection, CLAIM).unwrap(),
            Some(claim::WebhookClaimRecovery::Accepted { status: 204, .. })
        ));
    }

    #[test]
    fn live_claim_blocks_claimless_cancellation_and_delivery_deletion() {
        let mut connection = connection();
        let predecessor = snapshot(&connection);
        let claim = claim(&mut connection);
        assert!(connection
            .execute("DELETE FROM webhook_deliveries WHERE event_id=?1", [EVENT])
            .is_err());
        let cancel = ExactWebhookDeliverySettlementPlan::new(
            ACCOUNT.into(),
            predecessor,
            None,
            WebhookSettlementKind::Cancel {
                code: "subscription_deleted".into(),
            },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            cancel.apply_direct(&transaction),
            Err(WalIdempotencyError::Precondition)
        );
        drop(transaction);
        let accept = ExactWebhookDeliverySettlementPlan::new(
            ACCOUNT.into(),
            snapshot(&connection),
            Some(claim),
            WebhookSettlementKind::Accepted { status: 200 },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        accept.apply_direct(&transaction).unwrap();
    }

    #[test]
    fn bare_preactivation_and_exhausted_rows_cancel_without_increment() {
        for (event_id, attempt) in [
            ("evt_legacy", 0_i64),
            (
                "w1_3333333333333333333333333333333333333333333333333333333333333333",
                MAX_ATTEMPTS,
            ),
        ] {
            let connection = Connection::open_in_memory().unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE webhook_deliveries (
                       episode_id INTEGER NOT NULL,subscription_id TEXT NOT NULL,
                       delivery_version INTEGER NOT NULL,event_id TEXT NOT NULL UNIQUE,
                       state TEXT NOT NULL,attempt_count INTEGER NOT NULL,
                       next_attempt_at TEXT,response_status INTEGER,error_code TEXT,
                       created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
                       PRIMARY KEY(episode_id,subscription_id,delivery_version));",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO webhook_deliveries VALUES
                     (7,?1,1,?2,'pending',?3,NULL,NULL,NULL,
                      '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z')",
                    params![SUBSCRIPTION, event_id, attempt],
                )
                .unwrap();
            let predecessor = load_delivery_snapshot(&connection, event_id)
                .unwrap()
                .unwrap();
            assert!(predecessor.send_admission_refusal().unwrap().is_some());
            let plan = ExactWebhookDeliverySettlementPlan::new(
                ACCOUNT.into(),
                predecessor,
                None,
                WebhookSettlementKind::Cancel {
                    code: "activation_ineligible".into(),
                },
                COMMITTED.into(),
            )
            .unwrap();
            let transaction = connection.unchecked_transaction().unwrap();
            plan.apply_direct(&transaction).unwrap();
            transaction.commit().unwrap();
            let stored: (String, i64, String) = connection
                .query_row(
                    "SELECT state,attempt_count,typeof(attempt_count) FROM webhook_deliveries",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(stored, ("cancelled".into(), attempt, "integer".into()));
        }
    }

    #[test]
    fn more_than_the_legacy_bulk_limit_cancel_and_purge_as_independent_exact_rows() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE webhook_deliveries (
                   episode_id INTEGER NOT NULL,subscription_id TEXT NOT NULL,
                   delivery_version INTEGER NOT NULL,event_id TEXT NOT NULL UNIQUE,
                   state TEXT NOT NULL,attempt_count INTEGER NOT NULL,
                   next_attempt_at TEXT,response_status INTEGER,error_code TEXT,
                   created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
                   PRIMARY KEY(episode_id,subscription_id,delivery_version));",
            )
            .unwrap();
        for ordinal in 1..=257_i64 {
            let event_id = format!("w1_{ordinal:064x}");
            connection
                .execute(
                    "INSERT INTO webhook_deliveries VALUES
                     (?1,?2,1,?3,'pending',0,NULL,NULL,NULL,
                      '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z')",
                    params![ordinal, SUBSCRIPTION, event_id],
                )
                .unwrap();
        }
        for ordinal in 1..=257_i64 {
            let event_id = format!("w1_{ordinal:064x}");
            let predecessor = load_delivery_snapshot(&connection, &event_id)
                .unwrap()
                .unwrap();
            let plan = ExactWebhookDeliverySettlementPlan::new(
                ACCOUNT.into(),
                predecessor,
                None,
                WebhookSettlementKind::Cancel {
                    code: "subscription_deleted".into(),
                },
                COMMITTED.into(),
            )
            .unwrap();
            let transaction = connection.unchecked_transaction().unwrap();
            plan.apply_direct(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        let unsettled: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM webhook_deliveries WHERE state IN ('pending','retry')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unsettled, 0);
        for _ in 1..=257_i64 {
            let candidate = load_subscription_purge_candidate(&connection, SUBSCRIPTION)
                .unwrap()
                .unwrap();
            let WebhookSubscriptionPurgeCandidate::Terminal(evidence) = candidate else {
                panic!("every settled row must be purgeable");
            };
            let plan = ExactWebhookDeliveryPurgePlan::new(ACCOUNT.into(), evidence).unwrap();
            let transaction = connection.unchecked_transaction().unwrap();
            plan.apply_direct(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        assert!(load_subscription_purge_candidate(&connection, SUBSCRIPTION)
            .unwrap()
            .is_none());
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM webhook_deliveries", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn exact_purge_erases_frozen_secret_body_and_terminal_claim_after_rowid_relocation() {
        let mut connection = connection();
        let claim = claim(&mut connection);
        let accept = ExactWebhookDeliverySettlementPlan::new(
            ACCOUNT.into(),
            snapshot(&connection),
            Some(claim),
            WebhookSettlementKind::Accepted { status: 204 },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        accept.apply_direct(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
            .execute(
                "UPDATE webhook_deliveries SET rowid=rowid+100 WHERE event_id=?1",
                [EVENT],
            )
            .unwrap();
        let WebhookSubscriptionPurgeCandidate::Terminal(evidence) =
            load_subscription_purge_candidate(&connection, SUBSCRIPTION)
                .unwrap()
                .unwrap()
        else {
            panic!("accepted delivery must be terminal purge evidence");
        };
        let plan = ExactWebhookDeliveryPurgePlan::new(ACCOUNT.into(), evidence).unwrap();
        let canonical = plan.canonical_request().unwrap();
        for forbidden in [
            b"https://hooks.example.com/frozen".as_slice(),
            b"whsec_test-secret".as_slice(),
            b"immutable".as_slice(),
        ] {
            assert!(
                !canonical
                    .windows(forbidden.len())
                    .any(|window| window == forbidden),
                "canonical purge request retained sensitive request bytes"
            );
        }
        let transaction = connection.transaction().unwrap();
        plan.apply_direct(&transaction).unwrap();
        transaction.commit().unwrap();
        for table in [
            "webhook_deliveries",
            "archive_v3_wal_webhook_frozen_requests",
            "archive_v3_wal_webhook_send_claims",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
        let accounting: (i64, i64) = connection
            .query_row(
                "SELECT frozen_request_count,frozen_request_bytes
                 FROM archive_v3_wal_webhook_claim_state WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(accounting, (0, 0));
        let transaction = connection.transaction().unwrap();
        plan.apply_direct(&transaction).unwrap();
    }

    #[test]
    fn purge_ledger_applies_reopens_replays_and_retains_only_commitments() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("webhook-purge.sqlite");
        let prepared = {
            let mut connection = Connection::open(&path).unwrap();
            connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
            connection
                .execute_batch(&format!(
                    "CREATE TABLE webhook_deliveries (
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
            let prepared =
                PreparedLogicalMutation::prepare(accepted_purge_plan(&mut connection)).unwrap();
            assert!(matches!(
                execute_purge(&mut connection, &prepared).unwrap(),
                LogicalMutationResult::Applied(_)
            ));
            let retained: (Vec<u8>, Vec<u8>, Vec<u8>) = connection
                .query_row(
                    "SELECT request_fingerprint,result_bytes,result_commitment
                     FROM archive_v3_wal_webhook_exact_settlement_operations",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            let retained = [retained.0, retained.1, retained.2].concat();
            for forbidden in [
                b"https://hooks.example.com/frozen".as_slice(),
                b"whsec_test-secret".as_slice(),
                b"immutable".as_slice(),
            ] {
                assert!(
                    !retained
                        .windows(forbidden.len())
                        .any(|window| window == forbidden),
                    "permanent purge ledger retained sensitive request bytes"
                );
            }
            prepared
        };

        let mut reopened = Connection::open(&path).unwrap();
        reopened.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let changes = reopened.total_changes();
        assert!(matches!(
            execute_purge(&mut reopened, &prepared).unwrap(),
            LogicalMutationResult::Replayed(_)
        ));
        assert_eq!(reopened.total_changes(), changes);
        assert_eq!(load_ledger_state(&reopened).unwrap(), (1, 9));
        assert!(webhook_subtree_absent(&reopened, EVENT).unwrap());
    }

    #[test]
    fn late_purge_ledger_failure_rolls_back_row_and_sensitive_subtree() {
        let mut connection = connection();
        let prepared =
            PreparedLogicalMutation::prepare(accepted_purge_plan(&mut connection)).unwrap();
        {
            let transaction = connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER reject_webhook_purge_ledger_insert
                 BEFORE INSERT ON archive_v3_wal_webhook_exact_settlement_operations
                 BEGIN SELECT RAISE(ABORT,'injected late purge failure'); END;",
            )
            .unwrap();
        assert_eq!(
            execute_purge(&mut connection, &prepared).err().unwrap(),
            WalIdempotencyError::Unavailable
        );
        for table in [
            "webhook_deliveries",
            "archive_v3_wal_webhook_frozen_requests",
            "archive_v3_wal_webhook_send_claims",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 1, "late ledger failure changed {table}");
        }
        assert_eq!(load_ledger_state(&connection).unwrap(), (0, 0));
        let accounting: (i64, i64) = connection
            .query_row(
                "SELECT frozen_request_count,frozen_request_bytes
                 FROM archive_v3_wal_webhook_claim_state WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(accounting.0 > 0 && accounting.1 > 0);
    }

    #[test]
    fn purge_ledger_refuses_changed_row_changed_subtree_and_partial_schemas() {
        let mut changed_row = connection();
        let prepared =
            PreparedLogicalMutation::prepare(accepted_purge_plan(&mut changed_row)).unwrap();
        changed_row
            .execute(
                "UPDATE webhook_deliveries SET updated_at='2026-08-20T20:00:02.000Z'
                 WHERE event_id=?1",
                [EVENT],
            )
            .unwrap();
        assert_eq!(
            execute_purge(&mut changed_row, &prepared).err().unwrap(),
            WalIdempotencyError::Precondition
        );
        assert!(load_delivery_snapshot(&changed_row, EVENT)
            .unwrap()
            .is_some());

        let mut changed_subtree = connection();
        let prepared =
            PreparedLogicalMutation::prepare(accepted_purge_plan(&mut changed_subtree)).unwrap();
        changed_subtree
            .execute(
                "UPDATE archive_v3_wal_webhook_frozen_requests
                 SET signing_secret='whsec_changed-after-observation' WHERE event_id=?1",
                [EVENT],
            )
            .unwrap();
        assert_eq!(
            execute_purge(&mut changed_subtree, &prepared)
                .err()
                .unwrap(),
            WalIdempotencyError::Precondition
        );
        assert!(load_delivery_snapshot(&changed_subtree, EVENT)
            .unwrap()
            .is_some());

        let mut partial_ledger = connection();
        let settlement = ExactWebhookDeliverySettlementPlan::new(
            ACCOUNT.into(),
            snapshot(&partial_ledger),
            None,
            WebhookSettlementKind::Cancel {
                code: "subscription_deleted".into(),
            },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = partial_ledger.transaction().unwrap();
        settlement.apply_direct(&transaction).unwrap();
        transaction.commit().unwrap();
        let WebhookSubscriptionPurgeCandidate::Terminal(evidence) =
            load_subscription_purge_candidate(&partial_ledger, SUBSCRIPTION)
                .unwrap()
                .unwrap()
        else {
            panic!("cancelled row must be purgeable");
        };
        let prepared = PreparedLogicalMutation::prepare(
            ExactWebhookDeliveryPurgePlan::new(ACCOUNT.into(), evidence).unwrap(),
        )
        .unwrap();
        partial_ledger
            .execute_batch(
                "CREATE TABLE archive_v3_wal_webhook_exact_settlement_schema (
                   singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            execute_purge(&mut partial_ledger, &prepared).err().unwrap(),
            WalIdempotencyError::Corrupt
        );
        assert!(load_delivery_snapshot(&partial_ledger, EVENT)
            .unwrap()
            .is_some());

        let partial_claim = connection();
        partial_claim
            .execute(
                "UPDATE webhook_deliveries SET state='sent',attempt_count=1,response_status=204
                 WHERE event_id=?1",
                [EVENT],
            )
            .unwrap();
        partial_claim
            .execute_batch(
                "CREATE TABLE archive_v3_wal_webhook_claim_schema (
                   singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            load_subscription_purge_candidate(&partial_claim, SUBSCRIPTION),
            Err(WalIdempotencyError::Corrupt)
        );
        assert!(load_delivery_snapshot(&partial_claim, EVENT)
            .unwrap()
            .is_some());
    }

    #[test]
    fn exact_purge_refuses_a_live_send_claim() {
        let mut connection = connection();
        let _claim = claim(&mut connection);
        connection
            .execute(
                "UPDATE webhook_deliveries
                 SET state='sent',attempt_count=1,response_status=200,
                     updated_at='2026-08-20T19:00:01.000Z'
                 WHERE event_id=?1",
                [EVENT],
            )
            .unwrap();
        assert_eq!(
            load_subscription_purge_candidate(&connection, SUBSCRIPTION),
            Err(WalIdempotencyError::Precondition)
        );
    }
}
