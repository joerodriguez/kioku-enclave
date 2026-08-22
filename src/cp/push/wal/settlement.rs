//! Exact push-delivery settlement after a durable send claim (ADR-0022 F13).
//!
//! The provider owner carries one complete due-row snapshot across the send;
//! it never substitutes a post-I/O reread. Pre-send cancellations move only
//! that snapshot. Provider outcomes additionally require the exact durable
//! claim created before I/O. Every immutable and mutable column participates
//! in adoption and CAS, including nullable response/error evidence.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};
use crate::cp::isotime;

use super::claim::{self, PushClaimOutcome, PushSendClaim};

const REQUEST_V2: u16 = 2;
const SUBTYPE: &[u8] = b"adr-0022-push-delivery-settlement-v2";
const MAX_ID_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_ATTEMPTS: i64 = 10;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_push_settlement_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_push_settlement_operations";
const STATE_TABLE: &str = "archive_v3_wal_push_settlement_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

pub(in crate::cp) const AMBIGUOUS_ERROR_CODE: &str = "provider_outcome_ambiguous_v1";

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// Complete pre-send evidence for one due push row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) struct PushDeliverySnapshot {
    pub(in crate::cp) rowid: i64,
    pub(in crate::cp) episode_id: i64,
    pub(in crate::cp) installation_binding: String,
    pub(in crate::cp) delivery_version: i64,
    pub(in crate::cp) delivery_id: String,
    pub(in crate::cp) handoff_handle: String,
    pub(in crate::cp) collapse_id: String,
    pub(in crate::cp) state: String,
    pub(in crate::cp) attempt_count: i64,
    pub(in crate::cp) next_attempt_at: String,
    pub(in crate::cp) response_status: Option<i64>,
    pub(in crate::cp) error_code: Option<String>,
    pub(in crate::cp) created_at: String,
    pub(in crate::cp) updated_at: String,
}

impl PushDeliverySnapshot {
    pub(in crate::cp) fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            rowid: row.get(0)?,
            episode_id: row.get(1)?,
            installation_binding: row.get(2)?,
            delivery_version: row.get(3)?,
            delivery_id: row.get(4)?,
            handoff_handle: row.get(5)?,
            collapse_id: row.get(6)?,
            state: row.get(7)?,
            attempt_count: row.get(8)?,
            next_attempt_at: row.get(9)?,
            response_status: row.get(10)?,
            error_code: row.get(11)?,
            created_at: row.get(12)?,
            updated_at: row.get(13)?,
        })
    }

    /// Validate only the bounded, exact evidence needed to identify and CAS a
    /// stored row. This deliberately does not pronounce the row sendable:
    /// malformed but targetable pending rows must still be terminal-cancellable
    /// without incrementing an attempt or reaching the provider.
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

    /// Classify deterministic poison before a send claim is constructed. An
    /// error means the row lacks bounded identity/evidence and therefore is
    /// observable but not safe to charge or mutate automatically.
    pub(in crate::cp) fn send_admission_refusal(&self) -> Result<Option<&'static str>> {
        self.validate_stored_predecessor()?;
        if self.delivery_id.is_empty()
            || self.delivery_id.len() > MAX_ID_BYTES
            || self.installation_binding.len() > MAX_ID_BYTES
            || self.handoff_handle.len() > MAX_ID_BYTES
            || self.collapse_id.len() > MAX_ID_BYTES
            || self.state.len() > MAX_TEXT_BYTES
            || self.next_attempt_at.len() > MAX_TIMESTAMP_BYTES
            || self.created_at.len() > MAX_TIMESTAMP_BYTES
            || self.updated_at.len() > MAX_TIMESTAMP_BYTES
            || self
                .error_code
                .as_deref()
                .is_some_and(|value| value.len() > MAX_TEXT_BYTES)
        {
            return Ok(Some("delivery_malformed"));
        }
        if crate::cp::push::PushInstallationBinding::parse(&self.installation_binding).is_none() {
            return Ok(Some("activation_ineligible"));
        }
        if self.episode_id <= 0
            || self.delivery_version <= 0
            || !valid_uuid(&self.delivery_id)
            || !valid_handoff(&self.handoff_handle)
            || !valid_uuid(&self.collapse_id)
        {
            return Ok(Some("delivery_malformed"));
        }
        if self.attempt_count < 0 {
            return Ok(Some("attempt_count_invalid"));
        }
        if self.attempt_count >= MAX_ATTEMPTS {
            return Ok(Some("attempt_cap"));
        }
        if !valid_timestamp(&self.next_attempt_at)
            || !valid_timestamp(&self.created_at)
            || !valid_timestamp(&self.updated_at)
            || self
                .response_status
                .is_some_and(|status| !(100..=599).contains(&status))
            || !valid_optional_text(self.error_code.as_deref())
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
        hash_field(&mut hasher, self.installation_binding.as_bytes())?;
        hash_i64(&mut hasher, self.delivery_version);
        hash_field(&mut hasher, self.delivery_id.as_bytes())?;
        hash_field(&mut hasher, self.handoff_handle.as_bytes())?;
        hash_field(&mut hasher, self.collapse_id.as_bytes())?;
        hash_field(&mut hasher, self.state.as_bytes())?;
        hash_i64(&mut hasher, self.attempt_count);
        hash_field(&mut hasher, self.next_attempt_at.as_bytes())?;
        hash_optional_i64(&mut hasher, self.response_status);
        hash_optional_text(&mut hasher, self.error_code.as_deref())?;
        hash_field(&mut hasher, self.created_at.as_bytes())?;
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        nonzero_digest(hasher)
    }

    /// SQLite rowids may change under VACUUM. Durable identity therefore
    /// binds every stored column but deliberately excludes rowid; rowid is
    /// only a lookup/CAS optimization and must always be followed by this
    /// complete comparison.
    pub(super) fn same_stored_contents(&self, other: &Self) -> bool {
        self.episode_id == other.episode_id
            && self.installation_binding == other.installation_binding
            && self.delivery_version == other.delivery_version
            && self.delivery_id == other.delivery_id
            && self.handoff_handle == other.handoff_handle
            && self.collapse_id == other.collapse_id
            && self.state == other.state
            && self.attempt_count == other.attempt_count
            && self.next_attempt_at == other.next_attempt_at
            && self.response_status == other.response_status
            && self.error_code == other.error_code
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) enum PushSettlementKind {
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
    TokenTerminal {
        status: i64,
        code: String,
    },
    Ambiguous,
}

impl PushSettlementKind {
    fn tag(&self) -> u8 {
        match self {
            Self::Cancel { .. } => 1,
            Self::Accepted { .. } => 2,
            Self::Retry { .. } => 3,
            Self::Failed { .. } => 4,
            Self::Ambiguous => 5,
            Self::Defer { .. } => 6,
            Self::TokenTerminal { .. } => 7,
        }
    }
}

pub(crate) struct PushDeliverySettlementPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    predecessor: PushDeliverySnapshot,
    claim: Option<PushSendClaim>,
    kind: PushSettlementKind,
    target: PushDeliverySnapshot,
    committed_at: String,
}

impl PushDeliverySettlementPlan {
    pub(in crate::cp) fn new(
        account_id: String,
        predecessor: PushDeliverySnapshot,
        claim: Option<PushSendClaim>,
        kind: PushSettlementKind,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        predecessor.validate_stored_predecessor()?;
        validate_timestamp(&committed_at)?;

        match (&claim, &kind) {
            (None, PushSettlementKind::Cancel { code }) => {
                validate_text(code)?;
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
                    PushSettlementKind::Cancel { code }
                    | PushSettlementKind::Failed { code, .. }
                    | PushSettlementKind::TokenTerminal { code, .. } => validate_text(code)?,
                    PushSettlementKind::Retry {
                        status,
                        code,
                        retry_at,
                    } => {
                        if claim.send_attempt() >= MAX_ATTEMPTS {
                            return Err(WalIdempotencyError::Limit);
                        }
                        validate_status(*status)?;
                        validate_text(code)?;
                        validate_timestamp(retry_at)?;
                        if timestamp_millis(retry_at)? < timestamp_millis(&committed_at)? {
                            return Err(WalIdempotencyError::Malformed);
                        }
                    }
                    PushSettlementKind::Defer { code, retry_at } => {
                        validate_text(code)?;
                        validate_timestamp(retry_at)?;
                        if timestamp_millis(retry_at)? < timestamp_millis(&committed_at)? {
                            return Err(WalIdempotencyError::Malformed);
                        }
                    }
                    PushSettlementKind::Accepted { status } => {
                        validate_status(Some(*status))?;
                    }
                    PushSettlementKind::Ambiguous => {}
                }
                if let PushSettlementKind::Failed { status, .. } = kind {
                    validate_status(*status)?;
                }
                if let PushSettlementKind::TokenTerminal { status, .. } = kind {
                    validate_status(Some(*status))?;
                }
            }
        }

        let target = target_snapshot(&predecessor, claim.as_ref(), &kind, &committed_at)?;
        let predecessor_commitment = predecessor.commitment()?;
        let claim_commitment = match &claim {
            Some(claim) => claim.commitment()?.to_vec(),
            None => Vec::new(),
        };
        let target_commitment = target_commitment(&target)?;
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
            WalLogicalOperationId::from_stable_source(WalOperationKind::PushDelivery, &source)?;
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

    pub(in crate::cp) fn apply_direct(&self, transaction: &Transaction<'_>) -> Result<()> {
        self.apply(transaction).and_then(|result| {
            self.validate_replay(&result)?;
            Ok(())
        })
    }

    fn apply_exact(&self, transaction: &Transaction<'_>) -> Result<()> {
        let current = load_current_candidate(transaction, &self.predecessor, &self.target)?;
        if self.claim.is_none()
            && claim::load_open_claim(transaction, &self.predecessor.delivery_id)?.is_some()
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
                "UPDATE push_deliveries
                 SET state=?1,attempt_count=?2,next_attempt_at=?3,response_status=?4,
                     error_code=?5,updated_at=?6
                 WHERE rowid=?7 AND episode_id=?8 AND installation_id=?9 AND delivery_version=?10
                   AND delivery_id=?11 AND handoff_handle=?12 AND collapse_id=?13
                   AND state=?14 AND attempt_count=?15 AND next_attempt_at=?16
                   AND response_status IS ?17 AND error_code IS ?18
                   AND created_at=?19 AND updated_at=?20",
                params![
                    self.target.state,
                    self.target.attempt_count,
                    self.target.next_attempt_at,
                    self.target.response_status,
                    self.target.error_code,
                    self.target.updated_at,
                    current.rowid,
                    self.predecessor.episode_id,
                    self.predecessor.installation_binding,
                    self.predecessor.delivery_version,
                    self.predecessor.delivery_id,
                    self.predecessor.handoff_handle,
                    self.predecessor.collapse_id,
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
                self.target.error_code.as_deref(),
                &self.committed_at,
            )?;
        }
        let settled = load_delivery_snapshot_by_rowid(transaction, current.rowid)?
            .ok_or(WalIdempotencyError::Corrupt)?;
        if !settled.same_stored_contents(&self.target) {
            return Err(WalIdempotencyError::Corrupt);
        }
        if let Some(claim) = &self.claim {
            claim::require_settled_claim(
                transaction,
                claim,
                claim_outcome(&self.kind),
                self.target.response_status,
                self.target.error_code.as_deref(),
                &self.committed_at,
            )?;
        }
        Ok(())
    }
}

pub(crate) struct PushDeliverySettlementLedger;

impl WalLogicalDomainPlan for PushDeliverySettlementPlan {
    type Ledger = PushDeliverySettlementLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::PushDelivery
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(256));
        request.extend_from_slice(&REQUEST_V2.to_be_bytes());
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
        request.extend_from_slice(&target_commitment(&self.target)?);
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

impl WalLogicalDomainLedger<PushDeliverySettlementPlan> for PushDeliverySettlementLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<PushDeliverySettlementPlan>,
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
                 FROM archive_v3_wal_push_settlement_operations
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
        let kind = WalOperationKind::PushDelivery;
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
        prepared: &PreparedLogicalMutation<PushDeliverySettlementPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::PushDelivery;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_push_settlement_operations
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
                "UPDATE archive_v3_wal_push_settlement_state
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
        Ok(LogicalMutationResult::Applied(result))
    }
}

pub(super) fn target_snapshot(
    predecessor: &PushDeliverySnapshot,
    claim: Option<&PushSendClaim>,
    kind: &PushSettlementKind,
    committed_at: &str,
) -> Result<PushDeliverySnapshot> {
    let mut target = predecessor.clone();
    target.attempt_count = if matches!(
        kind,
        PushSettlementKind::Cancel { .. } | PushSettlementKind::Defer { .. }
    ) {
        predecessor.attempt_count
    } else {
        claim
            .map(PushSendClaim::send_attempt)
            .unwrap_or(predecessor.attempt_count)
    };
    target.updated_at = committed_at.to_owned();
    target.next_attempt_at = committed_at.to_owned();
    match kind {
        PushSettlementKind::Cancel { code } => {
            target.state = "cancelled".into();
            target.response_status = None;
            target.error_code = Some(code.clone());
        }
        PushSettlementKind::Accepted { status } => {
            target.state = "accepted".into();
            target.response_status = Some(*status);
            target.error_code = None;
        }
        PushSettlementKind::Retry {
            status,
            code,
            retry_at,
        } => {
            target.state = "retry".into();
            target.response_status = *status;
            target.error_code = Some(code.clone());
            target.next_attempt_at = retry_at.clone();
        }
        PushSettlementKind::Defer { code, retry_at } => {
            target.state = "retry".into();
            target.response_status = None;
            target.error_code = Some(code.clone());
            target.next_attempt_at = retry_at.clone();
        }
        PushSettlementKind::Failed { status, code } => {
            target.state = "failed".into();
            target.response_status = *status;
            target.error_code = Some(code.clone());
        }
        PushSettlementKind::TokenTerminal { status, code } => {
            target.state = "failed".into();
            target.response_status = Some(*status);
            target.error_code = Some(code.clone());
        }
        PushSettlementKind::Ambiguous => {
            target.state = "failed".into();
            target.response_status = None;
            target.error_code = Some(AMBIGUOUS_ERROR_CODE.into());
        }
    }
    validate_target(&target)?;
    Ok(target)
}

fn validate_target(target: &PushDeliverySnapshot) -> Result<()> {
    target.validate_exact_evidence()?;
    if !matches!(
        target.state.as_str(),
        "retry" | "accepted" | "cancelled" | "failed"
    ) || !valid_timestamp(&target.next_attempt_at)
        || !valid_timestamp(&target.updated_at)
        || !valid_optional_text(target.error_code.as_deref())
    {
        return Err(WalIdempotencyError::Malformed);
    }
    validate_status(target.response_status)
}

fn target_commitment(target: &PushDeliverySnapshot) -> Result<[u8; 32]> {
    validate_target(target)?;
    let mut hasher = Sha256::new();
    hash_i64(&mut hasher, target.episode_id);
    hash_field(&mut hasher, target.installation_binding.as_bytes())?;
    hash_i64(&mut hasher, target.delivery_version);
    hash_field(&mut hasher, target.delivery_id.as_bytes())?;
    hash_field(&mut hasher, target.handoff_handle.as_bytes())?;
    hash_field(&mut hasher, target.collapse_id.as_bytes())?;
    hash_field(&mut hasher, target.state.as_bytes())?;
    hash_i64(&mut hasher, target.attempt_count);
    hash_field(&mut hasher, target.next_attempt_at.as_bytes())?;
    hash_optional_i64(&mut hasher, target.response_status);
    hash_optional_text(&mut hasher, target.error_code.as_deref())?;
    hash_field(&mut hasher, target.created_at.as_bytes())?;
    hash_field(&mut hasher, target.updated_at.as_bytes())?;
    nonzero_digest(hasher)
}

fn claim_outcome(kind: &PushSettlementKind) -> PushClaimOutcome {
    match kind {
        PushSettlementKind::Cancel { .. } => PushClaimOutcome::Cancelled,
        PushSettlementKind::Accepted { .. } => PushClaimOutcome::Accepted,
        PushSettlementKind::Retry { .. } => PushClaimOutcome::Rejected,
        PushSettlementKind::Defer { .. } => PushClaimOutcome::Deferred,
        PushSettlementKind::Failed { .. } => PushClaimOutcome::Failed,
        PushSettlementKind::TokenTerminal { .. } => PushClaimOutcome::TokenTerminal,
        PushSettlementKind::Ambiguous => PushClaimOutcome::Ambiguous,
    }
}

pub(super) fn load_delivery_snapshot(
    connection: &Connection,
    delivery_id: &str,
) -> Result<Option<PushDeliverySnapshot>> {
    connection
        .query_row(
            "SELECT rowid,episode_id,installation_id,delivery_version,delivery_id,handoff_handle,
                    collapse_id,state,attempt_count,next_attempt_at,response_status,error_code,
                    created_at,updated_at
             FROM push_deliveries WHERE delivery_id=?1",
            [delivery_id],
            PushDeliverySnapshot::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_delivery_snapshot_by_rowid(
    connection: &Connection,
    rowid: i64,
) -> Result<Option<PushDeliverySnapshot>> {
    connection
        .query_row(
            "SELECT rowid,episode_id,installation_id,delivery_version,delivery_id,handoff_handle,
                    collapse_id,state,attempt_count,next_attempt_at,response_status,error_code,
                    created_at,updated_at
             FROM push_deliveries WHERE rowid=?1",
            [rowid],
            PushDeliverySnapshot::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_current_candidate(
    connection: &Connection,
    predecessor: &PushDeliverySnapshot,
    target: &PushDeliverySnapshot,
) -> Result<PushDeliverySnapshot> {
    if let Some(current) = load_delivery_snapshot_by_rowid(connection, predecessor.rowid)? {
        if current.same_stored_contents(predecessor) || current.same_stored_contents(target) {
            return Ok(current);
        }
    }
    if let Some(current) = load_delivery_snapshot(connection, &predecessor.delivery_id)? {
        if current.same_stored_contents(predecessor) || current.same_stored_contents(target) {
            return Ok(current);
        }
    }
    Err(WalIdempotencyError::Precondition)
}

fn require_kind(prepared: &PreparedLogicalMutation<PushDeliverySettlementPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::PushDelivery)
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
                    "CREATE TABLE archive_v3_wal_push_settlement_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_push_settlement_operations (
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
                     CREATE TABLE archive_v3_wal_push_settlement_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_push_settlement_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_push_settlement_state
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
             FROM archive_v3_wal_push_settlement_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::PushDelivery.codec_version()),
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
             FROM archive_v3_wal_push_settlement_state WHERE singleton=1",
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

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn valid_handoff(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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

fn validate_timestamp(value: &str) -> Result<()> {
    valid_timestamp(value)
        .then_some(())
        .ok_or(WalIdempotencyError::Malformed)
}

fn validate_status(value: Option<i64>) -> Result<()> {
    if value.is_some_and(|status| !(100..=599).contains(&status)) {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn valid_optional_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| validate_text(value).is_ok())
}

fn nonzero_digest(hasher: Sha256) -> Result<[u8; 32]> {
    let digest: [u8; 32] = hasher.finalize().into();
    (digest != [0; 32])
        .then_some(digest)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_be_bytes());
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

fn hash_optional_i64(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        None => hasher.update([0]),
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
    }
}

fn hash_optional_text(hasher: &mut Sha256, value: Option<&str>) -> Result<()> {
    match value {
        None => hasher.update([0]),
        Some(value) => {
            hasher.update([1]);
            hash_field(hasher, value.as_bytes())?;
        }
    }
    Ok(())
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
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use crate::cp::push::wal::claim::{PushSendClaimDisposition, PushSendClaimPlan};

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const DELIVERY: &str = "22222222-2222-4222-8222-222222222222";
    const CLAIM: &str = "44444444-4444-4444-8444-444444444444";
    const STARTED: &str = "2026-08-20T20:00:00.000Z";
    const COMMITTED: &str = "2026-08-20T20:00:01.000Z";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE push_deliveries (
                    episode_id INTEGER NOT NULL,
                    installation_id TEXT NOT NULL,
                    delivery_version INTEGER NOT NULL,
                    delivery_id TEXT NOT NULL UNIQUE,
                    handoff_handle TEXT NOT NULL,
                    collapse_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    next_attempt_at TEXT NOT NULL,
                    response_status INTEGER,
                    error_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (episode_id,installation_id,delivery_version)
                 );
                 INSERT INTO push_deliveries VALUES (
                    5,'p1:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:7',1,
                    '22222222-2222-4222-8222-222222222222',
                    'hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh',
                    '33333333-3333-4333-8333-333333333333','pending',0,
                    '2026-08-20T19:30:00.000Z',NULL,NULL,
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z');",
            )
            .unwrap();
    }

    fn snapshot(connection: &Connection) -> PushDeliverySnapshot {
        load_delivery_snapshot(connection, DELIVERY)
            .unwrap()
            .unwrap()
    }

    fn claim(connection: &mut Connection) -> PushSendClaim {
        let predecessor = snapshot(connection);
        let plan =
            PushSendClaimPlan::new(ACCOUNT.into(), CLAIM.into(), predecessor, STARTED.into())
                .unwrap();
        let prepared = PreparedLogicalMutation::prepare(plan).unwrap();
        let outcome = execute_prepared_for_owner(connection, prepared).unwrap();
        assert_eq!(outcome.disposition(), LogicalMutationDisposition::Applied);
        let output = outcome.into_validated_result().release().unwrap();
        assert_eq!(output, PushSendClaimDisposition::Authorized);
        claim::load_open_claim(connection, DELIVERY)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn complete_snapshot_and_claim_settle_exactly_and_replay() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        install_schema(&connection);
        let predecessor = snapshot(&connection);
        let claim = claim(&mut connection);
        connection
            .execute(
                "UPDATE push_deliveries SET rowid=rowid+100 WHERE delivery_id=?1",
                [DELIVERY],
            )
            .unwrap();
        let relocated = snapshot(&connection);
        assert_ne!(relocated.rowid, predecessor.rowid);
        assert!(relocated.same_stored_contents(&predecessor));
        let plan = PushDeliverySettlementPlan::new(
            ACCOUNT.into(),
            relocated.clone(),
            Some(claim.clone()),
            PushSettlementKind::Accepted { status: 200 },
            COMMITTED.into(),
        )
        .unwrap();
        let replay = PushDeliverySettlementPlan::new(
            ACCOUNT.into(),
            relocated,
            Some(claim),
            PushSettlementKind::Accepted { status: 200 },
            COMMITTED.into(),
        )
        .unwrap();
        let first = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan).unwrap(),
        )
        .unwrap();
        assert_eq!(first.disposition(), LogicalMutationDisposition::Applied);
        let second = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(replay).unwrap(),
        )
        .unwrap();
        assert_eq!(second.disposition(), LogicalMutationDisposition::Replayed);
        let settled = load_delivery_snapshot(&connection, DELIVERY)
            .unwrap()
            .unwrap();
        assert_eq!(settled.state, "accepted");
        assert_eq!(settled.attempt_count, 1);
        assert_eq!(settled.response_status, Some(200));
        connection
            .execute(
                "DELETE FROM push_deliveries WHERE rowid=?1",
                [settled.rowid],
            )
            .unwrap();
        let claim_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM archive_v3_wal_push_send_claims",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            claim_count, 0,
            "delivery lifecycle must cascade claim evidence"
        );
    }

    #[test]
    fn recovery_refuses_claim_receipt_fields_that_disagree_with_the_exact_target() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        install_schema(&connection);
        let predecessor = snapshot(&connection);
        let claim = claim(&mut connection);
        let plan = PushDeliverySettlementPlan::new(
            ACCOUNT.into(),
            predecessor,
            Some(claim),
            PushSettlementKind::Accepted { status: 200 },
            COMMITTED.into(),
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            claim::load_claim_recovery(&connection, CLAIM).unwrap(),
            Some(claim::PushClaimRecovery::Accepted { status: 200, .. })
        ));
        connection
            .execute(
                "UPDATE archive_v3_wal_push_send_claims SET provider_error='stale-extra-field' \
                 WHERE claim_id=?1",
                [CLAIM],
            )
            .unwrap();
        assert_eq!(
            claim::load_claim_recovery(&connection, CLAIM),
            Err(WalIdempotencyError::Corrupt)
        );
    }

    #[test]
    fn live_claim_blocks_delete_and_reinsert_until_exact_settlement() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        install_schema(&connection);
        let claim = claim(&mut connection);
        assert!(connection
            .execute(
                "DELETE FROM push_deliveries WHERE delivery_id=?1",
                [DELIVERY],
            )
            .is_err());
        let predecessor = snapshot(&connection);
        let plan = PushDeliverySettlementPlan::new(
            ACCOUNT.into(),
            predecessor,
            Some(claim),
            PushSettlementKind::Accepted { status: 200 },
            COMMITTED.into(),
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan).unwrap(),
        )
        .unwrap();
        assert_eq!(
            connection
                .execute(
                    "DELETE FROM push_deliveries WHERE delivery_id=?1",
                    [DELIVERY],
                )
                .unwrap(),
            1
        );
        connection
            .execute_batch(
                "INSERT INTO push_deliveries VALUES (
                    5,'p1:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:7',1,
                    '22222222-2222-4222-8222-222222222222',
                    'hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh',
                    '33333333-3333-4333-8333-333333333333','pending',0,
                    '2026-08-20T19:30:00.000Z',NULL,NULL,
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z');",
            )
            .unwrap();
    }

    #[test]
    fn stale_nullable_or_immutable_evidence_cannot_overwrite() {
        let mut connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        let predecessor = snapshot(&connection);
        let plan = PushDeliverySettlementPlan::new(
            ACCOUNT.into(),
            predecessor,
            None,
            PushSettlementKind::Cancel {
                code: "activation_ineligible".into(),
            },
            COMMITTED.into(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE push_deliveries SET response_status=503 WHERE delivery_id=?1",
                [DELIVERY],
            )
            .unwrap();
        let result = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan).unwrap(),
        );
        assert!(matches!(result, Err(WalIdempotencyError::Precondition)));
    }

    #[test]
    fn claimless_provider_free_settlement_refuses_a_live_claim() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        install_schema(&connection);
        let predecessor = snapshot(&connection);
        let live_claim = claim(&mut connection);
        let plan = PushDeliverySettlementPlan::new(
            ACCOUNT.into(),
            predecessor.clone(),
            None,
            PushSettlementKind::Cancel {
                code: "delivery_expired".into(),
            },
            COMMITTED.into(),
        )
        .unwrap();
        assert!(matches!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            ),
            Err(WalIdempotencyError::Precondition)
        ));
        assert!(snapshot(&connection).same_stored_contents(&predecessor));
        assert_eq!(
            claim::load_open_claim(&connection, DELIVERY).unwrap(),
            Some(live_claim)
        );
    }

    #[test]
    fn targetable_poison_cancels_without_attempt_charge_and_unpins_the_lane() {
        let cases = [
            (
                "malformed identity",
                "UPDATE push_deliveries SET collapse_id='not-a-uuid' WHERE delivery_id='22222222-2222-4222-8222-222222222222'",
                Some("delivery_malformed"),
                "delivery_malformed",
            ),
            (
                "malformed stored timestamp",
                "UPDATE push_deliveries SET updated_at='not-a-time' WHERE delivery_id='22222222-2222-4222-8222-222222222222'",
                Some("delivery_malformed"),
                "delivery_malformed",
            ),
            (
                "legacy bare installation",
                "UPDATE push_deliveries SET installation_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' WHERE delivery_id='22222222-2222-4222-8222-222222222222'",
                Some("activation_ineligible"),
                "activation_ineligible",
            ),
            (
                "negative attempt",
                "UPDATE push_deliveries SET attempt_count=-1 WHERE delivery_id='22222222-2222-4222-8222-222222222222'",
                Some("attempt_count_invalid"),
                "attempt_count_invalid",
            ),
            (
                "attempt cap",
                "UPDATE push_deliveries SET attempt_count=10 WHERE delivery_id='22222222-2222-4222-8222-222222222222'",
                Some("attempt_cap"),
                "attempt_cap",
            ),
            (
                "attempt cap plus one",
                "UPDATE push_deliveries SET attempt_count=11 WHERE delivery_id='22222222-2222-4222-8222-222222222222'",
                Some("attempt_cap"),
                "attempt_cap",
            ),
            (
                "attempt i64 max",
                "UPDATE push_deliveries SET attempt_count=9223372036854775807 WHERE delivery_id='22222222-2222-4222-8222-222222222222'",
                Some("attempt_cap"),
                "attempt_cap",
            ),
            (
                "expired but otherwise sendable",
                "UPDATE push_deliveries SET created_at='2026-08-19T19:00:00.000Z' WHERE delivery_id='22222222-2222-4222-8222-222222222222'",
                None,
                "delivery_expired",
            ),
            (
                "generation mismatch but otherwise sendable",
                "UPDATE push_deliveries SET installation_id='p1:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:8' WHERE delivery_id='22222222-2222-4222-8222-222222222222'",
                None,
                "token_generation_changed",
            ),
        ];

        for (name, mutation, expected_refusal, cancellation_code) in cases {
            let mut connection = Connection::open_in_memory().unwrap();
            install_schema(&connection);
            connection.execute_batch(mutation).unwrap();
            connection
                .execute(
                    "INSERT INTO push_deliveries VALUES (
                        6,'p1:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb:1',1,
                        '66666666-6666-4666-8666-666666666666',
                        'iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii',
                        '77777777-7777-4777-8777-777777777777','pending',0,
                        '2026-08-20T19:31:00.000Z',NULL,NULL,
                        '2026-08-20T19:01:00.000Z','2026-08-20T19:01:00.000Z')",
                    [],
                )
                .unwrap();
            let predecessor = snapshot(&connection);
            assert_eq!(
                predecessor.send_admission_refusal().unwrap(),
                expected_refusal,
                "{name}"
            );
            let original_attempt = predecessor.attempt_count;
            let plan = PushDeliverySettlementPlan::new(
                ACCOUNT.into(),
                predecessor,
                None,
                PushSettlementKind::Cancel {
                    code: cancellation_code.into(),
                },
                COMMITTED.into(),
            )
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            )
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let (state, attempt, storage_class): (String, i64, String) = connection
                .query_row(
                    "SELECT state,attempt_count,typeof(attempt_count) FROM push_deliveries
                     WHERE delivery_id=?1",
                    [DELIVERY],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(state, "cancelled", "{name}");
            assert_eq!(attempt, original_attempt, "{name}");
            assert_eq!(storage_class, "integer", "{name}");
            let next: String = connection
                .query_row(
                    "SELECT delivery_id FROM push_deliveries
                     WHERE state IN ('pending','retry')
                     ORDER BY created_at,episode_id LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(next, "66666666-6666-4666-8666-666666666666", "{name}");
        }
    }

    #[test]
    fn rowid_commitment_quarantines_absent_and_very_large_identity() {
        for (name, malformed_identity) in
            [("absent", String::new()), ("very large", "x".repeat(9_001))]
        {
            let mut connection = Connection::open_in_memory().unwrap();
            install_schema(&connection);
            let rowid = snapshot(&connection).rowid;
            connection
                .execute(
                    "UPDATE push_deliveries SET delivery_id=?1 WHERE rowid=?2",
                    params![malformed_identity, rowid],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO push_deliveries VALUES (
                        6,'p1:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb:1',1,
                        '66666666-6666-4666-8666-666666666666',
                        'iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii',
                        '77777777-7777-4777-8777-777777777777','pending',0,
                        '2026-08-20T19:31:00.000Z',NULL,NULL,
                        '2026-08-20T19:01:00.000Z','2026-08-20T19:01:00.000Z')",
                    [],
                )
                .unwrap();
            let predecessor = load_delivery_snapshot_by_rowid(&connection, rowid)
                .unwrap()
                .unwrap();
            assert_eq!(
                predecessor.send_admission_refusal().unwrap(),
                Some("delivery_malformed"),
                "{name}"
            );
            let replay = PushDeliverySettlementPlan::new(
                ACCOUNT.into(),
                predecessor.clone(),
                None,
                PushSettlementKind::Cancel {
                    code: "delivery_malformed".into(),
                },
                COMMITTED.into(),
            )
            .unwrap();
            let plan = PushDeliverySettlementPlan::new(
                ACCOUNT.into(),
                predecessor,
                None,
                PushSettlementKind::Cancel {
                    code: "delivery_malformed".into(),
                },
                COMMITTED.into(),
            )
            .unwrap();
            let canonical = plan.canonical_request().unwrap();
            assert!(canonical.len() < 256, "{name}: {}", canonical.len());
            assert!(!canonical
                .windows(malformed_identity.len().max(1))
                .any(|window| window == malformed_identity.as_bytes()));
            let first = execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            )
            .unwrap();
            assert_eq!(first.disposition(), LogicalMutationDisposition::Applied);
            let second = execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(replay).unwrap(),
            )
            .unwrap();
            assert_eq!(second.disposition(), LogicalMutationDisposition::Replayed);
            let state: String = connection
                .query_row(
                    "SELECT state FROM push_deliveries WHERE rowid=?1",
                    [rowid],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(state, "cancelled", "{name}");
            let next: String = connection
                .query_row(
                    "SELECT delivery_id FROM push_deliveries
                     WHERE state IN ('pending','retry')
                     ORDER BY created_at,episode_id LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(next, "66666666-6666-4666-8666-666666666666", "{name}");
        }
    }
}
