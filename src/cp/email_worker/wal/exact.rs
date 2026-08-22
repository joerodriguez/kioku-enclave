//! Exact email-delivery settlement after a durable, payload-bearing send claim.
//!
//! The provider owner carries one complete due-row snapshot across the send.
//! It never substitutes a post-I/O reread, and every stored column participates
//! in adoption and CAS. Provider outcomes require the exact durable claim;
//! provider-free cancellation is allowed only when no live claim exists.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};
use crate::cp::isotime;

use super::claim::{self, EmailClaimOutcome, EmailSendClaim};

const REQUEST_V1: u16 = 1;
const SUBTYPE: &[u8] = b"adr-0022-email-delivery-exact-settlement-v1";
const MAX_ID_BYTES: usize = 96;
const MAX_PROVIDER_ID_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
pub(super) const MAX_ATTEMPTS: i64 = 10;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_email_exact_settlement_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_email_exact_settlement_operations";
const STATE_TABLE: &str = "archive_v3_wal_email_exact_settlement_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

pub(in crate::cp) const AMBIGUOUS_ERROR_CODE: &str = "provider_outcome_ambiguous_v1";

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) struct EmailDeliverySnapshot {
    pub(in crate::cp) rowid: i64,
    pub(in crate::cp) episode_id: i64,
    pub(in crate::cp) delivery_version: i64,
    pub(in crate::cp) delivery_id: String,
    pub(in crate::cp) include_content: bool,
    pub(in crate::cp) state: String,
    pub(in crate::cp) attempt_count: i64,
    pub(in crate::cp) next_attempt_at: String,
    pub(in crate::cp) provider_message_id: Option<String>,
    pub(in crate::cp) response_status: Option<i64>,
    pub(in crate::cp) error_code: Option<String>,
    pub(in crate::cp) created_at: String,
    pub(in crate::cp) updated_at: String,
}

impl EmailDeliverySnapshot {
    pub(in crate::cp) fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            rowid: row.get(0)?,
            episode_id: row.get(1)?,
            delivery_version: row.get(2)?,
            delivery_id: row.get(3)?,
            include_content: row.get::<_, i64>(4)? != 0,
            state: row.get(5)?,
            attempt_count: row.get(6)?,
            next_attempt_at: row.get(7)?,
            provider_message_id: row.get(8)?,
            response_status: row.get(9)?,
            error_code: row.get(10)?,
            created_at: row.get(11)?,
            updated_at: row.get(12)?,
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
        if self.delivery_id.is_empty()
            || self.delivery_id.len() > MAX_ID_BYTES
            || self.state.len() > MAX_TEXT_BYTES
            || self.next_attempt_at.len() > MAX_TIMESTAMP_BYTES
            || self.created_at.len() > MAX_TIMESTAMP_BYTES
            || self.updated_at.len() > MAX_TIMESTAMP_BYTES
            || self
                .provider_message_id
                .as_deref()
                .is_some_and(|value| !valid_text(value, MAX_PROVIDER_ID_BYTES))
            || self
                .error_code
                .as_deref()
                .is_some_and(|value| !valid_text(value, MAX_TEXT_BYTES))
        {
            return Ok(Some("delivery_malformed"));
        }
        if !valid_selected_delivery_id(&self.delivery_id) {
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
        if !valid_timestamp(&self.next_attempt_at)
            || !valid_timestamp(&self.created_at)
            || !valid_timestamp(&self.updated_at)
            || self
                .response_status
                .is_some_and(|status| !(100..=599).contains(&status))
            || !valid_optional_text(self.provider_message_id.as_deref(), MAX_PROVIDER_ID_BYTES)
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
        hash_i64(&mut hasher, self.delivery_version);
        hash_field(&mut hasher, self.delivery_id.as_bytes())?;
        hasher.update([u8::from(self.include_content)]);
        hash_field(&mut hasher, self.state.as_bytes())?;
        hash_i64(&mut hasher, self.attempt_count);
        hash_field(&mut hasher, self.next_attempt_at.as_bytes())?;
        hash_optional_text(
            &mut hasher,
            self.provider_message_id.as_deref(),
            MAX_PROVIDER_ID_BYTES,
        )?;
        hash_optional_i64(&mut hasher, self.response_status);
        hash_optional_text(&mut hasher, self.error_code.as_deref(), MAX_TEXT_BYTES)?;
        hash_field(&mut hasher, self.created_at.as_bytes())?;
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        nonzero_digest(hasher)
    }

    pub(super) fn same_stored_contents(&self, other: &Self) -> bool {
        self.episode_id == other.episode_id
            && self.delivery_version == other.delivery_version
            && self.delivery_id == other.delivery_id
            && self.include_content == other.include_content
            && self.state == other.state
            && self.attempt_count == other.attempt_count
            && self.next_attempt_at == other.next_attempt_at
            && self.provider_message_id == other.provider_message_id
            && self.response_status == other.response_status
            && self.error_code == other.error_code
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) enum EmailSettlementKind {
    Cancel {
        code: String,
    },
    Accepted {
        status: i64,
        provider_message_id: String,
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

impl EmailSettlementKind {
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

pub(crate) struct ExactEmailDeliverySettlementPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    predecessor: EmailDeliverySnapshot,
    claim: Option<EmailSendClaim>,
    kind: EmailSettlementKind,
    target: EmailDeliverySnapshot,
    committed_at: String,
}

impl ExactEmailDeliverySettlementPlan {
    pub(in crate::cp) fn new(
        account_id: String,
        predecessor: EmailDeliverySnapshot,
        claim: Option<EmailSendClaim>,
        kind: EmailSettlementKind,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        predecessor.validate_stored_predecessor()?;
        validate_timestamp(&committed_at)?;
        match (&claim, &kind) {
            (None, EmailSettlementKind::Cancel { code }) => {
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
                    EmailSettlementKind::Cancel { code }
                    | EmailSettlementKind::Failed { code, .. } => {
                        validate_text(code, MAX_TEXT_BYTES)?
                    }
                    EmailSettlementKind::Accepted {
                        status,
                        provider_message_id,
                    } => {
                        if !(200..=299).contains(status) {
                            return Err(WalIdempotencyError::Malformed);
                        }
                        validate_text(provider_message_id, MAX_PROVIDER_ID_BYTES)?;
                    }
                    EmailSettlementKind::Retry {
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
                    EmailSettlementKind::Defer { code, retry_at } => {
                        validate_text(code, MAX_TEXT_BYTES)?;
                        validate_timestamp(retry_at)?;
                        if timestamp_millis(retry_at)? < timestamp_millis(&committed_at)? {
                            return Err(WalIdempotencyError::Malformed);
                        }
                    }
                    EmailSettlementKind::Ambiguous => {}
                }
                if let EmailSettlementKind::Failed { status, .. } = kind {
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
            WalLogicalOperationId::from_stable_source(WalOperationKind::EmailDelivery, &source)?;
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
                    self.target.provider_message_id.as_deref(),
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
                "UPDATE email_deliveries
                 SET state=?1,attempt_count=?2,next_attempt_at=?3,provider_message_id=?4,
                     response_status=?5,error_code=?6,updated_at=?7
                 WHERE rowid=?8 AND episode_id=?9 AND delivery_version=?10
                   AND delivery_id=?11 AND include_content=?12 AND state=?13
                   AND attempt_count=?14 AND next_attempt_at=?15
                   AND provider_message_id IS ?16 AND response_status IS ?17
                   AND error_code IS ?18 AND created_at=?19 AND updated_at=?20",
                params![
                    self.target.state,
                    self.target.attempt_count,
                    self.target.next_attempt_at,
                    self.target.provider_message_id,
                    self.target.response_status,
                    self.target.error_code,
                    self.target.updated_at,
                    current.rowid,
                    self.predecessor.episode_id,
                    self.predecessor.delivery_version,
                    self.predecessor.delivery_id,
                    i64::from(self.predecessor.include_content),
                    self.predecessor.state,
                    self.predecessor.attempt_count,
                    self.predecessor.next_attempt_at,
                    self.predecessor.provider_message_id,
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
                self.target.provider_message_id.as_deref(),
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

pub(crate) struct ExactEmailDeliverySettlementLedger;

impl WalLogicalDomainPlan for ExactEmailDeliverySettlementPlan {
    type Ledger = ExactEmailDeliverySettlementLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::EmailDelivery
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainLedger<ExactEmailDeliverySettlementPlan>
    for ExactEmailDeliverySettlementLedger
{
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<ExactEmailDeliverySettlementPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,result_bytes,result_commitment
                 FROM archive_v3_wal_email_exact_settlement_operations WHERE operation_id=?1",
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
        let kind = WalOperationKind::EmailDelivery;
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
        prepared: &PreparedLogicalMutation<ExactEmailDeliverySettlementPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::EmailDelivery;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_email_exact_settlement_operations
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
                "UPDATE archive_v3_wal_email_exact_settlement_state
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
    prepared: &PreparedLogicalMutation<ExactEmailDeliverySettlementPlan>,
) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::EmailDelivery)
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
                    "CREATE TABLE archive_v3_wal_email_exact_settlement_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_email_exact_settlement_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
                        result_bytes BLOB NOT NULL CHECK(length(result_bytes)=9),
                        result_commitment BLOB NOT NULL CHECK(length(result_commitment)=32)
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_email_exact_settlement_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_email_exact_settlement_schema VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_email_exact_settlement_state VALUES (1,0,0);",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            validate_schema_marker(transaction)
        }
    }
}

fn validate_schema_marker(connection: &Connection) -> Result<()> {
    let marker = connection
        .query_row(
            "SELECT format_version,codec_version FROM archive_v3_wal_email_exact_settlement_schema
             WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::EmailDelivery.codec_version()),
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
            "SELECT row_count,result_bytes FROM archive_v3_wal_email_exact_settlement_state
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
    predecessor: &EmailDeliverySnapshot,
    claim: Option<&EmailSendClaim>,
    kind: &EmailSettlementKind,
    committed_at: &str,
) -> Result<EmailDeliverySnapshot> {
    let mut target = predecessor.clone();
    target.attempt_count = if matches!(
        kind,
        EmailSettlementKind::Cancel { .. } | EmailSettlementKind::Defer { .. }
    ) {
        predecessor.attempt_count
    } else {
        claim
            .map(EmailSendClaim::send_attempt)
            .unwrap_or(predecessor.attempt_count)
    };
    target.updated_at = committed_at.to_owned();
    target.next_attempt_at = committed_at.to_owned();
    target.provider_message_id = None;
    match kind {
        EmailSettlementKind::Cancel { code } => {
            target.state = "cancelled".into();
            target.response_status = None;
            target.error_code = Some(code.clone());
        }
        EmailSettlementKind::Accepted {
            status,
            provider_message_id,
        } => {
            target.state = "accepted".into();
            target.provider_message_id = Some(provider_message_id.clone());
            target.response_status = Some(*status);
            target.error_code = None;
        }
        EmailSettlementKind::Retry {
            status,
            code,
            retry_at,
        } => {
            target.state = "retry".into();
            target.response_status = *status;
            target.error_code = Some(code.clone());
            target.next_attempt_at = retry_at.clone();
        }
        EmailSettlementKind::Defer { code, retry_at } => {
            target.state = "retry".into();
            target.attempt_count = predecessor.attempt_count;
            target.response_status = None;
            target.error_code = Some(code.clone());
            target.next_attempt_at = retry_at.clone();
        }
        EmailSettlementKind::Failed { status, code } => {
            target.state = "failed".into();
            target.response_status = *status;
            target.error_code = Some(code.clone());
        }
        EmailSettlementKind::Ambiguous => {
            target.state = "failed".into();
            target.response_status = None;
            target.error_code = Some(AMBIGUOUS_ERROR_CODE.into());
        }
    }
    target.validate_target()?;
    Ok(target)
}

impl EmailDeliverySnapshot {
    fn validate_target(&self) -> Result<()> {
        self.validate_exact_evidence()?;
        if !matches!(
            self.state.as_str(),
            "retry" | "accepted" | "cancelled" | "failed"
        ) || self.attempt_count < 0
            || !valid_timestamp(&self.next_attempt_at)
            || !valid_timestamp(&self.updated_at)
            || !valid_optional_text(self.provider_message_id.as_deref(), MAX_PROVIDER_ID_BYTES)
            || !valid_optional_text(self.error_code.as_deref(), MAX_TEXT_BYTES)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        validate_status(self.response_status)
    }

    fn commitment_for_target(&self) -> Result<[u8; 32]> {
        self.validate_target()?;
        let mut hasher = Sha256::new();
        hash_i64(&mut hasher, self.episode_id);
        hash_i64(&mut hasher, self.delivery_version);
        hash_field(&mut hasher, self.delivery_id.as_bytes())?;
        hasher.update([u8::from(self.include_content)]);
        hash_field(&mut hasher, self.state.as_bytes())?;
        hash_i64(&mut hasher, self.attempt_count);
        hash_field(&mut hasher, self.next_attempt_at.as_bytes())?;
        hash_optional_text(
            &mut hasher,
            self.provider_message_id.as_deref(),
            MAX_PROVIDER_ID_BYTES,
        )?;
        hash_optional_i64(&mut hasher, self.response_status);
        hash_optional_text(&mut hasher, self.error_code.as_deref(), MAX_TEXT_BYTES)?;
        hash_field(&mut hasher, self.created_at.as_bytes())?;
        hash_field(&mut hasher, self.updated_at.as_bytes())?;
        nonzero_digest(hasher)
    }
}

fn claim_outcome(kind: &EmailSettlementKind) -> EmailClaimOutcome {
    match kind {
        EmailSettlementKind::Cancel { .. } => EmailClaimOutcome::Cancelled,
        EmailSettlementKind::Accepted { .. } => EmailClaimOutcome::Accepted,
        EmailSettlementKind::Retry { .. } => EmailClaimOutcome::Rejected,
        EmailSettlementKind::Defer { .. } => EmailClaimOutcome::Deferred,
        EmailSettlementKind::Failed { .. } => EmailClaimOutcome::Failed,
        EmailSettlementKind::Ambiguous => EmailClaimOutcome::Ambiguous,
    }
}

pub(super) fn load_delivery_snapshot(
    connection: &Connection,
    delivery_id: &str,
) -> Result<Option<EmailDeliverySnapshot>> {
    connection
        .query_row(
            "SELECT rowid,episode_id,delivery_version,delivery_id,include_content,state,
                    attempt_count,next_attempt_at,provider_message_id,response_status,error_code,
                    created_at,updated_at FROM email_deliveries WHERE delivery_id=?1",
            [delivery_id],
            EmailDeliverySnapshot::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_delivery_snapshot_by_rowid(
    connection: &Connection,
    rowid: i64,
) -> Result<Option<EmailDeliverySnapshot>> {
    connection
        .query_row(
            "SELECT rowid,episode_id,delivery_version,delivery_id,include_content,state,
                    attempt_count,next_attempt_at,provider_message_id,response_status,error_code,
                    created_at,updated_at FROM email_deliveries WHERE rowid=?1",
            [rowid],
            EmailDeliverySnapshot::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_current_candidate(
    connection: &Connection,
    predecessor: &EmailDeliverySnapshot,
    target: &EmailDeliverySnapshot,
) -> Result<EmailDeliverySnapshot> {
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

fn valid_selected_delivery_id(value: &str) -> bool {
    value
        .strip_prefix(super::super::SELECTED_EMAIL_DELIVERY_PREFIX)
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
    use crate::cp::email_worker::wal::claim::{
        EmailFrozenRequest, EmailSendClaimDisposition, EmailSendClaimPlan,
    };

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const DELIVERY: &str = "e1_2222222222222222222222222222222222222222222222222222222222222222";
    const CLAIM: &str = "44444444-4444-4444-8444-444444444444";
    const STARTED: &str = "2026-08-20T20:00:00.000Z";
    const COMMITTED: &str = "2026-08-20T20:00:01.000Z";

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(&format!(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE email_deliveries (
                    episode_id INTEGER NOT NULL,delivery_version INTEGER NOT NULL,
                    delivery_id TEXT NOT NULL UNIQUE,include_content INTEGER NOT NULL,
                    state TEXT NOT NULL,attempt_count INTEGER NOT NULL,
                    next_attempt_at TEXT NOT NULL,provider_message_id TEXT,
                    response_status INTEGER,error_code TEXT,created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,PRIMARY KEY(episode_id,delivery_version));
                 INSERT INTO email_deliveries VALUES (
                    5,1,'{DELIVERY}',1,'pending',0,'2026-08-20T19:30:00.000Z',
                    NULL,NULL,NULL,'2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z');"
            ))
            .unwrap();
        connection
    }

    fn snapshot(connection: &Connection) -> EmailDeliverySnapshot {
        load_delivery_snapshot(connection, DELIVERY)
            .unwrap()
            .unwrap()
    }

    fn claim(connection: &mut Connection) -> EmailSendClaim {
        let plan = EmailSendClaimPlan::new(
            ACCOUNT.into(),
            CLAIM.into(),
            snapshot(connection),
            EmailFrozenRequest::new(
                "user@example.com".into(),
                "Your Kioku brief is ready".into(),
                "immutable text".into(),
                "<p>immutable html</p>".into(),
                DELIVERY.into(),
                true,
            )
            .unwrap(),
            STARTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            plan.apply_direct(&transaction).unwrap(),
            EmailSendClaimDisposition::Authorized
        );
        transaction.commit().unwrap();
        claim::load_open_claim(connection, DELIVERY)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn complete_snapshot_and_claim_settle_actual_acceptance_exactly() {
        let mut connection = connection();
        let predecessor = snapshot(&connection);
        let claim = claim(&mut connection);
        connection
            .execute(
                "UPDATE email_deliveries SET rowid=rowid+100 WHERE delivery_id=?1",
                [DELIVERY],
            )
            .unwrap();
        let relocated = snapshot(&connection);
        assert_ne!(relocated.rowid, predecessor.rowid);
        assert!(relocated.same_stored_contents(&predecessor));
        let plan = ExactEmailDeliverySettlementPlan::new(
            ACCOUNT.into(),
            relocated,
            Some(claim),
            EmailSettlementKind::Accepted {
                status: 202,
                provider_message_id: "resend_message_1".into(),
            },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        plan.apply_direct(&transaction).unwrap();
        transaction.commit().unwrap();
        let settled = snapshot(&connection);
        assert_eq!(settled.state, "accepted");
        assert_eq!(settled.attempt_count, 1);
        assert_eq!(settled.response_status, Some(202));
        assert_eq!(
            settled.provider_message_id.as_deref(),
            Some("resend_message_1")
        );
        assert!(matches!(
            claim::load_claim_recovery(&connection, CLAIM).unwrap(),
            Some(claim::EmailClaimRecovery::Accepted { status: 202, .. })
        ));
    }

    #[test]
    fn live_claim_blocks_claimless_cancellation_and_delivery_deletion() {
        let mut connection = connection();
        let predecessor = snapshot(&connection);
        let claim = claim(&mut connection);
        assert!(connection
            .execute(
                "DELETE FROM email_deliveries WHERE delivery_id=?1",
                [DELIVERY],
            )
            .is_err());
        let cancel = ExactEmailDeliverySettlementPlan::new(
            ACCOUNT.into(),
            predecessor,
            None,
            EmailSettlementKind::Cancel {
                code: "preference_disabled".into(),
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
        let accept = ExactEmailDeliverySettlementPlan::new(
            ACCOUNT.into(),
            snapshot(&connection),
            Some(claim),
            EmailSettlementKind::Accepted {
                status: 200,
                provider_message_id: "resend_message_2".into(),
            },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        accept.apply_direct(&transaction).unwrap();
    }

    #[test]
    fn stale_mutable_predecessor_cannot_be_overwritten_or_resurrected() {
        let mut connection = connection();
        let predecessor = snapshot(&connection);
        let claim = claim(&mut connection);
        connection
            .execute(
                "UPDATE email_deliveries SET error_code='newer-state' WHERE delivery_id=?1",
                [DELIVERY],
            )
            .unwrap();
        let plan = ExactEmailDeliverySettlementPlan::new(
            ACCOUNT.into(),
            predecessor,
            Some(claim),
            EmailSettlementKind::Accepted {
                status: 200,
                provider_message_id: "resend_message_3".into(),
            },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            plan.apply_direct(&transaction),
            Err(WalIdempotencyError::Precondition)
        );
    }

    #[test]
    fn activation_ineligible_and_exhausted_rows_cancel_without_increment() {
        for (delivery_id, attempt) in [
            ("deliv_legacy_bare", 0_i64),
            (
                "e1_3333333333333333333333333333333333333333333333333333333333333333",
                MAX_ATTEMPTS,
            ),
            (
                "e1_4444444444444444444444444444444444444444444444444444444444444444",
                i64::MAX,
            ),
        ] {
            let connection = Connection::open_in_memory().unwrap();
            connection
                .execute_batch(&format!(
                    "CREATE TABLE email_deliveries (
                       episode_id INTEGER NOT NULL,delivery_version INTEGER NOT NULL,
                       delivery_id TEXT NOT NULL UNIQUE,include_content INTEGER NOT NULL,
                       state TEXT NOT NULL,attempt_count INTEGER NOT NULL,
                       next_attempt_at TEXT NOT NULL,provider_message_id TEXT,
                       response_status INTEGER,error_code TEXT,created_at TEXT NOT NULL,
                       updated_at TEXT NOT NULL,PRIMARY KEY(episode_id,delivery_version));
                     INSERT INTO email_deliveries VALUES (
                       7,1,'{delivery_id}',0,'pending',{attempt},'2026-08-20T19:30:00.000Z',
                       NULL,NULL,NULL,'2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z');"
                ))
                .unwrap();
            let predecessor = load_delivery_snapshot(&connection, delivery_id)
                .unwrap()
                .unwrap();
            assert!(predecessor.send_admission_refusal().unwrap().is_some());
            let plan = ExactEmailDeliverySettlementPlan::new(
                ACCOUNT.into(),
                predecessor,
                None,
                EmailSettlementKind::Cancel {
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
                    "SELECT state,attempt_count,typeof(attempt_count) FROM email_deliveries",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(stored, ("cancelled".into(), attempt, "integer".into()));
        }

        let delivery_id = format!("e1_{}", "5".repeat(9_001));
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE email_deliveries (
                   episode_id INTEGER NOT NULL,delivery_version INTEGER NOT NULL,
                   delivery_id TEXT NOT NULL UNIQUE,include_content INTEGER NOT NULL,
                   state TEXT NOT NULL,attempt_count INTEGER NOT NULL,
                   next_attempt_at TEXT NOT NULL,provider_message_id TEXT,
                   response_status INTEGER,error_code TEXT,created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,PRIMARY KEY(episode_id,delivery_version));",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO email_deliveries VALUES
                   (8,1,?1,0,'pending',0,'2026-08-20T19:30:00.000Z',NULL,NULL,NULL,
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z')",
                [&delivery_id],
            )
            .unwrap();
        let predecessor = load_delivery_snapshot(&connection, &delivery_id)
            .unwrap()
            .unwrap();
        let plan = ExactEmailDeliverySettlementPlan::new(
            ACCOUNT.into(),
            predecessor,
            None,
            EmailSettlementKind::Cancel {
                code: "delivery_malformed".into(),
            },
            COMMITTED.into(),
        )
        .unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        plan.apply_direct(&transaction).unwrap();
        transaction.commit().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT state FROM email_deliveries", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "cancelled"
        );
    }

    #[test]
    fn more_than_legacy_bulk_limit_cancels_as_bounded_independent_rows() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE email_deliveries (
                   episode_id INTEGER NOT NULL,delivery_version INTEGER NOT NULL,
                   delivery_id TEXT NOT NULL UNIQUE,include_content INTEGER NOT NULL,
                   state TEXT NOT NULL,attempt_count INTEGER NOT NULL,
                   next_attempt_at TEXT NOT NULL,provider_message_id TEXT,
                   response_status INTEGER,error_code TEXT,created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,PRIMARY KEY(episode_id,delivery_version));",
            )
            .unwrap();
        for ordinal in 1..=257_i64 {
            let delivery_id = format!("e1_{ordinal:064x}");
            connection
                .execute(
                    "INSERT INTO email_deliveries VALUES
                       (?1,1,?2,0,'pending',0,'2026-08-20T19:30:00.000Z',NULL,NULL,NULL,
                        '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z')",
                    params![ordinal, delivery_id],
                )
                .unwrap();
        }
        for ordinal in 1..=257_i64 {
            let delivery_id = format!("e1_{ordinal:064x}");
            let predecessor = load_delivery_snapshot(&connection, &delivery_id)
                .unwrap()
                .unwrap();
            let plan = ExactEmailDeliverySettlementPlan::new(
                ACCOUNT.into(),
                predecessor,
                None,
                EmailSettlementKind::Cancel {
                    code: "preference_disabled".into(),
                },
                COMMITTED.into(),
            )
            .unwrap();
            let transaction = connection.unchecked_transaction().unwrap();
            plan.apply_direct(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        let states: (i64, i64) = connection
            .query_row(
                "SELECT COUNT(*),SUM(state='cancelled') FROM email_deliveries",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(states, (257, 257));
    }
}
