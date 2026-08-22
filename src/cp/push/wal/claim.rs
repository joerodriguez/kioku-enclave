//! Durable pre-send boundary for best-effort at-most-once APNs delivery.
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

use super::settlement::{
    load_delivery_snapshot, target_snapshot, PushDeliverySnapshot, PushSettlementKind,
    AMBIGUOUS_ERROR_CODE,
};

const REQUEST_V1: u16 = 1;
const RESULT_V1: u16 = 1;
const RESULT_AUTHORIZED: u8 = 1;
const RESULT_BUSY: u8 = 2;
const SUBTYPE: &[u8] = b"adr-0022-push-send-claim-v1";
const MAX_ATTEMPTS: i64 = 10;
const MAX_DEFERRED_CLAIMS_PER_ATTEMPT: i64 = 16;
#[cfg(not(test))]
pub(in crate::cp) const CLAIM_LEASE_MILLIS: i64 = 60_000;
#[cfg(test)]
pub(in crate::cp) const CLAIM_LEASE_MILLIS: i64 = 3_000;
#[cfg(not(test))]
pub(in crate::cp) const MIN_SEND_LEASE_MILLIS: i64 = 20_000;
#[cfg(test)]
pub(in crate::cp) const MIN_SEND_LEASE_MILLIS: i64 = 500;
const MAX_TEXT_BYTES: usize = 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_CANONICAL_RESULT_BYTES: usize = 3;
const SCHEMA_TABLE: &str = "archive_v3_wal_push_claim_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_push_claim_operations";
const STATE_TABLE: &str = "archive_v3_wal_push_claim_state";
pub(super) const CLAIMS_TABLE: &str = "archive_v3_wal_push_send_claims";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PushClaimOutcome {
    Started,
    Accepted,
    Rejected,
    Deferred,
    Ambiguous,
    Cancelled,
    Failed,
    TokenTerminal,
}

impl PushClaimOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Deferred => "deferred",
            Self::Ambiguous => "ambiguous",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::TokenTerminal => "token_terminal",
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
            "token_terminal" => Ok(Self::TokenTerminal),
            _ => Err(WalIdempotencyError::Corrupt),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) struct PushSendClaim {
    claim_id: String,
    predecessor: PushDeliverySnapshot,
    send_attempt: i64,
    started_at: String,
    lease_expires_at: String,
}

impl PushSendClaim {
    pub(in crate::cp) fn claim_id(&self) -> &str {
        &self.claim_id
    }

    pub(in crate::cp) fn predecessor(&self) -> &PushDeliverySnapshot {
        &self.predecessor
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

    pub(super) fn validate_for(&self, predecessor: &PushDeliverySnapshot) -> Result<()> {
        predecessor.validate_sendable()?;
        if !self.predecessor.same_stored_contents(predecessor)
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
pub(crate) enum PushSendClaimDisposition {
    Authorized,
    Busy,
    DeferredLimit,
}

pub(crate) struct PushSendClaimPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    claim: PushSendClaim,
}

impl PushSendClaimPlan {
    pub(in crate::cp) fn new(
        account_id: String,
        claim_id: String,
        predecessor: PushDeliverySnapshot,
        started_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        let send_attempt = predecessor
            .attempt_count
            .checked_add(1)
            .ok_or(WalIdempotencyError::Limit)?;
        let claim = PushSendClaim {
            claim_id,
            predecessor,
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
            WalLogicalOperationId::from_stable_source(WalOperationKind::PushDelivery, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            claim,
        })
    }

    pub(in crate::cp) fn apply_direct(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<PushSendClaimDisposition> {
        ensure_schema(transaction)?;
        decode_disposition(&self.apply(transaction)?)
    }

    fn apply_claim(&self, transaction: &Transaction<'_>) -> Result<PushSendClaimDisposition> {
        let current = load_delivery_snapshot(transaction, &self.claim.predecessor.delivery_id)?
            .ok_or(WalIdempotencyError::Precondition)?;
        if !current.same_stored_contents(&self.claim.predecessor) {
            return Err(WalIdempotencyError::Precondition);
        }
        if load_open_claim(transaction, &self.claim.predecessor.delivery_id)?.is_some() {
            return Ok(PushSendClaimDisposition::Busy);
        }
        if deferred_claim_count(
            transaction,
            &self.claim.predecessor.delivery_id,
            self.claim.send_attempt,
        )? >= MAX_DEFERRED_CLAIMS_PER_ATTEMPT
        {
            return Ok(PushSendClaimDisposition::DeferredLimit);
        }
        let predecessor = &self.claim.predecessor;
        let changed = transaction
            .execute(
                "INSERT INTO archive_v3_wal_push_send_claims
                 (claim_id,delivery_id,predecessor_rowid,episode_id,installation_binding,delivery_version,
                  handoff_handle,collapse_id,predecessor_state,predecessor_attempt_count,
                  predecessor_next_attempt_at,predecessor_response_status,
                  predecessor_error_code,predecessor_created_at,predecessor_updated_at,
                  send_attempt,started_at,lease_expires_at,outcome,provider_status,provider_error,settled_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,
                         'started',NULL,NULL,NULL)",
                params![
                    self.claim.claim_id,
                    predecessor.delivery_id,
                    predecessor.rowid,
                    predecessor.episode_id,
                    predecessor.installation_binding,
                    predecessor.delivery_version,
                    predecessor.handoff_handle,
                    predecessor.collapse_id,
                    predecessor.state,
                    predecessor.attempt_count,
                    predecessor.next_attempt_at,
                    predecessor.response_status,
                    predecessor.error_code,
                    predecessor.created_at,
                    predecessor.updated_at,
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
        Ok(PushSendClaimDisposition::Authorized)
    }
}

pub(crate) struct PushSendClaimLedger;

impl WalLogicalDomainPlan for PushSendClaimPlan {
    type Ledger = PushSendClaimLedger;
    type Output = PushSendClaimDisposition;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::PushDelivery
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

impl WalLogicalDomainLedger<PushSendClaimPlan> for PushSendClaimLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<PushSendClaimPlan>,
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
                 FROM archive_v3_wal_push_claim_operations WHERE operation_id=?1",
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
        prepared: &PreparedLogicalMutation<PushSendClaimPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        let kind = WalOperationKind::PushDelivery;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        BOUNDS.admit(row_count, result_bytes, encoded.len())?;
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_push_claim_operations
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
                "UPDATE archive_v3_wal_push_claim_state
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredClaim {
    claim: PushSendClaim,
    outcome: PushClaimOutcome,
    provider_status: Option<i64>,
    provider_error: Option<String>,
    settled_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp) enum PushClaimRecovery {
    Started(PushSendClaim),
    Accepted {
        claim: PushSendClaim,
        status: i64,
        settled_at: String,
    },
    Retry {
        claim: PushSendClaim,
        status: Option<i64>,
        code: String,
        retry_at: String,
        settled_at: String,
    },
    Deferred,
    Ambiguous {
        claim: PushSendClaim,
        settled_at: String,
    },
    Failed {
        claim: PushSendClaim,
        status: Option<i64>,
        code: String,
        settled_at: String,
    },
    TokenTerminal {
        claim: PushSendClaim,
        status: i64,
        code: String,
        settled_at: String,
    },
    Cancelled {
        claim: PushSendClaim,
        code: String,
        settled_at: String,
    },
}

impl StoredClaim {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let outcome: String = row.get(18)?;
        Ok(Self {
            claim: PushSendClaim {
                claim_id: row.get(0)?,
                predecessor: PushDeliverySnapshot {
                    delivery_id: row.get(1)?,
                    rowid: row.get(2)?,
                    episode_id: row.get(3)?,
                    installation_binding: row.get(4)?,
                    delivery_version: row.get(5)?,
                    handoff_handle: row.get(6)?,
                    collapse_id: row.get(7)?,
                    state: row.get(8)?,
                    attempt_count: row.get(9)?,
                    next_attempt_at: row.get(10)?,
                    response_status: row.get(11)?,
                    error_code: row.get(12)?,
                    created_at: row.get(13)?,
                    updated_at: row.get(14)?,
                },
                send_attempt: row.get(15)?,
                started_at: row.get(16)?,
                lease_expires_at: row.get(17)?,
            },
            outcome: PushClaimOutcome::parse(&outcome).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    18,
                    rusqlite::types::Type::Text,
                    "invalid push claim outcome".into(),
                )
            })?,
            provider_status: row.get(19)?,
            provider_error: row.get(20)?,
            settled_at: row.get(21)?,
        })
    }
}

const CLAIM_SELECT: &str =
    "SELECT claim_id,delivery_id,predecessor_rowid,episode_id,installation_binding,delivery_version,
            handoff_handle,collapse_id,predecessor_state,predecessor_attempt_count,
            predecessor_next_attempt_at,predecessor_response_status,predecessor_error_code,
            predecessor_created_at,predecessor_updated_at,send_attempt,started_at,lease_expires_at,outcome,
            provider_status,provider_error,settled_at
     FROM archive_v3_wal_push_send_claims";

pub(in crate::cp) fn claim_table_present(connection: &Connection) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [CLAIMS_TABLE],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
}

pub(in crate::cp) fn load_open_claim(
    connection: &Connection,
    delivery_id: &str,
) -> Result<Option<PushSendClaim>> {
    if !claim_table_present(connection)? {
        return Ok(None);
    }
    let sql = format!(
        "{CLAIM_SELECT} WHERE delivery_id=?1 AND outcome='started' ORDER BY send_attempt LIMIT 1"
    );
    let stored = connection
        .query_row(&sql, [delivery_id], StoredClaim::from_row)
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    stored.claim.validate_for(&stored.claim.predecessor)?;
    if stored.provider_status.is_some()
        || stored.provider_error.is_some()
        || stored.settled_at.is_some()
        || stored.outcome != PushClaimOutcome::Started
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(Some(stored.claim))
}

fn deferred_claim_count(
    connection: &Connection,
    delivery_id: &str,
    send_attempt: i64,
) -> Result<i64> {
    if !claim_table_present(connection)? {
        return Ok(0);
    }
    connection
        .query_row(
            "SELECT COUNT(*) FROM archive_v3_wal_push_send_claims
             WHERE delivery_id=?1 AND send_attempt=?2 AND outcome='deferred'",
            params![delivery_id, send_attempt],
            |row| row.get(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_claim_by_id(connection: &Connection, claim_id: &str) -> Result<Option<StoredClaim>> {
    if !claim_table_present(connection)? {
        return Ok(None);
    }
    let sql = format!("{CLAIM_SELECT} WHERE claim_id=?1");
    connection
        .query_row(&sql, [claim_id], StoredClaim::from_row)
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

pub(in crate::cp) fn load_claim_recovery(
    connection: &Connection,
    claim_id: &str,
) -> Result<Option<PushClaimRecovery>> {
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
        load_delivery_snapshot(connection, &stored.claim.predecessor.delivery_id)?
            .ok_or(WalIdempotencyError::Corrupt)
    };
    let require_target = |kind: PushSettlementKind| {
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
        PushClaimOutcome::Started => {
            if stored.provider_status.is_some()
                || stored.provider_error.is_some()
                || stored.settled_at.is_some()
            {
                return Err(WalIdempotencyError::Corrupt);
            }
            PushClaimRecovery::Started(stored.claim)
        }
        PushClaimOutcome::Accepted => {
            let status = stored.provider_status.ok_or(WalIdempotencyError::Corrupt)?;
            if stored.provider_error.is_some() {
                return Err(WalIdempotencyError::Corrupt);
            }
            require_target(PushSettlementKind::Accepted { status })?;
            PushClaimRecovery::Accepted {
                claim: stored.claim,
                status,
                settled_at: settled_at()?,
            }
        }
        PushClaimOutcome::Rejected => {
            let target = current_target()?;
            let code = code()?;
            require_target(PushSettlementKind::Retry {
                status: stored.provider_status,
                code: code.clone(),
                retry_at: target.next_attempt_at.clone(),
            })?;
            PushClaimRecovery::Retry {
                claim: stored.claim,
                status: stored.provider_status,
                code,
                retry_at: target.next_attempt_at,
                settled_at: settled_at()?,
            }
        }
        PushClaimOutcome::Deferred => {
            let target = current_target()?;
            let code = code()?;
            if stored.provider_status.is_some() {
                return Err(WalIdempotencyError::Corrupt);
            }
            require_target(PushSettlementKind::Defer {
                code,
                retry_at: target.next_attempt_at,
            })?;
            PushClaimRecovery::Deferred
        }
        PushClaimOutcome::Ambiguous => {
            if stored.provider_status.is_some()
                || stored.provider_error.as_deref() != Some(AMBIGUOUS_ERROR_CODE)
            {
                return Err(WalIdempotencyError::Corrupt);
            }
            require_target(PushSettlementKind::Ambiguous)?;
            PushClaimRecovery::Ambiguous {
                claim: stored.claim,
                settled_at: settled_at()?,
            }
        }
        PushClaimOutcome::Cancelled => {
            let code = code()?;
            if stored.provider_status.is_some() {
                return Err(WalIdempotencyError::Corrupt);
            }
            require_target(PushSettlementKind::Cancel { code: code.clone() })?;
            PushClaimRecovery::Cancelled {
                claim: stored.claim,
                code,
                settled_at: settled_at()?,
            }
        }
        PushClaimOutcome::Failed => {
            let code = code()?;
            require_target(PushSettlementKind::Failed {
                status: stored.provider_status,
                code: code.clone(),
            })?;
            PushClaimRecovery::Failed {
                claim: stored.claim,
                status: stored.provider_status,
                code,
                settled_at: settled_at()?,
            }
        }
        PushClaimOutcome::TokenTerminal => {
            let status = stored.provider_status.ok_or(WalIdempotencyError::Corrupt)?;
            let code = code()?;
            require_target(PushSettlementKind::TokenTerminal {
                status,
                code: code.clone(),
            })?;
            PushClaimRecovery::TokenTerminal {
                claim: stored.claim,
                status,
                code,
                settled_at: settled_at()?,
            }
        }
    };
    Ok(Some(recovery))
}

pub(in crate::cp) fn validate_live_send_authority(
    connection: &Connection,
    claim: &PushSendClaim,
    now_millis: i64,
) -> Result<()> {
    require_started_claim(connection, claim)?;
    let current = load_delivery_snapshot(connection, &claim.predecessor.delivery_id)?
        .ok_or(WalIdempotencyError::Precondition)?;
    if !current.same_stored_contents(&claim.predecessor) || !claim.admits_send_at(now_millis)? {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

pub(super) fn require_started_claim(connection: &Connection, claim: &PushSendClaim) -> Result<()> {
    let stored =
        load_claim_by_id(connection, &claim.claim_id)?.ok_or(WalIdempotencyError::Precondition)?;
    if stored.claim != *claim
        || stored.outcome != PushClaimOutcome::Started
        || stored.provider_status.is_some()
        || stored.provider_error.is_some()
        || stored.settled_at.is_some()
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

pub(super) fn settle_claim(
    transaction: &Transaction<'_>,
    claim: &PushSendClaim,
    outcome: PushClaimOutcome,
    provider_status: Option<i64>,
    provider_error: Option<&str>,
    settled_at: &str,
) -> Result<()> {
    if outcome == PushClaimOutcome::Started
        || !valid_timestamp(settled_at)
        || !valid_optional_text(provider_error)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    require_started_claim(transaction, claim)?;
    let predecessor = &claim.predecessor;
    let changed = transaction
        .execute(
            "UPDATE archive_v3_wal_push_send_claims
             SET outcome=?1,provider_status=?2,provider_error=?3,settled_at=?4
             WHERE claim_id=?5 AND delivery_id=?6 AND predecessor_rowid=?7 AND episode_id=?8
               AND installation_binding=?9 AND delivery_version=?10
               AND handoff_handle=?11 AND collapse_id=?12
               AND predecessor_state=?13 AND predecessor_attempt_count=?14
               AND predecessor_next_attempt_at=?15
               AND predecessor_response_status IS ?16 AND predecessor_error_code IS ?17
               AND predecessor_created_at=?18 AND predecessor_updated_at=?19
               AND send_attempt=?20 AND started_at=?21 AND lease_expires_at=?22
               AND outcome='started'
               AND provider_status IS NULL AND provider_error IS NULL AND settled_at IS NULL",
            params![
                outcome.as_str(),
                provider_status,
                provider_error,
                settled_at,
                claim.claim_id,
                predecessor.delivery_id,
                predecessor.rowid,
                predecessor.episode_id,
                predecessor.installation_binding,
                predecessor.delivery_version,
                predecessor.handoff_handle,
                predecessor.collapse_id,
                predecessor.state,
                predecessor.attempt_count,
                predecessor.next_attempt_at,
                predecessor.response_status,
                predecessor.error_code,
                predecessor.created_at,
                predecessor.updated_at,
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
        provider_error,
        settled_at,
    )
}

pub(super) fn require_settled_claim(
    connection: &Connection,
    claim: &PushSendClaim,
    outcome: PushClaimOutcome,
    provider_status: Option<i64>,
    provider_error: Option<&str>,
    settled_at: &str,
) -> Result<()> {
    let stored =
        load_claim_by_id(connection, &claim.claim_id)?.ok_or(WalIdempotencyError::Precondition)?;
    if stored.claim != *claim
        || stored.outcome != outcome
        || stored.provider_status != provider_status
        || stored.provider_error.as_deref() != provider_error
        || stored.settled_at.as_deref() != Some(settled_at)
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

fn encode_disposition(disposition: PushSendClaimDisposition) -> Result<WalReplayResult> {
    let tag = match disposition {
        PushSendClaimDisposition::Authorized => RESULT_AUTHORIZED,
        PushSendClaimDisposition::Busy => RESULT_BUSY,
        PushSendClaimDisposition::DeferredLimit => 3,
    };
    let mut bytes = Vec::with_capacity(MAX_CANONICAL_RESULT_BYTES);
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(tag);
    WalReplayResult::canonical_response(WalOperationKind::PushDelivery, bytes)
}

fn decode_disposition(result: &WalReplayResult) -> Result<PushSendClaimDisposition> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    if bytes.len() != MAX_CANONICAL_RESULT_BYTES
        || u16::from_be_bytes([bytes[0], bytes[1]]) != RESULT_V1
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    match bytes[2] {
        RESULT_AUTHORIZED => Ok(PushSendClaimDisposition::Authorized),
        RESULT_BUSY => Ok(PushSendClaimDisposition::Busy),
        3 => Ok(PushSendClaimDisposition::DeferredLimit),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn require_kind(prepared: &PreparedLogicalMutation<PushSendClaimPlan>) -> Result<()> {
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
             WHERE type='table' AND name IN (?1,?2,?3,?4)",
            params![SCHEMA_TABLE, LEDGER_TABLE, STATE_TABLE, CLAIMS_TABLE],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(LedgerSchemaState::Absent),
        4 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_push_claim_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_push_claim_operations (
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
                     CREATE TABLE archive_v3_wal_push_claim_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 33554432)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_push_send_claims (
                        claim_id TEXT PRIMARY KEY NOT NULL,
                        delivery_id TEXT NOT NULL REFERENCES push_deliveries(delivery_id) ON DELETE CASCADE,
                        predecessor_rowid INTEGER NOT NULL,
                        episode_id INTEGER NOT NULL,
                        installation_binding TEXT NOT NULL,
                        delivery_version INTEGER NOT NULL,
                        handoff_handle TEXT NOT NULL,
                        collapse_id TEXT NOT NULL,
                        predecessor_state TEXT NOT NULL CHECK(predecessor_state IN ('pending','retry')),
                        predecessor_attempt_count INTEGER NOT NULL CHECK(predecessor_attempt_count BETWEEN 0 AND 9),
                        predecessor_next_attempt_at TEXT NOT NULL,
                        predecessor_response_status INTEGER,
                        predecessor_error_code TEXT,
                        predecessor_created_at TEXT NOT NULL,
                        predecessor_updated_at TEXT NOT NULL,
                        send_attempt INTEGER NOT NULL CHECK(send_attempt BETWEEN 1 AND 10),
                        started_at TEXT NOT NULL,
                        lease_expires_at TEXT NOT NULL,
                        outcome TEXT NOT NULL CHECK(outcome IN ('started','accepted','rejected','deferred','ambiguous','cancelled','failed','token_terminal')),
                        provider_status INTEGER,
                        provider_error TEXT,
                        settled_at TEXT
                     ) STRICT;
                     CREATE UNIQUE INDEX archive_v3_wal_push_one_live_claim
                     ON archive_v3_wal_push_send_claims(delivery_id) WHERE outcome='started';
                     CREATE TRIGGER archive_v3_wal_push_live_claim_delete_guard
                     BEFORE DELETE ON push_deliveries
                     WHEN EXISTS(
                       SELECT 1 FROM archive_v3_wal_push_send_claims
                       WHERE delivery_id=OLD.delivery_id AND outcome='started'
                     )
                     BEGIN
                       SELECT RAISE(ABORT,'push delivery has a live send claim');
                     END;
                     INSERT INTO archive_v3_wal_push_claim_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_push_claim_state
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
             FROM archive_v3_wal_push_claim_schema WHERE singleton=1",
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
    let guards: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE \
             (type='index' AND name='archive_v3_wal_push_one_live_claim' \
               AND sql LIKE '%WHERE outcome=''started''%') OR \
             (type='trigger' AND name='archive_v3_wal_push_live_claim_delete_guard' \
               AND sql LIKE '%BEFORE DELETE ON push_deliveries%' \
               AND sql LIKE '%outcome=''started''%')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if guards != 2 {
        return Err(WalIdempotencyError::Corrupt);
    }
    let _ = load_ledger_state(connection)?;
    Ok(())
}

fn load_ledger_state(connection: &Connection) -> Result<(u32, u64)> {
    let state = connection
        .query_row(
            "SELECT row_count,result_bytes FROM archive_v3_wal_push_claim_state WHERE singleton=1",
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

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const CLAIM_A: &str = "44444444-4444-4444-8444-444444444444";
    const CLAIM_B: &str = "55555555-5555-4555-8555-555555555555";

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE push_deliveries (
                    episode_id INTEGER NOT NULL,installation_id TEXT NOT NULL,
                    delivery_version INTEGER NOT NULL,delivery_id TEXT NOT NULL UNIQUE,
                    handoff_handle TEXT NOT NULL,collapse_id TEXT NOT NULL,state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,next_attempt_at TEXT NOT NULL,
                    response_status INTEGER,error_code TEXT,created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL);
                 INSERT INTO push_deliveries VALUES (
                    5,'p1:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:7',1,
                    '22222222-2222-4222-8222-222222222222',
                    'hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh',
                    '33333333-3333-4333-8333-333333333333','pending',0,
                    '2026-08-20T19:30:00.000Z',NULL,NULL,
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z');",
            )
            .unwrap();
        connection
    }

    fn snapshot(connection: &Connection) -> PushDeliverySnapshot {
        load_delivery_snapshot(connection, "22222222-2222-4222-8222-222222222222")
            .unwrap()
            .unwrap()
    }

    #[test]
    fn first_random_claim_authorizes_and_competing_claim_is_busy() {
        let mut connection = connection();
        let predecessor = snapshot(&connection);
        let first = PushSendClaimPlan::new(
            ACCOUNT.into(),
            CLAIM_A.into(),
            predecessor.clone(),
            "2026-08-20T20:00:00.000Z".into(),
        )
        .unwrap();
        let outcome = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(first).unwrap(),
        )
        .unwrap();
        assert_eq!(outcome.disposition(), LogicalMutationDisposition::Applied);
        assert_eq!(
            outcome.into_validated_result().release().unwrap(),
            PushSendClaimDisposition::Authorized
        );

        let second = PushSendClaimPlan::new(
            ACCOUNT.into(),
            CLAIM_B.into(),
            predecessor,
            "2026-08-20T20:00:01.000Z".into(),
        )
        .unwrap();
        let outcome = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(second).unwrap(),
        )
        .unwrap();
        assert_eq!(
            outcome.into_validated_result().release().unwrap(),
            PushSendClaimDisposition::Busy
        );
        assert_eq!(
            load_open_claim(&connection, "22222222-2222-4222-8222-222222222222")
                .unwrap()
                .unwrap()
                .claim_id(),
            CLAIM_A
        );
    }

    #[test]
    fn deferred_claims_retry_the_same_attempt_and_stop_at_a_hard_bound() {
        let mut connection = connection();
        let predecessor = snapshot(&connection);
        for ordinal in 0..MAX_DEFERRED_CLAIMS_PER_ATTEMPT {
            let claim_id = format!("44444444-4444-4444-8444-{ordinal:012x}");
            let started_at = isotime::format_epoch_millis(
                isotime::parse_epoch_millis("2026-08-20T20:00:00.000Z").unwrap() + ordinal * 1_000,
            );
            let plan = PushSendClaimPlan::new(
                ACCOUNT.into(),
                claim_id,
                predecessor.clone(),
                started_at.clone(),
            )
            .unwrap();
            let transaction = connection.transaction().unwrap();
            assert_eq!(
                plan.apply_direct(&transaction).unwrap(),
                PushSendClaimDisposition::Authorized
            );
            let claim = load_open_claim(&transaction, &predecessor.delivery_id)
                .unwrap()
                .unwrap();
            settle_claim(
                &transaction,
                &claim,
                PushClaimOutcome::Deferred,
                None,
                Some("control_recheck_unavailable"),
                &started_at,
            )
            .unwrap();
            transaction.commit().unwrap();
        }

        let capped = PushSendClaimPlan::new(
            ACCOUNT.into(),
            "55555555-5555-4555-8555-555555555555".into(),
            predecessor,
            "2026-08-20T21:00:00.000Z".into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            capped.apply_direct(&transaction).unwrap(),
            PushSendClaimDisposition::DeferredLimit
        );
        assert!(
            load_open_claim(&transaction, "22222222-2222-4222-8222-222222222222")
                .unwrap()
                .is_none()
        );
        let count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM archive_v3_wal_push_send_claims \
                 WHERE outcome='deferred' AND send_attempt=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, MAX_DEFERRED_CLAIMS_PER_ATTEMPT);
    }
}
