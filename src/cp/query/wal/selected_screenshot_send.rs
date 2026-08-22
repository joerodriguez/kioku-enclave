#![allow(
    dead_code,
    reason = "inactive ADR-0022 selected-screenshot send-start marker is reviewed before provider or launcher ownership"
)]

//! Durable send-start boundary for one selected-screenshot upload. Slice 10g
//! once wired this marker to the selected route; Genesis retirement now leaves
//! it compiled and sealed with no production route owner.
//!
//! Construction requires the exact-name, DEK-authenticated ciphertext
//! candidate. This child derives one stable request identity and atomically
//! records `SendStarted` before any future provider call. It can reload only a
//! caller-named marker and its already-retained ciphertext. It cannot obtain a
//! key, enumerate work, contact a provider, classify an outcome, retry, settle
//! success/rejection, delete/list an object, call Store, launch work, or
//! acknowledge a request.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    archive_v3_wal_idempotency::{
        DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
        WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
        WalReplayResult,
    },
    crypto::Dek,
};

use super::selected_screenshot_upload::{
    authenticate_selected_screenshot_upload_candidate,
    load_authenticated_selected_screenshot_upload_candidate,
    AuthenticatedSelectedScreenshotUploadCandidate, SelectedScreenshotUploadCandidateReceipt,
};

const REQUEST_V1: u16 = 1;
const REQUEST_SELECTED_SCREENSHOT_SEND_STARTED: u8 = 5;
const RESULT_V1: u16 = 1;
const RESULT_SELECTED_SCREENSHOT_SEND_STARTED: u8 = 5;
const OPERATION_SOURCE_DOMAIN: &[u8] = b"selected-screenshot-send-started-v1\0";
const SEND_REQUEST_ID_DOMAIN: &[u8] = b"selected-screenshot-provider-request-id-v1\0";
const SEND_BINDING_DOMAIN: &[u8] = b"selected-screenshot-send-started-binding-v1\0";
const MAX_ACCOUNT_ID_BYTES: usize = 128;
const MAX_OBJECT_KEY_BYTES: usize = 512;
const SEND_REQUEST_ID_BYTES: usize = 64;
const MAX_ENCODED_RESULT_BYTES: usize = 1024;
const SCHEMA_TABLE: &str = "archive_v3_wal_selected_screenshot_send_started_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_selected_screenshot_send_started";
const STATE_TABLE: &str = "archive_v3_wal_selected_screenshot_send_started_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 256 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(PartialEq, Eq)]
pub(crate) struct SelectedScreenshotSendStartedReceipt {
    account_id: String,
    image_id: String,
    object_key: String,
    candidate_request_fingerprint: [u8; 32],
    attempt_binding_commitment: [u8; 32],
    wrapped_dek_commitment: [u8; 32],
    media_dek_binding_commitment: [u8; 32],
    aad_commitment: [u8; 32],
    ciphertext_length: u32,
    ciphertext_sha256: [u8; 32],
    candidate_binding_commitment: [u8; 32],
    send_request_id: String,
    send_binding_commitment: [u8; 32],
}

impl SelectedScreenshotSendStartedReceipt {
    pub(in crate::cp::query) fn image_id(&self) -> &str {
        &self.image_id
    }

    pub(in crate::cp::query) fn object_key(&self) -> &str {
        &self.object_key
    }

    pub(in crate::cp::query) fn send_request_id(&self) -> &str {
        &self.send_request_id
    }

    pub(in crate::cp::query) const fn send_binding_commitment(&self) -> [u8; 32] {
        self.send_binding_commitment
    }

    pub(super) fn provider_facts(&self) -> SelectedScreenshotSendProviderFacts<'_> {
        SelectedScreenshotSendProviderFacts {
            account_id: &self.account_id,
            image_id: &self.image_id,
            object_key: &self.object_key,
            candidate_request_fingerprint: self.candidate_request_fingerprint,
            attempt_binding_commitment: self.attempt_binding_commitment,
            wrapped_dek_commitment: self.wrapped_dek_commitment,
            media_dek_binding_commitment: self.media_dek_binding_commitment,
            aad_commitment: self.aad_commitment,
            ciphertext_length: self.ciphertext_length,
            ciphertext_sha256: self.ciphertext_sha256,
            candidate_binding_commitment: self.candidate_binding_commitment,
            send_request_id: &self.send_request_id,
            send_binding_commitment: self.send_binding_commitment,
        }
    }
}

pub(super) struct SelectedScreenshotSendProviderFacts<'a> {
    pub(super) account_id: &'a str,
    pub(super) image_id: &'a str,
    pub(super) object_key: &'a str,
    pub(super) candidate_request_fingerprint: [u8; 32],
    pub(super) attempt_binding_commitment: [u8; 32],
    pub(super) wrapped_dek_commitment: [u8; 32],
    pub(super) media_dek_binding_commitment: [u8; 32],
    pub(super) aad_commitment: [u8; 32],
    pub(super) ciphertext_length: u32,
    pub(super) ciphertext_sha256: [u8; 32],
    pub(super) candidate_binding_commitment: [u8; 32],
    pub(super) send_request_id: &'a str,
    pub(super) send_binding_commitment: [u8; 32],
}

impl std::fmt::Debug for SelectedScreenshotSendStartedReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedScreenshotSendStartedReceipt(<redacted>)")
    }
}

/// Exact marker plan derived only from a caller-named authenticated candidate.
/// It retains commitments and identities, never ciphertext, plaintext, or a
/// DEK.
pub(crate) struct SelectedScreenshotSendStartedPlan {
    operation_id: WalLogicalOperationId,
    candidate_receipt: SelectedScreenshotUploadCandidateReceipt,
    receipt: SelectedScreenshotSendStartedReceipt,
}

impl SelectedScreenshotSendStartedPlan {
    fn new(candidate: &AuthenticatedSelectedScreenshotUploadCandidate) -> Result<Self> {
        let account_id = candidate.account_id().to_owned();
        let candidate_receipt = candidate.receipt().clone();
        let candidate_request_fingerprint = candidate.request_fingerprint();
        if candidate_request_fingerprint == [0; 32] {
            return Err(WalIdempotencyError::Malformed);
        }
        let send_request_id = derive_send_request_id(
            &account_id,
            candidate_receipt.image_id(),
            candidate_receipt.object_key(),
            &candidate_request_fingerprint,
            &candidate_receipt.candidate_binding_commitment(),
        )?;
        let send_binding_commitment = derive_send_binding_commitment(
            &account_id,
            candidate_receipt.image_id(),
            candidate_receipt.object_key(),
            &candidate_request_fingerprint,
            &candidate_receipt,
            &send_request_id,
        )?;
        let operation_id = derive_operation_id(candidate_receipt.image_id())?;
        Ok(Self {
            operation_id,
            receipt: SelectedScreenshotSendStartedReceipt {
                account_id,
                image_id: candidate_receipt.image_id().to_owned(),
                object_key: candidate_receipt.object_key().to_owned(),
                candidate_request_fingerprint,
                attempt_binding_commitment: candidate_receipt.attempt_binding_commitment(),
                wrapped_dek_commitment: candidate_receipt.wrapped_dek_commitment(),
                media_dek_binding_commitment: candidate_receipt.media_dek_binding_commitment(),
                aad_commitment: candidate_receipt.aad_commitment(),
                ciphertext_length: candidate_receipt.ciphertext_length(),
                ciphertext_sha256: candidate_receipt.ciphertext_sha256(),
                candidate_binding_commitment: candidate_receipt.candidate_binding_commitment(),
                send_request_id,
                send_binding_commitment,
            },
            candidate_receipt,
        })
    }
}

impl Drop for SelectedScreenshotSendStartedPlan {
    fn drop(&mut self) {
        self.receipt.account_id.zeroize();
        self.receipt.image_id.zeroize();
        self.receipt.object_key.zeroize();
        self.receipt.send_request_id.zeroize();
    }
}

pub(crate) struct SelectedScreenshotSendStartedLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for SelectedScreenshotSendStartedPlan {
    type Ledger = SelectedScreenshotSendStartedLedger;
    type Output = SelectedScreenshotSendStartedReceipt;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::SelectedScreenshot
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(
            self.receipt
                .account_id
                .len()
                .saturating_add(self.receipt.image_id.len())
                .saturating_add(self.receipt.object_key.len())
                .saturating_add(self.receipt.send_request_id.len())
                .saturating_add(420),
        ));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        request.push(REQUEST_SELECTED_SCREENSHOT_SEND_STARTED);
        append_string(&mut request, &self.receipt.account_id)?;
        append_string(&mut request, &self.receipt.image_id)?;
        append_string(&mut request, &self.receipt.object_key)?;
        request.extend_from_slice(&self.receipt.candidate_request_fingerprint);
        request.extend_from_slice(&self.receipt.attempt_binding_commitment);
        request.extend_from_slice(&self.receipt.wrapped_dek_commitment);
        request.extend_from_slice(&self.receipt.media_dek_binding_commitment);
        request.extend_from_slice(&self.receipt.aad_commitment);
        request.extend_from_slice(&self.receipt.ciphertext_length.to_be_bytes());
        request.extend_from_slice(&self.receipt.ciphertext_sha256);
        request.extend_from_slice(&self.receipt.candidate_binding_commitment);
        append_string(&mut request, &self.receipt.send_request_id)?;
        request.extend_from_slice(&self.receipt.send_binding_commitment);
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        authenticate_candidate(transaction, self, true)?;
        encode_receipt(&self.receipt)
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        (decode_receipt(result)? == self.receipt)
            .then_some(())
            .ok_or(WalIdempotencyError::Corrupt)
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        let receipt = decode_receipt(result)?;
        (receipt == self.receipt)
            .then_some(receipt)
            .ok_or(WalIdempotencyError::Corrupt)
    }
}

impl WalLogicalDomainLedger<SelectedScreenshotSendStartedPlan>
    for SelectedScreenshotSendStartedLedger
{
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<SelectedScreenshotSendStartedPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let Some(result_length) = connection
            .query_row(
                "SELECT length(result_bytes)
                 FROM archive_v3_wal_selected_screenshot_send_started
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
        else {
            return Ok(None);
        };
        validate_result_length(result_length)?;
        let row = connection
            .query_row(
                "SELECT operation_id,format_version,codec_version,request_fingerprint,
                        account_id,image_id,object_key,candidate_request_fingerprint,
                        attempt_binding_commitment,wrapped_dek_commitment,
                        media_dek_binding_commitment,aad_commitment,ciphertext_length,
                        ciphertext_sha256,candidate_binding_commitment,send_request_id,
                        send_binding_commitment,result_bytes,result_commitment
                 FROM archive_v3_wal_selected_screenshot_send_started
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                StoredSendStartedRow::from_row,
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .ok_or(WalIdempotencyError::Corrupt)?;
        validate_stored_row_shape(&row)?;
        let plan = prepared.plan_for_domain_ledger();
        if row.request_fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        if !row.matches_plan(plan)
            || row.operation_id.as_slice() != derive_operation_id(&row.image_id)?.as_bytes()
            || derive_send_request_id(
                &row.account_id,
                &row.image_id,
                &row.object_key,
                &array_32(&row.candidate_request_fingerprint)?,
                &array_32(&row.candidate_binding_commitment)?,
            )? != row.send_request_id
            || derive_send_binding_commitment(
                &row.account_id,
                &row.image_id,
                &row.object_key,
                &array_32(&row.candidate_request_fingerprint)?,
                &plan.candidate_receipt,
                &row.send_request_id,
            )? != array_32(&row.send_binding_commitment)?
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        authenticate_candidate(connection, plan, false)?;
        let result =
            WalReplayResult::decode(WalOperationKind::SelectedScreenshot, &row.result_bytes)?;
        if row.result_commitment.as_slice()
            != result
                .commitment(WalOperationKind::SelectedScreenshot)?
                .as_slice()
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        plan.validate_replay(&result)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<SelectedScreenshotSendStartedPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let plan = prepared.plan_for_domain_ledger();
        let expected = encode_receipt(&plan.receipt)?;
        let expected_encoded = expected.encode(WalOperationKind::SelectedScreenshot)?;
        if expected_encoded.len() > MAX_ENCODED_RESULT_BYTES {
            return Err(WalIdempotencyError::Limit);
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, expected_encoded.len())?;
        let result = plan.apply(transaction)?;
        plan.validate_replay(&result)?;
        let encoded = result.encode(WalOperationKind::SelectedScreenshot)?;
        if encoded != expected_encoded {
            return Err(WalIdempotencyError::Corrupt);
        }
        let result_commitment = result.commitment(WalOperationKind::SelectedScreenshot)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_selected_screenshot_send_started
                 (operation_id,format_version,codec_version,request_fingerprint,
                  account_id,image_id,object_key,candidate_request_fingerprint,
                  attempt_binding_commitment,wrapped_dek_commitment,
                  media_dek_binding_commitment,aad_commitment,ciphertext_length,
                  ciphertext_sha256,candidate_binding_commitment,send_request_id,
                  send_binding_commitment,result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,
                         ?16,?17,?18,?19)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(WalOperationKind::SelectedScreenshot.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    plan.receipt.account_id,
                    plan.receipt.image_id,
                    plan.receipt.object_key,
                    plan.receipt.candidate_request_fingerprint.as_slice(),
                    plan.receipt.attempt_binding_commitment.as_slice(),
                    plan.receipt.wrapped_dek_commitment.as_slice(),
                    plan.receipt.media_dek_binding_commitment.as_slice(),
                    plan.receipt.aad_commitment.as_slice(),
                    i64::from(plan.receipt.ciphertext_length),
                    plan.receipt.ciphertext_sha256.as_slice(),
                    plan.receipt.candidate_binding_commitment.as_slice(),
                    plan.receipt.send_request_id,
                    plan.receipt.send_binding_commitment.as_slice(),
                    encoded.as_slice(),
                    result_commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_send_started_state
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

/// Exact send-ready payload for one caller-named marker. The ciphertext is
/// returned only after both the candidate and `SendStarted` ledgers have been
/// reauthenticated with the caller's already obtained plaintext DEK.
pub(super) struct AuthenticatedSelectedScreenshotSendStarted {
    receipt: SelectedScreenshotSendStartedReceipt,
    ciphertext: Zeroizing<Vec<u8>>,
}

impl AuthenticatedSelectedScreenshotSendStarted {
    pub(super) fn receipt(&self) -> &SelectedScreenshotSendStartedReceipt {
        &self.receipt
    }

    pub(super) fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }
}

impl std::fmt::Debug for AuthenticatedSelectedScreenshotSendStarted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedSelectedScreenshotSendStarted(<redacted>)")
    }
}

/// Exact-name restart loader. It cannot enumerate markers, obtain a DEK, or
/// contact the object provider.
pub(super) fn load_authenticated_selected_screenshot_send_started(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
    plaintext_dek: &Dek,
) -> Result<Option<AuthenticatedSelectedScreenshotSendStarted>> {
    let Some(candidate) = load_authenticated_selected_screenshot_upload_candidate(
        connection,
        account_id,
        image_id,
        plaintext_dek,
    )?
    else {
        return Ok(None);
    };
    let plan = SelectedScreenshotSendStartedPlan::new(&candidate)?;
    let prepared = PreparedLogicalMutation::prepare(plan)?;
    let Some(result) = SelectedScreenshotSendStartedLedger::lookup(connection, &prepared)? else {
        return Ok(None);
    };
    let receipt = decode_receipt(&result)?;
    Ok(Some(AuthenticatedSelectedScreenshotSendStarted {
        receipt,
        ciphertext: Zeroizing::new(candidate.ciphertext().to_vec()),
    }))
}

/// WAL-owned pre-marker factory. The parent can receive only the opaque plan;
/// pre-marker ciphertext remains confined to this private WAL family.
pub(super) fn prepare_selected_screenshot_send_started(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
    plaintext_dek: &Dek,
) -> Result<Option<SelectedScreenshotSendStartedPlan>> {
    let Some(candidate) = load_authenticated_selected_screenshot_upload_candidate(
        connection,
        account_id,
        image_id,
        plaintext_dek,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(SelectedScreenshotSendStartedPlan::new(&candidate)?))
}

/// Reauthenticates one exact durable marker and its candidate from the complete
/// provider binding. No DEK, ciphertext, enumeration, or provider capability
/// crosses this terminal-settlement helper.
pub(super) fn authenticate_selected_screenshot_send_provider_facts(
    connection: &Connection,
    facts: &SelectedScreenshotSendProviderFacts<'_>,
) -> Result<()> {
    let candidate_receipt = SelectedScreenshotUploadCandidateReceipt::from_terminal_facts(
        facts.image_id.to_owned(),
        facts.object_key.to_owned(),
        facts.attempt_binding_commitment,
        facts.wrapped_dek_commitment,
        facts.media_dek_binding_commitment,
        facts.aad_commitment,
        facts.ciphertext_length,
        facts.ciphertext_sha256,
        facts.candidate_binding_commitment,
    )?;
    let receipt = SelectedScreenshotSendStartedReceipt {
        account_id: facts.account_id.to_owned(),
        image_id: facts.image_id.to_owned(),
        object_key: facts.object_key.to_owned(),
        candidate_request_fingerprint: facts.candidate_request_fingerprint,
        attempt_binding_commitment: facts.attempt_binding_commitment,
        wrapped_dek_commitment: facts.wrapped_dek_commitment,
        media_dek_binding_commitment: facts.media_dek_binding_commitment,
        aad_commitment: facts.aad_commitment,
        ciphertext_length: facts.ciphertext_length,
        ciphertext_sha256: facts.ciphertext_sha256,
        candidate_binding_commitment: facts.candidate_binding_commitment,
        send_request_id: facts.send_request_id.to_owned(),
        send_binding_commitment: facts.send_binding_commitment,
    };
    let plan = SelectedScreenshotSendStartedPlan {
        operation_id: derive_operation_id(facts.image_id)?,
        candidate_receipt,
        receipt,
    };
    let prepared =
        PreparedLogicalMutation::prepare(plan).map_err(|_| WalIdempotencyError::Corrupt)?;
    SelectedScreenshotSendStartedLedger::lookup(connection, &prepared)?
        .ok_or(WalIdempotencyError::Precondition)?;
    Ok(())
}

fn authenticate_candidate(
    connection: &Connection,
    plan: &SelectedScreenshotSendStartedPlan,
    require_unconsumed: bool,
) -> Result<()> {
    authenticate_selected_screenshot_upload_candidate(
        connection,
        &plan.receipt.account_id,
        &plan.receipt.candidate_request_fingerprint,
        &plan.candidate_receipt,
        require_unconsumed,
    )
}

struct StoredSendStartedRow {
    operation_id: Vec<u8>,
    format_version: i64,
    codec_version: i64,
    request_fingerprint: Vec<u8>,
    account_id: String,
    image_id: String,
    object_key: String,
    candidate_request_fingerprint: Vec<u8>,
    attempt_binding_commitment: Vec<u8>,
    wrapped_dek_commitment: Vec<u8>,
    media_dek_binding_commitment: Vec<u8>,
    aad_commitment: Vec<u8>,
    ciphertext_length: i64,
    ciphertext_sha256: Vec<u8>,
    candidate_binding_commitment: Vec<u8>,
    send_request_id: String,
    send_binding_commitment: Vec<u8>,
    result_bytes: Vec<u8>,
    result_commitment: Vec<u8>,
}

impl StoredSendStartedRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            operation_id: row.get(0)?,
            format_version: row.get(1)?,
            codec_version: row.get(2)?,
            request_fingerprint: row.get(3)?,
            account_id: row.get(4)?,
            image_id: row.get(5)?,
            object_key: row.get(6)?,
            candidate_request_fingerprint: row.get(7)?,
            attempt_binding_commitment: row.get(8)?,
            wrapped_dek_commitment: row.get(9)?,
            media_dek_binding_commitment: row.get(10)?,
            aad_commitment: row.get(11)?,
            ciphertext_length: row.get(12)?,
            ciphertext_sha256: row.get(13)?,
            candidate_binding_commitment: row.get(14)?,
            send_request_id: row.get(15)?,
            send_binding_commitment: row.get(16)?,
            result_bytes: row.get(17)?,
            result_commitment: row.get(18)?,
        })
    }

    fn matches_plan(&self, plan: &SelectedScreenshotSendStartedPlan) -> bool {
        let receipt = &plan.receipt;
        self.operation_id.as_slice() == plan.operation_id.as_bytes()
            && self.account_id == receipt.account_id
            && self.image_id == receipt.image_id
            && self.object_key == receipt.object_key
            && self.candidate_request_fingerprint.as_slice()
                == receipt.candidate_request_fingerprint
            && self.attempt_binding_commitment.as_slice() == receipt.attempt_binding_commitment
            && self.wrapped_dek_commitment.as_slice() == receipt.wrapped_dek_commitment
            && self.media_dek_binding_commitment.as_slice() == receipt.media_dek_binding_commitment
            && self.aad_commitment.as_slice() == receipt.aad_commitment
            && self.ciphertext_length == i64::from(receipt.ciphertext_length)
            && self.ciphertext_sha256.as_slice() == receipt.ciphertext_sha256
            && self.candidate_binding_commitment.as_slice() == receipt.candidate_binding_commitment
            && self.send_request_id == receipt.send_request_id
            && self.send_binding_commitment.as_slice() == receipt.send_binding_commitment
    }
}

fn validate_stored_row_shape(row: &StoredSendStartedRow) -> Result<()> {
    validate_result_length(
        i64::try_from(row.result_bytes.len()).map_err(|_| WalIdempotencyError::Corrupt)?,
    )?;
    if row.operation_id.len() != 16
        || row.request_fingerprint.len() != 32
        || row.candidate_request_fingerprint.len() != 32
        || row.attempt_binding_commitment.len() != 32
        || row.wrapped_dek_commitment.len() != 32
        || row.media_dek_binding_commitment.len() != 32
        || row.aad_commitment.len() != 32
        || row.ciphertext_sha256.len() != 32
        || row.candidate_binding_commitment.len() != 32
        || row.send_binding_commitment.len() != 32
        || row.result_commitment.len() != 32
        || row.format_version != i64::from(WalOperationKind::format_version())
        || row.codec_version != i64::from(WalOperationKind::SelectedScreenshot.codec_version())
        || row.ciphertext_length <= 0
        || !super::valid_lower_hex(&row.send_request_id, SEND_REQUEST_ID_BYTES)
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn validate_result_length(result_length: i64) -> Result<()> {
    let result_length = usize::try_from(result_length).map_err(|_| WalIdempotencyError::Corrupt)?;
    if !(300..=MAX_ENCODED_RESULT_BYTES).contains(&result_length) {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn array_32(value: &[u8]) -> Result<[u8; 32]> {
    value.try_into().map_err(|_| WalIdempotencyError::Corrupt)
}

fn derive_operation_id(image_id: &str) -> Result<WalLogicalOperationId> {
    if !super::valid_lower_hex(image_id, 32) {
        return Err(WalIdempotencyError::Corrupt);
    }
    let mut source =
        Vec::with_capacity(OPERATION_SOURCE_DOMAIN.len().saturating_add(image_id.len()));
    source.extend_from_slice(OPERATION_SOURCE_DOMAIN);
    source.extend_from_slice(image_id.as_bytes());
    WalLogicalOperationId::from_stable_source(WalOperationKind::SelectedScreenshot, &source)
        .map_err(|_| WalIdempotencyError::Corrupt)
}

fn derive_send_request_id(
    account_id: &str,
    image_id: &str,
    object_key: &str,
    candidate_request_fingerprint: &[u8; 32],
    candidate_binding_commitment: &[u8; 32],
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(SEND_REQUEST_ID_DOMAIN);
    hash_field(&mut hasher, account_id.as_bytes())?;
    hash_field(&mut hasher, image_id.as_bytes())?;
    hash_field(&mut hasher, object_key.as_bytes())?;
    hash_field(&mut hasher, candidate_request_fingerprint)?;
    hash_field(&mut hasher, candidate_binding_commitment)?;
    let request_id = format!("{:x}", hasher.finalize());
    if !super::valid_lower_hex(&request_id, SEND_REQUEST_ID_BYTES) {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(request_id)
}

fn derive_send_binding_commitment(
    account_id: &str,
    image_id: &str,
    object_key: &str,
    candidate_request_fingerprint: &[u8; 32],
    candidate: &SelectedScreenshotUploadCandidateReceipt,
    send_request_id: &str,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(SEND_BINDING_DOMAIN);
    hash_field(&mut hasher, account_id.as_bytes())?;
    hash_field(&mut hasher, image_id.as_bytes())?;
    hash_field(&mut hasher, object_key.as_bytes())?;
    hash_field(&mut hasher, candidate_request_fingerprint)?;
    hash_field(&mut hasher, &candidate.attempt_binding_commitment())?;
    hash_field(&mut hasher, &candidate.wrapped_dek_commitment())?;
    hash_field(&mut hasher, &candidate.media_dek_binding_commitment())?;
    hash_field(&mut hasher, &candidate.aad_commitment())?;
    hash_field(&mut hasher, &candidate.ciphertext_length().to_be_bytes())?;
    hash_field(&mut hasher, &candidate.ciphertext_sha256())?;
    hash_field(&mut hasher, &candidate.candidate_binding_commitment())?;
    hash_field(&mut hasher, send_request_id.as_bytes())?;
    let commitment: [u8; 32] = hasher.finalize().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalIdempotencyError::Corrupt)
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

fn append_string(destination: &mut Vec<u8>, value: &str) -> Result<()> {
    destination.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    destination.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_receipt(receipt: &SelectedScreenshotSendStartedReceipt) -> Result<WalReplayResult> {
    let mut bytes = Vec::with_capacity(
        receipt
            .account_id
            .len()
            .saturating_add(receipt.image_id.len())
            .saturating_add(receipt.object_key.len())
            .saturating_add(receipt.send_request_id.len())
            .saturating_add(420),
    );
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(RESULT_SELECTED_SCREENSHOT_SEND_STARTED);
    append_string(&mut bytes, &receipt.account_id)?;
    append_string(&mut bytes, &receipt.image_id)?;
    append_string(&mut bytes, &receipt.object_key)?;
    bytes.extend_from_slice(&receipt.candidate_request_fingerprint);
    bytes.extend_from_slice(&receipt.attempt_binding_commitment);
    bytes.extend_from_slice(&receipt.wrapped_dek_commitment);
    bytes.extend_from_slice(&receipt.media_dek_binding_commitment);
    bytes.extend_from_slice(&receipt.aad_commitment);
    bytes.extend_from_slice(&receipt.ciphertext_length.to_be_bytes());
    bytes.extend_from_slice(&receipt.ciphertext_sha256);
    bytes.extend_from_slice(&receipt.candidate_binding_commitment);
    append_string(&mut bytes, &receipt.send_request_id)?;
    bytes.extend_from_slice(&receipt.send_binding_commitment);
    WalReplayResult::canonical_response(WalOperationKind::SelectedScreenshot, bytes)
}

fn decode_receipt(result: &WalReplayResult) -> Result<SelectedScreenshotSendStartedReceipt> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    if bytes.len() < 300
        || bytes.len() > MAX_ENCODED_RESULT_BYTES
        || bytes[0..2] != RESULT_V1.to_be_bytes()
        || bytes[2] != RESULT_SELECTED_SCREENSHOT_SEND_STARTED
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let mut offset = 3usize;
    let account_id = take_string(bytes, &mut offset, MAX_ACCOUNT_ID_BYTES)?;
    let image_id = take_string(bytes, &mut offset, 32)?;
    let object_key = take_string(bytes, &mut offset, MAX_OBJECT_KEY_BYTES)?;
    let candidate_request_fingerprint = take_array::<32>(bytes, &mut offset)?;
    let attempt_binding_commitment = take_array::<32>(bytes, &mut offset)?;
    let wrapped_dek_commitment = take_array::<32>(bytes, &mut offset)?;
    let media_dek_binding_commitment = take_array::<32>(bytes, &mut offset)?;
    let aad_commitment = take_array::<32>(bytes, &mut offset)?;
    let ciphertext_length = u32::from_be_bytes(take_array::<4>(bytes, &mut offset)?);
    let ciphertext_sha256 = take_array::<32>(bytes, &mut offset)?;
    let candidate_binding_commitment = take_array::<32>(bytes, &mut offset)?;
    let send_request_id = take_string(bytes, &mut offset, SEND_REQUEST_ID_BYTES)?;
    let send_binding_commitment = take_array::<32>(bytes, &mut offset)?;
    if offset != bytes.len()
        || !super::valid_lower_hex(&image_id, 32)
        || !super::valid_lower_hex(&send_request_id, SEND_REQUEST_ID_BYTES)
        || ciphertext_length == 0
        || [
            candidate_request_fingerprint,
            attempt_binding_commitment,
            wrapped_dek_commitment,
            media_dek_binding_commitment,
            aad_commitment,
            ciphertext_sha256,
            candidate_binding_commitment,
            send_binding_commitment,
        ]
        .contains(&[0; 32])
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(SelectedScreenshotSendStartedReceipt {
        account_id,
        image_id,
        object_key,
        candidate_request_fingerprint,
        attempt_binding_commitment,
        wrapped_dek_commitment,
        media_dek_binding_commitment,
        aad_commitment,
        ciphertext_length,
        ciphertext_sha256,
        candidate_binding_commitment,
        send_request_id,
        send_binding_commitment,
    })
}

fn take_string(bytes: &[u8], offset: &mut usize, maximum: usize) -> Result<String> {
    let length = usize::try_from(u32::from_be_bytes(take_array::<4>(bytes, offset)?))
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if length == 0 || length > maximum || bytes.len().saturating_sub(*offset) < length {
        return Err(WalIdempotencyError::Corrupt);
    }
    let end = offset
        .checked_add(length)
        .ok_or(WalIdempotencyError::Corrupt)?;
    let value = std::str::from_utf8(&bytes[*offset..end])
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .to_owned();
    *offset = end;
    Ok(value)
}

fn take_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(WalIdempotencyError::Corrupt)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(WalIdempotencyError::Corrupt)?
        .try_into()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    *offset = end;
    Ok(value)
}

fn require_kind(
    prepared: &PreparedLogicalMutation<SelectedScreenshotSendStartedPlan>,
) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::SelectedScreenshot)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
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
                    "CREATE TABLE archive_v3_wal_selected_screenshot_send_started_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_selected_screenshot_send_started (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        account_id TEXT NOT NULL,
                        image_id TEXT NOT NULL UNIQUE,
                        object_key TEXT NOT NULL UNIQUE,
                        candidate_request_fingerprint BLOB NOT NULL UNIQUE,
                        attempt_binding_commitment BLOB NOT NULL,
                        wrapped_dek_commitment BLOB NOT NULL,
                        media_dek_binding_commitment BLOB NOT NULL,
                        aad_commitment BLOB NOT NULL,
                        ciphertext_length INTEGER NOT NULL CHECK(ciphertext_length BETWEEN 1 AND 153664),
                        ciphertext_sha256 BLOB NOT NULL,
                        candidate_binding_commitment BLOB NOT NULL UNIQUE,
                        send_request_id TEXT NOT NULL UNIQUE,
                        send_binding_commitment BLOB NOT NULL UNIQUE,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(account_id) BETWEEN 1 AND 128),
                        CHECK(length(image_id)=32),
                        CHECK(length(object_key) BETWEEN 1 AND 512),
                        CHECK(length(candidate_request_fingerprint)=32 AND candidate_request_fingerprint<>zeroblob(32)),
                        CHECK(length(attempt_binding_commitment)=32 AND attempt_binding_commitment<>zeroblob(32)),
                        CHECK(length(wrapped_dek_commitment)=32 AND wrapped_dek_commitment<>zeroblob(32)),
                        CHECK(length(media_dek_binding_commitment)=32 AND media_dek_binding_commitment<>zeroblob(32)),
                        CHECK(length(aad_commitment)=32 AND aad_commitment<>zeroblob(32)),
                        CHECK(length(ciphertext_sha256)=32 AND ciphertext_sha256<>zeroblob(32)),
                        CHECK(length(candidate_binding_commitment)=32 AND candidate_binding_commitment<>zeroblob(32)),
                        CHECK(length(send_request_id)=64),
                        CHECK(length(send_binding_commitment)=32 AND send_binding_commitment<>zeroblob(32)),
                        CHECK(length(result_bytes) BETWEEN 300 AND 1024),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_selected_screenshot_send_started_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 268435456)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_selected_screenshot_send_started_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_selected_screenshot_send_started_state
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
             FROM archive_v3_wal_selected_screenshot_send_started_schema WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker
        != Some((
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::SelectedScreenshot.codec_version()),
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
             FROM archive_v3_wal_selected_screenshot_send_started_state WHERE singleton=1",
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
    let actual = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(result_bytes)),0)
             FROM archive_v3_wal_selected_screenshot_send_started",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if actual.0 != i64::from(row_count)
        || actual.1 != i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok((row_count, result_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3_wal_idempotency::{execute_prepared_for_owner, LogicalMutationDisposition},
        cp::{
            media::wal::MediaDekInstallPlan,
            query::wal::{
                selected_screenshot_attempt::{
                    authenticate_selected_screenshot_upload_predecessor,
                    SelectedScreenshotAttemptPlan,
                },
                selected_screenshot_upload::SelectedScreenshotUploadCandidatePlan,
                ValidatedJpeg,
            },
        },
    };
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};

    const ACCOUNT: &str = "account-1";
    const IMAGE_ID: &str = "11111111111111111111111111111111";
    const SOURCE_KEY: &str = "cloud-v2:screen-1";
    const CAPTURED_AT: &str = "2026-08-15T13:00:00.000Z";

    struct Fixture {
        connection: Connection,
        dek: Dek,
        object_key: String,
        ciphertext: Vec<u8>,
        jpeg: ValidatedJpeg,
    }

    fn initialize(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE app_metadata(
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                 ) STRICT, WITHOUT ROWID;
                 CREATE TABLE episodes(
                    id INTEGER PRIMARY KEY,
                    substance TEXT NOT NULL,
                    visual_evidence TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE screenshots(
                    id INTEGER PRIMARY KEY,
                    captured_at TEXT NOT NULL,
                    source_key TEXT NOT NULL UNIQUE,
                    is_duplicate INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE episode_members(
                    episode_id INTEGER NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE screenshot_images(
                    id TEXT PRIMARY KEY,
                    screenshot_id INTEGER NOT NULL,
                    episode_id INTEGER NOT NULL,
                    source_key TEXT NOT NULL UNIQUE,
                    captured_at TEXT NOT NULL,
                    object_key TEXT NOT NULL UNIQUE,
                    mime_type TEXT NOT NULL,
                    width INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    byte_length INTEGER NOT NULL,
                    sha256 TEXT NOT NULL
                 ) STRICT;
                 INSERT INTO episodes(id,substance,visual_evidence)
                    VALUES (7,'normal','useful');
                 INSERT INTO screenshots(id,captured_at,source_key,is_duplicate)
                    VALUES (41,'2026-08-15T13:00:00.000Z','cloud-v2:screen-1',0);
                 INSERT INTO episode_members(episode_id,record_type,record_id)
                    VALUES (7,'screenshot',41);",
            )
            .unwrap();
    }

    fn fixture_with_connection(mut connection: Connection) -> Fixture {
        let dek = Dek([7; 32]);
        let media_plan = MediaDekInstallPlan::new_for_cross_domain_test(
            ACCOUNT.to_owned(),
            BASE64_STANDARD.encode([9; 64]),
            &dek,
        )
        .unwrap();
        let media_receipt = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(media_plan).unwrap(),
        )
        .unwrap()
        .into_validated_result()
        .release()
        .unwrap();
        let plaintext = b"bounded-jpeg-fixture".to_vec();
        let jpeg = ValidatedJpeg {
            width: 2,
            height: 2,
            byte_length: i64::try_from(plaintext.len()).unwrap(),
            sha256: format!("{:x}", Sha256::digest(&plaintext)),
        };
        let target = authenticate_selected_screenshot_upload_predecessor(
            &connection,
            ACCOUNT,
            7,
            SOURCE_KEY,
            CAPTURED_AT,
            &jpeg,
        )
        .unwrap();
        let attempt_plan = SelectedScreenshotAttemptPlan::new(
            ACCOUNT.to_owned(),
            IMAGE_ID.to_owned(),
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            jpeg.clone(),
            target,
        )
        .unwrap();
        let attempt_receipt = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(attempt_plan).unwrap(),
        )
        .unwrap()
        .into_validated_result()
        .release()
        .unwrap();
        let object_key = attempt_receipt.object_key().to_owned();
        let ciphertext = crate::crypto::encrypt_bound_blob(
            &dek,
            &plaintext,
            &crate::store::media_blob_context(ACCOUNT, &object_key),
        )
        .unwrap();
        let candidate_plan = SelectedScreenshotUploadCandidatePlan::new(
            ACCOUNT.to_owned(),
            IMAGE_ID.to_owned(),
            object_key.clone(),
            attempt_receipt.binding_commitment(),
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            jpeg.clone(),
            media_receipt,
            &dek,
            &plaintext,
            ciphertext.clone(),
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(candidate_plan).unwrap(),
        )
        .unwrap();
        Fixture {
            connection,
            dek,
            object_key,
            ciphertext,
            jpeg,
        }
    }

    fn fixture() -> Fixture {
        let connection = Connection::open_in_memory().unwrap();
        initialize(&connection);
        fixture_with_connection(connection)
    }

    fn plan(fixture: &Fixture) -> SelectedScreenshotSendStartedPlan {
        let candidate = load_authenticated_selected_screenshot_upload_candidate(
            &fixture.connection,
            ACCOUNT,
            IMAGE_ID,
            &fixture.dek,
        )
        .unwrap()
        .unwrap();
        SelectedScreenshotSendStartedPlan::new(&candidate).unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: SelectedScreenshotSendStartedPlan,
    ) -> std::result::Result<
        crate::archive_v3_wal_idempotency::ExecutedLogicalMutation<
            SelectedScreenshotSendStartedPlan,
        >,
        WalIdempotencyError,
    > {
        execute_prepared_for_owner(connection, PreparedLogicalMutation::prepare(plan)?)
    }

    fn execute_error(
        connection: &mut Connection,
        plan: SelectedScreenshotSendStartedPlan,
    ) -> WalIdempotencyError {
        match execute(connection, plan) {
            Ok(_) => panic!("mutation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    fn insert_exact_local_result(fixture: &Connection, object_key: &str, jpeg: &ValidatedJpeg) {
        fixture
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,
                  width,height,byte_length,sha256)
                 VALUES (?1,41,7,?2,?3,?4,'image/jpeg',?5,?6,?7,?8)",
                params![
                    IMAGE_ID,
                    SOURCE_KEY,
                    CAPTURED_AT,
                    object_key,
                    jpeg.width,
                    jpeg.height,
                    jpeg.byte_length,
                    jpeg.sha256,
                ],
            )
            .unwrap();
    }

    #[test]
    fn exact_send_start_applies_replays_and_has_one_stable_request_identity() {
        let mut fixture = fixture();
        let first_plan = plan(&fixture);
        let first = execute(&mut fixture.connection, first_plan).unwrap();
        assert_eq!(first.disposition(), LogicalMutationDisposition::Applied);
        let receipt = first.into_validated_result().release().unwrap();
        assert_eq!(receipt.image_id(), IMAGE_ID);
        assert_eq!(receipt.object_key(), fixture.object_key);
        assert!(super::super::valid_lower_hex(receipt.send_request_id(), 64));
        assert_ne!(receipt.send_binding_commitment(), [0; 32]);
        let loaded = load_authenticated_selected_screenshot_send_started(
            &fixture.connection,
            ACCOUNT,
            IMAGE_ID,
            &fixture.dek,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            loaded.receipt().send_request_id(),
            receipt.send_request_id()
        );
        assert_eq!(loaded.ciphertext(), fixture.ciphertext);
        let before = fixture.connection.total_changes();
        let replay_plan = plan(&fixture);
        let replay = execute(&mut fixture.connection, replay_plan).unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(fixture.connection.total_changes(), before);
    }

    #[test]
    fn reopen_exact_loader_retains_the_original_marker_and_ciphertext() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let path = temporary.path().to_owned();
        let connection = Connection::open(&path).unwrap();
        initialize(&connection);
        let mut fixture = fixture_with_connection(connection);
        let first_plan = plan(&fixture);
        let first = execute(&mut fixture.connection, first_plan).unwrap();
        let request_id = first
            .into_validated_result()
            .release()
            .unwrap()
            .send_request_id()
            .to_owned();
        let Fixture {
            connection,
            dek,
            ciphertext,
            ..
        } = fixture;
        drop(connection);
        let mut reopened = Connection::open(path).unwrap();
        let loaded =
            load_authenticated_selected_screenshot_send_started(&reopened, ACCOUNT, IMAGE_ID, &dek)
                .unwrap()
                .unwrap();
        assert_eq!(loaded.receipt().send_request_id(), request_id);
        assert_eq!(loaded.ciphertext(), ciphertext);
        let candidate = load_authenticated_selected_screenshot_upload_candidate(
            &reopened, ACCOUNT, IMAGE_ID, &dek,
        )
        .unwrap()
        .unwrap();
        let before = reopened.total_changes();
        let replay = execute(
            &mut reopened,
            SelectedScreenshotSendStartedPlan::new(&candidate).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(reopened.total_changes(), before);
    }

    #[test]
    fn local_consumption_blocks_first_send_but_exact_replay_survives_later_settlement() {
        let mut consumed = fixture();
        insert_exact_local_result(&consumed.connection, &consumed.object_key, &consumed.jpeg);
        let consumed_plan = plan(&consumed);
        assert_eq!(
            execute_error(&mut consumed.connection, consumed_plan),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            schema_state(&consumed.connection).unwrap(),
            LedgerSchemaState::Absent
        );

        let mut replay = fixture();
        let first_plan = plan(&replay);
        execute(&mut replay.connection, first_plan).unwrap();
        insert_exact_local_result(&replay.connection, &replay.object_key, &replay.jpeg);
        let before = replay.connection.total_changes();
        let replay_plan = plan(&replay);
        let result = execute(&mut replay.connection, replay_plan).unwrap();
        assert_eq!(result.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(replay.connection.total_changes(), before);
    }

    #[test]
    fn candidate_marker_or_counter_tamper_fails_closed() {
        let mut candidate = fixture();
        let candidate_plan = plan(&candidate);
        candidate
            .connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_upload_candidates
                 SET request_fingerprint=?1",
                [[3u8; 32].as_slice()],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut candidate.connection, candidate_plan),
            WalIdempotencyError::Corrupt
        );

        let mut marker = fixture();
        let first_plan = plan(&marker);
        execute(&mut marker.connection, first_plan).unwrap();
        marker
            .connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_send_started
                 SET send_binding_commitment=?1",
                [[4u8; 32].as_slice()],
            )
            .unwrap();
        let marker_plan = plan(&marker);
        assert_eq!(
            execute_error(&mut marker.connection, marker_plan),
            WalIdempotencyError::Corrupt
        );

        let mut counter = fixture();
        let first_plan = plan(&counter);
        execute(&mut counter.connection, first_plan).unwrap();
        counter
            .connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_send_started_state
                 SET result_bytes=result_bytes+1",
                [],
            )
            .unwrap();
        let counter_plan = plan(&counter);
        assert_eq!(
            execute_error(&mut counter.connection, counter_plan),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn partial_schema_and_late_readback_failure_roll_back_exactly() {
        let mut partial = fixture();
        partial
            .connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_selected_screenshot_send_started_schema(
                    singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        let partial_plan = plan(&partial);
        assert_eq!(
            execute_error(&mut partial.connection, partial_plan),
            WalIdempotencyError::Corrupt
        );

        let mut late = fixture();
        {
            let transaction = late.connection.transaction().unwrap();
            ensure_schema(&transaction).unwrap();
            transaction.commit().unwrap();
        }
        late.connection
            .execute_batch(
                "CREATE TEMP TRIGGER corrupt_send_started_after_insert
                 AFTER INSERT ON archive_v3_wal_selected_screenshot_send_started
                 BEGIN
                   UPDATE archive_v3_wal_selected_screenshot_send_started
                   SET send_request_id=
                       CASE substr(send_request_id,1,1)
                         WHEN 'a' THEN 'b' || substr(send_request_id,2)
                         ELSE 'a' || substr(send_request_id,2)
                       END
                   WHERE operation_id=NEW.operation_id;
                 END;",
            )
            .unwrap();
        let late_plan = plan(&late);
        assert!(execute(&mut late.connection, late_plan).is_err());
        assert_eq!(
            schema_state(&late.connection).unwrap(),
            LedgerSchemaState::Present
        );
        assert_eq!(load_ledger_state(&late.connection).unwrap(), (0, 0));
    }
}
