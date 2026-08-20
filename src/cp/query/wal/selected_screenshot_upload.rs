#![allow(
    dead_code,
    reason = "inactive ADR-0022 selected-screenshot ciphertext candidate is reviewed before send or launcher ownership"
)]

//! Ciphertext-candidate boundary for one selected-screenshot attempt (wired
//! to the selected upload route by ADR-0022 slice 10g via the WAL-owned
//! factory in the parent).
//!
//! A future producer supplies already validated JPEG bytes, the exact
//! context-bound ciphertext, the borrowed media DEK, and the typed receipts
//! from the permanent attempt and media-DEK installation boundaries. This
//! child verifies the AEAD/plaintext pair in memory, retains only ciphertext,
//! and atomically records one exact `CandidateReady` row. It cannot allocate a
//! key or identity, call KMS, read Store, contact a provider, mark send-start,
//! classify a provider outcome, retry, delete/list an object, or acknowledge a
//! request.

use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    archive_v3_wal_idempotency::{
        DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
        WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
        WalReplayResult,
    },
    cp::media::wal::{authenticate_media_dek_install_receipt, MediaDekInstallReceipt},
    crypto::Dek,
};

use super::super::{
    ValidatedJpeg, MAX_SCREENSHOT_IMAGE_BYTES, MAX_SCREENSHOT_LONG_EDGE,
    MAX_SCREENSHOT_METADATA_FIELD_BYTES,
};

const REQUEST_V1: u16 = 1;
const REQUEST_SELECTED_SCREENSHOT_UPLOAD_CANDIDATE: u8 = 4;
const RESULT_V1: u16 = 1;
const RESULT_SELECTED_SCREENSHOT_UPLOAD_CANDIDATE: u8 = 4;
const OPERATION_SOURCE_DOMAIN: &[u8] = b"selected-screenshot-upload-candidate-v1\0";
const CANDIDATE_BINDING_DOMAIN: &[u8] =
    b"archive-v3-selected-screenshot-upload-candidate-binding-v1\0";
const MAX_ACCOUNT_ID_BYTES: usize = 128;
const MAX_OBJECT_KEY_BYTES: usize = 512;
const MAX_CIPHERTEXT_BYTES: usize = MAX_SCREENSHOT_IMAGE_BYTES + 64;
const MAX_ENCODED_RESULT_BYTES: usize = 1024;
const SCHEMA_TABLE: &str = "archive_v3_wal_selected_screenshot_upload_candidate_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_selected_screenshot_upload_candidates";
const STATE_TABLE: &str = "archive_v3_wal_selected_screenshot_upload_candidate_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RETAINED_CIPHERTEXT_BYTES: u64 = 512 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type HmacSha256 = Hmac<Sha256>;
type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SelectedScreenshotUploadCandidateReceipt {
    image_id: String,
    object_key: String,
    attempt_binding_commitment: [u8; 32],
    wrapped_dek_commitment: [u8; 32],
    media_dek_binding_commitment: [u8; 32],
    aad_commitment: [u8; 32],
    ciphertext_length: u32,
    ciphertext_sha256: [u8; 32],
    candidate_binding_commitment: [u8; 32],
}

impl SelectedScreenshotUploadCandidateReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_terminal_facts(
        image_id: String,
        object_key: String,
        attempt_binding_commitment: [u8; 32],
        wrapped_dek_commitment: [u8; 32],
        media_dek_binding_commitment: [u8; 32],
        aad_commitment: [u8; 32],
        ciphertext_length: u32,
        ciphertext_sha256: [u8; 32],
        candidate_binding_commitment: [u8; 32],
    ) -> Result<Self> {
        if !super::valid_lower_hex(&image_id, 32)
            || object_key.is_empty()
            || object_key.len() > MAX_OBJECT_KEY_BYTES
            || ciphertext_length == 0
            || usize::try_from(ciphertext_length)
                .ok()
                .is_none_or(|length| length > MAX_CIPHERTEXT_BYTES)
            || [
                attempt_binding_commitment,
                wrapped_dek_commitment,
                media_dek_binding_commitment,
                aad_commitment,
                ciphertext_sha256,
                candidate_binding_commitment,
            ]
            .contains(&[0; 32])
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(Self {
            image_id,
            object_key,
            attempt_binding_commitment,
            wrapped_dek_commitment,
            media_dek_binding_commitment,
            aad_commitment,
            ciphertext_length,
            ciphertext_sha256,
            candidate_binding_commitment,
        })
    }

    pub(super) fn image_id(&self) -> &str {
        &self.image_id
    }

    pub(super) fn object_key(&self) -> &str {
        &self.object_key
    }

    pub(super) const fn candidate_binding_commitment(&self) -> [u8; 32] {
        self.candidate_binding_commitment
    }

    pub(super) const fn attempt_binding_commitment(&self) -> [u8; 32] {
        self.attempt_binding_commitment
    }

    pub(super) const fn wrapped_dek_commitment(&self) -> [u8; 32] {
        self.wrapped_dek_commitment
    }

    pub(super) const fn media_dek_binding_commitment(&self) -> [u8; 32] {
        self.media_dek_binding_commitment
    }

    pub(super) const fn aad_commitment(&self) -> [u8; 32] {
        self.aad_commitment
    }

    pub(super) const fn ciphertext_length(&self) -> u32 {
        self.ciphertext_length
    }

    pub(super) const fn ciphertext_sha256(&self) -> [u8; 32] {
        self.ciphertext_sha256
    }
}

impl std::fmt::Debug for SelectedScreenshotUploadCandidateReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedScreenshotUploadCandidateReceipt(<redacted>)")
    }
}

/// Exact durable ciphertext candidate. Plaintext and the DEK are borrowed only
/// during construction; neither is retained in this plan or its ledger.
pub(crate) struct SelectedScreenshotUploadCandidatePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    image_id: String,
    object_key: String,
    episode_id: i64,
    source_key: String,
    captured_at: String,
    jpeg: ValidatedJpeg,
    media_dek_receipt: MediaDekInstallReceipt,
    ciphertext: Zeroizing<Vec<u8>>,
    receipt: SelectedScreenshotUploadCandidateReceipt,
}

impl SelectedScreenshotUploadCandidatePlan {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        account_id: String,
        image_id: String,
        object_key: String,
        attempt_binding_commitment: [u8; 32],
        episode_id: i64,
        source_key: String,
        captured_at: String,
        jpeg: ValidatedJpeg,
        media_dek_receipt: MediaDekInstallReceipt,
        plaintext_dek: &Dek,
        plaintext_jpeg: &[u8],
        ciphertext: Vec<u8>,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if account_id.len() > MAX_ACCOUNT_ID_BYTES
            || !super::valid_lower_hex(&image_id, 32)
            || object_key.is_empty()
            || object_key.len() > MAX_OBJECT_KEY_BYTES
            || episode_id <= 0
            || source_key.is_empty()
            || source_key.len() > MAX_SCREENSHOT_METADATA_FIELD_BYTES
            || captured_at.is_empty()
            || captured_at.len() > MAX_SCREENSHOT_METADATA_FIELD_BYTES
            || jpeg.width <= 0
            || jpeg.height <= 0
            || jpeg.width > i32::from(MAX_SCREENSHOT_LONG_EDGE)
            || jpeg.height > i32::from(MAX_SCREENSHOT_LONG_EDGE)
            || jpeg.byte_length <= 0
            || usize::try_from(jpeg.byte_length).ok() != Some(plaintext_jpeg.len())
            || plaintext_jpeg.is_empty()
            || plaintext_jpeg.len() > MAX_SCREENSHOT_IMAGE_BYTES
            || !super::valid_lower_hex(&jpeg.sha256, 64)
            || attempt_binding_commitment == [0; 32]
            || ciphertext.is_empty()
            || ciphertext.len() > MAX_CIPHERTEXT_BYTES
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let expected_object_key =
            crate::store::selected_evidence_media_object_key(&account_id, &image_id)
                .map_err(|_| WalIdempotencyError::Malformed)?;
        if object_key != expected_object_key {
            return Err(WalIdempotencyError::Malformed);
        }
        let plaintext_sha256 = format!("{:x}", Sha256::digest(plaintext_jpeg));
        if plaintext_sha256 != jpeg.sha256 {
            return Err(WalIdempotencyError::Malformed);
        }
        media_dek_receipt.validate_plaintext_dek(&account_id, plaintext_dek)?;
        let aad = Zeroizing::new(crate::store::media_blob_context(&account_id, &object_key));
        let opened = crate::crypto::decrypt_bound_blob(plaintext_dek, &ciphertext, aad.as_slice())
            .map_err(|_| WalIdempotencyError::Malformed)?;
        let opened_plaintext = Zeroizing::new(opened.plaintext);
        if opened.requires_rewrite || opened_plaintext.as_slice() != plaintext_jpeg {
            return Err(WalIdempotencyError::Malformed);
        }
        let aad_commitment: [u8; 32] = Sha256::digest(aad.as_slice()).into();
        let ciphertext_sha256: [u8; 32] = Sha256::digest(&ciphertext).into();
        let ciphertext_length =
            u32::try_from(ciphertext.len()).map_err(|_| WalIdempotencyError::Limit)?;
        let candidate_binding_commitment = derive_candidate_binding_commitment(
            plaintext_dek,
            &account_id,
            &image_id,
            &object_key,
            episode_id,
            &source_key,
            &captured_at,
            &jpeg,
            &attempt_binding_commitment,
            &media_dek_receipt,
            &aad_commitment,
            ciphertext_length,
            &ciphertext_sha256,
        )?;
        let operation_id = derive_operation_id(&image_id)?;
        Ok(Self {
            operation_id,
            account_id,
            image_id: image_id.clone(),
            object_key: object_key.clone(),
            episode_id,
            source_key,
            captured_at,
            jpeg,
            media_dek_receipt,
            ciphertext: Zeroizing::new(ciphertext),
            receipt: SelectedScreenshotUploadCandidateReceipt {
                image_id,
                object_key,
                attempt_binding_commitment,
                wrapped_dek_commitment: media_dek_receipt.wrapped_dek_commitment(),
                media_dek_binding_commitment: media_dek_receipt.binding_commitment(),
                aad_commitment,
                ciphertext_length,
                ciphertext_sha256,
                candidate_binding_commitment,
            },
        })
    }
}

impl Drop for SelectedScreenshotUploadCandidatePlan {
    fn drop(&mut self) {
        self.account_id.zeroize();
        self.image_id.zeroize();
        self.object_key.zeroize();
        self.source_key.zeroize();
        self.captured_at.zeroize();
        self.jpeg.sha256.zeroize();
    }
}

pub(crate) struct SelectedScreenshotUploadCandidateLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for SelectedScreenshotUploadCandidatePlan {
    type Ledger = SelectedScreenshotUploadCandidateLedger;
    type Output = SelectedScreenshotUploadCandidateReceipt;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::SelectedScreenshot
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(
            self.ciphertext
                .len()
                .saturating_add(self.account_id.len())
                .saturating_add(self.image_id.len())
                .saturating_add(self.object_key.len())
                .saturating_add(self.source_key.len())
                .saturating_add(self.captured_at.len())
                .saturating_add(self.jpeg.sha256.len())
                .saturating_add(320),
        ));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        request.push(REQUEST_SELECTED_SCREENSHOT_UPLOAD_CANDIDATE);
        append_string(&mut request, &self.account_id)?;
        append_string(&mut request, &self.image_id)?;
        append_string(&mut request, &self.object_key)?;
        request.extend_from_slice(&self.episode_id.to_be_bytes());
        append_string(&mut request, &self.source_key)?;
        append_string(&mut request, &self.captured_at)?;
        request.extend_from_slice(&self.jpeg.width.to_be_bytes());
        request.extend_from_slice(&self.jpeg.height.to_be_bytes());
        request.extend_from_slice(&self.jpeg.byte_length.to_be_bytes());
        append_string(&mut request, &self.jpeg.sha256)?;
        request.extend_from_slice(&self.receipt.attempt_binding_commitment);
        request.extend_from_slice(&self.receipt.wrapped_dek_commitment);
        request.extend_from_slice(&self.receipt.media_dek_binding_commitment);
        request.extend_from_slice(&self.receipt.aad_commitment);
        request.extend_from_slice(&self.receipt.ciphertext_length.to_be_bytes());
        request.extend_from_slice(&self.receipt.ciphertext_sha256);
        request.extend_from_slice(&self.receipt.candidate_binding_commitment);
        request.extend_from_slice(&self.receipt.ciphertext_length.to_be_bytes());
        request.extend_from_slice(self.ciphertext.as_slice());
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        authenticate_predecessors(transaction, self, true)?;
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

impl WalLogicalDomainLedger<SelectedScreenshotUploadCandidatePlan>
    for SelectedScreenshotUploadCandidateLedger
{
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<SelectedScreenshotUploadCandidatePlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let Some((ciphertext_length, result_length)) = connection
            .query_row(
                "SELECT length(ciphertext),length(result_bytes)
                 FROM archive_v3_wal_selected_screenshot_upload_candidates
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
        else {
            return Ok(None);
        };
        validate_encoded_lengths(ciphertext_length, result_length)?;
        let row = connection
            .query_row(
                "SELECT operation_id,format_version,codec_version,request_fingerprint,
                        account_id,image_id,object_key,episode_id,source_key,captured_at,
                        width,height,plaintext_length,plaintext_sha256,
                        attempt_binding_commitment,wrapped_dek_commitment,
                        media_dek_binding_commitment,aad_commitment,
                        ciphertext_length,ciphertext_sha256,candidate_binding_commitment,
                        ciphertext,result_bytes,result_commitment
                 FROM archive_v3_wal_selected_screenshot_upload_candidates
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                StoredCandidateRow::from_row,
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let row = row.ok_or(WalIdempotencyError::Corrupt)?;
        let plan = prepared.plan_for_domain_ledger();
        validate_stored_candidate_shape(&row)?;
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
            || Sha256::digest(&row.ciphertext).as_slice() != row.ciphertext_sha256.as_slice()
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        let aad = crate::store::media_blob_context(&row.account_id, &row.object_key);
        if Sha256::digest(&aad).as_slice() != row.aad_commitment.as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        authenticate_predecessors(connection, plan, false)?;
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
        prepared: &PreparedLogicalMutation<SelectedScreenshotUploadCandidatePlan>,
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
        let (row_count, result_bytes, ciphertext_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, expected_encoded.len())?;
        let next_ciphertext_bytes = ciphertext_bytes
            .checked_add(
                u64::try_from(plan.ciphertext.len()).map_err(|_| WalIdempotencyError::Limit)?,
            )
            .filter(|total| *total <= MAX_RETAINED_CIPHERTEXT_BYTES)
            .ok_or(WalIdempotencyError::Limit)?;
        let result = plan.apply(transaction)?;
        plan.validate_replay(&result)?;
        let encoded = result.encode(WalOperationKind::SelectedScreenshot)?;
        if encoded != expected_encoded {
            return Err(WalIdempotencyError::Corrupt);
        }
        let result_commitment = result.commitment(WalOperationKind::SelectedScreenshot)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_selected_screenshot_upload_candidates
                 (operation_id,format_version,codec_version,request_fingerprint,
                  account_id,image_id,object_key,episode_id,source_key,captured_at,
                  width,height,plaintext_length,plaintext_sha256,
                  attempt_binding_commitment,wrapped_dek_commitment,
                  media_dek_binding_commitment,aad_commitment,
                  ciphertext_length,ciphertext_sha256,candidate_binding_commitment,
                  ciphertext,result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                         ?17,?18,?19,?20,?21,?22,?23,?24)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(WalOperationKind::SelectedScreenshot.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    plan.account_id,
                    plan.image_id,
                    plan.object_key,
                    plan.episode_id,
                    plan.source_key,
                    plan.captured_at,
                    plan.jpeg.width,
                    plan.jpeg.height,
                    plan.jpeg.byte_length,
                    plan.jpeg.sha256,
                    plan.receipt.attempt_binding_commitment.as_slice(),
                    plan.receipt.wrapped_dek_commitment.as_slice(),
                    plan.receipt.media_dek_binding_commitment.as_slice(),
                    plan.receipt.aad_commitment.as_slice(),
                    i64::from(plan.receipt.ciphertext_length),
                    plan.receipt.ciphertext_sha256.as_slice(),
                    plan.receipt.candidate_binding_commitment.as_slice(),
                    plan.ciphertext.as_slice(),
                    encoded.as_slice(),
                    result_commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_upload_candidate_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1,ciphertext_bytes=?2
                 WHERE singleton=1 AND row_count=?3 AND result_bytes=?4 AND ciphertext_bytes=?5",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::try_from(next_ciphertext_bytes).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                    i64::try_from(ciphertext_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
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

/// Exact restart payload for one caller-named candidate. Loading requires the
/// plaintext DEK so the stored keyed binding and AEAD are revalidated; there is
/// no enumeration or provider capability on this type.
pub(super) struct AuthenticatedSelectedScreenshotUploadCandidate {
    account_id: String,
    request_fingerprint: [u8; 32],
    receipt: SelectedScreenshotUploadCandidateReceipt,
    ciphertext: Zeroizing<Vec<u8>>,
}

impl AuthenticatedSelectedScreenshotUploadCandidate {
    pub(super) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(super) const fn request_fingerprint(&self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub(super) fn receipt(&self) -> &SelectedScreenshotUploadCandidateReceipt {
        &self.receipt
    }

    pub(super) fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }
}

impl std::fmt::Debug for AuthenticatedSelectedScreenshotUploadCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedSelectedScreenshotUploadCandidate(<redacted>)")
    }
}

/// Exact-name restart loader. The caller supplies the already selected account
/// and attempt ID plus the KMS-authenticated plaintext DEK; this function cannot
/// discover candidates or obtain a key/provider on its own.
pub(super) fn load_authenticated_selected_screenshot_upload_candidate(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
    plaintext_dek: &Dek,
) -> Result<Option<AuthenticatedSelectedScreenshotUploadCandidate>> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    if account_id.len() > MAX_ACCOUNT_ID_BYTES || !super::valid_lower_hex(image_id, 32) {
        return Err(WalIdempotencyError::Malformed);
    }
    if schema_state(connection)? == LedgerSchemaState::Absent {
        return Ok(None);
    }
    validate_schema_marker(connection)?;
    let Some((ciphertext_length, result_length)) = connection
        .query_row(
            "SELECT length(ciphertext),length(result_bytes)
             FROM archive_v3_wal_selected_screenshot_upload_candidates
             WHERE image_id=?1",
            [image_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
    else {
        return Ok(None);
    };
    validate_encoded_lengths(ciphertext_length, result_length)?;
    let row = connection
        .query_row(
            "SELECT operation_id,format_version,codec_version,request_fingerprint,
                    account_id,image_id,object_key,episode_id,source_key,captured_at,
                    width,height,plaintext_length,plaintext_sha256,
                    attempt_binding_commitment,wrapped_dek_commitment,
                    media_dek_binding_commitment,aad_commitment,
                    ciphertext_length,ciphertext_sha256,candidate_binding_commitment,
                    ciphertext,result_bytes,result_commitment
             FROM archive_v3_wal_selected_screenshot_upload_candidates
             WHERE image_id=?1",
            [image_id],
            StoredCandidateRow::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    validate_stored_candidate_shape(&row)?;
    if row.account_id != account_id || row.image_id != image_id {
        return Err(WalIdempotencyError::Precondition);
    }
    let media_dek_receipt = MediaDekInstallReceipt::from_stored_commitments(
        array_32(&row.wrapped_dek_commitment)?,
        array_32(&row.media_dek_binding_commitment)?,
    )?;
    let aad = Zeroizing::new(crate::store::media_blob_context(
        account_id,
        &row.object_key,
    ));
    let opened = crate::crypto::decrypt_bound_blob(plaintext_dek, &row.ciphertext, aad.as_slice())
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    let plaintext = Zeroizing::new(opened.plaintext);
    if opened.requires_rewrite
        || i64::try_from(plaintext.len()).map_err(|_| WalIdempotencyError::Corrupt)?
            != row.plaintext_length
        || format!("{:x}", Sha256::digest(plaintext.as_slice())) != row.plaintext_sha256
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let plan = SelectedScreenshotUploadCandidatePlan::new(
        row.account_id.clone(),
        row.image_id.clone(),
        row.object_key.clone(),
        array_32(&row.attempt_binding_commitment)?,
        row.episode_id,
        row.source_key.clone(),
        row.captured_at.clone(),
        ValidatedJpeg {
            width: row.width,
            height: row.height,
            byte_length: row.plaintext_length,
            sha256: row.plaintext_sha256.clone(),
        },
        media_dek_receipt,
        plaintext_dek,
        plaintext.as_slice(),
        row.ciphertext.clone(),
    )
    .map_err(|_| WalIdempotencyError::Corrupt)?;
    let prepared =
        PreparedLogicalMutation::prepare(plan).map_err(|_| WalIdempotencyError::Corrupt)?;
    let request_fingerprint = *prepared.request_fingerprint_for_owner().as_bytes();
    let result = SelectedScreenshotUploadCandidateLedger::lookup(connection, &prepared)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let receipt = decode_receipt(&result)?;
    Ok(Some(AuthenticatedSelectedScreenshotUploadCandidate {
        account_id: account_id.to_owned(),
        request_fingerprint,
        receipt,
        ciphertext: Zeroizing::new(row.ciphertext),
    }))
}

/// Reauthenticates the exact permanent candidate against the fingerprint and
/// keyed receipt captured by the exact-name DEK-bearing loader. This helper
/// exposes no ciphertext and cannot discover another candidate.
pub(super) fn authenticate_selected_screenshot_upload_candidate(
    connection: &Connection,
    account_id: &str,
    expected_request_fingerprint: &[u8; 32],
    expected_receipt: &SelectedScreenshotUploadCandidateReceipt,
    require_unconsumed: bool,
) -> Result<()> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    if account_id.len() > MAX_ACCOUNT_ID_BYTES
        || expected_request_fingerprint == &[0; 32]
        || !super::valid_lower_hex(expected_receipt.image_id(), 32)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    if schema_state(connection)? == LedgerSchemaState::Absent {
        return Err(WalIdempotencyError::Precondition);
    }
    validate_schema_marker(connection)?;
    let Some((ciphertext_length, result_length)) = connection
        .query_row(
            "SELECT length(ciphertext),length(result_bytes)
             FROM archive_v3_wal_selected_screenshot_upload_candidates
             WHERE image_id=?1",
            [expected_receipt.image_id()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
    else {
        return Err(WalIdempotencyError::Precondition);
    };
    validate_encoded_lengths(ciphertext_length, result_length)?;
    let row = connection
        .query_row(
            "SELECT operation_id,format_version,codec_version,request_fingerprint,
                    account_id,image_id,object_key,episode_id,source_key,captured_at,
                    width,height,plaintext_length,plaintext_sha256,
                    attempt_binding_commitment,wrapped_dek_commitment,
                    media_dek_binding_commitment,aad_commitment,
                    ciphertext_length,ciphertext_sha256,candidate_binding_commitment,
                    ciphertext,result_bytes,result_commitment
             FROM archive_v3_wal_selected_screenshot_upload_candidates
             WHERE image_id=?1",
            [expected_receipt.image_id()],
            StoredCandidateRow::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    validate_stored_candidate_shape(&row)?;
    if row.account_id != account_id
        || row.request_fingerprint.as_slice() != expected_request_fingerprint
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let media_dek_receipt = MediaDekInstallReceipt::from_stored_commitments(
        array_32(&row.wrapped_dek_commitment)?,
        array_32(&row.media_dek_binding_commitment)?,
    )?;
    let receipt = SelectedScreenshotUploadCandidateReceipt {
        image_id: row.image_id.clone(),
        object_key: row.object_key.clone(),
        attempt_binding_commitment: array_32(&row.attempt_binding_commitment)?,
        wrapped_dek_commitment: array_32(&row.wrapped_dek_commitment)?,
        media_dek_binding_commitment: array_32(&row.media_dek_binding_commitment)?,
        aad_commitment: array_32(&row.aad_commitment)?,
        ciphertext_length: u32::try_from(row.ciphertext_length)
            .map_err(|_| WalIdempotencyError::Corrupt)?,
        ciphertext_sha256: array_32(&row.ciphertext_sha256)?,
        candidate_binding_commitment: array_32(&row.candidate_binding_commitment)?,
    };
    if &receipt != expected_receipt {
        return Err(WalIdempotencyError::Corrupt);
    }
    let plan = SelectedScreenshotUploadCandidatePlan {
        operation_id: derive_operation_id(&row.image_id)?,
        account_id: row.account_id,
        image_id: row.image_id,
        object_key: row.object_key,
        episode_id: row.episode_id,
        source_key: row.source_key,
        captured_at: row.captured_at,
        jpeg: ValidatedJpeg {
            width: row.width,
            height: row.height,
            byte_length: row.plaintext_length,
            sha256: row.plaintext_sha256,
        },
        media_dek_receipt,
        ciphertext: Zeroizing::new(row.ciphertext),
        receipt,
    };
    let prepared =
        PreparedLogicalMutation::prepare(plan).map_err(|_| WalIdempotencyError::Corrupt)?;
    if prepared.request_fingerprint_for_owner().as_bytes() != expected_request_fingerprint {
        return Err(WalIdempotencyError::Corrupt);
    }
    if require_unconsumed {
        authenticate_predecessors(connection, prepared.plan_for_domain_ledger(), true)?;
    }
    let result = SelectedScreenshotUploadCandidateLedger::lookup(connection, &prepared)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    (&decode_receipt(&result)? == expected_receipt)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

#[allow(clippy::too_many_arguments)]
fn authenticate_predecessors(
    connection: &Connection,
    plan: &SelectedScreenshotUploadCandidatePlan,
    require_unconsumed: bool,
) -> Result<()> {
    let screenshot_id = if require_unconsumed {
        super::selected_screenshot_attempt::authenticate_unconsumed_selected_screenshot_attempt(
            connection,
            &plan.account_id,
            &plan.image_id,
            &plan.object_key,
            plan.episode_id,
            &plan.source_key,
            &plan.captured_at,
            &plan.jpeg,
            &plan.receipt.attempt_binding_commitment,
        )?
    } else {
        super::selected_screenshot_attempt::authenticate_selected_screenshot_attempt_binding(
            connection,
            &plan.account_id,
            &plan.image_id,
            &plan.object_key,
            plan.episode_id,
            &plan.source_key,
            &plan.captured_at,
            &plan.jpeg,
            &plan.receipt.attempt_binding_commitment,
        )?
    };
    if screenshot_id <= 0 {
        return Err(WalIdempotencyError::Corrupt);
    }
    authenticate_media_dek_install_receipt(connection, &plan.account_id, &plan.media_dek_receipt)
}

struct StoredCandidateRow {
    operation_id: Vec<u8>,
    format_version: i64,
    codec_version: i64,
    request_fingerprint: Vec<u8>,
    account_id: String,
    image_id: String,
    object_key: String,
    episode_id: i64,
    source_key: String,
    captured_at: String,
    width: i32,
    height: i32,
    plaintext_length: i64,
    plaintext_sha256: String,
    attempt_binding_commitment: Vec<u8>,
    wrapped_dek_commitment: Vec<u8>,
    media_dek_binding_commitment: Vec<u8>,
    aad_commitment: Vec<u8>,
    ciphertext_length: i64,
    ciphertext_sha256: Vec<u8>,
    candidate_binding_commitment: Vec<u8>,
    ciphertext: Vec<u8>,
    result_bytes: Vec<u8>,
    result_commitment: Vec<u8>,
}

impl StoredCandidateRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            operation_id: row.get(0)?,
            format_version: row.get(1)?,
            codec_version: row.get(2)?,
            request_fingerprint: row.get(3)?,
            account_id: row.get(4)?,
            image_id: row.get(5)?,
            object_key: row.get(6)?,
            episode_id: row.get(7)?,
            source_key: row.get(8)?,
            captured_at: row.get(9)?,
            width: row.get(10)?,
            height: row.get(11)?,
            plaintext_length: row.get(12)?,
            plaintext_sha256: row.get(13)?,
            attempt_binding_commitment: row.get(14)?,
            wrapped_dek_commitment: row.get(15)?,
            media_dek_binding_commitment: row.get(16)?,
            aad_commitment: row.get(17)?,
            ciphertext_length: row.get(18)?,
            ciphertext_sha256: row.get(19)?,
            candidate_binding_commitment: row.get(20)?,
            ciphertext: row.get(21)?,
            result_bytes: row.get(22)?,
            result_commitment: row.get(23)?,
        })
    }

    fn matches_plan(&self, plan: &SelectedScreenshotUploadCandidatePlan) -> bool {
        self.operation_id.as_slice() == plan.operation_id.as_bytes()
            && self.account_id == plan.account_id
            && self.image_id == plan.image_id
            && self.object_key == plan.object_key
            && self.episode_id == plan.episode_id
            && self.source_key == plan.source_key
            && self.captured_at == plan.captured_at
            && self.width == plan.jpeg.width
            && self.height == plan.jpeg.height
            && self.plaintext_length == plan.jpeg.byte_length
            && self.plaintext_sha256 == plan.jpeg.sha256
            && self.attempt_binding_commitment.as_slice() == plan.receipt.attempt_binding_commitment
            && self.wrapped_dek_commitment.as_slice() == plan.receipt.wrapped_dek_commitment
            && self.media_dek_binding_commitment.as_slice()
                == plan.receipt.media_dek_binding_commitment
            && self.aad_commitment.as_slice() == plan.receipt.aad_commitment
            && self.ciphertext_length == i64::from(plan.receipt.ciphertext_length)
            && self.ciphertext_sha256.as_slice() == plan.receipt.ciphertext_sha256
            && self.candidate_binding_commitment.as_slice()
                == plan.receipt.candidate_binding_commitment
            && self.ciphertext.as_slice() == plan.ciphertext.as_slice()
    }
}

fn validate_encoded_lengths(ciphertext_length: i64, result_length: i64) -> Result<()> {
    let ciphertext_length =
        usize::try_from(ciphertext_length).map_err(|_| WalIdempotencyError::Corrupt)?;
    let result_length = usize::try_from(result_length).map_err(|_| WalIdempotencyError::Corrupt)?;
    if ciphertext_length == 0
        || ciphertext_length > MAX_CIPHERTEXT_BYTES
        || !(200..=MAX_ENCODED_RESULT_BYTES).contains(&result_length)
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn validate_stored_candidate_shape(row: &StoredCandidateRow) -> Result<()> {
    validate_encoded_lengths(
        i64::try_from(row.ciphertext.len()).map_err(|_| WalIdempotencyError::Corrupt)?,
        i64::try_from(row.result_bytes.len()).map_err(|_| WalIdempotencyError::Corrupt)?,
    )?;
    if row.operation_id.len() != 16
        || row.request_fingerprint.len() != 32
        || row.attempt_binding_commitment.len() != 32
        || row.wrapped_dek_commitment.len() != 32
        || row.media_dek_binding_commitment.len() != 32
        || row.aad_commitment.len() != 32
        || row.ciphertext_sha256.len() != 32
        || row.candidate_binding_commitment.len() != 32
        || row.result_commitment.len() != 32
        || usize::try_from(row.ciphertext_length).ok() != Some(row.ciphertext.len())
        || row.format_version != i64::from(WalOperationKind::format_version())
        || row.codec_version != i64::from(WalOperationKind::SelectedScreenshot.codec_version())
    {
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

#[allow(clippy::too_many_arguments)]
fn derive_candidate_binding_commitment(
    plaintext_dek: &Dek,
    account_id: &str,
    image_id: &str,
    object_key: &str,
    episode_id: i64,
    source_key: &str,
    captured_at: &str,
    jpeg: &ValidatedJpeg,
    attempt_binding_commitment: &[u8; 32],
    media_dek_receipt: &MediaDekInstallReceipt,
    aad_commitment: &[u8; 32],
    ciphertext_length: u32,
    ciphertext_sha256: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut mac =
        HmacSha256::new_from_slice(&plaintext_dek.0).map_err(|_| WalIdempotencyError::Corrupt)?;
    mac.update(CANDIDATE_BINDING_DOMAIN);
    mac_field(&mut mac, account_id.as_bytes())?;
    mac_field(&mut mac, image_id.as_bytes())?;
    mac_field(&mut mac, object_key.as_bytes())?;
    mac_field(&mut mac, &episode_id.to_be_bytes())?;
    mac_field(&mut mac, source_key.as_bytes())?;
    mac_field(&mut mac, captured_at.as_bytes())?;
    mac_field(&mut mac, &jpeg.width.to_be_bytes())?;
    mac_field(&mut mac, &jpeg.height.to_be_bytes())?;
    mac_field(&mut mac, &jpeg.byte_length.to_be_bytes())?;
    mac_field(&mut mac, jpeg.sha256.as_bytes())?;
    mac_field(&mut mac, attempt_binding_commitment)?;
    mac_field(&mut mac, &media_dek_receipt.wrapped_dek_commitment())?;
    mac_field(&mut mac, &media_dek_receipt.binding_commitment())?;
    mac_field(&mut mac, aad_commitment)?;
    mac_field(&mut mac, &ciphertext_length.to_be_bytes())?;
    mac_field(&mut mac, ciphertext_sha256)?;
    let commitment: [u8; 32] = mac.finalize().into_bytes().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn mac_field(mac: &mut HmacSha256, value: &[u8]) -> Result<()> {
    mac.update(
        &u32::try_from(value.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    mac.update(value);
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

fn encode_receipt(receipt: &SelectedScreenshotUploadCandidateReceipt) -> Result<WalReplayResult> {
    let mut bytes = Vec::with_capacity(
        receipt
            .image_id
            .len()
            .saturating_add(receipt.object_key.len())
            .saturating_add(240),
    );
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(RESULT_SELECTED_SCREENSHOT_UPLOAD_CANDIDATE);
    append_string(&mut bytes, &receipt.image_id)?;
    append_string(&mut bytes, &receipt.object_key)?;
    bytes.extend_from_slice(&receipt.attempt_binding_commitment);
    bytes.extend_from_slice(&receipt.wrapped_dek_commitment);
    bytes.extend_from_slice(&receipt.media_dek_binding_commitment);
    bytes.extend_from_slice(&receipt.aad_commitment);
    bytes.extend_from_slice(&receipt.ciphertext_length.to_be_bytes());
    bytes.extend_from_slice(&receipt.ciphertext_sha256);
    bytes.extend_from_slice(&receipt.candidate_binding_commitment);
    WalReplayResult::canonical_response(WalOperationKind::SelectedScreenshot, bytes)
}

fn decode_receipt(result: &WalReplayResult) -> Result<SelectedScreenshotUploadCandidateReceipt> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    if bytes.len() < 239
        || bytes.len() > MAX_ENCODED_RESULT_BYTES
        || bytes[0..2] != RESULT_V1.to_be_bytes()
        || bytes[2] != RESULT_SELECTED_SCREENSHOT_UPLOAD_CANDIDATE
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let mut offset = 3usize;
    let image_id = take_string(bytes, &mut offset, 32)?;
    let object_key = take_string(bytes, &mut offset, MAX_OBJECT_KEY_BYTES)?;
    if !super::valid_lower_hex(&image_id, 32) || object_key.is_empty() {
        return Err(WalIdempotencyError::Corrupt);
    }
    let attempt_binding_commitment = take_array::<32>(bytes, &mut offset)?;
    let wrapped_dek_commitment = take_array::<32>(bytes, &mut offset)?;
    let media_dek_binding_commitment = take_array::<32>(bytes, &mut offset)?;
    let aad_commitment = take_array::<32>(bytes, &mut offset)?;
    let ciphertext_length = u32::from_be_bytes(take_array::<4>(bytes, &mut offset)?);
    let ciphertext_sha256 = take_array::<32>(bytes, &mut offset)?;
    let candidate_binding_commitment = take_array::<32>(bytes, &mut offset)?;
    if offset != bytes.len()
        || ciphertext_length == 0
        || usize::try_from(ciphertext_length)
            .ok()
            .is_none_or(|length| length > MAX_CIPHERTEXT_BYTES)
        || [
            attempt_binding_commitment,
            wrapped_dek_commitment,
            media_dek_binding_commitment,
            aad_commitment,
            ciphertext_sha256,
            candidate_binding_commitment,
        ]
        .contains(&[0; 32])
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(SelectedScreenshotUploadCandidateReceipt {
        image_id,
        object_key,
        attempt_binding_commitment,
        wrapped_dek_commitment,
        media_dek_binding_commitment,
        aad_commitment,
        ciphertext_length,
        ciphertext_sha256,
        candidate_binding_commitment,
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
    prepared: &PreparedLogicalMutation<SelectedScreenshotUploadCandidatePlan>,
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
                    "CREATE TABLE archive_v3_wal_selected_screenshot_upload_candidate_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_selected_screenshot_upload_candidates (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        account_id TEXT NOT NULL,
                        image_id TEXT NOT NULL UNIQUE,
                        object_key TEXT NOT NULL UNIQUE,
                        episode_id INTEGER NOT NULL CHECK(episode_id>0),
                        source_key TEXT NOT NULL UNIQUE,
                        captured_at TEXT NOT NULL,
                        width INTEGER NOT NULL CHECK(width BETWEEN 1 AND 960),
                        height INTEGER NOT NULL CHECK(height BETWEEN 1 AND 960),
                        plaintext_length INTEGER NOT NULL CHECK(plaintext_length BETWEEN 1 AND 153600),
                        plaintext_sha256 TEXT NOT NULL,
                        attempt_binding_commitment BLOB NOT NULL,
                        wrapped_dek_commitment BLOB NOT NULL,
                        media_dek_binding_commitment BLOB NOT NULL,
                        aad_commitment BLOB NOT NULL,
                        ciphertext_length INTEGER NOT NULL CHECK(ciphertext_length BETWEEN 1 AND 153664),
                        ciphertext_sha256 BLOB NOT NULL,
                        candidate_binding_commitment BLOB NOT NULL,
                        ciphertext BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(account_id) BETWEEN 1 AND 128),
                        CHECK(length(image_id)=32),
                        CHECK(length(object_key) BETWEEN 1 AND 512),
                        CHECK(length(source_key) BETWEEN 1 AND 512),
                        CHECK(length(captured_at) BETWEEN 1 AND 512),
                        CHECK(length(plaintext_sha256)=64),
                        CHECK(length(attempt_binding_commitment)=32 AND attempt_binding_commitment<>zeroblob(32)),
                        CHECK(length(wrapped_dek_commitment)=32 AND wrapped_dek_commitment<>zeroblob(32)),
                        CHECK(length(media_dek_binding_commitment)=32 AND media_dek_binding_commitment<>zeroblob(32)),
                        CHECK(length(aad_commitment)=32 AND aad_commitment<>zeroblob(32)),
                        CHECK(length(ciphertext_sha256)=32 AND ciphertext_sha256<>zeroblob(32)),
                        CHECK(length(candidate_binding_commitment)=32 AND candidate_binding_commitment<>zeroblob(32)),
                        CHECK(length(ciphertext)=ciphertext_length),
                        CHECK(length(result_bytes) BETWEEN 200 AND 1024),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_selected_screenshot_upload_candidate_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 134217728),
                        ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes BETWEEN 0 AND 536870912)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_selected_screenshot_upload_candidate_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_selected_screenshot_upload_candidate_state
                        (singleton,row_count,result_bytes,ciphertext_bytes) VALUES (1,0,0,0);",
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
             FROM archive_v3_wal_selected_screenshot_upload_candidate_schema WHERE singleton=1",
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

fn load_ledger_state(connection: &Connection) -> Result<(u32, u64, u64)> {
    let state = connection
        .query_row(
            "SELECT row_count,result_bytes,ciphertext_bytes
             FROM archive_v3_wal_selected_screenshot_upload_candidate_state WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let row_count = u32::try_from(state.0).map_err(|_| WalIdempotencyError::Corrupt)?;
    let result_bytes = u64::try_from(state.1).map_err(|_| WalIdempotencyError::Corrupt)?;
    let ciphertext_bytes = u64::try_from(state.2).map_err(|_| WalIdempotencyError::Corrupt)?;
    if row_count > MAX_ROWS
        || result_bytes > MAX_RESULT_BYTES
        || ciphertext_bytes > MAX_RETAINED_CIPHERTEXT_BYTES
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let actual = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(result_bytes)),0),
                    COALESCE(SUM(length(ciphertext)),0)
             FROM archive_v3_wal_selected_screenshot_upload_candidates",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if actual.0 != i64::from(row_count)
        || actual.1 != i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?
        || actual.2 != i64::try_from(ciphertext_bytes).map_err(|_| WalIdempotencyError::Corrupt)?
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok((row_count, result_bytes, ciphertext_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };
    use crate::cp::{
        media::wal::MediaDekInstallPlan,
        query::wal::selected_screenshot_attempt::{
            authenticate_selected_screenshot_upload_predecessor, SelectedScreenshotAttemptPlan,
        },
    };
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};

    const ACCOUNT: &str = "account-1";
    const IMAGE_ID: &str = "11111111111111111111111111111111";
    const SOURCE_KEY: &str = "cloud-v2:screen-1";
    const CAPTURED_AT: &str = "2026-08-15T13:00:00.000Z";

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

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        initialize(&connection);
        connection
    }

    fn plaintext() -> Vec<u8> {
        b"bounded-jpeg-fixture".to_vec()
    }

    fn jpeg(bytes: &[u8]) -> ValidatedJpeg {
        ValidatedJpeg {
            width: 2,
            height: 2,
            byte_length: i64::try_from(bytes.len()).unwrap(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    struct Fixture {
        connection: Connection,
        dek: Dek,
        media_receipt: MediaDekInstallReceipt,
        attempt_binding: [u8; 32],
        object_key: String,
        ciphertext: Vec<u8>,
        jpeg: ValidatedJpeg,
        plaintext: Vec<u8>,
    }

    fn fixture_with_connection(mut connection: Connection) -> Fixture {
        let dek = Dek([7; 32]);
        let wrapped = BASE64_STANDARD.encode([9; 64]);
        let media_plan =
            MediaDekInstallPlan::new_for_cross_domain_test(ACCOUNT.to_owned(), wrapped, &dek)
                .unwrap();
        let media_receipt = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(media_plan).unwrap(),
        )
        .unwrap()
        .into_validated_result()
        .release()
        .unwrap();
        let plaintext = plaintext();
        let jpeg = jpeg(&plaintext);
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
        Fixture {
            connection,
            dek,
            media_receipt,
            attempt_binding: attempt_receipt.binding_commitment(),
            object_key,
            ciphertext,
            jpeg,
            plaintext,
        }
    }

    fn fixture() -> Fixture {
        fixture_with_connection(connection())
    }

    fn plan(fixture: &Fixture) -> SelectedScreenshotUploadCandidatePlan {
        SelectedScreenshotUploadCandidatePlan::new(
            ACCOUNT.to_owned(),
            IMAGE_ID.to_owned(),
            fixture.object_key.clone(),
            fixture.attempt_binding,
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            fixture.jpeg.clone(),
            fixture.media_receipt,
            &fixture.dek,
            &fixture.plaintext,
            fixture.ciphertext.clone(),
        )
        .unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: SelectedScreenshotUploadCandidatePlan,
    ) -> std::result::Result<
        crate::archive_v3_wal_idempotency::ExecutedLogicalMutation<
            SelectedScreenshotUploadCandidatePlan,
        >,
        WalIdempotencyError,
    > {
        execute_prepared_for_owner(connection, PreparedLogicalMutation::prepare(plan)?)
    }

    fn execute_error(
        connection: &mut Connection,
        plan: SelectedScreenshotUploadCandidatePlan,
    ) -> WalIdempotencyError {
        match execute(connection, plan) {
            Ok(_) => panic!("mutation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn exact_candidate_applies_and_replays_without_plaintext_or_another_write() {
        let mut fixture = fixture();
        let first_plan = plan(&fixture);
        let first = execute(&mut fixture.connection, first_plan).unwrap();
        assert_eq!(first.disposition(), LogicalMutationDisposition::Applied);
        let receipt = first.into_validated_result().release().unwrap();
        assert_eq!(receipt.image_id(), IMAGE_ID);
        assert_eq!(receipt.object_key(), fixture.object_key);
        assert_ne!(receipt.candidate_binding_commitment(), [0; 32]);
        let stored: Vec<u8> = fixture
            .connection
            .query_row(
                "SELECT ciphertext FROM archive_v3_wal_selected_screenshot_upload_candidates",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, fixture.ciphertext);
        assert_ne!(stored, fixture.plaintext);
        let loaded = load_authenticated_selected_screenshot_upload_candidate(
            &fixture.connection,
            ACCOUNT,
            IMAGE_ID,
            &fixture.dek,
        )
        .unwrap()
        .unwrap();
        assert_eq!(loaded.receipt(), &receipt);
        assert_eq!(loaded.ciphertext(), fixture.ciphertext);
        fixture
            .connection
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,
                  width,height,byte_length,sha256)
                 VALUES (?1,41,7,?2,?3,?4,'image/jpeg',?5,?6,?7,?8)",
                params![
                    IMAGE_ID,
                    SOURCE_KEY,
                    CAPTURED_AT,
                    fixture.object_key,
                    fixture.jpeg.width,
                    fixture.jpeg.height,
                    fixture.jpeg.byte_length,
                    fixture.jpeg.sha256,
                ],
            )
            .unwrap();
        let before = fixture.connection.total_changes();
        let replay_plan = plan(&fixture);
        let replay = execute(&mut fixture.connection, replay_plan).unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(fixture.connection.total_changes(), before);
    }

    #[test]
    fn reopen_exact_load_and_replay_retain_the_original_ciphertext() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let path = temporary.path().to_owned();
        let connection = Connection::open(&path).unwrap();
        initialize(&connection);
        let mut fixture = fixture_with_connection(connection);
        let initial_plan = plan(&fixture);
        execute(&mut fixture.connection, initial_plan).unwrap();
        let Fixture {
            connection,
            dek,
            media_receipt,
            attempt_binding,
            object_key,
            ciphertext,
            jpeg,
            plaintext,
        } = fixture;
        drop(connection);

        let mut reopened = Connection::open(&path).unwrap();
        let loaded = load_authenticated_selected_screenshot_upload_candidate(
            &reopened, ACCOUNT, IMAGE_ID, &dek,
        )
        .unwrap()
        .unwrap();
        assert_eq!(loaded.ciphertext(), ciphertext);
        let before = reopened.total_changes();
        let replay_plan = SelectedScreenshotUploadCandidatePlan::new(
            ACCOUNT.to_owned(),
            IMAGE_ID.to_owned(),
            object_key,
            attempt_binding,
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            jpeg,
            media_receipt,
            &dek,
            &plaintext,
            ciphertext,
        )
        .unwrap();
        let replay = execute(&mut reopened, replay_plan).unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(reopened.total_changes(), before);
    }

    #[test]
    fn wrong_plaintext_key_context_or_ciphertext_is_rejected_before_schema() {
        let fixture = fixture();
        let wrong_plaintext = b"different-jpeg".to_vec();
        assert!(SelectedScreenshotUploadCandidatePlan::new(
            ACCOUNT.to_owned(),
            IMAGE_ID.to_owned(),
            fixture.object_key.clone(),
            fixture.attempt_binding,
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            fixture.jpeg.clone(),
            fixture.media_receipt,
            &fixture.dek,
            &wrong_plaintext,
            fixture.ciphertext.clone(),
        )
        .is_err());
        assert!(SelectedScreenshotUploadCandidatePlan::new(
            ACCOUNT.to_owned(),
            IMAGE_ID.to_owned(),
            fixture.object_key.clone(),
            fixture.attempt_binding,
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            fixture.jpeg.clone(),
            fixture.media_receipt,
            &Dek([8; 32]),
            &fixture.plaintext,
            fixture.ciphertext.clone(),
        )
        .is_err());
        let mut tampered = fixture.ciphertext.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(SelectedScreenshotUploadCandidatePlan::new(
            ACCOUNT.to_owned(),
            IMAGE_ID.to_owned(),
            fixture.object_key.clone(),
            fixture.attempt_binding,
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            fixture.jpeg,
            fixture.media_receipt,
            &fixture.dek,
            &fixture.plaintext,
            tampered,
        )
        .is_err());
        assert_eq!(
            schema_state(&fixture.connection).unwrap(),
            LedgerSchemaState::Absent
        );
    }

    #[test]
    fn consumed_attempt_or_tampered_predecessor_never_creates_a_candidate() {
        let mut consumed = fixture();
        consumed
            .connection
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,
                  width,height,byte_length,sha256)
                 VALUES (?1,41,7,?2,?3,?4,'image/jpeg',?5,?6,?7,?8)",
                params![
                    IMAGE_ID,
                    SOURCE_KEY,
                    CAPTURED_AT,
                    consumed.object_key,
                    consumed.jpeg.width,
                    consumed.jpeg.height,
                    consumed.jpeg.byte_length,
                    consumed.jpeg.sha256,
                ],
            )
            .unwrap();
        let consumed_plan = plan(&consumed);
        assert_eq!(
            execute_error(&mut consumed.connection, consumed_plan),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            schema_state(&consumed.connection).unwrap(),
            LedgerSchemaState::Absent
        );

        let mut tampered = fixture();
        tampered
            .connection
            .execute(
                "UPDATE app_metadata SET value=?1 WHERE key='wrapped_media_dek'",
                [BASE64_STANDARD.encode([3; 64])],
            )
            .unwrap();
        let tampered_plan = plan(&tampered);
        assert!(execute(&mut tampered.connection, tampered_plan).is_err());
        assert_eq!(
            schema_state(&tampered.connection).unwrap(),
            LedgerSchemaState::Absent
        );
    }

    #[test]
    fn row_or_counter_tamper_fails_closed_on_replay() {
        let mut row_tamper = fixture();
        let initial_plan = plan(&row_tamper);
        execute(&mut row_tamper.connection, initial_plan).unwrap();
        row_tamper
            .connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_upload_candidates
                 SET candidate_binding_commitment=?1",
                [[4u8; 32].as_slice()],
            )
            .unwrap();
        let replay_plan = plan(&row_tamper);
        assert_eq!(
            execute_error(&mut row_tamper.connection, replay_plan),
            WalIdempotencyError::Corrupt
        );

        let mut counters = fixture();
        let initial_plan = plan(&counters);
        execute(&mut counters.connection, initial_plan).unwrap();
        counters
            .connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_upload_candidate_state
                 SET ciphertext_bytes=ciphertext_bytes+1",
                [],
            )
            .unwrap();
        let replay_plan = plan(&counters);
        assert_eq!(
            execute_error(&mut counters.connection, replay_plan),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn partial_schema_and_late_readback_failure_roll_back_exactly() {
        let mut partial = fixture();
        partial
            .connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_selected_screenshot_upload_candidate_schema(
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
                "CREATE TEMP TRIGGER corrupt_candidate_after_insert
                 AFTER INSERT ON archive_v3_wal_selected_screenshot_upload_candidates
                 BEGIN
                   UPDATE archive_v3_wal_selected_screenshot_upload_candidates
                   SET ciphertext=zeroblob(length(ciphertext))
                   WHERE operation_id=NEW.operation_id;
                 END;",
            )
            .unwrap();
        let late_plan = plan(&late);
        assert_eq!(
            execute_error(&mut late.connection, late_plan),
            WalIdempotencyError::Corrupt
        );
        assert_eq!(
            schema_state(&late.connection).unwrap(),
            LedgerSchemaState::Present
        );
        assert_eq!(load_ledger_state(&late.connection).unwrap(), (0, 0, 0));
    }

    #[test]
    fn wal_owned_candidate_factory_requires_the_authenticated_install_row() {
        // ADR-0022 slice 10g regression: the parent-facing factory must load
        // the media-DEK install receipt from the durable install ledger and
        // fail closed when the ledger is absent or its row is tampered; the
        // parent can never substitute commitments of its own.
        let mut connection = connection();
        let dek = Dek([7; 32]);
        let plaintext = plaintext();
        let jpeg = jpeg(&plaintext);
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
        let ciphertext = crate::crypto::encrypt_bound_blob(
            &dek,
            &plaintext,
            &crate::store::media_blob_context(ACCOUNT, attempt_receipt.object_key()),
        )
        .unwrap();

        // No sealed install exists yet: the factory refuses before any plan.
        let missing_install = crate::cp::query::wal::prepare_selected_screenshot_upload_candidate(
            &connection,
            ACCOUNT,
            &attempt_receipt,
            7,
            SOURCE_KEY,
            CAPTURED_AT,
            &jpeg,
            &dek,
            &plaintext,
            ciphertext.clone(),
        );
        match missing_install {
            Ok(_) => panic!("factory unexpectedly succeeded without a sealed install"),
            Err(error) => assert_eq!(error, WalIdempotencyError::Precondition),
        }

        let wrapped = BASE64_STANDARD.encode([9; 64]);
        let media_plan =
            MediaDekInstallPlan::new_for_cross_domain_test(ACCOUNT.to_owned(), wrapped, &dek)
                .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(media_plan).unwrap(),
        )
        .unwrap();

        // With the sealed install durable, the factory returns an applicable
        // opaque candidate plan.
        let factory_plan = crate::cp::query::wal::prepare_selected_screenshot_upload_candidate(
            &connection,
            ACCOUNT,
            &attempt_receipt,
            7,
            SOURCE_KEY,
            CAPTURED_AT,
            &jpeg,
            &dek,
            &plaintext,
            ciphertext.clone(),
        )
        .unwrap();
        let applied = execute(&mut connection, factory_plan).unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);

        // Tampering with the durable install row's binding commitment must
        // fail the factory's own ledger reauthentication closed (the stored
        // fingerprint no longer covers the row), before candidate
        // construction can even inspect the DEK.
        connection
            .execute(
                "UPDATE archive_v3_wal_media_dek_install_operations SET binding_commitment=?1",
                [vec![0x5a; 32]],
            )
            .unwrap();
        let tampered = crate::cp::query::wal::prepare_selected_screenshot_upload_candidate(
            &connection,
            ACCOUNT,
            &attempt_receipt,
            7,
            SOURCE_KEY,
            CAPTURED_AT,
            &jpeg,
            &dek,
            &plaintext,
            ciphertext,
        );
        match tampered {
            Ok(_) => panic!("factory unexpectedly accepted a tampered install row"),
            Err(error) => assert_eq!(error, WalIdempotencyError::FingerprintConflict),
        }
    }
}
