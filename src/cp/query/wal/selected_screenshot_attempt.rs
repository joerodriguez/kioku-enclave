#![allow(
    dead_code,
    reason = "inactive ADR-0022 selected-screenshot attempt is reviewed before provider or launcher ownership"
)]

//! Inactive pre-provider identity for one selected-screenshot upload attempt.
//!
//! The caller fixes a nonzero opaque attempt ID before actor admission. This
//! child reauthenticates the complete eligible screenshot target and atomically
//! reserves its count/bytes while retaining the exact numeric screenshot ID,
//! account-bound object key, predecessor commitment, request fingerprint,
//! binding, and typed receipt. Its sibling A codec can reauthenticate only one
//! exact binding for local settlement. This child cannot allocate randomness or
//! a DEK, read media bytes, encrypt, call a provider or Store, launch work,
//! retry, release a rejected reservation, clean up an object, or acknowledge a
//! request.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

use super::super::{
    validate_screenshot_upload_target, ScreenshotUploadTarget, ValidatedJpeg, MAX_EPISODE_IMAGES,
    MAX_EPISODE_IMAGE_BYTES, MAX_SCREENSHOT_IMAGE_BYTES, MAX_SCREENSHOT_LONG_EDGE,
    MAX_SCREENSHOT_METADATA_FIELD_BYTES,
};

const REQUEST_V1: u16 = 1;
const REQUEST_SELECTED_SCREENSHOT_ATTEMPT: u8 = 2;
const RESULT_V1: u16 = 1;
const RESULT_SELECTED_SCREENSHOT_ATTEMPT: u8 = 2;
const OPERATION_SOURCE_DOMAIN: &[u8] = b"selected-screenshot-upload-attempt-v1\0";
const PREDECESSOR_DOMAIN: &[u8] = b"archive-v3-selected-screenshot-predecessor-v1\0";
const BINDING_DOMAIN: &[u8] = b"archive-v3-selected-screenshot-upload-binding-v1\0";
const MAX_ACCOUNT_ID_BYTES: usize = 128;
const MAX_OBJECT_KEY_BYTES: usize = 512;
const MAX_ENCODED_RESULT_BYTES: usize = 1024;
const SCHEMA_TABLE: &str = "archive_v3_wal_selected_screenshot_attempt_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_selected_screenshot_attempt_operations";
const STATE_TABLE: &str = "archive_v3_wal_selected_screenshot_attempt_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 128 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cp::query) struct SelectedScreenshotAttemptTarget {
    screenshot_id: i64,
    predecessor_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedScreenshotAttemptReceipt {
    image_id: String,
    object_key: String,
    binding_commitment: [u8; 32],
}

impl SelectedScreenshotAttemptReceipt {
    pub(in crate::cp::query) fn image_id(&self) -> &str {
        &self.image_id
    }

    pub(in crate::cp::query) fn object_key(&self) -> &str {
        &self.object_key
    }

    pub(in crate::cp::query) const fn binding_commitment(&self) -> [u8; 32] {
        self.binding_commitment
    }
}

/// Exact local reservation for a future selected-screenshot provider attempt.
/// The attempt/image ID is caller-fixed; its account-bound object key is
/// derived here and is never accepted as an independent authority input.
pub(crate) struct SelectedScreenshotAttemptPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    image_id: String,
    object_key: String,
    episode_id: i64,
    screenshot_id: i64,
    source_key: String,
    captured_at: String,
    jpeg: ValidatedJpeg,
    predecessor_commitment: [u8; 32],
    receipt: SelectedScreenshotAttemptReceipt,
}

impl SelectedScreenshotAttemptPlan {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::query) fn new(
        account_id: String,
        image_id: String,
        episode_id: i64,
        source_key: String,
        captured_at: String,
        jpeg: ValidatedJpeg,
        target: SelectedScreenshotAttemptTarget,
    ) -> Result<Self> {
        Self::build(
            None,
            account_id,
            image_id,
            episode_id,
            source_key,
            captured_at,
            jpeg,
            target,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        operation_id: Option<WalLogicalOperationId>,
        account_id: String,
        image_id: String,
        episode_id: i64,
        source_key: String,
        captured_at: String,
        jpeg: ValidatedJpeg,
        target: SelectedScreenshotAttemptTarget,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if account_id.len() > MAX_ACCOUNT_ID_BYTES
            || !super::valid_lower_hex(&image_id, 32)
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
            || usize::try_from(jpeg.byte_length)
                .ok()
                .is_none_or(|length| length > MAX_SCREENSHOT_IMAGE_BYTES)
            || !super::valid_lower_hex(&jpeg.sha256, 64)
            || target.screenshot_id <= 0
            || target.predecessor_commitment == [0; 32]
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let object_key = crate::store::selected_evidence_media_object_key(&account_id, &image_id)
            .map_err(|_| WalIdempotencyError::Malformed)?;
        if object_key.is_empty() || object_key.len() > MAX_OBJECT_KEY_BYTES {
            return Err(WalIdempotencyError::Malformed);
        }
        let binding_commitment = derive_binding_commitment(
            &account_id,
            &image_id,
            &object_key,
            episode_id,
            target.screenshot_id,
            &source_key,
            &captured_at,
            &jpeg,
            &target.predecessor_commitment,
        )?;
        let operation_id = match operation_id {
            Some(value) => value,
            None => {
                let mut source = Vec::with_capacity(
                    OPERATION_SOURCE_DOMAIN.len().saturating_add(image_id.len()),
                );
                source.extend_from_slice(OPERATION_SOURCE_DOMAIN);
                source.extend_from_slice(image_id.as_bytes());
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::SelectedScreenshot,
                    &source,
                )?
            }
        };
        Ok(Self {
            operation_id,
            account_id,
            image_id: image_id.clone(),
            object_key: object_key.clone(),
            episode_id,
            screenshot_id: target.screenshot_id,
            source_key,
            captured_at,
            jpeg,
            predecessor_commitment: target.predecessor_commitment,
            receipt: SelectedScreenshotAttemptReceipt {
                image_id,
                object_key,
                binding_commitment,
            },
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        account_id: String,
        image_id: String,
        episode_id: i64,
        source_key: String,
        captured_at: String,
        jpeg: ValidatedJpeg,
        target: SelectedScreenshotAttemptTarget,
    ) -> Result<Self> {
        Self::build(
            Some(operation_id),
            account_id,
            image_id,
            episode_id,
            source_key,
            captured_at,
            jpeg,
            target,
        )
    }
}

pub(crate) struct SelectedScreenshotAttemptLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for SelectedScreenshotAttemptPlan {
    type Ledger = SelectedScreenshotAttemptLedger;
    type Output = SelectedScreenshotAttemptReceipt;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::SelectedScreenshot
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        request.push(REQUEST_SELECTED_SCREENSHOT_ATTEMPT);
        super::append_string(&mut request, &self.account_id)?;
        super::append_string(&mut request, &self.image_id)?;
        super::append_string(&mut request, &self.object_key)?;
        request.extend_from_slice(&self.episode_id.to_be_bytes());
        request.extend_from_slice(&self.screenshot_id.to_be_bytes());
        super::append_string(&mut request, &self.source_key)?;
        super::append_string(&mut request, &self.captured_at)?;
        request.extend_from_slice(&self.jpeg.width.to_be_bytes());
        request.extend_from_slice(&self.jpeg.height.to_be_bytes());
        request.extend_from_slice(&self.jpeg.byte_length.to_be_bytes());
        request.extend_from_slice(self.jpeg.sha256.as_bytes());
        request.extend_from_slice(&self.predecessor_commitment);
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let current = authenticate_selected_screenshot_upload_predecessor(
            transaction,
            &self.account_id,
            self.episode_id,
            &self.source_key,
            &self.captured_at,
            &self.jpeg,
        )?;
        if current.screenshot_id != self.screenshot_id
            || current.predecessor_commitment != self.predecessor_commitment
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let reserved_target = transaction
            .query_row(
                "SELECT COUNT(*)
                 FROM archive_v3_wal_selected_screenshot_attempt_operations
                 WHERE source_key=?1",
                [&self.source_key],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if reserved_target != 0 {
            return Err(WalIdempotencyError::Precondition);
        }
        let collisions = transaction
            .query_row(
                "SELECT COUNT(*)
                 FROM archive_v3_wal_selected_screenshot_attempt_operations
                 WHERE image_id=?1 OR object_key=?2",
                params![self.image_id, self.object_key],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if collisions != 0 {
            return Err(WalIdempotencyError::Corrupt);
        }
        let local_collisions = transaction
            .query_row(
                "SELECT COUNT(*) FROM screenshot_images
                 WHERE id=?1 OR object_key=?2",
                params![self.image_id, self.object_key],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if local_collisions != 0 {
            return Err(WalIdempotencyError::Corrupt);
        }
        validate_episode_budget_reservation(transaction, self)?;
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

impl WalLogicalDomainLedger<SelectedScreenshotAttemptPlan> for SelectedScreenshotAttemptLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<SelectedScreenshotAttemptPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT operation_id,format_version,codec_version,request_fingerprint,
                        account_id,image_id,object_key,episode_id,screenshot_id,source_key,captured_at,
                        width,height,byte_length,sha256,predecessor_commitment,
                        binding_commitment,result_bytes,result_commitment
                 FROM archive_v3_wal_selected_screenshot_attempt_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                StoredLedgerRow::from_row,
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let plan = prepared.plan_for_domain_ledger();
        if row.format_version != i64::from(WalOperationKind::format_version())
            || row.codec_version != i64::from(WalOperationKind::SelectedScreenshot.codec_version())
            || row.request_fingerprint.len() != 32
            || row.predecessor_commitment.len() != 32
            || row.binding_commitment.len() != 32
            || row.result_commitment.len() != 32
            || row.result_bytes.len() > MAX_ENCODED_RESULT_BYTES
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        if row.request_fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        if !row.matches_plan(plan) {
            return Err(WalIdempotencyError::Corrupt);
        }
        let stored_target = SelectedScreenshotAttemptTarget {
            screenshot_id: row.screenshot_id,
            predecessor_commitment: row
                .predecessor_commitment
                .as_slice()
                .try_into()
                .map_err(|_| WalIdempotencyError::Corrupt)?,
        };
        let expected = SelectedScreenshotAttemptPlan::build(
            None,
            row.account_id.clone(),
            row.image_id.clone(),
            row.episode_id,
            row.source_key.clone(),
            row.captured_at.clone(),
            ValidatedJpeg {
                width: row.width,
                height: row.height,
                byte_length: row.byte_length,
                sha256: row.sha256.clone(),
            },
            stored_target,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
        if row.operation_id.as_slice() != expected.operation_id.as_bytes().as_slice()
            || row.binding_commitment.as_slice() != expected.receipt.binding_commitment.as_slice()
        {
            return Err(WalIdempotencyError::Corrupt);
        }
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
        validate_bound_result_if_present(connection, plan)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<SelectedScreenshotAttemptPlan>,
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
                "INSERT INTO archive_v3_wal_selected_screenshot_attempt_operations
                 (operation_id,format_version,codec_version,request_fingerprint,
                  account_id,image_id,object_key,episode_id,screenshot_id,source_key,captured_at,
                  width,height,byte_length,sha256,predecessor_commitment,
                  binding_commitment,result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
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
                    plan.screenshot_id,
                    plan.source_key,
                    plan.captured_at,
                    plan.jpeg.width,
                    plan.jpeg.height,
                    plan.jpeg.byte_length,
                    plan.jpeg.sha256,
                    plan.predecessor_commitment.as_slice(),
                    plan.receipt.binding_commitment.as_slice(),
                    encoded.as_slice(),
                    result_commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_attempt_state
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

struct StoredLedgerRow {
    operation_id: Vec<u8>,
    format_version: i64,
    codec_version: i64,
    request_fingerprint: Vec<u8>,
    account_id: String,
    image_id: String,
    object_key: String,
    episode_id: i64,
    screenshot_id: i64,
    source_key: String,
    captured_at: String,
    width: i32,
    height: i32,
    byte_length: i64,
    sha256: String,
    predecessor_commitment: Vec<u8>,
    binding_commitment: Vec<u8>,
    result_bytes: Vec<u8>,
    result_commitment: Vec<u8>,
}

impl StoredLedgerRow {
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
            screenshot_id: row.get(8)?,
            source_key: row.get(9)?,
            captured_at: row.get(10)?,
            width: row.get(11)?,
            height: row.get(12)?,
            byte_length: row.get(13)?,
            sha256: row.get(14)?,
            predecessor_commitment: row.get(15)?,
            binding_commitment: row.get(16)?,
            result_bytes: row.get(17)?,
            result_commitment: row.get(18)?,
        })
    }

    fn matches_plan(&self, plan: &SelectedScreenshotAttemptPlan) -> bool {
        self.operation_id.as_slice() == plan.operation_id.as_bytes().as_slice()
            && self.account_id == plan.account_id
            && self.image_id == plan.image_id
            && self.object_key == plan.object_key
            && self.episode_id == plan.episode_id
            && self.screenshot_id == plan.screenshot_id
            && self.source_key == plan.source_key
            && self.captured_at == plan.captured_at
            && self.width == plan.jpeg.width
            && self.height == plan.jpeg.height
            && self.byte_length == plan.jpeg.byte_length
            && self.sha256 == plan.jpeg.sha256
            && self.predecessor_commitment.as_slice() == plan.predecessor_commitment.as_slice()
            && self.binding_commitment.as_slice() == plan.receipt.binding_commitment.as_slice()
    }
}

/// Reauthenticates one permanent pre-provider selected-screenshot attempt for
/// its exact local result. The caller receives only the bound numeric
/// screenshot identity; it cannot enumerate attempts or recover an unrelated
/// object capability.
#[allow(clippy::too_many_arguments)]
pub(in crate::cp::query) fn authenticate_selected_screenshot_attempt_binding(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
    object_key: &str,
    episode_id: i64,
    source_key: &str,
    captured_at: &str,
    jpeg: &ValidatedJpeg,
    binding_commitment: &[u8; 32],
) -> Result<i64> {
    if schema_state(connection)? == LedgerSchemaState::Absent {
        return Err(WalIdempotencyError::Precondition);
    }
    validate_schema_marker(connection)?;
    let row = connection
        .query_row(
            "SELECT operation_id,format_version,codec_version,request_fingerprint,
                    account_id,image_id,object_key,episode_id,screenshot_id,source_key,captured_at,
                    width,height,byte_length,sha256,predecessor_commitment,
                    binding_commitment,result_bytes,result_commitment
             FROM archive_v3_wal_selected_screenshot_attempt_operations
             WHERE image_id=?1",
            [image_id],
            StoredLedgerRow::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
    if row.operation_id.len() != 16
        || row.request_fingerprint.len() != 32
        || row.predecessor_commitment.len() != 32
        || row.binding_commitment.len() != 32
        || row.result_commitment.len() != 32
        || row.result_bytes.len() > MAX_ENCODED_RESULT_BYTES
        || row.format_version != i64::from(WalOperationKind::format_version())
        || row.codec_version != i64::from(WalOperationKind::SelectedScreenshot.codec_version())
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let target = SelectedScreenshotAttemptTarget {
        screenshot_id: row.screenshot_id,
        predecessor_commitment: row
            .predecessor_commitment
            .as_slice()
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?,
    };
    let expected = SelectedScreenshotAttemptPlan::build(
        None,
        row.account_id.clone(),
        row.image_id.clone(),
        row.episode_id,
        row.source_key.clone(),
        row.captured_at.clone(),
        ValidatedJpeg {
            width: row.width,
            height: row.height,
            byte_length: row.byte_length,
            sha256: row.sha256.clone(),
        },
        target,
    )
    .map_err(|_| WalIdempotencyError::Corrupt)?;
    if row.operation_id.as_slice() != expected.operation_id.as_bytes().as_slice()
        || row.object_key != expected.object_key
        || row.binding_commitment.as_slice() != expected.receipt.binding_commitment.as_slice()
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let prepared =
        PreparedLogicalMutation::prepare(expected).map_err(|_| WalIdempotencyError::Corrupt)?;
    if row.request_fingerprint.as_slice()
        != prepared
            .request_fingerprint_for_owner()
            .as_bytes()
            .as_slice()
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    SelectedScreenshotAttemptLedger::lookup(connection, &prepared)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    if row.account_id != account_id
        || row.image_id != image_id
        || row.object_key != object_key
        || row.episode_id != episode_id
        || row.source_key != source_key
        || row.captured_at != captured_at
        || row.width != jpeg.width
        || row.height != jpeg.height
        || row.byte_length != jpeg.byte_length
        || row.sha256 != jpeg.sha256
        || row.binding_commitment.as_slice() != binding_commitment
    {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(row.screenshot_id)
}

/// Candidate preparation authenticates the same permanent B binding but must
/// still precede any exact local A settlement. A committed matching A row is a
/// valid later state for ordinary B replay, not permission to prepare another
/// provider candidate.
#[allow(clippy::too_many_arguments)]
pub(in crate::cp::query) fn authenticate_unconsumed_selected_screenshot_attempt(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
    object_key: &str,
    episode_id: i64,
    source_key: &str,
    captured_at: &str,
    jpeg: &ValidatedJpeg,
    binding_commitment: &[u8; 32],
) -> Result<i64> {
    let screenshot_id = authenticate_selected_screenshot_attempt_binding(
        connection,
        account_id,
        image_id,
        object_key,
        episode_id,
        source_key,
        captured_at,
        jpeg,
        binding_commitment,
    )?;
    let matches = connection
        .query_row(
            "SELECT COUNT(*) FROM screenshot_images
             WHERE source_key=?1 OR id=?2 OR object_key=?3",
            params![source_key, image_id, object_key],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match matches {
        0 => Ok(screenshot_id),
        1 => Err(WalIdempotencyError::Precondition),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

pub(in crate::cp::query) fn authenticate_selected_screenshot_upload_predecessor(
    connection: &Connection,
    account_id: &str,
    episode_id: i64,
    source_key: &str,
    captured_at: &str,
    jpeg: &ValidatedJpeg,
) -> Result<SelectedScreenshotAttemptTarget> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    let target = validate_screenshot_upload_target(
        connection,
        episode_id,
        source_key,
        captured_at,
        &jpeg.sha256,
        jpeg.byte_length,
    )
    .map_err(super::map_domain_error)?;
    let ScreenshotUploadTarget::New {
        screenshot_id,
        captured_at: stored_captured_at,
    } = target
    else {
        return Err(WalIdempotencyError::Precondition);
    };
    let topology = load_selected_screenshot_topology(connection, source_key, episode_id)?
        .ok_or(WalIdempotencyError::Precondition)?;
    if topology.screenshot_id != screenshot_id
        || topology.captured_at != stored_captured_at
        || topology.captured_at != captured_at
        || topology.screenshot_id <= 0
        || topology.is_duplicate != 0
        || topology.substance != "normal"
        || topology.visual_evidence != "useful"
        || topology.image_count < 0
        || topology.image_bytes < 0
    {
        return Err(WalIdempotencyError::Precondition);
    }
    let mut hasher = Sha256::new();
    hasher.update(PREDECESSOR_DOMAIN);
    hash_field(&mut hasher, account_id.as_bytes())?;
    hash_field(&mut hasher, &episode_id.to_be_bytes())?;
    hash_field(&mut hasher, source_key.as_bytes())?;
    hash_field(&mut hasher, captured_at.as_bytes())?;
    hash_field(&mut hasher, &jpeg.width.to_be_bytes())?;
    hash_field(&mut hasher, &jpeg.height.to_be_bytes())?;
    hash_field(&mut hasher, &jpeg.byte_length.to_be_bytes())?;
    hash_field(&mut hasher, jpeg.sha256.as_bytes())?;
    hash_field(&mut hasher, &topology.screenshot_id.to_be_bytes())?;
    hash_field(&mut hasher, topology.captured_at.as_bytes())?;
    hash_field(&mut hasher, &topology.is_duplicate.to_be_bytes())?;
    hash_field(&mut hasher, topology.substance.as_bytes())?;
    hash_field(&mut hasher, topology.visual_evidence.as_bytes())?;
    hash_field(&mut hasher, &topology.image_count.to_be_bytes())?;
    hash_field(&mut hasher, &topology.image_bytes.to_be_bytes())?;
    Ok(SelectedScreenshotAttemptTarget {
        screenshot_id,
        predecessor_commitment: nonzero_hash(hasher)?,
    })
}

struct SelectedScreenshotTopology {
    screenshot_id: i64,
    captured_at: String,
    is_duplicate: i64,
    substance: String,
    visual_evidence: String,
    image_count: i64,
    image_bytes: i64,
}

fn load_selected_screenshot_topology(
    connection: &Connection,
    source_key: &str,
    episode_id: i64,
) -> Result<Option<SelectedScreenshotTopology>> {
    connection
        .query_row(
            "SELECT c.id,c.captured_at,c.is_duplicate,e.substance,e.visual_evidence,
                    (SELECT COUNT(*) FROM screenshot_images WHERE episode_id=?2),
                    (SELECT COALESCE(SUM(byte_length),0) FROM screenshot_images WHERE episode_id=?2)
             FROM screenshots c
             JOIN episode_members m
               ON m.record_type='screenshot' AND m.record_id=c.id
             JOIN episodes e ON e.id=m.episode_id
             WHERE c.source_key=?1 AND e.id=?2",
            params![source_key, episode_id],
            |row| {
                Ok(SelectedScreenshotTopology {
                    screenshot_id: row.get(0)?,
                    captured_at: row.get(1)?,
                    is_duplicate: row.get(2)?,
                    substance: row.get(3)?,
                    visual_evidence: row.get(4)?,
                    image_count: row.get(5)?,
                    image_bytes: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn validate_bound_result_if_present(
    connection: &Connection,
    plan: &SelectedScreenshotAttemptPlan,
) -> Result<()> {
    let matches = connection
        .query_row(
            "SELECT COUNT(*) FROM screenshot_images
             WHERE source_key=?1 OR id=?2 OR object_key=?3",
            params![plan.source_key, plan.image_id, plan.object_key],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if !(0..=1).contains(&matches) {
        return Err(WalIdempotencyError::Corrupt);
    }
    if matches == 0 {
        return Ok(());
    }
    let stored = connection
        .query_row(
            "SELECT id,screenshot_id,episode_id,source_key,captured_at,object_key,
                    mime_type,width,height,byte_length,sha256
             FROM screenshot_images
             WHERE source_key=?1 OR id=?2 OR object_key=?3",
            params![plan.source_key, plan.image_id, plan.object_key],
            StoredBoundResult::from_row,
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if !matches_stored_result(plan, &stored) {
        return Err(WalIdempotencyError::Corrupt);
    }
    let topology =
        load_selected_screenshot_topology(connection, &plan.source_key, plan.episode_id)?
            .ok_or(WalIdempotencyError::Corrupt)?;
    if topology.screenshot_id != plan.screenshot_id
        || topology.captured_at != plan.captured_at
        || topology.is_duplicate != 0
        || topology.substance != "normal"
        || topology.visual_evidence != "useful"
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

struct StoredBoundResult {
    id: String,
    screenshot_id: i64,
    episode_id: i64,
    source_key: String,
    captured_at: String,
    object_key: String,
    mime_type: String,
    width: i32,
    height: i32,
    byte_length: i64,
    sha256: String,
}

impl StoredBoundResult {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            screenshot_id: row.get(1)?,
            episode_id: row.get(2)?,
            source_key: row.get(3)?,
            captured_at: row.get(4)?,
            object_key: row.get(5)?,
            mime_type: row.get(6)?,
            width: row.get(7)?,
            height: row.get(8)?,
            byte_length: row.get(9)?,
            sha256: row.get(10)?,
        })
    }
}

fn matches_stored_result(plan: &SelectedScreenshotAttemptPlan, stored: &StoredBoundResult) -> bool {
    stored.id == plan.image_id
        && stored.screenshot_id == plan.screenshot_id
        && stored.episode_id == plan.episode_id
        && stored.source_key == plan.source_key
        && stored.captured_at == plan.captured_at
        && stored.object_key == plan.object_key
        && stored.mime_type == "image/jpeg"
        && stored.width == plan.jpeg.width
        && stored.height == plan.jpeg.height
        && stored.byte_length == plan.jpeg.byte_length
        && stored.sha256 == plan.jpeg.sha256
}

fn validate_episode_budget_reservation(
    connection: &Connection,
    plan: &SelectedScreenshotAttemptPlan,
) -> Result<()> {
    let (committed_count, committed_bytes) = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(byte_length),0)
             FROM screenshot_images WHERE episode_id=?1",
            [plan.episode_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let (pending_count, pending_bytes) = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(a.byte_length),0)
             FROM archive_v3_wal_selected_screenshot_attempt_operations a
             WHERE a.episode_id=?1
               AND NOT EXISTS (
                 SELECT 1 FROM screenshot_images s
                 WHERE s.id=a.image_id
                   AND s.screenshot_id=a.screenshot_id
                   AND s.episode_id=a.episode_id
                   AND s.source_key=a.source_key
                   AND s.captured_at=a.captured_at
                   AND s.object_key=a.object_key
                   AND s.mime_type='image/jpeg'
                   AND s.width=a.width
                   AND s.height=a.height
                   AND s.byte_length=a.byte_length
                   AND s.sha256=a.sha256
               )",
            [plan.episode_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if committed_count < 0 || committed_bytes < 0 || pending_count < 0 || pending_bytes < 0 {
        return Err(WalIdempotencyError::Corrupt);
    }
    let projected_count = committed_count
        .checked_add(pending_count)
        .and_then(|count| count.checked_add(1))
        .ok_or(WalIdempotencyError::Corrupt)?;
    let projected_bytes = committed_bytes
        .checked_add(pending_bytes)
        .and_then(|bytes| bytes.checked_add(plan.jpeg.byte_length))
        .ok_or(WalIdempotencyError::Corrupt)?;
    if projected_count > MAX_EPISODE_IMAGES || projected_bytes > MAX_EPISODE_IMAGE_BYTES {
        return Err(WalIdempotencyError::Precondition);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn derive_binding_commitment(
    account_id: &str,
    image_id: &str,
    object_key: &str,
    episode_id: i64,
    screenshot_id: i64,
    source_key: &str,
    captured_at: &str,
    jpeg: &ValidatedJpeg,
    predecessor_commitment: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hash_field(&mut hasher, account_id.as_bytes())?;
    hash_field(&mut hasher, image_id.as_bytes())?;
    hash_field(&mut hasher, object_key.as_bytes())?;
    hash_field(&mut hasher, &episode_id.to_be_bytes())?;
    hash_field(&mut hasher, &screenshot_id.to_be_bytes())?;
    hash_field(&mut hasher, source_key.as_bytes())?;
    hash_field(&mut hasher, captured_at.as_bytes())?;
    hash_field(&mut hasher, &jpeg.width.to_be_bytes())?;
    hash_field(&mut hasher, &jpeg.height.to_be_bytes())?;
    hash_field(&mut hasher, &jpeg.byte_length.to_be_bytes())?;
    hash_field(&mut hasher, jpeg.sha256.as_bytes())?;
    hash_field(&mut hasher, predecessor_commitment)?;
    nonzero_hash(hasher)
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

fn nonzero_hash(hasher: Sha256) -> Result<[u8; 32]> {
    let commitment: [u8; 32] = hasher.finalize().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn encode_receipt(receipt: &SelectedScreenshotAttemptReceipt) -> Result<WalReplayResult> {
    let mut bytes = Vec::with_capacity(MAX_ENCODED_RESULT_BYTES);
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(RESULT_SELECTED_SCREENSHOT_ATTEMPT);
    super::append_string(&mut bytes, &receipt.image_id)?;
    super::append_string(&mut bytes, &receipt.object_key)?;
    bytes.extend_from_slice(&receipt.binding_commitment);
    WalReplayResult::canonical_response(WalOperationKind::SelectedScreenshot, bytes)
}

fn decode_receipt(result: &WalReplayResult) -> Result<SelectedScreenshotAttemptReceipt> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    let mut reader = super::ResultReader::new(bytes);
    if reader.take_u16()? != RESULT_V1 || reader.take_u8()? != RESULT_SELECTED_SCREENSHOT_ATTEMPT {
        return Err(WalIdempotencyError::Corrupt);
    }
    let image_id = reader.take_string()?;
    let object_key = reader.take_string()?;
    let binding_commitment: [u8; 32] = reader
        .take(32)?
        .try_into()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if !reader.is_empty()
        || !super::valid_lower_hex(&image_id, 32)
        || object_key.is_empty()
        || object_key.len() > MAX_OBJECT_KEY_BYTES
        || binding_commitment == [0; 32]
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(SelectedScreenshotAttemptReceipt {
        image_id,
        object_key,
        binding_commitment,
    })
}

fn require_kind(prepared: &PreparedLogicalMutation<SelectedScreenshotAttemptPlan>) -> Result<()> {
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
                    "CREATE TABLE archive_v3_wal_selected_screenshot_attempt_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_selected_screenshot_attempt_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        account_id TEXT NOT NULL,
                        image_id TEXT NOT NULL UNIQUE,
                        object_key TEXT NOT NULL UNIQUE,
                        episode_id INTEGER NOT NULL CHECK(episode_id>0),
                        screenshot_id INTEGER NOT NULL CHECK(screenshot_id>0),
                        source_key TEXT NOT NULL UNIQUE,
                        captured_at TEXT NOT NULL,
                        width INTEGER NOT NULL CHECK(width BETWEEN 1 AND 960),
                        height INTEGER NOT NULL CHECK(height BETWEEN 1 AND 960),
                        byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 153600),
                        sha256 TEXT NOT NULL,
                        predecessor_commitment BLOB NOT NULL,
                        binding_commitment BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(account_id) BETWEEN 1 AND 128),
                        CHECK(length(image_id)=32),
                        CHECK(length(object_key) BETWEEN 1 AND 512),
                        CHECK(length(source_key) BETWEEN 1 AND 512),
                        CHECK(length(captured_at) BETWEEN 1 AND 512),
                        CHECK(length(sha256)=64),
                        CHECK(length(predecessor_commitment)=32 AND predecessor_commitment<>zeroblob(32)),
                        CHECK(length(binding_commitment)=32 AND binding_commitment<>zeroblob(32)),
                        CHECK(length(result_bytes) BETWEEN 80 AND 1024),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_selected_screenshot_attempt_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 134217728)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_selected_screenshot_attempt_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_selected_screenshot_attempt_state
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
             FROM archive_v3_wal_selected_screenshot_attempt_schema WHERE singleton=1",
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
             FROM archive_v3_wal_selected_screenshot_attempt_state WHERE singleton=1",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };

    const ACCOUNT: &str = "account-1";
    const SOURCE: &str = "device-1:screen-1";
    const SOURCE_TWO: &str = "device-1:screen-2";
    const CAPTURED: &str = "2026-08-15T12:00:00.000Z";
    const CAPTURED_TWO: &str = "2026-08-15T12:01:00.000Z";

    fn install_domain_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE episodes(
                    id INTEGER PRIMARY KEY,
                    substance TEXT NOT NULL,
                    visual_evidence TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE screenshots(
                    id INTEGER PRIMARY KEY,
                    source_key TEXT UNIQUE NOT NULL,
                    captured_at TEXT NOT NULL,
                    is_duplicate INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE episode_members(
                    episode_id INTEGER NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id INTEGER NOT NULL,
                    PRIMARY KEY(episode_id,record_type,record_id)
                 ) STRICT, WITHOUT ROWID;
                 CREATE TABLE screenshot_images(
                    id TEXT PRIMARY KEY NOT NULL,
                    screenshot_id INTEGER NOT NULL,
                    episode_id INTEGER NOT NULL,
                    source_key TEXT UNIQUE NOT NULL,
                    captured_at TEXT NOT NULL,
                    object_key TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    width INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    byte_length INTEGER NOT NULL,
                    sha256 TEXT NOT NULL
                 ) STRICT;
                 INSERT INTO episodes(id,substance,visual_evidence)
                    VALUES (7,'normal','useful');
                 INSERT INTO screenshots(id,source_key,captured_at,is_duplicate)
                    VALUES (11,'device-1:screen-1','2026-08-15T12:00:00.000Z',0),
                           (12,'device-1:screen-2','2026-08-15T12:01:00.000Z',0);
                 INSERT INTO episode_members(episode_id,record_type,record_id)
                    VALUES (7,'screenshot',11),(7,'screenshot',12);",
            )
            .unwrap();
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_domain_schema(&connection);
        connection
    }

    fn jpeg(seed: char) -> ValidatedJpeg {
        ValidatedJpeg {
            width: 320,
            height: 180,
            byte_length: 1024,
            sha256: seed.to_string().repeat(64),
        }
    }

    fn plan_for(
        connection: &Connection,
        image_seed: char,
        jpeg_seed: char,
    ) -> SelectedScreenshotAttemptPlan {
        plan_for_target(connection, image_seed, jpeg_seed, SOURCE, CAPTURED)
    }

    fn plan_for_target(
        connection: &Connection,
        image_seed: char,
        jpeg_seed: char,
        source_key: &str,
        captured_at: &str,
    ) -> SelectedScreenshotAttemptPlan {
        let jpeg = jpeg(jpeg_seed);
        let target = authenticate_selected_screenshot_upload_predecessor(
            connection,
            ACCOUNT,
            7,
            source_key,
            captured_at,
            &jpeg,
        )
        .unwrap();
        SelectedScreenshotAttemptPlan::new(
            ACCOUNT.to_owned(),
            image_seed.to_string().repeat(32),
            7,
            source_key.to_owned(),
            captured_at.to_owned(),
            jpeg,
            target,
        )
        .unwrap()
    }

    fn insert_exact_result(
        connection: &Connection,
        image_seed: char,
        jpeg_seed: char,
        screenshot_id: i64,
        source_key: &str,
        captured_at: &str,
    ) {
        let image_id = image_seed.to_string().repeat(32);
        connection
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,
                  mime_type,width,height,byte_length,sha256)
                 VALUES (?1,?2,7,?3,?4,?5,'image/jpeg',320,180,1024,?6)",
                params![
                    image_id,
                    screenshot_id,
                    source_key,
                    captured_at,
                    crate::store::selected_evidence_media_object_key(
                        ACCOUNT,
                        &image_seed.to_string().repeat(32),
                    )
                    .unwrap(),
                    jpeg_seed.to_string().repeat(64),
                ],
            )
            .unwrap();
    }

    fn insert_committed_budget_rows(connection: &Connection, count: i64, byte_length: i64) {
        for ordinal in 0..count {
            connection
                .execute(
                    "INSERT INTO screenshot_images
                     (id,screenshot_id,episode_id,source_key,captured_at,object_key,
                      mime_type,width,height,byte_length,sha256)
                     VALUES (?1,?2,7,?3,?4,?5,'image/jpeg',1,1,?6,?7)",
                    params![
                        format!("{ordinal:032x}"),
                        10_000_i64 + ordinal,
                        format!("budget-source-{ordinal}"),
                        format!("2026-08-15T13:{ordinal:02}:00.000Z"),
                        format!("budget-object-{ordinal}"),
                        byte_length,
                        format!("{:064x}", ordinal + 1),
                    ],
                )
                .unwrap();
        }
    }

    fn execute(
        connection: &mut Connection,
        plan: SelectedScreenshotAttemptPlan,
    ) -> std::result::Result<
        crate::archive_v3_wal_idempotency::ExecutedLogicalMutation<SelectedScreenshotAttemptPlan>,
        WalIdempotencyError,
    > {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared)
    }

    fn execute_error(
        connection: &mut Connection,
        plan: SelectedScreenshotAttemptPlan,
    ) -> WalIdempotencyError {
        match execute(connection, plan) {
            Ok(_) => panic!("mutation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn exact_attempt_applies_reopens_and_replays_without_local_result_write() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let path = temporary.path().to_owned();
        let mut connection = Connection::open(&path).unwrap();
        install_domain_schema(&connection);
        let replay = plan_for(&connection, 'a', 'b');
        let first = plan_for(&connection, 'a', 'b');
        let operation_id = first.operation_id();
        assert_ne!(
            operation_id,
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::SelectedScreenshot,
                first.image_id.as_bytes(),
            )
            .unwrap()
        );
        let applied = execute(&mut connection, first).unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        let receipt = applied.into_validated_result().release().unwrap();
        assert_eq!(receipt.image_id(), "a".repeat(32));
        assert_eq!(
            receipt.object_key(),
            crate::store::selected_evidence_media_object_key(ACCOUNT, receipt.image_id()).unwrap()
        );
        assert_ne!(receipt.binding_commitment(), [0; 32]);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        drop(connection);

        let mut reopened = Connection::open(&path).unwrap();
        let replay_after_result = plan_for(&reopened, 'a', 'b');
        let replayed = execute(&mut reopened, replay).unwrap();
        assert_eq!(replayed.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(replayed.operation_id(), operation_id);
        assert_eq!(replayed.into_validated_result().release().unwrap(), receipt);
        insert_exact_result(&reopened, 'a', 'b', 11, SOURCE, CAPTURED);
        assert_eq!(
            execute(&mut reopened, replay_after_result)
                .unwrap()
                .disposition(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(load_ledger_state(&reopened).unwrap().0, 1);
    }

    #[test]
    fn replay_rejects_exact_result_rebound_to_another_screenshot() {
        let mut connection = connection();
        let replay_before_rebind = plan_for(&connection, 'a', 'b');
        let replay_after_rebind = plan_for(&connection, 'a', 'b');
        let first = plan_for(&connection, 'a', 'b');
        execute(&mut connection, first).unwrap();
        insert_exact_result(&connection, 'a', 'b', 11, SOURCE, CAPTURED);
        assert_eq!(
            execute(&mut connection, replay_before_rebind)
                .unwrap()
                .disposition(),
            LogicalMutationDisposition::Replayed
        );
        connection
            .execute(
                "UPDATE screenshot_images SET screenshot_id=12 WHERE source_key=?1",
                [SOURCE],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut connection, replay_after_rebind),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn pending_attempts_reserve_episode_count_and_bytes_without_result_double_counting() {
        let mut count_blocked = connection();
        insert_committed_budget_rows(&count_blocked, 23, 1);
        let first = plan_for(&count_blocked, 'a', 'b');
        execute(&mut count_blocked, first).unwrap();
        let second = plan_for_target(&count_blocked, 'c', 'd', SOURCE_TWO, CAPTURED_TWO);
        assert_eq!(
            execute_error(&mut count_blocked, second),
            WalIdempotencyError::Precondition
        );

        let mut consumed = connection();
        insert_committed_budget_rows(&consumed, 22, 1);
        let first = plan_for(&consumed, 'a', 'b');
        execute(&mut consumed, first).unwrap();
        insert_exact_result(&consumed, 'a', 'b', 11, SOURCE, CAPTURED);
        let second = plan_for_target(&consumed, 'c', 'd', SOURCE_TWO, CAPTURED_TWO);
        assert_eq!(
            execute(&mut consumed, second).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );

        let mut bytes_blocked = connection();
        insert_committed_budget_rows(&bytes_blocked, 1, MAX_EPISODE_IMAGE_BYTES - 1024);
        let first = plan_for(&bytes_blocked, 'a', 'b');
        execute(&mut bytes_blocked, first).unwrap();
        let second = plan_for_target(&bytes_blocked, 'c', 'd', SOURCE_TWO, CAPTURED_TWO);
        assert_eq!(
            execute_error(&mut bytes_blocked, second),
            WalIdempotencyError::Precondition
        );
    }

    #[test]
    fn same_attempt_change_conflicts_and_one_target_cannot_reserve_two_attempts() {
        let mut connection = connection();
        let first = plan_for(&connection, 'a', 'b');
        let first_id = first.operation_id();
        execute(&mut connection, first).unwrap();

        let changed = plan_for(&connection, 'a', 'c');
        assert_eq!(
            execute_error(&mut connection, changed),
            WalIdempotencyError::FingerprintConflict
        );
        let duplicate_target = plan_for(&connection, 'd', 'b');
        assert_eq!(
            execute_error(&mut connection, duplicate_target),
            WalIdempotencyError::Precondition
        );
        let second = plan_for_target(&connection, 'd', 'b', SOURCE_TWO, CAPTURED_TWO);
        let second_id = second.operation_id();
        assert_ne!(first_id, second_id);
        assert_eq!(
            execute(&mut connection, second).unwrap().disposition(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(load_ledger_state(&connection).unwrap().0, 2);
    }

    #[test]
    fn changed_or_already_consumed_target_fails_before_attempt_retention() {
        let mut changed = connection();
        let stale = plan_for(&changed, 'a', 'b');
        changed
            .execute("UPDATE episodes SET visual_evidence='none' WHERE id=7", [])
            .unwrap();
        assert_eq!(
            execute_error(&mut changed, stale),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            changed
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name='archive_v3_wal_selected_screenshot_attempt_operations'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        let mut consumed = connection();
        let plan = plan_for(&consumed, 'a', 'b');
        let object_key =
            crate::store::selected_evidence_media_object_key(ACCOUNT, &"a".repeat(32)).unwrap();
        consumed
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,
                  mime_type,width,height,byte_length,sha256)
                 VALUES (?1,11,7,?2,?3,?4,'image/jpeg',320,180,1024,?5)",
                params!["a".repeat(32), SOURCE, CAPTURED, object_key, "b".repeat(64)],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut consumed, plan),
            WalIdempotencyError::Precondition
        );
    }

    #[test]
    fn capacity_and_late_readback_failure_roll_back_the_new_attempt() {
        let mut capacity = connection();
        let first_capacity = plan_for(&capacity, 'a', 'b');
        execute(&mut capacity, first_capacity).unwrap();
        capacity
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_attempt_state
                 SET row_count=?1 WHERE singleton=1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        let over_capacity = plan_for(&capacity, 'c', 'b');
        assert_eq!(
            execute_error(&mut capacity, over_capacity),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            capacity
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_wal_selected_screenshot_attempt_operations",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );

        let mut late = connection();
        let first_late = plan_for(&late, 'a', 'b');
        execute(&mut late, first_late).unwrap();
        late.execute_batch(
            "CREATE TRIGGER rewrite_new_attempt AFTER INSERT
             ON archive_v3_wal_selected_screenshot_attempt_operations
             WHEN NEW.image_id='cccccccccccccccccccccccccccccccc'
             BEGIN
               UPDATE archive_v3_wal_selected_screenshot_attempt_operations
               SET binding_commitment=randomblob(32)
               WHERE operation_id=NEW.operation_id;
             END;",
        )
        .unwrap();
        let rewritten = plan_for_target(&late, 'c', 'b', SOURCE_TWO, CAPTURED_TWO);
        assert_eq!(
            execute_error(&mut late, rewritten),
            WalIdempotencyError::Corrupt
        );
        assert_eq!(load_ledger_state(&late).unwrap().0, 1);
    }

    #[test]
    fn malformed_constructor_and_tampered_permanent_binding_fail_closed() {
        let jpeg = jpeg('b');
        assert!(SelectedScreenshotAttemptPlan::new(
            ACCOUNT.to_owned(),
            "A".repeat(32),
            7,
            SOURCE.to_owned(),
            CAPTURED.to_owned(),
            jpeg.clone(),
            SelectedScreenshotAttemptTarget {
                screenshot_id: 11,
                predecessor_commitment: [1; 32],
            },
        )
        .is_err());
        assert!(SelectedScreenshotAttemptPlan::with_operation_id(
            WalLogicalOperationId::from_bytes([9; 16]).unwrap(),
            ACCOUNT.to_owned(),
            "a".repeat(32),
            7,
            SOURCE.to_owned(),
            CAPTURED.to_owned(),
            jpeg,
            SelectedScreenshotAttemptTarget {
                screenshot_id: 11,
                predecessor_commitment: [0; 32],
            },
        )
        .is_err());

        let mut tampered = connection();
        let replay = plan_for(&tampered, 'a', 'b');
        let first_tampered = plan_for(&tampered, 'a', 'b');
        execute(&mut tampered, first_tampered).unwrap();
        tampered
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_attempt_operations
                 SET binding_commitment=?1",
                [&[7_u8; 32][..]],
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut tampered, replay),
            WalIdempotencyError::Corrupt
        );

        let mut partial = connection();
        let partial_plan = plan_for(&partial, 'a', 'b');
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_selected_screenshot_attempt_schema(
                    singleton INTEGER PRIMARY KEY
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            execute_error(&mut partial, partial_plan),
            WalIdempotencyError::Corrupt
        );
    }
}
