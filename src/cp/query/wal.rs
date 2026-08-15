#![allow(
    dead_code,
    reason = "inactive ADR-0022 query codecs are reviewed before provider, launcher, or route ownership"
)]

//! Inactive query-owned logical WAL domains.
//!
//! The parent owns the selected-screenshot receipt and consumes its private
//! child's permanent pre-provider attempt binding. A second private child
//! verifies and retains the exact context-bound ciphertext candidate for that
//! attempt without send authority. A third private child durably marks the
//! exact candidate `SendStarted` and derives its stable request identity while
//! owning no provider. Another private child owns an exact
//! finalization-queue transition. None can call Store, launch work, invoke a
//! provider, schedule a retry, allocate randomness or a clock, or acknowledge
//! a request.

mod finalization_queue;
mod selected_screenshot_attempt;
mod selected_screenshot_send;
mod selected_screenshot_upload;
pub(crate) use finalization_queue::{FinalizationQueueLedger, FinalizationQueuePlan};
pub(crate) use selected_screenshot_attempt::{
    SelectedScreenshotAttemptLedger, SelectedScreenshotAttemptPlan,
};
pub(crate) use selected_screenshot_send::{
    SelectedScreenshotSendStartedLedger, SelectedScreenshotSendStartedPlan,
};
pub(crate) use selected_screenshot_upload::{
    SelectedScreenshotUploadCandidateLedger, SelectedScreenshotUploadCandidatePlan,
};

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult, MAX_ENCODED_REPLAY_RESULT_BYTES,
};
use crate::error::EnclaveError;

use super::{
    record_screenshot_image_in_transaction, ScreenshotRecordOutcome, StoredScreenshotImage,
    ValidatedJpeg, MAX_SCREENSHOT_IMAGE_BYTES, MAX_SCREENSHOT_LONG_EDGE,
    MAX_SCREENSHOT_METADATA_FIELD_BYTES,
};

const REQUEST_V1: u16 = 1;
const REQUEST_V2: u16 = 2;
const REQUEST_SELECTED_SCREENSHOT: u8 = 1;
const REQUEST_SELECTED_SCREENSHOT_BOUND_ATTEMPT: u8 = 3;
const BOUND_OPERATION_SOURCE_DOMAIN: &[u8] = b"selected-screenshot-result-bound-v2\0";
const RESULT_V1: u16 = 1;
const RESULT_SELECTED_SCREENSHOT: u8 = 1;
const SCHEMA_TABLE: &str = "archive_v3_wal_selected_screenshot_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_selected_screenshot_operations";
const STATE_TABLE: &str = "archive_v3_wal_selected_screenshot_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 512 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

pub(in crate::cp::query) fn prepare_selected_screenshot_send_started(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
    plaintext_dek: &crate::crypto::Dek,
) -> Result<Option<SelectedScreenshotSendStartedPlan>> {
    selected_screenshot_send::prepare_selected_screenshot_send_started(
        connection,
        account_id,
        image_id,
        plaintext_dek,
    )
}

pub(in crate::cp::query) fn load_authenticated_selected_screenshot_send_started(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
    plaintext_dek: &crate::crypto::Dek,
) -> Result<Option<selected_screenshot_send::AuthenticatedSelectedScreenshotSendStarted>> {
    selected_screenshot_send::load_authenticated_selected_screenshot_send_started(
        connection,
        account_id,
        image_id,
        plaintext_dek,
    )
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SelectedScreenshotOutcome {
    image_id: String,
    object_key: String,
    width: i32,
    height: i32,
    byte_length: i64,
    sha256: String,
}

impl SelectedScreenshotOutcome {
    pub(super) fn image_id(&self) -> &str {
        &self.image_id
    }

    pub(super) fn object_key(&self) -> &str {
        &self.object_key
    }

    pub(super) const fn width(&self) -> i32 {
        self.width
    }

    pub(super) const fn height(&self) -> i32 {
        self.height
    }

    pub(super) const fn byte_length(&self) -> i64 {
        self.byte_length
    }

    pub(super) fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl std::fmt::Debug for SelectedScreenshotOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedScreenshotOutcome(<redacted>)")
    }
}

/// Exact local half of an already durable selected-screenshot upload attempt.
/// Production v2 consumes the permanent B binding; historical unbound v1 is
/// test-only.
pub(crate) struct SelectedScreenshotPlan {
    operation_id: WalLogicalOperationId,
    request_contract: SelectedScreenshotRequestContract,
    account_id: String,
    image_id: String,
    object_key: String,
    episode_id: i64,
    source_key: String,
    captured_at: String,
    jpeg: ValidatedJpeg,
}

#[derive(Clone, Copy)]
enum SelectedScreenshotRequestContract {
    UnboundV1,
    BoundV2 {
        attempt_binding_commitment: [u8; 32],
    },
}

impl SelectedScreenshotPlan {
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
    ) -> Result<Self> {
        if attempt_binding_commitment == [0; 32] {
            return Err(WalIdempotencyError::Malformed);
        }
        Self::build(
            SelectedScreenshotRequestContract::BoundV2 {
                attempt_binding_commitment,
            },
            None,
            account_id,
            image_id,
            object_key,
            episode_id,
            source_key,
            captured_at,
            jpeg,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn new_unbound_v1(
        account_id: String,
        image_id: String,
        object_key: String,
        episode_id: i64,
        source_key: String,
        captured_at: String,
        jpeg: ValidatedJpeg,
    ) -> Result<Self> {
        Self::build(
            SelectedScreenshotRequestContract::UnboundV1,
            None,
            account_id,
            image_id,
            object_key,
            episode_id,
            source_key,
            captured_at,
            jpeg,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        request_contract: SelectedScreenshotRequestContract,
        operation_id: Option<WalLogicalOperationId>,
        account_id: String,
        image_id: String,
        object_key: String,
        episode_id: i64,
        source_key: String,
        captured_at: String,
        jpeg: ValidatedJpeg,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        if !valid_lower_hex(&image_id, 32)
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
            || !valid_lower_hex(&jpeg.sha256, 64)
        {
            return Err(WalIdempotencyError::Malformed);
        }
        let expected_object_key =
            crate::store::selected_evidence_media_object_key(&account_id, &image_id)
                .map_err(|_| WalIdempotencyError::Malformed)?;
        if object_key != expected_object_key {
            return Err(WalIdempotencyError::Malformed);
        }
        let operation_id = match (request_contract, operation_id) {
            (_, Some(value)) => value,
            (SelectedScreenshotRequestContract::UnboundV1, None) => {
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::SelectedScreenshot,
                    image_id.as_bytes(),
                )?
            }
            (SelectedScreenshotRequestContract::BoundV2 { .. }, None) => {
                let mut source = Vec::with_capacity(
                    BOUND_OPERATION_SOURCE_DOMAIN
                        .len()
                        .saturating_add(image_id.len()),
                );
                source.extend_from_slice(BOUND_OPERATION_SOURCE_DOMAIN);
                source.extend_from_slice(image_id.as_bytes());
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::SelectedScreenshot,
                    &source,
                )?
            }
        };
        Ok(Self {
            operation_id,
            request_contract,
            account_id,
            image_id,
            object_key,
            episode_id,
            source_key,
            captured_at,
            jpeg,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn with_operation_id(
        operation_id: WalLogicalOperationId,
        account_id: String,
        image_id: String,
        object_key: String,
        episode_id: i64,
        source_key: String,
        captured_at: String,
        jpeg: ValidatedJpeg,
    ) -> Result<Self> {
        Self::build(
            SelectedScreenshotRequestContract::UnboundV1,
            Some(operation_id),
            account_id,
            image_id,
            object_key,
            episode_id,
            source_key,
            captured_at,
            jpeg,
        )
    }

    fn matches_stored(&self, stored: &StoredScreenshotImage) -> bool {
        stored.id == self.image_id
            && stored.episode_id == self.episode_id
            && stored.captured_at == self.captured_at
            && stored.object_key == self.object_key
            && stored.mime_type == "image/jpeg"
            && stored.width == self.jpeg.width
            && stored.height == self.jpeg.height
            && stored.byte_length == self.jpeg.byte_length
            && stored.sha256 == self.jpeg.sha256
    }

    fn expected_outcome(&self) -> SelectedScreenshotOutcome {
        SelectedScreenshotOutcome {
            image_id: self.image_id.clone(),
            object_key: self.object_key.clone(),
            width: self.jpeg.width,
            height: self.jpeg.height,
            byte_length: self.jpeg.byte_length,
            sha256: self.jpeg.sha256.clone(),
        }
    }
}

pub(crate) struct SelectedScreenshotLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

impl WalLogicalDomainPlan for SelectedScreenshotPlan {
    type Ledger = SelectedScreenshotLedger;
    type Output = SelectedScreenshotOutcome;

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::SelectedScreenshot
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::new());
        match self.request_contract {
            SelectedScreenshotRequestContract::UnboundV1 => {
                request.extend_from_slice(&REQUEST_V1.to_be_bytes());
                request.push(REQUEST_SELECTED_SCREENSHOT);
            }
            SelectedScreenshotRequestContract::BoundV2 {
                attempt_binding_commitment,
            } => {
                request.extend_from_slice(&REQUEST_V2.to_be_bytes());
                request.push(REQUEST_SELECTED_SCREENSHOT_BOUND_ATTEMPT);
                request.extend_from_slice(&attempt_binding_commitment);
            }
        }
        append_string(&mut request, &self.account_id)?;
        append_string(&mut request, &self.image_id)?;
        append_string(&mut request, &self.object_key)?;
        request.extend_from_slice(&self.episode_id.to_be_bytes());
        append_string(&mut request, &self.source_key)?;
        append_string(&mut request, &self.captured_at)?;
        request.extend_from_slice(&self.jpeg.width.to_be_bytes());
        request.extend_from_slice(&self.jpeg.height.to_be_bytes());
        request.extend_from_slice(&self.jpeg.byte_length.to_be_bytes());
        request.extend_from_slice(self.jpeg.sha256.as_bytes());
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let bound_screenshot_id = self.authenticate_attempt_binding(transaction)?;
        let observed = record_screenshot_image_in_transaction(
            transaction,
            &self.image_id,
            &self.object_key,
            self.episode_id,
            &self.source_key,
            &self.captured_at,
            &self.jpeg,
        )
        .map_err(map_domain_error)?;
        let stored = match observed {
            ScreenshotRecordOutcome::Created(stored)
            | ScreenshotRecordOutcome::Existing(stored) => stored,
        };
        let screenshot_binding = transaction
            .query_row(
                "SELECT image.screenshot_id,screen.id
                 FROM screenshot_images image
                 JOIN screenshots screen ON screen.source_key=image.source_key
                 WHERE image.source_key=?1",
                [&self.source_key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if screenshot_binding.0 != screenshot_binding.1
            || bound_screenshot_id.is_some_and(|expected| expected != screenshot_binding.0)
        {
            return Err(WalIdempotencyError::Precondition);
        }
        if !self.matches_stored(&stored) {
            return Err(WalIdempotencyError::Precondition);
        }
        encode_outcome(&SelectedScreenshotOutcome::from_stored(stored))
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        let outcome = decode_outcome(result)?;
        if outcome != self.expected_outcome() {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(())
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        let outcome = decode_outcome(result)?;
        self.validate_replay(result)?;
        Ok(outcome)
    }
}

impl SelectedScreenshotPlan {
    fn authenticate_attempt_binding(&self, connection: &Connection) -> Result<Option<i64>> {
        match self.request_contract {
            SelectedScreenshotRequestContract::UnboundV1 => Ok(None),
            SelectedScreenshotRequestContract::BoundV2 {
                attempt_binding_commitment,
            } => selected_screenshot_attempt::authenticate_selected_screenshot_attempt_binding(
                connection,
                &self.account_id,
                &self.image_id,
                &self.object_key,
                self.episode_id,
                &self.source_key,
                &self.captured_at,
                &self.jpeg,
                &attempt_binding_commitment,
            )
            .map(Some),
        }
    }
}

impl SelectedScreenshotOutcome {
    fn from_stored(stored: StoredScreenshotImage) -> Self {
        Self {
            image_id: stored.id,
            object_key: stored.object_key,
            width: stored.width,
            height: stored.height,
            byte_length: stored.byte_length,
            sha256: stored.sha256,
        }
    }
}

impl WalLogicalDomainLedger<SelectedScreenshotPlan> for SelectedScreenshotLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<SelectedScreenshotPlan>,
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
                 FROM archive_v3_wal_selected_screenshot_operations
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
        let kind = WalOperationKind::SelectedScreenshot;
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
        let _ = prepared
            .plan_for_domain_ledger()
            .authenticate_attempt_binding(connection)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<SelectedScreenshotPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, MAX_ENCODED_REPLAY_RESULT_BYTES)?;

        let kind = WalOperationKind::SelectedScreenshot;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_selected_screenshot_operations
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
        let encoded_length =
            i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?;
        let previous_result_bytes =
            i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![encoded_length, i64::from(row_count), previous_result_bytes],
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

fn require_kind(prepared: &PreparedLogicalMutation<SelectedScreenshotPlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::SelectedScreenshot)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

fn append_string(destination: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u16::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value.as_bytes());
    Ok(())
}

fn map_domain_error(error: EnclaveError) -> WalIdempotencyError {
    match error {
        EnclaveError::InvalidRequest(_)
        | EnclaveError::Conflict(_)
        | EnclaveError::NotFound
        | EnclaveError::CaptureReference(_)
        | EnclaveError::CaptureReferenceBatch { .. } => WalIdempotencyError::Precondition,
        EnclaveError::Db(_)
        | EnclaveError::Crypto(_)
        | EnclaveError::Store(_)
        | EnclaveError::Kms(_)
        | EnclaveError::Gcs(_)
        | EnclaveError::Http(_)
        | EnclaveError::Io(_)
        | EnclaveError::Attestation(_)
        | EnclaveError::Auth(_)
        | EnclaveError::Embedding(_)
        | EnclaveError::Config(_)
        | EnclaveError::Json(_)
        | EnclaveError::DeletionPending(_) => WalIdempotencyError::Unavailable,
    }
}

fn encode_outcome(outcome: &SelectedScreenshotOutcome) -> Result<WalReplayResult> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&RESULT_V1.to_be_bytes());
    bytes.push(RESULT_SELECTED_SCREENSHOT);
    append_string(&mut bytes, &outcome.image_id)?;
    append_string(&mut bytes, &outcome.object_key)?;
    bytes.extend_from_slice(&outcome.width.to_be_bytes());
    bytes.extend_from_slice(&outcome.height.to_be_bytes());
    bytes.extend_from_slice(&outcome.byte_length.to_be_bytes());
    bytes.extend_from_slice(outcome.sha256.as_bytes());
    WalReplayResult::canonical_response(WalOperationKind::SelectedScreenshot, bytes)
}

fn decode_outcome(result: &WalReplayResult) -> Result<SelectedScreenshotOutcome> {
    let WalReplayResult::CanonicalResponse(bytes) = result else {
        return Err(WalIdempotencyError::ResultUnsupported);
    };
    let mut reader = ResultReader::new(bytes);
    if reader.take_u16()? != RESULT_V1 || reader.take_u8()? != RESULT_SELECTED_SCREENSHOT {
        return Err(WalIdempotencyError::Corrupt);
    }
    let image_id = reader.take_string()?;
    let object_key = reader.take_string()?;
    let width = reader.take_i32()?;
    let height = reader.take_i32()?;
    let byte_length = reader.take_i64()?;
    let sha256 = reader.take_fixed_string(64)?;
    if !reader.is_empty()
        || !valid_lower_hex(&image_id, 32)
        || object_key.is_empty()
        || object_key.len() > MAX_SCREENSHOT_METADATA_FIELD_BYTES
        || width <= 0
        || height <= 0
        || width > i32::from(MAX_SCREENSHOT_LONG_EDGE)
        || height > i32::from(MAX_SCREENSHOT_LONG_EDGE)
        || byte_length <= 0
        || usize::try_from(byte_length)
            .ok()
            .is_none_or(|length| length > MAX_SCREENSHOT_IMAGE_BYTES)
        || !valid_lower_hex(&sha256, 64)
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(SelectedScreenshotOutcome {
        image_id,
        object_key,
        width,
        height,
        byte_length,
        sha256,
    })
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct ResultReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ResultReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WalIdempotencyError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(WalIdempotencyError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(WalIdempotencyError::Corrupt)
    }

    fn take_u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn take_i32(&mut self) -> Result<i32> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(i32::from_be_bytes(bytes))
    }

    fn take_i64(&mut self) -> Result<i64> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn take_string(&mut self) -> Result<String> {
        let length = usize::from(self.take_u16()?);
        self.take_fixed_string(length)
    }

    fn take_fixed_string(&mut self, length: usize) -> Result<String> {
        let value =
            std::str::from_utf8(self.take(length)?).map_err(|_| WalIdempotencyError::Corrupt)?;
        Ok(value.to_owned())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
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
                    "CREATE TABLE archive_v3_wal_selected_screenshot_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_selected_screenshot_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes) BETWEEN 9 AND 4105),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_selected_screenshot_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 536870912)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_selected_screenshot_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_selected_screenshot_state
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
             FROM archive_v3_wal_selected_screenshot_schema WHERE singleton=1",
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
             FROM archive_v3_wal_selected_screenshot_state WHERE singleton=1",
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
    const CAPTURED: &str = "2026-08-14T12:00:00.000Z";

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_domain_schema(&connection);
        connection
    }

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
                 ) STRICT;",
            )
            .unwrap();
    }

    fn insert_eligible(connection: &Connection, episode_id: i64, screenshot_id: i64, source: &str) {
        connection
            .execute(
                "INSERT INTO episodes(id,substance,visual_evidence) VALUES (?1,'normal','useful')",
                [episode_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO screenshots(id,source_key,captured_at,is_duplicate)
                 VALUES (?1,?2,?3,0)",
                params![screenshot_id, source, CAPTURED],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO episode_members(episode_id,record_type,record_id)
                 VALUES (?1,'screenshot',?2)",
                params![episode_id, screenshot_id],
            )
            .unwrap();
    }

    fn jpeg(seed: char) -> ValidatedJpeg {
        ValidatedJpeg {
            width: 640,
            height: 480,
            byte_length: 1234,
            sha256: seed.to_string().repeat(64),
        }
    }

    fn plan_for(image_seed: char, episode_id: i64, source: &str) -> SelectedScreenshotPlan {
        let image_id = image_seed.to_string().repeat(32);
        let object_key =
            crate::store::selected_evidence_media_object_key(ACCOUNT, &image_id).unwrap();
        SelectedScreenshotPlan::new_unbound_v1(
            ACCOUNT.to_owned(),
            image_id,
            object_key,
            episode_id,
            source.to_owned(),
            CAPTURED.to_owned(),
            jpeg(image_seed),
        )
        .unwrap()
    }

    fn bound_plan_for(
        image_seed: char,
        episode_id: i64,
        source: &str,
        binding_commitment: [u8; 32],
    ) -> SelectedScreenshotPlan {
        let image_id = image_seed.to_string().repeat(32);
        let object_key =
            crate::store::selected_evidence_media_object_key(ACCOUNT, &image_id).unwrap();
        SelectedScreenshotPlan::new(
            ACCOUNT.to_owned(),
            image_id,
            object_key,
            binding_commitment,
            episode_id,
            source.to_owned(),
            CAPTURED.to_owned(),
            jpeg(image_seed),
        )
        .unwrap()
    }

    fn reserve_attempt_binding(
        connection: &mut Connection,
        image_seed: char,
        episode_id: i64,
        source: &str,
    ) -> ([u8; 32], WalLogicalOperationId) {
        let image_id = image_seed.to_string().repeat(32);
        let jpeg = jpeg(image_seed);
        let target =
            selected_screenshot_attempt::authenticate_selected_screenshot_upload_predecessor(
                connection, ACCOUNT, episode_id, source, CAPTURED, &jpeg,
            )
            .unwrap();
        let plan = SelectedScreenshotAttemptPlan::new(
            ACCOUNT.to_owned(),
            image_id,
            episode_id,
            source.to_owned(),
            CAPTURED.to_owned(),
            jpeg,
            target,
        )
        .unwrap();
        let operation_id = plan.operation_id();
        let applied =
            execute_prepared_for_owner(connection, PreparedLogicalMutation::prepare(plan).unwrap())
                .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        let receipt = applied.into_validated_result().release().unwrap();
        (receipt.binding_commitment(), operation_id)
    }

    fn forced_plan(
        operation: u8,
        image_seed: char,
        episode_id: i64,
        source: &str,
    ) -> SelectedScreenshotPlan {
        let image_id = image_seed.to_string().repeat(32);
        let object_key =
            crate::store::selected_evidence_media_object_key(ACCOUNT, &image_id).unwrap();
        SelectedScreenshotPlan::with_operation_id(
            WalLogicalOperationId::from_bytes([operation; 16]).unwrap(),
            ACCOUNT.to_owned(),
            image_id,
            object_key,
            episode_id,
            source.to_owned(),
            CAPTURED.to_owned(),
            jpeg(image_seed),
        )
        .unwrap()
    }

    #[test]
    fn historical_v1_identity_is_kind_scoped_and_request_binds_every_receipt_fact() {
        let one = plan_for('a', 7, SOURCE);
        let replay = plan_for('a', 7, SOURCE);
        assert_eq!(one.operation_id(), replay.operation_id());
        assert_eq!(
            one.canonical_request().unwrap(),
            replay.canonical_request().unwrap()
        );
        assert_ne!(
            one.operation_id(),
            WalLogicalOperationId::from_stable_source(
                WalOperationKind::MediaCaptureEvent,
                one.image_id.as_bytes(),
            )
            .unwrap()
        );

        let mut changed = plan_for('a', 7, SOURCE);
        changed.jpeg.sha256 = "b".repeat(64);
        assert_eq!(one.operation_id(), changed.operation_id());
        assert_ne!(
            one.canonical_request().unwrap(),
            changed.canonical_request().unwrap()
        );
    }

    #[test]
    fn bound_v2_identity_is_distinct_from_attempt_and_historical_v1() {
        let mut connection = connection();
        insert_eligible(&connection, 7, 9, SOURCE);
        let (binding, attempt_id) = reserve_attempt_binding(&mut connection, 'a', 7, SOURCE);
        let bound = bound_plan_for('a', 7, SOURCE, binding);
        let historical = plan_for('a', 7, SOURCE);
        assert_ne!(bound.operation_id(), attempt_id);
        assert_ne!(bound.operation_id(), historical.operation_id());
        assert_ne!(
            bound.canonical_request().unwrap(),
            historical.canonical_request().unwrap()
        );
        let changed_binding = bound_plan_for('a', 7, SOURCE, [9; 32]);
        assert_eq!(bound.operation_id(), changed_binding.operation_id());
        assert_ne!(
            bound.canonical_request().unwrap(),
            changed_binding.canonical_request().unwrap()
        );
    }

    #[test]
    fn bound_v2_consumes_exact_attempt_and_replay_reauthenticates_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected-bound.sqlite");
        let mut connection = Connection::open(&path).unwrap();
        install_domain_schema(&connection);
        insert_eligible(&connection, 7, 9, SOURCE);
        let (binding, _) = reserve_attempt_binding(&mut connection, 'a', 7, SOURCE);
        let first = bound_plan_for('a', 7, SOURCE, binding);
        let replay = bound_plan_for('a', 7, SOURCE, binding);
        let replay_after_result_tamper = bound_plan_for('a', 7, SOURCE, binding);
        let replay_after_binding_tamper = bound_plan_for('a', 7, SOURCE, binding);
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(first).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        drop(connection);

        let mut reopened = Connection::open(&path).unwrap();
        let changes = reopened.total_changes();
        let replayed = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(replay).unwrap(),
        )
        .unwrap();
        assert_eq!(replayed.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(reopened.total_changes(), changes);
        reopened
            .execute(
                "UPDATE screenshot_images SET screenshot_id=10 WHERE source_key=?1",
                [SOURCE],
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(replay_after_result_tamper).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Corrupt);
        reopened
            .execute(
                "UPDATE screenshot_images SET screenshot_id=9 WHERE source_key=?1",
                [SOURCE],
            )
            .unwrap();
        reopened
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_attempt_operations
                 SET binding_commitment=?1 WHERE image_id=?2",
                params![&[7_u8; 32][..], "a".repeat(32)],
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(replay_after_binding_tamper).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Corrupt);
        assert_eq!(
            reopened
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
    }

    #[test]
    fn bound_v2_late_binding_failure_rolls_back_result_and_preserves_attempt() {
        let mut connection = connection();
        insert_eligible(&connection, 7, 9, SOURCE);
        let (binding, _) = reserve_attempt_binding(&mut connection, 'a', 7, SOURCE);
        connection
            .execute_batch(
                "CREATE TRIGGER corrupt_attempt_after_result
                 AFTER INSERT ON screenshot_images
                 BEGIN
                   UPDATE archive_v3_wal_selected_screenshot_attempt_operations
                   SET binding_commitment=randomblob(32)
                   WHERE image_id=NEW.id;
                 END;",
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(bound_plan_for('a', 7, SOURCE, binding)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Corrupt);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        let retained: Vec<u8> = connection
            .query_row(
                "SELECT binding_commitment
                 FROM archive_v3_wal_selected_screenshot_attempt_operations
                 WHERE image_id=?1",
                ["a".repeat(32)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained.as_slice(), binding.as_slice());
    }

    #[test]
    fn bound_v2_rejects_missing_or_substituted_attempt_before_local_write() {
        let mut missing = connection();
        insert_eligible(&missing, 7, 9, SOURCE);
        let error = execute_prepared_for_owner(
            &mut missing,
            PreparedLogicalMutation::prepare(bound_plan_for('a', 7, SOURCE, [1; 32])).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            missing
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );

        let mut substituted = connection();
        insert_eligible(&substituted, 7, 9, SOURCE);
        let (binding, _) = reserve_attempt_binding(&mut substituted, 'a', 7, SOURCE);
        assert_ne!(binding, [9; 32]);
        let error = execute_prepared_for_owner(
            &mut substituted,
            PreparedLogicalMutation::prepare(bound_plan_for('a', 7, SOURCE, [9; 32])).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            substituted
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn malformed_attempt_or_noncanonical_object_key_is_rejected_before_prepare() {
        assert!(SelectedScreenshotPlan::new(
            ACCOUNT.to_owned(),
            "a".repeat(32),
            crate::store::selected_evidence_media_object_key(ACCOUNT, &"a".repeat(32)).unwrap(),
            [0; 32],
            7,
            SOURCE.to_owned(),
            CAPTURED.to_owned(),
            jpeg('a'),
        )
        .is_err());
        let error = SelectedScreenshotPlan::new(
            ACCOUNT.to_owned(),
            "A".repeat(32),
            "raw/account-1/evidence/not-the-attempt.enc".to_owned(),
            [1; 32],
            7,
            SOURCE.to_owned(),
            CAPTURED.to_owned(),
            jpeg('a'),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Malformed);
    }

    #[test]
    fn exact_receipt_applies_once_and_replays_after_reopen_without_writes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected.sqlite");
        let mut connection = Connection::open(&path).unwrap();
        install_domain_schema(&connection);
        insert_eligible(&connection, 7, 9, SOURCE);

        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        let outcome = applied.into_validated_result().release().unwrap();
        assert_eq!(outcome.image_id(), "a".repeat(32));
        assert_eq!(outcome.width(), 640);
        assert_eq!(outcome.height(), 480);
        assert_eq!(outcome.byte_length(), 1234);
        assert_eq!(outcome.sha256(), "a".repeat(64));
        assert!(outcome
            .object_key()
            .ends_with(&format!("/{}.enc", "a".repeat(32))));
        drop(connection);

        let mut reopened = Connection::open(&path).unwrap();
        let changes = reopened.total_changes();
        let replay = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(replay.into_validated_result().release().unwrap(), outcome);
        assert_eq!(reopened.total_changes(), changes);
    }

    #[test]
    fn missing_eligibility_rolls_back_schema_and_same_identity_can_later_apply() {
        let mut connection = connection();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name=?1",
                    [LEDGER_TABLE],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        insert_eligible(&connection, 7, 9, SOURCE);
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn preexisting_alternate_object_cannot_be_adopted_by_this_attempt() {
        let mut exact = connection();
        insert_eligible(&exact, 7, 9, SOURCE);
        exact
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,
                  width,height,byte_length,sha256)
                 VALUES (?1,9,7,?2,?3,?4,'image/jpeg',640,480,1234,?5)",
                params![
                    "b".repeat(32),
                    SOURCE,
                    CAPTURED,
                    crate::store::selected_evidence_media_object_key(ACCOUNT, &"b".repeat(32))
                        .unwrap(),
                    "a".repeat(64),
                ],
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut exact,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            exact
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| row
                    .get::<_, i64>(0),)
                .unwrap(),
            1
        );
    }

    #[test]
    fn exact_preexisting_attempt_is_adopted_but_wrong_screenshot_binding_is_rejected() {
        let mut connection = connection();
        insert_eligible(&connection, 7, 9, SOURCE);
        let object_key =
            crate::store::selected_evidence_media_object_key(ACCOUNT, &"a".repeat(32)).unwrap();
        connection
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,
                  width,height,byte_length,sha256)
                 VALUES (?1,9,7,?2,?3,?4,'image/jpeg',640,480,1234,?5)",
                params!["a".repeat(32), SOURCE, CAPTURED, object_key, "a".repeat(64)],
            )
            .unwrap();
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| row
                    .get::<_, i64>(0),)
                .unwrap(),
            1
        );

        let mut wrong = self::connection();
        insert_eligible(&wrong, 7, 9, SOURCE);
        wrong
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,
                  width,height,byte_length,sha256)
                 VALUES (?1,10,7,?2,?3,?4,'image/jpeg',640,480,1234,?5)",
                params![
                    "a".repeat(32),
                    SOURCE,
                    CAPTURED,
                    crate::store::selected_evidence_media_object_key(ACCOUNT, &"a".repeat(32))
                        .unwrap(),
                    "a".repeat(64),
                ],
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut wrong,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Precondition);
    }

    #[test]
    fn row_cap_is_checked_before_domain_insert_but_existing_replay_survives() {
        let mut connection = connection();
        insert_eligible(&connection, 7, 9, SOURCE);
        insert_eligible(&connection, 8, 10, "device-1:screen-2");
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(1, 'a', 7, SOURCE)).unwrap(),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_state SET row_count=?1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        let replay = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(1, 'a', 7, SOURCE)).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(2, 'b', 8, "device-1:screen-2")).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Limit);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| row
                    .get::<_, i64>(0),)
                .unwrap(),
            1
        );
    }

    #[test]
    fn result_byte_cap_is_checked_before_domain_insert() {
        let mut connection = connection();
        insert_eligible(&connection, 7, 9, SOURCE);
        let transaction = connection.transaction().unwrap();
        ensure_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_state SET result_bytes=?1",
                [i64::try_from(MAX_RESULT_BYTES).unwrap()],
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Limit);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| row
                    .get::<_, i64>(0),)
                .unwrap(),
            0
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_the_screenshot_row() {
        let mut connection = connection();
        insert_eligible(&connection, 7, 9, SOURCE);
        let transaction = connection.transaction().unwrap();
        ensure_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_selected_screenshot_ledger
                 BEFORE INSERT ON archive_v3_wal_selected_screenshot_operations
                 BEGIN SELECT RAISE(ABORT,'blocked'); END;",
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Unavailable);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| row
                    .get::<_, i64>(0),)
                .unwrap(),
            0
        );
    }

    #[test]
    fn changed_same_attempt_conflicts_and_tampered_result_fails_closed() {
        let mut connection = connection();
        insert_eligible(&connection, 7, 9, SOURCE);
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .unwrap();

        let mut changed = plan_for('a', 7, SOURCE);
        changed.jpeg.sha256 = "b".repeat(64);
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(changed).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::FingerprintConflict);

        connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_operations
                 SET result_bytes=zeroblob(9)",
                [],
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            WalIdempotencyError::Corrupt | WalIdempotencyError::ResultUnsupported
        ));
    }

    #[test]
    fn partial_ledger_schema_is_rejected() {
        let mut connection = connection();
        connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_selected_screenshot_schema(
                    singleton INTEGER PRIMARY KEY,
                    format_version INTEGER NOT NULL,
                    codec_version INTEGER NOT NULL
                 ) STRICT;",
            )
            .unwrap();
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan_for('a', 7, SOURCE)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Corrupt);
    }
}
