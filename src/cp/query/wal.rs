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
//! owning no provider. A fourth private child exposes only an injected exact
//! create/readback seam and mints sealed success or definitive-no-object proof;
//! it has no concrete transport or caller. The sole production A contract
//! consumes that exact success proof and atomically retains a complete typed
//! restart row plus the local screenshot; historical A-v1/v2 are test-only.
//! Another private child owns an exact
//! finalization-queue transition. None can call Store, launch work, invoke a
//! concrete provider, schedule a retry, allocate randomness or a clock, or
//! acknowledge a request.

mod finalization_queue;
mod selected_screenshot_attempt;
mod selected_screenshot_provider;
mod selected_screenshot_send;
mod selected_screenshot_termination;
mod selected_screenshot_upload;
pub(in crate::cp::query) use finalization_queue::FinalizationQueuePredecessor;
pub(crate) use finalization_queue::{FinalizationQueueLedger, FinalizationQueuePlan};
pub(crate) use selected_screenshot_attempt::{
    SelectedScreenshotAttemptLedger, SelectedScreenshotAttemptPlan,
};
pub(crate) use selected_screenshot_send::{
    SelectedScreenshotSendStartedLedger, SelectedScreenshotSendStartedPlan,
};
pub(crate) use selected_screenshot_termination::{
    SelectedScreenshotTerminationLedger, SelectedScreenshotTerminationPlan,
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
const REQUEST_V3: u16 = 3;
const REQUEST_SELECTED_SCREENSHOT: u8 = 1;
const REQUEST_SELECTED_SCREENSHOT_BOUND_ATTEMPT: u8 = 3;
const REQUEST_SELECTED_SCREENSHOT_PROVIDER_ACCEPTED: u8 = 7;
const BOUND_OPERATION_SOURCE_DOMAIN: &[u8] = b"selected-screenshot-result-bound-v2\0";
const PROVIDER_ACCEPTED_OPERATION_SOURCE_DOMAIN: &[u8] =
    b"selected-screenshot-provider-accepted-result-v3\0";
const RESULT_V1: u16 = 1;
const RESULT_SELECTED_SCREENSHOT: u8 = 1;
const SCHEMA_TABLE: &str = "archive_v3_wal_selected_screenshot_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_selected_screenshot_operations";
const STATE_TABLE: &str = "archive_v3_wal_selected_screenshot_state";
const LEDGER_SCHEMA_REVISION: i64 = 2;
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 512 * 1024 * 1024;
const MIN_STORED_RESULT_BYTES: i64 = 9;
const MAX_STORED_RESULT_BYTES: i64 = 4_105;
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

fn ensure_no_selected_screenshot_result_ledger(
    connection: &Connection,
    image_id: &str,
) -> Result<()> {
    if schema_state(connection)? == LedgerSchemaState::Absent {
        return Ok(());
    }
    validate_schema_marker(connection)?;
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM archive_v3_wal_selected_screenshot_operations
             WHERE image_id=?1",
            [image_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(()),
        1 => Err(WalIdempotencyError::Precondition),
        _ => Err(WalIdempotencyError::Corrupt),
    }
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

/// Exact local half of an already provider-accepted selected-screenshot upload.
/// Production v3 consumes the sealed positive readback proof. Historical
/// unbound v1 and B-only v2 are test-only.
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

enum SelectedScreenshotRequestContract {
    #[cfg(test)]
    UnboundV1,
    #[cfg(test)]
    BoundV2 {
        attempt_binding_commitment: [u8; 32],
    },
    ProviderAcceptedV3 {
        attempt_operation_id: WalLogicalOperationId,
        attempt_request_fingerprint: [u8; 32],
        screenshot_id: i64,
        predecessor_commitment: [u8; 32],
        provider_binding: Box<selected_screenshot_provider::SelectedScreenshotProviderBinding>,
        provider_generation: u64,
        readback_commitment: [u8; 32],
    },
}

impl SelectedScreenshotPlan {
    #[cfg(test)]
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
        match &request_contract {
            #[cfg(test)]
            SelectedScreenshotRequestContract::UnboundV1
            | SelectedScreenshotRequestContract::BoundV2 { .. } => {}
            SelectedScreenshotRequestContract::ProviderAcceptedV3 {
                attempt_request_fingerprint,
                screenshot_id,
                predecessor_commitment,
                provider_binding,
                provider_generation,
                readback_commitment,
                ..
            } => {
                if *attempt_request_fingerprint == [0; 32]
                    || *screenshot_id <= 0
                    || *predecessor_commitment == [0; 32]
                    || *provider_generation == 0
                    || *readback_commitment == [0; 32]
                    || provider_binding.account_id() != account_id
                    || provider_binding.image_id() != image_id
                    || provider_binding.object_key() != object_key
                {
                    return Err(WalIdempotencyError::Malformed);
                }
                selected_screenshot_provider::authenticate_accepted_facts(
                    provider_binding,
                    *provider_generation,
                    readback_commitment,
                )
                .map_err(|_| WalIdempotencyError::Malformed)?;
            }
        }
        let operation_id = match (&request_contract, operation_id) {
            (_, Some(value)) => value,
            #[cfg(test)]
            (SelectedScreenshotRequestContract::UnboundV1, None) => {
                WalLogicalOperationId::from_stable_source(
                    WalOperationKind::SelectedScreenshot,
                    image_id.as_bytes(),
                )?
            }
            #[cfg(test)]
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
            (
                SelectedScreenshotRequestContract::ProviderAcceptedV3 {
                    attempt_operation_id,
                    ..
                },
                None,
            ) => {
                let mut source = Vec::with_capacity(
                    PROVIDER_ACCEPTED_OPERATION_SOURCE_DOMAIN
                        .len()
                        .saturating_add(attempt_operation_id.as_bytes().len()),
                );
                source.extend_from_slice(PROVIDER_ACCEPTED_OPERATION_SOURCE_DOMAIN);
                source.extend_from_slice(attempt_operation_id.as_bytes());
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

/// WAL-private bridge from the sealed positive provider readback into the
/// durable local A result. It derives all local facts from the permanent B row;
/// callers cannot substitute episode, screenshot, source, time, or JPEG facts.
fn prepare_selected_screenshot_provider_accepted_result(
    connection: &Connection,
    accepted: selected_screenshot_provider::SelectedScreenshotProviderAccepted,
) -> Result<SelectedScreenshotPlan> {
    let (provider_binding, provider_generation, readback_commitment) = accepted.into_parts();
    selected_screenshot_provider::authenticate_accepted_facts(
        &provider_binding,
        provider_generation,
        &readback_commitment,
    )?;
    selected_screenshot_provider::authenticate_provider_execution_claim(
        connection,
        &provider_binding,
    )?;
    selected_screenshot_send::authenticate_selected_screenshot_send_provider_facts(
        connection,
        &provider_binding.send_facts(),
    )?;
    let attempt =
        selected_screenshot_attempt::authenticate_selected_screenshot_attempt_for_terminal(
            connection,
            provider_binding.account_id(),
            provider_binding.image_id(),
            provider_binding.object_key(),
            &provider_binding.attempt_binding_commitment(),
        )?;
    if provider_binding.account_id() != attempt.account_id
        || provider_binding.image_id() != attempt.image_id
        || provider_binding.object_key() != attempt.object_key
        || provider_binding.attempt_binding_commitment() != attempt.binding_commitment
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    selected_screenshot_termination::ensure_attempt_not_terminated(
        connection,
        &attempt.account_id,
        &attempt.image_id,
        &attempt.object_key,
        &attempt.binding_commitment,
    )?;
    SelectedScreenshotPlan::build(
        SelectedScreenshotRequestContract::ProviderAcceptedV3 {
            attempt_operation_id: attempt.operation_id,
            attempt_request_fingerprint: attempt.request_fingerprint,
            screenshot_id: attempt.screenshot_id,
            predecessor_commitment: attempt.predecessor_commitment,
            provider_binding: Box::new(provider_binding),
            provider_generation,
            readback_commitment,
        },
        None,
        attempt.account_id,
        attempt.image_id,
        attempt.object_key,
        attempt.episode_id,
        attempt.source_key,
        attempt.captured_at,
        attempt.jpeg,
    )
}

/// Exact-name restart loader for an already durable provider-accepted A row.
/// It reconstructs no provider request and returns only after the full typed
/// row, predecessor chain, accepted proof, local result, and C exclusion have
/// reauthenticated.
fn load_selected_screenshot_provider_accepted_result(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
) -> Result<Option<SelectedScreenshotPlan>> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    if !valid_lower_hex(image_id, 32) {
        return Err(WalIdempotencyError::Malformed);
    }
    if schema_state(connection)? == LedgerSchemaState::Absent {
        return Ok(None);
    }
    validate_schema_marker(connection)?;
    let result_length = connection
        .query_row(
            "SELECT length(result_bytes)
             FROM archive_v3_wal_selected_screenshot_operations WHERE image_id=?1",
            [image_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(result_length) = result_length else {
        return Ok(None);
    };
    if !(MIN_STORED_RESULT_BYTES..=MAX_STORED_RESULT_BYTES).contains(&result_length) {
        return Err(WalIdempotencyError::Corrupt);
    }
    let row = load_selected_screenshot_row_by_image(connection, image_id)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.account_id != account_id {
        return Err(WalIdempotencyError::Corrupt);
    }
    let prepared = PreparedLogicalMutation::prepare(row.to_v3_plan()?)
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    SelectedScreenshotLedger::lookup(connection, &prepared)?.ok_or(WalIdempotencyError::Corrupt)?;
    Ok(Some(row.to_v3_plan()?))
}

fn load_selected_screenshot_row_by_image(
    connection: &Connection,
    image_id: &str,
) -> Result<Option<StoredSelectedScreenshotRow>> {
    connection
        .query_row(
            "SELECT operation_id,format_version,codec_version,request_version,request_subtype,
                    request_fingerprint,account_id,image_id,object_key,episode_id,screenshot_id,
                    source_key,captured_at,width,height,byte_length,sha256,
                    attempt_operation_id,attempt_request_fingerprint,predecessor_commitment,
                    attempt_binding_commitment,candidate_request_fingerprint,
                    wrapped_dek_commitment,media_dek_binding_commitment,aad_commitment,
                    ciphertext_length,ciphertext_sha256,candidate_binding_commitment,
                    send_request_id,send_binding_commitment,provider_generation,
                    readback_commitment,result_bytes,result_commitment
             FROM archive_v3_wal_selected_screenshot_operations WHERE image_id=?1",
            [image_id],
            StoredSelectedScreenshotRow::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

pub(crate) struct SelectedScreenshotLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

struct StoredSelectedScreenshotRow {
    operation_id: Vec<u8>,
    format_version: i64,
    codec_version: i64,
    request_version: i64,
    request_subtype: i64,
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
    attempt_operation_id: Option<Vec<u8>>,
    attempt_request_fingerprint: Option<Vec<u8>>,
    predecessor_commitment: Option<Vec<u8>>,
    attempt_binding_commitment: Option<Vec<u8>>,
    candidate_request_fingerprint: Option<Vec<u8>>,
    wrapped_dek_commitment: Option<Vec<u8>>,
    media_dek_binding_commitment: Option<Vec<u8>>,
    aad_commitment: Option<Vec<u8>>,
    ciphertext_length: Option<i64>,
    ciphertext_sha256: Option<Vec<u8>>,
    candidate_binding_commitment: Option<Vec<u8>>,
    send_request_id: Option<String>,
    send_binding_commitment: Option<Vec<u8>>,
    provider_generation: Option<Vec<u8>>,
    readback_commitment: Option<Vec<u8>>,
    result_bytes: Vec<u8>,
    result_commitment: Vec<u8>,
}

impl StoredSelectedScreenshotRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            operation_id: row.get(0)?,
            format_version: row.get(1)?,
            codec_version: row.get(2)?,
            request_version: row.get(3)?,
            request_subtype: row.get(4)?,
            request_fingerprint: row.get(5)?,
            account_id: row.get(6)?,
            image_id: row.get(7)?,
            object_key: row.get(8)?,
            episode_id: row.get(9)?,
            screenshot_id: row.get(10)?,
            source_key: row.get(11)?,
            captured_at: row.get(12)?,
            width: row.get(13)?,
            height: row.get(14)?,
            byte_length: row.get(15)?,
            sha256: row.get(16)?,
            attempt_operation_id: row.get(17)?,
            attempt_request_fingerprint: row.get(18)?,
            predecessor_commitment: row.get(19)?,
            attempt_binding_commitment: row.get(20)?,
            candidate_request_fingerprint: row.get(21)?,
            wrapped_dek_commitment: row.get(22)?,
            media_dek_binding_commitment: row.get(23)?,
            aad_commitment: row.get(24)?,
            ciphertext_length: row.get(25)?,
            ciphertext_sha256: row.get(26)?,
            candidate_binding_commitment: row.get(27)?,
            send_request_id: row.get(28)?,
            send_binding_commitment: row.get(29)?,
            provider_generation: row.get(30)?,
            readback_commitment: row.get(31)?,
            result_bytes: row.get(32)?,
            result_commitment: row.get(33)?,
        })
    }

    fn request_identity(&self) -> Result<(u16, u8)> {
        Ok((
            u16::try_from(self.request_version).map_err(|_| WalIdempotencyError::Corrupt)?,
            u8::try_from(self.request_subtype).map_err(|_| WalIdempotencyError::Corrupt)?,
        ))
    }

    fn matches_plan(&self, plan: &SelectedScreenshotPlan) -> Result<bool> {
        let request_identity = plan.request_identity();
        if self.operation_id.as_slice() != plan.operation_id.as_bytes().as_slice()
            || self.request_identity()? != request_identity
            || self.account_id != plan.account_id
            || self.image_id != plan.image_id
            || self.object_key != plan.object_key
            || self.episode_id != plan.episode_id
            || self.source_key != plan.source_key
            || self.captured_at != plan.captured_at
            || self.width != plan.jpeg.width
            || self.height != plan.jpeg.height
            || self.byte_length != plan.jpeg.byte_length
            || self.sha256 != plan.jpeg.sha256
        {
            return Ok(false);
        }
        match &plan.request_contract {
            #[cfg(test)]
            SelectedScreenshotRequestContract::UnboundV1 => Ok(self.v3_fields_absent()),
            #[cfg(test)]
            SelectedScreenshotRequestContract::BoundV2 {
                attempt_binding_commitment,
            } => Ok(self.attempt_binding_commitment.as_deref()
                == Some(attempt_binding_commitment.as_slice())
                && self.other_v3_fields_absent()),
            SelectedScreenshotRequestContract::ProviderAcceptedV3 {
                attempt_operation_id,
                attempt_request_fingerprint,
                screenshot_id,
                predecessor_commitment,
                provider_binding,
                provider_generation,
                readback_commitment,
            } => Ok(self.screenshot_id == *screenshot_id
                && self.attempt_operation_id.as_deref()
                    == Some(attempt_operation_id.as_bytes().as_slice())
                && self.attempt_request_fingerprint.as_deref()
                    == Some(attempt_request_fingerprint.as_slice())
                && self.predecessor_commitment.as_deref()
                    == Some(predecessor_commitment.as_slice())
                && self.attempt_binding_commitment.as_deref()
                    == Some(provider_binding.attempt_binding_commitment().as_slice())
                && self.candidate_request_fingerprint.as_deref()
                    == Some(provider_binding.candidate_request_fingerprint().as_slice())
                && self.wrapped_dek_commitment.as_deref()
                    == Some(provider_binding.wrapped_dek_commitment().as_slice())
                && self.media_dek_binding_commitment.as_deref()
                    == Some(provider_binding.media_dek_binding_commitment().as_slice())
                && self.aad_commitment.as_deref()
                    == Some(provider_binding.aad_commitment().as_slice())
                && self.ciphertext_length == Some(i64::from(provider_binding.ciphertext_length()))
                && self.ciphertext_sha256.as_deref()
                    == Some(provider_binding.ciphertext_sha256().as_slice())
                && self.candidate_binding_commitment.as_deref()
                    == Some(provider_binding.candidate_binding_commitment().as_slice())
                && self.send_request_id.as_deref() == Some(provider_binding.send_request_id())
                && self.send_binding_commitment.as_deref()
                    == Some(provider_binding.send_binding_commitment().as_slice())
                && self.provider_generation.as_deref()
                    == Some(provider_generation.to_be_bytes().as_slice())
                && self.readback_commitment.as_deref() == Some(readback_commitment.as_slice())),
        }
    }

    fn v3_fields_absent(&self) -> bool {
        self.attempt_operation_id.is_none()
            && self.attempt_request_fingerprint.is_none()
            && self.predecessor_commitment.is_none()
            && self.attempt_binding_commitment.is_none()
            && self.other_v3_fields_absent()
    }

    fn other_v3_fields_absent(&self) -> bool {
        self.candidate_request_fingerprint.is_none()
            && self.wrapped_dek_commitment.is_none()
            && self.media_dek_binding_commitment.is_none()
            && self.aad_commitment.is_none()
            && self.ciphertext_length.is_none()
            && self.ciphertext_sha256.is_none()
            && self.candidate_binding_commitment.is_none()
            && self.send_request_id.is_none()
            && self.send_binding_commitment.is_none()
            && self.provider_generation.is_none()
            && self.readback_commitment.is_none()
    }

    fn to_v3_plan(&self) -> Result<SelectedScreenshotPlan> {
        if self.request_identity()? != (REQUEST_V3, REQUEST_SELECTED_SCREENSHOT_PROVIDER_ACCEPTED) {
            return Err(WalIdempotencyError::Corrupt);
        }
        let attempt_operation_id =
            WalLogicalOperationId::from_bytes(required_array_16(&self.attempt_operation_id)?)
                .map_err(|_| WalIdempotencyError::Corrupt)?;
        let attempt_request_fingerprint = required_array_32(&self.attempt_request_fingerprint)?;
        let predecessor_commitment = required_array_32(&self.predecessor_commitment)?;
        let attempt_binding_commitment = required_array_32(&self.attempt_binding_commitment)?;
        let candidate_request_fingerprint = required_array_32(&self.candidate_request_fingerprint)?;
        let wrapped_dek_commitment = required_array_32(&self.wrapped_dek_commitment)?;
        let media_dek_binding_commitment = required_array_32(&self.media_dek_binding_commitment)?;
        let aad_commitment = required_array_32(&self.aad_commitment)?;
        let ciphertext_length =
            u32::try_from(self.ciphertext_length.ok_or(WalIdempotencyError::Corrupt)?)
                .map_err(|_| WalIdempotencyError::Corrupt)?;
        let ciphertext_sha256 = required_array_32(&self.ciphertext_sha256)?;
        let candidate_binding_commitment = required_array_32(&self.candidate_binding_commitment)?;
        let send_request_id = self
            .send_request_id
            .clone()
            .ok_or(WalIdempotencyError::Corrupt)?;
        let send_binding_commitment = required_array_32(&self.send_binding_commitment)?;
        let provider_generation = u64::from_be_bytes(required_array_8(&self.provider_generation)?);
        let readback_commitment = required_array_32(&self.readback_commitment)?;
        let provider_binding =
            selected_screenshot_provider::SelectedScreenshotProviderBinding::from_terminal_facts(
                self.account_id.clone(),
                self.image_id.clone(),
                self.object_key.clone(),
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
            )?;
        SelectedScreenshotPlan::build(
            SelectedScreenshotRequestContract::ProviderAcceptedV3 {
                attempt_operation_id,
                attempt_request_fingerprint,
                screenshot_id: self.screenshot_id,
                predecessor_commitment,
                provider_binding: Box::new(provider_binding),
                provider_generation,
                readback_commitment,
            },
            None,
            self.account_id.clone(),
            self.image_id.clone(),
            self.object_key.clone(),
            self.episode_id,
            self.source_key.clone(),
            self.captured_at.clone(),
            ValidatedJpeg {
                width: self.width,
                height: self.height,
                byte_length: self.byte_length,
                sha256: self.sha256.clone(),
            },
        )
        .map_err(|_| WalIdempotencyError::Corrupt)
    }
}

fn required_array_16(value: &Option<Vec<u8>>) -> Result<[u8; 16]> {
    value
        .as_deref()
        .ok_or(WalIdempotencyError::Corrupt)?
        .try_into()
        .map_err(|_| WalIdempotencyError::Corrupt)
}

fn required_array_8(value: &Option<Vec<u8>>) -> Result<[u8; 8]> {
    value
        .as_deref()
        .ok_or(WalIdempotencyError::Corrupt)?
        .try_into()
        .map_err(|_| WalIdempotencyError::Corrupt)
}

fn required_array_32(value: &Option<Vec<u8>>) -> Result<[u8; 32]> {
    value
        .as_deref()
        .ok_or(WalIdempotencyError::Corrupt)?
        .try_into()
        .map_err(|_| WalIdempotencyError::Corrupt)
}

impl SelectedScreenshotPlan {
    const fn request_identity(&self) -> (u16, u8) {
        match &self.request_contract {
            #[cfg(test)]
            SelectedScreenshotRequestContract::UnboundV1 => {
                (REQUEST_V1, REQUEST_SELECTED_SCREENSHOT)
            }
            #[cfg(test)]
            SelectedScreenshotRequestContract::BoundV2 { .. } => {
                (REQUEST_V2, REQUEST_SELECTED_SCREENSHOT_BOUND_ATTEMPT)
            }
            SelectedScreenshotRequestContract::ProviderAcceptedV3 { .. } => {
                (REQUEST_V3, REQUEST_SELECTED_SCREENSHOT_PROVIDER_ACCEPTED)
            }
        }
    }
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
        match &self.request_contract {
            #[cfg(test)]
            SelectedScreenshotRequestContract::UnboundV1 => {
                request.extend_from_slice(&REQUEST_V1.to_be_bytes());
                request.push(REQUEST_SELECTED_SCREENSHOT);
            }
            #[cfg(test)]
            SelectedScreenshotRequestContract::BoundV2 {
                attempt_binding_commitment,
            } => {
                request.extend_from_slice(&REQUEST_V2.to_be_bytes());
                request.push(REQUEST_SELECTED_SCREENSHOT_BOUND_ATTEMPT);
                request.extend_from_slice(attempt_binding_commitment);
            }
            SelectedScreenshotRequestContract::ProviderAcceptedV3 {
                attempt_operation_id,
                attempt_request_fingerprint,
                screenshot_id,
                predecessor_commitment,
                provider_binding,
                provider_generation,
                readback_commitment,
            } => {
                request.extend_from_slice(&REQUEST_V3.to_be_bytes());
                request.push(REQUEST_SELECTED_SCREENSHOT_PROVIDER_ACCEPTED);
                request.extend_from_slice(attempt_operation_id.as_bytes());
                request.extend_from_slice(attempt_request_fingerprint);
                request.extend_from_slice(&screenshot_id.to_be_bytes());
                request.extend_from_slice(predecessor_commitment);
                append_provider_binding(&mut request, provider_binding)?;
                request.extend_from_slice(&provider_generation.to_be_bytes());
                request.extend_from_slice(readback_commitment);
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
        if matches!(
            self.request_contract,
            SelectedScreenshotRequestContract::ProviderAcceptedV3 { .. }
        ) {
            let exact_screenshot_id = bound_screenshot_id.ok_or(WalIdempotencyError::Corrupt)?;
            let local = transaction
                .query_row(
                    "SELECT COUNT(*) FROM screenshot_images
                     WHERE id=?1 OR source_key=?2 OR object_key=?3 OR screenshot_id=?4",
                    params![
                        self.image_id,
                        self.source_key,
                        self.object_key,
                        exact_screenshot_id,
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if local != 0 {
                return Err(if local == 1 {
                    WalIdempotencyError::Precondition
                } else {
                    WalIdempotencyError::Corrupt
                });
            }
        }
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
        match &self.request_contract {
            #[cfg(test)]
            SelectedScreenshotRequestContract::UnboundV1 => Ok(None),
            #[cfg(test)]
            SelectedScreenshotRequestContract::BoundV2 {
                attempt_binding_commitment,
            } => {
                let screenshot_id =
                    selected_screenshot_attempt::authenticate_selected_screenshot_attempt_binding(
                        connection,
                        &self.account_id,
                        &self.image_id,
                        &self.object_key,
                        self.episode_id,
                        &self.source_key,
                        &self.captured_at,
                        &self.jpeg,
                        attempt_binding_commitment,
                    )?;
                selected_screenshot_termination::ensure_attempt_not_terminated(
                    connection,
                    &self.account_id,
                    &self.image_id,
                    &self.object_key,
                    attempt_binding_commitment,
                )?;
                Ok(Some(screenshot_id))
            }
            SelectedScreenshotRequestContract::ProviderAcceptedV3 {
                attempt_operation_id,
                attempt_request_fingerprint,
                screenshot_id,
                predecessor_commitment,
                provider_binding,
                provider_generation,
                readback_commitment,
            } => {
                let attempt = selected_screenshot_attempt::authenticate_selected_screenshot_attempt_for_terminal(
                    connection,
                    &self.account_id,
                    &self.image_id,
                    &self.object_key,
                    &provider_binding.attempt_binding_commitment(),
                )?;
                if attempt.operation_id != *attempt_operation_id
                    || attempt.request_fingerprint != *attempt_request_fingerprint
                    || attempt.account_id != self.account_id
                    || attempt.image_id != self.image_id
                    || attempt.object_key != self.object_key
                    || attempt.episode_id != self.episode_id
                    || attempt.screenshot_id != *screenshot_id
                    || attempt.source_key != self.source_key
                    || attempt.captured_at != self.captured_at
                    || attempt.jpeg != self.jpeg
                    || attempt.predecessor_commitment != *predecessor_commitment
                    || attempt.binding_commitment != provider_binding.attempt_binding_commitment()
                    || provider_binding.account_id() != self.account_id
                    || provider_binding.image_id() != self.image_id
                    || provider_binding.object_key() != self.object_key
                {
                    return Err(WalIdempotencyError::Corrupt);
                }
                selected_screenshot_send::authenticate_selected_screenshot_send_provider_facts(
                    connection,
                    &provider_binding.send_facts(),
                )?;
                selected_screenshot_provider::authenticate_provider_execution_claim(
                    connection,
                    provider_binding,
                )?;
                selected_screenshot_provider::authenticate_accepted_facts(
                    provider_binding,
                    *provider_generation,
                    readback_commitment,
                )?;
                selected_screenshot_termination::ensure_attempt_not_terminated(
                    connection,
                    &self.account_id,
                    &self.image_id,
                    &self.object_key,
                    &attempt.binding_commitment,
                )?;
                Ok(Some(*screenshot_id))
            }
        }
    }

    fn authenticate_v3_local_uniqueness(&self, connection: &Connection) -> Result<()> {
        let screenshot_id = match &self.request_contract {
            #[cfg(test)]
            SelectedScreenshotRequestContract::UnboundV1
            | SelectedScreenshotRequestContract::BoundV2 { .. } => return Ok(()),
            SelectedScreenshotRequestContract::ProviderAcceptedV3 { screenshot_id, .. } => {
                screenshot_id
            }
        };
        let matches = connection
            .query_row(
                "SELECT COUNT(*) FROM screenshot_images
                 WHERE id=?1 OR source_key=?2 OR object_key=?3 OR screenshot_id=?4",
                params![
                    self.image_id,
                    self.source_key,
                    self.object_key,
                    screenshot_id,
                ],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        (matches == 1)
            .then_some(())
            .ok_or(WalIdempotencyError::Corrupt)
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
        let result_length = connection
            .query_row(
                "SELECT length(result_bytes)
                 FROM archive_v3_wal_selected_screenshot_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some(result_length) = result_length else {
            return Ok(None);
        };
        if !(MIN_STORED_RESULT_BYTES..=MAX_STORED_RESULT_BYTES).contains(&result_length) {
            return Err(WalIdempotencyError::Corrupt);
        }
        let row = connection
            .query_row(
                "SELECT operation_id,format_version,codec_version,request_version,request_subtype,
                        request_fingerprint,account_id,image_id,object_key,episode_id,screenshot_id,
                        source_key,captured_at,width,height,byte_length,sha256,
                        attempt_operation_id,attempt_request_fingerprint,predecessor_commitment,
                        attempt_binding_commitment,candidate_request_fingerprint,
                        wrapped_dek_commitment,media_dek_binding_commitment,aad_commitment,
                        ciphertext_length,ciphertext_sha256,candidate_binding_commitment,
                        send_request_id,send_binding_commitment,provider_generation,
                        readback_commitment,result_bytes,result_commitment
                 FROM archive_v3_wal_selected_screenshot_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                StoredSelectedScreenshotRow::from_row,
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let kind = WalOperationKind::SelectedScreenshot;
        if row.format_version != i64::from(WalOperationKind::format_version())
            || row.codec_version != i64::from(kind.codec_version())
            || row.request_fingerprint.len() != 32
            || row.result_commitment.len() != 32
            || row.result_bytes.len() > MAX_ENCODED_REPLAY_RESULT_BYTES
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
        if !row.matches_plan(prepared.plan_for_domain_ledger())? {
            return Err(WalIdempotencyError::Corrupt);
        }
        let result = WalReplayResult::decode(kind, &row.result_bytes)?;
        if row.result_commitment.as_slice() != result.commitment(kind)?.as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let _ = prepared
            .plan_for_domain_ledger()
            .authenticate_attempt_binding(connection)?;
        prepared
            .plan_for_domain_ledger()
            .authenticate_v3_local_uniqueness(connection)?;
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
        let plan = prepared.plan_for_domain_ledger();
        let screenshot_id = transaction
            .query_row(
                "SELECT screenshot_id FROM screenshot_images WHERE id=?1",
                [plan.image_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| WalIdempotencyError::Corrupt)?;
        let (request_version, request_subtype) = plan.request_identity();
        type V3StoredFields = (
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<i64>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<String>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let v3: V3StoredFields = match &plan.request_contract {
            #[cfg(test)]
            SelectedScreenshotRequestContract::UnboundV1 => (
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None,
            ),
            #[cfg(test)]
            SelectedScreenshotRequestContract::BoundV2 {
                attempt_binding_commitment,
            } => (
                None,
                None,
                None,
                Some(attempt_binding_commitment.to_vec()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            SelectedScreenshotRequestContract::ProviderAcceptedV3 {
                attempt_operation_id,
                attempt_request_fingerprint,
                predecessor_commitment,
                provider_binding,
                provider_generation,
                readback_commitment,
                ..
            } => (
                Some(attempt_operation_id.as_bytes().to_vec()),
                Some(attempt_request_fingerprint.to_vec()),
                Some(predecessor_commitment.to_vec()),
                Some(provider_binding.attempt_binding_commitment().to_vec()),
                Some(provider_binding.candidate_request_fingerprint().to_vec()),
                Some(provider_binding.wrapped_dek_commitment().to_vec()),
                Some(provider_binding.media_dek_binding_commitment().to_vec()),
                Some(provider_binding.aad_commitment().to_vec()),
                Some(i64::from(provider_binding.ciphertext_length())),
                Some(provider_binding.ciphertext_sha256().to_vec()),
                Some(provider_binding.candidate_binding_commitment().to_vec()),
                Some(provider_binding.send_request_id().to_owned()),
                Some(provider_binding.send_binding_commitment().to_vec()),
                Some(provider_generation.to_be_bytes().to_vec()),
                Some(readback_commitment.to_vec()),
            ),
        };
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_selected_screenshot_operations
                 (operation_id,format_version,codec_version,request_version,request_subtype,
                  request_fingerprint,account_id,image_id,object_key,episode_id,screenshot_id,
                  source_key,captured_at,width,height,byte_length,sha256,
                  attempt_operation_id,attempt_request_fingerprint,predecessor_commitment,
                  attempt_binding_commitment,candidate_request_fingerprint,
                  wrapped_dek_commitment,media_dek_binding_commitment,aad_commitment,
                  ciphertext_length,ciphertext_sha256,candidate_binding_commitment,
                  send_request_id,send_binding_commitment,provider_generation,
                  readback_commitment,result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,
                         ?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,
                         ?33,?34)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    i64::from(request_version),
                    i64::from(request_subtype),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    plan.account_id,
                    plan.image_id,
                    plan.object_key,
                    plan.episode_id,
                    screenshot_id,
                    plan.source_key,
                    plan.captured_at,
                    plan.jpeg.width,
                    plan.jpeg.height,
                    plan.jpeg.byte_length,
                    plan.jpeg.sha256,
                    v3.0,
                    v3.1,
                    v3.2,
                    v3.3,
                    v3.4,
                    v3.5,
                    v3.6,
                    v3.7,
                    v3.8,
                    v3.9,
                    v3.10,
                    v3.11,
                    v3.12,
                    v3.13,
                    v3.14,
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

fn append_provider_binding(
    destination: &mut Vec<u8>,
    binding: &selected_screenshot_provider::SelectedScreenshotProviderBinding,
) -> Result<()> {
    append_string(destination, binding.account_id())?;
    append_string(destination, binding.image_id())?;
    append_string(destination, binding.object_key())?;
    destination.extend_from_slice(&binding.candidate_request_fingerprint());
    destination.extend_from_slice(&binding.attempt_binding_commitment());
    destination.extend_from_slice(&binding.wrapped_dek_commitment());
    destination.extend_from_slice(&binding.media_dek_binding_commitment());
    destination.extend_from_slice(&binding.aad_commitment());
    destination.extend_from_slice(&binding.ciphertext_length().to_be_bytes());
    destination.extend_from_slice(&binding.ciphertext_sha256());
    destination.extend_from_slice(&binding.candidate_binding_commitment());
    append_string(destination, binding.send_request_id())?;
    destination.extend_from_slice(&binding.send_binding_commitment());
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
        | EnclaveError::SignupLimited
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
                        format_version INTEGER NOT NULL CHECK(format_version=2),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_selected_screenshot_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_version INTEGER NOT NULL,
                        request_subtype INTEGER NOT NULL,
                        request_fingerprint BLOB NOT NULL,
                        account_id TEXT NOT NULL,
                        image_id TEXT NOT NULL UNIQUE,
                        object_key TEXT NOT NULL UNIQUE,
                        episode_id INTEGER NOT NULL,
                        screenshot_id INTEGER NOT NULL,
                        source_key TEXT NOT NULL UNIQUE,
                        captured_at TEXT NOT NULL,
                        width INTEGER NOT NULL,
                        height INTEGER NOT NULL,
                        byte_length INTEGER NOT NULL,
                        sha256 TEXT NOT NULL,
                        attempt_operation_id BLOB,
                        attempt_request_fingerprint BLOB,
                        predecessor_commitment BLOB,
                        attempt_binding_commitment BLOB,
                        candidate_request_fingerprint BLOB,
                        wrapped_dek_commitment BLOB,
                        media_dek_binding_commitment BLOB,
                        aad_commitment BLOB,
                        ciphertext_length INTEGER,
                        ciphertext_sha256 BLOB,
                        candidate_binding_commitment BLOB,
                        send_request_id TEXT,
                        send_binding_commitment BLOB,
                        provider_generation BLOB,
                        readback_commitment BLOB,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(account_id) BETWEEN 1 AND 128),
                        CHECK(length(image_id)=32),
                        CHECK(length(object_key) BETWEEN 1 AND 512),
                        CHECK(episode_id>0 AND screenshot_id>0),
                        CHECK(length(source_key) BETWEEN 1 AND 4096),
                        CHECK(length(captured_at) BETWEEN 1 AND 4096),
                        CHECK(width BETWEEN 1 AND 16384 AND height BETWEEN 1 AND 16384),
                        CHECK(byte_length BETWEEN 1 AND 4194304),
                        CHECK(length(sha256)=64),
                        CHECK(
                          (request_version=1 AND request_subtype=1
                           AND attempt_operation_id IS NULL
                           AND attempt_request_fingerprint IS NULL
                           AND predecessor_commitment IS NULL
                           AND attempt_binding_commitment IS NULL
                           AND candidate_request_fingerprint IS NULL
                           AND wrapped_dek_commitment IS NULL
                           AND media_dek_binding_commitment IS NULL
                           AND aad_commitment IS NULL AND ciphertext_length IS NULL
                           AND ciphertext_sha256 IS NULL
                           AND candidate_binding_commitment IS NULL
                           AND send_request_id IS NULL AND send_binding_commitment IS NULL
                           AND provider_generation IS NULL AND readback_commitment IS NULL)
                          OR
                          (request_version=2 AND request_subtype=3
                           AND attempt_operation_id IS NULL
                           AND attempt_request_fingerprint IS NULL
                           AND predecessor_commitment IS NULL
                           AND length(attempt_binding_commitment)=32
                           AND attempt_binding_commitment<>zeroblob(32)
                           AND candidate_request_fingerprint IS NULL
                           AND wrapped_dek_commitment IS NULL
                           AND media_dek_binding_commitment IS NULL
                           AND aad_commitment IS NULL AND ciphertext_length IS NULL
                           AND ciphertext_sha256 IS NULL
                           AND candidate_binding_commitment IS NULL
                           AND send_request_id IS NULL AND send_binding_commitment IS NULL
                           AND provider_generation IS NULL AND readback_commitment IS NULL)
                          OR
                          (request_version=3 AND request_subtype=7
                           AND length(attempt_operation_id)=16
                           AND attempt_operation_id<>zeroblob(16)
                           AND length(attempt_request_fingerprint)=32
                           AND attempt_request_fingerprint<>zeroblob(32)
                           AND length(predecessor_commitment)=32
                           AND predecessor_commitment<>zeroblob(32)
                           AND length(attempt_binding_commitment)=32
                           AND attempt_binding_commitment<>zeroblob(32)
                           AND length(candidate_request_fingerprint)=32
                           AND candidate_request_fingerprint<>zeroblob(32)
                           AND length(wrapped_dek_commitment)=32
                           AND wrapped_dek_commitment<>zeroblob(32)
                           AND length(media_dek_binding_commitment)=32
                           AND media_dek_binding_commitment<>zeroblob(32)
                           AND length(aad_commitment)=32 AND aad_commitment<>zeroblob(32)
                           AND ciphertext_length>0
                           AND length(ciphertext_sha256)=32
                           AND ciphertext_sha256<>zeroblob(32)
                           AND length(candidate_binding_commitment)=32
                           AND candidate_binding_commitment<>zeroblob(32)
                           AND length(send_request_id)=64
                           AND length(send_binding_commitment)=32
                           AND send_binding_commitment<>zeroblob(32)
                           AND length(provider_generation)=8
                           AND provider_generation<>zeroblob(8)
                           AND length(readback_commitment)=32
                           AND readback_commitment<>zeroblob(32))
                        ),
                        CHECK(length(result_bytes) BETWEEN 9 AND 4105),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_selected_screenshot_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 536870912)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_selected_screenshot_schema
                        (singleton,format_version,codec_version) VALUES (1,2,1);
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
            LEDGER_SCHEMA_REVISION,
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
    let actual = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(result_bytes)),0)
             FROM archive_v3_wal_selected_screenshot_operations",
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
    fn forged_row_cap_counter_fails_closed_before_replay_or_new_insert() {
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
        let replay_error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(1, 'a', 7, SOURCE)).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(replay_error, WalIdempotencyError::Corrupt);
        let error = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(forced_plan(2, 'b', 8, "device-1:screen-2")).unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error, WalIdempotencyError::Corrupt);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| row
                    .get::<_, i64>(0),)
                .unwrap(),
            1
        );
    }

    #[test]
    fn forged_result_byte_cap_counter_fails_closed_before_domain_insert() {
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
        assert_eq!(error, WalIdempotencyError::Corrupt);
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
