#![allow(
    dead_code,
    reason = "inactive ADR-0022 selected-screenshot C settlement is reviewed before launcher ownership"
)]

//! Inactive definitive-no-object C settlement for one selected-screenshot send.
//!
//! Construction consumes only the provider boundary's non-cloneable rejection
//! proof. One immediate transaction reauthenticates the permanent B attempt,
//! ciphertext candidate, `SendStarted` marker, exact provider proof, and the
//! continued absence of an A result before retaining a unit terminal row. The
//! same target remains permanently burned, but an exact C row releases its
//! episode count/byte reservation for a different target. Unknown, unavailable,
//! collision, or manual outcomes cannot construct this plan. This child has no
//! provider, retry, list/delete, Store, launcher, task, clock, or acknowledgement
//! authority.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation, WalIdempotencyError,
    WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind,
    WalReplayResult,
};

use super::{
    selected_screenshot_attempt::{
        authenticate_selected_screenshot_attempt_for_terminal, SelectedScreenshotAttemptFacts,
    },
    selected_screenshot_provider::{
        authenticate_provider_execution_claim, authenticate_rejected_no_object_facts,
        SelectedScreenshotProviderBinding, SelectedScreenshotProviderRejectedNoObject,
    },
    selected_screenshot_send::authenticate_selected_screenshot_send_provider_facts,
    ValidatedJpeg, MAX_SCREENSHOT_IMAGE_BYTES, MAX_SCREENSHOT_LONG_EDGE,
    MAX_SCREENSHOT_METADATA_FIELD_BYTES,
};

const REQUEST_V1: u16 = 1;
const REQUEST_SELECTED_SCREENSHOT_TERMINATION: u8 = 6;
const OPERATION_SOURCE_DOMAIN: &[u8] = b"selected-screenshot-upload-termination-v1\0";
const TERMINAL_KIND_DEFINITIVELY_REJECTED_NO_OBJECT: i64 = 1;
const MAX_ACCOUNT_ID_BYTES: usize = 128;
const MAX_OBJECT_KEY_BYTES: usize = 512;
const MAX_TIMESTAMP_BYTES: usize = 64;
const SEND_REQUEST_ID_BYTES: usize = 64;
const UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_selected_screenshot_termination_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_selected_screenshot_terminations";
const STATE_TABLE: &str = "archive_v3_wal_selected_screenshot_termination_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 16 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

pub(crate) struct SelectedScreenshotTerminationPlan {
    operation_id: WalLogicalOperationId,
    attempt: SelectedScreenshotAttemptFacts,
    provider_binding: SelectedScreenshotProviderBinding,
    evidence_commitment: [u8; 32],
    rejection_commitment: [u8; 32],
    observed_at: String,
}

impl SelectedScreenshotTerminationPlan {
    fn from_parts(
        attempt: SelectedScreenshotAttemptFacts,
        provider_binding: SelectedScreenshotProviderBinding,
        evidence_commitment: [u8; 32],
        rejection_commitment: [u8; 32],
        observed_at: String,
    ) -> Result<Self> {
        validate_attempt_shape(&attempt)?;
        validate_canonical_timestamp(&observed_at)?;
        authenticate_rejected_no_object_facts(
            &provider_binding,
            &evidence_commitment,
            &rejection_commitment,
        )?;
        if provider_binding.account_id() != attempt.account_id
            || provider_binding.image_id() != attempt.image_id
            || provider_binding.object_key() != attempt.object_key
            || provider_binding.attempt_binding_commitment() != attempt.binding_commitment
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        let operation_id = derive_operation_id(attempt.operation_id)?;
        Ok(Self {
            operation_id,
            attempt,
            provider_binding,
            evidence_commitment,
            rejection_commitment,
            observed_at,
        })
    }
}

pub(crate) struct SelectedScreenshotTerminationLedger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

/// WAL-private factory for the sole release-authorizing terminal outcome. The
/// caller supplies time; this child has no clock and performs no provider I/O.
pub(super) fn prepare_selected_screenshot_termination(
    connection: &Connection,
    rejection: SelectedScreenshotProviderRejectedNoObject,
    observed_at: String,
) -> Result<SelectedScreenshotTerminationPlan> {
    let (provider_binding, evidence_commitment, rejection_commitment) = rejection.into_parts();
    let attempt = authenticate_selected_screenshot_attempt_for_terminal(
        connection,
        provider_binding.account_id(),
        provider_binding.image_id(),
        provider_binding.object_key(),
        &provider_binding.attempt_binding_commitment(),
    )?;
    authenticate_provider_execution_claim(connection, &provider_binding)?;
    SelectedScreenshotTerminationPlan::from_parts(
        attempt,
        provider_binding,
        evidence_commitment,
        rejection_commitment,
        observed_at,
    )
}

/// Exact-name restart loader for one already durable terminal. It reconstructs
/// no provider authority and returns a plan only after the complete C row and
/// every durable predecessor reauthenticate.
pub(super) fn load_selected_screenshot_termination_plan(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
) -> Result<Option<SelectedScreenshotTerminationPlan>> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    if account_id.len() > MAX_ACCOUNT_ID_BYTES || !super::valid_lower_hex(image_id, 32) {
        return Err(WalIdempotencyError::Malformed);
    }
    if schema_state(connection)? == LedgerSchemaState::Absent {
        return Ok(None);
    }
    validate_schema_marker(connection)?;
    let operation = connection
        .query_row(
            "SELECT operation_id FROM archive_v3_wal_selected_screenshot_terminations
             WHERE image_id=?1",
            [image_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(operation) = operation else {
        return Ok(None);
    };
    let operation_id = WalLogicalOperationId::from_bytes(array_16(&operation)?)
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    let row =
        load_row_by_operation(connection, operation_id)?.ok_or(WalIdempotencyError::Corrupt)?;
    if row.account_id != account_id || row.image_id != image_id {
        return Err(WalIdempotencyError::Corrupt);
    }
    let prepared = PreparedLogicalMutation::prepare(row.to_plan()?)
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    SelectedScreenshotTerminationLedger::lookup(connection, &prepared)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    Ok(Some(row.to_plan()?))
}

impl WalLogicalDomainPlan for SelectedScreenshotTerminationPlan {
    type Ledger = SelectedScreenshotTerminationLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::SelectedScreenshot
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        request.push(REQUEST_SELECTED_SCREENSHOT_TERMINATION);
        request.extend_from_slice(self.attempt.operation_id.as_bytes());
        request.extend_from_slice(&self.attempt.request_fingerprint);
        append_string(&mut request, &self.attempt.account_id)?;
        append_string(&mut request, &self.attempt.image_id)?;
        append_string(&mut request, &self.attempt.object_key)?;
        request.extend_from_slice(&self.attempt.episode_id.to_be_bytes());
        request.extend_from_slice(&self.attempt.screenshot_id.to_be_bytes());
        append_string(&mut request, &self.attempt.source_key)?;
        append_string(&mut request, &self.attempt.captured_at)?;
        request.extend_from_slice(&self.attempt.jpeg.width.to_be_bytes());
        request.extend_from_slice(&self.attempt.jpeg.height.to_be_bytes());
        request.extend_from_slice(&self.attempt.jpeg.byte_length.to_be_bytes());
        append_string(&mut request, &self.attempt.jpeg.sha256)?;
        request.extend_from_slice(&self.attempt.predecessor_commitment);
        request.extend_from_slice(&self.attempt.binding_commitment);
        let provider = self.provider_binding.send_facts();
        request.extend_from_slice(&provider.candidate_request_fingerprint);
        request.extend_from_slice(&provider.wrapped_dek_commitment);
        request.extend_from_slice(&provider.media_dek_binding_commitment);
        request.extend_from_slice(&provider.aad_commitment);
        request.extend_from_slice(&provider.ciphertext_length.to_be_bytes());
        request.extend_from_slice(&provider.ciphertext_sha256);
        request.extend_from_slice(&provider.candidate_binding_commitment);
        append_string(&mut request, provider.send_request_id)?;
        request.extend_from_slice(&provider.send_binding_commitment);
        request.extend_from_slice(&self.evidence_commitment);
        request.extend_from_slice(&self.rejection_commitment);
        append_string(&mut request, &self.observed_at)?;
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        authenticate_predecessors(transaction, self, false)?;
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

impl WalLogicalDomainLedger<SelectedScreenshotTerminationPlan>
    for SelectedScreenshotTerminationLedger
{
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<SelectedScreenshotTerminationPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let Some(result_length) = connection
            .query_row(
                "SELECT length(result_bytes)
                 FROM archive_v3_wal_selected_screenshot_terminations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
        else {
            return Ok(None);
        };
        if result_length != i64::try_from(UNIT_RESULT_BYTES).unwrap_or(i64::MAX) {
            return Err(WalIdempotencyError::Corrupt);
        }
        let row = load_row_by_operation(connection, prepared.operation_id_for_owner())?
            .ok_or(WalIdempotencyError::Corrupt)?;
        validate_stored_row_shape(&row)?;
        if row.request_fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
        }
        let plan = prepared.plan_for_domain_ledger();
        if !row.matches_plan(plan)
            || row.operation_id.as_slice()
                != derive_operation_id(plan.attempt.operation_id)?.as_bytes()
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        authenticate_predecessors(connection, plan, true)?;
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
        prepared: &PreparedLogicalMutation<SelectedScreenshotTerminationPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, UNIT_RESULT_BYTES)?;
        let plan = prepared.plan_for_domain_ledger();
        let result = plan.apply(transaction)?;
        plan.validate_replay(&result)?;
        let encoded = result.encode(WalOperationKind::SelectedScreenshot)?;
        if encoded.len() != UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let result_commitment = result.commitment(WalOperationKind::SelectedScreenshot)?;
        let provider = plan.provider_binding.send_facts();
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_selected_screenshot_terminations
                 (operation_id,format_version,codec_version,request_fingerprint,
                  attempt_operation_id,attempt_request_fingerprint,
                  account_id,image_id,object_key,episode_id,screenshot_id,source_key,captured_at,
                  width,height,byte_length,sha256,predecessor_commitment,
                  attempt_binding_commitment,candidate_request_fingerprint,
                  wrapped_dek_commitment,media_dek_binding_commitment,aad_commitment,
                  ciphertext_length,ciphertext_sha256,candidate_binding_commitment,
                  send_request_id,send_binding_commitment,terminal_kind,
                  evidence_commitment,rejection_commitment,observed_at,
                  result_bytes,result_commitment)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,
                         ?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,
                         ?29,?30,?31,?32,?33,?34)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(WalOperationKind::SelectedScreenshot.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    plan.attempt.operation_id.as_bytes().as_slice(),
                    plan.attempt.request_fingerprint.as_slice(),
                    plan.attempt.account_id,
                    plan.attempt.image_id,
                    plan.attempt.object_key,
                    plan.attempt.episode_id,
                    plan.attempt.screenshot_id,
                    plan.attempt.source_key,
                    plan.attempt.captured_at,
                    plan.attempt.jpeg.width,
                    plan.attempt.jpeg.height,
                    plan.attempt.jpeg.byte_length,
                    plan.attempt.jpeg.sha256,
                    plan.attempt.predecessor_commitment.as_slice(),
                    plan.attempt.binding_commitment.as_slice(),
                    provider.candidate_request_fingerprint.as_slice(),
                    provider.wrapped_dek_commitment.as_slice(),
                    provider.media_dek_binding_commitment.as_slice(),
                    provider.aad_commitment.as_slice(),
                    i64::from(provider.ciphertext_length),
                    provider.ciphertext_sha256.as_slice(),
                    provider.candidate_binding_commitment.as_slice(),
                    provider.send_request_id,
                    provider.send_binding_commitment.as_slice(),
                    TERMINAL_KIND_DEFINITIVELY_REJECTED_NO_OBJECT,
                    plan.evidence_commitment.as_slice(),
                    plan.rejection_commitment.as_slice(),
                    plan.observed_at,
                    encoded.as_slice(),
                    result_commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_termination_state
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

/// Rejects A/candidate admission when an exact C terminal already burned this
/// B attempt. A conflicting or malformed terminal fails as corruption.
pub(super) fn ensure_attempt_not_terminated(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
    object_key: &str,
    attempt_binding_commitment: &[u8; 32],
) -> Result<()> {
    if schema_state(connection)? == LedgerSchemaState::Absent {
        return Ok(());
    }
    validate_schema_marker(connection)?;
    let attempt = authenticate_selected_screenshot_attempt_for_terminal(
        connection,
        account_id,
        image_id,
        object_key,
        attempt_binding_commitment,
    )?;
    let operation_id = derive_operation_id(attempt.operation_id)?;
    let collisions = connection
        .query_row(
            "SELECT COUNT(*) FROM archive_v3_wal_selected_screenshot_terminations
             WHERE operation_id=?1 OR attempt_operation_id=?2 OR image_id=?3
                OR object_key=?4 OR attempt_binding_commitment=?5",
            params![
                operation_id.as_bytes().as_slice(),
                attempt.operation_id.as_bytes().as_slice(),
                image_id,
                object_key,
                attempt_binding_commitment.as_slice(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match collisions {
        0 => Ok(()),
        1 => {
            let row = load_row_by_operation(connection, operation_id)?
                .ok_or(WalIdempotencyError::Corrupt)?;
            let plan = row.to_plan()?;
            let prepared =
                PreparedLogicalMutation::prepare(plan).map_err(|_| WalIdempotencyError::Corrupt)?;
            SelectedScreenshotTerminationLedger::lookup(connection, &prepared)?
                .ok_or(WalIdempotencyError::Corrupt)?;
            Err(WalIdempotencyError::Precondition)
        }
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

/// Returns only fully authenticated C releases for one exact episode. Missing,
/// partial, conflicting, or tampered terminal state errors before any new B
/// reservation can be admitted.
pub(super) fn authenticated_episode_release_totals(
    connection: &Connection,
    episode_id: i64,
) -> Result<(i64, i64)> {
    if episode_id <= 0 || schema_state(connection)? == LedgerSchemaState::Absent {
        return Ok((0, 0));
    }
    validate_schema_marker(connection)?;
    let mut statement = connection
        .prepare(
            "SELECT operation_id FROM archive_v3_wal_selected_screenshot_terminations
             WHERE episode_id=?1 ORDER BY operation_id",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let operations = statement
        .query_map([episode_id], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    drop(statement);
    let mut count = 0i64;
    let mut bytes = 0i64;
    for operation in operations {
        let operation_id = WalLogicalOperationId::from_bytes(
            operation
                .as_slice()
                .try_into()
                .map_err(|_| WalIdempotencyError::Corrupt)?,
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
        let row =
            load_row_by_operation(connection, operation_id)?.ok_or(WalIdempotencyError::Corrupt)?;
        let plan = row.to_plan()?;
        if plan.attempt.episode_id != episode_id {
            return Err(WalIdempotencyError::Corrupt);
        }
        let byte_length = plan.attempt.jpeg.byte_length;
        let prepared =
            PreparedLogicalMutation::prepare(plan).map_err(|_| WalIdempotencyError::Corrupt)?;
        SelectedScreenshotTerminationLedger::lookup(connection, &prepared)?
            .ok_or(WalIdempotencyError::Corrupt)?;
        count = count.checked_add(1).ok_or(WalIdempotencyError::Corrupt)?;
        bytes = bytes
            .checked_add(byte_length)
            .ok_or(WalIdempotencyError::Corrupt)?;
    }
    Ok((count, bytes))
}

fn authenticate_predecessors(
    connection: &Connection,
    plan: &SelectedScreenshotTerminationPlan,
    terminal_exists: bool,
) -> Result<()> {
    let attempt = authenticate_selected_screenshot_attempt_for_terminal(
        connection,
        &plan.attempt.account_id,
        &plan.attempt.image_id,
        &plan.attempt.object_key,
        &plan.attempt.binding_commitment,
    )?;
    if attempt != plan.attempt {
        return Err(WalIdempotencyError::Corrupt);
    }
    authenticate_selected_screenshot_send_provider_facts(
        connection,
        &plan.provider_binding.send_facts(),
    )?;
    authenticate_provider_execution_claim(connection, &plan.provider_binding)?;
    authenticate_rejected_no_object_facts(
        &plan.provider_binding,
        &plan.evidence_commitment,
        &plan.rejection_commitment,
    )?;
    let local = connection
        .query_row(
            "SELECT COUNT(*) FROM screenshot_images
             WHERE source_key=?1 OR id=?2 OR object_key=?3 OR screenshot_id=?4",
            params![
                plan.attempt.source_key,
                plan.attempt.image_id,
                plan.attempt.object_key,
                plan.attempt.screenshot_id,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if local != 0 {
        return Err(if terminal_exists {
            WalIdempotencyError::Corrupt
        } else {
            WalIdempotencyError::Precondition
        });
    }
    if let Err(error) =
        super::ensure_no_bound_selected_screenshot_result_ledger(connection, &plan.attempt.image_id)
    {
        return Err(
            if terminal_exists && error == WalIdempotencyError::Precondition {
                WalIdempotencyError::Corrupt
            } else {
                error
            },
        );
    }
    Ok(())
}

fn validate_attempt_shape(attempt: &SelectedScreenshotAttemptFacts) -> Result<()> {
    crate::store::validate_user_id(&attempt.account_id)
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    let expected_object_key =
        crate::store::selected_evidence_media_object_key(&attempt.account_id, &attempt.image_id)
            .map_err(|_| WalIdempotencyError::Corrupt)?;
    if attempt.account_id.len() > MAX_ACCOUNT_ID_BYTES
        || !super::valid_lower_hex(&attempt.image_id, 32)
        || attempt.object_key != expected_object_key
        || attempt.object_key.len() > MAX_OBJECT_KEY_BYTES
        || attempt.episode_id <= 0
        || attempt.screenshot_id <= 0
        || attempt.source_key.is_empty()
        || attempt.source_key.len() > MAX_SCREENSHOT_METADATA_FIELD_BYTES
        || attempt.captured_at.is_empty()
        || attempt.captured_at.len() > MAX_SCREENSHOT_METADATA_FIELD_BYTES
        || attempt.jpeg.width <= 0
        || attempt.jpeg.height <= 0
        || attempt.jpeg.width > i32::from(MAX_SCREENSHOT_LONG_EDGE)
        || attempt.jpeg.height > i32::from(MAX_SCREENSHOT_LONG_EDGE)
        || attempt.jpeg.byte_length <= 0
        || usize::try_from(attempt.jpeg.byte_length)
            .ok()
            .is_none_or(|length| length > MAX_SCREENSHOT_IMAGE_BYTES)
        || !super::valid_lower_hex(&attempt.jpeg.sha256, 64)
        || [
            attempt.request_fingerprint,
            attempt.predecessor_commitment,
            attempt.binding_commitment,
        ]
        .contains(&[0; 32])
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn validate_canonical_timestamp(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TIMESTAMP_BYTES {
        return Err(WalIdempotencyError::Malformed);
    }
    let millis = super::super::super::isotime::parse_epoch_millis(value)
        .ok_or(WalIdempotencyError::Malformed)?;
    if super::super::super::isotime::format_epoch_millis(millis) != value {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn derive_operation_id(
    attempt_operation_id: WalLogicalOperationId,
) -> Result<WalLogicalOperationId> {
    let mut source = Vec::with_capacity(OPERATION_SOURCE_DOMAIN.len().saturating_add(16));
    source.extend_from_slice(OPERATION_SOURCE_DOMAIN);
    source.extend_from_slice(attempt_operation_id.as_bytes());
    WalLogicalOperationId::from_stable_source(WalOperationKind::SelectedScreenshot, &source)
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

fn require_kind(
    prepared: &PreparedLogicalMutation<SelectedScreenshotTerminationPlan>,
) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::SelectedScreenshot)
        .then_some(())
        .ok_or(WalIdempotencyError::ResultUnsupported)
}

struct StoredTerminationRow {
    operation_id: Vec<u8>,
    format_version: i64,
    codec_version: i64,
    request_fingerprint: Vec<u8>,
    attempt_operation_id: Vec<u8>,
    attempt_request_fingerprint: Vec<u8>,
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
    attempt_binding_commitment: Vec<u8>,
    candidate_request_fingerprint: Vec<u8>,
    wrapped_dek_commitment: Vec<u8>,
    media_dek_binding_commitment: Vec<u8>,
    aad_commitment: Vec<u8>,
    ciphertext_length: i64,
    ciphertext_sha256: Vec<u8>,
    candidate_binding_commitment: Vec<u8>,
    send_request_id: String,
    send_binding_commitment: Vec<u8>,
    terminal_kind: i64,
    evidence_commitment: Vec<u8>,
    rejection_commitment: Vec<u8>,
    observed_at: String,
    result_bytes: Vec<u8>,
    result_commitment: Vec<u8>,
}

impl StoredTerminationRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            operation_id: row.get(0)?,
            format_version: row.get(1)?,
            codec_version: row.get(2)?,
            request_fingerprint: row.get(3)?,
            attempt_operation_id: row.get(4)?,
            attempt_request_fingerprint: row.get(5)?,
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
            predecessor_commitment: row.get(17)?,
            attempt_binding_commitment: row.get(18)?,
            candidate_request_fingerprint: row.get(19)?,
            wrapped_dek_commitment: row.get(20)?,
            media_dek_binding_commitment: row.get(21)?,
            aad_commitment: row.get(22)?,
            ciphertext_length: row.get(23)?,
            ciphertext_sha256: row.get(24)?,
            candidate_binding_commitment: row.get(25)?,
            send_request_id: row.get(26)?,
            send_binding_commitment: row.get(27)?,
            terminal_kind: row.get(28)?,
            evidence_commitment: row.get(29)?,
            rejection_commitment: row.get(30)?,
            observed_at: row.get(31)?,
            result_bytes: row.get(32)?,
            result_commitment: row.get(33)?,
        })
    }

    fn to_plan(&self) -> Result<SelectedScreenshotTerminationPlan> {
        let attempt = SelectedScreenshotAttemptFacts {
            operation_id: WalLogicalOperationId::from_bytes(array_16(&self.attempt_operation_id)?)
                .map_err(|_| WalIdempotencyError::Corrupt)?,
            request_fingerprint: array_32(&self.attempt_request_fingerprint)?,
            account_id: self.account_id.clone(),
            image_id: self.image_id.clone(),
            object_key: self.object_key.clone(),
            episode_id: self.episode_id,
            screenshot_id: self.screenshot_id,
            source_key: self.source_key.clone(),
            captured_at: self.captured_at.clone(),
            jpeg: ValidatedJpeg {
                width: self.width,
                height: self.height,
                byte_length: self.byte_length,
                sha256: self.sha256.clone(),
            },
            predecessor_commitment: array_32(&self.predecessor_commitment)?,
            binding_commitment: array_32(&self.attempt_binding_commitment)?,
        };
        let provider_binding = SelectedScreenshotProviderBinding::from_terminal_facts(
            self.account_id.clone(),
            self.image_id.clone(),
            self.object_key.clone(),
            array_32(&self.candidate_request_fingerprint)?,
            array_32(&self.attempt_binding_commitment)?,
            array_32(&self.wrapped_dek_commitment)?,
            array_32(&self.media_dek_binding_commitment)?,
            array_32(&self.aad_commitment)?,
            u32::try_from(self.ciphertext_length).map_err(|_| WalIdempotencyError::Corrupt)?,
            array_32(&self.ciphertext_sha256)?,
            array_32(&self.candidate_binding_commitment)?,
            self.send_request_id.clone(),
            array_32(&self.send_binding_commitment)?,
        )?;
        SelectedScreenshotTerminationPlan::from_parts(
            attempt,
            provider_binding,
            array_32(&self.evidence_commitment)?,
            array_32(&self.rejection_commitment)?,
            self.observed_at.clone(),
        )
    }

    fn matches_plan(&self, plan: &SelectedScreenshotTerminationPlan) -> bool {
        let provider = plan.provider_binding.send_facts();
        self.operation_id.as_slice() == plan.operation_id.as_bytes()
            && self.attempt_operation_id.as_slice() == plan.attempt.operation_id.as_bytes()
            && self.attempt_request_fingerprint.as_slice() == plan.attempt.request_fingerprint
            && self.account_id == plan.attempt.account_id
            && self.image_id == plan.attempt.image_id
            && self.object_key == plan.attempt.object_key
            && self.episode_id == plan.attempt.episode_id
            && self.screenshot_id == plan.attempt.screenshot_id
            && self.source_key == plan.attempt.source_key
            && self.captured_at == plan.attempt.captured_at
            && self.width == plan.attempt.jpeg.width
            && self.height == plan.attempt.jpeg.height
            && self.byte_length == plan.attempt.jpeg.byte_length
            && self.sha256 == plan.attempt.jpeg.sha256
            && self.predecessor_commitment.as_slice() == plan.attempt.predecessor_commitment
            && self.attempt_binding_commitment.as_slice() == plan.attempt.binding_commitment
            && self.candidate_request_fingerprint.as_slice()
                == provider.candidate_request_fingerprint
            && self.wrapped_dek_commitment.as_slice() == provider.wrapped_dek_commitment
            && self.media_dek_binding_commitment.as_slice() == provider.media_dek_binding_commitment
            && self.aad_commitment.as_slice() == provider.aad_commitment
            && self.ciphertext_length == i64::from(provider.ciphertext_length)
            && self.ciphertext_sha256.as_slice() == provider.ciphertext_sha256
            && self.candidate_binding_commitment.as_slice() == provider.candidate_binding_commitment
            && self.send_request_id == provider.send_request_id
            && self.send_binding_commitment.as_slice() == provider.send_binding_commitment
            && self.terminal_kind == TERMINAL_KIND_DEFINITIVELY_REJECTED_NO_OBJECT
            && self.evidence_commitment.as_slice() == plan.evidence_commitment
            && self.rejection_commitment.as_slice() == plan.rejection_commitment
            && self.observed_at == plan.observed_at
    }
}

fn load_row_by_operation(
    connection: &Connection,
    operation_id: WalLogicalOperationId,
) -> Result<Option<StoredTerminationRow>> {
    connection
        .query_row(
            "SELECT operation_id,format_version,codec_version,request_fingerprint,
                    attempt_operation_id,attempt_request_fingerprint,
                    account_id,image_id,object_key,episode_id,screenshot_id,source_key,captured_at,
                    width,height,byte_length,sha256,predecessor_commitment,
                    attempt_binding_commitment,candidate_request_fingerprint,
                    wrapped_dek_commitment,media_dek_binding_commitment,aad_commitment,
                    ciphertext_length,ciphertext_sha256,candidate_binding_commitment,
                    send_request_id,send_binding_commitment,terminal_kind,
                    evidence_commitment,rejection_commitment,observed_at,
                    result_bytes,result_commitment
             FROM archive_v3_wal_selected_screenshot_terminations
             WHERE operation_id=?1",
            [operation_id.as_bytes().as_slice()],
            StoredTerminationRow::from_row,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn validate_stored_row_shape(row: &StoredTerminationRow) -> Result<()> {
    if row.operation_id.len() != 16
        || row.attempt_operation_id.len() != 16
        || row.request_fingerprint.len() != 32
        || row.attempt_request_fingerprint.len() != 32
        || row.predecessor_commitment.len() != 32
        || row.attempt_binding_commitment.len() != 32
        || row.candidate_request_fingerprint.len() != 32
        || row.wrapped_dek_commitment.len() != 32
        || row.media_dek_binding_commitment.len() != 32
        || row.aad_commitment.len() != 32
        || row.ciphertext_sha256.len() != 32
        || row.candidate_binding_commitment.len() != 32
        || row.send_binding_commitment.len() != 32
        || row.evidence_commitment.len() != 32
        || row.rejection_commitment.len() != 32
        || row.result_bytes.len() != UNIT_RESULT_BYTES
        || row.result_commitment.len() != 32
        || row.format_version != i64::from(WalOperationKind::format_version())
        || row.codec_version != i64::from(WalOperationKind::SelectedScreenshot.codec_version())
        || row.terminal_kind != TERMINAL_KIND_DEFINITIVELY_REJECTED_NO_OBJECT
        || !super::valid_lower_hex(&row.send_request_id, SEND_REQUEST_ID_BYTES)
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    let plan = row.to_plan()?;
    let prepared =
        PreparedLogicalMutation::prepare(plan).map_err(|_| WalIdempotencyError::Corrupt)?;
    if prepared.operation_id_for_owner().as_bytes().as_slice() != row.operation_id.as_slice()
        || prepared
            .request_fingerprint_for_owner()
            .as_bytes()
            .as_slice()
            != row.request_fingerprint.as_slice()
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn array_16(value: &[u8]) -> Result<[u8; 16]> {
    value.try_into().map_err(|_| WalIdempotencyError::Corrupt)
}

fn array_32(value: &[u8]) -> Result<[u8; 32]> {
    value.try_into().map_err(|_| WalIdempotencyError::Corrupt)
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
                    "CREATE TABLE archive_v3_wal_selected_screenshot_termination_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_selected_screenshot_terminations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        attempt_operation_id BLOB NOT NULL UNIQUE,
                        attempt_request_fingerprint BLOB NOT NULL UNIQUE,
                        account_id TEXT NOT NULL,
                        image_id TEXT NOT NULL UNIQUE,
                        object_key TEXT NOT NULL UNIQUE,
                        episode_id INTEGER NOT NULL CHECK(episode_id>0),
                        screenshot_id INTEGER NOT NULL CHECK(screenshot_id>0),
                        source_key TEXT NOT NULL UNIQUE,
                        captured_at TEXT NOT NULL,
                        width INTEGER NOT NULL CHECK(width BETWEEN 1 AND 8192),
                        height INTEGER NOT NULL CHECK(height BETWEEN 1 AND 8192),
                        byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 153600),
                        sha256 TEXT NOT NULL,
                        predecessor_commitment BLOB NOT NULL,
                        attempt_binding_commitment BLOB NOT NULL UNIQUE,
                        candidate_request_fingerprint BLOB NOT NULL UNIQUE,
                        wrapped_dek_commitment BLOB NOT NULL,
                        media_dek_binding_commitment BLOB NOT NULL,
                        aad_commitment BLOB NOT NULL,
                        ciphertext_length INTEGER NOT NULL CHECK(ciphertext_length BETWEEN 1 AND 153664),
                        ciphertext_sha256 BLOB NOT NULL,
                        candidate_binding_commitment BLOB NOT NULL UNIQUE,
                        send_request_id TEXT NOT NULL UNIQUE,
                        send_binding_commitment BLOB NOT NULL UNIQUE,
                        terminal_kind INTEGER NOT NULL CHECK(terminal_kind=1),
                        evidence_commitment BLOB NOT NULL,
                        rejection_commitment BLOB NOT NULL UNIQUE,
                        observed_at TEXT NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(attempt_operation_id)=16 AND attempt_operation_id<>zeroblob(16)),
                        CHECK(length(attempt_request_fingerprint)=32 AND attempt_request_fingerprint<>zeroblob(32)),
                        CHECK(length(account_id) BETWEEN 1 AND 128),
                        CHECK(length(image_id)=32),
                        CHECK(length(object_key) BETWEEN 1 AND 512),
                        CHECK(length(source_key) BETWEEN 1 AND 512),
                        CHECK(length(captured_at) BETWEEN 1 AND 512),
                        CHECK(length(sha256)=64),
                        CHECK(length(predecessor_commitment)=32 AND predecessor_commitment<>zeroblob(32)),
                        CHECK(length(attempt_binding_commitment)=32 AND attempt_binding_commitment<>zeroblob(32)),
                        CHECK(length(candidate_request_fingerprint)=32 AND candidate_request_fingerprint<>zeroblob(32)),
                        CHECK(length(wrapped_dek_commitment)=32 AND wrapped_dek_commitment<>zeroblob(32)),
                        CHECK(length(media_dek_binding_commitment)=32 AND media_dek_binding_commitment<>zeroblob(32)),
                        CHECK(length(aad_commitment)=32 AND aad_commitment<>zeroblob(32)),
                        CHECK(length(ciphertext_sha256)=32 AND ciphertext_sha256<>zeroblob(32)),
                        CHECK(length(candidate_binding_commitment)=32 AND candidate_binding_commitment<>zeroblob(32)),
                        CHECK(length(send_request_id)=64),
                        CHECK(length(send_binding_commitment)=32 AND send_binding_commitment<>zeroblob(32)),
                        CHECK(length(evidence_commitment)=32 AND evidence_commitment<>zeroblob(32)),
                        CHECK(length(rejection_commitment)=32 AND rejection_commitment<>zeroblob(32)),
                        CHECK(length(observed_at) BETWEEN 1 AND 64),
                        CHECK(length(result_bytes)=9),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE INDEX archive_v3_wal_selected_screenshot_terminations_episode
                        ON archive_v3_wal_selected_screenshot_terminations(episode_id,operation_id);
                     CREATE TABLE archive_v3_wal_selected_screenshot_termination_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 16777216)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_selected_screenshot_termination_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_selected_screenshot_termination_state
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
             FROM archive_v3_wal_selected_screenshot_termination_schema WHERE singleton=1",
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
             FROM archive_v3_wal_selected_screenshot_termination_state WHERE singleton=1",
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
             FROM archive_v3_wal_selected_screenshot_terminations",
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
        archive_v3_wal_idempotency::{
            execute_prepared_for_owner, LogicalMutationDisposition, PreparedLogicalMutation,
        },
        cp::{
            media::wal::MediaDekInstallPlan,
            query::wal::{
                selected_screenshot_attempt::{
                    authenticate_selected_screenshot_upload_predecessor,
                    SelectedScreenshotAttemptPlan, SelectedScreenshotAttemptReceipt,
                },
                selected_screenshot_provider::{
                    execute_selected_screenshot_provider_request,
                    prepare_selected_screenshot_provider_request,
                    SelectedScreenshotExactCreateProvider, SelectedScreenshotProviderCreateResult,
                    SelectedScreenshotProviderOutcome, SelectedScreenshotProviderReadback,
                    SelectedScreenshotProviderTransportError,
                },
                selected_screenshot_send::prepare_selected_screenshot_send_started,
                selected_screenshot_upload::SelectedScreenshotUploadCandidatePlan,
                SelectedScreenshotPlan, ValidatedJpeg,
            },
        },
        crypto::Dek,
    };
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
    use sha2::{Digest, Sha256};

    const ACCOUNT: &str = "account-1";
    const IMAGE_ID: &str = "11111111111111111111111111111111";
    const SOURCE_KEY: &str = "cloud-v2:screen-1";
    const CAPTURED_AT: &str = "2026-08-15T13:00:00.000Z";
    const OBSERVED_AT: &str = "2026-08-15T13:00:01.000Z";

    struct DefinitiveNoObjectProvider;

    #[async_trait::async_trait]
    impl SelectedScreenshotExactCreateProvider for DefinitiveNoObjectProvider {
        async fn create_if_absent(
            &self,
            _object_key: &str,
            _ciphertext: &[u8],
            _wrapped_dek_b64: &str,
            _send_request_id: &str,
        ) -> std::result::Result<
            SelectedScreenshotProviderCreateResult,
            SelectedScreenshotProviderTransportError,
        > {
            Ok(
                SelectedScreenshotProviderCreateResult::DefinitivelyRejectedNoObject {
                    evidence_commitment: [91; 32],
                },
            )
        }

        async fn get_exact(
            &self,
            _object_key: &str,
            _max_ciphertext_bytes: usize,
        ) -> std::result::Result<
            Option<SelectedScreenshotProviderReadback>,
            SelectedScreenshotProviderTransportError,
        > {
            Ok(None)
        }
    }

    struct Fixture {
        connection: Connection,
        dek: Dek,
        attempt: SelectedScreenshotAttemptReceipt,
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
        initialize(&connection);
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
        let attempt = execute_prepared_for_owner(
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
            &crate::store::media_blob_context(ACCOUNT, attempt.object_key()),
        )
        .unwrap();
        let candidate = SelectedScreenshotUploadCandidatePlan::new(
            ACCOUNT.to_owned(),
            IMAGE_ID.to_owned(),
            attempt.object_key().to_owned(),
            attempt.binding_commitment(),
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            jpeg.clone(),
            media_receipt,
            &dek,
            &plaintext,
            ciphertext,
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(candidate).unwrap(),
        )
        .unwrap();
        let send = prepare_selected_screenshot_send_started(&connection, ACCOUNT, IMAGE_ID, &dek)
            .unwrap()
            .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(send).unwrap(),
        )
        .unwrap();
        Fixture {
            connection,
            dek,
            attempt,
            jpeg,
        }
    }

    fn fixture() -> Fixture {
        fixture_with_connection(Connection::open_in_memory().unwrap())
    }

    async fn rejection(
        connection: &Connection,
        dek: &Dek,
    ) -> SelectedScreenshotProviderRejectedNoObject {
        let request =
            prepare_selected_screenshot_provider_request(connection, ACCOUNT, IMAGE_ID, dek)
                .unwrap()
                .unwrap();
        let outcome =
            execute_selected_screenshot_provider_request(&DefinitiveNoObjectProvider, request)
                .await;
        let SelectedScreenshotProviderOutcome::DefinitivelyRejectedNoObject(proof) = outcome else {
            panic!("expected definitive rejection")
        };
        proof
    }

    fn result_plan(fixture: &Fixture) -> SelectedScreenshotPlan {
        SelectedScreenshotPlan::new(
            ACCOUNT.to_owned(),
            IMAGE_ID.to_owned(),
            fixture.attempt.object_key().to_owned(),
            fixture.attempt.binding_commitment(),
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            fixture.jpeg.clone(),
        )
        .unwrap()
    }

    fn add_target(connection: &Connection, ordinal: i64) -> (String, String, ValidatedJpeg) {
        let source_key = format!("cloud-v2:screen-{ordinal}");
        let captured_at = format!("2026-08-15T13:{:02}:00.000Z", ordinal % 60);
        let screenshot_id = 40 + ordinal;
        connection
            .execute(
                "INSERT INTO screenshots(id,captured_at,source_key,is_duplicate)
                 VALUES (?1,?2,?3,0)",
                params![screenshot_id, captured_at, source_key],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO episode_members(episode_id,record_type,record_id)
                 VALUES (7,'screenshot',?1)",
                [screenshot_id],
            )
            .unwrap();
        let bytes = format!("jpeg-{ordinal}");
        let jpeg = ValidatedJpeg {
            width: 2,
            height: 2,
            byte_length: i64::try_from(bytes.len()).unwrap(),
            sha256: format!("{:x}", Sha256::digest(bytes.as_bytes())),
        };
        (source_key, captured_at, jpeg)
    }

    fn attempt_plan_for(connection: &Connection, ordinal: i64) -> SelectedScreenshotAttemptPlan {
        let (source_key, captured_at, jpeg) = add_target(connection, ordinal);
        let target = authenticate_selected_screenshot_upload_predecessor(
            connection,
            ACCOUNT,
            7,
            &source_key,
            &captured_at,
            &jpeg,
        )
        .unwrap();
        SelectedScreenshotAttemptPlan::new(
            ACCOUNT.to_owned(),
            format!("{ordinal:032x}"),
            7,
            source_key,
            captured_at,
            jpeg,
            target,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn exact_termination_applies_reopens_and_replays_without_provider_retry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("terminal.sqlite");
        let mut fixture = fixture_with_connection(Connection::open(&path).unwrap());
        let proof = rejection(&fixture.connection, &fixture.dek).await;
        let plan = prepare_selected_screenshot_termination(
            &fixture.connection,
            proof,
            OBSERVED_AT.to_owned(),
        )
        .unwrap();
        let applied = execute_prepared_for_owner(
            &mut fixture.connection,
            PreparedLogicalMutation::prepare(plan).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        applied.into_validated_result().release().unwrap();
        assert_eq!(load_ledger_state(&fixture.connection).unwrap(), (1, 9));
        drop(fixture.connection);

        let mut reopened = Connection::open(&path).unwrap();
        assert_eq!(
            prepare_selected_screenshot_provider_request(
                &reopened,
                ACCOUNT,
                IMAGE_ID,
                &fixture.dek,
            )
            .err(),
            Some(WalIdempotencyError::Precondition)
        );
        let replay_plan = load_selected_screenshot_termination_plan(&reopened, ACCOUNT, IMAGE_ID)
            .unwrap()
            .unwrap();
        let replay = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(replay_plan).unwrap(),
        )
        .unwrap();
        assert_eq!(replay.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(load_ledger_state(&reopened).unwrap(), (1, 9));
    }

    #[tokio::test]
    async fn exact_c_releases_budget_for_another_target_but_never_retries_the_same_target() {
        let mut fixture = fixture();
        for ordinal in 2..=24 {
            let plan = attempt_plan_for(&fixture.connection, ordinal);
            execute_prepared_for_owner(
                &mut fixture.connection,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            )
            .unwrap();
        }
        let next = attempt_plan_for(&fixture.connection, 25);
        assert_eq!(
            execute_prepared_for_owner(
                &mut fixture.connection,
                PreparedLogicalMutation::prepare(next).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );

        let proof = rejection(&fixture.connection, &fixture.dek).await;
        let terminal = prepare_selected_screenshot_termination(
            &fixture.connection,
            proof,
            OBSERVED_AT.to_owned(),
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut fixture.connection,
            PreparedLogicalMutation::prepare(terminal).unwrap(),
        )
        .unwrap();
        let retry_next = {
            let source_key = "cloud-v2:screen-25".to_owned();
            let captured_at = "2026-08-15T13:25:00.000Z".to_owned();
            let bytes = "jpeg-25";
            let jpeg = ValidatedJpeg {
                width: 2,
                height: 2,
                byte_length: i64::try_from(bytes.len()).unwrap(),
                sha256: format!("{:x}", Sha256::digest(bytes.as_bytes())),
            };
            let target = authenticate_selected_screenshot_upload_predecessor(
                &fixture.connection,
                ACCOUNT,
                7,
                &source_key,
                &captured_at,
                &jpeg,
            )
            .unwrap();
            SelectedScreenshotAttemptPlan::new(
                ACCOUNT.to_owned(),
                format!("{:032x}", 25),
                7,
                source_key,
                captured_at,
                jpeg,
                target,
            )
            .unwrap()
        };
        execute_prepared_for_owner(
            &mut fixture.connection,
            PreparedLogicalMutation::prepare(retry_next).unwrap(),
        )
        .unwrap();

        let first_target = authenticate_selected_screenshot_upload_predecessor(
            &fixture.connection,
            ACCOUNT,
            7,
            SOURCE_KEY,
            CAPTURED_AT,
            &fixture.jpeg,
        )
        .unwrap();
        let same_target = SelectedScreenshotAttemptPlan::new(
            ACCOUNT.to_owned(),
            "ffffffffffffffffffffffffffffffff".to_owned(),
            7,
            SOURCE_KEY.to_owned(),
            CAPTURED_AT.to_owned(),
            fixture.jpeg.clone(),
            first_target,
        )
        .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut fixture.connection,
                PreparedLogicalMutation::prepare(same_target).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
    }

    #[tokio::test]
    async fn a_and_c_are_mutually_exclusive() {
        let mut a_first = fixture();
        let proof = rejection(&a_first.connection, &a_first.dek).await;
        let terminal = prepare_selected_screenshot_termination(
            &a_first.connection,
            proof,
            OBSERVED_AT.to_owned(),
        )
        .unwrap();
        let result = result_plan(&a_first);
        execute_prepared_for_owner(
            &mut a_first.connection,
            PreparedLogicalMutation::prepare(result).unwrap(),
        )
        .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut a_first.connection,
                PreparedLogicalMutation::prepare(terminal).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );

        let mut c_first = fixture();
        let proof = rejection(&c_first.connection, &c_first.dek).await;
        let terminal = prepare_selected_screenshot_termination(
            &c_first.connection,
            proof,
            OBSERVED_AT.to_owned(),
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut c_first.connection,
            PreparedLogicalMutation::prepare(terminal).unwrap(),
        )
        .unwrap();
        let result = result_plan(&c_first);
        assert_eq!(
            execute_prepared_for_owner(
                &mut c_first.connection,
                PreparedLogicalMutation::prepare(result).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            c_first
                .connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn changed_terminal_facts_conflict_and_tamper_fails_closed() {
        let mut fixture = fixture();
        let first_proof = rejection(&fixture.connection, &fixture.dek).await;
        let first = prepare_selected_screenshot_termination(
            &fixture.connection,
            first_proof,
            OBSERVED_AT.to_owned(),
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut fixture.connection,
            PreparedLogicalMutation::prepare(first).unwrap(),
        )
        .unwrap();
        let mut changed =
            load_selected_screenshot_termination_plan(&fixture.connection, ACCOUNT, IMAGE_ID)
                .unwrap()
                .unwrap();
        changed.observed_at = "2026-08-15T13:00:02.000Z".to_owned();
        assert_eq!(
            execute_prepared_for_owner(
                &mut fixture.connection,
                PreparedLogicalMutation::prepare(changed).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::FingerprintConflict
        );
        fixture
            .connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_terminations
                 SET evidence_commitment=?1",
                [vec![33u8; 32]],
            )
            .unwrap();
        assert_eq!(
            load_selected_screenshot_termination_plan(&fixture.connection, ACCOUNT, IMAGE_ID,)
                .err()
                .unwrap(),
            WalIdempotencyError::Corrupt
        );
        let next = attempt_plan_for(&fixture.connection, 2);
        assert_eq!(
            execute_prepared_for_owner(
                &mut fixture.connection,
                PreparedLogicalMutation::prepare(next).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );
    }

    #[tokio::test]
    async fn late_terminal_readback_failure_rolls_back_row_and_counters() {
        let mut fixture = fixture();
        let proof = rejection(&fixture.connection, &fixture.dek).await;
        let plan = prepare_selected_screenshot_termination(
            &fixture.connection,
            proof,
            OBSERVED_AT.to_owned(),
        )
        .unwrap();
        let transaction = fixture.connection.transaction().unwrap();
        ensure_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        fixture
            .connection
            .execute_batch(
                "CREATE TRIGGER corrupt_selected_screenshot_terminal
                 AFTER INSERT ON archive_v3_wal_selected_screenshot_terminations
                 BEGIN
                   UPDATE archive_v3_wal_selected_screenshot_terminations
                   SET rejection_commitment=X'0101010101010101010101010101010101010101010101010101010101010101'
                   WHERE operation_id=NEW.operation_id;
                 END;",
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut fixture.connection,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );
        assert_eq!(load_ledger_state(&fixture.connection).unwrap(), (0, 0));
    }

    #[tokio::test]
    async fn partial_schema_and_predecessor_tamper_fail_closed() {
        let mut partial = fixture();
        let proof = rejection(&partial.connection, &partial.dek).await;
        let plan = prepare_selected_screenshot_termination(
            &partial.connection,
            proof,
            OBSERVED_AT.to_owned(),
        )
        .unwrap();
        partial
            .connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_selected_screenshot_termination_schema(
                    singleton INTEGER PRIMARY KEY,
                    format_version INTEGER NOT NULL,
                    codec_version INTEGER NOT NULL
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut partial.connection,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            )
            .err()
            .unwrap(),
            WalIdempotencyError::Corrupt
        );

        let mut tampered = fixture();
        let proof = rejection(&tampered.connection, &tampered.dek).await;
        let plan = prepare_selected_screenshot_termination(
            &tampered.connection,
            proof,
            OBSERVED_AT.to_owned(),
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut tampered.connection,
            PreparedLogicalMutation::prepare(plan).unwrap(),
        )
        .unwrap();
        tampered
            .connection
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_send_started
                 SET send_binding_commitment=?1",
                [vec![44u8; 32]],
            )
            .unwrap();
        assert_eq!(
            load_selected_screenshot_termination_plan(&tampered.connection, ACCOUNT, IMAGE_ID,)
                .err()
                .unwrap(),
            WalIdempotencyError::Corrupt
        );
    }
}
