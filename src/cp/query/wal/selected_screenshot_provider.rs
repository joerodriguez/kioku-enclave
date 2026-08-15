#![allow(
    dead_code,
    reason = "inactive ADR-0022 selected-screenshot provider proof boundary is reviewed before concrete transport or launcher ownership"
)]

//! Inactive provider-neutral outcome boundary for one selected-screenshot send.
//!
//! The boundary can be prepared only from an exact-name, DEK-authenticated
//! `SendStarted` marker and the exact installed wrapped DEK. Its injected
//! transport has create-if-absent and exact-get authority only. Every submitted
//! create is followed by one exact readback; there is no retry, enumeration, or
//! deletion. Exact bytes plus metadata mint an unforgeable success proof. Only
//! an explicitly definitive no-create response followed by exact absence mints
//! a rejection proof. Timeouts, unavailable responses, missing readback after
//! a claimed create, and collisions remain unresolved or manual and retain all
//! durable budget reservation.

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{archive_v3_wal_idempotency::WalIdempotencyError, crypto::Dek};

use super::selected_screenshot_send::{
    load_authenticated_selected_screenshot_send_started,
    AuthenticatedSelectedScreenshotSendStarted, SelectedScreenshotSendProviderFacts,
};

const MEDIA_DEK_METADATA_KEY: &str = "wrapped_media_dek";
const ACCEPTED_BINDING_DOMAIN: &[u8] = b"selected-screenshot-provider-accepted-v1\0";
const REJECTED_BINDING_DOMAIN: &[u8] = b"selected-screenshot-provider-definitive-no-object-v1\0";
const EXECUTION_CLAIM_DOMAIN: &[u8] = b"selected-screenshot-provider-execution-claim-v1\0";
const EXECUTION_CLAIM_SCHEMA_TABLE: &str =
    "archive_v3_wal_selected_screenshot_provider_execution_schema";
const EXECUTION_CLAIM_TABLE: &str = "archive_v3_wal_selected_screenshot_provider_executions";
const EXECUTION_CLAIM_STATE_TABLE: &str =
    "archive_v3_wal_selected_screenshot_provider_execution_state";
const MAX_EXECUTION_CLAIMS: u32 = 1_048_576;
const MAX_ACCOUNT_ID_BYTES: usize = 128;
const MAX_OBJECT_KEY_BYTES: usize = 512;
const MAX_WRAPPED_DEK_B64_BYTES: usize = 24 * 1024;
const SEND_REQUEST_ID_BYTES: usize = 64;

type Result<T> = std::result::Result<T, WalIdempotencyError>;

/// Narrow provider seam for one already-marked immutable create. Implementors
/// must enforce `max_ciphertext_bytes` before materializing an exact readback.
/// Errors are fixed classifications and must never carry provider bodies,
/// object names, ciphertext hashes, or credentials.
#[async_trait::async_trait]
pub(super) trait SelectedScreenshotExactCreateProvider: Send + Sync {
    async fn create_if_absent(
        &self,
        object_key: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
        send_request_id: &str,
    ) -> std::result::Result<
        SelectedScreenshotProviderCreateResult,
        SelectedScreenshotProviderTransportError,
    >;

    async fn get_exact(
        &self,
        object_key: &str,
        max_ciphertext_bytes: usize,
    ) -> std::result::Result<
        Option<SelectedScreenshotProviderReadback>,
        SelectedScreenshotProviderTransportError,
    >;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelectedScreenshotProviderTransportError {
    /// A submitted create may have committed.
    OutcomeUnknown,
    /// Availability failed after submission could have begun.
    Unavailable,
    /// A local or protocol fault that cannot prove a provider outcome.
    Protocol,
    /// The provider exceeded the exact bounded read contract.
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelectedScreenshotProviderCreateResult {
    Created,
    PreconditionFailed,
    /// The trusted transport proved that this request was rejected without an
    /// object create. The commitment is over its bounded canonical evidence;
    /// raw provider bodies never cross this seam.
    DefinitivelyRejectedNoObject {
        evidence_commitment: [u8; 32],
    },
}

pub(super) struct SelectedScreenshotProviderReadback {
    object_key: String,
    ciphertext: Zeroizing<Vec<u8>>,
    wrapped_dek_b64: Zeroizing<String>,
    send_request_id: String,
    generation: u64,
}

impl SelectedScreenshotProviderReadback {
    pub(super) fn new(
        object_key: String,
        ciphertext: Vec<u8>,
        wrapped_dek_b64: String,
        send_request_id: String,
        generation: u64,
    ) -> Self {
        Self {
            object_key,
            ciphertext: Zeroizing::new(ciphertext),
            wrapped_dek_b64: Zeroizing::new(wrapped_dek_b64),
            send_request_id,
            generation,
        }
    }
}

impl std::fmt::Debug for SelectedScreenshotProviderReadback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedScreenshotProviderReadback(<redacted>)")
    }
}

impl Drop for SelectedScreenshotProviderReadback {
    fn drop(&mut self) {
        self.object_key.zeroize();
        self.send_request_id.zeroize();
    }
}

#[derive(PartialEq, Eq)]
pub(super) struct SelectedScreenshotProviderBinding {
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

impl SelectedScreenshotProviderBinding {
    fn from_authenticated_send(
        authenticated: &AuthenticatedSelectedScreenshotSendStarted,
    ) -> Result<Self> {
        let facts = authenticated.receipt().provider_facts();
        validate_send_facts(&facts, authenticated.ciphertext())?;
        Ok(Self {
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
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_terminal_facts(
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
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Corrupt)?;
        let expected_object_key =
            crate::store::selected_evidence_media_object_key(&account_id, &image_id)
                .map_err(|_| WalIdempotencyError::Corrupt)?;
        if account_id.len() > MAX_ACCOUNT_ID_BYTES
            || !super::valid_lower_hex(&image_id, 32)
            || object_key != expected_object_key
            || object_key.is_empty()
            || object_key.len() > MAX_OBJECT_KEY_BYTES
            || ciphertext_length == 0
            || !super::valid_lower_hex(&send_request_id, SEND_REQUEST_ID_BYTES)
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
        Ok(Self {
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

    pub(super) fn send_facts(&self) -> SelectedScreenshotSendProviderFacts<'_> {
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

    pub(super) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(super) fn image_id(&self) -> &str {
        &self.image_id
    }

    pub(super) fn object_key(&self) -> &str {
        &self.object_key
    }

    pub(super) const fn candidate_request_fingerprint(&self) -> [u8; 32] {
        self.candidate_request_fingerprint
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

    pub(super) const fn candidate_binding_commitment(&self) -> [u8; 32] {
        self.candidate_binding_commitment
    }

    pub(super) fn send_request_id(&self) -> &str {
        &self.send_request_id
    }

    pub(super) const fn send_binding_commitment(&self) -> [u8; 32] {
        self.send_binding_commitment
    }
}

impl std::fmt::Debug for SelectedScreenshotProviderBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedScreenshotProviderBinding(<redacted>)")
    }
}

impl Drop for SelectedScreenshotProviderBinding {
    fn drop(&mut self) {
        self.account_id.zeroize();
        self.image_id.zeroize();
        self.object_key.zeroize();
        self.send_request_id.zeroize();
    }
}

pub(super) struct SelectedScreenshotProviderRequest {
    binding: SelectedScreenshotProviderBinding,
    ciphertext: Zeroizing<Vec<u8>>,
    wrapped_dek_b64: Zeroizing<String>,
}

impl std::fmt::Debug for SelectedScreenshotProviderRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedScreenshotProviderRequest(<redacted>)")
    }
}

pub(super) struct SelectedScreenshotProviderAccepted {
    binding: SelectedScreenshotProviderBinding,
    provider_generation: u64,
    readback_commitment: [u8; 32],
}

impl SelectedScreenshotProviderAccepted {
    pub(super) fn binding(&self) -> &SelectedScreenshotProviderBinding {
        &self.binding
    }

    pub(super) const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub(super) const fn readback_commitment(&self) -> [u8; 32] {
        self.readback_commitment
    }

    pub(super) fn into_parts(self) -> (SelectedScreenshotProviderBinding, u64, [u8; 32]) {
        (
            self.binding,
            self.provider_generation,
            self.readback_commitment,
        )
    }
}

impl std::fmt::Debug for SelectedScreenshotProviderAccepted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedScreenshotProviderAccepted(<redacted>)")
    }
}

pub(super) struct SelectedScreenshotProviderRejectedNoObject {
    binding: SelectedScreenshotProviderBinding,
    evidence_commitment: [u8; 32],
    rejection_commitment: [u8; 32],
}

impl SelectedScreenshotProviderRejectedNoObject {
    pub(super) fn binding(&self) -> &SelectedScreenshotProviderBinding {
        &self.binding
    }

    pub(super) const fn evidence_commitment(&self) -> [u8; 32] {
        self.evidence_commitment
    }

    pub(super) const fn rejection_commitment(&self) -> [u8; 32] {
        self.rejection_commitment
    }

    pub(super) fn into_parts(self) -> (SelectedScreenshotProviderBinding, [u8; 32], [u8; 32]) {
        (
            self.binding,
            self.evidence_commitment,
            self.rejection_commitment,
        )
    }
}

impl std::fmt::Debug for SelectedScreenshotProviderRejectedNoObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SelectedScreenshotProviderRejectedNoObject(<redacted>)")
    }
}

pub(super) enum SelectedScreenshotProviderOutcome {
    Accepted(SelectedScreenshotProviderAccepted),
    DefinitivelyRejectedNoObject(SelectedScreenshotProviderRejectedNoObject),
    OutcomeUnknown,
    ManualRequired,
}

impl std::fmt::Debug for SelectedScreenshotProviderOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted(_) => formatter.write_str("Accepted(<redacted>)"),
            Self::DefinitivelyRejectedNoObject(_) => {
                formatter.write_str("DefinitivelyRejectedNoObject(<redacted>)")
            }
            Self::OutcomeUnknown => formatter.write_str("OutcomeUnknown"),
            Self::ManualRequired => formatter.write_str("ManualRequired"),
        }
    }
}

/// Prepare one exact provider request without performing I/O. The wrapped DEK
/// is loaded only by its fixed metadata key and must match the commitment in
/// the already reauthenticated send marker.
pub(super) fn prepare_selected_screenshot_provider_request(
    connection: &Connection,
    account_id: &str,
    image_id: &str,
    plaintext_dek: &Dek,
) -> Result<Option<SelectedScreenshotProviderRequest>> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(authenticated) = load_authenticated_selected_screenshot_send_started(
        &transaction,
        account_id,
        image_id,
        plaintext_dek,
    )?
    else {
        return Ok(None);
    };
    let binding = SelectedScreenshotProviderBinding::from_authenticated_send(&authenticated)?;
    super::selected_screenshot_termination::ensure_attempt_not_terminated(
        &transaction,
        binding.account_id(),
        binding.image_id(),
        binding.object_key(),
        &binding.attempt_binding_commitment(),
    )?;
    let wrapped_dek_b64 = transaction
        .query_row(
            "SELECT value FROM app_metadata WHERE key=?1",
            [MEDIA_DEK_METADATA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    validate_wrapped_dek(&wrapped_dek_b64, &binding.wrapped_dek_commitment)?;
    claim_provider_execution(&transaction, &binding)?;
    let request = SelectedScreenshotProviderRequest {
        binding,
        ciphertext: Zeroizing::new(authenticated.ciphertext().to_vec()),
        wrapped_dek_b64: Zeroizing::new(wrapped_dek_b64),
    };
    transaction
        .commit()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    Ok(Some(request))
}

/// Perform exactly one create attempt and one exact readback. This function
/// never retries. Its returned authority is limited to a sealed accepted or
/// definitive-no-object proof; unresolved classifications convey no settlement
/// capability.
pub(super) async fn execute_selected_screenshot_provider_request(
    provider: &dyn SelectedScreenshotExactCreateProvider,
    request: SelectedScreenshotProviderRequest,
) -> SelectedScreenshotProviderOutcome {
    let create = provider
        .create_if_absent(
            &request.binding.object_key,
            request.ciphertext.as_slice(),
            request.wrapped_dek_b64.as_str(),
            &request.binding.send_request_id,
        )
        .await;

    if matches!(
        create,
        Err(SelectedScreenshotProviderTransportError::Protocol
            | SelectedScreenshotProviderTransportError::TooLarge)
    ) {
        return SelectedScreenshotProviderOutcome::ManualRequired;
    }

    let readback = provider
        .get_exact(
            &request.binding.object_key,
            usize::try_from(request.binding.ciphertext_length).unwrap_or(usize::MAX),
        )
        .await;
    let readback = match readback {
        Ok(value) => value,
        Err(
            SelectedScreenshotProviderTransportError::Protocol
            | SelectedScreenshotProviderTransportError::TooLarge,
        ) => return SelectedScreenshotProviderOutcome::ManualRequired,
        Err(
            SelectedScreenshotProviderTransportError::OutcomeUnknown
            | SelectedScreenshotProviderTransportError::Unavailable,
        ) => return SelectedScreenshotProviderOutcome::OutcomeUnknown,
    };

    if let Some(readback) = readback {
        if !readback_matches(&request, &readback) {
            return SelectedScreenshotProviderOutcome::ManualRequired;
        }
        let commitment =
            derive_accepted_commitment(&request.binding, readback.generation).unwrap_or([0; 32]);
        if commitment == [0; 32] {
            return SelectedScreenshotProviderOutcome::ManualRequired;
        }
        return SelectedScreenshotProviderOutcome::Accepted(SelectedScreenshotProviderAccepted {
            binding: request.binding,
            provider_generation: readback.generation,
            readback_commitment: commitment,
        });
    }

    match create {
        Ok(SelectedScreenshotProviderCreateResult::DefinitivelyRejectedNoObject {
            evidence_commitment,
        }) if evidence_commitment != [0; 32] => {
            let rejection_commitment =
                derive_rejected_commitment(&request.binding, &evidence_commitment)
                    .unwrap_or([0; 32]);
            if rejection_commitment == [0; 32] {
                SelectedScreenshotProviderOutcome::ManualRequired
            } else {
                SelectedScreenshotProviderOutcome::DefinitivelyRejectedNoObject(
                    SelectedScreenshotProviderRejectedNoObject {
                        binding: request.binding,
                        evidence_commitment,
                        rejection_commitment,
                    },
                )
            }
        }
        Err(
            SelectedScreenshotProviderTransportError::OutcomeUnknown
            | SelectedScreenshotProviderTransportError::Unavailable,
        ) => SelectedScreenshotProviderOutcome::OutcomeUnknown,
        Ok(
            SelectedScreenshotProviderCreateResult::Created
            | SelectedScreenshotProviderCreateResult::PreconditionFailed
            | SelectedScreenshotProviderCreateResult::DefinitivelyRejectedNoObject { .. },
        )
        | Err(
            SelectedScreenshotProviderTransportError::Protocol
            | SelectedScreenshotProviderTransportError::TooLarge,
        ) => SelectedScreenshotProviderOutcome::ManualRequired,
    }
}

fn validate_send_facts(
    facts: &SelectedScreenshotSendProviderFacts<'_>,
    ciphertext: &[u8],
) -> Result<()> {
    crate::store::validate_user_id(facts.account_id).map_err(|_| WalIdempotencyError::Corrupt)?;
    let expected_length =
        usize::try_from(facts.ciphertext_length).map_err(|_| WalIdempotencyError::Corrupt)?;
    if facts.account_id.len() > MAX_ACCOUNT_ID_BYTES
        || !super::valid_lower_hex(facts.image_id, 32)
        || facts.object_key.is_empty()
        || facts.object_key.len() > MAX_OBJECT_KEY_BYTES
        || !super::valid_lower_hex(facts.send_request_id, SEND_REQUEST_ID_BYTES)
        || expected_length == 0
        || ciphertext.len() != expected_length
        || <[u8; 32]>::from(Sha256::digest(ciphertext)) != facts.ciphertext_sha256
        || [
            facts.candidate_request_fingerprint,
            facts.attempt_binding_commitment,
            facts.wrapped_dek_commitment,
            facts.media_dek_binding_commitment,
            facts.aad_commitment,
            facts.ciphertext_sha256,
            facts.candidate_binding_commitment,
            facts.send_binding_commitment,
        ]
        .contains(&[0; 32])
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn validate_wrapped_dek(value: &str, expected_commitment: &[u8; 32]) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_WRAPPED_DEK_B64_BYTES
        || <[u8; 32]>::from(Sha256::digest(value.as_bytes())) != *expected_commitment
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionClaimSchemaState {
    Absent,
    Present,
}

/// Atomically and permanently admits the sole provider execution for this
/// `SendStarted` binding. Losing the returned in-memory request after commit is
/// fail-closed/manual; the boundary deliberately has no retry authority.
fn claim_provider_execution(
    transaction: &Transaction<'_>,
    binding: &SelectedScreenshotProviderBinding,
) -> Result<()> {
    ensure_execution_claim_schema(transaction)?;
    let collisions = transaction
        .query_row(
            "SELECT COUNT(*) FROM archive_v3_wal_selected_screenshot_provider_executions
             WHERE image_id=?1 OR object_key=?2 OR attempt_binding_commitment=?3
                OR send_request_id=?4 OR send_binding_commitment=?5",
            params![
                binding.image_id,
                binding.object_key,
                binding.attempt_binding_commitment.as_slice(),
                binding.send_request_id,
                binding.send_binding_commitment.as_slice(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if collisions != 0 {
        if collisions != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
        authenticate_provider_execution_claim(transaction, binding)?;
        return Err(WalIdempotencyError::Precondition);
    }
    let row_count = load_execution_claim_state(transaction)?;
    if row_count >= MAX_EXECUTION_CLAIMS {
        return Err(WalIdempotencyError::Limit);
    }
    let claim_commitment = derive_execution_claim_commitment(binding)?;
    transaction
        .execute(
            "INSERT INTO archive_v3_wal_selected_screenshot_provider_executions
             (claim_commitment,account_id,image_id,object_key,
              attempt_binding_commitment,send_request_id,send_binding_commitment)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                claim_commitment.as_slice(),
                binding.account_id,
                binding.image_id,
                binding.object_key,
                binding.attempt_binding_commitment.as_slice(),
                binding.send_request_id,
                binding.send_binding_commitment.as_slice(),
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let changed = transaction
        .execute(
            "UPDATE archive_v3_wal_selected_screenshot_provider_execution_state
             SET row_count=row_count+1 WHERE singleton=1 AND row_count=?1",
            [i64::from(row_count)],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    authenticate_provider_execution_claim(transaction, binding)?;
    if load_execution_claim_state(transaction)? != row_count.saturating_add(1) {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

/// Reauthenticates the unique durable execution claim consumed by a C
/// terminal. Missing, partial, colliding, or tampered state is corruption; it
/// can never authorize release.
pub(super) fn authenticate_provider_execution_claim(
    connection: &Connection,
    binding: &SelectedScreenshotProviderBinding,
) -> Result<()> {
    if execution_claim_schema_state(connection)? != ExecutionClaimSchemaState::Present {
        return Err(WalIdempotencyError::Corrupt);
    }
    validate_execution_claim_schema(connection)?;
    let expected = derive_execution_claim_commitment(binding)?;
    let stored = connection
        .query_row(
            "SELECT claim_commitment,account_id,image_id,object_key,
                    attempt_binding_commitment,send_request_id,send_binding_commitment
             FROM archive_v3_wal_selected_screenshot_provider_executions
             WHERE image_id=?1",
            [binding.image_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    if stored.0.as_slice() != expected
        || stored.1 != binding.account_id
        || stored.2 != binding.image_id
        || stored.3 != binding.object_key
        || stored.4.as_slice() != binding.attempt_binding_commitment
        || stored.5 != binding.send_request_id
        || stored.6.as_slice() != binding.send_binding_commitment
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn execution_claim_schema_state(connection: &Connection) -> Result<ExecutionClaimSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name IN (?1,?2,?3)",
            params![
                EXECUTION_CLAIM_SCHEMA_TABLE,
                EXECUTION_CLAIM_TABLE,
                EXECUTION_CLAIM_STATE_TABLE,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
        0 => Ok(ExecutionClaimSchemaState::Absent),
        3 => Ok(ExecutionClaimSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_execution_claim_schema(transaction: &Transaction<'_>) -> Result<()> {
    match execution_claim_schema_state(transaction)? {
        ExecutionClaimSchemaState::Present => validate_execution_claim_schema(transaction),
        ExecutionClaimSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_selected_screenshot_provider_execution_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_selected_screenshot_provider_executions (
                        claim_commitment BLOB PRIMARY KEY NOT NULL,
                        account_id TEXT NOT NULL,
                        image_id TEXT NOT NULL UNIQUE,
                        object_key TEXT NOT NULL UNIQUE,
                        attempt_binding_commitment BLOB NOT NULL UNIQUE,
                        send_request_id TEXT NOT NULL UNIQUE,
                        send_binding_commitment BLOB NOT NULL UNIQUE,
                        CHECK(length(claim_commitment)=32 AND claim_commitment<>zeroblob(32)),
                        CHECK(length(account_id) BETWEEN 1 AND 128),
                        CHECK(length(image_id)=32),
                        CHECK(length(object_key) BETWEEN 1 AND 512),
                        CHECK(length(attempt_binding_commitment)=32 AND attempt_binding_commitment<>zeroblob(32)),
                        CHECK(length(send_request_id)=64),
                        CHECK(length(send_binding_commitment)=32 AND send_binding_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_selected_screenshot_provider_execution_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count BETWEEN 0 AND 1048576)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_selected_screenshot_provider_execution_schema
                        (singleton,format_version,codec_version) VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_selected_screenshot_provider_execution_state
                        (singleton,row_count) VALUES (1,0);",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            validate_execution_claim_schema(transaction)
        }
    }
}

fn validate_execution_claim_schema(connection: &Connection) -> Result<()> {
    let marker = connection
        .query_row(
            "SELECT format_version,codec_version
             FROM archive_v3_wal_selected_screenshot_provider_execution_schema
             WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if marker != Some((1, 1)) {
        return Err(WalIdempotencyError::Corrupt);
    }
    let _ = load_execution_claim_state(connection)?;
    Ok(())
}

fn load_execution_claim_state(connection: &Connection) -> Result<u32> {
    let stored = connection
        .query_row(
            "SELECT row_count
             FROM archive_v3_wal_selected_screenshot_provider_execution_state
             WHERE singleton=1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Corrupt)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    let row_count = u32::try_from(stored).map_err(|_| WalIdempotencyError::Corrupt)?;
    let actual = connection
        .query_row(
            "SELECT COUNT(*) FROM archive_v3_wal_selected_screenshot_provider_executions",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Corrupt)?;
    if row_count > MAX_EXECUTION_CLAIMS || actual != i64::from(row_count) {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(row_count)
}

fn derive_execution_claim_commitment(
    binding: &SelectedScreenshotProviderBinding,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(EXECUTION_CLAIM_DOMAIN);
    hash_provider_binding(&mut hasher, binding)?;
    let commitment: [u8; 32] = hasher.finalize().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn readback_matches(
    request: &SelectedScreenshotProviderRequest,
    readback: &SelectedScreenshotProviderReadback,
) -> bool {
    readback.generation > 0
        && readback.object_key == request.binding.object_key
        && readback.send_request_id == request.binding.send_request_id
        && readback.ciphertext.as_slice() == request.ciphertext.as_slice()
        && readback.wrapped_dek_b64.as_str() == request.wrapped_dek_b64.as_str()
        && usize::try_from(request.binding.ciphertext_length)
            .is_ok_and(|length| readback.ciphertext.len() == length)
        && <[u8; 32]>::from(Sha256::digest(readback.ciphertext.as_slice()))
            == request.binding.ciphertext_sha256
        && <[u8; 32]>::from(Sha256::digest(readback.wrapped_dek_b64.as_bytes()))
            == request.binding.wrapped_dek_commitment
}

fn derive_accepted_commitment(
    binding: &SelectedScreenshotProviderBinding,
    provider_generation: u64,
) -> Result<[u8; 32]> {
    if provider_generation == 0 {
        return Err(WalIdempotencyError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(ACCEPTED_BINDING_DOMAIN);
    hash_provider_binding(&mut hasher, binding)?;
    hash_field(&mut hasher, &provider_generation.to_be_bytes())?;
    let commitment: [u8; 32] = hasher.finalize().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalIdempotencyError::Corrupt)
}

fn derive_rejected_commitment(
    binding: &SelectedScreenshotProviderBinding,
    evidence_commitment: &[u8; 32],
) -> Result<[u8; 32]> {
    if *evidence_commitment == [0; 32] {
        return Err(WalIdempotencyError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(REJECTED_BINDING_DOMAIN);
    hash_provider_binding(&mut hasher, binding)?;
    hash_field(&mut hasher, evidence_commitment)?;
    let commitment: [u8; 32] = hasher.finalize().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalIdempotencyError::Corrupt)
}

pub(super) fn authenticate_rejected_no_object_facts(
    binding: &SelectedScreenshotProviderBinding,
    evidence_commitment: &[u8; 32],
    rejection_commitment: &[u8; 32],
) -> Result<()> {
    (derive_rejected_commitment(binding, evidence_commitment)? == *rejection_commitment)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

pub(super) fn authenticate_accepted_facts(
    binding: &SelectedScreenshotProviderBinding,
    provider_generation: u64,
    readback_commitment: &[u8; 32],
) -> Result<()> {
    (derive_accepted_commitment(binding, provider_generation)? == *readback_commitment)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

fn hash_provider_binding(
    hasher: &mut Sha256,
    binding: &SelectedScreenshotProviderBinding,
) -> Result<()> {
    hash_field(hasher, binding.account_id.as_bytes())?;
    hash_field(hasher, binding.image_id.as_bytes())?;
    hash_field(hasher, binding.object_key.as_bytes())?;
    hash_field(hasher, &binding.candidate_request_fingerprint)?;
    hash_field(hasher, &binding.attempt_binding_commitment)?;
    hash_field(hasher, &binding.wrapped_dek_commitment)?;
    hash_field(hasher, &binding.media_dek_binding_commitment)?;
    hash_field(hasher, &binding.aad_commitment)?;
    hash_field(hasher, &binding.ciphertext_length.to_be_bytes())?;
    hash_field(hasher, &binding.ciphertext_sha256)?;
    hash_field(hasher, &binding.candidate_binding_commitment)?;
    hash_field(hasher, binding.send_request_id.as_bytes())?;
    hash_field(hasher, &binding.send_binding_commitment)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3_wal_idempotency::{
            execute_prepared_for_owner, LogicalMutationDisposition, PreparedLogicalMutation,
            WalLogicalDomainPlan,
        },
        cp::{
            media::wal::MediaDekInstallPlan,
            query::wal::{
                selected_screenshot_attempt::{
                    authenticate_selected_screenshot_attempt_for_terminal,
                    authenticate_selected_screenshot_upload_predecessor,
                    SelectedScreenshotAttemptPlan,
                },
                selected_screenshot_send::prepare_selected_screenshot_send_started,
                selected_screenshot_upload::SelectedScreenshotUploadCandidatePlan,
                SelectedScreenshotPlan, ValidatedJpeg,
            },
        },
    };
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
    use std::sync::Mutex;

    use super::super::selected_screenshot_termination::prepare_selected_screenshot_termination;
    use super::super::{
        ensure_schema as ensure_selected_screenshot_result_schema,
        load_selected_screenshot_provider_accepted_result,
        prepare_selected_screenshot_provider_accepted_result,
    };

    const ACCOUNT: &str = "account-1";
    const IMAGE_ID: &str = "11111111111111111111111111111111";
    const OBJECT_KEY: &str = "media/selected/account-1/11111111111111111111111111111111.enc";
    const SEND_REQUEST_ID: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SOURCE_KEY: &str = "cloud-v2:screen-1";
    const CAPTURED_AT: &str = "2026-08-15T13:00:00.000Z";

    struct ProviderScript {
        create: std::result::Result<
            SelectedScreenshotProviderCreateResult,
            SelectedScreenshotProviderTransportError,
        >,
        readback: std::result::Result<
            Option<SelectedScreenshotProviderReadback>,
            SelectedScreenshotProviderTransportError,
        >,
    }

    struct FakeProvider {
        script: Mutex<Option<ProviderScript>>,
        calls: Mutex<Vec<&'static str>>,
    }

    type SubmittedProviderCreate = (String, Vec<u8>, String, String);

    struct ExactAcceptProvider {
        submitted: Mutex<Option<SubmittedProviderCreate>>,
        calls: Mutex<Vec<&'static str>>,
        generation: u64,
    }

    impl ExactAcceptProvider {
        fn new() -> Self {
            Self::with_generation(17)
        }

        fn with_generation(generation: u64) -> Self {
            Self {
                submitted: Mutex::new(None),
                calls: Mutex::new(Vec::new()),
                generation,
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl SelectedScreenshotExactCreateProvider for ExactAcceptProvider {
        async fn create_if_absent(
            &self,
            object_key: &str,
            ciphertext: &[u8],
            wrapped_dek_b64: &str,
            send_request_id: &str,
        ) -> std::result::Result<
            SelectedScreenshotProviderCreateResult,
            SelectedScreenshotProviderTransportError,
        > {
            self.calls.lock().unwrap().push("create");
            *self.submitted.lock().unwrap() = Some((
                object_key.to_owned(),
                ciphertext.to_vec(),
                wrapped_dek_b64.to_owned(),
                send_request_id.to_owned(),
            ));
            Ok(SelectedScreenshotProviderCreateResult::Created)
        }

        async fn get_exact(
            &self,
            object_key: &str,
            _max_ciphertext_bytes: usize,
        ) -> std::result::Result<
            Option<SelectedScreenshotProviderReadback>,
            SelectedScreenshotProviderTransportError,
        > {
            self.calls.lock().unwrap().push("get");
            let submitted = self.submitted.lock().unwrap().take().unwrap();
            assert_eq!(submitted.0, object_key);
            Ok(Some(SelectedScreenshotProviderReadback::new(
                submitted.0,
                submitted.1,
                submitted.2,
                submitted.3,
                self.generation,
            )))
        }
    }

    impl FakeProvider {
        fn new(script: ProviderScript) -> Self {
            Self {
                script: Mutex::new(Some(script)),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl SelectedScreenshotExactCreateProvider for FakeProvider {
        async fn create_if_absent(
            &self,
            object_key: &str,
            ciphertext: &[u8],
            wrapped_dek_b64: &str,
            send_request_id: &str,
        ) -> std::result::Result<
            SelectedScreenshotProviderCreateResult,
            SelectedScreenshotProviderTransportError,
        > {
            assert_eq!(object_key, OBJECT_KEY);
            assert_eq!(ciphertext, b"ciphertext");
            assert_eq!(wrapped_dek_b64, "wrapped");
            assert_eq!(send_request_id, SEND_REQUEST_ID);
            self.calls.lock().unwrap().push("create");
            self.script.lock().unwrap().as_ref().unwrap().create
        }

        async fn get_exact(
            &self,
            object_key: &str,
            max_ciphertext_bytes: usize,
        ) -> std::result::Result<
            Option<SelectedScreenshotProviderReadback>,
            SelectedScreenshotProviderTransportError,
        > {
            assert_eq!(object_key, OBJECT_KEY);
            assert_eq!(max_ciphertext_bytes, b"ciphertext".len());
            self.calls.lock().unwrap().push("get");
            self.script.lock().unwrap().take().unwrap().readback
        }
    }

    fn request() -> SelectedScreenshotProviderRequest {
        let ciphertext = b"ciphertext".to_vec();
        let wrapped = "wrapped".to_owned();
        SelectedScreenshotProviderRequest {
            binding: SelectedScreenshotProviderBinding {
                account_id: ACCOUNT.to_owned(),
                image_id: IMAGE_ID.to_owned(),
                object_key: OBJECT_KEY.to_owned(),
                candidate_request_fingerprint: [1; 32],
                attempt_binding_commitment: [2; 32],
                wrapped_dek_commitment: Sha256::digest(wrapped.as_bytes()).into(),
                media_dek_binding_commitment: [3; 32],
                aad_commitment: [4; 32],
                ciphertext_length: u32::try_from(ciphertext.len()).unwrap(),
                ciphertext_sha256: Sha256::digest(&ciphertext).into(),
                candidate_binding_commitment: [5; 32],
                send_request_id: SEND_REQUEST_ID.to_owned(),
                send_binding_commitment: [6; 32],
            },
            ciphertext: Zeroizing::new(ciphertext),
            wrapped_dek_b64: Zeroizing::new(wrapped),
        }
    }

    fn exact_readback(generation: u64) -> SelectedScreenshotProviderReadback {
        SelectedScreenshotProviderReadback::new(
            OBJECT_KEY.to_owned(),
            b"ciphertext".to_vec(),
            "wrapped".to_owned(),
            SEND_REQUEST_ID.to_owned(),
            generation,
        )
    }

    fn duplicate_binding(
        binding: &SelectedScreenshotProviderBinding,
    ) -> SelectedScreenshotProviderBinding {
        SelectedScreenshotProviderBinding::from_terminal_facts(
            binding.account_id().to_owned(),
            binding.image_id().to_owned(),
            binding.object_key().to_owned(),
            binding.candidate_request_fingerprint(),
            binding.attempt_binding_commitment(),
            binding.wrapped_dek_commitment(),
            binding.media_dek_binding_commitment(),
            binding.aad_commitment(),
            binding.ciphertext_length(),
            binding.ciphertext_sha256(),
            binding.candidate_binding_commitment(),
            binding.send_request_id().to_owned(),
            binding.send_binding_commitment(),
        )
        .unwrap()
    }

    fn rejection_from_binding(
        binding: SelectedScreenshotProviderBinding,
    ) -> SelectedScreenshotProviderRejectedNoObject {
        let evidence_commitment = [89; 32];
        let rejection_commitment =
            derive_rejected_commitment(&binding, &evidence_commitment).unwrap();
        SelectedScreenshotProviderRejectedNoObject {
            binding,
            evidence_commitment,
            rejection_commitment,
        }
    }

    fn initialized_connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        initialize(&connection);
        connection
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

    fn candidate_ready_fixture() -> (Connection, Dek) {
        candidate_ready_fixture_with_connection(initialized_connection())
    }

    fn candidate_ready_fixture_with_connection(mut connection: Connection) -> (Connection, Dek) {
        initialize_if_needed(&connection);
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
            object_key,
            attempt_receipt.binding_commitment(),
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
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(candidate_plan).unwrap(),
        )
        .unwrap();
        (connection, dek)
    }

    fn initialize_if_needed(connection: &Connection) {
        let initialized = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='episodes'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        if initialized == 0 {
            initialize(connection);
        }
    }

    fn send_started_fixture() -> (Connection, Dek) {
        let (mut connection, dek) = candidate_ready_fixture();
        let send_plan =
            prepare_selected_screenshot_send_started(&connection, ACCOUNT, IMAGE_ID, &dek)
                .unwrap()
                .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(send_plan).unwrap(),
        )
        .unwrap();
        (connection, dek)
    }

    fn send_started_fixture_with_connection(connection: Connection) -> (Connection, Dek) {
        let (mut connection, dek) = candidate_ready_fixture_with_connection(connection);
        let send_plan =
            prepare_selected_screenshot_send_started(&connection, ACCOUNT, IMAGE_ID, &dek)
                .unwrap()
                .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(send_plan).unwrap(),
        )
        .unwrap();
        (connection, dek)
    }

    #[test]
    fn preparation_requires_exact_send_marker_and_installed_wrapper() {
        let (mut connection, dek) = candidate_ready_fixture();
        assert!(
            prepare_selected_screenshot_provider_request(&connection, ACCOUNT, IMAGE_ID, &dek)
                .unwrap()
                .is_none()
        );

        let send_plan =
            prepare_selected_screenshot_send_started(&connection, ACCOUNT, IMAGE_ID, &dek)
                .unwrap()
                .unwrap();
        execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(send_plan).unwrap(),
        )
        .unwrap();
        let prepared =
            prepare_selected_screenshot_provider_request(&connection, ACCOUNT, IMAGE_ID, &dek)
                .unwrap()
                .unwrap();
        assert_eq!(prepared.binding.account_id(), ACCOUNT);
        assert_eq!(prepared.binding.image_id(), IMAGE_ID);
        assert_eq!(
            prepared.ciphertext.len(),
            usize::try_from(prepared.binding.ciphertext_length()).unwrap()
        );
        assert!(!prepared.wrapped_dek_b64.is_empty());
        assert_eq!(
            prepare_selected_screenshot_provider_request(&connection, ACCOUNT, IMAGE_ID, &dek)
                .err(),
            Some(WalIdempotencyError::Precondition)
        );

        connection
            .execute(
                "UPDATE app_metadata SET value='tampered' WHERE key=?1",
                [MEDIA_DEK_METADATA_KEY],
            )
            .unwrap();
        assert_eq!(
            prepare_selected_screenshot_provider_request(&connection, ACCOUNT, IMAGE_ID, &dek)
                .unwrap_err(),
            WalIdempotencyError::Corrupt
        );
    }

    #[test]
    fn execution_claim_partial_schema_late_readback_and_counter_tamper_fail_closed() {
        let (partial, partial_dek) = send_started_fixture();
        partial
            .execute_batch(
                "CREATE TABLE archive_v3_wal_selected_screenshot_provider_execution_schema (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    format_version INTEGER NOT NULL CHECK(format_version=1),
                    codec_version INTEGER NOT NULL CHECK(codec_version=1)
                 ) STRICT;",
            )
            .unwrap();
        assert_eq!(
            prepare_selected_screenshot_provider_request(
                &partial,
                ACCOUNT,
                IMAGE_ID,
                &partial_dek,
            )
            .err(),
            Some(WalIdempotencyError::Corrupt)
        );

        let (mut late, late_dek) = send_started_fixture();
        let transaction = late.transaction().unwrap();
        ensure_execution_claim_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        late.execute_batch(
            "CREATE TRIGGER corrupt_provider_execution_claim_readback
             AFTER INSERT ON archive_v3_wal_selected_screenshot_provider_executions
             BEGIN
               UPDATE archive_v3_wal_selected_screenshot_provider_executions
               SET claim_commitment=X'0101010101010101010101010101010101010101010101010101010101010101'
               WHERE image_id=NEW.image_id;
             END;",
        )
        .unwrap();
        assert_eq!(
            prepare_selected_screenshot_provider_request(&late, ACCOUNT, IMAGE_ID, &late_dek).err(),
            Some(WalIdempotencyError::Corrupt)
        );
        assert_eq!(
            late.query_row(
                "SELECT COUNT(*) FROM archive_v3_wal_selected_screenshot_provider_executions",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        assert_eq!(load_execution_claim_state(&late).unwrap(), 0);

        let (tampered, tampered_dek) = send_started_fixture();
        let request = prepare_selected_screenshot_provider_request(
            &tampered,
            ACCOUNT,
            IMAGE_ID,
            &tampered_dek,
        )
        .unwrap()
        .unwrap();
        drop(request);
        tampered
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_provider_execution_state
                 SET row_count=0 WHERE singleton=1",
                [],
            )
            .unwrap();
        assert_eq!(
            prepare_selected_screenshot_provider_request(
                &tampered,
                ACCOUNT,
                IMAGE_ID,
                &tampered_dek,
            )
            .err(),
            Some(WalIdempotencyError::Corrupt)
        );
    }

    #[tokio::test]
    async fn created_or_preconditioned_exact_readback_mints_only_exact_acceptance() {
        for create in [
            SelectedScreenshotProviderCreateResult::Created,
            SelectedScreenshotProviderCreateResult::PreconditionFailed,
        ] {
            let provider = FakeProvider::new(ProviderScript {
                create: Ok(create),
                readback: Ok(Some(exact_readback(17))),
            });
            let outcome = execute_selected_screenshot_provider_request(&provider, request()).await;
            let SelectedScreenshotProviderOutcome::Accepted(accepted) = outcome else {
                panic!("expected accepted outcome")
            };
            assert_eq!(accepted.binding().account_id(), ACCOUNT);
            assert_eq!(accepted.binding().image_id(), IMAGE_ID);
            assert_eq!(accepted.binding().object_key(), OBJECT_KEY);
            assert_eq!(accepted.binding().send_request_id(), SEND_REQUEST_ID);
            assert_eq!(accepted.provider_generation(), 17);
            assert_ne!(accepted.readback_commitment(), [0; 32]);
            assert_eq!(provider.calls(), vec!["create", "get"]);
        }
    }

    #[tokio::test]
    async fn only_definitive_rejection_plus_exact_absence_mints_rejection() {
        let provider = FakeProvider::new(ProviderScript {
            create: Ok(
                SelectedScreenshotProviderCreateResult::DefinitivelyRejectedNoObject {
                    evidence_commitment: [9; 32],
                },
            ),
            readback: Ok(None),
        });
        let outcome = execute_selected_screenshot_provider_request(&provider, request()).await;
        let SelectedScreenshotProviderOutcome::DefinitivelyRejectedNoObject(rejected) = outcome
        else {
            panic!("expected definitive rejection")
        };
        assert_eq!(rejected.binding().object_key(), OBJECT_KEY);
        assert_eq!(rejected.evidence_commitment(), [9; 32]);
        assert_ne!(rejected.rejection_commitment(), [0; 32]);
        assert_eq!(provider.calls(), vec!["create", "get"]);

        let zero_evidence = FakeProvider::new(ProviderScript {
            create: Ok(
                SelectedScreenshotProviderCreateResult::DefinitivelyRejectedNoObject {
                    evidence_commitment: [0; 32],
                },
            ),
            readback: Ok(None),
        });
        assert!(matches!(
            execute_selected_screenshot_provider_request(&zero_evidence, request()).await,
            SelectedScreenshotProviderOutcome::ManualRequired
        ));
    }

    #[tokio::test]
    async fn unknown_absence_stays_unknown_but_exact_readback_recovers_success() {
        let unknown = FakeProvider::new(ProviderScript {
            create: Err(SelectedScreenshotProviderTransportError::OutcomeUnknown),
            readback: Ok(None),
        });
        assert!(matches!(
            execute_selected_screenshot_provider_request(&unknown, request()).await,
            SelectedScreenshotProviderOutcome::OutcomeUnknown
        ));

        let recovered = FakeProvider::new(ProviderScript {
            create: Err(SelectedScreenshotProviderTransportError::Unavailable),
            readback: Ok(Some(exact_readback(23))),
        });
        let outcome = execute_selected_screenshot_provider_request(&recovered, request()).await;
        let SelectedScreenshotProviderOutcome::Accepted(accepted) = outcome else {
            panic!("expected recovered acceptance")
        };
        assert_eq!(accepted.provider_generation(), 23);
    }

    #[tokio::test]
    async fn collisions_claimed_create_without_readback_and_protocol_faults_are_manual() {
        let mut conflict = exact_readback(29);
        conflict.send_request_id = "b".repeat(SEND_REQUEST_ID_BYTES);
        let provider = FakeProvider::new(ProviderScript {
            create: Ok(SelectedScreenshotProviderCreateResult::PreconditionFailed),
            readback: Ok(Some(conflict)),
        });
        assert!(matches!(
            execute_selected_screenshot_provider_request(&provider, request()).await,
            SelectedScreenshotProviderOutcome::ManualRequired
        ));

        let missing = FakeProvider::new(ProviderScript {
            create: Ok(SelectedScreenshotProviderCreateResult::Created),
            readback: Ok(None),
        });
        assert!(matches!(
            execute_selected_screenshot_provider_request(&missing, request()).await,
            SelectedScreenshotProviderOutcome::ManualRequired
        ));

        let protocol = FakeProvider::new(ProviderScript {
            create: Err(SelectedScreenshotProviderTransportError::Protocol),
            readback: Ok(None),
        });
        assert!(matches!(
            execute_selected_screenshot_provider_request(&protocol, request()).await,
            SelectedScreenshotProviderOutcome::ManualRequired
        ));
        assert_eq!(protocol.calls(), vec!["create"]);
    }

    #[tokio::test]
    async fn accepted_v3_applies_once_and_exact_name_replays_after_reopen_without_provider_io() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accepted-v3.sqlite");
        let (mut connection, dek) =
            send_started_fixture_with_connection(Connection::open(&path).unwrap());
        let provider = ExactAcceptProvider::with_generation(u64::MAX);
        let request =
            prepare_selected_screenshot_provider_request(&connection, ACCOUNT, IMAGE_ID, &dek)
                .unwrap()
                .unwrap();
        let attempt = authenticate_selected_screenshot_attempt_for_terminal(
            &connection,
            request.binding.account_id(),
            request.binding.image_id(),
            request.binding.object_key(),
            &request.binding.attempt_binding_commitment(),
        )
        .unwrap();
        let outcome = execute_selected_screenshot_provider_request(&provider, request).await;
        let SelectedScreenshotProviderOutcome::Accepted(accepted) = outcome else {
            panic!("expected accepted provider proof")
        };
        let plan =
            prepare_selected_screenshot_provider_accepted_result(&connection, accepted).unwrap();
        let historical_v2 = SelectedScreenshotPlan::new(
            attempt.account_id,
            attempt.image_id,
            attempt.object_key,
            attempt.binding_commitment,
            attempt.episode_id,
            attempt.source_key,
            attempt.captured_at,
            attempt.jpeg,
        )
        .unwrap();
        assert_ne!(plan.operation_id(), historical_v2.operation_id());
        assert_ne!(
            plan.canonical_request().unwrap(),
            historical_v2.canonical_request().unwrap()
        );
        let applied = execute_prepared_for_owner(
            &mut connection,
            PreparedLogicalMutation::prepare(plan).unwrap(),
        )
        .unwrap();
        assert_eq!(applied.disposition(), LogicalMutationDisposition::Applied);
        assert_eq!(provider.calls(), vec!["create", "get"]);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        drop(connection);

        let mut reopened = Connection::open(&path).unwrap();
        let replay_plan =
            load_selected_screenshot_provider_accepted_result(&reopened, ACCOUNT, IMAGE_ID)
                .unwrap()
                .unwrap();
        let changes = reopened.total_changes();
        let replayed = execute_prepared_for_owner(
            &mut reopened,
            PreparedLogicalMutation::prepare(replay_plan).unwrap(),
        )
        .unwrap();
        assert_eq!(replayed.disposition(), LogicalMutationDisposition::Replayed);
        assert_eq!(reopened.total_changes(), changes);
        assert_eq!(provider.calls(), vec!["create", "get"]);
        assert_eq!(
            prepare_selected_screenshot_provider_request(&reopened, ACCOUNT, IMAGE_ID, &dek).err(),
            Some(WalIdempotencyError::Precondition)
        );
        reopened
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,
                  width,height,byte_length,sha256)
                 VALUES (?1,41,7,'rebound:source',?2,?3,'image/jpeg',2,2,20,?4)",
                params![
                    "2".repeat(32),
                    CAPTURED_AT,
                    crate::store::selected_evidence_media_object_key(ACCOUNT, &"2".repeat(32),)
                        .unwrap(),
                    format!("{:x}", Sha256::digest(b"bounded-jpeg-fixture")),
                ],
            )
            .unwrap();
        assert_eq!(
            load_selected_screenshot_provider_accepted_result(&reopened, ACCOUNT, IMAGE_ID).err(),
            Some(WalIdempotencyError::Corrupt)
        );
        reopened
            .execute(
                "DELETE FROM screenshot_images WHERE id=?1",
                ["2".repeat(32)],
            )
            .unwrap();
        reopened
            .execute(
                "UPDATE archive_v3_wal_selected_screenshot_operations
                 SET provider_generation=X'0000000000000012' WHERE image_id=?1",
                [IMAGE_ID],
            )
            .unwrap();
        assert_eq!(
            load_selected_screenshot_provider_accepted_result(&reopened, ACCOUNT, IMAGE_ID).err(),
            Some(WalIdempotencyError::Corrupt)
        );
        assert_eq!(provider.calls(), vec!["create", "get"]);
    }

    #[tokio::test]
    async fn lost_accepted_proof_and_unledgered_local_result_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let lost_path = directory.path().join("lost-accepted.sqlite");
        let (connection, dek) =
            send_started_fixture_with_connection(Connection::open(&lost_path).unwrap());
        let request =
            prepare_selected_screenshot_provider_request(&connection, ACCOUNT, IMAGE_ID, &dek)
                .unwrap()
                .unwrap();
        let provider = ExactAcceptProvider::new();
        let outcome = execute_selected_screenshot_provider_request(&provider, request).await;
        let SelectedScreenshotProviderOutcome::Accepted(accepted) = outcome else {
            panic!("expected accepted provider proof")
        };
        drop(accepted);
        assert_eq!(provider.calls(), vec!["create", "get"]);
        drop(connection);
        let reopened = Connection::open(&lost_path).unwrap();
        assert!(
            load_selected_screenshot_provider_accepted_result(&reopened, ACCOUNT, IMAGE_ID)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            prepare_selected_screenshot_provider_request(&reopened, ACCOUNT, IMAGE_ID, &dek).err(),
            Some(WalIdempotencyError::Precondition)
        );
        assert_eq!(provider.calls(), vec!["create", "get"]);

        let (tampered_proof, tampered_dek) = send_started_fixture();
        let provider = ExactAcceptProvider::new();
        let request = prepare_selected_screenshot_provider_request(
            &tampered_proof,
            ACCOUNT,
            IMAGE_ID,
            &tampered_dek,
        )
        .unwrap()
        .unwrap();
        let SelectedScreenshotProviderOutcome::Accepted(mut accepted) =
            execute_selected_screenshot_provider_request(&provider, request).await
        else {
            panic!("expected accepted provider proof")
        };
        accepted.provider_generation = accepted.provider_generation.saturating_add(1);
        assert_eq!(
            prepare_selected_screenshot_provider_accepted_result(&tampered_proof, accepted).err(),
            Some(WalIdempotencyError::Corrupt)
        );
        assert_eq!(
            tampered_proof
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );

        let (mut collision, collision_dek) = send_started_fixture();
        let provider = ExactAcceptProvider::new();
        let request = prepare_selected_screenshot_provider_request(
            &collision,
            ACCOUNT,
            IMAGE_ID,
            &collision_dek,
        )
        .unwrap()
        .unwrap();
        let SelectedScreenshotProviderOutcome::Accepted(accepted) =
            execute_selected_screenshot_provider_request(&provider, request).await
        else {
            panic!("expected accepted provider proof")
        };
        let plan =
            prepare_selected_screenshot_provider_accepted_result(&collision, accepted).unwrap();
        collision
            .execute(
                "INSERT INTO screenshot_images
                 (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,
                  width,height,byte_length,sha256)
                 VALUES (?1,41,7,'unrelated:source',?2,?3,'image/jpeg',2,2,20,?4)",
                params![
                    "2".repeat(32),
                    CAPTURED_AT,
                    crate::store::selected_evidence_media_object_key(ACCOUNT, &"2".repeat(32),)
                        .unwrap(),
                    format!("{:x}", Sha256::digest(b"bounded-jpeg-fixture")),
                ],
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut collision,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            )
            .err(),
            Some(WalIdempotencyError::Precondition)
        );
        assert_eq!(
            collision
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='table'
                       AND name='archive_v3_wal_selected_screenshot_operations'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn provider_accepted_a_and_definitive_rejection_c_are_mutually_exclusive() {
        let (mut a_first, a_dek) = send_started_fixture();
        let provider = ExactAcceptProvider::new();
        let request =
            prepare_selected_screenshot_provider_request(&a_first, ACCOUNT, IMAGE_ID, &a_dek)
                .unwrap()
                .unwrap();
        let SelectedScreenshotProviderOutcome::Accepted(accepted) =
            execute_selected_screenshot_provider_request(&provider, request).await
        else {
            panic!("expected accepted provider proof")
        };
        let rejection = rejection_from_binding(duplicate_binding(accepted.binding()));
        let a_plan =
            prepare_selected_screenshot_provider_accepted_result(&a_first, accepted).unwrap();
        execute_prepared_for_owner(
            &mut a_first,
            PreparedLogicalMutation::prepare(a_plan).unwrap(),
        )
        .unwrap();
        let c_plan = prepare_selected_screenshot_termination(
            &a_first,
            rejection,
            "2026-08-15T13:00:01.000Z".to_owned(),
        )
        .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut a_first,
                PreparedLogicalMutation::prepare(c_plan).unwrap(),
            )
            .err(),
            Some(WalIdempotencyError::Precondition)
        );

        let (mut c_first, c_dek) = send_started_fixture();
        let provider = ExactAcceptProvider::new();
        let request =
            prepare_selected_screenshot_provider_request(&c_first, ACCOUNT, IMAGE_ID, &c_dek)
                .unwrap()
                .unwrap();
        let SelectedScreenshotProviderOutcome::Accepted(accepted) =
            execute_selected_screenshot_provider_request(&provider, request).await
        else {
            panic!("expected accepted provider proof")
        };
        let rejection = rejection_from_binding(duplicate_binding(accepted.binding()));
        let c_plan = prepare_selected_screenshot_termination(
            &c_first,
            rejection,
            "2026-08-15T13:00:01.000Z".to_owned(),
        )
        .unwrap();
        execute_prepared_for_owner(
            &mut c_first,
            PreparedLogicalMutation::prepare(c_plan).unwrap(),
        )
        .unwrap();
        assert_eq!(
            prepare_selected_screenshot_provider_accepted_result(&c_first, accepted).err(),
            Some(WalIdempotencyError::Precondition)
        );
        assert_eq!(
            c_first
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn accepted_v3_late_typed_readback_failure_rolls_back_local_result_and_ledger() {
        let (mut connection, dek) = send_started_fixture();
        let provider = ExactAcceptProvider::new();
        let request =
            prepare_selected_screenshot_provider_request(&connection, ACCOUNT, IMAGE_ID, &dek)
                .unwrap()
                .unwrap();
        let SelectedScreenshotProviderOutcome::Accepted(accepted) =
            execute_selected_screenshot_provider_request(&provider, request).await
        else {
            panic!("expected accepted provider proof")
        };
        let plan =
            prepare_selected_screenshot_provider_accepted_result(&connection, accepted).unwrap();
        let transaction = connection.transaction().unwrap();
        ensure_selected_screenshot_result_schema(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER corrupt_accepted_result_readback
                 AFTER INSERT ON archive_v3_wal_selected_screenshot_operations
                 BEGIN
                   UPDATE archive_v3_wal_selected_screenshot_operations
                   SET readback_commitment=X'0101010101010101010101010101010101010101010101010101010101010101'
                   WHERE image_id=NEW.image_id;
                 END;",
            )
            .unwrap();
        assert_eq!(
            execute_prepared_for_owner(
                &mut connection,
                PreparedLogicalMutation::prepare(plan).unwrap(),
            )
            .err(),
            Some(WalIdempotencyError::Corrupt)
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM screenshot_images", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_wal_selected_screenshot_operations",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn proof_commitments_bind_every_send_fact_and_provider_evidence() {
        let first = request();
        let first_accepted = derive_accepted_commitment(&first.binding, 31).unwrap();
        let first_rejected = derive_rejected_commitment(&first.binding, &[8; 32]).unwrap();
        assert_ne!(first_accepted, first_rejected);

        let mut changed = request();
        changed.binding.aad_commitment = [7; 32];
        assert_ne!(
            first_accepted,
            derive_accepted_commitment(&changed.binding, 31).unwrap()
        );
        assert_ne!(
            first_rejected,
            derive_rejected_commitment(&changed.binding, &[8; 32]).unwrap()
        );
        assert_ne!(
            first_accepted,
            derive_accepted_commitment(&first.binding, 32).unwrap()
        );
        assert_ne!(
            first_rejected,
            derive_rejected_commitment(&first.binding, &[9; 32]).unwrap()
        );
    }
}
