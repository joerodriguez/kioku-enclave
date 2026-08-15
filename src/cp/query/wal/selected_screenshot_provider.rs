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

use rusqlite::{Connection, OptionalExtension};
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
    let Some(authenticated) = load_authenticated_selected_screenshot_send_started(
        connection,
        account_id,
        image_id,
        plaintext_dek,
    )?
    else {
        return Ok(None);
    };
    let binding = SelectedScreenshotProviderBinding::from_authenticated_send(&authenticated)?;
    let wrapped_dek_b64 = connection
        .query_row(
            "SELECT value FROM app_metadata WHERE key=?1",
            [MEDIA_DEK_METADATA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    validate_wrapped_dek(&wrapped_dek_b64, &binding.wrapped_dek_commitment)?;
    Ok(Some(SelectedScreenshotProviderRequest {
        binding,
        ciphertext: Zeroizing::new(authenticated.ciphertext().to_vec()),
        wrapped_dek_b64: Zeroizing::new(wrapped_dek_b64),
    }))
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
        archive_v3_wal_idempotency::{execute_prepared_for_owner, PreparedLogicalMutation},
        cp::{
            media::wal::MediaDekInstallPlan,
            query::wal::{
                selected_screenshot_attempt::{
                    authenticate_selected_screenshot_upload_predecessor,
                    SelectedScreenshotAttemptPlan,
                },
                selected_screenshot_send::prepare_selected_screenshot_send_started,
                selected_screenshot_upload::SelectedScreenshotUploadCandidatePlan,
                ValidatedJpeg,
            },
        },
    };
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
    use std::sync::Mutex;

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

    fn initialized_connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
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
        connection
    }

    fn candidate_ready_fixture() -> (Connection, Dek) {
        let mut connection = initialized_connection();
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
