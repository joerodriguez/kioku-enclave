#![allow(
    dead_code,
    reason = "active signed-runtime registry KMS adapter retains test-only constructors"
)]

//! Cloud KMS adapter for archive-v3 key-registry envelopes.
//!
//! The live legacy [`crate::crypto::KmsClient`] remains unchanged. This seam
//! accepts only one numeric version below the exact already-configured KMS
//! key, verifies that version is enabled `GOOGLE_SYMMETRIC_ENCRYPTION` at the
//! current software protection level, and binds wrap/unwrap to the same
//! zeroizing canonical [`KeyRegistryContext`]-plus-version AAD. Stored bytes
//! carry the exact key-version coordinate and fixed algorithm/protection
//! discriminators, so a later decrypt cannot silently select a different key
//! coordinate.
//!
//! This module has no environment constructor, Store, route, or caller-selected
//! authority; the signed runtime supplies the fixed KMS version and archive providers.

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::Bytes;
use serde::Deserialize;
use std::{fmt, sync::Arc, time::Duration};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    archive_v3::{
        KeyKind, KeyRegistryContext, KeyRegistryPlaintext, KEY_REGISTRY_PLAINTEXT_BYTES,
        MAX_WRAPPED_KEY_REGISTRY_BYTES,
    },
    archive_v3_gcs::{ArchiveV3RegistryKms, GcsArchiveV3TransportError},
    crypto::GcpKmsClient,
};

const KMS_ORIGIN: &str = "https://cloudkms.googleapis.com";
const EXPECTED_ALGORITHM: &str = "GOOGLE_SYMMETRIC_ENCRYPTION";
const EXPECTED_PROTECTION_LEVEL: &str = "SOFTWARE";
const EXPECTED_VERSION_STATE: &str = "ENABLED";
const WRAPPED_MAGIC: &[u8; 16] = b"KIOKU-KMSREG-v1\0";
const KMS_VERSION_AAD_DOMAIN: &[u8] = b"kioku:archive:v3:kms-key-version\0";
const WRAPPED_FORMAT_VERSION: u8 = 1;
const ALGORITHM_GOOGLE_SYMMETRIC_ENCRYPTION: u8 = 1;
const PROTECTION_SOFTWARE: u8 = 1;
const MAX_KEY_VERSION_NAME_BYTES: usize = 256;
const MAX_KMS_RESPONSE_BYTES: usize = 32 * 1024;
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const WRAPPED_HEADER_BYTES: usize = WRAPPED_MAGIC.len() + 1 + 1 + 1 + 2 + 4;

type TransportResult<T> = std::result::Result<T, GcsArchiveV3TransportError>;

/// Own a request body whose base64 plaintext/ciphertext and canonical AAD are
/// zeroized after reqwest releases the body.
struct ZeroizingJsonBody(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for ZeroizingJsonBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Exact enabled key-version facts returned by Cloud KMS. No field can contain
/// registry plaintext or ciphertext.
struct VersionDescription {
    name: String,
    state: String,
    algorithm: String,
    protection_level: String,
}

/// KMS ciphertext plus the exact key-version response coordinate.
struct EncryptOutput {
    name: String,
    protection_level: String,
    ciphertext: Zeroizing<Vec<u8>>,
}

/// KMS plaintext remains under a zeroizing owner until copied to the caller's
/// fixed buffer.
struct DecryptOutput {
    protection_level: String,
    plaintext: Zeroizing<Vec<u8>>,
}

#[async_trait]
trait ArchiveRegistryKmsWire: Send + Sync {
    async fn describe_version(&self, version_name: &str) -> TransportResult<VersionDescription>;

    async fn encrypt(
        &self,
        version_name: &str,
        plaintext: &[u8],
        canonical_aad: &[u8],
    ) -> TransportResult<EncryptOutput>;

    async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &[u8],
        canonical_aad: &[u8],
    ) -> TransportResult<DecryptOutput>;
}

/// Fixed-origin wire client that reuses only the existing attestation-derived
/// KMS token source and exact key coordinate.
struct GcpArchiveRegistryKmsWire {
    http: reqwest::Client,
    kms: Arc<GcpKmsClient>,
}

impl GcpArchiveRegistryKmsWire {
    fn new(kms: Arc<GcpKmsClient>) -> TransportResult<Self> {
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
        Ok(Self { http, kms })
    }

    async fn execute_json(
        &self,
        request: reqwest::RequestBuilder,
    ) -> TransportResult<Zeroizing<Vec<u8>>> {
        let token = self
            .kms
            .archive_registry_access_token()
            .await
            .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
        let response = request
            .bearer_auth(token.as_str())
            .send()
            .await
            .map_err(|_| GcsArchiveV3TransportError::Unavailable)?;
        if !response.status().is_success() {
            // Never consume or report a provider error body: it may contain
            // reflected request material.
            return Err(GcsArchiveV3TransportError::Unavailable);
        }
        bounded_response(response, MAX_KMS_RESPONSE_BYTES).await
    }
}

#[async_trait]
impl ArchiveRegistryKmsWire for GcpArchiveRegistryKmsWire {
    async fn describe_version(&self, version_name: &str) -> TransportResult<VersionDescription> {
        let body = self
            .execute_json(self.http.get(version_url(version_name)?))
            .await?;
        parse_version_description(&body)
    }

    async fn encrypt(
        &self,
        version_name: &str,
        plaintext: &[u8],
        canonical_aad: &[u8],
    ) -> TransportResult<EncryptOutput> {
        let body = encrypt_request_body(plaintext, canonical_aad)?;
        let request = self
            .http
            .post(encrypt_url(version_name)?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(reqwest::Body::from(Bytes::from_owner(ZeroizingJsonBody(
                body,
            ))));
        let response = self.execute_json(request).await?;
        parse_encrypt_response(&response)
    }

    async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &[u8],
        canonical_aad: &[u8],
    ) -> TransportResult<DecryptOutput> {
        let body = decrypt_request_body(ciphertext, canonical_aad)?;
        let request = self
            .http
            .post(decrypt_url(key_name)?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(reqwest::Body::from(Bytes::from_owner(ZeroizingJsonBody(
                body,
            ))));
        let response = self.execute_json(request).await?;
        parse_decrypt_response(&response)
    }
}

/// Exact signed-runtime archive-registry KMS adapter. Debug never exposes the key
/// coordinate, archive context, ciphertext, or plaintext.
pub(crate) struct GcpArchiveV3RegistryKms {
    key_name: String,
    version_name: String,
    wire: Arc<dyn ArchiveRegistryKmsWire>,
}

impl GcpArchiveV3RegistryKms {
    /// Construct beneath the exact key already selected by `GcpKmsClient`.
    /// `version_id` is numeric and canonical; no full resource coordinate is
    /// accepted from this caller. Construction performs no I/O.
    pub(crate) fn new(kms: Arc<GcpKmsClient>, version_id: &str) -> TransportResult<Self> {
        let key_name = kms.archive_registry_key_name().to_owned();
        let version_name = exact_version_name(&key_name, version_id)?;
        let wire = Arc::new(GcpArchiveRegistryKmsWire::new(kms)?);
        Ok(Self {
            key_name,
            version_name,
            wire,
        })
    }

    #[cfg(test)]
    fn with_test_wire(
        key_name: &str,
        version_id: &str,
        wire: Arc<dyn ArchiveRegistryKmsWire>,
    ) -> TransportResult<Self> {
        Ok(Self {
            key_name: key_name.to_owned(),
            version_name: exact_version_name(key_name, version_id)?,
            wire,
        })
    }

    async fn verify_version(&self) -> TransportResult<()> {
        let description = self.wire.describe_version(&self.version_name).await?;
        if description.name != self.version_name
            || description.state != EXPECTED_VERSION_STATE
            || description.algorithm != EXPECTED_ALGORITHM
            || description.protection_level != EXPECTED_PROTECTION_LEVEL
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        Ok(())
    }
}

impl fmt::Debug for GcpArchiveV3RegistryKms {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GcpArchiveV3RegistryKms(<inactive-redacted>)")
    }
}

#[async_trait]
impl ArchiveV3RegistryKms for GcpArchiveV3RegistryKms {
    async fn wrap_registry(
        &self,
        context: &KeyRegistryContext,
        registry_plaintext: &[u8],
        destination: &mut [u8],
    ) -> TransportResult<usize> {
        destination.zeroize();
        if context.key_kind() != KeyKind::Archive {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        if registry_plaintext.len() != KEY_REGISTRY_PLAINTEXT_BYTES {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        if destination.len() < MAX_WRAPPED_KEY_REGISTRY_BYTES {
            return Err(GcsArchiveV3TransportError::TooLarge);
        }
        // Reject a correctly sized but context-substituted registry before it
        // can become a durable KMS ciphertext. The verified DEK is immediately
        // dropped under its zeroizing owner and never becomes authority here.
        drop(
            KeyRegistryPlaintext::decode_verified(
                Zeroizing::new(registry_plaintext.to_vec()),
                context,
            )
            .map_err(|_| GcsArchiveV3TransportError::Protocol)?,
        );
        self.verify_version().await?;
        let canonical_aad = canonical_registry_kms_aad(context, &self.version_name)?;
        let encrypted = self
            .wire
            .encrypt(&self.version_name, registry_plaintext, &canonical_aad)
            .await?;
        if encrypted.name != self.version_name
            || encrypted.protection_level != EXPECTED_PROTECTION_LEVEL
            || encrypted.ciphertext.is_empty()
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        let encoded = encode_wrapped_registry(&self.version_name, &encrypted.ciphertext)?;
        if encoded.len() > destination.len() {
            return Err(GcsArchiveV3TransportError::TooLarge);
        }
        destination[..encoded.len()].copy_from_slice(&encoded);
        Ok(encoded.len())
    }

    async fn unwrap_registry(
        &self,
        context: &KeyRegistryContext,
        wrapped_registry_ciphertext: &[u8],
        destination: &mut [u8],
    ) -> TransportResult<usize> {
        destination.zeroize();
        if context.key_kind() != KeyKind::Archive {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        if destination.len() < KEY_REGISTRY_PLAINTEXT_BYTES
            || wrapped_registry_ciphertext.is_empty()
            || wrapped_registry_ciphertext.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
        {
            return Err(GcsArchiveV3TransportError::TooLarge);
        }
        let wrapped = parse_wrapped_registry(wrapped_registry_ciphertext)?;
        if wrapped.version_name != self.version_name {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        self.verify_version().await?;
        let canonical_aad = canonical_registry_kms_aad(context, &self.version_name)?;
        let decrypted = self
            .wire
            .decrypt(&self.key_name, wrapped.ciphertext, &canonical_aad)
            .await?;
        if decrypted.protection_level != EXPECTED_PROTECTION_LEVEL
            || decrypted.plaintext.len() != KEY_REGISTRY_PLAINTEXT_BYTES
        {
            return Err(GcsArchiveV3TransportError::Protocol);
        }
        destination[..decrypted.plaintext.len()].copy_from_slice(&decrypted.plaintext);
        Ok(decrypted.plaintext.len())
    }
}

struct WrappedRegistry<'a> {
    version_name: &'a str,
    ciphertext: &'a [u8],
}

fn encode_wrapped_registry(
    version_name: &str,
    ciphertext: &[u8],
) -> TransportResult<Zeroizing<Vec<u8>>> {
    if version_name.is_empty()
        || version_name.len() > MAX_KEY_VERSION_NAME_BYTES
        || ciphertext.is_empty()
        || ciphertext.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
    {
        return Err(GcsArchiveV3TransportError::TooLarge);
    }
    let total = WRAPPED_HEADER_BYTES
        .checked_add(version_name.len())
        .and_then(|value| value.checked_add(ciphertext.len()))
        .ok_or(GcsArchiveV3TransportError::TooLarge)?;
    if total > MAX_WRAPPED_KEY_REGISTRY_BYTES {
        return Err(GcsArchiveV3TransportError::TooLarge);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(total));
    output.extend_from_slice(WRAPPED_MAGIC);
    output.push(WRAPPED_FORMAT_VERSION);
    output.push(ALGORITHM_GOOGLE_SYMMETRIC_ENCRYPTION);
    output.push(PROTECTION_SOFTWARE);
    output.extend_from_slice(&(version_name.len() as u16).to_be_bytes());
    output.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    output.extend_from_slice(version_name.as_bytes());
    output.extend_from_slice(ciphertext);
    Ok(output)
}

fn parse_wrapped_registry(input: &[u8]) -> TransportResult<WrappedRegistry<'_>> {
    if input.len() < WRAPPED_HEADER_BYTES
        || input.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
        || &input[..WRAPPED_MAGIC.len()] != WRAPPED_MAGIC
    {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    let mut offset = WRAPPED_MAGIC.len();
    if input[offset] != WRAPPED_FORMAT_VERSION
        || input[offset + 1] != ALGORITHM_GOOGLE_SYMMETRIC_ENCRYPTION
        || input[offset + 2] != PROTECTION_SOFTWARE
    {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    offset += 3;
    let name_len = u16::from_be_bytes(
        input[offset..offset + 2]
            .try_into()
            .map_err(|_| GcsArchiveV3TransportError::Protocol)?,
    ) as usize;
    offset += 2;
    let ciphertext_len = u32::from_be_bytes(
        input[offset..offset + 4]
            .try_into()
            .map_err(|_| GcsArchiveV3TransportError::Protocol)?,
    ) as usize;
    offset += 4;
    let expected = offset
        .checked_add(name_len)
        .and_then(|value| value.checked_add(ciphertext_len))
        .ok_or(GcsArchiveV3TransportError::Protocol)?;
    if !(1..=MAX_KEY_VERSION_NAME_BYTES).contains(&name_len)
        || ciphertext_len == 0
        || expected != input.len()
    {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    let version_name = std::str::from_utf8(&input[offset..offset + name_len])
        .map_err(|_| GcsArchiveV3TransportError::Protocol)?;
    let ciphertext = &input[offset + name_len..];
    Ok(WrappedRegistry {
        version_name,
        ciphertext,
    })
}

fn exact_version_name(key_name: &str, version_id: &str) -> TransportResult<String> {
    if !valid_key_name(key_name)
        || version_id.is_empty()
        || version_id.len() > 20
        || version_id.starts_with('0')
        || !version_id.bytes().all(|byte| byte.is_ascii_digit())
        || version_id.parse::<u64>().is_err()
    {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    let version_name = format!("{key_name}/cryptoKeyVersions/{version_id}");
    if version_name.len() > MAX_KEY_VERSION_NAME_BYTES {
        return Err(GcsArchiveV3TransportError::TooLarge);
    }
    Ok(version_name)
}

fn valid_key_name(value: &str) -> bool {
    let parts = value.split('/').collect::<Vec<_>>();
    parts.len() == 8
        && parts[0] == "projects"
        && valid_project(parts[1])
        && parts[2] == "locations"
        && valid_resource_id(parts[3], 1, 63, true)
        && parts[4] == "keyRings"
        && valid_resource_id(parts[5], 1, 63, false)
        && parts[6] == "cryptoKeys"
        && valid_resource_id(parts[7], 1, 63, false)
}

fn valid_project(value: &str) -> bool {
    (6..=30).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_resource_id(value: &str, min: usize, max: usize, lowercase_only: bool) -> bool {
    (min..=max).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_digit()
                || byte == b'-'
                || byte == b'_'
                || if lowercase_only {
                    byte.is_ascii_lowercase()
                } else {
                    byte.is_ascii_alphabetic()
                }
        })
}

fn version_url(version_name: &str) -> TransportResult<String> {
    if !valid_version_name(version_name) {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    Ok(format!("{KMS_ORIGIN}/v1/{version_name}"))
}

fn encrypt_url(version_name: &str) -> TransportResult<String> {
    Ok(format!("{}:encrypt", version_url(version_name)?))
}

fn decrypt_url(key_name: &str) -> TransportResult<String> {
    if !valid_key_name(key_name) {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    Ok(format!("{KMS_ORIGIN}/v1/{key_name}:decrypt"))
}

fn valid_version_name(value: &str) -> bool {
    let Some((key_name, version_id)) = value.rsplit_once("/cryptoKeyVersions/") else {
        return false;
    };
    exact_version_name(key_name, version_id).is_ok_and(|expected| expected == value)
}

/// Bind both the canonical typed registry context and the exact version
/// coordinate into one zeroizing AAD value. Cloud KMS symmetric decrypt is
/// addressed at the parent key, so this version suffix prevents a valid
/// ciphertext from another version from being relabeled as the pinned one.
fn canonical_registry_kms_aad(
    context: &KeyRegistryContext,
    version_name: &str,
) -> TransportResult<Zeroizing<Vec<u8>>> {
    if !valid_version_name(version_name) || version_name.len() > u16::MAX as usize {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    let base = context.canonical_kms_aad();
    let mut aad = Zeroizing::new(Vec::with_capacity(
        base.len() + KMS_VERSION_AAD_DOMAIN.len() + 2 + version_name.len(),
    ));
    aad.extend_from_slice(&base);
    aad.extend_from_slice(KMS_VERSION_AAD_DOMAIN);
    aad.extend_from_slice(&(version_name.len() as u16).to_be_bytes());
    aad.extend_from_slice(version_name.as_bytes());
    Ok(aad)
}

fn encrypt_request_body(
    plaintext: &[u8],
    canonical_aad: &[u8],
) -> TransportResult<Zeroizing<Vec<u8>>> {
    if plaintext.len() != KEY_REGISTRY_PLAINTEXT_BYTES || canonical_aad.is_empty() {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    let plaintext_b64 = Zeroizing::new(B64.encode(plaintext));
    let aad_b64 = Zeroizing::new(B64.encode(canonical_aad));
    Ok(Zeroizing::new(
        format!(
            "{{\"plaintext\":\"{}\",\"additionalAuthenticatedData\":\"{}\",\"plaintextCrc32c\":\"{}\",\"additionalAuthenticatedDataCrc32c\":\"{}\"}}",
            plaintext_b64.as_str(),
            aad_b64.as_str(),
            crc32c(plaintext),
            crc32c(canonical_aad),
        )
        .into_bytes(),
    ))
}

fn decrypt_request_body(
    ciphertext: &[u8],
    canonical_aad: &[u8],
) -> TransportResult<Zeroizing<Vec<u8>>> {
    if ciphertext.is_empty()
        || ciphertext.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
        || canonical_aad.is_empty()
    {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    let ciphertext_b64 = Zeroizing::new(B64.encode(ciphertext));
    let aad_b64 = Zeroizing::new(B64.encode(canonical_aad));
    Ok(Zeroizing::new(
        format!(
            "{{\"ciphertext\":\"{}\",\"additionalAuthenticatedData\":\"{}\",\"ciphertextCrc32c\":\"{}\",\"additionalAuthenticatedDataCrc32c\":\"{}\"}}",
            ciphertext_b64.as_str(),
            aad_b64.as_str(),
            crc32c(ciphertext),
            crc32c(canonical_aad),
        )
        .into_bytes(),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionWire {
    name: String,
    state: String,
    algorithm: String,
    protection_level: String,
}

fn parse_version_description(input: &[u8]) -> TransportResult<VersionDescription> {
    let parsed: VersionWire =
        serde_json::from_slice(input).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
    Ok(VersionDescription {
        name: parsed.name,
        state: parsed.state,
        algorithm: parsed.algorithm,
        protection_level: parsed.protection_level,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptWire<'a> {
    ciphertext: &'a str,
    ciphertext_crc32c: String,
    name: String,
    protection_level: String,
    verified_additional_authenticated_data_crc32c: bool,
    verified_plaintext_crc32c: bool,
}

fn parse_encrypt_response(input: &[u8]) -> TransportResult<EncryptOutput> {
    let parsed: EncryptWire<'_> =
        serde_json::from_slice(input).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
    let ciphertext = Zeroizing::new(
        B64.decode(parsed.ciphertext.as_bytes())
            .map_err(|_| GcsArchiveV3TransportError::Protocol)?,
    );
    let expected_crc32c = parse_crc32c(&parsed.ciphertext_crc32c)?;
    if ciphertext.is_empty()
        || ciphertext.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
        || crc32c(&ciphertext) != expected_crc32c
        || !parsed.verified_additional_authenticated_data_crc32c
        || !parsed.verified_plaintext_crc32c
    {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    Ok(EncryptOutput {
        name: parsed.name,
        protection_level: parsed.protection_level,
        ciphertext,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecryptWire<'a> {
    plaintext: &'a str,
    plaintext_crc32c: String,
    protection_level: String,
    #[serde(default)]
    used_primary: bool,
}

fn parse_decrypt_response(input: &[u8]) -> TransportResult<DecryptOutput> {
    let parsed: DecryptWire<'_> =
        serde_json::from_slice(input).map_err(|_| GcsArchiveV3TransportError::Protocol)?;
    let _used_primary = parsed.used_primary;
    let plaintext = Zeroizing::new(
        B64.decode(parsed.plaintext.as_bytes())
            .map_err(|_| GcsArchiveV3TransportError::Protocol)?,
    );
    let expected_crc32c = parse_crc32c(&parsed.plaintext_crc32c)?;
    if plaintext.len() != KEY_REGISTRY_PLAINTEXT_BYTES || crc32c(&plaintext) != expected_crc32c {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    Ok(DecryptOutput {
        protection_level: parsed.protection_level,
        plaintext,
    })
}

fn parse_crc32c(input: &str) -> TransportResult<u32> {
    if input.is_empty()
        || (input.len() > 1 && input.starts_with('0'))
        || !input.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    input
        .parse::<u32>()
        .map_err(|_| GcsArchiveV3TransportError::Protocol)
}

async fn bounded_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> TransportResult<Zeroizing<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(GcsArchiveV3TransportError::TooLarge);
    }
    // Allocate the full fixed bound up front. Growing a `Vec` that already
    // contains plaintext response bytes could otherwise leave the retired
    // allocation outside the zeroizing owner after reallocation.
    let mut output = Zeroizing::new(Vec::with_capacity(max_bytes));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GcsArchiveV3TransportError::Unavailable)?
    {
        let next = output
            .len()
            .checked_add(chunk.len())
            .ok_or(GcsArchiveV3TransportError::TooLarge)?;
        if next > max_bytes {
            return Err(GcsArchiveV3TransportError::TooLarge);
        }
        output.extend_from_slice(&chunk);
    }
    if output.is_empty() {
        return Err(GcsArchiveV3TransportError::Protocol);
    }
    Ok(output)
}

/// Castagnoli CRC32C used by Cloud KMS request/response integrity fields.
fn crc32c(input: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in input {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3::{ArchiveDek, ArchiveId, KeyEpoch, KeyRegistryPlaintext};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use tokio::sync::Notify;

    const KEY_NAME: &str =
        "projects/kioku-project/locations/us-central1/keyRings/kioku/cryptoKeys/kioku-kek";
    const VERSION: &str = "7";

    fn context(byte: u8) -> KeyRegistryContext {
        KeyRegistryContext::with_rotation_generation(
            ArchiveId::from_bytes([byte; 16]),
            KeyKind::Archive,
            KeyEpoch::from_bytes([3; 16]),
            9,
        )
    }

    fn plaintext(context: &KeyRegistryContext) -> Zeroizing<Vec<u8>> {
        KeyRegistryPlaintext::encode_archive(context, &ArchiveDek::from_bytes([8; 32])).unwrap()
    }

    struct FakeWire {
        expected_aad: Mutex<Vec<u8>>,
        expected_plaintext: Mutex<Vec<u8>>,
        ciphertext: Vec<u8>,
        description: Mutex<VersionDescription>,
        encrypt_name: Mutex<String>,
        encrypt_protection: Mutex<String>,
        decrypt_protection: Mutex<String>,
        calls: AtomicUsize,
    }

    impl FakeWire {
        fn new(context: &KeyRegistryContext) -> Self {
            Self {
                expected_aad: Mutex::new(
                    canonical_registry_kms_aad(
                        context,
                        &exact_version_name(KEY_NAME, VERSION).unwrap(),
                    )
                    .unwrap()
                    .to_vec(),
                ),
                expected_plaintext: Mutex::new(plaintext(context).to_vec()),
                ciphertext: b"opaque-kms-ciphertext".to_vec(),
                description: Mutex::new(VersionDescription {
                    name: exact_version_name(KEY_NAME, VERSION).unwrap(),
                    state: EXPECTED_VERSION_STATE.to_owned(),
                    algorithm: EXPECTED_ALGORITHM.to_owned(),
                    protection_level: EXPECTED_PROTECTION_LEVEL.to_owned(),
                }),
                encrypt_name: Mutex::new(exact_version_name(KEY_NAME, VERSION).unwrap()),
                encrypt_protection: Mutex::new(EXPECTED_PROTECTION_LEVEL.to_owned()),
                decrypt_protection: Mutex::new(EXPECTED_PROTECTION_LEVEL.to_owned()),
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ArchiveRegistryKmsWire for FakeWire {
        async fn describe_version(
            &self,
            _version_name: &str,
        ) -> TransportResult<VersionDescription> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let description = self.description.lock().unwrap();
            Ok(VersionDescription {
                name: description.name.clone(),
                state: description.state.clone(),
                algorithm: description.algorithm.clone(),
                protection_level: description.protection_level.clone(),
            })
        }

        async fn encrypt(
            &self,
            _version_name: &str,
            plaintext: &[u8],
            canonical_aad: &[u8],
        ) -> TransportResult<EncryptOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if plaintext != self.expected_plaintext.lock().unwrap().as_slice()
                || canonical_aad != self.expected_aad.lock().unwrap().as_slice()
            {
                return Err(GcsArchiveV3TransportError::Protocol);
            }
            Ok(EncryptOutput {
                name: self.encrypt_name.lock().unwrap().clone(),
                protection_level: self.encrypt_protection.lock().unwrap().clone(),
                ciphertext: Zeroizing::new(self.ciphertext.clone()),
            })
        }

        async fn decrypt(
            &self,
            key_name: &str,
            ciphertext: &[u8],
            canonical_aad: &[u8],
        ) -> TransportResult<DecryptOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if key_name != KEY_NAME
                || ciphertext != self.ciphertext
                || canonical_aad != self.expected_aad.lock().unwrap().as_slice()
            {
                return Err(GcsArchiveV3TransportError::Protocol);
            }
            Ok(DecryptOutput {
                protection_level: self.decrypt_protection.lock().unwrap().clone(),
                plaintext: Zeroizing::new(self.expected_plaintext.lock().unwrap().clone()),
            })
        }
    }

    #[tokio::test]
    async fn exact_context_wrap_and_unwrap_round_trip() {
        let context = context(1);
        let wire = Arc::new(FakeWire::new(&context));
        let adapter =
            GcpArchiveV3RegistryKms::with_test_wire(KEY_NAME, VERSION, wire.clone()).unwrap();
        let plaintext = plaintext(&context);
        let mut wrapped = [0u8; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        let wrapped_len = adapter
            .wrap_registry(&context, &plaintext, &mut wrapped)
            .await
            .unwrap();
        assert_ne!(&wrapped[..wrapped_len], plaintext.as_slice());
        let mut opened = [0u8; KEY_REGISTRY_PLAINTEXT_BYTES];
        let opened_len = adapter
            .unwrap_registry(&context, &wrapped[..wrapped_len], &mut opened)
            .await
            .unwrap();
        assert_eq!(&opened[..opened_len], plaintext.as_slice());
        assert_eq!(wire.calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            format!("{adapter:?}"),
            "GcpArchiveV3RegistryKms(<inactive-redacted>)"
        );
    }

    #[tokio::test]
    async fn context_substitution_fails_without_partial_plaintext() {
        let expected = context(1);
        let wire = Arc::new(FakeWire::new(&expected));
        let adapter =
            GcpArchiveV3RegistryKms::with_test_wire(KEY_NAME, VERSION, wire.clone()).unwrap();
        let plaintext = plaintext(&expected);
        let mut wrapped = [0u8; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        let wrapped_len = adapter
            .wrap_registry(&expected, &plaintext, &mut wrapped)
            .await
            .unwrap();
        let calls_before = wire.calls.load(Ordering::SeqCst);
        let mut substituted_wrap = [0x6c; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        assert_eq!(
            adapter
                .wrap_registry(&context(2), &plaintext, &mut substituted_wrap)
                .await,
            Err(GcsArchiveV3TransportError::Protocol)
        );
        assert!(substituted_wrap.iter().all(|byte| *byte == 0));
        assert_eq!(wire.calls.load(Ordering::SeqCst), calls_before);
        let mut output = [0xa5; KEY_REGISTRY_PLAINTEXT_BYTES];
        assert_eq!(
            adapter
                .unwrap_registry(&context(2), &wrapped[..wrapped_len], &mut output)
                .await,
            Err(GcsArchiveV3TransportError::Protocol)
        );
        assert!(output.iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn decrypt_protection_substitution_fails_without_partial_plaintext() {
        let context = context(1);
        let wire = Arc::new(FakeWire::new(&context));
        let adapter =
            GcpArchiveV3RegistryKms::with_test_wire(KEY_NAME, VERSION, wire.clone()).unwrap();
        let mut wrapped = [0u8; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        let wrapped_len = adapter
            .wrap_registry(&context, &plaintext(&context), &mut wrapped)
            .await
            .unwrap();
        *wire.decrypt_protection.lock().unwrap() = "HSM".into();
        let mut output = [0x91; KEY_REGISTRY_PLAINTEXT_BYTES];
        assert_eq!(
            adapter
                .unwrap_registry(&context, &wrapped[..wrapped_len], &mut output)
                .await,
            Err(GcsArchiveV3TransportError::Protocol)
        );
        assert!(output.iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn algorithm_state_protection_and_coordinate_substitution_reject() {
        let context = context(1);
        for mutation in [
            "algorithm",
            "state",
            "description_name",
            "encrypt_name",
            "encrypt_protection",
        ] {
            let wire = Arc::new(FakeWire::new(&context));
            match mutation {
                "algorithm" => {
                    wire.description.lock().unwrap().algorithm = "RSA_SIGN_PSS_2048_SHA256".into()
                }
                "state" => wire.description.lock().unwrap().state = "DESTROY_SCHEDULED".into(),
                "description_name" => {
                    wire.description.lock().unwrap().name =
                        exact_version_name(KEY_NAME, "8").unwrap()
                }
                "encrypt_name" => {
                    *wire.encrypt_name.lock().unwrap() = exact_version_name(KEY_NAME, "8").unwrap()
                }
                "encrypt_protection" => *wire.encrypt_protection.lock().unwrap() = "HSM".into(),
                _ => unreachable!(),
            }
            let adapter = GcpArchiveV3RegistryKms::with_test_wire(KEY_NAME, VERSION, wire).unwrap();
            let mut output = [0x5a; MAX_WRAPPED_KEY_REGISTRY_BYTES];
            assert_eq!(
                adapter
                    .wrap_registry(&context, &plaintext(&context), &mut output)
                    .await,
                Err(GcsArchiveV3TransportError::Protocol),
                "mutation {mutation}"
            );
            assert!(output.iter().all(|byte| *byte == 0));
        }
    }

    #[tokio::test]
    async fn wrapped_coordinate_and_discriminators_reject_before_decrypt() {
        let context = context(1);
        let wire = Arc::new(FakeWire::new(&context));
        let adapter =
            GcpArchiveV3RegistryKms::with_test_wire(KEY_NAME, VERSION, wire.clone()).unwrap();
        let mut wrapped = [0u8; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        let wrapped_len = adapter
            .wrap_registry(&context, &plaintext(&context), &mut wrapped)
            .await
            .unwrap();
        let calls_before = wire.calls.load(Ordering::SeqCst);
        for offset in [
            WRAPPED_MAGIC.len(),
            WRAPPED_MAGIC.len() + 1,
            WRAPPED_MAGIC.len() + 2,
        ] {
            let mut changed = wrapped[..wrapped_len].to_vec();
            changed[offset] ^= 0x7f;
            let mut output = [0x33; KEY_REGISTRY_PLAINTEXT_BYTES];
            assert_eq!(
                adapter
                    .unwrap_registry(&context, &changed, &mut output)
                    .await,
                Err(GcsArchiveV3TransportError::Protocol)
            );
            assert!(output.iter().all(|byte| *byte == 0));
        }
        let other = encode_wrapped_registry(
            &exact_version_name(KEY_NAME, "8").unwrap(),
            b"opaque-kms-ciphertext",
        )
        .unwrap();
        let mut output = [0x33; KEY_REGISTRY_PLAINTEXT_BYTES];
        assert_eq!(
            adapter.unwrap_registry(&context, &other, &mut output).await,
            Err(GcsArchiveV3TransportError::Protocol)
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert_eq!(wire.calls.load(Ordering::SeqCst), calls_before);
    }

    #[tokio::test]
    async fn size_and_resource_inputs_fail_closed_without_wire_io() {
        let context = context(1);
        let wire = Arc::new(FakeWire::new(&context));
        let adapter =
            GcpArchiveV3RegistryKms::with_test_wire(KEY_NAME, VERSION, wire.clone()).unwrap();
        let mut short = [0xdd; 8];
        assert_eq!(
            adapter
                .wrap_registry(&context, &plaintext(&context), &mut short)
                .await,
            Err(GcsArchiveV3TransportError::TooLarge)
        );
        assert!(short.iter().all(|byte| *byte == 0));
        let mut destination = [0xee; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        assert_eq!(
            adapter
                .wrap_registry(&context, b"short", &mut destination)
                .await,
            Err(GcsArchiveV3TransportError::Protocol)
        );
        assert!(destination.iter().all(|byte| *byte == 0));
        assert_eq!(wire.calls.load(Ordering::SeqCst), 0);
        for (key, version) in [
            ("projects/other/locations/us/keyRings/r/cryptoKeys/k", "1"),
            (KEY_NAME, "0"),
            (KEY_NAME, "01"),
            (KEY_NAME, "1/../../other"),
        ] {
            assert!(GcpArchiveV3RegistryKms::with_test_wire(key, version, wire.clone()).is_err());
        }
    }

    struct BlockingWire {
        entered: Notify,
        calls: AtomicUsize,
        context: KeyRegistryContext,
    }

    #[async_trait]
    impl ArchiveRegistryKmsWire for BlockingWire {
        async fn describe_version(
            &self,
            _version_name: &str,
        ) -> TransportResult<VersionDescription> {
            Ok(VersionDescription {
                name: exact_version_name(KEY_NAME, VERSION).unwrap(),
                state: EXPECTED_VERSION_STATE.into(),
                algorithm: EXPECTED_ALGORITHM.into(),
                protection_level: EXPECTED_PROTECTION_LEVEL.into(),
            })
        }

        async fn encrypt(
            &self,
            _version_name: &str,
            _plaintext: &[u8],
            canonical_aad: &[u8],
        ) -> TransportResult<EncryptOutput> {
            assert_eq!(
                canonical_aad,
                canonical_registry_kms_aad(
                    &self.context,
                    &exact_version_name(KEY_NAME, VERSION).unwrap(),
                )
                .unwrap()
                .as_slice()
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            std::future::pending().await
        }

        async fn decrypt(
            &self,
            _key_name: &str,
            _ciphertext: &[u8],
            _canonical_aad: &[u8],
        ) -> TransportResult<DecryptOutput> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn cancellation_drops_the_single_request_without_retry_or_detached_work() {
        let context = context(1);
        let wire = Arc::new(BlockingWire {
            entered: Notify::new(),
            calls: AtomicUsize::new(0),
            context,
        });
        let adapter =
            GcpArchiveV3RegistryKms::with_test_wire(KEY_NAME, VERSION, wire.clone()).unwrap();
        let registry_plaintext = plaintext(&context);
        let mut destination = [0xc7; MAX_WRAPPED_KEY_REGISTRY_BYTES];
        {
            let operation = adapter.wrap_registry(&context, &registry_plaintext, &mut destination);
            tokio::pin!(operation);
            tokio::select! {
                () = wire.entered.notified() => {}
                result = &mut operation => panic!("blocking encrypt unexpectedly completed: {result:?}"),
            }
        }
        tokio::task::yield_now().await;
        assert_eq!(wire.calls.load(Ordering::SeqCst), 1);
        assert!(destination.iter().all(|byte| *byte == 0));
    }

    struct BlockingDecryptWire {
        entered: Notify,
        calls: AtomicUsize,
        context: KeyRegistryContext,
    }

    #[async_trait]
    impl ArchiveRegistryKmsWire for BlockingDecryptWire {
        async fn describe_version(
            &self,
            _version_name: &str,
        ) -> TransportResult<VersionDescription> {
            Ok(VersionDescription {
                name: exact_version_name(KEY_NAME, VERSION).unwrap(),
                state: EXPECTED_VERSION_STATE.into(),
                algorithm: EXPECTED_ALGORITHM.into(),
                protection_level: EXPECTED_PROTECTION_LEVEL.into(),
            })
        }

        async fn encrypt(
            &self,
            _version_name: &str,
            _plaintext: &[u8],
            _canonical_aad: &[u8],
        ) -> TransportResult<EncryptOutput> {
            unreachable!()
        }

        async fn decrypt(
            &self,
            key_name: &str,
            ciphertext: &[u8],
            canonical_aad: &[u8],
        ) -> TransportResult<DecryptOutput> {
            assert_eq!(key_name, KEY_NAME);
            assert_eq!(ciphertext, b"pending-ciphertext");
            assert_eq!(
                canonical_aad,
                canonical_registry_kms_aad(
                    &self.context,
                    &exact_version_name(KEY_NAME, VERSION).unwrap(),
                )
                .unwrap()
                .as_slice()
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancelled_unwrap_never_publishes_partial_plaintext_or_retries() {
        let context = context(1);
        let wire = Arc::new(BlockingDecryptWire {
            entered: Notify::new(),
            calls: AtomicUsize::new(0),
            context,
        });
        let adapter =
            GcpArchiveV3RegistryKms::with_test_wire(KEY_NAME, VERSION, wire.clone()).unwrap();
        let wrapped = encode_wrapped_registry(
            &exact_version_name(KEY_NAME, VERSION).unwrap(),
            b"pending-ciphertext",
        )
        .unwrap();
        let mut output = [0xb4; KEY_REGISTRY_PLAINTEXT_BYTES];
        {
            let operation = adapter.unwrap_registry(&context, &wrapped, &mut output);
            tokio::pin!(operation);
            tokio::select! {
                () = wire.entered.notified() => {}
                result = &mut operation => panic!("blocking decrypt unexpectedly completed: {result:?}"),
            }
        }
        tokio::task::yield_now().await;
        assert_eq!(wire.calls.load(Ordering::SeqCst), 1);
        assert!(output.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn fixed_urls_crc_and_response_integrity_are_strict() {
        let version = exact_version_name(KEY_NAME, VERSION).unwrap();
        assert_eq!(
            encrypt_url(&version).unwrap(),
            format!("https://cloudkms.googleapis.com/v1/{version}:encrypt")
        );
        assert_eq!(
            decrypt_url(KEY_NAME).unwrap(),
            format!("https://cloudkms.googleapis.com/v1/{KEY_NAME}:decrypt")
        );
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        let context = context(1);
        let base_aad = context.canonical_kms_aad();
        let version_aad = canonical_registry_kms_aad(&context, &version).unwrap();
        let other_version_aad =
            canonical_registry_kms_aad(&context, &exact_version_name(KEY_NAME, "8").unwrap())
                .unwrap();
        assert!(version_aad.starts_with(&base_aad));
        assert_ne!(version_aad.as_slice(), other_version_aad.as_slice());

        let ciphertext = b"ciphertext";
        let good = format!(
            "{{\"ciphertext\":\"{}\",\"ciphertextCrc32c\":\"{}\",\"name\":\"{}\",\"protectionLevel\":\"SOFTWARE\",\"verifiedAdditionalAuthenticatedDataCrc32c\":true,\"verifiedPlaintextCrc32c\":true}}",
            B64.encode(ciphertext),
            crc32c(ciphertext),
            version,
        );
        assert_eq!(
            parse_encrypt_response(good.as_bytes())
                .unwrap()
                .ciphertext
                .as_slice(),
            ciphertext
        );
        for bad in [
            good.replace(&crc32c(ciphertext).to_string(), "0"),
            good.replace(
                "verifiedPlaintextCrc32c\":true",
                "verifiedPlaintextCrc32c\":false",
            ),
            good.replace("\"verifiedAdditionalAuthenticatedDataCrc32c\":true,", ""),
            good.replace(
                "\"verifiedAdditionalAuthenticatedDataCrc32c\":true",
                "\"verifiedAdditionalAuthenticatedDataCrc32c\":false",
            ),
            good.replace(",\"verifiedPlaintextCrc32c\":true", ""),
            good.replace(
                &format!("\"ciphertextCrc32c\":\"{}\",", crc32c(ciphertext)),
                "",
            ),
            good.replace(
                &format!("\"{}\"", crc32c(ciphertext)),
                &crc32c(ciphertext).to_string(),
            ),
            good.replace("}", ",\"unexpected\":true}"),
        ] {
            assert!(parse_encrypt_response(bad.as_bytes()).is_err());
        }

        let registry_plaintext = plaintext(&context);
        let decrypted = format!(
            "{{\"plaintext\":\"{}\",\"plaintextCrc32c\":\"{}\",\"protectionLevel\":\"SOFTWARE\"}}",
            B64.encode(registry_plaintext.as_slice()),
            crc32c(&registry_plaintext),
        );
        assert_eq!(
            parse_decrypt_response(decrypted.as_bytes())
                .unwrap()
                .plaintext
                .as_slice(),
            registry_plaintext.as_slice()
        );
        for bad in [
            decrypted.replace(&format!("\"{}\"", crc32c(&registry_plaintext)), "\"0\""),
            decrypted.replace(
                &format!("\"plaintextCrc32c\":\"{}\",", crc32c(&registry_plaintext)),
                "",
            ),
            decrypted.replace("}", ",\"unexpected\":true}"),
        ] {
            assert!(parse_decrypt_response(bad.as_bytes()).is_err());
        }
    }
}
