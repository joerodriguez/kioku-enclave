//! AES-256-GCM envelope encryption for per-user SQLite index blobs.
//!
//! # Blob wire formats
//!
//! ```text
//! v2:     [ "KIOKU-BLOB\\x02" ][ nonce: 12 bytes ][ ciphertext + auth-tag ]
//! legacy: [ nonce: 12 bytes ][ ciphertext + auth-tag ]
//! ```
//!
//! V2 authenticates a domain-separated logical-object context as AAD, which
//! prevents a valid ciphertext from being substituted at another object key.
//! The legacy format is accepted only during an explicitly enabled migration.
//!
//! # DEK format
//!
//! A DEK is 32 raw bytes (256 bits) of CSPRNG output, used directly as the
//! AES-256 key. DEKs are stored only in Cloud KMS-encrypted form (the KEK
//! wraps them via the REST encrypt endpoint) — plaintext DEKs live only in
//! enclave memory for the duration of a request.
//!
//! # KMS authentication (production)
//!
//! In Confidential Space, KMS credentials are derived from an attestation
//! token and exchanged through Workload Identity Federation. KMS IAM is bound
//! to the Workload Identity Pool with
//! an attribute condition that requires:
//!   - `google.subject` == the Confidential Space workload identity
//!   - `attribute.image_digest` == the published, provenance-verified digest
//!
//! No human principal has decrypt permission on the KEK.

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use serde::Deserialize;
use std::time::Duration;

use crate::attestation::AttestationCredentials;
use crate::error::{EnclaveError, Result};

/// Version marker for blobs whose AEAD tag binds them to a logical object.
/// Legacy blobs had no marker and, for databases, no AAD at all.
const BOUND_BLOB_V2_MAGIC: &[u8] = b"KIOKU-BLOB\x02";
const BOUND_BLOB_V2_DOMAIN: &[u8] = b"kioku-enclave:bound-blob:v2\0";

/// Result of opening a context-bound blob.
pub struct OpenedBoundBlob {
    pub plaintext: Vec<u8>,
}

// ── DEK type ──────────────────────────────────────────────────────────────────

/// 256-bit data-encryption key.  Plain bytes; lives only in enclave memory.
pub struct Dek(pub [u8; 32]);

impl Dek {
    /// Generate a fresh random DEK.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Dek(bytes)
    }

    fn as_aes_key(&self) -> &Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from_slice(&self.0)
    }
}

// ── Blob crypto ───────────────────────────────────────────────────────────────

/// Encrypt `plaintext` with `dek`.  Returns `nonce ‖ ciphertext ‖ tag`.
#[cfg(test)]
pub fn encrypt_blob(dek: &Dek, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(dek.as_aes_key());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12 random bytes
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| EnclaveError::Crypto(e.to_string()))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt the unbound legacy `nonce ‖ ciphertext ‖ tag` format.
pub fn decrypt_blob(dek: &Dek, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 12 {
        return Err(EnclaveError::Crypto("blob too short".into()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(dek.as_aes_key());
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| EnclaveError::Crypto(format!("decrypt failed: {e}")))
}

/// Encrypt `plaintext` with `dek`, binding `aad` as Additional Authenticated Data.
/// Returns `nonce ‖ ciphertext ‖ tag`.
pub fn encrypt_blob_with_aad(dek: &Dek, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Payload;
    let cipher = Aes256Gcm::new(dek.as_aes_key());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12 random bytes
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| EnclaveError::Crypto(e.to_string()))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt_blob_with_aad`], validating the `aad`.
pub fn decrypt_blob_with_aad(dek: &Dek, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Payload;
    if blob.len() < 12 {
        return Err(EnclaveError::Crypto("blob too short".into()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(dek.as_aes_key());
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|e| EnclaveError::Crypto(format!("decrypt failed: {e}")))
}

fn bound_blob_aad(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BOUND_BLOB_V2_DOMAIN.len() + context.len());
    aad.extend_from_slice(BOUND_BLOB_V2_DOMAIN);
    aad.extend_from_slice(context);
    aad
}

/// Encrypt a versioned blob and cryptographically bind it to `context` (for
/// example, the exact GCS object name plus user id). Moving the ciphertext and
/// wrapped DEK to a different object therefore fails authentication.
pub fn encrypt_bound_blob(dek: &Dek, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let aad = bound_blob_aad(context);
    let encrypted = encrypt_blob_with_aad(dek, plaintext, &aad)?;
    let mut out = Vec::with_capacity(BOUND_BLOB_V2_MAGIC.len() + encrypted.len());
    out.extend_from_slice(BOUND_BLOB_V2_MAGIC);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

/// Open a context-bound blob. Enforces v2 context-bound encryption.
pub fn decrypt_bound_blob(dek: &Dek, blob: &[u8], context: &[u8]) -> Result<OpenedBoundBlob> {
    if let Some(encrypted) = blob.strip_prefix(BOUND_BLOB_V2_MAGIC) {
        let aad = bound_blob_aad(context);
        return Ok(OpenedBoundBlob {
            plaintext: decrypt_blob_with_aad(dek, encrypted, &aad)?,
        });
    }

    Err(EnclaveError::Crypto(
        "invalid context-bound blob header".into(),
    ))
}

// ── KMS trait (seam for testing) ──────────────────────────────────────────────

/// Abstraction over Cloud KMS so unit tests can inject a fake.
#[async_trait::async_trait]
pub trait KmsClient: Send + Sync {
    /// Wrap (encrypt) a raw DEK with the KEK.  Returns base64-encoded ciphertext.
    async fn wrap_dek(&self, plaintext_dek: &[u8]) -> Result<String>;
    /// Unwrap (decrypt) a base64-encoded wrapped DEK.  Returns raw bytes.
    async fn unwrap_dek(&self, wrapped_b64: &str) -> Result<Vec<u8>>;
}

// ── Production KMS client ─────────────────────────────────────────────────────

/// Cloud KMS REST client. KMS encrypt/decrypt calls always use an
/// attestation-derived federated access token via the WIF principalSet binding.
/// Startup fails unless `ENCLAVE_KMS_VIA_ATTESTATION=1`; there is intentionally
/// no VM service-account metadata fallback because that would bypass the image
/// digest attestation boundary.
///
/// GCS operations (ciphertext blob storage) are never affected — they always
/// use the metadata SA token because the GCS bucket is not the security
/// boundary (the DEKs are).
pub struct GcpKmsClient {
    http: reqwest::Client,
    key_name: String, // projects/P/locations/L/keyRings/R/cryptoKeys/K
    attestation_creds: AttestationCredentials,
}

#[derive(Deserialize)]
struct KmsEncryptResponse {
    ciphertext: String,
}

#[derive(Deserialize)]
struct KmsDecryptResponse {
    plaintext: String,
}

impl GcpKmsClient {
    /// Construct from environment variables:
    /// - `KMS_PROJECT`, `KMS_LOCATION`, `KMS_KEY_RING`, `KMS_KEY`
    /// - `ENCLAVE_KMS_VIA_ATTESTATION`: must be exactly `"1"`.
    pub fn from_env() -> Result<Self> {
        let project = std::env::var("KMS_PROJECT")
            .map_err(|_| EnclaveError::Kms("KMS_PROJECT not set".into()))?;
        let location = std::env::var("KMS_LOCATION")
            .map_err(|_| EnclaveError::Kms("KMS_LOCATION not set".into()))?;
        let key_ring = std::env::var("KMS_KEY_RING")
            .map_err(|_| EnclaveError::Kms("KMS_KEY_RING not set".into()))?;
        let key =
            std::env::var("KMS_KEY").map_err(|_| EnclaveError::Kms("KMS_KEY not set".into()))?;
        let key_name =
            format!("projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{key}");

        if std::env::var("ENCLAVE_KMS_VIA_ATTESTATION").as_deref() != Ok("1") {
            return Err(EnclaveError::Kms(
                "ENCLAVE_KMS_VIA_ATTESTATION must be set to 1; metadata credentials are not permitted"
                    .into(),
            ));
        }
        let attestation_creds = AttestationCredentials::from_env()?;

        Ok(Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(30))
                .build()?,
            key_name,
            attestation_creds,
        })
    }

    /// Return an attestation-derived KMS access token for this request. The
    /// deployment must keep the attestation-gated principalSet as the only KMS
    /// decrypt grant and must not grant decrypt to the VM service account.
    async fn kms_token(&self) -> Result<String> {
        self.attestation_creds.kms_access_token().await
    }
}

#[async_trait::async_trait]
impl KmsClient for GcpKmsClient {
    async fn wrap_dek(&self, plaintext_dek: &[u8]) -> Result<String> {
        let token = self.kms_token().await?;
        let plaintext_b64 = B64.encode(plaintext_dek);
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:encrypt",
            self.key_name
        );
        let body = serde_json::json!({ "plaintext": plaintext_b64 });
        let resp: KmsEncryptResponse = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(resp.ciphertext)
    }

    async fn unwrap_dek(&self, wrapped_b64: &str) -> Result<Vec<u8>> {
        let token = self.kms_token().await?;
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:decrypt",
            self.key_name
        );
        let body = serde_json::json!({ "ciphertext": wrapped_b64 });
        let resp: KmsDecryptResponse = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let raw = B64
            .decode(&resp.plaintext)
            .map_err(|e| EnclaveError::Kms(format!("base64 decode: {e}")))?;
        Ok(raw)
    }
}

// ── Convenience wrappers ──────────────────────────────────────────────────────

/// Generate a fresh DEK and immediately wrap it with KMS.
/// Returns `(dek, wrapped_dek_b64)`.
pub async fn generate_and_wrap_dek(kms: &dyn KmsClient) -> Result<(Dek, String)> {
    let dek = Dek::generate();
    let wrapped = kms.wrap_dek(&dek.0).await?;
    Ok((dek, wrapped))
}

/// Unwrap a stored wrapped DEK into a plaintext [`Dek`].
pub async fn load_dek(kms: &dyn KmsClient, wrapped_b64: &str) -> Result<Dek> {
    let raw = kms.unwrap_dek(wrapped_b64).await?;
    if raw.len() != 32 {
        return Err(EnclaveError::Crypto(format!(
            "DEK must be 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw);
    Ok(Dek(bytes))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ── Fake KMS ──────────────────────────────────────────────────────────────

    /// In-memory fake: XOR-"encrypts" with a fixed key byte so the roundtrip
    /// tests without any network calls.
    struct FakeKms {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl FakeKms {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl KmsClient for FakeKms {
        async fn wrap_dek(&self, plaintext_dek: &[u8]) -> Result<String> {
            // Trivial fake: XOR with 0xAB then base64
            let masked: Vec<u8> = plaintext_dek.iter().map(|b| b ^ 0xAB).collect();
            let encoded = B64.encode(&masked);
            self.store
                .lock()
                .unwrap()
                .insert(encoded.clone(), plaintext_dek.to_vec());
            Ok(encoded)
        }

        async fn unwrap_dek(&self, wrapped_b64: &str) -> Result<Vec<u8>> {
            let masked = B64
                .decode(wrapped_b64)
                .map_err(|e| EnclaveError::Kms(e.to_string()))?;
            Ok(masked.iter().map(|b| b ^ 0xAB).collect())
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn blob_roundtrip() {
        let dek = Dek::generate();
        let plaintext = b"hello enclave world -- sensitive content";
        let blob = encrypt_blob(&dek, plaintext).expect("encrypt");
        let recovered = decrypt_blob(&dek, &blob).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn blob_wrong_key_fails() {
        let dek1 = Dek::generate();
        let dek2 = Dek::generate();
        let blob = encrypt_blob(&dek1, b"secret").expect("encrypt");
        assert!(
            decrypt_blob(&dek2, &blob).is_err(),
            "decrypting with wrong key must fail"
        );
    }

    #[test]
    fn nonce_uniqueness() {
        // Two encrypts of identical plaintext must produce different ciphertexts.
        let dek = Dek::generate();
        let pt = b"same plaintext";
        let b1 = encrypt_blob(&dek, pt).expect("encrypt 1");
        let b2 = encrypt_blob(&dek, pt).expect("encrypt 2");
        assert_ne!(
            &b1[..12],
            &b2[..12],
            "nonces should differ (birthday probability ~1/2^96)"
        );
        assert_ne!(b1, b2, "ciphertexts must differ");
    }

    #[test]
    fn blob_with_aad_roundtrip() {
        let dek = Dek::generate();
        let plaintext = b"hello enclave world -- AAD test content";
        let aad = b"user-12345";
        let blob = encrypt_blob_with_aad(&dek, plaintext, aad).expect("encrypt");
        let recovered = decrypt_blob_with_aad(&dek, &blob, aad).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn blob_with_aad_wrong_aad_fails() {
        let dek = Dek::generate();
        let plaintext = b"hello enclave world -- AAD test content";
        let aad1 = b"user-12345";
        let aad2 = b"user-67890";
        let blob = encrypt_blob_with_aad(&dek, plaintext, aad1).expect("encrypt");
        assert!(
            decrypt_blob_with_aad(&dek, &blob, aad2).is_err(),
            "decrypting with wrong AAD must fail"
        );
    }

    #[test]
    fn bound_blob_rejects_object_substitution() {
        let dek = Dek::generate();
        let alice_context = b"user-db\0indexes/alice.db.enc";
        let blob =
            encrypt_bound_blob(&dek, b"alice data", alice_context).expect("encrypt bound blob");

        let opened =
            decrypt_bound_blob(&dek, &blob, alice_context).expect("open with correct context");
        assert_eq!(opened.plaintext, b"alice data");

        assert!(decrypt_bound_blob(&dek, &blob, b"user-db\0indexes/bob.db.enc").is_err());
    }

    #[test]
    fn truncated_blob_rejected() {
        let dek = Dek::generate();
        assert!(decrypt_blob(&dek, &[0u8; 5]).is_err());
    }

    #[tokio::test]
    async fn kms_wrap_unwrap_roundtrip() {
        let kms = FakeKms::new();
        let original = Dek::generate();
        let wrapped = kms.wrap_dek(&original.0).await.expect("wrap");
        let recovered = kms.unwrap_dek(&wrapped).await.expect("unwrap");
        assert_eq!(&original.0[..], &recovered[..]);
    }

    #[tokio::test]
    async fn generate_and_wrap_roundtrip() {
        let kms = FakeKms::new();
        let (dek, wrapped) = generate_and_wrap_dek(&kms).await.expect("generate+wrap");
        let loaded = load_dek(&kms, &wrapped).await.expect("load");
        assert_eq!(&dek.0[..], &loaded.0[..]);
    }

    #[tokio::test]
    async fn full_encrypt_decrypt_with_kms_dek() {
        let kms = FakeKms::new();
        let (dek, wrapped) = generate_and_wrap_dek(&kms).await.unwrap();
        let plaintext = b"user transcript: the meeting was about Q3 budgets";
        let blob = encrypt_blob(&dek, plaintext).unwrap();

        // Simulate: forget the DEK, reload it via KMS, decrypt
        let loaded_dek = load_dek(&kms, &wrapped).await.unwrap();
        let recovered = decrypt_blob(&loaded_dek, &blob).unwrap();
        assert_eq!(&recovered, plaintext);
    }
}
