//! AES-256-GCM envelope encryption for per-user SQLite index blobs.
//!
//! # Blob wire format
//!
//! ```text
//! [ nonce: 12 bytes ][ ciphertext + auth-tag: variable ]
//! ```
//!
//! The 96-bit (12-byte) nonce is randomly generated per encrypt call and
//! prepended to the output so the decryptor can find it without side-channel.
//! The 128-bit GCM auth tag is appended by the aes-gcm crate after the
//! ciphertext (standard AEAD convention).
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
//! In Confidential Space, the default service account token is fetched from
//! the metadata server. KMS IAM is bound to the Workload Identity Pool with
//! an attribute condition that requires:
//!   - `google.subject` == the Confidential Space workload identity
//!   - `attribute.image_digest` == the published, reproducibly-built digest
//!
//! No human principal has decrypt permission on the KEK.

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use serde::Deserialize;

use crate::attestation::AttestationCredentials;
use crate::error::{EnclaveError, Result};

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

/// Decrypt a blob produced by [`encrypt_blob`].
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

/// Cloud KMS REST client.  Uses the metadata server token, which in Confidential
/// Space is attestation-gated to the exact image digest.
///
/// ## Feature flag: `ENCLAVE_KMS_VIA_ATTESTATION=1`
///
/// When this env var is set to `"1"`, KMS encrypt/decrypt calls use an
/// attestation-derived federated access token (via the WIF principalSet
/// binding) instead of the VM service-account metadata token.  The metadata
/// token path is the **fallback** and remains operational so no cutover is
/// required before the flag is flipped.
///
/// GCS operations (ciphertext blob storage) are never affected — they always
/// use the metadata SA token because the GCS bucket is not the security
/// boundary (the DEKs are).
pub struct GcpKmsClient {
    http: reqwest::Client,
    key_name: String, // projects/P/locations/L/keyRings/R/cryptoKeys/K
    /// Present only when ENCLAVE_KMS_VIA_ATTESTATION=1.
    attestation_creds: Option<AttestationCredentials>,
}

#[derive(Deserialize)]
struct KmsEncryptResponse {
    ciphertext: String,
}

#[derive(Deserialize)]
struct KmsDecryptResponse {
    plaintext: String,
}

#[derive(Deserialize)]
struct MetadataTokenResponse {
    access_token: String,
}

impl GcpKmsClient {
    /// Construct from environment variables:
    /// - `KMS_PROJECT`, `KMS_LOCATION`, `KMS_KEY_RING`, `KMS_KEY`
    /// - `ENCLAVE_KMS_VIA_ATTESTATION` (optional, default off): when `"1"`,
    ///   KMS calls use the attestation-derived federated token.
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

        // Attestation credential source — built only when the flag is on.
        let attestation_creds =
            if std::env::var("ENCLAVE_KMS_VIA_ATTESTATION").as_deref() == Ok("1") {
                Some(AttestationCredentials::from_env()?)
            } else {
                None
            };

        Ok(Self {
            http: reqwest::Client::new(),
            key_name,
            attestation_creds,
        })
    }

    /// Fetch an access token from the GCE metadata server (VM SA path).
    /// This is the legacy/fallback credential used when
    /// `ENCLAVE_KMS_VIA_ATTESTATION` is not set.
    async fn metadata_token(&self) -> Result<String> {
        let resp: MetadataTokenResponse = self
            .http
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(resp.access_token)
    }

    /// Return the KMS access token for this request.
    ///
    /// - If `ENCLAVE_KMS_VIA_ATTESTATION=1`: uses the attestation-derived
    ///   federated token (WIF principalSet path). The security property only
    ///   holds when the attestation-gated principalSet is the *only* KMS
    ///   decrypt grant — the deployment must not also bind the VM service
    ///   account to the key.
    /// - Otherwise: uses the metadata server SA token (fallback path).
    async fn kms_token(&self) -> Result<String> {
        if let Some(ref creds) = self.attestation_creds {
            creds.kms_access_token().await
        } else {
            self.metadata_token().await
        }
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
