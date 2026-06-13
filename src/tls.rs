//! Optional in-enclave TLS termination (ADR-0001).
//!
//! By default the enclave serves plain HTTP and relies on the private VPC firewall +
//! per-request Google ID-token auth (see `main.rs`). When `ENCLAVE_TLS` is set, the
//! enclave terminates TLS **itself**, so the attested, open-source binary is the first
//! and only code to see request plaintext — closing the gap where an upstream proxy
//! (today: Cloud Run) terminates TLS and can read everything. See
//! `docs/adr/0001-enclave-as-sole-backend.md` in the monorepo.
//!
//! ## What this module does today (ADR step A)
//!
//! - Loads a **deploy-provided** cert + key (base64-encoded DER, via env). Using DER
//!   avoids pulling a PEM parser and keeps the dependency set minimal.
//! - Builds a rustls [`ServerConfig`] using the ring provider (pure-Rust-friendly, no
//!   OpenSSL — required for the musl FROM-scratch image).
//! - Computes the leaf certificate's **SHA-256 fingerprint**. This is the channel-binding
//!   value: a later step (ADR step C) generates the keypair *inside* the TEE at boot and
//!   binds this fingerprint into the Confidential Space attestation token, so a client
//!   can verify "the TLS key I'm talking to belongs to the attested image" (RA-TLS).
//!
//! ## What this module does NOT do yet
//!
//! - It does not *generate* the keypair in-enclave (needs a vetted cert-gen dep under the
//!   musl/pure-Rust constraint — ADR step C). Until then the cert is supplied at deploy
//!   time, which already moves TLS termination into the attested binary.
//! - It does not put the fingerprint into the attestation token (ADR step C) or have the
//!   client verify it (ADR step D).

use std::sync::Arc;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::{
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use tracing::info;

use crate::error::{EnclaveError as Error, Result};

/// A built TLS server config plus the leaf cert fingerprint used for attestation binding.
pub struct TlsKeystone {
    pub server_config: Arc<ServerConfig>,
    /// Lowercase hex SHA-256 of the leaf certificate DER (the RA-TLS channel-binding value).
    pub cert_fingerprint_hex: String,
}

/// Env var that gates in-enclave TLS termination. `1` / `true` (case-insensitive) → on.
const ENV_ENABLE: &str = "ENCLAVE_TLS";
/// Base64-encoded DER of the leaf certificate.
const ENV_CERT: &str = "ENCLAVE_TLS_CERT_DER_B64";
/// Base64-encoded DER (PKCS#8) of the private key.
const ENV_KEY: &str = "ENCLAVE_TLS_KEY_DER_B64";

fn is_enabled() -> bool {
    matches!(
        std::env::var(ENV_ENABLE).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("True")
    )
}

/// Returns `Ok(None)` when in-enclave TLS is not enabled (the default plain-HTTP path),
/// or `Ok(Some(keystone))` when `ENCLAVE_TLS` is set and a cert/key are provided.
pub fn from_env() -> Result<Option<TlsKeystone>> {
    if !is_enabled() {
        return Ok(None);
    }

    let cert_b64 = std::env::var(ENV_CERT)
        .map_err(|_| Error::Config(format!("{ENV_ENABLE} set but {ENV_CERT} missing")))?;
    let key_b64 = std::env::var(ENV_KEY)
        .map_err(|_| Error::Config(format!("{ENV_ENABLE} set but {ENV_KEY} missing")))?;

    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(cert_b64.trim())
        .map_err(|e| Error::Config(format!("{ENV_CERT} is not valid base64: {e}")))?;
    let key_der = base64::engine::general_purpose::STANDARD
        .decode(key_b64.trim())
        .map_err(|e| Error::Config(format!("{ENV_KEY} is not valid base64: {e}")))?;

    let keystone = build(cert_der, key_der)?;
    info!(
        cert_fingerprint = %keystone.cert_fingerprint_hex,
        "in-enclave TLS termination enabled (ADR-0001)"
    );
    Ok(Some(keystone))
}

/// Build a [`TlsKeystone`] from raw DER cert + PKCS#8 key bytes.
///
/// Separated from [`from_env`] so it can be unit-tested with fixed fixtures.
fn build(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<TlsKeystone> {
    let fingerprint = hex_lower(&Sha256::digest(&cert_der));

    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    // Explicit ring provider so we never depend on a process-default being installed,
    // and never link aws-lc / OpenSSL (musl FROM-scratch must stay pure-Rust-friendly).
    let server_config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Config(format!("rustls provider/protocol setup failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Config(format!("invalid TLS cert/key: {e}")))?;

    Ok(TlsKeystone {
        server_config: Arc::new(server_config),
        cert_fingerprint_hex: fingerprint,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway P-256 self-signed cert + PKCS#8 key (DER, base64), generated with openssl
    // for tests only. NOT used anywhere at runtime.
    const TEST_CERT_DER_B64: &str = "MIIBjjCCATWgAwIBAgIUIytx8lNz5aDdy67h5sxE8A+CJa0wCgYIKoZIzj0EAwIwHTEbMBkGA1UEAwwSa2lva3UtZW5jbGF2ZS10ZXN0MB4XDTI2MDYxMzIyMjMyOFoXDTI2MDYxNDIyMjMyOFowHTEbMBkGA1UEAwwSa2lva3UtZW5jbGF2ZS10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzGwDYRrcIjAqX48U+diBS3zb0UiR1OorU9wcCSQo6aUeN4Zp8pYOocJMdc4HnZ+V8voWl66YIP6eYq2H01CTU6NTMFEwHQYDVR0OBBYEFD0sLmpIXL9fop226VLPpN4hVyBWMB8GA1UdIwQYMBaAFD0sLmpIXL9fop226VLPpN4hVyBWMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgJjFTQmQRm5rcUmKBhYaQbMbUYFSnaeZa94kN8/V2q44CIHkGiPTacXw931l4DUrVtPvHwpZv2kUwKQQmFccYKZ0y";
    const TEST_KEY_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguFGp8VQUlYvbcw0sx185058IH6Inx/FXgjoQbrG1/pyhRANCAATMbANhGtwiMCpfjxT52IFLfNvRSJHU6itT3BwJJCjppR43hmnylg6hwkx1zgedn5Xy+haXrpgg/p5irYfTUJNT";
    // SHA-256 of the cert DER above (openssl dgst -sha256).
    const EXPECTED_FINGERPRINT: &str =
        "d1817916fc0ecb6a30f947b43f452325b09cc9c88067fcdcaadef547a4d84580";

    fn decode(b64: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    }

    #[test]
    fn builds_config_and_computes_fingerprint() {
        let ks = build(decode(TEST_CERT_DER_B64), decode(TEST_KEY_DER_B64))
            .expect("valid cert+key should build");
        assert_eq!(ks.cert_fingerprint_hex, EXPECTED_FINGERPRINT);
        assert_eq!(ks.cert_fingerprint_hex.len(), 64);
    }

    #[test]
    fn rejects_garbage_key() {
        let err = build(decode(TEST_CERT_DER_B64), vec![0u8; 8]);
        assert!(err.is_err(), "garbage key must be rejected");
    }

    #[test]
    fn disabled_by_default() {
        // ENCLAVE_TLS unset in the test environment → no keystone.
        assert!(!is_enabled());
    }
}
