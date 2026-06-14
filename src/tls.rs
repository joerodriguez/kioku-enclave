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
/// Base64-encoded PEM of the certificate **chain** (leaf first, then intermediates —
/// e.g. Let's Encrypt `fullchain.pem`). The full chain is required or clients that
/// don't already cache the issuing intermediate fail chain verification.
const ENV_CERT: &str = "ENCLAVE_TLS_CERT_PEM_B64";
/// Base64-encoded PEM of the private key (PKCS#8 / PKCS#1 / SEC1).
const ENV_KEY: &str = "ENCLAVE_TLS_KEY_PEM_B64";

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

    let cert_pem = decode_b64_env(ENV_CERT)?;
    let key_pem = decode_b64_env(ENV_KEY)?;

    let chain = parse_pem_blocks(&cert_pem, "CERTIFICATE");
    if chain.is_empty() {
        return Err(Error::Config(format!("{ENV_CERT} contains no CERTIFICATE blocks")));
    }
    let key = parse_pem_private_key(&key_pem)
        .ok_or_else(|| Error::Config(format!("{ENV_KEY} contains no usable PRIVATE KEY block")))?;

    let keystone = build_chain(chain, key)?;
    info!(
        cert_fingerprint = %keystone.cert_fingerprint_hex,
        chain_len = keystone_chain_note(),
        "in-enclave TLS termination enabled (ADR-0001)"
    );
    Ok(Some(keystone))
}

fn keystone_chain_note() -> &'static str {
    "leaf+intermediates"
}

fn decode_b64_env(var: &str) -> Result<Vec<u8>> {
    let b64 = std::env::var(var)
        .map_err(|_| Error::Config(format!("{ENV_ENABLE} set but {var} missing")))?;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| Error::Config(format!("{var} is not valid base64: {e}")))
}

/// Extract every `-----BEGIN <tag>----- … -----END <tag>-----` block from PEM text
/// and base64-decode its body to DER. Avoids a `rustls-pemfile` dependency.
fn parse_pem_blocks(pem: &[u8], tag: &str) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let begin = format!("-----BEGIN {tag}-----");
    let end = format!("-----END {tag}-----");
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(b) = rest.find(&begin) {
        let after = &rest[b + begin.len()..];
        let Some(e) = after.find(&end) else { break };
        let body: String = after[..e].split_whitespace().collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(body) {
            out.push(der);
        }
        rest = &after[e + end.len()..];
    }
    out
}

/// Parse the first private key found, trying PKCS#8, then PKCS#1 (RSA), then SEC1 (EC).
fn parse_pem_private_key(pem: &[u8]) -> Option<PrivateKeyDer<'static>> {
    if let Some(d) = parse_pem_blocks(pem, "PRIVATE KEY").into_iter().next() {
        return Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(d)));
    }
    if let Some(d) = parse_pem_blocks(pem, "RSA PRIVATE KEY").into_iter().next() {
        return Some(PrivateKeyDer::Pkcs1(
            tokio_rustls::rustls::pki_types::PrivatePkcs1KeyDer::from(d),
        ));
    }
    if let Some(d) = parse_pem_blocks(pem, "EC PRIVATE KEY").into_iter().next() {
        return Some(PrivateKeyDer::Sec1(
            tokio_rustls::rustls::pki_types::PrivateSec1KeyDer::from(d),
        ));
    }
    None
}

/// Build a [`TlsKeystone`] from a DER cert chain (leaf first) + a parsed private key.
fn build_chain(chain_der: Vec<Vec<u8>>, key: PrivateKeyDer<'static>) -> Result<TlsKeystone> {
    let fingerprint = hex_lower(&Sha256::digest(&chain_der[0]));
    let certs: Vec<CertificateDer<'static>> =
        chain_der.into_iter().map(CertificateDer::from).collect();

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

/// Test helper: build from a single DER cert + PKCS#8 key.
#[cfg(test)]
fn build(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<TlsKeystone> {
    build_chain(
        vec![cert_der],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
    )
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
