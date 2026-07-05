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
//! - Loads a **deploy-provided** cert chain + key (base64-encoded PEM, via env), parsed
//!   with the minimal in-house PEM-block scanner below (no `rustls-pemfile` dependency).
//! - Builds a rustls [`ServerConfig`] using the ring provider (pure-Rust-friendly, no
//!   OpenSSL — required for the musl FROM-scratch image).
//! - Computes the leaf certificate's **SHA-256 fingerprint**. This is the channel-binding
//!   value: a later step (ADR step C) generates the keypair *inside* the TEE at boot and
//!   binds this fingerprint into the Confidential Space attestation token, so a client
//!   can verify "the TLS key I'm talking to belongs to the attested image" (RA-TLS).
//!
//! ## ACME renewal (ADR-0003)
//!
//! The live deployment no longer bakes a cert: [`crate::acme`] obtains and renews it
//! from Let's Encrypt with the private key generated **inside** the enclave, and swaps
//! it into the running server via [`TlsKeystone::swap`] (a swappable rustls cert
//! resolver — no restart). The env-var path below remains as the static/bootstrap
//! fallback and for local testing.
//!
//! ## What this module does NOT do yet
//!
//! - It does not put the fingerprint into the attestation token (ADR step C) or have the
//!   client verify it (ADR step D). Note the ACME path already satisfies step C's key
//!   precondition: the key is generated in-TEE and never exists in operator-visible form.

use std::sync::{Arc, RwLock};

use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::{
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use tracing::info;

use crate::error::{EnclaveError as Error, Result};

/// A parsed certificate chain (leaf first) + private key, the unit the keystone
/// serves and the ACME renewal path swaps in (ADR-0003).
pub struct CertKeyPair {
    chain_der: Vec<Vec<u8>>,
    key: PrivateKeyDer<'static>,
}

impl CertKeyPair {
    /// Parse from PEM text: a `CERTIFICATE` chain (leaf first — e.g. Let's Encrypt
    /// `fullchain.pem`) and a `PRIVATE KEY` (PKCS#8 / PKCS#1 / SEC1).
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let chain = parse_pem_blocks(cert_pem, "CERTIFICATE");
        if chain.is_empty() {
            return Err(Error::Config(
                "cert PEM contains no CERTIFICATE blocks".into(),
            ));
        }
        let key = parse_pem_private_key(key_pem)
            .ok_or_else(|| Error::Config("key PEM contains no usable PRIVATE KEY block".into()))?;
        Ok(Self {
            chain_der: chain,
            key,
        })
    }

    /// Lowercase hex SHA-256 of the leaf certificate DER (the RA-TLS channel-binding value).
    pub fn fingerprint_hex(&self) -> String {
        hex_lower(&Sha256::digest(&self.chain_der[0]))
    }

    /// Build the rustls [`CertifiedKey`] (validates the key is usable by ring).
    fn into_certified_key(self) -> Result<CertifiedKey> {
        let signing_key = ring::sign::any_supported_type(&self.key)
            .map_err(|e| Error::Config(format!("unsupported TLS private key: {e}")))?;
        let certs: Vec<CertificateDer<'static>> = self
            .chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        Ok(CertifiedKey::new(certs, signing_key))
    }
}

/// Cert resolver whose [`CertifiedKey`] can be replaced at runtime, so an ACME
/// renewal swaps the served certificate without dropping connections or
/// restarting the accept loop. Handshakes read the current key atomically.
#[derive(Debug)]
struct SwappableCertResolver(RwLock<Arc<CertifiedKey>>);

impl ResolvesServerCert for SwappableCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().expect("cert resolver lock poisoned").clone())
    }
}

/// A built TLS server config plus the leaf cert fingerprint used for attestation binding.
pub struct TlsKeystone {
    pub server_config: Arc<ServerConfig>,
    /// Lowercase hex SHA-256 of the leaf certificate DER (the RA-TLS channel-binding
    /// value) as of the last build/swap.
    pub cert_fingerprint_hex: String,
    resolver: Arc<SwappableCertResolver>,
}

impl TlsKeystone {
    /// Build a keystone serving `pair`, with a resolver that supports live swaps.
    pub fn new(pair: CertKeyPair) -> Result<Self> {
        let fingerprint = pair.fingerprint_hex();
        let resolver = Arc::new(SwappableCertResolver(RwLock::new(Arc::new(
            pair.into_certified_key()?,
        ))));

        // Explicit ring provider so we never depend on a process-default being installed,
        // and never link aws-lc / OpenSSL (musl FROM-scratch must stay pure-Rust-friendly).
        let server_config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Config(format!("rustls provider/protocol setup failed: {e}")))?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());

        Ok(TlsKeystone {
            server_config: Arc::new(server_config),
            cert_fingerprint_hex: fingerprint,
            resolver,
        })
    }

    /// Replace the served certificate (ACME renewal). In-flight and future
    /// handshakes atomically pick up the new chain. Returns the new leaf
    /// fingerprint (logged by the caller — never key material).
    pub fn swap(&self, pair: CertKeyPair) -> Result<String> {
        let fingerprint = pair.fingerprint_hex();
        let certified = Arc::new(pair.into_certified_key()?);
        *self
            .resolver
            .0
            .write()
            .expect("cert resolver lock poisoned") = certified;
        Ok(fingerprint)
    }
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

/// Generate a self-signed certificate and PKCS#8 key DER using rcgen.
/// Extracts Subject Alternative Names (SANs) from the provided base URL and enclave audience.
pub fn generate_self_signed(base_url: &str, enclave_audience: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut subject_alt_names = vec!["localhost".to_string()];

    // Parse hosts from base_url
    if let Ok(url) = reqwest::Url::parse(base_url) {
        if let Some(host) = url.host_str() {
            if host != "localhost" {
                subject_alt_names.push(host.to_string());
            }
        }
    }

    // Parse hosts from enclave_audience
    if let Ok(url) = reqwest::Url::parse(enclave_audience) {
        if let Some(host) = url.host_str() {
            if host != "localhost" && !subject_alt_names.contains(&host.to_string()) {
                subject_alt_names.push(host.to_string());
            }
        }
    }

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(subject_alt_names)
            .map_err(|e| Error::Config(format!("Failed to generate self-signed cert: {e}")))?;

    let cert_der = cert.der().to_vec();
    let key_der = signing_key.serialize_der();

    Ok((cert_der, key_der))
}

/// Returns `Ok(None)` when in-enclave TLS is not enabled (the default plain-HTTP path),
/// or `Ok(Some(keystone))` when `ENCLAVE_TLS` is set.
/// Loads certs from the environment variables (if provided), or fetches them from Secret Manager (if they are
/// in Secret Manager), or dynamically generates a self-signed certificate at runtime.
pub async fn from_env(base_url: &str, enclave_audience: &str) -> Result<Option<TlsKeystone>> {
    if !is_enabled() {
        return Ok(None);
    }

    // 1. Try environment variables first (legacy/custom cert path)
    let cert_pair =
        if let (Ok(cert_b64), Ok(key_b64)) = (std::env::var(ENV_CERT), std::env::var(ENV_KEY)) {
            if !cert_b64.is_empty() && !key_b64.is_empty() {
                let cert_pem = base64::engine::general_purpose::STANDARD
                    .decode(cert_b64.trim())
                    .map_err(|e| Error::Config(format!("{ENV_CERT} is not valid base64: {e}")))?;
                let key_pem = base64::engine::general_purpose::STANDARD
                    .decode(key_b64.trim())
                    .map_err(|e| Error::Config(format!("{ENV_KEY} is not valid base64: {e}")))?;
                Some(CertKeyPair::from_pem(&cert_pem, &key_pem)?)
            } else {
                None
            }
        } else {
            None
        };

    let cert_pair = match cert_pair {
        Some(pair) => pair,
        None => {
            // 2. Try fetching from Secret Manager (if KMS_PROJECT is set and we're not in test mode)
            let fetched = if std::env::var("ENCLAVE_TEST_MODE").is_err()
                && std::env::var("KMS_PROJECT").is_ok()
            {
                info!("attempting to fetch TLS cert/key from Secret Manager");
                match (
                    crate::cp::fetch_secret_from_manager("kioku-enclave-tls-cert", "latest").await,
                    crate::cp::fetch_secret_from_manager("kioku-enclave-tls-key", "latest").await,
                ) {
                    (Ok(cert_str), Ok(key_str)) => {
                        CertKeyPair::from_pem(cert_str.as_bytes(), key_str.as_bytes()).ok()
                    }
                    _ => None,
                }
            } else {
                None
            };

            match fetched {
                Some(pair) => pair,
                None => {
                    // 3. Fall back to generating a self-signed cert dynamically at runtime
                    info!("generating dynamic self-signed cert/key at runtime");
                    let (cert_der, key_der) = generate_self_signed(base_url, enclave_audience)?;
                    CertKeyPair {
                        chain_der: vec![cert_der],
                        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
                    }
                }
            }
        }
    };

    let keystone = TlsKeystone::new(cert_pair)?;
    info!(
        cert_fingerprint = %keystone.cert_fingerprint_hex,
        "in-enclave TLS termination enabled (ADR-0001)"
    );
    Ok(Some(keystone))
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

/// Test helper: build from a single DER cert + PKCS#8 key.
#[cfg(test)]
fn build(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<TlsKeystone> {
    TlsKeystone::new(CertKeyPair {
        chain_der: vec![cert_der],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
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

    /// A swap must atomically change what the resolver serves (the ACME renewal path).
    #[test]
    fn swap_replaces_served_cert() {
        let ks = build(decode(TEST_CERT_DER_B64), decode(TEST_KEY_DER_B64)).unwrap();
        assert_eq!(ks.cert_fingerprint_hex, EXPECTED_FINGERPRINT);

        // Fresh self-signed cert generated with rcgen (same crate the ACME path
        // uses in-enclave via instant-acme).
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["renewed.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pair =
            CertKeyPair::from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
        let new_fp = pair.fingerprint_hex();
        assert_ne!(new_fp, EXPECTED_FINGERPRINT);

        let swapped_fp = ks.swap(pair).unwrap();
        assert_eq!(swapped_fp, new_fp);

        // The resolver now hands out the new leaf.
        let served = ks
            .resolver
            .0
            .read()
            .unwrap()
            .cert
            .first()
            .unwrap()
            .as_ref()
            .to_vec();
        assert_eq!(hex_lower(&Sha256::digest(&served)), new_fp);
    }
}
