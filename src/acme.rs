//! In-enclave ACME certificate issuance + auto-renewal (ADR-0003).
//!
//! The enclave holds the public IP, so it answers Let's Encrypt HTTP-01
//! challenges itself on :80 and terminates TLS with a certificate whose
//! **private key is generated inside the TEE and never leaves it** in
//! plaintext. This replaces the baked `ENCLAVE_TLS_*_PEM_B64` build args —
//! which leaked the key into the Confidential Space attestation token
//! (container env is published to serial console / Cloud Logging) — and makes
//! renewal a background task instead of an image rebuild + KMS digest
//! rebinding.
//!
//! ## How it works
//!
//! - **State** (`acme/tls.json.enc` in the existing GCS bucket): the ACME
//!   account credentials, key PEM, chain PEM, and issuance timestamp — AES-256-
//!   GCM under a KMS-wrapped DEK, exactly like the control DB. Only the
//!   attested image can decrypt it, so renewals and VM rolls need no deploys.
//! - **Boot** (`Renewer::initial_pair`): load state → serve; missing or ≥85 d
//!   old → synchronous first issuance (the :80 challenge listener must already
//!   be running — `main.rs` spawns it first).
//! - **Renewal** (`Renewer::spawn`): checks every 6 h, renews at issuance +
//!   60 d (Let's Encrypt certs live 90 d; renewing at 2/3 lifetime matches
//!   certbot). On success the new pair is persisted and hot-swapped into the
//!   running listener via [`TlsKeystone::swap`]; on failure the old cert keeps
//!   serving (≥30 d of headroom) and the next tick retries sooner.
//!
//! ## Security notes
//!
//! - Key material is never logged; only fingerprints and timestamps are.
//! - The :80 listener serves *only* `/.well-known/acme-challenge/<token>`
//!   lookups from an in-memory map (404 otherwise) — no new plaintext sink
//!   (invariant §4.4-5) and no user data anywhere near it.
//! - Rate limits: ~6 renewals/year is far under every Let's Encrypt limit for
//!   the production domain (`api.kiokuu.com` as of 2026-07-06; the original
//!   sslip.io hostname sat on the Public Suffix List, which made this a
//!   non-issue by construction — a plain registered domain is still fine at
//!   this cadence). A domain change is handled at boot: persisted ACME state
//!   for a different domain/directory is discarded and a fresh cert issued.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use bytes::Bytes;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType,
    HttpClient, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    crypto::{decrypt_bound_blob, encrypt_bound_blob, generate_and_wrap_dek, load_dek, KmsClient},
    error::{EnclaveError as Error, Result},
    store::GcsClient,
    tls::{CertKeyPair, TlsKeystone},
};

/// GCS object holding the encrypted ACME state (account + cert + key).
const STATE_OBJECT: &str = "acme/tls.json.enc";
const STATE_CONTEXT: &[u8] = b"acme-state\0acme/tls.json.enc";
/// Renew at issuance + 60 d (2/3 of Let's Encrypt's 90-d lifetime, certbot's default).
const RENEW_AFTER: Duration = Duration::from_secs(60 * 24 * 60 * 60);
/// Past issuance + 85 d, treat the stored cert as unusable and block boot on reissue
/// rather than serving a cert about to expire (or already expired).
const HARD_EXPIRY: Duration = Duration::from_secs(85 * 24 * 60 * 60);
/// Steady-state renewal check interval.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// Retry interval after a failed issuance attempt.
const RETRY_INTERVAL: Duration = Duration::from_secs(15 * 60);

// ── Config ────────────────────────────────────────────────────────────────────

/// Env var gating in-enclave ACME. `1` / `true` (case-insensitive) → on.
const ENV_ENABLE: &str = "ENCLAVE_ACME";
/// ACME directory URL; defaults to Let's Encrypt production. Baked per-deploy
/// (point at the LE staging directory for issuance tests).
const ENV_DIRECTORY: &str = "ENCLAVE_ACME_DIRECTORY";
/// Optional `mailto:` contact registered with the ACME account.
const ENV_CONTACT: &str = "ENCLAVE_ACME_CONTACT";
/// HTTP-01 challenge listener port (default 80; overridable for local tests).
const ENV_HTTP_PORT: &str = "ENCLAVE_ACME_HTTP_PORT";

const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

#[derive(Clone)]
pub struct AcmeConfig {
    /// DNS name to issue for, derived from `BASE_URL` (e.g. `api.kiokuu.com`).
    pub domain: String,
    pub directory_url: String,
    pub contact: Option<String>,
    pub http_port: u16,
}

impl AcmeConfig {
    /// `Ok(None)` unless `ENCLAVE_ACME` is enabled. The domain comes from the
    /// (image-baked) `BASE_URL`, so cert identity can't drift from the OAuth
    /// issuer identity.
    pub fn from_env() -> Result<Option<Self>> {
        let enabled = matches!(
            std::env::var(ENV_ENABLE).ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE") | Some("True")
        );
        if !enabled {
            return Ok(None);
        }

        let base_url = std::env::var("BASE_URL")
            .map_err(|_| Error::Config(format!("{ENV_ENABLE} set but BASE_URL missing")))?;
        let domain = domain_from_base_url(&base_url)?;

        Ok(Some(Self {
            domain,
            directory_url: std::env::var(ENV_DIRECTORY)
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| LETS_ENCRYPT_PRODUCTION.to_string()),
            contact: std::env::var(ENV_CONTACT).ok().filter(|s| !s.is_empty()),
            http_port: std::env::var(ENV_HTTP_PORT)
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(80),
        }))
    }
}

/// Extract the host from a URL like `https://203-0-113-10.sslip.io[/...]`.
fn domain_from_base_url(base_url: &str) -> Result<String> {
    let rest = base_url
        .trim()
        .strip_prefix("https://")
        .or_else(|| base_url.trim().strip_prefix("http://"))
        .unwrap_or(base_url.trim());
    let host = rest
        .split(['/', ':'])
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty()
        || host.contains(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '.')
    {
        return Err(Error::Config(format!(
            "cannot derive ACME domain from BASE_URL {base_url:?}"
        )));
    }
    Ok(host)
}

// ── HTTP-01 challenge listener ────────────────────────────────────────────────

/// token → key-authorization map shared between the issuance flow and the :80
/// challenge handler.
#[derive(Default)]
pub struct ChallengeMap(RwLock<HashMap<String, String>>);

impl ChallengeMap {
    fn insert(&self, token: String, key_auth: String) {
        self.0
            .write()
            .expect("challenge map poisoned")
            .insert(token, key_auth);
    }
    fn clear(&self) {
        self.0.write().expect("challenge map poisoned").clear();
    }
    fn get(&self, token: &str) -> Option<String> {
        self.0
            .read()
            .expect("challenge map poisoned")
            .get(token)
            .cloned()
    }
}

/// Router for the plain-HTTP :80 listener: ACME challenges only, 404 for
/// everything else. Serving nothing but the challenge map keeps this listener
/// out of the threat model (no auth, no user data, no state writes).
pub fn challenge_router(challenges: Arc<ChallengeMap>) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(serve_challenge))
        .with_state(challenges)
}

async fn serve_challenge(
    State(challenges): State<Arc<ChallengeMap>>,
    Path(token): Path<String>,
) -> axum::response::Response {
    match challenges.get(&token) {
        Some(key_auth) => key_auth.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── HTTP client adapter ───────────────────────────────────────────────────────

/// instant-acme [`HttpClient`] backed by reqwest. The crate's built-in hyper
/// client verifies TLS via the *platform* trust store, which doesn't exist in
/// the FROM-scratch image; reqwest here is built with rustls-tls-webpki-roots
/// (Mozilla roots compiled into the binary), same as the KMS/GCS clients.
struct ReqwestHttpClient(reqwest::Client);

impl HttpClient for ReqwestHttpClient {
    fn request(
        &self,
        req: axum::http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<BytesResponse, instant_acme::Error>> + Send>>
    {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, mut body) = req.into_parts();
            // BodyWrapper<Bytes> is a single-frame http_body::Body (Error =
            // Infallible); drain it without pulling in http-body-util.
            let mut body_bytes = Vec::new();
            while let Some(frame) =
                std::future::poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut body), cx))
                    .await
            {
                let Ok(frame) = frame; // Error = Infallible
                if let Ok(data) = frame.into_data() {
                    body_bytes.extend_from_slice(&data);
                }
            }
            let rsp = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body_bytes)
                .send()
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;

            let mut builder = axum::http::Response::builder().status(rsp.status());
            if let Some(headers) = builder.headers_mut() {
                *headers = rsp.headers().clone();
            }
            let bytes = rsp
                .bytes()
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            let (rsp_parts, ()) = builder
                .body(())
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?
                .into_parts();
            Ok(BytesResponse {
                parts: rsp_parts,
                body: Box::new(bytes),
            })
        })
    }
}

fn acme_http_client() -> Box<dyn HttpClient> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("static ACME HTTP client configuration is valid");
    Box::new(ReqwestHttpClient(client))
}

// ── Persisted state ───────────────────────────────────────────────────────────

/// The encrypted-at-rest ACME state. `account` is instant-acme's opaque
/// serialized credentials (contains the account's private key — same secrecy
/// class as `key_pem`; both exist in plaintext only inside the enclave).
#[derive(Serialize, Deserialize)]
struct AcmeState {
    version: u32,
    domain: String,
    directory_url: String,
    account: AccountCredentials,
    key_pem: String,
    chain_pem: String,
    issued_at_unix: u64,
}

impl AcmeState {
    fn age(&self, now: SystemTime) -> Duration {
        let issued = UNIX_EPOCH + Duration::from_secs(self.issued_at_unix);
        now.duration_since(issued).unwrap_or(Duration::ZERO)
    }

    fn matches(&self, config: &AcmeConfig) -> bool {
        self.domain == config.domain && self.directory_url == config.directory_url
    }
}

// ── Renewer ───────────────────────────────────────────────────────────────────

pub struct Renewer {
    config: AcmeConfig,
    kms: Arc<dyn KmsClient>,
    gcs: Arc<dyn GcsClient>,
    challenges: Arc<ChallengeMap>,
    /// Loaded state + its GCS generation (for `if_generation_match` writes).
    state: tokio::sync::Mutex<Option<(AcmeState, i64)>>,
}

impl Renewer {
    pub fn new(
        config: AcmeConfig,
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        challenges: Arc<ChallengeMap>,
    ) -> Self {
        Self {
            config,
            kms,
            gcs,
            challenges,
            state: tokio::sync::Mutex::new(None),
        }
    }

    /// Boot path: return a serving-ready cert/key pair. Prefers persisted state
    /// (fast, no ACME round-trip on ordinary VM rolls); issues synchronously
    /// when state is missing, for a different domain/directory, or ≥85 d old.
    pub async fn initial_pair(&self) -> Result<CertKeyPair> {
        let mut guard = self.state.lock().await;
        match self.load().await {
            Ok(Some((state, generation))) if state.matches(&self.config) => {
                let age_days = state.age(SystemTime::now()).as_secs() / 86_400;
                if state.age(SystemTime::now()) < HARD_EXPIRY {
                    info!(
                        domain = %state.domain,
                        age_days,
                        "serving persisted ACME certificate"
                    );
                    let pair = CertKeyPair::from_pem(
                        state.chain_pem.as_bytes(),
                        state.key_pem.as_bytes(),
                    )?;
                    *guard = Some((state, generation));
                    return Ok(pair);
                }
                warn!(
                    age_days,
                    "persisted ACME certificate too old; reissuing at boot"
                );
                *guard = Some((state, generation));
            }
            Ok(Some((state, generation))) => {
                warn!(
                    stored_domain = %state.domain,
                    configured_domain = %self.config.domain,
                    "persisted ACME state is for a different domain/directory; reissuing"
                );
                // Keep generation so the overwrite is race-safe; drop the state.
                *guard = Some((state, generation));
            }
            Ok(None) => info!(domain = %self.config.domain, "no ACME state; first issuance"),
            Err(e) => return Err(e),
        }
        self.issue_and_persist(&mut guard).await
    }

    /// Background renewal loop. `keystone` is the live TLS server to hot-swap.
    pub fn spawn(self: Arc<Self>, keystone: Arc<TlsKeystone>) {
        tokio::spawn(async move {
            loop {
                let interval = match self.tick(&keystone).await {
                    Ok(()) => CHECK_INTERVAL,
                    Err(e) => {
                        error!(error = %e, "ACME renewal attempt failed; will retry");
                        RETRY_INTERVAL
                    }
                };
                tokio::time::sleep(interval).await;
            }
        });
    }

    /// One renewal check: reissue + persist + swap when due, no-op otherwise.
    async fn tick(&self, keystone: &TlsKeystone) -> Result<()> {
        let mut guard = self.state.lock().await;
        if let Some((state, _)) = guard.as_ref() {
            if state.matches(&self.config) && state.age(SystemTime::now()) < RENEW_AFTER {
                return Ok(());
            }
        }
        info!(domain = %self.config.domain, "ACME renewal due");
        let pair = self.issue_and_persist(&mut guard).await?;
        let fingerprint = keystone.swap(pair)?;
        info!(
            cert_fingerprint = %fingerprint,
            "renewed certificate swapped into live listener"
        );
        Ok(())
    }

    /// Run one ACME order (HTTP-01), persist the result, and return the pair.
    /// The caller holds the state lock, so concurrent issuance is impossible.
    async fn issue_and_persist(&self, guard: &mut Option<(AcmeState, i64)>) -> Result<CertKeyPair> {
        // Reuse the persisted ACME account when its directory matches;
        // otherwise register a fresh one.
        let (account, credentials) = match guard
            .as_ref()
            .filter(|(s, _)| s.directory_url == self.config.directory_url)
        {
            Some((state, _)) => {
                // Round-trip through JSON: AccountCredentials is deliberately
                // opaque (no Clone), and we need to both use and re-store it.
                let creds_json = serde_json::to_value(&state.account)?;
                let account = Account::builder_with_http(acme_http_client())
                    .from_credentials(serde_json::from_value(creds_json.clone())?)
                    .await
                    .map_err(acme_err("restore ACME account"))?;
                (account, serde_json::from_value(creds_json)?)
            }
            None => {
                let contact: Vec<&str> = self.config.contact.as_deref().into_iter().collect();
                Account::builder_with_http(acme_http_client())
                    .create(
                        &NewAccount {
                            contact: &contact,
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        self.config.directory_url.clone(),
                        None,
                    )
                    .await
                    .map_err(acme_err("create ACME account"))?
            }
        };

        let issue_result = self.issue(&account).await;
        self.challenges.clear();
        let (key_pem, chain_pem) = issue_result?;

        let pair = CertKeyPair::from_pem(chain_pem.as_bytes(), key_pem.as_bytes())?;
        info!(
            domain = %self.config.domain,
            cert_fingerprint = %pair.fingerprint_hex(),
            "ACME issuance succeeded"
        );

        let state = AcmeState {
            version: 1,
            domain: self.config.domain.clone(),
            directory_url: self.config.directory_url.clone(),
            account: credentials,
            key_pem,
            chain_pem,
            issued_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
        };
        let prev_generation = guard.as_ref().map(|(_, g)| *g).unwrap_or(0);
        let generation = self.save(&state, prev_generation).await?;
        *guard = Some((state, generation));
        Ok(pair)
    }

    /// The RFC 8555 order dance against the configured directory.
    async fn issue(&self, account: &Account) -> Result<(String, String)> {
        let identifiers = [Identifier::Dns(self.config.domain.clone())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(acme_err("create order"))?;

        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(acme_err("fetch authorization"))?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => {
                    return Err(Error::Config(format!(
                        "ACME authorization in unexpected state {status:?}"
                    )))
                }
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| Error::Config("ACME server offered no HTTP-01 challenge".into()))?;
            self.challenges.insert(
                challenge.token.clone(),
                challenge.key_authorization().as_str().to_string(),
            );
            challenge
                .set_ready()
                .await
                .map_err(acme_err("set challenge ready"))?;
        }

        // The default RetryPolicy gives up after 30 s; Let's Encrypt validation
        // occasionally takes longer (multi-vantage-point checks), and a renewal
        // retries only every 15 min — be patient instead.
        let retry = RetryPolicy::default().timeout(Duration::from_secs(180));
        let status = order
            .poll_ready(&retry)
            .await
            .map_err(acme_err("poll order"))?;
        if status != OrderStatus::Ready {
            return Err(Error::Config(format!(
                "ACME order not ready after validation: {status:?}"
            )));
        }

        // finalize() generates the keypair via rcgen *inside this process* —
        // the private key is born in the TEE and only ever stored encrypted.
        let key_pem = order.finalize().await.map_err(acme_err("finalize order"))?;
        let chain_pem = order
            .poll_certificate(&retry)
            .await
            .map_err(acme_err("download certificate"))?;
        Ok((key_pem, chain_pem))
    }

    // ── Encrypted persistence (same envelope as the control DB) ──────────────

    async fn load(&self) -> Result<Option<(AcmeState, i64)>> {
        match self.gcs.get_object(STATE_OBJECT).await {
            Ok(rsp) => {
                let dek = load_dek(self.kms.as_ref(), &rsp.wrapped_dek_b64).await?;
                let opened = decrypt_bound_blob(&dek, &rsp.ciphertext, STATE_CONTEXT)?;
                let state: AcmeState = serde_json::from_slice(&opened.plaintext)?;
                Ok(Some((state, rsp.generation)))

            }
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Encrypt under a fresh KMS-wrapped DEK and write with generation match.
    /// Returns the new generation.
    async fn save(&self, state: &AcmeState, if_generation_match: i64) -> Result<i64> {
        let (dek, wrapped) = generate_and_wrap_dek(self.kms.as_ref()).await?;
        let ciphertext = encrypt_bound_blob(&dek, &serde_json::to_vec(state)?, STATE_CONTEXT)?;
        self.gcs
            .put_object(STATE_OBJECT, &ciphertext, &wrapped, if_generation_match)
            .await
    }
}

/// Wrap an instant-acme error with the step that failed. The Display of these
/// errors never contains key material.
fn acme_err(step: &'static str) -> impl Fn(instant_acme::Error) -> Error {
    move |e| Error::Config(format!("ACME {step} failed: {e}"))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{FakeGcs, FakeKms};

    #[test]
    fn disabled_by_default() {
        // ENCLAVE_ACME unset in the test environment → no config.
        assert!(AcmeConfig::from_env().unwrap().is_none());
    }

    #[test]
    fn derives_domain_from_base_url() {
        assert_eq!(
            domain_from_base_url("https://203-0-113-10.sslip.io").unwrap(),
            "203-0-113-10.sslip.io"
        );
        assert_eq!(
            domain_from_base_url("https://Example.COM/path?q=1").unwrap(),
            "example.com"
        );
        assert_eq!(
            domain_from_base_url("http://localhost:8080").unwrap(),
            "localhost"
        );
        assert!(domain_from_base_url("https:// bad url").is_err());
        assert!(domain_from_base_url("").is_err());
    }

    #[tokio::test]
    async fn challenge_router_serves_only_known_tokens() {
        use tower::ServiceExt as _;

        let challenges = Arc::new(ChallengeMap::default());
        challenges.insert("tok-1".into(), "tok-1.keyauth".into());
        let router = challenge_router(Arc::clone(&challenges));

        let ok = router
            .clone()
            .oneshot(
                axum::http::Request::get("/.well-known/acme-challenge/tok-1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let body = axum::body::to_bytes(ok.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"tok-1.keyauth");

        let missing = router
            .clone()
            .oneshot(
                axum::http::Request::get("/.well-known/acme-challenge/unknown")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        // Anything off the challenge path is 404 — this listener serves nothing else.
        let other = router
            .oneshot(
                axum::http::Request::get("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::NOT_FOUND);

        challenges.clear();
        assert!(challenges.get("tok-1").is_none());
    }

    fn test_state(issued_at_unix: u64, domain: &str) -> AcmeState {
        // Minimal opaque account credentials: instant-acme deserializes lazily
        // (key bytes are base64url), so a structurally-valid JSON object
        // round-trips fine for storage tests.
        let key_pkcs8_b64url = {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine as _;
            URL_SAFE_NO_PAD.encode(rcgen::KeyPair::generate().unwrap().serialize_der())
        };
        let account: AccountCredentials = serde_json::from_value(serde_json::json!({
            "id": "https://example.invalid/acct/1",
            "key_pkcs8": key_pkcs8_b64url,
            "directory": "https://example.invalid/dir",
            "urls": null
        }))
        .expect("test credentials deserialize");
        AcmeState {
            version: 1,
            domain: domain.into(),
            directory_url: "https://example.invalid/dir".into(),
            account,
            key_pem: "KEY".into(),
            chain_pem: "CHAIN".into(),
            issued_at_unix,
        }
    }

    fn test_renewer(gcs: Arc<FakeGcs>) -> Renewer {
        Renewer::new(
            AcmeConfig {
                domain: "203-0-113-10.sslip.io".into(),
                directory_url: "https://example.invalid/dir".into(),
                contact: None,
                http_port: 80,
            },
            Arc::new(FakeKms),
            gcs,
            Arc::new(ChallengeMap::default()),
        )
    }

    #[tokio::test]
    async fn state_round_trips_encrypted() {
        let gcs = Arc::new(FakeGcs::new());
        let renewer = test_renewer(Arc::clone(&gcs));

        assert!(renewer.load().await.unwrap().is_none());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let state = test_state(now, "203-0-113-10.sslip.io");
        let generation = renewer.save(&state, 0).await.unwrap();
        assert!(generation > 0);

        let (loaded, loaded_gen) = renewer.load().await.unwrap().unwrap();
        assert_eq!(loaded_gen, generation);
        assert_eq!(loaded.domain, "203-0-113-10.sslip.io");
        assert_eq!(loaded.key_pem, "KEY");
        assert_eq!(loaded.chain_pem, "CHAIN");
        assert_eq!(loaded.issued_at_unix, now);

        // The blob at rest must be ciphertext, not the JSON.
        let raw = gcs.get_object(STATE_OBJECT).await.unwrap();
        assert!(!raw
            .ciphertext
            .windows(b"key_pem".len())
            .any(|w| w == b"key_pem"));

        // Generation mismatch is a conflict (lost-update protection).
        assert!(matches!(
            renewer.save(&state, 0).await,
            Err(Error::Conflict(_))
        ));
    }

    #[test]
    fn renewal_timing() {
        let now = SystemTime::now();
        let now_unix = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let fresh = test_state(now_unix - 86_400, "d");
        assert!(fresh.age(now) < RENEW_AFTER, "1-day-old cert not due");

        let due = test_state(now_unix - 61 * 86_400, "d");
        assert!(due.age(now) >= RENEW_AFTER, "61-day-old cert due");
        assert!(due.age(now) < HARD_EXPIRY, "…but still serveable at boot");

        let dead = test_state(now_unix - 86 * 86_400, "d");
        assert!(dead.age(now) >= HARD_EXPIRY, "86-day-old cert unserveable");

        // Clock skew before issuance ⇒ age 0, never a panic.
        let future = test_state(now_unix + 3_600, "d");
        assert_eq!(future.age(now), Duration::ZERO);
    }
}
