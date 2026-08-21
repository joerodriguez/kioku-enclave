//! In-enclave control plane (ADR-0001).
//!
//! It provides OAuth 2.1 and Dynamic Client Registration, device-to-enclave
//! sync, the MCP server, account export/delete, per-user quotas, and the LLM
//! episode summarizer. It runs inside the same attested binary as storage and
//! query, so the code that
//! terminates TLS and first touches request plaintext is the open-source,
//! release-digest-pinned enclave — not an un-attested proxy. The build is
//! dependency-locked but is not yet claimed to be bit-for-bit reproducible.
//!
//! Identity and accounting live in [`control_store`] as an encrypted SQLite
//! blob in GCS.

pub mod apple;
pub mod auth;
pub mod billing;
pub mod control_store;
pub mod cors;
pub mod delivery;
pub mod dlp;
pub mod email_renderer;
pub mod email_worker;
pub mod finalizer;
pub mod identity;
pub mod isotime;
pub mod limits;
pub mod mcp_projection;
pub mod mcp_query;
pub(crate) mod mcp_safety;
pub mod media;
pub mod media_planner;
pub mod media_worker;
pub mod model_usage;
pub mod oauth;
pub mod push;
pub mod query;
pub mod reviewer;
// Retained for legacy-index migrations and focused regression tests after
// local screenshot ingestion was retired.
#[allow(dead_code)]
pub mod screen_understanding;
pub mod summarizer;
pub mod sync;
pub mod tokens;
pub mod vertex;
pub mod voice_eval;
pub mod voice_eval_assets;
pub mod voice_eval_evidence;
pub mod voice_eval_similarity;
pub mod voice_lineage;
pub mod voice_memory;
pub mod voice_quality;
pub mod webhook_worker;

use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use crate::store::Store;

const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OUTBOUND_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) fn bounded_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(OUTBOUND_CONNECT_TIMEOUT)
        .timeout(OUTBOUND_REQUEST_TIMEOUT)
        .build()
        .expect("static control-plane HTTP client configuration")
}

/// Control-plane configuration, read from the (image-baked) environment.
// Some fields (vertex_*, scheduler_sa_email) are consumed by the summarizer,
// wired in a later commit of this same change.
#[allow(dead_code)]
pub struct CpConfig {
    pub base_url: String,
    /// JWT signing secrets: current first, then rotation-fallback(s).
    pub jwt_secrets: Vec<String>,
    pub google_desktop_client_id: String,
    pub google_ios_client_id: String,
    pub google_web_client_id: String,
    pub google_web_client_secret: String,
    /// Optional Sign in with Apple public configuration. The private key is
    /// fetched separately from Secret Manager and never enters image metadata.
    pub apple_sign_in: Option<apple::AppleSignInConfig>,
    /// Stable UUIDs authorized for owner-only operational reporting. Sign-up is
    /// open to every verified identity; this list only gates owner reporting.
    pub admin_user_ids: Vec<String>,
    pub scheduler_sa_email: Option<String>,
    pub vertex_project: String,
    pub vertex_location: String,
    pub vertex_model: String,
    /// Service-wide ceiling on new accounts per UTC day. Image-baked and
    /// required: signup is open to any verified identity, so this is the only
    /// bound on account creation and it must not have a permissive default.
    pub signup_limit_per_day: i64,
    pub quota_utterances_per_day: i64,
    pub quota_screenshots_per_day: i64,
    pub quota_mcp_calls_per_day: i64,
    pub quota_vertex_output_tokens_per_day: i64,
    pub web_origin: String,
    /// Optional exact-match Google Identity Platform account used only by the
    /// public plugin-review login page. The password never enters this config.
    pub reviewer_auth: Option<ReviewerAuthConfig>,
    pub billing_enforcement_mode: BillingEnforcementMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BillingEnforcementMode {
    Shadow,
    Enforce,
}

impl BillingEnforcementMode {
    pub fn enforces(self) -> bool {
        self == Self::Enforce
    }
}

#[derive(Clone)]
pub struct ReviewerAuthConfig {
    pub api_key: String,
    pub uid: String,
    pub email: String,
}

fn config_value(key: &str, test_default: &str) -> crate::error::Result<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ if crate::test_mode_enabled() => Ok(test_default.to_string()),
        _ => Err(crate::error::EnclaveError::Config(format!(
            "{key} must be set to a non-empty value"
        ))),
    }
}

fn validate_https_origin(name: &str, value: &str) -> crate::error::Result<String> {
    let url = reqwest::Url::parse(value).map_err(|e| {
        crate::error::EnclaveError::Config(format!("{name} is not a valid URL: {e}"))
    })?;
    let path_is_origin = url.path().is_empty() || url.path() == "/";
    if (!crate::test_mode_enabled() && url.scheme() != "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !path_is_origin
    {
        return Err(crate::error::EnclaveError::Config(format!(
            "{name} must be an HTTPS origin without credentials, path, query, or fragment"
        )));
    }
    Ok(value.trim_end_matches('/').to_string())
}

impl CpConfig {
    pub fn from_env(
        jwt_secrets: Vec<String>,
        google_web_client_secret: String,
    ) -> crate::error::Result<Self> {
        // Required, with no production default: an operator who forgets it gets
        // a boot failure rather than an accidentally uncapped service. The test
        // value is deliberately unrelated to any deployed budget.
        let signup_limit_per_day = {
            let raw = config_value("SIGNUP_LIMIT_PER_DAY", "3")?;
            let parsed: i64 = raw.trim().parse().map_err(|_| {
                crate::error::EnclaveError::Config(
                    "SIGNUP_LIMIT_PER_DAY must be a whole number of accounts".into(),
                )
            })?;
            if parsed < 1 {
                return Err(crate::error::EnclaveError::Config(
                    "SIGNUP_LIMIT_PER_DAY must be at least 1".into(),
                ));
            }
            parsed
        };
        let admin_user_ids = std::env::var("ADMIN_USER_IDS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if (!crate::test_mode_enabled() && admin_user_ids.is_empty())
            || admin_user_ids.iter().any(|value| !is_stable_uuid(value))
        {
            return Err(crate::error::EnclaveError::Config(
                "ADMIN_USER_IDS must contain explicit stable UUIDs".into(),
            ));
        }

        if jwt_secrets.is_empty()
            || (!crate::test_mode_enabled() && jwt_secrets.iter().any(|secret| secret.len() < 32))
        {
            return Err(crate::error::EnclaveError::Config(
                "JWT signing secrets are missing or too short".into(),
            ));
        }
        if !crate::test_mode_enabled() && google_web_client_secret.is_empty() {
            return Err(crate::error::EnclaveError::Config(
                "Google web client secret is empty".into(),
            ));
        }

        let parse_i64 = |k: &str, d: i64| -> crate::error::Result<i64> {
            match std::env::var(k) {
                Ok(value) => value.parse::<i64>().ok().filter(|v| *v > 0).ok_or_else(|| {
                    crate::error::EnclaveError::Config(format!("{k} must be a positive integer"))
                }),
                Err(_) => Ok(d),
            }
        };

        let base_url = validate_https_origin(
            "BASE_URL",
            &config_value("BASE_URL", "http://localhost:8080")?,
        )?;
        let web_origin = validate_https_origin(
            "WEB_ORIGIN",
            &config_value("WEB_ORIGIN", "http://localhost:3000")?,
        )?;
        let reviewer_values = [
            std::env::var("REVIEWER_AUTH_API_KEY")
                .unwrap_or_default()
                .trim()
                .to_string(),
            std::env::var("REVIEWER_AUTH_UID")
                .unwrap_or_default()
                .trim()
                .to_string(),
            std::env::var("REVIEWER_AUTH_EMAIL")
                .unwrap_or_default()
                .trim()
                .to_lowercase(),
        ];
        let reviewer_auth = if reviewer_values.iter().all(String::is_empty) {
            None
        } else if reviewer_values.iter().any(String::is_empty) {
            return Err(crate::error::EnclaveError::Config(
                "REVIEWER_AUTH_API_KEY, REVIEWER_AUTH_UID, and REVIEWER_AUTH_EMAIL must be set together"
                    .into(),
            ));
        } else {
            let [api_key, uid, email] = reviewer_values;
            if api_key.len() > 256
                || !api_key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return Err(crate::error::EnclaveError::Config(
                    "REVIEWER_AUTH_API_KEY has an invalid format".into(),
                ));
            }
            if uid.len() > 128
                || !uid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return Err(crate::error::EnclaveError::Config(
                    "REVIEWER_AUTH_UID has an invalid format".into(),
                ));
            }
            if email.len() > 254
                || email
                    .bytes()
                    .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                || email.matches('@').count() != 1
            {
                return Err(crate::error::EnclaveError::Config(
                    "REVIEWER_AUTH_EMAIL has an invalid format".into(),
                ));
            }
            Some(ReviewerAuthConfig {
                api_key,
                uid,
                email,
            })
        };

        let apple_values = [
            std::env::var("APPLE_TEAM_ID")
                .unwrap_or_default()
                .trim()
                .to_string(),
            std::env::var("APPLE_KEY_ID")
                .unwrap_or_default()
                .trim()
                .to_string(),
            std::env::var("APPLE_IOS_CLIENT_ID")
                .unwrap_or_default()
                .trim()
                .to_string(),
            std::env::var("APPLE_MACOS_CLIENT_ID")
                .unwrap_or_default()
                .trim()
                .to_string(),
            std::env::var("APPLE_WEB_CLIENT_ID")
                .unwrap_or_default()
                .trim()
                .to_string(),
        ];
        let apple_sign_in = if apple_values.iter().all(String::is_empty) {
            None
        } else if apple_values.iter().any(String::is_empty) {
            return Err(crate::error::EnclaveError::Config(
                "APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_IOS_CLIENT_ID, APPLE_MACOS_CLIENT_ID, and APPLE_WEB_CLIENT_ID must be set together".into(),
            ));
        } else {
            let [team_id, key_id, ios_client_id, macos_client_id, web_client_id] = apple_values;
            let identifier_valid = |value: &str| {
                value.len() == 10 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
            };
            if !identifier_valid(&team_id)
                || !identifier_valid(&key_id)
                || ios_client_id != "com.kioku.ios"
                || macos_client_id != "com.kiokuu.app"
                || web_client_id != "com.kiokuu.web"
            {
                return Err(crate::error::EnclaveError::Config(
                    "Sign in with Apple public configuration is invalid".into(),
                ));
            }
            Some(apple::AppleSignInConfig {
                team_id,
                key_id,
                ios_client_id,
                macos_client_id,
                web_client_id,
                web_redirect_uri: format!("{base_url}/oauth/apple/callback"),
            })
        };

        let vertex_model = config_value("VERTEX_MODEL", "gemini-3.5-flash")?;
        if !vertex_model_name_is_billing_safe(&vertex_model) {
            return Err(crate::error::EnclaveError::Config(
                "VERTEX_MODEL must be 1-128 ASCII letters, digits, '.', '_', ':', or '-'".into(),
            ));
        }
        let billing_enforcement_mode = match std::env::var("BILLING_ENFORCEMENT_MODE")
            .unwrap_or_else(|_| {
                if crate::test_mode_enabled() {
                    "enforce".into()
                } else {
                    String::new()
                }
            })
            .as_str()
        {
            "shadow" => BillingEnforcementMode::Shadow,
            "enforce" => BillingEnforcementMode::Enforce,
            _ => {
                return Err(crate::error::EnclaveError::Config(
                    "BILLING_ENFORCEMENT_MODE must be shadow or enforce".into(),
                ))
            }
        };

        Ok(Self {
            base_url,
            jwt_secrets,
            google_desktop_client_id: config_value(
                "GOOGLE_DESKTOP_CLIENT_ID",
                "test-desktop.apps.googleusercontent.com",
            )?,
            google_web_client_id: config_value(
                "GOOGLE_WEB_CLIENT_ID",
                "test-web.apps.googleusercontent.com",
            )?,
            google_ios_client_id: config_value(
                "GOOGLE_IOS_CLIENT_ID",
                "test-ios.apps.googleusercontent.com",
            )?,
            google_web_client_secret,
            apple_sign_in,
            admin_user_ids,
            scheduler_sa_email: std::env::var("SCHEDULER_SA_EMAIL")
                .ok()
                .filter(|s| !s.is_empty()),
            vertex_project: config_value("VERTEX_PROJECT", "test-project")?,
            vertex_location: config_value("VERTEX_LOCATION", "us-central1")?,
            vertex_model,
            signup_limit_per_day,
            quota_utterances_per_day: parse_i64("QUOTA_UTTERANCES_PER_DAY", 50_000)?,
            quota_screenshots_per_day: parse_i64("QUOTA_SCREENSHOTS_PER_DAY", 20_000)?,
            quota_mcp_calls_per_day: parse_i64("QUOTA_MCP_CALLS_PER_DAY", 10_000)?,
            quota_vertex_output_tokens_per_day: parse_i64(
                "QUOTA_VERTEX_OUTPUT_TOKENS_PER_DAY",
                524_288,
            )?,
            web_origin,
            reviewer_auth,
            billing_enforcement_mode,
        })
    }

    /// Google ID-token audiences accepted for end-user (device + web) sign-in.
    pub fn user_audiences(&self) -> Vec<String> {
        [
            &self.google_desktop_client_id,
            &self.google_ios_client_id,
            &self.google_web_client_id,
        ]
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
    }

    pub fn is_admin(&self, user_id: &str) -> bool {
        self.admin_user_ids.iter().any(|value| value == user_id)
    }
}

fn is_stable_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

pub(crate) fn vertex_model_name_is_billing_safe(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// Shared state for the control-plane HTTP surface. Holds the same `Arc<Store>`
/// as the data plane so MCP/sync call the content handlers in-process.
// mcp_limiter is consumed by the MCP routes, wired in a later commit.
#[allow(dead_code)]
pub struct CpState {
    pub store: Arc<Store>,
    pub control: Arc<control_store::ControlStore>,
    pub billing: Arc<dyn billing::BillingGateway>,
    pub recording_lease_gate: Arc<billing::RecordingLeaseGates>,
    pub config: Arc<CpConfig>,
    pub user_verifier: Arc<auth::UserIdTokenVerifier>,
    pub reviewer_verifier: Option<Arc<auth::ReviewerIdentityVerifier>>,
    pub apple_provider: Option<Arc<apple::AppleIdentityProvider>>,
    pub sync_limiter: limits::RateLimiter,
    pub reference_batch_limiter: limits::RateLimiter,
    pub reference_batch_concurrency: Arc<tokio::sync::Semaphore>,
    pub mcp_limiter: limits::RateLimiter,
    pub oauth_limiter: limits::RateLimiter,
    pub test_email_limiter: limits::RateLimiter,
    pub email_transport: Option<Arc<dyn email_worker::EmailTransport>>,
    pub push_transport: Option<Arc<dyn push::PushTransport>>,
    /// In-enclave query embedder (hybrid search). `None` → FTS-only mode
    /// (model not baked/downloaded, or failed to load — never fatal).
    pub embedding: Option<Arc<crate::embedding::EmbeddingEngine>>,
    /// Python-free WeSpeaker voiceprint engine. The production image bakes the
    /// pinned ONNX model; local tests may run without it.
    pub voice: Option<Arc<voice_memory::VoiceEngine>>,
}

impl CpState {
    /// ADR-0022 D4 — the unmigrated-domain gate for a background worker's
    /// per-user pass.
    ///
    /// `true` means `domain` still reaches its rows through the legacy
    /// per-user store and this user's archive is WAL-authoritative, so the
    /// caller must skip that domain. The skip is counted and logged here —
    /// exactly once per call — so a deferral is inert but never silent: on a
    /// `true` the caller makes no provider call, leases nothing, and writes
    /// nothing. Call it once per pass, never once per inner iteration, or the
    /// "exactly one counted skip per pass" contract breaks.
    ///
    /// Gate the deferred domain, not the worker: several of these workers
    /// already route migrated domains through `wal_authoritative_read` /
    /// `wal_authoritative_submit`, and gating one of those off would silently
    /// disable live work.
    pub(crate) fn wal_domain_skipped(&self, user_id: &str, domain: &'static str) -> bool {
        if !self.store.is_wal_authoritative(user_id) {
            return false;
        }
        tracing::warn!(
            user_id,
            metric = crate::error::WAL_DOMAIN_UNMIGRATED_REASON,
            domain,
            "not migrated to WAL; skipping"
        );
        true
    }

    /// ADR-0022 D4 — the same gate on a request path.
    ///
    /// `Some(error)` refuses with the distinguishable 503 that names the
    /// domain; `None` means the legacy path is safe for this user. The
    /// refusal is counted where it becomes a response, so this returns the
    /// error rather than logging it here.
    pub(crate) fn wal_domain_refusal(
        &self,
        user_id: &str,
        domain: &'static str,
    ) -> Option<crate::error::EnclaveError> {
        self.store
            .is_wal_authoritative(user_id)
            .then(|| crate::error::EnclaveError::wal_domain_unmigrated(domain))
    }
}

/// The stable machine-readable reason a failed routed read reports.
pub(crate) const ROUTED_READ_UNAVAILABLE_REASON: &str = "enclave_unavailable";

/// ADR-0022 — **the failure-status rule for the read lane, stated once.**
///
/// > A routed read (`Store::wal_authoritative_read`) that returns `Err` answers
/// > **503 `enclave_unavailable`**.
///
/// A routed read fails for exactly one class of reason: the archive behind it
/// could not be read. For a WAL-authoritative user that is a serving authority
/// that is unregistered, quarantined, or mid-relaunch; for an unselected user
/// it is the guarded legacy load failing. Both are transient and retryable, and
/// 503 is the only status that says so. The three statuses it is deliberately
/// NOT, each of which shipped as a defect on this lane:
///
/// * **200** with an `error` key in the body. Every client that switches on the
///   status before the body reads that as data. `/api/search` did this.
/// * **404**. That is an absence, and the archive is present and merely
///   unreadable — it tells the caller their screenshot does not exist.
///   `/api/screenshot-images/{id}/content` did this.
/// * **500**. That is a fault: it invites a bug report instead of a retry, and
///   it makes a retryable read failure indistinguishable from the genuinely
///   non-retryable failures (a KMS unwrap, an AEAD authentication failure) that
///   keep 500 on purpose.
///
/// The one exception, stated here so it cannot be mistaken for drift: a failure
/// arm that ALSO covers a genuinely non-retryable failure keeps its own status
/// and says why at the call site. In this lane that is
/// `query.rs::rest_screenshot_image_content`'s DEK-load and decrypt arms, which
/// stay 500 because a key that will not unwrap or a blob that will not
/// authenticate is not fixed by retrying.
///
/// `sync.rs::export` is NOT such an exception: it keeps its distinct
/// `export_failed` reason (a client contract) but answers it at 503, because
/// the only thing behind it is the same routed read.
pub(crate) fn routed_read_unavailable(
    context: &'static str,
    error: &crate::error::EnclaveError,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    tracing::error!(error = %error, metric = ROUTED_READ_UNAVAILABLE_REASON, context, "routed read failed");
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::response::Json(serde_json::json!({ "error": ROUTED_READ_UNAVAILABLE_REASON })),
    )
        .into_response()
}

/// Shared harness for the ADR-0022 D4 gate's tests.
///
/// Every gated worker lives in its own module, so its gate test must live
/// there too; this keeps the *state* they all observe in one place, along with
/// the tracing capture that proves "exactly one counted skip per pass".
#[cfg(test)]
pub(crate) mod wal_gate_test_support {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::{BillingEnforcementMode, CpConfig, CpState};
    use crate::store::Store;

    /// A `CpState` over fake KMS/GCS with no transports wired.
    pub(crate) fn state() -> Arc<CpState> {
        let kms = Arc::new(crate::store::tests::FakeKms);
        let gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        Arc::new(CpState {
            store,
            control: Arc::new(super::control_store::ControlStore::new(kms, gcs)),
            billing: Arc::new(super::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(super::billing::RecordingLeaseGates::default()),
            config: Arc::new(CpConfig {
                base_url: "http://localhost:8080".into(),
                jwt_secrets: vec!["test-secret".into()],
                google_desktop_client_id: "desktop".into(),
                google_ios_client_id: "ios".into(),
                google_web_client_id: "web".into(),
                google_web_client_secret: "secret".into(),
                apple_sign_in: None,
                admin_user_ids: Vec::new(),
                signup_limit_per_day: super::control_store::TEST_SIGNUP_LIMIT,
                scheduler_sa_email: None,
                vertex_project: "project".into(),
                vertex_location: "location".into(),
                vertex_model: "model".into(),
                quota_utterances_per_day: 1,
                quota_screenshots_per_day: 1,
                quota_mcp_calls_per_day: 1,
                quota_vertex_output_tokens_per_day: 524_288,
                web_origin: "http://localhost:3000".into(),
                reviewer_auth: None,
                billing_enforcement_mode: BillingEnforcementMode::Enforce,
            }),
            user_verifier: Arc::new(super::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: super::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_limiter: super::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: super::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: super::limits::RateLimiter::new(10.0, 1.0),
            test_email_limiter: super::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
            push_transport: None,
            embedding: None,
            voice: None,
        })
    }

    /// Give `user_id` the durable-terminal WAL-authority selection the gate
    /// keys on. No serving authority is registered, which is deliberate: it
    /// makes EVERY store touch fail, legacy or routed. A gated worker that
    /// still returns `Ok` therefore provably touched no store at all — so it
    /// left nothing leased and nothing half-written.
    pub(crate) fn select_wal_authoritative(store: &Store, user_id: &str) {
        store
            .install_wal_authority_persistence(
                super::control_store::WalAuthoritativePersistenceSelection::for_test(
                    user_id,
                    crate::archive_v3::ArchiveId::from_bytes([0x4d; 16]),
                ),
            )
            .expect("the test selection installs once");
        assert!(
            store.is_wal_authoritative(user_id),
            "the harness must actually select the user"
        );
    }

    /// Make `user_id`'s LEGACY archive unreadable, without selecting them.
    ///
    /// This is the second half of the read lane's failure story. `select_wal_
    /// authoritative` covers a selected user, but a selected user is answered
    /// by the D4 gate before the routed read is ever called — so on its own it
    /// cannot see a failure arm hiding behind a gate. Both blockers found in
    /// the read-lane review lived exactly there: `/api/search` answered 200
    /// with an error body and `/api/screenshot-images/{id}/content` answered a
    /// bare 404, and the gate hid both.
    ///
    /// An unselected user with a corrupt index blob takes the OTHER branch of
    /// `wal_authoritative_read` — the guarded legacy load — and fails in it.
    /// That is the shape of a real transient store fault, and no gate stands
    /// in front of it.
    ///
    /// The helper proves its own sabotage before returning, so a test built on
    /// it can never pass vacuously if the object naming or the load path
    /// changes underneath it.
    pub(crate) async fn make_legacy_archive_unreadable(store: &Store, user_id: &str) {
        // Mirrors `store::gcs_object_name`, which is private. The assertion
        // below is what keeps this honest.
        let index = format!("indexes/{user_id}.db.enc");
        store
            .gcs
            .put_object(
                &index,
                b"not an encrypted sqlite archive",
                "not-base64!!",
                0,
            )
            .await
            .expect("the fake provider accepts the corrupt blob");
        assert!(
            !store.is_wal_authoritative(user_id),
            "this lane must exercise the LEGACY branch, so the user must not be selected"
        );
        let probe = store.with_user(user_id, |_| Ok(())).await;
        assert!(
            probe.is_err(),
            "the sabotage did not bite: {user_id}'s legacy archive still loads, so any test \
             built on this helper would pass vacuously"
        );
    }

    /// Every response key that would make a refusal look like data.
    ///
    /// A refusal must never present as a success, an empty collection, or an
    /// absence — so it must not carry the shape the successful response has,
    /// at any status.
    pub(crate) const DATA_SHAPED_KEYS: &[&str] = &[
        "episodes",
        "episode_count",
        "hidden_count",
        "results",
        "utterances",
        "screenshots",
        "screenshot_images",
        "members",
        "member_count",
        "participant_details",
        "records",
        "next_before",
        "tabs",
        "counts",
        "latest",
        "total_utterances",
        "total_screenshots",
        "capture_events",
        "capture_sessions",
    ];

    /// The read lane's one property: an archive that cannot be read is
    /// answered with a non-2xx that carries no data.
    ///
    /// It deliberately does NOT pin a particular status or reason. Whether the
    /// D4 gate answered (503 `wal_domain_unmigrated`, naming the domain) or
    /// the routed read's own failure arm did (503 `enclave_unavailable`, or
    /// `export_failed`), both are correct answers and the surface is free to
    /// pick. What is never correct is a 2xx, or a body a client can mistake
    /// for an empty archive.
    pub(crate) async fn assert_refuses_without_data(
        label: &str,
        response: axum::response::Response,
    ) {
        let status = response.status();
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            !status.is_success() && !status.is_redirection(),
            "{label} answered {status} for an unreadable archive; a refusal must never present \
             as a success"
        );
        // A 404 is an ABSENCE, and the archive is present and merely
        // unreadable. `/api/screenshot-images/{id}/content` shipped exactly
        // this: `Err(_) => NOT_FOUND`, byte-identical to its genuine-absence
        // arm. "Non-2xx" alone does not catch it, which is the whole reason
        // this assertion names it.
        assert_ne!(
            status,
            axum::http::StatusCode::NOT_FOUND,
            "{label} answered 404 for an unreadable archive; a refusal must never present as an \
             absence"
        );
        assert!(
            !content_type.starts_with("image/"),
            "{label} answered {status} but shipped {content_type}: a refusal must never present \
             as content"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        // A bare status with no body is the other half of the same defect: it
        // is unlogged, has no machine-readable reason, and a client cannot
        // tell it from any other failure. Parsing is an assertion, not a
        // convenience.
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{label} answered {status} with no JSON body; a refusal must carry a \
                 machine-readable reason: {:?}",
                String::from_utf8_lossy(&bytes)
            )
        });
        for key in DATA_SHAPED_KEYS {
            assert!(
                body.get(*key).is_none(),
                "{label} answered {status} but carried a data-shaped `{key}`, which reads as an \
                 empty archive: {body}"
            );
        }
        assert!(
            body.get("error")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|reason| !reason.is_empty()),
            "{label} answered {status} with no `error` reason: {body}"
        );
    }

    #[derive(Clone, Default)]
    pub(crate) struct CapturedEvents(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedEvents {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedEvents {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl CapturedEvents {
        pub(crate) fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("events are utf-8")
        }

        /// How many counted D4 skips name `domain`. The contract is exactly
        /// one per worker pass per user.
        pub(crate) fn skips(&self, domain: &str) -> usize {
            let metric = format!(
                r#""metric":"{}""#,
                crate::error::WAL_DOMAIN_UNMIGRATED_REASON
            );
            let domain = format!(r#""domain":"{domain}""#);
            self.text()
                .lines()
                .filter(|line| line.contains(&metric) && line.contains(&domain))
                .count()
        }

        /// Every counted D4 skip, whatever its domain.
        pub(crate) fn total_skips(&self) -> usize {
            let metric = format!(
                r#""metric":"{}""#,
                crate::error::WAL_DOMAIN_UNMIGRATED_REASON
            );
            self.text()
                .lines()
                .filter(|line| line.contains(&metric))
                .count()
        }
    }

    /// Capture tracing events for as long as the returned guard lives. The
    /// default subscriber is thread-local and `#[tokio::test]` polls on the
    /// calling thread, so an awaited worker pass is captured.
    pub(crate) fn capture_events() -> (CapturedEvents, tracing::subscriber::DefaultGuard) {
        let captured = CapturedEvents::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(captured.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (captured, guard)
    }
}

#[cfg(test)]
mod tests {
    use super::wal_gate_test_support::{capture_events, select_wal_authoritative, state};
    use crate::error::{wal_domain, EnclaveError};

    #[test]
    fn the_worker_gate_is_inert_until_the_user_is_selected_then_counts_one_skip() {
        let state = state();
        let (captured, guard) = capture_events();
        assert!(
            !state.wal_domain_skipped("unselected-user", wal_domain::PUSH_OUTBOX),
            "an unselected user keeps the legacy path"
        );
        assert_eq!(captured.total_skips(), 0, "{}", captured.text());

        select_wal_authoritative(&state.store, "selected-user");
        assert!(state.wal_domain_skipped("selected-user", wal_domain::PUSH_OUTBOX));
        drop(guard);

        assert_eq!(
            captured.skips(wal_domain::PUSH_OUTBOX),
            1,
            "{}",
            captured.text()
        );
        assert_eq!(captured.total_skips(), 1, "{}", captured.text());
        assert!(
            captured.text().contains(r#""user_id":"selected-user""#),
            "the skip must name the user it deferred: {}",
            captured.text()
        );
    }

    #[test]
    fn the_request_gate_refuses_the_named_domain_only_for_a_selected_user() {
        let state = state();
        assert!(state
            .wal_domain_refusal("unselected-user", wal_domain::QUERY_FEED)
            .is_none());

        select_wal_authoritative(&state.store, "selected-user");
        let refusal = state
            .wal_domain_refusal("selected-user", wal_domain::QUERY_FEED)
            .expect("a selected user is refused");
        assert!(matches!(
            refusal,
            EnclaveError::WalDomainUnmigrated(domain) if domain == wal_domain::QUERY_FEED
        ));
    }
}

/// Helper to fetch a secret from GCP Secret Manager at runtime, using the GCE metadata server token.
/// Retries with exponential backoff on failure to handle startup network flakes.
pub async fn fetch_secret_from_manager(secret_id: &str, version: &str) -> Result<String, String> {
    let http = bounded_http_client();
    let project = std::env::var("KMS_PROJECT").map_err(|_| {
        "KMS_PROJECT environment variable must be set to locate GCP secrets".to_string()
    })?;

    // Try fetching the metadata server token with retry/backoff
    let mut token = None;
    let mut backoff = Duration::from_millis(100);
    for attempt in 1..=5 {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
        }
        match http
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .timeout(Duration::from_secs(3))
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(tok_resp) = resp.error_for_status() {
                    if let Ok(parsed) = tok_resp.json::<TokenResponse>().await {
                        token = Some(parsed.access_token);
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Metadata token fetch attempt {} failed: {}", attempt, e);
            }
        }
        tokio::time::sleep(backoff).await;
        backoff *= 2;
    }

    let token = token.ok_or_else(|| {
        "Failed to fetch VM service account metadata token after retries".to_string()
    })?;

    // Try fetching the secret from Secret Manager with retry/backoff
    let url = format!(
        "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/{}:access",
        project, secret_id, version
    );

    #[derive(Deserialize)]
    struct SecretPayload {
        data: String,
    }
    #[derive(Deserialize)]
    struct SecretAccessResponse {
        payload: SecretPayload,
    }

    let mut secret_data = None;
    let mut backoff = Duration::from_millis(100);
    for attempt in 1..=5 {
        match http.get(&url).bearer_auth(&token).send().await {
            Ok(resp) => {
                if let Ok(sec_resp) = resp.error_for_status() {
                    if let Ok(parsed) = sec_resp.json::<SecretAccessResponse>().await {
                        secret_data = Some(parsed.payload.data);
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Secret Manager fetch attempt {} for {} failed: {}",
                    attempt,
                    secret_id,
                    e
                );
            }
        }
        tokio::time::sleep(backoff).await;
        backoff *= 2;
    }

    let raw_b64 = secret_data.ok_or_else(|| {
        format!(
            "Failed to fetch secret {} from Secret Manager after retries",
            secret_id
        )
    })?;

    use base64::Engine as _;
    let decoded_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_b64.trim())
        .map_err(|e| {
            format!(
                "Failed to decode base64 payload for secret {}: {}",
                secret_id, e
            )
        })?;

    let decoded_str = String::from_utf8(decoded_bytes)
        .map_err(|e| format!("Secret {} payload is not valid UTF-8: {}", secret_id, e))?;

    Ok(decoded_str)
}

#[cfg(test)]
mod configuration_tests {
    use super::vertex_model_name_is_billing_safe;

    #[test]
    fn vertex_model_grammar_matches_the_billing_contract() {
        assert!(vertex_model_name_is_billing_safe("gemini-3.5-flash"));
        assert!(vertex_model_name_is_billing_safe("publisher:model_001"));
        assert!(!vertex_model_name_is_billing_safe(
            "publishers/google/model"
        ));
        assert!(!vertex_model_name_is_billing_safe(&"m".repeat(129)));
        assert!(!vertex_model_name_is_billing_safe(""));
    }
}
