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
//! Identity, accounting, work claims, and user-visible structured state live
//! in PostgreSQL behind typed repository ports.

pub mod apple;
pub mod auth;
pub mod billing;
pub mod cors;
pub mod delivery;
pub mod dlp;
pub mod email_renderer;
pub mod email_worker;
pub mod finalizer;
pub mod identity;
pub mod isotime;
pub mod limits;
pub(crate) mod mcp_safety;
pub mod media;
pub mod media_planner;
pub mod media_worker;
pub mod model_usage;
pub mod oauth;
pub mod playback;
pub mod push;
pub mod query;
pub mod reconciler;
pub mod retention;
pub mod screen_understanding;
pub mod summarizer;
pub mod sync;
pub mod tokens;
pub mod vertex;
pub mod voice_eval;
pub mod voice_eval_assets;
pub mod voice_eval_evidence;
pub mod voice_eval_similarity;
pub mod voice_memory;
pub mod voice_quality;
pub mod webhook_worker;

use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OUTBOUND_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The exact configured reviewer identity can create at most one account and
/// must remain available when the public daily signup budget is exhausted.
pub(super) const REVIEWER_SIGNUP_EXEMPT: i64 = i64::MAX;

const REVIEWER_IDENTITY_SUBJECT_PREFIX: &str = "reviewer:identity-platform:";

/// Domain-separate the preconfigured Identity Platform reviewer from ordinary
/// Google subjects before deriving its durable account id.
pub(crate) fn reviewer_identity_subject(uid: &str) -> String {
    format!("{REVIEWER_IDENTITY_SUBJECT_PREFIX}{uid}")
}

/// Content-free observation for a daily signup-budget refusal.
pub(super) fn observe_signup_refused(provider: &'static str, budget: i64) {
    tracing::warn!(
        target: "kioku::signup",
        metric_schema = "signup_v1",
        provider,
        outcome = "refused",
        accounts_today = budget,
        budget,
        "signup refused by the daily budget"
    );
}

pub(crate) fn bounded_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(OUTBOUND_CONNECT_TIMEOUT)
        .timeout(OUTBOUND_REQUEST_TIMEOUT)
        .build()
        .expect("static control-plane HTTP client configuration")
}

/// Control-plane configuration, read from the image-baked environment.
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
    pub vertex_project: String,
    pub vertex_location: String,
    pub vertex_model: String,
    /// Exact optional operator request, retained separately from the resolved
    /// model for rollout evidence.
    pub vertex_reconciliation_model_requested: Option<String>,
    /// Optional stronger model used only for settled memory-topology
    /// reconciliation. Keeping this separate lets operators qualify the
    /// writer without changing the latency-sensitive summarizer model.
    pub vertex_reconciliation_model: String,
    /// Image-baked declaration of the compiled producer contract. When an
    /// explicit reconciliation model is present, startup recomputes and must
    /// exactly match this lowercase SHA-256 label even while the writer is dark.
    pub memory_reconciliation_producer_contract_sha256: Option<String>,
    /// Service-wide ceiling on new accounts per UTC day. Image-baked and
    /// required: signup is open to any verified identity, so this is the only
    /// bound on account creation and it must not have a permissive default.
    pub signup_limit_per_day: i64,
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

impl ReviewerAuthConfig {
    /// The reviewer account id is deterministic, matching the identity upsert
    /// path used by `/oauth/reviewer`.
    pub(crate) fn account_id(&self) -> String {
        tokens::derive_stable_uuid(&reviewer_identity_subject(&self.uid))
    }
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

fn reconciliation_model_from_config(
    requested: Option<String>,
    fallback: &str,
) -> crate::error::Result<(Option<String>, String)> {
    let requested = requested.filter(|value| !value.trim().is_empty());
    let resolved = requested.clone().unwrap_or_else(|| fallback.to_string());
    if !vertex_model_name_is_billing_safe(&resolved) {
        return Err(crate::error::EnclaveError::Config(
            "VERTEX_RECONCILIATION_MODEL must be 1-128 ASCII letters, digits, '.', '_', ':', or '-'"
                .into(),
        ));
    }
    Ok((requested, resolved))
}

fn reviewed_vertex_output_tokens_per_day_from_config(value: &str) -> crate::error::Result<i64> {
    let canonical = !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && !value.starts_with('0');
    let parsed = canonical.then(|| value.parse::<i64>().ok()).flatten();
    if parsed != Some(limits::REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY) {
        return Err(crate::error::EnclaveError::Config(
            "QUOTA_VERTEX_OUTPUT_TOKENS_PER_DAY must be the reviewed canonical daily limit".into(),
        ));
    }
    Ok(limits::REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY)
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
            if parsed < 0 {
                return Err(crate::error::EnclaveError::Config(
                    "SIGNUP_LIMIT_PER_DAY must be non-negative".into(),
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
        let (vertex_reconciliation_model_requested, vertex_reconciliation_model) =
            reconciliation_model_from_config(
                std::env::var("VERTEX_RECONCILIATION_MODEL").ok(),
                &vertex_model,
            )?;
        let producer_contract_sha256 =
            std::env::var("MEMORY_RECONCILIATION_PRODUCER_CONTRACT_SHA256").unwrap_or_default();
        let memory_reconciliation_producer_contract_sha256 = match (
            &vertex_reconciliation_model_requested,
            producer_contract_sha256.as_str(),
        ) {
            (None, "") => None,
            (Some(_), value)
                if value.strip_prefix("sha256:").is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }) =>
            {
                Some(value.to_owned())
            }
            _ => {
                return Err(crate::error::EnclaveError::Config(
                        "VERTEX_RECONCILIATION_MODEL and MEMORY_RECONCILIATION_PRODUCER_CONTRACT_SHA256 must be supplied together with an exact lowercase sha256 label".into(),
                    ));
            }
        };
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
            vertex_project: config_value("VERTEX_PROJECT", "test-project")?,
            vertex_location: config_value("VERTEX_LOCATION", "us-central1")?,
            vertex_model,
            vertex_reconciliation_model_requested,
            vertex_reconciliation_model,
            memory_reconciliation_producer_contract_sha256,
            signup_limit_per_day,
            quota_vertex_output_tokens_per_day: reviewed_vertex_output_tokens_per_day_from_config(
                &config_value("QUOTA_VERTEX_OUTPUT_TOKENS_PER_DAY", "2621440")?,
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

/// Shared state for the control-plane HTTP surface.
pub struct CpState {
    pub(crate) kms: Arc<dyn crate::crypto::KmsClient>,
    pub(crate) durable_recording_storage_bound: bool,
    pub(crate) repositories: crate::persistence::RepositorySet,
    pub billing: Arc<dyn billing::BillingGateway>,
    pub recording_lease_gate: Arc<billing::RecordingLeaseGates>,
    pub config: Arc<CpConfig>,
    pub user_verifier: Arc<auth::UserIdTokenVerifier>,
    pub reviewer_verifier: Option<Arc<auth::ReviewerIdentityVerifier>>,
    pub apple_provider: Option<Arc<apple::AppleIdentityProvider>>,
    pub capture_event_limiter: limits::RateLimiter,
    pub reference_batch_limiter: limits::RateLimiter,
    pub mcp_limiter: limits::RateLimiter,
    pub oauth_limiter: limits::RateLimiter,
    pub test_email_limiter: limits::RateLimiter,
    pub email_transport: Option<Arc<dyn email_worker::EmailTransport>>,
    pub push_transport: Option<Arc<dyn push::PushTransport>>,
    /// In-enclave query embedder (hybrid search). `None` → FTS-only mode
    /// (model not baked/downloaded, or failed to load — never fatal).
    pub embedding: Option<Arc<crate::embedding::EmbeddingEngine>>,
}

/// The stable machine-readable reason a failed PostgreSQL-backed read reports.
pub(crate) const ROUTED_READ_UNAVAILABLE_REASON: &str = "enclave_unavailable";

/// The failure-status rule for the PostgreSQL read lane, stated once.
///
/// A repository read that fails transiently answers **503
/// `enclave_unavailable`**. In particular, it must not answer:
///
/// * **200** with an `error` key in the body. Every client that switches on the
///   status before the body reads that as data. `/api/search` did this.
/// * **404**. That is an absence and would tell the caller their screenshot
///   does not exist when its authoritative row was merely unreadable.
///   `/api/screenshot-images/{id}/content` did this.
/// * **500**. That is a fault: it invites a bug report instead of a retry, and
///   it makes a retryable read failure indistinguishable from genuinely
///   non-retryable corruption (a malformed wrapped key or an AEAD
///   authentication failure), which keeps 500 on purpose. KMS transport and
///   provider outages are retryable and answer 503.
///
/// A failure arm that also covers a genuinely non-retryable failure keeps its
/// own status and documents why at the call site. In this lane that is
/// `query.rs::rest_screenshot_image_content`'s malformed-key and decrypt arms,
/// which stay 500 because malformed wrapping or a blob that will not
/// authenticate is not fixed by retrying; its KMS HTTP/attestation failures
/// use this 503 boundary instead.
///
/// `sync.rs::export` is not such an exception: it keeps its distinct
/// `export_failed` reason (a client contract) but answers it at 503.
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
    use super::{
        reconciliation_model_from_config, reviewed_vertex_output_tokens_per_day_from_config,
        reviewer_identity_subject, vertex_model_name_is_billing_safe, ReviewerAuthConfig,
    };

    #[test]
    fn reconciliation_model_preserves_requested_and_resolved_provenance() {
        let (requested, resolved) = reconciliation_model_from_config(None, "gemini-fast").unwrap();
        assert_eq!(requested, None);
        assert_eq!(resolved, "gemini-fast");

        let (requested, resolved) =
            reconciliation_model_from_config(Some("gemini-strong".into()), "gemini-fast").unwrap();
        assert_eq!(requested.as_deref(), Some("gemini-strong"));
        assert_eq!(resolved, "gemini-strong");
        assert!(reconciliation_model_from_config(Some("bad model".into()), "gemini-fast").is_err());
    }

    #[test]
    fn reviewer_account_id_uses_the_exact_namespaced_identity_derivation() {
        let config = ReviewerAuthConfig {
            api_key: "test-api-key".into(),
            uid: "reviewer_uid".into(),
            email: "reviewer@example.com".into(),
        };
        assert_eq!(
            reviewer_identity_subject(&config.uid),
            "reviewer:identity-platform:reviewer_uid"
        );
        assert_eq!(config.account_id(), "dfc9a6b7-9e79-5b31-97b7-72ec53872984");
    }

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

    #[test]
    fn vertex_daily_quota_is_exact_canonical_and_fail_closed() {
        assert_eq!(
            reviewed_vertex_output_tokens_per_day_from_config("2621440").unwrap(),
            super::limits::REVIEWED_VERTEX_OUTPUT_TOKENS_PER_DAY
        );
        for malformed in [
            "",
            "0",
            "02621440",
            "+2621440",
            "2621440 ",
            " 2621440",
            "2621440.0",
            "1310720",
            "2621441",
            "9223372036854775808",
        ] {
            assert!(
                reviewed_vertex_output_tokens_per_day_from_config(malformed).is_err(),
                "accepted malformed or unreviewed quota {malformed:?}"
            );
        }
    }
}
