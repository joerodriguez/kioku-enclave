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
pub mod control_store;
pub mod cors;
pub mod delivery;
pub mod dlp;
pub mod email_renderer;
pub mod email_worker;
pub mod finalizer;
pub mod isotime;
pub mod limits;
pub mod mcp_projection;
pub mod mcp_query;
pub(crate) mod mcp_safety;
pub mod media;
pub mod media_planner;
pub mod media_worker;
pub mod oauth;
pub mod query;
pub mod reviewer;
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
    /// Lowercased allow-list. `None` is permitted only in debug test mode.
    pub allowed_emails: Option<Vec<String>>,
    pub scheduler_sa_email: Option<String>,
    pub vertex_project: String,
    pub vertex_location: String,
    pub vertex_model: String,
    pub quota_utterances_per_day: i64,
    pub quota_screenshots_per_day: i64,
    pub quota_mcp_calls_per_day: i64,
    pub quota_vertex_output_tokens_per_day: i64,
    pub web_origin: String,
    /// Optional exact-match Google Identity Platform account used only by the
    /// public plugin-review login page. The password never enters this config.
    pub reviewer_auth: Option<ReviewerAuthConfig>,
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
        let allowed_emails = std::env::var("ALLOWED_EMAILS").ok().and_then(|raw| {
            let list: Vec<String> = raw
                .split(',')
                .map(|e| e.trim().to_lowercase())
                .filter(|e| !e.is_empty())
                .collect();
            if list.is_empty() {
                None
            } else {
                Some(list)
            }
        });

        if !crate::test_mode_enabled() && allowed_emails.is_none() {
            return Err(crate::error::EnclaveError::Config(
                "ALLOWED_EMAILS must contain at least one explicit account".into(),
            ));
        }
        if allowed_emails
            .as_ref()
            .is_some_and(|emails| emails.iter().any(|email| email == "*"))
        {
            return Err(crate::error::EnclaveError::Config(
                "ALLOWED_EMAILS does not permit a wildcard".into(),
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
        ];
        let apple_sign_in = if apple_values.iter().all(String::is_empty) {
            None
        } else if apple_values.iter().any(String::is_empty) {
            return Err(crate::error::EnclaveError::Config(
                "APPLE_TEAM_ID, APPLE_KEY_ID, and APPLE_IOS_CLIENT_ID must be set together".into(),
            ));
        } else {
            let [team_id, key_id, client_id] = apple_values;
            let identifier_valid = |value: &str| {
                value.len() == 10 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
            };
            if !identifier_valid(&team_id)
                || !identifier_valid(&key_id)
                || client_id != "com.kioku.ios"
            {
                return Err(crate::error::EnclaveError::Config(
                    "Sign in with Apple public configuration is invalid".into(),
                ));
            }
            Some(apple::AppleSignInConfig {
                team_id,
                key_id,
                client_id,
            })
        };

        let vertex_model = config_value("VERTEX_MODEL", "gemini-3.5-flash")?;

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
            allowed_emails,
            scheduler_sa_email: std::env::var("SCHEDULER_SA_EMAIL")
                .ok()
                .filter(|s| !s.is_empty()),
            vertex_project: config_value("VERTEX_PROJECT", "test-project")?,
            vertex_location: config_value("VERTEX_LOCATION", "us-central1")?,
            vertex_model,
            quota_utterances_per_day: parse_i64("QUOTA_UTTERANCES_PER_DAY", 50_000)?,
            quota_screenshots_per_day: parse_i64("QUOTA_SCREENSHOTS_PER_DAY", 20_000)?,
            quota_mcp_calls_per_day: parse_i64("QUOTA_MCP_CALLS_PER_DAY", 10_000)?,
            quota_vertex_output_tokens_per_day: parse_i64(
                "QUOTA_VERTEX_OUTPUT_TOKENS_PER_DAY",
                524_288,
            )?,
            web_origin,
            reviewer_auth,
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

    pub fn email_allowed(&self, email: &str) -> bool {
        match &self.allowed_emails {
            None => crate::test_mode_enabled(),
            Some(list) => list.contains(&email.to_lowercase()),
        }
    }
}

/// Shared state for the control-plane HTTP surface. Holds the same `Arc<Store>`
/// as the data plane so MCP/sync call the content handlers in-process.
// mcp_limiter is consumed by the MCP routes, wired in a later commit.
#[allow(dead_code)]
pub struct CpState {
    pub store: Arc<Store>,
    pub control: Arc<control_store::ControlStore>,
    pub config: Arc<CpConfig>,
    pub user_verifier: Arc<auth::UserIdTokenVerifier>,
    pub reviewer_verifier: Option<Arc<auth::ReviewerIdentityVerifier>>,
    pub apple_provider: Option<Arc<apple::AppleIdentityProvider>>,
    pub sync_limiter: limits::RateLimiter,
    pub mcp_limiter: limits::RateLimiter,
    pub oauth_limiter: limits::RateLimiter,
    pub test_email_limiter: limits::RateLimiter,
    pub email_transport: Option<Arc<dyn email_worker::EmailTransport>>,
    /// In-enclave query embedder (hybrid search). `None` → FTS-only mode
    /// (model not baked/downloaded, or failed to load — never fatal).
    pub embedding: Option<Arc<crate::embedding::EmbeddingEngine>>,
    /// Python-free WeSpeaker voiceprint engine. The production image bakes the
    /// pinned ONNX model; local tests may run without it.
    pub voice: Option<Arc<voice_memory::VoiceEngine>>,
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
