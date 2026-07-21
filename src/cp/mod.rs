//! In-enclave control plane (ADR-0001).
//!
//! This module subsumes what used to be the Node Cloud Run service (`cloud/`):
//! OAuth 2.1 + Dynamic Client Registration, device→cloud sync, the MCP server,
//! account export/delete, per-user quotas, and the LLM episode summarizer. It
//! runs inside the same attested binary as the data plane, so the code that
//! terminates TLS and first touches request plaintext is the open-source,
//! reproducibly-built enclave — not an un-attested proxy.
//!
//! Identity + accounting live in [`control_store`] (an encrypted SQLite blob in
//! GCS), replacing Cloud SQL Postgres. There is no Node.js anywhere in the system.

pub mod auth;
pub mod control_store;
pub mod cors;
pub mod isotime;
pub mod limits;
pub mod oauth;
pub mod email_worker;
pub mod finalizer;
pub mod query;
pub mod summarizer;
pub mod sync;
pub mod tokens;
pub mod vertex;

use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use crate::store::Store;

/// Control-plane configuration, read from the (image-baked) environment.
// Some fields (vertex_*, scheduler_sa_email) are consumed by the summarizer,
// wired in a later commit of this same change.
#[allow(dead_code)]
pub struct CpConfig {
    pub base_url: String,
    /// JWT signing secrets: current first, then rotation-fallback(s).
    pub jwt_secrets: Vec<String>,
    pub google_desktop_client_id: String,
    pub google_web_client_id: String,
    pub google_web_client_secret: String,
    /// `None` = allow any Google account; `Some` = allow-list (lowercased).
    pub allowed_emails: Option<Vec<String>>,
    pub scheduler_sa_email: Option<String>,
    pub vertex_project: String,
    pub vertex_location: String,
    pub vertex_model: String,
    pub quota_utterances_per_day: i64,
    pub quota_screenshots_per_day: i64,
    pub quota_mcp_calls_per_day: i64,
    pub web_origin: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
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

        let parse_i64 = |k: &str, d: i64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };

        Ok(Self {
            base_url: env_or("BASE_URL", "http://localhost:8080")
                .trim_end_matches('/')
                .to_string(),
            jwt_secrets,
            google_desktop_client_id: env_or("GOOGLE_DESKTOP_CLIENT_ID", ""),
            google_web_client_id: env_or("GOOGLE_WEB_CLIENT_ID", ""),
            google_web_client_secret,
            allowed_emails,
            scheduler_sa_email: std::env::var("SCHEDULER_SA_EMAIL")
                .ok()
                .filter(|s| !s.is_empty()),
            vertex_project: env_or("VERTEX_PROJECT", ""),
            vertex_location: env_or("VERTEX_LOCATION", "us-central1"),
            vertex_model: env_or("VERTEX_MODEL", "gemini-2.5-flash"),
            quota_utterances_per_day: parse_i64("QUOTA_UTTERANCES_PER_DAY", 50_000),
            quota_screenshots_per_day: parse_i64("QUOTA_SCREENSHOTS_PER_DAY", 20_000),
            quota_mcp_calls_per_day: parse_i64("QUOTA_MCP_CALLS_PER_DAY", 10_000),
            web_origin: env_or("WEB_ORIGIN", "https://kiokuu.com")
                .trim_end_matches('/')
                .to_string(),
        })
    }

    /// Google ID-token audiences accepted for end-user (device + web) sign-in.
    pub fn user_audiences(&self) -> Vec<String> {
        [&self.google_desktop_client_id, &self.google_web_client_id]
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    pub fn email_allowed(&self, email: &str) -> bool {
        match &self.allowed_emails {
            None => true,
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
    pub sync_limiter: limits::RateLimiter,
    pub mcp_limiter: limits::RateLimiter,
    pub attestation_cache: Option<Arc<crate::attestation::AttestationCache>>,
    pub cert_fingerprint: Option<String>,
    /// In-enclave query embedder (hybrid search). `None` → FTS-only mode
    /// (model not baked/downloaded, or failed to load — never fatal).
    pub embedding: Option<Arc<crate::embedding::EmbeddingEngine>>,
}

/// Helper to fetch a secret from GCP Secret Manager at runtime, using the GCE metadata server token.
/// Retries with exponential backoff on failure to handle startup network flakes.
pub async fn fetch_secret_from_manager(secret_id: &str, version: &str) -> Result<String, String> {
    let http = reqwest::Client::new();
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
