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
pub mod isotime;
pub mod limits;
pub mod oauth;
pub mod query;
pub mod summarizer;
pub mod sync;
pub mod tokens;
pub mod vertex;

use std::sync::Arc;

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
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl CpConfig {
    pub fn from_env() -> crate::error::Result<Self> {
        let test_mode = std::env::var("ENCLAVE_TEST_MODE").is_ok();
        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
            if test_mode {
                "test-jwt-secret".to_string()
            } else {
                panic!("JWT_SECRET must be set")
            }
        });
        let mut jwt_secrets = vec![jwt_secret];
        if let Ok(prev) = std::env::var("JWT_SECRET_PREVIOUS") {
            if !prev.is_empty() {
                jwt_secrets.push(prev);
            }
        }

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
            google_web_client_secret: env_or("GOOGLE_WEB_CLIENT_SECRET", ""),
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
}
