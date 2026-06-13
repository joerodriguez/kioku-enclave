//! End-user authentication for the control plane (ports `cloud/src/auth.js`
//! `requireAuth`): accept either one of our own HS256 access tokens, or a Google
//! ID token (device sync / web sign-in) whose `aud` is one of our OAuth client
//! ids. On success the resolved user id is attached as a request extension.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::warn;

use crate::error::{EnclaveError, Result};

use super::{tokens, CpState};

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS: &[&str] = &["https://accounts.google.com", "accounts.google.com"];
const EXP_LEEWAY_SECS: u64 = 30;
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(300);

/// The authenticated user id, attached to the request by [`require_auth`].
#[derive(Clone)]
pub struct AuthUser(pub String);

#[derive(Debug, Deserialize)]
struct UserClaims {
    sub: String,
    email: String,
    #[serde(default)]
    email_verified: bool,
}

struct JwksCache {
    keys: HashMap<String, serde_json::Value>,
    expires: Instant,
}

/// Verifies Google ID tokens for end users (audiences = our OAuth client ids).
pub struct UserIdTokenVerifier {
    http: reqwest::Client,
    audiences: Vec<String>,
    cache: Mutex<Option<JwksCache>>,
}

impl UserIdTokenVerifier {
    pub fn new(audiences: Vec<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            audiences,
            cache: Mutex::new(None),
        }
    }

    /// Returns `(google_sub, email)` on success.
    pub async fn verify(&self, token: &str) -> Result<(String, String)> {
        if self.audiences.is_empty() {
            return Err(EnclaveError::Auth("no Google client ids configured".into()));
        }
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| EnclaveError::Auth(format!("decode header: {e}")))?;
        let kid = header
            .kid
            .ok_or_else(|| EnclaveError::Auth("JWT header missing kid".into()))?;
        let jwk = self.get_jwk(&kid).await?;
        let key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| EnclaveError::Auth(format!("build key: {e}")))?;

        let auds: Vec<&str> = self.audiences.iter().map(|s| s.as_str()).collect();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&auds);
        validation.set_issuer(GOOGLE_ISSUERS);
        validation.leeway = EXP_LEEWAY_SECS;

        let data = jsonwebtoken::decode::<UserClaims>(token, &key, &validation)
            .map_err(|e| EnclaveError::Auth(format!("verify: {e}")))?;
        if !data.claims.email_verified {
            return Err(EnclaveError::Auth("email_verified false".into()));
        }
        Ok((data.claims.sub, data.claims.email))
    }

    async fn get_jwk(&self, kid: &str) -> Result<jsonwebtoken::jwk::Jwk> {
        let mut cache = self.cache.lock().await;
        let refresh = match cache.as_ref() {
            None => true,
            Some(c) => Instant::now() >= c.expires,
        };
        if refresh {
            let resp = self
                .http
                .get(GOOGLE_JWKS_URL)
                .send()
                .await?
                .error_for_status()?;
            let ttl = parse_max_age(resp.headers()).unwrap_or(DEFAULT_JWKS_TTL);
            #[derive(Deserialize)]
            struct Body {
                keys: Vec<serde_json::Value>,
            }
            let body: Body = resp.json().await?;
            let mut keys = HashMap::new();
            for k in body.keys {
                if let Some(kid) = k.get("kid").and_then(|v| v.as_str()) {
                    keys.insert(kid.to_owned(), k);
                }
            }
            *cache = Some(JwksCache {
                keys,
                expires: Instant::now() + ttl,
            });
        }
        let cache = cache.as_ref().expect("populated");
        let v = cache
            .keys
            .get(kid)
            .ok_or_else(|| EnclaveError::Auth(format!("no JWK for kid={kid}")))?;
        serde_json::from_value(v.clone()).map_err(|e| EnclaveError::Auth(format!("parse JWK: {e}")))
    }
}

fn parse_max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
    for part in value.split(',') {
        if let Some(age) = part.trim().strip_prefix("max-age=") {
            if let Ok(secs) = age.trim().parse::<u64>() {
                return Some(Duration::from_secs(secs));
            }
        }
    }
    None
}

/// 401 with the MCP discovery hint, matching the Node behaviour.
fn unauthorized(base_url: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            "WWW-Authenticate",
            format!("Bearer resource_metadata=\"{base_url}/.well-known/oauth-protected-resource\""),
        )],
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

/// axum middleware: resolve the caller to a user id (our JWT, else Google ID
/// token) and attach [`AuthUser`]. 403 if an otherwise-valid Google account is
/// not on the `ALLOWED_EMAILS` list.
pub async fn require_auth(
    State(state): State<Arc<CpState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let base = &state.config.base_url;
    let token = match req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.trim().to_string(),
        None => return unauthorized(base),
    };

    // 1) our own access token (fast, no network)
    if let Ok(user_id) =
        tokens::verify_access_token(&state.config.jwt_secrets, &state.config.base_url, &token)
    {
        req.extensions_mut().insert(AuthUser(user_id));
        return next.run(req).await;
    }

    // 2) Google ID token (device sync / web)
    match state.user_verifier.verify(&token).await {
        Ok((google_sub, email)) => {
            if !state.config.email_allowed(&email) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "forbidden", "error_description": "Account not allowed"})),
                )
                    .into_response();
            }
            match state.control.upsert_user(&google_sub, &email).await {
                Ok(user) => {
                    req.extensions_mut().insert(AuthUser(user.id));
                    next.run(req).await
                }
                Err(e) => {
                    warn!(error = %e, "user upsert failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "server_error"})),
                    )
                        .into_response()
                }
            }
        }
        Err(_) => unauthorized(base),
    }
}
