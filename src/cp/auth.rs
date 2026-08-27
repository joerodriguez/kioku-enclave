//! End-user authentication for the control plane: accept either one of our own
//! HS256 access tokens, or a Google
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
use crate::persistence::AccountStatus;

use super::{tokens, CpState, ReviewerAuthConfig};

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS: &[&str] = &["https://accounts.google.com", "accounts.google.com"];
const EXP_LEEWAY_SECS: u64 = 30;
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(300);
const GOOGLE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GOOGLE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const REVIEWER_TOKEN_MAX_BYTES: usize = 8192;

/// The authenticated user id, attached to the request by [`require_auth`].
#[derive(Clone)]
pub struct AuthUser(pub String);

#[derive(Debug, Deserialize)]
struct UserClaims {
    sub: String,
    email: String,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    auth_time: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthCredentialKind {
    KiokuAccessToken,
    GoogleIdToken,
}

/// Content-free authentication evidence attached alongside [`AuthUser`].
/// Ordinary access tokens deliberately do not satisfy destructive step-up;
/// callers must present a freshly issued provider identity token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthEvidence {
    pub(crate) kind: AuthCredentialKind,
    pub(crate) authenticated_at_epoch_seconds: Option<u64>,
}

impl AuthEvidence {
    pub(crate) fn is_recent_provider_auth(self, max_age: Duration) -> bool {
        if self.kind != AuthCredentialKind::GoogleIdToken {
            return false;
        }
        let Some(authenticated_at) = self.authenticated_at_epoch_seconds else {
            return false;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        authenticated_at <= now.saturating_add(EXP_LEEWAY_SECS)
            && now.saturating_sub(authenticated_at) <= max_age.as_secs()
    }
}

struct VerifiedUserToken {
    subject: String,
    email: String,
    authenticated_at_epoch_seconds: Option<u64>,
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
            http: reqwest::Client::builder()
                .connect_timeout(GOOGLE_CONNECT_TIMEOUT)
                .timeout(GOOGLE_REQUEST_TIMEOUT)
                .build()
                .expect("static Google JWKS HTTP client configuration"),
            audiences,
            cache: Mutex::new(None),
        }
    }

    /// Returns `(google_sub, email)` on success.
    pub async fn verify(&self, token: &str) -> Result<(String, String)> {
        let verified = self.verify_with_evidence(token).await?;
        Ok((verified.subject, verified.email))
    }

    async fn verify_with_evidence(&self, token: &str) -> Result<VerifiedUserToken> {
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
        Ok(VerifiedUserToken {
            subject: data.claims.sub,
            email: data.claims.email,
            authenticated_at_epoch_seconds: data.claims.auth_time.or(data.claims.iat),
        })
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReviewerIdentity {
    local_id: String,
    email: String,
    #[serde(default)]
    disabled: bool,
}

#[derive(Deserialize)]
struct ReviewerLookupResponse {
    #[serde(default)]
    users: Vec<ReviewerIdentity>,
}

/// Verifies the short-lived Identity Platform token produced by
/// `kiokuu.com/app/login`. Google performs the signature/account lookup; Kioku
/// then enforces an exact preconfigured UID + email match.
pub struct ReviewerIdentityVerifier {
    http: reqwest::Client,
    config: ReviewerAuthConfig,
}

impl ReviewerIdentityVerifier {
    pub fn new(config: ReviewerAuthConfig) -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(GOOGLE_CONNECT_TIMEOUT)
                .timeout(GOOGLE_REQUEST_TIMEOUT)
                .build()
                .expect("static reviewer identity HTTP client configuration"),
            config,
        }
    }

    pub async fn verify(&self, token: &str) -> Result<(String, String)> {
        if token.is_empty() || token.len() > REVIEWER_TOKEN_MAX_BYTES || !token.is_ascii() {
            return Err(EnclaveError::Auth("invalid reviewer identity token".into()));
        }
        let mut url =
            reqwest::Url::parse("https://identitytoolkit.googleapis.com/v1/accounts:lookup")
                .expect("static Identity Platform lookup URL");
        url.query_pairs_mut()
            .append_pair("key", &self.config.api_key);
        let response = self
            .http
            .post(url)
            .json(&serde_json::json!({"idToken": token}))
            .send()
            .await
            .map_err(|_| EnclaveError::Auth("review identity provider unavailable".into()))?;
        if !response.status().is_success() {
            return Err(EnclaveError::Auth("review identity rejected".into()));
        }
        let lookup: ReviewerLookupResponse = response
            .json()
            .await
            .map_err(|_| EnclaveError::Auth("invalid review identity response".into()))?;
        exact_reviewer_identity(&self.config, lookup.users)
    }
}

fn exact_reviewer_identity(
    config: &ReviewerAuthConfig,
    mut users: Vec<ReviewerIdentity>,
) -> Result<(String, String)> {
    if users.len() != 1 {
        return Err(EnclaveError::Auth("review identity rejected".into()));
    }
    let user = users.pop().expect("one reviewer identity");
    if user.disabled
        || user.local_id != config.uid
        || !user.email.eq_ignore_ascii_case(&config.email)
    {
        return Err(EnclaveError::Auth("review identity rejected".into()));
    }
    Ok((user.local_id, user.email.to_lowercase()))
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod reviewer_tests {
    use super::*;

    fn config() -> ReviewerAuthConfig {
        ReviewerAuthConfig {
            api_key: "public-api-key".into(),
            uid: "reviewer_uid".into(),
            email: "reviewer@kiokuu.com".into(),
        }
    }

    #[test]
    fn reviewer_identity_requires_exact_enabled_account() {
        let accepted = exact_reviewer_identity(
            &config(),
            vec![ReviewerIdentity {
                local_id: "reviewer_uid".into(),
                email: "Reviewer@Kiokuu.com".into(),
                disabled: false,
            }],
        )
        .unwrap();
        assert_eq!(
            accepted,
            ("reviewer_uid".into(), "reviewer@kiokuu.com".into())
        );

        for rejected in [
            ReviewerIdentity {
                local_id: "other".into(),
                email: "reviewer@kiokuu.com".into(),
                disabled: false,
            },
            ReviewerIdentity {
                local_id: "reviewer_uid".into(),
                email: "other@kiokuu.com".into(),
                disabled: false,
            },
            ReviewerIdentity {
                local_id: "reviewer_uid".into(),
                email: "reviewer@kiokuu.com".into(),
                disabled: true,
            },
        ] {
            assert!(exact_reviewer_identity(&config(), vec![rejected]).is_err());
        }
    }

    #[test]
    fn only_delete_and_status_routes_accept_tombstoned_authentication() {
        use axum::http::Method;

        assert!(deletion_status_access(&Method::DELETE, "/api/account"));
        assert!(deletion_status_access(
            &Method::GET,
            "/api/account/deletion"
        ));
        assert!(!deletion_status_access(&Method::GET, "/api/account"));
        assert!(!deletion_status_access(
            &Method::POST,
            "/api/account/deletion"
        ));
        assert!(!deletion_status_access(&Method::GET, "/api/export"));
    }
}

/// 401 with the MCP discovery hint, matching the Node behaviour.
fn unauthorized(base_url: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            "WWW-Authenticate",
            format!(
                "Bearer resource_metadata=\"{base_url}/.well-known/oauth-protected-resource\", scope=\"kioku:read\""
            ),
        )],
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

fn unavailable_account() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "forbidden",
            "error_description": "Account is unavailable",
        })),
    )
        .into_response()
}

/// Today's service-wide signup budget is spent. This refuses account creation
/// only; every existing account keeps working.
fn signup_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": "signup_limit_reached",
            "error_description": "Kioku is accepting a limited number of new accounts per day. Please try again tomorrow."
        })),
    )
        .into_response()
}

fn auth_store_error() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "temporarily_unavailable"})),
    )
        .into_response()
}

fn deletion_status_access(method: &axum::http::Method, path: &str) -> bool {
    (*method == axum::http::Method::DELETE && path == "/api/account")
        || (*method == axum::http::Method::GET && path == "/api/account/deletion")
}

/// axum middleware: resolve the caller to a user id (our JWT, else Google ID
/// token) and attach [`AuthUser`]. Any account Google verifies is accepted;
/// sign-up is open.
pub async fn require_auth(
    State(state): State<Arc<CpState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let base = &state.config.base_url;
    let deletion_status_access = deletion_status_access(req.method(), req.uri().path());
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
    if let Ok((user_id, issued_at)) = tokens::verify_access_token_with_issued_at(
        &state.config.jwt_secrets,
        &state.config.base_url,
        &token,
    ) {
        match state
            .repositories
            .identity_sessions()
            .account_status(&user_id)
            .await
        {
            Ok(Some(status))
                if status == AccountStatus::Active
                    || (deletion_status_access
                        && matches!(status, AccountStatus::Deleting | AccountStatus::Deleted)) =>
            {
                req.extensions_mut().insert(AuthUser(user_id));
                req.extensions_mut().insert(AuthEvidence {
                    kind: AuthCredentialKind::KiokuAccessToken,
                    authenticated_at_epoch_seconds: issued_at,
                });
                return next.run(req).await;
            }
            Ok(_) => return unavailable_account(),
            Err(e) => {
                warn!(error = %e, "account-status lookup failed");
                return auth_store_error();
            }
        }
    }

    // 2) Google ID token (device sync / web)
    match state.user_verifier.verify_with_evidence(&token).await {
        Ok(verified) => {
            let google_sub = verified.subject;
            let email = verified.email;
            let evidence = AuthEvidence {
                kind: AuthCredentialKind::GoogleIdToken,
                authenticated_at_epoch_seconds: verified.authenticated_at_epoch_seconds,
            };
            if deletion_status_access {
                let user_id = tokens::derive_stable_uuid(&google_sub);
                match state
                    .repositories
                    .identity_sessions()
                    .account_status(&user_id)
                    .await
                {
                    Ok(Some(AccountStatus::Deleting | AccountStatus::Deleted)) => {
                        req.extensions_mut().insert(AuthUser(user_id));
                        req.extensions_mut().insert(evidence);
                        return next.run(req).await;
                    }
                    Ok(Some(AccountStatus::Active)) => {}
                    Ok(_) => return unavailable_account(),
                    Err(e) => {
                        warn!(error = %e, "account-status lookup failed");
                        return auth_store_error();
                    }
                }
            }
            match state
                .repositories
                .identity_sessions()
                .upsert_subject_account(&google_sub, &email, state.config.signup_limit_per_day)
                .await
            {
                Ok(user) => {
                    req.extensions_mut().insert(AuthUser(user.id));
                    req.extensions_mut().insert(evidence);
                    next.run(req).await
                }
                Err(EnclaveError::SignupLimited) => {
                    super::control_store::observe_signup_refused(
                        "google",
                        state.config.signup_limit_per_day,
                    );
                    signup_limited()
                }
                Err(EnclaveError::Auth(_)) => unavailable_account(),
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
