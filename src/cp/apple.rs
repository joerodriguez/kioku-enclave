//! Native Sign in with Apple verification and account linking.
//!
//! The iPhone sends both Apple's identity token and single-use authorization
//! code. The enclave verifies the signed identity token (including nonce,
//! issuer, audience, and expiry), exchanges the code directly with Apple, and
//! verifies the returned token before issuing a Kioku session. Apple refresh
//! tokens stay only in the KMS-bound encrypted control database so account
//! deletion can revoke them before identity data is erased.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Router,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use crate::error::{EnclaveError, Result};

use super::auth::AuthUser;
use super::{oauth, tokens, CpState};

const APPLE_ISSUER: &str = "https://appleid.apple.com";
const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
const APPLE_TOKEN_URL: &str = "https://appleid.apple.com/auth/token";
const APPLE_REVOKE_URL: &str = "https://appleid.apple.com/auth/revoke";
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(300);
const EXP_LEEWAY_SECS: u64 = 30;
const MAX_TOKEN_BYTES: usize = 8192;
const MAX_CODE_BYTES: usize = 4096;
const MAX_NONCE_BYTES: usize = 128;

#[derive(Clone)]
pub struct AppleSignInConfig {
    pub team_id: String,
    pub key_id: String,
    pub client_id: String,
}

pub struct AppleIdentityProvider {
    http: reqwest::Client,
    config: AppleSignInConfig,
    signing_key: EncodingKey,
    jwks: Mutex<Option<JwksCache>>,
}

struct JwksCache {
    keys: HashMap<String, serde_json::Value>,
    expires: Instant,
}

#[derive(Debug)]
enum AppleFlowError {
    Rejected,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAppleGrant {
    pub subject: String,
    pub email: String,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Boolish {
    Bool(bool),
    String(String),
}

impl Boolish {
    fn is_true(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::String(value) => value.eq_ignore_ascii_case("true"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AppleIdClaims {
    sub: String,
    email: Option<String>,
    email_verified: Option<Boolish>,
    nonce: Option<String>,
}

#[derive(Deserialize)]
struct AppleTokenResponse {
    id_token: String,
    refresh_token: String,
}

#[derive(Serialize)]
struct AppleClientSecretClaims<'a> {
    iss: &'a str,
    iat: u64,
    exp: u64,
    aud: &'static str,
    sub: &'a str,
}

impl AppleIdentityProvider {
    pub fn new(config: AppleSignInConfig, private_key_pem: &str) -> Result<Self> {
        let signing_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
            .map_err(|_| EnclaveError::Config("invalid Sign in with Apple private key".into()))?;
        Ok(Self {
            http: super::bounded_http_client(),
            config,
            signing_key,
            jwks: Mutex::new(None),
        })
    }

    async fn authenticate(
        &self,
        identity_token: &str,
        authorization_code: &str,
        raw_nonce: &str,
    ) -> std::result::Result<VerifiedAppleGrant, AppleFlowError> {
        validate_request_shape(identity_token, authorization_code, raw_nonce)?;
        let first = self
            .verify_identity_token(identity_token, raw_nonce)
            .await?;
        let exchanged = self.exchange_authorization_code(authorization_code).await?;
        let confirmed = self
            .verify_identity_token(&exchanged.id_token, raw_nonce)
            .await?;
        if confirmed.sub != first.sub {
            return Err(AppleFlowError::Rejected);
        }
        let email = first
            .email
            .or(confirmed.email)
            .map(|value| value.trim().to_lowercase())
            .filter(|value| valid_email(value))
            .ok_or(AppleFlowError::Rejected)?;
        if exchanged.refresh_token.is_empty()
            || exchanged.refresh_token.len() > MAX_TOKEN_BYTES
            || !exchanged.refresh_token.is_ascii()
        {
            return Err(AppleFlowError::Rejected);
        }
        Ok(VerifiedAppleGrant {
            subject: first.sub,
            email,
            refresh_token: exchanged.refresh_token,
        })
    }

    async fn verify_identity_token(
        &self,
        token: &str,
        raw_nonce: &str,
    ) -> std::result::Result<AppleIdClaims, AppleFlowError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| AppleFlowError::Rejected)?;
        if header.alg != Algorithm::RS256 {
            return Err(AppleFlowError::Rejected);
        }
        let kid = header.kid.ok_or(AppleFlowError::Rejected)?;
        let jwk = self.get_jwk(&kid).await?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| AppleFlowError::Rejected)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.set_issuer(&[APPLE_ISSUER]);
        validation.leeway = EXP_LEEWAY_SECS;
        let claims = jsonwebtoken::decode::<AppleIdClaims>(token, &key, &validation)
            .map_err(|_| AppleFlowError::Rejected)?
            .claims;
        if claims.sub.trim().is_empty() || claims.sub.len() > 255 {
            return Err(AppleFlowError::Rejected);
        }
        let expected_nonce = tokens::sha256_hex(raw_nonce);
        if claims.nonce.as_deref() != Some(expected_nonce.as_str()) {
            return Err(AppleFlowError::Rejected);
        }
        if claims.email.is_some() && !claims.email_verified.as_ref().is_some_and(Boolish::is_true) {
            return Err(AppleFlowError::Rejected);
        }
        Ok(claims)
    }

    async fn exchange_authorization_code(
        &self,
        code: &str,
    ) -> std::result::Result<AppleTokenResponse, AppleFlowError> {
        let client_secret = self.client_secret()?;
        let body = serde_urlencoded::to_string([
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
        ])
        .map_err(|_| AppleFlowError::Unavailable)?;
        let response = self
            .http
            .post(APPLE_TOKEN_URL)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|_| AppleFlowError::Unavailable)?;
        if response.status().is_client_error() {
            return Err(AppleFlowError::Rejected);
        }
        if !response.status().is_success() {
            return Err(AppleFlowError::Unavailable);
        }
        response
            .json()
            .await
            .map_err(|_| AppleFlowError::Unavailable)
    }

    pub async fn revoke_refresh_token(&self, refresh_token: &str) -> Result<()> {
        if refresh_token.is_empty()
            || refresh_token.len() > MAX_TOKEN_BYTES
            || !refresh_token.is_ascii()
        {
            return Err(EnclaveError::Auth("invalid Apple refresh token".into()));
        }
        let client_secret = self
            .client_secret()
            .map_err(|_| EnclaveError::Auth("Apple client secret unavailable".into()))?;
        let body = serde_urlencoded::to_string([
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("token", refresh_token),
            ("token_type_hint", "refresh_token"),
        ])
        .map_err(|e| EnclaveError::Auth(format!("encode Apple revocation: {e}")))?;
        let response = self
            .http
            .post(APPLE_REVOKE_URL)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(EnclaveError::Auth(
                "Apple credential revocation rejected".into(),
            ))
        }
    }

    fn client_secret(&self) -> std::result::Result<String, AppleFlowError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AppleFlowError::Unavailable)?
            .as_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.config.key_id.clone());
        jsonwebtoken::encode(
            &header,
            &AppleClientSecretClaims {
                iss: &self.config.team_id,
                iat: now,
                exp: now + 300,
                aud: APPLE_ISSUER,
                sub: &self.config.client_id,
            },
            &self.signing_key,
        )
        .map_err(|_| AppleFlowError::Unavailable)
    }

    async fn get_jwk(
        &self,
        kid: &str,
    ) -> std::result::Result<jsonwebtoken::jwk::Jwk, AppleFlowError> {
        let mut cache = self.jwks.lock().await;
        if cache
            .as_ref()
            .is_none_or(|entry| Instant::now() >= entry.expires || !entry.keys.contains_key(kid))
        {
            let response = self
                .http
                .get(APPLE_JWKS_URL)
                .send()
                .await
                .map_err(|_| AppleFlowError::Unavailable)?;
            if !response.status().is_success() {
                return Err(AppleFlowError::Unavailable);
            }
            let ttl = parse_max_age(response.headers()).unwrap_or(DEFAULT_JWKS_TTL);
            #[derive(Deserialize)]
            struct Body {
                keys: Vec<serde_json::Value>,
            }
            let body: Body = response
                .json()
                .await
                .map_err(|_| AppleFlowError::Unavailable)?;
            let keys = body
                .keys
                .into_iter()
                .filter_map(|key| {
                    let kid = key
                        .get("kid")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)?;
                    Some((kid, key))
                })
                .collect();
            *cache = Some(JwksCache {
                keys,
                expires: Instant::now() + ttl,
            });
        }
        let value = cache
            .as_ref()
            .and_then(|entry| entry.keys.get(kid))
            .ok_or(AppleFlowError::Rejected)?;
        serde_json::from_value(value.clone()).map_err(|_| AppleFlowError::Rejected)
    }
}

#[derive(Deserialize)]
struct AppleAuthorizationBody {
    identity_token: String,
    authorization_code: String,
    nonce: String,
}

pub fn public_router() -> Router<Arc<CpState>> {
    Router::new()
        .route("/oauth/apple/native", post(native_login))
        .layer(DefaultBodyLimit::max(24 * 1024))
}

pub fn authenticated_router() -> Router<Arc<CpState>> {
    Router::new()
        .route("/api/auth/session", get(session))
        .route("/api/auth/apple/link", post(link))
        .layer(DefaultBodyLimit::max(24 * 1024))
}

async fn native_login(
    State(state): State<Arc<CpState>>,
    Json(body): Json<AppleAuthorizationBody>,
) -> Response {
    let Some(provider) = state.apple_provider.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "apple_sign_in_unavailable"})),
        )
            .into_response();
    };
    let grant = match provider
        .authenticate(&body.identity_token, &body.authorization_code, &body.nonce)
        .await
    {
        Ok(grant) => grant,
        Err(AppleFlowError::Rejected) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid_apple_authorization"})),
            )
                .into_response()
        }
        Err(AppleFlowError::Unavailable) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "apple_identity_provider_unavailable"})),
            )
                .into_response()
        }
    };

    let existing = match state.control.identity_user("apple", &grant.subject).await {
        Ok(existing) => existing,
        Err(_) => return server_error(),
    };
    if existing.is_none() && !state.config.email_allowed(&grant.email) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "account_not_allowed"})),
        )
            .into_response();
    }
    let user = match state
        .control
        .upsert_apple_user(&grant.subject, &grant.email, &grant.refresh_token)
        .await
    {
        Ok(user) => user,
        Err(EnclaveError::Auth(_)) | Err(EnclaveError::Conflict(_)) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "account_unavailable"})),
            )
                .into_response()
        }
        Err(_) => return server_error(),
    };
    let (access, refresh) = match oauth::issue_native_session(&state, &user.id).await {
        Ok(tokens) => tokens,
        Err(_) => return server_error(),
    };
    let providers = match state.control.linked_providers(&user.id).await {
        Ok(providers) => providers,
        Err(_) => return server_error(),
    };
    no_store_json(json!({
        "access_token": access,
        "token_type": "bearer",
        "expires_in": 900,
        "refresh_token": refresh,
        "account_id": user.id,
        "email": user.email,
        "provider": "apple",
        "provider_subject": grant.subject,
        "providers": providers,
        "issuer": state.config.base_url,
    }))
}

async fn session(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let email = match state.control.user_email(&user.0).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "account_unavailable"})),
            )
                .into_response()
        }
        Err(_) => return server_error(),
    };
    let providers = match state.control.linked_providers(&user.0).await {
        Ok(providers) => providers,
        Err(_) => return server_error(),
    };
    no_store_json(json!({
        "account_id": user.0,
        "email": email,
        "issuer": state.config.base_url,
        "providers": providers,
    }))
}

async fn link(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<AppleAuthorizationBody>,
) -> Response {
    let Some(provider) = state.apple_provider.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "apple_sign_in_unavailable"})),
        )
            .into_response();
    };
    let grant = match provider
        .authenticate(&body.identity_token, &body.authorization_code, &body.nonce)
        .await
    {
        Ok(grant) => grant,
        Err(AppleFlowError::Rejected) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid_apple_authorization"})),
            )
                .into_response()
        }
        Err(AppleFlowError::Unavailable) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "apple_identity_provider_unavailable"})),
            )
                .into_response()
        }
    };
    match state
        .control
        .link_apple_identity(&user.0, &grant.subject, &grant.email, &grant.refresh_token)
        .await
    {
        Ok(()) => {
            let providers = state
                .control
                .linked_providers(&user.0)
                .await
                .unwrap_or_else(|_| vec!["apple".into()]);
            no_store_json(json!({"linked": true, "providers": providers}))
        }
        Err(EnclaveError::Conflict(_)) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "apple_identity_already_linked"})),
        )
            .into_response(),
        Err(EnclaveError::Auth(_)) => (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "account_unavailable"})),
        )
            .into_response(),
        Err(_) => server_error(),
    }
}

fn validate_request_shape(
    identity_token: &str,
    authorization_code: &str,
    raw_nonce: &str,
) -> std::result::Result<(), AppleFlowError> {
    if identity_token.is_empty()
        || identity_token.len() > MAX_TOKEN_BYTES
        || !identity_token.is_ascii()
        || authorization_code.is_empty()
        || authorization_code.len() > MAX_CODE_BYTES
        || !authorization_code.is_ascii()
        || !(43..=MAX_NONCE_BYTES).contains(&raw_nonce.len())
        || !raw_nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AppleFlowError::Rejected);
    }
    Ok(())
}

fn valid_email(value: &str) -> bool {
    value.len() <= 254
        && value.matches('@').count() == 1
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn parse_max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
    value.split(',').find_map(|part| {
        part.trim()
            .strip_prefix("max-age=")?
            .trim()
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
    })
}

fn no_store_json(value: serde_json::Value) -> Response {
    (
        [
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
            ("X-Content-Type-Options", "nosniff"),
        ],
        Json(value),
    )
        .into_response()
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "server_error"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shape_requires_bounded_urlsafe_nonce_and_both_apple_credentials() {
        let nonce = "a".repeat(43);
        assert!(validate_request_shape("a.b.c", "code", &nonce).is_ok());
        assert!(validate_request_shape("", "code", &nonce).is_err());
        assert!(validate_request_shape("a.b.c", "", &nonce).is_err());
        assert!(validate_request_shape("a.b.c", "code", "short").is_err());
        assert!(validate_request_shape("a.b.c", "code", &format!("{}!", "a".repeat(42))).is_err());
    }

    #[test]
    fn apple_email_validation_accepts_private_relay_without_special_casing() {
        assert!(valid_email("opaque@privaterelay.appleid.com"));
        assert!(!valid_email("not an email"));
        assert!(!valid_email("two@@example.com"));
    }

    #[test]
    fn boolish_email_verification_is_strict() {
        assert!(Boolish::Bool(true).is_true());
        assert!(Boolish::String("true".into()).is_true());
        assert!(!Boolish::String("false".into()).is_true());
    }
}
