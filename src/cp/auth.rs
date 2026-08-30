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
use base64::Engine as _;
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
const IDENTITY_PLATFORM_TOKEN_MAX_BYTES: usize = 8192;

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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityPlatformIdentity {
    local_id: String,
    email: String,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    valid_since: Option<String>,
}

#[derive(Deserialize)]
struct IdentityPlatformLookupResponse {
    #[serde(default)]
    users: Vec<IdentityPlatformIdentity>,
}

/// Performs the authenticated Identity Platform account lookup shared by the
/// exact reviewer bridge and the separately gated general password provider.
struct IdentityPlatformTokenLookup {
    http: reqwest::Client,
    api_key: String,
}

impl IdentityPlatformTokenLookup {
    fn new(api_key: String) -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(GOOGLE_CONNECT_TIMEOUT)
                .timeout(GOOGLE_REQUEST_TIMEOUT)
                .build()
                .expect("static Identity Platform HTTP client configuration"),
            api_key,
        }
    }

    async fn lookup(&self, token: &str) -> Result<Vec<IdentityPlatformIdentity>> {
        if token.is_empty() || token.len() > IDENTITY_PLATFORM_TOKEN_MAX_BYTES || !token.is_ascii()
        {
            return Err(EnclaveError::Auth("invalid identity token".into()));
        }
        let mut url =
            reqwest::Url::parse("https://identitytoolkit.googleapis.com/v1/accounts:lookup")
                .expect("static Identity Platform lookup URL");
        url.query_pairs_mut().append_pair("key", &self.api_key);
        let response = self
            .http
            .post(url)
            .json(&serde_json::json!({"idToken": token}))
            .send()
            .await
            .map_err(|_| EnclaveError::Auth("identity provider unavailable".into()))?;
        if !response.status().is_success() {
            return Err(EnclaveError::Auth("identity rejected".into()));
        }
        let lookup: IdentityPlatformLookupResponse = response
            .json()
            .await
            .map_err(|_| EnclaveError::Auth("invalid identity response".into()))?;
        Ok(lookup.users)
    }
}

/// Verifies the short-lived Identity Platform token produced by
/// `kiokuu.com/app/login`. Google performs the signature/account lookup; Kioku
/// then enforces an exact preconfigured UID + email match.
pub struct ReviewerIdentityVerifier {
    lookup: IdentityPlatformTokenLookup,
    config: ReviewerAuthConfig,
}

impl ReviewerIdentityVerifier {
    pub fn new(config: ReviewerAuthConfig) -> Self {
        Self {
            lookup: IdentityPlatformTokenLookup::new(config.api_key.clone()),
            config,
        }
    }

    pub async fn verify(&self, token: &str) -> Result<(String, String)> {
        exact_reviewer_identity(&self.config, self.lookup.lookup(token).await?)
    }
}

fn exact_reviewer_identity(
    config: &ReviewerAuthConfig,
    mut users: Vec<IdentityPlatformIdentity>,
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

#[derive(Debug, Deserialize)]
struct PasswordTokenClaims {
    sub: String,
    aud: String,
    iss: String,
    email: String,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    auth_time: Option<u64>,
    firebase: PasswordFirebaseClaims,
}

#[derive(Debug, Deserialize)]
struct PasswordFirebaseClaims {
    sign_in_provider: String,
    #[serde(default)]
    tenant: Option<String>,
}

fn password_token_claims(token: &str) -> Result<PasswordTokenClaims> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(EnclaveError::Auth("invalid password identity token".into()));
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(parts[1]))
        .map_err(|_| EnclaveError::Auth("invalid password identity token".into()))?;
    serde_json::from_slice(&payload)
        .map_err(|_| EnclaveError::Auth("invalid password identity token".into()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedPasswordIdentity {
    pub(crate) subject: String,
    pub(crate) email: String,
}

fn exact_password_identity(
    token: &str,
    mut users: Vec<IdentityPlatformIdentity>,
    expected_project_id: &str,
    expected_tenant_id: Option<&str>,
    excluded_uid: Option<&str>,
) -> Result<VerifiedPasswordIdentity> {
    if users.len() != 1 {
        return Err(EnclaveError::Auth("password identity rejected".into()));
    }
    let user = users.pop().expect("one password identity");
    let claims = password_token_claims(token)?;
    let email = user.email.trim().to_lowercase();
    let Some(valid_since) = user
        .valid_since
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return Err(EnclaveError::Auth("password identity rejected".into()));
    };
    let Some(authenticated_at) = claims.auth_time else {
        return Err(EnclaveError::Auth("password identity rejected".into()));
    };
    if user.disabled
        || !user.email_verified
        || claims.firebase.sign_in_provider != "password"
        || claims.aud != expected_project_id
        || claims.iss != format!("https://securetoken.google.com/{expected_project_id}")
        || claims.firebase.tenant.as_deref() != expected_tenant_id
        || user.tenant_id.as_deref() != expected_tenant_id
        || authenticated_at < valid_since
        || !claims.email_verified
        || claims.sub != user.local_id
        || excluded_uid.is_some_and(|excluded| excluded == user.local_id)
        || !claims.email.eq_ignore_ascii_case(&user.email)
        || user.local_id.is_empty()
        || user.local_id.len() > 128
        || email.is_empty()
        || email.len() > 254
        || email.matches('@').count() != 1
        || email
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(EnclaveError::Auth("password identity rejected".into()));
    }
    Ok(VerifiedPasswordIdentity {
        subject: qualified_password_subject(
            expected_project_id,
            expected_tenant_id,
            &user.local_id,
        ),
        email,
    })
}

fn qualified_password_subject(project_id: &str, tenant_id: Option<&str>, uid: &str) -> String {
    let encode =
        |value: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes());
    format!(
        "identity-platform:v1:{}:{}:{}",
        encode(project_id),
        encode(tenant_id.unwrap_or_default()),
        encode(uid)
    )
}

/// Verifies an email/password Identity Platform ID token. A successful lookup
/// proves project membership/signature/expiry; the signed JWT claims are then
/// cross-checked so a federated token from the same project cannot be treated
/// as possession of the account password.
pub struct PasswordIdentityVerifier {
    lookup: IdentityPlatformTokenLookup,
    project_id: String,
    tenant_id: Option<String>,
    excluded_uid: Option<String>,
}

impl PasswordIdentityVerifier {
    pub fn new(
        api_key: String,
        project_id: String,
        tenant_id: Option<String>,
        excluded_uid: Option<String>,
    ) -> Self {
        Self {
            lookup: IdentityPlatformTokenLookup::new(api_key),
            project_id,
            tenant_id,
            excluded_uid,
        }
    }

    pub async fn verify(&self, token: &str) -> Result<VerifiedPasswordIdentity> {
        let users = self.lookup.lookup(token).await?;
        exact_password_identity(
            token,
            users,
            &self.project_id,
            self.tenant_id.as_deref(),
            self.excluded_uid.as_deref(),
        )
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod reviewer_tests {
    use super::*;

    fn identity(local_id: &str, email: &str) -> IdentityPlatformIdentity {
        IdentityPlatformIdentity {
            local_id: local_id.into(),
            email: email.into(),
            email_verified: true,
            disabled: false,
            tenant_id: None,
            valid_since: Some("0".into()),
        }
    }

    fn password_token_at(
        subject: &str,
        email: &str,
        email_verified: bool,
        sign_in_provider: &str,
        auth_time: Option<u64>,
    ) -> String {
        password_token_for(
            subject,
            email,
            email_verified,
            sign_in_provider,
            auth_time,
            "kioku-public-auth",
            "https://securetoken.google.com/kioku-public-auth",
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn password_token_for(
        subject: &str,
        email: &str,
        email_verified: bool,
        sign_in_provider: &str,
        auth_time: Option<u64>,
        audience: &str,
        issuer: &str,
        tenant: Option<&str>,
    ) -> String {
        let payload = serde_json::json!({
            "sub": subject,
            "aud": audience,
            "iss": issuer,
            "email": email,
            "email_verified": email_verified,
            "auth_time": auth_time,
            "firebase": {"sign_in_provider": sign_in_provider, "tenant": tenant},
        });
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).expect("serialize password claims"));
        format!("header.{encoded}.signature")
    }

    fn password_token(
        subject: &str,
        email: &str,
        email_verified: bool,
        sign_in_provider: &str,
    ) -> String {
        password_token_at(subject, email, email_verified, sign_in_provider, Some(1))
    }

    fn exact_test_password(
        token: &str,
        users: Vec<IdentityPlatformIdentity>,
    ) -> Result<VerifiedPasswordIdentity> {
        exact_password_identity(
            token,
            users,
            "kioku-public-auth",
            None,
            Some("reviewer_uid"),
        )
    }

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
            vec![identity("reviewer_uid", "Reviewer@Kiokuu.com")],
        )
        .unwrap();
        assert_eq!(
            accepted,
            ("reviewer_uid".into(), "reviewer@kiokuu.com".into())
        );

        for rejected in [
            identity("other", "reviewer@kiokuu.com"),
            identity("reviewer_uid", "other@kiokuu.com"),
            IdentityPlatformIdentity {
                disabled: true,
                ..identity("reviewer_uid", "reviewer@kiokuu.com")
            },
        ] {
            assert!(exact_reviewer_identity(&config(), vec![rejected]).is_err());
        }
    }

    #[test]
    fn password_identity_requires_verified_password_provider_claims() {
        let token = password_token("password_uid", "Person@Example.com", true, "password");
        assert_eq!(
            exact_test_password(&token, vec![identity("password_uid", "person@example.com")])
                .unwrap(),
            VerifiedPasswordIdentity {
                subject: qualified_password_subject("kioku-public-auth", None, "password_uid"),
                email: "person@example.com".into(),
            }
        );

        let rejected_tokens = [
            password_token("other", "person@example.com", true, "password"),
            password_token("password_uid", "other@example.com", true, "password"),
            password_token("password_uid", "person@example.com", false, "password"),
            password_token("password_uid", "person@example.com", true, "google.com"),
            "not-a-jwt".to_string(),
        ];
        for rejected in rejected_tokens {
            assert!(exact_test_password(
                &rejected,
                vec![identity("password_uid", "person@example.com")]
            )
            .is_err());
        }
    }

    #[test]
    fn password_identity_rejects_unverified_disabled_or_ambiguous_lookup() {
        let token = password_token("password_uid", "person@example.com", true, "password");
        let mut unverified = identity("password_uid", "person@example.com");
        unverified.email_verified = false;
        let mut disabled = identity("password_uid", "person@example.com");
        disabled.disabled = true;

        assert!(exact_test_password(&token, vec![unverified]).is_err());
        assert!(exact_test_password(&token, vec![disabled]).is_err());
        assert!(exact_test_password(&token, Vec::new()).is_err());
        assert!(exact_test_password(
            &token,
            vec![
                identity("password_uid", "person@example.com"),
                identity("other", "other@example.com"),
            ]
        )
        .is_err());

        let mut revoked = identity("password_uid", "person@example.com");
        revoked.valid_since = Some("2".into());
        assert!(exact_test_password(&token, vec![revoked]).is_err());
        let mut exact_boundary = identity("password_uid", "person@example.com");
        exact_boundary.valid_since = Some("1".into());
        assert!(exact_test_password(&token, vec![exact_boundary]).is_ok());
        for invalid_boundary in [
            None,
            Some("not-a-timestamp".into()),
            Some("18446744073709551616".into()),
        ] {
            let mut invalid = identity("password_uid", "person@example.com");
            invalid.valid_since = invalid_boundary;
            assert!(exact_test_password(&token, vec![invalid]).is_err());
        }
        assert!(exact_test_password(
            &password_token_at("password_uid", "person@example.com", true, "password", None,),
            vec![identity("password_uid", "person@example.com")],
        )
        .is_err());
    }

    #[test]
    fn password_identity_is_exactly_project_tenant_qualified_and_excludes_reviewer() {
        let default_token = password_token("password_uid", "person@example.com", true, "password");
        assert!(exact_password_identity(
            &default_token,
            vec![identity("password_uid", "person@example.com")],
            "other-project",
            None,
            None,
        )
        .is_err());
        let wrong_issuer = password_token_for(
            "password_uid",
            "person@example.com",
            true,
            "password",
            Some(1),
            "kioku-public-auth",
            "https://securetoken.google.com/other-project",
            None,
        );
        assert!(exact_test_password(
            &wrong_issuer,
            vec![identity("password_uid", "person@example.com")]
        )
        .is_err());
        assert!(exact_test_password(
            &password_token("reviewer_uid", "reviewer@kiokuu.com", true, "password"),
            vec![identity("reviewer_uid", "reviewer@kiokuu.com")],
        )
        .is_err());

        let tenant_token = password_token_for(
            "password_uid",
            "person@example.com",
            true,
            "password",
            Some(1),
            "kioku-public-auth",
            "https://securetoken.google.com/kioku-public-auth",
            Some("public-tenant"),
        );
        let mut tenant_user = identity("password_uid", "person@example.com");
        tenant_user.tenant_id = Some("public-tenant".into());
        let tenant_identity = exact_password_identity(
            &tenant_token,
            vec![tenant_user.clone()],
            "kioku-public-auth",
            Some("public-tenant"),
            None,
        )
        .unwrap();
        assert_eq!(
            tenant_identity.subject,
            qualified_password_subject("kioku-public-auth", Some("public-tenant"), "password_uid")
        );
        assert_ne!(
            tenant_identity.subject,
            qualified_password_subject("kioku-public-auth", None, "password_uid")
        );
        assert!(exact_password_identity(
            &tenant_token,
            vec![tenant_user],
            "kioku-public-auth",
            Some("other-tenant"),
            None,
        )
        .is_err());
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
                        && matches!(
                            status,
                            AccountStatus::DeletionRequested
                                | AccountStatus::Deleting
                                | AccountStatus::Deleted
                        )) =>
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
                    Ok(Some(
                        AccountStatus::DeletionRequested
                        | AccountStatus::Deleting
                        | AccountStatus::Deleted,
                    )) => {
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
                    super::observe_signup_refused("google", state.config.signup_limit_per_day);
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
