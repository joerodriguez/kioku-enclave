use std::time::Duration;

use async_trait::async_trait;

use crate::error::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OAuthClient {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) redirect_uris: Vec<String>,
}

pub(crate) struct OAuthClientDefinition {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) allow_empty_redirect_upgrade: bool,
}

pub(crate) struct OAuthClientRegistrationRequest {
    pub(crate) proposed_id: String,
    pub(crate) name: Option<String>,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) protected_client_ids: [String; 2],
    pub(crate) capacity: i64,
    pub(crate) unused_ttl: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OAuthClientRegistration {
    Existing(String),
    Created(String),
    AtCapacity,
}

pub(crate) struct PendingConsent {
    pub(crate) consent_hash: String,
    pub(crate) account_id: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) ttl: Duration,
}

pub(crate) struct ConsentApproval {
    pub(crate) consent_hash: String,
    pub(crate) authorization_code_hash: String,
    pub(crate) account_id: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) code_ttl: Duration,
}

pub(crate) struct DirectAuthorizationCode {
    pub(crate) authorization_code_hash: String,
    pub(crate) account_id: String,
    pub(crate) client_id: String,
    pub(crate) ttl: Duration,
}

pub(crate) struct AuthorizationCodeExchange {
    pub(crate) authorization_code_hash: String,
    pub(crate) account_id: String,
    pub(crate) client_id: String,
    pub(crate) refresh_token_hash: String,
    pub(crate) refresh_ttl: Duration,
}

pub(crate) struct RefreshTokenRotation {
    pub(crate) old_token_hash: String,
    pub(crate) client_id: String,
    pub(crate) new_token_hash: String,
    pub(crate) refresh_ttl: Duration,
}

pub(crate) struct NativeSessionRefresh {
    pub(crate) account_id: String,
    pub(crate) client: OAuthClientDefinition,
    pub(crate) refresh_token_hash: String,
    pub(crate) refresh_ttl: Duration,
}

/// OAuth client, consent, authorization-code, and refresh-token transactions.
///
/// Token values are generated and signed outside persistence. Only digests
/// cross this boundary, and every consume/replace operation is atomic.
#[async_trait]
pub(crate) trait OAuthRepository: Send + Sync {
    async fn ensure_client(&self, client: OAuthClientDefinition) -> Result<()>;

    async fn register_client(
        &self,
        request: OAuthClientRegistrationRequest,
    ) -> Result<OAuthClientRegistration>;

    async fn client(&self, client_id: &str) -> Result<Option<OAuthClient>>;

    async fn store_pending_consent(&self, consent: PendingConsent) -> Result<bool>;

    async fn approve_consent(&self, approval: ConsentApproval) -> Result<bool>;

    async fn store_direct_authorization_code(&self, code: DirectAuthorizationCode) -> Result<bool>;

    async fn exchange_authorization_code(
        &self,
        exchange: AuthorizationCodeExchange,
    ) -> Result<bool>;

    async fn rotate_refresh_token(&self, rotation: RefreshTokenRotation) -> Result<Option<String>>;

    async fn create_native_session_refresh(&self, session: NativeSessionRefresh) -> Result<()>;
}
