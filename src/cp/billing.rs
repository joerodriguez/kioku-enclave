//! Narrow, content-free external-control-plane port for entitlement admission,
//! inference telemetry, owner-only account economics, and deletion detach.
//! Merchant and catalog implementations are deliberately outside this crate.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    extract::{Query, State},
    http::{header::CACHE_CONTROL, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Router,
};
use base64::Engine as _;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::error::EnclaveError;

use super::{auth::AuthUser, control_store::RetainedAccountMetrics, CpState};

const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_ID_TOKEN_BYTES: usize = 32 * 1024;
const ID_TOKEN_REFRESH_SKEW_SECS: u64 = 60;
const RECORDING_LEASE_SECONDS: i64 = 60;
// A source segment may begin just before a one-minute billing lease rolls and
// finish at the capture hard cap. The signed retention authority therefore
// distinguishes the last permitted *start* from the last permitted *end*.
// This does not extend billing authority: the ordinary lease check remains
// independent and the current server policy epoch is revalidated at ingest.
const RECORDING_RETENTION_SEGMENT_TAIL_MILLIS: i64 = 125_000;
const RECORDING_LEASE_RENEWAL_HEADROOM_MS: i64 = 20_000;
// Clients schedule renewal from the server-authored absolute expiry using their
// local wall clock. Permit a small positive client/server skew without turning
// the already-paid recording off at the exact 20-second boundary. A successful
// renewal still reserves exactly one minute and extends from the prior expiry,
// so this tolerance cannot create overlapping or unmetered recording time.
const RECORDING_LEASE_RENEWAL_CLOCK_SKEW_MS: i64 = 5_000;

pub struct RecordingLeaseGates {
    by_user: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    limiter: super::limits::RateLimiter,
}

impl Default for RecordingLeaseGates {
    fn default() -> Self {
        Self {
            by_user: tokio::sync::Mutex::new(HashMap::new()),
            // Normal clients renew at most once per minute. This burst/refill
            // permits recovery retries while bounding shared-control writes.
            limiter: super::limits::RateLimiter::new(6.0, 0.1),
        }
    }
}

impl RecordingLeaseGates {
    async fn lock(&self, user_id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let gate = {
            let mut gates = self.by_user.lock().await;
            Arc::clone(
                gates
                    .entry(user_id.to_string())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        gate.lock_owned().await
    }

    async fn allow(&self, user_id: &str) -> bool {
        self.limiter.consume(user_id).await
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VertexUsageEvent {
    pub account_id: String,
    pub event_id: String,
    pub operation: String,
    pub requested_model: String,
    pub returned_model: Option<String>,
    pub location: String,
    pub traffic_type: String,
    pub outcome: String,
    pub http_status: Option<u16>,
    pub prompt_tokens: Option<u64>,
    pub input_text_tokens: Option<u64>,
    pub input_audio_tokens: Option<u64>,
    pub input_image_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub cached_input_text_tokens: Option<u64>,
    pub cached_input_audio_tokens: Option<u64>,
    pub cached_input_image_tokens: Option<u64>,
    pub output_text_tokens: Option<u64>,
    pub thought_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub observed_at: String,
}

#[derive(Debug, Serialize)]
struct VertexUsageBatchRequest<'a> {
    events: &'a [VertexUsageEvent],
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct VertexUsageBatchResponse {
    pub accepted: usize,
    pub duplicates: usize,
    pub unpriced: usize,
    pub ambiguous: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VertexCoverageSnapshot {
    pub account_id: String,
    pub period: String,
    pub sequence: u64,
    pub pending_events: u64,
    pub lost_events: u64,
    pub observed_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct VertexCoverageResponse {
    pub accepted: bool,
    pub duplicate: bool,
    pub stale: bool,
}

impl VertexCoverageResponse {
    pub fn acknowledged(&self) -> bool {
        !self.stale && usize::from(self.accepted) + usize::from(self.duplicate) == 1
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UsageAuthorizeRequest {
    pub account_id: String,
    pub event_id: String,
    pub meter: &'static str,
    pub quantity_seconds: i64,
    pub observed_at: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UsageAuthorizeResponse {
    pub decision: String,
    pub reason: Option<String>,
    #[allow(dead_code)]
    pub duplicate: bool,
    pub summary: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckoutRequest {
    pub plan_id: String,
    pub interval: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingLeaseRequest {
    pub request_id: String,
    pub lease_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineRecordingUsageRequest {
    pub request_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UrlResponse {
    pub url: String,
}

impl VertexUsageBatchResponse {
    pub fn accounts_for(&self, count: usize) -> bool {
        self.accepted.checked_add(self.duplicates) == Some(count)
            && self.unpriced <= self.accepted
            && self.ambiguous <= self.accepted
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct DetachResponse {
    pub detached: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum BillingError {
    #[error("external control plane unavailable")]
    Unavailable,
    #[error("external control plane rejected request with status {0}")]
    Rejected(u16),
    #[error("external control plane returned an invalid response")]
    InvalidResponse,
}

#[async_trait]
pub trait BillingGateway: Send + Sync {
    async fn summary(&self, account_id: &str) -> Result<Value, BillingError>;
    async fn authorize(
        &self,
        request: &UsageAuthorizeRequest,
    ) -> Result<UsageAuthorizeResponse, BillingError>;
    async fn checkout(
        &self,
        account_id: &str,
        request: &CheckoutRequest,
    ) -> Result<UrlResponse, BillingError>;
    async fn portal(&self, account_id: &str) -> Result<UrlResponse, BillingError>;
    async fn report_vertex_usage(
        &self,
        events: &[VertexUsageEvent],
    ) -> Result<VertexUsageBatchResponse, BillingError>;
    async fn report_vertex_coverage(
        &self,
        snapshot: &VertexCoverageSnapshot,
    ) -> Result<VertexCoverageResponse, BillingError>;
    async fn admin_margin(
        &self,
        month: &str,
        limit: u8,
        after: Option<&str>,
    ) -> Result<Value, BillingError>;
    async fn detach(&self, account_id: &str) -> Result<DetachResponse, BillingError>;
}

pub struct HttpBillingGateway {
    http: reqwest::Client,
    base_url: String,
    audience: String,
    test_bearer: Option<String>,
    identity_token: tokio::sync::Mutex<Option<CachedIdentityToken>>,
}

#[derive(Clone)]
struct CachedIdentityToken {
    token: String,
    expires_at: u64,
}

impl HttpBillingGateway {
    pub fn from_env() -> Result<Self, String> {
        let base_url = required_env("BILLING_SERVICE_URL", "http://localhost:9090")?;
        let parsed = reqwest::Url::parse(&base_url)
            .map_err(|error| format!("BILLING_SERVICE_URL is invalid: {error}"))?;
        let origin_only = (parsed.path().is_empty() || parsed.path() == "/")
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.username().is_empty()
            && parsed.password().is_none();
        if parsed.host_str().is_none()
            || !origin_only
            || (!crate::test_mode_enabled() && parsed.scheme() != "https")
        {
            return Err(
                "BILLING_SERVICE_URL must be an HTTPS origin without credentials or a path".into(),
            );
        }
        let audience = required_env("BILLING_SERVICE_AUDIENCE", &base_url)?;
        if audience != base_url.trim_end_matches('/') {
            return Err("BILLING_SERVICE_AUDIENCE must exactly match BILLING_SERVICE_URL".into());
        }
        Ok(Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| format!("failed to build billing client: {error}"))?,
            base_url: base_url.trim_end_matches('/').to_string(),
            audience,
            test_bearer: crate::test_mode_enabled().then(|| {
                std::env::var("BILLING_TEST_BEARER").unwrap_or_else(|_| "test-billing-token".into())
            }),
            identity_token: tokio::sync::Mutex::new(None),
        })
    }

    async fn bearer_token(&self) -> Result<String, BillingError> {
        if let Some(token) = &self.test_bearer {
            return Ok(token.clone());
        }
        let mut cached = self.identity_token.lock().await;
        let now = epoch_seconds();
        if let Some(token) = cached
            .as_ref()
            .filter(|token| now.saturating_add(ID_TOKEN_REFRESH_SKEW_SECS) < token.expires_at)
        {
            return Ok(token.token.clone());
        }
        let url = format!(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={}&format=full",
            urlencoding::encode(&self.audience)
        );
        let response = self
            .http
            .get(url)
            .header("Metadata-Flavor", "Google")
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|_| BillingError::Unavailable)?
            .error_for_status()
            .map_err(|_| BillingError::Unavailable)?;
        let bytes = read_limited(response, MAX_ID_TOKEN_BYTES).await?;
        let token = std::str::from_utf8(&bytes)
            .map_err(|_| BillingError::InvalidResponse)?
            .trim()
            .to_string();
        let expires_at = jwt_exp(&token)?;
        if epoch_seconds().saturating_add(ID_TOKEN_REFRESH_SKEW_SECS) >= expires_at {
            return Err(BillingError::InvalidResponse);
        }
        *cached = Some(CachedIdentityToken {
            token: token.clone(),
            expires_at,
        });
        Ok(token)
    }

    async fn send<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, BillingError> {
        let response = request
            .bearer_auth(self.bearer_token().await?)
            .send()
            .await
            .map_err(|_| BillingError::Unavailable)?;
        let status = response.status();
        if !status.is_success() {
            return if status.is_server_error() {
                Err(BillingError::Unavailable)
            } else {
                Err(BillingError::Rejected(status.as_u16()))
            };
        }
        let bytes = read_limited(response, MAX_RESPONSE_BYTES).await?;
        serde_json::from_slice(&bytes).map_err(|_| BillingError::InvalidResponse)
    }
}

#[async_trait]
impl BillingGateway for HttpBillingGateway {
    async fn summary(&self, account_id: &str) -> Result<Value, BillingError> {
        self.send(self.http.get(format!(
            "{}/internal/v1/accounts/{}/summary",
            self.base_url,
            urlencoding::encode(account_id)
        )))
        .await
    }

    async fn authorize(
        &self,
        request: &UsageAuthorizeRequest,
    ) -> Result<UsageAuthorizeResponse, BillingError> {
        self.send(
            self.http
                .post(format!("{}/internal/v1/usage/authorize", self.base_url))
                .json(request),
        )
        .await
    }

    async fn checkout(
        &self,
        account_id: &str,
        request: &CheckoutRequest,
    ) -> Result<UrlResponse, BillingError> {
        self.send(
            self.http
                .post(format!(
                    "{}/internal/v1/accounts/{}/checkout",
                    self.base_url,
                    urlencoding::encode(account_id)
                ))
                .json(request),
        )
        .await
    }

    async fn portal(&self, account_id: &str) -> Result<UrlResponse, BillingError> {
        self.send(
            self.http
                .post(format!(
                    "{}/internal/v1/accounts/{}/portal",
                    self.base_url,
                    urlencoding::encode(account_id)
                ))
                .json(&serde_json::json!({})),
        )
        .await
    }

    async fn report_vertex_usage(
        &self,
        events: &[VertexUsageEvent],
    ) -> Result<VertexUsageBatchResponse, BillingError> {
        if events.is_empty() || events.len() > 100 {
            return Err(BillingError::InvalidResponse);
        }
        self.send(
            self.http
                .post(format!("{}/internal/v1/vertex-usage/batch", self.base_url))
                .json(&VertexUsageBatchRequest { events }),
        )
        .await
    }

    async fn report_vertex_coverage(
        &self,
        snapshot: &VertexCoverageSnapshot,
    ) -> Result<VertexCoverageResponse, BillingError> {
        self.send(
            self.http
                .post(format!(
                    "{}/internal/v1/vertex-usage/coverage",
                    self.base_url
                ))
                .json(snapshot),
        )
        .await
    }

    async fn admin_margin(
        &self,
        month: &str,
        limit: u8,
        after: Option<&str>,
    ) -> Result<Value, BillingError> {
        let mut request = self
            .http
            .get(format!("{}/internal/v1/admin/margin", self.base_url))
            .query(&[("month", month)])
            .query(&[("limit", limit)]);
        if let Some(after) = after {
            request = request.query(&[("after", after)]);
        }
        self.send(request).await
    }

    async fn detach(&self, account_id: &str) -> Result<DetachResponse, BillingError> {
        self.send(
            self.http
                .post(format!(
                    "{}/internal/v1/accounts/{}/detach",
                    self.base_url,
                    urlencoding::encode(account_id)
                ))
                .json(&serde_json::json!({})),
        )
        .await
    }
}

fn required_env(name: &str, test_default: &str) -> Result<String, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim_end_matches('/').to_string()),
        _ if crate::test_mode_enabled() => Ok(test_default.to_string()),
        _ => Err(format!("{name} must be set to a non-empty value")),
    }
}

async fn read_limited(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BillingError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(BillingError::InvalidResponse);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BillingError::Unavailable)?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(BillingError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn jwt_exp(token: &str) -> Result<u64, BillingError> {
    #[derive(Deserialize)]
    struct Claims {
        exp: u64,
    }
    let mut parts = token.split('.');
    let header = parts.next().ok_or(BillingError::InvalidResponse)?;
    let payload = parts.next().ok_or(BillingError::InvalidResponse)?;
    let signature = parts.next().ok_or(BillingError::InvalidResponse)?;
    if header.is_empty() || payload.is_empty() || signature.is_empty() || parts.next().is_some() {
        return Err(BillingError::InvalidResponse);
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| BillingError::InvalidResponse)?;
    serde_json::from_slice::<Claims>(&decoded)
        .map(|claims| claims.exp)
        .map_err(|_| BillingError::InvalidResponse)
}

pub fn router() -> Router<std::sync::Arc<CpState>> {
    Router::new()
        .route("/api/billing", get(get_billing))
        .route("/api/billing/recording-lease", post(create_recording_lease))
        .route(
            "/api/billing/offline-recording-usage",
            post(record_offline_recording_usage),
        )
        .route("/api/billing/checkout", post(create_checkout))
        .route("/api/billing/portal", post(create_portal))
        .route("/api/admin/capabilities", get(admin_capabilities))
        .route("/api/admin/margin", get(admin_margin))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn service_unavailable() -> Response {
    no_store(
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error":"billing_unavailable"})),
        )
            .into_response(),
    )
}

fn checkout_conflict() -> Response {
    no_store(
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"billing_checkout_conflict"})),
        )
            .into_response(),
    )
}

async fn get_billing(
    State(state): State<std::sync::Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let account_id = match state
        .repositories
        .billing()
        .billing_account_id(&user.0)
        .await
    {
        Ok(value) => value,
        Err(_) => return service_unavailable(),
    };
    match state.billing.summary(&account_id).await {
        Ok(summary) => no_store(Json(summary).into_response()),
        Err(_) => service_unavailable(),
    }
}

fn valid_checkout(request: &CheckoutRequest) -> bool {
    !request.plan_id.is_empty()
        && request.plan_id.len() <= 64
        && request
            .plan_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && request.interval == "month"
}

fn uuid_v4(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            14 => byte == b'4',
            19 => matches!(byte.to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b'),
            _ => byte.is_ascii_hexdigit(),
        })
}

fn valid_recording_lease(request: &RecordingLeaseRequest) -> bool {
    uuid_v4(&request.request_id)
        && request.lease_id.as_ref().is_none_or(|value| {
            value.len() == 70
                && value.starts_with("lease_")
                && value[6..].bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn recording_event_id(account_id: &str, request_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"kioku.recording_seconds_v1\0");
    digest.update(account_id.as_bytes());
    digest.update([0]);
    digest.update(request_id.as_bytes());
    format!("evt_{:x}", digest.finalize())
}

fn offline_recording_event_id(account_id: &str, request_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"kioku.offline_recording_seconds_v1\0");
    digest.update(account_id.as_bytes());
    digest.update([0]);
    digest.update(request_id.as_bytes());
    format!("evt_{:x}", digest.finalize())
}

fn lease_request_matches(
    existing: &super::control_store::RecordingLeaseRequestRow,
    request: &RecordingLeaseRequest,
) -> bool {
    existing.requested_lease_id == request.lease_id
}

fn duplicate_is_conflict(existing_pending: bool, upstream_duplicate: bool) -> bool {
    upstream_duplicate && !existing_pending
}

fn renewal_too_early(now_ms: i64, expires_ms: i64) -> bool {
    expires_ms.saturating_sub(now_ms)
        > RECORDING_LEASE_RENEWAL_HEADROOM_MS + RECORDING_LEASE_RENEWAL_CLOCK_SKEW_MS
}

fn can_reattach_paid_lease(now_ms: i64, expires_ms: i64) -> bool {
    expires_ms.saturating_sub(now_ms) > RECORDING_LEASE_RENEWAL_HEADROOM_MS
}

fn lease_authorized_summary(mut summary: Value) -> Value {
    // A successful lease response describes the entitlement of this already
    // reserved interval. The aggregate summary may simultaneously report zero
    // remaining seconds after reserving the account's final minute; that must
    // not make the client discard the minute that was just admitted.
    if let Some(recording) = summary.get_mut("recording").and_then(Value::as_object_mut) {
        recording.insert("allowed".into(), Value::Bool(true));
        recording.insert("reason".into(), Value::Null);
    }
    if let Some(usage) = summary.get_mut("usage").and_then(Value::as_object_mut) {
        let allowance = usage.get("allowance_seconds").and_then(Value::as_i64);
        let used = usage.get("used_seconds").and_then(Value::as_i64);
        let remaining = usage.get("remaining_seconds").and_then(Value::as_i64);
        if let (Some(allowance), Some(used), Some(0)) = (allowance, used, remaining) {
            // Shipped clients require an allowed snapshot to have positive
            // remaining time and exact allowance arithmetic. The upstream
            // authorization summary is post-reservation, so expose the final
            // granted minute as still usable inside this lease response. A
            // later ordinary summary remains post-reservation and denied.
            if used >= RECORDING_LEASE_SECONDS && allowance.saturating_sub(used) == 0 {
                usage.insert(
                    "used_seconds".into(),
                    Value::from(used - RECORDING_LEASE_SECONDS),
                );
                usage.insert(
                    "remaining_seconds".into(),
                    Value::from(RECORDING_LEASE_SECONDS),
                );
            }
        }
    }
    summary
}

fn recording_lease_response(lease_id: String, expires_at: String, mut summary: Value) -> Response {
    let recording_retention = summary
        .as_object_mut()
        .and_then(|object| object.remove("_recording_retention_authority"));
    no_store(
        Json(serde_json::json!({
            "lease_id":lease_id,
            "expires_at":expires_at,
            "billing":lease_authorized_summary(summary),
            "recording_retention":recording_retention,
        }))
        .into_response(),
    )
}

async fn attach_recording_retention_authority(
    state: &CpState,
    user_id: &str,
    lease_id: &str,
    expires_at: &str,
    mut summary: Value,
) -> Result<Value, RecordingAuthorizationFailure> {
    if summary.get("_recording_retention_authority").is_some() {
        return Ok(summary);
    }
    let preference = state
        .repositories
        .recording_retention()
        .preference(user_id)
        .await
        .map_err(|_| RecordingAuthorizationFailure::Unavailable)?;
    let mut authority = serde_json::json!({
        "policy": preference.policy,
        "policy_revision": preference.revision,
        "consent_version": preference.consent_version,
        "status": "processing_only",
    });
    if preference.policy == super::control_store::RecordingRetentionPolicy::UntilDeleted {
        let schema_present = super::retention::recording_authority_schema_present(state, user_id)
            .await
            .map_err(|_| RecordingAuthorizationFailure::Unavailable)?;
        let policy_epoch = preference
            .policy_epoch
            .as_deref()
            .ok_or(RecordingAuthorizationFailure::Unavailable)?;
        let expires_ms = super::isotime::parse_epoch_millis(expires_at)
            .ok_or(RecordingAuthorizationFailure::Unavailable)?;
        if !state.durable_recording_storage_bound || !schema_present {
            authority["status"] = Value::String("temporarily_unavailable".into());
        } else {
            let claims = super::tokens::RecordingRetentionLeaseClaims {
                user_id: user_id.to_string(),
                lease_id: lease_id.to_string(),
                policy_revision: preference.revision,
                policy_epoch: policy_epoch.to_string(),
                valid_from_epoch_millis: expires_ms
                    .saturating_sub(RECORDING_LEASE_SECONDS.saturating_mul(1_000)),
                capture_started_before_epoch_millis: expires_ms,
                valid_until_epoch_millis: expires_ms
                    .saturating_add(RECORDING_RETENTION_SEGMENT_TAIL_MILLIS),
            };
            let secret = state
                .config
                .jwt_secrets
                .first()
                .ok_or(RecordingAuthorizationFailure::Unavailable)?;
            let token = super::tokens::issue_recording_retention_lease(secret, &claims)
                .map_err(|_| RecordingAuthorizationFailure::Unavailable)?;
            authority = serde_json::json!({
                "policy": preference.policy,
                "policy_revision": preference.revision,
                "policy_epoch": policy_epoch,
                "consent_version": preference.consent_version,
                "status": "authorized",
                "valid_from": super::isotime::format_epoch_millis(claims.valid_from_epoch_millis),
                "capture_started_before": expires_at,
                "valid_until": super::isotime::format_epoch_millis(claims.valid_until_epoch_millis),
                "authority_token": token,
            });
        }
    }
    let object = summary
        .as_object_mut()
        .ok_or(RecordingAuthorizationFailure::Unavailable)?;
    object.insert("_recording_retention_authority".into(), authority);
    Ok(summary)
}

async fn current_recording_summary(
    state: &CpState,
    user_id: &str,
) -> Result<Value, RecordingAuthorizationFailure> {
    let account_id = match state
        .repositories
        .billing()
        .billing_account_id(user_id)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            warn!(error = %error, "recording billing account mapping unavailable");
            return if state.config.billing_enforcement_mode.enforces() {
                Err(RecordingAuthorizationFailure::Unavailable)
            } else {
                Ok(serde_json::json!({"recording":{"allowed":true,"shadow":true}}))
            };
        }
    };
    match state.billing.summary(&account_id).await {
        Ok(summary) => Ok(summary),
        Err(_) if !state.config.billing_enforcement_mode.enforces() => {
            warn!("recording billing shadow summary unavailable");
            Ok(serde_json::json!({"recording":{"allowed":true,"shadow":true}}))
        }
        Err(_) => Err(RecordingAuthorizationFailure::Unavailable),
    }
}

async fn authorize_recording_seconds(
    state: &CpState,
    user_id: &str,
    request_id: &str,
) -> Result<(Value, bool), RecordingAuthorizationFailure> {
    let account_id = match state
        .repositories
        .billing()
        .billing_account_id(user_id)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            warn!(error = %error, "recording billing account mapping unavailable");
            return if state.config.billing_enforcement_mode.enforces() {
                Err(RecordingAuthorizationFailure::Unavailable)
            } else {
                Ok((
                    serde_json::json!({"recording":{"allowed":true,"shadow":true}}),
                    false,
                ))
            };
        }
    };
    let event_id = recording_event_id(&account_id, request_id);
    let observed_at = super::isotime::format_epoch_millis(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64,
    );
    let request = UsageAuthorizeRequest {
        account_id,
        event_id,
        meter: "recording_seconds_v1",
        quantity_seconds: RECORDING_LEASE_SECONDS,
        observed_at,
    };
    match state.billing.authorize(&request).await {
        Ok(response) if response.decision == "allow" => Ok((response.summary, response.duplicate)),
        Ok(response) if !state.config.billing_enforcement_mode.enforces() => {
            warn!("recording billing shadow denial ignored");
            Ok((response.summary, response.duplicate))
        }
        Ok(response) => Err(RecordingAuthorizationFailure::Denied {
            code: public_denial_code(response.reason.as_deref()).to_string(),
            summary: response.summary,
        }),
        Err(_) if !state.config.billing_enforcement_mode.enforces() => {
            warn!("recording billing shadow outage ignored");
            Ok((
                serde_json::json!({"recording":{"allowed":true,"shadow":true}}),
                false,
            ))
        }
        Err(_) => Err(RecordingAuthorizationFailure::Unavailable),
    }
}

async fn authorize_offline_recording_seconds(
    state: &CpState,
    user_id: &str,
    request_id: &str,
) -> Result<(Value, bool), RecordingAuthorizationFailure> {
    let account_id = match state
        .repositories
        .billing()
        .billing_account_id(user_id)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            warn!(error = %error, "offline recording billing account mapping unavailable");
            return if state.config.billing_enforcement_mode.enforces() {
                Err(RecordingAuthorizationFailure::Unavailable)
            } else {
                Ok((
                    serde_json::json!({"recording":{"allowed":true,"shadow":true}}),
                    false,
                ))
            };
        }
    };
    let event_id = offline_recording_event_id(&account_id, request_id);
    let observed_at = super::isotime::format_epoch_millis(epoch_millis());
    let request = UsageAuthorizeRequest {
        account_id,
        event_id,
        meter: "recording_seconds_v1",
        quantity_seconds: RECORDING_LEASE_SECONDS,
        observed_at,
    };
    match state.billing.authorize(&request).await {
        Ok(response) if response.decision == "allow" => Ok((response.summary, response.duplicate)),
        Ok(response) if !state.config.billing_enforcement_mode.enforces() => {
            warn!("offline recording billing shadow denial ignored");
            Ok((response.summary, response.duplicate))
        }
        Ok(response) => Err(RecordingAuthorizationFailure::Denied {
            code: public_denial_code(response.reason.as_deref()).to_string(),
            summary: response.summary,
        }),
        Err(_) if !state.config.billing_enforcement_mode.enforces() => {
            warn!("offline recording billing shadow outage ignored");
            Ok((
                serde_json::json!({"recording":{"allowed":true,"shadow":true}}),
                false,
            ))
        }
        Err(_) => Err(RecordingAuthorizationFailure::Unavailable),
    }
}

enum RecordingAuthorizationFailure {
    Denied { code: String, summary: Value },
    Unavailable,
}

fn recording_denial_response(code: &str, summary: Value) -> Response {
    no_store(
        (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({"error":code,"billing":summary})),
        )
            .into_response(),
    )
}

async fn create_recording_lease(
    State(state): State<std::sync::Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(request): Json<RecordingLeaseRequest>,
) -> Response {
    if !valid_recording_lease(&request) {
        return no_store(
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid_recording_lease"})),
            )
                .into_response(),
        );
    }
    let _gate = state.recording_lease_gate.lock(&user.0).await;
    let existing = match state
        .repositories
        .billing()
        .recording_lease_receipt(&user.0, &request.request_id)
        .await
    {
        Ok(value) => value,
        Err(_) => return service_unavailable(),
    };
    if let Some(existing) = &existing {
        if !lease_request_matches(existing, &request) || existing.state == "conflict" {
            return idempotency_conflict();
        }
        if existing.state == "granted" {
            let Some(summary) = existing.summary.clone() else {
                return service_unavailable();
            };
            // A granted request is an immutable idempotency receipt. In
            // particular, do not synthesize a new retention epoch into an old
            // response after the account setting changes. A fresh lease (or
            // reattachment request) is the only way to obtain new authority.
            return recording_lease_response(
                existing.issued_lease_id.clone(),
                existing.expires_at.clone(),
                summary,
            );
        }
        if existing.state == "denied" {
            let (Some(summary), Some(code)) =
                (existing.summary.clone(), existing.denial_code.as_deref())
            else {
                return service_unavailable();
            };
            return recording_denial_response(code, summary);
        }
    }
    if !state.recording_lease_gate.allow(&user.0).await {
        return no_store(
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error":"recording_lease_rate_limited",
                    "retry_after":10
                })),
            )
                .into_response(),
        );
    }

    let now_ms = epoch_millis();
    let mut effective_request_id = request.request_id.clone();
    let mut existing_pending = existing.is_some();
    if !existing_pending {
        let abandoned = match state
            .repositories
            .billing()
            .pending_recording_lease_request(&user.0)
            .await
        {
            Ok(value) => value,
            Err(_) => return service_unavailable(),
        };
        if let Some((pending_request_id, _pending)) = abandoned {
            // A billing response can succeed immediately before the enclave
            // transaction fails or the process exits. Reconcile that durable
            // intent with its original idempotency key before accepting a new
            // reservation. A pending row was never granted locally, so its
            // paid interval can safely start from recovery time exactly once.
            effective_request_id = pending_request_id;
            existing_pending = true;
        }
    }
    if existing.is_none() && !existing_pending {
        let active = match state
            .repositories
            .billing()
            .active_recording_lease(&user.0)
            .await
        {
            Ok(value) => value,
            Err(_) => return service_unavailable(),
        };
        let (lease_id, base_ms) = match (&request.lease_id, active) {
            (None, Some((active_id, expires_at))) => {
                let Some(expires_ms) = super::isotime::parse_epoch_millis(&expires_at) else {
                    return service_unavailable();
                };
                if can_reattach_paid_lease(now_ms, expires_ms) {
                    // A stopped/restarted or relaunched first-party client may
                    // have lost its in-memory lease id. Reattach it to the
                    // already-paid interval without extending or double
                    // charging it. Upload authorization is already per-user,
                    // so this grants no capability beyond the active lease.
                    let summary = match current_recording_summary(&state, &user.0).await {
                        Ok(summary) => summary,
                        Err(RecordingAuthorizationFailure::Unavailable) => {
                            return service_unavailable();
                        }
                        Err(RecordingAuthorizationFailure::Denied { .. }) => unreachable!(),
                    };
                    let summary = match attach_recording_retention_authority(
                        &state,
                        &user.0,
                        &active_id,
                        &expires_at,
                        summary,
                    )
                    .await
                    {
                        Ok(summary) => summary,
                        Err(_) => return service_unavailable(),
                    };
                    return recording_lease_response(active_id, expires_at, summary);
                }
                // With at most the renewal headroom left, or after expiry,
                // reserve one new minute from server-now. Lease ids are scoped
                // to a user and opaque; reusing the identity also avoids an
                // expired durable row racing activation of the paid interval.
                (active_id, now_ms)
            }
            (None, _) => (
                format!("lease_{}", super::tokens::random_token_hex()),
                now_ms,
            ),
            (Some(requested), Some((active_id, expires_at))) if requested == &active_id => {
                let Some(expires_ms) = super::isotime::parse_epoch_millis(&expires_at) else {
                    return service_unavailable();
                };
                if expires_ms <= now_ms {
                    return inactive_lease();
                }
                if renewal_too_early(now_ms, expires_ms) {
                    return lease_conflict("recording_lease_renewal_too_early");
                }
                (active_id, now_ms.max(expires_ms))
            }
            (Some(_), _) => return inactive_lease(),
        };
        let expires_at = super::isotime::format_epoch_millis(
            base_ms.saturating_add(RECORDING_LEASE_SECONDS * 1_000),
        );
        if state
            .repositories
            .billing()
            .begin_recording_lease_request(
                &user.0,
                &request.request_id,
                request.lease_id.as_deref(),
                &lease_id,
                &expires_at,
            )
            .await
            .is_err()
        {
            return service_unavailable();
        }
    }
    let (summary, upstream_duplicate) =
        match authorize_recording_seconds(&state, &user.0, &effective_request_id).await {
            Ok(result) => result,
            Err(RecordingAuthorizationFailure::Denied { code, summary }) => {
                if state
                    .repositories
                    .billing()
                    .deny_recording_lease_request(&user.0, &effective_request_id, &code, &summary)
                    .await
                    .is_err()
                {
                    return service_unavailable();
                }
                return recording_denial_response(&code, summary);
            }
            Err(RecordingAuthorizationFailure::Unavailable) => return service_unavailable(),
        };
    if duplicate_is_conflict(existing_pending, upstream_duplicate) {
        let _ = state
            .repositories
            .billing()
            .conflict_recording_lease_request(&user.0, &effective_request_id)
            .await;
        return idempotency_conflict();
    }
    let pending = match state
        .repositories
        .billing()
        .pending_recording_lease_request(&user.0)
        .await
    {
        Ok(Some((_request_id, pending))) => pending,
        _ => return service_unavailable(),
    };
    let summary = match attach_recording_retention_authority(
        &state,
        &user.0,
        &pending.issued_lease_id,
        &pending.expires_at,
        summary,
    )
    .await
    {
        Ok(summary) => summary,
        Err(_) => return service_unavailable(),
    };
    let retry_now_ms = existing_pending.then(epoch_millis);
    let (lease_id, expires_at) = match state
        .repositories
        .billing()
        .complete_recording_lease(&user.0, &effective_request_id, retry_now_ms, &summary)
        .await
    {
        Ok(receipt) => receipt,
        Err(_) => return service_unavailable(),
    };
    recording_lease_response(lease_id, expires_at, summary)
}

async fn record_offline_recording_usage(
    State(state): State<std::sync::Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(request): Json<OfflineRecordingUsageRequest>,
) -> Response {
    if !uuid_v4(&request.request_id) {
        return no_store(
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid_offline_recording_usage"})),
            )
                .into_response(),
        );
    }
    // Serialize this accounting write with live lease admission for the same
    // user so plan exhaustion has one deterministic order. The upstream event
    // id is derived from the stable request id, making response-loss retries
    // idempotent without persisting client or capture metadata in the enclave.
    let _gate = state.recording_lease_gate.lock(&user.0).await;
    let already_completed = match state
        .repositories
        .billing()
        .offline_recording_usage_receipt(&user.0, &request.request_id)
        .await
    {
        Ok(value) => value,
        Err(_) => return service_unavailable(),
    };
    if already_completed {
        return match current_recording_summary(&state, &user.0).await {
            Ok(summary) => no_store(
                Json(serde_json::json!({"duplicate":true,"billing":summary})).into_response(),
            ),
            Err(_) => service_unavailable(),
        };
    }
    match authorize_offline_recording_seconds(&state, &user.0, &request.request_id).await {
        Ok((summary, upstream_duplicate)) => {
            let inserted = match state
                .repositories
                .billing()
                .complete_offline_recording_usage(&user.0, &request.request_id)
                .await
            {
                Ok(value) => value,
                Err(_) => return service_unavailable(),
            };
            no_store(
                Json(serde_json::json!({
                    "duplicate":upstream_duplicate || !inserted,
                    "billing":summary
                }))
                .into_response(),
            )
        }
        Err(RecordingAuthorizationFailure::Denied { code, summary }) => {
            recording_denial_response(&code, summary)
        }
        Err(RecordingAuthorizationFailure::Unavailable) => service_unavailable(),
    }
}

fn inactive_lease() -> Response {
    no_store(
        (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({"error":"recording_lease_inactive"})),
        )
            .into_response(),
    )
}

fn lease_conflict(error: &'static str) -> Response {
    no_store(
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":error})),
        )
            .into_response(),
    )
}

fn idempotency_conflict() -> Response {
    lease_conflict("idempotency_conflict")
}

/// Uploads do not consume the meter: the Mac client reserves wall-clock time
/// in bounded idempotent ticks. A new audio object still checks the current
/// entitlement before persistence so a client cannot bypass a stopped lease.
pub async fn check_recording_entitlement(state: &CpState, user_id: &str) -> Result<(), Response> {
    match state
        .repositories
        .billing()
        .active_recording_lease(user_id)
        .await
    {
        Ok(Some((_lease_id, expires_at)))
            if super::isotime::parse_epoch_millis(&expires_at)
                .is_some_and(|expires| expires > epoch_millis()) =>
        {
            Ok(())
        }
        Ok(_) if !state.config.billing_enforcement_mode.enforces() => Ok(()),
        Ok(_) => Err(inactive_lease()),
        Err(_) if !state.config.billing_enforcement_mode.enforces() => Ok(()),
        Err(_) => Err(service_unavailable()),
    }
}

pub async fn reserve_recording_delivery(
    state: &CpState,
    user_id: &str,
    event_id: &str,
    media_bytes: i64,
) -> Result<(), Response> {
    match state
        .repositories
        .billing()
        .reserve_recording_delivery(user_id, event_id, media_bytes)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) if !state.config.billing_enforcement_mode.enforces() => Ok(()),
        Ok(false) => Err(inactive_lease()),
        Err(_) if !state.config.billing_enforcement_mode.enforces() => Ok(()),
        Err(_) => Err(service_unavailable()),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn reserve_recording_delivery_batch(
    state: &CpState,
    user_id: &str,
    batch_id: &str,
    manifest_digest: &str,
    stream_id: &str,
    first_sequence: i64,
    last_sequence: i64,
    event_ids: &[String],
    new_event_ids: &[String],
) -> Result<(), Response> {
    match state
        .repositories
        .billing()
        .reserve_recording_delivery_batch(
            user_id,
            batch_id,
            manifest_digest,
            stream_id,
            first_sequence,
            last_sequence,
            event_ids,
            new_event_ids,
        )
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) if !state.config.billing_enforcement_mode.enforces() => Ok(()),
        Ok(false) => Err(inactive_lease()),
        Err(EnclaveError::Conflict(message)) => {
            Err(lease_conflict(if message.contains("too many pending") {
                "reference_batch_limit"
            } else {
                "idempotency_conflict"
            }))
        }
        Err(_) if !state.config.billing_enforcement_mode.enforces() => Ok(()),
        Err(_) => Err(service_unavailable()),
    }
}

pub async fn complete_recording_delivery_batch(
    state: &CpState,
    user_id: &str,
    batch_id: &str,
    manifest_digest: &str,
    event_ids: &[String],
) {
    if let Err(error) = state
        .repositories
        .billing()
        .complete_recording_delivery_batch(user_id, batch_id, manifest_digest, event_ids)
        .await
    {
        warn!(error = %error, "recording delivery batch reservation cleanup failed");
    }
}

pub async fn complete_recording_delivery(state: &CpState, user_id: &str, event_id: &str) {
    if let Err(error) = state
        .repositories
        .billing()
        .complete_recording_delivery(user_id, event_id)
        .await
    {
        warn!(error = %error, "recording delivery reservation cleanup failed");
    }
}

fn epoch_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn public_denial_code(reason: Option<&str>) -> &'static str {
    match reason {
        Some("allowance_exhausted") => "recording_allowance_exhausted",
        _ => "recording_not_entitled",
    }
}

fn valid_external_action_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
    {
        return false;
    }
    parsed.host_str().is_some()
}

fn checkout_response(result: Result<UrlResponse, BillingError>) -> Response {
    match result {
        Ok(response) if valid_external_action_url(&response.url) => {
            no_store(Json(response).into_response())
        }
        Err(BillingError::Rejected(409)) => checkout_conflict(),
        _ => service_unavailable(),
    }
}

async fn create_checkout(
    State(state): State<std::sync::Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(request): Json<CheckoutRequest>,
) -> Response {
    if !valid_checkout(&request) {
        return no_store(
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid_plan"})),
            )
                .into_response(),
        );
    }
    let account_id = match state
        .repositories
        .billing()
        .billing_account_id(&user.0)
        .await
    {
        Ok(value) => value,
        Err(_) => return service_unavailable(),
    };
    checkout_response(state.billing.checkout(&account_id, &request).await)
}

async fn create_portal(
    State(state): State<std::sync::Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let account_id = match state
        .repositories
        .billing()
        .billing_account_id(&user.0)
        .await
    {
        Ok(value) => value,
        Err(_) => return service_unavailable(),
    };
    match state.billing.portal(&account_id).await {
        Ok(response) if valid_external_action_url(&response.url) => {
            no_store(Json(response).into_response())
        }
        _ => service_unavailable(),
    }
}

fn require_admin(state: &CpState, user_id: &str) -> Option<Response> {
    if state.config.is_admin(user_id) {
        None
    } else {
        Some(no_store(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error":"forbidden"})),
            )
                .into_response(),
        ))
    }
}

async fn admin_capabilities(
    State(state): State<std::sync::Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    if let Some(response) = require_admin(&state, &user.0) {
        return response;
    }
    no_store(
        Json(serde_json::json!({
            "owner": true,
            "admin": true,
            "margin_report": true,
            "margin_kind": "estimated_contribution_margin",
            "storage_bytes": "current_logical_bytes"
        }))
        .into_response(),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MarginQuery {
    limit: Option<u8>,
    after: Option<String>,
}

fn valid_margin_query(query: &MarginQuery) -> bool {
    query.limit.is_none_or(|value| (1..=100).contains(&value))
        && query.after.as_ref().is_none_or(|value| {
            value.len() == 43
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

#[derive(Clone)]
struct LocalVertexCoverage {
    sequence: u64,
    pending_events: u64,
    lost_events: u64,
    observed_at: String,
}

impl LocalVertexCoverage {
    fn complete(&self) -> bool {
        self.pending_events == 0 && self.lost_events == 0
    }
}

struct AccountDrivers {
    storage_bytes: u64,
    accepted_email_count: u64,
    vertex_coverage: Option<LocalVertexCoverage>,
}

struct MarginIdentity {
    email: String,
    account_id: String,
    drivers: Option<AccountDrivers>,
}

fn producer_coverage_json(
    coverage: Option<&LocalVertexCoverage>,
    upstream: Option<&Value>,
    generated_at: Option<&str>,
) -> Value {
    let freshness_max_seconds = upstream
        .and_then(|value| value.get("freshness_max_seconds"))
        .and_then(Value::as_u64);
    let age_seconds = coverage.and_then(|coverage| {
        let generated_ms = super::isotime::parse_epoch_millis(generated_at?)?;
        let observed_ms = super::isotime::parse_epoch_millis(&coverage.observed_at)?;
        let age_ms = generated_ms.checked_sub(observed_ms)?;
        (age_ms >= 0).then_some(u64::try_from(age_ms / 1_000).ok()?)
    });
    let fresh = age_seconds
        .zip(freshness_max_seconds)
        .is_some_and(|(age, maximum)| age <= maximum);
    let complete = coverage.is_some_and(LocalVertexCoverage::complete) && fresh;
    let status = match coverage {
        None => "missing",
        Some(_) if !fresh => "stale",
        Some(value) if value.lost_events != 0 => "lost_events",
        Some(value) if value.pending_events != 0 => "pending_events",
        Some(_) => "bounded_recent_zero_backlog",
    };
    serde_json::json!({
        "reported": coverage.is_some(),
        "pending_events": coverage.map(|value| value.pending_events),
        "lost_events": coverage.map(|value| value.lost_events),
        "sequence": coverage.map(|value| value.sequence),
        "observed_at": coverage.map(|value| value.observed_at.as_str()),
        "age_seconds": age_seconds,
        "freshness_max_seconds": freshness_max_seconds,
        "fresh": fresh,
        "basis": "bounded_recent_zero_backlog_snapshot",
        "population_complete": false,
        "status": status,
        "complete": complete,
    })
}

fn null_row_vertex_cost(account: &mut serde_json::Map<String, Value>) {
    if let Some(direct) = account
        .get_mut("direct_vertex")
        .and_then(Value::as_object_mut)
    {
        direct.insert("complete".into(), Value::Bool(false));
        direct.insert("estimated_total_usd_micros".into(), Value::Null);
        if let Some(audio) = direct
            .get_mut("by_operation")
            .and_then(Value::as_object_mut)
            .and_then(|operations| operations.get_mut("audio_understanding"))
            .and_then(Value::as_object_mut)
        {
            audio.insert("complete".into(), Value::Bool(false));
            audio.insert("uncached_input_audio_usd_micros".into(), Value::Null);
        }
    }
    for key in [
        "allocated_known_cost_usd_micros",
        "total_attributable_cost_usd_micros",
        "estimated_direct_contribution_usd_micros",
        "estimated_cash_direct_contribution_after_credits_usd_micros",
        "estimated_fully_loaded_contribution_usd_micros",
        "estimated_fully_loaded_margin_bps",
        "modeled_rate_card_direct_contribution_usd_micros",
        "modeled_rate_card_direct_margin_bps",
        "estimated_contribution_before_storage_and_shared_usd_micros",
        "estimated_margin_before_storage_and_shared_bps",
    ] {
        account.insert(key.into(), Value::Null);
    }
}

fn unallocate_row_vertex_pool(account: &mut serde_json::Map<String, Value>) {
    let Some(vertex) = account
        .get_mut("allocated_gcp_observed_costs")
        .and_then(Value::as_object_mut)
        .and_then(|costs| costs.get_mut("vertex"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    for key in [
        "usd_micros",
        "gross_usd_micros",
        "credits_usd_micros",
        "net_usd_micros",
        "cash_usd_micros",
    ] {
        vertex.insert(key.into(), Value::Null);
    }
    vertex.insert("status".into(), Value::String("unallocated".into()));
}

fn reconciled_vertex_net(object: &serde_json::Map<String, Value>) -> Value {
    object
        .get("cost_reconciliation")
        .and_then(|value| value.get("categories_usd_micros"))
        .and_then(|value| value.get("vertex_direct_reconciliation"))
        .and_then(|value| value.get("net_usd_micros"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn unallocate_report_vertex_pool(object: &mut serde_json::Map<String, Value>) {
    let actual_vertex_net = reconciled_vertex_net(object);
    object.insert("cost_completeness".into(), Value::Bool(false));
    object.insert(
        "allocation_status".into(),
        Value::String("unallocated".into()),
    );
    if let Some(basis) = object
        .get_mut("allocation_basis")
        .and_then(Value::as_object_mut)
    {
        basis.insert("vertex_cost_complete".into(), Value::Bool(false));
    }
    if let Some(allocation) = object.get_mut("allocation").and_then(Value::as_object_mut) {
        allocation.insert("status".into(), Value::String("unallocated".into()));
        allocation.insert(
            "reason".into(),
            Value::String("local_vertex_coverage_incomplete".into()),
        );
        if let Some(unallocated) = allocation
            .get_mut("unallocated_usd_micros")
            .and_then(Value::as_object_mut)
        {
            unallocated.insert("vertex".into(), actual_vertex_net);
        }
        if let Some(reconciliation) = allocation
            .get_mut("vertex_reconciliation")
            .and_then(Value::as_object_mut)
        {
            reconciliation.insert("complete_producer_coverage".into(), Value::Bool(false));
            reconciliation.insert("observed_within_tolerance".into(), Value::Bool(false));
        }
    }
}

fn decorate_margin(
    report: Value,
    identities: &[MarginIdentity],
    anchored_global_coverage_complete: bool,
    account_metrics: RetainedAccountMetrics,
    period: &str,
    account_metrics_as_of: &str,
) -> Value {
    let mut object = report.as_object().cloned().unwrap_or_default();
    let generated_at = object
        .get("generated_at")
        .and_then(Value::as_str)
        .map(str::to_string);
    let upstream_accounts = object
        .remove("rows")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut accounts = upstream_accounts
        .iter()
        .filter_map(|value| {
            let account_id = value.get("account_id").and_then(Value::as_str)?;
            let identity = identities
                .iter()
                .find(|identity| identity.account_id == account_id)?;
            let coverage = identity
                .drivers
                .as_ref()
                .and_then(|drivers| drivers.vertex_coverage.as_ref());
            let mut account = value.as_object()?.clone();
            account.remove("account_id");
            account.insert("email".into(), Value::String(identity.email.clone()));
            account.insert(
                "storage_bytes".into(),
                identity
                    .drivers
                    .as_ref()
                    .map_or(Value::Null, |drivers| Value::from(drivers.storage_bytes)),
            );
            account.insert(
                "storage_measurement".into(),
                Value::String(
                    if identity.drivers.is_some() {
                        "current_logical_bytes"
                    } else {
                        "unavailable"
                    }
                    .into(),
                ),
            );
            account.insert(
                "email_delivery".into(),
                serde_json::json!({
                    "accepted_message_count": identity.drivers.as_ref().map(|drivers| drivers.accepted_email_count),
                    "usd_micros": null,
                    "status": "provider_invoice_unavailable"
                }),
            );
            let upstream_coverage = account
                .get("direct_vertex")
                .and_then(|value| value.get("producer_coverage"))
                .cloned();
            let producer_coverage = producer_coverage_json(
                coverage,
                upstream_coverage.as_ref(),
                generated_at.as_deref(),
            );
            let coverage_complete = producer_coverage
                .get("complete")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(direct) = account
                .get_mut("direct_vertex")
                .and_then(Value::as_object_mut)
            {
                direct.insert("producer_coverage".into(), producer_coverage);
            }
            if !coverage_complete {
                null_row_vertex_cost(&mut account);
            }
            Some(Value::Object(account))
        })
        .collect::<Vec<_>>();
    let global_vertex_coverage_complete = anchored_global_coverage_complete
        && accounts.iter().all(|account| {
            account
                .get("direct_vertex")
                .and_then(|value| value.get("producer_coverage"))
                .and_then(|value| value.get("complete"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        });
    if !global_vertex_coverage_complete {
        for account in &mut accounts {
            if let Some(account) = account.as_object_mut() {
                unallocate_row_vertex_pool(account);
            }
        }
        unallocate_report_vertex_pool(&mut object);
    }
    object.insert("accounts".into(), Value::Array(accounts));
    object.insert(
        "margin_kind".into(),
        Value::String("estimated_contribution_margin".into()),
    );
    object.insert(
        "account_metrics".into(),
        serde_json::json!({
            "retained_active_accounts": account_metrics.retained_active_accounts,
            "new_retained_active_accounts_mtd": account_metrics.new_retained_active_accounts_mtd,
            "period": period,
            "as_of": account_metrics_as_of,
        }),
    );
    Value::Object(object)
}

fn validated_margin_account_ids(report: &Value, limit: u8) -> Option<Vec<String>> {
    let report = report.as_object()?;
    let generated_at = report.get("generated_at")?.as_str()?;
    super::isotime::parse_epoch_millis(generated_at)?;
    let rows = report.get("rows")?.as_array()?;
    if rows.len() > usize::from(limit) {
        return None;
    }
    let mut seen = std::collections::HashSet::with_capacity(rows.len());
    let mut account_ids = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row.as_object()?;
        let account_id = row.get("account_id")?.as_str()?;
        if account_id.len() != 69
            || !account_id.starts_with("acct_")
            || !account_id[5..].bytes().all(|byte| byte.is_ascii_hexdigit())
            || !seen.insert(account_id)
        {
            return None;
        }
        if !row.get("allocated_gcp_observed_costs")?.is_object()
            || !row
                .get("allocated_gcp_observed_costs")?
                .get("vertex")?
                .is_object()
            || row.contains_key("allocated_invoice_costs")
        {
            return None;
        }
        let coverage = row
            .get("direct_vertex")?
            .get("producer_coverage")?
            .as_object()?;
        let freshness_max_valid = coverage
            .get("freshness_max_seconds")?
            .as_u64()
            .is_some_and(|value| value > 0);
        if !coverage.get("reported")?.is_boolean()
            || !coverage
                .get("age_seconds")
                .is_some_and(|value| value.is_null() || value.as_u64().is_some())
            || !freshness_max_valid
            || !coverage.get("fresh")?.is_boolean()
            || !coverage.get("basis")?.is_string()
            || !coverage.get("population_complete")?.is_boolean()
            || !coverage.get("status")?.is_string()
            || !coverage.get("complete")?.is_boolean()
        {
            return None;
        }
        account_ids.push(account_id.to_string());
    }
    Some(account_ids)
}

async fn current_account_drivers(
    state: &CpState,
    user_id: &str,
    period: &str,
) -> Option<AccountDrivers> {
    let user_id = user_id.to_string();
    let period = period.to_string();
    // Routed, not legacy: for a WAL-authoritative account the archive IS the
    // authoritative database, so its page count and media bytes are the
    // correct drivers. `wal_authoritative_read` falls through to exactly the
    // `with_user_read` this used to call for every unselected account, so the
    // legacy answer is unchanged.
    //
    // This was the last ungated legacy read outside the D4 sweep. It mattered
    // quietly: the refusal for a selected account was swallowed by this
    // function's `Option` return, so the margin dashboard showed an account
    // with no drivers rather than an error.
    let mut drivers = state
        .store
        .wal_authoritative_read(&user_id, {
            let period = period.clone();
            move |conn| {
                let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
                let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
                let media_bytes: i64 = conn.query_row(
                    "SELECT COALESCE(SUM(byte_length),0) FROM media_objects",
                    [],
                    |row| row.get(0),
                )?;
                let accepted_email_count: i64 = conn.query_row(
                    "SELECT count(*) FROM email_deliveries
                 WHERE state='accepted'
                   AND substr(updated_at,1,7)=?1",
                    [&period],
                    |row| row.get(0),
                )?;
                let bytes = page_count
                    .checked_mul(page_size)
                    .and_then(|value| value.checked_add(media_bytes))
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or_else(|| {
                        crate::error::EnclaveError::Config("storage size overflow".into())
                    })?;
                let accepted_email_count = u64::try_from(accepted_email_count).map_err(|_| {
                    crate::error::EnclaveError::Config("email delivery count overflow".into())
                })?;
                let coverage = conn
                    .query_row(
                        "SELECT sequence,pending_events,lost_events,updated_at
                     FROM vertex_usage_coverage
                     WHERE period=?1",
                        [&period],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, String>(3)?,
                            ))
                        },
                    )
                    .optional()?;
                let vertex_coverage = coverage
                    .map(|(sequence, pending_events, lost_events, observed_at)| {
                        Ok::<LocalVertexCoverage, crate::error::EnclaveError>(LocalVertexCoverage {
                            sequence: u64::try_from(sequence).map_err(|_| {
                                crate::error::EnclaveError::Config(
                                    "coverage sequence overflow".into(),
                                )
                            })?,
                            pending_events: u64::try_from(pending_events).map_err(|_| {
                                crate::error::EnclaveError::Config(
                                    "coverage pending count overflow".into(),
                                )
                            })?,
                            lost_events: u64::try_from(lost_events).map_err(|_| {
                                crate::error::EnclaveError::Config(
                                    "coverage lost count overflow".into(),
                                )
                            })?,
                            observed_at,
                        })
                    })
                    .transpose()?;
                Ok(AccountDrivers {
                    storage_bytes: bytes,
                    accepted_email_count,
                    vertex_coverage,
                })
            }
        })
        .await
        .ok()?;

    let anchor = state
        .repositories
        .billing()
        .vertex_coverage_anchor(&user_id, &period)
        .await
        .ok()
        .flatten();
    drivers.vertex_coverage = match (drivers.vertex_coverage.take(), anchor) {
        (Some(local), Some(anchor))
            if local.sequence == anchor.sequence
                && local.pending_events == anchor.pending_events
                && local.lost_events == anchor.lost_events
                && local.observed_at == anchor.observed_at =>
        {
            Some(local)
        }
        (Some(local), Some(anchor)) => Some(LocalVertexCoverage {
            sequence: local.sequence.max(anchor.sequence),
            pending_events: local.pending_events.max(anchor.pending_events),
            lost_events: local.lost_events.max(anchor.lost_events).max(1),
            observed_at: local.observed_at.max(anchor.observed_at),
        }),
        (None, Some(anchor)) => Some(LocalVertexCoverage {
            sequence: anchor.sequence,
            pending_events: anchor.pending_events,
            lost_events: anchor.lost_events.max(1),
            observed_at: anchor.observed_at,
        }),
        (_, None) => None,
    };
    Some(drivers)
}

fn utc_month_at(now: SystemTime) -> String {
    let millis = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64;
    super::isotime::format_epoch_millis(millis)
        .chars()
        .take(7)
        .collect()
}

fn current_utc_month() -> String {
    utc_month_at(SystemTime::now())
}

async fn admin_margin(
    State(state): State<std::sync::Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(query): Query<MarginQuery>,
) -> Response {
    // Authorization is intentionally the first operation: a denied caller
    // cannot trigger an upstream request or enumerate active-user email.
    if let Some(response) = require_admin(&state, &user.0) {
        return response;
    }
    if !valid_margin_query(&query) {
        return no_store(
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid_pagination"})),
            )
                .into_response(),
        );
    }
    let period = current_utc_month();
    let limit = query.limit.unwrap_or(50);
    let report = match state
        .billing
        .admin_margin(&period, limit, query.after.as_deref())
        .await
    {
        Ok(report) => report,
        Err(_) => return service_unavailable(),
    };
    let account_ids = match validated_margin_account_ids(&report, limit) {
        Some(account_ids) => account_ids,
        None => return service_unavailable(),
    };
    let account_metrics = match state
        .repositories
        .billing()
        .retained_active_account_metrics(&period)
        .await
    {
        Ok(metrics) => metrics,
        Err(_) => return service_unavailable(),
    };
    let account_metrics_as_of = super::isotime::format_epoch_millis(epoch_millis());
    let users = match state
        .repositories
        .billing()
        .active_identities_for_billing_accounts(account_ids)
        .await
    {
        Ok(users) => users,
        Err(_) => return service_unavailable(),
    };
    let anchored_global_coverage_complete = match state
        .repositories
        .billing()
        .active_vertex_coverage_complete(&period)
        .await
    {
        Ok(complete) => complete,
        Err(_) => return service_unavailable(),
    };
    let mut identities = Vec::with_capacity(users.len());
    for (user_id, email, account_id) in users {
        let drivers = current_account_drivers(&state, &user_id, &period).await;
        identities.push(MarginIdentity {
            email,
            account_id,
            drivers,
        });
    }
    // Never combine drivers from one UTC accounting period with billing rows
    // from another. The upstream also validates the explicit month, so a
    // rollover during the request fails closed and the browser retries.
    if current_utc_month() != period {
        return service_unavailable();
    }
    no_store(
        Json(decorate_margin(
            report,
            &identities,
            anchored_global_coverage_complete,
            account_metrics,
            &period,
            &account_metrics_as_of,
        ))
        .into_response(),
    )
}

pub fn spawn_detach_worker(state: std::sync::Arc<CpState>) {
    tokio::spawn(async move {
        loop {
            drain_detach_outbox(&state).await;
            tokio::time::sleep(Duration::from_secs(300)).await;
        }
    });
}

pub async fn drain_detach_outbox(state: &CpState) {
    let account_ids = match state
        .repositories
        .billing()
        .pending_billing_detach_ids(50)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            warn!(error = %error, "billing detach scan deferred");
            return;
        }
    };
    for account_id in account_ids {
        match state.billing.detach(&account_id).await {
            Ok(response) if response.detached => {
                if let Err(error) = state
                    .repositories
                    .billing()
                    .complete_billing_detach(&account_id)
                    .await
                {
                    warn!(error = %error, "billing detach acknowledgement deferred");
                }
            }
            _ => {
                let _ = state
                    .repositories
                    .billing()
                    .record_billing_detach_failure(&account_id)
                    .await;
                warn!("billing detach deferred");
            }
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct FakeBillingGateway;

#[cfg(test)]
#[async_trait]
impl BillingGateway for FakeBillingGateway {
    async fn summary(&self, _account_id: &str) -> Result<Value, BillingError> {
        Ok(serde_json::json!({
            "plan": {"id":"free","name":"Free"},
            "usage": {"allowance_seconds":1800,"used_seconds":0,"remaining_seconds":1800},
            "recording": {"allowed":true,"reason":null}
        }))
    }

    async fn authorize(
        &self,
        _request: &UsageAuthorizeRequest,
    ) -> Result<UsageAuthorizeResponse, BillingError> {
        Ok(UsageAuthorizeResponse {
            decision: "allow".into(),
            reason: None,
            duplicate: false,
            summary: self.summary("").await?,
        })
    }

    async fn checkout(
        &self,
        _account_id: &str,
        _request: &CheckoutRequest,
    ) -> Result<UrlResponse, BillingError> {
        Ok(UrlResponse {
            url: "https://checkout.example.test/session".into(),
        })
    }

    async fn portal(&self, _account_id: &str) -> Result<UrlResponse, BillingError> {
        Ok(UrlResponse {
            url: "https://account.example.test/session".into(),
        })
    }

    async fn report_vertex_usage(
        &self,
        events: &[VertexUsageEvent],
    ) -> Result<VertexUsageBatchResponse, BillingError> {
        Ok(VertexUsageBatchResponse {
            accepted: events.len(),
            duplicates: 0,
            unpriced: 0,
            ambiguous: 0,
        })
    }

    async fn report_vertex_coverage(
        &self,
        _snapshot: &VertexCoverageSnapshot,
    ) -> Result<VertexCoverageResponse, BillingError> {
        Ok(VertexCoverageResponse {
            accepted: true,
            duplicate: false,
            stale: false,
        })
    }

    async fn admin_margin(
        &self,
        _month: &str,
        _limit: u8,
        _after: Option<&str>,
    ) -> Result<Value, BillingError> {
        Ok(serde_json::json!({
            "generated_at": "2026-08-09T12:00:00.000Z",
            "period": {"starts_at":"2026-08-01T00:00:00Z","ends_at":"2026-09-01T00:00:00Z"},
            "rows": [],
            "next_cursor": null,
            "cost_reconciliation": {},
            "cost_completeness": "partial"
        }))
    }

    async fn detach(&self, _account_id: &str) -> Result<DetachResponse, BillingError> {
        Ok(DetachResponse { detached: true })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{FakeGcs, FakeKms};
    use crate::store::Store;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct ProbeGateway {
        admin_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BillingGateway for ProbeGateway {
        async fn summary(&self, _: &str) -> Result<Value, BillingError> {
            unreachable!()
        }
        async fn authorize(
            &self,
            _: &UsageAuthorizeRequest,
        ) -> Result<UsageAuthorizeResponse, BillingError> {
            unreachable!()
        }
        async fn checkout(
            &self,
            _: &str,
            _: &CheckoutRequest,
        ) -> Result<UrlResponse, BillingError> {
            unreachable!()
        }
        async fn portal(&self, _: &str) -> Result<UrlResponse, BillingError> {
            unreachable!()
        }
        async fn report_vertex_usage(
            &self,
            _: &[VertexUsageEvent],
        ) -> Result<VertexUsageBatchResponse, BillingError> {
            unreachable!()
        }
        async fn report_vertex_coverage(
            &self,
            _: &VertexCoverageSnapshot,
        ) -> Result<VertexCoverageResponse, BillingError> {
            unreachable!()
        }
        async fn admin_margin(
            &self,
            _: &str,
            _: u8,
            _: Option<&str>,
        ) -> Result<Value, BillingError> {
            self.admin_calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({}))
        }
        async fn detach(&self, _: &str) -> Result<DetachResponse, BillingError> {
            unreachable!()
        }
    }

    fn probe_state(admin_calls: Arc<AtomicUsize>) -> Arc<CpState> {
        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let control = Arc::new(super::super::control_store::ControlStore::new(
            kms.clone(),
            gcs.clone(),
        ));
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        Arc::new(CpState {
            kms: Arc::clone(&store.kms),
            durable_recording_storage_bound: store.durable_recording_storage_bound(),
            store: Arc::clone(&store),
            control: Arc::clone(&control),
            repositories: crate::persistence::RepositorySet::legacy(control, store),
            billing: Arc::new(ProbeGateway { admin_calls }),
            recording_lease_gate: Arc::new(RecordingLeaseGates::default()),
            config: Arc::new(super::super::CpConfig {
                base_url: "http://localhost:8080".into(),
                jwt_secrets: vec!["test".into()],
                google_desktop_client_id: "desktop".into(),
                google_ios_client_id: "ios".into(),
                google_web_client_id: "web".into(),
                google_web_client_secret: "secret".into(),
                admin_user_ids: vec!["11111111-1111-4111-8111-111111111111".into()],
                signup_limit_per_day: crate::cp::control_store::TEST_SIGNUP_LIMIT,
                scheduler_sa_email: None,
                vertex_project: "project".into(),
                vertex_location: "global".into(),
                vertex_model: "model".into(),
                quota_utterances_per_day: 1,
                quota_screenshots_per_day: 1,
                quota_mcp_calls_per_day: 1,
                quota_vertex_output_tokens_per_day: 1,
                web_origin: "http://localhost:3000".into(),
                reviewer_auth: None,
                apple_sign_in: None,
                billing_enforcement_mode: super::super::BillingEnforcementMode::Enforce,
            }),
            user_verifier: Arc::new(super::super::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            reference_batch_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            oauth_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            test_email_limiter: super::super::limits::RateLimiter::new(1.0, 1.0),
            email_transport: None,
            push_transport: None,
            embedding: None,
            voice: None,
        })
    }

    #[test]
    fn batch_accounting_requires_every_event_to_be_classified() {
        assert!(VertexUsageBatchResponse {
            accepted: 3,
            duplicates: 1,
            unpriced: 1,
            ambiguous: 1,
        }
        .accounts_for(4));
        assert!(!VertexUsageBatchResponse {
            accepted: 1,
            duplicates: 0,
            unpriced: 0,
            ambiguous: 0,
        }
        .accounts_for(2));
        assert!(!VertexUsageBatchResponse {
            accepted: 1,
            duplicates: 0,
            unpriced: 2,
            ambiguous: 0,
        }
        .accounts_for(1));
    }

    #[test]
    fn coverage_ack_requires_exactly_one_terminal_classification() {
        assert!(VertexCoverageResponse {
            accepted: true,
            duplicate: false,
            stale: false,
        }
        .acknowledged());
        assert!(!VertexCoverageResponse {
            accepted: false,
            duplicate: false,
            stale: true,
        }
        .acknowledged());
        assert!(!VertexCoverageResponse {
            accepted: true,
            duplicate: true,
            stale: false,
        }
        .acknowledged());
    }

    #[test]
    fn utc_month_window_detects_a_mid_scan_rollover() {
        let before_ms =
            super::super::isotime::parse_epoch_millis("2026-08-31T23:59:59.999Z").unwrap();
        let after_ms =
            super::super::isotime::parse_epoch_millis("2026-09-01T00:00:00.000Z").unwrap();
        let before = UNIX_EPOCH + Duration::from_millis(before_ms as u64);
        let after = UNIX_EPOCH + Duration::from_millis(after_ms as u64);
        assert_eq!(utc_month_at(before), "2026-08");
        assert_eq!(utc_month_at(after), "2026-09");
        assert_ne!(utc_month_at(before), utc_month_at(after));
    }

    #[test]
    fn public_contract_validation_is_fail_closed() {
        assert!(valid_checkout(&CheckoutRequest {
            plan_id: "pro".into(),
            interval: "month".into(),
        }));
        assert!(!valid_checkout(&CheckoutRequest {
            plan_id: "pro".into(),
            interval: "year".into(),
        }));
        assert!(valid_external_action_url(
            "https://checkout.example.test/session"
        ));
        assert!(!valid_external_action_url(
            "http://checkout.example.test/session"
        ));
        assert!(!valid_external_action_url(
            "https://user@checkout.example.test/session"
        ));
        assert!(valid_margin_query(&MarginQuery {
            limit: Some(100),
            after: Some("a".repeat(43)),
        }));
        assert!(!valid_margin_query(&MarginQuery {
            limit: Some(0),
            after: None,
        }));
        assert!(serde_urlencoded::from_str::<MarginQuery>("period=2026-08").is_err());
    }

    #[test]
    fn checkout_conflicts_are_not_mislabeled_as_unavailability() {
        let conflict = checkout_response(Err(BillingError::Rejected(409)));
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(conflict.headers().get(CACHE_CONTROL).unwrap(), "no-store");

        let rejected = checkout_response(Err(BillingError::Rejected(422)));
        assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);

        let invalid_destination = checkout_response(Ok(UrlResponse {
            url: "http://checkout.example.test/session".into(),
        }));
        assert_eq!(
            invalid_destination.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn denial_reasons_are_bounded_before_reaching_clients() {
        assert_eq!(
            public_denial_code(Some("allowance_exhausted")),
            "recording_allowance_exhausted"
        );
        assert_eq!(
            public_denial_code(Some("upstream secret detail")),
            "recording_not_entitled"
        );
    }

    #[test]
    fn recording_requests_are_strict_and_idempotent() {
        let request = RecordingLeaseRequest {
            request_id: "12345678-1234-4234-8234-123456789abc".into(),
            lease_id: None,
        };
        assert!(valid_recording_lease(&request));
        assert_eq!(
            recording_event_id("acct_random", &request.request_id),
            recording_event_id("acct_random", &request.request_id)
        );
        assert_ne!(
            recording_event_id("acct_random", &request.request_id),
            recording_event_id("acct_random", "22345678-1234-4234-8234-123456789abc")
        );
        assert!(!valid_recording_lease(&RecordingLeaseRequest {
            request_id: "not-a-uuid".into(),
            lease_id: None,
        }));
        assert_eq!(
            offline_recording_event_id("acct_random", &request.request_id),
            offline_recording_event_id("acct_random", &request.request_id)
        );
        assert_ne!(
            offline_recording_event_id("acct_random", &request.request_id),
            recording_event_id("acct_random", &request.request_id)
        );
        assert!(
            serde_json::from_value::<OfflineRecordingUsageRequest>(serde_json::json!({
                "request_id":request.request_id
            }))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<OfflineRecordingUsageRequest>(serde_json::json!({
                "request_id":request.request_id,
                "capture_session_id":"must-not-cross-billing-boundary"
            }))
            .is_err()
        );
    }

    #[test]
    fn old_or_unknown_duplicate_cannot_mint_a_fresh_lease() {
        assert!(duplicate_is_conflict(false, true));
        assert!(!duplicate_is_conflict(true, true));
        assert!(!duplicate_is_conflict(false, false));
    }

    #[test]
    fn request_id_payload_conflicts_and_unsafe_early_renewals_are_rejected() {
        let row = super::super::control_store::RecordingLeaseRequestRow {
            requested_lease_id: None,
            issued_lease_id:
                "lease_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            expires_at: "2026-08-09T18:01:00.000Z".into(),
            state: "pending".into(),
            summary: None,
            denial_code: None,
        };
        assert!(lease_request_matches(
            &row,
            &RecordingLeaseRequest {
                request_id: "12345678-1234-4234-8234-123456789abc".into(),
                lease_id: None,
            }
        ));
        assert!(!lease_request_matches(
            &row,
            &RecordingLeaseRequest {
                request_id: "12345678-1234-4234-8234-123456789abc".into(),
                lease_id: Some(row.issued_lease_id.clone()),
            }
        ));
        assert!(renewal_too_early(1_000, 26_001));
        assert!(!renewal_too_early(1_000, 26_000));
        assert!(!renewal_too_early(1_000, 21_001));
        // Clock-skew tolerance applies only to a renewal that presents the
        // active lease id. It must not move the fresh-null reattach/charge
        // boundary from the public 20-second contract.
        assert!(can_reattach_paid_lease(1_000, 21_001));
        assert!(!can_reattach_paid_lease(1_000, 21_000));
        assert!(!can_reattach_paid_lease(21_001, 21_000));
    }

    #[test]
    fn successful_final_minute_remains_an_authorized_lease() {
        let summary = lease_authorized_summary(serde_json::json!({
            "usage":{"allowance_seconds":300,"used_seconds":300,"remaining_seconds":0},
            "recording":{"allowed":false,"reason":"allowance_exhausted"}
        }));
        assert_eq!(summary["usage"]["used_seconds"], 240);
        assert_eq!(summary["usage"]["remaining_seconds"], 60);
        assert_eq!(summary["recording"]["allowed"], true);
        assert_eq!(summary["recording"]["reason"], Value::Null);
    }

    #[test]
    fn margin_decoration_removes_pseudonyms_and_labels_logical_storage() {
        let decorated = decorate_margin(
            serde_json::json!({
                "generated_at":"2026-08-09T12:01:00.000Z",
                "rows": [{"account_id":"acct_random","direct_vertex":{"complete":true,"estimated_total_usd_micros":1,
                    "producer_coverage":{"freshness_max_seconds":300}}}],
                "next_cursor": null
            }),
            &[MarginIdentity {
                email: "owner@example.com".into(),
                account_id: "acct_random".into(),
                drivers: Some(AccountDrivers {
                    storage_bytes: 123,
                    accepted_email_count: 4,
                    vertex_coverage: Some(LocalVertexCoverage {
                        sequence: 7,
                        pending_events: 0,
                        lost_events: 0,
                        observed_at: "2026-08-09T12:00:00.000Z".into(),
                    }),
                }),
            }],
            true,
            RetainedAccountMetrics {
                retained_active_accounts: 7,
                new_retained_active_accounts_mtd: 2,
            },
            "2026-08",
            "2026-08-09T12:01:01.000Z",
        );
        let account = &decorated["accounts"][0];
        assert_eq!(account["email"], "owner@example.com");
        assert!(account.get("account_id").is_none());
        assert_eq!(account["storage_bytes"], 123);
        assert_eq!(account["storage_measurement"], "current_logical_bytes");
        assert_eq!(account["email_delivery"]["accepted_message_count"], 4);
        assert!(account["email_delivery"]["usd_micros"].is_null());
        assert_eq!(account["direct_vertex"]["producer_coverage"]["sequence"], 7);
        assert_eq!(
            account["direct_vertex"]["producer_coverage"]["age_seconds"],
            60
        );
        assert_eq!(account["direct_vertex"]["producer_coverage"]["fresh"], true);
        assert_eq!(
            account["direct_vertex"]["producer_coverage"]["status"],
            "bounded_recent_zero_backlog"
        );
        assert_eq!(decorated["margin_kind"], "estimated_contribution_margin");
        assert_eq!(
            decorated["account_metrics"],
            serde_json::json!({
                "retained_active_accounts": 7,
                "new_retained_active_accounts_mtd": 2,
                "period": "2026-08",
                "as_of": "2026-08-09T12:01:01.000Z"
            })
        );
    }

    #[test]
    fn local_pending_coverage_nulls_direct_cost_and_unallocates_actual_vertex() {
        let decorated = decorate_margin(
            serde_json::json!({
                "generated_at":"2026-08-09T12:02:00.000Z",
                "rows": [{
                    "account_id":"acct_random",
                    "commercial":{"opaque":true},
                    "direct_vertex": {
                        "complete": true,
                        "estimated_total_usd_micros": 100,
                        "by_operation": {"audio_understanding": {
                            "event_count":1,"incomplete_event_count":0,
                            "estimated_known_uncached_input_audio_usd_micros":40,
                            "uncached_input_audio_usd_micros":40,"complete":true
                        }},
                        "producer_coverage": {"reported":true,"pending_events":0,"lost_events":0,"sequence":6,
                            "observed_at":"2026-08-09T12:00:00.000Z","age_seconds":120,
                            "freshness_max_seconds":300,"fresh":true,"basis":"bounded_recent_zero_backlog_snapshot",
                            "population_complete":false,"status":"bounded_recent_zero_backlog","complete":true}
                    },
                    "allocated_gcp_observed_costs": {"vertex": {"usd_micros":100,"cash_usd_micros":90,
                        "gross_usd_micros":100,"credits_usd_micros":-10,"net_usd_micros":90,
                        "status":"allocated_observed_provisional"}},
                    "estimated_direct_contribution_usd_micros": 900,
                    "estimated_cash_direct_contribution_after_credits_usd_micros": 910,
                    "modeled_rate_card_direct_contribution_usd_micros":900,
                    "modeled_rate_card_direct_margin_bps":9000,
                    "estimated_contribution_before_storage_and_shared_usd_micros": 900,
                    "estimated_margin_before_storage_and_shared_bps": 9000
                }],
                "allocation_basis": {"vertex_cost_complete":true},
                "allocation": {
                    "status":"direct_vertex_reconciled_overhead_unallocated",
                    "unallocated_usd_micros":{"vertex":0},
                    "vertex_reconciliation":{"complete_producer_coverage":true,"observed_within_tolerance":true}
                },
                "allocation_status":"direct_vertex_reconciled_overhead_unallocated",
                "cost_reconciliation":{"categories_usd_micros":{"vertex_direct_reconciliation":{"net_usd_micros":90}}},
                "cost_completeness": true
            }),
            &[MarginIdentity {
                email: "owner@example.com".into(),
                account_id: "acct_random".into(),
                drivers: Some(AccountDrivers {
                    storage_bytes: 123,
                    accepted_email_count: 4,
                    vertex_coverage: Some(LocalVertexCoverage {
                        sequence: 8,
                        pending_events: 1,
                        lost_events: 0,
                        observed_at: "2026-08-09T12:01:00.000Z".into(),
                    }),
                }),
            }],
            true,
            RetainedAccountMetrics {
                retained_active_accounts: 7,
                new_retained_active_accounts_mtd: 2,
            },
            "2026-08",
            "2026-08-09T12:01:01.000Z",
        );
        let account = &decorated["accounts"][0];
        assert_eq!(account["direct_vertex"]["complete"], false);
        assert!(account["direct_vertex"]["estimated_total_usd_micros"].is_null());
        assert_eq!(
            account["direct_vertex"]["by_operation"]["audio_understanding"]["complete"],
            false
        );
        assert!(
            account["direct_vertex"]["by_operation"]["audio_understanding"]
                ["uncached_input_audio_usd_micros"]
                .is_null()
        );
        assert_eq!(
            account["direct_vertex"]["producer_coverage"],
            serde_json::json!({
                "reported":true,"pending_events":1,"lost_events":0,"sequence":8,
                "observed_at":"2026-08-09T12:01:00.000Z","age_seconds":60,
                "freshness_max_seconds":300,"fresh":true,
                "basis":"bounded_recent_zero_backlog_snapshot","population_complete":false,
                "status":"pending_events","complete":false
            })
        );
        assert!(account["estimated_direct_contribution_usd_micros"].is_null());
        assert!(account["estimated_cash_direct_contribution_after_credits_usd_micros"].is_null());
        assert!(account["modeled_rate_card_direct_contribution_usd_micros"].is_null());
        assert!(account["modeled_rate_card_direct_margin_bps"].is_null());
        assert!(account["allocated_gcp_observed_costs"]["vertex"]["usd_micros"].is_null());
        assert!(account["allocated_gcp_observed_costs"]["vertex"]["cash_usd_micros"].is_null());
        assert_eq!(
            account["allocated_gcp_observed_costs"]["vertex"]["status"],
            "unallocated"
        );
        assert_eq!(account["commercial"]["opaque"], true);
        assert_eq!(
            decorated["allocation"]["unallocated_usd_micros"]["vertex"],
            90
        );
        assert_eq!(
            decorated["allocation"]["vertex_reconciliation"]["complete_producer_coverage"],
            false
        );
        assert_eq!(
            decorated["allocation"]["vertex_reconciliation"]["observed_within_tolerance"],
            false
        );
    }

    #[test]
    fn margin_page_account_ids_are_strict_and_bounded_before_index_reads() {
        let first = format!("acct_{}", "a".repeat(64));
        let second = format!("acct_{}", "b".repeat(64));
        let row = |account_id: &str| {
            serde_json::json!({
                "account_id":account_id,
                "commercial":{"opaque":true},
                "direct_vertex":{"producer_coverage":{
                    "reported":true,"age_seconds":1,"freshness_max_seconds":300,
                    "fresh":true,"basis":"bounded_recent_zero_backlog_snapshot",
                    "population_complete":false,"status":"bounded_recent_zero_backlog",
                    "complete":true
                }},
                "allocated_gcp_observed_costs":{"vertex":{}}
            })
        };
        let report = |rows: Vec<Value>| {
            serde_json::json!({
                "generated_at":"2026-08-09T12:00:00.000Z",
                "rows":rows
            })
        };
        assert_eq!(
            validated_margin_account_ids(&report(vec![row(&first), row(&second)]), 2)
                .unwrap()
                .len(),
            2
        );
        assert!(validated_margin_account_ids(&report(vec![row("acct_random")]), 50).is_none());
        assert!(
            validated_margin_account_ids(&report(vec![row(&first), row(&first)]), 50).is_none()
        );
        assert!(
            validated_margin_account_ids(&report(vec![row(&first), row(&second)]), 1).is_none()
        );

        let mut legacy = row(&first);
        legacy
            .as_object_mut()
            .unwrap()
            .insert("allocated_invoice_costs".into(), serde_json::json!({}));
        assert!(validated_margin_account_ids(&report(vec![legacy]), 50).is_none());

        let mut opaque_commercial_extension = row(&first);
        opaque_commercial_extension
            .as_object_mut()
            .unwrap()
            .insert("commercial_extension".into(), Value::from(1));
        assert!(
            validated_margin_account_ids(&report(vec![opaque_commercial_extension]), 50).is_some()
        );
    }

    #[tokio::test]
    async fn admin_capabilities_are_owner_named_and_legacy_compatible() {
        let calls = Arc::new(AtomicUsize::new(0));
        let response = admin_capabilities(
            State(probe_state(calls.clone())),
            Extension(AuthUser("11111111-1111-4111-8111-111111111111".into())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
        let body = axum::body::to_bytes(response.into_body(), 4 * 1024)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["owner"], true);
        assert_eq!(value["admin"], true);
        assert_eq!(value["margin_report"], true);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn non_admin_capability_denial_is_no_store() {
        let calls = Arc::new(AtomicUsize::new(0));
        let response = admin_capabilities(
            State(probe_state(calls.clone())),
            Extension(AuthUser("22222222-2222-4222-8222-222222222222".into())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn non_admin_margin_denial_precedes_identity_and_upstream_access() {
        let calls = Arc::new(AtomicUsize::new(0));
        let response = admin_margin(
            State(probe_state(calls.clone())),
            Extension(AuthUser("22222222-2222-4222-8222-222222222222".into())),
            Query(MarginQuery {
                limit: None,
                after: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
    }
}
