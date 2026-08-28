//! Privacy-minimized APNs installation registry, delivery worker, and browser handoff.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, put},
    Extension, Json, Router,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use crate::cp::auth::AuthUser;
use crate::cp::CpState;
use crate::error::{EnclaveError, Result};
use crate::persistence::{PushInstallation, PushProviderOutcome};

const IOS_TOPIC: &str = "com.kioku.ios";
const MACOS_TOPIC: &str = "com.kiokuu.app";
const INSTALLATION_BINDING_PREFIX: &str = "p1:";
const MAX_DELIVERIES_PER_SWEEP: usize = 2;
const MAX_ATTEMPTS: i32 = 10;
const MAX_DELIVERY_AGE_SECONDS: i64 = 24 * 60 * 60;
const GLOBAL_SEND_PACE_MILLIS: u64 = 250;
const RETRYABLE_CIRCUIT_SECONDS: u64 = 60;
const PROVIDER_CIRCUIT_SECONDS: u64 = 5 * 60;

/// Durable activation and token fence. Version `p1` binds the exact PostgreSQL
/// installation generation that was enabled when the finalizer created the
/// delivery. Bare pre-activation rows remain cancellation-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PushInstallationBinding {
    pub(crate) installation_id: String,
    pub(crate) token_generation: i64,
}

impl PushInstallationBinding {
    pub(crate) fn new(installation_id: &str, token_generation: i64) -> Result<Self> {
        if !valid_uuid(installation_id) || token_generation <= 0 {
            return Err(EnclaveError::Store(
                "push installation binding is invalid".into(),
            ));
        }
        Ok(Self {
            installation_id: installation_id.to_owned(),
            token_generation,
        })
    }

    pub(crate) fn encode(&self) -> String {
        format!(
            "{INSTALLATION_BINDING_PREFIX}{}:{}",
            self.installation_id, self.token_generation
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationRequest {
    platform: String,
    environment: String,
    device_token: String,
}

#[derive(Debug, Serialize)]
struct InstallationResponse {
    id: String,
    platform: String,
    environment: String,
    enabled: bool,
}

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route(
            "/api/push/installations/{installation_id}",
            put(upsert_installation).delete(delete_installation),
        )
        .route(
            "/api/notifications/{handoff_handle}",
            get(resolve_notification_handoff),
        )
}

async fn upsert_installation(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(installation_id): Path<String>,
    Json(request): Json<InstallationRequest>,
) -> Response {
    if !valid_uuid(&installation_id) {
        return bad_request("installation_id must be a UUID");
    }
    let topic = match request.platform.as_str() {
        "ios" => IOS_TOPIC,
        "macos" => MACOS_TOPIC,
        _ => return bad_request("platform must be ios or macos"),
    };
    if !matches!(request.environment.as_str(), "sandbox" | "production") {
        return bad_request("environment must be sandbox or production");
    }
    if !valid_device_token(&request.device_token) {
        return bad_request("device_token must be bounded hexadecimal APNs token data");
    }
    let installation = PushInstallation {
        id: installation_id,
        user_id: user.0,
        platform: request.platform,
        topic: topic.into(),
        environment: request.environment,
        device_token: request.device_token.to_ascii_lowercase(),
        token_generation: 1,
        enabled: true,
    };
    match state
        .repositories
        .notifications()
        .upsert_push_installation(installation)
        .await
    {
        Ok(installed) => Json(InstallationResponse {
            id: installed.id,
            platform: installed.platform,
            environment: installed.environment,
            enabled: installed.enabled,
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn delete_installation(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(installation_id): Path<String>,
) -> Response {
    if !valid_uuid(&installation_id) {
        return bad_request("installation_id must be a UUID");
    }
    match state
        .repositories
        .notifications()
        .delete_push_installation(&user.0, &installation_id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => EnclaveError::NotFound.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn resolve_notification_handoff(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(handoff_handle): Path<String>,
) -> Response {
    if !valid_handoff(&handoff_handle) {
        return EnclaveError::NotFound.into_response();
    }
    let resolved = state
        .repositories
        .deliveries()
        .resolve_push_handoff(&user.0, &handoff_handle)
        .await;
    match resolved {
        Ok(Some(memory_id)) => Json(json!({"memory_id": memory_id})).into_response(),
        Ok(None) => EnclaveError::NotFound.into_response(),
        Err(error) => super::routed_read_unavailable("push_handoff", &error),
    }
}

fn bad_request(message: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, message).into_response()
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn valid_handoff(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_device_token(value: &str) -> bool {
    (32..=200).contains(&value.len())
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, PartialEq, Eq)]
pub struct PushRequest {
    pub topic: String,
    pub environment: String,
    pub device_token: String,
    pub token_generation: i64,
    pub apns_id: String,
    pub collapse_id: String,
    pub handoff_handle: String,
    pub expiration_epoch_seconds: u64,
}

impl std::fmt::Debug for PushRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PushRequest")
            .field("topic", &self.topic)
            .field("environment", &self.environment)
            .field("device_token", &"[REDACTED]")
            .field("token_generation", &self.token_generation)
            .field("apns_id", &"[REDACTED]")
            .field("collapse_id", &"[REDACTED]")
            .field("handoff_handle", &"[REDACTED]")
            .field("expiration_epoch_seconds", &self.expiration_epoch_seconds)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushTransportError {
    Retryable {
        status: Option<u16>,
        code: &'static str,
        retry_after_seconds: Option<u64>,
        scope: PushRetryScope,
    },
    TokenTerminal {
        status: u16,
        code: &'static str,
    },
    ProviderTerminal {
        status: Option<u16>,
        code: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushRetryScope {
    TokenLocal,
    ProviderWide,
}

#[async_trait]
pub trait PushTransport: Send + Sync {
    async fn send(&self, request: PushRequest) -> std::result::Result<u16, PushTransportError>;
}

struct ProviderTokenCache {
    token: String,
    created_at: u64,
}

pub struct ApnsCredential {
    team_id: String,
    key_id: String,
    key: EncodingKey,
    client: reqwest::Client,
    token: Mutex<Option<ProviderTokenCache>>,
}

impl ApnsCredential {
    pub fn new(team_id: String, key_id: String, private_key_pem: &str) -> Result<Self> {
        if team_id.is_empty() || key_id.is_empty() {
            return Err(EnclaveError::Config(
                "APNs team and key ids are required".into(),
            ));
        }
        let key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
            .map_err(|_| EnclaveError::Config("APNs private key is invalid".into()))?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .http2_adaptive_window(true)
            .build()
            .map_err(|_| EnclaveError::Config("APNs HTTP/2 client could not initialize".into()))?;
        Ok(Self {
            team_id,
            key_id,
            key,
            client,
            token: Mutex::new(None),
        })
    }

    async fn provider_token(&self) -> std::result::Result<String, PushTransportError> {
        let now = epoch_seconds();
        let mut cached = self.token.lock().await;
        if let Some(value) = cached
            .as_ref()
            .filter(|value| now.saturating_sub(value.created_at) < 50 * 60)
        {
            return Ok(value.token.clone());
        }
        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            iat: u64,
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let token = encode(
            &header,
            &Claims {
                iss: &self.team_id,
                iat: now,
            },
            &self.key,
        )
        .map_err(|_| PushTransportError::ProviderTerminal {
            status: None,
            code: "provider_token_invalid",
        })?;
        *cached = Some(ProviderTokenCache {
            token: token.clone(),
            created_at: now,
        });
        Ok(token)
    }

    async fn send(
        &self,
        endpoint: &str,
        request: &PushRequest,
    ) -> std::result::Result<u16, PushTransportError> {
        let provider_token = self.provider_token().await?;
        let response = self
            .client
            .post(format!("{endpoint}/3/device/{}", request.device_token))
            .bearer_auth(provider_token)
            .header("apns-push-type", "alert")
            .header("apns-topic", &request.topic)
            .header("apns-priority", "5")
            .header(
                "apns-expiration",
                request.expiration_epoch_seconds.to_string(),
            )
            .header("apns-id", &request.apns_id)
            .header("apns-collapse-id", &request.collapse_id)
            .json(&notification_payload(&request.handoff_handle))
            .send()
            .await
            .map_err(|_| PushTransportError::Retryable {
                status: None,
                code: "network",
                retry_after_seconds: None,
                scope: PushRetryScope::ProviderWide,
            })?;
        let status = response.status().as_u16();
        if status == 200 {
            return Ok(status);
        }
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(|seconds| seconds.clamp(1, 6 * 60 * 60));
        #[derive(Deserialize)]
        struct ErrorBody {
            reason: Option<String>,
        }
        let reason = response
            .json::<ErrorBody>()
            .await
            .ok()
            .and_then(|body| body.reason)
            .unwrap_or_default();
        if matches!(
            reason.as_str(),
            "BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered"
        ) {
            return Err(PushTransportError::TokenTerminal {
                status,
                code: "invalid_device_token",
            });
        }
        if status == 429 || status >= 500 {
            let scope = apns_retry_scope(status, &reason);
            return Err(PushTransportError::Retryable {
                status: Some(status),
                code: if scope == PushRetryScope::TokenLocal {
                    "provider_retryable"
                } else if status == 429 {
                    "provider_token_rate_limited"
                } else {
                    "provider_retryable"
                },
                retry_after_seconds,
                scope,
            });
        }
        Err(PushTransportError::ProviderTerminal {
            status: Some(status),
            code: "provider_configuration",
        })
    }
}

fn apns_retry_scope(status: u16, reason: &str) -> PushRetryScope {
    if status == 429 && reason == "TooManyRequests" {
        PushRetryScope::TokenLocal
    } else {
        PushRetryScope::ProviderWide
    }
}

fn notification_payload(handoff_handle: &str) -> serde_json::Value {
    json!({
        "aps": {
            "alert": {"title": "Kioku", "body": "Your memory is ready."},
            "category": "KIOKU_MEMORY_READY",
            "thread-id": "kioku.memories"
        },
        "v": 1,
        "handoff": handoff_handle
    })
}

pub struct ApnsTransport {
    production: Arc<ApnsCredential>,
    sandbox: Option<Arc<ApnsCredential>>,
}

impl ApnsTransport {
    pub fn new(production: ApnsCredential, sandbox: Option<ApnsCredential>) -> Self {
        Self {
            production: Arc::new(production),
            sandbox: sandbox.map(Arc::new),
        }
    }
}

#[async_trait]
impl PushTransport for ApnsTransport {
    async fn send(&self, request: PushRequest) -> std::result::Result<u16, PushTransportError> {
        match request.environment.as_str() {
            "production" => {
                self.production
                    .send("https://api.push.apple.com", &request)
                    .await
            }
            "sandbox" => match self.sandbox.as_ref() {
                Some(credential) => {
                    credential
                        .send("https://api.sandbox.push.apple.com", &request)
                        .await
                }
                None => Err(PushTransportError::ProviderTerminal {
                    status: None,
                    code: "sandbox_unconfigured",
                }),
            },
            _ => Err(PushTransportError::ProviderTerminal {
                status: None,
                code: "environment_invalid",
            }),
        }
    }
}

pub async fn deliver_user_pushes(
    state: &CpState,
    transport: &dyn PushTransport,
    user_id: &str,
) -> Result<()> {
    deliver_postgres_user_pushes(state, transport, user_id).await
}

async fn deliver_postgres_user_pushes(
    state: &CpState,
    transport: &dyn PushTransport,
    user_id: &str,
) -> Result<()> {
    let repository = state.repositories.deliveries();
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        let Some(candidate) = repository.next_push_candidate(user_id).await? else {
            break;
        };
        let frozen = crate::persistence::FrozenPushDelivery {
            topic: candidate.topic.clone(),
            environment: candidate.environment.clone(),
            device_token: candidate.device_token.clone(),
            token_generation: candidate.token_generation,
        };
        let mut claim = repository
            .claim_push(&candidate, frozen.clone(), 60)
            .await?;
        if claim.is_none() {
            tokio::time::sleep(Duration::from_millis(
                GLOBAL_SEND_PACE_MILLIS.saturating_add(25),
            ))
            .await;
            claim = repository.claim_push(&candidate, frozen, 60).await?;
        }
        let Some(claim) = claim else {
            break;
        };
        let created_at = crate::cp::isotime::parse_epoch_millis(&claim.created_at)
            .ok_or_else(|| EnclaveError::Store("push creation time is invalid".into()))?;
        let expiration_millis = created_at
            .checked_add(MAX_DELIVERY_AGE_SECONDS * 1_000)
            .ok_or_else(|| EnclaveError::Store("push expiration overflow".into()))?;
        let now = epoch_millis();
        if expiration_millis <= now {
            repository
                .settle_push(
                    &claim,
                    PushProviderOutcome::Failed {
                        status: None,
                        code: "delivery_expired".into(),
                    },
                    None,
                )
                .await?;
            continue;
        }
        let expiration_epoch_seconds = u64::try_from(expiration_millis / 1_000)
            .map_err(|_| EnclaveError::Store("push expiration is invalid".into()))?;
        let result = transport
            .send(PushRequest {
                topic: claim.request.topic.clone(),
                environment: claim.request.environment.clone(),
                device_token: claim.request.device_token.clone(),
                token_generation: claim.request.token_generation,
                apns_id: claim.delivery_id.clone(),
                collapse_id: claim.collapse_id.clone(),
                handoff_handle: claim.handoff_handle.clone(),
                expiration_epoch_seconds,
            })
            .await;
        let outcome_at = crate::cp::isotime::format_epoch_millis(epoch_millis());
        let (outcome, circuit_seconds) =
            classify_push_transport_result(result, claim.attempt_count, &outcome_at)?;
        repository
            .settle_push(&claim, outcome, circuit_seconds)
            .await?;
        emit_push_outcome("settled");
    }
    Ok(())
}

fn classify_push_transport_result(
    result: std::result::Result<u16, PushTransportError>,
    attempt_count: i64,
    outcome_at: &str,
) -> Result<(PushProviderOutcome, Option<i64>)> {
    Ok(match result {
        Ok(status) => (
            PushProviderOutcome::Accepted {
                status: i64::from(status),
            },
            None,
        ),
        Err(PushTransportError::TokenTerminal { status, code }) => (
            PushProviderOutcome::TokenTerminal {
                status: i64::from(status),
                code: code.into(),
            },
            None,
        ),
        Err(PushTransportError::Retryable {
            status,
            code: _,
            retry_after_seconds: _,
            scope,
        }) if status.is_none() => (
            PushProviderOutcome::Ambiguous,
            (scope == PushRetryScope::ProviderWide).then_some(RETRYABLE_CIRCUIT_SECONDS as i64),
        ),
        Err(PushTransportError::Retryable {
            status,
            code,
            retry_after_seconds,
            scope,
        }) => {
            let circuit = (scope == PushRetryScope::ProviderWide).then_some(
                i64::try_from(retry_after_seconds.unwrap_or(RETRYABLE_CIRCUIT_SECONDS))
                    .unwrap_or(RETRYABLE_CIRCUIT_SECONDS as i64)
                    .clamp(1, 6 * 60 * 60),
            );
            if attempt_count >= i64::from(MAX_ATTEMPTS) {
                (
                    PushProviderOutcome::Failed {
                        status: status.map(i64::from),
                        code: "attempt_cap".into(),
                    },
                    circuit,
                )
            } else {
                let delay = retry_after_seconds
                    .and_then(|seconds| i64::try_from(seconds).ok())
                    .unwrap_or_else(|| retry_delay(attempt_count))
                    .clamp(1, 6 * 60 * 60);
                (
                    PushProviderOutcome::Retry {
                        status: status.map(i64::from),
                        code: code.into(),
                        retry_at: add_seconds(outcome_at, delay)?,
                    },
                    circuit,
                )
            }
        }
        Err(PushTransportError::ProviderTerminal { status, code }) => {
            let outcome = if attempt_count >= i64::from(MAX_ATTEMPTS) {
                PushProviderOutcome::Failed {
                    status: status.map(i64::from),
                    code: code.into(),
                }
            } else {
                PushProviderOutcome::Retry {
                    status: status.map(i64::from),
                    code: code.into(),
                    retry_at: add_seconds(outcome_at, 60 * 60)?,
                }
            };
            (outcome, Some(PROVIDER_CIRCUIT_SECONDS as i64))
        }
    })
}

fn retry_delay(attempt: i64) -> i64 {
    let exponent = u32::try_from(attempt.saturating_sub(1).clamp(0, 8)).unwrap_or(0);
    (30_i64 * 2_i64.pow(exponent)).min(6 * 60 * 60)
}

fn add_seconds(timestamp: &str, seconds: i64) -> Result<String> {
    let millis = crate::cp::isotime::parse_epoch_millis(timestamp)
        .and_then(|value| value.checked_add(seconds.checked_mul(1_000)?))
        .ok_or_else(|| EnclaveError::Store("push retry timestamp overflow".into()))?;
    Ok(crate::cp::isotime::format_epoch_millis(millis))
}

fn epoch_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn emit_push_outcome(outcome: &'static str) {
    tracing::info!(
        metric = "push_outbox_outcome",
        outcome,
        count = 1,
        "push delivery outcome"
    );
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALLATION_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    fn request() -> PushRequest {
        PushRequest {
            topic: IOS_TOPIC.into(),
            environment: "production".into(),
            device_token: "ab".repeat(32),
            token_generation: 7,
            apns_id: "delivery-secret".into(),
            collapse_id: "collapse-secret".into(),
            handoff_handle: "handoff-secret".into(),
            expiration_epoch_seconds: 1_800_000_000,
        }
    }

    #[test]
    fn installation_binding_encodes_the_exact_generation() {
        let binding = PushInstallationBinding::new(INSTALLATION_ID, 7).unwrap();
        assert_eq!(binding.encode(), format!("p1:{INSTALLATION_ID}:7"));
        assert!(PushInstallationBinding::new(INSTALLATION_ID, 0).is_err());
        assert!(PushInstallationBinding::new("not-a-uuid", 7).is_err());
    }

    #[test]
    fn request_validators_are_bounded() {
        assert!(valid_uuid(INSTALLATION_ID));
        assert!(!valid_uuid("not-a-uuid"));
        assert!(valid_handoff(&"a".repeat(43)));
        assert!(!valid_handoff(&"a".repeat(42)));
        assert!(valid_device_token(&"ab".repeat(16)));
        assert!(valid_device_token(&"AB".repeat(100)));
        assert!(!valid_device_token(&"ab".repeat(15)));
        assert!(!valid_device_token(&format!("{}z", "a".repeat(31))));
    }

    #[test]
    fn notification_payload_is_generic_and_handoff_only() {
        let payload = notification_payload("opaque_handoff");
        assert_eq!(payload["aps"]["alert"]["title"], "Kioku");
        assert_eq!(payload["aps"]["alert"]["body"], "Your memory is ready.");
        assert_eq!(payload["handoff"], "opaque_handoff");
        let encoded = serde_json::to_string(&payload).unwrap();
        assert!(!encoded.contains("episode"));
        assert!(!encoded.contains("transcript"));
    }

    #[test]
    fn request_debug_redacts_provider_and_handoff_identifiers() {
        let debug = format!("{:?}", request());
        assert!(debug.contains(IOS_TOPIC));
        assert!(!debug.contains("delivery-secret"));
        assert!(!debug.contains("collapse-secret"));
        assert!(!debug.contains("handoff-secret"));
        assert!(!debug.contains(&"ab".repeat(32)));
    }

    #[test]
    fn apns_retry_scope_distinguishes_token_local_throttling() {
        assert_eq!(
            apns_retry_scope(429, "TooManyRequests"),
            PushRetryScope::TokenLocal
        );
        assert_eq!(
            apns_retry_scope(429, "TooManyProviderTokenUpdates"),
            PushRetryScope::ProviderWide
        );
        assert_eq!(
            apns_retry_scope(503, "ServiceUnavailable"),
            PushRetryScope::ProviderWide
        );
    }

    #[test]
    fn unknown_network_outcome_is_terminally_ambiguous() {
        let outcome_at = crate::cp::isotime::format_epoch_millis(0);
        let (outcome, circuit) = classify_push_transport_result(
            Err(PushTransportError::Retryable {
                status: None,
                code: "network",
                retry_after_seconds: None,
                scope: PushRetryScope::ProviderWide,
            }),
            1,
            &outcome_at,
        )
        .unwrap();

        assert_eq!(outcome, PushProviderOutcome::Ambiguous);
        assert_eq!(circuit, Some(RETRYABLE_CIRCUIT_SECONDS as i64));
    }

    #[test]
    fn definitive_retry_and_token_failure_classify_without_content() {
        let outcome_at = crate::cp::isotime::format_epoch_millis(0);
        let (retry, circuit) = classify_push_transport_result(
            Err(PushTransportError::Retryable {
                status: Some(429),
                code: "provider_retryable",
                retry_after_seconds: Some(17),
                scope: PushRetryScope::TokenLocal,
            }),
            1,
            &outcome_at,
        )
        .unwrap();
        assert!(matches!(
            retry,
            PushProviderOutcome::Retry {
                status: Some(429),
                ref code,
                ..
            } if code == "provider_retryable"
        ));
        assert_eq!(circuit, None);

        let (terminal, circuit) = classify_push_transport_result(
            Err(PushTransportError::TokenTerminal {
                status: 410,
                code: "invalid_device_token",
            }),
            1,
            &outcome_at,
        )
        .unwrap();
        assert_eq!(
            terminal,
            PushProviderOutcome::TokenTerminal {
                status: 410,
                code: "invalid_device_token".into(),
            }
        );
        assert_eq!(circuit, None);
    }

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(retry_delay(1), 30);
        assert_eq!(retry_delay(2), 60);
        assert_eq!(
            retry_delay(i64::MAX),
            retry_delay(i64::from(MAX_ATTEMPTS - 1))
        );
        assert!(retry_delay(i64::MAX) <= 6 * 60 * 60);
    }
}
