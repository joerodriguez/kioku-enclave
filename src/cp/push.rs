//! Privacy-minimized APNs installation registry, delivery worker, and browser handoff.

pub(crate) mod wal;

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
use crate::cp::control_store::PushInstallation;
use crate::cp::CpState;
use crate::error::{EnclaveError, Result};

const IOS_TOPIC: &str = "com.kioku.ios";
const MACOS_TOPIC: &str = "com.kiokuu.app";
const MAX_DELIVERIES_PER_SWEEP: usize = 10;
const MAX_ATTEMPTS: i32 = 10;

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
    match state.control.upsert_push_installation(installation).await {
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
        .control
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
    match state
        .store
        .resolve_push_handoff(&user.0, &handoff_handle)
        .await
    {
        Ok(Some(memory_id)) => Json(json!({"memory_id": memory_id})).into_response(),
        Ok(None) => EnclaveError::NotFound.into_response(),
        Err(error) => error.into_response(),
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
}

impl std::fmt::Debug for PushRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PushRequest")
            .field("topic", &self.topic)
            .field("environment", &self.environment)
            .field("device_token", &"[REDACTED]")
            .field("token_generation", &self.token_generation)
            .field("apns_id", &self.apns_id)
            .field("collapse_id", &self.collapse_id)
            .field("handoff_handle", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushTransportError {
    Retryable {
        status: Option<u16>,
        code: &'static str,
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
            .filter(|value| now - value.created_at < 50 * 60)
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
        let expiration = epoch_seconds() + 24 * 60 * 60;
        let response = self
            .client
            .post(format!("{endpoint}/3/device/{}", request.device_token))
            .bearer_auth(provider_token)
            .header("apns-push-type", "alert")
            .header("apns-topic", &request.topic)
            .header("apns-priority", "5")
            .header("apns-expiration", expiration.to_string())
            .header("apns-id", &request.apns_id)
            .header("apns-collapse-id", &request.collapse_id)
            .json(&notification_payload(&request.handoff_handle))
            .send()
            .await
            .map_err(|_| PushTransportError::Retryable {
                status: None,
                code: "network",
            })?;
        let status = response.status().as_u16();
        if status == 200 {
            return Ok(status);
        }
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
            return Err(PushTransportError::Retryable {
                status: Some(status),
                code: "provider_retryable",
            });
        }
        Err(PushTransportError::ProviderTerminal {
            status: Some(status),
            code: "provider_configuration",
        })
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
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        let Some(delivery) = state.store.next_push_delivery(user_id).await? else {
            break;
        };
        let Some(installation) = state
            .control
            .get_push_installation(user_id, &delivery.installation_id)
            .await?
            .filter(|installation| installation.enabled)
        else {
            update_delivery(
                state,
                user_id,
                &delivery,
                "cancelled",
                None,
                Some("installation_disabled"),
                None,
            )
            .await?;
            continue;
        };
        let request = PushRequest {
            topic: installation.topic,
            environment: installation.environment,
            device_token: installation.device_token,
            token_generation: installation.token_generation,
            apns_id: delivery.delivery_id.clone(),
            collapse_id: delivery.collapse_id.clone(),
            handoff_handle: delivery.handoff_handle.clone(),
        };
        match transport.send(request).await {
            Ok(status) => {
                update_delivery(
                    state,
                    user_id,
                    &delivery,
                    "accepted",
                    Some(status),
                    None,
                    None,
                )
                .await?;
            }
            Err(PushTransportError::TokenTerminal { status, code }) => {
                state
                    .control
                    .disable_push_installation_generation(
                        user_id,
                        &delivery.installation_id,
                        installation.token_generation,
                    )
                    .await?;
                update_delivery(
                    state,
                    user_id,
                    &delivery,
                    "failed",
                    Some(status),
                    Some(code),
                    None,
                )
                .await?;
            }
            Err(PushTransportError::Retryable { status, code }) => {
                let attempts = delivery.attempt_count + 1;
                let terminal = attempts >= MAX_ATTEMPTS;
                update_delivery(
                    state,
                    user_id,
                    &delivery,
                    if terminal { "failed" } else { "retry" },
                    status,
                    Some(code),
                    (!terminal).then(|| retry_delay(attempts)),
                )
                .await?;
            }
            Err(PushTransportError::ProviderTerminal { status, code }) => {
                let attempts = delivery.attempt_count + 1;
                let terminal = attempts >= MAX_ATTEMPTS;
                update_delivery(
                    state,
                    user_id,
                    &delivery,
                    if terminal { "failed" } else { "retry" },
                    status,
                    Some(code),
                    (!terminal).then_some(60 * 60),
                )
                .await?;
                // Provider-wide credential/topic faults must not disable an
                // installation or churn every queued delivery in one sweep.
                break;
            }
        }
    }
    Ok(())
}

async fn update_delivery(
    state: &CpState,
    user_id: &str,
    delivery: &crate::store::PushDeliveryRow,
    status: &str,
    response_status: Option<u16>,
    error_code: Option<&str>,
    retry_after_seconds: Option<i64>,
) -> Result<()> {
    if state.store.is_wal_authoritative(user_id) {
        // ADR-0022 F13: routed predecessor read plus the sealed settlement.
        // next_attempt_at is computed in Rust exactly as the legacy store
        // method computes it, then written absolutely.
        let probe_id = delivery.delivery_id.clone();
        let predecessor = state
            .store
            .wal_authoritative_read(user_id, move |conn| {
                conn.query_row(
                    "SELECT state,attempt_count,next_attempt_at,updated_at
                     FROM push_deliveries WHERE delivery_id=?1",
                    [&probe_id],
                    |row| {
                        Ok(wal::PushDeliveryPredecessor {
                            state: row.get(0)?,
                            attempt_count: row.get(1)?,
                            next_attempt_at: row.get(2)?,
                            updated_at: row.get(3)?,
                        })
                    },
                )
                .map_err(crate::error::EnclaveError::from)
            })
            .await?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let committed_at = crate::cp::isotime::format_epoch_millis(now_ms);
        let next_attempt_at = crate::cp::isotime::format_epoch_millis(
            now_ms + retry_after_seconds.unwrap_or(0).max(0) * 1_000,
        );
        let plan = wal::PushDeliverySettlementPlan::new(
            user_id.to_owned(),
            delivery.delivery_id.clone(),
            delivery.episode_id,
            delivery.installation_id.clone(),
            i64::from(delivery.delivery_version),
            predecessor,
            status.to_owned(),
            i64::from(delivery.attempt_count + 1),
            response_status.map(i64::from),
            error_code.map(str::to_owned),
            next_attempt_at,
            committed_at,
        )
        .map_err(|_| {
            crate::error::EnclaveError::Store("push settlement plan construction failed".into())
        })?;
        let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
            .map_err(|_| {
                crate::error::EnclaveError::Store("push settlement plan construction failed".into())
            })?;
        return state
            .store
            .wal_authoritative_submit(user_id, prepared)
            .await;
    }
    state
        .store
        .update_push_delivery_state(
            user_id,
            delivery.episode_id,
            &delivery.installation_id,
            delivery.delivery_version,
            status,
            delivery.attempt_count + 1,
            response_status,
            error_code,
            retry_after_seconds,
        )
        .await
}

fn retry_delay(attempt: i32) -> i64 {
    (30_i64 * 2_i64.pow(attempt.saturating_sub(1).min(8) as u32)).min(6 * 60 * 60)
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

    fn installation(user_id: String, id: &str, token_byte: char) -> PushInstallation {
        PushInstallation {
            id: id.into(),
            user_id,
            platform: "ios".into(),
            topic: IOS_TOPIC.into(),
            environment: "production".into(),
            device_token: token_byte.to_string().repeat(64),
            token_generation: 1,
            enabled: true,
        }
    }

    #[test]
    fn payload_identifiers_are_strict_and_retry_is_bounded() {
        assert!(valid_uuid("019ff39e-11f2-7880-bc8f-bf0316a2ff91"));
        assert!(!valid_uuid("../device"));
        assert!(valid_handoff(&"a".repeat(43)));
        assert!(!valid_handoff(&"a".repeat(44)));
        assert!(valid_device_token(&"a1".repeat(16)));
        assert!(valid_device_token(&"b2".repeat(100)));
        assert!(!valid_device_token(&"a".repeat(31)));
        assert!(!valid_device_token(&"a".repeat(201)));
        assert!(!valid_device_token(&format!("{}z", "a".repeat(31))));
        assert!(retry_delay(100) <= 6 * 60 * 60);
    }

    #[test]
    fn payload_is_generic_and_contains_only_the_per_installation_handoff() {
        let handle = "a".repeat(43);
        let payload = notification_payload(&handle);
        assert_eq!(payload["aps"]["alert"]["body"], "Your memory is ready.");
        assert_eq!(payload["handoff"], handle);
        let encoded = serde_json::to_string(&payload).unwrap();
        for forbidden in [
            "memory_id",
            "episode_id",
            "transcript",
            "participant",
            "summary",
            "email",
            "https://",
        ] {
            assert!(!encoded.contains(forbidden), "payload leaked {forbidden}");
        }
    }

    #[tokio::test]
    async fn delayed_terminal_response_cannot_disable_a_rotated_token() {
        let control = crate::cp::control_store::ControlStore::new(
            Arc::new(crate::store::tests::FakeKms),
            Arc::new(crate::store::tests::FakeGcs::new()),
        );
        let user = control
            .upsert_user(
                "push-rotation-owner",
                "push@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let id = "22222222-2222-4222-8222-222222222222";
        let first = control
            .upsert_push_installation(installation(user.id.clone(), id, 'a'))
            .await
            .unwrap();
        let rotated = control
            .upsert_push_installation(installation(user.id.clone(), id, 'b'))
            .await
            .unwrap();
        assert!(rotated.token_generation > first.token_generation);
        assert!(!control
            .disable_push_installation_generation(&user.id, id, first.token_generation)
            .await
            .unwrap());
        assert!(
            control
                .get_push_installation(&user.id, id)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
    }

    #[tokio::test]
    async fn token_rebind_removes_the_prior_accounts_installation() {
        let control = crate::cp::control_store::ControlStore::new(
            Arc::new(crate::store::tests::FakeKms),
            Arc::new(crate::store::tests::FakeGcs::new()),
        );
        let first_user = control
            .upsert_user(
                "push-first-owner",
                "first@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let second_user = control
            .upsert_user(
                "push-second-owner",
                "second@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        control
            .upsert_push_installation(installation(
                first_user.id.clone(),
                "22222222-2222-4222-8222-222222222222",
                'c',
            ))
            .await
            .unwrap();
        control
            .upsert_push_installation(installation(
                second_user.id.clone(),
                "33333333-3333-4333-8333-333333333333",
                'c',
            ))
            .await
            .unwrap();
        assert!(control
            .list_push_installations(&first_user.id)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            control
                .list_push_installations(&second_user.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
