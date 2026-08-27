//! Privacy-minimized APNs installation registry, delivery worker, and browser handoff.

pub(crate) mod wal;

use std::sync::{Arc, OnceLock};
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
use crate::cp::control_store::{
    PushControlCancellation, PushFenceOutcome, PushInstallation, PushProviderOutcome,
    PushProviderReceipt, PushSendFence, PushSendFenceDisposition,
};
use crate::cp::CpState;
use crate::error::{EnclaveError, Result};

const IOS_TOPIC: &str = "com.kioku.ios";
const MACOS_TOPIC: &str = "com.kiokuu.app";
const INSTALLATION_BINDING_PREFIX: &str = "p1:";
const MAX_DELIVERIES_PER_SWEEP: usize = 2;
const MAX_ATTEMPTS: i32 = 10;
const MAX_DELIVERY_AGE_SECONDS: i64 = 24 * 60 * 60;
const GLOBAL_SEND_PACE_MILLIS: u64 = 250;
const RETRYABLE_CIRCUIT_SECONDS: u64 = 60;
const PROVIDER_CIRCUIT_SECONDS: u64 = 5 * 60;

struct GlobalPushPacer {
    next_send_at: tokio::time::Instant,
    circuit_until: Option<tokio::time::Instant>,
}

fn global_push_pacer() -> &'static Mutex<GlobalPushPacer> {
    static PACER: OnceLock<Mutex<GlobalPushPacer>> = OnceLock::new();
    PACER.get_or_init(|| {
        Mutex::new(GlobalPushPacer {
            next_send_at: tokio::time::Instant::now(),
            circuit_until: None,
        })
    })
}

/// Durable, schema-neutral activation and token fence. The pre-activation
/// representation was a bare installation UUID; version `p1` is written only
/// by the reviewed finalizer and binds the exact Control generation that was
/// enabled when that delivery was created. Bare rows are cancellation-only.
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

    pub(crate) fn parse(value: &str) -> Option<Self> {
        let rest = value.strip_prefix(INSTALLATION_BINDING_PREFIX)?;
        let (installation_id, generation) = rest.split_once(':')?;
        if generation.contains(':') {
            return None;
        }
        let token_generation = generation.parse::<i64>().ok()?;
        valid_uuid(installation_id)
            .then_some(())
            .filter(|_| token_generation > 0)
            .map(|_| Self {
                installation_id: installation_id.to_owned(),
                token_generation,
            })
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
    match state
        .store
        .resolve_push_handoff(&user.0, &handoff_handle)
        .await
    {
        Ok(Some(memory_id)) => Json(json!({"memory_id": memory_id})).into_response(),
        Ok(None) => EnclaveError::NotFound.into_response(),
        Err(error) if state.store.is_wal_authoritative(&user.0) => {
            super::routed_read_unavailable("push_handoff", &error)
        }
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
    deliver_user_pushes_routed(state, transport, user_id).await
}

async fn deliver_user_pushes_routed(
    state: &CpState,
    transport: &dyn PushTransport,
    user_id: &str,
) -> Result<()> {
    if state.repositories.deliveries().is_some() {
        return deliver_postgres_user_pushes(state, transport, user_id).await;
    }
    reconcile_push_send_fences(state, user_id).await?;
    emit_push_depth(state, user_id).await;
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        // One FIFO process-wide critical section spans claim -> bounded
        // provider I/O -> settlement. Under the release-sealed production
        // singleton this is also service-wide. Overlapping runtimes are
        // forbidden: archive/Control CAS is defensive recovery evidence, not
        // a distributed APNs pacing or send-safety fence.
        let mut pacer = global_push_pacer().lock().await;
        if pacer
            .circuit_until
            .is_some_and(|until| until > tokio::time::Instant::now())
        {
            tracing::warn!(
                metric = "push_outbox_circuit_open",
                count = 1,
                "push provider circuit is open"
            );
            break;
        }
        pacer.circuit_until = None;

        let Some(delivery) = state.store.next_push_delivery(user_id).await? else {
            break;
        };
        let snapshot = delivery_snapshot(delivery);

        // Once deletion linearizes, the deletion ledger and exact archive
        // purge own this row and any open claim. WAL ingress correctly closes;
        // do not turn that monotone ownership transfer into a provider send or
        // a noisy cancellation retry.
        if state
            .repositories
            .work()
            .push_outbox_deletion_owned(user_id)
            .await?
        {
            emit_push_deletion_owned();
            break;
        }

        if let Some(open_claim) =
            load_open_send_claim(state, user_id, &snapshot.delivery_id).await?
        {
            if !recover_expired_send_claim(state, user_id, snapshot, open_claim).await? {
                break;
            }
            emit_push_outcome("ambiguous_recovery");
            continue;
        }

        let now_ms = epoch_millis();
        let created_ms = crate::cp::isotime::parse_epoch_millis(&snapshot.created_at);
        let updated_ms = crate::cp::isotime::parse_epoch_millis(&snapshot.updated_at);
        let admission_refusal = match snapshot.send_admission_refusal() {
            Ok(refusal) => refusal,
            Err(_) => {
                tracing::error!(
                    metric = "push_outbox_untargetable_row",
                    count = 1,
                    "push delivery has unbounded or absent exact identity evidence"
                );
                break;
            }
        };
        let pre_send_cancel = if admission_refusal.is_some() {
            admission_refusal
        } else if created_ms.is_none()
            || updated_ms.is_none()
            || created_ms.is_some_and(|created| created > now_ms)
            || updated_ms.is_some_and(|updated| updated > now_ms)
            || created_ms
                .zip(updated_ms)
                .is_some_and(|(created, updated)| created > updated)
        {
            Some("delivery_time_invalid")
        } else if created_ms.is_some_and(|created| {
            now_ms.saturating_sub(created) >= MAX_DELIVERY_AGE_SECONDS * 1_000
        }) {
            Some("delivery_expired")
        } else {
            None
        };
        if let Some(code) = pre_send_cancel {
            if !settle_before_provider_or_deletion_owned(
                state,
                user_id,
                snapshot,
                None,
                wal::PushSettlementKind::Cancel { code: code.into() },
            )
            .await?
            {
                break;
            }
            emit_push_cancellation(code);
            continue;
        }
        let binding = PushInstallationBinding::parse(&snapshot.installation_binding)
            .expect("send admission validated the versioned binding");

        let now = tokio::time::Instant::now();
        if pacer.next_send_at > now {
            tokio::time::sleep_until(pacer.next_send_at).await;
        }

        let started_at = now_for_snapshot(&snapshot, None);
        let claim_plan = wal::PushSendClaimPlan::new(
            user_id.to_owned(),
            super::tokens::new_uuid(),
            snapshot.clone(),
            started_at,
        )
        .map_err(|_| EnclaveError::Store("push send claim construction failed".into()))?;
        match submit_send_claim(state, user_id, claim_plan).await? {
            wal::PushSendClaimDisposition::Busy => {
                let open_claim = load_open_send_claim(state, user_id, &snapshot.delivery_id)
                    .await?
                    .ok_or_else(|| {
                        EnclaveError::Conflict(
                            "push send claim was busy without durable evidence".into(),
                        )
                    })?;
                if !recover_expired_send_claim(state, user_id, snapshot, open_claim).await? {
                    break;
                }
                emit_push_outcome("ambiguous_competing_claim");
                continue;
            }
            wal::PushSendClaimDisposition::DeferredLimit => {
                if !settle_before_provider_or_deletion_owned(
                    state,
                    user_id,
                    snapshot,
                    None,
                    wal::PushSettlementKind::Cancel {
                        code: "control_defer_cap".into(),
                    },
                )
                .await?
                {
                    break;
                }
                emit_push_cancellation("control_defer_cap");
                continue;
            }
            wal::PushSendClaimDisposition::Authorized => {}
        }
        let claim = load_open_send_claim(state, user_id, &snapshot.delivery_id)
            .await?
            .ok_or_else(|| EnclaveError::Store("durable push send claim disappeared".into()))?;

        let expiration_millis = created_ms
            .and_then(|created| created.checked_add(MAX_DELIVERY_AGE_SECONDS * 1_000))
            .ok_or_else(|| EnclaveError::Store("push expiration overflow".into()))?;
        if expiration_millis <= epoch_millis() {
            if !settle_before_provider_or_deletion_owned(
                state,
                user_id,
                snapshot,
                Some(claim),
                wal::PushSettlementKind::Cancel {
                    code: "delivery_expired".into(),
                },
            )
            .await?
            {
                break;
            }
            emit_push_cancellation("delivery_expired");
            continue;
        }
        let expiration_epoch_seconds = u64::try_from(expiration_millis / 1_000)
            .map_err(|_| EnclaveError::Store("push expiration is invalid".into()))?;
        let authorized_installation = match state
            .repositories
            .work()
            .begin_push_send_fence(
                user_id,
                &binding.installation_id,
                binding.token_generation,
                claim.claim_id(),
                claim.lease_expires_at(),
                &now_for_snapshot(&snapshot, Some(&claim)),
            )
            .await
        {
            Ok(PushSendFenceDisposition::Authorized(installation)) => installation,
            Ok(PushSendFenceDisposition::DeletionOwned) => {
                emit_push_deletion_owned();
                break;
            }
            Ok(PushSendFenceDisposition::Recorded(fence)) => {
                replay_fence_receipt(state, user_id, snapshot, claim, &binding, fence).await?;
                continue;
            }
            Err(error) => {
                if state
                    .repositories
                    .work()
                    .list_push_send_fences(user_id)
                    .await
                    .is_ok_and(|fences| {
                        !fences.iter().any(|fence| {
                            fence.claim_id == claim.claim_id()
                                && fence.lease_expires_at == claim.lease_expires_at()
                        })
                    })
                {
                    let committed_at = now_for_snapshot(&snapshot, Some(&claim));
                    let retry_at = add_seconds(&committed_at, 60)?;
                    settle_delivery_at(
                        state,
                        user_id,
                        snapshot,
                        Some(claim),
                        wal::PushSettlementKind::Defer {
                            code: "control_recheck_unavailable".into(),
                            retry_at,
                        },
                        committed_at,
                    )
                    .await?;
                }
                return Err(error);
            }
        };
        let revalidate_at = epoch_millis();
        validate_archive_send_authority(state, user_id, &claim, revalidate_at).await?;
        let minimum_fence_expiry = revalidate_at
            .checked_add(wal::MIN_SEND_LEASE_MILLIS)
            .ok_or_else(|| EnclaveError::Store("push lease horizon overflow".into()))?;
        if !state
            .repositories
            .work()
            .validate_push_send_fence(
                user_id,
                &binding.installation_id,
                binding.token_generation,
                claim.claim_id(),
                claim.lease_expires_at(),
                minimum_fence_expiry,
            )
            .await?
        {
            return Err(EnclaveError::Conflict(
                "push send fence is no longer live".into(),
            ));
        }
        pacer.next_send_at =
            tokio::time::Instant::now() + Duration::from_millis(GLOBAL_SEND_PACE_MILLIS);
        let provider_outcome = transport
            .send(PushRequest {
                topic: authorized_installation.topic,
                environment: authorized_installation.environment,
                device_token: authorized_installation.device_token,
                token_generation: binding.token_generation,
                apns_id: snapshot.delivery_id.clone(),
                collapse_id: snapshot.collapse_id.clone(),
                handoff_handle: snapshot.handoff_handle.clone(),
                expiration_epoch_seconds,
            })
            .await;
        match provider_outcome {
            Ok(status) => {
                let outcome_at = now_for_snapshot(&snapshot, Some(&claim));
                persist_provider_outcome(
                    state,
                    user_id,
                    snapshot,
                    claim,
                    &binding,
                    PushProviderOutcome::Accepted {
                        status: i64::from(status),
                    },
                    outcome_at,
                )
                .await?;
                emit_push_outcome("accepted");
            }
            Err(PushTransportError::TokenTerminal { status, code }) => {
                let outcome_at = now_for_snapshot(&snapshot, Some(&claim));
                persist_provider_outcome(
                    state,
                    user_id,
                    snapshot,
                    claim,
                    &binding,
                    PushProviderOutcome::TokenTerminal {
                        status: i64::from(status),
                        code: code.into(),
                    },
                    outcome_at,
                )
                .await?;
                emit_push_outcome("token_terminal");
            }
            Err(PushTransportError::Retryable {
                status,
                code,
                retry_after_seconds,
                scope,
            }) => {
                if status.is_none() {
                    let outcome_at = now_for_snapshot(&snapshot, Some(&claim));
                    persist_provider_outcome(
                        state,
                        user_id,
                        snapshot,
                        claim,
                        &binding,
                        PushProviderOutcome::Ambiguous,
                        outcome_at,
                    )
                    .await?;
                    if scope == PushRetryScope::ProviderWide {
                        open_circuit(&mut pacer, RETRYABLE_CIRCUIT_SECONDS);
                    }
                    emit_push_outcome("ambiguous_network");
                } else if claim.send_attempt() >= i64::from(MAX_ATTEMPTS) {
                    let outcome_at = now_for_snapshot(&snapshot, Some(&claim));
                    persist_provider_outcome(
                        state,
                        user_id,
                        snapshot,
                        claim,
                        &binding,
                        PushProviderOutcome::Failed {
                            status: status.map(i64::from),
                            code: "attempt_cap".into(),
                        },
                        outcome_at,
                    )
                    .await?;
                    if scope == PushRetryScope::ProviderWide {
                        open_circuit(
                            &mut pacer,
                            retry_after_seconds.unwrap_or(RETRYABLE_CIRCUIT_SECONDS),
                        );
                    }
                    emit_push_outcome("attempt_cap");
                } else {
                    let committed_at = now_for_snapshot(&snapshot, Some(&claim));
                    let delay = retry_after_seconds
                        .and_then(|seconds| i64::try_from(seconds).ok())
                        .unwrap_or_else(|| retry_delay(claim.send_attempt()))
                        .clamp(1, 6 * 60 * 60);
                    let retry_at = add_seconds(&committed_at, delay)?;
                    persist_provider_outcome(
                        state,
                        user_id,
                        snapshot,
                        claim,
                        &binding,
                        PushProviderOutcome::Retry {
                            status: status.map(i64::from),
                            code: code.into(),
                            retry_at,
                        },
                        committed_at,
                    )
                    .await?;
                    if scope == PushRetryScope::ProviderWide {
                        open_circuit(
                            &mut pacer,
                            retry_after_seconds.unwrap_or(RETRYABLE_CIRCUIT_SECONDS),
                        );
                    }
                    emit_push_outcome("retryable_rejected");
                }
            }
            Err(PushTransportError::ProviderTerminal { status, code }) => {
                let terminal = claim.send_attempt() >= i64::from(MAX_ATTEMPTS);
                let outcome_at = now_for_snapshot(&snapshot, Some(&claim));
                if terminal {
                    persist_provider_outcome(
                        state,
                        user_id,
                        snapshot,
                        claim,
                        &binding,
                        PushProviderOutcome::Failed {
                            status: status.map(i64::from),
                            code: code.into(),
                        },
                        outcome_at,
                    )
                    .await?;
                } else {
                    let retry_at = add_seconds(&outcome_at, 60 * 60)?;
                    persist_provider_outcome(
                        state,
                        user_id,
                        snapshot,
                        claim,
                        &binding,
                        PushProviderOutcome::Retry {
                            status: status.map(i64::from),
                            code: code.into(),
                            retry_at,
                        },
                        outcome_at,
                    )
                    .await?;
                }
                open_circuit(&mut pacer, PROVIDER_CIRCUIT_SECONDS);
                emit_push_outcome("provider_terminal");
                break;
            }
        }
    }
    Ok(())
}

async fn deliver_postgres_user_pushes(
    state: &CpState,
    transport: &dyn PushTransport,
    user_id: &str,
) -> Result<()> {
    let repository = state
        .repositories
        .deliveries()
        .ok_or_else(|| EnclaveError::Store("PostgreSQL delivery repository is missing".into()))?;
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
        let (outcome, circuit_seconds) = match result {
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
                if claim.attempt_count >= i64::from(MAX_ATTEMPTS) {
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
                        .unwrap_or_else(|| retry_delay(claim.attempt_count))
                        .clamp(1, 6 * 60 * 60);
                    (
                        PushProviderOutcome::Retry {
                            status: status.map(i64::from),
                            code: code.into(),
                            retry_at: add_seconds(&outcome_at, delay)?,
                        },
                        circuit,
                    )
                }
            }
            Err(PushTransportError::ProviderTerminal { status, code }) => {
                let outcome = if claim.attempt_count >= i64::from(MAX_ATTEMPTS) {
                    PushProviderOutcome::Failed {
                        status: status.map(i64::from),
                        code: code.into(),
                    }
                } else {
                    PushProviderOutcome::Retry {
                        status: status.map(i64::from),
                        code: code.into(),
                        retry_at: add_seconds(&outcome_at, 60 * 60)?,
                    }
                };
                (outcome, Some(PROVIDER_CIRCUIT_SECONDS as i64))
            }
        };
        repository
            .settle_push(&claim, outcome, circuit_seconds)
            .await?;
        emit_push_outcome("settled");
    }
    Ok(())
}

async fn submit_send_claim(
    state: &CpState,
    user_id: &str,
    plan: wal::PushSendClaimPlan,
) -> Result<wal::PushSendClaimDisposition> {
    if state.store.is_wal_authoritative(user_id) {
        let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
            .map_err(|_| EnclaveError::Store("push send claim preparation failed".into()))?;
        return state
            .store
            .wal_authoritative_submit(user_id, prepared)
            .await;
    }
    let user = user_id.to_owned();
    let result = state
        .store
        .with_user(&user, move |connection| {
            let transaction = connection.unchecked_transaction()?;
            let outcome = plan
                .apply_direct(&transaction)
                .map_err(|_| EnclaveError::Store("push send claim failed".into()))?;
            transaction.commit()?;
            Ok(outcome)
        })
        .await?;
    state.store.save_user(user_id).await?;
    Ok(result)
}

async fn settle_delivery(
    state: &CpState,
    user_id: &str,
    predecessor: wal::PushDeliverySnapshot,
    claim: Option<wal::PushSendClaim>,
    kind: wal::PushSettlementKind,
) -> Result<()> {
    let committed_at = now_for_snapshot(&predecessor, claim.as_ref());
    settle_delivery_at(state, user_id, predecessor, claim, kind, committed_at).await
}

async fn settle_before_provider_or_deletion_owned(
    state: &CpState,
    user_id: &str,
    predecessor: wal::PushDeliverySnapshot,
    claim: Option<wal::PushSendClaim>,
    kind: wal::PushSettlementKind,
) -> Result<bool> {
    match settle_delivery(state, user_id, predecessor, claim, kind).await {
        Ok(()) => Ok(true),
        Err(EnclaveError::Conflict(_))
            if state
                .repositories
                .work()
                .push_outbox_deletion_owned(user_id)
                .await? =>
        {
            emit_push_deletion_owned();
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Defensive competing-owner handling. A live owner's exact claim/fence is
/// never touched; only an expired claim can be recovered. Production still
/// requires the release-sealed single-runtime topology: this lease is not an
/// external provider fence and does not authorize overlapping runtimes.
async fn recover_expired_send_claim(
    state: &CpState,
    user_id: &str,
    predecessor: wal::PushDeliverySnapshot,
    claim: wal::PushSendClaim,
) -> Result<bool> {
    if claim
        .is_live_at(epoch_millis())
        .map_err(|_| EnclaveError::Store("push claim lease is invalid".into()))?
    {
        emit_push_outcome("busy_live_claim");
        return Ok(false);
    }
    let binding = PushInstallationBinding::parse(&predecessor.installation_binding)
        .ok_or_else(|| EnclaveError::Store("push claim binding became invalid".into()))?;
    let fence = state
        .repositories
        .work()
        .get_push_send_fence(user_id, &binding.installation_id)
        .await?;
    if let Some(fence) = fence {
        if !exact_fence_for_claim(&fence, user_id, &binding, &claim) {
            return Err(EnclaveError::Conflict(
                "expired push claim found a different Control fence".into(),
            ));
        }
        if fence.outcome.is_some() {
            replay_fence_receipt(state, user_id, predecessor, claim, &binding, fence).await?;
            return Ok(true);
        }
        let outcome_at = now_for_snapshot(&predecessor, Some(&claim));
        persist_provider_outcome(
            state,
            user_id,
            predecessor,
            claim,
            &binding,
            PushProviderOutcome::Ambiguous,
            outcome_at,
        )
        .await?;
        return Ok(true);
    }
    settle_before_provider_or_deletion_owned(
        state,
        user_id,
        predecessor,
        Some(claim),
        wal::PushSettlementKind::Ambiguous,
    )
    .await
}

async fn settle_delivery_at(
    state: &CpState,
    user_id: &str,
    predecessor: wal::PushDeliverySnapshot,
    claim: Option<wal::PushSendClaim>,
    kind: wal::PushSettlementKind,
    committed_at: String,
) -> Result<()> {
    let plan = wal::PushDeliverySettlementPlan::new(
        user_id.to_owned(),
        predecessor,
        claim,
        kind,
        committed_at,
    )
    .map_err(|_| EnclaveError::Store("push settlement plan construction failed".into()))?;
    if state.store.is_wal_authoritative(user_id) {
        let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
            .map_err(|_| EnclaveError::Store("push settlement preparation failed".into()))?;
        return state
            .store
            .wal_authoritative_submit(user_id, prepared)
            .await;
    }
    let user = user_id.to_owned();
    state
        .store
        .with_user(&user, move |connection| {
            let transaction = connection.unchecked_transaction()?;
            plan.apply_direct(&transaction)
                .map_err(|_| EnclaveError::Store("push settlement failed".into()))?;
            transaction.commit()?;
            Ok(())
        })
        .await?;
    state.store.save_user(user_id).await
}

fn settlement_kind(outcome: &PushProviderOutcome) -> wal::PushSettlementKind {
    match outcome {
        PushProviderOutcome::Accepted { status } => {
            wal::PushSettlementKind::Accepted { status: *status }
        }
        PushProviderOutcome::Retry {
            status,
            code,
            retry_at,
        } => wal::PushSettlementKind::Retry {
            status: *status,
            code: code.clone(),
            retry_at: retry_at.clone(),
        },
        PushProviderOutcome::Ambiguous => wal::PushSettlementKind::Ambiguous,
        PushProviderOutcome::Failed { status, code } => wal::PushSettlementKind::Failed {
            status: *status,
            code: code.clone(),
        },
        PushProviderOutcome::TokenTerminal { status, code } => {
            wal::PushSettlementKind::TokenTerminal {
                status: *status,
                code: code.clone(),
            }
        }
    }
}

fn fence_for_claim(
    user_id: &str,
    binding: &PushInstallationBinding,
    claim: &wal::PushSendClaim,
    outcome: Option<PushFenceOutcome>,
    outcome_at: Option<String>,
) -> PushSendFence {
    PushSendFence {
        user_id: user_id.to_owned(),
        installation_id: binding.installation_id.clone(),
        token_generation: binding.token_generation,
        claim_id: claim.claim_id().to_owned(),
        lease_expires_at: claim.lease_expires_at().to_owned(),
        outcome,
        outcome_at,
    }
}

fn exact_fence_for_claim(
    fence: &PushSendFence,
    user_id: &str,
    binding: &PushInstallationBinding,
    claim: &wal::PushSendClaim,
) -> bool {
    fence.user_id == user_id
        && fence.installation_id == binding.installation_id
        && fence.token_generation == binding.token_generation
        && fence.claim_id == claim.claim_id()
        && fence.lease_expires_at == claim.lease_expires_at()
}

async fn persist_control_cancellation(
    state: &CpState,
    user_id: &str,
    predecessor: wal::PushDeliverySnapshot,
    claim: wal::PushSendClaim,
    fence: PushSendFence,
    cancellation: PushControlCancellation,
    outcome_at: String,
) -> Result<()> {
    settle_delivery_at(
        state,
        user_id,
        predecessor,
        Some(claim),
        wal::PushSettlementKind::Cancel {
            code: cancellation.code().into(),
        },
        outcome_at,
    )
    .await?;
    state
        .repositories
        .work()
        .finish_push_cancellation_fence(&fence, cancellation)
        .await
}

async fn replay_fence_receipt(
    state: &CpState,
    user_id: &str,
    predecessor: wal::PushDeliverySnapshot,
    claim: wal::PushSendClaim,
    binding: &PushInstallationBinding,
    fence: PushSendFence,
) -> Result<()> {
    if !exact_fence_for_claim(&fence, user_id, binding, &claim) {
        return Err(EnclaveError::Conflict(
            "push fence does not match the exact archive claim".into(),
        ));
    }
    let outcome_at = fence
        .outcome_at
        .clone()
        .ok_or_else(|| EnclaveError::Store("push receipt lacks timestamp".into()))?;
    match fence.outcome.clone() {
        Some(PushFenceOutcome::Provider(outcome)) => {
            persist_provider_outcome(
                state,
                user_id,
                predecessor,
                claim,
                binding,
                outcome,
                outcome_at,
            )
            .await
        }
        Some(PushFenceOutcome::Cancellation(cancellation)) => {
            let code = cancellation.code();
            persist_control_cancellation(
                state,
                user_id,
                predecessor,
                claim,
                fence,
                cancellation,
                outcome_at,
            )
            .await?;
            emit_push_cancellation(code);
            Ok(())
        }
        None => Err(EnclaveError::Store(
            "recorded push fence lacks an outcome".into(),
        )),
    }
}

/// Persist provider evidence independently in both durable stores. A failure
/// in either write never prevents attempting the other. The Control receipt
/// remains until the archive settlement is durable; restart reconciliation
/// can therefore recover either asymmetric failure without downgrading a
/// known provider result to ambiguity.
async fn persist_provider_outcome(
    state: &CpState,
    user_id: &str,
    predecessor: wal::PushDeliverySnapshot,
    claim: wal::PushSendClaim,
    binding: &PushInstallationBinding,
    outcome: PushProviderOutcome,
    outcome_at: String,
) -> Result<()> {
    let mut authoritative_outcome = outcome;
    let mut authoritative_at = outcome_at;
    let control_result = state
        .repositories
        .work()
        .record_push_send_outcome(
            user_id,
            &binding.installation_id,
            binding.token_generation,
            claim.claim_id(),
            claim.lease_expires_at(),
            PushProviderReceipt::new(authoritative_outcome.clone(), authoritative_at.clone())?,
        )
        .await;
    let control_error = match control_result {
        Ok(()) => None,
        Err(error) => {
            let fence = state
                .repositories
                .work()
                .get_push_send_fence(user_id, &binding.installation_id)
                .await?;
            let Some(fence) = fence else {
                return Err(error);
            };
            if !exact_fence_for_claim(&fence, user_id, binding, &claim) {
                return Err(EnclaveError::Conflict(
                    "push outcome reload found a different fence".into(),
                ));
            }
            match fence.outcome {
                Some(PushFenceOutcome::Provider(stored)) => {
                    authoritative_outcome = stored;
                    authoritative_at = fence.outcome_at.ok_or_else(|| {
                        EnclaveError::Store("push outcome receipt lacks timestamp".into())
                    })?;
                    None
                }
                Some(PushFenceOutcome::Cancellation(_)) => {
                    return Err(EnclaveError::Conflict(
                        "provider result conflicts with a Control cancellation receipt".into(),
                    ));
                }
                None => Some(error),
            }
        }
    };
    let archive_result = settle_delivery_at(
        state,
        user_id,
        predecessor,
        Some(claim.clone()),
        settlement_kind(&authoritative_outcome),
        authoritative_at.clone(),
    )
    .await;

    if let Err(archive_error) = archive_result {
        if control_error.is_some() {
            tracing::error!(
                metric = "push_outbox_dual_outcome_persist_failure",
                count = 1,
                "both push outcome evidence writes failed"
            );
        }
        return Err(archive_error);
    }

    if let Some(control_error) = control_error {
        // The archive now durably carries the exact typed result. Preserve
        // any in-memory/remote Control fence state for restart reconciliation
        // instead of erasing evidence after a failed Control acknowledgement.
        return Err(control_error);
    }

    let fence = fence_for_claim(
        user_id,
        binding,
        &claim,
        Some(PushFenceOutcome::Provider(authoritative_outcome.clone())),
        Some(authoritative_at),
    );
    state
        .repositories
        .work()
        .finish_push_send_fence(&fence, authoritative_outcome)
        .await
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

fn now_for_snapshot(
    snapshot: &wal::PushDeliverySnapshot,
    claim: Option<&wal::PushSendClaim>,
) -> String {
    let floor = crate::cp::isotime::parse_epoch_millis(&snapshot.updated_at)
        .into_iter()
        .chain(claim.and_then(|claim| crate::cp::isotime::parse_epoch_millis(claim.started_at())))
        .max()
        .unwrap_or_default();
    crate::cp::isotime::format_epoch_millis(epoch_millis().max(floor))
}

fn delivery_snapshot(delivery: crate::store::PushDeliveryRow) -> wal::PushDeliverySnapshot {
    wal::PushDeliverySnapshot {
        rowid: delivery.rowid,
        episode_id: delivery.episode_id,
        installation_binding: delivery.installation_binding,
        delivery_version: delivery.delivery_version,
        delivery_id: delivery.delivery_id,
        handoff_handle: delivery.handoff_handle,
        collapse_id: delivery.collapse_id,
        state: delivery.state,
        attempt_count: delivery.attempt_count,
        next_attempt_at: delivery.next_attempt_at,
        response_status: delivery.response_status,
        error_code: delivery.error_code,
        created_at: delivery.created_at,
        updated_at: delivery.updated_at,
    }
}

async fn load_open_send_claim(
    state: &CpState,
    user_id: &str,
    delivery_id: &str,
) -> Result<Option<wal::PushSendClaim>> {
    let delivery_id = delivery_id.to_owned();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_open_claim(connection, &delivery_id)
                .map_err(|_| EnclaveError::Store("push send claim read failed".into()))
        })
        .await
}

async fn load_send_claim_recovery(
    state: &CpState,
    user_id: &str,
    claim_id: &str,
) -> Result<Option<wal::PushClaimRecovery>> {
    let claim_id = claim_id.to_owned();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_claim_recovery(connection, &claim_id)
                .map_err(|_| EnclaveError::Store("push claim recovery read failed".into()))
        })
        .await
}

async fn validate_archive_send_authority(
    state: &CpState,
    user_id: &str,
    claim: &wal::PushSendClaim,
    now_millis: i64,
) -> Result<()> {
    let claim = claim.clone();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::validate_live_send_authority(connection, &claim, now_millis)
                .map_err(|_| EnclaveError::Conflict("push send lease is no longer live".into()))
        })
        .await
}

fn recovery_outcome(recovery: &wal::PushClaimRecovery) -> Option<PushProviderOutcome> {
    match recovery {
        wal::PushClaimRecovery::Accepted { status, .. } => {
            Some(PushProviderOutcome::Accepted { status: *status })
        }
        wal::PushClaimRecovery::Retry {
            status,
            code,
            retry_at,
            ..
        } => Some(PushProviderOutcome::Retry {
            status: *status,
            code: code.clone(),
            retry_at: retry_at.clone(),
        }),
        wal::PushClaimRecovery::Ambiguous { .. } => Some(PushProviderOutcome::Ambiguous),
        wal::PushClaimRecovery::Failed { status, code, .. } => Some(PushProviderOutcome::Failed {
            status: *status,
            code: code.clone(),
        }),
        wal::PushClaimRecovery::TokenTerminal { status, code, .. } => {
            Some(PushProviderOutcome::TokenTerminal {
                status: *status,
                code: code.clone(),
            })
        }
        wal::PushClaimRecovery::Started(_)
        | wal::PushClaimRecovery::Deferred
        | wal::PushClaimRecovery::Cancelled { .. } => None,
    }
}

fn recovery_provider_outcome_at(recovery: &wal::PushClaimRecovery) -> Option<&str> {
    match recovery {
        wal::PushClaimRecovery::Accepted { settled_at, .. }
        | wal::PushClaimRecovery::Retry { settled_at, .. }
        | wal::PushClaimRecovery::Ambiguous { settled_at, .. }
        | wal::PushClaimRecovery::Failed { settled_at, .. }
        | wal::PushClaimRecovery::TokenTerminal { settled_at, .. } => Some(settled_at),
        wal::PushClaimRecovery::Started(_)
        | wal::PushClaimRecovery::Deferred
        | wal::PushClaimRecovery::Cancelled { .. } => None,
    }
}

async fn reconcile_push_send_fences(state: &CpState, user_id: &str) -> Result<()> {
    for fence in state
        .repositories
        .work()
        .list_push_send_fences(user_id)
        .await?
    {
        let Some(recovery) = load_send_claim_recovery(state, user_id, &fence.claim_id).await?
        else {
            if state
                .repositories
                .work()
                .push_outbox_deletion_owned(user_id)
                .await?
            {
                emit_push_deletion_owned();
                return Ok(());
            }
            return Err(EnclaveError::Store(
                "push send fence lacks exact archive claim evidence".into(),
            ));
        };
        match recovery {
            wal::PushClaimRecovery::Started(claim) => {
                if let Some(outcome) = fence.outcome.clone() {
                    let predecessor = claim.predecessor().clone();
                    let binding = PushInstallationBinding::parse(&predecessor.installation_binding)
                        .ok_or_else(|| {
                            EnclaveError::Store("push claim binding became invalid".into())
                        })?;
                    let replay = PushSendFence {
                        outcome: Some(outcome),
                        ..fence.clone()
                    };
                    replay_fence_receipt(state, user_id, predecessor, claim, &binding, replay)
                        .await?;
                } else if !claim
                    .is_live_at(epoch_millis())
                    .map_err(|_| EnclaveError::Store("push claim lease is invalid".into()))?
                {
                    let predecessor = claim.predecessor().clone();
                    let binding = PushInstallationBinding::parse(&predecessor.installation_binding)
                        .ok_or_else(|| {
                            EnclaveError::Store("push claim binding became invalid".into())
                        })?;
                    let outcome_at = now_for_snapshot(&predecessor, Some(&claim));
                    persist_provider_outcome(
                        state,
                        user_id,
                        predecessor,
                        claim,
                        &binding,
                        PushProviderOutcome::Ambiguous,
                        outcome_at,
                    )
                    .await?;
                }
            }
            wal::PushClaimRecovery::Cancelled {
                claim,
                code,
                settled_at,
            } => {
                let cancellation = match fence.outcome.as_ref() {
                    Some(PushFenceOutcome::Cancellation(cancellation))
                        if cancellation.code() == code
                            && fence.outcome_at.as_deref() == Some(settled_at.as_str()) =>
                    {
                        *cancellation
                    }
                    _ => {
                        return Err(EnclaveError::Store(
                            "push cancellation receipt differs from archive evidence".into(),
                        ));
                    }
                };
                let binding =
                    PushInstallationBinding::parse(&claim.predecessor().installation_binding)
                        .ok_or_else(|| {
                            EnclaveError::Store("push claim binding became invalid".into())
                        })?;
                if !exact_fence_for_claim(&fence, user_id, &binding, &claim) {
                    return Err(EnclaveError::Conflict(
                        "push cancellation fence differs from archive evidence".into(),
                    ));
                }
                state
                    .repositories
                    .work()
                    .finish_push_cancellation_fence(&fence, cancellation)
                    .await?;
            }
            settled => {
                let outcome = recovery_outcome(&settled).ok_or_else(|| {
                    EnclaveError::Store("push fence points to a non-provider claim outcome".into())
                })?;
                let outcome_at = recovery_provider_outcome_at(&settled)
                    .ok_or_else(|| {
                        EnclaveError::Store("push archive outcome lacks a timestamp".into())
                    })?
                    .to_owned();
                let archive_fence = PushSendFence {
                    outcome: Some(PushFenceOutcome::Provider(outcome.clone())),
                    outcome_at: Some(outcome_at),
                    ..fence
                };
                state
                    .repositories
                    .work()
                    .finish_push_send_fence(&archive_fence, outcome)
                    .await?;
            }
        }
    }
    Ok(())
}

async fn emit_push_depth(state: &CpState, user_id: &str) {
    let result = state
        .store
        .wal_authoritative_read(user_id, |connection| {
            connection
                .query_row(
                    "SELECT COUNT(*),MIN(created_at) FROM push_deliveries \
                     WHERE state IN ('pending','retry')",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .map_err(EnclaveError::from)
        })
        .await;
    match result {
        Ok((depth, oldest)) => {
            let oldest_age_seconds = oldest
                .as_deref()
                .and_then(crate::cp::isotime::parse_epoch_millis)
                .map(|created| epoch_millis().saturating_sub(created).max(0) / 1_000)
                .unwrap_or(0);
            tracing::info!(
                metric = "push_outbox_depth",
                depth,
                oldest_age_seconds,
                "push outbox depth"
            );
        }
        Err(_) => tracing::warn!(
            metric = "push_outbox_metrics_error",
            count = 1,
            "push outbox depth unavailable"
        ),
    }
}

fn emit_push_outcome(outcome: &'static str) {
    tracing::info!(
        metric = "push_outbox_outcome",
        outcome,
        count = 1,
        "push delivery outcome"
    );
}

fn emit_push_cancellation(reason: &'static str) {
    tracing::info!(
        metric = "push_outbox_cancellation",
        reason,
        count = 1,
        "push delivery cancelled before provider acceptance"
    );
}

fn emit_push_deletion_owned() {
    tracing::info!(
        metric = "push_outbox_deletion_owned",
        outcome = "deletion_owned",
        count = 1,
        "account deletion owns remaining push evidence"
    );
}

fn open_circuit(pacer: &mut GlobalPushPacer, seconds: u64) {
    pacer.circuit_until = Some(tokio::time::Instant::now() + Duration::from_secs(seconds));
    tracing::warn!(
        metric = "push_outbox_circuit_opened",
        seconds,
        count = 1,
        "push provider circuit opened"
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
    use rusqlite::params;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    fn push_test_serial() -> &'static Mutex<()> {
        static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
        SERIAL.get_or_init(|| Mutex::new(()))
    }

    struct ScriptedTransport {
        outcomes: StdMutex<VecDeque<std::result::Result<u16, PushTransportError>>>,
        requests: StdMutex<Vec<PushRequest>>,
    }

    impl ScriptedTransport {
        fn new(
            outcomes: impl IntoIterator<Item = std::result::Result<u16, PushTransportError>>,
        ) -> Self {
            Self {
                outcomes: StdMutex::new(outcomes.into_iter().collect()),
                requests: StdMutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<PushRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PushTransport for ScriptedTransport {
        async fn send(&self, request: PushRequest) -> std::result::Result<u16, PushTransportError> {
            self.requests.lock().unwrap().push(request);
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .expect("the push transport script must name every provider call")
        }
    }

    struct BlockingTransport {
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
        requests: StdMutex<Vec<PushRequest>>,
    }

    impl BlockingTransport {
        fn new() -> Self {
            Self {
                started: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                requests: StdMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl PushTransport for BlockingTransport {
        async fn send(&self, request: PushRequest) -> std::result::Result<u16, PushTransportError> {
            self.requests.lock().unwrap().push(request);
            self.started.notify_one();
            self.release.notified().await;
            Ok(200)
        }
    }

    struct FairnessTransport {
        first_started: tokio::sync::Notify,
        first_release: tokio::sync::Notify,
        requests: StdMutex<Vec<(String, tokio::time::Instant)>>,
    }

    impl FairnessTransport {
        fn new() -> Self {
            Self {
                first_started: tokio::sync::Notify::new(),
                first_release: tokio::sync::Notify::new(),
                requests: StdMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl PushTransport for FairnessTransport {
        async fn send(&self, request: PushRequest) -> std::result::Result<u16, PushTransportError> {
            let first = {
                let mut requests = self.requests.lock().unwrap();
                requests.push((request.apns_id, tokio::time::Instant::now()));
                requests.len() == 1
            };
            if first {
                self.first_started.notify_one();
                self.first_release.notified().await;
            }
            Ok(200)
        }
    }

    async fn reset_test_pacer() {
        let mut pacer = global_push_pacer().lock().await;
        pacer.next_send_at = tokio::time::Instant::now();
        pacer.circuit_until = None;
    }

    async fn delivery_evidence(
        state: &CpState,
        user_id: &str,
        delivery_id: &str,
    ) -> (String, i64, Option<String>) {
        let delivery_id = delivery_id.to_owned();
        state
            .store
            .wal_authoritative_read(user_id, move |connection| {
                connection
                    .query_row(
                        "SELECT state,attempt_count,error_code FROM push_deliveries
                         WHERE delivery_id=?1",
                        [delivery_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .map_err(EnclaveError::from)
            })
            .await
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_legacy_delivery(
        state: &CpState,
        user_id: &str,
        episode_id: i64,
        installation_binding: &str,
        delivery_id: &str,
        handoff: &str,
        collapse_id: &str,
        attempt_count: i64,
        created_at: &str,
    ) {
        let user = user_id.to_owned();
        let installation_binding = installation_binding.to_owned();
        let delivery_id = delivery_id.to_owned();
        let handoff = handoff.to_owned();
        let collapse_id = collapse_id.to_owned();
        let created_at = created_at.to_owned();
        state
            .store
            .with_user(&user, move |connection| {
                connection.execute(
                    "INSERT INTO episodes
                     (id,started_at,ended_at,finalized_at,finalization_status,title,substance)
                     VALUES (?1,?2,?2,?2,'complete','Push owner fixture','normal')",
                    params![episode_id, created_at],
                )?;
                connection.execute(
                    "INSERT INTO push_deliveries
                     (episode_id,installation_id,delivery_version,delivery_id,handoff_handle,
                      collapse_id,state,attempt_count,next_attempt_at,created_at,updated_at)
                     VALUES (?1,?2,1,?3,?4,?5,'pending',?6,?7,?7,?7)",
                    params![
                        episode_id,
                        installation_binding,
                        delivery_id,
                        handoff,
                        collapse_id,
                        attempt_count,
                        created_at,
                    ],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        state.store.save_user(user_id).await.unwrap();
    }

    async fn resolved_memory_id(state: &Arc<CpState>, user_id: &str, handoff: &str) -> Option<i64> {
        let response = resolve_notification_handoff(
            State(Arc::clone(state)),
            Extension(AuthUser(user_id.to_owned())),
            Path(handoff.to_owned()),
        )
        .await;
        if response.status() == StatusCode::NOT_FOUND {
            return None;
        }
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("the handoff response is bounded");
        let resolved: serde_json::Value =
            serde_json::from_slice(&body).expect("the handoff response is JSON");
        resolved["memory_id"].as_i64()
    }

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
    async fn exact_terminal_fence_cannot_disable_a_later_token_generation() {
        let _serial = push_test_serial().lock().await;
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
        let claim_id = "33333333-3333-4333-8333-333333333333";
        let lease_expires_at = crate::cp::isotime::format_epoch_millis(
            epoch_millis() + wal::claim::CLAIM_LEASE_MILLIS,
        );
        assert!(matches!(
            control
                .begin_push_send_fence(
                    &user.id,
                    id,
                    first.token_generation,
                    claim_id,
                    &lease_expires_at,
                    &crate::cp::isotime::format_epoch_millis(epoch_millis()),
                )
                .await
                .unwrap(),
            PushSendFenceDisposition::Authorized(_)
        ));
        assert!(matches!(
            control
                .upsert_push_installation(installation(user.id.clone(), id, 'b'))
                .await,
            Err(EnclaveError::Conflict(_))
        ));
        let terminal = PushProviderOutcome::TokenTerminal {
            status: 410,
            code: "invalid_device_token".into(),
        };
        let outcome_at = crate::cp::isotime::format_epoch_millis(epoch_millis());
        control
            .record_push_send_outcome(
                &user.id,
                id,
                first.token_generation,
                claim_id,
                &lease_expires_at,
                PushProviderReceipt::new(terminal.clone(), outcome_at.clone()).unwrap(),
            )
            .await
            .unwrap();
        let old_fence = control
            .list_push_send_fences(&user.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let mut wrong_time = old_fence.clone();
        wrong_time.outcome_at = Some(crate::cp::isotime::format_epoch_millis(
            epoch_millis() + 1_000,
        ));
        assert!(matches!(
            control
                .finish_push_send_fence(&wrong_time, terminal.clone())
                .await,
            Err(EnclaveError::Conflict(_))
        ));
        control
            .finish_push_send_fence(&old_fence, terminal.clone())
            .await
            .unwrap();
        let rotated = control
            .upsert_push_installation(installation(user.id.clone(), id, 'b'))
            .await
            .unwrap();
        assert!(rotated.token_generation > first.token_generation);
        control
            .finish_push_send_fence(&old_fence, terminal)
            .await
            .unwrap();
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
    async fn expired_claim_replays_every_exact_control_receipt_without_downgrade() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state;

        let state = state();
        let user = state
            .control
            .upsert_user(
                "push-expired-receipts",
                "push-expired-receipts@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installation_id = "11111111-1111-4111-8111-111111111171";
        let installed = state
            .control
            .upsert_push_installation(installation(user.id.clone(), installation_id, '9'))
            .await
            .unwrap();
        let binding = PushInstallationBinding::new(installation_id, installed.token_generation)
            .unwrap()
            .encode();
        let now = epoch_millis();
        let started_at =
            crate::cp::isotime::format_epoch_millis(now - wal::claim::CLAIM_LEASE_MILLIS - 1_000);
        let created_at =
            crate::cp::isotime::format_epoch_millis(now - wal::claim::CLAIM_LEASE_MILLIS - 2_000);
        let retry_at = crate::cp::isotime::format_epoch_millis(now + 60_000);
        let cases = [
            PushProviderOutcome::Accepted { status: 200 },
            PushProviderOutcome::Retry {
                status: Some(503),
                code: "provider_retryable".into(),
                retry_at,
            },
            PushProviderOutcome::Failed {
                status: Some(400),
                code: "provider_request_invalid".into(),
            },
            PushProviderOutcome::Ambiguous,
            PushProviderOutcome::TokenTerminal {
                status: 410,
                code: "invalid_device_token".into(),
            },
        ];
        let delivery_ids = [
            "22222222-2222-4222-8222-222222222271",
            "22222222-2222-4222-8222-222222222272",
            "22222222-2222-4222-8222-222222222273",
            "22222222-2222-4222-8222-222222222274",
            "22222222-2222-4222-8222-222222222275",
        ];
        let claim_ids = [
            "44444444-4444-4444-8444-444444444471",
            "44444444-4444-4444-8444-444444444472",
            "44444444-4444-4444-8444-444444444473",
            "44444444-4444-4444-8444-444444444474",
            "44444444-4444-4444-8444-444444444475",
        ];
        for (index, outcome) in cases.into_iter().enumerate() {
            insert_legacy_delivery(
                &state,
                &user.id,
                271 + i64::try_from(index).unwrap(),
                &binding,
                delivery_ids[index],
                &char::from(b'a' + u8::try_from(index).unwrap())
                    .to_string()
                    .repeat(43),
                &format!("33333333-3333-4333-8333-33333333337{}", index + 1),
                0,
                &created_at,
            )
            .await;
            let snapshot = delivery_snapshot(
                state
                    .store
                    .next_push_delivery(&user.id)
                    .await
                    .unwrap()
                    .unwrap(),
            );
            assert_eq!(snapshot.delivery_id, delivery_ids[index]);
            let plan = wal::PushSendClaimPlan::new(
                user.id.clone(),
                claim_ids[index].into(),
                snapshot.clone(),
                started_at.clone(),
            )
            .unwrap();
            assert_eq!(
                submit_send_claim(&state, &user.id, plan).await.unwrap(),
                wal::PushSendClaimDisposition::Authorized
            );
            let claim = load_open_send_claim(&state, &user.id, delivery_ids[index])
                .await
                .unwrap()
                .unwrap();
            let outcome_at = now_for_snapshot(&snapshot, Some(&claim));
            assert!(matches!(
                state
                    .repositories
                    .work()
                    .begin_push_send_fence(
                        &user.id,
                        installation_id,
                        installed.token_generation,
                        claim.claim_id(),
                        claim.lease_expires_at(),
                        &outcome_at,
                    )
                    .await
                    .unwrap(),
                PushSendFenceDisposition::Authorized(_)
            ));
            state
                .repositories
                .work()
                .record_push_send_outcome(
                    &user.id,
                    installation_id,
                    installed.token_generation,
                    claim.claim_id(),
                    claim.lease_expires_at(),
                    PushProviderReceipt::new(outcome.clone(), outcome_at.clone()).unwrap(),
                )
                .await
                .unwrap();
            assert!(
                recover_expired_send_claim(&state, &user.id, snapshot, claim,)
                    .await
                    .unwrap()
            );
            let recovered = load_send_claim_recovery(&state, &user.id, claim_ids[index])
                .await
                .unwrap()
                .unwrap();
            assert_eq!(recovery_outcome(&recovered), Some(outcome));
            assert!(state
                .control
                .list_push_send_fences(&user.id)
                .await
                .unwrap()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn stale_expiry_reader_adopts_the_concurrent_typed_receipt() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state_over;

        let kms = Arc::new(crate::store::tests::FakeKms);
        let gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let primary_control = Arc::new(crate::cp::control_store::ControlStore::new(
            kms.clone(),
            gcs.clone(),
        ));
        let state = state_over(store, primary_control);
        let user = state
            .control
            .upsert_user(
                "push-stale-expiry-reader",
                "push-stale-expiry@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installation_id = "11111111-1111-4111-8111-111111111176";
        let installed = state
            .control
            .upsert_push_installation(installation(user.id.clone(), installation_id, '8'))
            .await
            .unwrap();
        let binding = PushInstallationBinding::new(installation_id, installed.token_generation)
            .unwrap()
            .encode();
        let now = epoch_millis();
        let started_at =
            crate::cp::isotime::format_epoch_millis(now - wal::claim::CLAIM_LEASE_MILLIS - 1_000);
        let created_at =
            crate::cp::isotime::format_epoch_millis(now - wal::claim::CLAIM_LEASE_MILLIS - 2_000);
        let delivery_id = "22222222-2222-4222-8222-222222222276";
        let claim_id = "44444444-4444-4444-8444-444444444476";
        insert_legacy_delivery(
            &state,
            &user.id,
            276,
            &binding,
            delivery_id,
            &"z".repeat(43),
            "33333333-3333-4333-8333-333333333376",
            0,
            &created_at,
        )
        .await;
        let snapshot = delivery_snapshot(
            state
                .store
                .next_push_delivery(&user.id)
                .await
                .unwrap()
                .unwrap(),
        );
        let plan = wal::PushSendClaimPlan::new(
            user.id.clone(),
            claim_id.into(),
            snapshot.clone(),
            started_at,
        )
        .unwrap();
        assert_eq!(
            submit_send_claim(&state, &user.id, plan).await.unwrap(),
            wal::PushSendClaimDisposition::Authorized
        );
        let claim = load_open_send_claim(&state, &user.id, delivery_id)
            .await
            .unwrap()
            .unwrap();
        let outcome_at = now_for_snapshot(&snapshot, Some(&claim));
        assert!(matches!(
            state
                .repositories
                .work()
                .begin_push_send_fence(
                    &user.id,
                    installation_id,
                    installed.token_generation,
                    claim.claim_id(),
                    claim.lease_expires_at(),
                    &outcome_at,
                )
                .await
                .unwrap(),
            PushSendFenceDisposition::Authorized(_)
        ));

        // A second Control handle commits Accepted while the recovery handle
        // still caches the empty send-start fence. Its attempted Ambiguous
        // receipt loses the Control generation CAS, reloads the winner, and
        // must settle that exact Accepted result in the archive.
        let concurrent = crate::cp::control_store::ControlStore::new(kms, gcs);
        concurrent
            .record_push_send_outcome(
                &user.id,
                installation_id,
                installed.token_generation,
                claim.claim_id(),
                claim.lease_expires_at(),
                PushProviderReceipt::new(
                    PushProviderOutcome::Accepted { status: 200 },
                    outcome_at.clone(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            recover_expired_send_claim(&state, &user.id, snapshot, claim,)
                .await
                .unwrap()
        );
        assert!(matches!(
            load_send_claim_recovery(&state, &user.id, claim_id)
                .await
                .unwrap(),
            Some(wal::PushClaimRecovery::Accepted { status: 200, .. })
        ));
        assert_eq!(
            delivery_evidence(&state, &user.id, delivery_id).await,
            ("accepted".into(), 1, None)
        );
    }

    #[tokio::test]
    async fn stale_control_handles_cannot_mint_a_false_destination_cancellation() {
        let _serial = push_test_serial().lock().await;
        let decision_at = crate::cp::isotime::format_epoch_millis(epoch_millis());
        let lease_expires_at = crate::cp::isotime::format_epoch_millis(
            epoch_millis() + wal::claim::CLAIM_LEASE_MILLIS,
        );

        // A cached absence loses to a concurrent registration. Retry reloads
        // the current generation and authorizes; no cancellation is durable.
        let kms = Arc::new(crate::store::tests::FakeKms);
        let gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let creator = crate::cp::control_store::ControlStore::new(kms.clone(), gcs.clone());
        let user = creator
            .upsert_user(
                "push-stale-missing",
                "push-stale-missing@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let stale = crate::cp::control_store::ControlStore::new(kms.clone(), gcs.clone());
        assert!(stale
            .get_push_installation(&user.id, "11111111-1111-4111-8111-111111111177")
            .await
            .unwrap()
            .is_none());
        let writer = crate::cp::control_store::ControlStore::new(kms, gcs);
        let installed = writer
            .upsert_push_installation(installation(
                user.id.clone(),
                "11111111-1111-4111-8111-111111111177",
                '7',
            ))
            .await
            .unwrap();
        assert!(stale
            .begin_push_send_fence(
                &user.id,
                &installed.id,
                installed.token_generation,
                "44444444-4444-4444-8444-444444444477",
                &lease_expires_at,
                &decision_at,
            )
            .await
            .is_err());
        assert!(matches!(
            stale
                .begin_push_send_fence(
                    &user.id,
                    &installed.id,
                    installed.token_generation,
                    "44444444-4444-4444-8444-444444444477",
                    &lease_expires_at,
                    &decision_at,
                )
                .await
                .unwrap(),
            PushSendFenceDisposition::Authorized(_)
        ));

        // Conversely, a cached enabled row loses to a concurrent disable.
        // Retry records the exact current disabled proof; it cannot authorize.
        let kms = Arc::new(crate::store::tests::FakeKms);
        let gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let creator = crate::cp::control_store::ControlStore::new(kms.clone(), gcs.clone());
        let user = creator
            .upsert_user(
                "push-stale-disabled",
                "push-stale-disabled@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installed = creator
            .upsert_push_installation(installation(
                user.id.clone(),
                "11111111-1111-4111-8111-111111111178",
                '6',
            ))
            .await
            .unwrap();
        let stale = crate::cp::control_store::ControlStore::new(kms.clone(), gcs.clone());
        assert!(
            stale
                .get_push_installation(&user.id, &installed.id)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        let writer = crate::cp::control_store::ControlStore::new(kms, gcs);
        assert!(writer
            .delete_push_installation(&user.id, &installed.id)
            .await
            .unwrap());
        assert!(stale
            .begin_push_send_fence(
                &user.id,
                &installed.id,
                installed.token_generation,
                "44444444-4444-4444-8444-444444444478",
                &lease_expires_at,
                &decision_at,
            )
            .await
            .is_err());
        let recorded = stale
            .begin_push_send_fence(
                &user.id,
                &installed.id,
                installed.token_generation,
                "44444444-4444-4444-8444-444444444478",
                &lease_expires_at,
                &decision_at,
            )
            .await
            .unwrap();
        assert!(matches!(
            recorded,
            PushSendFenceDisposition::Recorded(PushSendFence {
                outcome: Some(PushFenceOutcome::Cancellation(
                    PushControlCancellation::InstallationDisabled
                )),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn token_generations_never_reuse_and_registry_churn_is_bounded_across_restart() {
        let _serial = push_test_serial().lock().await;
        let kms = Arc::new(crate::store::tests::FakeKms);
        let gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let control = crate::cp::control_store::ControlStore::new(kms.clone(), gcs.clone());
        let user = control
            .upsert_user(
                "push-generation-owner",
                "push-generation@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let first_id = "11111111-1111-4111-8111-111111111181";
        let first = control
            .upsert_push_installation(installation(user.id.clone(), first_id, 'a'))
            .await
            .unwrap();
        assert!(control
            .delete_push_installation(&user.id, first_id)
            .await
            .unwrap());
        drop(control);

        let reopened = crate::cp::control_store::ControlStore::new(kms, gcs);
        let recreated = reopened
            .upsert_push_installation(installation(user.id.clone(), first_id, 'a'))
            .await
            .unwrap();
        assert!(recreated.token_generation > first.token_generation);

        let duplicate_id = "11111111-1111-4111-8111-111111111182";
        let displaced = reopened
            .upsert_push_installation(installation(user.id.clone(), duplicate_id, 'a'))
            .await
            .unwrap();
        assert!(displaced.token_generation > recreated.token_generation);
        assert!(reopened
            .get_push_installation(&user.id, first_id)
            .await
            .unwrap()
            .is_none());
        let rebound = reopened
            .upsert_push_installation(installation(user.id.clone(), first_id, 'a'))
            .await
            .unwrap();
        assert!(rebound.token_generation > displaced.token_generation);

        let mut highest = rebound.token_generation;
        for ordinal in 0..12_i64 {
            let id = format!("10000000-0000-4000-8000-{ordinal:012x}");
            let mut candidate = installation(user.id.clone(), &id, 'b');
            candidate.device_token = format!("{ordinal:064x}");
            let installed = reopened.upsert_push_installation(candidate).await.unwrap();
            assert!(installed.token_generation > highest);
            highest = installed.token_generation;
        }
        let (total, enabled, _) = reopened
            .push_registry_counts_for_test(&user.id)
            .await
            .unwrap();
        assert_eq!((total, enabled), (10, 10));

        for ordinal in 0..24_i64 {
            let id = format!("20000000-0000-4000-8000-{ordinal:012x}");
            let mut candidate = installation(user.id.clone(), &id, 'c');
            candidate.device_token = format!("{:064x}", ordinal + 100);
            let installed = reopened.upsert_push_installation(candidate).await.unwrap();
            assert!(installed.token_generation > highest);
            highest = installed.token_generation;
            assert!(reopened
                .delete_push_installation(&user.id, &id)
                .await
                .unwrap());
            let (total, enabled, next_generation) = reopened
                .push_registry_counts_for_test(&user.id)
                .await
                .unwrap();
            assert!(total <= 10);
            assert!(enabled <= 9);
            assert!(next_generation > highest);
        }
    }

    #[tokio::test]
    async fn token_rebind_removes_the_prior_accounts_installation() {
        let _serial = push_test_serial().lock().await;
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

    /// The policy-neutral half of the push lift: a selected user's real
    /// finalizer-enqueued row is visible to the due scan and its authenticated
    /// handoff resolves through the same settled archive. Provider activation
    /// remains gated separately.
    #[tokio::test]
    async fn selected_push_scan_and_handoff_resolve_the_real_finalizer_row() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        const USER_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const INSTALLATION_ID: &str = "11111111-1111-4111-8111-111111111111";
        const DELIVERY_ID: &str = "22222222-2222-4222-8222-222222222222";
        const COLLAPSE_ID: &str = "33333333-3333-4333-8333-333333333333";
        const HANDOFF: &str = "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";

        let archive = answerable_wal_archive(USER_ID).await;
        let episode_id = crate::cp::finalizer::enqueue_push_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            INSTALLATION_ID,
            DELIVERY_ID,
            HANDOFF,
            COLLAPSE_ID,
        )
        .await
        .expect("the production finalization plan enqueues the push row");

        let pending = archive
            .state
            .store
            .next_push_delivery(&archive.user_id)
            .await
            .expect("the routed outbox read answers")
            .expect("the real pending row is selectable");
        assert_eq!(pending.episode_id, episode_id);
        assert_eq!(pending.delivery_id, DELIVERY_ID);

        let response = resolve_notification_handoff(
            State(Arc::clone(&archive.state)),
            Extension(AuthUser(archive.user_id.clone())),
            Path(HANDOFF.to_owned()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("the handoff response is bounded");
        let resolved: serde_json::Value =
            serde_json::from_slice(&body).expect("the handoff response is JSON");
        assert_eq!(resolved["memory_id"], episode_id);
    }

    #[tokio::test]
    async fn selected_activation_finalization_enqueues_generation_bound_row() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaf").await;
        archive
            .state
            .control
            .upsert_push_installation(installation(
                archive.user_id.clone(),
                "11111111-1111-4111-8111-111111111111",
                'f',
            ))
            .await
            .unwrap();
        assert_eq!(
            archive
                .state
                .control
                .list_push_installations(&archive.user_id)
                .await
                .unwrap()
                .len(),
            1
        );
        let episode_id = crate::cp::finalizer::enqueue_push_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222231",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "33333333-3333-4333-8333-333333333331",
        )
        .await
        .unwrap();
        let (count, binding, status): (i64, String, String) = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, move |connection| {
                Ok((
                    connection
                        .query_row("SELECT COUNT(*) FROM push_deliveries", [], |row| row.get(0))?,
                    connection.query_row(
                        "SELECT installation_id FROM push_deliveries WHERE episode_id=?1",
                        [episode_id],
                        |row| row.get(0),
                    )?,
                    connection.query_row(
                        "SELECT finalization_status FROM episodes WHERE id=?1",
                        [episode_id],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            PushInstallationBinding::parse(&binding),
            Some(PushInstallationBinding {
                installation_id: "11111111-1111-4111-8111-111111111111".into(),
                token_generation: 1,
            })
        );
        assert_eq!(status, "complete");
    }

    #[tokio::test]
    async fn selected_owner_is_at_most_once_and_generation_fenced_end_to_end() {
        let _serial = push_test_serial().lock().await;
        use crate::archive_v3_wal_idempotency::PreparedLogicalMutation;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        const USER_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab";
        const INSTALLATION_ID: &str = "11111111-1111-4111-8111-111111111111";
        const ACCEPTED_ID: &str = "22222222-2222-4222-8222-222222222221";
        const AMBIGUOUS_ID: &str = "22222222-2222-4222-8222-222222222222";
        const CRASH_ID: &str = "22222222-2222-4222-8222-222222222223";
        const ROTATED_ID: &str = "22222222-2222-4222-8222-222222222224";
        const ACCEPTED_HANDOFF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const AMBIGUOUS_HANDOFF: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const CRASH_HANDOFF: &str = "ccccccccccccccccccccccccccccccccccccccccccc";
        const ROTATED_HANDOFF: &str = "ddddddddddddddddddddddddddddddddddddddddddd";

        let archive = answerable_wal_archive(USER_ID).await;
        let installed = archive
            .state
            .control
            .upsert_push_installation(installation(archive.user_id.clone(), INSTALLATION_ID, 'a'))
            .await
            .unwrap();
        assert_eq!(installed.token_generation, 1);

        let accepted_episode = crate::cp::finalizer::enqueue_push_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            INSTALLATION_ID,
            ACCEPTED_ID,
            ACCEPTED_HANDOFF,
            "33333333-3333-4333-8333-333333333331",
        )
        .await
        .unwrap();
        reset_test_pacer().await;
        let accepted = ScriptedTransport::new([Ok(200)]);
        deliver_user_pushes_routed(&archive.state, &accepted, &archive.user_id)
            .await
            .unwrap();
        let requests = accepted.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].token_generation, 1);
        assert_eq!(requests[0].apns_id, ACCEPTED_ID);
        assert!(requests[0].expiration_epoch_seconds > epoch_seconds());
        assert_eq!(
            delivery_evidence(&archive.state, &archive.user_id, ACCEPTED_ID).await,
            ("accepted".into(), 1, None)
        );
        assert_eq!(
            resolved_memory_id(&archive.state, &archive.user_id, ACCEPTED_HANDOFF).await,
            Some(accepted_episode)
        );

        let ambiguous_episode = crate::cp::finalizer::enqueue_push_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            INSTALLATION_ID,
            AMBIGUOUS_ID,
            AMBIGUOUS_HANDOFF,
            "33333333-3333-4333-8333-333333333332",
        )
        .await
        .unwrap();
        reset_test_pacer().await;
        let ambiguous = ScriptedTransport::new([Err(PushTransportError::Retryable {
            status: None,
            code: "network_lost_response",
            retry_after_seconds: None,
            scope: PushRetryScope::ProviderWide,
        })]);
        deliver_user_pushes_routed(&archive.state, &ambiguous, &archive.user_id)
            .await
            .unwrap();
        assert_eq!(ambiguous.requests().len(), 1);
        assert_eq!(
            delivery_evidence(&archive.state, &archive.user_id, AMBIGUOUS_ID).await,
            (
                "failed".into(),
                1,
                Some(wal::settlement::AMBIGUOUS_ERROR_CODE.into())
            )
        );
        reset_test_pacer().await;
        let never_resend = ScriptedTransport::new([]);
        deliver_user_pushes_routed(&archive.state, &never_resend, &archive.user_id)
            .await
            .unwrap();
        assert!(never_resend.requests().is_empty());
        assert_eq!(
            resolved_memory_id(&archive.state, &archive.user_id, AMBIGUOUS_HANDOFF).await,
            Some(ambiguous_episode)
        );

        let crash_episode = crate::cp::finalizer::enqueue_push_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            INSTALLATION_ID,
            CRASH_ID,
            CRASH_HANDOFF,
            "33333333-3333-4333-8333-333333333333",
        )
        .await
        .unwrap();
        let due = archive
            .state
            .store
            .next_push_delivery(&archive.user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(due.delivery_id, CRASH_ID);
        let snapshot = delivery_snapshot(due);
        let claim_plan = wal::PushSendClaimPlan::new(
            archive.user_id.clone(),
            "44444444-4444-4444-8444-444444444444".into(),
            snapshot.clone(),
            now_for_snapshot(&snapshot, None),
        )
        .unwrap();
        let disposition = archive
            .state
            .store
            .wal_authoritative_submit(
                &archive.user_id,
                PreparedLogicalMutation::prepare(claim_plan).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disposition, wal::PushSendClaimDisposition::Authorized);
        reset_test_pacer().await;
        let after_crash = ScriptedTransport::new([]);
        deliver_user_pushes_routed(&archive.state, &after_crash, &archive.user_id)
            .await
            .unwrap();
        assert!(after_crash.requests().is_empty());
        assert_eq!(
            delivery_evidence(&archive.state, &archive.user_id, CRASH_ID).await,
            ("pending".into(), 0, None)
        );
        tokio::time::sleep(Duration::from_millis(
            u64::try_from(wal::claim::CLAIM_LEASE_MILLIS + 100).unwrap(),
        ))
        .await;
        deliver_user_pushes_routed(&archive.state, &after_crash, &archive.user_id)
            .await
            .unwrap();
        assert_eq!(
            delivery_evidence(&archive.state, &archive.user_id, CRASH_ID).await,
            (
                "failed".into(),
                1,
                Some(wal::settlement::AMBIGUOUS_ERROR_CODE.into())
            )
        );
        assert_eq!(
            resolved_memory_id(&archive.state, &archive.user_id, CRASH_HANDOFF).await,
            Some(crash_episode)
        );

        crate::cp::finalizer::enqueue_push_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            INSTALLATION_ID,
            ROTATED_ID,
            ROTATED_HANDOFF,
            "33333333-3333-4333-8333-333333333334",
        )
        .await
        .unwrap();
        assert!(archive
            .state
            .control
            .delete_push_installation(&archive.user_id, INSTALLATION_ID)
            .await
            .unwrap());
        let rebound = archive
            .state
            .control
            .upsert_push_installation(installation(archive.user_id.clone(), INSTALLATION_ID, 'a'))
            .await
            .unwrap();
        assert_eq!(rebound.token_generation, 2);
        reset_test_pacer().await;
        let generation_fenced = ScriptedTransport::new([]);
        deliver_user_pushes_routed(&archive.state, &generation_fenced, &archive.user_id)
            .await
            .unwrap();
        assert!(generation_fenced.requests().is_empty());
        assert_eq!(
            delivery_evidence(&archive.state, &archive.user_id, ROTATED_ID).await,
            (
                "cancelled".into(),
                0,
                Some("token_generation_changed".into())
            )
        );
        assert_eq!(
            resolved_memory_id(&archive.state, &archive.user_id, ROTATED_HANDOFF).await,
            None
        );
    }

    #[tokio::test]
    async fn selected_owner_cancels_missing_and_disabled_then_defers_to_deletion() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        const USER_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaac";
        const INSTALLATION_ID: &str = "11111111-1111-4111-8111-111111111111";
        let archive = answerable_wal_archive(USER_ID).await;
        archive
            .state
            .control
            .upsert_push_installation(installation(archive.user_id.clone(), INSTALLATION_ID, 'c'))
            .await
            .unwrap();

        let cases = [
            (
                "99999999-9999-4999-8999-999999999999",
                "22222222-2222-4222-8222-222222222225",
                "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii",
                "33333333-3333-4333-8333-333333333335",
                "installation_missing",
            ),
            (
                INSTALLATION_ID,
                "22222222-2222-4222-8222-222222222226",
                "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj",
                "33333333-3333-4333-8333-333333333336",
                "installation_disabled",
            ),
            (
                INSTALLATION_ID,
                "22222222-2222-4222-8222-222222222227",
                "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
                "33333333-3333-4333-8333-333333333337",
                "account_inactive",
            ),
        ];
        for (index, (installation_id, delivery_id, handoff, collapse, reason)) in
            cases.into_iter().enumerate()
        {
            crate::cp::finalizer::enqueue_push_delivery_for_activation_test(
                &archive.state,
                &archive.user_id,
                installation_id,
                delivery_id,
                handoff,
                collapse,
            )
            .await
            .unwrap();
            if index == 1 {
                archive
                    .state
                    .control
                    .delete_push_installation(&archive.user_id, INSTALLATION_ID)
                    .await
                    .unwrap();
            } else if index == 2 {
                let unclaimed_id = "22222222-2222-4222-8222-222222222228";
                crate::cp::finalizer::enqueue_push_delivery_for_activation_test(
                    &archive.state,
                    &archive.user_id,
                    INSTALLATION_ID,
                    unclaimed_id,
                    "ooooooooooooooooooooooooooooooooooooooooooo",
                    "33333333-3333-4333-8333-333333333338",
                )
                .await
                .unwrap();
                let due = archive
                    .state
                    .store
                    .next_push_delivery(&archive.user_id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(due.delivery_id, delivery_id);
                let snapshot = delivery_snapshot(due);
                let claim_plan = wal::PushSendClaimPlan::new(
                    archive.user_id.clone(),
                    "55555555-5555-4555-8555-555555555555".into(),
                    snapshot.clone(),
                    now_for_snapshot(&snapshot, None),
                )
                .unwrap();
                let claim =
                    crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(claim_plan)
                        .unwrap();
                assert_eq!(
                    archive
                        .state
                        .store
                        .wal_authoritative_submit(&archive.user_id, claim)
                        .await
                        .unwrap(),
                    wal::PushSendClaimDisposition::Authorized
                );
                archive
                    .state
                    .control
                    .begin_user_deletion(&archive.user_id)
                    .await
                    .unwrap();
            }
            reset_test_pacer().await;
            let no_send = ScriptedTransport::new([]);
            deliver_user_pushes_routed(&archive.state, &no_send, &archive.user_id)
                .await
                .unwrap_or_else(|error| panic!("{reason}: {error:?}"));
            assert!(no_send.requests().is_empty(), "{reason}");
            if index == 2 {
                assert_eq!(
                    delivery_evidence(&archive.state, &archive.user_id, delivery_id).await,
                    ("pending".into(), 0, None)
                );
                assert_eq!(
                    delivery_evidence(
                        &archive.state,
                        &archive.user_id,
                        "22222222-2222-4222-8222-222222222228"
                    )
                    .await,
                    ("pending".into(), 0, None)
                );
            } else {
                assert_eq!(
                    delivery_evidence(&archive.state, &archive.user_id, delivery_id).await,
                    ("cancelled".into(), 0, Some(reason.into()))
                );
            }
        }
    }

    #[tokio::test]
    async fn legacy_owner_accepts_retries_caps_and_terminally_disables() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state;

        let state = state();
        let user = state
            .control
            .upsert_user(
                "legacy-push-owner",
                "legacy-push@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installation_id = "11111111-1111-4111-8111-111111111111";
        let installed = state
            .control
            .upsert_push_installation(installation(user.id.clone(), installation_id, 'e'))
            .await
            .unwrap();
        let binding = PushInstallationBinding::new(installation_id, installed.token_generation)
            .unwrap()
            .encode();
        let now = crate::cp::isotime::format_epoch_millis(epoch_millis());

        insert_legacy_delivery(
            &state,
            &user.id,
            101,
            &binding,
            "22222222-2222-4222-8222-222222222231",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "33333333-3333-4333-8333-333333333331",
            0,
            &now,
        )
        .await;
        reset_test_pacer().await;
        let accepted = ScriptedTransport::new([Ok(200)]);
        deliver_user_pushes(&state, &accepted, &user.id)
            .await
            .unwrap();
        assert_eq!(accepted.requests().len(), 1);
        assert_eq!(
            delivery_evidence(&state, &user.id, "22222222-2222-4222-8222-222222222231").await,
            ("accepted".into(), 1, None)
        );
        assert_eq!(
            resolved_memory_id(
                &state,
                &user.id,
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            )
            .await,
            Some(101)
        );

        let retry_id = "22222222-2222-4222-8222-222222222232";
        insert_legacy_delivery(
            &state,
            &user.id,
            102,
            &binding,
            retry_id,
            "fffffffffffffffffffffffffffffffffffffffffff",
            "33333333-3333-4333-8333-333333333332",
            0,
            &now,
        )
        .await;
        reset_test_pacer().await;
        let retryable = ScriptedTransport::new([Err(PushTransportError::Retryable {
            status: Some(429),
            code: "provider_retryable",
            retry_after_seconds: Some(120),
            scope: PushRetryScope::TokenLocal,
        })]);
        deliver_user_pushes(&state, &retryable, &user.id)
            .await
            .unwrap();
        assert_eq!(retryable.requests().len(), 1);
        assert_eq!(
            delivery_evidence(&state, &user.id, retry_id).await,
            ("retry".into(), 1, Some("provider_retryable".into()))
        );
        let retry_delta = state
            .store
            .wal_authoritative_read(&user.id, {
                let retry_id = retry_id.to_owned();
                move |connection| {
                    connection
                        .query_row(
                            "SELECT next_attempt_at,updated_at FROM push_deliveries
                             WHERE delivery_id=?1",
                            [retry_id],
                            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                        )
                        .map_err(EnclaveError::from)
                }
            })
            .await
            .unwrap();
        assert_eq!(
            crate::cp::isotime::parse_epoch_millis(&retry_delta.0).unwrap()
                - crate::cp::isotime::parse_epoch_millis(&retry_delta.1).unwrap(),
            120_000
        );

        let capped_id = "22222222-2222-4222-8222-222222222233";
        insert_legacy_delivery(
            &state,
            &user.id,
            103,
            &binding,
            capped_id,
            "ggggggggggggggggggggggggggggggggggggggggggg",
            "33333333-3333-4333-8333-333333333333",
            9,
            &now,
        )
        .await;
        reset_test_pacer().await;
        let capped = ScriptedTransport::new([Err(PushTransportError::Retryable {
            status: Some(503),
            code: "provider_retryable",
            retry_after_seconds: None,
            scope: PushRetryScope::ProviderWide,
        })]);
        deliver_user_pushes(&state, &capped, &user.id)
            .await
            .unwrap();
        assert_eq!(capped.requests().len(), 1);
        assert_eq!(
            delivery_evidence(&state, &user.id, capped_id).await,
            ("failed".into(), 10, Some("attempt_cap".into()))
        );

        let terminal_id = "22222222-2222-4222-8222-222222222234";
        insert_legacy_delivery(
            &state,
            &user.id,
            104,
            &binding,
            terminal_id,
            "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
            "33333333-3333-4333-8333-333333333334",
            0,
            &now,
        )
        .await;
        reset_test_pacer().await;
        let terminal = ScriptedTransport::new([Err(PushTransportError::TokenTerminal {
            status: 410,
            code: "invalid_device_token",
        })]);
        deliver_user_pushes(&state, &terminal, &user.id)
            .await
            .unwrap();
        assert_eq!(terminal.requests().len(), 1);
        assert_eq!(
            delivery_evidence(&state, &user.id, terminal_id).await,
            ("failed".into(), 1, Some("invalid_device_token".into()))
        );
        assert!(
            !state
                .control
                .get_push_installation(&user.id, installation_id)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );

        let expired_id = "22222222-2222-4222-8222-222222222235";
        let bare_id = "22222222-2222-4222-8222-222222222236";
        let malformed_id = "22222222-2222-4222-8222-222222222237";
        let expired_at = crate::cp::isotime::format_epoch_millis(
            epoch_millis() - (MAX_DELIVERY_AGE_SECONDS + 60) * 1_000,
        );
        insert_legacy_delivery(
            &state,
            &user.id,
            105,
            &binding,
            expired_id,
            "lllllllllllllllllllllllllllllllllllllllllll",
            "33333333-3333-4333-8333-333333333335",
            0,
            &expired_at,
        )
        .await;
        insert_legacy_delivery(
            &state,
            &user.id,
            106,
            installation_id,
            bare_id,
            "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm",
            "33333333-3333-4333-8333-333333333336",
            0,
            &now,
        )
        .await;
        insert_legacy_delivery(
            &state,
            &user.id,
            107,
            &binding,
            malformed_id,
            "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn",
            "not-a-collapse-id",
            0,
            &now,
        )
        .await;
        reset_test_pacer().await;
        let poison = ScriptedTransport::new([]);
        deliver_user_pushes(&state, &poison, &user.id)
            .await
            .unwrap();
        deliver_user_pushes(&state, &poison, &user.id)
            .await
            .unwrap();
        assert!(poison.requests().is_empty());
        assert_eq!(
            delivery_evidence(&state, &user.id, expired_id).await,
            ("cancelled".into(), 0, Some("delivery_expired".into()))
        );
        assert_eq!(
            delivery_evidence(&state, &user.id, bare_id).await,
            ("cancelled".into(), 0, Some("activation_ineligible".into()))
        );
        assert_eq!(
            delivery_evidence(&state, &user.id, malformed_id).await,
            ("cancelled".into(), 0, Some("delivery_malformed".into()))
        );
    }

    #[tokio::test]
    async fn provider_circuit_preserves_later_accounts_without_attempt_charge() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state;

        let state = state();
        let mut users = Vec::new();
        for (subject, email, installation_id, token, episode_id, delivery_id, handoff, collapse) in [
            (
                "push-circuit-first",
                "circuit-first@example.com",
                "11111111-1111-4111-8111-111111111121",
                'a',
                201,
                "22222222-2222-4222-8222-222222222241",
                "ppppppppppppppppppppppppppppppppppppppppppp",
                "33333333-3333-4333-8333-333333333341",
            ),
            (
                "push-circuit-second",
                "circuit-second@example.com",
                "11111111-1111-4111-8111-111111111122",
                'b',
                202,
                "22222222-2222-4222-8222-222222222242",
                "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                "33333333-3333-4333-8333-333333333342",
            ),
        ] {
            let user = state
                .control
                .upsert_user(subject, email, crate::cp::control_store::TEST_SIGNUP_LIMIT)
                .await
                .unwrap();
            let installed = state
                .control
                .upsert_push_installation(installation(user.id.clone(), installation_id, token))
                .await
                .unwrap();
            let binding = PushInstallationBinding::new(installation_id, installed.token_generation)
                .unwrap()
                .encode();
            let now = crate::cp::isotime::format_epoch_millis(epoch_millis());
            insert_legacy_delivery(
                &state,
                &user.id,
                episode_id,
                &binding,
                delivery_id,
                handoff,
                collapse,
                0,
                &now,
            )
            .await;
            users.push((user.id, delivery_id));
        }

        reset_test_pacer().await;
        let terminal = ScriptedTransport::new([Err(PushTransportError::ProviderTerminal {
            status: None,
            code: "provider_credentials",
        })]);
        deliver_user_pushes(&state, &terminal, &users[0].0)
            .await
            .unwrap();
        assert_eq!(terminal.requests().len(), 1);
        assert_eq!(
            delivery_evidence(&state, &users[0].0, users[0].1).await,
            ("retry".into(), 1, Some("provider_credentials".into()))
        );

        let circuit_blocked = ScriptedTransport::new([]);
        deliver_user_pushes(&state, &circuit_blocked, &users[1].0)
            .await
            .unwrap();
        assert!(circuit_blocked.requests().is_empty());
        assert_eq!(
            delivery_evidence(&state, &users[1].0, users[1].1).await,
            ("pending".into(), 0, None)
        );
        reset_test_pacer().await;
    }

    #[tokio::test]
    async fn token_local_429_does_not_open_the_provider_wide_circuit() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state;

        let state = state();
        let mut rows = Vec::new();
        for (ordinal, subject, token) in [
            (1_i64, "push-local-429-a", 'a'),
            (2_i64, "push-local-429-b", 'b'),
        ] {
            let user = state
                .control
                .upsert_user(
                    subject,
                    &format!("{subject}@example.com"),
                    crate::cp::control_store::TEST_SIGNUP_LIMIT,
                )
                .await
                .unwrap();
            let installation_id = format!("11111111-1111-4111-8111-{ordinal:012x}");
            let installed = state
                .control
                .upsert_push_installation(installation(user.id.clone(), &installation_id, token))
                .await
                .unwrap();
            let binding =
                PushInstallationBinding::new(&installation_id, installed.token_generation)
                    .unwrap()
                    .encode();
            let delivery_id = format!("22222222-2222-4222-8222-{ordinal:012x}");
            insert_legacy_delivery(
                &state,
                &user.id,
                290 + ordinal,
                &binding,
                &delivery_id,
                &format!("{:0>43}", ordinal),
                &format!("33333333-3333-4333-8333-{ordinal:012x}"),
                0,
                &crate::cp::isotime::format_epoch_millis(epoch_millis()),
            )
            .await;
            rows.push((user.id, delivery_id));
        }

        reset_test_pacer().await;
        let local = ScriptedTransport::new([Err(PushTransportError::Retryable {
            status: Some(429),
            code: "provider_retryable",
            retry_after_seconds: Some(6 * 60 * 60),
            scope: PushRetryScope::TokenLocal,
        })]);
        deliver_user_pushes(&state, &local, &rows[0].0)
            .await
            .unwrap();
        assert_eq!(local.requests().len(), 1);

        let neighbor = ScriptedTransport::new([Ok(200)]);
        deliver_user_pushes(&state, &neighbor, &rows[1].0)
            .await
            .unwrap();
        assert_eq!(neighbor.requests().len(), 1);
        assert_eq!(
            delivery_evidence(&state, &rows[1].0, &rows[1].1).await,
            ("accepted".into(), 1, None)
        );
    }

    #[tokio::test]
    async fn durable_send_fence_is_exact_nonblocking_and_recovers_cancelled_provider_future() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state;

        let state = state();
        let sending_user = state
            .control
            .upsert_user(
                "push-fence-sender",
                "push-fence-sender@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let unrelated_user = state
            .control
            .upsert_user(
                "push-fence-unrelated",
                "push-fence-unrelated@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installation_id = "11111111-1111-4111-8111-111111111141";
        let installed = state
            .control
            .upsert_push_installation(installation(sending_user.id.clone(), installation_id, 'e'))
            .await
            .unwrap();
        let binding = PushInstallationBinding::new(installation_id, installed.token_generation)
            .unwrap()
            .encode();
        let delivery_id = "22222222-2222-4222-8222-222222222261";
        insert_legacy_delivery(
            &state,
            &sending_user.id,
            261,
            &binding,
            delivery_id,
            "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv",
            "33333333-3333-4333-8333-333333333361",
            0,
            &crate::cp::isotime::format_epoch_millis(epoch_millis()),
        )
        .await;

        reset_test_pacer().await;
        let transport = Arc::new(BlockingTransport::new());
        let owner_state = Arc::clone(&state);
        let owner_transport = Arc::clone(&transport);
        let owner_user = sending_user.id.clone();
        let owner = tokio::spawn(async move {
            deliver_user_pushes(&owner_state, owner_transport.as_ref(), &owner_user).await
        });
        tokio::time::timeout(Duration::from_secs(2), transport.started.notified())
            .await
            .expect("the provider future starts after both durable claims");
        assert_eq!(transport.requests.lock().unwrap().len(), 1);

        // A defensive independent claimant can race without sharing this
        // process's pacer. It observes Busy, proves A's lease is live, and
        // leaves both A's archive claim and Control fence untouched. This is
        // not permission to run overlapping production senders.
        let competing_snapshot = delivery_snapshot(
            state
                .store
                .next_push_delivery(&sending_user.id)
                .await
                .unwrap()
                .unwrap(),
        );
        let competing = wal::PushSendClaimPlan::new(
            sending_user.id.clone(),
            "44444444-4444-4444-8444-444444444461".into(),
            competing_snapshot.clone(),
            now_for_snapshot(&competing_snapshot, None),
        )
        .unwrap();
        assert_eq!(
            submit_send_claim(&state, &sending_user.id, competing)
                .await
                .unwrap(),
            wal::PushSendClaimDisposition::Busy
        );
        let owner_claim = load_open_send_claim(&state, &sending_user.id, delivery_id)
            .await
            .unwrap()
            .unwrap();
        assert!(!recover_expired_send_claim(
            &state,
            &sending_user.id,
            competing_snapshot,
            owner_claim,
        )
        .await
        .unwrap());
        assert_eq!(
            state
                .control
                .list_push_send_fences(&sending_user.id)
                .await
                .unwrap()
                .len(),
            1
        );

        // An unrelated Control mutation completes while the provider future is
        // deliberately blocked: no global Control mutex crosses provider I/O.
        tokio::time::timeout(
            Duration::from_secs(2),
            state
                .control
                .set_email_preference(&unrelated_user.id, false, false),
        )
        .await
        .expect("an unrelated account must not wait for APNs")
        .unwrap();
        assert!(matches!(
            state.control.begin_user_deletion(&sending_user.id).await,
            Err(EnclaveError::Conflict(_))
        ));
        assert!(matches!(
            state
                .control
                .delete_push_installation(&sending_user.id, installation_id)
                .await,
            Err(EnclaveError::Conflict(_))
        ));
        assert!(matches!(
            state
                .control
                .upsert_push_installation(installation(
                    sending_user.id.clone(),
                    installation_id,
                    'f',
                ))
                .await,
            Err(EnclaveError::Conflict(_))
        ));

        // Cancellation at the lost-response boundary leaves both exact claims
        // durable. Restart recovery closes the Control fence, marks the
        // archive claim ambiguous, and never invokes the provider again.
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        reset_test_pacer().await;
        let no_resend = ScriptedTransport::new([]);
        deliver_user_pushes(&state, &no_resend, &sending_user.id)
            .await
            .unwrap();
        assert!(no_resend.requests().is_empty());
        assert_eq!(
            delivery_evidence(&state, &sending_user.id, delivery_id).await,
            ("pending".into(), 0, None)
        );
        assert!(matches!(
            state.control.begin_user_deletion(&sending_user.id).await,
            Err(EnclaveError::Conflict(_))
        ));
        tokio::time::sleep(Duration::from_millis(
            u64::try_from(wal::claim::CLAIM_LEASE_MILLIS + 100).unwrap(),
        ))
        .await;
        deliver_user_pushes(&state, &no_resend, &sending_user.id)
            .await
            .unwrap();
        assert_eq!(
            delivery_evidence(&state, &sending_user.id, delivery_id).await,
            (
                "failed".into(),
                1,
                Some(wal::settlement::AMBIGUOUS_ERROR_CODE.into())
            )
        );
        assert!(state
            .control
            .begin_user_deletion(&sending_user.id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn global_fifo_pacing_is_fair_and_each_account_sweep_is_bounded() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state;

        let state = state();
        let user_a = state
            .control
            .upsert_user(
                "push-fair-user-a",
                "push-fair-a@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let user_b = state
            .control
            .upsert_user(
                "push-fair-user-b",
                "push-fair-b@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installation_a = "11111111-1111-4111-8111-111111111151";
        let installation_b = "11111111-1111-4111-8111-111111111152";
        let installed_a = state
            .control
            .upsert_push_installation(installation(user_a.id.clone(), installation_a, '1'))
            .await
            .unwrap();
        let installed_b = state
            .control
            .upsert_push_installation(installation(user_b.id.clone(), installation_b, '2'))
            .await
            .unwrap();
        let binding_a = PushInstallationBinding::new(installation_a, installed_a.token_generation)
            .unwrap()
            .encode();
        let binding_b = PushInstallationBinding::new(installation_b, installed_b.token_generation)
            .unwrap()
            .encode();
        let now = crate::cp::isotime::format_epoch_millis(epoch_millis());
        let a_ids = [
            "22222222-2222-4222-8222-222222222271",
            "22222222-2222-4222-8222-222222222272",
            "22222222-2222-4222-8222-222222222273",
        ];
        for (index, delivery_id) in a_ids.iter().enumerate() {
            insert_legacy_delivery(
                &state,
                &user_a.id,
                271 + i64::try_from(index).unwrap(),
                &binding_a,
                delivery_id,
                &char::from(b'a' + u8::try_from(index).unwrap())
                    .to_string()
                    .repeat(43),
                &format!("33333333-3333-4333-8333-33333333337{}", index + 1),
                0,
                &now,
            )
            .await;
        }
        let b_id = "22222222-2222-4222-8222-222222222274";
        insert_legacy_delivery(
            &state,
            &user_b.id,
            274,
            &binding_b,
            b_id,
            &"d".repeat(43),
            "33333333-3333-4333-8333-333333333374",
            0,
            &now,
        )
        .await;

        reset_test_pacer().await;
        let transport = Arc::new(FairnessTransport::new());
        let state_a = Arc::clone(&state);
        let transport_a = Arc::clone(&transport);
        let user_a_id = user_a.id.clone();
        let sweep_a = tokio::spawn(async move {
            deliver_user_pushes(&state_a, transport_a.as_ref(), &user_a_id).await
        });
        tokio::time::timeout(Duration::from_secs(2), transport.first_started.notified())
            .await
            .unwrap();
        let state_b = Arc::clone(&state);
        let transport_b = Arc::clone(&transport);
        let user_b_id = user_b.id.clone();
        let sweep_b = tokio::spawn(async move {
            deliver_user_pushes(&state_b, transport_b.as_ref(), &user_b_id).await
        });
        tokio::task::yield_now().await;
        transport.first_release.notify_one();
        sweep_a.await.unwrap().unwrap();
        sweep_b.await.unwrap().unwrap();

        let requests = transport.requests.lock().unwrap().clone();
        assert_eq!(
            requests
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            vec![a_ids[0], b_id, a_ids[1]],
            "the queued account must run before the first account reacquires"
        );
        for pair in requests.windows(2) {
            assert!(
                pair[1].1.duration_since(pair[0].1)
                    >= Duration::from_millis(GLOBAL_SEND_PACE_MILLIS - 25),
                "provider calls must obey the content-independent global pace"
            );
        }
        assert_eq!(
            delivery_evidence(&state, &user_a.id, a_ids[2]).await,
            ("pending".into(), 0, None),
            "one account sweep may charge at most two rows"
        );
    }

    #[tokio::test]
    async fn push_depth_age_and_outcome_metrics_are_content_free() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::{capture_events, state};

        let state = state();
        let user = state
            .control
            .upsert_user(
                "push-metric-owner",
                "push-metric-owner@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installation_id = "11111111-1111-4111-8111-111111111161";
        let installed = state
            .control
            .upsert_push_installation(installation(user.id.clone(), installation_id, '9'))
            .await
            .unwrap();
        let binding = PushInstallationBinding::new(installation_id, installed.token_generation)
            .unwrap()
            .encode();
        let delivery_id = "22222222-2222-4222-8222-222222222281";
        let handoff = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        insert_legacy_delivery(
            &state,
            &user.id,
            281,
            &binding,
            delivery_id,
            handoff,
            "33333333-3333-4333-8333-333333333381",
            0,
            &crate::cp::isotime::format_epoch_millis(epoch_millis()),
        )
        .await;

        reset_test_pacer().await;
        let (captured, guard) = capture_events();
        let accepted = ScriptedTransport::new([Ok(200)]);
        deliver_user_pushes(&state, &accepted, &user.id)
            .await
            .unwrap();
        drop(guard);
        let text = captured.text();
        assert!(text.contains("push_outbox_depth"), "{text}");
        assert!(text.contains("oldest_age_seconds"), "{text}");
        assert!(text.contains("push_outbox_outcome"), "{text}");
        for secret in [
            user.id.as_str(),
            "push-metric-owner@example.com",
            installation_id,
            delivery_id,
            handoff,
            &"9".repeat(64),
        ] {
            assert!(
                !text.contains(secret),
                "push metric leaked {secret}: {text}"
            );
        }
    }

    #[tokio::test]
    async fn control_fence_unavailable_defers_without_send_or_attempt_charge() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state_over;

        let kms = Arc::new(crate::store::tests::FakeKms);
        let store_gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let control_gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let state = state_over(
            Arc::new(crate::store::Store::new(kms.clone(), store_gcs)),
            Arc::new(crate::cp::control_store::ControlStore::new(
                kms,
                control_gcs.clone(),
            )),
        );
        let user = state
            .control
            .upsert_user(
                "push-control-unavailable",
                "push-control-unavailable@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installation_id = "11111111-1111-4111-8111-111111111142";
        let installed = state
            .control
            .upsert_push_installation(installation(user.id.clone(), installation_id, '8'))
            .await
            .unwrap();
        let binding = PushInstallationBinding::new(installation_id, installed.token_generation)
            .unwrap()
            .encode();
        let delivery_id = "22222222-2222-4222-8222-222222222262";
        let handoff = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww";
        insert_legacy_delivery(
            &state,
            &user.id,
            262,
            &binding,
            delivery_id,
            handoff,
            "33333333-3333-4333-8333-333333333362",
            0,
            &crate::cp::isotime::format_epoch_millis(epoch_millis()),
        )
        .await;

        // All read preflights use the already-loaded Control handle. The next
        // persisted write is the short send-fence admission, so this failure
        // occurs after archive claim but provably before provider I/O.
        control_gcs.fail_next_put(EnclaveError::Gcs(
            "injected Control send-fence unavailability".into(),
        ));
        reset_test_pacer().await;
        let no_send = ScriptedTransport::new([]);
        assert!(deliver_user_pushes(&state, &no_send, &user.id)
            .await
            .is_err());
        assert!(no_send.requests().is_empty());
        assert_eq!(
            delivery_evidence(&state, &user.id, delivery_id).await,
            (
                "retry".into(),
                0,
                Some("control_recheck_unavailable".into())
            )
        );
        assert_eq!(
            resolved_memory_id(&state, &user.id, handoff).await,
            Some(262)
        );
    }

    #[tokio::test]
    async fn account_content_deletion_removes_delivery_and_open_claim_together() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state_over;
        use crate::store::GcsClient;

        let kms = Arc::new(crate::store::tests::FakeKms);
        let gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let state = state_over(
            Arc::new(crate::store::Store::new(kms.clone(), gcs.clone())),
            Arc::new(crate::cp::control_store::ControlStore::new(
                kms,
                gcs.clone(),
            )),
        );
        let user = state
            .control
            .upsert_user(
                "push-delete-content",
                "push-delete-content@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installation_id = "11111111-1111-4111-8111-111111111143";
        let installed = state
            .control
            .upsert_push_installation(installation(user.id.clone(), installation_id, '7'))
            .await
            .unwrap();
        let binding = PushInstallationBinding::new(installation_id, installed.token_generation)
            .unwrap()
            .encode();
        let delivery_id = "22222222-2222-4222-8222-222222222263";
        insert_legacy_delivery(
            &state,
            &user.id,
            263,
            &binding,
            delivery_id,
            &"y".repeat(43),
            "33333333-3333-4333-8333-333333333363",
            0,
            &crate::cp::isotime::format_epoch_millis(epoch_millis()),
        )
        .await;
        let snapshot = delivery_snapshot(
            state
                .store
                .next_push_delivery(&user.id)
                .await
                .unwrap()
                .unwrap(),
        );
        let claim = wal::PushSendClaimPlan::new(
            user.id.clone(),
            "44444444-4444-4444-8444-444444444463".into(),
            snapshot.clone(),
            now_for_snapshot(&snapshot, None),
        )
        .unwrap();
        assert_eq!(
            submit_send_claim(&state, &user.id, claim).await.unwrap(),
            wal::PushSendClaimDisposition::Authorized
        );
        assert!(load_open_send_claim(&state, &user.id, delivery_id)
            .await
            .unwrap()
            .is_some());
        assert!(state
            .control
            .begin_user_deletion(&user.id)
            .await
            .unwrap()
            .is_some());
        state.store.delete_user(&user.id).await.unwrap();
        assert!(matches!(
            GcsClient::get_object(gcs.as_ref(), &format!("indexes/{}.db.enc", user.id)).await,
            Err(EnclaveError::NotFound)
        ));
    }

    #[tokio::test]
    async fn settlement_save_failure_after_200_never_resends_and_still_resolves() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::state_over;

        struct FailSettlementSave {
            gcs: Arc<crate::store::tests::FakeGcs>,
            object_name: String,
            requests: StdMutex<Vec<PushRequest>>,
        }

        #[async_trait]
        impl PushTransport for FailSettlementSave {
            async fn send(
                &self,
                request: PushRequest,
            ) -> std::result::Result<u16, PushTransportError> {
                self.requests.lock().unwrap().push(request);
                self.gcs.fail_next_put_for_object(
                    &self.object_name,
                    EnclaveError::Gcs("injected settlement save failure".into()),
                );
                Ok(200)
            }
        }

        struct FailTerminalSettlementSave {
            gcs: Arc<crate::store::tests::FakeGcs>,
            object_name: String,
            requests: StdMutex<Vec<PushRequest>>,
        }

        #[async_trait]
        impl PushTransport for FailTerminalSettlementSave {
            async fn send(
                &self,
                request: PushRequest,
            ) -> std::result::Result<u16, PushTransportError> {
                self.requests.lock().unwrap().push(request);
                self.gcs.fail_next_put_for_object(
                    &self.object_name,
                    EnclaveError::Gcs("injected terminal settlement save failure".into()),
                );
                Err(PushTransportError::TokenTerminal {
                    status: 410,
                    code: "invalid_device_token",
                })
            }
        }

        struct FailControlTerminalOutcomeSave {
            gcs: Arc<crate::store::tests::FakeGcs>,
            requests: StdMutex<Vec<PushRequest>>,
        }

        #[async_trait]
        impl PushTransport for FailControlTerminalOutcomeSave {
            async fn send(
                &self,
                request: PushRequest,
            ) -> std::result::Result<u16, PushTransportError> {
                self.requests.lock().unwrap().push(request);
                self.gcs.fail_next_put_for_object(
                    "control/control.db.enc",
                    EnclaveError::Gcs("injected Control outcome save failure".into()),
                );
                Err(PushTransportError::TokenTerminal {
                    status: 410,
                    code: "invalid_device_token",
                })
            }
        }

        struct LoseSettlementResponse {
            gcs: Arc<crate::store::tests::FakeGcs>,
            object_name: String,
            requests: StdMutex<Vec<PushRequest>>,
        }

        #[async_trait]
        impl PushTransport for LoseSettlementResponse {
            async fn send(
                &self,
                request: PushRequest,
            ) -> std::result::Result<u16, PushTransportError> {
                self.requests.lock().unwrap().push(request);
                self.gcs.fail_next_put_for_object_after_commit(
                    &self.object_name,
                    EnclaveError::Gcs("injected lost settlement response".into()),
                );
                Ok(200)
            }
        }

        let kms = Arc::new(crate::store::tests::FakeKms);
        let gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let control = Arc::new(crate::cp::control_store::ControlStore::new(
            kms.clone(),
            gcs.clone(),
        ));
        let state = state_over(store, control);
        let user = state
            .control
            .upsert_user(
                "push-settlement-save-failure",
                "push-save-failure@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let installation_id = "11111111-1111-4111-8111-111111111131";
        let installed = state
            .control
            .upsert_push_installation(installation(user.id.clone(), installation_id, 'd'))
            .await
            .unwrap();
        let binding = PushInstallationBinding::new(installation_id, installed.token_generation)
            .unwrap()
            .encode();
        let delivery_id = "22222222-2222-4222-8222-222222222251";
        let handoff = "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr";
        insert_legacy_delivery(
            &state,
            &user.id,
            251,
            &binding,
            delivery_id,
            handoff,
            "33333333-3333-4333-8333-333333333351",
            0,
            &crate::cp::isotime::format_epoch_millis(epoch_millis()),
        )
        .await;
        reset_test_pacer().await;
        let transport = FailSettlementSave {
            gcs: gcs.clone(),
            object_name: format!("indexes/{}.db.enc", user.id),
            requests: StdMutex::new(Vec::new()),
        };
        assert!(deliver_user_pushes(&state, &transport, &user.id)
            .await
            .is_err());
        assert_eq!(transport.requests.lock().unwrap().len(), 1);

        // Restart from the last durable generation: it contains the exact
        // pre-send claim but not the accepted settlement whose save failed.
        let restarted = state_over(
            Arc::new(crate::store::Store::new(kms.clone(), gcs.clone())),
            Arc::clone(&state.control),
        );
        reset_test_pacer().await;
        let no_resend = ScriptedTransport::new([]);
        deliver_user_pushes(&restarted, &no_resend, &user.id)
            .await
            .unwrap();
        assert!(no_resend.requests().is_empty());
        assert_eq!(
            delivery_evidence(&restarted, &user.id, delivery_id).await,
            ("accepted".into(), 1, None)
        );
        assert_eq!(
            resolved_memory_id(&restarted, &user.id, handoff).await,
            Some(251)
        );

        // Archive-side failure after a known token-terminal result leaves the
        // exact Control receipt and generation disable durable. Restart
        // replays that typed result into the archive without another send.
        let terminal_id = "22222222-2222-4222-8222-222222222253";
        let terminal_handoff = "w".repeat(43);
        insert_legacy_delivery(
            &restarted,
            &user.id,
            253,
            &binding,
            terminal_id,
            &terminal_handoff,
            "33333333-3333-4333-8333-333333333353",
            0,
            &crate::cp::isotime::format_epoch_millis(epoch_millis()),
        )
        .await;
        reset_test_pacer().await;
        let terminal_archive_failure = FailTerminalSettlementSave {
            gcs: gcs.clone(),
            object_name: format!("indexes/{}.db.enc", user.id),
            requests: StdMutex::new(Vec::new()),
        };
        assert!(
            deliver_user_pushes(&restarted, &terminal_archive_failure, &user.id)
                .await
                .is_err()
        );
        assert_eq!(terminal_archive_failure.requests.lock().unwrap().len(), 1);
        let after_terminal_archive_failure = state_over(
            Arc::new(crate::store::Store::new(kms.clone(), gcs.clone())),
            Arc::clone(&restarted.control),
        );
        let terminal_no_resend = ScriptedTransport::new([]);
        deliver_user_pushes(
            &after_terminal_archive_failure,
            &terminal_no_resend,
            &user.id,
        )
        .await
        .unwrap();
        assert!(terminal_no_resend.requests().is_empty());
        assert_eq!(
            delivery_evidence(&after_terminal_archive_failure, &user.id, terminal_id).await,
            ("failed".into(), 1, Some("invalid_device_token".into()))
        );
        assert!(
            !after_terminal_archive_failure
                .control
                .get_push_installation(&user.id, installation_id)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );

        // Control-side outcome-save failure still permits the archive's exact
        // token-terminal settlement. Reopening both stores adopts that
        // archive evidence, disables the same generation, and clears the
        // surviving Started fence without resending.
        let rotated = after_terminal_archive_failure
            .control
            .upsert_push_installation(installation(user.id.clone(), installation_id, 'e'))
            .await
            .unwrap();
        let rotated_binding =
            PushInstallationBinding::new(installation_id, rotated.token_generation)
                .unwrap()
                .encode();
        let control_failure_id = "22222222-2222-4222-8222-222222222254";
        insert_legacy_delivery(
            &after_terminal_archive_failure,
            &user.id,
            254,
            &rotated_binding,
            control_failure_id,
            &"x".repeat(43),
            "33333333-3333-4333-8333-333333333354",
            0,
            &crate::cp::isotime::format_epoch_millis(epoch_millis()),
        )
        .await;
        reset_test_pacer().await;
        let terminal_control_failure = FailControlTerminalOutcomeSave {
            gcs: gcs.clone(),
            requests: StdMutex::new(Vec::new()),
        };
        assert!(deliver_user_pushes(
            &after_terminal_archive_failure,
            &terminal_control_failure,
            &user.id,
        )
        .await
        .is_err());
        assert_eq!(terminal_control_failure.requests.lock().unwrap().len(), 1);
        let reopened_both = state_over(
            Arc::new(crate::store::Store::new(kms.clone(), gcs.clone())),
            Arc::new(crate::cp::control_store::ControlStore::new(
                kms.clone(),
                gcs.clone(),
            )),
        );
        let control_failure_no_resend = ScriptedTransport::new([]);
        deliver_user_pushes(&reopened_both, &control_failure_no_resend, &user.id)
            .await
            .unwrap();
        assert!(control_failure_no_resend.requests().is_empty());
        assert_eq!(
            delivery_evidence(&reopened_both, &user.id, control_failure_id).await,
            ("failed".into(), 1, Some("invalid_device_token".into()))
        );
        assert!(
            !reopened_both
                .control
                .get_push_installation(&user.id, installation_id)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );

        // At the response-lost boundary the remote generation already holds
        // accepted state. Store reconciles the exact put, and another restart
        // adopts that terminal without resending.
        let response_lost_id = "22222222-2222-4222-8222-222222222252";
        let response_lost_handoff = "u".repeat(43);
        let response_installation = reopened_both
            .control
            .upsert_push_installation(installation(user.id.clone(), installation_id, 'f'))
            .await
            .unwrap();
        let response_binding =
            PushInstallationBinding::new(installation_id, response_installation.token_generation)
                .unwrap()
                .encode();
        insert_legacy_delivery(
            &reopened_both,
            &user.id,
            252,
            &response_binding,
            response_lost_id,
            &response_lost_handoff,
            "33333333-3333-4333-8333-333333333352",
            0,
            &crate::cp::isotime::format_epoch_millis(epoch_millis()),
        )
        .await;
        reset_test_pacer().await;
        let response_lost = LoseSettlementResponse {
            gcs: gcs.clone(),
            object_name: format!("indexes/{}.db.enc", user.id),
            requests: StdMutex::new(Vec::new()),
        };
        deliver_user_pushes(&reopened_both, &response_lost, &user.id)
            .await
            .unwrap();
        assert_eq!(response_lost.requests.lock().unwrap().len(), 1);
        let restarted_again = state_over(
            Arc::new(crate::store::Store::new(kms, gcs)),
            Arc::clone(&reopened_both.control),
        );
        reset_test_pacer().await;
        let still_no_resend = ScriptedTransport::new([]);
        deliver_user_pushes(&restarted_again, &still_no_resend, &user.id)
            .await
            .unwrap();
        assert!(still_no_resend.requests().is_empty());
        assert_eq!(
            delivery_evidence(&restarted_again, &user.id, response_lost_id).await,
            ("accepted".into(), 1, None)
        );
        assert_eq!(
            resolved_memory_id(&restarted_again, &user.id, &response_lost_handoff).await,
            Some(252)
        );
    }

    #[tokio::test]
    async fn push_handoff_distinguishes_absence_from_unavailable_authority() {
        let _serial = push_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::{select_wal_authoritative, state};

        let unavailable = state();
        let selected = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaad";
        select_wal_authoritative(&unavailable.store, selected);
        let unavailable_response = resolve_notification_handoff(
            State(Arc::clone(&unavailable)),
            Extension(AuthUser(selected.into())),
            Path("sssssssssssssssssssssssssssssssssssssssssss".into()),
        )
        .await;
        assert_eq!(
            unavailable_response.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let absent = state();
        let legacy = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaae";
        absent.store.with_user(legacy, |_| Ok(())).await.unwrap();
        let absent_response = resolve_notification_handoff(
            State(absent),
            Extension(AuthUser(legacy.into())),
            Path("ttttttttttttttttttttttttttttttttttttttttttt".into()),
        )
        .await;
        assert_eq!(absent_response.status(), StatusCode::NOT_FOUND);
    }
}
