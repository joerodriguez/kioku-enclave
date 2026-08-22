//! Transactional email outbox worker and Resend transport implementation.
//!
//! Processes due `email_deliveries` outbox rows for active users, enforcing per-user
//! snapshot and current preferences, 24-hour stable idempotency keys, bounded retries,
//! and fail-closed secret hygiene.

pub(crate) mod wal;

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::warn;

use crate::cp::control_store::{
    EmailControlCancellation, EmailFenceOutcome, EmailProviderOutcome, EmailSendFence,
    EmailSendFenceDisposition,
};
use crate::cp::delivery;
use crate::cp::email_renderer;
use crate::cp::{isotime, CpState};
use crate::error::{EnclaveError, Result};

const MAX_DELIVERIES_PER_SWEEP: usize = 2;
const MAX_ATTEMPTS: i64 = 10;
const MAX_DELIVERY_AGE_SECONDS: i64 = 24 * 60 * 60;
const GLOBAL_SEND_PACE_MILLIS: u64 = 250;
const PROVIDER_CIRCUIT_SECONDS: u64 = 5 * 60;
pub(crate) const SELECTED_EMAIL_DELIVERY_PREFIX: &str = "e1_";

struct GlobalEmailPacer {
    next_send_at: tokio::time::Instant,
    circuit_until: Option<tokio::time::Instant>,
}

fn global_email_pacer() -> &'static Mutex<GlobalEmailPacer> {
    static PACER: OnceLock<Mutex<GlobalEmailPacer>> = OnceLock::new();
    PACER.get_or_init(|| {
        Mutex::new(GlobalEmailPacer {
            next_send_at: tokio::time::Instant::now(),
            circuit_until: None,
        })
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct EmailRequest {
    pub to: String,
    pub subject: String,
    pub text_body: String,
    pub html_body: String,
    pub idempotency_key: String,
}

impl std::fmt::Debug for EmailRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EmailRequest(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailTransportResponse {
    pub provider_message_id: String,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailTransportError {
    Ambiguous {
        code: String,
    },
    Retryable {
        status: Option<u16>,
        code: String,
        retry_after_seconds: Option<u64>,
    },
    DeliveryTerminal {
        status: Option<u16>,
        code: String,
    },
    ProviderTerminal {
        status: Option<u16>,
        code: String,
    },
}

impl std::fmt::Display for EmailTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ambiguous { code } => write!(f, "ambiguous error: {code}"),
            Self::Retryable { code, .. } => write!(f, "retryable error: {code}"),
            Self::DeliveryTerminal { code, .. } => write!(f, "delivery error: {code}"),
            Self::ProviderTerminal { code, .. } => write!(f, "provider error: {code}"),
        }
    }
}

impl std::error::Error for EmailTransportError {}

#[async_trait]
pub trait EmailTransport: Send + Sync {
    async fn send(
        &self,
        request: EmailRequest,
    ) -> std::result::Result<EmailTransportResponse, EmailTransportError>;
}

/// Production Resend API client (`https://api.resend.com/emails`).
pub struct ResendTransport {
    api_key: String,
    from_address: String,
    client: Client,
}

impl ResendTransport {
    pub fn new(api_key: String, from_address: String) -> Self {
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            api_key,
            from_address,
            client,
        }
    }

    pub fn build_request_payload(&self, request: &EmailRequest) -> serde_json::Value {
        json!({
            "from": self.from_address,
            "to": [request.to],
            "subject": request.subject,
            "text": request.text_body,
            "html": request.html_body,
        })
    }
}

#[derive(Deserialize)]
struct ResendSuccessResponseBody {
    id: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ResendErrorResponseBody {
    name: Option<String>,
    message: Option<String>,
}

#[async_trait]
impl EmailTransport for ResendTransport {
    async fn send(
        &self,
        request: EmailRequest,
    ) -> std::result::Result<EmailTransportResponse, EmailTransportError> {
        let payload = self.build_request_payload(&request);
        let resp = self
            .client
            .post("https://api.resend.com/emails")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Idempotency-Key", &request.idempotency_key)
            .header("Content-Type", "application/json")
            .header("User-Agent", "Kioku-Enclave-Email/1.0")
            .json(&payload)
            .send()
            .await;

        let response = match resp {
            Ok(r) => r,
            Err(_) => {
                return Err(EmailTransportError::Ambiguous {
                    code: "network_outcome_unknown".into(),
                });
            }
        };

        let status = response.status().as_u16();
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(|seconds| seconds.clamp(1, 6 * 60 * 60));

        if (200..300).contains(&status) {
            let body: std::result::Result<ResendSuccessResponseBody, _> = response.json().await;
            match body {
                Ok(ResendSuccessResponseBody { id: Some(id) })
                    if valid_provider_message_id(&id) =>
                {
                    Ok(EmailTransportResponse {
                        provider_message_id: id,
                        status,
                    })
                }
                _ => Err(EmailTransportError::Ambiguous {
                    code: "accepted_without_provider_message_id".into(),
                }),
            }
        } else {
            let err_body = response.json::<ResendErrorResponseBody>().await.ok();
            let err_name = err_body
                .as_ref()
                .and_then(|b| b.name.as_deref())
                .unwrap_or("");

            match status {
                409 => {
                    if err_name == "invalid_idempotent_request" {
                        Err(EmailTransportError::DeliveryTerminal {
                            status: Some(status),
                            code: "invalid_idempotent_request".into(),
                        })
                    } else {
                        Err(EmailTransportError::Retryable {
                            status: Some(status),
                            code: "concurrent_idempotent_request".into(),
                            retry_after_seconds,
                        })
                    }
                }
                401 | 403 => Err(EmailTransportError::ProviderTerminal {
                    status: Some(status),
                    code: format!("http_{status}"),
                }),
                400 | 422 => Err(EmailTransportError::DeliveryTerminal {
                    status: Some(status),
                    code: format!("http_{status}"),
                }),
                408 | 425 | 429 => Err(EmailTransportError::Retryable {
                    status: Some(status),
                    code: format!("http_{status}"),
                    retry_after_seconds,
                }),
                _ if (500..600).contains(&status) => Err(EmailTransportError::Retryable {
                    status: Some(status),
                    code: format!("http_{status}"),
                    retry_after_seconds,
                }),
                _ => Err(EmailTransportError::DeliveryTerminal {
                    status: Some(status),
                    code: format!("http_{status}"),
                }),
            }
        }
    }
}

/// Fake transport for unit and integration testing.
pub struct FakeEmailTransport {
    pub sent_requests: tokio::sync::Mutex<Vec<EmailRequest>>,
    pub force_error: tokio::sync::Mutex<Option<EmailTransportError>>,
}

#[allow(dead_code)]
impl FakeEmailTransport {
    pub fn new() -> Self {
        Self {
            sent_requests: tokio::sync::Mutex::new(Vec::new()),
            force_error: tokio::sync::Mutex::new(None),
        }
    }

    #[allow(dead_code)]
    pub async fn set_force_error(&self, err: Option<EmailTransportError>) {
        *self.force_error.lock().await = err;
    }

    pub async fn get_sent_requests(&self) -> Vec<EmailRequest> {
        self.sent_requests.lock().await.clone()
    }
}

#[async_trait]
impl EmailTransport for FakeEmailTransport {
    async fn send(
        &self,
        request: EmailRequest,
    ) -> std::result::Result<EmailTransportResponse, EmailTransportError> {
        let msg_id = format!("msg_fake_{}", request.idempotency_key);
        self.sent_requests.lock().await.push(request);
        if let Some(err) = self.force_error.lock().await.take() {
            return Err(err);
        }
        Ok(EmailTransportResponse {
            provider_message_id: msg_id,
            status: 202,
        })
    }
}

/// Process due email outbox rows for one user.
pub async fn deliver_user_emails(
    state: &CpState,
    transport: &dyn EmailTransport,
    user_id: &str,
) -> Result<()> {
    if state.store.is_wal_authoritative(user_id) {
        deliver_selected_user_emails(state, transport, user_id).await
    } else {
        deliver_legacy_user_emails(state, transport, user_id).await
    }
}

async fn deliver_selected_user_emails(
    state: &CpState,
    transport: &dyn EmailTransport,
    user_id: &str,
) -> Result<()> {
    reconcile_email_send_fences(state, user_id).await?;
    emit_email_depth(state, user_id).await;
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        // Production rollout is release-sealed to one runtime. This mutex is
        // therefore service-wide in production and keeps the provider pace,
        // claim, disclosure fence, send, and settlement in FIFO order.
        let mut pacer = global_email_pacer().lock().await;
        if pacer
            .circuit_until
            .is_some_and(|until| until > tokio::time::Instant::now())
        {
            emit_email_metric("circuit_open");
            break;
        }
        pacer.circuit_until = None;

        let Some(row) = state.store.next_email_delivery(user_id).await? else {
            break;
        };
        let snapshot = delivery_snapshot(row);
        if state.control.email_outbox_deletion_owned(user_id).await? {
            emit_email_metric("deletion_owned");
            break;
        }
        if let Some(open_claim) =
            load_open_email_claim(state, user_id, &snapshot.delivery_id).await?
        {
            if !recover_existing_email_claim(state, user_id, snapshot, open_claim).await? {
                break;
            }
            continue;
        }

        let now_ms = epoch_millis();
        let created_ms = isotime::parse_epoch_millis(&snapshot.created_at);
        let updated_ms = isotime::parse_epoch_millis(&snapshot.updated_at);
        let refusal = match snapshot.send_admission_refusal() {
            Ok(refusal) => refusal,
            Err(_) => {
                tracing::error!(
                    metric = "email_outbox_untargetable_row",
                    count = 1,
                    "email delivery has unbounded exact identity evidence"
                );
                break;
            }
        };
        let cancel = if refusal.is_some() {
            refusal
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
        if let Some(code) = cancel {
            settle_exact_email(
                state,
                user_id,
                snapshot,
                None,
                wal::EmailSettlementKind::Cancel { code: code.into() },
                None,
            )
            .await?;
            emit_email_metric(code);
            continue;
        }

        let frozen_request =
            match load_frozen_email_request(state, user_id, &snapshot.delivery_id).await? {
                Some(request) => request,
                None => {
                    let preference = state.control.get_email_preference(user_id).await?;
                    let effective_include_content =
                        snapshot.include_content && preference.include_content;
                    let loaded =
                        delivery::load_finalized_episode(state, user_id, snapshot.episode_id).await;
                    let episode = match loaded {
                        Ok(delivery::FinalizedEpisodeLoad::Present(episode)) => episode,
                        Ok(delivery::FinalizedEpisodeLoad::Missing) => {
                            settle_exact_email(
                                state,
                                user_id,
                                snapshot,
                                None,
                                wal::EmailSettlementKind::Cancel {
                                    code: "missing_final_brief".into(),
                                },
                                None,
                            )
                            .await?;
                            continue;
                        }
                        Ok(delivery::FinalizedEpisodeLoad::Malformed(_)) => {
                            settle_exact_email(
                                state,
                                user_id,
                                snapshot,
                                None,
                                wal::EmailSettlementKind::Cancel {
                                    code: "malformed_final_brief".into(),
                                },
                                None,
                            )
                            .await?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    let subject =
                        email_renderer::render_email_subject(&episode, effective_include_content);
                    let (text_body, html_body) = email_renderer::render_email_body(
                        &episode,
                        effective_include_content,
                        &state.config.web_origin,
                    );
                    let request = wal::EmailFrozenRequest::new(
                        preference.recipient_email,
                        subject,
                        text_body,
                        html_body,
                        snapshot.delivery_id.clone(),
                        effective_include_content,
                    );
                    let Ok(request) = request else {
                        settle_exact_email(
                            state,
                            user_id,
                            snapshot,
                            None,
                            wal::EmailSettlementKind::Cancel {
                                code: "rendered_request_invalid".into(),
                            },
                            None,
                        )
                        .await?;
                        continue;
                    };
                    request
                }
            };

        let now = tokio::time::Instant::now();
        if pacer.next_send_at > now {
            tokio::time::sleep_until(pacer.next_send_at).await;
        }
        let started_at = now_for_email_snapshot(&snapshot, None);
        let claim_plan = wal::EmailSendClaimPlan::new(
            user_id.to_owned(),
            super::tokens::new_uuid(),
            snapshot.clone(),
            frozen_request,
            started_at,
        )
        .map_err(|_| EnclaveError::Store("email send claim construction failed".into()))?;
        match submit_email_claim(state, user_id, claim_plan).await? {
            wal::EmailSendClaimDisposition::Busy => {
                emit_email_metric("busy");
                break;
            }
            wal::EmailSendClaimDisposition::DeferredLimit => {
                settle_exact_email(
                    state,
                    user_id,
                    snapshot,
                    None,
                    wal::EmailSettlementKind::Cancel {
                        code: "control_defer_cap".into(),
                    },
                    None,
                )
                .await?;
                continue;
            }
            wal::EmailSendClaimDisposition::RequestCapacity => {
                settle_exact_email(
                    state,
                    user_id,
                    snapshot,
                    None,
                    wal::EmailSettlementKind::Cancel {
                        code: "frozen_request_capacity".into(),
                    },
                    None,
                )
                .await?;
                emit_email_metric("frozen_request_capacity");
                continue;
            }
            wal::EmailSendClaimDisposition::Authorized => {}
        }
        let claim = load_open_email_claim(state, user_id, &snapshot.delivery_id)
            .await?
            .ok_or_else(|| EnclaveError::Store("email send claim disappeared".into()))?;
        let fence = match begin_or_reload_email_fence(state, user_id, &claim).await {
            Ok(Some(fence)) => fence,
            Ok(None) => break,
            Err(error) => {
                if let Ok(None) = state
                    .control
                    .get_email_send_fence(user_id, &snapshot.delivery_id)
                    .await
                {
                    let committed_at = now_for_email_snapshot(&snapshot, Some(&claim));
                    let retry_at = add_seconds(&committed_at, 60)?;
                    settle_exact_email(
                        state,
                        user_id,
                        snapshot,
                        Some(claim),
                        wal::EmailSettlementKind::Defer {
                            code: "control_recheck_unavailable".into(),
                            retry_at,
                        },
                        Some(committed_at),
                    )
                    .await?;
                }
                return Err(error);
            }
        };
        if let Some(outcome) = fence.outcome.clone() {
            replay_email_fence_receipt(state, user_id, snapshot, claim, fence, outcome).await?;
            continue;
        }

        let revalidate_at = epoch_millis();
        validate_archive_email_send_authority(state, user_id, &claim, revalidate_at).await?;
        let minimum_valid_at = revalidate_at
            .checked_add(wal::MIN_SEND_LEASE_MILLIS)
            .ok_or_else(|| EnclaveError::Store("email lease horizon overflow".into()))?;
        if !state
            .control
            .validate_email_send_fence(&fence, minimum_valid_at)
            .await?
        {
            return Err(EnclaveError::Conflict(
                "email disclosure fence is no longer live".into(),
            ));
        }
        pacer.next_send_at =
            tokio::time::Instant::now() + Duration::from_millis(GLOBAL_SEND_PACE_MILLIS);
        let request = EmailRequest {
            to: claim.request().to().into(),
            subject: claim.request().subject().into(),
            text_body: claim.request().text_body().into(),
            html_body: claim.request().html_body().into(),
            idempotency_key: claim.request().idempotency_key().into(),
        };
        let result = transport.send(request).await;
        let outcome_at = now_for_email_snapshot(&snapshot, Some(&claim));
        let outcome = match result {
            Ok(response) => EmailProviderOutcome::Accepted {
                status: i64::from(response.status),
                provider_message_id: response.provider_message_id,
            },
            Err(EmailTransportError::Ambiguous { .. }) => EmailProviderOutcome::Ambiguous,
            Err(EmailTransportError::DeliveryTerminal { status, code }) => {
                EmailProviderOutcome::Failed {
                    status: status.map(i64::from),
                    code,
                }
            }
            Err(EmailTransportError::Retryable {
                status,
                code,
                retry_after_seconds,
            }) => {
                if status.is_some_and(|status| status == 429 || status >= 500) {
                    open_email_circuit(
                        &mut pacer,
                        retry_after_seconds.unwrap_or(PROVIDER_CIRCUIT_SECONDS),
                    );
                }
                if claim.send_attempt() >= MAX_ATTEMPTS {
                    EmailProviderOutcome::Failed {
                        status: status.map(i64::from),
                        code: "attempt_cap".into(),
                    }
                } else {
                    let delay = retry_after_seconds
                        .and_then(|seconds| i64::try_from(seconds).ok())
                        .unwrap_or_else(|| retry_delay(claim.send_attempt()));
                    EmailProviderOutcome::Retry {
                        status: status.map(i64::from),
                        code,
                        retry_at: add_seconds(&outcome_at, delay)?,
                    }
                }
            }
            Err(EmailTransportError::ProviderTerminal { status, code }) => {
                open_email_circuit(&mut pacer, PROVIDER_CIRCUIT_SECONDS);
                if claim.send_attempt() >= MAX_ATTEMPTS {
                    EmailProviderOutcome::Failed {
                        status: status.map(i64::from),
                        code,
                    }
                } else {
                    EmailProviderOutcome::Retry {
                        status: status.map(i64::from),
                        code,
                        retry_at: add_seconds(&outcome_at, 60 * 60)?,
                    }
                }
            }
        };
        persist_email_provider_outcome(state, user_id, snapshot, claim, fence, outcome, outcome_at)
            .await?;
        emit_email_metric("settled");
    }
    Ok(())
}

async fn deliver_legacy_user_emails(
    state: &CpState,
    transport: &dyn EmailTransport,
    user_id: &str,
) -> Result<()> {
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        let pref = match state.control.get_email_preference(user_id).await {
            Ok(p) => p,
            Err(EnclaveError::Auth(_)) => {
                // User unknown, inactive, or deleting — cancel all pending/retry email outbox rows
                cancel_user_email_deliveries(state, user_id, "user_inactive").await?;
                break;
            }
            Err(error) => return Err(error),
        };

        if !pref.enabled {
            cancel_user_email_deliveries(state, user_id, "preference_disabled").await?;
            break;
        }

        let Some(outbox) = state.store.next_email_delivery(user_id).await? else {
            break;
        };
        if outbox.attempt_count < 0 || outbox.attempt_count >= MAX_ATTEMPTS {
            settle_email_delivery(
                state,
                user_id,
                &outbox.delivery_id,
                outbox.episode_id,
                outbox.delivery_version,
                "failed",
                outbox.attempt_count,
                None,
                None,
                Some("attempt_count_invalid"),
                None,
            )
            .await?;
            continue;
        }
        let attempts = outbox
            .attempt_count
            .checked_add(1)
            .ok_or_else(|| EnclaveError::Store("legacy email attempt overflow".into()))?;

        // Effective include_content = snapshot && current_preference
        let effective_include_content = outbox.include_content && pref.include_content;

        let loaded = delivery::load_finalized_episode(state, user_id, outbox.episode_id).await;
        let episode = match loaded {
            Ok(delivery::FinalizedEpisodeLoad::Present(episode)) => episode,
            Ok(delivery::FinalizedEpisodeLoad::Missing) => {
                state
                    .store
                    .update_email_delivery_state(
                        user_id,
                        outbox.episode_id,
                        outbox.delivery_version,
                        "failed",
                        attempts,
                        None,
                        None,
                        Some("missing_final_brief"),
                        None,
                    )
                    .await?;
                continue;
            }
            Ok(delivery::FinalizedEpisodeLoad::Malformed(_)) => {
                state
                    .store
                    .update_email_delivery_state(
                        user_id,
                        outbox.episode_id,
                        outbox.delivery_version,
                        "failed",
                        attempts,
                        None,
                        None,
                        Some("malformed_final_brief"),
                        None,
                    )
                    .await?;
                continue;
            }
            Err(error) => return Err(error),
        };

        let subject = email_renderer::render_email_subject(&episode, effective_include_content);
        let (text_body, html_body) = email_renderer::render_email_body(
            &episode,
            effective_include_content,
            &state.config.web_origin,
        );

        let email_req = EmailRequest {
            to: pref.recipient_email.clone(),
            subject,
            text_body,
            html_body,
            idempotency_key: outbox.delivery_id.clone(),
        };

        tracing::info!(
            metric = "email_outbox_provider_attempt",
            include_content = effective_include_content,
            count = 1,
            "delivering transactional episode email"
        );

        match transport.send(email_req).await {
            Ok(resp) => {
                settle_email_delivery(
                    state,
                    user_id,
                    &outbox.delivery_id,
                    outbox.episode_id,
                    outbox.delivery_version,
                    "accepted",
                    attempts,
                    Some(&resp.provider_message_id),
                    Some(resp.status),
                    None,
                    None,
                )
                .await?;
            }
            Err(EmailTransportError::DeliveryTerminal { status, code })
            | Err(EmailTransportError::ProviderTerminal { status, code }) => {
                warn!(
                    metric = "email_outbox_legacy_terminal",
                    count = 1,
                    "email transport returned terminal failure"
                );
                settle_email_delivery(
                    state,
                    user_id,
                    &outbox.delivery_id,
                    outbox.episode_id,
                    outbox.delivery_version,
                    "failed",
                    attempts,
                    None,
                    status,
                    Some(&code),
                    None,
                )
                .await?;
            }
            Err(EmailTransportError::Ambiguous { code }) => {
                settle_email_delivery(
                    state,
                    user_id,
                    &outbox.delivery_id,
                    outbox.episode_id,
                    outbox.delivery_version,
                    "failed",
                    attempts,
                    None,
                    None,
                    Some(&code),
                    None,
                )
                .await?;
            }
            Err(EmailTransportError::Retryable {
                status,
                code,
                retry_after_seconds,
            }) => {
                warn!(
                    metric = "email_outbox_legacy_retry",
                    attempt = attempts,
                    count = 1,
                    "email transport returned transient failure"
                );
                if attempts >= MAX_ATTEMPTS {
                    settle_email_delivery(
                        state,
                        user_id,
                        &outbox.delivery_id,
                        outbox.episode_id,
                        outbox.delivery_version,
                        "failed",
                        attempts,
                        None,
                        None,
                        Some("max_attempts_exceeded"),
                        None,
                    )
                    .await?;
                } else {
                    let backoff_secs = retry_after_seconds
                        .and_then(|seconds| i64::try_from(seconds).ok())
                        .unwrap_or_else(|| retry_delay(attempts));
                    let next_attempt_at =
                        add_seconds(&isotime::format_epoch_millis(epoch_millis()), backoff_secs)?;
                    settle_email_delivery(
                        state,
                        user_id,
                        &outbox.delivery_id,
                        outbox.episode_id,
                        outbox.delivery_version,
                        "retry",
                        attempts,
                        None,
                        status,
                        Some(&code),
                        Some(&next_attempt_at),
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}

fn delivery_snapshot(row: crate::store::EmailDeliveryRow) -> wal::EmailDeliverySnapshot {
    wal::EmailDeliverySnapshot {
        rowid: row.rowid,
        episode_id: row.episode_id,
        delivery_version: row.delivery_version,
        delivery_id: row.delivery_id,
        include_content: row.include_content,
        state: row.state,
        attempt_count: row.attempt_count,
        next_attempt_at: row.next_attempt_at,
        provider_message_id: row.provider_message_id,
        response_status: row.response_status,
        error_code: row.error_code,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

async fn submit_email_claim(
    state: &CpState,
    user_id: &str,
    plan: wal::EmailSendClaimPlan,
) -> Result<wal::EmailSendClaimDisposition> {
    let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
        .map_err(|_| EnclaveError::Store("email send claim preparation failed".into()))?;
    state
        .store
        .wal_authoritative_submit(user_id, prepared)
        .await
}

async fn load_open_email_claim(
    state: &CpState,
    user_id: &str,
    delivery_id: &str,
) -> Result<Option<wal::EmailSendClaim>> {
    let delivery_id = delivery_id.to_owned();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_open_claim(connection, &delivery_id)
                .map_err(|_| EnclaveError::Store("email send claim read failed".into()))
        })
        .await
}

async fn load_frozen_email_request(
    state: &CpState,
    user_id: &str,
    delivery_id: &str,
) -> Result<Option<wal::EmailFrozenRequest>> {
    let delivery_id = delivery_id.to_owned();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_frozen_request(connection, &delivery_id)
                .map_err(|_| EnclaveError::Store("email frozen request read failed".into()))
        })
        .await
}

async fn load_email_claim_recovery(
    state: &CpState,
    user_id: &str,
    claim_id: &str,
) -> Result<Option<wal::EmailClaimRecovery>> {
    let claim_id = claim_id.to_owned();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_claim_recovery(connection, &claim_id)
                .map_err(|_| EnclaveError::Store("email claim recovery read failed".into()))
        })
        .await
}

async fn validate_archive_email_send_authority(
    state: &CpState,
    user_id: &str,
    claim: &wal::EmailSendClaim,
    now_millis: i64,
) -> Result<()> {
    let claim = claim.clone();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::validate_live_send_authority(connection, &claim, now_millis)
                .map_err(|_| EnclaveError::Conflict("email send lease is no longer live".into()))
        })
        .await
}

fn fence_for_email_claim(
    user_id: &str,
    claim: &wal::EmailSendClaim,
    outcome: Option<EmailFenceOutcome>,
    outcome_at: Option<String>,
) -> EmailSendFence {
    EmailSendFence {
        user_id: user_id.to_owned(),
        delivery_id: claim.predecessor().delivery_id.clone(),
        claim_id: claim.claim_id().to_owned(),
        lease_expires_at: claim.lease_expires_at().to_owned(),
        recipient_email: claim.request().to().to_owned(),
        include_content: claim.request().include_content(),
        outcome,
        outcome_at,
    }
}

fn exact_email_fence_for_claim(
    fence: &EmailSendFence,
    user_id: &str,
    claim: &wal::EmailSendClaim,
) -> bool {
    fence.user_id == user_id
        && fence.delivery_id == claim.predecessor().delivery_id
        && fence.claim_id == claim.claim_id()
        && fence.lease_expires_at == claim.lease_expires_at()
        && fence.recipient_email == claim.request().to()
        && fence.include_content == claim.request().include_content()
}

async fn begin_or_reload_email_fence(
    state: &CpState,
    user_id: &str,
    claim: &wal::EmailSendClaim,
) -> Result<Option<EmailSendFence>> {
    let requested = fence_for_email_claim(user_id, claim, None, None);
    match state
        .control
        .begin_email_send_fence(
            &requested,
            &now_for_email_snapshot(claim.predecessor(), Some(claim)),
        )
        .await?
    {
        EmailSendFenceDisposition::DeletionOwned => Ok(None),
        EmailSendFenceDisposition::Recorded(fence) => Ok(Some(fence)),
        EmailSendFenceDisposition::Authorized(preference) => {
            if !preference.enabled
                || preference.recipient_email != claim.request().to()
                || (claim.request().include_content() && !preference.include_content)
            {
                return Err(EnclaveError::Conflict(
                    "email disclosure authority changed".into(),
                ));
            }
            Ok(Some(fence_for_email_claim(user_id, claim, None, None)))
        }
    }
}

async fn settle_exact_email(
    state: &CpState,
    user_id: &str,
    predecessor: wal::EmailDeliverySnapshot,
    claim: Option<wal::EmailSendClaim>,
    kind: wal::EmailSettlementKind,
    committed_at: Option<String>,
) -> Result<()> {
    let committed_at =
        committed_at.unwrap_or_else(|| now_for_email_snapshot(&predecessor, claim.as_ref()));
    let plan = wal::ExactEmailDeliverySettlementPlan::new(
        user_id.to_owned(),
        predecessor,
        claim,
        kind,
        committed_at,
    )
    .map_err(|_| EnclaveError::Store("exact email settlement construction failed".into()))?;
    let prepared = crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
        .map_err(|_| EnclaveError::Store("exact email settlement preparation failed".into()))?;
    state
        .store
        .wal_authoritative_submit(user_id, prepared)
        .await
}

fn email_settlement_kind(outcome: &EmailProviderOutcome) -> wal::EmailSettlementKind {
    match outcome {
        EmailProviderOutcome::Accepted {
            status,
            provider_message_id,
        } => wal::EmailSettlementKind::Accepted {
            status: *status,
            provider_message_id: provider_message_id.clone(),
        },
        EmailProviderOutcome::Retry {
            status,
            code,
            retry_at,
        } => wal::EmailSettlementKind::Retry {
            status: *status,
            code: code.clone(),
            retry_at: retry_at.clone(),
        },
        EmailProviderOutcome::Ambiguous => wal::EmailSettlementKind::Ambiguous,
        EmailProviderOutcome::Failed { status, code } => wal::EmailSettlementKind::Failed {
            status: *status,
            code: code.clone(),
        },
    }
}

fn cancellation_code(cancellation: &EmailControlCancellation) -> &'static str {
    match cancellation {
        EmailControlCancellation::AccountInactive => "account_inactive",
        EmailControlCancellation::PreferenceDisabled => "preference_disabled",
        EmailControlCancellation::RecipientChanged => "recipient_changed",
        EmailControlCancellation::ContentConsentChanged => "content_consent_changed",
    }
}

async fn replay_email_fence_receipt(
    state: &CpState,
    user_id: &str,
    predecessor: wal::EmailDeliverySnapshot,
    claim: wal::EmailSendClaim,
    fence: EmailSendFence,
    outcome: EmailFenceOutcome,
) -> Result<()> {
    if !exact_email_fence_for_claim(&fence, user_id, &claim) {
        return Err(EnclaveError::Conflict(
            "email fence does not match archive claim".into(),
        ));
    }
    let committed_at = fence
        .outcome_at
        .clone()
        .ok_or_else(|| EnclaveError::Store("email fence outcome lacks timestamp".into()))?;
    match &outcome {
        EmailFenceOutcome::Provider(provider) => {
            settle_exact_email(
                state,
                user_id,
                predecessor,
                Some(claim),
                email_settlement_kind(provider),
                Some(committed_at),
            )
            .await?;
        }
        EmailFenceOutcome::Cancellation(cancellation) => {
            settle_exact_email(
                state,
                user_id,
                predecessor,
                Some(claim),
                wal::EmailSettlementKind::Cancel {
                    code: cancellation_code(cancellation).into(),
                },
                Some(committed_at),
            )
            .await?;
        }
    }
    state.control.finish_email_send_fence(&fence, outcome).await
}

async fn persist_email_provider_outcome(
    state: &CpState,
    user_id: &str,
    predecessor: wal::EmailDeliverySnapshot,
    claim: wal::EmailSendClaim,
    fence: EmailSendFence,
    outcome: EmailProviderOutcome,
    outcome_at: String,
) -> Result<()> {
    let control_result = state
        .control
        .record_email_send_outcome(&fence, outcome.clone(), &outcome_at)
        .await;
    let archive_result = settle_exact_email(
        state,
        user_id,
        predecessor,
        Some(claim.clone()),
        email_settlement_kind(&outcome),
        Some(outcome_at.clone()),
    )
    .await;
    archive_result?;
    control_result?;
    let completed = fence_for_email_claim(
        user_id,
        &claim,
        Some(EmailFenceOutcome::Provider(outcome.clone())),
        Some(outcome_at),
    );
    state
        .control
        .finish_email_send_fence(&completed, EmailFenceOutcome::Provider(outcome))
        .await
}

async fn recover_existing_email_claim(
    state: &CpState,
    user_id: &str,
    predecessor: wal::EmailDeliverySnapshot,
    claim: wal::EmailSendClaim,
) -> Result<bool> {
    let fence = state
        .control
        .get_email_send_fence(user_id, &predecessor.delivery_id)
        .await?;
    if let Some(fence) = fence {
        if !exact_email_fence_for_claim(&fence, user_id, &claim) {
            return Err(EnclaveError::Conflict(
                "email claim found a different disclosure fence".into(),
            ));
        }
        if let Some(outcome) = fence.outcome.clone() {
            replay_email_fence_receipt(state, user_id, predecessor, claim, fence, outcome).await?;
            return Ok(true);
        }
        if claim
            .is_live_at(epoch_millis())
            .map_err(|_| EnclaveError::Store("email claim lease is invalid".into()))?
        {
            return Ok(false);
        }
        let outcome_at = now_for_email_snapshot(&predecessor, Some(&claim));
        persist_email_provider_outcome(
            state,
            user_id,
            predecessor,
            claim,
            fence,
            EmailProviderOutcome::Ambiguous,
            outcome_at,
        )
        .await?;
        return Ok(true);
    }
    if claim
        .is_live_at(epoch_millis())
        .map_err(|_| EnclaveError::Store("email claim lease is invalid".into()))?
    {
        return Ok(false);
    }
    let committed_at = now_for_email_snapshot(&predecessor, Some(&claim));
    let retry_at = add_seconds(&committed_at, 30)?;
    settle_exact_email(
        state,
        user_id,
        predecessor,
        Some(claim),
        wal::EmailSettlementKind::Defer {
            code: "provider_not_authorized".into(),
            retry_at,
        },
        Some(committed_at),
    )
    .await?;
    Ok(true)
}

async fn reconcile_email_send_fences(state: &CpState, user_id: &str) -> Result<()> {
    for fence in state.control.list_email_send_fences(user_id).await? {
        let Some(recovery) = load_email_claim_recovery(state, user_id, &fence.claim_id).await?
        else {
            if state.control.email_outbox_deletion_owned(user_id).await? {
                return Ok(());
            }
            return Err(EnclaveError::Store(
                "email disclosure fence lacks archive evidence".into(),
            ));
        };
        match recovery {
            wal::EmailClaimRecovery::Started(claim) => {
                if let Some(outcome) = fence.outcome.clone() {
                    let predecessor = claim.predecessor().clone();
                    replay_email_fence_receipt(state, user_id, predecessor, claim, fence, outcome)
                        .await?;
                } else if !claim
                    .is_live_at(epoch_millis())
                    .map_err(|_| EnclaveError::Store("email claim lease is invalid".into()))?
                {
                    let predecessor = claim.predecessor().clone();
                    let outcome_at = now_for_email_snapshot(&predecessor, Some(&claim));
                    persist_email_provider_outcome(
                        state,
                        user_id,
                        predecessor,
                        claim,
                        fence,
                        EmailProviderOutcome::Ambiguous,
                        outcome_at,
                    )
                    .await?;
                }
            }
            recovery => {
                if let Some(provider) = recovery_provider_outcome(&recovery) {
                    let settled_at = recovery_settled_at(&recovery)
                        .ok_or_else(|| EnclaveError::Store("email outcome lacks time".into()))?;
                    let claim = recovery_claim(&recovery)
                        .ok_or_else(|| EnclaveError::Store("email outcome lacks claim".into()))?;
                    if fence.outcome.is_none() {
                        state
                            .control
                            .record_email_send_outcome(&fence, provider.clone(), settled_at)
                            .await?;
                    }
                    let completed = fence_for_email_claim(
                        user_id,
                        claim,
                        Some(EmailFenceOutcome::Provider(provider.clone())),
                        Some(settled_at.into()),
                    );
                    state
                        .control
                        .finish_email_send_fence(&completed, EmailFenceOutcome::Provider(provider))
                        .await?;
                } else if let wal::EmailClaimRecovery::Cancelled {
                    claim,
                    code,
                    settled_at,
                } = recovery
                {
                    let cancellation = cancellation_from_code(&code).ok_or_else(|| {
                        EnclaveError::Store("email cancellation receipt is invalid".into())
                    })?;
                    let completed = fence_for_email_claim(
                        user_id,
                        &claim,
                        Some(EmailFenceOutcome::Cancellation(cancellation.clone())),
                        Some(settled_at),
                    );
                    state
                        .control
                        .finish_email_send_fence(
                            &completed,
                            EmailFenceOutcome::Cancellation(cancellation),
                        )
                        .await?;
                }
            }
        }
    }
    Ok(())
}

fn recovery_provider_outcome(recovery: &wal::EmailClaimRecovery) -> Option<EmailProviderOutcome> {
    match recovery {
        wal::EmailClaimRecovery::Accepted {
            status,
            provider_message_id,
            ..
        } => Some(EmailProviderOutcome::Accepted {
            status: *status,
            provider_message_id: provider_message_id.clone(),
        }),
        wal::EmailClaimRecovery::Retry {
            status,
            code,
            retry_at,
            ..
        } => Some(EmailProviderOutcome::Retry {
            status: *status,
            code: code.clone(),
            retry_at: retry_at.clone(),
        }),
        wal::EmailClaimRecovery::Ambiguous { .. } => Some(EmailProviderOutcome::Ambiguous),
        wal::EmailClaimRecovery::Failed { status, code, .. } => {
            Some(EmailProviderOutcome::Failed {
                status: *status,
                code: code.clone(),
            })
        }
        wal::EmailClaimRecovery::Started(_)
        | wal::EmailClaimRecovery::Deferred
        | wal::EmailClaimRecovery::Cancelled { .. } => None,
    }
}

fn recovery_claim(recovery: &wal::EmailClaimRecovery) -> Option<&wal::EmailSendClaim> {
    match recovery {
        wal::EmailClaimRecovery::Started(claim)
        | wal::EmailClaimRecovery::Accepted { claim, .. }
        | wal::EmailClaimRecovery::Retry { claim, .. }
        | wal::EmailClaimRecovery::Ambiguous { claim, .. }
        | wal::EmailClaimRecovery::Failed { claim, .. }
        | wal::EmailClaimRecovery::Cancelled { claim, .. } => Some(claim),
        wal::EmailClaimRecovery::Deferred => None,
    }
}

fn recovery_settled_at(recovery: &wal::EmailClaimRecovery) -> Option<&str> {
    match recovery {
        wal::EmailClaimRecovery::Accepted { settled_at, .. }
        | wal::EmailClaimRecovery::Retry { settled_at, .. }
        | wal::EmailClaimRecovery::Ambiguous { settled_at, .. }
        | wal::EmailClaimRecovery::Failed { settled_at, .. }
        | wal::EmailClaimRecovery::Cancelled { settled_at, .. } => Some(settled_at),
        wal::EmailClaimRecovery::Started(_) | wal::EmailClaimRecovery::Deferred => None,
    }
}

fn cancellation_from_code(code: &str) -> Option<EmailControlCancellation> {
    match code {
        "account_inactive" => Some(EmailControlCancellation::AccountInactive),
        "preference_disabled" => Some(EmailControlCancellation::PreferenceDisabled),
        "recipient_changed" => Some(EmailControlCancellation::RecipientChanged),
        "content_consent_changed" => Some(EmailControlCancellation::ContentConsentChanged),
        _ => None,
    }
}

fn open_email_circuit(pacer: &mut GlobalEmailPacer, seconds: u64) {
    pacer.circuit_until =
        Some(tokio::time::Instant::now() + Duration::from_secs(seconds.clamp(1, 6 * 60 * 60)));
}

fn retry_delay(attempt: i64) -> i64 {
    let exponent = u32::try_from(attempt.saturating_sub(1).clamp(0, 8)).unwrap_or(0);
    (30_i64 * 2_i64.pow(exponent)).min(6 * 60 * 60)
}

fn add_seconds(timestamp: &str, seconds: i64) -> Result<String> {
    let millis = isotime::parse_epoch_millis(timestamp)
        .and_then(|value| value.checked_add(seconds.checked_mul(1_000)?))
        .ok_or_else(|| EnclaveError::Store("email retry timestamp overflow".into()))?;
    Ok(isotime::format_epoch_millis(millis))
}

fn epoch_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn now_for_email_snapshot(
    snapshot: &wal::EmailDeliverySnapshot,
    claim: Option<&wal::EmailSendClaim>,
) -> String {
    let floor = isotime::parse_epoch_millis(&snapshot.updated_at)
        .into_iter()
        .chain(claim.and_then(|claim| isotime::parse_epoch_millis(claim.started_at())))
        .max()
        .unwrap_or_default();
    isotime::format_epoch_millis(epoch_millis().max(floor))
}

async fn emit_email_depth(state: &CpState, user_id: &str) {
    let result = state
        .store
        .wal_authoritative_read(user_id, |connection| {
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM email_deliveries WHERE state IN ('pending','retry')",
                [],
                |row| row.get(0),
            )?;
            let oldest: Option<String> = connection.query_row(
                "SELECT MIN(created_at) FROM email_deliveries WHERE state IN ('pending','retry')",
                [],
                |row| row.get(0),
            )?;
            Ok((count, oldest))
        })
        .await;
    if let Ok((count, oldest)) = result {
        let age_seconds = oldest
            .as_deref()
            .and_then(isotime::parse_epoch_millis)
            .map(|created| epoch_millis().saturating_sub(created) / 1_000)
            .unwrap_or_default();
        tracing::info!(
            metric = "email_outbox_depth",
            count,
            oldest_age_seconds = age_seconds.max(0),
            "email outbox depth observed"
        );
    }
}

fn emit_email_metric(outcome: &'static str) {
    tracing::info!(
        metric = "email_outbox_outcome",
        outcome,
        count = 1,
        "email outbox outcome"
    );
}

fn valid_provider_message_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

/// Preserve the pre-ADR legacy sequence for unselected accounts only.
#[allow(clippy::too_many_arguments)]
async fn settle_email_delivery(
    state: &CpState,
    user_id: &str,
    _delivery_id: &str,
    episode_id: i64,
    delivery_version: i64,
    new_state: &str,
    attempts: i64,
    provider_message_id: Option<&str>,
    response_status: Option<u16>,
    error_code: Option<&str>,
    next_attempt_at: Option<&str>,
) -> Result<()> {
    if state.store.is_wal_authoritative(user_id) {
        return Err(EnclaveError::Conflict(
            "selected email delivery must use the exact owner".into(),
        ));
    }
    state
        .store
        .update_email_delivery_state(
            user_id,
            episode_id,
            delivery_version,
            new_state,
            attempts,
            provider_message_id,
            response_status,
            error_code,
            next_attempt_at,
        )
        .await
}

async fn cancel_user_email_deliveries(state: &CpState, user_id: &str, reason: &str) -> Result<()> {
    if state.store.is_wal_authoritative(user_id) {
        return Err(EnclaveError::Conflict(
            "selected email cancellation must use exact row settlement".into(),
        ));
    }
    state
        .store
        .cancel_pending_email_deliveries(user_id, reason)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn email_test_serial() -> &'static tokio::sync::Mutex<()> {
        static SERIAL: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    async fn reset_test_pacer() {
        let mut pacer = global_email_pacer().lock().await;
        pacer.next_send_at = tokio::time::Instant::now();
        pacer.circuit_until = None;
    }

    #[test]
    fn resend_transport_builds_correct_json_payload() {
        let transport = ResendTransport::new(
            "re_123456789".into(),
            "Kioku <notifications@notify.kiokuu.com>".into(),
        );

        let req = EmailRequest {
            to: "user@example.com".into(),
            subject: "Your Kioku brief is ready".into(),
            text_body: "Brief text".into(),
            html_body: "<p>Brief html</p>".into(),
            idempotency_key: "deliv_123".into(),
        };

        let payload = transport.build_request_payload(&req);
        assert_eq!(payload["from"], "Kioku <notifications@notify.kiokuu.com>");
        assert_eq!(payload["to"][0], "user@example.com");
        assert_eq!(payload["subject"], "Your Kioku brief is ready");
        assert_eq!(payload["text"], "Brief text");
        assert_eq!(payload["html"], "<p>Brief html</p>");
    }

    #[tokio::test]
    async fn fake_transport_records_requests() {
        let fake = FakeEmailTransport::new();
        let req = EmailRequest {
            to: "user@example.com".into(),
            subject: "Test".into(),
            text_body: "Text".into(),
            html_body: "Html".into(),
            idempotency_key: "key_1".into(),
        };

        let res = fake.send(req.clone()).await.unwrap();
        assert_eq!(res.provider_message_id, "msg_fake_key_1");

        let sent = fake.get_sent_requests().await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], req);
    }

    fn test_cp_config() -> Arc<crate::cp::CpConfig> {
        Arc::new(crate::cp::CpConfig {
            base_url: "http://localhost:8080".into(),
            jwt_secrets: vec!["test-secret".into()],
            google_desktop_client_id: "desktop".into(),
            google_web_client_id: "web".into(),
            google_ios_client_id: "ios".into(),
            google_web_client_secret: "secret".into(),
            apple_sign_in: None,
            admin_user_ids: Vec::new(),
            signup_limit_per_day: crate::cp::control_store::TEST_SIGNUP_LIMIT,
            scheduler_sa_email: None,
            vertex_project: "project".into(),
            vertex_location: "location".into(),
            vertex_model: "model".into(),
            quota_utterances_per_day: 1,
            quota_screenshots_per_day: 1,
            quota_mcp_calls_per_day: 1,
            quota_vertex_output_tokens_per_day: 524_288,
            web_origin: "http://localhost:3000".into(),
            reviewer_auth: None,
            billing_enforcement_mode: crate::cp::BillingEnforcementMode::Enforce,
        })
    }

    #[tokio::test]
    async fn deliver_user_emails_pending_to_accepted() {
        let _serial = email_test_serial().lock().await;
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let control = Arc::new(crate::cp::control_store::ControlStore::new(kms, gcs));

        let user = control
            .upsert_user(
                "google-sub-worker-test",
                "user@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        control
            .set_email_preference(&user.id, true, false)
            .await
            .unwrap();

        // Seed episode & brief
        store.with_user(&user.id, |conn| {
            conn.execute_batch(
                "INSERT INTO episodes (id, started_at, ended_at, finalized_at, title, summary, substance, finalization_status)
                 VALUES (1, '2026-07-30T10:00:00Z', '2026-07-30T10:30:00Z', '2026-07-30T10:30:00Z', 'Test Title', 'Test Summary', 'normal', 'complete');
                 INSERT INTO episode_final_briefs (episode_id, overview, decisions, action_items, important_links, open_questions)
                 VALUES (1, 'Overview text', '[]', '[]', '[]', '[]');"
            )?;
            Ok(())
        }).await.unwrap();

        let delivery_id = store
            .enqueue_email_delivery(&user.id, 1, 1, false)
            .await
            .unwrap();

        let state = Arc::new(CpState {
            store: store.clone(),
            control: control.clone(),
            billing: Arc::new(crate::cp::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(crate::cp::billing::RecordingLeaseGates::default()),
            config: test_cp_config(),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
            push_transport: None,
            embedding: None,
            voice: None,
        });

        let fake_transport = FakeEmailTransport::new();
        deliver_user_emails(&state, &fake_transport, &user.id)
            .await
            .unwrap();

        let sent = fake_transport.get_sent_requests().await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "user@example.com");
        assert_eq!(sent[0].subject, "Your Kioku brief is ready");
        assert_eq!(sent[0].idempotency_key, delivery_id);

        let due = store.next_email_delivery(&user.id).await.unwrap();
        assert!(due.is_none());
    }

    #[tokio::test]
    async fn deliver_user_emails_downgrades_on_opt_out() {
        let _serial = email_test_serial().lock().await;
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let control = Arc::new(crate::cp::control_store::ControlStore::new(kms, gcs));

        let user = control
            .upsert_user(
                "google-sub-optout-test",
                "optout@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        // Enable full content initially
        control
            .set_email_preference(&user.id, true, true)
            .await
            .unwrap();

        store.with_user(&user.id, |conn| {
            conn.execute_batch(
                "INSERT INTO episodes (id, started_at, ended_at, finalized_at, title, summary, substance, finalization_status)
                 VALUES (2, '2026-07-30T10:00:00Z', '2026-07-30T10:30:00Z', '2026-07-30T10:30:00Z', 'Secret Title', 'Test Summary', 'normal', 'complete');
                 INSERT INTO episode_final_briefs (episode_id, overview, decisions, action_items, important_links, open_questions)
                 VALUES (2, 'Secret Overview', '[]', '[]', '[]', '[]');"
            )?;
            Ok(())
        }).await.unwrap();

        // Enqueue with snapshot include_content = true
        store
            .enqueue_email_delivery(&user.id, 2, 1, true)
            .await
            .unwrap();

        // Later user opts out of full content (include_content = false)
        control
            .set_email_preference(&user.id, true, false)
            .await
            .unwrap();

        let state = Arc::new(CpState {
            store: store.clone(),
            control: control.clone(),
            billing: Arc::new(crate::cp::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(crate::cp::billing::RecordingLeaseGates::default()),
            config: test_cp_config(),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
            push_transport: None,
            embedding: None,
            voice: None,
        });

        let fake_transport = FakeEmailTransport::new();
        deliver_user_emails(&state, &fake_transport, &user.id)
            .await
            .unwrap();

        let sent = fake_transport.get_sent_requests().await;
        assert_eq!(sent.len(), 1);
        // Subject MUST be downgraded to notification-only!
        assert_eq!(sent[0].subject, "Your Kioku brief is ready");
        assert!(!sent[0].text_body.contains("Secret Title"));
    }

    #[tokio::test]
    async fn deliver_user_emails_cancels_when_disabled() {
        let _serial = email_test_serial().lock().await;
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let control = Arc::new(crate::cp::control_store::ControlStore::new(kms, gcs));

        let user = control
            .upsert_user(
                "google-sub-disabled-test",
                "off@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        // User opts out completely
        control
            .set_email_preference(&user.id, false, false)
            .await
            .unwrap();

        store.with_user(&user.id, |conn| {
            conn.execute_batch(
                "INSERT INTO episodes (id, started_at, ended_at, finalized_at, title, summary, substance, finalization_status)
                 VALUES (1, '2026-07-30T10:00:00Z', '2026-07-30T10:30:00Z', '2026-07-30T10:30:00Z', 'Test Title', 'Test Summary', 'normal', 'complete');"
            )?;
            Ok(())
        }).await.unwrap();

        store
            .enqueue_email_delivery(&user.id, 1, 1, true)
            .await
            .unwrap();

        let state = Arc::new(CpState {
            store: store.clone(),
            control: control.clone(),
            billing: Arc::new(crate::cp::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(crate::cp::billing::RecordingLeaseGates::default()),
            config: test_cp_config(),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
            push_transport: None,
            embedding: None,
            voice: None,
        });

        let fake_transport = FakeEmailTransport::new();
        deliver_user_emails(&state, &fake_transport, &user.id)
            .await
            .unwrap();

        let sent = fake_transport.get_sent_requests().await;
        assert_eq!(sent.len(), 0);

        let due = store.next_email_delivery(&user.id).await.unwrap();
        assert!(due.is_none());
    }

    /// The selected lane is exercised through the real finalization owner,
    /// not a direct SQL seed: one generation-bound row freezes content,
    /// reaches the provider once, settles exact acceptance, and never resends.
    #[tokio::test]
    async fn selected_finalization_sends_once_and_settles_exact_acceptance() {
        let _serial = email_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaae").await;
        archive
            .state
            .control
            .set_email_preference(&archive.user_id, true, true)
            .await
            .unwrap();
        let episode_id = crate::cp::finalizer::enqueue_email_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            true,
        )
        .await
        .expect("the production finalizer enqueues one selected email");

        let transport = FakeEmailTransport::new();
        deliver_user_emails(&archive.state, &transport, &archive.user_id)
            .await
            .expect("selected email delivery settles");
        deliver_user_emails(&archive.state, &transport, &archive.user_id)
            .await
            .expect("accepted delivery is inert on replay");

        let sent = transport.get_sent_requests().await;
        assert_eq!(sent.len(), 1);
        assert!(sent[0]
            .idempotency_key
            .starts_with(SELECTED_EMAIL_DELIVERY_PREFIX));
        assert!(sent[0].text_body.contains("Delivery activation fixture"));
        let settled = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, move |connection| {
                connection
                    .query_row(
                        "SELECT state,attempt_count,response_status,provider_message_id
                     FROM email_deliveries WHERE episode_id=?1",
                        [episode_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, Option<i64>>(2)?,
                                row.get::<_, Option<String>>(3)?,
                            ))
                        },
                    )
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(settled.0, "accepted");
        assert_eq!(settled.1, 1);
        assert_eq!(settled.2, Some(202));
        assert!(settled.3.is_some());
    }

    #[tokio::test]
    async fn selected_network_ambiguity_is_never_resent() {
        let _serial = email_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaad").await;
        archive
            .state
            .control
            .set_email_preference(&archive.user_id, true, false)
            .await
            .unwrap();
        let episode_id = crate::cp::finalizer::enqueue_email_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            false,
        )
        .await
        .unwrap();
        let transport = FakeEmailTransport::new();
        transport
            .set_force_error(Some(EmailTransportError::Ambiguous {
                code: "network_outcome_unknown".into(),
            }))
            .await;
        deliver_user_emails(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        transport.set_force_error(None).await;
        deliver_user_emails(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        assert_eq!(transport.get_sent_requests().await.len(), 1);
        let settled = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, move |connection| {
                connection
                    .query_row(
                        "SELECT state,attempt_count,error_code FROM email_deliveries
                         WHERE episode_id=?1",
                        [episode_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, Option<String>>(2)?,
                            ))
                        },
                    )
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(settled.0, "failed");
        assert_eq!(settled.1, 1);
        assert_eq!(settled.2.as_deref(), Some(wal::AMBIGUOUS_ERROR_CODE));
    }

    #[tokio::test]
    async fn selected_definitive_retry_reuses_the_exact_frozen_request() {
        let _serial = email_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaac").await;
        archive
            .state
            .control
            .set_email_preference(&archive.user_id, true, true)
            .await
            .unwrap();
        crate::cp::finalizer::enqueue_email_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            true,
        )
        .await
        .unwrap();
        let transport = FakeEmailTransport::new();
        transport
            .set_force_error(Some(EmailTransportError::Retryable {
                status: Some(409),
                code: "concurrent_idempotent_request".into(),
                retry_after_seconds: Some(1),
            }))
            .await;
        deliver_user_emails(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        transport.set_force_error(None).await;
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        deliver_user_emails(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        let requests = transport.get_sent_requests().await;
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        let accepted: (String, i64, Option<i64>) = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, |connection| {
                connection
                    .query_row(
                        "SELECT state,attempt_count,response_status FROM email_deliveries",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(accepted, ("accepted".into(), 2, Some(202)));
    }

    #[tokio::test]
    async fn selected_disabled_preference_cancels_before_provider_without_charging_attempt() {
        let _serial = email_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab").await;
        archive
            .state
            .control
            .set_email_preference(&archive.user_id, true, true)
            .await
            .unwrap();
        crate::cp::finalizer::enqueue_email_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            true,
        )
        .await
        .unwrap();
        archive
            .state
            .control
            .set_email_preference(&archive.user_id, false, false)
            .await
            .unwrap();
        let transport = FakeEmailTransport::new();
        deliver_user_emails(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        assert!(transport.get_sent_requests().await.is_empty());
        let cancelled: (String, i64, Option<String>) = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, |connection| {
                connection
                    .query_row(
                        "SELECT state,attempt_count,error_code FROM email_deliveries",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            cancelled,
            ("cancelled".into(), 0, Some("preference_disabled".into()))
        );
        assert!(archive
            .state
            .control
            .list_email_send_fences(&archive.user_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn selected_control_outcome_save_failure_reconciles_without_resend() {
        let _serial = email_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::{answerable_wal_archive, state_over};

        struct FailControlOutcomeSave {
            gcs: Arc<crate::store::tests::FakeGcs>,
            sent: tokio::sync::Mutex<Vec<EmailRequest>>,
        }

        #[async_trait]
        impl EmailTransport for FailControlOutcomeSave {
            async fn send(
                &self,
                request: EmailRequest,
            ) -> std::result::Result<EmailTransportResponse, EmailTransportError> {
                self.sent.lock().await.push(request);
                self.gcs.fail_next_put_for_object(
                    "control/control.db.enc",
                    EnclaveError::Gcs("injected email outcome save failure".into()),
                );
                Ok(EmailTransportResponse {
                    provider_message_id: "resend_exact_accepted".into(),
                    status: 202,
                })
            }
        }

        let archive = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9").await;
        archive
            .state
            .control
            .set_email_preference(&archive.user_id, true, false)
            .await
            .unwrap();
        let episode_id = crate::cp::finalizer::enqueue_email_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            false,
        )
        .await
        .unwrap();
        let control_gcs = archive.control_gcs();
        let transport = FailControlOutcomeSave {
            gcs: Arc::clone(&control_gcs),
            sent: tokio::sync::Mutex::new(Vec::new()),
        };
        reset_test_pacer().await;
        assert!(
            deliver_user_emails(&archive.state, &transport, &archive.user_id)
                .await
                .is_err()
        );
        assert_eq!(transport.sent.lock().await.len(), 1);

        // Reload only Control from its last durable generation. The archive
        // already owns exact accepted evidence, so reconciliation must finish
        // the Control receipt without a second provider call.
        let restarted = state_over(
            Arc::clone(&archive.state.store),
            Arc::new(crate::cp::control_store::ControlStore::new(
                Arc::new(crate::store::tests::FakeKms),
                control_gcs,
            )),
        );
        let no_resend = FakeEmailTransport::new();
        reset_test_pacer().await;
        deliver_user_emails(&restarted, &no_resend, &archive.user_id)
            .await
            .unwrap();
        assert!(no_resend.get_sent_requests().await.is_empty());
        let settled: (String, i64, Option<i64>, Option<String>) = restarted
            .store
            .wal_authoritative_read(&archive.user_id, move |connection| {
                connection
                    .query_row(
                        "SELECT state,attempt_count,response_status,provider_message_id
                         FROM email_deliveries WHERE episode_id=?1",
                        [episode_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            settled,
            (
                "accepted".into(),
                1,
                Some(202),
                Some("resend_exact_accepted".into())
            )
        );
        assert!(restarted
            .control
            .list_email_send_fences(&archive.user_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn selected_control_unavailability_before_claim_never_sends_or_charges_attempt() {
        let _serial = email_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa8").await;
        archive
            .state
            .control
            .set_email_preference(&archive.user_id, true, false)
            .await
            .unwrap();
        let episode_id = crate::cp::finalizer::enqueue_email_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            false,
        )
        .await
        .unwrap();
        let control_gcs = archive.control_gcs();
        control_gcs.fail_next_put_for_object(
            "control/control.db.enc",
            EnclaveError::Gcs("injected email fence admission failure".into()),
        );
        let no_send = FakeEmailTransport::new();
        reset_test_pacer().await;
        let first = deliver_user_emails(&archive.state, &no_send, &archive.user_id).await;
        assert!(first.is_err());
        assert!(no_send.get_sent_requests().await.is_empty());
        let first_row = archive
            .state
            .store
            .next_email_delivery(&archive.user_id)
            .await
            .unwrap();
        let first_claim = load_open_email_claim(
            &archive.state,
            &archive.user_id,
            &first_row.as_ref().unwrap().delivery_id,
        )
        .await
        .unwrap();
        let first_fence = archive
            .state
            .control
            .get_email_send_fence(&archive.user_id, &first_row.as_ref().unwrap().delivery_id)
            .await;
        assert!(first_claim.is_none());
        assert!(matches!(first_fence, Ok(None)));

        // Once Control is available again the untouched row can claim and
        // send normally. The failed pass itself spent and charged nothing.
        reset_test_pacer().await;
        deliver_user_emails(&archive.state, &no_send, &archive.user_id)
            .await
            .unwrap();
        assert_eq!(no_send.get_sent_requests().await.len(), 1);

        let accepted: (String, i64, Option<String>) = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, move |connection| {
                connection
                    .query_row(
                        "SELECT state,attempt_count,error_code FROM email_deliveries
                         WHERE episode_id=?1",
                        [episode_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(accepted, ("accepted".into(), 1, None));
        assert!(archive
            .state
            .control
            .list_email_send_fences(&archive.user_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn selected_sweep_caps_one_account_at_two_provider_calls() {
        let _serial = email_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa7").await;
        archive
            .state
            .control
            .set_email_preference(&archive.user_id, true, false)
            .await
            .unwrap();
        for _ in 0..3 {
            crate::cp::finalizer::enqueue_email_delivery_for_activation_test(
                &archive.state,
                &archive.user_id,
                false,
            )
            .await
            .unwrap();
        }
        let transport = FakeEmailTransport::new();
        reset_test_pacer().await;
        deliver_user_emails(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        assert_eq!(transport.get_sent_requests().await.len(), 2);
        let remaining: i64 = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, |connection| {
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM email_deliveries
                         WHERE state IN ('pending','retry')",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[tokio::test]
    async fn selected_provider_wide_failure_stops_a_neighbor_account() {
        let _serial = email_test_serial().lock().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let first = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6").await;
        let second = answerable_wal_archive("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5").await;
        for archive in [&first, &second] {
            archive
                .state
                .control
                .set_email_preference(&archive.user_id, true, false)
                .await
                .unwrap();
            crate::cp::finalizer::enqueue_email_delivery_for_activation_test(
                &archive.state,
                &archive.user_id,
                false,
            )
            .await
            .unwrap();
        }
        let transport = FakeEmailTransport::new();
        transport
            .set_force_error(Some(EmailTransportError::ProviderTerminal {
                status: Some(401),
                code: "http_401".into(),
            }))
            .await;
        reset_test_pacer().await;
        deliver_user_emails(&first.state, &transport, &first.user_id)
            .await
            .unwrap();
        deliver_user_emails(&second.state, &transport, &second.user_id)
            .await
            .unwrap();
        assert_eq!(transport.get_sent_requests().await.len(), 1);
        let untouched: (String, i64) = second
            .state
            .store
            .wal_authoritative_read(&second.user_id, |connection| {
                connection
                    .query_row(
                        "SELECT state,attempt_count FROM email_deliveries",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(untouched, ("pending".into(), 0));
        reset_test_pacer().await;
    }
}
