//! Transactional email outbox worker and Resend transport implementation.
//!
//! Processes due `email_deliveries` outbox rows for active users, enforcing per-user
//! snapshot and current preferences, 24-hour stable idempotency keys, bounded retries,
//! and fail-closed secret hygiene.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cp::email_renderer;
use crate::cp::{isotime, CpState};
use crate::error::{EnclaveError, Result};
use crate::persistence::EmailProviderOutcome;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

const MAX_DELIVERIES_PER_SWEEP: usize = 2;
const MAX_ATTEMPTS: i64 = 10;
const GLOBAL_SEND_PACE_MILLIS: u64 = 250;
const PROVIDER_CIRCUIT_SECONDS: u64 = 5 * 60;

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
struct ResendErrorResponseBody {
    name: Option<String>,
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
            let provider_message_id = response
                .json::<ResendSuccessResponseBody>()
                .await
                .ok()
                .and_then(|body| body.id);
            classify_resend_response(status, provider_message_id, None, retry_after_seconds)
        } else {
            let err_body = response.json::<ResendErrorResponseBody>().await.ok();
            let err_name = err_body
                .as_ref()
                .and_then(|b| b.name.as_deref())
                .unwrap_or("");
            classify_resend_response(status, None, Some(err_name), retry_after_seconds)
        }
    }
}

fn classify_resend_response(
    status: u16,
    provider_message_id: Option<String>,
    error_name: Option<&str>,
    retry_after_seconds: Option<u64>,
) -> std::result::Result<EmailTransportResponse, EmailTransportError> {
    if (200..300).contains(&status) {
        return match provider_message_id {
            Some(id) if valid_provider_message_id(&id) => Ok(EmailTransportResponse {
                provider_message_id: id,
                status,
            }),
            _ => Err(EmailTransportError::Ambiguous {
                code: "accepted_without_provider_message_id".into(),
            }),
        };
    }
    match status {
        409 if error_name == Some("invalid_idempotent_request") => {
            Err(EmailTransportError::DeliveryTerminal {
                status: Some(status),
                code: "invalid_idempotent_request".into(),
            })
        }
        409 => Err(EmailTransportError::Retryable {
            status: Some(status),
            code: "concurrent_idempotent_request".into(),
            retry_after_seconds,
        }),
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

/// Process due email outbox rows for one user.
pub async fn deliver_user_emails(
    state: &CpState,
    transport: &dyn EmailTransport,
    user_id: &str,
) -> Result<()> {
    deliver_postgres_user_emails(state, transport, user_id).await
}

async fn deliver_postgres_user_emails(
    state: &CpState,
    transport: &dyn EmailTransport,
    user_id: &str,
) -> Result<()> {
    let repository = state.repositories.deliveries();
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        let Some(candidate) = repository.next_email_candidate(user_id).await? else {
            break;
        };
        let subject =
            email_renderer::render_email_subject(&candidate.episode, candidate.include_content);
        let (text_body, html_body) = email_renderer::render_email_body(
            &candidate.episode,
            candidate.include_content,
            &state.config.web_origin,
        );
        let frozen = crate::persistence::FrozenEmailDelivery {
            recipient_email: candidate.recipient_email.clone(),
            include_content: candidate.include_content,
            subject,
            text_body,
            html_body,
        };
        let mut claim = repository
            .claim_email(&candidate, frozen.clone(), 60)
            .await?;
        if claim.is_none() {
            // The provider lane deliberately serializes calls across every
            // process. Give the prior settlement's short pacing window one
            // chance to elapse; a circuit or competing sender waits for the
            // next normal sweep.
            tokio::time::sleep(Duration::from_millis(
                GLOBAL_SEND_PACE_MILLIS.saturating_add(25),
            ))
            .await;
            claim = repository.claim_email(&candidate, frozen, 60).await?;
        }
        let Some(claim) = claim else {
            break;
        };
        let result = transport
            .send(EmailRequest {
                to: claim.request.recipient_email.clone(),
                subject: claim.request.subject.clone(),
                text_body: claim.request.text_body.clone(),
                html_body: claim.request.html_body.clone(),
                idempotency_key: claim.delivery_id.clone(),
            })
            .await;
        let now = isotime::format_epoch_millis(epoch_millis());
        let (outcome, circuit_seconds) =
            classify_email_transport_result(result, claim.attempt_count, &now)?;
        repository
            .settle_email(
                &claim,
                outcome,
                circuit_seconds.and_then(|seconds| i64::try_from(seconds).ok()),
            )
            .await?;
        emit_email_metric("settled");
    }
    Ok(())
}

fn classify_email_transport_result(
    result: std::result::Result<EmailTransportResponse, EmailTransportError>,
    attempt_count: i64,
    outcome_at: &str,
) -> Result<(EmailProviderOutcome, Option<u64>)> {
    Ok(match result {
        Ok(response) => (
            EmailProviderOutcome::Accepted {
                status: i64::from(response.status),
                provider_message_id: response.provider_message_id,
            },
            None,
        ),
        Err(EmailTransportError::Ambiguous { .. }) => (EmailProviderOutcome::Ambiguous, None),
        Err(EmailTransportError::DeliveryTerminal { status, code }) => (
            EmailProviderOutcome::Failed {
                status: status.map(i64::from),
                code,
            },
            None,
        ),
        Err(EmailTransportError::Retryable {
            status,
            code,
            retry_after_seconds,
        }) => {
            let circuit = status
                .is_some_and(|value| value == 429 || value >= 500)
                .then_some(
                    retry_after_seconds
                        .unwrap_or(PROVIDER_CIRCUIT_SECONDS)
                        .clamp(1, 6 * 60 * 60),
                );
            if attempt_count >= MAX_ATTEMPTS {
                (
                    EmailProviderOutcome::Failed {
                        status: status.map(i64::from),
                        code: "attempt_cap".into(),
                    },
                    circuit,
                )
            } else {
                let delay = retry_after_seconds
                    .and_then(|seconds| i64::try_from(seconds).ok())
                    .unwrap_or_else(|| retry_delay(attempt_count));
                (
                    EmailProviderOutcome::Retry {
                        status: status.map(i64::from),
                        code,
                        retry_at: add_seconds(outcome_at, delay)?,
                    },
                    circuit,
                )
            }
        }
        Err(EmailTransportError::ProviderTerminal { status, code }) => {
            let outcome = if attempt_count >= MAX_ATTEMPTS {
                EmailProviderOutcome::Failed {
                    status: status.map(i64::from),
                    code,
                }
            } else {
                EmailProviderOutcome::Retry {
                    status: status.map(i64::from),
                    code,
                    retry_at: add_seconds(outcome_at, 60 * 60)?,
                }
            };
            (outcome, Some(PROVIDER_CIRCUIT_SECONDS))
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> EmailRequest {
        EmailRequest {
            to: "user@example.com".into(),
            subject: "Your Kioku brief is ready".into(),
            text_body: "Brief text".into(),
            html_body: "<p>Brief html</p>".into(),
            idempotency_key: "delivery_123".into(),
        }
    }

    #[test]
    fn resend_payload_contains_only_the_frozen_request() {
        let transport = ResendTransport::new(
            "re_secret".into(),
            "Kioku <notifications@notify.kiokuu.com>".into(),
        );
        let payload = transport.build_request_payload(&request());

        assert_eq!(payload["from"], "Kioku <notifications@notify.kiokuu.com>");
        assert_eq!(payload["to"][0], "user@example.com");
        assert_eq!(payload["subject"], "Your Kioku brief is ready");
        assert_eq!(payload["text"], "Brief text");
        assert_eq!(payload["html"], "<p>Brief html</p>");
        assert!(payload.get("idempotency_key").is_none());
    }

    #[test]
    fn request_debug_redacts_recipient_content_and_idempotency_key() {
        assert_eq!(format!("{:?}", request()), "EmailRequest(<redacted>)");
    }

    #[test]
    fn resend_response_classification_is_fail_closed() {
        assert_eq!(
            classify_resend_response(202, Some("msg_123".into()), None, None).unwrap(),
            EmailTransportResponse {
                provider_message_id: "msg_123".into(),
                status: 202,
            }
        );
        assert!(matches!(
            classify_resend_response(202, None, None, None),
            Err(EmailTransportError::Ambiguous { .. })
        ));
        assert!(matches!(
            classify_resend_response(409, None, Some("invalid_idempotent_request"), None),
            Err(EmailTransportError::DeliveryTerminal { .. })
        ));
        assert!(matches!(
            classify_resend_response(429, None, None, Some(17)),
            Err(EmailTransportError::Retryable {
                retry_after_seconds: Some(17),
                ..
            })
        ));
        assert!(matches!(
            classify_resend_response(401, None, None, None),
            Err(EmailTransportError::ProviderTerminal { .. })
        ));
    }

    #[test]
    fn ambiguous_send_is_settled_without_a_retry_timestamp() {
        let (outcome, circuit) = classify_email_transport_result(
            Err(EmailTransportError::Ambiguous {
                code: "network_outcome_unknown".into(),
            }),
            1,
            "2026-08-28T12:00:00.000Z",
        )
        .unwrap();

        assert_eq!(outcome, EmailProviderOutcome::Ambiguous);
        assert_eq!(circuit, None);
    }

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(retry_delay(1), 30);
        assert_eq!(retry_delay(2), 60);
        assert_eq!(retry_delay(i64::MAX), retry_delay(MAX_ATTEMPTS - 1));
        assert!(retry_delay(i64::MAX) <= 6 * 60 * 60);
        assert!(valid_provider_message_id("msg_123"));
        assert!(!valid_provider_message_id(""));
        assert!(!valid_provider_message_id("msg\n123"));
    }
}
