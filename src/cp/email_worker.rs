//! Transactional email outbox worker and Resend transport implementation.
//!
//! Processes due `email_deliveries` outbox rows for active users, enforcing per-user
//! snapshot and current preferences, 24-hour stable idempotency keys, bounded retries,
//! and fail-closed secret hygiene.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use crate::cp::delivery;
use crate::cp::email_renderer;
use crate::cp::{isotime, CpState};
use crate::error::Result;

const MAX_DELIVERIES_PER_SWEEP: usize = 10;
const MAX_ATTEMPTS: i32 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailRequest {
    pub to: String,
    pub subject: String,
    pub text_body: String,
    pub html_body: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailTransportResponse {
    pub provider_message_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailTransportError {
    Transient(String),
    Terminal(String),
}

impl std::fmt::Display for EmailTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(code) => write!(f, "transient error: {code}"),
            Self::Terminal(code) => write!(f, "terminal error: {code}"),
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
            Err(err) => {
                return Err(EmailTransportError::Transient(format!(
                    "network_error: {}",
                    err
                )));
            }
        };

        let status = response.status().as_u16();

        if (200..300).contains(&status) {
            let body: std::result::Result<ResendSuccessResponseBody, _> = response.json().await;
            match body {
                Ok(b) if b.id.is_some() && !b.id.as_ref().unwrap().is_empty() => {
                    Ok(EmailTransportResponse {
                        provider_message_id: b.id.unwrap(),
                    })
                }
                _ => Err(EmailTransportError::Transient(
                    "missing_provider_message_id".into(),
                )),
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
                        Err(EmailTransportError::Terminal(
                            "invalid_idempotent_request".into(),
                        ))
                    } else {
                        // 409 concurrent_idempotent_requests or other transient conflicts
                        Err(EmailTransportError::Transient(
                            "concurrent_idempotent_request".into(),
                        ))
                    }
                }
                400 | 401 | 403 | 422 => {
                    Err(EmailTransportError::Terminal(format!("http_{status}")))
                }
                408 | 425 | 429 => Err(EmailTransportError::Transient(format!("http_{status}"))),
                _ if (500..600).contains(&status) => {
                    Err(EmailTransportError::Transient(format!("http_{status}")))
                }
                _ => Err(EmailTransportError::Terminal(format!("http_{status}"))),
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
        if let Some(err) = self.force_error.lock().await.clone() {
            return Err(err);
        }
        let msg_id = format!("msg_fake_{}", request.idempotency_key);
        self.sent_requests.lock().await.push(request);
        Ok(EmailTransportResponse {
            provider_message_id: msg_id,
        })
    }
}

/// Process due email outbox rows for one user.
pub async fn deliver_user_emails(
    state: &CpState,
    transport: &dyn EmailTransport,
    user_id: &str,
) -> Result<()> {
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        let pref = match state.control.get_email_preference(user_id).await {
            Ok(p) => p,
            Err(_) => {
                // User unknown, inactive, or deleting — cancel all pending/retry email outbox rows
                cancel_user_email_deliveries(state, user_id, "user_inactive").await?;
                break;
            }
        };

        if !pref.enabled {
            cancel_user_email_deliveries(state, user_id, "preference_disabled").await?;
            break;
        }

        let Some(outbox) = state.store.next_email_delivery(user_id).await? else {
            break;
        };

        // Effective include_content = snapshot && current_preference
        let effective_include_content = outbox.include_content && pref.include_content;

        let Some(episode) =
            delivery::load_finalized_episode(state, user_id, outbox.episode_id).await?
        else {
            state
                .store
                .update_email_delivery_state(
                    user_id,
                    outbox.episode_id,
                    outbox.delivery_version,
                    "failed",
                    outbox.attempt_count + 1,
                    None,
                    None,
                    Some("missing_final_brief"),
                )
                .await?;
            continue;
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

        info!(
            user_id = %user_id,
            episode_id = outbox.episode_id,
            delivery_id = %outbox.delivery_id,
            include_content = effective_include_content,
            "delivering transactional episode email"
        );

        let attempts = outbox.attempt_count + 1;

        match transport.send(email_req).await {
            Ok(resp) => {
                state
                    .store
                    .update_email_delivery_state(
                        user_id,
                        outbox.episode_id,
                        outbox.delivery_version,
                        "accepted",
                        attempts,
                        Some(&resp.provider_message_id),
                        Some(200),
                        None,
                    )
                    .await?;
            }
            Err(EmailTransportError::Terminal(code)) => {
                warn!(
                    user_id = %user_id,
                    episode_id = outbox.episode_id,
                    error_code = %code,
                    "email transport returned terminal failure"
                );
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
                        Some(&code),
                    )
                    .await?;
            }
            Err(EmailTransportError::Transient(code)) => {
                warn!(
                    user_id = %user_id,
                    episode_id = outbox.episode_id,
                    error_code = %code,
                    attempt = attempts,
                    "email transport returned transient failure"
                );
                if attempts >= MAX_ATTEMPTS {
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
                            Some("max_attempts_exceeded"),
                        )
                        .await?;
                } else {
                    let backoff_secs = (1.5_f64.powi(attempts) * 10.0).min(14_400.0) as i64;
                    let next_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64
                        + backoff_secs * 1_000;
                    let next_attempt_at = isotime::format_epoch_millis(next_ms);
                    state
                        .store
                        .update_email_delivery_state(
                            user_id,
                            outbox.episode_id,
                            outbox.delivery_version,
                            "retry",
                            attempts,
                            None,
                            None,
                            Some(&code),
                        )
                        .await?;
                    let _ = state
                        .store
                        .set_email_delivery_next_attempt(
                            user_id,
                            outbox.episode_id,
                            outbox.delivery_version,
                            &next_attempt_at,
                        )
                        .await;
                }
            }
        }
    }

    Ok(())
}

async fn cancel_user_email_deliveries(state: &CpState, user_id: &str, reason: &str) -> Result<()> {
    state
        .store
        .cancel_pending_email_deliveries(user_id, reason)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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
            allowed_emails: None,
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
        })
    }

    #[tokio::test]
    async fn deliver_user_emails_pending_to_accepted() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let control = Arc::new(crate::cp::control_store::ControlStore::new(kms, gcs));

        let user = control
            .upsert_user("google-sub-worker-test", "user@example.com")
            .await
            .unwrap();
        control
            .set_email_preference(&user.id, true, false)
            .await
            .unwrap();

        // Seed episode & brief
        store.with_user(&user.id, |conn| {
            conn.execute_batch(
                "INSERT INTO episodes (id, started_at, ended_at, finalized_at, title, summary, substance)
                 VALUES (1, '2026-07-30T10:00:00Z', '2026-07-30T10:30:00Z', '2026-07-30T10:30:00Z', 'Test Title', 'Test Summary', 'normal');
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
            config: test_cp_config(),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            mcp_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
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
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let control = Arc::new(crate::cp::control_store::ControlStore::new(kms, gcs));

        let user = control
            .upsert_user("google-sub-optout-test", "optout@example.com")
            .await
            .unwrap();
        // Enable full content initially
        control
            .set_email_preference(&user.id, true, true)
            .await
            .unwrap();

        store.with_user(&user.id, |conn| {
            conn.execute_batch(
                "INSERT INTO episodes (id, started_at, ended_at, finalized_at, title, summary, substance)
                 VALUES (2, '2026-07-30T10:00:00Z', '2026-07-30T10:30:00Z', '2026-07-30T10:30:00Z', 'Secret Title', 'Test Summary', 'normal');
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
            config: test_cp_config(),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            mcp_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
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
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(crate::store::Store::new(kms.clone(), gcs.clone()));
        let control = Arc::new(crate::cp::control_store::ControlStore::new(kms, gcs));

        let user = control
            .upsert_user("google-sub-disabled-test", "off@example.com")
            .await
            .unwrap();
        // User opts out completely
        control
            .set_email_preference(&user.id, false, false)
            .await
            .unwrap();

        store.with_user(&user.id, |conn| {
            conn.execute_batch(
                "INSERT INTO episodes (id, started_at, ended_at, finalized_at, title, summary, substance)
                 VALUES (1, '2026-07-30T10:00:00Z', '2026-07-30T10:30:00Z', '2026-07-30T10:30:00Z', 'Test Title', 'Test Summary', 'normal');"
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
            config: test_cp_config(),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            mcp_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
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
}
