//! Signed, user-configured delivery of finalized-episode events.
//!
//! Endpoint URLs, signing secrets, and the outbox live in PostgreSQL. A bounded
//! request is frozen in the same durable claim before
//! provider I/O. Delivery re-resolves and pins a public IP for every attempt,
//! does not follow redirects or system proxies, and never logs an endpoint,
//! payload, signature, or response body. Deleting a destination purges its
//! frozen requests before the subscription is physically removed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cp::{isotime, CpState};
use crate::error::{EnclaveError, Result};
use crate::persistence::{WebhookProviderOutcome, WebhookSubscription};
use async_trait::async_trait;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::Url;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::Sha256;

const MAX_ATTEMPTS: i64 = 10;
const MAX_PROVIDER_CALLS_PER_ACCOUNT: usize = 2;
const SEND_PACE_MILLIS: u64 = 250;
const DNS_TIMEOUT_SECONDS: u64 = 5;
const MAX_DNS_ANSWERS: usize = 64;
const WEBHOOK_SOURCE: &str = "https://api.kiokuu.com";
const WEBHOOK_EVENT_PREFIX: &str = "w1_";

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct WebhookDeliveryStatusSummary {
    pub(crate) pending: i64,
    pub(crate) retry: i64,
    pub(crate) sent: i64,
    pub(crate) failed: i64,
    pub(crate) ambiguous: i64,
    pub(crate) cancelled: i64,
    pub(crate) latest: Option<WebhookDeliveryStatusEntry>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct WebhookDeliveryStatusEntry {
    pub(crate) outcome: &'static str,
    pub(crate) attempt_count: Option<i64>,
    pub(crate) response_status: Option<i64>,
    pub(crate) updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SendFailure {
    InvalidEndpoint,
    Preflight,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookTransportResponse {
    status: u16,
    retry_after_seconds: Option<u64>,
}

#[derive(Clone)]
struct WebhookRequest {
    endpoint_url: String,
    signing_secret: String,
    event_id: String,
    body: Vec<u8>,
}

impl std::fmt::Debug for WebhookRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebhookRequest(<redacted>)")
    }
}

#[async_trait]
trait WebhookTransport: Send + Sync {
    async fn send(
        &self,
        request: WebhookRequest,
    ) -> std::result::Result<WebhookTransportResponse, SendFailure>;
}

struct ProductionWebhookTransport;

#[async_trait]
impl WebhookTransport for ProductionWebhookTransport {
    async fn send(
        &self,
        request: WebhookRequest,
    ) -> std::result::Result<WebhookTransportResponse, SendFailure> {
        send_signed_request(request).await
    }
}

pub fn new_signing_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

pub fn new_event_id() -> String {
    format!(
        "{WEBHOOK_EVENT_PREFIX}{}",
        super::tokens::random_token_hex()
    )
}

/// Return a display-only origin. Paths and query strings often contain the
/// destination's own bearer credential and are intentionally redacted.
pub fn endpoint_display(endpoint: &str) -> String {
    let Ok(url) = Url::parse(endpoint) else {
        return "Invalid endpoint".into();
    };
    let Some(host) = url.host_str() else {
        return "Invalid endpoint".into();
    };
    let bare_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let host = if bare_host.contains(':') {
        format!("[{bare_host}]")
    } else {
        bare_host.to_string()
    };
    format!("{}://{host}/…", url.scheme())
}

/// Syntax and literal-address validation used before a subscription is stored.
/// DNS is resolved and checked again immediately before every outbound request.
pub fn validate_endpoint_syntax(endpoint: &str) -> Result<Url> {
    if endpoint.len() > 2048 {
        return Err(EnclaveError::InvalidRequest(
            "webhook endpoint is too long".into(),
        ));
    }
    let url = Url::parse(endpoint)
        .map_err(|_| EnclaveError::InvalidRequest("webhook endpoint is not a valid URL".into()))?;
    let host = url
        .host_str()
        .ok_or_else(|| EnclaveError::InvalidRequest("webhook endpoint needs a host".into()))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return Err(EnclaveError::InvalidRequest(
            "webhook endpoint must use HTTPS port 443 without credentials or a fragment".into(),
        ));
    }
    let host_lower = host.trim_end_matches('.').to_ascii_lowercase();
    if host_lower == "localhost"
        || host_lower.ends_with(".localhost")
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
    {
        return Err(EnclaveError::InvalidRequest(
            "webhook endpoint must use a public host".into(),
        ));
    }
    let literal_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = literal_host.parse::<IpAddr>() {
        if !is_public_ip(ip) {
            return Err(EnclaveError::InvalidRequest(
                "webhook endpoint must use a public address".into(),
            ));
        }
    }
    Ok(url)
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xe000) != 0x2000
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x2001 && segments[1] == 0)
        || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020)
        || segments[0] == 0x2002)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn signature(secret: &str, event_id: &str, timestamp: i64, body: &[u8]) -> Result<String> {
    let encoded = secret.strip_prefix("whsec_").ok_or_else(|| {
        EnclaveError::Config("webhook signing secret has an invalid format".into())
    })?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| EnclaveError::Config("webhook signing secret is invalid".into()))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|_| EnclaveError::Config("webhook signing secret is invalid".into()))?;
    mac.update(event_id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!(
        "v1,{}",
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    ))
}

async fn pinned_destination(
    endpoint: &str,
) -> std::result::Result<(Url, String, SocketAddr), SendFailure> {
    let url = validate_endpoint_syntax(endpoint).map_err(|_| SendFailure::InvalidEndpoint)?;
    let url_host = url
        .host_str()
        .ok_or(SendFailure::InvalidEndpoint)?
        .to_string();
    let host = url_host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(&url_host)
        .to_string();
    let mut addresses = tokio::time::timeout(
        Duration::from_secs(DNS_TIMEOUT_SECONDS),
        tokio::net::lookup_host((host.as_str(), 443)),
    )
    .await
    .map_err(|_| SendFailure::Preflight)?
    .map_err(|_| SendFailure::Preflight)?
    .take(MAX_DNS_ANSWERS + 1)
    .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(SendFailure::Preflight);
    }
    if addresses.len() > MAX_DNS_ANSWERS {
        return Err(SendFailure::Preflight);
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(SendFailure::InvalidEndpoint);
    }
    addresses.sort_by_key(|address| match address.ip() {
        IpAddr::V4(_) => 0,
        IpAddr::V6(_) => 1,
    });
    Ok((url, host, addresses[0]))
}

async fn send_signed(
    subscription: &WebhookSubscription,
    event_id: &str,
    body: Vec<u8>,
) -> std::result::Result<WebhookTransportResponse, SendFailure> {
    send_signed_request(WebhookRequest {
        endpoint_url: subscription.endpoint_url.clone(),
        signing_secret: subscription.signing_secret.clone(),
        event_id: event_id.to_owned(),
        body,
    })
    .await
}

async fn send_signed_request(
    request: WebhookRequest,
) -> std::result::Result<WebhookTransportResponse, SendFailure> {
    let (url, host, address) = pinned_destination(&request.endpoint_url).await?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let webhook_signature = signature(
        &request.signing_secret,
        &request.event_id,
        timestamp,
        &request.body,
    )
    .map_err(|_| SendFailure::InvalidEndpoint)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, address)
        .build()
        .map_err(|_| SendFailure::Preflight)?;
    let response = client
        .post(url)
        .header("content-type", "application/cloudevents+json")
        .header("user-agent", "Kioku-Webhook/1.0")
        .header("webhook-id", &request.event_id)
        .header("webhook-timestamp", timestamp.to_string())
        .header("webhook-signature", webhook_signature)
        .body(request.body)
        .send()
        .await
        .map_err(|_| SendFailure::Ambiguous)?;
    let retry_after_seconds = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| seconds.clamp(1, 6 * 60 * 60));
    Ok(WebhookTransportResponse {
        status: response.status().as_u16(),
        retry_after_seconds,
    })
}

fn cloud_event(event_id: &str, event_type: &str, subject: &str, time: &str, data: Value) -> Value {
    json!({
        "specversion": "1.0",
        "id": event_id,
        "source": WEBHOOK_SOURCE,
        "type": event_type,
        "subject": subject,
        "time": time,
        "datacontenttype": "application/json",
        "data": data,
    })
}

pub async fn send_test_webhook(subscription: &WebhookSubscription) -> Result<u16> {
    let event_id = new_event_id();
    let now = isotime::format_epoch_millis(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    );
    let event = cloud_event(
        &event_id,
        "com.kiokuu.webhook.test.v1",
        "webhook/test",
        &now,
        json!({"message": "Kioku webhook connection test", "content_included": false}),
    );
    let body = serde_json::to_vec(&event)?;
    send_signed(subscription, &event_id, body)
        .await
        .map(|response| response.status)
        .map_err(|failure| match failure {
            SendFailure::InvalidEndpoint => {
                EnclaveError::InvalidRequest("webhook endpoint is not a public HTTPS target".into())
            }
            SendFailure::Preflight | SendFailure::Ambiguous => {
                EnclaveError::Store("webhook destination is unavailable".into())
            }
        })
}

/// Deliver a bounded number of due events for one user.
pub async fn deliver_user_webhooks(state: &CpState, user_id: &str) -> Result<()> {
    deliver_postgres_user_webhooks(state, &ProductionWebhookTransport, user_id).await
}

async fn deliver_postgres_user_webhooks(
    state: &CpState,
    transport: &dyn WebhookTransport,
    user_id: &str,
) -> Result<()> {
    let repository = state.repositories.deliveries();
    for _ in 0..MAX_PROVIDER_CALLS_PER_ACCOUNT {
        let Some(candidate) = repository.next_webhook_candidate(user_id).await? else {
            break;
        };
        let details = &candidate.episode;
        let mut data = json!({
            "episode_id": candidate.episode_id,
            "finalized_at": details.finalized_at,
            "kioku_url": format!("{}/app#memory/{}", state.config.web_origin, candidate.episode_id),
            "content_included": candidate.include_content,
        });
        if candidate.include_content {
            data["title"] = json!(details.title);
            data["started_at"] = json!(details.started_at);
            data["ended_at"] = json!(details.ended_at);
            data["episode_type"] = json!(details.episode_type);
            data["participants"] = json!(details.participants);
            data["final_brief"] = json!({
                "overview": details.overview,
                "decisions": details.decisions,
                "action_items": details.action_items,
                "important_links": details.important_links,
                "open_questions": details.open_questions,
            });
        }
        let event = cloud_event(
            &candidate.event_id,
            "com.kiokuu.episode.finalized.v1",
            &format!("episode/{}", candidate.episode_id),
            &details.finalized_at,
            data,
        );
        let frozen = crate::persistence::FrozenWebhookDelivery {
            endpoint_url: candidate.endpoint_url.clone(),
            signing_secret: candidate.signing_secret.clone(),
            include_content: candidate.include_content,
            event_body: serde_json::to_string(&event)?,
        };
        let mut claim = repository
            .claim_webhook(&candidate, frozen.clone(), 60)
            .await?;
        if claim.is_none() {
            tokio::time::sleep(Duration::from_millis(SEND_PACE_MILLIS.saturating_add(25))).await;
            claim = repository.claim_webhook(&candidate, frozen, 60).await?;
        }
        let Some(claim) = claim else {
            break;
        };
        let result = transport
            .send(WebhookRequest {
                endpoint_url: claim.request.endpoint_url.clone(),
                signing_secret: claim.request.signing_secret.clone(),
                event_id: claim.event_id.clone(),
                body: claim.request.event_body.as_bytes().to_vec(),
            })
            .await;
        let outcome_at = isotime::format_epoch_millis(epoch_millis());
        let (outcome, circuit_seconds) =
            classify_webhook_transport_result(result, claim.attempt_count, &outcome_at)?;
        let metric = webhook_provider_metric(&outcome);
        repository
            .settle_webhook(&claim, outcome, circuit_seconds)
            .await?;
        emit_webhook_metric(metric);
    }
    Ok(())
}

fn classify_webhook_transport_result(
    result: std::result::Result<WebhookTransportResponse, SendFailure>,
    attempt_count: i64,
    outcome_at: &str,
) -> Result<(WebhookProviderOutcome, Option<i64>)> {
    Ok(match result {
        Ok(response) if (200..300).contains(&response.status) => (
            WebhookProviderOutcome::Sent {
                status: i64::from(response.status),
            },
            None,
        ),
        Ok(response) if retryable_status(response.status) => {
            if attempt_count >= MAX_ATTEMPTS {
                (
                    WebhookProviderOutcome::Failed {
                        status: Some(i64::from(response.status)),
                        code: "attempt_cap".into(),
                    },
                    None,
                )
            } else {
                let delay = response
                    .retry_after_seconds
                    .and_then(|seconds| i64::try_from(seconds).ok())
                    .unwrap_or_else(|| retry_delay(attempt_count));
                (
                    WebhookProviderOutcome::Retry {
                        status: Some(i64::from(response.status)),
                        code: format!("http_{}", response.status),
                        retry_at: add_seconds(outcome_at, delay)?,
                    },
                    (response.status == 429 || response.status >= 500)
                        .then_some(delay.clamp(1, 6 * 60 * 60)),
                )
            }
        }
        Ok(response) => (
            WebhookProviderOutcome::Failed {
                status: Some(i64::from(response.status)),
                code: format!("http_{}", response.status),
            },
            None,
        ),
        Err(SendFailure::InvalidEndpoint) => (
            WebhookProviderOutcome::Failed {
                status: None,
                code: "invalid_endpoint".into(),
            },
            None,
        ),
        Err(SendFailure::Preflight) if attempt_count < MAX_ATTEMPTS => (
            WebhookProviderOutcome::Retry {
                status: None,
                code: "destination_preflight_unavailable".into(),
                retry_at: add_seconds(outcome_at, 60)?,
            },
            None,
        ),
        Err(SendFailure::Preflight) => (
            WebhookProviderOutcome::Failed {
                status: None,
                code: "attempt_cap".into(),
            },
            None,
        ),
        Err(SendFailure::Ambiguous) => (WebhookProviderOutcome::Ambiguous, None),
    })
}

/// Cancel and physically purge every delivery for one already-disabled
/// subscription. PostgreSQL settles or purges one complete predecessor at a
/// time, so an unbounded historical backlog is resumable. A live send claim
/// refuses before its row, frozen secret/body, or subscription can be removed.
pub(crate) async fn cancel_subscription_deliveries(
    state: &CpState,
    user_id: &str,
    subscription_id: &str,
) -> Result<()> {
    state
        .repositories
        .deliveries()
        .cancel_webhook_deliveries(user_id, subscription_id)
        .await
}

pub(crate) async fn webhook_delivery_status(
    state: &CpState,
    user_id: &str,
    subscription_id: &str,
) -> Result<WebhookDeliveryStatusSummary> {
    state
        .repositories
        .deliveries()
        .webhook_delivery_status(user_id, subscription_id)
        .await
}

fn retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429) || (500..600).contains(&status)
}

fn webhook_provider_metric(outcome: &WebhookProviderOutcome) -> &'static str {
    match outcome {
        WebhookProviderOutcome::Sent { .. } => "sent",
        WebhookProviderOutcome::Retry { .. } => "retry",
        WebhookProviderOutcome::Ambiguous => "ambiguous",
        WebhookProviderOutcome::Failed { .. } => "failed",
    }
}

fn retry_delay(attempt: i64) -> i64 {
    let exponent = u32::try_from(attempt.saturating_sub(1).clamp(0, 8)).unwrap_or(0);
    (30_i64 * 2_i64.pow(exponent)).min(6 * 60 * 60)
}

fn add_seconds(timestamp: &str, seconds: i64) -> Result<String> {
    let millis = isotime::parse_epoch_millis(timestamp)
        .and_then(|value| value.checked_add(seconds.checked_mul(1_000)?))
        .ok_or_else(|| EnclaveError::Store("webhook retry timestamp overflow".into()))?;
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

fn emit_webhook_metric(outcome: &'static str) {
    tracing::info!(
        metric = "webhook_outbox_outcome",
        outcome,
        count = 1,
        "webhook outbox outcome"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_validation_rejects_credentials_private_hosts_and_non_https() {
        for endpoint in [
            "http://example.com/hook",
            "https://user:pass@example.com/hook",
            "https://localhost/hook",
            "https://127.0.0.1/hook",
            "https://10.0.0.1/hook",
            "https://[::1]/hook",
            "https://example.com:8443/hook",
            "https://example.com/hook#secret",
        ] {
            assert!(validate_endpoint_syntax(endpoint).is_err(), "{endpoint}");
        }
        assert!(validate_endpoint_syntax("https://hooks.example.com/a?token=secret").is_ok());
    }

    #[test]
    fn endpoint_display_hides_paths_and_query_credentials() {
        assert_eq!(
            endpoint_display("https://hooks.example.com/a/secret?token=also-secret"),
            "https://hooks.example.com/…"
        );
        assert_eq!(
            endpoint_display("https://[2606:4700:4700::1111]/hook"),
            "https://[2606:4700:4700::1111]/…"
        );
        assert_eq!(endpoint_display("not a url"), "Invalid endpoint");
    }

    #[test]
    fn signatures_are_stable_and_body_sensitive() {
        let key = base64::engine::general_purpose::STANDARD.encode([7_u8; 32]);
        let secret = format!("whsec_{key}");
        let first = signature(&secret, "w1_event", 123, br#"{"ok":true}"#).unwrap();
        let second = signature(&secret, "w1_event", 123, br#"{"ok":true}"#).unwrap();
        let changed = signature(&secret, "w1_event", 123, br#"{"ok":false}"#).unwrap();

        assert_eq!(first, second);
        assert_ne!(first, changed);
        assert!(first.starts_with("v1,"));
        assert!(signature("bad", "w1_event", 123, b"{}").is_err());
    }

    #[test]
    fn generated_secrets_and_event_ids_have_stable_wire_shapes() {
        let secret = new_signing_secret();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(secret.strip_prefix("whsec_").unwrap())
            .unwrap();
        assert_eq!(decoded.len(), 32);

        let event_id = new_event_id();
        assert!(event_id.starts_with(WEBHOOK_EVENT_PREFIX));
        assert!(event_id.len() > WEBHOOK_EVENT_PREFIX.len());
    }

    #[test]
    fn private_and_documentation_ranges_are_not_public() {
        for ip in [
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "198.51.100.2",
            "203.0.113.2",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn cloud_event_and_request_debug_preserve_the_public_contract() {
        let event = cloud_event(
            "w1_event",
            "com.kiokuu.episode.finalized.v1",
            "episode/42",
            "2026-08-28T12:00:00Z",
            json!({"content_included": false}),
        );
        assert_eq!(event["specversion"], "1.0");
        assert_eq!(event["source"], WEBHOOK_SOURCE);
        assert_eq!(event["subject"], "episode/42");
        assert_eq!(event["data"]["content_included"], false);

        let request = WebhookRequest {
            endpoint_url: "https://hooks.example.com/private".into(),
            signing_secret: "whsec_secret".into(),
            event_id: "w1_secret".into(),
            body: b"private body".to_vec(),
        };
        assert_eq!(format!("{request:?}"), "WebhookRequest(<redacted>)");
    }

    #[test]
    fn response_classification_preserves_retry_and_terminal_boundaries() {
        let outcome_at = isotime::format_epoch_millis(0);
        let (sent, circuit) = classify_webhook_transport_result(
            Ok(WebhookTransportResponse {
                status: 204,
                retry_after_seconds: None,
            }),
            1,
            &outcome_at,
        )
        .unwrap();
        assert_eq!(sent, WebhookProviderOutcome::Sent { status: 204 });
        assert_eq!(circuit, None);

        let (retry, circuit) = classify_webhook_transport_result(
            Ok(WebhookTransportResponse {
                status: 429,
                retry_after_seconds: Some(17),
            }),
            1,
            &outcome_at,
        )
        .unwrap();
        assert!(matches!(
            retry,
            WebhookProviderOutcome::Retry {
                status: Some(429),
                ..
            }
        ));
        assert_eq!(circuit, Some(17));

        let (failed, circuit) = classify_webhook_transport_result(
            Ok(WebhookTransportResponse {
                status: 400,
                retry_after_seconds: None,
            }),
            1,
            &outcome_at,
        )
        .unwrap();
        assert!(matches!(
            failed,
            WebhookProviderOutcome::Failed {
                status: Some(400),
                ..
            }
        ));
        assert_eq!(circuit, None);
    }

    #[test]
    fn ambiguous_send_is_settled_without_a_retry_timestamp() {
        let outcome_at = isotime::format_epoch_millis(0);
        let (outcome, circuit) =
            classify_webhook_transport_result(Err(SendFailure::Ambiguous), 1, &outcome_at).unwrap();

        assert_eq!(outcome, WebhookProviderOutcome::Ambiguous);
        assert_eq!(circuit, None);
    }

    #[test]
    fn retry_backoff_and_status_set_are_bounded() {
        assert!(retryable_status(408));
        assert!(retryable_status(425));
        assert!(retryable_status(429));
        assert!(retryable_status(503));
        assert!(!retryable_status(400));
        assert_eq!(retry_delay(1), 30);
        assert_eq!(retry_delay(i64::MAX), retry_delay(MAX_ATTEMPTS - 1));
        assert!(retry_delay(i64::MAX) <= 6 * 60 * 60);
    }
}
