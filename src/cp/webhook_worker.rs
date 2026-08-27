//! Signed, user-configured delivery of finalized-episode events.
//!
//! Endpoint URLs and signing secrets live in the encrypted control DB. The
//! per-user content DB holds the outbox plus a bounded request frozen before
//! provider I/O. Delivery re-resolves and pins a public IP for every attempt,
//! does not follow redirects or system proxies, and never logs an endpoint,
//! payload, signature, or response body. Deleting a destination purges its
//! frozen requests before the Control subscription is physically removed.

pub(crate) mod wal;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::Url;
use rusqlite::OptionalExtension;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::Sha256;
use tracing::{info, warn};

use crate::archive_v3_wal_idempotency::PreparedLogicalMutation;
use crate::cp::control_store::{
    WebhookControlCancellation, WebhookFenceOutcome, WebhookProviderOutcome, WebhookSendFence,
    WebhookSendFenceDisposition, WebhookSubscription,
};
use crate::cp::delivery;
use crate::cp::{isotime, CpState};
use crate::error::{EnclaveError, Result};

const MAX_DELIVERIES_PER_SWEEP: usize = 10;
const MAX_ATTEMPTS: i64 = 10;
const MAX_PROVIDER_CALLS_PER_ACCOUNT: usize = 2;
const SEND_PACE_MILLIS: u64 = 250;
const ACTIVATION_MAX_AGE_MILLIS: i64 = 24 * 60 * 60 * 1_000;
const MAX_RETRY_DELAY_MILLIS: i64 = 6 * 60 * 60 * 1_000;
const DNS_TIMEOUT_SECONDS: u64 = 5;
const MAX_DNS_ANSWERS: usize = 64;
const WEBHOOK_SOURCE: &str = "https://api.kiokuu.com";
pub(super) const SELECTED_WEBHOOK_EVENT_PREFIX: &str = "w1_";

#[derive(Debug)]
struct OutboxRow {
    episode_id: i64,
    subscription_id: String,
    delivery_version: i64,
    event_id: String,
    attempt_count: i64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct WebhookDeliveryStatusSummary {
    pending: i64,
    retry: i64,
    sent: i64,
    failed: i64,
    ambiguous: i64,
    cancelled: i64,
    latest: Option<WebhookDeliveryStatusEntry>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct WebhookDeliveryStatusEntry {
    outcome: &'static str,
    attempt_count: Option<i64>,
    response_status: Option<i64>,
    updated_at: Option<String>,
}

struct DeliveryStateUpdate<'a> {
    state: &'a str,
    attempt_count: i64,
    next_attempt_at: Option<String>,
    response_status: Option<u16>,
    error_code: Option<&'a str>,
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

struct SendPacer {
    next_send_at: tokio::time::Instant,
}

fn send_pacer() -> &'static tokio::sync::Mutex<SendPacer> {
    static PACER: OnceLock<tokio::sync::Mutex<SendPacer>> = OnceLock::new();
    PACER.get_or_init(|| {
        tokio::sync::Mutex::new(SendPacer {
            next_send_at: tokio::time::Instant::now(),
        })
    })
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
        "{SELECTED_WEBHOOK_EVENT_PREFIX}{}",
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

async fn load_event(
    state: &CpState,
    user_id: &str,
    outbox: &OutboxRow,
    include_content: bool,
) -> Result<Option<Vec<u8>>> {
    let details = match delivery::load_finalized_episode(state, user_id, outbox.episode_id).await? {
        delivery::FinalizedEpisodeLoad::Present(details) => details,
        delivery::FinalizedEpisodeLoad::Missing | delivery::FinalizedEpisodeLoad::Malformed(_) => {
            return Ok(None)
        }
    };

    let mut data = json!({
        "episode_id": outbox.episode_id,
        "finalized_at": details.finalized_at,
        "kioku_url": format!("{}/app#memory/{}", state.config.web_origin, outbox.episode_id),
        "content_included": include_content,
    });
    if include_content {
        data["title"] = json!(details.title);
        data["started_at"] = json!(details.started_at);
        data["ended_at"] = json!(details.ended_at);
        data["episode_type"] = json!(details.episode_type);
        data["participants"] = json!(details.participants);
        data["final_brief"] = json!({
            "overview": details.overview,
            "decisions": details.decisions.iter().map(|item| json!({"text": item.text})).collect::<Vec<_>>(),
            "action_items": details.action_items.iter().map(|item| json!({
                "text": item.text,
                "owner": item.owner,
                "due_at": item.due_at,
            })).collect::<Vec<_>>(),
            "important_links": details.important_links.iter().map(|item| json!({
                "url": item.url,
                "label": item.label,
                "why_it_matters": item.why_it_matters,
            })).collect::<Vec<_>>(),
            "open_questions": details.open_questions,
        });
    }
    let event = cloud_event(
        &outbox.event_id,
        "com.kiokuu.episode.finalized.v1",
        &format!("episode/{}", outbox.episode_id),
        &details.finalized_at,
        data,
    );
    Ok(Some(serde_json::to_vec(&event)?))
}

async fn set_legacy_delivery_state(
    state: &CpState,
    user_id: &str,
    outbox: &OutboxRow,
    update: DeliveryStateUpdate<'_>,
) -> Result<()> {
    let user = user_id.to_string();
    let episode_id = outbox.episode_id;
    let subscription_id = outbox.subscription_id.clone();
    let version = outbox.delivery_version;
    let delivery_state = update.state.to_string();
    let error_code = update.error_code.map(str::to_string);
    let attempt_count = update.attempt_count;
    let next_attempt_at = update.next_attempt_at;
    let response_status = update.response_status;
    if state.store.is_wal_authoritative(user_id) {
        return Err(EnclaveError::Conflict(
            "selected webhook delivery must use the exact owner".into(),
        ));
    }
    state
        .store
        .with_user(&user, move |conn| {
            conn.execute(
                "UPDATE webhook_deliveries
                 SET state = ?1, attempt_count = ?2, next_attempt_at = ?3,
                     response_status = ?4, error_code = ?5,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE episode_id = ?6 AND subscription_id = ?7 AND delivery_version = ?8",
                rusqlite::params![
                    delivery_state,
                    attempt_count,
                    next_attempt_at,
                    response_status.map(i64::from),
                    error_code,
                    episode_id,
                    subscription_id,
                    version,
                ],
            )?;
            Ok(())
        })
        .await?;
    state.store.save_user(user_id).await
}

fn is_terminal_status(status: u16) -> bool {
    (300..400).contains(&status) || matches!(status, 400 | 401 | 403 | 404 | 410 | 422)
}

async fn handle_failure(
    state: &CpState,
    user_id: &str,
    outbox: &OutboxRow,
    response_status: Option<u16>,
    error_code: &str,
    terminal: bool,
) -> Result<()> {
    let attempts = outbox
        .attempt_count
        .checked_add(1)
        .ok_or_else(|| EnclaveError::Store("webhook attempt count overflow".into()))?;
    if terminal || attempts >= MAX_ATTEMPTS {
        set_legacy_delivery_state(
            state,
            user_id,
            outbox,
            DeliveryStateUpdate {
                state: "failed",
                attempt_count: attempts,
                next_attempt_at: None,
                response_status,
                error_code: Some(error_code),
            },
        )
        .await?;
        if attempts >= MAX_ATTEMPTS
            || matches!(response_status, Some(404 | 410))
            || error_code == "invalid_endpoint"
        {
            let _ = state
                .repositories
                .notifications()
                .disable_webhook_subscription(user_id, &outbox.subscription_id)
                .await;
        }
        return Ok(());
    }
    let exponent = i32::try_from(attempts)
        .map_err(|_| EnclaveError::Store("webhook attempt count is out of range".into()))?;
    let backoff_secs = (1.5_f64.powi(exponent) * 10.0).min(14_400.0) as i64;
    let next_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
        + backoff_secs * 1_000;
    set_legacy_delivery_state(
        state,
        user_id,
        outbox,
        DeliveryStateUpdate {
            state: "retry",
            attempt_count: attempts,
            next_attempt_at: Some(isotime::format_epoch_millis(next_ms)),
            response_status,
            error_code: Some(error_code),
        },
    )
    .await
}

async fn next_delivery(state: &CpState, user_id: &str) -> Result<Option<OutboxRow>> {
    let now = isotime::format_epoch_millis(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    );
    let user = user_id.to_string();
    state
        .store
        .with_user(&user, move |conn| {
            Ok(conn
                .query_row(
                    "SELECT episode_id, subscription_id, delivery_version, event_id, attempt_count
                     FROM webhook_deliveries
                     WHERE state IN ('pending', 'retry')
                       AND (next_attempt_at IS NULL OR next_attempt_at <= ?1)
                       AND NOT EXISTS (
                         SELECT 1 FROM webhook_deliveries earlier
                         WHERE earlier.subscription_id=webhook_deliveries.subscription_id
                           AND earlier.state IN ('pending','retry')
                           AND (earlier.created_at<webhook_deliveries.created_at OR
                                (earlier.created_at=webhook_deliveries.created_at AND
                                 earlier.event_id<webhook_deliveries.event_id)))
                     ORDER BY created_at, subscription_id
                     LIMIT 1",
                    [&now],
                    |r| {
                        Ok(OutboxRow {
                            episode_id: r.get(0)?,
                            subscription_id: r.get(1)?,
                            delivery_version: r.get(2)?,
                            event_id: r.get(3)?,
                            attempt_count: r.get(4)?,
                        })
                    },
                )
                .optional()?)
        })
        .await
}

/// Deliver a bounded number of due events for one user.
pub async fn deliver_user_webhooks(state: &CpState, user_id: &str) -> Result<()> {
    if state.repositories.deliveries().is_some() {
        return deliver_postgres_user_webhooks(state, &ProductionWebhookTransport, user_id).await;
    }
    if state.store.is_wal_authoritative(user_id) {
        deliver_selected_user_webhooks(state, &ProductionWebhookTransport, user_id).await
    } else {
        deliver_legacy_user_webhooks(state, &ProductionWebhookTransport, user_id).await
    }
}

async fn deliver_postgres_user_webhooks(
    state: &CpState,
    transport: &dyn WebhookTransport,
    user_id: &str,
) -> Result<()> {
    let repository = state
        .repositories
        .deliveries()
        .ok_or_else(|| EnclaveError::Store("PostgreSQL delivery repository is missing".into()))?;
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
        let (outcome, circuit_seconds) = match result {
            Ok(response) if (200..300).contains(&response.status) => (
                WebhookProviderOutcome::Sent {
                    status: i64::from(response.status),
                },
                None,
            ),
            Ok(response) if retryable_status(response.status) => {
                if claim.attempt_count >= MAX_ATTEMPTS {
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
                        .unwrap_or_else(|| retry_delay(claim.attempt_count));
                    (
                        WebhookProviderOutcome::Retry {
                            status: Some(i64::from(response.status)),
                            code: format!("http_{}", response.status),
                            retry_at: add_seconds(&outcome_at, delay)?,
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
            Err(SendFailure::Preflight) if claim.attempt_count < MAX_ATTEMPTS => (
                WebhookProviderOutcome::Retry {
                    status: None,
                    code: "destination_preflight_unavailable".into(),
                    retry_at: add_seconds(&outcome_at, 60)?,
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
        };
        let metric = webhook_provider_metric(&outcome);
        repository
            .settle_webhook(&claim, outcome, circuit_seconds)
            .await?;
        emit_webhook_metric(metric);
    }
    Ok(())
}

/// Cancel and physically purge every delivery for one already-disabled
/// subscription. Selected archives settle or purge one complete predecessor
/// at a time, so an unbounded historical backlog is resumable. A live send
/// claim refuses before its row, frozen secret/body, or Control subscription
/// can be removed.
pub(crate) async fn cancel_subscription_deliveries(
    state: &CpState,
    user_id: &str,
    subscription_id: &str,
) -> Result<()> {
    if state.store.is_wal_authoritative(user_id) {
        loop {
            let subscription_id = subscription_id.to_owned();
            let candidate = state
                .store
                .wal_authoritative_read(user_id, move |connection| {
                    wal::load_subscription_purge_candidate(connection, &subscription_id)
                        .map_err(|_| EnclaveError::Store("webhook purge evidence failed".into()))
                })
                .await?;
            let Some(candidate) = candidate else {
                return Ok(());
            };
            match candidate {
                wal::WebhookSubscriptionPurgeCandidate::Active(predecessor) => {
                    settle_exact_webhook(
                        state,
                        user_id,
                        predecessor,
                        None,
                        wal::WebhookSettlementKind::Cancel {
                            code: "subscription_deleted".into(),
                        },
                        None,
                    )
                    .await?;
                }
                wal::WebhookSubscriptionPurgeCandidate::Terminal(evidence) => {
                    purge_exact_webhook(state, user_id, evidence).await?;
                }
            }
        }
    }

    let user = user_id.to_owned();
    let subscription = subscription_id.to_owned();
    state
        .store
        .with_user(&user, move |connection| {
            connection.execute(
                "UPDATE webhook_deliveries
                 SET state='cancelled',error_code='subscription_deleted',
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE subscription_id=?1 AND state IN ('pending','retry')",
                [subscription],
            )?;
            Ok(())
        })
        .await?;
    state.store.save_user(user_id).await
}

pub(crate) async fn webhook_delivery_status(
    state: &CpState,
    user_id: &str,
    subscription_id: &str,
) -> Result<WebhookDeliveryStatusSummary> {
    let subscription_id = subscription_id.to_owned();
    if state.store.is_wal_authoritative(user_id) {
        state
            .store
            .wal_authoritative_read(user_id, move |connection| {
                load_webhook_delivery_status(connection, &subscription_id)
            })
            .await
    } else {
        state
            .store
            .with_user_read(user_id, move |connection| {
                load_webhook_delivery_status(connection, &subscription_id)
            })
            .await
    }
}

fn load_webhook_delivery_status(
    connection: &rusqlite::Connection,
    subscription_id: &str,
) -> Result<WebhookDeliveryStatusSummary> {
    let (pending, retry, sent, failed, ambiguous, cancelled) = connection.query_row(
        "SELECT
           COALESCE(SUM(state='pending'),0),
           COALESCE(SUM(state='retry'),0),
           COALESCE(SUM(state='sent'),0),
           COALESCE(SUM(state='failed' AND error_code IS NOT ?2),0),
           COALESCE(SUM(state='failed' AND error_code=?2),0),
           COALESCE(SUM(state='cancelled'),0)
         FROM webhook_deliveries WHERE subscription_id=?1",
        rusqlite::params![subscription_id, wal::exact::AMBIGUOUS_ERROR_CODE],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let latest = connection
        .query_row(
            "SELECT state,attempt_count,response_status,error_code,updated_at
             FROM webhook_deliveries WHERE subscription_id=?1
             ORDER BY updated_at DESC,event_id DESC LIMIT 1",
            [subscription_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .map(
            |(state, attempt_count, response_status, error_code, updated_at)| {
                let outcome = match state.as_str() {
                    "pending" => "pending",
                    "retry" => "retry",
                    "sent" => "sent",
                    "cancelled" => "cancelled",
                    "failed" if error_code.as_deref() == Some(wal::exact::AMBIGUOUS_ERROR_CODE) => {
                        "ambiguous"
                    }
                    "failed" => "failed",
                    _ => "invalid",
                };
                WebhookDeliveryStatusEntry {
                    outcome,
                    attempt_count: (0..=MAX_ATTEMPTS)
                        .contains(&attempt_count)
                        .then_some(attempt_count),
                    response_status: response_status.filter(|status| (100..=599).contains(status)),
                    updated_at: (updated_at.len() <= 64
                        && isotime::parse_epoch_millis(&updated_at).is_some())
                    .then_some(updated_at),
                }
            },
        );
    Ok(WebhookDeliveryStatusSummary {
        pending,
        retry,
        sent,
        failed,
        ambiguous,
        cancelled,
        latest,
    })
}

async fn deliver_selected_user_webhooks(
    state: &CpState,
    transport: &dyn WebhookTransport,
    user_id: &str,
) -> Result<()> {
    emit_webhook_depth(state, user_id).await;
    let mut provider_calls = 0usize;
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        if provider_calls >= MAX_PROVIDER_CALLS_PER_ACCOUNT {
            break;
        }
        let mut pacer = send_pacer().lock().await;
        // The singleton production runtime and this process-wide owner lock
        // make recovery mutually exclusive with a live DNS/HTTP attempt. A
        // second kick cannot expire and close the disclosure fence while the
        // first owner still has authority to send.
        reconcile_webhook_send_fences(state, user_id).await?;
        let Some(snapshot) = next_selected_delivery(state, user_id).await? else {
            break;
        };
        if state
            .repositories
            .work()
            .webhook_outbox_deletion_owned(user_id)
            .await?
        {
            emit_webhook_metric("deletion_owned");
            break;
        }
        if let Some(claim) = load_open_webhook_claim(state, user_id, &snapshot.event_id).await? {
            if !recover_existing_webhook_claim(state, user_id, snapshot, claim).await? {
                break;
            }
            continue;
        }

        let now_ms = epoch_millis();
        let created_ms = isotime::parse_epoch_millis(&snapshot.created_at);
        let updated_ms = isotime::parse_epoch_millis(&snapshot.updated_at);
        let next_attempt_ms = snapshot
            .next_attempt_at
            .as_deref()
            .and_then(isotime::parse_epoch_millis);
        let refusal = snapshot
            .send_admission_refusal()
            .map_err(|_| EnclaveError::Store("webhook row evidence is not bounded".into()))?;
        let cancellation = if refusal.is_some() {
            refusal
        } else if created_ms.is_none()
            || updated_ms.is_none()
            || (snapshot.next_attempt_at.is_some() && next_attempt_ms.is_none())
            || created_ms.is_some_and(|created| created > now_ms)
            || updated_ms.is_some_and(|updated| updated > now_ms)
            || next_attempt_ms
                .is_some_and(|next| next > now_ms.saturating_add(MAX_RETRY_DELAY_MILLIS))
            || created_ms
                .zip(updated_ms)
                .is_some_and(|(created, updated)| created > updated)
        {
            Some("delivery_time_invalid")
        } else if created_ms
            .is_some_and(|created| now_ms.saturating_sub(created) >= ACTIVATION_MAX_AGE_MILLIS)
        {
            Some("delivery_expired")
        } else {
            None
        };
        if let Some(code) = cancellation {
            settle_exact_webhook(
                state,
                user_id,
                snapshot,
                None,
                wal::WebhookSettlementKind::Cancel { code: code.into() },
                None,
            )
            .await?;
            emit_webhook_metric(code);
            continue;
        }

        let frozen = match load_frozen_webhook_request(state, user_id, &snapshot.event_id).await? {
            Some(request) => request,
            None => {
                let subscription = state
                    .repositories
                    .notifications()
                    .get_webhook_subscription(user_id, &snapshot.subscription_id)
                    .await?;
                let Some(subscription) = subscription else {
                    settle_exact_webhook(
                        state,
                        user_id,
                        snapshot,
                        None,
                        wal::WebhookSettlementKind::Cancel {
                            code: "subscription_missing".into(),
                        },
                        None,
                    )
                    .await?;
                    continue;
                };
                let legacy_view = OutboxRow {
                    episode_id: snapshot.episode_id,
                    subscription_id: snapshot.subscription_id.clone(),
                    delivery_version: snapshot.delivery_version,
                    event_id: snapshot.event_id.clone(),
                    attempt_count: snapshot.attempt_count,
                };
                let body =
                    match load_event(state, user_id, &legacy_view, subscription.include_content)
                        .await?
                    {
                        Some(body) => body,
                        None => {
                            settle_exact_webhook(
                                state,
                                user_id,
                                snapshot,
                                None,
                                wal::WebhookSettlementKind::Cancel {
                                    code: "event_data_missing".into(),
                                },
                                None,
                            )
                            .await?;
                            continue;
                        }
                    };
                let body = String::from_utf8(body)
                    .map_err(|_| EnclaveError::Store("webhook event body is not UTF-8".into()))?;
                wal::WebhookFrozenRequest::new(
                    subscription.endpoint_url,
                    subscription.signing_secret,
                    body,
                    snapshot.subscription_id.clone(),
                    snapshot.event_id.clone(),
                    subscription.include_content,
                )
                .map_err(|_| EnclaveError::Store("webhook request is not bounded".into()))?
            }
        };

        let now = tokio::time::Instant::now();
        if pacer.next_send_at > now {
            tokio::time::sleep_until(pacer.next_send_at).await;
        }
        let started_at = now_for_webhook_snapshot(&snapshot, None);
        let plan = wal::WebhookSendClaimPlan::new(
            user_id.to_owned(),
            super::tokens::new_uuid(),
            snapshot.clone(),
            frozen,
            started_at,
        )
        .map_err(|_| EnclaveError::Store("webhook send claim construction failed".into()))?;
        match submit_webhook_claim(state, user_id, plan).await? {
            wal::WebhookSendClaimDisposition::Busy => {
                emit_webhook_metric("busy");
                break;
            }
            wal::WebhookSendClaimDisposition::DeferredLimit => {
                settle_exact_webhook(
                    state,
                    user_id,
                    snapshot,
                    None,
                    wal::WebhookSettlementKind::Cancel {
                        code: "control_defer_cap".into(),
                    },
                    None,
                )
                .await?;
                continue;
            }
            wal::WebhookSendClaimDisposition::RequestCapacity => {
                settle_exact_webhook(
                    state,
                    user_id,
                    snapshot,
                    None,
                    wal::WebhookSettlementKind::Cancel {
                        code: "frozen_request_capacity".into(),
                    },
                    None,
                )
                .await?;
                continue;
            }
            wal::WebhookSendClaimDisposition::Authorized => {}
        }
        let claim = load_open_webhook_claim(state, user_id, &snapshot.event_id)
            .await?
            .ok_or_else(|| EnclaveError::Store("webhook send claim disappeared".into()))?;
        let fence = match begin_or_reload_webhook_fence(state, user_id, &claim).await {
            Ok(Some(fence)) => fence,
            Ok(None) => break,
            Err(error) => {
                if let Ok(None) = state
                    .repositories
                    .work()
                    .get_webhook_send_fence(user_id, &snapshot.event_id)
                    .await
                {
                    let committed_at = now_for_webhook_snapshot(&snapshot, Some(&claim));
                    let retry_at = add_seconds(&committed_at, 60)?;
                    settle_exact_webhook(
                        state,
                        user_id,
                        snapshot,
                        Some(claim),
                        wal::WebhookSettlementKind::Defer {
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
            replay_webhook_fence_receipt(state, user_id, snapshot, claim, fence, outcome).await?;
            continue;
        }

        let revalidate_at = epoch_millis();
        validate_archive_webhook_send_authority(state, user_id, &claim, revalidate_at).await?;
        let minimum_valid_at = revalidate_at
            .checked_add(wal::MIN_SEND_LEASE_MILLIS)
            .ok_or_else(|| EnclaveError::Store("webhook lease horizon overflow".into()))?;
        if !state
            .repositories
            .work()
            .validate_webhook_send_fence(&fence, minimum_valid_at)
            .await?
        {
            return Err(EnclaveError::Conflict(
                "webhook disclosure fence is no longer live".into(),
            ));
        }
        provider_calls = provider_calls.saturating_add(1);
        pacer.next_send_at = tokio::time::Instant::now() + Duration::from_millis(SEND_PACE_MILLIS);
        let request = WebhookRequest {
            endpoint_url: claim.request().endpoint_url().into(),
            signing_secret: claim.request().signing_secret().into(),
            event_id: claim.request().event_id().into(),
            body: claim.request().event_body().to_vec(),
        };
        let result = transport.send(request).await;
        let outcome_at = now_for_webhook_snapshot(&snapshot, Some(&claim));
        let outcome = match result {
            Ok(response) if (200..300).contains(&response.status) => WebhookProviderOutcome::Sent {
                status: i64::from(response.status),
            },
            Ok(response) if retryable_status(response.status) => {
                if claim.send_attempt() >= MAX_ATTEMPTS {
                    WebhookProviderOutcome::Failed {
                        status: Some(i64::from(response.status)),
                        code: "attempt_cap".into(),
                    }
                } else {
                    let delay = response
                        .retry_after_seconds
                        .and_then(|value| i64::try_from(value).ok())
                        .unwrap_or_else(|| retry_delay(claim.send_attempt()));
                    WebhookProviderOutcome::Retry {
                        status: Some(i64::from(response.status)),
                        code: format!("http_{}", response.status),
                        retry_at: add_seconds(&outcome_at, delay)?,
                    }
                }
            }
            Ok(response) => WebhookProviderOutcome::Failed {
                status: Some(i64::from(response.status)),
                code: format!("http_{}", response.status),
            },
            Err(SendFailure::InvalidEndpoint) => WebhookProviderOutcome::Failed {
                status: None,
                code: "invalid_endpoint".into(),
            },
            Err(SendFailure::Preflight) if claim.send_attempt() < MAX_ATTEMPTS => {
                WebhookProviderOutcome::Retry {
                    status: None,
                    code: "destination_preflight_unavailable".into(),
                    retry_at: add_seconds(&outcome_at, 60)?,
                }
            }
            Err(SendFailure::Preflight) => WebhookProviderOutcome::Failed {
                status: None,
                code: "attempt_cap".into(),
            },
            Err(SendFailure::Ambiguous) => WebhookProviderOutcome::Ambiguous,
        };
        let outcome_metric = webhook_provider_metric(&outcome);
        persist_webhook_provider_outcome(
            state, user_id, snapshot, claim, fence, outcome, outcome_at,
        )
        .await?;
        emit_webhook_metric(outcome_metric);
    }
    Ok(())
}

async fn deliver_legacy_user_webhooks(
    state: &CpState,
    transport: &dyn WebhookTransport,
    user_id: &str,
) -> Result<()> {
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        let Some(outbox) = next_delivery(state, user_id).await? else {
            break;
        };
        if outbox.attempt_count < 0 || outbox.attempt_count >= MAX_ATTEMPTS {
            set_legacy_delivery_state(
                state,
                user_id,
                &outbox,
                DeliveryStateUpdate {
                    state: "failed",
                    attempt_count: outbox.attempt_count,
                    next_attempt_at: None,
                    response_status: None,
                    error_code: Some("invalid_attempt_count"),
                },
            )
            .await?;
            continue;
        }
        let subscription = state
            .repositories
            .notifications()
            .get_webhook_subscription(user_id, &outbox.subscription_id)
            .await?;
        let Some(subscription) = subscription.filter(|subscription| subscription.enabled) else {
            set_legacy_delivery_state(
                state,
                user_id,
                &outbox,
                DeliveryStateUpdate {
                    state: "cancelled",
                    attempt_count: outbox.attempt_count,
                    next_attempt_at: None,
                    response_status: None,
                    error_code: Some("subscription_inactive"),
                },
            )
            .await?;
            continue;
        };
        let Some(body) = load_event(state, user_id, &outbox, subscription.include_content).await?
        else {
            handle_failure(state, user_id, &outbox, None, "event_data_missing", true).await?;
            continue;
        };

        info!("delivering finalized-episode webhook");
        let request = WebhookRequest {
            endpoint_url: subscription.endpoint_url.clone(),
            signing_secret: subscription.signing_secret.clone(),
            event_id: outbox.event_id.clone(),
            body,
        };
        match transport.send(request).await {
            Ok(response) if (200..300).contains(&response.status) => {
                let attempts = outbox
                    .attempt_count
                    .checked_add(1)
                    .ok_or_else(|| EnclaveError::Store("webhook attempt count overflow".into()))?;
                set_legacy_delivery_state(
                    state,
                    user_id,
                    &outbox,
                    DeliveryStateUpdate {
                        state: "sent",
                        attempt_count: attempts,
                        next_attempt_at: None,
                        response_status: Some(response.status),
                        error_code: None,
                    },
                )
                .await?;
            }
            Ok(response) => {
                let status = response.status;
                warn!(status, "webhook destination rejected event");
                handle_failure(
                    state,
                    user_id,
                    &outbox,
                    Some(status),
                    &format!("http_{status}"),
                    is_terminal_status(status),
                )
                .await?;
            }
            Err(SendFailure::InvalidEndpoint) => {
                handle_failure(state, user_id, &outbox, None, "invalid_endpoint", true).await?;
            }
            Err(SendFailure::Preflight) => {
                handle_failure(state, user_id, &outbox, None, "network", false).await?;
            }
            Err(SendFailure::Ambiguous) => {
                handle_failure(state, user_id, &outbox, None, "network_ambiguous", false).await?;
            }
        }
    }
    Ok(())
}

async fn next_selected_delivery(
    state: &CpState,
    user_id: &str,
) -> Result<Option<wal::WebhookDeliverySnapshot>> {
    let now_ms = epoch_millis();
    let now = isotime::format_epoch_millis(now_ms);
    let maximum_retry_at =
        isotime::format_epoch_millis(now_ms.saturating_add(MAX_RETRY_DELAY_MILLIS));
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            load_next_selected_delivery(connection, &now, &maximum_retry_at)
        })
        .await
}

fn load_next_selected_delivery(
    connection: &rusqlite::Connection,
    now: &str,
    maximum_retry_at: &str,
) -> Result<Option<wal::WebhookDeliverySnapshot>> {
    connection
        .query_row(
            "SELECT rowid,episode_id,subscription_id,delivery_version,event_id,state,
                    attempt_count,next_attempt_at,response_status,error_code,created_at,updated_at
             FROM webhook_deliveries
             WHERE state IN ('pending','retry')
               AND (next_attempt_at IS NULL OR next_attempt_at <= ?1
                    OR next_attempt_at > ?2
                    OR length(next_attempt_at)>64
                    OR strftime('%Y-%m-%dT%H:%M:%fZ',next_attempt_at) IS NULL
                    OR strftime('%Y-%m-%dT%H:%M:%fZ',next_attempt_at)<>next_attempt_at)
               AND NOT EXISTS (
                 SELECT 1 FROM webhook_deliveries earlier
                 WHERE earlier.subscription_id=webhook_deliveries.subscription_id
                   AND earlier.state IN ('pending','retry')
                   AND (earlier.created_at<webhook_deliveries.created_at OR
                        (earlier.created_at=webhook_deliveries.created_at AND
                         earlier.event_id<webhook_deliveries.event_id)))
             ORDER BY created_at,event_id LIMIT 1",
            rusqlite::params![now, maximum_retry_at],
            wal::WebhookDeliverySnapshot::from_row,
        )
        .optional()
        .map_err(EnclaveError::from)
}

async fn submit_webhook_claim(
    state: &CpState,
    user_id: &str,
    plan: wal::WebhookSendClaimPlan,
) -> Result<wal::WebhookSendClaimDisposition> {
    let prepared = PreparedLogicalMutation::prepare(plan)
        .map_err(|_| EnclaveError::Store("webhook send claim preparation failed".into()))?;
    state
        .store
        .wal_authoritative_submit(user_id, prepared)
        .await
}

async fn load_open_webhook_claim(
    state: &CpState,
    user_id: &str,
    event_id: &str,
) -> Result<Option<wal::WebhookSendClaim>> {
    let event_id = event_id.to_owned();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_open_claim(connection, &event_id)
                .map_err(|_| EnclaveError::Store("webhook send claim read failed".into()))
        })
        .await
}

async fn load_frozen_webhook_request(
    state: &CpState,
    user_id: &str,
    event_id: &str,
) -> Result<Option<wal::WebhookFrozenRequest>> {
    let event_id = event_id.to_owned();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_frozen_request(connection, &event_id)
                .map_err(|_| EnclaveError::Store("webhook frozen request read failed".into()))
        })
        .await
}

async fn load_webhook_claim_recovery(
    state: &CpState,
    user_id: &str,
    claim_id: &str,
) -> Result<Option<wal::WebhookClaimRecovery>> {
    let claim_id = claim_id.to_owned();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_claim_recovery(connection, &claim_id)
                .map_err(|_| EnclaveError::Store("webhook claim recovery read failed".into()))
        })
        .await
}

async fn validate_archive_webhook_send_authority(
    state: &CpState,
    user_id: &str,
    claim: &wal::WebhookSendClaim,
    now_millis: i64,
) -> Result<()> {
    let claim = claim.clone();
    state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::validate_live_send_authority(connection, &claim, now_millis)
                .map_err(|_| EnclaveError::Conflict("webhook send lease is no longer live".into()))
        })
        .await
}

fn fence_for_webhook_claim(
    user_id: &str,
    claim: &wal::WebhookSendClaim,
    outcome: Option<WebhookFenceOutcome>,
    outcome_at: Option<String>,
) -> WebhookSendFence {
    WebhookSendFence {
        user_id: user_id.to_owned(),
        event_id: claim.predecessor().event_id.clone(),
        subscription_id: claim.predecessor().subscription_id.clone(),
        claim_id: claim.claim_id().to_owned(),
        lease_expires_at: claim.lease_expires_at().to_owned(),
        endpoint_url: claim.request().endpoint_url().to_owned(),
        signing_secret: claim.request().signing_secret().to_owned(),
        include_content: claim.request().include_content(),
        outcome,
        outcome_at,
    }
}

fn exact_webhook_fence_for_claim(
    fence: &WebhookSendFence,
    user_id: &str,
    claim: &wal::WebhookSendClaim,
) -> bool {
    fence.user_id == user_id
        && fence.event_id == claim.predecessor().event_id
        && fence.subscription_id == claim.predecessor().subscription_id
        && fence.claim_id == claim.claim_id()
        && fence.lease_expires_at == claim.lease_expires_at()
        && fence.endpoint_url == claim.request().endpoint_url()
        && fence.signing_secret == claim.request().signing_secret()
        && fence.include_content == claim.request().include_content()
}

async fn begin_or_reload_webhook_fence(
    state: &CpState,
    user_id: &str,
    claim: &wal::WebhookSendClaim,
) -> Result<Option<WebhookSendFence>> {
    let requested = fence_for_webhook_claim(user_id, claim, None, None);
    match state
        .repositories
        .work()
        .begin_webhook_send_fence(
            &requested,
            &now_for_webhook_snapshot(claim.predecessor(), Some(claim)),
        )
        .await?
    {
        WebhookSendFenceDisposition::DeletionOwned => Ok(None),
        WebhookSendFenceDisposition::Recorded(fence) => Ok(Some(fence)),
        WebhookSendFenceDisposition::Authorized(subscription) => {
            if !subscription.enabled
                || subscription.id != claim.request().subscription_id()
                || subscription.endpoint_url != claim.request().endpoint_url()
                || subscription.signing_secret != claim.request().signing_secret()
                || subscription.include_content != claim.request().include_content()
            {
                return Err(EnclaveError::Conflict(
                    "webhook disclosure authority changed".into(),
                ));
            }
            Ok(Some(requested))
        }
    }
}

async fn settle_exact_webhook(
    state: &CpState,
    user_id: &str,
    predecessor: wal::WebhookDeliverySnapshot,
    claim: Option<wal::WebhookSendClaim>,
    kind: wal::WebhookSettlementKind,
    committed_at: Option<String>,
) -> Result<()> {
    let committed_at =
        committed_at.unwrap_or_else(|| now_for_webhook_snapshot(&predecessor, claim.as_ref()));
    let plan = wal::ExactWebhookDeliverySettlementPlan::new(
        user_id.to_owned(),
        predecessor,
        claim,
        kind,
        committed_at,
    )
    .map_err(|_| EnclaveError::Store("exact webhook settlement construction failed".into()))?;
    let prepared = PreparedLogicalMutation::prepare(plan)
        .map_err(|_| EnclaveError::Store("exact webhook settlement preparation failed".into()))?;
    state
        .store
        .wal_authoritative_submit(user_id, prepared)
        .await
}

async fn purge_exact_webhook(
    state: &CpState,
    user_id: &str,
    evidence: wal::exact::WebhookDeliveryPurgeEvidence,
) -> Result<()> {
    let plan = wal::ExactWebhookDeliveryPurgePlan::new(user_id.to_owned(), evidence)
        .map_err(|_| EnclaveError::Store("exact webhook purge construction failed".into()))?;
    let prepared = PreparedLogicalMutation::prepare(plan)
        .map_err(|_| EnclaveError::Store("exact webhook purge preparation failed".into()))?;
    state
        .store
        .wal_authoritative_submit(user_id, prepared)
        .await
}

fn webhook_settlement_kind(outcome: &WebhookProviderOutcome) -> wal::WebhookSettlementKind {
    match outcome {
        WebhookProviderOutcome::Sent { status } => {
            wal::WebhookSettlementKind::Accepted { status: *status }
        }
        WebhookProviderOutcome::Retry {
            status,
            code,
            retry_at,
        } => wal::WebhookSettlementKind::Retry {
            status: *status,
            code: code.clone(),
            retry_at: retry_at.clone(),
        },
        WebhookProviderOutcome::Ambiguous => wal::WebhookSettlementKind::Ambiguous,
        WebhookProviderOutcome::Failed { status, code } => wal::WebhookSettlementKind::Failed {
            status: *status,
            code: code.clone(),
        },
    }
}

fn webhook_cancellation_code(cancellation: &WebhookControlCancellation) -> &'static str {
    match cancellation {
        WebhookControlCancellation::AccountInactive => "account_inactive",
        WebhookControlCancellation::SubscriptionMissing => "subscription_missing",
        WebhookControlCancellation::SubscriptionDisabled => "subscription_disabled",
        WebhookControlCancellation::DestinationChanged => "destination_changed",
    }
}

async fn replay_webhook_fence_receipt(
    state: &CpState,
    user_id: &str,
    predecessor: wal::WebhookDeliverySnapshot,
    claim: wal::WebhookSendClaim,
    fence: WebhookSendFence,
    outcome: WebhookFenceOutcome,
) -> Result<()> {
    if !exact_webhook_fence_for_claim(&fence, user_id, &claim) {
        return Err(EnclaveError::Conflict(
            "webhook fence does not match archive claim".into(),
        ));
    }
    let committed_at = fence
        .outcome_at
        .clone()
        .ok_or_else(|| EnclaveError::Store("webhook fence outcome lacks timestamp".into()))?;
    let kind = match &outcome {
        WebhookFenceOutcome::Provider(provider) => webhook_settlement_kind(provider),
        WebhookFenceOutcome::Cancellation(cancellation) => wal::WebhookSettlementKind::Cancel {
            code: webhook_cancellation_code(cancellation).into(),
        },
    };
    settle_exact_webhook(
        state,
        user_id,
        predecessor,
        Some(claim),
        kind,
        Some(committed_at),
    )
    .await?;
    state
        .repositories
        .work()
        .close_webhook_send_fence(&fence)
        .await
}

async fn persist_webhook_provider_outcome(
    state: &CpState,
    user_id: &str,
    predecessor: wal::WebhookDeliverySnapshot,
    claim: wal::WebhookSendClaim,
    fence: WebhookSendFence,
    outcome: WebhookProviderOutcome,
    outcome_at: String,
) -> Result<()> {
    let control_result = state
        .repositories
        .work()
        .record_webhook_send_outcome(&fence, outcome.clone(), &outcome_at)
        .await;
    let archive_result = settle_exact_webhook(
        state,
        user_id,
        predecessor,
        Some(claim),
        webhook_settlement_kind(&outcome),
        Some(outcome_at),
    )
    .await;
    archive_result?;
    control_result?;
    let completed = state
        .repositories
        .work()
        .get_webhook_send_fence(user_id, &fence.event_id)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("webhook send receipt disappeared".into()))?;
    state
        .repositories
        .work()
        .close_webhook_send_fence(&completed)
        .await
}

async fn recover_existing_webhook_claim(
    state: &CpState,
    user_id: &str,
    predecessor: wal::WebhookDeliverySnapshot,
    claim: wal::WebhookSendClaim,
) -> Result<bool> {
    let fence = state
        .repositories
        .work()
        .get_webhook_send_fence(user_id, &predecessor.event_id)
        .await?;
    if let Some(fence) = fence {
        if !exact_webhook_fence_for_claim(&fence, user_id, &claim) {
            return Err(EnclaveError::Conflict(
                "webhook claim found a different disclosure fence".into(),
            ));
        }
        if let Some(outcome) = fence.outcome.clone() {
            replay_webhook_fence_receipt(state, user_id, predecessor, claim, fence, outcome)
                .await?;
            return Ok(true);
        }
        if claim
            .is_live_at(epoch_millis())
            .map_err(|_| EnclaveError::Store("webhook claim lease is invalid".into()))?
        {
            return Ok(false);
        }
        let outcome_at = now_for_webhook_snapshot(&predecessor, Some(&claim));
        persist_webhook_provider_outcome(
            state,
            user_id,
            predecessor,
            claim,
            fence,
            WebhookProviderOutcome::Ambiguous,
            outcome_at,
        )
        .await?;
        return Ok(true);
    }
    if claim
        .is_live_at(epoch_millis())
        .map_err(|_| EnclaveError::Store("webhook claim lease is invalid".into()))?
    {
        return Ok(false);
    }
    let committed_at = now_for_webhook_snapshot(&predecessor, Some(&claim));
    let retry_at = add_seconds(&committed_at, 30)?;
    settle_exact_webhook(
        state,
        user_id,
        predecessor,
        Some(claim),
        wal::WebhookSettlementKind::Defer {
            code: "provider_not_authorized".into(),
            retry_at,
        },
        Some(committed_at),
    )
    .await?;
    Ok(true)
}

async fn reconcile_webhook_send_fences(state: &CpState, user_id: &str) -> Result<()> {
    for fence in state
        .repositories
        .work()
        .list_webhook_send_fences(user_id)
        .await?
    {
        let Some(recovery) = load_webhook_claim_recovery(state, user_id, &fence.claim_id).await?
        else {
            if state
                .repositories
                .work()
                .webhook_outbox_deletion_owned(user_id)
                .await?
            {
                return Ok(());
            }
            return Err(EnclaveError::Store(
                "webhook disclosure fence lacks archive evidence".into(),
            ));
        };
        match recovery {
            wal::WebhookClaimRecovery::Started(claim) => {
                if let Some(outcome) = fence.outcome.clone() {
                    let predecessor = claim.predecessor().clone();
                    replay_webhook_fence_receipt(
                        state,
                        user_id,
                        predecessor,
                        claim,
                        fence,
                        outcome,
                    )
                    .await?;
                } else if !claim
                    .is_live_at(epoch_millis())
                    .map_err(|_| EnclaveError::Store("webhook claim lease is invalid".into()))?
                {
                    let predecessor = claim.predecessor().clone();
                    let outcome_at = now_for_webhook_snapshot(&predecessor, Some(&claim));
                    persist_webhook_provider_outcome(
                        state,
                        user_id,
                        predecessor,
                        claim,
                        fence,
                        WebhookProviderOutcome::Ambiguous,
                        outcome_at,
                    )
                    .await?;
                }
            }
            recovery => {
                if let Some(provider) = webhook_recovery_provider_outcome(&recovery) {
                    let settled_at = webhook_recovery_settled_at(&recovery)
                        .ok_or_else(|| EnclaveError::Store("webhook outcome lacks time".into()))?;
                    let claim = webhook_recovery_claim(&recovery)
                        .ok_or_else(|| EnclaveError::Store("webhook outcome lacks claim".into()))?;
                    let mut completed = fence.clone();
                    if completed.outcome.is_none() {
                        state
                            .repositories
                            .work()
                            .record_webhook_send_outcome(&completed, provider.clone(), settled_at)
                            .await?;
                        completed = state
                            .repositories
                            .work()
                            .get_webhook_send_fence(user_id, claim.predecessor().event_id.as_str())
                            .await?
                            .ok_or_else(|| {
                                EnclaveError::Conflict("webhook receipt disappeared".into())
                            })?;
                    }
                    state
                        .repositories
                        .work()
                        .close_webhook_send_fence(&completed)
                        .await?;
                } else if let wal::WebhookClaimRecovery::Cancelled {
                    code, settled_at, ..
                } = recovery
                {
                    let cancellation = webhook_cancellation_from_code(&code).ok_or_else(|| {
                        EnclaveError::Store("webhook cancellation receipt is invalid".into())
                    })?;
                    let mut completed = fence.clone();
                    if completed.outcome.is_none() {
                        completed.outcome = Some(WebhookFenceOutcome::Cancellation(cancellation));
                        completed.outcome_at = Some(settled_at);
                    }
                    state
                        .repositories
                        .work()
                        .close_webhook_send_fence(&completed)
                        .await?;
                }
            }
        }
    }
    Ok(())
}

fn webhook_recovery_provider_outcome(
    recovery: &wal::WebhookClaimRecovery,
) -> Option<WebhookProviderOutcome> {
    match recovery {
        wal::WebhookClaimRecovery::Accepted { status, .. } => {
            Some(WebhookProviderOutcome::Sent { status: *status })
        }
        wal::WebhookClaimRecovery::Retry {
            status,
            code,
            retry_at,
            ..
        } => Some(WebhookProviderOutcome::Retry {
            status: *status,
            code: code.clone(),
            retry_at: retry_at.clone(),
        }),
        wal::WebhookClaimRecovery::Ambiguous { .. } => Some(WebhookProviderOutcome::Ambiguous),
        wal::WebhookClaimRecovery::Failed { status, code, .. } => {
            Some(WebhookProviderOutcome::Failed {
                status: *status,
                code: code.clone(),
            })
        }
        wal::WebhookClaimRecovery::Started(_)
        | wal::WebhookClaimRecovery::Deferred
        | wal::WebhookClaimRecovery::Cancelled { .. } => None,
    }
}

fn webhook_recovery_claim(recovery: &wal::WebhookClaimRecovery) -> Option<&wal::WebhookSendClaim> {
    match recovery {
        wal::WebhookClaimRecovery::Started(claim)
        | wal::WebhookClaimRecovery::Accepted { claim, .. }
        | wal::WebhookClaimRecovery::Retry { claim, .. }
        | wal::WebhookClaimRecovery::Ambiguous { claim, .. }
        | wal::WebhookClaimRecovery::Failed { claim, .. }
        | wal::WebhookClaimRecovery::Cancelled { claim, .. } => Some(claim),
        wal::WebhookClaimRecovery::Deferred => None,
    }
}

fn webhook_recovery_settled_at(recovery: &wal::WebhookClaimRecovery) -> Option<&str> {
    match recovery {
        wal::WebhookClaimRecovery::Accepted { settled_at, .. }
        | wal::WebhookClaimRecovery::Retry { settled_at, .. }
        | wal::WebhookClaimRecovery::Ambiguous { settled_at, .. }
        | wal::WebhookClaimRecovery::Failed { settled_at, .. }
        | wal::WebhookClaimRecovery::Cancelled { settled_at, .. } => Some(settled_at),
        wal::WebhookClaimRecovery::Started(_) | wal::WebhookClaimRecovery::Deferred => None,
    }
}

fn webhook_cancellation_from_code(code: &str) -> Option<WebhookControlCancellation> {
    match code {
        "account_inactive" => Some(WebhookControlCancellation::AccountInactive),
        "subscription_missing" => Some(WebhookControlCancellation::SubscriptionMissing),
        "subscription_disabled" => Some(WebhookControlCancellation::SubscriptionDisabled),
        "destination_changed" => Some(WebhookControlCancellation::DestinationChanged),
        _ => None,
    }
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

fn now_for_webhook_snapshot(
    snapshot: &wal::WebhookDeliverySnapshot,
    claim: Option<&wal::WebhookSendClaim>,
) -> String {
    let floor = isotime::parse_epoch_millis(&snapshot.updated_at)
        .into_iter()
        .chain(claim.and_then(|claim| isotime::parse_epoch_millis(claim.started_at())))
        .max()
        .unwrap_or_default();
    isotime::format_epoch_millis(epoch_millis().max(floor))
}

async fn emit_webhook_depth(state: &CpState, user_id: &str) {
    let result = state
        .store
        .wal_authoritative_read(user_id, |connection| {
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM webhook_deliveries WHERE state IN ('pending','retry')",
                [],
                |row| row.get(0),
            )?;
            let oldest: Option<String> = connection.query_row(
                "SELECT MIN(created_at) FROM webhook_deliveries WHERE state IN ('pending','retry')",
                [],
                |row| row.get(0),
            )?;
            Ok((count, oldest))
        })
        .await;
    if let Ok((count, oldest)) = result {
        let oldest_age_seconds = oldest
            .as_deref()
            .and_then(isotime::parse_epoch_millis)
            .map(|created| epoch_millis().saturating_sub(created) / 1_000)
            .unwrap_or_default()
            .max(0);
        tracing::info!(
            metric = "webhook_outbox_depth",
            count,
            oldest_age_seconds,
            "webhook outbox depth observed"
        );
    }
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct FakeWebhookTransport {
        requests: tokio::sync::Mutex<Vec<WebhookRequest>>,
        result:
            tokio::sync::Mutex<Option<std::result::Result<WebhookTransportResponse, SendFailure>>>,
    }

    impl FakeWebhookTransport {
        fn accepting() -> Self {
            Self {
                requests: tokio::sync::Mutex::new(Vec::new()),
                result: tokio::sync::Mutex::new(None),
            }
        }

        async fn respond_with(
            &self,
            result: std::result::Result<WebhookTransportResponse, SendFailure>,
        ) {
            *self.result.lock().await = Some(result);
        }
    }

    #[async_trait]
    impl WebhookTransport for FakeWebhookTransport {
        async fn send(
            &self,
            request: WebhookRequest,
        ) -> std::result::Result<WebhookTransportResponse, SendFailure> {
            self.requests.lock().await.push(request);
            self.result
                .lock()
                .await
                .take()
                .unwrap_or(Ok(WebhookTransportResponse {
                    status: 204,
                    retry_after_seconds: None,
                }))
        }
    }

    fn webhook_test_serial() -> &'static tokio::sync::Mutex<()> {
        static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    async fn reset_test_pacer() {
        let mut pacer = send_pacer().lock().await;
        pacer.next_send_at = tokio::time::Instant::now();
    }

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
        ] {
            assert!(validate_endpoint_syntax(endpoint).is_err(), "{endpoint}");
        }
        assert!(validate_endpoint_syntax("https://hooks.example.com/a?token=secret").is_ok());
    }

    #[test]
    fn endpoint_display_hides_path_and_query_credentials() {
        assert_eq!(
            endpoint_display("https://hooks.example.com/a/secret?token=also-secret"),
            "https://hooks.example.com/…"
        );
    }

    #[test]
    fn signatures_are_stable_and_body_sensitive() {
        let key = base64::engine::general_purpose::STANDARD.encode([7_u8; 32]);
        let secret = format!("whsec_{key}");
        let first = signature(&secret, "evt_1", 123, br#"{"ok":true}"#).unwrap();
        let second = signature(&secret, "evt_1", 123, br#"{"ok":true}"#).unwrap();
        let changed = signature(&secret, "evt_1", 123, br#"{"ok":false}"#).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, changed);
        assert!(first.starts_with("v1,"));
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
    fn production_transport_source_seals_dns_and_redirect_bounds() {
        let source = include_str!("webhook_worker.rs");
        for required in [
            "Duration::from_secs(DNS_TIMEOUT_SECONDS)",
            ".take(MAX_DNS_ANSWERS + 1)",
            "addresses.len() > MAX_DNS_ANSWERS",
            "addresses.iter().any(|address| !is_public_ip(address.ip()))",
            ".no_proxy()",
            ".redirect(reqwest::redirect::Policy::none())",
            ".resolve(&host, address)",
        ] {
            assert!(
                source.contains(required),
                "missing transport seal: {required}"
            );
        }
    }

    #[test]
    fn malformed_retry_head_is_selected_for_cancellation_and_releases_its_successor() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE webhook_deliveries (
                   episode_id INTEGER NOT NULL,subscription_id TEXT NOT NULL,
                   delivery_version INTEGER NOT NULL,event_id TEXT NOT NULL UNIQUE,
                   state TEXT NOT NULL,attempt_count INTEGER NOT NULL,
                   next_attempt_at TEXT,response_status INTEGER,error_code TEXT,
                   created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
                   PRIMARY KEY(episode_id,subscription_id,delivery_version));
                 INSERT INTO webhook_deliveries VALUES
                   (1,'11111111-1111-4111-8111-111111111111',1,
                    'w1_0000000000000000000000000000000000000000000000000000000000000101',
                    'retry',1,'zzzz',503,'http_503',
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z'),
                   (2,'11111111-1111-4111-8111-111111111111',1,
                    'w1_0000000000000000000000000000000000000000000000000000000000000102',
                    'pending',0,NULL,NULL,NULL,
                    '2026-08-20T19:01:00.000Z','2026-08-20T19:01:00.000Z'),
                   (3,'22222222-2222-4222-8222-222222222222',1,
                    'w1_0000000000000000000000000000000000000000000000000000000000000103',
                    'retry',1,'2026-08-20T20:00:00.000Z',503,'http_503',
                    '2026-08-20T19:00:30.000Z','2026-08-20T19:00:30.000Z');",
            )
            .unwrap();
        let now = "2026-08-20T19:30:00.000Z";
        let horizon = "2026-08-21T01:30:00.000Z";
        let poisoned = load_next_selected_delivery(&connection, now, horizon)
            .unwrap()
            .unwrap();
        assert!(poisoned.next_attempt_at.as_deref() == Some("zzzz"));
        assert_eq!(
            poisoned.send_admission_refusal().unwrap(),
            Some("delivery_malformed")
        );
        let plan = wal::ExactWebhookDeliverySettlementPlan::new(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            poisoned,
            None,
            wal::WebhookSettlementKind::Cancel {
                code: "delivery_malformed".into(),
            },
            now.into(),
        )
        .unwrap();
        let transaction = connection.transaction().unwrap();
        plan.apply_direct(&transaction).unwrap();
        transaction.commit().unwrap();
        let successor = load_next_selected_delivery(&connection, now, horizon)
            .unwrap()
            .unwrap();
        assert!(successor.event_id.ends_with("0102"));
        assert_ne!(
            successor.next_attempt_at.as_deref(),
            Some("2026-08-20T20:00:00.000Z")
        );
    }

    #[test]
    fn delivery_status_distinguishes_outcomes_without_exposing_error_text() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE webhook_deliveries (
                   episode_id INTEGER NOT NULL,subscription_id TEXT NOT NULL,
                   delivery_version INTEGER NOT NULL,event_id TEXT NOT NULL UNIQUE,
                   state TEXT NOT NULL,attempt_count INTEGER NOT NULL,
                   next_attempt_at TEXT,response_status INTEGER,error_code TEXT,
                   created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
                   PRIMARY KEY(episode_id,subscription_id,delivery_version));
                 INSERT INTO webhook_deliveries VALUES
                   (1,'11111111-1111-4111-8111-111111111111',1,'w1_01','pending',0,NULL,NULL,NULL,
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:00:00.000Z'),
                   (2,'11111111-1111-4111-8111-111111111111',1,'w1_02','retry',1,NULL,503,'private_provider_detail',
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:01:00.000Z'),
                   (3,'11111111-1111-4111-8111-111111111111',1,'w1_03','sent',1,NULL,204,NULL,
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:02:00.000Z'),
                   (4,'11111111-1111-4111-8111-111111111111',1,'w1_04','failed',2,NULL,400,'provider_terminal',
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:03:00.000Z'),
                   (5,'11111111-1111-4111-8111-111111111111',1,'w1_05','cancelled',0,NULL,NULL,'revoked',
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:04:00.000Z'),
                   (6,'11111111-1111-4111-8111-111111111111',1,'w1_06','failed',1,NULL,NULL,'provider_outcome_ambiguous_v1',
                    '2026-08-20T19:00:00.000Z','2026-08-20T19:05:00.000Z');",
            )
            .unwrap();
        let status =
            load_webhook_delivery_status(&connection, "11111111-1111-4111-8111-111111111111")
                .unwrap();
        assert_eq!(
            (status.pending, status.retry, status.sent, status.failed),
            (1, 1, 1, 1)
        );
        assert_eq!((status.ambiguous, status.cancelled), (1, 1));
        assert_eq!(status.latest.as_ref().unwrap().outcome, "ambiguous");
        let encoded = serde_json::to_string(&status).unwrap();
        assert!(!encoded.contains("private_provider_detail"));
        assert!(!encoded.contains("provider_terminal"));
        assert!(!encoded.contains("provider_outcome_ambiguous_v1"));
    }

    #[test]
    fn signature_fixed_vector() {
        // Known secret key: 32 bytes of 0x01
        let key_bytes = [1_u8; 32];
        let secret = format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode(key_bytes)
        );
        let sig = signature(&secret, "evt_test123", 1700000000, b"{\"test\":true}").unwrap();
        assert!(sig.starts_with("v1,"));
        let sig2 = signature(&secret, "evt_test123", 1700000000, b"{\"test\":true}").unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn cloud_event_structure_matches_specification() {
        let event = cloud_event(
            "evt_123",
            "com.kiokuu.episode.finalized.v1",
            "episode/42",
            "2026-07-30T12:00:00Z",
            json!({"episode_id": 42}),
        );
        assert_eq!(event["specversion"], "1.0");
        assert_eq!(event["id"], "evt_123");
        assert_eq!(event["source"], WEBHOOK_SOURCE);
        assert_eq!(event["type"], "com.kiokuu.episode.finalized.v1");
        assert_eq!(event["subject"], "episode/42");
        assert_eq!(event["time"], "2026-07-30T12:00:00Z");
        assert_eq!(event["datacontenttype"], "application/json");
        assert_eq!(event["data"]["episode_id"], 42);
    }

    #[tokio::test]
    async fn selected_finalization_freezes_sends_once_and_settles_exact_acceptance() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-ddddddddddd1").await;
        let subscription_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
        let event_id = new_event_id();
        archive
            .state
            .control
            .create_webhook_subscription(WebhookSubscription {
                id: subscription_id.into(),
                user_id: archive.user_id.clone(),
                name: "selected fixture".into(),
                endpoint_url: "https://hooks.example.com/finalized".into(),
                signing_secret: new_signing_secret(),
                include_content: true,
                enabled: true,
                created_at: isotime::format_epoch_millis(epoch_millis()),
            })
            .await
            .unwrap();
        let episode_id = crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            subscription_id,
            &event_id,
        )
        .await
        .unwrap();

        let transport = FakeWebhookTransport::accepting();
        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        let requests = transport.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].event_id, event_id);
        assert_eq!(
            requests[0].endpoint_url,
            "https://hooks.example.com/finalized"
        );
        assert!(String::from_utf8_lossy(&requests[0].body).contains("Delivery activation fixture"));
        drop(requests);

        let settled = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, move |connection| {
                connection
                    .query_row(
                        "SELECT state,attempt_count,response_status FROM webhook_deliveries
                         WHERE episode_id=?1",
                        [episode_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, Option<i64>>(2)?,
                            ))
                        },
                    )
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(settled, ("sent".into(), 1, Some(204)));
        let status = webhook_delivery_status(&archive.state, &archive.user_id, subscription_id)
            .await
            .unwrap();
        assert_eq!(status.sent, 1);
        assert_eq!(
            status.pending + status.retry + status.failed + status.ambiguous,
            0
        );
        let latest = status.latest.unwrap();
        assert_eq!(latest.outcome, "sent");
        assert_eq!(latest.attempt_count, Some(1));
        assert_eq!(latest.response_status, Some(204));
        assert!(latest.updated_at.is_some());
    }

    #[tokio::test]
    async fn selected_subscription_delete_purges_delivery_claim_secret_and_body_before_control() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-dddddddddddb").await;
        let subscription_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let event_id = "w1_0000000000000000000000000000000000000000000000000000000000000301";
        archive
            .state
            .control
            .create_webhook_subscription(WebhookSubscription {
                id: subscription_id.into(),
                user_id: archive.user_id.clone(),
                name: "purge fixture".into(),
                endpoint_url: "https://hooks.example.com/purge".into(),
                signing_secret: new_signing_secret(),
                include_content: true,
                enabled: true,
                created_at: isotime::format_epoch_millis(epoch_millis()),
            })
            .await
            .unwrap();
        crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            subscription_id,
            event_id,
        )
        .await
        .unwrap();
        let transport = FakeWebhookTransport::accepting();
        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        assert_eq!(transport.requests.lock().await.len(), 1);

        archive
            .state
            .control
            .disable_webhook_subscription(&archive.user_id, subscription_id)
            .await
            .unwrap();
        cancel_subscription_deliveries(&archive.state, &archive.user_id, subscription_id)
            .await
            .unwrap();
        assert!(archive
            .state
            .control
            .delete_webhook_subscription(&archive.user_id, subscription_id)
            .await
            .unwrap());
        let residue = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, |connection| {
                Ok((
                    connection.query_row("SELECT COUNT(*) FROM webhook_deliveries", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM archive_v3_wal_webhook_frozen_requests",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                    connection.query_row(
                        "SELECT COUNT(*) FROM archive_v3_wal_webhook_send_claims",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(residue, (0, 0, 0));
        assert!(archive
            .state
            .control
            .get_webhook_subscription(&archive.user_id, subscription_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn selected_ambiguous_send_is_never_retried() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-ddddddddddd2").await;
        let subscription_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
        let event_id = new_event_id();
        archive
            .state
            .control
            .create_webhook_subscription(WebhookSubscription {
                id: subscription_id.into(),
                user_id: archive.user_id.clone(),
                name: "ambiguous fixture".into(),
                endpoint_url: "https://hooks.example.com/ambiguous".into(),
                signing_secret: new_signing_secret(),
                include_content: false,
                enabled: true,
                created_at: isotime::format_epoch_millis(epoch_millis()),
            })
            .await
            .unwrap();
        crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            subscription_id,
            &event_id,
        )
        .await
        .unwrap();
        let transport = FakeWebhookTransport::accepting();
        transport.respond_with(Err(SendFailure::Ambiguous)).await;
        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        assert_eq!(transport.requests.lock().await.len(), 1);
        let remaining = next_selected_delivery(&archive.state, &archive.user_id)
            .await
            .unwrap();
        assert!(remaining.is_none());
    }

    #[tokio::test]
    async fn selected_disabled_destination_cancels_without_send() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-ddddddddddd3").await;
        let subscription_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3";
        let event_id = new_event_id();
        archive
            .state
            .control
            .create_webhook_subscription(WebhookSubscription {
                id: subscription_id.into(),
                user_id: archive.user_id.clone(),
                name: "disabled fixture".into(),
                endpoint_url: "https://hooks.example.com/disabled".into(),
                signing_secret: new_signing_secret(),
                include_content: false,
                enabled: true,
                created_at: isotime::format_epoch_millis(epoch_millis()),
            })
            .await
            .unwrap();
        crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            subscription_id,
            &event_id,
        )
        .await
        .unwrap();
        archive
            .state
            .control
            .disable_webhook_subscription(&archive.user_id, subscription_id)
            .await
            .unwrap();

        let transport = FakeWebhookTransport::accepting();
        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        assert!(transport.requests.lock().await.is_empty());
        assert!(next_selected_delivery(&archive.state, &archive.user_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn selected_gone_destination_disables_exact_subscription() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-ddddddddddd4").await;
        let subscription_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb4";
        let event_id = new_event_id();
        archive
            .state
            .control
            .create_webhook_subscription(WebhookSubscription {
                id: subscription_id.into(),
                user_id: archive.user_id.clone(),
                name: "gone fixture".into(),
                endpoint_url: "https://hooks.example.com/gone".into(),
                signing_secret: new_signing_secret(),
                include_content: false,
                enabled: true,
                created_at: isotime::format_epoch_millis(epoch_millis()),
            })
            .await
            .unwrap();
        crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            subscription_id,
            &event_id,
        )
        .await
        .unwrap();
        let transport = FakeWebhookTransport::accepting();
        transport
            .respond_with(Ok(WebhookTransportResponse {
                status: 410,
                retry_after_seconds: None,
            }))
            .await;
        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        assert_eq!(transport.requests.lock().await.len(), 1);
        let subscription = archive
            .state
            .control
            .get_webhook_subscription(&archive.user_id, subscription_id)
            .await
            .unwrap()
            .unwrap();
        assert!(!subscription.enabled);
    }

    #[tokio::test]
    async fn selected_retry_preserves_subscription_order_without_blocking_another_destination() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-ddddddddddd7").await;
        let first_subscription = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb7";
        let second_subscription = "cccccccc-cccc-4ccc-8ccc-ccccccccccc7";
        for (id, endpoint) in [
            (first_subscription, "https://hooks.example.com/ordered"),
            (second_subscription, "https://hooks.example.com/neighbor"),
        ] {
            archive
                .state
                .control
                .create_webhook_subscription(WebhookSubscription {
                    id: id.into(),
                    user_id: archive.user_id.clone(),
                    name: "ordering fixture".into(),
                    endpoint_url: endpoint.into(),
                    signing_secret: new_signing_secret(),
                    include_content: false,
                    enabled: true,
                    created_at: isotime::format_epoch_millis(epoch_millis()),
                })
                .await
                .unwrap();
        }
        let first_event = "w1_0000000000000000000000000000000000000000000000000000000000000001";
        let blocked_event = "w1_0000000000000000000000000000000000000000000000000000000000000002";
        let neighbor_event = "w1_0000000000000000000000000000000000000000000000000000000000000003";
        for (subscription, event) in [
            (first_subscription, first_event),
            (first_subscription, blocked_event),
            (second_subscription, neighbor_event),
        ] {
            crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
                &archive.state,
                &archive.user_id,
                subscription,
                event,
            )
            .await
            .unwrap();
        }

        let transport = FakeWebhookTransport::accepting();
        transport
            .respond_with(Ok(WebhookTransportResponse {
                status: 429,
                retry_after_seconds: Some(3_600),
            }))
            .await;
        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        let requests = transport.requests.lock().await;
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].event_id, first_event);
        assert_eq!(requests[1].event_id, neighbor_event);
        assert!(requests
            .iter()
            .all(|request| request.event_id != blocked_event));
        drop(requests);

        let states = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, |connection| {
                let mut statement = connection.prepare(
                    "SELECT event_id,state,attempt_count FROM webhook_deliveries
                     ORDER BY event_id",
                )?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(EnclaveError::from)?;
                Ok(rows)
            })
            .await
            .unwrap();
        assert_eq!(
            states,
            vec![
                (first_event.into(), "retry".into(), 1),
                (blocked_event.into(), "pending".into(), 0),
                (neighbor_event.into(), "sent".into(), 1),
            ]
        );
    }

    #[tokio::test]
    async fn selected_provider_cap_leaves_the_third_destination_unclaimed_until_next_sweep() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-ddddddddddd8").await;
        let subscriptions = [
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb8",
            "cccccccc-cccc-4ccc-8ccc-ccccccccccc8",
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee8",
        ];
        let events = [
            "w1_0000000000000000000000000000000000000000000000000000000000000011",
            "w1_0000000000000000000000000000000000000000000000000000000000000012",
            "w1_0000000000000000000000000000000000000000000000000000000000000013",
        ];
        for (index, (subscription_id, event_id)) in
            subscriptions.iter().zip(events.iter()).enumerate()
        {
            archive
                .state
                .control
                .create_webhook_subscription(WebhookSubscription {
                    id: (*subscription_id).into(),
                    user_id: archive.user_id.clone(),
                    name: format!("cap fixture {index}"),
                    endpoint_url: format!("https://hooks.example.com/cap-{index}"),
                    signing_secret: new_signing_secret(),
                    include_content: false,
                    enabled: true,
                    created_at: isotime::format_epoch_millis(epoch_millis()),
                })
                .await
                .unwrap();
            crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
                &archive.state,
                &archive.user_id,
                subscription_id,
                event_id,
            )
            .await
            .unwrap();
        }

        let transport = FakeWebhookTransport::accepting();
        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        assert_eq!(transport.requests.lock().await.len(), 2);
        let third_event = events[2].to_owned();
        let third_evidence = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, move |connection| {
                Ok((
                    wal::load_open_claim(connection, &third_event)
                        .map_err(|_| EnclaveError::Store("claim read failed".into()))?,
                    wal::load_frozen_request(connection, &third_event)
                        .map_err(|_| EnclaveError::Store("request read failed".into()))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(third_evidence, (None, None));

        deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id)
            .await
            .unwrap();
        let requests = transport.requests.lock().await;
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[2].event_id, events[2]);
    }

    #[tokio::test]
    async fn selected_control_outcome_save_failure_reconciles_without_resend() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::{answerable_wal_archive, state_over};

        struct FailControlOutcomeSave {
            gcs: Arc<crate::store::tests::FakeGcs>,
            requests: tokio::sync::Mutex<Vec<WebhookRequest>>,
        }

        #[async_trait]
        impl WebhookTransport for FailControlOutcomeSave {
            async fn send(
                &self,
                request: WebhookRequest,
            ) -> std::result::Result<WebhookTransportResponse, SendFailure> {
                self.requests.lock().await.push(request);
                self.gcs.fail_next_put_for_object(
                    "control/control.db.enc",
                    EnclaveError::Gcs("injected webhook outcome save failure".into()),
                );
                Ok(WebhookTransportResponse {
                    status: 204,
                    retry_after_seconds: None,
                })
            }
        }

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-ddddddddddd5").await;
        let subscription_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb5";
        archive
            .state
            .control
            .create_webhook_subscription(WebhookSubscription {
                id: subscription_id.into(),
                user_id: archive.user_id.clone(),
                name: "save failure fixture".into(),
                endpoint_url: "https://hooks.example.com/save-failure".into(),
                signing_secret: new_signing_secret(),
                include_content: false,
                enabled: true,
                created_at: isotime::format_epoch_millis(epoch_millis()),
            })
            .await
            .unwrap();
        crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            subscription_id,
            &new_event_id(),
        )
        .await
        .unwrap();

        let control_gcs = archive.control_gcs();
        let transport = FailControlOutcomeSave {
            gcs: Arc::clone(&control_gcs),
            requests: tokio::sync::Mutex::new(Vec::new()),
        };
        let outcome =
            deliver_selected_user_webhooks(&archive.state, &transport, &archive.user_id).await;
        assert_eq!(
            transport.requests.lock().await.len(),
            1,
            "the injected Control save failure must occur after provider I/O; outcome={outcome:?}"
        );
        assert!(outcome.is_err());

        let restarted = state_over(
            Arc::clone(&archive.state.store),
            Arc::new(crate::cp::control_store::ControlStore::new(
                Arc::new(crate::store::tests::FakeKms),
                control_gcs,
            )),
        );
        let no_resend = FakeWebhookTransport::accepting();
        reset_test_pacer().await;
        deliver_selected_user_webhooks(&restarted, &no_resend, &archive.user_id)
            .await
            .unwrap();
        assert!(no_resend.requests.lock().await.is_empty());
        assert!(next_selected_delivery(&restarted, &archive.user_id)
            .await
            .unwrap()
            .is_none());
        assert!(restarted
            .control
            .list_webhook_send_fences(&archive.user_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn selected_expired_send_claim_recovers_ambiguous_without_provider_call() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-ddddddddddd6").await;
        let subscription_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb6";
        archive
            .state
            .control
            .create_webhook_subscription(WebhookSubscription {
                id: subscription_id.into(),
                user_id: archive.user_id.clone(),
                name: "expired claim fixture".into(),
                endpoint_url: "https://hooks.example.com/expired-claim".into(),
                signing_secret: new_signing_secret(),
                include_content: false,
                enabled: true,
                created_at: isotime::format_epoch_millis(epoch_millis()),
            })
            .await
            .unwrap();
        crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            subscription_id,
            &new_event_id(),
        )
        .await
        .unwrap();

        let snapshot = next_selected_delivery(&archive.state, &archive.user_id)
            .await
            .unwrap()
            .unwrap();
        let subscription = archive
            .state
            .control
            .get_webhook_subscription(&archive.user_id, subscription_id)
            .await
            .unwrap()
            .unwrap();
        let body = load_event(
            &archive.state,
            &archive.user_id,
            &OutboxRow {
                episode_id: snapshot.episode_id,
                subscription_id: snapshot.subscription_id.clone(),
                delivery_version: snapshot.delivery_version,
                event_id: snapshot.event_id.clone(),
                attempt_count: snapshot.attempt_count,
            },
            subscription.include_content,
        )
        .await
        .unwrap()
        .unwrap();
        let plan = wal::WebhookSendClaimPlan::new(
            archive.user_id.clone(),
            crate::cp::tokens::new_uuid(),
            snapshot.clone(),
            wal::WebhookFrozenRequest::new(
                subscription.endpoint_url,
                subscription.signing_secret,
                String::from_utf8(body).unwrap(),
                snapshot.subscription_id.clone(),
                snapshot.event_id.clone(),
                subscription.include_content,
            )
            .unwrap(),
            now_for_webhook_snapshot(&snapshot, None),
        )
        .unwrap();
        assert_eq!(
            submit_webhook_claim(&archive.state, &archive.user_id, plan)
                .await
                .unwrap(),
            wal::WebhookSendClaimDisposition::Authorized
        );
        let claim = load_open_webhook_claim(&archive.state, &archive.user_id, &snapshot.event_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            begin_or_reload_webhook_fence(&archive.state, &archive.user_id, &claim)
                .await
                .unwrap()
                .is_some()
        );

        tokio::time::sleep(Duration::from_millis(
            u64::try_from(wal::CLAIM_LEASE_MILLIS).unwrap() + 100,
        ))
        .await;
        let no_send = FakeWebhookTransport::accepting();
        deliver_selected_user_webhooks(&archive.state, &no_send, &archive.user_id)
            .await
            .unwrap();
        assert!(no_send.requests.lock().await.is_empty());
        assert!(next_selected_delivery(&archive.state, &archive.user_id)
            .await
            .unwrap()
            .is_none());
        assert!(archive
            .state
            .control
            .list_webhook_send_fences(&archive.user_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn concurrent_recovery_cannot_close_a_live_provider_fence() {
        let _serial = webhook_test_serial().lock().await;
        reset_test_pacer().await;
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        struct BlockingTransport {
            requests: AtomicUsize,
            entered: tokio::sync::Semaphore,
            release: tokio::sync::Semaphore,
        }

        #[async_trait]
        impl WebhookTransport for BlockingTransport {
            async fn send(
                &self,
                _request: WebhookRequest,
            ) -> std::result::Result<WebhookTransportResponse, SendFailure> {
                self.requests.fetch_add(1, Ordering::SeqCst);
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
                Ok(WebhookTransportResponse {
                    status: 204,
                    retry_after_seconds: None,
                })
            }
        }

        let archive = answerable_wal_archive("dddddddd-dddd-4ddd-8ddd-ddddddddddda").await;
        let subscription_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbba";
        archive
            .state
            .control
            .create_webhook_subscription(WebhookSubscription {
                id: subscription_id.into(),
                user_id: archive.user_id.clone(),
                name: "live fence fixture".into(),
                endpoint_url: "https://hooks.example.com/live-fence".into(),
                signing_secret: new_signing_secret(),
                include_content: false,
                enabled: true,
                created_at: isotime::format_epoch_millis(epoch_millis()),
            })
            .await
            .unwrap();
        crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            subscription_id,
            "w1_0000000000000000000000000000000000000000000000000000000000000201",
        )
        .await
        .unwrap();

        let transport = Arc::new(BlockingTransport {
            requests: AtomicUsize::new(0),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        });
        let first_state = Arc::clone(&archive.state);
        let first_user = archive.user_id.clone();
        let first_transport = Arc::clone(&transport);
        let first = tokio::spawn(async move {
            deliver_selected_user_webhooks(&first_state, first_transport.as_ref(), &first_user)
                .await
        });
        transport.entered.acquire().await.unwrap().forget();

        let second_state = Arc::clone(&archive.state);
        let second_user = archive.user_id.clone();
        let second_transport = Arc::clone(&transport);
        let second = tokio::spawn(async move {
            deliver_selected_user_webhooks(&second_state, second_transport.as_ref(), &second_user)
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!second.is_finished());
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
        assert!(archive
            .state
            .control
            .disable_webhook_subscription(&archive.user_id, subscription_id)
            .await
            .is_err());

        transport.release.add_permits(1);
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
        archive
            .state
            .control
            .disable_webhook_subscription(&archive.user_id, subscription_id)
            .await
            .unwrap();
    }
}
