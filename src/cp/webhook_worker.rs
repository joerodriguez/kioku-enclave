//! Signed, user-configured delivery of finalized-episode events.
//!
//! Endpoint URLs and signing secrets live in the encrypted control DB. The
//! per-user content DB holds an opaque outbox only. Delivery re-resolves and
//! pins a public IP for every attempt, does not follow redirects, and never
//! logs an endpoint, payload, signature, or response body.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::Url;
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use sha2::Sha256;
use tracing::{info, warn};

use crate::cp::control_store::WebhookSubscription;
use crate::cp::delivery;
use crate::cp::{isotime, CpState};
use crate::error::{EnclaveError, Result};

const MAX_DELIVERIES_PER_SWEEP: usize = 10;
const MAX_ATTEMPTS: i32 = 10;
const WEBHOOK_SOURCE: &str = "https://api.kiokuu.com";

#[derive(Debug)]
struct OutboxRow {
    episode_id: i64,
    subscription_id: String,
    delivery_version: i32,
    event_id: String,
    attempt_count: i32,
}

struct DeliveryStateUpdate<'a> {
    state: &'a str,
    attempt_count: i32,
    next_attempt_at: Option<String>,
    response_status: Option<u16>,
    error_code: Option<&'a str>,
}

#[derive(Debug)]
enum SendFailure {
    InvalidEndpoint,
    Network,
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
    format!("evt_{}", super::tokens::random_token_hex())
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
    let mut addresses = tokio::net::lookup_host((host.as_str(), 443))
        .await
        .map_err(|_| SendFailure::Network)?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(SendFailure::Network);
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
) -> std::result::Result<u16, SendFailure> {
    let (url, host, address) = pinned_destination(&subscription.endpoint_url).await?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let webhook_signature = signature(&subscription.signing_secret, event_id, timestamp, &body)
        .map_err(|_| SendFailure::InvalidEndpoint)?;
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, address)
        .build()
        .map_err(|_| SendFailure::Network)?;
    let response = client
        .post(url)
        .header("content-type", "application/cloudevents+json")
        .header("user-agent", "Kioku-Webhook/1.0")
        .header("webhook-id", event_id)
        .header("webhook-timestamp", timestamp.to_string())
        .header("webhook-signature", webhook_signature)
        .body(body)
        .send()
        .await
        .map_err(|_| SendFailure::Network)?;
    Ok(response.status().as_u16())
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
        .map_err(|failure| match failure {
            SendFailure::InvalidEndpoint => {
                EnclaveError::InvalidRequest("webhook endpoint is not a public HTTPS target".into())
            }
            SendFailure::Network => {
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
    let Some(details) = delivery::load_finalized_episode(state, user_id, outbox.episode_id).await?
    else {
        return Ok(None);
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

async fn set_delivery_state(
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
    let attempts = outbox.attempt_count + 1;
    if terminal || attempts >= MAX_ATTEMPTS {
        set_delivery_state(
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
                .control
                .disable_webhook_subscription(user_id, &outbox.subscription_id)
                .await;
        }
        return Ok(());
    }
    let backoff_secs = (1.5_f64.powi(attempts) * 10.0).min(14_400.0) as i64;
    let next_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
        + backoff_secs * 1_000;
    set_delivery_state(
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
    for _ in 0..MAX_DELIVERIES_PER_SWEEP {
        let Some(outbox) = next_delivery(state, user_id).await? else {
            break;
        };
        let subscription = state
            .control
            .get_webhook_subscription(user_id, &outbox.subscription_id)
            .await?;
        let Some(subscription) = subscription.filter(|subscription| subscription.enabled) else {
            set_delivery_state(
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

        info!(
            user_id = %user_id,
            episode_id = outbox.episode_id,
            subscription_id = %outbox.subscription_id,
            "delivering finalized-episode webhook"
        );
        match send_signed(&subscription, &outbox.event_id, body).await {
            Ok(status) if (200..300).contains(&status) => {
                set_delivery_state(
                    state,
                    user_id,
                    &outbox,
                    DeliveryStateUpdate {
                        state: "sent",
                        attempt_count: outbox.attempt_count + 1,
                        next_attempt_at: None,
                        response_status: Some(status),
                        error_code: None,
                    },
                )
                .await?;
            }
            Ok(status) => {
                warn!(
                    user_id = %user_id,
                    episode_id = outbox.episode_id,
                    subscription_id = %outbox.subscription_id,
                    status,
                    "webhook destination rejected event"
                );
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
            Err(SendFailure::Network) => {
                handle_failure(state, user_id, &outbox, None, "network", false).await?;
            }
        }
    }
    Ok(())
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
    fn parse_string_list_handles_malformed_and_missing_json() {
        assert_eq!(delivery::parse_string_list(None), Vec::<String>::new());
        assert_eq!(
            delivery::parse_string_list(Some("not json".into())),
            Vec::<String>::new()
        );
        assert_eq!(
            delivery::parse_string_list(Some("[\"alice\", \"bob\"]".into())),
            vec!["alice".to_string(), "bob".to_string()]
        );
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
}
