//! OAuth 2.1 facade and Dynamic Client Registration.
//! Public endpoints (no auth): discovery, /register, /authorize, the Google
//! callback, and /token. MCP clients (Claude/ChatGPT) use this to obtain our
//! HS256 access tokens; Google is the upstream IdP.

use std::{net::IpAddr, str::FromStr, sync::Arc};

use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{header::LOCATION, StatusCode, Uri},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use super::{tokens, CpState};

const MAX_CLIENT_NAME_BYTES: usize = 128;
const MAX_REDIRECT_URIS: usize = 5;
const MAX_REDIRECT_URI_BYTES: usize = 2048;
// The encrypted control DB is rewritten as one object. With at most five
// 2-KiB redirects per registration, 256 clients bounds DCR-controlled storage
// to roughly 2.5 MiB while leaving ample room for this single-owner service.
const MAX_OAUTH_CLIENTS: i64 = 256;
// Registrations that were never used can be safely re-created by a dynamic
// client. Reclaim them after an hour when the cap is reached so anonymous DCR
// traffic cannot consume the finite registration table permanently.
const UNUSED_CLIENT_TTL_SECS: i64 = 60 * 60;
const MAX_CLIENT_STATE_BYTES: usize = 1024;
const AUTH_CODE_TTL_SECS: i64 = 5 * 60;
const REFRESH_TTL_SECS: i64 = 90 * 24 * 60 * 60;

fn is_valid_client_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

fn is_valid_pkce_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_valid_pkce_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

fn is_valid_redirect_uri(uri: &str) -> bool {
    if uri.is_empty()
        || uri.len() > MAX_REDIRECT_URI_BYTES
        || uri.contains(['#', '\\'])
        || uri
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return false;
    }

    let Ok(parsed) = Uri::from_str(uri) else {
        return false;
    };
    let Some(scheme) = parsed.scheme_str() else {
        return false;
    };
    let Some(authority) = parsed.authority() else {
        return false;
    };
    if authority.as_str().contains('@') {
        return false;
    }
    let Some(host) = parsed.host() else {
        return false;
    };

    match scheme {
        "https" => uri.starts_with("https://"),
        "http" => uri.starts_with("http://") && is_loopback_host(host),
        _ => false,
    }
}

fn validated_registration(
    body: RegisterBody,
) -> std::result::Result<(Option<String>, Vec<String>), &'static str> {
    if body.redirect_uris.is_empty() || body.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err("redirect_uris must contain between 1 and 5 entries");
    }
    if body
        .redirect_uris
        .iter()
        .any(|uri| !is_valid_redirect_uri(uri))
    {
        return Err("redirect_uris must be absolute HTTPS URLs or loopback HTTP URLs");
    }

    let name = match body.client_name {
        Some(name) => {
            let trimmed = name.trim();
            if trimmed.is_empty()
                || trimmed.len() > MAX_CLIENT_NAME_BYTES
                || trimmed.chars().any(char::is_control)
            {
                return Err("client_name is invalid or too long");
            }
            Some(trimmed.to_string())
        }
        None => None,
    };

    let mut uris = body.redirect_uris;
    uris.sort();
    let original_len = uris.len();
    uris.dedup();
    if uris.len() != original_len {
        return Err("redirect_uris must not contain duplicates");
    }
    Ok((name, uris))
}

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(authz_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route("/register", post(register))
        .route("/authorize", get(authorize))
        .route("/oauth/google/callback", get(google_callback))
        .route("/oauth/consent", post(consent))
        .route("/oauth/gmail/callback", get(gmail_callback))
        .route("/token", post(token))
        .layer(DefaultBodyLimit::max(16 * 1024))
}

fn redirect_302(url: &str) -> Response {
    (StatusCode::FOUND, [(LOCATION, url.to_string())]).into_response()
}

const OAUTH_PAGE_STYLE: &str = r#"
*,
*::before,
*::after {
  box-sizing: border-box;
}

:root {
  color-scheme: dark;
  font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-synthesis: none;
  --bg: #080c16;
  --surface: rgba(17, 24, 39, 0.92);
  --surface-soft: rgba(255, 255, 255, 0.045);
  --border: rgba(255, 255, 255, 0.1);
  --border-strong: rgba(255, 255, 255, 0.16);
  --text: #f4f7ff;
  --muted: #a3aec4;
  --faint: #78849c;
  --amber: #f5a623;
  --amber-bright: #ffc45c;
  --amber-soft: rgba(245, 166, 35, 0.13);
  --red: #ff817a;
  --red-soft: rgba(255, 105, 97, 0.12);
}

html {
  min-width: 320px;
  min-height: 100%;
  background: var(--bg);
  -webkit-text-size-adjust: 100%;
}

body {
  min-height: 100vh;
  margin: 0;
  color: var(--text);
  background:
    radial-gradient(circle at 50% -15%, rgba(245, 166, 35, 0.16), transparent 38rem),
    radial-gradient(circle at 8% 90%, rgba(54, 83, 134, 0.12), transparent 27rem),
    var(--bg);
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}

body::before {
  position: fixed;
  inset: 0;
  pointer-events: none;
  content: "";
  opacity: 0.32;
  background-image:
    linear-gradient(rgba(255, 255, 255, 0.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.018) 1px, transparent 1px);
  background-size: 48px 48px;
  mask-image: linear-gradient(to bottom, black, transparent 74%);
}

.shell {
  position: relative;
  z-index: 1;
  width: min(100% - 32px, 640px);
  min-height: 100vh;
  margin: 0 auto;
  padding: 44px 0 32px;
  display: flex;
  flex-direction: column;
}

.brand {
  align-self: center;
  display: inline-flex;
  align-items: center;
  gap: 11px;
  color: var(--text);
  font-size: 18px;
  font-weight: 720;
  letter-spacing: -0.02em;
}

.brand-mark {
  width: 36px;
  height: 36px;
  display: grid;
  place-items: center;
  border: 1px solid rgba(255, 255, 255, 0.18);
  border-radius: 11px;
  color: white;
  background: linear-gradient(145deg, var(--amber-bright), #e88e12);
  box-shadow: 0 8px 26px rgba(245, 166, 35, 0.22);
  font-family: "Hiragino Sans", "Yu Gothic", sans-serif;
  font-size: 18px;
  font-weight: 800;
}

.card {
  position: relative;
  overflow: hidden;
  margin: auto 0;
  padding: 40px;
  border: 1px solid var(--border);
  border-radius: 24px;
  background: var(--surface);
  box-shadow:
    0 28px 80px rgba(0, 0, 0, 0.45),
    inset 0 1px 0 rgba(255, 255, 255, 0.045);
  backdrop-filter: blur(18px);
}

.card::before {
  position: absolute;
  top: 0;
  left: 32px;
  right: 32px;
  height: 1px;
  content: "";
  background: linear-gradient(90deg, transparent, rgba(245, 166, 35, 0.7), transparent);
}

.eyebrow {
  margin: 0 0 12px;
  color: var(--amber-bright);
  font-size: 11px;
  font-weight: 760;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

h1 {
  max-width: 520px;
  margin: 0;
  color: var(--text);
  font-size: clamp(29px, 7vw, 40px);
  font-weight: 740;
  letter-spacing: -0.04em;
  line-height: 1.08;
}

.lede {
  max-width: 520px;
  margin: 17px 0 0;
  color: var(--muted);
  font-size: 16px;
}

.status-icon {
  width: 48px;
  height: 48px;
  margin-bottom: 26px;
  display: grid;
  place-items: center;
  border: 1px solid rgba(255, 129, 122, 0.28);
  border-radius: 15px;
  color: var(--red);
  background: var(--red-soft);
  font-size: 23px;
  font-weight: 700;
}

.context {
  margin: 30px 0 0;
  padding: 18px;
  border: 1px solid var(--border);
  border-radius: 15px;
  background: var(--surface-soft);
}

.context-row {
  display: grid;
  grid-template-columns: 124px minmax(0, 1fr);
  gap: 14px;
  align-items: baseline;
}

.context-row + .context-row {
  margin-top: 13px;
  padding-top: 13px;
  border-top: 1px solid var(--border);
}

.context-label {
  color: var(--faint);
  font-size: 12px;
  font-weight: 650;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.context-value {
  min-width: 0;
  overflow-wrap: anywhere;
  color: var(--text);
  font-size: 14px;
  font-weight: 620;
}

code {
  color: #c8d2e7;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 12px;
  font-weight: 500;
}

.permission {
  margin-top: 18px;
  padding: 20px;
  display: grid;
  grid-template-columns: 38px minmax(0, 1fr);
  gap: 14px;
  border: 1px solid rgba(245, 166, 35, 0.2);
  border-radius: 16px;
  background: var(--amber-soft);
}

.permission-icon {
  width: 38px;
  height: 38px;
  display: grid;
  place-items: center;
  border-radius: 11px;
  color: var(--amber-bright);
  background: rgba(245, 166, 35, 0.14);
  font-size: 18px;
}

.permission strong {
  display: block;
  color: var(--text);
  font-size: 14px;
  font-weight: 680;
}

.permission p {
  margin: 4px 0 0;
  color: var(--muted);
  font-size: 13px;
}

.trust-note {
  margin: 18px 0 0;
  display: flex;
  gap: 10px;
  color: var(--faint);
  font-size: 12px;
}

.trust-note-symbol {
  flex: 0 0 auto;
  color: var(--amber);
}

.actions {
  margin-top: 28px;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 12px;
}

button {
  min-height: 48px;
  padding: 0 20px;
  border: 1px solid transparent;
  border-radius: 12px;
  font: inherit;
  font-size: 14px;
  font-weight: 720;
  cursor: pointer;
}

button:focus-visible {
  outline: 3px solid rgba(245, 166, 35, 0.28);
  outline-offset: 3px;
}

.primary {
  color: #171005;
  background: linear-gradient(180deg, var(--amber-bright), var(--amber));
  box-shadow: 0 10px 28px rgba(245, 166, 35, 0.18);
}

.primary:hover {
  filter: brightness(1.06);
}

.secondary {
  color: var(--muted);
  border-color: var(--border);
  background: transparent;
}

.secondary:hover {
  color: var(--text);
  border-color: var(--border-strong);
  background: var(--surface-soft);
}

.error-note {
  margin: 28px 0 0;
  padding: 15px 16px;
  border: 1px solid var(--border);
  border-radius: 13px;
  color: var(--muted);
  background: var(--surface-soft);
  font-size: 13px;
}

.footer {
  align-self: center;
  margin-top: 28px;
  display: flex;
  align-items: center;
  gap: 8px;
  color: #67738a;
  font-size: 11px;
  letter-spacing: 0.02em;
}

.footer-lock {
  color: var(--amber);
  font-size: 10px;
}

@media (max-width: 560px) {
  .shell {
    width: min(100% - 24px, 640px);
    padding: 24px 0 20px;
  }

  .card {
    padding: 28px 22px;
    border-radius: 20px;
  }

  .context-row {
    grid-template-columns: 1fr;
    gap: 4px;
  }

  .actions {
    grid-template-columns: 1fr;
  }

  .primary {
    order: -1;
  }
}

@media (prefers-reduced-transparency: reduce) {
  .card {
    background: #111827;
    backdrop-filter: none;
  }
}
"#;

fn oauth_page(title: &str, content: &str) -> String {
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#080c16">
  <meta name="color-scheme" content="dark">
  <title>{title} · Kioku</title>
  <style>{OAUTH_PAGE_STYLE}</style>
</head>
<body>
  <main class="shell">
    <div class="brand" aria-label="Kioku">
      <span class="brand-mark" aria-hidden="true">記</span>
      <span>Kioku</span>
    </div>
    {content}
    <div class="footer">
      <span class="footer-lock" aria-hidden="true">◆</span>
      <span>Protected by Kioku’s confidential cloud</span>
    </div>
  </main>
</body>
</html>"##,
        title = html_escape(title),
    )
}

// ── Discovery ───────────────────────────────────────────────────────────────────

async fn authz_metadata(State(s): State<Arc<CpState>>) -> Json<serde_json::Value> {
    let base = &s.config.base_url;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "registration_endpoint": format!("{base}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
}

async fn resource_metadata(State(s): State<Arc<CpState>>) -> Json<serde_json::Value> {
    let base = &s.config.base_url;
    Json(json!({ "resource": base, "authorization_servers": [base] }))
}

// ── Dynamic Client Registration ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterBody {
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
}

enum ClientRegistration {
    Existing(String),
    Created(String),
    AtCapacity,
}

fn register_client_conn(
    conn: &rusqlite::Connection,
    proposed_client_id: &str,
    client_name: Option<&str>,
    redirect_uris_json: &str,
) -> crate::error::Result<(ClientRegistration, bool)> {
    let tx = conn.unchecked_transaction()?;
    let existing: Option<String> = tx
        .query_row(
            "SELECT client_id FROM oauth_clients WHERE redirect_uris = ?1 LIMIT 1",
            [redirect_uris_json],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(client_id) = existing {
        tx.rollback()?;
        return Ok((ClientRegistration::Existing(client_id), false));
    }

    let mut count: i64 = tx.query_row("SELECT count(*) FROM oauth_clients", [], |r| r.get(0))?;
    let mut reclaimed = 0;
    if count >= MAX_OAUTH_CLIENTS {
        reclaimed = tx.execute(
            "DELETE FROM oauth_clients \
             WHERE created_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1) \
               AND NOT EXISTS (SELECT 1 FROM oauth_consents p \
                               WHERE p.client_id = oauth_clients.client_id \
                                 AND p.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
               AND NOT EXISTS (SELECT 1 FROM oauth_authorization_codes a \
                               WHERE a.client_id = oauth_clients.client_id \
                                 AND a.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
               AND NOT EXISTS (SELECT 1 FROM refresh_tokens r \
                               WHERE r.client_id = oauth_clients.client_id \
                                 AND r.revoked = 0 \
                                 AND r.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            [format!("-{UNUSED_CLIENT_TTL_SECS} seconds")],
        )?;
        count = tx.query_row("SELECT count(*) FROM oauth_clients", [], |r| r.get(0))?;
    }
    if count >= MAX_OAUTH_CLIENTS {
        if reclaimed == 0 {
            tx.rollback()?;
        } else {
            tx.commit()?;
        }
        return Ok((ClientRegistration::AtCapacity, reclaimed != 0));
    }

    tx.execute(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?1, ?2, ?3)",
        rusqlite::params![proposed_client_id, client_name, redirect_uris_json],
    )?;
    tx.commit()?;
    Ok((
        ClientRegistration::Created(proposed_client_id.to_string()),
        true,
    ))
}

async fn register(State(s): State<Arc<CpState>>, Json(body): Json<RegisterBody>) -> Response {
    let (name, redirect_uris) = match validated_registration(body) {
        Ok(validated) => validated,
        Err(description) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_client_metadata",
                    "error_description": description,
                })),
            )
                .into_response()
        }
    };

    let proposed_client_id = tokens::new_uuid();
    let uris_json = match serde_json::to_string(&redirect_uris) {
        Ok(json) => json,
        Err(_) => return server_error(),
    };
    let res = s
        .control
        .write_if_changed(move |conn| {
            register_client_conn(conn, &proposed_client_id, name.as_deref(), &uris_json)
        })
        .await;
    match res {
        Ok(ClientRegistration::Existing(client_id) | ClientRegistration::Created(client_id)) => (
            StatusCode::CREATED,
            Json(json!({
                "client_id": client_id,
                "redirect_uris": redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            })),
        )
            .into_response(),
        Ok(ClientRegistration::AtCapacity) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "invalid_client_metadata",
                "error_description": "client registration capacity reached",
            })),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "register failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "server_error"})),
            )
                .into_response()
        }
    }
}

// ── /authorize ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AuthorizeQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    response_type: Option<String>,
}

async fn authorize(State(s): State<Arc<CpState>>, Query(q): Query<AuthorizeQuery>) -> Response {
    if q.response_type.as_deref() != Some("code") {
        return bad_request("unsupported_response_type");
    }
    let Some(code_challenge) = q.code_challenge.clone() else {
        return bad_request_desc("invalid_request", "code_challenge required");
    };
    if !is_valid_pkce_challenge(&code_challenge) {
        return bad_request_desc("invalid_request", "invalid S256 code_challenge");
    }
    if q.code_challenge_method.as_deref() != Some("S256") {
        return bad_request_desc("invalid_request", "code_challenge_method must be S256");
    }
    let (client_id, redirect_uri) = match (q.client_id.clone(), q.redirect_uri.clone()) {
        (Some(c), Some(r)) => (c, r),
        _ => return bad_request_desc("invalid_request", "client_id and redirect_uri required"),
    };
    if !is_valid_client_id(&client_id) || !is_valid_redirect_uri(&redirect_uri) {
        return bad_request_desc("invalid_request", "invalid client_id or redirect_uri");
    }
    let client_state = q.state.unwrap_or_default();
    if client_state.len() > MAX_CLIENT_STATE_BYTES || client_state.chars().any(char::is_control) {
        return bad_request_desc("invalid_request", "state is invalid or too long");
    }

    // Validate client + exact redirect_uri match.
    let cid = client_id.clone();
    let registered: Option<String> = match s
        .control
        .read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT redirect_uris FROM oauth_clients WHERE client_id = ?1",
                    [&cid],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
        })
        .await
    {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "server_error"})),
            )
                .into_response()
        }
    };
    let Some(uris_json) = registered else {
        return bad_request("invalid_client");
    };
    let uris: Vec<String> = match serde_json::from_str(&uris_json) {
        Ok(uris) => uris,
        Err(_) => return server_error(),
    };
    if !uris.contains(&redirect_uri) {
        return bad_request_desc("invalid_request", "redirect_uri mismatch");
    }

    let state_jwt = match tokens::issue_state(
        &s.config.jwt_secrets[0],
        &tokens::StateClaims {
            client_id: client_id.clone(),
            redirect_uri,
            client_state,
            code_challenge,
            exp: 0,
        },
    ) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "server_error"})),
            )
                .into_response()
        }
    };

    let base = &s.config.base_url;
    let mut url = String::from("https://accounts.google.com/o/oauth2/v2/auth?");
    url.push_str(
        &serde_urlencoded::to_string([
            ("client_id", s.config.google_web_client_id.as_str()),
            ("redirect_uri", &format!("{base}/oauth/google/callback")),
            ("response_type", "code"),
            ("scope", "openid email profile"),
            ("state", &state_jwt),
            ("prompt", "select_account"),
        ])
        .unwrap_or_default(),
    );
    redirect_302(&url)
}

// ── Google callback ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GoogleTokenResp {
    id_token: String,
}

fn callback_error(status: StatusCode, heading: &'static str, message: &'static str) -> Response {
    let content = format!(
        r#"<section class="card" aria-labelledby="page-title">
      <div class="status-icon" aria-hidden="true">!</div>
      <p class="eyebrow">Connection interrupted</p>
      <h1 id="page-title">{}</h1>
      <p class="lede">{}</p>
      <p class="error-note">You can close this window and return to the app that started the connection.</p>
    </section>"#,
        html_escape(heading),
        html_escape(message),
    );
    let body = oauth_page(heading, &content);
    (
        status,
        [
            ("Cache-Control", "no-store"),
            (
                "Content-Security-Policy",
                "default-src 'none'; style-src 'sha256-DVNu+rDXsiq2UWPkz03Yd5TzilN7mANE0PgSufIM2Is='; base-uri 'none'; frame-ancestors 'none'",
            ),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ],
        Html(body),
    )
        .into_response()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn redirect_origin(redirect_uri: &str) -> Option<String> {
    let uri = Uri::from_str(redirect_uri).ok()?;
    Some(format!(
        "{}://{}",
        uri.scheme_str()?,
        uri.authority()?.as_str()
    ))
}

struct RegisteredClient {
    name: Option<String>,
}

fn registered_client_conn(
    conn: &rusqlite::Connection,
    client_id: &str,
    redirect_uri: &str,
) -> crate::error::Result<Option<RegisteredClient>> {
    let row: Option<(Option<String>, String)> = conn
        .query_row(
            "SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = ?1",
            [client_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((name, redirect_uris_json)) = row else {
        return Ok(None);
    };
    let redirect_uris: Vec<String> = serde_json::from_str(&redirect_uris_json)?;
    if !is_valid_redirect_uri(redirect_uri) || !redirect_uris.iter().any(|uri| uri == redirect_uri)
    {
        return Ok(None);
    }
    Ok(Some(RegisteredClient { name }))
}

fn consent_page(client_name: Option<&str>, origin: &str, consent_token: &str) -> Response {
    let display_name = client_name
        .map(|name| name.chars().take(MAX_CLIENT_NAME_BYTES).collect::<String>())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Unnamed OAuth client".to_string());
    let content = format!(
        r#"<section class="card" aria-labelledby="page-title">
      <p class="eyebrow">MCP connection request</p>
      <h1 id="page-title">Connect this app to your memory?</h1>
      <p class="lede">Review the app and destination before giving it access to your Kioku archive.</p>
      <div class="context">
        <div class="context-row">
          <span class="context-label">Requesting app</span>
          <span class="context-value">{}</span>
        </div>
        <div class="context-row">
          <span class="context-label">Redirects to</span>
          <code>{}</code>
        </div>
      </div>
      <div class="permission">
        <span class="permission-icon" aria-hidden="true">↗</span>
        <div>
          <strong>Full archive access</strong>
          <p>Search, read, and export your Kioku archive. The app can stay connected until you revoke access.</p>
        </div>
      </div>
      <p class="trust-note">
        <span class="trust-note-symbol" aria-hidden="true">◆</span>
        <span>Only continue if you recognize this app and trust the redirect destination above.</span>
      </p>
      <form method="post" action="/oauth/consent">
        <input type="hidden" name="consent_token" value="{}">
        <div class="actions">
          <button class="primary" type="submit" name="decision" value="approve">Allow archive access</button>
          <button class="secondary" type="submit" name="decision" value="deny">Cancel</button>
        </div>
      </form>
    </section>"#,
        html_escape(&display_name),
        html_escape(origin),
        html_escape(consent_token),
    );
    let body = oauth_page("Connect to Kioku", &content);
    // Browsers enforce `form-action` across redirects from a submitted form.
    // Allow the already-validated registered client origin so the consent POST's
    // 302 can complete without permitting arbitrary form destinations.
    let content_security_policy = format!(
        "default-src 'none'; style-src 'sha256-DVNu+rDXsiq2UWPkz03Yd5TzilN7mANE0PgSufIM2Is='; \
         form-action 'self' {origin}; base-uri 'none'; frame-ancestors 'none'"
    );
    (
        StatusCode::OK,
        [
            ("Cache-Control", "no-store".to_string()),
            ("Content-Security-Policy", content_security_policy),
            ("Referrer-Policy", "no-referrer".to_string()),
            ("X-Content-Type-Options", "nosniff".to_string()),
            ("X-Frame-Options", "DENY".to_string()),
        ],
        Html(body),
    )
        .into_response()
}

fn store_pending_consent_conn(
    conn: &rusqlite::Connection,
    consent_hash: &str,
    user_id: &str,
    client_id: &str,
    redirect_uri: &str,
) -> crate::error::Result<bool> {
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "DELETE FROM oauth_consents \
         WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        [],
    )?;
    let inserted = tx.execute(
        "INSERT INTO oauth_consents (consent_hash, user_id, client_id, redirect_uri, expires_at) \
         SELECT ?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?5) \
         WHERE EXISTS (SELECT 1 FROM users WHERE id = ?2 AND status = 'active') \
           AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = ?3)",
        rusqlite::params![
            consent_hash,
            user_id,
            client_id,
            redirect_uri,
            format!("+{AUTH_CODE_TTL_SECS} seconds")
        ],
    )?;
    if inserted != 1 {
        tx.rollback()?;
        return Ok(false);
    }
    tx.commit()?;
    Ok(true)
}

fn approve_consent_conn(
    conn: &rusqlite::Connection,
    consent_hash: &str,
    code_hash: &str,
    user_id: &str,
    client_id: &str,
    redirect_uri: &str,
) -> crate::error::Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let consumed = tx.execute(
        "DELETE FROM oauth_consents \
         WHERE consent_hash = ?1 AND user_id = ?2 AND client_id = ?3 AND redirect_uri = ?4 \
           AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') \
           AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND status = 'active') \
           AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = ?3)",
        rusqlite::params![consent_hash, user_id, client_id, redirect_uri],
    )?;
    if consumed != 1 {
        tx.rollback()?;
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO oauth_authorization_codes (code_hash, user_id, client_id, expires_at) \
         VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4))",
        rusqlite::params![
            code_hash,
            user_id,
            client_id,
            format!("+{AUTH_CODE_TTL_SECS} seconds")
        ],
    )?;
    tx.commit()?;
    Ok(true)
}

async fn google_callback(
    State(s): State<Arc<CpState>>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if q.error.is_some() {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Authentication failed",
            "Authentication was not completed.",
        );
    }
    let (Some(code), Some(state_jwt)) = (q.code, q.state) else {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Authentication failed",
            "The callback was missing required parameters.",
        );
    };
    let state = match tokens::verify_state(&s.config.jwt_secrets[0], &state_jwt) {
        Ok(st) => st,
        Err(_) => {
            // Try rotation-fallback secret(s).
            match s
                .config
                .jwt_secrets
                .iter()
                .skip(1)
                .find_map(|sec| tokens::verify_state(sec, &state_jwt).ok())
            {
                Some(st) => st,
                None => {
                    return callback_error(
                        StatusCode::BAD_REQUEST,
                        "Authentication failed",
                        "The authorization request is invalid or expired.",
                    )
                }
            }
        }
    };

    let base = &s.config.base_url;
    let body = serde_urlencoded::to_string([
        ("code", code.as_str()),
        ("client_id", s.config.google_web_client_id.as_str()),
        ("client_secret", s.config.google_web_client_secret.as_str()),
        ("redirect_uri", &format!("{base}/oauth/google/callback")),
        ("grant_type", "authorization_code"),
    ])
    .unwrap_or_default();

    let http = super::bounded_http_client();
    let resp = http
        .post("https://oauth2.googleapis.com/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await;
    let token_data: GoogleTokenResp = match resp {
        Ok(r) if r.status().is_success() => match r.json().await {
            Ok(t) => t,
            Err(_) => {
                return callback_error(
                    StatusCode::BAD_GATEWAY,
                    "Authentication failed",
                    "The identity provider returned an invalid response.",
                )
            }
        },
        _ => {
            return callback_error(
                StatusCode::BAD_GATEWAY,
                "Authentication failed",
                "The identity provider could not complete authentication.",
            )
        }
    };

    let (google_sub, email) = match s.user_verifier.verify(&token_data.id_token).await {
        Ok(v) => v,
        Err(_) => {
            return callback_error(
                StatusCode::BAD_GATEWAY,
                "Authentication failed",
                "The identity response could not be verified.",
            )
        }
    };
    if !s.config.email_allowed(&email) {
        return callback_error(
            StatusCode::FORBIDDEN,
            "Access denied",
            "This account is not authorized.",
        );
    }

    let user = match s.control.upsert_user(&google_sub, &email).await {
        Ok(u) => u,
        Err(_) => {
            return callback_error(
                StatusCode::FORBIDDEN,
                "Access denied",
                "This account is unavailable.",
            )
        }
    };

    let (client_id, redirect_uri) = (state.client_id.clone(), state.redirect_uri.clone());
    let registered = s
        .control
        .read({
            let client_id = client_id.clone();
            let redirect_uri = redirect_uri.clone();
            move |conn| registered_client_conn(conn, &client_id, &redirect_uri)
        })
        .await;
    let RegisteredClient { name } = match registered {
        Ok(Some(client)) => client,
        _ => {
            return callback_error(
                StatusCode::BAD_REQUEST,
                "Authentication failed",
                "The OAuth client registration is unavailable.",
            )
        }
    };
    let Some(origin) = redirect_origin(&redirect_uri) else {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Authentication failed",
            "The OAuth client redirect is invalid.",
        );
    };

    let consent_token = match tokens::issue_consent(
        &s.config.jwt_secrets[0],
        &tokens::ConsentClaims {
            user_id: user.id.clone(),
            client_id: client_id.clone(),
            redirect_uri: redirect_uri.clone(),
            client_state: state.client_state,
            code_challenge: state.code_challenge,
            exp: 0,
        },
    ) {
        Ok(token) => token,
        Err(_) => {
            return callback_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication failed",
                "The authorization could not be completed.",
            )
        }
    };
    let consent_hash = tokens::sha256_hex(&consent_token);
    let user_id = user.id;
    let stored = s
        .control
        .write_if_changed(move |conn| {
            let stored = store_pending_consent_conn(
                conn,
                &consent_hash,
                &user_id,
                &client_id,
                &redirect_uri,
            )?;
            Ok((stored, stored))
        })
        .await;
    if !matches!(stored, Ok(true)) {
        return callback_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Authentication failed",
            "The authorization could not be completed.",
        );
    }
    consent_page(name.as_deref(), &origin, &consent_token)
}

#[derive(Deserialize)]
struct ConsentForm {
    consent_token: Option<String>,
    decision: Option<String>,
}

async fn consent(State(s): State<Arc<CpState>>, body: String) -> Response {
    if body.len() > 8192 {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Authorization failed",
            "The consent response is invalid.",
        );
    }
    let form: ConsentForm = match serde_urlencoded::from_str(&body) {
        Ok(form) => form,
        Err(_) => {
            return callback_error(
                StatusCode::BAD_REQUEST,
                "Authorization failed",
                "The consent response is invalid.",
            )
        }
    };
    if form.decision.as_deref() != Some("approve") {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Authorization denied",
            "Full archive access was not approved.",
        );
    }
    let Some(consent_token) = form.consent_token else {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Authorization failed",
            "The consent response is invalid.",
        );
    };
    if consent_token.len() > 4096 || !consent_token.is_ascii() {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Authorization failed",
            "The consent response is invalid or expired.",
        );
    }
    let claims = match s
        .config
        .jwt_secrets
        .iter()
        .find_map(|secret| tokens::verify_consent(secret, &consent_token).ok())
    {
        Some(claims) => claims,
        None => {
            return callback_error(
                StatusCode::BAD_REQUEST,
                "Authorization failed",
                "The consent response is invalid or expired.",
            )
        }
    };
    if !is_valid_client_id(&claims.client_id)
        || !is_valid_redirect_uri(&claims.redirect_uri)
        || !is_valid_pkce_challenge(&claims.code_challenge)
        || claims.client_state.len() > MAX_CLIENT_STATE_BYTES
    {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Authorization failed",
            "The consent response is invalid.",
        );
    }

    let registered = s
        .control
        .read({
            let client_id = claims.client_id.clone();
            let redirect_uri = claims.redirect_uri.clone();
            move |conn| registered_client_conn(conn, &client_id, &redirect_uri)
        })
        .await;
    if !matches!(registered, Ok(Some(_))) {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Authorization failed",
            "The OAuth client registration is unavailable.",
        );
    }

    let auth_code = match tokens::issue_auth_code(
        &s.config.jwt_secrets[0],
        &claims.user_id,
        &claims.client_id,
        &claims.code_challenge,
    ) {
        Ok(code) => code,
        Err(_) => return server_error(),
    };
    let consent_hash = tokens::sha256_hex(&consent_token);
    let code_hash = tokens::sha256_hex(&auth_code);
    let (user_id, client_id, redirect_uri) = (
        claims.user_id.clone(),
        claims.client_id.clone(),
        claims.redirect_uri.clone(),
    );
    let approved = s
        .control
        .write_if_changed(move |conn| {
            let approved = approve_consent_conn(
                conn,
                &consent_hash,
                &code_hash,
                &user_id,
                &client_id,
                &redirect_uri,
            )?;
            Ok((approved, approved))
        })
        .await;
    match approved {
        Ok(true) => {}
        Ok(false) => {
            return callback_error(
                StatusCode::BAD_REQUEST,
                "Authorization failed",
                "This consent response was already used or has expired.",
            )
        }
        Err(_) => return server_error(),
    }

    let mut params = vec![("code", auth_code.as_str())];
    if !claims.client_state.is_empty() {
        params.push(("state", claims.client_state.as_str()));
    }
    let separator = if claims.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let redirect = format!(
        "{}{}{}",
        claims.redirect_uri,
        separator,
        serde_urlencoded::to_string(&params).unwrap_or_default()
    );
    redirect_302(&redirect)
}

// ── Gmail OAuth Callback and Connection ──────────────────────────────────────────

#[derive(Deserialize)]
struct GmailTokenResp {
    #[serde(rename = "access_token")]
    _access_token: String,
    refresh_token: Option<String>,
    id_token: String,
}

async fn gmail_callback(State(s): State<Arc<CpState>>, Query(q): Query<CallbackQuery>) -> Response {
    if q.error.is_some() {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Gmail authorization failed",
            "Gmail authorization was not completed.",
        );
    }
    let (Some(code), Some(state_jwt)) = (q.code, q.state) else {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Gmail authorization failed",
            "The callback was missing required parameters.",
        );
    };

    let gmail_state = match tokens::verify_gmail_state(&s.config.jwt_secrets[0], &state_jwt) {
        Ok(st) => st,
        Err(_) => {
            match s
                .config
                .jwt_secrets
                .iter()
                .skip(1)
                .find_map(|sec| tokens::verify_gmail_state(sec, &state_jwt).ok())
            {
                Some(st) => st,
                None => {
                    return callback_error(
                        StatusCode::BAD_REQUEST,
                        "Gmail authorization failed",
                        "The authorization request is invalid or expired.",
                    )
                }
            }
        }
    };

    let base = &s.config.base_url;
    let body = serde_urlencoded::to_string([
        ("code", code.as_str()),
        ("client_id", s.config.google_web_client_id.as_str()),
        ("client_secret", s.config.google_web_client_secret.as_str()),
        ("redirect_uri", &format!("{base}/oauth/gmail/callback")),
        ("grant_type", "authorization_code"),
    ])
    .unwrap_or_default();

    let http = super::bounded_http_client();
    let resp = http
        .post("https://oauth2.googleapis.com/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await;

    let token_data: GmailTokenResp = match resp {
        Ok(r) if r.status().is_success() => match r.json().await {
            Ok(t) => t,
            Err(_) => {
                return callback_error(
                    StatusCode::BAD_GATEWAY,
                    "Gmail authorization failed",
                    "The identity provider returned an invalid response.",
                )
            }
        },
        _ => {
            return callback_error(
                StatusCode::BAD_GATEWAY,
                "Gmail authorization failed",
                "The identity provider could not complete authorization.",
            )
        }
    };

    let (returned_sub, returned_email) = match s.user_verifier.verify(&token_data.id_token).await {
        Ok(v) => v,
        Err(_) => {
            return callback_error(
                StatusCode::BAD_GATEWAY,
                "Gmail authorization failed",
                "The identity response could not be verified.",
            )
        }
    };

    let user_id = gmail_state.user_id;
    let expected_email = match s.control.user_email(&user_id).await {
        Ok(Some(email)) => email,
        _ => {
            return callback_error(
                StatusCode::UNAUTHORIZED,
                "Gmail authorization failed",
                "The Kioku account is unavailable.",
            )
        }
    };

    let dest_lower = returned_email.to_lowercase();
    if !dest_lower.ends_with("@gmail.com") && !dest_lower.ends_with("@googlemail.com") {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Gmail authorization failed",
            "This feature requires a personal Gmail account.",
        );
    }

    if expected_email.to_lowercase() != dest_lower {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Gmail authorization failed",
            "The authorized Google account does not match the Kioku account.",
        );
    }

    let Some(refresh_token) = token_data.refresh_token else {
        return callback_error(
            StatusCode::BAD_REQUEST,
            "Gmail authorization failed",
            "Reconnect Gmail and allow offline access.",
        );
    };

    let now_iso = crate::cp::isotime::format_epoch_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    );
    let config = crate::cp::control_store::GmailConfig {
        user_id: user_id.clone(),
        enabled: true,
        enabled_at: Some(now_iso),
        gmail_email: Some(returned_email),
        google_sub: Some(returned_sub),
        refresh_token: Some(refresh_token),
        reconnect_required: false,
    };

    if let Err(e) = s.control.upsert_gmail_config(config).await {
        tracing::error!(error = %e, "failed to save Gmail configuration");
        return callback_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Gmail authorization failed",
            "The authorization could not be saved.",
        );
    }

    let redirect_url = format!("{}/app#settings", s.config.web_origin);
    redirect_302(&redirect_url)
}

pub async fn connect_gmail_url(
    State(s): State<Arc<CpState>>,
    axum::Extension(user): axum::Extension<crate::cp::auth::AuthUser>,
) -> Response {
    let user_id = user.0;

    let email = match s.control.user_email(&user_id).await {
        Ok(Some(email)) => email,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
                .into_response()
        }
    };

    let email_lower = email.to_lowercase();
    if !email_lower.ends_with("@gmail.com") && !email_lower.ends_with("@googlemail.com") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "gmail_only", "message": "Only personal Gmail accounts support this feature"})),
        )
            .into_response();
    }

    let state_jwt = match tokens::issue_gmail_state(&s.config.jwt_secrets[0], &user_id) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "server_error"})),
            )
                .into_response()
        }
    };

    let base = &s.config.base_url;
    let mut url = String::from("https://accounts.google.com/o/oauth2/v2/auth?");
    url.push_str(
        &serde_urlencoded::to_string([
            ("client_id", s.config.google_web_client_id.as_str()),
            ("redirect_uri", &format!("{base}/oauth/gmail/callback")),
            ("response_type", "code"),
            (
                "scope",
                "openid email https://www.googleapis.com/auth/gmail.send",
            ),
            ("state", &state_jwt),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("include_granted_scopes", "true"),
        ])
        .unwrap_or_default(),
    );

    Json(json!({ "url": url })).into_response()
}

// ── /token ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    code_verifier: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
}

async fn token(State(s): State<Arc<CpState>>, body: String) -> Response {
    if body.len() > 8192 {
        return bad_request("invalid_request");
    }
    let form: TokenForm = match serde_urlencoded::from_str(&body) {
        Ok(f) => f,
        Err(_) => return bad_request("invalid_request"),
    };

    match form.grant_type.as_deref() {
        Some("authorization_code") => token_auth_code(s, form).await,
        Some("refresh_token") => token_refresh(s, form).await,
        other => bad_request_desc(
            "unsupported_grant_type",
            &format!("Unsupported grant_type: {}", other.unwrap_or("")),
        ),
    }
}

fn exchange_authorization_code_conn(
    conn: &rusqlite::Connection,
    code_hash: &str,
    user_id: &str,
    client_id: &str,
    refresh_hash: &str,
) -> crate::error::Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let consumed = tx.execute(
        "DELETE FROM oauth_authorization_codes \
         WHERE code_hash = ?1 AND user_id = ?2 AND client_id = ?3 \
           AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') \
           AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND status = 'active') \
           AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = ?3)",
        rusqlite::params![code_hash, user_id, client_id],
    )?;
    if consumed != 1 {
        tx.rollback()?;
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
         VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4))",
        rusqlite::params![
            refresh_hash,
            user_id,
            client_id,
            format!("+{REFRESH_TTL_SECS} seconds")
        ],
    )?;
    tx.commit()?;
    Ok(true)
}

fn rotate_refresh_token_conn(
    conn: &rusqlite::Connection,
    old_hash: &str,
    client_id: &str,
    new_hash: &str,
) -> crate::error::Result<Option<String>> {
    let tx = conn.unchecked_transaction()?;
    let user_id: Option<String> = tx
        .query_row(
            "SELECT r.user_id FROM refresh_tokens r \
             JOIN users u ON u.id = r.user_id AND u.status = 'active' \
             JOIN oauth_clients c ON c.client_id = r.client_id \
             WHERE r.token_hash = ?1 AND r.client_id = ?2 AND r.revoked = 0 \
               AND r.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            rusqlite::params![old_hash, client_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(user_id) = user_id else {
        tx.rollback()?;
        return Ok(None);
    };

    let updated = tx.execute(
        "UPDATE refresh_tokens SET revoked = 1 \
         WHERE token_hash = ?1 AND client_id = ?2 AND revoked = 0",
        rusqlite::params![old_hash, client_id],
    )?;
    if updated != 1 {
        tx.rollback()?;
        return Ok(None);
    }
    tx.execute(
        "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
         VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4))",
        rusqlite::params![
            new_hash,
            user_id,
            client_id,
            format!("+{REFRESH_TTL_SECS} seconds")
        ],
    )?;
    tx.commit()?;
    Ok(Some(user_id))
}

async fn token_auth_code(s: Arc<CpState>, form: TokenForm) -> Response {
    let Some(code) = form.code else {
        return bad_request_desc("invalid_request", "code required");
    };
    if code.len() > 4096 || !code.is_ascii() {
        return bad_request_desc("invalid_grant", "Invalid or expired code");
    }
    let claims = match s
        .config
        .jwt_secrets
        .iter()
        .find_map(|sec| tokens::verify_auth_code(sec, &code).ok())
    {
        Some(c) => c,
        None => return bad_request_desc("invalid_grant", "Invalid or expired code"),
    };
    let Some(verifier) = form.code_verifier else {
        return bad_request_desc("invalid_request", "code_verifier required");
    };
    if !is_valid_pkce_verifier(&verifier) {
        return bad_request_desc("invalid_request", "invalid code_verifier");
    }
    if tokens::pkce_s256(&verifier) != claims.code_challenge {
        return bad_request_desc("invalid_grant", "PKCE verification failed");
    }
    let Some(client_id) = form.client_id else {
        return bad_request_desc("invalid_request", "client_id required");
    };
    if !is_valid_client_id(&client_id)
        || client_id != claims.client_id
        || !is_valid_pkce_challenge(&claims.code_challenge)
    {
        return bad_request_desc("invalid_grant", "client_id mismatch");
    }

    let access = match tokens::issue_access_token(
        &s.config.jwt_secrets[0],
        &s.config.base_url,
        &claims.user_id,
    ) {
        Ok(t) => t,
        Err(_) => return server_error(),
    };
    let raw_refresh = tokens::random_token_hex();
    let refresh_hash = tokens::sha256_hex(&raw_refresh);
    let code_hash = tokens::sha256_hex(&code);
    let (user_id, stored_client_id) = (claims.user_id, client_id);
    let exchanged = s
        .control
        .write_if_changed(move |conn| {
            let exchanged = exchange_authorization_code_conn(
                conn,
                &code_hash,
                &user_id,
                &stored_client_id,
                &refresh_hash,
            )?;
            Ok((exchanged, exchanged))
        })
        .await;
    match exchanged {
        Ok(true) => token_response(&access, &raw_refresh),
        Ok(false) => bad_request_desc("invalid_grant", "Invalid or already-used code"),
        Err(_) => server_error(),
    }
}

async fn token_refresh(s: Arc<CpState>, form: TokenForm) -> Response {
    let Some(incoming) = form.refresh_token else {
        return bad_request_desc("invalid_request", "refresh_token required");
    };
    let Some(client_id) = form.client_id else {
        return bad_request_desc("invalid_request", "client_id required");
    };
    if incoming.len() != 64
        || !incoming.bytes().all(|b| b.is_ascii_hexdigit())
        || !is_valid_client_id(&client_id)
    {
        return bad_request_desc("invalid_grant", "Invalid refresh token");
    }

    let old_hash = tokens::sha256_hex(&incoming);
    let raw_refresh = tokens::random_token_hex();
    let new_hash = tokens::sha256_hex(&raw_refresh);
    let rotated = s
        .control
        .write_if_changed(move |conn| {
            let user_id = rotate_refresh_token_conn(conn, &old_hash, &client_id, &new_hash)?;
            Ok((user_id.clone(), user_id.is_some()))
        })
        .await;
    let user_id = match rotated {
        Ok(Some(user_id)) => user_id,
        Ok(None) => return bad_request_desc("invalid_grant", "Invalid refresh token"),
        Err(_) => return server_error(),
    };
    let access =
        match tokens::issue_access_token(&s.config.jwt_secrets[0], &s.config.base_url, &user_id) {
            Ok(t) => t,
            Err(_) => return server_error(),
        };
    token_response(&access, &raw_refresh)
}

fn token_response(access: &str, refresh: &str) -> Response {
    (
        [
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
            ("X-Content-Type-Options", "nosniff"),
        ],
        Json(json!({
            "access_token": access,
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": refresh,
            "scope": "",
        })),
    )
        .into_response()
}

fn bad_request(err: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": err}))).into_response()
}
fn bad_request_desc(err: &str, desc: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": err, "error_description": desc})),
    )
        .into_response()
}
fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "server_error"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use base64::Engine as _;
    use rusqlite::Connection;
    use sha2::{Digest, Sha256};

    const CLIENT: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_CLIENT: &str = "22222222-2222-4222-8222-222222222222";
    const USER: &str = "33333333-3333-4333-8333-333333333333";
    const REDIRECT: &str = "https://client.example/oauth/callback";

    fn assert_exact_style_hash(csp: &str) {
        let digest = Sha256::digest(OAUTH_PAGE_STYLE.as_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
        assert!(
            csp.contains(&format!("style-src 'sha256-{encoded}'")),
            "CSP must authorize the exact embedded OAuth stylesheet"
        );
    }

    fn oauth_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (id TEXT PRIMARY KEY, status TEXT NOT NULL); \
             CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL); \
             CREATE TABLE oauth_consents (consent_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, expires_at TEXT NOT NULL); \
             CREATE TABLE oauth_authorization_codes (code_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, client_id TEXT NOT NULL, expires_at TEXT NOT NULL); \
             CREATE TABLE refresh_tokens (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, client_id TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (id, status) VALUES (?1, 'active')",
            [USER],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?1, 'Test Client', ?2)",
            rusqlite::params![CLIENT, serde_json::to_string(&vec![REDIRECT]).unwrap()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?1, 'Other Client', ?2)",
            rusqlite::params![OTHER_CLIENT, serde_json::to_string(&vec!["https://other.example/cb"]).unwrap()],
        )
        .unwrap();
        conn
    }

    #[test]
    fn redirect_validation_is_strict() {
        assert!(is_valid_redirect_uri(REDIRECT));
        assert!(is_valid_redirect_uri("http://127.0.0.1:49152/callback"));
        assert!(is_valid_redirect_uri("http://localhost:8080/callback"));
        assert!(is_valid_redirect_uri("http://[::1]:8080/callback"));

        for invalid in [
            "http://client.example/callback",
            "https://user@client.example/callback",
            "https://client.example/callback#fragment",
            "http://evil.example\\@localhost/callback",
            "javascript:alert(1)",
            "https://client.example/callback\nSet-Cookie:x",
        ] {
            assert!(!is_valid_redirect_uri(invalid), "accepted {invalid:?}");
        }
        assert!(!is_valid_redirect_uri(&format!(
            "https://client.example/{}",
            "x".repeat(MAX_REDIRECT_URI_BYTES)
        )));
    }

    #[test]
    fn registration_validation_bounds_and_canonicalizes() {
        let (_, uris) = validated_registration(RegisterBody {
            client_name: Some("  Client  ".into()),
            redirect_uris: vec!["https://b.example/cb".into(), "https://a.example/cb".into()],
        })
        .unwrap();
        assert_eq!(uris[0], "https://a.example/cb");

        assert!(validated_registration(RegisterBody {
            client_name: Some("x".repeat(MAX_CLIENT_NAME_BYTES + 1)),
            redirect_uris: vec![REDIRECT.into()],
        })
        .is_err());
        assert!(validated_registration(RegisterBody {
            client_name: None,
            redirect_uris: vec![REDIRECT.into(), REDIRECT.into()],
        })
        .is_err());
        assert!(validated_registration(RegisterBody {
            client_name: None,
            redirect_uris: (0..=MAX_REDIRECT_URIS)
                .map(|i| format!("https://client{i}.example/cb"))
                .collect(),
        })
        .is_err());
    }

    #[test]
    fn registration_is_idempotent_for_the_same_redirect_set() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL);",
        )
        .unwrap();
        let json = serde_json::to_string(&vec![REDIRECT]).unwrap();
        let (first, changed) = register_client_conn(&conn, CLIENT, Some("Client"), &json).unwrap();
        assert!(matches!(first, ClientRegistration::Created(_)));
        assert!(changed);
        let (second, changed) =
            register_client_conn(&conn, OTHER_CLIENT, Some("Spoof"), &json).unwrap();
        assert!(matches!(second, ClientRegistration::Existing(ref id) if id == CLIENT));
        assert!(!changed);
        assert_eq!(
            conn.query_row("SELECT count(*) FROM oauth_clients", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn registration_cap_bounds_control_database_growth() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))); \
             CREATE TABLE oauth_consents (client_id TEXT NOT NULL, expires_at TEXT NOT NULL); \
             CREATE TABLE oauth_authorization_codes (client_id TEXT NOT NULL, expires_at TEXT NOT NULL); \
             CREATE TABLE refresh_tokens (client_id TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0); \
             WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x + 1 FROM n WHERE x < 256) \
             INSERT INTO oauth_clients (client_id, redirect_uris) \
             SELECT printf('client-%d', x), printf('[\"https://client-%d.example/cb\"]', x) FROM n;",
        )
        .unwrap();
        let (result, changed) = register_client_conn(
            &conn,
            CLIENT,
            Some("Overflow"),
            "[\"https://overflow.example/cb\"]",
        )
        .unwrap();
        assert!(matches!(result, ClientRegistration::AtCapacity));
        assert!(!changed);
    }

    #[test]
    fn registration_reclaims_only_stale_unreferenced_clients() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))); \
             CREATE TABLE oauth_consents (client_id TEXT NOT NULL, expires_at TEXT NOT NULL); \
             CREATE TABLE oauth_authorization_codes (client_id TEXT NOT NULL, expires_at TEXT NOT NULL); \
             CREATE TABLE refresh_tokens (client_id TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0); \
             WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x + 1 FROM n WHERE x < 256) \
             INSERT INTO oauth_clients (client_id, redirect_uris, created_at) \
             SELECT printf('client-%d', x), printf('[\"https://client-%d.example/cb\"]', x), \
                    '2000-01-01T00:00:00.000Z' FROM n; \
             INSERT INTO refresh_tokens (client_id, expires_at, revoked) \
             VALUES ('client-1', '2099-01-01T00:00:00.000Z', 0);",
        )
        .unwrap();

        let (result, changed) = register_client_conn(
            &conn,
            CLIENT,
            Some("Replacement"),
            "[\"https://replacement.example/cb\"]",
        )
        .unwrap();
        assert!(matches!(result, ClientRegistration::Created(ref id) if id == CLIENT));
        assert!(changed);
        assert_eq!(
            conn.query_row("SELECT count(*) FROM oauth_clients", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM oauth_clients WHERE client_id = 'client-1'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn consent_and_authorization_code_are_each_single_use() {
        let conn = oauth_conn();
        assert!(store_pending_consent_conn(&conn, "consent", USER, CLIENT, REDIRECT).unwrap());
        assert!(approve_consent_conn(&conn, "consent", "code", USER, CLIENT, REDIRECT).unwrap());
        assert!(
            !approve_consent_conn(&conn, "consent", "other-code", USER, CLIENT, REDIRECT).unwrap()
        );

        assert!(exchange_authorization_code_conn(&conn, "code", USER, CLIENT, "refresh").unwrap());
        assert!(
            !exchange_authorization_code_conn(&conn, "code", USER, CLIENT, "other-refresh")
                .unwrap()
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM refresh_tokens", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn refresh_rotation_is_atomic_single_use_and_client_bound() {
        let conn = oauth_conn();
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
             VALUES ('old', ?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now','+1 day'))",
            rusqlite::params![USER, CLIENT],
        )
        .unwrap();

        assert_eq!(
            rotate_refresh_token_conn(&conn, "old", OTHER_CLIENT, "wrong").unwrap(),
            None
        );
        assert_eq!(
            rotate_refresh_token_conn(&conn, "old", CLIENT, "new").unwrap(),
            Some(USER.to_string())
        );
        assert_eq!(
            rotate_refresh_token_conn(&conn, "old", CLIENT, "replay").unwrap(),
            None
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM refresh_tokens WHERE revoked = 0 AND token_hash = 'new'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn inactive_user_cannot_exchange_or_refresh() {
        let conn = oauth_conn();
        assert!(store_pending_consent_conn(&conn, "consent", USER, CLIENT, REDIRECT).unwrap());
        conn.execute("UPDATE users SET status = 'deleting' WHERE id = ?1", [USER])
            .unwrap();
        assert!(!approve_consent_conn(&conn, "consent", "code", USER, CLIENT, REDIRECT).unwrap());
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
             VALUES ('old', ?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now','+1 day'))",
            rusqlite::params![USER, CLIENT],
        )
        .unwrap();
        assert_eq!(
            rotate_refresh_token_conn(&conn, "old", CLIENT, "new").unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn consent_page_escapes_client_metadata_and_is_not_cacheable() {
        let response = consent_page(
            Some("<script>alert(1)</script>"),
            "https://client.example",
            "token\" autofocus onfocus=alert(1)",
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["Cache-Control"], "no-store");
        assert!(response.headers()["Content-Security-Policy"]
            .to_str()
            .unwrap()
            .contains("form-action 'self' https://client.example;"));
        let csp = response.headers()["Content-Security-Policy"]
            .to_str()
            .unwrap();
        assert_exact_style_hash(csp);
        assert!(!csp.contains("'unsafe-inline'"));
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("<script>"));
        assert!(body.contains("&lt;script&gt;"));
        assert!(body.contains("&quot; autofocus"));
        assert!(body.contains("MCP connection request"));
        assert!(body.contains("Protected by Kioku’s confidential cloud"));
        assert!(body.contains("name=\"decision\" value=\"approve\""));
        assert!(body.contains("name=\"decision\" value=\"deny\""));
    }

    #[tokio::test]
    async fn callback_error_uses_the_branded_private_shell() {
        let response = callback_error(
            StatusCode::BAD_REQUEST,
            "Authentication failed",
            "The callback was missing required parameters.",
        );
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["Cache-Control"], "no-store");
        let csp = response.headers()["Content-Security-Policy"]
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'none'"));
        assert_exact_style_hash(csp);
        assert!(!csp.contains("'unsafe-inline'"));
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<title>Authentication failed · Kioku</title>"));
        assert!(body.contains("Connection interrupted"));
        assert!(body.contains("class=\"brand-mark\""));
    }
}
