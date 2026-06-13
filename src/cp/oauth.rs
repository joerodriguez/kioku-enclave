//! OAuth 2.1 facade + Dynamic Client Registration (ports `cloud/src/oauth.js`).
//! Public endpoints (no auth): discovery, /register, /authorize, the Google
//! callback, and /token. MCP clients (Claude/ChatGPT) use this to obtain our
//! HS256 access tokens; Google is the upstream IdP.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header::LOCATION, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use super::{tokens, CpState};

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
        .route("/token", post(token))
}

fn redirect_302(url: &str) -> Response {
    (StatusCode::FOUND, [(LOCATION, url.to_string())]).into_response()
}

fn is_valid_redirect_uri(uri: &str) -> bool {
    match url_parts(uri) {
        Some((scheme, host)) => {
            scheme == "https" || (scheme == "http" && (host == "localhost" || host == "127.0.0.1"))
        }
        None => false,
    }
}

/// Minimal scheme+host extraction (avoids a url crate dependency).
fn url_parts(uri: &str) -> Option<(String, String)> {
    let (scheme, rest) = uri.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.split('@').next_back().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if scheme.is_empty() || host.is_empty() {
        return None;
    }
    Some((scheme.to_lowercase(), host.to_lowercase()))
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

async fn register(State(s): State<Arc<CpState>>, Json(body): Json<RegisterBody>) -> Response {
    if body.redirect_uris.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_client_metadata", "error_description": "redirect_uris required"})),
        )
            .into_response();
    }
    for uri in &body.redirect_uris {
        if !is_valid_redirect_uri(uri) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_redirect_uri", "error_description": format!("bad redirect_uri: {uri}")})),
            )
                .into_response();
        }
    }
    let client_id = tokens::new_uuid();
    let uris_json = serde_json::to_string(&body.redirect_uris).unwrap_or_else(|_| "[]".into());
    let name = body.client_name.clone();
    let res = s
        .control
        .write(move |conn| {
            conn.execute(
                "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?1, ?2, ?3)",
                rusqlite::params![client_id, name, uris_json],
            )?;
            Ok(client_id)
        })
        .await;
    match res {
        Ok(client_id) => (
            StatusCode::CREATED,
            Json(json!({
                "client_id": client_id,
                "redirect_uris": body.redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
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
    if let Some(m) = &q.code_challenge_method {
        if m != "S256" {
            return bad_request_desc("invalid_request", "Only S256 supported");
        }
    }
    let (client_id, redirect_uri) = match (q.client_id.clone(), q.redirect_uri.clone()) {
        (Some(c), Some(r)) => (c, r),
        _ => return bad_request_desc("invalid_request", "client_id and redirect_uri required"),
    };

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
                .ok())
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
    let uris: Vec<String> = serde_json::from_str(&uris_json).unwrap_or_default();
    if !uris.contains(&redirect_uri) {
        return bad_request_desc("invalid_request", "redirect_uri mismatch");
    }

    let state_jwt = match tokens::issue_state(
        &s.config.jwt_secrets[0],
        &tokens::StateClaims {
            client_id: client_id.clone(),
            redirect_uri,
            client_state: q.state.clone().unwrap_or_default(),
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

async fn google_callback(
    State(s): State<Arc<CpState>>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if let Some(e) = q.error {
        return (
            StatusCode::BAD_REQUEST,
            Html(format!("<h1>Authentication failed</h1><p>{e}</p>")),
        )
            .into_response();
    }
    let (Some(code), Some(state_jwt)) = (q.code, q.state) else {
        return (
            StatusCode::BAD_REQUEST,
            Html("<h1>Missing code/state</h1>".to_string()),
        )
            .into_response();
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
                    return (
                        StatusCode::BAD_REQUEST,
                        Html("<h1>Invalid or expired state</h1>".to_string()),
                    )
                        .into_response()
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

    let http = reqwest::Client::new();
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
                return (
                    StatusCode::BAD_GATEWAY,
                    Html("<h1>Google token parse failed</h1>".to_string()),
                )
                    .into_response()
            }
        },
        _ => {
            return (
                StatusCode::BAD_GATEWAY,
                Html("<h1>Google token exchange failed</h1>".to_string()),
            )
                .into_response()
        }
    };

    let (google_sub, email) = match s.user_verifier.verify(&token_data.id_token).await {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Html("<h1>ID token verification failed</h1>".to_string()),
            )
                .into_response()
        }
    };
    if !s.config.email_allowed(&email) {
        return (
            StatusCode::FORBIDDEN,
            Html(format!(
                "<h1>Access denied</h1><p>{email} is not authorized.</p>"
            )),
        )
            .into_response();
    }

    let user = match s.control.upsert_user(&google_sub, &email).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Internal error</h1>".to_string()),
            )
                .into_response()
        }
    };

    let auth_code = match tokens::issue_auth_code(
        &s.config.jwt_secrets[0],
        &user.id,
        &state.client_id,
        &state.code_challenge,
    ) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Internal error</h1>".to_string()),
            )
                .into_response()
        }
    };

    let mut params = vec![("code", auth_code.as_str())];
    if !state.client_state.is_empty() {
        params.push(("state", state.client_state.as_str()));
    }
    let sep = if state.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = format!(
        "{}{}{}",
        state.redirect_uri,
        sep,
        serde_urlencoded::to_string(&params).unwrap_or_default()
    );
    redirect_302(&url)
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

const REFRESH_TTL_SECS: i64 = 90 * 24 * 60 * 60;

async fn token(State(s): State<Arc<CpState>>, body: String) -> Response {
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

async fn token_auth_code(s: Arc<CpState>, form: TokenForm) -> Response {
    let Some(code) = form.code else {
        return bad_request_desc("invalid_request", "code required");
    };
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
    if tokens::pkce_s256(&verifier) != claims.code_challenge {
        return bad_request_desc("invalid_grant", "PKCE verification failed");
    }
    if form.client_id.as_deref() != Some(claims.client_id.as_str()) {
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
    let hash = tokens::sha256_hex(&raw_refresh);
    let (uid, cid) = (claims.user_id.clone(), claims.client_id.clone());
    if s.control
        .write(move |conn| {
            conn.execute(
                "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
                 VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4))",
                rusqlite::params![hash, uid, cid, format!("+{REFRESH_TTL_SECS} seconds")],
            )?;
            Ok(())
        })
        .await
        .is_err()
    {
        return server_error();
    }
    token_response(&access, &raw_refresh)
}

async fn token_refresh(s: Arc<CpState>, form: TokenForm) -> Response {
    let Some(incoming) = form.refresh_token else {
        return bad_request_desc("invalid_request", "refresh_token required");
    };
    let hash = tokens::sha256_hex(&incoming);

    // Read the row, validate, rotate (revoke old + insert new) atomically.
    let hash_for_read = hash.clone();
    let row: Option<(String, String, bool, bool)> = match s
        .control
        .read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT user_id, client_id, revoked, (expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
                     FROM refresh_tokens WHERE token_hash = ?1",
                    [&hash_for_read],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0, r.get::<_, i64>(3)? != 0)),
                )
                .ok())
        })
        .await
    {
        Ok(v) => v,
        Err(_) => return server_error(),
    };

    let Some((user_id, client_id, revoked, expired)) = row else {
        return bad_request_desc("invalid_grant", "Refresh token not found");
    };
    if revoked {
        return bad_request_desc("invalid_grant", "Refresh token revoked");
    }
    if expired {
        return bad_request_desc("invalid_grant", "Refresh token expired");
    }

    let access =
        match tokens::issue_access_token(&s.config.jwt_secrets[0], &s.config.base_url, &user_id) {
            Ok(t) => t,
            Err(_) => return server_error(),
        };
    let raw_refresh = tokens::random_token_hex();
    let new_hash = tokens::sha256_hex(&raw_refresh);
    let (uid, cid) = (user_id.clone(), client_id.clone());
    if s.control
        .write(move |conn| {
            conn.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?1",
                [&hash],
            )?;
            conn.execute(
                "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
                 VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4))",
                rusqlite::params![new_hash, uid, cid, format!("+{REFRESH_TTL_SECS} seconds")],
            )?;
            Ok(())
        })
        .await
        .is_err()
    {
        return server_error();
    }
    token_response(&access, &raw_refresh)
}

fn token_response(access: &str, refresh: &str) -> Response {
    Json(json!({
        "access_token": access,
        "token_type": "bearer",
        "expires_in": 3600,
        "refresh_token": refresh,
        "scope": "",
    }))
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
