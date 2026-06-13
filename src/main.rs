//! # kioku-enclave — Kioku data-plane service
//!
//! This is the only process that holds plaintext user data. It runs inside a
//! GCP Confidential Space VM (AMD SEV) where the TEE guarantees that even the
//! operator cannot inspect memory.
//!
//! ## Authentication
//!
//! Every request (except `/health`) must carry a Google-signed ID token
//! (RS256, `https://accounts.google.com`) in the `Authorization: Bearer`
//! header, with:
//!
//! - `aud` == `ENCLAVE_AUDIENCE` env var (baked into the image)
//! - `email` == `RUN_SA_EMAIL` env var (the trusted control-plane service
//!   account, baked into the image)
//! - `email_verified` == true
//! - `exp` not yet passed
//!
//! This is the ONLY authentication path — there is no shared-secret
//! fallback and no flag to disable ID-token verification.
//!
//! The listener binds `0.0.0.0` and is not itself access-controlled; the
//! network boundary is the private VPC firewall plus this per-request
//! ID-token check. See SECURITY.md.
//!
//! **Future end state**: mTLS between control plane and enclave, with the
//! enclave's certificate bound to its attested identity. See SECURITY.md.
//!
//! ## Routes
//!
//! | Method | Path                       | Description                                  |
//! |--------|----------------------------|----------------------------------------------|
//! | GET    | /health                    | Liveness probe; returns `{"ok":true}`        |
//! | POST   | /v1/ingest                 | Append utterances / screenshots to user index|
//! | POST   | /v1/search                 | FTS5 search (optional kinds filter)          |
//! | POST   | /v1/context                | Rows nearest a center timestamp              |
//! | POST   | /v1/range                  | Raw rows in [from, to) for summariser        |
//! | POST   | /v1/episodes/upsert        | Write / replace summarised episodes          |
//! | POST   | /v1/episodes/list          | List episodes newest-first                   |
//! | POST   | /v1/episodes/delete_range  | Delete episodes in [from, to)                |
//! | POST   | /v1/stats                  | Per-user row counts + latest timestamps      |
//! | GET    | /v1/export                 | Full JSON export of user's index             |
//! | DELETE | /v1/user                   | Hard-delete all user data (GDPR)             |

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use base64::Engine as _; // trait in scope for .encode()
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod attestation;
mod auth;
mod crypto;
mod episodes;
mod error;
mod ingest;
mod search;
mod store;
mod timeline;

use crate::{
    episodes::{
        handle_episodes_delete_range, handle_episodes_list, handle_episodes_members,
        handle_episodes_upsert,
    },
    ingest::handle_ingest,
    search::handle_search,
    store::{GcpGcsClient, Store},
    timeline::{handle_context, handle_range, handle_stats},
};

// ── Application state ─────────────────────────────────────────────────────────

pub struct AppState {
    pub store: Store,
    /// JWKS verifier for Google ID tokens — the only authentication path.
    id_token_verifier: Arc<auth::IdTokenVerifier>,
}

// ── Auth middleware ───────────────────────────────────────────────────────────

/// Bearer token check. Accepts ONLY a Google-signed ID token (RS256) with:
/// `aud == ENCLAVE_AUDIENCE`, `email == RUN_SA_EMAIL`,
/// `email_verified == true`, and `exp > now`.
///
/// There is no other authentication path. Logs the authorized caller email
/// (never token content).
async fn require_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let provided = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);

    let Some(token) = provided else {
        warn!("rejected request: no Authorization header");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
            .into_response();
    };

    match state.id_token_verifier.verify(&token).await {
        Ok(claims) => {
            info!(
                auth_path = "google_id_token",
                email = %claims.email,
                "request authorized"
            );
            next.run(req).await
        }
        Err(e) => {
            warn!(reason = %e, "rejected request: ID token verification failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
                .into_response()
        }
    }
}

// ── Export handler ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ExportQuery {
    user_id: String,
}

async fn handle_export(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ExportQuery>,
) -> error::Result<Json<serde_json::Value>> {
    let user_id = q.user_id;
    store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, "export request");

    let data = state
        .store
        .with_user(&user_id, |conn| {
            // Export all tables as JSON arrays
            let utterances = dump_table(conn, "SELECT * FROM utterances ORDER BY id")?;
            let screenshots = dump_table(conn, "SELECT * FROM screenshots ORDER BY id")?;
            let episodes = dump_table(conn, "SELECT * FROM episodes ORDER BY id")?;
            Ok(json!({
                "utterances": utterances,
                "screenshots": screenshots,
                "episodes": episodes,
            }))
        })
        .await?;

    Ok(Json(data))
}

fn dump_table(
    conn: &rusqlite::Connection,
    sql: &str,
) -> crate::error::Result<Vec<serde_json::Value>> {
    let mut stmt = conn.prepare(sql)?;
    let col_count = stmt.column_count();
    let col_names: Vec<String> = (0..col_count)
        .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
        .collect();

    let rows = stmt.query_map([], |row| {
        let mut map = serde_json::Map::new();
        for (i, name) in col_names.iter().enumerate() {
            let val: rusqlite::types::Value = row.get(i)?;
            map.insert(name.clone(), sqlite_value_to_json(val));
        }
        Ok(serde_json::Value::Object(map))
    })?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn sqlite_value_to_json(v: rusqlite::types::Value) -> serde_json::Value {
    match v {
        rusqlite::types::Value::Null => serde_json::Value::Null,
        rusqlite::types::Value::Integer(i) => serde_json::Value::Number(i.into()),
        rusqlite::types::Value::Real(f) => serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
        rusqlite::types::Value::Blob(b) => {
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(b))
        }
    }
}

// ── Delete handler ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DeleteBody {
    user_id: String,
}

async fn handle_delete_user(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeleteBody>,
) -> error::Result<Json<serde_json::Value>> {
    let user_id = body.user_id;
    store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, "delete user request");

    state.store.delete_user(&user_id).await?;

    Ok(Json(json!({
        "deleted": true,
        "user_id": user_id,
    })))
}

// ── Health handler ────────────────────────────────────────────────────────────

async fn handle_health() -> Json<serde_json::Value> {
    Json(json!({"ok": true, "service": "kioku-enclave"}))
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Structured logging; RUST_LOG overrides the default.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "kioku-enclave starting"
    );

    // ── Auth config ───────────────────────────────────────────────────────────
    //
    // ENCLAVE_AUDIENCE and RUN_SA_EMAIL are required: every request must carry
    // a Google-signed ID token whose `aud` and `email` claims match them. In
    // production they are baked into the image at build time; ENCLAVE_TEST_MODE
    // provides local-dev defaults only.
    let enclave_audience = std::env::var("ENCLAVE_AUDIENCE").unwrap_or_else(|_| {
        if std::env::var("ENCLAVE_TEST_MODE").is_ok() {
            "http://localhost:8080".to_string()
        } else {
            panic!("ENCLAVE_AUDIENCE must be set");
        }
    });

    let run_sa_email = std::env::var("RUN_SA_EMAIL").unwrap_or_else(|_| {
        if std::env::var("ENCLAVE_TEST_MODE").is_ok() {
            "test@example.com".to_string()
        } else {
            panic!("RUN_SA_EMAIL must be set");
        }
    });

    let id_token_verifier = Arc::new(auth::IdTokenVerifier::new(enclave_audience, run_sa_email));

    // ── KMS + GCS ─────────────────────────────────────────────────────────────

    let kms: Arc<dyn crate::crypto::KmsClient> = Arc::new(
        crypto::GcpKmsClient::from_env()
            .expect("KMS env vars (KMS_PROJECT, KMS_LOCATION, KMS_KEY_RING, KMS_KEY) must be set"),
    );
    let gcs: Arc<dyn crate::store::GcsClient> =
        Arc::new(GcpGcsClient::from_env().expect("GCS_BUCKET must be set"));

    let state = Arc::new(AppState {
        store: Store::new(kms, gcs),
        id_token_verifier,
    });

    let authenticated = Router::new()
        .route("/v1/ingest", post(handle_ingest))
        .route("/v1/search", post(handle_search))
        .route("/v1/context", post(handle_context))
        .route("/v1/range", post(handle_range))
        .route("/v1/episodes/upsert", post(handle_episodes_upsert))
        .route("/v1/episodes/list", post(handle_episodes_list))
        .route("/v1/episodes/members", post(handle_episodes_members))
        .route(
            "/v1/episodes/delete_range",
            post(handle_episodes_delete_range),
        )
        .route("/v1/stats", post(handle_stats))
        .route("/v1/export", get(handle_export))
        .route("/v1/user", delete(handle_delete_user))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ))
        .with_state(Arc::clone(&state));

    let app = Router::new()
        .route("/health", get(handle_health))
        .merge(authenticated);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(addr = %addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind failed");

    axum::serve(listener, app).await.expect("server error");
}
