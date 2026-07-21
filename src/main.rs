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
//! By default the listener binds `0.0.0.0` over plain HTTP and is not itself
//! access-controlled; the network boundary is the private VPC firewall plus
//! this per-request ID-token check. See SECURITY.md.
//!
//! **In-enclave TLS termination (ADR-0001):** when `ENCLAVE_TLS` is set, the
//! enclave terminates TLS itself (see `tls.rs` and `serve_tls` below) so the
//! attested binary is the first code to see request plaintext, rather than an
//! upstream proxy. The cert fingerprint is the channel-binding value a later
//! step binds into the attestation token (RA-TLS). See
//! `docs/adr/0001-enclave-as-sole-backend.md` in the monorepo.
//!
//! **ACME auto-renewal (ADR-0003):** when `ENCLAVE_ACME` is set, the enclave
//! obtains and renews that certificate itself from Let's Encrypt — HTTP-01
//! answered on :80, key generated in-TEE, state persisted KMS-encrypted in GCS,
//! live cert hot-swapped on renewal. See `acme.rs`. `ENCLAVE_TLS_*` env certs
//! then serve only as a bootstrap fallback while issuance retries.
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

mod acme;
mod attestation;
mod auth;
mod cp;
mod crypto;
mod embedding;
mod episodes;
mod error;
mod ingest;
mod search;
mod store;
mod timeline;
mod tls;

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
    pub store: Arc<Store>,
    /// JWKS verifier for Google ID tokens — the only authentication path.
    id_token_verifier: Arc<auth::IdTokenVerifier>,
    pub attestation_cache: Option<Arc<attestation::AttestationCache>>,
    pub cert_fingerprint: Option<String>,
}

/// In-process full export of a user's index as JSON (utterances, screenshots,
/// episodes). Shared by the legacy `/v1/export` handler and the control-plane
/// `/api/export` route (ADR-0001).
pub(crate) async fn dump_user_export(
    store: &Store,
    user_id: &str,
) -> error::Result<serde_json::Value> {
    store::validate_user_id(user_id)?;
    store
        .with_user(user_id, |conn| {
            let utterances = dump_table(conn, "SELECT * FROM utterances ORDER BY id")?;
            let screenshots = dump_table(conn, "SELECT * FROM screenshots ORDER BY id")?;
            let episodes = dump_table(conn, "SELECT * FROM episodes ORDER BY id")?;
            let final_briefs = dump_table(conn, "SELECT * FROM episode_final_briefs ORDER BY episode_id")?;
            let deliveries = dump_table(conn, "SELECT * FROM episode_deliveries ORDER BY episode_id")?;
            Ok(json!({
                "utterances": utterances,
                "screenshots": screenshots,
                "episodes": episodes,
                "episode_final_briefs": final_briefs,
                "episode_deliveries": deliveries,
            }))
        })
        .await
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
    info!(user_id = %q.user_id, "export request");
    let data = dump_user_export(&state.store, &q.user_id).await?;
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

// ── Attestation handler ───────────────────────────────────────────────────────

async fn handle_attestation(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match (&state.attestation_cache, &state.cert_fingerprint) {
        (Some(cache), Some(fingerprint)) => match cache.get_token(fingerprint).await {
            Ok(token) => (
                StatusCode::OK,
                Json(json!({
                    "token": token,
                    "fingerprint": fingerprint,
                })),
            ),
            Err(e) => {
                warn!(error = %e, "failed to fetch attestation token on demand");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": format!("failed to fetch attestation token: {e}")
                    })),
                )
            }
        },
        _ => (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "attestation not available (enclave not running in TEE or TLS disabled)"
            })),
        ),
    }
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

    let id_token_verifier = Arc::new(auth::IdTokenVerifier::new(
        enclave_audience.clone(),
        run_sa_email,
    ));

    // ── KMS + GCS ─────────────────────────────────────────────────────────────

    let kms: Arc<dyn crate::crypto::KmsClient> = Arc::new(
        crypto::GcpKmsClient::from_env()
            .expect("KMS env vars (KMS_PROJECT, KMS_LOCATION, KMS_KEY_RING, KMS_KEY) must be set"),
    );
    let gcs: Arc<dyn crate::store::GcsClient> =
        Arc::new(GcpGcsClient::from_env().expect("GCS_BUCKET must be set"));

    let store = Arc::new(Store::new(Arc::clone(&kms), Arc::clone(&gcs)));

    // ACME renewal (ADR-0003) shares the KMS/GCS clients; take clones before the
    // control store consumes the originals.
    let acme_kms = Arc::clone(&kms);
    let acme_gcs = Arc::clone(&gcs);

    // ── In-enclave control plane (ADR-0001): OAuth, sync, account, MCP. ─────────
    let control_store = Arc::new(cp::control_store::ControlStore::new(kms, gcs));

    let (jwt_secrets, google_web_client_secret) = if std::env::var("ENCLAVE_TEST_MODE").is_ok() {
        let jwt_secret =
            std::env::var("JWT_SECRET").unwrap_or_else(|_| "test-jwt-secret".to_string());
        let mut secrets = vec![jwt_secret];
        if let Ok(prev) = std::env::var("JWT_SECRET_PREVIOUS") {
            if !prev.is_empty() {
                secrets.push(prev);
            }
        }
        (
            secrets,
            std::env::var("GOOGLE_WEB_CLIENT_SECRET").unwrap_or_default(),
        )
    } else {
        info!("fetching runtime configuration from Secret Manager");
        let client_secret =
            cp::fetch_secret_from_manager("kioku-google-web-client-secret", "latest")
                .await
                .unwrap_or_else(|e| panic!("Failed to fetch web client secret: {}", e));

        let jwt_secrets = control_store
            .get_or_generate_jwt_secrets()
            .await
            .unwrap_or_else(|e| panic!("Failed to load/generate JWT secrets: {}", e));

        (jwt_secrets, client_secret)
    };

    let cp_config = Arc::new(
        cp::CpConfig::from_env(jwt_secrets, google_web_client_secret)
            .expect("control-plane config"),
    );

    // ── TLS & Attestation setup ───────────────────────────────────────────────
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind failed");

    let acme_opt = acme::AcmeConfig::from_env().expect("ACME config");
    let (keystone, cert_fingerprint) = match acme_opt {
        Some(acme_config) => {
            // ADR-0003: in-enclave ACME. The :80 HTTP-01 listener must be up
            // before any issuance attempt (Let's Encrypt validates against it).
            let challenges = Arc::new(acme::ChallengeMap::default());
            let http_addr = SocketAddr::from(([0, 0, 0, 0], acme_config.http_port));
            let http_listener = tokio::net::TcpListener::bind(http_addr)
                .await
                .expect("bind ACME HTTP-01 port failed");
            info!(addr = %http_addr, "ACME HTTP-01 challenge listener up");
            let challenge_app = acme::challenge_router(Arc::clone(&challenges));
            tokio::spawn(async move {
                axum::serve(http_listener, challenge_app)
                    .await
                    .expect("ACME HTTP-01 server error");
            });

            let renewer = Arc::new(acme::Renewer::new(
                acme_config,
                acme_kms,
                acme_gcs,
                challenges,
            ));
            let ks = Arc::new(
                acme_boot_keystone(&renewer, &cp_config.base_url, &enclave_audience).await,
            );
            Arc::clone(&renewer).spawn(Arc::clone(&ks));
            let fp = ks.cert_fingerprint_hex.clone();
            (Some(ks), Some(fp))
        }
        None => match tls::from_env(&cp_config.base_url, &enclave_audience)
            .await
            .expect("TLS config")
        {
            Some(ks) => {
                let fp = ks.cert_fingerprint_hex.clone();
                (Some(Arc::new(ks)), Some(fp))
            }
            None => (None, None),
        },
    };

    let attestation_cache = cert_fingerprint.as_ref().map(|_| {
        Arc::new(attestation::AttestationCache::new(
            std::env::var("ATTEST_STS_AUDIENCE").unwrap_or_default(),
        ))
    });

    let state = Arc::new(AppState {
        store: Arc::clone(&store),
        id_token_verifier,
        attestation_cache: attestation_cache.clone(),
        cert_fingerprint: cert_fingerprint.clone(),
    });

    // In-enclave query embedder for hybrid search. Loading is eager (boot
    // warm-up: ~470 MB of weights, seconds) so the first MCP query doesn't
    // eat the cold start; absence is non-fatal (FTS-only mode).
    let embedding_engine = embedding::EmbeddingEngine::from_env();

    let cp_state = Arc::new(cp::CpState {
        store: Arc::clone(&store),
        control: control_store,
        user_verifier: Arc::new(cp::auth::UserIdTokenVerifier::new(
            cp_config.user_audiences(),
        )),
        sync_limiter: cp::limits::RateLimiter::new(10.0, 0.2),
        mcp_limiter: cp::limits::RateLimiter::new(60.0, 1.0),
        config: cp_config,
        attestation_cache,
        cert_fingerprint,
        embedding: embedding_engine,
    });

    // Internal summarizer cron (replaces Cloud Scheduler — no external trigger).
    cp::summarizer::spawn_scheduler(Arc::clone(&cp_state));

    // ── Legacy data-plane routes ──────────────────────────────────────────────
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

    // Public OAuth routes + auth-gated sync/account/MCP/REST routes.
    let cp_authed = cp::sync::router()
        .merge(cp::query::router())
        .layer(middleware::from_fn_with_state(
            Arc::clone(&cp_state),
            cp::auth::require_auth,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&cp_state),
            cp::cors::cors_middleware,
        ));
    let control_plane = cp::oauth::router()
        .merge(cp_authed)
        .with_state(Arc::clone(&cp_state));

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/v1/attestation", get(handle_attestation))
        .merge(authenticated)
        .merge(control_plane)
        .with_state(Arc::clone(&state));

    // Listen
    match keystone {
        Some(ks) => {
            info!(addr = %addr, tls = true, "listening (in-enclave TLS termination)");
            serve_tls(listener, app, ks).await;
        }
        None => {
            info!(addr = %addr, tls = false, "listening (plain HTTP behind VPC firewall)");
            axum::serve(listener, app).await.expect("server error");
        }
    }
}

/// Get a serving-ready keystone at boot in ACME mode (ADR-0003), in order of
/// preference: persisted/fresh ACME cert → baked `ENCLAVE_TLS_*` fallback cert
/// (the renewal cron then replaces it) → keep retrying issuance. The enclave
/// never gives up: with no cert there is nothing useful to serve anyway.
async fn acme_boot_keystone(
    renewer: &acme::Renewer,
    base_url: &str,
    enclave_audience: &str,
) -> tls::TlsKeystone {
    let first_err = match renewer.initial_pair().await {
        Ok(pair) => match tls::TlsKeystone::new(pair) {
            Ok(keystone) => return keystone,
            Err(e) => e,
        },
        Err(e) => e,
    };
    tracing::error!(error = %first_err, "boot ACME issuance failed");

    if let Ok(Some(keystone)) = tls::from_env(base_url, enclave_audience).await {
        warn!("serving baked fallback certificate; ACME renewal will keep retrying");
        return keystone;
    }

    let mut attempt = 1u32;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        attempt += 1;
        match renewer.initial_pair().await {
            Ok(pair) => match tls::TlsKeystone::new(pair) {
                Ok(keystone) => return keystone,
                Err(e) => tracing::error!(error = %e, attempt, "ACME cert unusable"),
            },
            Err(e) => tracing::error!(error = %e, attempt, "boot ACME issuance retry failed"),
        }
    }
}

/// Serve `app` over TLS terminated inside the enclave (ADR-0001).
///
/// `axum::serve` has no TLS path, so we run the accept loop by hand: accept TCP, complete
/// the rustls handshake, then hand the connection to hyper with the axum router wrapped as
/// a hyper service. One task per connection; a handshake or connection error drops only
/// that connection.
async fn serve_tls(
    listener: tokio::net::TcpListener,
    app: Router,
    keystone: Arc<tls::TlsKeystone>,
) {
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use tokio_rustls::TlsAcceptor;

    let acceptor = TlsAcceptor::from(Arc::clone(&keystone.server_config));

    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "TCP accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "TLS handshake failed");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let service = TowerToHyperService::new(app);
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                tracing::debug!(error = %e, "connection closed with error");
            }
        });
    }
}
