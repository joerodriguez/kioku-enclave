//! # kioku-enclave — attested Kioku backend
//!
//! This process terminates TLS and handles server-side user plaintext inside a
//! GCP Confidential Space VM (AMD SEV). Deliberate Vertex summarization and
//! user-configured webhook delivery are documented egresses; encrypted storage and the
//! workload operator do not otherwise receive plaintext.
//!
//! ## Authentication
//!
//! The compatibility `/v1/*` data routes require a Google-signed service-account
//! ID token (RS256, `https://accounts.google.com`) with:
//!
//! - `aud` == `ENCLAVE_AUDIENCE` env var (baked into the image)
//! - `email` == `RUN_SA_EMAIL` env var (the trusted control-plane service
//!   account, baked into the image)
//! - `email_verified` == true
//! - `exp` not yet passed
//!
//! The integrated `/api/*` and `/mcp` routes accept short-lived Kioku access
//! tokens or configured end-user Google ID tokens and check active account
//! state. OAuth discovery/registration/callback routes, `/health`, and the
//! public verifier-audience `/v1/attestation` route are intentionally public.
//! There is no shared-secret auth fallback or auth-disable flag.
//!
//! Production builds fail closed unless in-enclave TLS is configured. Plain
//! HTTP is available only from debug builds with `ENCLAVE_TEST_MODE=1`.
//!
//! The enclave terminates production TLS itself (see `tls.rs` and `serve_tls`),
//! so the attested binary is the first server-side application code to see a
//! request. `/v1/attestation` binds the live certificate fingerprint into the
//! token nonce for verifier-side channel comparison.
//!
//! **ACME auto-renewal (ADR-0003):** when `ENCLAVE_ACME` is set, the enclave
//! obtains and renews that certificate itself from Let's Encrypt — HTTP-01
//! answered on :80, key generated in-TEE, state persisted KMS-encrypted in GCS,
//! live cert hot-swapped on renewal. See `acme.rs`. Static `ENCLAVE_TLS_*`
//! inputs remain only for debug/custom bootstrap images.
//!
//! ## Compatibility routes
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
//! | DELETE | /v1/user                   | Legacy content-only delete (trusted SA)      |

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
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
// ADR-0022 format/crypto/backend and checkpoint/WAL primitives only.  These are
// intentionally not connected to the live Store, SQLite VFS, witness, routes,
// or write authority.
mod archive_v3;
// Inactive ADR-0022 GCS semantic adapters. A concrete GCP HTTP transport and
// all runtime/authority wiring remain intentionally absent.
mod archive_v3_gcs;
mod archive_v3_journal;
mod archive_v3_operation;
// ADR-0022's bounded synchronous WAL-shadow capture state. It is not yet a
// registered SQLite VFS and has no Store, provider, route, or authority wiring.
mod archive_v3_shadow;
// ADR-0022's inactive, in-memory witness contract.  It intentionally has no
// provider, Store, VFS, route, or authority wiring.
mod archive_v3_witness;
mod attestation;
mod auth;
mod cp;
mod crypto;
mod embedding;
mod episodes;
mod error;
mod ingest;
mod ocr;
mod search;
mod storage_observability;
mod store;
mod timeline;
mod tls;

/// Local test mode is deliberately impossible in release binaries. Checking
/// for the exact value also prevents values such as `0`, `false`, or an empty
/// variable from accidentally enabling test credentials.
pub(crate) fn test_mode_enabled() -> bool {
    cfg!(debug_assertions) && std::env::var("ENCLAVE_TEST_MODE").as_deref() == Ok("1")
}

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

async fn resolve_resend_api_key<F, Fut>(
    test_mode: bool,
    local_key: Option<String>,
    fetch_production_key: F,
) -> Result<Option<String>, String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    if test_mode {
        local_key.map(validate_resend_api_key).transpose()
    } else {
        fetch_production_key()
            .await
            .and_then(validate_resend_api_key)
            .map(Some)
    }
}

fn validate_resend_api_key(api_key: String) -> Result<String, String> {
    let api_key = api_key.trim();
    if !api_key.starts_with("re_")
        || !(8..=256).contains(&api_key.len())
        || !api_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("Resend API key has an invalid format".into());
    }
    Ok(api_key.to_string())
}

// ── Application state ─────────────────────────────────────────────────────────

pub struct AppState {
    pub store: Arc<Store>,
    /// JWKS verifier for Google ID tokens — the only authentication path.
    id_token_verifier: Arc<auth::IdTokenVerifier>,
    pub attestation_cache: Option<Arc<attestation::AttestationCache>>,
    pub tls_keystone: Option<Arc<tls::TlsKeystone>>,
}

/// In-process full export of a user's searchable index, capture provenance,
/// learned people, and voice-memory records. Encrypted raw object bytes remain
/// represented by their media-object inventory; the export never exposes KMS
/// wrapping keys or reusable authentication material.
pub(crate) async fn dump_user_export(
    store: &Store,
    user_id: &str,
) -> error::Result<serde_json::Value> {
    store::validate_user_id(user_id)?;
    store
        .with_user(user_id, |conn| {
            let utterances = dump_table(conn, "SELECT * FROM utterances ORDER BY id")?;
            let screenshots = dump_table(conn, "SELECT * FROM screenshots ORDER BY id")?;
            let screenshot_images = {
                let table_exists: i64 = conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='screenshot_images'",
                    [],
                    |r| r.get(0),
                )?;
                if table_exists > 0 {
                    dump_table(conn, "SELECT * FROM screenshot_images ORDER BY id")?
                } else {
                    Vec::new()
                }
            };
            let episodes = dump_table(conn, "SELECT * FROM episodes ORDER BY id")?;
            let final_briefs = dump_table(conn, "SELECT * FROM episode_final_briefs ORDER BY episode_id")?;
            let webhook_deliveries =
                dump_table(conn, "SELECT * FROM webhook_deliveries ORDER BY episode_id, subscription_id")?;
            Ok(json!({
                "utterances": utterances,
                "screenshots": screenshots,
                "screenshot_images": screenshot_images,
                "episodes": episodes,
                "episode_final_briefs": final_briefs,
                "webhook_deliveries": webhook_deliveries,
                "email_deliveries": dump_optional_table(conn, "email_deliveries", "episode_id, delivery_version")?,
                "capture_sessions": dump_optional_table(conn, "capture_sessions", "created_at")?,
                "capture_streams": dump_optional_table(conn, "capture_streams", "created_at")?,
                "capture_events": dump_optional_table(conn, "capture_events", "started_at, event_id")?,
                "media_objects": dump_optional_table(conn, "media_objects", "created_at, event_id")?,
                "browser_states": dump_optional_table(conn, "browser_states_v2", "created_at, state_key")?,
                "browser_observations": dump_optional_table(conn, "browser_observations_v2", "observed_at, event_id")?,
                "media_processing_jobs": dump_optional_table(conn, "media_processing_jobs", "updated_at, event_id")?,
                "media_work_units": dump_optional_table(conn, "media_work_units", "updated_at, id")?,
                "media_work_members": dump_optional_table(conn, "media_work_members", "work_unit_id, ordinal")?,
                "speaker_observations": dump_optional_table(conn, "speaker_observations", "started_at, event_id, id")?,
                "speaker_observation_sources": dump_optional_table(conn, "speaker_observation_sources", "speaker_observation_id, window_start_ms")?,
                "people": dump_optional_table(conn, "people", "display_name, id")?,
                "voice_profiles": dump_optional_table(conn, "voice_profiles", "person_id, id")?,
                "voice_samples": dump_optional_table(conn, "voice_samples", "speaker_observation_id, id")?,
                "voice_profile_proposals": dump_optional_table(conn, "voice_profile_proposals", "created_at, id")?,
                "voice_profile_revisions": dump_optional_table(conn, "voice_profile_revisions", "profile_id, id")?,
                "voice_sample_profile_assignments": dump_optional_table(conn, "voice_sample_profile_assignments", "sample_id, id")?,
                "voice_profile_proposal_profiles": dump_optional_table(conn, "voice_profile_proposal_profiles", "proposal_id, role, partition_ordinal, profile_id")?,
                "voice_profile_proposal_samples": dump_optional_table(conn, "voice_profile_proposal_samples", "proposal_id, partition_ordinal, sample_id")?,
                "identity_evidence": dump_optional_table(conn, "identity_evidence", "created_at, id")?,
                "person_name_claims": dump_optional_table(conn, "person_name_claims", "observed_at, id")?,
                "profile_identity_bindings": dump_optional_table(conn, "profile_identity_bindings", "updated_at, id")?,
                "person_facts": dump_optional_table(conn, "person_facts", "person_id, created_at, id")?,
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

fn dump_optional_table(
    conn: &rusqlite::Connection,
    name: &str,
    order: &str,
) -> crate::error::Result<Vec<serde_json::Value>> {
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Ok(Vec::new());
    }
    dump_table(conn, &format!("SELECT * FROM {name} ORDER BY {order}"))
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

// This service-account-authenticated compatibility route invokes the same
// generation-aware content deletion as account deletion. It does not remove
// the control-store identity or install the durable account tombstone; those
// steps remain exclusive to DELETE /api/account.
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
    info!("delete user request");

    state.store.delete_user(&user_id).await?;

    Ok(Json(json!({
        "deleted": true,
        "user_id": user_id,
    })))
}

// ── Health handler ────────────────────────────────────────────────────────────

async fn handle_health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let progress = state.store.legacy_checkpoint_reconciliation().await;
    Json(health_json(progress))
}

fn health_json(progress: store::LegacyCheckpointReconciliation) -> serde_json::Value {
    json!({
        "ok": true,
        "service": "kioku-enclave",
        "legacy_checkpoint_reconciliation_ready": progress.ready,
        "legacy_checkpoint_reconciliation": {
            "completed_scans": progress.completed_scans,
            "listed_live_objects": progress.listed_live_objects,
            "live_archives_checked": progress.live_archives_checked,
            "checkpoints_verified": progress.checkpoints_verified,
            "failures": progress.failures,
        }
    })
}

async fn limit_public_oauth(
    State(state): State<Arc<cp::CpState>>,
    req: Request,
    next: Next,
) -> Response {
    if state.oauth_limiter.consume("public-oauth").await {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "1")],
            Json(json!({"error": "temporarily_unavailable"})),
        )
            .into_response()
    }
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

// ── Attestation handler ───────────────────────────────────────────────────────

async fn handle_attestation(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match (&state.attestation_cache, &state.tls_keystone) {
        (Some(cache), Some(keystone)) => {
            let fingerprint = keystone.fingerprint_hex();
            match cache.get_token(&fingerprint).await {
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
                        Json(json!({"error": "attestation temporarily unavailable"})),
                    )
                }
            }
        }
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
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--measure-voice-eval-similarity") {
        let spec_path = args.get(2).expect(
            "--measure-voice-eval-similarity requires private specification, media directory, and voice model paths",
        );
        let media_directory = args.get(3).expect(
            "--measure-voice-eval-similarity requires private specification, media directory, and voice model paths",
        );
        let model_path = args.get(4).expect(
            "--measure-voice-eval-similarity requires private specification, media directory, and voice model paths",
        );
        let spec = std::fs::read_to_string(spec_path)
            .expect("read private voice similarity specification");
        match cp::voice_eval_similarity::measure_similarity(
            &spec,
            std::path::Path::new(media_directory),
            std::path::Path::new(model_path),
        ) {
            Ok(report) => print!("{report}"),
            Err(error) => {
                eprintln!("Voice similarity measurement failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--derive-voice-eval-assets") {
        let manifest_path = args.get(2).expect(
            "--derive-voice-eval-assets requires manifest, private recipe, artifact directory, and output directory paths",
        );
        let recipe_path = args.get(3).expect(
            "--derive-voice-eval-assets requires manifest, private recipe, artifact directory, and output directory paths",
        );
        let artifact_directory = args.get(4).expect(
            "--derive-voice-eval-assets requires manifest, private recipe, artifact directory, and output directory paths",
        );
        let output_directory = args.get(5).expect(
            "--derive-voice-eval-assets requires manifest, private recipe, artifact directory, and output directory paths",
        );
        let manifest =
            std::fs::read_to_string(manifest_path).expect("read voice evaluation manifest");
        let recipe = std::fs::read_to_string(recipe_path).expect("read private derivation recipe");
        match cp::voice_eval_assets::derive_assets(
            &manifest,
            &recipe,
            std::path::Path::new(artifact_directory),
            std::path::Path::new(output_directory),
        ) {
            Ok(receipt) => print!("{receipt}"),
            Err(error) => {
                eprintln!("Voice evaluation asset derivation failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--build-voice-eval-cases") {
        let manifest_path = args.get(2).expect(
            "--build-voice-eval-cases requires source manifest and private run-evidence paths",
        );
        let evidence_path = args.get(3).expect(
            "--build-voice-eval-cases requires source manifest and private run-evidence paths",
        );
        let manifest =
            std::fs::read_to_string(manifest_path).expect("read voice evaluation manifest");
        let evidence =
            std::fs::read_to_string(evidence_path).expect("read private voice run evidence");
        match cp::voice_eval_evidence::build_cases_json(&manifest, &evidence) {
            Ok(cases) => println!("{cases}"),
            Err(error) => {
                eprintln!("Voice evaluation case generation failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--score-voice-eval") {
        let path = args
            .get(2)
            .expect("--score-voice-eval requires one aggregate case JSON path");
        let raw = std::fs::read_to_string(path).expect("read voice evaluation cases");
        println!(
            "{}",
            cp::voice_eval::score_json(&raw).expect("score voice evaluation cases")
        );
        return;
    }
    if args.get(1).map(String::as_str) == Some("--validate-voice-eval-manifest") {
        let path = args
            .get(2)
            .expect("--validate-voice-eval-manifest requires one manifest JSON path");
        let raw = std::fs::read_to_string(path).expect("read voice evaluation manifest");
        match cp::voice_eval::validate_manifest_json(&raw) {
            Ok(sha256) => {
                println!("Voice evaluation manifest is valid; raw-byte SHA-256: {sha256}")
            }
            Err(error) => {
                eprintln!("Voice evaluation manifest validation failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("--check-voice-eval") {
        let manifest_path = args
            .get(2)
            .expect("--check-voice-eval requires manifest, aggregate cases, and report paths");
        let cases_path = args
            .get(3)
            .expect("--check-voice-eval requires manifest, aggregate cases, and report paths");
        let report_path = args
            .get(4)
            .expect("--check-voice-eval requires manifest, aggregate cases, and report paths");
        let manifest =
            std::fs::read_to_string(manifest_path).expect("read voice evaluation manifest");
        let cases = std::fs::read_to_string(cases_path).expect("read voice evaluation cases");
        let report = std::fs::read_to_string(report_path).expect("read voice evaluation report");
        if let Err(error) = cp::voice_eval::validate_release_bundle(&manifest, &cases, &report) {
            eprintln!("Voice evaluation release gate failed: {error}");
            std::process::exit(1);
        }
        println!("Voice evaluation release gates passed.");
        return;
    }
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
        if test_mode_enabled() {
            "http://localhost:8080".to_string()
        } else {
            panic!("ENCLAVE_AUDIENCE must be set");
        }
    });

    let run_sa_email = std::env::var("RUN_SA_EMAIL").unwrap_or_else(|_| {
        if test_mode_enabled() {
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

    let media_gcs: Arc<dyn crate::store::GcsClient> =
        if let Ok(bucket) = std::env::var("GCS_MEDIA_BUCKET") {
            Arc::new(GcpGcsClient::from_bucket(bucket))
        } else {
            Arc::clone(&gcs)
        };

    let store = Arc::new(Store::new_with_media(
        Arc::clone(&kms),
        Arc::clone(&gcs),
        media_gcs,
    ));
    Store::spawn_metrics_reporter(Arc::clone(&store));
    Store::spawn_legacy_checkpoint_reconciler(Arc::clone(&store));

    // ACME renewal (ADR-0003) shares the KMS/GCS clients; take clones before the
    // control store consumes the originals.
    let acme_kms = Arc::clone(&kms);
    let acme_gcs = Arc::clone(&gcs);

    // ── In-enclave control plane (ADR-0001): OAuth, sync, account, MCP. ─────────
    let control_store = Arc::new(cp::control_store::ControlStore::new(kms, gcs));

    let (jwt_secrets, google_web_client_secret) = if test_mode_enabled() {
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
    let apple_provider = if let Some(config) = cp_config.apple_sign_in.clone() {
        let private_key = if test_mode_enabled() {
            std::env::var("APPLE_PRIVATE_KEY_PEM")
                .unwrap_or_else(|_| panic!("APPLE_PRIVATE_KEY_PEM is required when Apple sign-in is configured in test mode"))
        } else {
            cp::fetch_secret_from_manager("kioku-apple-sign-in-private-key", "latest")
                .await
                .unwrap_or_else(|e| panic!("Failed to fetch Sign in with Apple private key: {e}"))
        };
        Some(Arc::new(
            cp::apple::AppleIdentityProvider::new(config, &private_key)
                .expect("valid Sign in with Apple private key"),
        ))
    } else {
        None
    };

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
            let fp = ks.fingerprint_hex();
            (Some(ks), Some(fp))
        }
        None => match tls::from_env(&cp_config.base_url, &enclave_audience)
            .await
            .expect("TLS config")
        {
            Some(ks) => {
                let fp = ks.fingerprint_hex();
                (Some(Arc::new(ks)), Some(fp))
            }
            None => (None, None),
        },
    };

    // This public token uses a verifier-specific HTTPS audience. It must never
    // use ATTEST_STS_AUDIENCE: a WIF-audience token is an STS bearer credential.
    let public_attestation_audience = format!(
        "{}/v1/attestation",
        cp_config.base_url.trim_end_matches('/')
    );
    let attestation_cache = cert_fingerprint.as_ref().map(|_| {
        Arc::new(
            attestation::AttestationCache::new(public_attestation_audience.clone())
                .expect("valid public attestation audience"),
        )
    });

    let state = Arc::new(AppState {
        store: Arc::clone(&store),
        id_token_verifier,
        attestation_cache: attestation_cache.clone(),
        tls_keystone: keystone.clone(),
    });

    // In-enclave query embedder for hybrid search. Loading is eager (boot
    // warm-up: ~470 MB of weights, seconds) so the first MCP query doesn't
    // eat the cold start; absence is non-fatal (FTS-only mode).
    let embedding_engine = embedding::EmbeddingEngine::from_env();
    let voice_engine = cp::voice_memory::VoiceEngine::from_env();
    assert!(
        voice_engine.is_some() || test_mode_enabled(),
        "the pinned voice embedding model is required in production"
    );

    // Production always reads the credential from Secret Manager. It is never
    // accepted as a launch-time environment override, which keeps it out of
    // the Confidential Space attestation token and VM configuration. Local
    // test mode may opt into Resend with RESEND_API_KEY or omit it entirely.
    let resend_api_key = resolve_resend_api_key(
        test_mode_enabled(),
        std::env::var("RESEND_API_KEY").ok(),
        || cp::fetch_secret_from_manager("kioku-resend-api-key", "latest"),
    )
    .await
    .unwrap_or_else(|error| panic!("Failed to configure Resend API key: {error}"));
    let email_from_address = std::env::var("EMAIL_FROM_ADDRESS")
        .unwrap_or_else(|_| "Kioku <notifications@notify.kiokuu.com>".to_string());

    let email_transport: Option<Arc<dyn cp::email_worker::EmailTransport>> =
        resend_api_key.map(|key| {
            Arc::new(cp::email_worker::ResendTransport::new(
                key,
                email_from_address,
            )) as Arc<dyn cp::email_worker::EmailTransport>
        });

    let cp_state = Arc::new(cp::CpState {
        store: Arc::clone(&store),
        control: control_store,
        user_verifier: Arc::new(cp::auth::UserIdTokenVerifier::new(
            cp_config.user_audiences(),
        )),
        reviewer_verifier: cp_config
            .reviewer_auth
            .as_ref()
            .map(|config| Arc::new(cp::auth::ReviewerIdentityVerifier::new(config.clone()))),
        apple_provider,
        sync_limiter: cp::limits::RateLimiter::new(10.0, 0.2),
        mcp_limiter: cp::limits::RateLimiter::new(60.0, 1.0),
        oauth_limiter: cp::limits::RateLimiter::new(120.0, 2.0),
        test_email_limiter: cp::limits::RateLimiter::new(3.0, 0.05),
        email_transport,
        config: cp_config,
        embedding: embedding_engine,
        voice: voice_engine,
    });

    // Internal summarizer cron (replaces Cloud Scheduler — no external trigger).
    cp::summarizer::spawn_scheduler(Arc::clone(&cp_state));
    cp::media_worker::spawn_scheduler(Arc::clone(&cp_state));
    cp::sync::spawn_account_deletion_reconciler(Arc::clone(&cp_state));

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
        .merge(cp::media::router())
        .merge(cp::query::router())
        .merge(cp::apple::authenticated_router())
        .layer(middleware::from_fn_with_state(
            Arc::clone(&cp_state),
            cp::auth::require_auth,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&cp_state),
            cp::cors::cors_middleware,
        ));
    let public_oauth = cp::oauth::router()
        .merge(cp::apple::public_router())
        .layer(middleware::from_fn_with_state(
            Arc::clone(&cp_state),
            limit_public_oauth,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&cp_state),
            cp::cors::cors_middleware,
        ));
    let control_plane = public_oauth
        .merge(cp_authed)
        .with_state(Arc::clone(&cp_state));

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/v1/attestation", get(handle_attestation))
        .merge(authenticated)
        .merge(control_plane)
        .layer(middleware::from_fn(security_headers))
        .with_state(Arc::clone(&state));

    // Listen
    match keystone {
        Some(ks) => {
            info!(addr = %addr, tls = true, "listening (in-enclave TLS termination)");
            serve_tls(listener, app, ks).await;
        }
        None if test_mode_enabled() => {
            warn!(addr = %addr, tls = false, "listening over plain HTTP in debug test mode");
            axum::serve(listener, app).await.expect("server error");
        }
        None => panic!("production startup refused: in-enclave TLS is not configured"),
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

#[cfg(test)]
mod email_startup_tests {
    use super::{health_json, resolve_resend_api_key};
    use crate::store::LegacyCheckpointReconciliation;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn local_test_mode_can_omit_email_without_fetching_a_secret() {
        let fetched = Arc::new(AtomicBool::new(false));
        let fetched_in_closure = Arc::clone(&fetched);

        let key = resolve_resend_api_key(true, None, move || async move {
            fetched_in_closure.store(true, Ordering::SeqCst);
            Ok("re_production_key".to_string())
        })
        .await
        .unwrap();

        assert_eq!(key, None);
        assert!(!fetched.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn production_ignores_environment_key_and_fetches_secret_manager() {
        let key = resolve_resend_api_key(false, Some("re_environment_key".into()), || async {
            Ok("re_secret_manager_key".to_string())
        })
        .await
        .unwrap();

        assert_eq!(key.as_deref(), Some("re_secret_manager_key"));
    }

    #[tokio::test]
    async fn production_normalizes_surrounding_whitespace_from_secret_manager() {
        let key = resolve_resend_api_key(false, None, || async {
            Ok("\n\tre_secret_manager_key\r\n".to_string())
        })
        .await
        .unwrap();

        assert_eq!(key.as_deref(), Some("re_secret_manager_key"));
    }

    #[tokio::test]
    async fn production_fails_closed_for_missing_or_malformed_secret() {
        let missing = resolve_resend_api_key(false, None, || async {
            Err("secret version unavailable".to_string())
        })
        .await;
        assert_eq!(missing.unwrap_err(), "secret version unavailable");

        let malformed = resolve_resend_api_key(false, None, || async {
            Ok("re_bad\r\nInjected: value".to_string())
        })
        .await;
        assert_eq!(
            malformed.unwrap_err(),
            "Resend API key has an invalid format"
        );
    }

    #[test]
    fn health_serializes_only_aggregate_checkpoint_readiness() {
        let health = health_json(LegacyCheckpointReconciliation {
            ready: true,
            completed_scans: 2,
            listed_live_objects: 3,
            live_archives_checked: 3,
            checkpoints_verified: 3,
            failures: 0,
        });
        assert_eq!(health["ok"], true);
        assert_eq!(health["service"], "kioku-enclave");
        assert_eq!(health["legacy_checkpoint_reconciliation_ready"], true);
        assert_eq!(
            health["legacy_checkpoint_reconciliation"]["checkpoints_verified"],
            3
        );
        assert!(health
            .as_object()
            .unwrap()
            .keys()
            .all(|key| !key.contains("user")));
    }
}
