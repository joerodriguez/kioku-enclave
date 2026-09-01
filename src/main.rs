//! # kioku-enclave — attested Kioku backend
//!
//! This process terminates TLS and handles server-side user plaintext inside a
//! GCP Confidential Space VM (AMD SEV). PostgreSQL mode deliberately trusts a
//! private managed database with structured plaintext; Vertex summarization
//! and user-configured webhook delivery are additional documented egresses.
//!
//! ## Authentication
//!
//! Retired `/v1/*` data routes require the former Google-signed service-account
//! ID token before returning an explicit `410 Gone`; they cannot read or write
//! user data. The public `/v1/attestation` verifier route remains active.
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
//! The fleet uses the shared Secret-Manager certificate required for
//! horizontally safe rolling releases.
//!
//! ## Public and retired compatibility routes
//!
//! | Method | Path                       | Description                                  |
//! |--------|----------------------------|----------------------------------------------|
//! | GET    | /health                    | PostgreSQL-backed liveness and readiness data |
//! | ANY    | /v1/* data routes          | Authenticated `410 Gone`; permanently retired|

use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{any, get},
    Router,
};
use serde_json::json;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod attestation;
mod auth;
mod cp;
mod crypto;
mod embedding;
mod error;
mod gcs;
mod ocr;
mod persistence;
mod tls;

/// Local test mode is deliberately impossible in release binaries. Checking
/// for the exact value also prevents values such as `0`, `false`, or an empty
/// variable from accidentally enabling test credentials.
pub(crate) fn test_mode_enabled() -> bool {
    cfg!(debug_assertions) && std::env::var("ENCLAVE_TEST_MODE").as_deref() == Ok("1")
}

const BAKED_IMAGE_CONFIGURATION_KEYS: &[&str] = &[
    "KIOKU_BUILD_PROFILE",
    "KMS_PROJECT",
    "KMS_LOCATION",
    "KMS_KEY_RING",
    "KMS_KEY",
    "GCS_MEDIA_BUCKET",
    "RUN_SA_EMAIL",
    "ENCLAVE_AUDIENCE",
    "ATTEST_STS_AUDIENCE",
    "GOOGLE_DESKTOP_CLIENT_ID",
    "GOOGLE_IOS_CLIENT_ID",
    "GOOGLE_WEB_CLIENT_ID",
    "APPLE_TEAM_ID",
    "APPLE_KEY_ID",
    "APPLE_IOS_CLIENT_ID",
    "APPLE_MACOS_CLIENT_ID",
    "APPLE_WEB_CLIENT_ID",
    "APNS_TEAM_ID",
    "APNS_PRODUCTION_KEY_ID",
    "APNS_SANDBOX_KEY_ID",
    "ADMIN_USER_IDS",
    "SIGNUP_LIMIT_PER_DAY",
    "BASE_URL",
    "WEB_ORIGIN",
    "BILLING_SERVICE_URL",
    "BILLING_SERVICE_AUDIENCE",
    "BILLING_ENFORCEMENT_MODE",
    "REVIEWER_AUTH_API_KEY",
    "REVIEWER_AUTH_UID",
    "REVIEWER_AUTH_EMAIL",
    "VERTEX_PROJECT",
    "VERTEX_LOCATION",
    "VERTEX_MODEL",
    "VERTEX_RECONCILIATION_MODEL",
    "MEMORY_RECONCILIATION_PRODUCER_CONTRACT_SHA256",
    "SCHEMA_FINALIZATION_PUBLIC_KEY_DER_BASE64",
    "SCHEMA_FINALIZATION_PUBLIC_KEY_SHA256",
    "POSTGRES_MAX_CONNECTIONS",
    "HEALTH_PORT",
    "DRAIN_TIMEOUT_SECONDS",
    "ENCLAVE_TLS",
];

/// Load the allowlisted image configuration assembled by the final Docker
/// stage. The file is deliberately parsed as data rather than sourced as shell
/// and is read before any provider/client construction. `PORT` and explicit
/// test-only variables remain process environment inputs; all security
/// configuration comes from the image file and overwrites ambient values.
fn load_baked_image_configuration() {
    let configured_path = std::env::var_os("KIOKU_BAKED_CONFIG");
    if let Some(value) = configured_path.as_deref() {
        if value != std::ffi::OsStr::new("/kioku-config") {
            panic!("KIOKU_BAKED_CONFIG must name the fixed baked image path");
        }
    }
    let path = configured_path
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/kioku-config"));
    let metadata = std::fs::symlink_metadata(&path)
        .unwrap_or_else(|error| panic!("baked image configuration is unavailable: {error}"));
    if !metadata.file_type().is_file() {
        panic!("baked image configuration must be a regular file");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        panic!("baked image configuration must not be group/world accessible");
    }
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("baked image configuration cannot be read: {error}"));
    let mut seen = Vec::with_capacity(BAKED_IMAGE_CONFIGURATION_KEYS.len());
    for (line_number, line) in contents.lines().enumerate() {
        let Some((name, value)) = line.split_once('=') else {
            panic!("invalid baked image configuration line {}", line_number + 1);
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            panic!("invalid baked image configuration line {}", line_number + 1);
        }
        if !BAKED_IMAGE_CONFIGURATION_KEYS.contains(&name) || seen.contains(&name) {
            panic!(
                "invalid baked image configuration key at line {}",
                line_number + 1
            );
        }
        std::env::set_var(name, value);
        seen.push(name);
    }
    if seen.len() != BAKED_IMAGE_CONFIGURATION_KEYS.len()
        || BAKED_IMAGE_CONFIGURATION_KEYS
            .iter()
            .any(|name| !seen.contains(name))
    {
        panic!("baked image configuration is incomplete");
    }
}

use crate::gcs::GcpGcsClient;
use crate::persistence::MemoryReconciliationActivationRepository;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApnsIdentifiers {
    team_id: String,
    production_key_id: String,
    sandbox_key_id: String,
}

fn resolve_apns_identifiers(
    profile: &str,
    team_id: Option<String>,
    production_key_id: Option<String>,
    sandbox_key_id: Option<String>,
) -> Result<Option<ApnsIdentifiers>, String> {
    let supplied = [
        team_id.as_ref(),
        production_key_id.as_ref(),
        sandbox_key_id.as_ref(),
    ]
    .into_iter()
    .filter(|value| value.is_some_and(|value| !value.trim().is_empty()))
    .count();
    if supplied == 0 && profile == "evaluation" {
        return Ok(None);
    }
    if supplied != 3 {
        return Err(format!(
            "{profile} startup requires a complete APNs team, production key, and sandbox key configuration"
        ));
    }
    Ok(Some(ApnsIdentifiers {
        team_id: team_id.unwrap().trim().to_string(),
        production_key_id: production_key_id.unwrap().trim().to_string(),
        sandbox_key_id: sandbox_key_id.unwrap().trim().to_string(),
    }))
}

// ── Application state ─────────────────────────────────────────────────────────

pub struct AppState {
    postgres: Arc<persistence::PostgresPersistence>,
    serving_lifecycle: Arc<ServingLifecycle>,
    vertex_reconciliation_model: Option<String>,
    vertex_location: String,
    reconciliation_producer_contract_sha256: Option<[u8; 32]>,
    /// JWKS verifier for Google ID tokens — the only authentication path.
    id_token_verifier: Arc<auth::IdTokenVerifier>,
    pub attestation_cache: Option<Arc<attestation::AttestationCache>>,
    pub tls_keystone: Option<Arc<tls::TlsKeystone>>,
}

#[derive(Default)]
struct ServingLifecycle {
    draining: AtomicBool,
    active_requests: AtomicUsize,
    shutdown_complete: AtomicBool,
    changed: tokio::sync::Notify,
}

impl ServingLifecycle {
    fn enter(self: &Arc<Self>) -> Option<ServingRequestGuard> {
        if self.draining.load(Ordering::Acquire) {
            return None;
        }
        self.active_requests.fetch_add(1, Ordering::AcqRel);
        if self.draining.load(Ordering::Acquire) {
            self.request_finished();
            return None;
        }
        Some(ServingRequestGuard {
            lifecycle: Arc::clone(self),
        })
    }

    fn request_finished(&self) {
        if self.active_requests.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.changed.notify_waiters();
        }
    }

    fn begin_draining(&self) {
        self.draining.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    fn is_ready(&self) -> bool {
        !self.draining.load(Ordering::Acquire)
    }

    async fn wait_for_quiet(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let changed = self.changed.notified();
            if self.active_requests.load(Ordering::Acquire) == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                return false;
            }
        }
    }

    fn finish_shutdown(&self) {
        self.shutdown_complete.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn wait_for_shutdown(&self) {
        loop {
            let changed = self.changed.notified();
            if self.shutdown_complete.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

struct ServingRequestGuard {
    lifecycle: Arc<ServingLifecycle>,
}

impl Drop for ServingRequestGuard {
    fn drop(&mut self) {
        self.lifecycle.request_finished();
    }
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

async fn legacy_data_plane_retired() -> Response {
    (
        StatusCode::GONE,
        Json(json!({
            "error": "legacy_data_plane_retired",
            "message": "Use Kioku Cloud Capture v2."
        })),
    )
        .into_response()
}

#[derive(Debug, PartialEq, Eq)]
struct BillingRequestObservation {
    route: &'static str,
    status: u16,
    status_class: &'static str,
    duration_ms: u64,
}

fn billing_request_observation(
    method: &Method,
    path: &str,
    status: StatusCode,
    duration_ms: u64,
) -> Option<BillingRequestObservation> {
    let route = match (method, path) {
        (method, "/api/billing") if method == Method::GET => "billing_summary",
        (method, "/api/billing/apple/account-token") if method == Method::GET => {
            "apple_account_token"
        }
        (method, "/api/billing/apple/purchase-attempt") if method == Method::POST => {
            "apple_purchase_attempt"
        }
        (method, "/api/billing/apple/transactions") if method == Method::POST => {
            "apple_transaction_bind"
        }
        (method, "/api/billing/apple/purchase-intent") if method == Method::POST => {
            "apple_purchase_intent"
        }
        (method, "/api/billing/recording-lease") if method == Method::POST => "recording_lease",
        (method, "/api/billing/offline-recording-usage") if method == Method::POST => {
            "offline_recording_usage"
        }
        _ => return None,
    };
    let status_class = match status.as_u16() {
        200..=299 => "2xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };
    Some(BillingRequestObservation {
        route,
        status: status.as_u16(),
        status_class,
        duration_ms,
    })
}

/// Emits one content-free event only for the fixed billing admission
/// method-and-route pairs. Raw paths, queries, account IDs, tokens, headers,
/// and bodies never enter the event, so its fields remain safe for
/// low-cardinality log metrics.
async fn observe_billing_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = Instant::now();
    let response = next.run(request).await;
    let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    if let Some(observation) =
        billing_request_observation(&method, &path, response.status(), duration_ms)
    {
        let route = observation.route;
        let status = observation.status;
        let status_class = observation.status_class;
        let duration_ms = observation.duration_ms;
        if status_class == "5xx" {
            warn!(
                target: "kioku::billing_request",
                metric_schema = "billing_request_v1",
                route,
                status,
                status_class,
                duration_ms,
                "billing request completed"
            );
        } else {
            info!(
                target: "kioku::billing_request",
                metric_schema = "billing_request_v1",
                route,
                status,
                status_class,
                duration_ms,
                "billing request completed"
            );
        }
    }
    response
}

fn legacy_data_plane_router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/ingest", any(legacy_data_plane_retired))
        .route("/v1/search", any(legacy_data_plane_retired))
        .route("/v1/context", any(legacy_data_plane_retired))
        .route("/v1/range", any(legacy_data_plane_retired))
        .route("/v1/episodes/upsert", any(legacy_data_plane_retired))
        .route("/v1/episodes/list", any(legacy_data_plane_retired))
        .route("/v1/episodes/members", any(legacy_data_plane_retired))
        .route("/v1/episodes/delete_range", any(legacy_data_plane_retired))
        .route("/v1/stats", any(legacy_data_plane_retired))
        .route("/v1/export", any(legacy_data_plane_retired))
        .route("/v1/user", any(legacy_data_plane_retired))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ))
        .with_state::<Arc<AppState>>(state)
}

// ── Health handler ────────────────────────────────────────────────────────────

async fn handle_livez() -> Json<serde_json::Value> {
    Json(json!({"ok": true, "service": "kioku-enclave"}))
}

async fn handle_health(State(state): State<Arc<AppState>>) -> Response {
    if !state.serving_lifecycle.is_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "service": "kioku-enclave",
                "reason": "draining",
            })),
        )
            .into_response();
    }
    let schema_ready = state
        .postgres
        .verify_reconciliation_runtime_schema(
            state.vertex_reconciliation_model.as_deref(),
            &state.vertex_location,
            state.reconciliation_producer_contract_sha256.as_ref(),
        )
        .await
        .is_ok();
    let activation = if schema_ready {
        state
            .postgres
            .memory_reconciliation_activation_status()
            .await
            .ok()
    } else {
        None
    };
    let ready = schema_ready && activation.is_some();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ok": ready,
            "service": "kioku-enclave",
            "persistence_backend": "postgres",
            "memory_reconciliation_activation": activation.map(|activation| json!({
                "phase": activation.phase.as_str(),
                "generation": activation.generation,
                "formation_backfill_complete": activation.formation_backfill_complete,
                "finalization_claim_drain_complete": activation.finalization_claim_drain_complete,
            })),
        })),
    )
        .into_response()
}

async fn admit_while_serving(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if matches!(request.uri().path(), "/health" | "/livez" | "/readyz") {
        return next.run(request).await;
    }
    let Some(_guard) = state.serving_lifecycle.enter() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::RETRY_AFTER, "1"),
            ],
            Json(json!({"error":"service_draining"})),
        )
            .into_response();
    };
    next.run(request).await
}

async fn wait_for_termination() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.expect("install Ctrl-C handler"),
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("install Ctrl-C handler");
}

async fn drain_on_termination(lifecycle: Arc<ServingLifecycle>, timeout: Duration) {
    wait_for_termination().await;
    lifecycle.begin_draining();
    info!(
        timeout_seconds = timeout.as_secs(),
        "shutdown drain started"
    );
    if lifecycle.wait_for_quiet(timeout).await {
        info!("shutdown drain completed");
    } else {
        warn!("shutdown drain deadline reached");
    }
    lifecycle.finish_shutdown();
}

async fn limit_public_oauth(
    State(state): State<Arc<cp::CpState>>,
    req: Request,
    next: Next,
) -> Response {
    if state
        .oauth_limiter
        .consume_scoped(&state.repositories, "oauth-public", "global")
        .await
    {
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

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--print-memory-reconciliation-producer-contract") {
        if args.len() != 4 {
            panic!(
                "--print-memory-reconciliation-producer-contract requires exact model and location arguments"
            );
        }
        let contract = cp::reconciler::producer_contract_sha256_label(&args[2], &args[3])
            .unwrap_or_else(|error| panic!("invalid reconciliation producer contract: {error}"));
        println!("{contract}");
        return;
    }
    load_baked_image_configuration();
    // Do not let Tokio create worker threads before the image-baked security
    // configuration has been parsed and installed. The Tokio main attribute
    // constructs the runtime before entering the
    // function body, which would make that ordering implicit and too late.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("construct Tokio runtime");
    runtime.block_on(async_main());
}

async fn async_main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--migrate-postgres") {
        migrate_postgres_release_schema().await;
        return;
    }
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
    info!(
        persistence_backend = "postgres",
        "using the sole structured-state authority"
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

    // ── KMS + encrypted media objects ────────────────────────────────────────

    let kms_project =
        std::env::var("KMS_PROJECT").expect("KMS_PROJECT must be baked into the image");
    let concrete_kms = Arc::new(
        crypto::GcpKmsClient::from_env()
            .expect("KMS env vars (KMS_PROJECT, KMS_LOCATION, KMS_KEY_RING, KMS_KEY) must be set"),
    );
    let kms: Arc<dyn crate::crypto::KmsClient> = Arc::clone(&concrete_kms) as _;

    let media_bucket =
        std::env::var("GCS_MEDIA_BUCKET").expect("GCS_MEDIA_BUCKET must be baked into the image");
    let media_gcs: Arc<dyn crate::gcs::GcsClient> =
        Arc::new(GcpGcsClient::from_bucket(media_bucket.clone()));
    // ADR-0036 derives the durable-recording provider name from the attested
    // project rather than accepting a mutable runtime override.
    let recording_media_bucket = format!("{kms_project}-enclave-recordings");
    if recording_media_bucket == media_bucket {
        panic!("durable recordings must be isolated from processing media storage");
    }
    let recording_media_gcs: Arc<dyn crate::gcs::GcsClient> =
        Arc::new(GcpGcsClient::from_bucket(recording_media_bucket));
    let application_media_gcs: Arc<dyn crate::gcs::GcsClient> =
        Arc::new(crate::gcs::RoutedMediaGcsClient::new(
            Arc::clone(&media_gcs),
            Arc::clone(&recording_media_gcs),
        ));

    let (jwt_secrets, google_web_client_secret) = if test_mode_enabled() {
        let jwt_secret =
            std::env::var("JWT_SECRET").unwrap_or_else(|_| "test-jwt-secret".to_string());
        let mut secrets = vec![jwt_secret];
        if let Ok(previous) = std::env::var("JWT_SECRET_PREVIOUS") {
            if !previous.is_empty() {
                secrets.push(previous);
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
                .unwrap_or_else(|error| panic!("Failed to fetch web client secret: {error}"));
        let jwt_secret = cp::fetch_secret_from_manager("kioku-jwt-secret", "latest")
            .await
            .unwrap_or_else(|error| panic!("Failed to fetch JWT secret: {error}"));
        (vec![jwt_secret], client_secret)
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

    let (keystone, cert_fingerprint) = match tls::from_env(&cp_config.base_url, &enclave_audience)
        .await
        .expect("TLS config")
    {
        Some(keystone) => {
            let fingerprint = keystone.fingerprint_hex();
            (Some(Arc::new(keystone)), Some(fingerprint))
        }
        None => (None, None),
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

    // In-enclave query embedder for hybrid search. Loading is eager (boot
    // warm-up: ~470 MB of weights, seconds) so the first MCP query doesn't
    // eat the cold start; absence is non-fatal (FTS-only mode).
    let embedding_engine = embedding::EmbeddingEngine::from_env();

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

    let build_profile = std::env::var("KIOKU_BUILD_PROFILE").unwrap_or_else(|_| {
        if test_mode_enabled() {
            "evaluation"
        } else {
            "production"
        }
        .into()
    });
    let apns_identifiers = resolve_apns_identifiers(
        &build_profile,
        std::env::var("APNS_TEAM_ID").ok(),
        std::env::var("APNS_PRODUCTION_KEY_ID").ok(),
        std::env::var("APNS_SANDBOX_KEY_ID").ok(),
    )
    .unwrap_or_else(|error| panic!("Failed to configure APNs: {error}"));
    let push_transport: Option<Arc<dyn cp::push::PushTransport>> =
        if let Some(identifiers) = apns_identifiers {
            let production_key = if test_mode_enabled() {
                std::env::var("APNS_PRODUCTION_PRIVATE_KEY_PEM").ok()
            } else {
                Some(
                    cp::fetch_secret_from_manager("kioku-apns-production-private-key", "latest")
                        .await
                        .unwrap_or_else(|error| {
                            panic!("Failed to configure production APNs credential: {error}")
                        }),
                )
            };
            let sandbox_key = if test_mode_enabled() {
                std::env::var("APNS_SANDBOX_PRIVATE_KEY_PEM").ok()
            } else {
                Some(
                    cp::fetch_secret_from_manager("kioku-apns-sandbox-private-key", "latest")
                        .await
                        .unwrap_or_else(|error| {
                            panic!("Failed to configure sandbox APNs credential: {error}")
                        }),
                )
            };
            match (production_key, sandbox_key) {
                (Some(production_key), Some(sandbox_key)) => {
                    let production = cp::push::ApnsCredential::new(
                        identifiers.team_id.clone(),
                        identifiers.production_key_id,
                        &production_key,
                    )
                    .expect("valid production APNs credential");
                    let sandbox = cp::push::ApnsCredential::new(
                        identifiers.team_id,
                        identifiers.sandbox_key_id,
                        &sandbox_key,
                    )
                    .expect("valid sandbox APNs credential");
                    Some(
                        Arc::new(cp::push::ApnsTransport::new(production, Some(sandbox)))
                            as Arc<dyn cp::push::PushTransport>,
                    )
                }
                _ if build_profile == "evaluation" => None,
                _ => panic!("production startup requires both APNs private-key secrets"),
            }
        } else {
            None
        };

    let billing_gateway: Arc<dyn cp::billing::BillingGateway> = Arc::new(
        cp::billing::HttpBillingGateway::from_env()
            .unwrap_or_else(|error| panic!("Invalid billing service configuration: {error}")),
    );

    let database_url = if test_mode_enabled() {
        std::env::var("POSTGRES_DATABASE_URL")
            .expect("POSTGRES_DATABASE_URL is required in PostgreSQL test mode")
    } else {
        cp::fetch_secret_from_manager("kioku-app-database-url", "latest")
            .await
            .unwrap_or_else(|error| panic!("Failed to fetch PostgreSQL URL: {error}"))
    };
    let root_ca_pem = if test_mode_enabled() {
        std::env::var("POSTGRES_ROOT_CA_PEM")
            .ok()
            .map(String::into_bytes)
    } else {
        Some(
            cp::fetch_secret_from_manager("kioku-app-database-ca", "latest")
                .await
                .unwrap_or_else(|error| panic!("Failed to fetch PostgreSQL root CA: {error}"))
                .into_bytes(),
        )
    };
    let max_connections = std::env::var("POSTGRES_MAX_CONNECTIONS")
        .unwrap_or_else(|_| "12".into())
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("POSTGRES_MAX_CONNECTIONS must be a positive integer"));
    let postgres = Arc::new(
        persistence::PostgresPersistence::connect(persistence::PostgresPoolConfig {
            database_url,
            root_ca_pem,
            max_connections,
            acquire_timeout: std::time::Duration::from_secs(5),
            statement_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap_or_else(|error| panic!("Failed to connect to PostgreSQL: {error}")),
    );
    postgres
        .verify_schema()
        .await
        .unwrap_or_else(|error| panic!("PostgreSQL is not release-ready: {error}"));
    let reconciliation_producer_contract = cp_config
        .vertex_reconciliation_model_requested
        .as_deref()
        .map(|reconciliation_model| {
            let digest = cp::reconciler::producer_contract_commitment(
                reconciliation_model,
                &cp_config.vertex_location,
            )
            .unwrap_or_else(|error| panic!("invalid reconciliation producer contract: {error}"));
            let label = cp::reconciler::producer_contract_sha256_label(
                reconciliation_model,
                &cp_config.vertex_location,
            )
            .unwrap_or_else(|error| panic!("invalid reconciliation producer contract: {error}"));
            if cp_config
                .memory_reconciliation_producer_contract_sha256
                .as_deref()
                != Some(label.as_str())
            {
                panic!("baked memory reconciliation producer contract does not match this binary");
            }
            digest
        });
    postgres
        .verify_reconciliation_runtime_schema(
            cp_config.vertex_reconciliation_model_requested.as_deref(),
            &cp_config.vertex_location,
            reconciliation_producer_contract.as_ref(),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("memory reconciliation runtime is not release-ready: {error}")
        });
    let media_objects: Arc<dyn persistence::MediaObjectStore> = Arc::new(
        persistence::GcsMediaObjectStore::new(Arc::clone(&application_media_gcs)),
    );
    let repositories = persistence::RepositorySet::postgres(Arc::clone(&postgres), media_objects);
    let serving_lifecycle = Arc::new(ServingLifecycle::default());
    let state = Arc::new(AppState {
        postgres: Arc::clone(&postgres),
        serving_lifecycle: Arc::clone(&serving_lifecycle),
        vertex_reconciliation_model: cp_config.vertex_reconciliation_model_requested.clone(),
        vertex_location: cp_config.vertex_location.clone(),
        reconciliation_producer_contract_sha256: reconciliation_producer_contract,
        id_token_verifier,
        attestation_cache: attestation_cache.clone(),
        tls_keystone: keystone.clone(),
    });
    let cp_state = Arc::new(cp::CpState {
        kms: Arc::clone(&kms),
        durable_recording_storage_bound: true,
        repositories,
        billing: billing_gateway,
        recording_lease_gate: Arc::new(cp::billing::RecordingLeaseGates::default()),
        user_verifier: Arc::new(cp::auth::UserIdTokenVerifier::new(
            cp_config.user_audiences(),
        )),
        reviewer_verifier: cp_config
            .reviewer_auth
            .as_ref()
            .map(|config| Arc::new(cp::auth::ReviewerIdentityVerifier::new(config.clone()))),
        apple_provider,
        capture_event_limiter: cp::limits::capture_event_limiter(),
        reference_batch_limiter: cp::limits::RateLimiter::new(20.0, 2.0),
        mcp_limiter: cp::limits::RateLimiter::new(60.0, 1.0),
        oauth_limiter: cp::limits::RateLimiter::new(120.0, 2.0),
        test_email_limiter: cp::limits::RateLimiter::new(3.0, 0.05),
        email_transport,
        push_transport,
        config: cp_config,
        embedding: embedding_engine,
    });

    // Billing detach is part of account-deletion completion.
    cp::billing::spawn_detach_worker(Arc::clone(&cp_state));
    // Internal workers use PostgreSQL claims/leases and are safe across the
    // horizontally scaled fleet.
    cp::summarizer::spawn_scheduler(Arc::clone(&cp_state));
    cp::query::spawn_episode_delete_worker(Arc::clone(&cp_state));
    cp::media_worker::spawn_scheduler(Arc::clone(&cp_state));
    cp::model_usage::spawn_delivery_worker(Arc::clone(&cp_state));
    cp::sync::spawn_account_deletion_reconciler(Arc::clone(&cp_state));
    cp::retention::spawn_reconciler(Arc::clone(&cp_state));

    // ── Retired legacy data-plane tombstones ─────────────────────────────────
    let authenticated = legacy_data_plane_router(Arc::clone(&state));

    // Public OAuth routes + auth-gated sync/account/MCP/REST routes.
    let cp_authed = cp::sync::router()
        .merge(cp::media::router())
        .merge(cp::playback::router())
        .merge(cp::retention::router())
        .merge(cp::push::router())
        .merge(cp::query::router())
        .merge(cp::billing::router())
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
        .route("/livez", get(handle_livez))
        .route("/readyz", get(handle_health))
        .route("/v1/attestation", get(handle_attestation))
        .merge(authenticated)
        .merge(control_plane)
        .layer(middleware::from_fn(observe_billing_request))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            admit_while_serving,
        ))
        .with_state(Arc::clone(&state));

    if let Some(health_port) = std::env::var("HEALTH_PORT").ok().map(|value| {
        value
            .parse::<u16>()
            .unwrap_or_else(|_| panic!("HEALTH_PORT must be a valid TCP port"))
    }) {
        if health_port == port {
            panic!("HEALTH_PORT must differ from PORT");
        }
        let health_addr = SocketAddr::from(([0, 0, 0, 0], health_port));
        let health_listener = tokio::net::TcpListener::bind(health_addr)
            .await
            .expect("bind health listener failed");
        let health_app = Router::new()
            .route("/livez", get(handle_livez))
            .route("/readyz", get(handle_health))
            .with_state(Arc::clone(&state));
        let health_lifecycle = Arc::clone(&serving_lifecycle);
        tokio::spawn(async move {
            info!(addr = %health_addr, "content-free health listener up");
            axum::serve(health_listener, health_app)
                .with_graceful_shutdown(async move { health_lifecycle.wait_for_shutdown().await })
                .await
                .expect("health listener failed");
        });
    }

    let drain_timeout = std::env::var("DRAIN_TIMEOUT_SECONDS")
        .unwrap_or_else(|_| "105".into())
        .parse::<u64>()
        .ok()
        .filter(|seconds| (1..=115).contains(seconds))
        .map(Duration::from_secs)
        .unwrap_or_else(|| panic!("DRAIN_TIMEOUT_SECONDS must be between 1 and 115"));
    let shutdown = drain_on_termination(Arc::clone(&serving_lifecycle), drain_timeout);

    // Listen
    match keystone {
        Some(ks) => {
            info!(addr = %addr, tls = true, "listening (in-enclave TLS termination)");
            serve_tls(listener, app, ks, shutdown).await;
        }
        None if test_mode_enabled() => {
            warn!(addr = %addr, tls = false, "listening over plain HTTP in debug test mode");
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await
                .expect("server error");
        }
        None => panic!("production startup refused: in-enclave TLS is not configured"),
    }
}

const MEMORY_RECONCILIATION_EXPAND_CONFIRM: &str = "memory-reconciliation-v26-expand";
const MEMORY_RECONCILIATION_FINALIZE_CONFIRM: &str = "memory-reconciliation-v26-finalize";
const MEMORY_RECONCILIATION_ACTIVATION_INSTALL_CONFIRM: &str = "memory-reconciliation-v27-install";
const MEMORY_RECONCILIATION_ACTIVATION_BACKFILL_CONFIRM: &str =
    "memory-reconciliation-v27-backfill";
const MEMORY_RECONCILIATION_ACTIVATION_DRAIN_CONFIRM: &str = "memory-reconciliation-v27-drain";
const MEMORY_RECONCILIATION_ACTIVATE_CONFIRM: &str = "memory-reconciliation-v27-activate";
const MEMORY_RECONCILIATION_PAUSE_CONFIRM: &str = "memory-reconciliation-v27-pause";
const MEMORY_RECONCILIATION_RESUME_CONFIRM: &str = "memory-reconciliation-v27-resume";
const POSTGRES_FINALIZATION_RECEIPT_ENV: &str = "POSTGRES_MIGRATION_FINALIZATION_RECEIPT";
const POSTGRES_FINALIZATION_SIGNATURE_ENV: &str = "POSTGRES_MIGRATION_FINALIZATION_SIGNATURE";
const POSTGRES_ACTIVATION_RECEIPT_ENV: &str = "POSTGRES_MIGRATION_ACTIVATION_RECEIPT";
const POSTGRES_ACTIVATION_SIGNATURE_ENV: &str = "POSTGRES_MIGRATION_ACTIVATION_SIGNATURE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PostgresMigrationReleasePhase {
    ExpandMemoryReconciliation,
    FinalizeMemoryReconciliation,
    InstallMemoryReconciliationActivation,
    AdvanceMemoryReconciliationActivationBackfill,
    DrainMemoryReconciliationActivation,
    ActivateMemoryReconciliation,
    PauseMemoryReconciliation,
    ResumeMemoryReconciliation,
}

impl PostgresMigrationReleasePhase {
    fn requires_activation_receipt(self) -> bool {
        matches!(
            self,
            Self::DrainMemoryReconciliationActivation
                | Self::ActivateMemoryReconciliation
                | Self::PauseMemoryReconciliation
                | Self::ResumeMemoryReconciliation
        )
    }
}

fn postgres_migration_release_phase(
    confirmation: Option<&str>,
) -> Result<PostgresMigrationReleasePhase, &'static str> {
    match confirmation {
        Some(MEMORY_RECONCILIATION_EXPAND_CONFIRM) => {
            Ok(PostgresMigrationReleasePhase::ExpandMemoryReconciliation)
        }
        Some(MEMORY_RECONCILIATION_FINALIZE_CONFIRM) => {
            Ok(PostgresMigrationReleasePhase::FinalizeMemoryReconciliation)
        }
        Some(MEMORY_RECONCILIATION_ACTIVATION_INSTALL_CONFIRM) => {
            Ok(PostgresMigrationReleasePhase::InstallMemoryReconciliationActivation)
        }
        Some(MEMORY_RECONCILIATION_ACTIVATION_BACKFILL_CONFIRM) => {
            Ok(PostgresMigrationReleasePhase::AdvanceMemoryReconciliationActivationBackfill)
        }
        Some(MEMORY_RECONCILIATION_ACTIVATION_DRAIN_CONFIRM) => {
            Ok(PostgresMigrationReleasePhase::DrainMemoryReconciliationActivation)
        }
        Some(MEMORY_RECONCILIATION_ACTIVATE_CONFIRM) => {
            Ok(PostgresMigrationReleasePhase::ActivateMemoryReconciliation)
        }
        Some(MEMORY_RECONCILIATION_PAUSE_CONFIRM) => {
            Ok(PostgresMigrationReleasePhase::PauseMemoryReconciliation)
        }
        Some(MEMORY_RECONCILIATION_RESUME_CONFIRM) => {
            Ok(PostgresMigrationReleasePhase::ResumeMemoryReconciliation)
        }
        _ => {
            Err("POSTGRES_MIGRATION_CONFIRM must authorize the exact reviewed schema release phase")
        }
    }
}

fn postgres_memory_reconciliation_activation_receipt(
    raw_receipt: Option<&str>,
    raw_signature: Option<&str>,
    phase: PostgresMigrationReleasePhase,
) -> Result<persistence::VerifiedMemoryReconciliationActivationReceipt, String> {
    let raw_receipt = raw_receipt.ok_or_else(|| {
        format!("{POSTGRES_ACTIVATION_RECEIPT_ENV} is required for an activation transition")
    })?;
    let receipt: persistence::MemoryReconciliationActivationReceipt =
        serde_json::from_str(raw_receipt).map_err(|error| {
            format!(
            "{POSTGRES_ACTIVATION_RECEIPT_ENV} must contain the strict activation receipt: {error}"
        )
        })?;
    let expected_transition = match phase {
        PostgresMigrationReleasePhase::DrainMemoryReconciliationActivation => {
            receipt.requested_phase == "draining"
                && matches!(receipt.previous_phase.as_str(), "installed" | "paused")
        }
        PostgresMigrationReleasePhase::ActivateMemoryReconciliation => {
            receipt.previous_phase == "draining" && receipt.requested_phase == "active"
        }
        PostgresMigrationReleasePhase::PauseMemoryReconciliation => {
            receipt.previous_phase == "active" && receipt.requested_phase == "paused"
        }
        PostgresMigrationReleasePhase::ResumeMemoryReconciliation => {
            receipt.previous_phase == "paused" && receipt.requested_phase == "active"
        }
        _ => false,
    };
    if !expected_transition {
        return Err(format!(
            "{POSTGRES_ACTIVATION_RECEIPT_ENV} does not authorize the confirmed transition"
        ));
    }
    let raw_signature = raw_signature.ok_or_else(|| {
        format!("{POSTGRES_ACTIVATION_SIGNATURE_ENV} is required for an activation transition")
    })?;
    let signature =
        persistence::MemoryReconciliationActivationSignature::from_base64(raw_signature)
            .map_err(|error| format!("{POSTGRES_ACTIVATION_SIGNATURE_ENV} is invalid: {error}"))?;
    let authorization =
        persistence::verify_memory_reconciliation_activation_authorization(receipt, signature)
            .map_err(|error| {
                format!("memory reconciliation activation authorization is invalid: {error}")
            })?;
    if !authorization.has_exact_canonical_transport(raw_receipt) {
        return Err(format!(
            "{POSTGRES_ACTIVATION_RECEIPT_ENV} must be the exact canonical signed bytes"
        ));
    }
    Ok(authorization)
}

fn postgres_schema_finalization_receipt(
    raw_receipt: Option<&str>,
    raw_signature: Option<&str>,
) -> Result<persistence::VerifiedSchemaFinalizationReceipt, String> {
    let raw_receipt = raw_receipt.ok_or_else(|| {
        format!("{POSTGRES_FINALIZATION_RECEIPT_ENV} is required for schema finalization")
    })?;
    let receipt: persistence::SchemaFinalizationReceipt = serde_json::from_str(raw_receipt)
        .map_err(|error| {
            format!(
                "{POSTGRES_FINALIZATION_RECEIPT_ENV} must contain the strict fleet receipt: {error}"
            )
        })?;
    let raw_signature = raw_signature.ok_or_else(|| {
        format!("{POSTGRES_FINALIZATION_SIGNATURE_ENV} is required for schema finalization")
    })?;
    let signature = persistence::SchemaFinalizationSignature::from_base64(raw_signature)
        .map_err(|error| format!("{POSTGRES_FINALIZATION_SIGNATURE_ENV} is invalid: {error}"))?;
    let authorization =
        persistence::verify_schema_finalization_authorization(receipt, signature)
            .map_err(|error| format!("schema finalization authorization is invalid: {error}"))?;
    if !authorization.has_exact_canonical_transport(raw_receipt) {
        return Err(format!(
            "{POSTGRES_FINALIZATION_RECEIPT_ENV} must be the exact canonical signed bytes"
        ));
    }
    Ok(authorization)
}

/// Dedicated release role used by the private Cloud Run migration job.
///
/// It deliberately runs after the same fixed baked configuration loader used
/// by serving (the Ed25519 trust anchor is public image identity), but before
/// KMS, GCS, provider, model, listener, and worker construction. The job can
/// therefore hold only PostgreSQL credentials plus the detached receipt and
/// signature and cannot choose its verification key or become a serving runtime.
/// The expand and finalize confirmations are distinct so a marker advance can
/// never be inferred from successful DDL or performed before fleet inventory.
async fn migrate_postgres_release_schema() {
    let confirmation = std::env::var("POSTGRES_MIGRATION_CONFIRM").ok();
    let phase = postgres_migration_release_phase(confirmation.as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    let finalization_receipt = match phase {
        PostgresMigrationReleasePhase::FinalizeMemoryReconciliation => {
            let raw_receipt = std::env::var(POSTGRES_FINALIZATION_RECEIPT_ENV).ok();
            let raw_signature = std::env::var(POSTGRES_FINALIZATION_SIGNATURE_ENV).ok();
            Some(
                postgres_schema_finalization_receipt(
                    raw_receipt.as_deref(),
                    raw_signature.as_deref(),
                )
                .unwrap_or_else(|error| panic!("{error}")),
            )
        }
        PostgresMigrationReleasePhase::ExpandMemoryReconciliation => None,
        _ => None,
    };
    let activation_receipt = if phase.requires_activation_receipt() {
        let raw_receipt = std::env::var(POSTGRES_ACTIVATION_RECEIPT_ENV).ok();
        let raw_signature = std::env::var(POSTGRES_ACTIVATION_SIGNATURE_ENV).ok();
        Some(
            postgres_memory_reconciliation_activation_receipt(
                raw_receipt.as_deref(),
                raw_signature.as_deref(),
                phase,
            )
            .unwrap_or_else(|error| panic!("{error}")),
        )
    } else {
        None
    };
    let database_url = std::env::var("POSTGRES_DATABASE_URL")
        .expect("POSTGRES_DATABASE_URL is required by --migrate-postgres");
    let root_ca_pem = std::env::var("POSTGRES_ROOT_CA_PEM")
        .ok()
        .map(String::into_bytes);
    let persistence = persistence::PostgresPersistence::connect(persistence::PostgresPoolConfig {
        database_url,
        root_ca_pem,
        max_connections: 2,
        acquire_timeout: std::time::Duration::from_secs(10),
        statement_timeout: std::time::Duration::from_secs(120),
    })
    .await
    .unwrap_or_else(|error| panic!("PostgreSQL migrator connection failed: {error}"));
    let result = match phase {
        PostgresMigrationReleasePhase::ExpandMemoryReconciliation => persistence
            .expand_memory_reconciliation_release_schema()
            .await
            .map(|result| serde_json::to_value(result).expect("release result must serialize")),
        PostgresMigrationReleasePhase::FinalizeMemoryReconciliation => persistence
            .finalize_memory_reconciliation_release_schema(
                finalization_receipt
                    .as_ref()
                    .expect("finalization authorization was verified before PostgreSQL connection"),
            )
            .await
            .map(|result| serde_json::to_value(result).expect("release result must serialize")),
        PostgresMigrationReleasePhase::InstallMemoryReconciliationActivation => persistence
            .install_memory_reconciliation_activation_schema()
            .await
            .map(|result| serde_json::to_value(result).expect("release result must serialize")),
        PostgresMigrationReleasePhase::AdvanceMemoryReconciliationActivationBackfill => persistence
            .advance_memory_reconciliation_activation_backfill()
            .await
            .map(|result| serde_json::to_value(result).expect("release result must serialize")),
        PostgresMigrationReleasePhase::DrainMemoryReconciliationActivation
        | PostgresMigrationReleasePhase::ActivateMemoryReconciliation
        | PostgresMigrationReleasePhase::PauseMemoryReconciliation
        | PostgresMigrationReleasePhase::ResumeMemoryReconciliation => persistence
            .transition_memory_reconciliation_activation(
                activation_receipt
                    .as_ref()
                    .expect("activation authorization was verified before PostgreSQL connection"),
            )
            .await
            .map(|result| serde_json::to_value(result).expect("release result must serialize")),
    }
    .unwrap_or_else(|error| panic!("PostgreSQL migration phase failed: {error}"));
    println!(
        "{}",
        serde_json::to_string(&result).expect("PostgreSQL schema-release result must serialize")
    );
}

#[cfg(test)]
mod postgres_migration_release_tests {
    use super::{
        postgres_memory_reconciliation_activation_receipt, postgres_migration_release_phase,
        postgres_schema_finalization_receipt, PostgresMigrationReleasePhase,
        MEMORY_RECONCILIATION_ACTIVATE_CONFIRM, MEMORY_RECONCILIATION_ACTIVATION_BACKFILL_CONFIRM,
        MEMORY_RECONCILIATION_ACTIVATION_DRAIN_CONFIRM,
        MEMORY_RECONCILIATION_ACTIVATION_INSTALL_CONFIRM, MEMORY_RECONCILIATION_EXPAND_CONFIRM,
        MEMORY_RECONCILIATION_FINALIZE_CONFIRM, MEMORY_RECONCILIATION_PAUSE_CONFIRM,
        MEMORY_RECONCILIATION_RESUME_CONFIRM,
    };

    #[test]
    fn populated_schema_release_requires_an_exact_phase_confirmation() {
        assert_eq!(
            postgres_migration_release_phase(Some(MEMORY_RECONCILIATION_EXPAND_CONFIRM)).unwrap(),
            PostgresMigrationReleasePhase::ExpandMemoryReconciliation
        );
        assert_eq!(
            postgres_migration_release_phase(Some(MEMORY_RECONCILIATION_FINALIZE_CONFIRM)).unwrap(),
            PostgresMigrationReleasePhase::FinalizeMemoryReconciliation
        );
        for (confirmation, expected) in [
            (
                MEMORY_RECONCILIATION_ACTIVATION_INSTALL_CONFIRM,
                PostgresMigrationReleasePhase::InstallMemoryReconciliationActivation,
            ),
            (
                MEMORY_RECONCILIATION_ACTIVATION_BACKFILL_CONFIRM,
                PostgresMigrationReleasePhase::AdvanceMemoryReconciliationActivationBackfill,
            ),
            (
                MEMORY_RECONCILIATION_ACTIVATION_DRAIN_CONFIRM,
                PostgresMigrationReleasePhase::DrainMemoryReconciliationActivation,
            ),
            (
                MEMORY_RECONCILIATION_ACTIVATE_CONFIRM,
                PostgresMigrationReleasePhase::ActivateMemoryReconciliation,
            ),
            (
                MEMORY_RECONCILIATION_PAUSE_CONFIRM,
                PostgresMigrationReleasePhase::PauseMemoryReconciliation,
            ),
            (
                MEMORY_RECONCILIATION_RESUME_CONFIRM,
                PostgresMigrationReleasePhase::ResumeMemoryReconciliation,
            ),
        ] {
            assert_eq!(
                postgres_migration_release_phase(Some(confirmation)).unwrap(),
                expected
            );
        }
        for refused in [
            None,
            Some(""),
            Some("empty-production-adr0040"),
            Some("memory-reconciliation-v26"),
        ] {
            assert!(postgres_migration_release_phase(refused).is_err());
        }
    }

    #[test]
    fn activation_transition_requires_the_exact_confirmation_domain() {
        for phase in [
            PostgresMigrationReleasePhase::DrainMemoryReconciliationActivation,
            PostgresMigrationReleasePhase::ActivateMemoryReconciliation,
            PostgresMigrationReleasePhase::PauseMemoryReconciliation,
            PostgresMigrationReleasePhase::ResumeMemoryReconciliation,
        ] {
            assert!(postgres_memory_reconciliation_activation_receipt(None, None, phase).is_err());
            assert!(postgres_memory_reconciliation_activation_receipt(
                Some("{}"),
                Some("not-base64"),
                phase,
            )
            .is_err());
        }
        assert!(postgres_memory_reconciliation_activation_receipt(
            Some("{}"),
            Some("not-base64"),
            PostgresMigrationReleasePhase::InstallMemoryReconciliationActivation,
        )
        .is_err());
    }

    #[test]
    fn finalization_requires_strict_receipt_and_detached_signature_inputs() {
        assert!(postgres_schema_finalization_receipt(None, None).is_err());
        assert!(postgres_schema_finalization_receipt(Some("{}"), None).is_err());
        let receipt = serde_json::json!({
            "contract": "kioku.postgresql.schema-finalization",
            "contract_version": 1,
            "release_version": 26,
            "expand_contract_sha256": format!("sha256:{}", "0".repeat(64)),
            "candidate_image_digest": format!("sha256:{}", "1".repeat(64)),
            "fleet_evidence_sha256": format!("sha256:{}", "2".repeat(64)),
            "observed_at": "2026-08-30T12:00:00.000Z",
            "expires_at": "2026-08-30T12:10:00.000Z",
            "candidate_instances": 2,
            "predecessor_instances": 0,
            "unavailable_instances": 0,
            "writer_enabled": false
        });
        assert!(postgres_schema_finalization_receipt(Some(&receipt.to_string()), None).is_err());
        let mut with_unknown = receipt;
        with_unknown["unreviewed"] = serde_json::json!(true);
        assert!(postgres_schema_finalization_receipt(
            Some(&with_unknown.to_string()),
            Some("not-base64")
        )
        .is_err());
    }
}
/// that connection.
async fn serve_tls<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    keystone: Arc<tls::TlsKeystone>,
    shutdown: F,
) where
    F: Future<Output = ()>,
{
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use tokio_rustls::TlsAcceptor;

    let acceptor = TlsAcceptor::from(Arc::clone(&keystone.server_config));
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        let accepted = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = listener.accept() => accepted,
        };
        let (tcp, _peer) = match accepted {
            Ok(pair) => pair,
            Err(error) => {
                warn!(error = %error, "TCP accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        connections.spawn(async move {
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

    let finish_connections = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(10), finish_connections)
        .await
        .is_err()
    {
        warn!("closing idle TLS connections after drain grace");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

#[cfg(test)]
mod email_startup_tests {
    use super::{resolve_apns_identifiers, resolve_resend_api_key, ServingLifecycle};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn serving_lifecycle_closes_admission_before_waiting_for_inflight_work() {
        let lifecycle = Arc::new(ServingLifecycle::default());
        let request = lifecycle.enter().expect("initial request admitted");
        lifecycle.begin_draining();
        assert!(!lifecycle.is_ready());
        assert!(lifecycle.enter().is_none());
        assert!(
            !lifecycle
                .wait_for_quiet(std::time::Duration::from_millis(1))
                .await
        );
        drop(request);
        assert!(
            lifecycle
                .wait_for_quiet(std::time::Duration::from_secs(1))
                .await
        );
        lifecycle.finish_shutdown();
        lifecycle.wait_for_shutdown().await;
    }

    #[test]
    fn production_startup_requires_complete_apns_identifiers() {
        assert!(resolve_apns_identifiers("production", None, None, None).is_err());
        assert!(resolve_apns_identifiers(
            "production",
            Some("ABCDE12345".into()),
            Some("PRODKEY123".into()),
            None,
        )
        .is_err());
        assert!(resolve_apns_identifiers(
            "production",
            Some("ABCDE12345".into()),
            Some("PRODKEY123".into()),
            Some("SBOXKEY123".into()),
        )
        .unwrap()
        .is_some());
        assert_eq!(
            resolve_apns_identifiers("evaluation", None, None, None).unwrap(),
            None
        );
    }

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
}

#[cfg(test)]
mod billing_request_observability_tests {
    use super::*;

    #[test]
    fn only_fixed_billing_routes_produce_content_free_observations() {
        assert_eq!(
            billing_request_observation(&Method::GET, "/api/billing", StatusCode::OK, 61),
            Some(BillingRequestObservation {
                route: "billing_summary",
                status: 200,
                status_class: "2xx",
                duration_ms: 61,
            })
        );
        assert_eq!(
            billing_request_observation(
                &Method::POST,
                "/api/billing/recording-lease",
                StatusCode::SERVICE_UNAVAILABLE,
                2_001,
            ),
            Some(BillingRequestObservation {
                route: "recording_lease",
                status: 503,
                status_class: "5xx",
                duration_ms: 2_001,
            })
        );
        assert_eq!(
            billing_request_observation(
                &Method::GET,
                "/api/billing/apple/account-token",
                StatusCode::CONFLICT,
                82,
            ),
            Some(BillingRequestObservation {
                route: "apple_account_token",
                status: 409,
                status_class: "4xx",
                duration_ms: 82,
            })
        );
        assert_eq!(
            billing_request_observation(
                &Method::POST,
                "/api/billing/apple/purchase-attempt",
                StatusCode::CONFLICT,
                31,
            ),
            Some(BillingRequestObservation {
                route: "apple_purchase_attempt",
                status: 409,
                status_class: "4xx",
                duration_ms: 31,
            })
        );
        assert_eq!(
            billing_request_observation(
                &Method::POST,
                "/api/billing/apple/transactions",
                StatusCode::OK,
                93,
            ),
            Some(BillingRequestObservation {
                route: "apple_transaction_bind",
                status: 200,
                status_class: "2xx",
                duration_ms: 93,
            })
        );
        assert_eq!(
            billing_request_observation(
                &Method::POST,
                "/api/billing/apple/purchase-intent",
                StatusCode::CONFLICT,
                47,
            ),
            Some(BillingRequestObservation {
                route: "apple_purchase_intent",
                status: 409,
                status_class: "4xx",
                duration_ms: 47,
            })
        );
        assert_eq!(
            billing_request_observation(
                &Method::POST,
                "/api/billing/offline-recording-usage",
                StatusCode::OK,
                75,
            ),
            Some(BillingRequestObservation {
                route: "offline_recording_usage",
                status: 200,
                status_class: "2xx",
                duration_ms: 75,
            })
        );
        assert_eq!(
            billing_request_observation(&Method::GET, "/api/accounts/private", StatusCode::OK, 1),
            None
        );
        assert_eq!(
            billing_request_observation(&Method::GET, "/api/billing/private", StatusCode::OK, 1),
            None
        );
        for (method, path) in [
            (Method::OPTIONS, "/api/billing"),
            (Method::OPTIONS, "/api/billing/recording-lease"),
            (Method::POST, "/api/billing"),
            (Method::GET, "/api/billing/recording-lease"),
            (Method::GET, "/api/billing/offline-recording-usage"),
            (Method::POST, "/api/billing/apple/account-token"),
            (Method::GET, "/api/billing/apple/purchase-attempt"),
            (Method::GET, "/api/billing/apple/transactions"),
            (Method::GET, "/api/billing/apple/purchase-intent"),
        ] {
            assert_eq!(
                billing_request_observation(&method, path, StatusCode::METHOD_NOT_ALLOWED, 1),
                None,
                "observed wrong method {method} for {path}"
            );
        }
    }
}

#[cfg(test)]
mod retired_route_tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn every_retired_v1_route_authenticates_before_gone() {
        let state = Arc::new(AppState {
            postgres: Arc::new(persistence::PostgresPersistence::disconnected_test_instance()),
            serving_lifecycle: Arc::new(ServingLifecycle::default()),
            vertex_reconciliation_model: None,
            vertex_location: "us-central1".into(),
            reconciliation_producer_contract_sha256: None,
            id_token_verifier: Arc::new(auth::IdTokenVerifier::new(
                "test-audience".into(),
                "caller@example.com".into(),
            )),
            attestation_cache: None,
            tls_keystone: None,
        });
        let router = legacy_data_plane_router(Arc::clone(&state)).with_state(state);
        for path in [
            "/v1/ingest",
            "/v1/search",
            "/v1/context",
            "/v1/range",
            "/v1/episodes/upsert",
            "/v1/episodes/list",
            "/v1/episodes/members",
            "/v1/episodes/delete_range",
            "/v1/stats",
            "/v1/export",
            "/v1/user",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::from(r#"{"user_id":"retired-route-test"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    /// The 410 tombstone is a published contract: clients (including shipped
    /// iOS builds) branch on this exact body. Deleting the handlers behind the
    /// `/v1` routes must not perturb a single byte of it, so pin the status,
    /// the content type, and the serialized body verbatim.
    #[tokio::test]
    async fn legacy_data_plane_410_response_is_byte_identical() {
        let response = legacy_data_plane_retired().await;

        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .expect("410 tombstone must declare a content type"),
            "application/json"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("410 tombstone body must be readable");
        assert_eq!(
            body.as_ref(),
            br#"{"error":"legacy_data_plane_retired","message":"Use Kioku Cloud Capture v2."}"#
        );
    }
}
