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
//! **ACME auto-renewal (ADR-0003):** when `ENCLAVE_ACME` is set, the enclave
//! obtains and renews that certificate itself from Let's Encrypt — HTTP-01
//! answered on :80, key generated in-TEE, state persisted KMS-encrypted in GCS,
//! live cert hot-swapped on renewal. See `acme.rs`. Static Secret-Manager or
//! `ENCLAVE_TLS_*` inputs also support a shared fleet certificate.
//!
//! ## Public and retired compatibility routes
//!
//! | Method | Path                       | Description                                  |
//! |--------|----------------------------|----------------------------------------------|
//! | GET    | /health                    | Liveness probe; `{"ok":true}` + WAL counts   |
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
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod acme;
// ADR-0022 format/crypto/backend and checkpoint/WAL primitives only.  These are
// intentionally not connected to the live Store, SQLite VFS, witness, routes,
// or write authority.
mod archive_v3;
// Inactive archive-v3 export parity seam. Its cancellation-aware witness,
// exact walker, deletion-safe publication admission, and canonical product
// adapter are sealed test-only blockers; live `/api/export` remains legacy.
mod archive_v3_export;
// Inactive ADR-0022 GCS semantic adapters. Runtime/authority wiring remains
// intentionally absent.
mod archive_v3_gcs;
// Inactive archive-v3 registry KMS adapter. It reuses only the legacy client's
// exact key and attestation-token source, and has no provider construction,
// Store/startup/env/route/flag/authority wiring.
mod archive_v3_registry_kms;
// Concrete but inactive REST transport. It has no environment constructor,
// token acquisition, Store/VFS/witness connection, or production authority.
mod archive_v3_gcs_http;
// Inactive, archive-GCS-only Confidential Space bearer path. It deliberately
// has its own audience type, launcher boundary, STS client, cache, and no
// Store/VFS/route/transport/authority connection.
mod archive_v3_gcs_auth;
// Inactive ADR-0022 create-ahead/deletion lifecycle receipts and canonical
// hash-chained inventory codec. No runtime or provider authority is connected.
mod archive_v3_lifecycle;
// Inactive exact-name, control-key-derived encrypted lifecycle page store. It
// has no provider implementation, list API, runtime construction, or walker.
mod archive_v3_lifecycle_page_store;
// Inactive capability-only resolution for deletion before the first witness
// send. It has injected exact-read/control boundaries and no runtime caller.
mod archive_v3_witness_disposition;
// Inactive authenticated inventory coordinator. It joins exact tombstoned
// witness recovery, the frozen lifecycle snapshot, reachability, and encrypted
// v2 pages without startup/runtime/provider construction or deletion calls.
mod archive_v3_inventory_coordinator;
// Inactive, type-separated durable execution ledger for pre-witness deletion.
// It persists evidence commitments only and has no provider, page-store,
// witness, Store, startup, route, or destructive implementation.
mod archive_v3_pre_witness_deletion;
// Inactive exact-name authenticated reachability visitor. Its report remains
// non-authorizing and is consumed only by the inactive inventory coordinator.
mod archive_v3_reachability;
// Inactive ADR-0022 restart-safe genesis coordinator. It has no provider
// construction or authority wiring; only deterministic fake-tested contracts.
mod archive_v3_genesis;
// Inactive ADR-0022 genesis backend adapter. It composes the encrypted
// control-store lifecycle ledger with injected providers behind an unmintable
// release token; nothing in startup constructs it.
mod archive_v3_genesis_backend;
// Config-gated ADR-0022 genesis trigger at sign-in (genesis spine G9). The
// gate defaults to off and additionally requires the image-baked archive-v3
// runtime coordinates, so a production image today never fires it.
mod archive_v3_genesis_trigger;
// Inactive ADR-0022 deletion-driver seam. It accepts only witness-fenced
// archive contexts and authenticated canonical metadata; no route, Store,
// runtime/provider construction, or production authority is connected.
mod archive_v3_deletion;
// ADR-0022 archive-v3 deletion drive ladder. It orchestrates the reviewed
// witness FSM, inventory coordinator and deletion driver for a
// WAL-authoritative account; it mints no destructive authority of its own and
// is reachable only when an archive-v3 deletion runtime is installed.
mod archive_v3_deletion_lane;
// Inactive ADR-0022 immutable sparse-extent tree. It is fake-tested only and
// has no Store/VFS/provider/witness/route/flag/authority wiring.
mod archive_v3_extent;
// Inactive ADR-0022 SQLite Extent VFS and page cache paging layer.
mod archive_v3_extent_vfs;
// Inactive ADR-0022 WAL-to-extent streaming converter.
mod archive_v3_wal_to_extent;
// Inactive ADR-0022 Extent shadow coordinator and parity verifier.
mod archive_v3_extent_shadow;
// Inactive ADR-0022 durable shadow extent commit protocol.
mod archive_v3_extent_commit;
// Inactive ADR-0022 encrypted vector accelerator sidecar.
mod archive_v3_vector_accelerator;
// ADR-0022 Phase 3 comprehensive structural gate suite.
#[cfg(test)]
mod archive_v3_phase3_gates;
// Inactive ADR-0022 Firestore witness transaction adapter and bounded concrete
// REST transport. They have no runtime construction, Store, VFS, route, or
// authority wiring.
mod archive_v3_firestore_http;
mod archive_v3_firestore_witness;
// Inactive, Firestore-witness-only Confidential Space bearer path. It is
// deliberately distinct from the KMS and public attestation credential paths.
mod archive_v3_firestore_auth;
// Inert, non-authoritative singleton transaction probe for the dedicated
// named Firestore witness database. It has no Store, route, root, or rollout
// wiring while its image-baked mode remains off.
mod archive_v3_firestore_probe;
// Inactive, no-I/O composition of the exact Firestore namespace, dedicated
// bearer, fixed REST transport, and shadow-coordinator transaction boundary.
mod archive_v3_firestore_shadow;
mod archive_v3_journal;
// Inactive ADR-0022 legacy-conversion session codec and inventory ledger.
// It has no source adapter, provider, Store, VFS, route, witness CAS, recovery,
// deletion, cutover, or other production authority.
mod archive_v3_legacy_extent_session;
mod archive_v3_operation;
// Inactive ADR-0022 logical-write idempotency gate. It defines only a bounded,
// domain-sealed replay contract plus a test exemplar, and no production ledger,
// WAL publisher, Store authority, provider, witness, route, worker, or startup.
mod archive_v3_wal_idempotency;
// Inactive one-owner logical mutation/capture/durable-publication protocol.
// It has no production publication authority, provider construction, runtime,
// Store registry, startup, route, acknowledgement, or activation path.
mod archive_v3_wal_owner;
// Inactive Phase-1-only ShadowWal owner lease lifecycle. It is type-separated
// from the WalAuthoritative publisher and exposes no Store, capture, root,
// object, acknowledgement, startup, route, or serving capability.
// ADR-0022's bounded synchronous WAL-shadow capture state. It is not yet a
// registered SQLite VFS and has no Store, provider, route, or authority wiring.
mod archive_v3_shadow;
// Inactive ADR-0022 durable shadow-session codec. The operation module persists
// it, but no Store, VFS, startup, flag, route, or authority wiring constructs it.
mod archive_v3_shadow_session;
// Inactive ADR-0022 private-staging SQLite shadow-parity verifier. Only the
// exact composite recovery seam can mint its owned production capability; it
// has no Store, VFS, provider, route, scheduler, flag, or authority wiring.
mod archive_v3_shadow_parity;
// Inactive ADR-0022 single-archive WAL runtime capability. Its provider bundle
// remains private and can be sealed only by consuming an exact commitment-
// matched durable control-store binding; startup never constructs it and it
// has no Store/VFS/lifecycle, route, health, admission, deletion, task, flag,
// callback, operation, or authority wiring.
mod archive_v3_maintenance_import;
// ADR-0022's extracted root-advance core (genesis spine G1): the exact
// witness-advance provider boundary and zero-WAL root-candidate builder. It
// has no Store, VFS, startup, route, flag, provider-construction, or
// authority wiring.
mod archive_v3_root_advance;
mod archive_v3_serving_relaunch;
// Inactive ADR-0022 genesis bytes producer and witness-ladder driver (genesis
// spine G5/G6). It consumes only injected released providers, is fake-tested
// for kill-and-restart convergence, and has no Store, VFS, startup, route,
// flag, provider-construction, or authority wiring.
mod archive_v3_shadow_runtime;
mod archive_v3_wal_genesis;
// ADR-0022 checkpoint upload/recovery is compiled and fake-tested, but has no
// Store/VFS runtime connection, provider construction, flag, route, or authority.
mod archive_v3_shadow_checkpoint;
// Inactive ADR-0022 bounded multi-commit WAL lineage and exact witnessed
// checkpoint+WAL recovery into an owned private staging copy. It never lists
// objects and has no VFS, Store, startup, flag, provider, route, or authority.
mod archive_v3_shadow_wal;
// Inactive ADR-0022 checkpoint publication composition with durable exact-
// candidate reconciliation. It has no Store, VFS, route, flag, provider
// construction, or authority wiring.
mod archive_v3_shadow_coordinator;
// ADR-0022's opt-in transparent SQLite VFS wrapper. It is compiled and
// oracle-tested, but startup never registers it and it has no Store/provider/
// witness/route/authority wiring.
mod archive_v3_sqlite_vfs;
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
// Inactive migration-only reader for the historic GCM envelope. It has no
// Store, GCS provider, route, flag, or authority wiring.
mod legacy_gcm;
mod ocr;
mod persistence;
mod schema_ladder;
mod search;
mod storage_observability;
mod store;
// `fetch_context` outlived the `/v1/context` handler that called it; the MCP
// `get_context` tool is served by `cp::mcp_query::fetch_safe_context` instead.
// Retained with its own regression coverage as the reference query shape.
#[allow(dead_code)]
mod timeline;
mod tls;

/// Local test mode is deliberately impossible in release binaries. Checking
/// for the exact value also prevents values such as `0`, `false`, or an empty
/// variable from accidentally enabling test credentials.
pub(crate) fn test_mode_enabled() -> bool {
    cfg!(debug_assertions) && std::env::var("ENCLAVE_TEST_MODE").as_deref() == Ok("1")
}

/// The zero-archive image is destructive by construction: every legacy
/// archive is about to enter the deletion owner, so minting or refreshing a
/// recovery checkpoint first is both unnecessary and harmful. In particular,
/// a large checkpoint upload can retain the same content-write admission for
/// minutes and repeatedly outrun the deletion owner on restart. Only the exact
/// attested zero budget selects this exception; ordinary and malformed values
/// retain the established fail-closed startup path (the latter is rejected by
/// [`cp::CpConfig`] before request admission).
fn should_spawn_legacy_checkpoint_reconciler(signup_limit_per_day: &str) -> bool {
    signup_limit_per_day != "0"
}

#[cfg(test)]
mod zero_cutover_startup_tests {
    use super::should_spawn_legacy_checkpoint_reconciler;

    #[test]
    fn only_the_exact_closed_signup_budget_skips_legacy_checkpoint_work() {
        assert!(!should_spawn_legacy_checkpoint_reconciler("0"));
        for ordinary_or_invalid in ["1", "25", "", "00", "-1", "unlimited"] {
            assert!(
                should_spawn_legacy_checkpoint_reconciler(ordinary_or_invalid),
                "unexpectedly suppressed established startup validation for {ordinary_or_invalid:?}"
            );
        }
    }
}

const BAKED_IMAGE_CONFIGURATION_KEYS: &[&str] = &[
    "KIOKU_BUILD_PROFILE",
    "KMS_PROJECT",
    "KMS_LOCATION",
    "KMS_KEY_RING",
    "KMS_KEY",
    "GCS_BUCKET",
    "GCS_MEDIA_BUCKET",
    "GCS_LEGACY_MEDIA_BUCKET",
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
    "PERSISTENCE_BACKEND",
    "POSTGRES_SCHEMA_MODE",
    "POSTGRES_MAX_CONNECTIONS",
    "HEALTH_PORT",
    "DRAIN_TIMEOUT_SECONDS",
    "ENCLAVE_TLS",
    "ENCLAVE_ACME",
    "ENCLAVE_ACME_DIRECTORY",
    "ENCLAVE_ACME_CONTACT",
    "ARCHIVE_WITNESS_SHADOW_MODE",
    "ARCHIVE_WITNESS_PROJECT_ID",
    "ARCHIVE_WITNESS_PROJECT_NUMBER",
    "ARCHIVE_WITNESS_DATABASE_ID",
    "ARCHIVE_V3_SHADOW_RUNTIME_MODE",
    "ARCHIVE_V3_ARCHIVE_BUCKET",
    "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER",
    "ARCHIVE_V3_REGISTRY_KMS_VERSION",
    "ARCHIVE_V3_WITNESS_PROJECT_ID",
    "ARCHIVE_V3_WITNESS_PROJECT_NUMBER",
    "ARCHIVE_V3_WITNESS_DATABASE_ID",
    "ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT",
    "GENESIS_WAL_NATIVE",
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

use crate::store::{GcpGcsClient, Store};

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
    pub store: Arc<Store>,
    persistence_backend: PersistenceBackend,
    postgres: Option<Arc<persistence::PostgresPersistence>>,
    serving_lifecycle: Arc<ServingLifecycle>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistenceBackend {
    LegacySqliteGcs,
    Postgres,
}

impl PersistenceBackend {
    fn from_env() -> Result<Self, String> {
        match std::env::var("PERSISTENCE_BACKEND")
            .unwrap_or_else(|_| "sqlite-gcs".into())
            .as_str()
        {
            "sqlite-gcs" => Ok(Self::LegacySqliteGcs),
            "postgres" => Ok(Self::Postgres),
            value => Err(format!("unsupported PERSISTENCE_BACKEND {value:?}")),
        }
    }

    const fn is_legacy(self) -> bool {
        matches!(self, Self::LegacySqliteGcs)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::LegacySqliteGcs => "sqlite-gcs",
            Self::Postgres => "postgres",
        }
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
    if let Some(postgres) = state.postgres.as_ref() {
        let ready = postgres.verify_schema().await.is_ok();
        let status = if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        return (
            status,
            Json(json!({
                "ok": ready,
                "service": "kioku-enclave",
                "persistence_backend": state.persistence_backend.as_str(),
            })),
        )
            .into_response();
    }
    let progress = state.store.legacy_checkpoint_reconciliation().await;
    let wal_serving = state.store.wal_serving_health();
    (StatusCode::OK, Json(health_json(progress, wal_serving))).into_response()
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

fn health_json(
    progress: store::LegacyCheckpointReconciliation,
    wal_serving: store::WalServingHealth,
) -> serde_json::Value {
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
        },
        // Counts only, never a user id or an archive id. The three `_total`
        // fields are EVENT counters: a lane that keeps dying and healing under
        // budget shows a steady `serving: 1` but a climbing `relaunches_total`,
        // so a genuine-corruption heal loop cannot hide behind a green probe.
        "wal_serving": {
            "serving": wal_serving.serving,
            "terminal": wal_serving.terminal,
            "quarantined": wal_serving.quarantined,
            "relaunches_total": wal_serving.relaunches_total,
            "launch_failures_total": wal_serving.launch_failures_total,
            "quarantines_total": wal_serving.quarantines_total,
        }
    })
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
    let persistence_backend = PersistenceBackend::from_env()
        .unwrap_or_else(|error| panic!("Invalid persistence configuration: {error}"));
    info!(
        persistence_backend = persistence_backend.as_str(),
        "selected one application persistence authority"
    );

    // Non-authoritative ADR-0022 transport probe. Off is the baked default and
    // performs zero I/O. probe-v1 is awaited under one fixed deadline before
    // any application Store/KMS/GCS construction. Its redacted result is
    // observational only and never gates startup, health, or archive authority.
    if persistence_backend.is_legacy() {
        archive_v3_firestore_probe::run_startup_probe(
            archive_v3_firestore_probe::FirestoreProbeStartupConfig::from_env()
                .expect("valid image-baked archive witness probe configuration"),
        )
        .await
        .expect("construct archive witness transport probe");
    }

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

    let kms_project =
        std::env::var("KMS_PROJECT").expect("KMS_PROJECT must be baked into the image");
    let concrete_kms = Arc::new(
        crypto::GcpKmsClient::from_env()
            .expect("KMS env vars (KMS_PROJECT, KMS_LOCATION, KMS_KEY_RING, KMS_KEY) must be set"),
    );
    let kms: Arc<dyn crate::crypto::KmsClient> = Arc::clone(&concrete_kms) as _;
    let gcs: Arc<dyn crate::store::GcsClient> =
        Arc::new(GcpGcsClient::from_env().expect("GCS_BUCKET must be set"));

    let media_bucket =
        std::env::var("GCS_MEDIA_BUCKET").expect("GCS_MEDIA_BUCKET must be baked into the image");
    let legacy_media_bucket = std::env::var("GCS_LEGACY_MEDIA_BUCKET")
        .expect("GCS_LEGACY_MEDIA_BUCKET must be baked into the image");
    let index_bucket =
        std::env::var("GCS_BUCKET").expect("GCS_BUCKET must be baked into the image");
    if legacy_media_bucket != index_bucket {
        panic!("GCS_LEGACY_MEDIA_BUCKET must exactly match GCS_BUCKET for the Phase-0 dual-media migration");
    }
    let media_gcs: Arc<dyn crate::store::GcsClient> =
        Arc::new(GcpGcsClient::from_bucket(media_bucket.clone()));
    // ADR-0036 deliberately derives the fourth provider name from the already
    // baked, image-attested project rather than accepting a mutable runtime
    // override. Terraform uses the same collision-resistant project suffix.
    let recording_media_bucket = format!("{kms_project}-enclave-recordings");
    if recording_media_bucket == index_bucket
        || recording_media_bucket == media_bucket
        || recording_media_bucket == legacy_media_bucket
    {
        panic!("the durable recordings bucket must be isolated from index and processing media storage");
    }
    let recording_media_gcs: Arc<dyn crate::store::GcsClient> =
        Arc::new(GcpGcsClient::from_bucket(recording_media_bucket));
    let legacy_media_gcs: Arc<dyn crate::store::GcsClient> =
        Arc::new(GcpGcsClient::from_bucket(legacy_media_bucket));

    let application_media_gcs: Arc<dyn crate::store::GcsClient> =
        Arc::new(crate::store::RoutedMediaGcsClient::new(
            Arc::clone(&media_gcs),
            Some(Arc::clone(&recording_media_gcs)),
        ));
    let (store, legacy_control_gcs): (Arc<Store>, Arc<dyn crate::store::GcsClient>) =
        if persistence_backend.is_legacy() {
            let store = Arc::new(Store::new_with_recording_media(
                Arc::clone(&kms),
                Arc::clone(&gcs),
                media_gcs,
                recording_media_gcs,
                legacy_media_gcs,
            ));
            Store::spawn_metrics_reporter(Arc::clone(&store));
            (store, Arc::clone(&gcs))
        } else {
            let disabled: Arc<dyn crate::store::GcsClient> =
                Arc::new(persistence::DisabledLegacyGcs);
            (
                Arc::new(Store::new(Arc::clone(&kms), Arc::clone(&disabled))),
                disabled,
            )
        };

    // ACME renewal (ADR-0003) shares the KMS/GCS clients; take clones before the
    // control store consumes the originals.
    let acme_kms = Arc::clone(&kms);
    let acme_gcs = Arc::clone(&gcs);

    // ── In-enclave control plane (ADR-0001): OAuth, sync, account, MCP. ─────────
    let control_store = Arc::new(cp::control_store::ControlStore::new_with_store(
        Arc::clone(&kms),
        legacy_control_gcs,
        Arc::clone(&store),
    ));
    if persistence_backend.is_legacy() {
        control_store
            .initialize_legacy_fence_key()
            .await
            .unwrap_or_else(|error| panic!("Failed to initialize legacy fence key: {error}"));
    }

    if persistence_backend.is_legacy() {
        // ADR-0022 Group D: install the exact archive-v3 deletion runtime before
        // any selected account can enter deletion or the startup reconciler can
        // revisit an interrupted operation. Off-profile images install nothing;
        // an active but malformed runtime fails startup closed. The principal and
        // lifecycle-page roots are derived from the durable encrypted Control DEK
        // and no raw key material escapes this composition.
        if let Some(deployment) =
            archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeDeployment::from_baked_env()
                .unwrap_or_else(|error| panic!("Failed to validate deletion runtime: {error}"))
        {
            let secrets = control_store
                .archive_deletion_runtime_secrets()
                .await
                .unwrap_or_else(|error| panic!("Failed to derive deletion runtime keys: {error}"));
            let factory = Arc::new(
                archive_v3_shadow_runtime::ProductionArchiveDeletionRuntimeFactory::new(
                    deployment,
                    Arc::clone(&concrete_kms),
                    Arc::clone(&control_store),
                    secrets.lifecycle_page_key,
                    Arc::clone(&secrets.principal_key),
                ),
            );
            store
                .install_wal_deletion_lane(Arc::new(
                    archive_v3_deletion_lane::WalDeletionLane::new(secrets.principal_key, factory),
                ))
                .unwrap_or_else(|error| {
                    panic!("Failed to install archive-v3 deletion runtime: {error}")
                });
            info!("archive-v3 account deletion runtime installed");
        }
        let baked_signup_limit = std::env::var("SIGNUP_LIMIT_PER_DAY")
            .expect("SIGNUP_LIMIT_PER_DAY must be baked into the image");
        if should_spawn_legacy_checkpoint_reconciler(&baked_signup_limit) {
            Store::spawn_legacy_checkpoint_reconciler(Arc::clone(&store));
        } else {
            info!("legacy checkpoint reconciliation skipped for the zero-archive cutover");
        }
        let recovered_rebinds = control_store
            .reconcile_pending_identity_rebinds()
            .await
            .unwrap_or_else(|error| panic!("Failed to reconcile identity rebinds: {error}"));
        if recovered_rebinds > 0 {
            info!(
                recovered = recovered_rebinds,
                "reconciled pending identity rebinds before request admission"
            );
        }

        // ADR-0022: a user whose archive durably reached the wal_authoritative
        // terminal must never see legacy snapshot persistence again, across every
        // restart. Install the Control-derived selections before any request is
        // admitted; any refusal fails startup closed. Content-free: count only.
        let wal_authority_selections = control_store
            .load_wal_authoritative_persistence_selections()
            .await
            .unwrap_or_else(|error| {
                panic!("Failed to load WAL-authority persistence selections: {error}")
            });
        let installed_wal_authority_selections = wal_authority_selections.len();
        for selection in wal_authority_selections {
            store
                .install_wal_authority_persistence(selection)
                .unwrap_or_else(|error| {
                    panic!("Failed to install a WAL-authority persistence selection: {error}")
                });
        }
        if installed_wal_authority_selections > 0 {
            info!(
                installed = installed_wal_authority_selections,
                "installed WAL-authority persistence selections before request admission"
            );
        }

        // ADR-0022: relaunch every selected user's WAL serving authority from
        // durable state through the image-baked runtime coordinates, so the
        // routed read serves the settled lane from the first admitted request.
        // Off-config images with selected users fail startup closed here.
        let wal_serving_relaunch_counts =
            archive_v3_serving_relaunch::relaunch_wal_serving_authorities(
                || Ok(Arc::clone(&concrete_kms)),
                Arc::clone(&control_store),
                Arc::clone(&store),
            )
            .await
            .unwrap_or_else(|error| panic!("Failed to relaunch WAL serving authorities: {error}"));
        info!(
            metric = "archive_v3_schema_epoch_rollout",
            schema_epoch_head = crate::schema_ladder::SCHEMA_EPOCH_HEAD,
            schema_epoch_target = crate::schema_ladder::SCHEMA_EPOCH_TARGET,
            schema_epoch_min_servable = crate::schema_ladder::SCHEMA_EPOCH_MIN_SERVABLE,
            selected = wal_serving_relaunch_counts.selected(),
            relaunched = wal_serving_relaunch_counts.relaunched,
            at_target = wal_serving_relaunch_counts.at_target,
            advanced = wal_serving_relaunch_counts.advanced,
            behind_target = wal_serving_relaunch_counts.behind_target,
            unservable_epoch = wal_serving_relaunch_counts.unservable_epoch,
            unavailable = wal_serving_relaunch_counts.unavailable,
            "authenticated the content-free schema epoch rollout state before request admission"
        );
        if wal_serving_relaunch_counts.relaunched > 0 {
            info!(
                relaunched = wal_serving_relaunch_counts.relaunched,
                "relaunched WAL serving authorities before request admission"
            );
        }
        if wal_serving_relaunch_counts.unavailable > 0 {
            // Contained, not ignored: these users are refused rather than served a
            // stale snapshot, and the rest of the fleet is admitted. Startup no
            // longer dies for everyone because one archive could not be
            // reconstructed.
            error!(
                unavailable = wal_serving_relaunch_counts.unavailable,
                "WAL serving authorities failed to relaunch; those users are unavailable"
            );
        }
        if wal_serving_relaunch_counts.behind_target > 0 {
            // A SUBSET of `relaunched`: these users are serving normally, at the
            // schema epoch their archive recorded, which is a complete servable
            // state. What it blocks is raising SCHEMA_EPOCH_MIN_SERVABLE — see the
            // runbook in `schema_ladder`. A ladder step no archive can take is a
            // step to split or withdraw, never one to force.
            error!(
                behind_target = wal_serving_relaunch_counts.behind_target,
                unservable_epoch = wal_serving_relaunch_counts.unservable_epoch,
                "WAL serving authorities are serving below this binary's schema epoch target"
            );
        }

        // ADR-0022 Group C: supervise the slots startup just registered. A
        // transient publication failure after a local commit used to take a user
        // 100% offline for reads and writes until the process restarted; the
        // driver replaces a proven-dead authority in place through the identical
        // ladder above. It fabricates nothing and re-submits nothing.
        store
            .install_wal_serving_relaunch(Arc::new(
                archive_v3_serving_relaunch::StartupWalServingRelaunch::new(
                    Arc::clone(&concrete_kms),
                    Arc::clone(&control_store),
                ),
            ))
            .unwrap_or_else(|error| {
                panic!("Failed to install the WAL serving relaunch driver: {error}")
            });

        // ADR-0022 genesis spine (G9): validate the new-user genesis gate against
        // the image before any request is admitted. An armed gate on an image with
        // no baked archive-v3 runtime coordinates has nothing to mint an archive
        // with, so it fails startup closed instead of silently never firing.
        // Content-free: one boolean.
        let genesis_native_signin = archive_v3_genesis_trigger::genesis_startup_agreement()
            .unwrap_or_else(|error| panic!("Failed to validate the genesis sign-in gate: {error}"));
        if genesis_native_signin {
            info!("new-user archive-v3 genesis is armed for sign-in");
            let converged =
                archive_v3_genesis_trigger::converge_all_active_users(&control_store, &store)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("Failed to converge every active account to Archive V3: {error}")
                    });
            info!(
                converged,
                "converged every active account to Archive V3 before request admission"
            );
        }
    } else {
        info!("legacy SQLite/GCS initialization and Archive V3 runtime skipped");
    }

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

        let jwt_secrets = if persistence_backend.is_legacy() {
            control_store
                .get_or_generate_jwt_secrets()
                .await
                .unwrap_or_else(|e| panic!("Failed to load/generate JWT secrets: {}", e))
        } else {
            vec![cp::fetch_secret_from_manager("kioku-jwt-secret", "latest")
                .await
                .unwrap_or_else(|e| panic!("Failed to fetch JWT secret: {e}"))]
        };

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
    if !persistence_backend.is_legacy() && acme_opt.is_some() {
        panic!(
            "PostgreSQL fleet mode requires shared Secret-Manager TLS; per-process ACME is disabled"
        );
    }
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

    let (repositories, postgres) = if persistence_backend.is_legacy() {
        (
            persistence::RepositorySet::legacy(Arc::clone(&control_store), Arc::clone(&store)),
            None,
        )
    } else {
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
        match std::env::var("POSTGRES_SCHEMA_MODE")
            .unwrap_or_else(|_| "verify".into())
            .as_str()
        {
            "migrate" => postgres
                .migrate()
                .await
                .unwrap_or_else(|error| panic!("Failed to migrate PostgreSQL: {error}")),
            "verify" => postgres
                .verify_schema()
                .await
                .unwrap_or_else(|error| panic!("PostgreSQL is not release-ready: {error}")),
            value => panic!("unsupported POSTGRES_SCHEMA_MODE {value:?}"),
        }
        let media_objects: Arc<dyn persistence::MediaObjectStore> =
            Arc::new(persistence::GcsMediaObjectStore::new(
                Arc::clone(&application_media_gcs),
                Arc::clone(&application_media_gcs),
            ));
        (
            persistence::RepositorySet::postgres(Arc::clone(&postgres), media_objects),
            Some(postgres),
        )
    };
    let serving_lifecycle = Arc::new(ServingLifecycle::default());
    let state = Arc::new(AppState {
        store: Arc::clone(&store),
        persistence_backend,
        postgres: postgres.clone(),
        serving_lifecycle: Arc::clone(&serving_lifecycle),
        id_token_verifier,
        attestation_cache: attestation_cache.clone(),
        tls_keystone: keystone.clone(),
    });
    let cp_state = Arc::new(cp::CpState {
        kms: Arc::clone(&kms),
        durable_recording_storage_bound: !persistence_backend.is_legacy()
            || store.durable_recording_storage_bound(),
        store: Arc::clone(&store),
        control: Arc::clone(&control_store),
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
        sync_limiter: cp::limits::RateLimiter::new(10.0, 0.2),
        reference_batch_limiter: cp::limits::RateLimiter::new(20.0, 2.0),
        reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(32)),
        mcp_limiter: cp::limits::RateLimiter::new(60.0, 1.0),
        oauth_limiter: cp::limits::RateLimiter::new(120.0, 2.0),
        test_email_limiter: cp::limits::RateLimiter::new(3.0, 0.05),
        email_transport,
        push_transport,
        config: cp_config,
        embedding: embedding_engine,
        voice: voice_engine,
    });

    // Billing detach is part of account-deletion completion and therefore
    // remains active in both runtime modes.
    cp::billing::spawn_detach_worker(Arc::clone(&cp_state));
    if cp_state.config.signup_limit_per_day == 0 {
        // This image has one job: erase every account and prove zero. Starting
        // summarization, episode cleanup, media/model provider work, or their
        // delivery tails would resurrect/advance backlog immediately before
        // deletion and can retain the same per-user write admissions for
        // minutes. The cutover owner directly settles usage and owns the full
        // account deletion lane, so none of those schedulers are prerequisites.
        cp::sync::spawn_adr0022_zero_archive_cutover(Arc::clone(&cp_state));
    } else {
        // Internal summarizer cron (replaces Cloud Scheduler — no external trigger).
        cp::summarizer::spawn_scheduler(Arc::clone(&cp_state));
        cp::query::spawn_episode_delete_worker(Arc::clone(&cp_state));
        cp::media_worker::spawn_scheduler(Arc::clone(&cp_state));
        cp::model_usage::spawn_delivery_worker(Arc::clone(&cp_state));
        cp::sync::spawn_account_deletion_reconciler(Arc::clone(&cp_state));
        cp::retention::spawn_reconciler(Arc::clone(&cp_state));
    }

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
    use super::{health_json, resolve_apns_identifiers, resolve_resend_api_key, ServingLifecycle};
    use crate::store::{self, LegacyCheckpointReconciliation};
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

    #[test]
    fn health_serializes_only_aggregate_checkpoint_readiness() {
        let health = health_json(
            LegacyCheckpointReconciliation {
                ready: true,
                completed_scans: 2,
                listed_live_objects: 3,
                live_archives_checked: 3,
                checkpoints_verified: 3,
                failures: 0,
            },
            store::WalServingHealth::default(),
        );
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

    #[test]
    fn health_reflects_relaunch_events_and_stays_content_free() {
        // State counts alone would let a genuine-corruption -> heal loop run
        // under budget while the probe kept reporting a steady `serving: 1`.
        // The three `_total` fields are event counters for exactly that case.
        let health = health_json(
            LegacyCheckpointReconciliation::default(),
            store::WalServingHealth {
                serving: 1,
                terminal: 0,
                quarantined: 2,
                relaunches_total: 7,
                launch_failures_total: 3,
                quarantines_total: 2,
            },
        );
        assert_eq!(health["ok"], true);
        assert_eq!(health["wal_serving"]["serving"], 1);
        assert_eq!(health["wal_serving"]["terminal"], 0);
        assert_eq!(health["wal_serving"]["quarantined"], 2);
        assert_eq!(health["wal_serving"]["relaunches_total"], 7);
        assert_eq!(health["wal_serving"]["launch_failures_total"], 3);
        assert_eq!(health["wal_serving"]["quarantines_total"], 2);
        // Content-free: the payload is counts, never an identity. Serialize
        // the whole document and assert no identifier-shaped key exists at any
        // depth, not merely at the top level.
        let rendered = serde_json::to_string(&health).unwrap();
        for forbidden in ["user_id", "archive_id", "user\":", "archive\":"] {
            assert!(
                !rendered.contains(forbidden),
                "health leaked {forbidden}: {rendered}"
            );
        }
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
    async fn every_retired_v1_route_authenticates_before_gone_and_never_mutates() {
        let gcs = Arc::new(crate::store::tests::FakeGcs::new());
        let store = Arc::new(Store::new(
            Arc::new(crate::store::tests::FakeKms),
            gcs.clone(),
        ));
        let user_id = "legacy-route-test";
        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at,ocr_text)
                     VALUES ('2026-08-09T12:00:00.000Z','must survive')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(user_id).await.unwrap();
        let object_name = format!("indexes/{user_id}.db.enc");
        let generations_before = gcs.exact_generation_count(&object_name);

        let state = Arc::new(AppState {
            store: Arc::clone(&store),
            persistence_backend: PersistenceBackend::LegacySqliteGcs,
            postgres: None,
            serving_lifecycle: Arc::new(ServingLifecycle::default()),
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
                        .body(Body::from(r#"{"user_id":"legacy-route-test"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }

        // This is the post-authentication destination for all paths above.
        let gone = legacy_data_plane_retired().await;
        assert_eq!(gone.status(), StatusCode::GONE);
        assert_eq!(gcs.exact_generation_count(&object_name), generations_before);
        let surviving: i64 = store
            .with_user(user_id, |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(surviving, 1);
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
