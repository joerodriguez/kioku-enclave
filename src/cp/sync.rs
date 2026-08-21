//! Device-to-enclave sync and account endpoints. All routes are auth-gated by the
//! [`super::auth::require_auth`] middleware applied in `main`.
//!
//! `POST /api/sync/batch`  — permanently retired local-sync endpoint.
//! `GET  /api/sync/status` — counts + latest timestamps.
//! `GET  /api/export`      — full JSON export.
//! `DELETE /api/account`   — begin/retry physical deletion.
//! `GET /api/account/deletion` — poll durable deletion status.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Extension, Router,
};
use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::warn;

use rusqlite::OptionalExtension;

use crate::{
    error::{EnclaveError, Result as EnclaveResult},
    store::Store,
};

use super::auth::AuthUser;
use super::control_store::{AccountDeletionOperation, ControlStore};
use super::CpState;

const DELETION_RECONCILE_INTERVAL: Duration = Duration::from_secs(300);
const DELETION_RECONCILE_BATCH_SIZE: usize = 64;
const DELETION_ATTEMPT_UNCONFIRMED: &str = "content_deletion_attempt_unconfirmed";
#[cfg(test)]
const LEGACY_GENERATION_UNAVAILABLE: &str = "legacy_generation_unavailable";

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route("/api/sync/batch", post(sync_batch_retired))
        .route("/api/sync/status", get(sync_status))
        .route("/api/export", get(export))
        .route("/api/account", delete(delete_account))
        .route("/api/account/deletion", get(account_deletion_status))
}

// Cloud capture has replaced device-side transcription and screenshot sync.
// Keep the authenticated route as an explicit tombstone so old clients cannot
// silently bypass recording leases and usage metering.
async fn sync_batch_retired() -> Response {
    (
        StatusCode::GONE,
        Json(json!({
            "error": "local_sync_retired",
            "message": "Update Kioku to record with cloud capture."
        })),
    )
        .into_response()
}

// ── Status ──────────────────────────────────────────────────────────────────────

async fn sync_status(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let user_id = user.0;
    // ADR-0022 D4: the `sync.status` gate is GONE. All three counted tables
    // have live sealed writers for a selected user — `utterances` and
    // `audio_segments` from `media_worker/wal/audio_result.rs::write_turns`,
    // `screenshots` from `media_worker/wal/result.rs::write_frame`, `episodes`
    // from `summarizer/wal/window.rs::apply` — so a zero count is now a
    // truthful zero rather than a deferral wearing the face of one.
    let email = s.control.user_email(&user_id).await.ok().flatten();

    // ADR-0022: the counts route through the settled-only serving lane for a
    // WAL-authoritative user and fall through to the guarded legacy read for
    // everyone else. A failure still answers 503 — never zeroed counts, which
    // would read as an emptied archive.
    let stats = s
        .store
        .wal_authoritative_read(&user_id, |conn| {
            let utt: i64 = conn.query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))?;
            let scr: i64 = conn.query_row("SELECT count(*) FROM screenshots", [], |r| r.get(0))?;
            let eps: i64 = conn.query_row("SELECT count(*) FROM episodes", [], |r| r.get(0))?;
            // `.optional()`, never `.ok()` — see the identical pair in
            // `query.rs::tool_get_capture_status`. `.ok()` made a failed
            // statement indistinguishable from an archive that has never
            // captured anything, and this route's whole job is to report
            // freshness truthfully.
            let last_u: Option<String> = conn
                .query_row(
                    "SELECT s.started_at FROM utterances u JOIN audio_segments s ON s.id = u.audio_segment_id ORDER BY s.started_at DESC LIMIT 1",
                    [],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten();
            let last_s: Option<String> = conn
                .query_row("SELECT captured_at FROM screenshots ORDER BY captured_at DESC LIMIT 1", [], |r| r.get::<_, Option<String>>(0))
                .optional()?
                .flatten();
            Ok((utt, scr, eps, last_u, last_s))
        })
        .await;

    match stats {
        Ok((utt, scr, eps, last_u, last_s)) => Json(json!({
            "email": email,
            "counts": { "utterances": utt, "screenshots": scr, "episodes": eps },
            "latest": { "utterance_at": last_u, "screenshot_at": last_s },
        }))
        .into_response(),
        Err(e) => super::routed_read_unavailable("api.sync_status", &e),
    }
}

// ── Export ──────────────────────────────────────────────────────────────────────

async fn export(State(s): State<Arc<CpState>>, Extension(user): Extension<AuthUser>) -> Response {
    // ADR-0022 D4: the `sync.export` gate is GONE. The premise it rested on —
    // "a complete-looking document with every array empty" — stopped being
    // true when the evidence chain came alive: `utterances`, `screenshots`,
    // `episodes`, `capture_events`, `capture_sessions`, `capture_streams`,
    // `media_objects`, `speaker_observations`, `speaker_clusters`,
    // `speaker_observation_sources` and `episode_final_briefs` all carry rows
    // for a selected user who has captured anything. The arrays that stay
    // empty (`people`, `person_facts`, `voice_profiles`) are empty because
    // those rows genuinely do not exist on this lane, which is the one thing
    // an export is supposed to report faithfully.
    match dump_user_export(&s.store, &user.0).await {
        Ok(data) => export_success_response(data),
        Err(e) => {
            // `export_failed` is a client contract and stays, but the status
            // moves 500 -> 503 under the read lane's rule (see
            // `super::routed_read_unavailable`): the only thing behind this
            // arm is one routed read, so the failure is retryable, and a 500
            // told the caller their export was broken rather than to try
            // again. The distinct reason string is kept rather than folded
            // into `enclave_unavailable` because callers already switch on it.
            warn!(error = %e, metric = super::ROUTED_READ_UNAVAILABLE_REASON, context = "api.export", "export failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "export_failed"})),
            )
                .into_response()
        }
    }
}

fn export_success_response(data: serde_json::Value) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/json; charset=utf-8".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"kioku-export.json\"".to_string(),
            ),
        ],
        Json(data),
    )
        .into_response()
}

/// ADR-0022: the export routes through `wal_authoritative_read`, which serves
/// a WAL-authoritative user from their serving authority's settled-only lane
/// and falls through to the ordinary guarded legacy read otherwise. It is the
/// same pure `canonical_logical_export` value either way, so the versioned
/// logical-export digest the inactive shadow verification hashes is unchanged.
/// An unreadable archive still propagates its error to the route's 500 rather
/// than exporting a truncated or empty document.
async fn dump_user_export(store: &Store, user_id: &str) -> EnclaveResult<serde_json::Value> {
    crate::store::validate_user_id(user_id)?;
    store
        .wal_authoritative_read(user_id, canonical_logical_export)
        .await
}

/// Version of the logical user export representation.  It is deliberately
/// separate from the HTTP route: inactive ADR-0022 shadow verification uses
/// the same pure value and hashes a version tag before comparing it.  Bump this
/// when a reviewed export-schema change is intentionally incompatible.
pub(crate) const CANONICAL_LOGICAL_EXPORT_VERSION: u16 = 2;

#[derive(Clone, Copy)]
struct CanonicalExportTable {
    response_field: &'static str,
    table: &'static str,
    response_order: &'static str,
    digest_order: &'static str,
}

/// This order is the existing `/api/export` object construction order and the
/// versioned logical-export digest order. All strings are compile-time SQL,
/// never caller input.
const CANONICAL_EXPORT_TABLES: &[CanonicalExportTable] = &[
    CanonicalExportTable {
        response_field: "utterances",
        table: "utterances",
        response_order: "id",
        digest_order: "id",
    },
    CanonicalExportTable {
        response_field: "screenshots",
        table: "screenshots",
        response_order: "id",
        digest_order: "id",
    },
    CanonicalExportTable {
        response_field: "screenshot_images",
        table: "screenshot_images",
        response_order: "id",
        digest_order: "id",
    },
    CanonicalExportTable {
        response_field: "episodes",
        table: "episodes",
        response_order: "id",
        digest_order: "id",
    },
    CanonicalExportTable {
        response_field: "episode_final_briefs",
        table: "episode_final_briefs",
        response_order: "episode_id",
        digest_order: "episode_id",
    },
    CanonicalExportTable {
        response_field: "capture_sessions",
        table: "capture_sessions",
        response_order: "created_at",
        digest_order: "created_at, id",
    },
    CanonicalExportTable {
        response_field: "capture_streams",
        table: "capture_streams",
        response_order: "created_at",
        digest_order: "created_at, id",
    },
    CanonicalExportTable {
        response_field: "capture_events",
        table: "capture_events",
        response_order: "started_at, event_id",
        digest_order: "started_at, event_id",
    },
    CanonicalExportTable {
        response_field: "media_objects",
        table: "media_objects",
        response_order: "created_at, event_id",
        digest_order: "created_at, event_id, asset_id",
    },
    CanonicalExportTable {
        response_field: "speaker_observations",
        table: "speaker_observations",
        response_order: "started_at, event_id, id",
        digest_order: "started_at, event_id, id",
    },
    CanonicalExportTable {
        response_field: "people",
        table: "people",
        response_order: "display_name, id",
        digest_order: "display_name, id",
    },
    CanonicalExportTable {
        response_field: "voice_profiles",
        table: "voice_profiles",
        response_order: "person_id, id",
        digest_order: "person_id, id",
    },
    CanonicalExportTable {
        response_field: "voice_samples",
        table: "voice_samples",
        response_order: "speaker_observation_id, id",
        digest_order: "speaker_observation_id, id",
    },
    CanonicalExportTable {
        response_field: "speaker_clusters",
        table: "speaker_clusters",
        response_order: "work_unit_id, speaker_local_id, id",
        digest_order: "work_unit_id, speaker_local_id, id",
    },
    CanonicalExportTable {
        response_field: "episode_speaker_slots",
        table: "episode_speaker_slots",
        response_order: "episode_id, slot_ordinal, id",
        digest_order: "episode_id, slot_ordinal, id",
    },
    CanonicalExportTable {
        response_field: "voice_profile_representatives",
        table: "voice_profile_representatives",
        response_order: "profile_id, channel_domain, id",
        digest_order: "profile_id, channel_domain, id",
    },
    CanonicalExportTable {
        response_field: "voice_embedding_jobs",
        table: "voice_embedding_jobs",
        response_order: "speaker_observation_id, embedding_space, processor_version, id",
        digest_order: "speaker_observation_id, embedding_space, processor_version, id",
    },
    CanonicalExportTable {
        response_field: "episode_participants",
        table: "episode_participants",
        response_order: "episode_id, participant_key, id",
        digest_order: "episode_id, participant_key, id",
    },
    CanonicalExportTable {
        response_field: "visual_speaker_observations",
        table: "visual_speaker_observations",
        response_order: "observed_at, event_id, id",
        digest_order: "observed_at, event_id, id",
    },
    CanonicalExportTable {
        response_field: "profile_identity_bindings",
        table: "profile_identity_bindings",
        response_order: "voice_profile_id, id",
        digest_order: "voice_profile_id, id",
    },
    CanonicalExportTable {
        response_field: "person_name_claims",
        table: "person_name_claims",
        response_order: "observed_at, id",
        digest_order: "observed_at, id",
    },
    CanonicalExportTable {
        response_field: "identity_evidence",
        table: "identity_evidence",
        response_order: "observed_at, id",
        digest_order: "observed_at, id",
    },
    CanonicalExportTable {
        response_field: "voice_profile_revisions",
        table: "voice_profile_revisions",
        response_order: "profile_id, id",
        digest_order: "profile_id, id",
    },
    CanonicalExportTable {
        response_field: "voice_sample_profile_assignments",
        table: "voice_sample_profile_assignments",
        response_order: "sample_id, profile_id, id",
        digest_order: "sample_id, profile_id, id",
    },
    CanonicalExportTable {
        response_field: "speaker_observation_sources",
        table: "speaker_observation_sources",
        response_order: "speaker_observation_id, event_id, window_start_ms",
        digest_order: "speaker_observation_id, event_id, window_start_ms",
    },
    CanonicalExportTable {
        response_field: "person_facts",
        table: "person_facts",
        response_order: "person_id, id",
        digest_order: "person_id, id",
    },
];

const MAX_CANONICAL_EXPORT_ROWS_PER_TABLE: u64 = 2_000_000;
const MAX_CANONICAL_EXPORT_TOTAL_ROWS: u64 = 8_000_000;
const MAX_CANONICAL_EXPORT_COLUMNS: usize = 256;
const MAX_CANONICAL_EXPORT_COLUMN_NAME_BYTES: usize = 256;
const MAX_CANONICAL_EXPORT_FIELD_BYTES: usize = 4 * 1024 * 1024;
const MAX_CANONICAL_EXPORT_ROW_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CANONICAL_EXPORT_TOTAL_BYTES: u64 = 40 * 1024 * 1024 * 1024;

/// The exact value served by `/api/export`, kept pure so an inactive shadow
/// verifier can compare the same representation without a route, Store, or
/// provider connection.  Keep field order and optional-table behavior stable:
/// callers serialize this value exactly as before.
pub(crate) fn canonical_logical_export(
    conn: &rusqlite::Connection,
) -> EnclaveResult<serde_json::Value> {
    let mut value = serde_json::Map::new();
    for table in CANONICAL_EXPORT_TABLES {
        value.insert(
            table.response_field.to_string(),
            serde_json::Value::Array(dump_optional_table(
                conn,
                table.table,
                table.response_order,
            )?),
        );
    }
    Ok(serde_json::Value::Object(value))
}

/// Version-bound, bounded-memory SHA-256 over the exact logical values exposed
/// by `/api/export`. It streams rows and SQL values directly into the digest;
/// the parity path never constructs or serializes the full export JSON value.
#[cfg(test)]
pub(crate) fn canonical_logical_export_stream_digest(
    conn: &rusqlite::Connection,
) -> EnclaveResult<[u8; 32]> {
    canonical_logical_export_stream_digest_guarded(conn, || true)
}

pub(crate) fn canonical_logical_export_stream_digest_guarded<F>(
    conn: &rusqlite::Connection,
    guard: F,
) -> EnclaveResult<[u8; 32]>
where
    F: FnMut() -> bool,
{
    canonical_logical_export_stream_digest_for_version(
        conn,
        CANONICAL_LOGICAL_EXPORT_VERSION,
        guard,
    )
}

fn canonical_logical_export_stream_digest_for_version<F>(
    conn: &rusqlite::Connection,
    version: u16,
    mut guard: F,
) -> EnclaveResult<[u8; 32]>
where
    F: FnMut() -> bool,
{
    let mut hasher = Sha256::new();
    hasher.update(b"kioku.adr0022.logical-export-digest\0");
    hasher.update(version.to_be_bytes());
    let mut budget = CanonicalExportDigestBudget::default();
    for table in CANONICAL_EXPORT_TABLES {
        if !guard() {
            return Err(EnclaveError::Store(
                "canonical export digest cancelled".into(),
            ));
        }
        hash_export_bytes(&mut hasher, table.response_field.as_bytes());
        stream_canonical_export_table(conn, *table, &mut hasher, &mut budget, &mut guard)?;
    }
    Ok(hasher.finalize().into())
}

#[derive(Default)]
struct CanonicalExportDigestBudget {
    total_rows: u64,
    total_bytes: u64,
}

fn stream_canonical_export_table<F>(
    conn: &rusqlite::Connection,
    table: CanonicalExportTable,
    hasher: &mut Sha256,
    budget: &mut CanonicalExportDigestBudget,
    guard: &mut F,
) -> EnclaveResult<()>
where
    F: FnMut() -> bool,
{
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [table.table],
        |row| row.get(0),
    )?;
    if exists == 0 {
        hasher.update(0_u64.to_be_bytes());
        return Ok(());
    }
    let mut statement = conn.prepare(&format!(
        "SELECT * FROM {} ORDER BY {}",
        table.table, table.digest_order
    ))?;
    if statement.column_count() > MAX_CANONICAL_EXPORT_COLUMNS {
        return Err(EnclaveError::Store(
            "canonical export digest column limit exceeded".into(),
        ));
    }
    let column_names: Vec<String> = statement
        .column_names()
        .into_iter()
        .map(str::to_string)
        .collect();
    if column_names
        .iter()
        .any(|name| name.len() > MAX_CANONICAL_EXPORT_COLUMN_NAME_BYTES)
    {
        return Err(EnclaveError::Store(
            "canonical export digest column-name limit exceeded".into(),
        ));
    }
    let mut rows = statement.query([])?;
    let mut table_rows = 0_u64;
    while let Some(row) = rows.next()? {
        if !guard() {
            return Err(EnclaveError::Store(
                "canonical export digest cancelled".into(),
            ));
        }
        table_rows = table_rows.saturating_add(1);
        budget.total_rows = budget.total_rows.saturating_add(1);
        if table_rows > MAX_CANONICAL_EXPORT_ROWS_PER_TABLE
            || budget.total_rows > MAX_CANONICAL_EXPORT_TOTAL_ROWS
        {
            return Err(EnclaveError::Store(
                "canonical export digest row limit exceeded".into(),
            ));
        }
        hasher.update(b"row\0");
        let mut row_bytes = 0_u64;
        for (index, column) in column_names.iter().enumerate() {
            hash_export_bytes(hasher, column.as_bytes());
            let value = row.get_ref(index)?;
            let value_bytes = hash_canonical_export_value(hasher, value)?;
            row_bytes = row_bytes.saturating_add(value_bytes);
            budget.total_bytes = budget.total_bytes.saturating_add(value_bytes);
            if row_bytes > MAX_CANONICAL_EXPORT_ROW_BYTES
                || budget.total_bytes > MAX_CANONICAL_EXPORT_TOTAL_BYTES
            {
                return Err(EnclaveError::Store(
                    "canonical export digest byte limit exceeded".into(),
                ));
            }
        }
    }
    hasher.update(table_rows.to_be_bytes());
    Ok(())
}

fn hash_canonical_export_value(
    hasher: &mut Sha256,
    value: rusqlite::types::ValueRef<'_>,
) -> EnclaveResult<u64> {
    use rusqlite::types::ValueRef;
    let bytes = match value {
        ValueRef::Null => {
            hasher.update([0]);
            1
        }
        ValueRef::Integer(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
            9
        }
        ValueRef::Real(value) if value.is_finite() => {
            hasher.update([2]);
            hasher.update(value.to_bits().to_be_bytes());
            9
        }
        ValueRef::Real(_) => {
            // `/api/export` maps non-JSON SQLite floats to JSON null.
            hasher.update([0]);
            1
        }
        ValueRef::Text(value) => {
            hash_bounded_export_field(hasher, 3, value)?;
            9_u64.saturating_add(value.len() as u64)
        }
        ValueRef::Blob(value) => {
            // The HTTP representation is base64, a one-to-one encoding. Hash
            // the exact source bytes with a distinct type tag without building
            // the temporary base64 string.
            hash_bounded_export_field(hasher, 4, value)?;
            9_u64.saturating_add(value.len() as u64)
        }
    };
    Ok(bytes)
}

fn hash_bounded_export_field(hasher: &mut Sha256, tag: u8, value: &[u8]) -> EnclaveResult<()> {
    if value.len() > MAX_CANONICAL_EXPORT_FIELD_BYTES {
        return Err(EnclaveError::Store(
            "canonical export digest field limit exceeded".into(),
        ));
    }
    hasher.update([tag]);
    hash_export_bytes(hasher, value);
    Ok(())
}

fn hash_export_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
pub(crate) fn canonical_logical_export_stream_digest_at_version(
    conn: &rusqlite::Connection,
    version: u16,
) -> EnclaveResult<[u8; 32]> {
    canonical_logical_export_stream_digest_for_version(conn, version, || true)
}

pub(crate) fn dump_optional_table(
    conn: &rusqlite::Connection,
    name: &str,
    order: &str,
) -> EnclaveResult<Vec<serde_json::Value>> {
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(&format!("SELECT * FROM {name} ORDER BY {order}"))?;
    let column_names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(str::to_string)
        .collect();
    let rows = stmt.query_map([], |row| {
        let mut value = serde_json::Map::new();
        for (index, column) in column_names.iter().enumerate() {
            let cell: rusqlite::types::Value = row.get(index)?;
            let cell = match cell {
                rusqlite::types::Value::Null => serde_json::Value::Null,
                rusqlite::types::Value::Integer(number) => number.into(),
                rusqlite::types::Value::Real(number) => serde_json::Number::from_f64(number)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null),
                rusqlite::types::Value::Text(text) => text.into(),
                rusqlite::types::Value::Blob(bytes) => base64::engine::general_purpose::STANDARD
                    .encode(bytes)
                    .into(),
            };
            value.insert(column.clone(), cell);
        }
        Ok(serde_json::Value::Object(value))
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

// ── Account deletion ────────────────────────────────────────────────────────────

async fn delete_account(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let user_id = user.0;
    let account_status = match s.control.user_status(&user_id).await {
        Ok(Some(status)) => status,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "account_unavailable"})),
            )
                .into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to load account deletion status");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "deletion_init_failed"})),
            )
                .into_response();
        }
    };
    // Serialize with every centralized Vertex call. Once acquired, all prior
    // calls have durably recorded terminal telemetry and no new call can begin.
    let lifecycle_guard = match s.store.lock_user_lifecycle(&user_id).await {
        Ok(guard) => guard,
        Err(e) => {
            warn!(error = %e, "failed to lock account lifecycle for deletion");
            return err503();
        }
    };
    // A transition to `deleting` happens only after settlement succeeds. On a
    // retry, content may already be gone, so reopening an empty index to settle
    // again would violate deletion. Finalized tombstone retries likewise skip.
    if account_status == "active" {
        let account_id = match s.control.billing_account_id_for_deletion(&user_id).await {
            Ok(account_id) => account_id,
            Err(e) => {
                warn!(error = %e, "failed to load deletion accounting identity");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "deletion_accounting_unavailable"})),
                )
                    .into_response();
            }
        };
        if let Err(e) =
            super::model_usage::settle_for_account_deletion(&s, &user_id, &account_id).await
        {
            warn!(error = %e, "failed to settle Vertex usage before deletion");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "deletion_accounting_unsettled"})),
            )
                .into_response();
        }
        // Freeze the WAL-authoritative account's exact media inventory while
        // it can still be read. `begin_user_deletion` tombstones the archive
        // binding, the startup selection scan filters tombstoned bindings, and
        // no serving authority is ever re-registered — so after that point the
        // archive's logical database is unreadable and media enumeration would
        // be wedged forever on the first crash. Doing it here, under the same
        // lifecycle guard as settlement and before any tombstone, makes the
        // rung idempotently re-runnable instead.
        if let Some(lane) = s.store.wal_deletion_lane() {
            if let Err(e) = lane
                .freeze_media_inventory(s.control.as_ref(), s.store.as_ref(), &user_id)
                .await
            {
                warn!(error = %e, "failed to freeze media inventory before deletion");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "deletion_media_inventory_unavailable"})),
                )
                    .into_response();
            }
        }
    } else if !matches!(account_status.as_str(), "deleting" | "deleted") {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "account_unavailable"})),
        )
            .into_response();
    }

    // 1. Fail closed before touching content: stop every other authenticated
    // route and revoke pending/renewable OAuth credentials. A retry of this
    // deletion route remains allowed while status is `deleting`.
    let operation = match s.control.begin_user_deletion(&user_id).await {
        Ok(Some(operation)) => operation,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "account_unavailable"})),
            )
                .into_response()
        }
        Err(_) => {
            // Errors from GCS/KMS can embed request URLs; never emit them on
            // the deletion path because object names are potentially content.
            warn!("failed to initialize account deletion");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "deletion_init_failed"})),
            )
                .into_response();
        }
    };
    if operation.status == "physical_complete" {
        return deletion_delete_response(operation);
    }
    if deletion_operation_requires_remediation(&operation) {
        return deletion_delete_response(operation);
    }
    // Store::delete_user takes the same fence. Release only after the account
    // is inactive; queued Vertex calls then acquire it, fail their post-lock
    // active check, and cannot egress or recreate the index.
    drop(lifecycle_guard);

    // Persist an in-progress marker before remote deletion. It remains pending
    // and is safe for the startup worker to retry after cancellation/restart;
    // an observed missing exact generation is promoted separately to
    // failed_retryable before this request returns.
    let operation = match s
        .control
        .update_user_deletion_status(&user_id, DELETION_ATTEMPT_UNCONFIRMED, None, None)
        .await
    {
        Ok(operation) => operation,
        Err(_) => {
            warn!("failed to fence account deletion attempt");
            return deletion_delete_response(operation);
        }
    };

    if revoke_apple_before_content_delete(s.control.as_ref(), s.apple_provider.as_ref(), &user_id)
        .await
        .is_err()
    {
        // The operation is durably fenced already. Do not delete content or
        // finalize identity state until revocation is durably recorded.
        warn!("Apple credential revocation prerequisite unavailable during account deletion");
        return deletion_delete_response(operation);
    }

    // 2. Delete content. Any incomplete outcome remains a durable 202
    // operation; every non-deletion account route stays denied.
    if let Err(error) = delete_account_content(&s.control, s.store.as_ref(), &user_id).await {
        let (reason, retry_after_seconds, hard_delete_time) = match &error {
            EnclaveError::DeletionPending(pending) => (
                pending.reason.as_str(),
                pending.retry_after_seconds,
                pending.hard_delete_time.as_deref(),
            ),
            _ => {
                warn!("enclave delete remains pending");
                ("content_store_unavailable", Some(30), None)
            }
        };
        let operation = persist_deletion_status(
            s.control.as_ref(),
            &user_id,
            operation,
            reason,
            retry_after_seconds,
            hard_delete_time,
        )
        .await;
        return deletion_delete_response(operation);
    }
    // 3. Remove identity/accounting rows and leave a stable deletion tombstone.
    match s.control.finalize_user_deletion(&user_id).await {
        Ok(operation) => deletion_delete_response(operation),
        Err(_) => {
            warn!("identity cleanup remains pending");
            let operation = persist_deletion_status(
                s.control.as_ref(),
                &user_id,
                operation,
                "identity_cleanup_in_progress",
                Some(30),
                None,
            )
            .await;
            deletion_delete_response(operation)
        }
    }
}

async fn account_deletion_status(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    match s.control.account_deletion_operation(&user.0).await {
        Ok(Some(operation)) => deletion_operation_response(StatusCode::OK, operation),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "deletion_not_started"})),
        )
            .into_response(),
        Err(_) => {
            warn!("account deletion status unavailable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "deletion_status_unavailable"})),
            )
                .into_response()
        }
    }
}

async fn persist_deletion_status(
    control: &ControlStore,
    user_id: &str,
    durable_fallback: AccountDeletionOperation,
    reason: &str,
    retry_after_seconds: Option<u64>,
    hard_delete_time: Option<&str>,
) -> AccountDeletionOperation {
    match control
        .update_user_deletion_status(user_id, reason, retry_after_seconds, hard_delete_time)
        .await
    {
        Ok(operation) => operation,
        Err(_) => {
            // The operation created by begin_user_deletion was already durable.
            // Return that honest fallback if richer status cannot be persisted.
            warn!("failed to persist richer account deletion status");
            durable_fallback
        }
    }
}

/// Apple authorization is a deletion barrier: when a retained credential is
/// present, its provider revocation and local durable revoked marker must both
/// succeed before either content deletion or identity finalization can run.
/// This intentionally returns only a generic error so callers never log a
/// refresh token, provider response, account id, or object name.
async fn revoke_apple_before_content_delete(
    control: &ControlStore,
    apple_provider: Option<&Arc<super::apple::AppleIdentityProvider>>,
    user_id: &str,
) -> EnclaveResult<()> {
    let credentials = control.apple_refresh_credentials(user_id).await?;
    if credentials.is_empty() {
        return Ok(());
    }
    let provider = apple_provider.ok_or_else(|| {
        EnclaveError::Store("Apple credential revocation provider is unavailable".into())
    })?;
    for (client_id, refresh_token) in credentials {
        provider
            .revoke_refresh_token(&client_id, &refresh_token)
            .await
            .map_err(|_| EnclaveError::Store("Apple credential revocation failed".into()))?;
        control
            .mark_apple_credential_revoked(user_id, &client_id)
            .await?;
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DeletionReconcileSummary {
    attempted: usize,
    completed: usize,
    pending: usize,
    failed_retryable: usize,
    failures: usize,
}

fn deletion_operation_requires_remediation(operation: &AccountDeletionOperation) -> bool {
    operation.status == "failed_retryable"
}

/// Retry durable `deleting` accounts even if a 202 client signs out and never
/// repeats DELETE. Work is serial and bounded so one sweep cannot fan out GCS,
/// KMS, or control-DB writes.
async fn reconcile_pending_account_deletions(
    control: &Arc<ControlStore>,
    store: &Store,
    apple_provider: Option<&Arc<super::apple::AppleIdentityProvider>>,
) -> EnclaveResult<DeletionReconcileSummary> {
    let user_ids = control
        .deleting_user_ids(DELETION_RECONCILE_BATCH_SIZE)
        .await?;
    let mut summary = DeletionReconcileSummary::default();
    for user_id in user_ids {
        summary.attempted += 1;
        let operation = match control.begin_user_deletion(&user_id).await {
            Ok(Some(operation)) => operation,
            Ok(None) | Err(_) => {
                summary.failures += 1;
                continue;
            }
        };
        if operation.status == "physical_complete" {
            summary.failures += 1;
            continue;
        }
        if deletion_operation_requires_remediation(&operation) {
            summary.failed_retryable += 1;
            continue;
        }
        if revoke_apple_before_content_delete(control, apple_provider, &user_id)
            .await
            .is_err()
        {
            // Keep the operation pending: an unavailable revocation provider
            // must never permit content deletion or finalization on restart.
            summary.pending += 1;
            continue;
        }
        if operation.reason == "identity_cleanup_in_progress" {
            match control.finalize_user_deletion(&user_id).await {
                Ok(_) => summary.completed += 1,
                Err(_) => summary.pending += 1,
            }
            continue;
        }
        if control
            .update_user_deletion_status(&user_id, DELETION_ATTEMPT_UNCONFIRMED, None, None)
            .await
            .is_err()
        {
            summary.failures += 1;
            continue;
        }

        match delete_account_content(control, store, &user_id).await {
            Ok(()) => match control.finalize_user_deletion(&user_id).await {
                Ok(_) => summary.completed += 1,
                Err(_) => {
                    if control
                        .update_user_deletion_status(
                            &user_id,
                            "identity_cleanup_in_progress",
                            Some(30),
                            None,
                        )
                        .await
                        .is_ok()
                    {
                        summary.pending += 1;
                    } else {
                        summary.failures += 1;
                    }
                }
            },
            Err(error) => {
                let (reason, retry_after_seconds, hard_delete_time) = match &error {
                    EnclaveError::DeletionPending(pending) => (
                        pending.reason.as_str(),
                        pending.retry_after_seconds,
                        pending.hard_delete_time.as_deref(),
                    ),
                    _ => ("content_store_unavailable", Some(30), None),
                };
                match control
                    .update_user_deletion_status(
                        &user_id,
                        reason,
                        retry_after_seconds,
                        hard_delete_time,
                    )
                    .await
                {
                    Ok(operation) if operation.status == "failed_retryable" => {
                        summary.failed_retryable += 1
                    }
                    Ok(_) => summary.pending += 1,
                    Err(_) => summary.failures += 1,
                }
            }
        }
    }
    Ok(summary)
}

/// Consume any durable identity-rebind authority before account content
/// deletion. The control claim precedes provider deletion, and a provider
/// create explicitly recorded as in-flight is retried instead of being
/// overtaken. Once claimed, both exact namespaces are purged under one
/// Store-owned admission/lifecycle fence and reconciled durably before final
/// identity cleanup is allowed.
async fn delete_account_content(
    control: &Arc<ControlStore>,
    store: &Store,
    user_id: &str,
) -> EnclaveResult<()> {
    // ADR-0022: for an archive that reached the `wal_authoritative` terminal the
    // authoritative data lives under the archive-v3 keyspace. The legacy sweep
    // enumerates its inventory from the frozen pre-cutover snapshot and touches
    // only the legacy namespaces, so letting it run would erase the legacy
    // artifacts, leave every checkpoint and WAL segment intact, and still let
    // finalization stamp the account `physical_complete` / `content_deleted`.
    // Fail closed as PENDING instead: the reconciler keeps retrying and the
    // account is never falsely reported deleted. This resolves the moment the
    // archive-v3 deletion driver is wired.
    // The in-memory predicate alone is NOT restart-stable: deletion
    // tombstones the binding first and the startup selection scan filters
    // tombstoned bindings, so after a mid-deletion restart the map is empty
    // and this branch would misroute a WAL-authoritative user into the
    // legacy sweep — which succeeds vacuously for a genesis-born user and
    // falsely stamps the account complete with the whole archive intact.
    // The durable ledger-backed lane predicate closes that window.
    if store.is_wal_authoritative(user_id) || control.wal_deletion_lane(user_id).await? {
        // The archive-v3 lane is the only correct erasure for this account.
        // With a lane installed, drive it; without one — every image today —
        // keep failing closed, because the alternative is the legacy sweep
        // succeeding vacuously and finalization stamping the account complete
        // with the whole archive intact. The refusal is never removed, only
        // superseded by real deletion.
        let Some(lane) = store.wal_deletion_lane() else {
            return Err(EnclaveError::DeletionPending(
                crate::error::DeletionPending {
                    reason: crate::error::DeletionPendingReason::ArchiveV3DeletionUnwired,
                    retry_after_seconds: Some(30),
                    hard_delete_time: None,
                },
            ));
        };
        // Freeze the media inventory here too, not only in the DELETE route.
        // The route's freeze runs under `account_status == "active"`, so every
        // account that reached `deleting` without one — which is every
        // WAL-authoritative account on today's no-lane images — would
        // otherwise arrive at a media rung it can never satisfy. This call is
        // mint-once and idempotent, and it still succeeds for any account
        // whose in-memory serving authority is installed in this process,
        // because the tombstone filters the startup selection scan rather than
        // the live map. A failure is deliberately not fatal: `drive` re-reads
        // the durable inventory and classifies its absence honestly, either as
        // a retryable rung or as `ManualRequired` when nothing can ever mint
        // it. Turning it into an error here would hide that classification.
        if let Err(error) = lane.freeze_media_inventory(control, store, user_id).await {
            warn!(error = %error, "media inventory freeze unavailable on the deletion lane");
        }
        return match lane.drive(control, store, user_id).await? {
            crate::archive_v3_deletion_lane::WalDeletionOutcome::Complete(residue) => {
                // Disclosure is part of completion, not a footnote to it: the
                // classes that survive are recorded on the operation's own
                // terminal metadata before the caller can observe success.
                control
                    .record_deletion_residue_disclosure(user_id, &residue.flags())
                    .await?;
                Ok(())
            }
            crate::archive_v3_deletion_lane::WalDeletionOutcome::Pending(stage) => {
                Err(stage.into_pending())
            }
        };
    }
    let operation = control.identity_rebind_operation_for_user(user_id).await?;
    let Some(operation) = operation else {
        return store.delete_user(user_id).await;
    };
    if !control.claim_identity_rebind_deletion(user_id).await? {
        return Err(EnclaveError::Conflict(
            "identity rebind provider transition is still in progress".into(),
        ));
    }
    store
        .delete_identity_rebind_users(&operation.old_user_id, &operation.stable_user_id)
        .await?;
    control
        .mark_identity_rebind_deletion_reconciled(user_id)
        .await
}

pub fn spawn_account_deletion_reconciler(state: Arc<CpState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DELETION_RECONCILE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match reconcile_pending_account_deletions(
                &state.control,
                &state.store,
                state.apple_provider.as_ref(),
            )
            .await
            {
                Ok(summary) if summary.attempted > 0 => {
                    tracing::info!(
                        attempted = summary.attempted,
                        completed = summary.completed,
                        pending = summary.pending,
                        failed_retryable = summary.failed_retryable,
                        failures = summary.failures,
                        "account deletion reconciliation sweep"
                    );
                }
                Ok(_) => {}
                Err(_) => warn!("account deletion reconciliation sweep unavailable"),
            }
        }
    });
}

fn deletion_operation_response(
    status_code: StatusCode,
    operation: AccountDeletionOperation,
) -> Response {
    let deleted = operation.status == "physical_complete";
    let retry_after_seconds = operation.retry_after_seconds;
    let mut response = (
        status_code,
        Json(json!({
            "deleted": deleted,
            "operation_id": operation.operation_id,
            "status": operation.status,
            "reason": operation.reason,
            "retry_after_seconds": retry_after_seconds,
            "hard_delete_time": operation.hard_delete_time,
        })),
    )
        .into_response();
    if let Some(seconds) = retry_after_seconds {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

fn deletion_delete_response(operation: AccountDeletionOperation) -> Response {
    let status = if operation.status == "physical_complete" {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    deletion_operation_response(status, operation)
}

fn err503() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "enclave_unavailable", "retry_after": 30})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        tests::{insert_screenshot_evidence, FakeGcs, FakeKms},
        GcsClient,
    };

    #[tokio::test]
    async fn canonical_export_helper_preserves_serialized_body_and_headers() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE utterances (id INTEGER PRIMARY KEY, text TEXT, payload BLOB);
             INSERT INTO utterances VALUES (1, 'hello', X'010203');",
        )
        .unwrap();
        let value = canonical_logical_export(&conn).unwrap();
        let expected = json!({
            "utterances": [{"id": 1, "text": "hello", "payload": "AQID"}],
            "screenshots": [],
            "screenshot_images": [],
            "episodes": [],
            "episode_final_briefs": [],
            "capture_sessions": [],
            "capture_streams": [],
            "capture_events": [],
            "media_objects": [],
            "speaker_observations": [],
            "people": [],
            "voice_profiles": [],
            "voice_samples": [],
            "speaker_clusters": [],
            "episode_speaker_slots": [],
            "voice_profile_representatives": [],
            "voice_embedding_jobs": [],
            "episode_participants": [],
            "visual_speaker_observations": [],
            "profile_identity_bindings": [],
            "person_name_claims": [],
            "identity_evidence": [],
            "voice_profile_revisions": [],
            "voice_sample_profile_assignments": [],
            "speaker_observation_sources": [],
            "person_facts": [],
        });
        let expected_bytes = serde_json::to_vec(&expected).unwrap();
        assert_eq!(value, expected);
        assert_eq!(serde_json::to_vec(&value).unwrap(), expected_bytes);

        let response = export_success_response(value);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"kioku-export.json\""
        );
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), expected_bytes.as_slice());
    }

    #[tokio::test]
    async fn pending_response_is_machine_readable_and_sets_retry_after() {
        let response = deletion_delete_response(AccountDeletionOperation {
            operation_id: "del_opaque".into(),
            status: "pending".into(),
            reason: "soft_delete_retention".into(),
            retry_after_seconds: Some(42),
            hard_delete_time: Some("2026-08-14T00:00:00.000Z".into()),
        });
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()[header::RETRY_AFTER], "42");
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["deleted"], false);
        assert_eq!(value["operation_id"], "del_opaque");
        assert_eq!(value["status"], "pending");
        assert_eq!(value["reason"], "soft_delete_retention");
        assert_eq!(value["retry_after_seconds"], 42);
        assert_eq!(value["hard_delete_time"], "2026-08-14T00:00:00.000Z");
    }

    #[tokio::test]
    async fn delete_wire_states_are_202_until_physical_complete() {
        for (status, reason) in [
            ("failed_retryable", LEGACY_GENERATION_UNAVAILABLE),
            ("failed_retryable", "legacy_snapshot_too_large"),
        ] {
            let response = deletion_delete_response(AccountDeletionOperation {
                operation_id: "del_failed".into(),
                status: status.into(),
                reason: reason.into(),
                retry_after_seconds: None,
                hard_delete_time: None,
            });
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
                .await
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["deleted"], false);
            assert_eq!(value["status"], "failed_retryable");
            assert_eq!(value["reason"], reason);
        }

        let response = deletion_delete_response(AccountDeletionOperation {
            operation_id: "del_complete".into(),
            status: "physical_complete".into(),
            reason: "content_deleted".into(),
            retry_after_seconds: None,
            hard_delete_time: None,
        });
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["deleted"], true);
        assert_eq!(value["status"], "physical_complete");
        assert_eq!(value["reason"], "content_deleted");

        let poll = deletion_operation_response(
            StatusCode::OK,
            AccountDeletionOperation {
                operation_id: "del_poll".into(),
                status: "failed_retryable".into(),
                reason: LEGACY_GENERATION_UNAVAILABLE.into(),
                retry_after_seconds: None,
                hard_delete_time: None,
            },
        );
        assert_eq!(poll.status(), StatusCode::OK);
        let body = axum::body::to_bytes(poll.into_body(), 16 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["deleted"], false);
        assert_eq!(value["status"], "failed_retryable");
    }

    #[tokio::test]
    async fn wal_authoritative_deletion_stays_pending_and_never_reports_complete() {
        use crate::store::tests::{FakeGcs, FakeKms};
        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let store = Arc::new(Store::new(kms, gcs.clone()));
        let user = control
            .upsert_user("wal-deletion-guard", "wal-deletion@example.com", 1_000)
            .await
            .unwrap();

        // Before cutover the legacy sweep owns deletion, unchanged.
        assert!(delete_account_content(&control, store.as_ref(), &user.id)
            .await
            .is_ok());

        // After cutover the authoritative data lives in the archive-v3
        // keyspace the legacy sweep cannot see. Deletion must stay PENDING —
        // never silently erase only the legacy artifacts and let finalization
        // stamp the account complete while every checkpoint and WAL segment
        // survives.
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    &user.id,
                    crate::archive_v3::ArchiveId::from_bytes([0x6d; 16]),
                ),
            )
            .unwrap();
        let error = delete_account_content(&control, store.as_ref(), &user.id)
            .await
            .expect_err("a wal-authoritative archive must not report deletion complete");
        match error {
            EnclaveError::DeletionPending(pending) => {
                assert_eq!(pending.reason.as_str(), "archive_v3_deletion_unwired");
                assert_eq!(pending.retry_after_seconds, Some(30));
            }
            other => panic!("expected a pending deletion, got {other:?}"),
        }
    }

    /// The live restart-misroute defect the deletion-driver design review
    /// proved: deletion tombstones the binding first, the startup selection
    /// scan filters tombstoned bindings, so after a mid-deletion restart the
    /// in-memory map is empty and dispatch fell through to the LEGACY sweep,
    /// which vacuously succeeds for a genesis-born user and falsely stamps
    /// the account complete. The durable ledger-backed lane predicate must
    /// route the WAL lane with NO selection installed.
    #[tokio::test]
    async fn restart_deletion_routes_the_wal_lane_from_the_durable_ledger() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let user = control
            .upsert_user(
                "wal-deletion-restart-subject",
                "owner@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        control
            .seed_wal_genesis_terminal_for_test(&user.id)
            .await
            .unwrap();
        // Deliberately NO install_wal_authority_persistence: this is the
        // post-restart shape where the in-memory map proves nothing.
        assert!(!store.is_wal_authoritative(&user.id));
        let error = delete_account_content(&control, store.as_ref(), &user.id)
            .await
            .expect_err("a durably WAL-authoritative archive must never take the legacy sweep");
        match error {
            EnclaveError::DeletionPending(pending) => {
                assert_eq!(pending.reason.as_str(), "archive_v3_deletion_unwired");
            }
            other => panic!("expected a pending deletion, got {other:?}"),
        }
    }

    /// The honest refusal is replaced by real deletion, never removed.
    ///
    /// With a lane installed the WAL-authoritative branch drives the archive-v3
    /// ladder and reports the rung it reached; with no lane — every image
    /// today — it still fails closed as `archive_v3_deletion_unwired`. Neither
    /// arm can return `Ok`, which is what would let finalization stamp the
    /// account complete with the archive intact.
    #[tokio::test]
    async fn an_installed_lane_drives_the_archive_v3_ladder_instead_of_refusing() {
        struct NeverBuildsRuntime;

        #[async_trait::async_trait]
        impl crate::archive_v3_deletion_lane::ArchiveDeletionRuntimeFactory for NeverBuildsRuntime {
            async fn runtime_for(
                &self,
                _archive_id: crate::archive_v3::ArchiveId,
            ) -> EnclaveResult<Arc<dyn crate::archive_v3_deletion_lane::ArchiveDeletionRuntime>>
            {
                panic!("this rung must not construct an archive-v3 deletion runtime")
            }
        }

        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let user = control
            .upsert_user(
                "wal-lane-dispatch",
                "wal-lane@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        control
            .seed_wal_genesis_terminal_for_test(&user.id)
            .await
            .unwrap();

        // No lane installed: the honest refusal still stands.
        match delete_account_content(&control, store.as_ref(), &user.id)
            .await
            .expect_err("no lane means no erasure and no completion")
        {
            EnclaveError::DeletionPending(pending) => {
                assert_eq!(pending.reason.as_str(), "archive_v3_deletion_unwired");
            }
            other => panic!("expected a pending deletion, got {other:?}"),
        }

        store
            .install_wal_deletion_lane(Arc::new(
                crate::archive_v3_deletion_lane::WalDeletionLane::new(
                    Arc::new(
                        crate::archive_v3_witness::DeletionPrincipalKey::derive_from_control_root(
                            &[0x41; 32],
                        )
                        .unwrap(),
                    ),
                    Arc::new(NeverBuildsRuntime),
                ),
            ))
            .unwrap();

        // With a lane, the account is on the real ladder: the reason names the
        // rung it reached, and it is still never `Ok`.
        match delete_account_content(&control, store.as_ref(), &user.id)
            .await
            .expect_err("the ladder has not completed")
        {
            EnclaveError::DeletionPending(pending) => {
                assert_eq!(pending.reason.as_str(), "archive_v3_tombstone_pending");
                assert_eq!(pending.retry_after_seconds, Some(30));
            }
            other => panic!("expected a pending deletion, got {other:?}"),
        }

        // Once the ledger is tombstoned this account is on the media rung with
        // no serving authority left to satisfy it: its binding is tombstoned
        // and the startup selection scan filters tombstoned bindings, so
        // nothing can ever enumerate its media. That is NOT progress — it is
        // an account no retry can erase — so it must surface as the terminal
        // `failed_retryable` class an operator is shown, not as a `pending`
        // rung that re-drives every 30 seconds forever.
        control.begin_user_deletion(&user.id).await.unwrap();
        assert!(!store.is_wal_authoritative(&user.id));
        match delete_account_content(&control, store.as_ref(), &user.id)
            .await
            .expect_err("the media inventory can never be frozen for this account")
        {
            EnclaveError::DeletionPending(pending) => {
                assert_eq!(pending.reason.as_str(), "archive_v3_manual_required");
                assert_eq!(pending.retry_after_seconds, None);
            }
            other => panic!("expected a pending deletion, got {other:?}"),
        }
        let operation = control
            .update_user_deletion_status(&user.id, "archive_v3_manual_required", None, None)
            .await
            .unwrap();
        assert_eq!(operation.status, "failed_retryable");
        assert!(deletion_operation_requires_remediation(&operation));
    }

    /// The reconciler's WAL branch must freeze the media inventory *before* it
    /// drives the ladder, so an account that reached `deleting` without one —
    /// which is every WAL-authoritative account on an image with no lane — is
    /// rescued while its selection is still installed rather than stranded on
    /// a rung nothing can satisfy.
    ///
    /// A successful freeze cannot be reached end to end from here: it needs a
    /// launched serving authority, and nothing in this crate can build one in
    /// a test. So pin the wiring at the source level — the same technique the
    /// lifecycle module already uses for its anti-wiring gate — scanning only
    /// the WAL branch's own body so a deleted call cannot be masked by the
    /// literals in this test.
    #[test]
    fn the_wal_branch_freezes_the_media_inventory_before_it_drives() {
        let source = include_str!("sync.rs");
        let (_, after_lane) = source
            .split_once("let Some(lane) = store.wal_deletion_lane() else {")
            .expect("the WAL branch resolves the installed lane");
        let (branch, _) = after_lane
            .split_once("let operation = control.identity_rebind_operation_for_user")
            .expect("the WAL branch ends before the identity-rebind path");
        let freeze = branch
            .find("lane.freeze_media_inventory(")
            .expect("the WAL branch must freeze the media inventory");
        let drive = branch
            .find("lane.drive(")
            .expect("the WAL branch must drive the ladder");
        assert!(
            freeze < drive,
            "the media inventory must be frozen before the ladder is driven"
        );
    }

    /// The same rung stays retryable while the account's selection is still
    /// installed in this process: `delete_account_content` now runs the
    /// pre-tombstone freeze itself, so an account the route never froze is
    /// rescued here instead of being stranded — and when the freeze cannot
    /// complete, the rung it reports is the retryable one, because a later
    /// pass genuinely can satisfy it.
    #[tokio::test]
    async fn the_reconciler_freezes_the_media_inventory_before_driving_the_ladder() {
        struct NeverBuildsRuntime;

        #[async_trait::async_trait]
        impl crate::archive_v3_deletion_lane::ArchiveDeletionRuntimeFactory for NeverBuildsRuntime {
            async fn runtime_for(
                &self,
                _archive_id: crate::archive_v3::ArchiveId,
            ) -> EnclaveResult<Arc<dyn crate::archive_v3_deletion_lane::ArchiveDeletionRuntime>>
            {
                panic!("this rung must not construct an archive-v3 deletion runtime")
            }
        }

        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let user = control
            .upsert_user(
                "wal-lane-freeze",
                "wal-lane-freeze@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let archive_id = control
            .seed_wal_genesis_terminal_for_test(&user.id)
            .await
            .unwrap();
        store
            .install_wal_deletion_lane(Arc::new(
                crate::archive_v3_deletion_lane::WalDeletionLane::new(
                    Arc::new(
                        crate::archive_v3_witness::DeletionPrincipalKey::derive_from_control_root(
                            &[0x42; 32],
                        )
                        .unwrap(),
                    ),
                    Arc::new(NeverBuildsRuntime),
                ),
            ))
            .unwrap();
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    &user.id, archive_id,
                ),
            )
            .unwrap();
        control.begin_user_deletion(&user.id).await.unwrap();

        assert!(store.is_wal_authoritative(&user.id));
        match delete_account_content(&control, store.as_ref(), &user.id)
            .await
            .expect_err("the ladder has not completed")
        {
            EnclaveError::DeletionPending(pending) => {
                assert_eq!(
                    pending.reason.as_str(),
                    "archive_v3_media_inventory_pending"
                );
                assert_eq!(pending.retry_after_seconds, Some(30));
            }
            other => panic!("expected a pending deletion, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn restart_reconciler_finalizes_after_provider_soft_delete_expires() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let user = control
            .upsert_user(
                "deletion-restart-subject",
                "owner@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        store
            .with_user(&user.id, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text)
                     VALUES ('2026-08-10T00:00:00Z', 'restart fixture')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(&user.id).await.unwrap();
        let operation = control
            .begin_user_deletion(&user.id)
            .await
            .unwrap()
            .unwrap();
        gcs.set_soft_delete_enabled(true);
        let pending = match store.delete_user(&user.id).await.unwrap_err() {
            EnclaveError::DeletionPending(pending) => pending,
            error => panic!("unexpected deletion result: {error:?}"),
        };
        let persisted = control
            .update_user_deletion_status(
                &user.id,
                pending.reason.as_str(),
                pending.retry_after_seconds,
                pending.hard_delete_time.as_deref(),
            )
            .await
            .unwrap();
        assert_eq!(persisted.status, "pending");
        assert_eq!(persisted.operation_id, operation.operation_id);

        drop(store);
        drop(control);
        gcs.expire_soft_deleted("");
        let restarted_control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let restarted_store = Store::new(kms, gcs);

        let summary =
            reconcile_pending_account_deletions(&restarted_control, &restarted_store, None)
                .await
                .unwrap();
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.completed, 1);
        assert_eq!(summary.pending, 0);
        assert_eq!(summary.failed_retryable, 0);
        assert_eq!(summary.failures, 0);
        assert_eq!(
            restarted_control
                .user_status(&user.id)
                .await
                .unwrap()
                .as_deref(),
            Some("deleted")
        );
        let completed = restarted_control
            .account_deletion_operation(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completed.operation_id, operation.operation_id);
        assert_eq!(completed.status, "physical_complete");
        assert_eq!(completed.reason, "content_deleted");
        assert!(completed.retry_after_seconds.is_none());
        assert!(completed.hard_delete_time.is_none());
    }

    #[tokio::test]
    async fn cancelled_in_progress_attempt_is_retried_after_restart() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let user = control
            .upsert_user(
                "cancelled-deletion-subject",
                "owner@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        store
            .with_user(&user.id, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text)
                     VALUES ('2026-08-10T00:00:00Z', 'cancel fixture')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(&user.id).await.unwrap();
        let operation = control
            .begin_user_deletion(&user.id)
            .await
            .unwrap()
            .unwrap();
        let in_progress = control
            .update_user_deletion_status(&user.id, DELETION_ATTEMPT_UNCONFIRMED, None, None)
            .await
            .unwrap();
        assert_eq!(in_progress.status, "pending");

        // Model cancellation immediately after the durable in-progress marker:
        // no request task remains to update status or finalize the identity.
        drop(store);
        drop(control);
        let restarted_control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let restarted_store = Store::new(kms, gcs);

        let summary =
            reconcile_pending_account_deletions(&restarted_control, &restarted_store, None)
                .await
                .unwrap();
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.completed, 1);
        assert_eq!(summary.pending, 0);
        assert_eq!(summary.failed_retryable, 0);
        assert_eq!(summary.failures, 0);
        let completed = restarted_control
            .account_deletion_operation(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completed.operation_id, operation.operation_id);
        assert_eq!(completed.status, "physical_complete");
        assert!(completed.hard_delete_time.is_none());
    }

    #[tokio::test]
    async fn cancelled_apple_deletion_stays_pending_without_revocation_provider() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let user = control
            .upsert_apple_user(
                "cancelled-apple-deletion-subject",
                "owner@privaterelay.appleid.com",
                "com.kioku.ios",
                "retained-refresh-token",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let same_user_from_mac = control
            .upsert_apple_user(
                "cancelled-apple-deletion-subject",
                "owner@privaterelay.appleid.com",
                "com.kiokuu.app",
                "retained-mac-refresh-token",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(same_user_from_mac.id, user.id);
        control
            .begin_user_deletion(&user.id)
            .await
            .unwrap()
            .unwrap();
        control
            .update_user_deletion_status(&user.id, DELETION_ATTEMPT_UNCONFIRMED, None, None)
            .await
            .unwrap();

        // Cancellation after the durable fence but before revocation must not
        // let the restart worker delete content or finalize the account.
        drop(store);
        drop(control);
        let restarted_control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let restarted_store = Store::new(kms, gcs);
        let summary =
            reconcile_pending_account_deletions(&restarted_control, &restarted_store, None)
                .await
                .unwrap();

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.completed, 0);
        assert_eq!(summary.pending, 1);
        assert_eq!(summary.failures, 0);
        assert_eq!(
            restarted_control
                .user_status(&user.id)
                .await
                .unwrap()
                .as_deref(),
            Some("deleting")
        );
        let operation = restarted_control
            .account_deletion_operation(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(operation.status, "pending");
        assert_eq!(
            restarted_control
                .apple_refresh_credentials(&user.id)
                .await
                .unwrap(),
            vec![
                ("com.kioku.ios".into(), "retained-refresh-token".into()),
                ("com.kiokuu.app".into(), "retained-mac-refresh-token".into())
            ]
        );
    }

    #[tokio::test]
    async fn unavailable_legacy_generation_stays_failed_after_restart_and_empty_listing() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let user = control
            .upsert_user(
                "missing-generation-subject",
                "owner@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let historical_media = "media/sticky-historical-evidence";
        store
            .with_user(&user.id, |conn| {
                insert_screenshot_evidence(conn, historical_media)
            })
            .await
            .unwrap();
        store.save_user(&user.id).await.unwrap();
        let index = format!("indexes/{}.db.enc", user.id);
        let historical_generation = gcs.get_object(&index).await.unwrap().generation;
        store
            .with_user(&user.id, |conn| {
                conn.execute("DELETE FROM screenshot_images", [])?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(&user.id).await.unwrap();
        gcs.put_object(historical_media, b"historical", "wrapped", 0)
            .await
            .unwrap();
        let scoped_residue = format!("raw/{}/residue.enc", user.id);
        gcs.put_object(&scoped_residue, b"residue", "wrapped", 0)
            .await
            .unwrap();
        let operation = control
            .begin_user_deletion(&user.id)
            .await
            .unwrap()
            .unwrap();
        control
            .update_user_deletion_status(&user.id, DELETION_ATTEMPT_UNCONFIRMED, None, None)
            .await
            .unwrap();
        gcs.set_soft_delete_enabled(true);
        gcs.vanish_next_exact_generation_get(&index, historical_generation);

        let pending = match store.delete_user(&user.id).await.unwrap_err() {
            EnclaveError::DeletionPending(pending) => pending,
            error => panic!("unexpected deletion result: {error:?}"),
        };
        assert_eq!(pending.reason.as_str(), LEGACY_GENERATION_UNAVAILABLE);
        let sticky = control
            .update_user_deletion_status(
                &user.id,
                pending.reason.as_str(),
                pending.retry_after_seconds,
                pending.hard_delete_time.as_deref(),
            )
            .await
            .unwrap();
        assert_eq!(sticky.operation_id, operation.operation_id);
        assert_eq!(sticky.status, "failed_retryable");
        assert!(deletion_operation_requires_remediation(&sticky));

        drop(store);
        drop(control);
        gcs.expire_soft_deleted("");
        gcs.purge_versions(&index);
        gcs.purge_versions(&format!("legacy-recovery/{}/", user.id));
        let restarted_control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let restarted_store = Store::new(kms, gcs.clone());

        let summary =
            reconcile_pending_account_deletions(&restarted_control, &restarted_store, None)
                .await
                .unwrap();
        assert_eq!(summary.attempted, 0);
        assert_eq!(summary.completed, 0);
        assert_eq!(summary.pending, 0);
        assert_eq!(summary.failed_retryable, 0);
        assert_eq!(summary.failures, 0);
        assert_eq!(
            restarted_control
                .user_status(&user.id)
                .await
                .unwrap()
                .as_deref(),
            Some("deleting")
        );
        let after_restart = restarted_control
            .account_deletion_operation(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_restart.operation_id, operation.operation_id);
        assert_eq!(after_restart.status, "failed_retryable");
        assert_eq!(after_restart.reason, LEGACY_GENERATION_UNAVAILABLE);
        assert!(gcs.get_object(historical_media).await.is_ok());
    }

    /// The sync twin of `query.rs`'s routed-read table. Same property, same
    /// two lanes, same status-agnostic assertion: an archive that cannot be
    /// read is answered with a non-2xx carrying no data.
    ///
    /// `/api/sync/status` must never answer 200 with zeroed counts (an emptied
    /// archive) and `/api/export` must never answer 200 with an empty or
    /// truncated document (a lost archive). The `[selected]` lane is answered
    /// by the D4 gate; the `[unreadable legacy]` lane, where no gate can fire,
    /// is answered by each route's own failure arm.
    #[tokio::test]
    async fn both_routed_sync_reads_refuse_without_reporting_an_empty_archive() {
        use crate::cp::wal_gate_test_support::{
            assert_refuses_without_data, make_legacy_archive_unreadable, select_wal_authoritative,
            state as gate_state,
        };
        use axum::extract::State;

        async fn routed_sync_reads(
            state: &Arc<CpState>,
            user_id: &str,
        ) -> Vec<(&'static str, Response)> {
            vec![
                (
                    "GET /api/sync/status",
                    sync_status(
                        State(Arc::clone(state)),
                        Extension(AuthUser(user_id.to_string())),
                    )
                    .await,
                ),
                (
                    "GET /api/export",
                    export(
                        State(Arc::clone(state)),
                        Extension(AuthUser(user_id.to_string())),
                    )
                    .await,
                ),
            ]
        }

        let state = gate_state();

        let selected = "sync-selected-user";
        select_wal_authoritative(&state.store, selected);
        for (label, response) in routed_sync_reads(&state, selected).await {
            assert_refuses_without_data(&format!("{label} [selected]"), response).await;
        }

        let unreadable = "sync-unreadable-user";
        make_legacy_archive_unreadable(&state.store, unreadable).await;
        for (label, response) in routed_sync_reads(&state, unreadable).await {
            assert_refuses_without_data(&format!("{label} [unreadable legacy]"), response).await;
        }

        // The export keeps its own machine-readable reason — clients switch on
        // it — but answers it at 503, not the 500 it used to: there is exactly
        // one routed read behind that arm and its failure is retryable.
        let failed = export(
            State(Arc::clone(&state)),
            Extension(AuthUser(unreadable.to_string())),
        )
        .await;
        assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(failed.into_body(), 4 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "export_failed");
    }

    /// The other half of the dual-path contract: an unselected user is served
    /// by exactly the same routed call, through the ordinary guarded legacy
    /// read. Same rows, same shape — the legacy lane is untouched.
    #[tokio::test]
    async fn routed_sync_reads_still_serve_an_unselected_user_from_the_legacy_lane() {
        use crate::cp::wal_gate_test_support::state as gate_state;
        use axum::extract::State;

        let state = gate_state();
        let user_id = "sync-legacy-user";
        state
            .store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at) VALUES (?1)",
                    ["2026-08-20T09:00:00Z"],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let status = sync_status(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.to_string())),
        )
        .await;
        assert_eq!(status.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(status.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["counts"]["screenshots"], 1);
        assert_eq!(body["latest"]["screenshot_at"], "2026-08-20T09:00:00Z");

        let exported = export(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.to_string())),
        )
        .await;
        assert_eq!(exported.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(exported.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["screenshots"]
                .as_array()
                .expect("the export carries a screenshots array")
                .len(),
            1
        );
    }

    /// **ADR-0022 D4, `sync.status` LIFTED: the counts are REAL.**
    ///
    /// The gate this replaces existed because `200 {"counts": {"utterances":
    /// 0, ...}}` reads as "your archive is empty". Deleting it is only correct
    /// if the counts can be non-zero, so this asserts the exact fixture
    /// cardinalities and the freshness stamps — a route that answered zeroes,
    /// or answered counts without the `audio_segments` join behind
    /// `utterance_at`, fails here.
    #[tokio::test]
    async fn the_lifted_sync_status_route_answers_a_selected_user_with_real_counts() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;
        use axum::extract::State;

        let archive = answerable_wal_archive("b0000000-0000-4000-8000-000000000001").await;
        let response = sync_status(
            State(Arc::clone(&archive.state)),
            Extension(AuthUser(archive.user_id.clone())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["counts"]["utterances"].as_i64(), Some(6), "{body}");
        assert_eq!(body["counts"]["screenshots"].as_i64(), Some(1), "{body}");
        assert_eq!(body["counts"]["episodes"].as_i64(), Some(4), "{body}");
        assert_eq!(
            body["latest"]["utterance_at"].as_str(),
            Some("2026-07-22T14:00:00Z"),
            "the freshness stamp comes from the audio_segments join: {body}"
        );
        assert_eq!(
            body["latest"]["screenshot_at"].as_str(),
            Some("2026-07-22T11:20:00Z"),
            "{body}"
        );
    }

    /// **`sync.export` LIFTED: the document carries rows.**
    ///
    /// This is the widest read in the lane, and its old rationale was that an
    /// ungated export hands back "a complete-looking document with every array
    /// empty". So the assertion is exactly that claim's negation, per table
    /// rather than in aggregate: an export that filled `utterances` and left
    /// `episodes` empty would be the same defect in a smaller place.
    ///
    /// The arrays that legitimately stay empty are asserted empty on purpose.
    /// `people` and `person_facts` have no WAL-lane writer by construction
    /// (see `wal_domain::MEDIA_PEOPLE`), and an export is the one surface
    /// whose job is to report that faithfully rather than hide it — but if a
    /// future change starts filling them, this fails and the reviewer has to
    /// decide deliberately rather than by drift.
    #[tokio::test]
    async fn the_lifted_export_route_answers_a_selected_user_with_a_populated_document() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;
        use axum::extract::State;

        let archive = answerable_wal_archive("b0000000-0000-4000-8000-000000000002").await;
        let response = export(
            State(Arc::clone(&archive.state)),
            Extension(AuthUser(archive.user_id.clone())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for (field, expected) in [
            ("utterances", 6usize),
            ("screenshots", 1),
            ("episodes", 4),
            ("episode_final_briefs", 4),
        ] {
            let rows = body[field]
                .as_array()
                .unwrap_or_else(|| panic!("the export carries a {field} array: {body}"));
            assert_eq!(rows.len(), expected, "{field}: {body}");
        }
        assert!(
            body["utterances"]
                .as_array()
                .expect("checked above")
                .iter()
                .any(|row| row["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("August 19"))),
            "the export must carry the transcript CONTENT, not just row count: {body}"
        );
        for empty in ["person_facts", "voice_profiles", "media_objects"] {
            assert_eq!(
                body[empty].as_array().map(Vec::len),
                Some(0),
                "{empty} has no WAL-lane writer reachable from this fixture; a \
                 non-empty array here needs a deliberate review, not a silent \
                 pass: {body}"
            );
        }
        // `people` is the one that is not empty and still carries no identity:
        // `init_schema` seeds a single `kind='owner'` row at `status='unknown'`,
        // which every people READ filters out (see `wal_domain::MEDIA_PEOPLE`).
        // Pinning its shape rather than its emptiness is what would catch a
        // future change that starts committing identity on this lane.
        let people = body["people"]
            .as_array()
            .unwrap_or_else(|| panic!("the export carries a people array: {body}"));
        assert_eq!(people.len(), 1, "{body}");
        assert_eq!(people[0]["kind"], "owner", "{body}");
        assert_eq!(
            people[0]["status"], "unknown",
            "no WAL-lane writer commits an identified person: {body}"
        );
    }
}
