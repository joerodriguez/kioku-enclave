//! Account-wide durable-recording retention settings.
//!
//! The HTTP surface is intentionally a two-step preview/confirm contract. A
//! preview is bound to a settled Control revision and a fingerprint of the
//! exact user-store recording inventory; the confirming request recomputes
//! that inventory while holding the same per-user lifecycle gate as capture.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Router,
};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::{EnclaveError, Result};

use super::{
    auth::{AuthEvidence, AuthUser},
    control_store::{
        RecordingRetentionInventory, RecordingRetentionPolicy, RECORDING_RETENTION_CONSENT_VERSION,
    },
    CpState,
};

const RECENT_DESTRUCTIVE_AUTH_MAX_AGE: Duration = Duration::from_secs(10 * 60);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);
const RECONCILE_BATCH_SIZE: usize = 8;

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route(
            "/api/v2/settings/recording-retention",
            get(get_recording_retention),
        )
        .route(
            "/api/v2/settings/recording-retention/preview",
            post(preview_recording_retention),
        )
        .route(
            "/api/v2/settings/recording-retention/changes",
            post(change_recording_retention),
        )
        .route(
            "/api/v2/settings/recording-retention/changes/{operation_id}",
            get(get_recording_retention_change),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionPreviewRequest {
    target_policy: RecordingRetentionPolicy,
    expected_revision: i64,
    consent_version: i64,
    #[serde(default)]
    promote_existing: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionChangeRequest {
    preview_id: String,
    target_policy: RecordingRetentionPolicy,
    expected_revision: i64,
    consent_version: i64,
    #[serde(default)]
    promote_existing: bool,
}

fn no_store_json(status: StatusCode, value: serde_json::Value) -> Response {
    (
        status,
        [
            ("cache-control", "private, no-store, max-age=0"),
            ("pragma", "no-cache"),
        ],
        Json(value),
    )
        .into_response()
}

fn retention_error(error: EnclaveError) -> Response {
    match error {
        EnclaveError::InvalidRequest(message) => {
            no_store_json(StatusCode::BAD_REQUEST, json!({"error": message}))
        }
        EnclaveError::Conflict(message) => {
            no_store_json(StatusCode::CONFLICT, json!({"error": message}))
        }
        EnclaveError::NotFound => {
            no_store_json(StatusCode::NOT_FOUND, json!({"error": "not_found"}))
        }
        EnclaveError::Auth(_) => {
            no_store_json(StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"}))
        }
        error => {
            tracing::error!(error = %error, "recording retention request failed");
            no_store_json(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "enclave_unavailable"}),
            )
        }
    }
}

fn retention_response(
    state: &CpState,
    preference: &super::control_store::RecordingRetentionPreference,
    inventory: &RecordingRetentionInventory,
) -> serde_json::Value {
    json!({
        "capability": {
            "id": "recording_retention_v1",
            "available": durable_recording_retention_available(state),
            "consent_version": RECORDING_RETENTION_CONSENT_VERSION,
            "prospective_enablement": true,
            "promotion_available": false,
        },
        "policy": preference.policy,
        "consent_version": preference.consent_version,
        "revision": preference.revision,
        "policy_epoch": preference.policy_epoch,
        "effective_at": preference.effective_at,
        "revocation_cutoff": preference.revocation_cutoff,
        "active_operation": preference.active_operation_id.as_ref().map(|operation_id| json!({
            "operation_id": operation_id,
            "state": preference.operation_state,
        })),
        "inventory": inventory,
    })
}

fn durable_recording_retention_available(state: &CpState) -> bool {
    state.durable_recording_storage_bound && crate::schema_ladder::durable_recording_schema_active()
}

async fn get_recording_retention(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let _lifecycle_guard = match state.store.lock_user_lifecycle(&user.0).await {
        Ok(guard) => guard,
        Err(error) => return retention_error(error),
    };
    let preference = match state
        .control
        .get_recording_retention_preference(&user.0)
        .await
    {
        Ok(preference) => preference,
        Err(error) => return retention_error(error),
    };
    let inventory = match recording_inventory(&state, &user.0, &preference).await {
        Ok(inventory) => inventory,
        Err(error) => return retention_error(error),
    };
    no_store_json(
        StatusCode::OK,
        retention_response(&state, &preference, &inventory),
    )
}

async fn preview_recording_retention(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(request): Json<RetentionPreviewRequest>,
) -> Response {
    if request.target_policy == RecordingRetentionPolicy::UntilDeleted
        && !durable_recording_retention_available(&state)
    {
        return no_store_json(
            StatusCode::PRECONDITION_FAILED,
            json!({"error": "recording_retention_unavailable"}),
        );
    }
    let _lifecycle_guard = match state.store.lock_user_lifecycle(&user.0).await {
        Ok(guard) => guard,
        Err(error) => return retention_error(error),
    };
    let preference = match state
        .control
        .get_recording_retention_preference(&user.0)
        .await
    {
        Ok(preference) => preference,
        Err(error) => return retention_error(error),
    };
    let inventory = match recording_inventory(&state, &user.0, &preference).await {
        Ok(inventory) => inventory,
        Err(error) => return retention_error(error),
    };
    match state
        .control
        .create_recording_retention_preview(
            &user.0,
            request.target_policy,
            request.expected_revision,
            request.consent_version,
            request.promote_existing,
            inventory,
        )
        .await
    {
        Ok(preview) => no_store_json(StatusCode::OK, json!(preview)),
        Err(error) => retention_error(error),
    }
}

async fn change_recording_retention(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    evidence: Option<Extension<AuthEvidence>>,
    headers: HeaderMap,
    Json(request): Json<RetentionChangeRequest>,
) -> Response {
    if request.target_policy == RecordingRetentionPolicy::UntilDeleted
        && !durable_recording_retention_available(&state)
    {
        return no_store_json(
            StatusCode::PRECONDITION_FAILED,
            json!({"error": "recording_retention_unavailable"}),
        );
    }
    if request.target_policy == RecordingRetentionPolicy::ProcessingWindow30d
        && !evidence
            .map(|Extension(value)| value.is_recent_provider_auth(RECENT_DESTRUCTIVE_AUTH_MAX_AGE))
            .unwrap_or(false)
    {
        return no_store_json(
            StatusCode::PRECONDITION_REQUIRED,
            json!({
                "error": "recent_authentication_required",
                "max_age_seconds": RECENT_DESTRUCTIVE_AUTH_MAX_AGE.as_secs(),
            }),
        );
    }
    let Some(idempotency_key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
    else {
        return no_store_json(
            StatusCode::BAD_REQUEST,
            json!({"error": "idempotency_key_required"}),
        );
    };

    let lifecycle_guard = match state.store.lock_user_lifecycle(&user.0).await {
        Ok(guard) => guard,
        Err(error) => return retention_error(error),
    };
    let preference = match state
        .control
        .get_recording_retention_preference(&user.0)
        .await
    {
        Ok(preference) => preference,
        Err(error) => return retention_error(error),
    };
    let inventory = match recording_inventory(&state, &user.0, &preference).await {
        Ok(inventory) => inventory,
        Err(error) => return retention_error(error),
    };
    let change = match state
        .control
        .change_recording_retention_policy(
            &user.0,
            request.target_policy,
            request.expected_revision,
            request.consent_version,
            request.promote_existing,
            &request.preview_id,
            inventory,
            idempotency_key,
        )
        .await
    {
        Ok(change) => change,
        Err(error) => return retention_error(error),
    };

    if change.policy == RecordingRetentionPolicy::UntilDeleted {
        let preference = match state
            .control
            .get_recording_retention_preference(&user.0)
            .await
        {
            Ok(preference) => preference,
            Err(error) => return retention_error(error),
        };
        let Some(policy_epoch) = preference.policy_epoch.as_deref() else {
            return retention_error(EnclaveError::Store(
                "durable recording policy lost its key epoch".into(),
            ));
        };
        if let Err(error) = state
            .control
            .load_or_create_recording_key_epoch(&user.0, preference.revision, policy_epoch)
            .await
        {
            return retention_error(error);
        }
        return no_store_json(StatusCode::OK, json!(change));
    }

    // The settled preference is already the monotonic read/write fence. Drop
    // the caller-owned gate before the reconciler reacquires it to do bounded
    // provider work; a failure remains a visible, retryable 202 operation.
    drop(lifecycle_guard);
    match state
        .control
        .reconcile_recording_retention_change(&user.0, &change.operation_id)
        .await
    {
        Ok(completed) => no_store_json(StatusCode::OK, json!(completed)),
        Err(error) => {
            tracing::warn!(error = %error, "recording retention deletion remains pending");
            no_store_json(StatusCode::ACCEPTED, json!(change))
        }
    }
}

async fn get_recording_retention_change(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(operation_id): Path<String>,
) -> Response {
    match state
        .control
        .recording_retention_change(&user.0, &operation_id)
        .await
    {
        Ok(Some(change)) => no_store_json(StatusCode::OK, json!(change)),
        Ok(None) => no_store_json(StatusCode::NOT_FOUND, json!({"error": "not_found"})),
        Err(error) => retention_error(error),
    }
}

async fn recording_inventory(
    state: &CpState,
    user_id: &str,
    preference: &super::control_store::RecordingRetentionPreference,
) -> Result<RecordingRetentionInventory> {
    let (policy_revision, policy_epoch) = match preference.policy {
        RecordingRetentionPolicy::UntilDeleted => {
            let epoch = preference.policy_epoch.clone().ok_or_else(|| {
                EnclaveError::Store("durable recording policy lost its epoch".into())
            })?;
            (Some(preference.revision), Some(epoch))
        }
        RecordingRetentionPolicy::ProcessingWindow30d if preference.operation_state.is_some() => {
            // A downgrade deletes the complete durable prefix, including any
            // historical epoch. Keep displaying that bounded work until its
            // provider/key purge settles.
            (None, None)
        }
        RecordingRetentionPolicy::ProcessingWindow30d => return Ok(empty_recording_inventory()),
    };
    let user_id = user_id.to_string();
    state
        .store
        .wal_authoritative_read(&user_id.clone(), move |connection| {
            recording_inventory_conn(
                connection,
                &user_id,
                policy_revision,
                policy_epoch.as_deref(),
            )
        })
        .await
}

pub(crate) async fn recording_authority_schema_present(
    state: &CpState,
    user_id: &str,
) -> Result<bool> {
    state
        .store
        .wal_authoritative_read(user_id, |connection| {
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='table' AND name='recording_media_authority'",
                [],
                |row| row.get(0),
            )?;
            Ok(count == 1)
        })
        .await
}

fn recording_inventory_conn(
    connection: &Connection,
    user_id: &str,
    policy_revision: Option<i64>,
    policy_epoch: Option<&str>,
) -> Result<RecordingRetentionInventory> {
    if policy_revision.is_some() != policy_epoch.is_some()
        || policy_revision.is_some_and(|revision| revision <= 0)
    {
        return Err(EnclaveError::Store(
            "recording inventory policy fence is malformed".into(),
        ));
    }
    let authority_table_present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema
         WHERE type='table' AND name='recording_media_authority')",
        [],
        |row| row.get(0),
    )?;
    if !authority_table_present {
        return Err(EnclaveError::Store(
            "recording inventory authority table is unavailable".into(),
        ));
    }
    let prefix = format!("recordings/{user_id}/");
    let mut statement = connection.prepare(
        "SELECT m.asset_id,m.object_key,COALESCE(m.object_generation,0),m.byte_length,
                m.sha256,e.capture_session_id,m.processing_state,COALESCE(m.deleted_at,''),
                ra.retention_policy_revision,ra.retention_policy_epoch,ra.recording_state
         FROM media_objects m
         JOIN capture_events e ON e.event_id=m.event_id
         JOIN recording_media_authority ra ON ra.asset_id=m.asset_id
         WHERE substr(m.object_key,1,?2)=?1
           AND ra.retention_decision='until_deleted'
           AND ra.storage_backend='recordings'
           AND ra.recording_state IN ('durable','delete_pending')
           AND (?3 IS NULL OR (
             ra.retention_policy_revision=?3 AND ra.retention_policy_epoch=?4
           ))
         ORDER BY m.asset_id,m.object_key",
    )?;
    let mut rows = statement.query(rusqlite::params![
        prefix,
        prefix.len() as i64,
        policy_revision,
        policy_epoch,
    ])?;
    let mut digest = Sha256::new();
    digest.update(b"kioku.recording-retention-inventory.v1\0");
    let mut object_count = 0_i64;
    let mut byte_count = 0_i64;
    let mut recordings = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let asset_id: String = row.get(0)?;
        let object_key: String = row.get(1)?;
        let generation: i64 = row.get(2)?;
        let bytes: i64 = row.get(3)?;
        let sha256: String = row.get(4)?;
        let recording_id: String = row.get(5)?;
        let state: String = row.get(6)?;
        let deleted_at: String = row.get(7)?;
        let authority_revision: i64 = row.get(8)?;
        let authority_epoch: String = row.get(9)?;
        let authority_state: String = row.get(10)?;
        for value in [
            asset_id.as_bytes(),
            object_key.as_bytes(),
            &generation.to_be_bytes(),
            &bytes.to_be_bytes(),
            sha256.as_bytes(),
            recording_id.as_bytes(),
            state.as_bytes(),
            deleted_at.as_bytes(),
            &authority_revision.to_be_bytes(),
            authority_epoch.as_bytes(),
            authority_state.as_bytes(),
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        if generation > 0 && bytes > 0 && deleted_at.is_empty() && state != "pruned" {
            object_count = object_count.saturating_add(1);
            byte_count = byte_count.saturating_add(bytes);
            recordings.insert(recording_id);
        }
    }
    Ok(RecordingRetentionInventory {
        inventory_fingerprint: format!("{:x}", digest.finalize()),
        object_count,
        byte_count,
        recording_count: i64::try_from(recordings.len()).unwrap_or(i64::MAX),
    })
}

fn empty_recording_inventory() -> RecordingRetentionInventory {
    RecordingRetentionInventory {
        inventory_fingerprint: format!(
            "{:x}",
            Sha256::digest(b"kioku.recording-retention-inventory.v1\0")
        ),
        object_count: 0,
        byte_count: 0,
        recording_count: 0,
    }
}

pub(crate) fn spawn_reconciler(state: Arc<CpState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
        loop {
            interval.tick().await;
            let pending = match state
                .control
                .pending_recording_retention_changes(RECONCILE_BATCH_SIZE)
                .await
            {
                Ok(pending) => pending,
                Err(error) => {
                    tracing::warn!(error = %error, "recording retention reconciliation scan failed");
                    continue;
                }
            };
            for (user_id, operation_id) in pending {
                if let Err(error) = state
                    .control
                    .reconcile_recording_retention_change(&user_id, &operation_id)
                    .await
                {
                    tracing::warn!(error = %error, "recording retention reconciliation deferred");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_inventory_is_owner_scoped_and_state_sensitive() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE capture_events(event_id TEXT PRIMARY KEY,capture_session_id TEXT NOT NULL);
                 CREATE TABLE media_objects(
                   asset_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,object_key TEXT NOT NULL,
                   object_generation INTEGER,byte_length INTEGER NOT NULL,sha256 TEXT NOT NULL,
                   processing_state TEXT NOT NULL,deleted_at TEXT
                 );
                 CREATE TABLE recording_media_authority(
                   asset_id TEXT PRIMARY KEY,retention_policy_revision INTEGER NOT NULL,
                   retention_policy_epoch TEXT NOT NULL,retention_decision TEXT NOT NULL,
                   storage_backend TEXT NOT NULL,recording_state TEXT NOT NULL
                 );
                 INSERT INTO capture_events VALUES ('e1','session-a'),('e2','session-a'),('e3','session-b');
                 INSERT INTO media_objects VALUES
                   ('a1','e1','recordings/alice/a1.enc',1,10,'aa','ready',NULL),
                   ('a2','e2','recordings/alice/a2.enc',2,20,'bb','ready',NULL),
                   ('a3','e3','recordings/bob/a3.enc',1,30,'cc','ready',NULL);
                 INSERT INTO recording_media_authority VALUES
                   ('a1',3,'rpe_current','until_deleted','recordings','durable'),
                   ('a2',2,'rpe_old','until_deleted','recordings','durable'),
                   ('a3',3,'rpe_current','until_deleted','recordings','durable');",
            )
            .unwrap();
        let alice = recording_inventory_conn(&connection, "alice", None, None).unwrap();
        assert_eq!(alice.object_count, 2);
        assert_eq!(alice.byte_count, 30);
        assert_eq!(alice.recording_count, 1);
        let current =
            recording_inventory_conn(&connection, "alice", Some(3), Some("rpe_current")).unwrap();
        assert_eq!(current.object_count, 1);
        assert_eq!(current.byte_count, 10);
        let before = alice.inventory_fingerprint;
        connection
            .execute(
                "UPDATE media_objects SET processing_state='pruned' WHERE asset_id='a2'",
                [],
            )
            .unwrap();
        let after = recording_inventory_conn(&connection, "alice", None, None).unwrap();
        assert_eq!(after.object_count, 1);
        assert_ne!(before, after.inventory_fingerprint);
        assert_eq!(empty_recording_inventory().object_count, 0);
    }
}
