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
use tracing::warn;

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
    let email = s.control.user_email(&user_id).await.ok().flatten();

    let stats = s
        .store
        .with_user(&user_id, |conn| {
            let utt: i64 = conn.query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))?;
            let scr: i64 = conn.query_row("SELECT count(*) FROM screenshots", [], |r| r.get(0))?;
            let eps: i64 = conn.query_row("SELECT count(*) FROM episodes", [], |r| r.get(0))?;
            let last_u: Option<String> = conn
                .query_row(
                    "SELECT s.started_at FROM utterances u JOIN audio_segments s ON s.id = u.audio_segment_id ORDER BY s.started_at DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .ok();
            let last_s: Option<String> = conn
                .query_row("SELECT captured_at FROM screenshots ORDER BY captured_at DESC LIMIT 1", [], |r| r.get(0))
                .ok();
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
        Err(_) => err503(),
    }
}

// ── Export ──────────────────────────────────────────────────────────────────────

async fn export(State(s): State<Arc<CpState>>, Extension(user): Extension<AuthUser>) -> Response {
    match dump_user_export(&s.store, &user.0).await {
        Ok(data) => (
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
            .into_response(),
        Err(e) => {
            warn!(error = %e, "export failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "export_failed"})),
            )
                .into_response()
        }
    }
}

async fn dump_user_export(store: &Store, user_id: &str) -> EnclaveResult<serde_json::Value> {
    crate::store::validate_user_id(user_id)?;
    store
        .read_user(user_id, |conn| {
            Ok(json!({
                "utterances": dump_optional_table(conn, "utterances", "id")?,
                "screenshots": dump_optional_table(conn, "screenshots", "id")?,
                "screenshot_images": dump_optional_table(conn, "screenshot_images", "id")?,
                "episodes": dump_optional_table(conn, "episodes", "id")?,
                "episode_final_briefs": dump_optional_table(conn, "episode_final_briefs", "episode_id")?,
                "capture_sessions": dump_optional_table(conn, "capture_sessions", "created_at")?,
                "capture_streams": dump_optional_table(conn, "capture_streams", "created_at")?,
                "capture_events": dump_optional_table(conn, "capture_events", "started_at, event_id")?,
                "media_objects": dump_optional_table(conn, "media_objects", "created_at, event_id")?,
                "speaker_observations": dump_optional_table(conn, "speaker_observations", "started_at, event_id, id")?,
                "people": dump_optional_table(conn, "people", "display_name, id")?,
                "voice_profiles": dump_optional_table(conn, "voice_profiles", "person_id, id")?,
                "voice_samples": dump_optional_table(conn, "voice_samples", "speaker_observation_id, id")?,
            }))
        })
        .await
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
    if let Err(error) = s.store.delete_user(&user_id).await {
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
    control: &ControlStore,
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

        match store.delete_user(&user_id).await {
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
    async fn restart_reconciler_finalizes_after_provider_soft_delete_expires() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let user = control
            .upsert_user("deletion-restart-subject", "owner@example.com")
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
        let restarted_control = ControlStore::new(kms.clone(), gcs.clone());
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
            .upsert_user("cancelled-deletion-subject", "owner@example.com")
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
        let restarted_control = ControlStore::new(kms.clone(), gcs.clone());
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
            )
            .await
            .unwrap();
        let same_user_from_mac = control
            .upsert_apple_user(
                "cancelled-apple-deletion-subject",
                "owner@privaterelay.appleid.com",
                "com.kiokuu.app",
                "retained-mac-refresh-token",
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
        let restarted_control = ControlStore::new(kms.clone(), gcs.clone());
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
            .upsert_user("missing-generation-subject", "owner@example.com")
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
        let restarted_control = ControlStore::new(kms.clone(), gcs.clone());
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
}
