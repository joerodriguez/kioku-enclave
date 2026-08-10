//! Device-to-enclave sync and account endpoints. All routes are auth-gated by the
//! [`super::auth::require_auth`] middleware applied in `main`.
//!
//! `POST /api/sync/batch`  — idempotent ingest (utterances joined to segments).
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
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::{
    error::{EnclaveError, Result as EnclaveResult},
    ingest::{IngestRequest, ScreenshotInput, UtteranceInput},
    store::Store,
};

use super::auth::AuthUser;
use super::control_store::{AccountDeletionOperation, ControlStore};
use super::{isotime, limits, CpState};

const DELETION_RECONCILE_INTERVAL: Duration = Duration::from_secs(300);
const DELETION_RECONCILE_BATCH_SIZE: usize = 64;
const DELETION_ATTEMPT_UNCONFIRMED: &str = "content_deletion_attempt_unconfirmed";
#[cfg(test)]
const LEGACY_GENERATION_UNAVAILABLE: &str = "legacy_generation_unavailable";

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route("/api/sync/batch", post(sync_batch))
        .route("/api/sync/status", get(sync_status))
        .route("/api/export", get(export))
        .route("/api/account", delete(delete_account))
        .route("/api/account/deletion", get(account_deletion_status))
}

// ── Batch shape (the wire format the Mac sends) ─────────────────────────────────

#[derive(Deserialize)]
struct Segment {
    local_id: i64,
    source_type: String,
    started_at: String,
    duration_seconds: Option<f64>,
    #[allow(dead_code)]
    detected_language: Option<String>,
}

#[derive(Deserialize)]
struct Utterance {
    local_id: i64,
    segment_local_id: i64,
    start_offset_seconds: f64,
    end_offset_seconds: f64,
    text: String,
    language: Option<String>,
    confidence: Option<f64>,
    speaker_label: Option<String>,
    embedding_b64: Option<String>,
}

#[derive(Deserialize)]
struct Screenshot {
    local_id: i64,
    captured_at: String,
    active_app: Option<String>,
    window_title: Option<String>,
    ocr_text: Option<String>,
    salient_ocr_text: Option<String>,
    url: Option<String>,
    image_hash: Option<String>,
    is_duplicate: Option<i64>,
    display_id: Option<i64>,
    capture_context_version: Option<i64>,
    capture_status: Option<String>,
    primary_bundle_id: Option<String>,
    primary_window_id: Option<i64>,
    capture_group_id: Option<String>,
    visible_windows: Option<serde_json::Value>,
    visible_windows_truncated: Option<bool>,
    visual_signals: Option<serde_json::Value>,
    semantic_context_hash: Option<String>,
    browser_snapshot_source_key: Option<String>,
    browser_snapshot: Option<crate::ingest::BrowserSnapshotInput>,
    duplicate_of_local_id: Option<i64>,
    visible_until: Option<String>,
    dedupe_version: Option<i64>,
    /// Optional 384-dim OCR-text embedding (see `crate::embedding::MODEL_ID`).
    embedding_b64: Option<String>,
}

#[derive(Deserialize)]
struct SettledWatermarks {
    audio: Option<String>,
    screen: Option<String>,
}

#[derive(Deserialize)]
struct Batch {
    device_id: String,
    /// Embedding-space id for every embedding_b64 in this batch. Old clients
    /// omit it (and send no embeddings); the ingest model gate handles both.
    #[serde(default)]
    embedding_model: Option<String>,
    #[serde(default)]
    segments: Vec<Segment>,
    #[serde(default)]
    utterances: Vec<Utterance>,
    #[serde(default)]
    screenshots: Vec<Screenshot>,
    #[serde(default)]
    settled_watermarks: Option<SettledWatermarks>,
}

async fn sync_batch(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(batch): Json<Batch>,
) -> Response {
    let user_id = user.0;

    // 1. Account active
    match limits::account_active(&s.control, &user_id).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "account_suspended"})),
            )
                .into_response()
        }
        Err(_) => return err503(),
    }

    // 2. Rate limit
    if !s.sync_limiter.consume(&user_id).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited", "retry_after": 5})),
        )
            .into_response();
    }

    // 3. Daily quota
    let limits = (
        s.config.quota_utterances_per_day,
        s.config.quota_screenshots_per_day,
        s.config.quota_mcp_calls_per_day,
    );
    match limits::daily_quota(
        &s.control,
        &user_id,
        batch.utterances.len() as i64,
        batch.screenshots.len() as i64,
        0,
        limits,
    )
    .await
    {
        Ok(q) if !q.allowed => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "quota_exceeded", "quota": q.quota})),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(_) => return err503(),
    }

    // 4. Join utterances → segments, build the in-process ingest request.
    let browser_prefix = format!("{}:browser-v1:", batch.device_id);
    if batch.screenshots.iter().any(|screenshot| {
        screenshot
            .browser_snapshot_source_key
            .as_deref()
            .is_some_and(|key| !key.starts_with(&browser_prefix))
            || screenshot
                .browser_snapshot
                .as_ref()
                .is_some_and(|snapshot| {
                    !snapshot.source_key.starts_with(&browser_prefix)
                        || screenshot.browser_snapshot_source_key.as_deref()
                            != Some(snapshot.source_key.as_str())
                })
    }) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_browser_snapshot_namespace"})),
        )
            .into_response();
    }
    let req = build_ingest(&user_id, &batch);

    let ingest_resp = match crate::ingest::ingest_batch(&s.store, &req).await {
        Ok(r) => r,
        Err(crate::error::EnclaveError::InvalidRequest(message)) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": message}))).into_response();
        }
        Err(e) => {
            warn!(error = %e, "enclave ingest failed");
            return err503();
        }
    };

    // 5. If watermarks are provided, upsert them and save the DB
    let mut trigger_finalization = false;
    if let Some(w) = &batch.settled_watermarks {
        let user_id_cloned = user_id.clone();
        let device_id = batch.device_id.clone();
        let audio = w.audio.clone();
        let screen = w.screen.clone();
        let db_res = s.store.with_user(&user_id_cloned, move |conn| {
            if let Some(a) = audio {
                conn.execute(
                    "INSERT INTO device_watermarks (device_id, modality, watermark_at)
                     VALUES (?1, 'audio', ?2)
                     ON CONFLICT(device_id, modality) DO UPDATE SET
                        watermark_at = CASE WHEN excluded.watermark_at > watermark_at THEN excluded.watermark_at ELSE watermark_at END,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                    [&device_id, &a],
                )?;
            }
            if let Some(sc) = screen {
                conn.execute(
                    "INSERT INTO device_watermarks (device_id, modality, watermark_at)
                     VALUES (?1, 'screen', ?2)
                     ON CONFLICT(device_id, modality) DO UPDATE SET
                        watermark_at = CASE WHEN excluded.watermark_at > watermark_at THEN excluded.watermark_at ELSE watermark_at END,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                    [&device_id, &sc],
                )?;
            }
            Ok(())
        }).await;
        if let Err(e) = db_res {
            warn!(error = %e, "failed to save settled watermarks");
        } else if let Err(e) = s.store.save_user(&user_id).await {
            warn!(error = %e, "failed to save user DB after watermark update");
        } else {
            trigger_finalization = w.audio.is_some() || w.screen.is_some();
        }
    }

    // A newly persisted settled watermark can make a pending episode eligible
    // immediately. Keep this detached from the sync response: the periodic
    // scheduler remains the retry path if finalization itself fails.
    if trigger_finalization {
        let state = Arc::clone(&s);
        let finalizer_user = user_id.clone();
        tokio::spawn(async move {
            if let Err(e) = super::finalizer::finalize_user_episodes(&state, &finalizer_user).await
            {
                warn!(
                    user_id = %finalizer_user,
                    error = %e,
                    "post-sync episode finalization failed"
                );
            }
            if let Err(e) =
                super::webhook_worker::deliver_user_webhooks(&state, &finalizer_user).await
            {
                warn!(
                    user_id = %finalizer_user,
                    error = %e,
                    "post-sync webhook delivery failed"
                );
            }
            if let Some(ref transport) = state.email_transport {
                if let Err(e) = super::email_worker::deliver_user_emails(
                    &state,
                    transport.as_ref(),
                    &finalizer_user,
                )
                .await
                {
                    warn!(
                        user_id = %finalizer_user,
                        error = %e,
                        "post-sync email delivery failed"
                    );
                }
            }
        });
    }

    Json(json!({
        "ok": true,
        "upserted": {
            "utterances": ingest_resp.utterances_inserted,
            "screenshots": ingest_resp.screenshots_inserted,
        }
    }))
    .into_response()
}

/// Join utterances to their segments (computing absolute timestamps +
/// source_key); utterances whose segment is absent from the batch are skipped.
fn build_ingest(user_id: &str, batch: &Batch) -> IngestRequest {
    let find_seg = |id: i64| batch.segments.iter().find(|s| s.local_id == id);
    let utterances = batch
        .utterances
        .iter()
        .filter_map(|u| {
            let seg = find_seg(u.segment_local_id)?;
            let seg_started = seg.started_at.clone();
            let seg_ended = match seg.duration_seconds {
                Some(d) => isotime::add_seconds(&seg_started, d),
                None => seg_started.clone(),
            };
            Some(UtteranceInput {
                segment_started_at: seg_started,
                segment_ended_at: seg_ended,
                duration_seconds: seg.duration_seconds,
                source_type: seg.source_type.clone(),
                start_offset_seconds: u.start_offset_seconds,
                end_offset_seconds: u.end_offset_seconds,
                text: u.text.clone(),
                speaker_label: u
                    .speaker_label
                    .clone()
                    .unwrap_or_else(|| "speaker_0".to_string()),
                language: u.language.clone(),
                confidence: u.confidence,
                source_key: Some(format!(
                    "{}:{}:{}",
                    batch.device_id, u.segment_local_id, u.local_id
                )),
                embedding_b64: u.embedding_b64.clone(),
            })
        })
        .collect();

    let screenshots = batch
        .screenshots
        .iter()
        .map(|sc| ScreenshotInput {
            captured_at: sc.captured_at.clone(),
            active_app: sc.active_app.clone(),
            window_title: sc.window_title.clone(),
            ocr_text: sc.ocr_text.clone(),
            salient_ocr_text: sc.salient_ocr_text.clone(),
            url: sc.url.clone(),
            image_hash: sc.image_hash.clone(),
            is_duplicate: sc.is_duplicate,
            display_id: sc.display_id,
            capture_context_version: sc.capture_context_version,
            capture_status: sc.capture_status.clone(),
            primary_bundle_id: sc.primary_bundle_id.clone(),
            primary_window_id: sc.primary_window_id,
            capture_group_id: sc.capture_group_id.clone(),
            visible_windows: sc.visible_windows.clone(),
            visible_windows_truncated: sc.visible_windows_truncated,
            visual_signals: sc.visual_signals.clone(),
            semantic_context_hash: sc.semantic_context_hash.clone(),
            browser_snapshot_source_key: sc.browser_snapshot_source_key.clone(),
            browser_snapshot: sc.browser_snapshot.clone(),
            duplicate_of_source_key: sc
                .duplicate_of_local_id
                .map(|local_id| format!("{}:{}", batch.device_id, local_id)),
            visible_until: sc.visible_until.clone(),
            dedupe_version: sc.dedupe_version,
            source_key: Some(format!("{}:{}", batch.device_id, sc.local_id)),
            embedding_b64: sc.embedding_b64.clone(),
        })
        .collect();

    IngestRequest {
        user_id: user_id.to_string(),
        embedding_model: batch.embedding_model.clone(),
        utterances,
        screenshots,
    }
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
    match crate::dump_user_export(&s.store, &user.0).await {
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

// ── Account deletion ────────────────────────────────────────────────────────────

async fn delete_account(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let user_id = user.0;
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

    // Revoke Apple's retained refresh authorization before deleting the local
    // credential. A failed revocation leaves the durable deleting operation in
    // place so this authenticated DELETE can safely retry it.
    let apple_refresh = match s.control.apple_refresh_token(&user_id).await {
        Ok(token) => token,
        Err(_) => {
            warn!("Apple credential lookup failed during account deletion");
            return deletion_delete_response(operation);
        }
    };
    if let Some(refresh_token) = apple_refresh {
        let Some(provider) = s.apple_provider.as_ref() else {
            warn!("Apple revocation provider unavailable during account deletion");
            return deletion_delete_response(operation);
        };
        if let Err(error) = provider.revoke_refresh_token(&refresh_token).await {
            warn!(error = %error, "Apple credential revocation failed");
            return deletion_delete_response(operation);
        }
        if let Err(error) = s.control.mark_apple_credential_revoked(&user_id).await {
            warn!(error = %error, "Apple credential revocation state failed to persist");
            return deletion_delete_response(operation);
        }
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
            match reconcile_pending_account_deletions(&state.control, &state.store).await {
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

        let summary = reconcile_pending_account_deletions(&restarted_control, &restarted_store)
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

        let summary = reconcile_pending_account_deletions(&restarted_control, &restarted_store)
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

        let summary = reconcile_pending_account_deletions(&restarted_control, &restarted_store)
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
