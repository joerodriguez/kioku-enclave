//! Device-to-enclave sync and account endpoints. All routes are auth-gated by the
//! [`super::auth::require_auth`] middleware applied in `main`.
//!
//! `POST /api/sync/batch`  — idempotent ingest (utterances joined to segments).
//! `GET  /api/sync/status` — counts + latest timestamps.
//! `GET  /api/export`      — full JSON export.
//! `DELETE /api/account`   — hard-delete content, then identity rows.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Extension, Router,
};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::ingest::{IngestRequest, ScreenshotInput, UtteranceInput};

use super::auth::AuthUser;
use super::{isotime, limits, CpState};

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route("/api/sync/batch", post(sync_batch))
        .route("/api/sync/status", get(sync_status))
        .route("/api/export", get(export))
        .route("/api/account", delete(delete_account))
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
    let req = build_ingest(&user_id, &batch);

    let ingest_resp = match crate::ingest::ingest_batch(&s.store, &req).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "enclave ingest failed");
            return err503();
        }
    };

    // 5. If watermarks are provided, upsert them and save the DB
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
        }
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
    match s.control.begin_user_deletion(&user_id).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "account_unavailable"})),
            )
                .into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to initialize account deletion");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "deletion_init_failed"})),
            )
                .into_response();
        }
    }

    // 2. Delete content. On failure the durable `deleting` status remains, so
    // all non-deletion access stays denied and this endpoint can safely retry.
    if let Err(e) = s.store.delete_user(&user_id).await {
        warn!(error = %e, "enclave delete failed");
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "enclave_delete_failed"})),
        )
            .into_response();
    }
    // 3. Remove identity/accounting rows and leave a stable deletion tombstone.
    match s.control.finalize_user_deletion(&user_id).await {
        Ok(deleted) => Json(json!({ "deleted": deleted })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "identity_cleanup_failed"})),
        )
            .into_response(),
    }
}

fn err503() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "enclave_unavailable", "retry_after": 30})),
    )
        .into_response()
}
