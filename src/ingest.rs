//! Ingest handler — appends utterances and screenshots into the user's SQLite index.
//!
//! # What happens here
//! The control plane sends pre-transcribed/OCR'd text batches. The enclave:
//! 1. Opens (or LRU-hits) the user's decrypted SQLite index via `Store::with_user`.
//! 2. Inserts rows into `audio_segments` + `utterances` (for transcripts) or
//!    `screenshots` (for screen captures). FTS5 triggers fire automatically.
//! 3. Saves the index back to GCS via `Store::save_user`.
//!
//! # Idempotency
//! When a `source_key` is present on an utterance or screenshot the handler uses
//! `INSERT OR IGNORE` so retried sync batches are harmless.  Rows without a
//! `source_key` (legacy senders) are inserted unconditionally.  The
//! response counts only rows that were actually written (`changes()`).
//!
//! # Embedding handling
//! When an utterance or screenshot carries `embedding_b64` (base64 of 384 ×
//! f32 LE, computed on the Mac — see `src/embedding.rs` for the pinned model),
//! the handler decodes it and writes the raw bytes into the matching vec0
//! virtual table (`vec_utterances` / `vec_screenshots`) keyed by the row's id.
//! Rows without an embedding are silently skipped — they are still found by
//! FTS but not by vector KNN.
//!
//! **Backfill path:** when a `source_key` row already exists (INSERT OR IGNORE
//! dedup) and the payload carries an embedding, the embedding is still
//! upserted against the existing rowid. This is how the Mac retrofits vectors
//! onto historical rows: it re-sends already-synced rows with embeddings
//! attached, the text dedups, the vector lands. Screenshot retries can likewise
//! fill an absent `salient_ocr_text` projection without replacing lossless OCR.
//!
//! **Model gate:** batches carry `embedding_model` naming the embedding space.
//! If it doesn't match this build's [`crate::embedding::MODEL_ID`] (or is
//! absent while embeddings are present), vectors are dropped with a warning —
//! text still ingests. Mixing embedding spaces silently corrupts KNN ranking,
//! which is strictly worse than FTS-only.
//!
//! # Not done here (TODOs for later passes)
//! - Deduplication of screenshots by image_hash.
//! - Episode boundary detection (done by the control plane scheduler; results
//!   ingested via a separate episode endpoint).

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{error::Result, AppState};

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct IngestRequest {
    pub user_id: String,
    /// Names the embedding space of every `embedding_b64` in this batch
    /// (the sender's `embedding::MODEL_ID`). Vectors are dropped unless this
    /// matches the enclave's own model id — see module docs.
    #[serde(default)]
    pub embedding_model: Option<String>,
    #[serde(default)]
    pub utterances: Vec<UtteranceInput>,
    #[serde(default)]
    pub screenshots: Vec<ScreenshotInput>,
}

#[derive(Debug, Deserialize)]
pub struct UtteranceInput {
    /// ISO-8601 start timestamp for the audio segment this utterance belongs to.
    pub segment_started_at: String,
    pub segment_ended_at: String,
    pub duration_seconds: Option<f64>,
    pub source_type: String, // "mic" | "system"
    pub start_offset_seconds: f64,
    pub end_offset_seconds: f64,
    pub text: String,
    #[serde(default = "default_speaker")]
    pub speaker_label: String,
    pub language: Option<String>,
    pub confidence: Option<f64>,
    /// Idempotency key: `device_id:segment_local_id:utterance_local_id`.
    /// When present, `INSERT OR IGNORE` is used so re-sent batches are no-ops.
    pub source_key: Option<String>,
    /// Optional 384-dim embedding (model pinned in `src/embedding.rs`),
    /// base64-encoded float32 LE. Computed on the Mac. The enclave computes
    /// only QUERY embeddings itself (in-TEE, at search time) — document
    /// vectors always arrive through sync.
    pub embedding_b64: Option<String>,
}

fn default_speaker() -> String {
    "speaker_0".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ScreenshotInput {
    pub captured_at: String,
    pub active_app: Option<String>,
    pub window_title: Option<String>,
    pub ocr_text: Option<String>,
    pub salient_ocr_text: Option<String>,
    pub url: Option<String>,
    pub image_hash: Option<String>,
    pub is_duplicate: Option<i64>,
    pub display_id: Option<i64>,
    pub capture_context_version: Option<i64>,
    pub capture_status: Option<String>,
    pub primary_bundle_id: Option<String>,
    pub primary_window_id: Option<i64>,
    pub capture_group_id: Option<String>,
    pub visible_windows: Option<serde_json::Value>,
    pub visible_windows_truncated: Option<bool>,
    pub visual_signals: Option<serde_json::Value>,
    pub semantic_context_hash: Option<String>,
    pub browser_snapshot_source_key: Option<String>,
    pub browser_snapshot: Option<BrowserSnapshotInput>,
    pub duplicate_of_source_key: Option<String>,
    pub visible_until: Option<String>,
    pub dedupe_version: Option<i64>,
    /// Idempotency key: `device_id:screenshot_local_id`.
    /// When present, `INSERT OR IGNORE` is used so re-sent batches are no-ops.
    pub source_key: Option<String>,
    /// Optional 384-dim embedding of `ocr_text` (capped at 10k chars on the
    /// Mac; chunked + mean-pooled). Same model/space rules as utterances.
    pub embedding_b64: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrowserSnapshotInput {
    pub schema_version: i64,
    pub source_key: String,
    pub captured_at: String,
    pub browser_bundle_id: String,
    pub browser_name: String,
    pub permission_status: String,
    pub active_window_index: Option<i64>,
    pub active_tab_index: Option<i64>,
    pub reported_tab_count: i64,
    pub truncated: bool,
    pub content_hash: String,
    #[serde(default)]
    pub tabs: Vec<BrowserTabInput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrowserTabInput {
    pub window_index: i64,
    pub tab_index: i64,
    pub title: Option<String>,
    pub url: Option<String>,
    pub url_scheme: Option<String>,
    pub is_active: bool,
    pub is_loading: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub utterances_inserted: usize,
    pub screenshots_inserted: usize,
}

// ── Handler ───────────────────────────────────────────────────────────────────

pub async fn handle_ingest(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IngestRequest>,
) -> Result<(StatusCode, Json<IngestResponse>)> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(
        user_id = %user_id,
        utterances = req.utterances.len(),
        screenshots = req.screenshots.len(),
        "ingest request"
    );

    let resp = ingest_batch(&state.store, &req).await?;
    Ok((StatusCode::OK, Json(resp)))
}

/// In-process ingest used by both the legacy `/v1/ingest` handler and the
/// in-enclave sync path (ADR-0001). Idempotent on `source_key`.
pub(crate) async fn ingest_batch(
    store: &crate::store::Store,
    req: &IngestRequest,
) -> Result<IngestResponse> {
    crate::store::validate_user_id(&req.user_id)?;

    // Model gate: only accept vectors from OUR embedding space. A batch with
    // embeddings but a missing/mismatched model id still ingests its text —
    // the vectors are dropped (mixing spaces corrupts KNN ranking).
    let accept_embeddings = req.embedding_model.as_deref() == Some(crate::embedding::MODEL_ID);
    if !accept_embeddings {
        let has_embeddings = req.utterances.iter().any(|u| u.embedding_b64.is_some())
            || req.screenshots.iter().any(|s| s.embedding_b64.is_some());
        if has_embeddings {
            warn!(
                batch_model = req.embedding_model.as_deref().unwrap_or("<absent>"),
                enclave_model = crate::embedding::MODEL_ID,
                "embedding model mismatch — dropping batch vectors, ingesting text only"
            );
        }
    }

    let (utterances_inserted, screenshots_inserted) = store
        .with_user(&req.user_id, |conn| {
            let transaction = conn.unchecked_transaction()?;
            let u = ingest_utterances(&transaction, &req.utterances, accept_embeddings)?;
            let s = ingest_screenshots(&transaction, &req.screenshots, accept_embeddings)?;
            transaction.commit()?;
            Ok((u, s))
        })
        .await?;
    store.save_user(&req.user_id).await?;
    Ok(IngestResponse {
        utterances_inserted,
        screenshots_inserted,
    })
}

// ── Insertion helpers ─────────────────────────────────────────────────────────

/// Insert utterances and return the count of rows actually written.
/// `accept_embeddings` is the model-gate verdict from [`ingest_batch`].
pub(crate) fn ingest_utterances(
    conn: &rusqlite::Connection,
    items: &[UtteranceInput],
    accept_embeddings: bool,
) -> Result<usize> {
    let mut inserted = 0usize;
    for u in items {
        // Upsert the audio segment (started_at is a natural dedup key).
        conn.execute(
            r#"INSERT OR IGNORE INTO audio_segments
               (started_at, ended_at, duration_seconds, source_type, transcription_status)
               VALUES (?1, ?2, ?3, ?4, 'done')"#,
            rusqlite::params![
                u.segment_started_at,
                u.segment_ended_at,
                u.duration_seconds,
                u.source_type
            ],
        )?;

        let seg_id: i64 = conn.query_row(
            "SELECT id FROM audio_segments WHERE started_at = ?1",
            [&u.segment_started_at],
            |r| r.get(0),
        )?;

        // Use INSERT OR IGNORE when a source_key is provided so retried batches
        // don't produce duplicate rows.  Plain INSERT otherwise (rows from
        // senders that predate source_key).
        if let Some(ref sk) = u.source_key {
            conn.execute(
                r#"INSERT OR IGNORE INTO utterances
                   (audio_segment_id, start_offset_seconds, end_offset_seconds,
                    text, language, confidence, speaker_label, source_key)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
                rusqlite::params![
                    seg_id,
                    u.start_offset_seconds,
                    u.end_offset_seconds,
                    u.text,
                    u.language,
                    u.confidence,
                    u.speaker_label,
                    sk,
                ],
            )?;
        } else {
            conn.execute(
                r#"INSERT INTO utterances
                   (audio_segment_id, start_offset_seconds, end_offset_seconds,
                    text, language, confidence, speaker_label)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                rusqlite::params![
                    seg_id,
                    u.start_offset_seconds,
                    u.end_offset_seconds,
                    u.text,
                    u.language,
                    u.confidence,
                    u.speaker_label,
                ],
            )?;
        }

        let row_inserted = conn.changes() as usize;
        inserted += row_inserted;

        // Relabel path (ADR-0006 §C.4): a re-sent row whose source_key already
        // exists may carry a NEW speaker_label (voice-memory naming on the Mac
        // renames "S7" → "Lynn" and re-queues the rows). Update the label in
        // place — utterances_fts doesn't index it and the update trigger is
        // scoped to `text` (§F.7), so this is churn-free — and patch the
        // containing episodes' participants arrays (exact-element match only;
        // prose is deliberately untouched, §E.3).
        if row_inserted == 0 {
            if let Some(ref sk) = u.source_key {
                let existing: Option<(i64, String)> = conn
                    .query_row(
                        "SELECT id, speaker_label FROM utterances WHERE source_key = ?1",
                        [sk],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .ok();
                if let Some((utt_id, old_label)) = existing {
                    if old_label != u.speaker_label && !u.speaker_label.is_empty() {
                        conn.execute(
                            "UPDATE utterances SET speaker_label = ?1 WHERE id = ?2",
                            rusqlite::params![u.speaker_label, utt_id],
                        )?;
                        patch_episode_participants(conn, utt_id, &old_label, &u.speaker_label)?;
                    }
                }
            }
        }

        if !accept_embeddings {
            continue;
        }
        if let Some(ref emb_b64) = u.embedding_b64 {
            if row_inserted > 0 {
                // Fresh row: last_insert_rowid is trustworthy.
                let utterance_id = conn.last_insert_rowid();
                write_embedding(conn, VecTable::Utterances, utterance_id, emb_b64, false);
            } else if let Some(ref sk) = u.source_key {
                // Backfill: the text row already exists (dedup no-op) but the
                // sender attached a vector — look the row up by source_key and
                // upsert. This is how historical rows gain embeddings.
                match conn.query_row(
                    "SELECT id FROM utterances WHERE source_key = ?1",
                    [sk],
                    |r| r.get::<_, i64>(0),
                ) {
                    Ok(utterance_id) => {
                        write_embedding(conn, VecTable::Utterances, utterance_id, emb_b64, true)
                    }
                    Err(e) => warn!("utterance backfill rowid lookup failed: {e}"),
                }
            }
        }
    }
    Ok(inserted)
}

/// Patch the `participants` JSON arrays of episodes containing a relabeled
/// utterance: replace array ELEMENTS exactly equal to the old label with the
/// new one (ADR-0006 §E.2). Free-text summaries and minute gists are NOT
/// rewritten (§E.3 — substring replacement in prose risks corrupting content).
/// The episodes FTS update trigger is scoped to title/summary/minutes_text
/// (§F.7), so a participants-only UPDATE causes no index churn.
fn patch_episode_participants(
    conn: &rusqlite::Connection,
    utterance_id: i64,
    old_label: &str,
    new_label: &str,
) -> Result<()> {
    let mut stmt = conn.prepare_cached(
        "SELECT e.id, e.participants FROM episodes e \
         JOIN episode_members m ON m.episode_id = e.id \
         WHERE m.record_type = 'utterance' AND m.record_id = ?1 \
           AND e.participants IS NOT NULL",
    )?;
    let episodes: Vec<(i64, String)> = stmt
        .query_map([utterance_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(|x| x.ok())
        .collect();

    for (episode_id, participants_json) in episodes {
        let Ok(serde_json::Value::Array(mut arr)) =
            serde_json::from_str::<serde_json::Value>(&participants_json)
        else {
            continue;
        };
        let mut changed = false;
        for v in arr.iter_mut() {
            if v.as_str() == Some(old_label) {
                *v = serde_json::Value::String(new_label.to_string());
                changed = true;
            }
        }
        if changed {
            let updated = serde_json::to_string(&arr).unwrap_or_else(|_| participants_json.clone());
            conn.execute(
                "UPDATE episodes SET participants = ?1 WHERE id = ?2",
                rusqlite::params![updated, episode_id],
            )?;
        }
    }
    Ok(())
}

/// Which vec0 table an embedding targets.
#[derive(Clone, Copy)]
enum VecTable {
    Utterances,
    Screenshots,
}

impl VecTable {
    fn table(self) -> &'static str {
        match self {
            VecTable::Utterances => "vec_utterances",
            VecTable::Screenshots => "vec_screenshots",
        }
    }
    fn key_col(self) -> &'static str {
        match self {
            VecTable::Utterances => "utterance_id",
            VecTable::Screenshots => "screenshot_id",
        }
    }
}

/// Decode a 384-dim embedding (base64 of f32 LE) and write it into the given
/// vec0 table.  Errors here are non-fatal — a bad or truncated embedding
/// silently falls back to FTS-only for this row; we log a warning rather than
/// aborting the whole batch.
///
/// `replace` distinguishes the two call sites: fresh inserts use
/// INSERT OR IGNORE (retry-idempotent); the backfill path DELETEs first so a
/// re-sent vector overwrites (vec0 does not honour ON CONFLICT clauses, so
/// upsert must be spelled DELETE + INSERT).
///
/// sqlite-vec gotcha: the vec0 rowid MUST be bound as an INTEGER (i64) and
/// the embedding as a blob (&[u8] of the raw float32 bytes).  Passing the
/// rowid as TEXT or the vector as a JSON array will fail or silently corrupt
/// the index.
fn write_embedding(
    conn: &rusqlite::Connection,
    target: VecTable,
    row_id: i64,
    emb_b64: &str,
    replace: bool,
) {
    const EXPECTED_BYTES: usize = 384 * 4; // 384 f32 × 4 bytes each

    let bytes = match B64.decode(emb_b64) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                row_id,
                table = target.table(),
                "embedding_b64 decode failed: {e}"
            );
            return;
        }
    };

    if bytes.len() != EXPECTED_BYTES {
        warn!(
            row_id,
            table = target.table(),
            "embedding has {} bytes, expected {EXPECTED_BYTES} — skipping",
            bytes.len()
        );
        return;
    }

    let (table, key) = (target.table(), target.key_col());
    if replace {
        if let Err(e) = conn.execute(
            &format!("DELETE FROM {table} WHERE {key} = ?1"),
            rusqlite::params![row_id],
        ) {
            warn!(row_id, table, "vec delete-before-upsert failed: {e}");
            return;
        }
    }
    let sql = if replace {
        format!("INSERT INTO {table} ({key}, embedding) VALUES (?1, ?2)")
    } else {
        format!("INSERT OR IGNORE INTO {table} ({key}, embedding) VALUES (?1, ?2)")
    };
    if let Err(e) = conn.execute(&sql, rusqlite::params![row_id, bytes.as_slice()]) {
        warn!(row_id, table, "vec insert failed: {e}");
    }
}

/// Insert screenshots and return the count of rows actually written.
/// `accept_embeddings` is the model-gate verdict from [`ingest_batch`].
pub(crate) fn ingest_screenshots(
    conn: &rusqlite::Connection,
    items: &[ScreenshotInput],
    accept_embeddings: bool,
) -> Result<usize> {
    let mut inserted = 0usize;
    for s in items {
        if let Some(snapshot) = s.browser_snapshot.as_ref() {
            ingest_browser_snapshot(conn, snapshot, s.browser_snapshot_source_key.as_deref())?;
        } else if s.browser_snapshot_source_key.is_some() {
            return Err(crate::error::EnclaveError::InvalidRequest(
                "browser snapshot reference missing payload".into(),
            ));
        }
        let duplicate_of_id = match s.duplicate_of_source_key.as_deref() {
            Some(source_key) => Some(conn.query_row(
                "SELECT id FROM screenshots WHERE source_key = ?1",
                [source_key],
                |row| row.get::<_, i64>(0),
            )?),
            None => None,
        };
        let salient_ocr_text =
            crate::ocr::select_salient_ocr(s.ocr_text.as_deref(), s.salient_ocr_text.as_deref());
        let visible_windows_json = s
            .visible_windows
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let visual_signals_json = s
            .visual_signals
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        if let Some(ref sk) = s.source_key {
            conn.execute(
                r#"INSERT OR IGNORE INTO screenshots
                   (captured_at, active_app, window_title, ocr_text, salient_ocr_text, url, image_hash, is_duplicate, source_key,
                    display_id, capture_context_version, capture_status, primary_bundle_id, primary_window_id,
                    capture_group_id, visible_windows_json, visible_windows_truncated, visual_signals_json,
                    semantic_context_hash, browser_snapshot_source_key, duplicate_of_id, visible_until, dedupe_version)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)"#,
                rusqlite::params![
                    s.captured_at,
                    s.active_app,
                    s.window_title,
                    s.ocr_text,
                    salient_ocr_text,
                    s.url,
                    s.image_hash,
                    s.is_duplicate.unwrap_or(0),
                    sk,
                    s.display_id,
                    s.capture_context_version,
                    s.capture_status,
                    s.primary_bundle_id,
                    s.primary_window_id,
                    s.capture_group_id,
                    visible_windows_json,
                    s.visible_windows_truncated.unwrap_or(false) as i64,
                    visual_signals_json,
                    s.semantic_context_hash,
                    s.browser_snapshot_source_key,
                    duplicate_of_id,
                    s.visible_until,
                    s.dedupe_version.unwrap_or(1),
                ],
            )?;
        } else {
            conn.execute(
                r#"INSERT INTO screenshots
                   (captured_at, active_app, window_title, ocr_text, salient_ocr_text, url, image_hash, is_duplicate,
                    display_id, capture_context_version, capture_status, primary_bundle_id, primary_window_id,
                    capture_group_id, visible_windows_json, visible_windows_truncated, visual_signals_json,
                    semantic_context_hash, browser_snapshot_source_key, duplicate_of_id, visible_until, dedupe_version)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)"#,
                rusqlite::params![
                    s.captured_at,
                    s.active_app,
                    s.window_title,
                    s.ocr_text,
                    salient_ocr_text,
                    s.url,
                    s.image_hash,
                    s.is_duplicate.unwrap_or(0),
                    s.display_id,
                    s.capture_context_version,
                    s.capture_status,
                    s.primary_bundle_id,
                    s.primary_window_id,
                    s.capture_group_id,
                    visible_windows_json,
                    s.visible_windows_truncated.unwrap_or(false) as i64,
                    visual_signals_json,
                    s.semantic_context_hash,
                    s.browser_snapshot_source_key,
                    duplicate_of_id,
                    s.visible_until,
                    s.dedupe_version.unwrap_or(1),
                ],
            )?;
        }
        let row_inserted = conn.changes() as usize;
        inserted += row_inserted;

        let screenshot_id = if row_inserted > 0 {
            conn.last_insert_rowid()
        } else if let Some(source_key) = s.source_key.as_deref() {
            conn.query_row(
                "SELECT id FROM screenshots WHERE source_key = ?1",
                [source_key],
                |row| row.get::<_, i64>(0),
            )?
        } else {
            conn.last_insert_rowid()
        };
        if s.is_duplicate.unwrap_or(0) == 0 {
            ensure_fallback_observation(conn, screenshot_id, s, salient_ocr_text.as_deref())?;
        }

        // Re-sent source-key rows may backfill the projection independently of
        // embeddings. This updates only the non-indexed additive column.
        if row_inserted == 0 {
            if let (Some(sk), Some(salient)) =
                (s.source_key.as_deref(), salient_ocr_text.as_deref())
            {
                if !salient.trim().is_empty() {
                    conn.execute(
                        "UPDATE screenshots SET salient_ocr_text = ?1
                         WHERE source_key = ?2
                           AND COALESCE(TRIM(salient_ocr_text), '') = ''",
                        rusqlite::params![salient, sk],
                    )?;
                }
            }
        }

        if !accept_embeddings {
            continue;
        }
        if let Some(ref emb_b64) = s.embedding_b64 {
            if row_inserted > 0 {
                let screenshot_id = conn.last_insert_rowid();
                write_embedding(conn, VecTable::Screenshots, screenshot_id, emb_b64, false);
            } else if let Some(ref sk) = s.source_key {
                // Backfill for existing screenshot rows — same pattern as
                // utterances above.
                match conn.query_row(
                    "SELECT id FROM screenshots WHERE source_key = ?1",
                    [sk],
                    |r| r.get::<_, i64>(0),
                ) {
                    Ok(screenshot_id) => {
                        write_embedding(conn, VecTable::Screenshots, screenshot_id, emb_b64, true)
                    }
                    Err(e) => warn!("screenshot backfill lookup failed: {e}"),
                }
            }
        }
    }
    Ok(inserted)
}

fn ingest_browser_snapshot(
    conn: &rusqlite::Connection,
    snapshot: &BrowserSnapshotInput,
    expected_source_key: Option<&str>,
) -> Result<()> {
    if snapshot.schema_version != 1
        || expected_source_key != Some(snapshot.source_key.as_str())
        || !snapshot.source_key.contains(":browser-v1:")
        || snapshot.tabs.len() > 500
        || snapshot.reported_tab_count < snapshot.tabs.len() as i64
        || snapshot.reported_tab_count > 100_000
        || (!snapshot.truncated && snapshot.reported_tab_count != snapshot.tabs.len() as i64)
        || snapshot.content_hash.len() != 64
        || !snapshot
            .content_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !snapshot.source_key.ends_with(&snapshot.content_hash)
        || snapshot.captured_at.len() > 40
        || !snapshot.captured_at.contains('T')
        || snapshot.browser_bundle_id.is_empty()
        || snapshot.browser_bundle_id.len() > 256
        || snapshot.browser_name.is_empty()
        || snapshot.browser_name.chars().count() > 256
        || !matches!(
            snapshot.permission_status.as_str(),
            "granted"
                | "not_determined"
                | "denied"
                | "unsupported"
                | "browser_not_running"
                | "timed_out"
                | "script_error"
        )
    {
        return Err(crate::error::EnclaveError::InvalidRequest(
            "invalid browser snapshot".into(),
        ));
    }
    let active_count = snapshot.tabs.iter().filter(|tab| tab.is_active).count();
    let active_tab = snapshot.tabs.iter().find(|tab| tab.is_active);
    if (snapshot.permission_status == "granted"
        && (active_count != 1
            || active_tab.is_none()
            || active_tab.is_some_and(|tab| {
                snapshot.active_window_index != Some(tab.window_index)
                    || snapshot.active_tab_index != Some(tab.tab_index)
            })))
        || (snapshot.permission_status != "granted"
            && (!snapshot.tabs.is_empty()
                || active_count != 0
                || snapshot.active_window_index.is_some()
                || snapshot.active_tab_index.is_some()))
    {
        return Err(crate::error::EnclaveError::InvalidRequest(
            "invalid browser active tab".into(),
        ));
    }
    conn.execute(
        "INSERT INTO browser_snapshots
         (source_key, captured_at, browser_bundle_id, browser_name, permission_status,
          active_window_index, active_tab_index, reported_tab_count, truncated, content_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(source_key) DO NOTHING",
        rusqlite::params![
            snapshot.source_key,
            snapshot.captured_at,
            snapshot.browser_bundle_id,
            snapshot.browser_name,
            snapshot.permission_status,
            snapshot.active_window_index,
            snapshot.active_tab_index,
            snapshot.reported_tab_count,
            snapshot.truncated as i64,
            snapshot.content_hash
        ],
    )?;
    let (snapshot_id, stored_hash): (i64, String) = conn.query_row(
        "SELECT id, content_hash FROM browser_snapshots WHERE source_key = ?1",
        [&snapshot.source_key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if stored_hash != snapshot.content_hash {
        return Err(crate::error::EnclaveError::InvalidRequest(
            "browser snapshot source collision".into(),
        ));
    }
    for tab in &snapshot.tabs {
        if tab.window_index <= 0
            || tab.tab_index <= 0
            || tab
                .title
                .as_ref()
                .is_some_and(|value| value.chars().count() > 1_000)
            || tab
                .url
                .as_ref()
                .is_some_and(|value| value.chars().count() > 4_096)
            || tab
                .url_scheme
                .as_ref()
                .is_some_and(|value| value.len() > 64)
        {
            return Err(crate::error::EnclaveError::InvalidRequest(
                "invalid browser tab".into(),
            ));
        }
        if let Some(url) = tab.url.as_deref() {
            let parsed = reqwest::Url::parse(url).map_err(|_| {
                crate::error::EnclaveError::InvalidRequest("invalid browser tab URL".into())
            })?;
            if tab.url_scheme.as_deref() != Some(parsed.scheme()) {
                return Err(crate::error::EnclaveError::InvalidRequest(
                    "browser tab URL scheme mismatch".into(),
                ));
            }
        } else if tab.url_scheme.is_some() {
            return Err(crate::error::EnclaveError::InvalidRequest(
                "browser tab URL scheme without URL".into(),
            ));
        }
        conn.execute(
            "INSERT OR IGNORE INTO browser_tabs
             (browser_snapshot_id, window_index, tab_index, title, url, url_scheme, is_active, is_loading)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![snapshot_id, tab.window_index, tab.tab_index, tab.title, tab.url,
                tab.url_scheme, tab.is_active as i64, tab.is_loading.map(i64::from)],
        )?;
    }
    Ok(())
}

fn ensure_fallback_observation(
    conn: &rusqlite::Connection,
    screenshot_id: i64,
    screenshot: &ScreenshotInput,
    salient_ocr_text: Option<&str>,
) -> Result<()> {
    let input = crate::cp::screen_understanding::ScreenObservationInput {
        screenshot_id,
        source_key: screenshot
            .source_key
            .clone()
            .unwrap_or_else(|| screenshot_id.to_string()),
        captured_at: screenshot.captured_at.clone(),
        capture_status: screenshot
            .capture_status
            .clone()
            .unwrap_or_else(|| "legacy".into()),
        primary_app: screenshot.active_app.clone(),
        window_title: screenshot.window_title.clone(),
        salient_ocr_text: salient_ocr_text.map(str::to_string),
        ocr_text: screenshot.ocr_text.clone(),
        active_url: screenshot.url.clone(),
        visual_signals_json: screenshot
            .visual_signals
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
    };
    let revision = crate::cp::screen_understanding::compute_observation_input_revision(&input);
    let fallback = crate::cp::screen_understanding::build_deterministic_fallback(&input, &revision);
    conn.execute(
        "INSERT INTO screen_observations
         (screenshot_id, input_revision, observation_version, status, generation_method,
          literal_description, screen_state, content_type, visible_text_summary,
          notable_items_json, model_name, prompt_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(screenshot_id) DO UPDATE SET
           input_revision=excluded.input_revision, status=excluded.status,
           generation_method=excluded.generation_method,
           literal_description=excluded.literal_description, screen_state=excluded.screen_state,
           content_type=excluded.content_type, visible_text_summary=excluded.visible_text_summary,
           notable_items_json=excluded.notable_items_json
         WHERE screen_observations.input_revision != excluded.input_revision",
        rusqlite::params![
            fallback.screenshot_id,
            fallback.input_revision,
            fallback.observation_version,
            fallback.status,
            fallback.generation_method,
            fallback.literal_description,
            fallback.screen_state,
            fallback.content_type,
            fallback.visible_text_summary,
            fallback.notable_items_json,
            fallback.model_name,
            fallback.prompt_version
        ],
    )?;
    conn.execute(
        "INSERT INTO screen_observation_jobs
         (screenshot_id, input_revision, observation_version, state)
         VALUES (?1, ?2, 1, 'fallback')
         ON CONFLICT(screenshot_id) DO UPDATE SET input_revision=excluded.input_revision,
           state='fallback', attempt_count=0, error_code=NULL
         WHERE screen_observation_jobs.input_revision != excluded.input_revision",
        rusqlite::params![screenshot_id, revision],
    )?;
    Ok(())
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{FakeGcs, FakeKms};
    use crate::store::Store;
    use std::sync::Arc;

    fn make_store() -> Store {
        Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()))
    }

    fn utt(source_key: Option<&str>, text: &str) -> UtteranceInput {
        UtteranceInput {
            segment_started_at: "2026-01-01T09:00:00Z".to_string(),
            segment_ended_at: "2026-01-01T09:01:00Z".to_string(),
            duration_seconds: Some(60.0),
            source_type: "mic".to_string(),
            start_offset_seconds: 0.0,
            end_offset_seconds: 5.0,
            text: text.to_string(),
            speaker_label: "speaker_0".to_string(),
            language: None,
            confidence: None,
            source_key: source_key.map(|s| s.to_string()),
            embedding_b64: None,
        }
    }

    /// Build a valid 384-dim all-MiniLM-L6-v2-shaped embedding (all same value,
    /// L2-normalized so unit-length cosine works).  Good enough for KNN tests.
    fn make_embedding_b64(val: f32) -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let n = 384_usize;
        // Build a unit-length vector by dividing val by sqrt(n * val²) = val * sqrt(n)
        let unit = if val == 0.0 {
            0.0
        } else {
            1.0 / (n as f32).sqrt()
        };
        let mut bytes = Vec::with_capacity(n * 4);
        for _ in 0..n {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        B64.encode(&bytes)
    }

    fn scr(source_key: Option<&str>) -> ScreenshotInput {
        ScreenshotInput {
            captured_at: "2026-06-01T14:00:00Z".to_string(),
            active_app: Some("Finder".to_string()),
            window_title: Some("Desktop".to_string()),
            ocr_text: Some("hello".to_string()),
            salient_ocr_text: None,
            url: None,
            image_hash: None,
            is_duplicate: None,
            display_id: None,
            capture_context_version: None,
            capture_status: None,
            primary_bundle_id: None,
            primary_window_id: None,
            capture_group_id: None,
            visible_windows: None,
            visible_windows_truncated: None,
            visual_signals: None,
            semantic_context_hash: None,
            browser_snapshot_source_key: None,
            browser_snapshot: None,
            duplicate_of_source_key: None,
            visible_until: None,
            dedupe_version: None,
            source_key: source_key.map(String::from),
            embedding_b64: None,
        }
    }

    fn browser_snapshot() -> BrowserSnapshotInput {
        let content_hash = "a".repeat(64);
        BrowserSnapshotInput {
            schema_version: 1,
            source_key: format!("device-1:browser-v1:{content_hash}"),
            captured_at: "2026-07-31T12:00:00Z".into(),
            browser_bundle_id: "com.apple.Safari".into(),
            browser_name: "Safari".into(),
            permission_status: "granted".into(),
            active_window_index: Some(1),
            active_tab_index: Some(2),
            reported_tab_count: 1,
            truncated: false,
            content_hash,
            tabs: vec![BrowserTabInput {
                window_index: 1,
                tab_index: 2,
                title: Some("Kioku".into()),
                url: Some("https://kioku.dev/design".into()),
                url_scheme: Some("https".into()),
                is_active: true,
                is_loading: Some(false),
            }],
        }
    }

    #[tokio::test]
    async fn browser_snapshot_validates_and_persists_active_tab() {
        let store = make_store();
        let snapshot = browser_snapshot();
        let source_key = snapshot.source_key.clone();
        store
            .with_user("browser_snapshot", |conn| {
                ingest_browser_snapshot(conn, &snapshot, Some(&source_key))
            })
            .await
            .unwrap();

        let stored: (String, String, i64) = store
            .with_user("browser_snapshot", |conn| {
                Ok(conn.query_row(
                    "SELECT bs.permission_status, bt.url, bt.is_active
                     FROM browser_snapshots bs
                     JOIN browser_tabs bt ON bt.browser_snapshot_id=bs.id",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(
            stored,
            ("granted".into(), "https://kioku.dev/design".into(), 1)
        );
    }

    #[tokio::test]
    async fn browser_snapshot_rejects_claimed_scheme_mismatch() {
        let store = make_store();
        let mut snapshot = browser_snapshot();
        snapshot.tabs[0].url_scheme = Some("http".into());
        let source_key = snapshot.source_key.clone();
        let result = store
            .with_user("browser_snapshot_bad_scheme", |conn| {
                ingest_browser_snapshot(conn, &snapshot, Some(&source_key))
            })
            .await;
        assert!(result.is_err());
    }

    /// Inserting the same source_key twice: second call must be ignored (0 rows inserted).
    #[tokio::test]
    async fn utterance_source_key_deduplicates() {
        let store = make_store();

        let first = store
            .with_user("dedup_u", |conn| {
                ingest_utterances(conn, &[utt(Some("dev:1:1"), "first send")], true)
            })
            .await
            .unwrap();
        assert_eq!(first, 1, "first insert should return 1");

        let second = store
            .with_user("dedup_u", |conn| {
                ingest_utterances(conn, &[utt(Some("dev:1:1"), "second send")], true)
            })
            .await
            .unwrap();
        assert_eq!(
            second, 0,
            "duplicate source_key must be ignored (0 inserted)"
        );

        let count: i64 = store
            .with_user("dedup_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(count, 1, "only one row should exist");
    }

    /// Inserting the same screenshot source_key twice: second call must be ignored.
    #[tokio::test]
    async fn screenshot_source_key_deduplicates() {
        let store = make_store();

        let first = store
            .with_user("dedup_s", |conn| {
                ingest_screenshots(conn, &[scr(Some("dev:42"))], true)
            })
            .await
            .unwrap();
        assert_eq!(first, 1);

        let second = store
            .with_user("dedup_s", |conn| {
                ingest_screenshots(conn, &[scr(Some("dev:42"))], true)
            })
            .await
            .unwrap();
        assert_eq!(second, 0, "duplicate screenshot source_key must be ignored");

        let observation: (i64, String, String) = store
            .with_user("dedup_s", |conn| {
                Ok(conn.query_row(
                    "SELECT count(*), status, screen_state FROM screen_observations",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(observation, (1, "fallback".into(), "content".into()));
    }

    #[tokio::test]
    async fn duplicate_screen_has_no_independent_observation() {
        let store = make_store();
        let mut duplicate = scr(Some("dev:duplicate"));
        duplicate.is_duplicate = Some(1);
        store
            .with_user("duplicate_screen", |conn| {
                ingest_screenshots(conn, &[duplicate], true)
            })
            .await
            .unwrap();
        let count = store
            .with_user("duplicate_screen", |conn| {
                Ok(
                    conn.query_row("SELECT count(*) FROM screen_observations", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                )
            })
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    /// Schema upgrade path: opening a fresh store twice must not error even
    /// though the ALTER TABLE … ADD COLUMN migration runs on every open.
    #[tokio::test]
    async fn schema_upgrade_is_idempotent() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let store = Store::new(kms.clone(), gcs.clone());

        // First open — creates schema + runs migrations
        store
            .with_user("upgrade_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM utterances", [], |_| Ok(0_i64))?)
            })
            .await
            .expect("first open failed");

        store.save_user("upgrade_u").await.expect("save failed");

        // Reload on a fresh store — simulates process restart, must run migrations again
        let store2 = Store::new(kms, gcs);
        store2
            .with_user("upgrade_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM utterances", [], |_| Ok(0_i64))?)
            })
            .await
            .expect("reload after schema upgrade failed");
    }

    /// Without a source_key, plain INSERT is used — same text inserted twice
    /// produces two rows (legacy-sender behaviour).
    #[tokio::test]
    async fn utterance_no_source_key_allows_duplicates() {
        let store = make_store();
        store
            .with_user("nokey_u", |conn| {
                ingest_utterances(conn, &[utt(None, "no key")], true)?;
                ingest_utterances(conn, &[utt(None, "no key")], true)?;
                Ok(())
            })
            .await
            .unwrap();

        let count: i64 = store
            .with_user("nokey_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(count, 2, "no source_key → both inserts should persist");
    }

    /// Ingest an utterance with a known embedding → vec_utterances gets a row.
    #[tokio::test]
    async fn utterance_with_embedding_inserts_vec_row() {
        let store = make_store();
        let emb = make_embedding_b64(1.0);

        store
            .with_user("vec_insert_u", |conn| {
                let mut u = utt(Some("dev:1:1"), "vector test utterance");
                u.embedding_b64 = Some(emb.clone());
                ingest_utterances(conn, &[u], true)
            })
            .await
            .expect("ingest");

        let vec_count: i64 = store
            .with_user("vec_insert_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM vec_utterances", [], |r| r.get(0))?)
            })
            .await
            .expect("count vec_utterances");

        assert_eq!(vec_count, 1, "embedding should be stored in vec_utterances");
    }

    /// Ingest an utterance WITHOUT an embedding → vec_utterances stays empty,
    /// FTS still works (graceful degradation).
    #[tokio::test]
    async fn utterance_without_embedding_skips_vec_row() {
        let store = make_store();

        store
            .with_user("no_vec_u", |conn| {
                ingest_utterances(conn, &[utt(Some("dev:1:1"), "fts only utterance")], true)
            })
            .await
            .expect("ingest");

        let vec_count: i64 = store
            .with_user("no_vec_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM vec_utterances", [], |r| r.get(0))?)
            })
            .await
            .expect("count vec_utterances");

        assert_eq!(
            vec_count, 0,
            "no embedding → vec_utterances should be empty"
        );
    }

    /// Dedup: retrying a source_key with embedding must not insert a second vec row.
    #[tokio::test]
    async fn embedding_dedup_with_source_key() {
        let store = make_store();
        let emb = make_embedding_b64(0.5);

        for _ in 0..2 {
            store
                .with_user("vec_dedup_u", |conn| {
                    let mut u = utt(Some("dev:1:1"), "dedup embedding test");
                    u.embedding_b64 = Some(emb.clone());
                    ingest_utterances(conn, &[u], true)
                })
                .await
                .expect("ingest");
        }

        let vec_count: i64 = store
            .with_user("vec_dedup_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM vec_utterances", [], |r| r.get(0))?)
            })
            .await
            .expect("count");
        assert_eq!(
            vec_count, 1,
            "duplicate source_key must not produce two vec rows"
        );
    }

    /// THE backfill scenario: a row synced long ago WITHOUT an embedding gets
    /// re-sent with one attached — the vector must land on the existing row.
    #[tokio::test]
    async fn embedding_backfill_upserts_existing_row() {
        let store = make_store();

        // Day 1: text-only sync (pre-vector client).
        store
            .with_user("backfill_u", |conn| {
                ingest_utterances(conn, &[utt(Some("dev:1:1"), "historical row")], true)
            })
            .await
            .expect("initial ingest");

        // Day 2: backfill re-sends the same source_key WITH an embedding.
        let emb = make_embedding_b64(1.0);
        let inserted = store
            .with_user("backfill_u", |conn| {
                let mut u = utt(Some("dev:1:1"), "historical row");
                u.embedding_b64 = Some(emb);
                ingest_utterances(conn, &[u], true)
            })
            .await
            .expect("backfill ingest");
        assert_eq!(inserted, 0, "text row must dedup (no new row)");

        let (rows, vecs): (i64, i64) = store
            .with_user("backfill_u", |conn| {
                let rows = conn.query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))?;
                let vecs =
                    conn.query_row("SELECT count(*) FROM vec_utterances", [], |r| r.get(0))?;
                Ok((rows, vecs))
            })
            .await
            .expect("counts");
        assert_eq!(rows, 1, "still exactly one text row");
        assert_eq!(
            vecs, 1,
            "backfill must attach the vector to the existing row"
        );
    }

    /// Screenshot embeddings: fresh insert AND backfill both land in vec_screenshots.
    #[tokio::test]
    async fn screenshot_embedding_insert_and_backfill() {
        let store = make_store();
        let emb = make_embedding_b64(1.0);

        // Fresh insert with embedding.
        store
            .with_user("scr_vec_u", |conn| {
                let mut s = scr(Some("dev:1"));
                s.embedding_b64 = Some(emb.clone());
                ingest_screenshots(conn, &[s], true)
            })
            .await
            .expect("ingest");

        // Backfill onto a pre-existing text-only screenshot.
        store
            .with_user("scr_vec_u", |conn| {
                ingest_screenshots(conn, &[scr(Some("dev:2"))], true)?;
                let mut s = scr(Some("dev:2"));
                s.embedding_b64 = Some(emb.clone());
                ingest_screenshots(conn, &[s], true)
            })
            .await
            .expect("backfill");

        let vecs: i64 = store
            .with_user("scr_vec_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM vec_screenshots", [], |r| r.get(0))?)
            })
            .await
            .expect("count");
        assert_eq!(vecs, 2, "both screenshots should have vectors");
    }

    #[tokio::test]
    async fn screenshot_salient_ocr_backfills_without_replacing_raw_ocr() {
        let store = make_store();
        store
            .with_user("scr_salient_u", |conn| {
                conn.execute(
                    "INSERT INTO screenshots
                     (captured_at, ocr_text, source_key)
                     VALUES ('2026-07-22T12:40:29Z', 'lossless raw OCR', 'dev:312')",
                    [],
                )?;
                let mut resent = scr(Some("dev:312"));
                resent.ocr_text = Some("different resent OCR".into());
                resent.salient_ocr_text = Some("MARY POPPINS".into());
                let inserted = ingest_screenshots(conn, &[resent], true)?;
                assert_eq!(inserted, 0);
                Ok(())
            })
            .await
            .expect("salient backfill");

        let (raw, salient): (String, Option<String>) = store
            .with_user("scr_salient_u", |conn| {
                Ok(conn.query_row(
                    "SELECT ocr_text, salient_ocr_text
                     FROM screenshots WHERE source_key = 'dev:312'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .await
            .expect("stored OCR");
        assert_eq!(raw, "lossless raw OCR");
        assert_eq!(salient.as_deref(), Some("MARY POPPINS"));
    }

    /// Model gate: a batch whose embedding_model doesn't match MODEL_ID keeps
    /// its text but drops its vectors; a matching batch keeps both.
    #[tokio::test]
    async fn model_gate_drops_foreign_vectors() {
        let store = make_store();
        let emb = make_embedding_b64(1.0);

        let mk_req = |model: Option<&str>, sk: &str| {
            let mut u = utt(Some(sk), "gated text");
            u.embedding_b64 = Some(emb.clone());
            IngestRequest {
                user_id: "gate_u".to_string(),
                embedding_model: model.map(String::from),
                utterances: vec![u],
                screenshots: vec![],
            }
        };

        // Foreign space → text lands, vector dropped.
        ingest_batch(&store, &mk_req(Some("some-other-model/9"), "dev:1:1"))
            .await
            .expect("foreign-model ingest");
        // Absent model id with embeddings present → also dropped.
        ingest_batch(&store, &mk_req(None, "dev:1:2"))
            .await
            .expect("absent-model ingest");
        // Matching space → vector lands.
        ingest_batch(&store, &mk_req(Some(crate::embedding::MODEL_ID), "dev:1:3"))
            .await
            .expect("matching-model ingest");

        let (rows, vecs): (i64, i64) = store
            .with_user("gate_u", |conn| {
                let rows = conn.query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))?;
                let vecs =
                    conn.query_row("SELECT count(*) FROM vec_utterances", [], |r| r.get(0))?;
                Ok((rows, vecs))
            })
            .await
            .expect("counts");
        assert_eq!(rows, 3, "all three texts ingest regardless of model gate");
        assert_eq!(vecs, 1, "only the matching-model vector survives");
    }
    /// ADR-0006 §C.4/§E.2: a re-sent utterance with the same source_key and a
    /// NEW speaker_label relabels the stored row and patches the containing
    /// episodes' participants arrays (exact element match only); FTS stays
    /// consistent and unindexed-column churn does not occur.
    #[tokio::test]
    async fn resend_with_new_label_relabels_and_patches_participants() {
        let store = make_store();

        // Ingest the original row.
        let mut original = utt(Some("dev:1:7"), "the quick brown fox");
        original.speaker_label = "S7".to_string();
        store
            .with_user("relabel_u", |conn| {
                ingest_utterances(conn, &[original], true)?;
                Ok(())
            })
            .await
            .unwrap();

        // Bind it to an episode whose participants mention S7 (and others).
        store
            .with_user("relabel_u", |conn| {
                let utt_id: i64 = conn.query_row(
                    "SELECT id FROM utterances WHERE source_key='dev:1:7'",
                    [],
                    |r| r.get(0),
                )?;
                crate::episodes::upsert_episodes(
                    conn,
                    &[crate::episodes::EpisodeInput {
                        id: None,
                        started_at: "2026-01-01T09:00:00Z".into(),
                        ended_at: "2026-01-01T09:30:00Z".into(),
                        episode_type: None,
                        title: "Chat with S7".into(),
                        summary: Some("S7 said things".into()),
                        participants: Some(vec!["Me".into(), "S7".into(), "Kate".into()]),
                        languages: None,
                        action_items: None,
                        substance: None,
                        visual_evidence: None,
                        minute_summaries: None,
                        model: None,
                        member_utterance_ids: vec![utt_id],
                        member_screenshot_ids: vec![],
                    }],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        // Re-send the same source_key with the resolved name.
        let mut renamed = utt(Some("dev:1:7"), "the quick brown fox");
        renamed.speaker_label = "Lynn".to_string();
        store
            .with_user("relabel_u", |conn| {
                let n = ingest_utterances(conn, &[renamed], true)?;
                assert_eq!(n, 0, "re-send is not a new insert");
                Ok(())
            })
            .await
            .unwrap();

        store
            .with_user("relabel_u", |conn| {
                let label: String = conn.query_row(
                    "SELECT speaker_label FROM utterances WHERE source_key='dev:1:7'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(label, "Lynn", "utterance relabeled in place");

                let participants: String =
                    conn.query_row("SELECT participants FROM episodes", [], |r| r.get(0))?;
                let arr: Vec<String> = serde_json::from_str(&participants).unwrap();
                assert_eq!(arr, vec!["Me", "Lynn", "Kate"], "exact element swapped");

                // Prose untouched (§E.3).
                let (title, summary): (String, String) =
                    conn.query_row("SELECT title, summary FROM episodes", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })?;
                assert_eq!(title, "Chat with S7");
                assert_eq!(summary, "S7 said things");

                // FTS consistent after relabel + participants patch.
                conn.execute_batch(
                    "INSERT INTO utterances_fts(utterances_fts) VALUES('integrity-check');
                     INSERT INTO episodes_fts(episodes_fts) VALUES('integrity-check');",
                )?;
                // Text unchanged and still searchable.
                let hits: i64 = conn.query_row(
                    "SELECT count(*) FROM utterances_fts WHERE utterances_fts MATCH 'fox'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(hits, 1);
                Ok(())
            })
            .await
            .unwrap();
    }
}
