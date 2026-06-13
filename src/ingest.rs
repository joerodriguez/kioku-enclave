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
//! When an utterance carries `embedding_b64` (base64 of 384 × f32 LE, produced
//! by all-MiniLM-L6-v2 on the Mac), the handler decodes it and inserts the raw
//! bytes into the `vec_utterances` vec0 virtual table keyed by the utterance's
//! rowid.  Rows without an embedding are silently skipped — they are still found
//! by FTS but not by vector KNN.
//!
//! Screenshots do not currently carry embeddings (the Mac does not send them),
//! so there is no `vec_screenshots` table.  Add one here when the Mac client
//! starts sending screenshot embeddings.
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
    /// Optional 384-dim all-MiniLM-L6-v2 embedding, base64-encoded float32 LE.
    /// Computed on the Mac; the enclave stores it but never computes embeddings
    /// itself — query embeddings arrive from the control plane.
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
    pub url: Option<String>,
    pub image_hash: Option<String>,
    /// Idempotency key: `device_id:screenshot_local_id`.
    /// When present, `INSERT OR IGNORE` is used so re-sent batches are no-ops.
    pub source_key: Option<String>,
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
    let (utterances_inserted, screenshots_inserted) = store
        .with_user(&req.user_id, |conn| {
            let u = ingest_utterances(conn, &req.utterances)?;
            let s = ingest_screenshots(conn, &req.screenshots)?;
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
pub(crate) fn ingest_utterances(
    conn: &rusqlite::Connection,
    items: &[UtteranceInput],
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

        // When this utterance was actually inserted (not a dedup ignore) and
        // carries an embedding, store it in the vec0 table.
        // We only do this when changes() == 1 — if the row was already there
        // (INSERT OR IGNORE no-op), skip to avoid a rowid lookup race.
        if row_inserted > 0 {
            if let Some(ref emb_b64) = u.embedding_b64 {
                let utterance_id: i64 = conn.last_insert_rowid();
                insert_embedding(conn, utterance_id, emb_b64);
            }
        }
    }
    Ok(inserted)
}

/// Decode an all-MiniLM-L6-v2 embedding (base64 of 384 × f32 LE) and insert
/// it into vec_utterances.  Errors here are non-fatal — a bad or truncated
/// embedding silently falls back to FTS-only for this utterance; we log a
/// warning rather than aborting the whole batch.
///
/// sqlite-vec gotcha: the vec0 rowid MUST be bound as an INTEGER (i64) and
/// the embedding as a blob (&[u8] of the raw float32 bytes).  Passing the
/// rowid as TEXT or the vector as a JSON array will fail or silently corrupt
/// the index.
fn insert_embedding(conn: &rusqlite::Connection, utterance_id: i64, emb_b64: &str) {
    const EXPECTED_BYTES: usize = 384 * 4; // 384 f32 × 4 bytes each

    let bytes = match B64.decode(emb_b64) {
        Ok(b) => b,
        Err(e) => {
            warn!(utterance_id, "embedding_b64 decode failed: {e}");
            return;
        }
    };

    if bytes.len() != EXPECTED_BYTES {
        warn!(
            utterance_id,
            "embedding has {} bytes, expected {EXPECTED_BYTES} — skipping",
            bytes.len()
        );
        return;
    }

    // Insert into vec0.  utterance_id bound as INTEGER; embedding as BLOB.
    // INSERT OR IGNORE: idempotent — if a retry already stored this embedding
    // (unlikely because row_inserted guard above), we silently skip.
    if let Err(e) = conn.execute(
        "INSERT OR IGNORE INTO vec_utterances (utterance_id, embedding) VALUES (?1, ?2)",
        rusqlite::params![utterance_id, bytes.as_slice()],
    ) {
        warn!(utterance_id, "vec_utterances insert failed: {e}");
    }
}

/// Insert screenshots and return the count of rows actually written.
pub(crate) fn ingest_screenshots(
    conn: &rusqlite::Connection,
    items: &[ScreenshotInput],
) -> Result<usize> {
    let mut inserted = 0usize;
    for s in items {
        if let Some(ref sk) = s.source_key {
            conn.execute(
                r#"INSERT OR IGNORE INTO screenshots
                   (captured_at, active_app, window_title, ocr_text, url, image_hash, source_key)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                rusqlite::params![
                    s.captured_at,
                    s.active_app,
                    s.window_title,
                    s.ocr_text,
                    s.url,
                    s.image_hash,
                    sk,
                ],
            )?;
        } else {
            conn.execute(
                r#"INSERT INTO screenshots
                   (captured_at, active_app, window_title, ocr_text, url, image_hash)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
                rusqlite::params![
                    s.captured_at,
                    s.active_app,
                    s.window_title,
                    s.ocr_text,
                    s.url,
                    s.image_hash,
                ],
            )?;
        }
        inserted += conn.changes() as usize;
    }
    Ok(inserted)
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
            captured_at: "2026-01-01T09:00:00Z".to_string(),
            active_app: None,
            window_title: None,
            ocr_text: Some("hello world".to_string()),
            url: None,
            image_hash: None,
            source_key: source_key.map(|s| s.to_string()),
        }
    }

    /// Inserting the same source_key twice: second call must be ignored (0 rows inserted).
    #[tokio::test]
    async fn utterance_source_key_deduplicates() {
        let store = make_store();

        let first = store
            .with_user("dedup_u", |conn| {
                ingest_utterances(conn, &[utt(Some("dev:1:1"), "first send")])
            })
            .await
            .unwrap();
        assert_eq!(first, 1, "first insert should return 1");

        let second = store
            .with_user("dedup_u", |conn| {
                ingest_utterances(conn, &[utt(Some("dev:1:1"), "second send")])
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
                ingest_screenshots(conn, &[scr(Some("dev:42"))])
            })
            .await
            .unwrap();
        assert_eq!(first, 1);

        let second = store
            .with_user("dedup_s", |conn| {
                ingest_screenshots(conn, &[scr(Some("dev:42"))])
            })
            .await
            .unwrap();
        assert_eq!(second, 0, "duplicate screenshot source_key must be ignored");
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
                ingest_utterances(conn, &[utt(None, "no key")])?;
                ingest_utterances(conn, &[utt(None, "no key")])?;
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
                ingest_utterances(conn, &[u])
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
                ingest_utterances(conn, &[utt(Some("dev:1:1"), "fts only utterance")])
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
                    ingest_utterances(conn, &[u])
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
}
