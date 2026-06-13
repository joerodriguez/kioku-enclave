//! Timeline handlers — context window, raw range, and stats.
//!
//! These three endpoints feed the LLM summariser and the MCP `get_context` tool:
//!
//! - `POST /v1/context` — rows *nearest* a center timestamp (capped per kind)
//! - `POST /v1/range`   — all rows in `[from, to)`, time-ascending, with per-kind limit
//! - `POST /v1/stats`   — row counts and latest-seen timestamps (sync monitoring)

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::info;

use crate::{error::Result, AppState};

// ── Context ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ContextRequest {
    pub user_id: String,
    /// ISO-8601 center timestamp.
    pub center: String,
    /// Minutes before center to include (default 30).
    #[serde(default = "default_30")]
    pub before_minutes: u32,
    /// Minutes after center to include (default 30).
    #[serde(default = "default_30")]
    pub after_minutes: u32,
    /// Max utterances to return (closest to center, default 200).
    #[serde(default = "default_max_utterances")]
    pub max_utterances: usize,
    /// Max screenshots to return (closest to center, default 100).
    #[serde(default = "default_max_screenshots")]
    pub max_screenshots: usize,
}

fn default_30() -> u32 {
    30
}
fn default_max_utterances() -> usize {
    200
}
fn default_max_screenshots() -> usize {
    100
}

pub async fn handle_context(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContextRequest>,
) -> Result<Json<Value>> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, center = %req.center, "context request");

    let result = state
        .store
        .with_user(&user_id, |conn| fetch_context(conn, &req))
        .await?;

    Ok(Json(result))
}

pub(crate) fn fetch_context(conn: &rusqlite::Connection, req: &ContextRequest) -> Result<Value> {
    // Compute window bounds using SQLite datetime arithmetic so we don't need
    // a Rust date library.  `strftime('%Y-%m-%dT%H:%M:%fZ', ...)` produces the
    // same ISO-8601 format used throughout the codebase.
    let from: String = conn.query_row(
        "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, ?2 || ' minutes')",
        rusqlite::params![req.center, format!("-{}", req.before_minutes)],
        |r| r.get(0),
    )?;
    let to: String = conn.query_row(
        "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, ?2 || ' minutes')",
        rusqlite::params![req.center, format!("+{}", req.after_minutes)],
        |r| r.get(0),
    )?;

    // Utterances: select N closest to center, then re-sort time-ascending.
    // We rank by abs(started_at - center) using julianday arithmetic.
    let utterances = fetch_context_utterances(conn, &from, &to, &req.center, req.max_utterances)?;
    let screenshots =
        fetch_context_screenshots(conn, &from, &to, &req.center, req.max_screenshots)?;

    Ok(json!({ "utterances": utterances, "screenshots": screenshots }))
}

fn fetch_context_utterances(
    conn: &rusqlite::Connection,
    from: &str,
    to: &str,
    center: &str,
    max: usize,
) -> Result<Vec<Value>> {
    // Sub-select ordered by proximity to center, outer re-sorts ascending.
    let mut stmt = conn.prepare(
        r#"
        SELECT u.id, u.audio_segment_id, u.start_offset_seconds, u.end_offset_seconds,
               u.text, u.language, u.confidence, u.speaker_label, u.source_key, u.created_at,
               s.started_at, s.ended_at, s.duration_seconds, s.source_type
        FROM (
            SELECT u2.id
            FROM utterances u2
            JOIN audio_segments s2 ON s2.id = u2.audio_segment_id
            WHERE s2.started_at >= ?1 AND s2.started_at < ?2
            ORDER BY ABS(julianday(s2.started_at) - julianday(?3))
            LIMIT ?4
        ) AS nearest
        JOIN utterances u ON u.id = nearest.id
        JOIN audio_segments s ON s.id = u.audio_segment_id
        ORDER BY s.started_at ASC, u.start_offset_seconds ASC
    "#,
    )?;

    let rows = stmt.query_map(
        rusqlite::params![from, to, center, max as i64],
        utterance_to_json,
    )?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn fetch_context_screenshots(
    conn: &rusqlite::Connection,
    from: &str,
    to: &str,
    center: &str,
    max: usize,
) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, captured_at, active_app, window_title, ocr_text, url,
               ocr_status, image_hash, is_duplicate, source_key, created_at
        FROM (
            SELECT id
            FROM screenshots
            WHERE captured_at >= ?1 AND captured_at < ?2
            ORDER BY ABS(julianday(captured_at) - julianday(?3))
            LIMIT ?4
        ) AS nearest
        JOIN screenshots USING (id)
        ORDER BY captured_at ASC
    "#,
    )?;

    let rows = stmt.query_map(
        rusqlite::params![from, to, center, max as i64],
        screenshot_to_json,
    )?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

// ── Range ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RangeRequest {
    pub user_id: String,
    pub from: String,
    pub to: String,
    /// Which kinds to return.  Absent = both.  Values: `"utterances"`, `"screenshots"`.
    #[serde(default)]
    pub include: Vec<String>,
    /// Per-kind row limit (default 5000).
    #[serde(default = "default_range_limit")]
    pub limit: usize,
}

fn default_range_limit() -> usize {
    5000
}

pub async fn handle_range(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RangeRequest>,
) -> Result<Json<Value>> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, from = %req.from, to = %req.to, "range request");

    let result = state
        .store
        .with_user(&user_id, |conn| fetch_range(conn, &req))
        .await?;

    Ok(Json(result))
}

fn fetch_range(conn: &rusqlite::Connection, req: &RangeRequest) -> Result<Value> {
    let want_all = req.include.is_empty();
    let want_utterances = want_all || req.include.iter().any(|x| x == "utterances");
    let want_screenshots = want_all || req.include.iter().any(|x| x == "screenshots");

    let mut obj = serde_json::Map::new();

    if want_utterances {
        let mut stmt = conn.prepare(
            r#"
            SELECT u.id, u.audio_segment_id, u.start_offset_seconds, u.end_offset_seconds,
                   u.text, u.language, u.confidence, u.speaker_label, u.source_key, u.created_at,
                   s.started_at, s.ended_at, s.duration_seconds, s.source_type
            FROM utterances u
            JOIN audio_segments s ON s.id = u.audio_segment_id
            WHERE s.started_at >= ?1 AND s.started_at < ?2
            ORDER BY s.started_at ASC, u.start_offset_seconds ASC
            LIMIT ?3
        "#,
        )?;
        let rows = stmt.query_map(
            rusqlite::params![req.from, req.to, req.limit as i64],
            utterance_to_json,
        )?;
        let utts: Vec<Value> = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(crate::error::EnclaveError::from)?;
        obj.insert("utterances".into(), Value::Array(utts));
    }

    if want_screenshots {
        let mut stmt = conn.prepare(
            r#"
            SELECT id, captured_at, active_app, window_title, ocr_text, url,
                   ocr_status, image_hash, is_duplicate, source_key, created_at
            FROM screenshots
            WHERE captured_at >= ?1 AND captured_at < ?2
            ORDER BY captured_at ASC
            LIMIT ?3
        "#,
        )?;
        let rows = stmt.query_map(
            rusqlite::params![req.from, req.to, req.limit as i64],
            screenshot_to_json,
        )?;
        let scrns: Vec<Value> = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(crate::error::EnclaveError::from)?;
        obj.insert("screenshots".into(), Value::Array(scrns));
    }

    Ok(Value::Object(obj))
}

// ── Stats ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StatsRequest {
    pub user_id: String,
}

pub async fn handle_stats(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StatsRequest>,
) -> Result<Json<Value>> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, "stats request");

    let result = state.store.with_user(&user_id, fetch_stats).await?;

    Ok(Json(result))
}

fn fetch_stats(conn: &rusqlite::Connection) -> Result<Value> {
    let utterance_count: i64 =
        conn.query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))?;

    let screenshot_count: i64 =
        conn.query_row("SELECT count(*) FROM screenshots", [], |r| r.get(0))?;

    let episode_count: i64 = conn.query_row("SELECT count(*) FROM episodes", [], |r| r.get(0))?;

    // last_utterance_at: max started_at of the audio segment of any utterance
    let last_utterance_at: Option<String> = conn.query_row(
        r#"SELECT MAX(s.started_at) FROM utterances u
           JOIN audio_segments s ON s.id = u.audio_segment_id"#,
        [],
        |r| r.get(0),
    )?;

    let last_screenshot_at: Option<String> =
        conn.query_row("SELECT MAX(captured_at) FROM screenshots", [], |r| r.get(0))?;

    Ok(json!({
        "utterance_count":   utterance_count,
        "screenshot_count":  screenshot_count,
        "episode_count":     episode_count,
        "last_utterance_at": last_utterance_at,
        "last_screenshot_at": last_screenshot_at,
    }))
}

// ── Row serialisers ────────────────────────────────────────────────────────────

/// Deserialise an utterances row (14-column join with audio_segments) to JSON.
fn utterance_to_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id":                    row.get::<_, i64>(0)?,
        "audio_segment_id":      row.get::<_, i64>(1)?,
        "start_offset_seconds":  row.get::<_, f64>(2)?,
        "end_offset_seconds":    row.get::<_, f64>(3)?,
        "text":                  row.get::<_, String>(4)?,
        "language":              row.get::<_, Option<String>>(5)?,
        "confidence":            row.get::<_, Option<f64>>(6)?,
        "speaker_label":         row.get::<_, String>(7)?,
        "source_key":            row.get::<_, Option<String>>(8)?,
        "created_at":            row.get::<_, String>(9)?,
        "started_at":            row.get::<_, String>(10)?,
        "ended_at":              row.get::<_, String>(11)?,
        "duration_seconds":      row.get::<_, Option<f64>>(12)?,
        "source_type":           row.get::<_, String>(13)?,
    }))
}

/// Deserialise a screenshots row (11 columns) to JSON.
fn screenshot_to_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id":           row.get::<_, i64>(0)?,
        "captured_at":  row.get::<_, String>(1)?,
        "active_app":   row.get::<_, Option<String>>(2)?,
        "window_title": row.get::<_, Option<String>>(3)?,
        "ocr_text":     row.get::<_, Option<String>>(4)?,
        "url":          row.get::<_, Option<String>>(5)?,
        "ocr_status":   row.get::<_, String>(6)?,
        "image_hash":   row.get::<_, Option<String>>(7)?,
        "is_duplicate": row.get::<_, i64>(8)?,
        "source_key":   row.get::<_, Option<String>>(9)?,
        "created_at":   row.get::<_, String>(10)?,
    }))
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

    /// Seed an audio segment + utterance at the given timestamp.
    async fn seed_utterance(store: &Store, user: &str, started_at: &str, text: &str) {
        let started = started_at.to_string();
        let txt = text.to_string();
        store
            .with_user(user, |conn| {
                conn.execute(
                    r#"INSERT OR IGNORE INTO audio_segments
                       (started_at, ended_at, duration_seconds, source_type)
                       VALUES (?1, ?1, 60.0, 'mic')"#,
                    [&started],
                )?;
                let seg_id: i64 = conn.query_row(
                    "SELECT id FROM audio_segments WHERE started_at = ?1",
                    [&started],
                    |r| r.get(0),
                )?;
                conn.execute(
                    r#"INSERT INTO utterances
                       (audio_segment_id, start_offset_seconds, end_offset_seconds,
                        text, speaker_label)
                       VALUES (?1, 0.0, 5.0, ?2, 'speaker_0')"#,
                    rusqlite::params![seg_id, txt],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }

    async fn seed_screenshot(store: &Store, user: &str, captured_at: &str) {
        let ts = captured_at.to_string();
        store
            .with_user(user, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES (?1, 'ocr')",
                    [&ts],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }

    // ── context ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn context_returns_rows_nearest_center() {
        let store = make_store();
        // 3 utterances spread around the center
        seed_utterance(&store, "ctx_u", "2026-01-01T09:00:00Z", "early").await;
        seed_utterance(&store, "ctx_u", "2026-01-01T09:29:00Z", "close before").await;
        seed_utterance(&store, "ctx_u", "2026-01-01T09:31:00Z", "close after").await;
        seed_utterance(&store, "ctx_u", "2026-01-01T10:00:00Z", "far after").await;

        let req = ContextRequest {
            user_id: "ctx_u".to_string(),
            center: "2026-01-01T09:30:00Z".to_string(),
            before_minutes: 60,
            after_minutes: 60,
            max_utterances: 2, // only 2 closest
            max_screenshots: 100,
        };

        let result = store
            .with_user("ctx_u", |conn| fetch_context(conn, &req))
            .await
            .unwrap();

        let utts = result["utterances"].as_array().unwrap();
        assert_eq!(utts.len(), 2, "should respect max_utterances cap");
        // Must be time-ascending
        let t0 = utts[0]["started_at"].as_str().unwrap();
        let t1 = utts[1]["started_at"].as_str().unwrap();
        assert!(t0 <= t1, "results must be time-ascending");
    }

    #[tokio::test]
    async fn context_respects_window_boundaries() {
        let store = make_store();
        seed_utterance(&store, "ctx_b", "2026-01-01T08:00:00Z", "too early").await;
        seed_utterance(&store, "ctx_b", "2026-01-01T09:30:00Z", "in window").await;
        seed_utterance(&store, "ctx_b", "2026-01-01T11:00:00Z", "too late").await;

        let req = ContextRequest {
            user_id: "ctx_b".to_string(),
            center: "2026-01-01T09:30:00Z".to_string(),
            before_minutes: 30,
            after_minutes: 30,
            max_utterances: 200,
            max_screenshots: 100,
        };

        let result = store
            .with_user("ctx_b", |conn| fetch_context(conn, &req))
            .await
            .unwrap();

        let utts = result["utterances"].as_array().unwrap();
        assert_eq!(utts.len(), 1);
        assert_eq!(utts[0]["text"].as_str().unwrap(), "in window");
    }

    // ── range ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn range_half_open_interval() {
        let store = make_store();
        seed_utterance(&store, "rng_u", "2026-01-01T09:00:00Z", "at from").await;
        seed_utterance(&store, "rng_u", "2026-01-01T09:30:00Z", "inside").await;
        seed_utterance(&store, "rng_u", "2026-01-01T10:00:00Z", "at to — excluded").await;

        let req = RangeRequest {
            user_id: "rng_u".to_string(),
            from: "2026-01-01T09:00:00Z".to_string(),
            to: "2026-01-01T10:00:00Z".to_string(),
            include: vec![],
            limit: 5000,
        };

        let result = store
            .with_user("rng_u", |conn| fetch_range(conn, &req))
            .await
            .unwrap();

        let utts = result["utterances"].as_array().unwrap();
        assert_eq!(utts.len(), 2, "[from, to) should exclude 'at to'");
        // time-ascending
        assert!(utts[0]["started_at"].as_str().unwrap() <= utts[1]["started_at"].as_str().unwrap());
    }

    #[tokio::test]
    async fn range_include_filter_screenshots_only() {
        let store = make_store();
        seed_utterance(&store, "rng_f", "2026-01-01T09:00:00Z", "utt").await;
        seed_screenshot(&store, "rng_f", "2026-01-01T09:05:00Z").await;

        let req = RangeRequest {
            user_id: "rng_f".to_string(),
            from: "2026-01-01T09:00:00Z".to_string(),
            to: "2026-01-01T10:00:00Z".to_string(),
            include: vec!["screenshots".to_string()],
            limit: 5000,
        };

        let result = store
            .with_user("rng_f", |conn| fetch_range(conn, &req))
            .await
            .unwrap();

        assert!(
            result.get("utterances").is_none(),
            "utterances key should be absent when not in include"
        );
        let scrns = result["screenshots"].as_array().unwrap();
        assert_eq!(scrns.len(), 1);
    }

    // ── stats ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn stats_counts_correct() {
        let store = make_store();
        seed_utterance(&store, "stat_u", "2026-01-01T09:00:00Z", "u1").await;
        seed_utterance(&store, "stat_u", "2026-01-01T09:05:00Z", "u2").await;
        seed_screenshot(&store, "stat_u", "2026-01-01T09:10:00Z").await;

        // Insert an episode directly
        store
            .with_user("stat_u", |conn| {
                conn.execute(
                    r#"INSERT INTO episodes (started_at, ended_at, title)
                       VALUES ('2026-01-01T09:00:00Z', '2026-01-01T09:30:00Z', 'ep')"#,
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let stats = store.with_user("stat_u", fetch_stats).await.unwrap();

        assert_eq!(stats["utterance_count"], 2);
        assert_eq!(stats["screenshot_count"], 1);
        assert_eq!(stats["episode_count"], 1);
        assert_eq!(
            stats["last_utterance_at"].as_str().unwrap(),
            "2026-01-01T09:05:00Z"
        );
        assert_eq!(
            stats["last_screenshot_at"].as_str().unwrap(),
            "2026-01-01T09:10:00Z"
        );
    }

    #[tokio::test]
    async fn stats_empty_user() {
        let store = make_store();
        let stats = store.with_user("empty_stat", fetch_stats).await.unwrap();

        assert_eq!(stats["utterance_count"], 0);
        assert_eq!(stats["screenshot_count"], 0);
        assert_eq!(stats["episode_count"], 0);
        assert!(stats["last_utterance_at"].is_null());
        assert!(stats["last_screenshot_at"].is_null());
    }
}
