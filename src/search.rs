//! Search handler — FTS5 full-text search + vector KNN (hybrid) over utterances,
//! screenshots, and episodes.
//!
//! # Search modes
//!
//! **FTS-only** (default when `query_embedding` is absent): SQLite FTS5 MATCH
//! with optional time-range filters.  Scores from `fts_score()` (bm25 negated).
//!
//! **Hybrid** (when `query_embedding` is present — a 384-dim float32 array in
//! the model space pinned by `crate::embedding::MODEL_ID`, computed in-enclave
//! at query time): runs vector KNN on the `vec_utterances` / `vec_screenshots`
//! / `vec_episodes` vec0 tables, then merges FTS + vector scores per kind
//! using **Reciprocal Rank Fusion (RRF)**. Episode vectors are computed
//! in-enclave at summarizer-upsert time (ADR-0004 §G.2); episode FTS covers
//! title + summary + minute-timeline gists.
//!
//! ## Why RRF
//!
//! RRF (Cormack et al., 2009) is robust to score-scale differences between BM25
//! and cosine distance without requiring calibration or normalization constants.
//! Formula: `RRF(d) = Σ 1 / (k + rank_i(d))` where k=60 is the standard
//! constant.  A document that ranks first in both lists gets ≈ 1/61 + 1/61 =
//! 0.032; a document that appears in only one list gets at most 1/61 ≈ 0.016.
//! Results are sorted by RRF score descending.
//!
//! ## sqlite-vec KNN gotcha (project known)
//!
//! The KNN query (`embedding MATCH ? ... LIMIT k`) MUST run as its own
//! sub-query BEFORE any JOINs.  Mixing the MATCH clause with JOINs makes
//! sqlite-vec silently return wrong or empty results.  We execute the KNN
//! standalone, collect (utterance_id, distance) pairs, then join to the base
//! `utterances` table in a second query.
//!
//! # `kinds` filter
//!
//! When `kinds` is empty, all content types are searched; vector search applies
//! to all three kinds when a query embedding is present.
//!
//! # Backward compatibility
//!
//! When `query_embedding` is absent the handler behaves exactly as before —
//! FTS-only, same SQL, same response shape.  The `score` field on each hit is
//! optional and clients that don't use it can ignore it.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{error::Result, AppState};

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SearchRequest {
    pub user_id: String,
    pub query: String,
    /// ISO-8601 lower bound (inclusive), optional
    pub time_start: Option<String>,
    /// ISO-8601 upper bound (inclusive), optional
    pub time_end: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    /// Optional filter: `["utterance"]`, `["screenshot"]`, `["episode"]` or any
    /// combination.  Absent (or empty) means search all kinds.
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Optional 384-dim query embedding (float32, unit-length, cosine space —
    /// model pinned by `crate::embedding::MODEL_ID`, computed in-enclave at
    /// query time).  When present, utterance and screenshot search use
    /// RRF-fused FTS + vector KNN.  When absent, FTS-only.
    pub query_embedding: Option<Vec<f32>>,
}

fn default_limit() -> usize {
    20
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub enum SearchHit {
    Utterance {
        id: i64,
        text: String,
        speaker_label: String,
        started_at: String,
        start_offset_seconds: f64,
        end_offset_seconds: f64,
        /// Combined RRF score (hybrid) or BM25 score (FTS-only).
        /// Higher is better.  Absent for non-utterance kinds.
        #[serde(skip_serializing_if = "Option::is_none")]
        score: Option<f64>,
    },
    Screenshot {
        id: i64,
        captured_at: String,
        active_app: Option<String>,
        window_title: Option<String>,
        ocr_text: Option<String>,
        url: Option<String>,
        /// Combined RRF score (hybrid). Absent in FTS-only mode — older
        /// clients never see the field (skip_serializing_if), so the response
        /// shape is backward compatible.
        #[serde(skip_serializing_if = "Option::is_none")]
        score: Option<f64>,
    },
    Episode {
        id: i64,
        started_at: String,
        ended_at: String,
        title: Option<String>,
        summary: Option<String>,
        /// Minute-timeline gists (ADR-0004): parsed JSON array of
        /// {start, gist}, empty for episodes summarized before the feature.
        minute_summaries: serde_json::Value,
        /// Contextual FTS5 snippet of the matched text (title, summary, or a
        /// minute gist). Absent for vector-only matches.
        #[serde(skip_serializing_if = "Option::is_none")]
        snippet: Option<String>,
        /// Combined RRF score (hybrid). Absent in FTS-only mode.
        #[serde(skip_serializing_if = "Option::is_none")]
        score: Option<f64>,
    },
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub hits: Vec<SearchHit>,
    pub total: usize,
}

// ── Handler ───────────────────────────────────────────────────────────────────

pub async fn handle_search(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SearchRequest>,
) -> Result<Json<SearchResponse>> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(
        user_id = %user_id,
        query = %req.query,
        has_embedding = req.query_embedding.is_some(),
        "search request"
    );

    let hits = state
        .store
        .with_user(&user_id, |conn| search_all(conn, &req))
        .await?;

    let total = hits.len();
    Ok(Json(SearchResponse { hits, total }))
}

// ── Core search logic ─────────────────────────────────────────────────────────

pub(crate) fn search_all(
    conn: &rusqlite::Connection,
    req: &SearchRequest,
) -> Result<Vec<SearchHit>> {
    let mut hits = Vec::new();

    // When `kinds` is empty, search everything; otherwise honour the filter.
    let want_all = req.kinds.is_empty();
    let want = |k: &str| want_all || req.kinds.iter().any(|x| x.eq_ignore_ascii_case(k));

    if want("utterance") {
        hits.extend(search_utterances(conn, req)?);
    }
    if want("screenshot") {
        hits.extend(search_screenshots(conn, req)?);
    }
    if want("episode") {
        hits.extend(search_episodes(conn, req)?);
    }

    // Sort all hits by timestamp descending (most recent first).
    // For utterance hits when hybrid scoring is active they are already ranked
    // by RRF score; here we re-sort the combined list by time for cross-kind
    // ordering.  Each variant exposes a string timestamp; lexicographic sort is
    // correct for ISO-8601.
    hits.sort_by(|a, b| hit_timestamp(b).cmp(hit_timestamp(a)));
    hits.truncate(req.limit);
    Ok(hits)
}

fn hit_timestamp(h: &SearchHit) -> &str {
    match h {
        SearchHit::Utterance { started_at, .. } => started_at,
        SearchHit::Screenshot { captured_at, .. } => captured_at,
        SearchHit::Episode { started_at, .. } => started_at,
    }
}

/// Merge two ranked candidate lists with Reciprocal Rank Fusion:
/// `RRF(d) = Σ 1/(k + rank_i(d))`, k=60. Input lists are already in rank
/// order (best first); output is (rowid, rrf_score) sorted descending.
fn rrf_merge(fts_rows: &[i64], knn_rows: &[(i64, f64)]) -> Vec<(i64, f64)> {
    const RRF_K: f64 = 60.0;
    use std::collections::HashMap;
    let mut scores: HashMap<i64, f64> = HashMap::new();
    for (rank0, &rowid) in fts_rows.iter().enumerate() {
        *scores.entry(rowid).or_default() += 1.0 / (RRF_K + rank0 as f64 + 1.0);
    }
    for (rank0, &(rowid, _distance)) in knn_rows.iter().enumerate() {
        *scores.entry(rowid).or_default() += 1.0 / (RRF_K + rank0 as f64 + 1.0);
    }
    let mut out: Vec<(i64, f64)> = scores.into_iter().collect();
    out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    out
}

// ── Utterance search (FTS-only or Hybrid RRF) ────────────────────────────────

fn search_utterances(conn: &rusqlite::Connection, req: &SearchRequest) -> Result<Vec<SearchHit>> {
    match &req.query_embedding {
        Some(qemb) => search_utterances_hybrid(conn, req, qemb),
        None => search_utterances_fts(conn, req),
    }
}

/// FTS-only utterance search — identical to the pre-vector implementation.
fn search_utterances_fts(
    conn: &rusqlite::Connection,
    req: &SearchRequest,
) -> Result<Vec<SearchHit>> {
    let sql = r#"
        SELECT u.id, u.text, u.speaker_label,
               s.started_at, u.start_offset_seconds, u.end_offset_seconds
        FROM utterances u
        JOIN audio_segments s ON s.id = u.audio_segment_id
        WHERE u.id IN (
            SELECT rowid FROM utterances_fts WHERE utterances_fts MATCH ?1
        )
        AND (?2 IS NULL OR s.started_at >= ?2)
        AND (?3 IS NULL OR s.started_at <= ?3)
        ORDER BY s.started_at DESC
        LIMIT ?4 OFFSET ?5
    "#;

    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(
        rusqlite::params![
            req.query,
            req.time_start,
            req.time_end,
            req.limit as i64,
            req.offset as i64,
        ],
        |r| {
            Ok(SearchHit::Utterance {
                id: r.get(0)?,
                text: r.get(1)?,
                speaker_label: r.get(2)?,
                started_at: r.get(3)?,
                start_offset_seconds: r.get(4)?,
                end_offset_seconds: r.get(5)?,
                score: None,
            })
        },
    )?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Hybrid utterance search using Reciprocal Rank Fusion.
///
/// 1. Run FTS5 MATCH to get the ranked FTS result set (up to `limit * 3` rows
///    so we have candidates for both lists).
/// 2. Run vec0 KNN as a STANDALONE subquery (sqlite-vec requirement: no JOINs
///    inside the MATCH clause) to get the ranked vector result set.
/// 3. Merge both ranked lists using RRF(k=60): score = Σ 1/(k + rank).
/// 4. Join back to the utterances + audio_segments tables for the full row.
/// 5. Apply time-range filter and return, sorted by RRF score descending.
fn search_utterances_hybrid(
    conn: &rusqlite::Connection,
    req: &SearchRequest,
    query_emb: &[f32],
) -> Result<Vec<SearchHit>> {
    // Fetch a wider candidate set from each signal; RRF re-ranks them.
    let candidate_limit = (req.limit * 3).max(60) as i64;

    // ── Step 1: FTS candidates ──────────────────────────────────────────────
    // We collect rowids in FTS rank order (BM25 descending = bm25() ascending
    // because bm25() returns a negative value; lower = better match).
    let fts_sql = r#"
        SELECT rowid
        FROM utterances_fts
        WHERE utterances_fts MATCH ?1
        ORDER BY rank
        LIMIT ?2
    "#;
    let mut fts_stmt = conn.prepare(fts_sql)?;
    let fts_rows: Vec<i64> = fts_stmt
        .query_map(rusqlite::params![req.query, candidate_limit], |r| r.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // ── Step 2: Vector KNN candidates (standalone, no JOINs) ───────────────
    // Encode the query vector as raw f32-LE bytes (the blob format sqlite-vec
    // expects on the right-hand side of MATCH).
    let query_bytes: Vec<u8> = query_emb.iter().flat_map(|f| f.to_le_bytes()).collect();

    let knn_sql = r#"
        SELECT utterance_id, distance
        FROM vec_utterances
        WHERE embedding MATCH ?1
        ORDER BY distance
        LIMIT ?2
    "#;
    let mut knn_stmt = conn.prepare(knn_sql)?;
    // Returns (utterance_id, distance) pairs, distance ascending (nearest first).
    let knn_rows: Vec<(i64, f64)> = knn_stmt
        .query_map(
            rusqlite::params![query_bytes.as_slice(), candidate_limit],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // ── Step 3: RRF merge ───────────────────────────────────────────────────
    let candidates = rrf_merge(&fts_rows, &knn_rows);

    // Apply offset and limit before the join
    let candidates_page: Vec<(i64, f64)> = candidates
        .into_iter()
        .skip(req.offset)
        .take(req.limit)
        .collect();

    if candidates_page.is_empty() {
        return Ok(vec![]);
    }

    // ── Step 4: Join back to get full utterance rows ────────────────────────
    // Build a VALUES clause to preserve ordering and pass the score through.
    // Example: VALUES (42, 0.031), (17, 0.025), ...
    let values_clause: String = candidates_page
        .iter()
        .map(|(id, score)| format!("({id},{score})"))
        .collect::<Vec<_>>()
        .join(",");

    let join_sql = format!(
        r#"
        WITH ranked(utterance_id, rrf_score) AS (VALUES {values_clause})
        SELECT u.id, u.text, u.speaker_label,
               s.started_at, u.start_offset_seconds, u.end_offset_seconds,
               r.rrf_score
        FROM ranked r
        JOIN utterances u ON u.id = r.utterance_id
        JOIN audio_segments s ON s.id = u.audio_segment_id
        WHERE (?1 IS NULL OR s.started_at >= ?1)
          AND (?2 IS NULL OR s.started_at <= ?2)
        ORDER BY r.rrf_score DESC
        "#
    );

    let mut stmt = conn.prepare(&join_sql)?;
    let rows = stmt.query_map(rusqlite::params![req.time_start, req.time_end], |r| {
        Ok(SearchHit::Utterance {
            id: r.get(0)?,
            text: r.get(1)?,
            speaker_label: r.get(2)?,
            started_at: r.get(3)?,
            start_offset_seconds: r.get(4)?,
            end_offset_seconds: r.get(5)?,
            score: Some(r.get::<_, f64>(6)?),
        })
    })?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

// ── Screenshot search (FTS-only or Hybrid RRF over OCR text) ──────────────────

fn search_screenshots(conn: &rusqlite::Connection, req: &SearchRequest) -> Result<Vec<SearchHit>> {
    match &req.query_embedding {
        Some(qemb) => search_screenshots_hybrid(conn, req, qemb),
        None => search_screenshots_fts(conn, req),
    }
}

fn search_screenshots_fts(
    conn: &rusqlite::Connection,
    req: &SearchRequest,
) -> Result<Vec<SearchHit>> {
    let sql = r#"
        SELECT id, captured_at, active_app, window_title, ocr_text, url
        FROM screenshots
        WHERE id IN (
            SELECT rowid FROM screenshots_fts WHERE screenshots_fts MATCH ?1
        )
        AND (?2 IS NULL OR captured_at >= ?2)
        AND (?3 IS NULL OR captured_at <= ?3)
        ORDER BY captured_at DESC
        LIMIT ?4 OFFSET ?5
    "#;

    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(
        rusqlite::params![
            req.query,
            req.time_start,
            req.time_end,
            req.limit as i64,
            req.offset as i64,
        ],
        |r| {
            Ok(SearchHit::Screenshot {
                id: r.get(0)?,
                captured_at: r.get(1)?,
                active_app: r.get(2)?,
                window_title: r.get(3)?,
                ocr_text: r.get(4)?,
                url: r.get(5)?,
                score: None,
            })
        },
    )?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Hybrid screenshot search — same shape as [`search_utterances_hybrid`]:
/// FTS candidates + standalone vec0 KNN (sqlite-vec: MATCH must not mix with
/// JOINs), RRF merge, then join back for full rows.
fn search_screenshots_hybrid(
    conn: &rusqlite::Connection,
    req: &SearchRequest,
    query_emb: &[f32],
) -> Result<Vec<SearchHit>> {
    let candidate_limit = (req.limit * 3).max(60) as i64;

    let fts_sql = r#"
        SELECT rowid
        FROM screenshots_fts
        WHERE screenshots_fts MATCH ?1
        ORDER BY rank
        LIMIT ?2
    "#;
    let mut fts_stmt = conn.prepare(fts_sql)?;
    let fts_rows: Vec<i64> = fts_stmt
        .query_map(rusqlite::params![req.query, candidate_limit], |r| r.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let query_bytes: Vec<u8> = query_emb.iter().flat_map(|f| f.to_le_bytes()).collect();
    let knn_sql = r#"
        SELECT screenshot_id, distance
        FROM vec_screenshots
        WHERE embedding MATCH ?1
        ORDER BY distance
        LIMIT ?2
    "#;
    let mut knn_stmt = conn.prepare(knn_sql)?;
    let knn_rows: Vec<(i64, f64)> = knn_stmt
        .query_map(
            rusqlite::params![query_bytes.as_slice(), candidate_limit],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let candidates_page: Vec<(i64, f64)> = rrf_merge(&fts_rows, &knn_rows)
        .into_iter()
        .skip(req.offset)
        .take(req.limit)
        .collect();

    if candidates_page.is_empty() {
        return Ok(vec![]);
    }

    let values_clause: String = candidates_page
        .iter()
        .map(|(id, score)| format!("({id},{score})"))
        .collect::<Vec<_>>()
        .join(",");

    let join_sql = format!(
        r#"
        WITH ranked(screenshot_id, rrf_score) AS (VALUES {values_clause})
        SELECT sc.id, sc.captured_at, sc.active_app, sc.window_title,
               sc.ocr_text, sc.url, r.rrf_score
        FROM ranked r
        JOIN screenshots sc ON sc.id = r.screenshot_id
        WHERE (?1 IS NULL OR sc.captured_at >= ?1)
          AND (?2 IS NULL OR sc.captured_at <= ?2)
        ORDER BY r.rrf_score DESC
        "#
    );

    let mut stmt = conn.prepare(&join_sql)?;
    let rows = stmt.query_map(rusqlite::params![req.time_start, req.time_end], |r| {
        Ok(SearchHit::Screenshot {
            id: r.get(0)?,
            captured_at: r.get(1)?,
            active_app: r.get(2)?,
            window_title: r.get(3)?,
            ocr_text: r.get(4)?,
            url: r.get(5)?,
            score: Some(r.get::<_, f64>(6)?),
        })
    })?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

// ── Episode search (FTS-only or Hybrid RRF over title/summary/minute gists) ──

/// Parse a stored JSON-array column into a Value, defaulting to `[]`.
fn json_array(raw: Option<String>) -> serde_json::Value {
    raw.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::Value::Array(vec![]))
}

/// FTS snippet arguments: auto-pick the matched column, bracket markers,
/// ~12 tokens of context.
const SNIPPET_FN: &str = "snippet(episodes_fts, -1, '[', ']', ' … ', 12)";

/// Episode search — the PRIMARY result entity as of ADR-0004. Indexed text is
/// title + exec summary + minute-timeline gists (minutes_text); vectors live
/// in `vec_episodes`, computed in-enclave at summarizer-upsert time. Results
/// come back in relevance order (FTS rank, or RRF when hybrid) — callers that
/// need time ordering re-sort (see [`search_all`]).
pub(crate) fn search_episodes(
    conn: &rusqlite::Connection,
    req: &SearchRequest,
) -> Result<Vec<SearchHit>> {
    match &req.query_embedding {
        Some(qemb) => search_episodes_hybrid(conn, req, qemb),
        None => search_episodes_fts(conn, req),
    }
}

fn search_episodes_fts(conn: &rusqlite::Connection, req: &SearchRequest) -> Result<Vec<SearchHit>> {
    let sql = format!(
        r#"
        SELECT e.id, e.started_at, e.ended_at, e.title, e.summary,
               e.minute_summaries, {SNIPPET_FN}
        FROM episodes_fts
        JOIN episodes e ON e.id = episodes_fts.rowid
        WHERE episodes_fts MATCH ?1
          AND (?2 IS NULL OR e.started_at >= ?2)
          AND (?3 IS NULL OR e.started_at <= ?3)
        ORDER BY rank
        LIMIT ?4 OFFSET ?5
    "#
    );

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params![
            req.query,
            req.time_start,
            req.time_end,
            req.limit as i64,
            req.offset as i64,
        ],
        |r| {
            Ok(SearchHit::Episode {
                id: r.get(0)?,
                started_at: r.get(1)?,
                ended_at: r.get(2)?,
                title: r.get(3)?,
                summary: r.get(4)?,
                minute_summaries: json_array(r.get(5)?),
                snippet: r.get(6)?,
                score: None,
            })
        },
    )?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Hybrid episode search — same shape as [`search_utterances_hybrid`]: FTS
/// candidates (with snippets) + standalone vec0 KNN over `vec_episodes`
/// (sqlite-vec: MATCH must not mix with JOINs), RRF merge, join back.
fn search_episodes_hybrid(
    conn: &rusqlite::Connection,
    req: &SearchRequest,
    query_emb: &[f32],
) -> Result<Vec<SearchHit>> {
    use std::collections::HashMap;
    let candidate_limit = (req.limit * 3).max(60) as i64;

    let fts_sql = format!(
        "SELECT rowid, {SNIPPET_FN} FROM episodes_fts \
         WHERE episodes_fts MATCH ?1 ORDER BY rank LIMIT ?2"
    );
    let mut fts_stmt = conn.prepare(&fts_sql)?;
    let fts: Vec<(i64, String)> = fts_stmt
        .query_map(rusqlite::params![req.query, candidate_limit], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let fts_rows: Vec<i64> = fts.iter().map(|(id, _)| *id).collect();
    let snippets: HashMap<i64, String> = fts.into_iter().collect();

    let query_bytes: Vec<u8> = query_emb.iter().flat_map(|f| f.to_le_bytes()).collect();
    let knn_sql = r#"
        SELECT episode_id, distance
        FROM vec_episodes
        WHERE embedding MATCH ?1
        ORDER BY distance
        LIMIT ?2
    "#;
    let mut knn_stmt = conn.prepare(knn_sql)?;
    let knn_rows: Vec<(i64, f64)> = knn_stmt
        .query_map(
            rusqlite::params![query_bytes.as_slice(), candidate_limit],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let candidates_page: Vec<(i64, f64)> = rrf_merge(&fts_rows, &knn_rows)
        .into_iter()
        .skip(req.offset)
        .take(req.limit)
        .collect();

    if candidates_page.is_empty() {
        return Ok(vec![]);
    }

    let values_clause: String = candidates_page
        .iter()
        .map(|(id, score)| format!("({id},{score})"))
        .collect::<Vec<_>>()
        .join(",");

    let join_sql = format!(
        r#"
        WITH ranked(episode_id, rrf_score) AS (VALUES {values_clause})
        SELECT e.id, e.started_at, e.ended_at, e.title, e.summary,
               e.minute_summaries, r.rrf_score
        FROM ranked r
        JOIN episodes e ON e.id = r.episode_id
        WHERE (?1 IS NULL OR e.started_at >= ?1)
          AND (?2 IS NULL OR e.started_at <= ?2)
        ORDER BY r.rrf_score DESC
        "#
    );

    let mut stmt = conn.prepare(&join_sql)?;
    let rows = stmt.query_map(rusqlite::params![req.time_start, req.time_end], |r| {
        let id: i64 = r.get(0)?;
        Ok(SearchHit::Episode {
            id,
            started_at: r.get(1)?,
            ended_at: r.get(2)?,
            title: r.get(3)?,
            summary: r.get(4)?,
            minute_summaries: json_array(r.get(5)?),
            snippet: None, // filled from the FTS map below
            score: Some(r.get::<_, f64>(6)?),
        })
    })?;
    let mut hits = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    for hit in &mut hits {
        if let SearchHit::Episode { id, snippet, .. } = hit {
            *snippet = snippets.get(id).cloned();
        }
    }
    Ok(hits)
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{ingest_utterances, UtteranceInput};
    use crate::store::tests::{FakeGcs, FakeKms};
    use crate::store::Store;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::sync::Arc;

    fn make_store() -> Store {
        Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()))
    }

    /// Build a unit-length 384-dim embedding where all components are the same
    /// sign and magnitude.  Two embeddings built with the same val will have
    /// cosine distance ≈ 0 (identical direction); different vals will differ.
    fn make_embedding(val: f32) -> Vec<f32> {
        let n = 384_usize;
        let unit = if val == 0.0 {
            0.0
        } else {
            val.signum() / (n as f32).sqrt()
        };
        vec![unit; n]
    }

    fn make_embedding_b64(val: f32) -> String {
        let floats = make_embedding(val);
        let bytes: Vec<u8> = floats.iter().flat_map(|f| f.to_le_bytes()).collect();
        B64.encode(&bytes)
    }

    fn utt_with_emb(key: &str, text: &str, emb_val: Option<f32>) -> UtteranceInput {
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
            source_key: Some(key.to_string()),
            embedding_b64: emb_val.map(make_embedding_b64),
        }
    }

    fn req_fts(user: &str, query: &str, kinds: Vec<String>) -> SearchRequest {
        SearchRequest {
            user_id: user.to_string(),
            query: query.to_string(),
            time_start: None,
            time_end: None,
            limit: 100,
            offset: 0,
            kinds,
            query_embedding: None,
        }
    }

    fn req_hybrid(user: &str, query: &str, emb_val: f32) -> SearchRequest {
        SearchRequest {
            user_id: user.to_string(),
            query: query.to_string(),
            time_start: None,
            time_end: None,
            limit: 100,
            offset: 0,
            kinds: vec![],
            query_embedding: Some(make_embedding(emb_val)),
        }
    }

    /// Seed one utterance, one screenshot, and one episode that all match "kioku".
    async fn seed_mixed(store: &Store, user: &str) {
        store
            .with_user(user, |conn| {
                conn.execute(
                    r#"INSERT OR IGNORE INTO audio_segments
                       (started_at, ended_at, duration_seconds, source_type)
                       VALUES ('2026-01-01T09:00:00Z','2026-01-01T09:01:00Z',60.0,'mic')"#,
                    [],
                )?;
                let seg_id: i64 = conn.query_row(
                    "SELECT id FROM audio_segments WHERE started_at='2026-01-01T09:00:00Z'",
                    [],
                    |r| r.get(0),
                )?;
                conn.execute(
                    r#"INSERT INTO utterances
                       (audio_segment_id, start_offset_seconds, end_offset_seconds,
                        text, speaker_label)
                       VALUES (?1, 0.0, 5.0, 'kioku utterance', 'speaker_0')"#,
                    [seg_id],
                )?;
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text)
                     VALUES ('2026-01-01T09:05:00Z', 'kioku screenshot')",
                    [],
                )?;
                conn.execute(
                    r#"INSERT INTO episodes
                       (started_at, ended_at, title, summary)
                       VALUES ('2026-01-01T09:00:00Z','2026-01-01T09:30:00Z',
                               'kioku episode','summary')"#,
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }

    // ── FTS tests (unchanged behaviour) ──────────────────────────────────────

    #[tokio::test]
    async fn kinds_empty_returns_all() {
        let store = make_store();
        seed_mixed(&store, "kinds_all").await;

        let hits = store
            .with_user("kinds_all", |conn| {
                search_all(conn, &req_fts("kinds_all", "kioku", vec![]))
            })
            .await
            .unwrap();

        let has_utt = hits
            .iter()
            .any(|h| matches!(h, SearchHit::Utterance { .. }));
        let has_scr = hits
            .iter()
            .any(|h| matches!(h, SearchHit::Screenshot { .. }));
        let has_ep = hits.iter().any(|h| matches!(h, SearchHit::Episode { .. }));
        assert!(has_utt && has_scr && has_ep, "all kinds should be present");
    }

    #[tokio::test]
    async fn kinds_utterance_only() {
        let store = make_store();
        seed_mixed(&store, "kinds_u").await;

        let hits = store
            .with_user("kinds_u", |conn| {
                search_all(
                    conn,
                    &req_fts("kinds_u", "kioku", vec!["utterance".to_string()]),
                )
            })
            .await
            .unwrap();

        assert!(!hits.is_empty());
        assert!(
            hits.iter()
                .all(|h| matches!(h, SearchHit::Utterance { .. })),
            "only utterances expected"
        );
    }

    #[tokio::test]
    async fn kinds_screenshot_only() {
        let store = make_store();
        seed_mixed(&store, "kinds_s").await;

        let hits = store
            .with_user("kinds_s", |conn| {
                search_all(
                    conn,
                    &req_fts("kinds_s", "kioku", vec!["screenshot".to_string()]),
                )
            })
            .await
            .unwrap();

        assert!(!hits.is_empty());
        assert!(
            hits.iter()
                .all(|h| matches!(h, SearchHit::Screenshot { .. })),
            "only screenshots expected"
        );
    }

    #[tokio::test]
    async fn kinds_episode_only() {
        let store = make_store();
        seed_mixed(&store, "kinds_e").await;

        let hits = store
            .with_user("kinds_e", |conn| {
                search_all(
                    conn,
                    &req_fts("kinds_e", "kioku", vec!["episode".to_string()]),
                )
            })
            .await
            .unwrap();

        assert!(!hits.is_empty());
        assert!(
            hits.iter().all(|h| matches!(h, SearchHit::Episode { .. })),
            "only episodes expected"
        );
    }

    // ── Vector / hybrid tests ─────────────────────────────────────────────────

    /// Ingest a row with a known embedding → vector search with a near vector
    /// returns it.
    #[tokio::test]
    async fn vector_search_returns_near_utterance() {
        let store = make_store();

        store
            .with_user("vsearch_u", |conn| {
                ingest_utterances(
                    conn,
                    &[utt_with_emb("k:1:1", "semantic memory test", Some(1.0))],
                    true,
                )
            })
            .await
            .expect("ingest");

        // Query with the same direction (cosine distance ≈ 0) → should be returned.
        let hits = store
            .with_user("vsearch_u", |conn| {
                search_all(conn, &req_hybrid("vsearch_u", "semantic", 1.0))
            })
            .await
            .expect("search");

        assert!(
            !hits.is_empty(),
            "vector search with near vector should return the ingested utterance"
        );
        assert!(
            hits.iter()
                .any(|h| matches!(h, SearchHit::Utterance { .. })),
            "result should be an utterance"
        );
    }

    /// Hybrid search: ingest two utterances — one matching FTS, one matching
    /// vector, one matching both — verify all appear in results.
    #[tokio::test]
    async fn hybrid_combines_fts_and_vector() {
        let store = make_store();

        store
            .with_user("hybrid_u", |conn| {
                // Utterance A: matches FTS ("unique_fts_term"), no embedding
                ingest_utterances(
                    conn,
                    &[utt_with_emb("k:1:1", "unique_fts_term alpha", None)],
                    true,
                )?;
                // Utterance B: matches vector (similar direction to query), text not matching FTS
                ingest_utterances(
                    conn,
                    &[utt_with_emb("k:1:2", "vector match candidate", Some(1.0))],
                    true,
                )?;
                Ok(())
            })
            .await
            .expect("ingest");

        // Hybrid query: FTS for "unique_fts_term", vector in direction of emb(1.0)
        let req = SearchRequest {
            user_id: "hybrid_u".to_string(),
            query: "unique_fts_term".to_string(),
            time_start: None,
            time_end: None,
            limit: 100,
            offset: 0,
            kinds: vec!["utterance".to_string()],
            query_embedding: Some(make_embedding(1.0)),
        };

        let hits = store
            .with_user("hybrid_u", |conn| search_all(conn, &req))
            .await
            .expect("search");

        // Both should appear: A from FTS, B from vector
        assert!(
            hits.len() >= 2,
            "hybrid should return both FTS and vector candidates, got {}",
            hits.len()
        );
    }

    /// Absent query_embedding → FTS-only, no error.
    #[tokio::test]
    async fn absent_query_embedding_falls_back_to_fts() {
        let store = make_store();

        store
            .with_user("fts_only_u", |conn| {
                ingest_utterances(
                    conn,
                    &[utt_with_emb("k:1:1", "kioku recall test", Some(0.5))],
                    true,
                )
            })
            .await
            .expect("ingest");

        let hits = store
            .with_user("fts_only_u", |conn| {
                search_all(conn, &req_fts("fts_only_u", "kioku", vec![]))
            })
            .await
            .expect("search");

        assert!(
            hits.iter()
                .any(|h| matches!(h, SearchHit::Utterance { .. })),
            "FTS-only should still find the utterance"
        );
    }

    /// Schema migration creating vec0 is idempotent: opening the same store
    /// twice (simulating a process restart) must not error.
    #[tokio::test]
    async fn vec0_schema_migration_is_idempotent() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let store = Store::new(kms.clone(), gcs.clone());

        // First open
        store
            .with_user("idempotent_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM vec_utterances", [], |_| Ok(0_i64))?)
            })
            .await
            .expect("first open");

        store.save_user("idempotent_u").await.expect("save");

        // Second open on fresh store (simulates restart)
        let store2 = Store::new(kms, gcs);
        store2
            .with_user("idempotent_u", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM vec_utterances", [], |_| Ok(0_i64))?)
            })
            .await
            .expect("reload should not error on existing vec0 table");
    }

    /// ADR-0004: a phrase that appears ONLY in a minute gist finds the
    /// episode, with a snippet and the parsed minute_summaries attached.
    #[tokio::test]
    async fn episode_found_by_minute_gist_with_snippet() {
        use crate::episodes::{upsert_episodes, EpisodeInput, MinuteBucket};
        let store = make_store();
        store
            .with_user("ep_gist_u", |conn| {
                upsert_episodes(
                    conn,
                    &[EpisodeInput {
                        id: None,
                        started_at: "2026-07-05T20:56:00Z".into(),
                        ended_at: "2026-07-05T21:01:00Z".into(),
                        episode_type: Some("other".into()),
                        title: "Family dinner chat".into(),
                        summary: Some("- catching up".into()),
                        participants: None,
                        languages: None,
                        action_items: None,
                        minute_summaries: Some(vec![MinuteBucket {
                            start: "2026-07-05T20:58:00Z".into(),
                            gist: "Pesto recipe, lobster question".into(),
                        }]),
                        model: None,
                        member_utterance_ids: vec![],
                        member_screenshot_ids: vec![],
                    }],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let hits = store
            .with_user("ep_gist_u", |conn| {
                search_episodes(
                    conn,
                    &req_fts("ep_gist_u", "lobster", vec!["episode".into()]),
                )
            })
            .await
            .unwrap();
        match hits.first() {
            Some(SearchHit::Episode {
                snippet,
                minute_summaries,
                ..
            }) => {
                assert!(
                    snippet.as_deref().unwrap_or("").contains("lobster"),
                    "snippet should mark the matched gist, got {snippet:?}"
                );
                assert_eq!(minute_summaries.as_array().unwrap().len(), 1);
            }
            other => panic!("expected episode hit via minute gist, got {other:?}"),
        }
    }

    /// Hybrid episode search: an episode whose text does NOT match FTS is
    /// still found via its in-enclave vector, with an RRF score attached.
    #[tokio::test]
    async fn episode_hybrid_finds_vector_match() {
        use crate::episodes::{upsert_episodes, write_episode_embedding, EpisodeInput};
        let store = make_store();
        store
            .with_user("ep_hybrid_u", |conn| {
                let ids = upsert_episodes(
                    conn,
                    &[EpisodeInput {
                        id: None,
                        started_at: "2026-07-05T09:00:00Z".into(),
                        ended_at: "2026-07-05T09:30:00Z".into(),
                        episode_type: None,
                        title: "Morning sync".into(),
                        summary: None,
                        participants: None,
                        languages: None,
                        action_items: None,
                        minute_summaries: None,
                        model: None,
                        member_utterance_ids: vec![],
                        member_screenshot_ids: vec![],
                    }],
                )?;
                write_episode_embedding(conn, ids[0], &make_embedding(1.0))?;
                Ok(())
            })
            .await
            .unwrap();

        let req = SearchRequest {
            kinds: vec!["episode".into()],
            ..req_hybrid("ep_hybrid_u", "nomatchterm", 1.0)
        };
        let hits = store
            .with_user("ep_hybrid_u", |conn| search_episodes(conn, &req))
            .await
            .unwrap();
        match hits.first() {
            Some(SearchHit::Episode { score, snippet, .. }) => {
                assert!(score.is_some(), "hybrid episode hit must carry RRF score");
                assert!(snippet.is_none(), "vector-only match has no FTS snippet");
            }
            other => panic!("expected vector-matched episode, got {other:?}"),
        }
    }

    /// Hybrid screenshot search: a screenshot whose OCR text does NOT match
    /// the FTS query is still found via vector KNN, with a score attached;
    /// FTS-only mode leaves score None.
    #[tokio::test]
    async fn screenshot_hybrid_finds_vector_match() {
        use crate::ingest::{ingest_screenshots, ScreenshotInput};
        let store = make_store();

        store
            .with_user("scr_hybrid_u", |conn| {
                ingest_screenshots(
                    conn,
                    &[ScreenshotInput {
                        captured_at: "2026-01-01T09:05:00Z".to_string(),
                        active_app: Some("zoom.us".to_string()),
                        window_title: None,
                        ocr_text: Some("participant panel names list".to_string()),
                        url: None,
                        image_hash: None,
                        source_key: Some("dev:9".to_string()),
                        embedding_b64: Some(make_embedding_b64(1.0)),
                    }],
                    true,
                )
            })
            .await
            .expect("ingest screenshot");

        // Hybrid query whose text matches nothing in FTS but whose vector is
        // aligned with the stored embedding.
        let req = req_hybrid("scr_hybrid_u", "nomatchterm", 1.0);
        let hits = store
            .with_user("scr_hybrid_u", |conn| search_all(conn, &req))
            .await
            .expect("search");

        let scr_hit = hits.iter().find_map(|h| match h {
            SearchHit::Screenshot { id, score, .. } => Some((*id, *score)),
            _ => None,
        });
        let (_, score) = scr_hit.expect("vector KNN should surface the screenshot");
        assert!(score.is_some(), "hybrid hit must carry an RRF score");

        // FTS-only search for a term that DOES match keeps score None.
        let req = req_fts("scr_hybrid_u", "participant", vec!["screenshot".into()]);
        let hits = store
            .with_user("scr_hybrid_u", |conn| search_all(conn, &req))
            .await
            .expect("fts search");
        match hits.first() {
            Some(SearchHit::Screenshot { score, .. }) => {
                assert!(
                    score.is_none(),
                    "FTS-only screenshot hit must have no score"
                )
            }
            other => panic!("expected screenshot hit, got {other:?}"),
        }
    }
}
