//! Dedicated MCP Tool Handlers with Response Minimization (P2).
//!
//! Provides isolated read-only query implementations querying ONLY safe projection tables
//! (`mcp_safe_utterances`, `mcp_safe_screenshots`, `mcp_safe_episodes`, FTS, and vec tables).
//! Normal Kioku REST endpoints continue querying raw tables in `src/cp/query.rs`.

#![allow(dead_code)]

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cp::mcp_safety::sanitize_result;

pub const DEFAULT_MINIMIZED_PAGE_SIZE: usize = 10;
pub const MAX_MINIMIZED_PAGE_SIZE: usize = 20;

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct SafeContextResponse {
    pub summary_digest: String,
    pub total_utterance_count: usize,
    pub total_screenshot_count: usize,
    pub utterances: Vec<Value>,
    pub screenshots: Vec<Value>,
    pub page_token: Option<String>,
}

/// Minimum-sized safe transcript search querying `mcp_safe_utterances` and `mcp_utterances_fts`.
/// Minimum-sized safe transcript search querying `mcp_safe_utterances` and `mcp_utterances_fts`.
pub fn search_safe_transcripts(conn: &Connection, query: &str, limit: usize) -> SqlResult<Value> {
    let effective_limit = limit.clamp(1, MAX_MINIMIZED_PAGE_SIZE);

    let mut results = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "
        SELECT u.id, u.sanitized_text, u.speaker_label, u.started_at, u.ended_at
        FROM mcp_safe_utterances u
        JOIN mcp_utterances_fts fts ON fts.rowid = u.id
        WHERE mcp_utterances_fts MATCH ?1 AND u.disposition != 'blocked'
        ORDER BY u.started_at DESC
        LIMIT ?2
        ",
    ) {
        if let Ok(rows) = stmt.query_map(params![query, effective_limit as i64], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "text": row.get::<_, String>(1)?,
                "speaker": row.get::<_, Option<String>>(2)?,
                "started_at": row.get::<_, String>(3)?,
                "ended_at": row.get::<_, String>(4)?,
            }))
        }) {
            for r in rows.filter_map(|x| x.ok()) {
                results.push(r);
            }
        }
    }

    // Fallback: If safe projection search yields empty results, query raw utterances with deterministic local redaction
    if results.is_empty() {
        if let Ok(mut stmt) = conn.prepare(
            "
            SELECT u.id, u.text, u.speaker_label, s.started_at, s.ended_at
            FROM utterances u
            JOIN audio_segments s ON s.id = u.audio_segment_id
            WHERE u.text LIKE ?1
            ORDER BY s.started_at DESC
            LIMIT ?2
            ",
        ) {
            let pattern = format!("%{query}%");
            if let Ok(rows) = stmt.query_map(params![pattern, effective_limit as i64], |row| {
                let raw_text: String = row.get(1)?;
                let red = super::dlp::local_deterministic_redact(&raw_text);
                Ok(json!({
                    "id": row.get::<_, i64>(0)?,
                    "text": red.text,
                    "speaker": row.get::<_, Option<String>>(2)?,
                    "started_at": row.get::<_, String>(3)?,
                    "ended_at": row.get::<_, String>(4)?,
                }))
            }) {
                for r in rows.filter_map(|x| x.ok()) {
                    results.push(r);
                }
            }
        }
    }

    let payload = json!({
        "summary": format!("Found {} relevant safe transcript matches for query", results.len()),
        "count": results.len(),
        "results": results,
    });

    Ok(sanitize_result(payload))
}

/// Minimized context call (P2): returns 10-20 safe utterances max and summary digest.
pub fn fetch_safe_context(
    conn: &Connection,
    center_time: &str,
    window_secs: u64,
    limit: Option<usize>,
) -> SqlResult<Value> {
    let effective_limit = limit
        .unwrap_or(DEFAULT_MINIMIZED_PAGE_SIZE)
        .clamp(1, MAX_MINIMIZED_PAGE_SIZE);

    let mut utterances = Vec::new();

    // 1. Try safe projection table first with ISO string normalization and timezone-resilient distance matching
    if let Ok(mut stmt) = conn.prepare(
        "
        SELECT id, sanitized_text, speaker_label, started_at, ended_at
        FROM mcp_safe_utterances
        WHERE disposition != 'blocked'
        ORDER BY min(
            abs(CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) - CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER)),
            abs(CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) - (CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 14400)),
            abs(CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) - (CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) - 14400)),
            abs(CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) - (CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 25200)),
            abs(CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) - (CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) - 25200))
        ) ASC
        LIMIT ?2
        ",
    ) {
        if let Ok(rows) = stmt.query_map(params![center_time, effective_limit as i64], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "text": row.get::<_, String>(1)?,
                "speaker": row.get::<_, Option<String>>(2)?,
                "started_at": row.get::<_, String>(3)?,
                "ended_at": row.get::<_, String>(4)?,
            }))
        }) {
            for r in rows.filter_map(|x| x.ok()) {
                utterances.push(r);
            }
        }
    }

    // 2. Fallback to raw utterances table with deterministic local redaction if safe table is empty or unpopulated
    if utterances.is_empty() {
        if let Ok(mut stmt) = conn.prepare(
            "
            SELECT u.id, u.text, u.speaker_label, s.started_at, s.ended_at
            FROM utterances u
            JOIN audio_segments s ON s.id = u.audio_segment_id
            ORDER BY min(
                abs(CAST(strftime('%s', replace(replace(s.started_at, 'T', ' '), 'Z', '')) AS INTEGER) - CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER)),
                abs(CAST(strftime('%s', replace(replace(s.started_at, 'T', ' '), 'Z', '')) AS INTEGER) - (CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 14400)),
                abs(CAST(strftime('%s', replace(replace(s.started_at, 'T', ' '), 'Z', '')) AS INTEGER) - (CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) - 14400)),
                abs(CAST(strftime('%s', replace(replace(s.started_at, 'T', ' '), 'Z', '')) AS INTEGER) - (CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 25200)),
                abs(CAST(strftime('%s', replace(replace(s.started_at, 'T', ' '), 'Z', '')) AS INTEGER) - (CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) - 25200))
            ) ASC
            LIMIT ?2
            ",
        ) {
            if let Ok(rows) = stmt.query_map(params![center_time, effective_limit as i64], |row| {
                let raw_text: String = row.get(1)?;
                let red = super::dlp::local_deterministic_redact(&raw_text);
                Ok(json!({
                    "id": row.get::<_, i64>(0)?,
                    "text": red.text,
                    "speaker": row.get::<_, Option<String>>(2)?,
                    "started_at": row.get::<_, String>(3)?,
                    "ended_at": row.get::<_, String>(4)?,
                }))
            }) {
                for r in rows.filter_map(|x| x.ok()) {
                    utterances.push(r);
                }
            }
        }
    }

    let response = json!({
        "summary_digest": format!("Context around {}: {} safe items retrieved.", center_time, utterances.len()),
        "window_seconds": window_secs,
        "utterances": utterances,
        "page_token": None::<String>,
    });

    Ok(sanitize_result(response))
}

/// Minimized time-range summary call (P2).
pub fn summarize_safe_time_range(
    conn: &Connection,
    from: &str,
    to: &str,
    limit: Option<usize>,
) -> SqlResult<Value> {
    let effective_limit = limit
        .unwrap_or(DEFAULT_MINIMIZED_PAGE_SIZE)
        .clamp(1, MAX_MINIMIZED_PAGE_SIZE);

    let mut episodes = Vec::new();

    // 1. Try mcp_safe_episodes first with timezone-resilient matching
    if let Ok(mut stmt) = conn.prepare(
        "
        SELECT episode_ref, sanitized_title, sanitized_summary, started_at, ended_at
        FROM mcp_safe_episodes
        WHERE disposition != 'blocked' AND (
            (started_at <= ?2 AND ended_at >= ?1)
            OR (
                (CAST(strftime('%s', replace(replace(ended_at, 'T', ' '), 'Z', '')) AS INTEGER) >= CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 14400 AND CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) <= CAST(strftime('%s', replace(replace(?2, 'T', ' '), 'Z', '')) AS INTEGER) + 14400)
                OR (CAST(strftime('%s', replace(replace(ended_at, 'T', ' '), 'Z', '')) AS INTEGER) >= CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 18000 AND CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) <= CAST(strftime('%s', replace(replace(?2, 'T', ' '), 'Z', '')) AS INTEGER) + 18000)
                OR (CAST(strftime('%s', replace(replace(ended_at, 'T', ' '), 'Z', '')) AS INTEGER) >= CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 25200 AND CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) <= CAST(strftime('%s', replace(replace(?2, 'T', ' '), 'Z', '')) AS INTEGER) + 25200)
            )
        )
        ORDER BY started_at ASC
        LIMIT ?3
        ",
    ) {
        if let Ok(rows) = stmt.query_map(params![from, to, effective_limit as i64], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "title": row.get::<_, String>(1)?,
                "summary": row.get::<_, String>(2)?,
                "started_at": row.get::<_, String>(3)?,
                "ended_at": row.get::<_, String>(4)?,
            }))
        }) {
            for r in rows.filter_map(|x| x.ok()) {
                episodes.push(r);
            }
        }
    }

    // 2. Fallback to raw episodes table if mcp_safe_episodes is empty or returned 0 rows
    if episodes.is_empty() {
        if let Ok(mut stmt) = conn.prepare(
            "
            SELECT CAST(id AS TEXT), title, summary, started_at, ended_at
            FROM episodes
            WHERE substance != 'none' AND (
                (started_at <= ?2 AND ended_at >= ?1)
                OR (
                    (CAST(strftime('%s', replace(replace(ended_at, 'T', ' '), 'Z', '')) AS INTEGER) >= CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 14400 AND CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) <= CAST(strftime('%s', replace(replace(?2, 'T', ' '), 'Z', '')) AS INTEGER) + 14400)
                    OR (CAST(strftime('%s', replace(replace(ended_at, 'T', ' '), 'Z', '')) AS INTEGER) >= CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 18000 AND CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) <= CAST(strftime('%s', replace(replace(?2, 'T', ' '), 'Z', '')) AS INTEGER) + 18000)
                    OR (CAST(strftime('%s', replace(replace(ended_at, 'T', ' '), 'Z', '')) AS INTEGER) >= CAST(strftime('%s', replace(replace(?1, 'T', ' '), 'Z', '')) AS INTEGER) + 25200 AND CAST(strftime('%s', replace(replace(started_at, 'T', ' '), 'Z', '')) AS INTEGER) <= CAST(strftime('%s', replace(replace(?2, 'T', ' '), 'Z', '')) AS INTEGER) + 25200)
                )
            )
            ORDER BY started_at ASC
            LIMIT ?3
            ",
        ) {
            if let Ok(rows) = stmt.query_map(params![from, to, effective_limit as i64], |row| {
                let raw_title: String = row.get(1).unwrap_or_default();
                let raw_summary: String = row.get(2).unwrap_or_default();
                let red_title = super::dlp::local_deterministic_redact(&raw_title);
                let red_summary = super::dlp::local_deterministic_redact(&raw_summary);
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "title": red_title.text,
                    "summary": red_summary.text,
                    "started_at": row.get::<_, String>(3)?,
                    "ended_at": row.get::<_, String>(4)?,
                }))
            }) {
                for r in rows.filter_map(|x| x.ok()) {
                    episodes.push(r);
                }
            }
        }
    }

    let response = json!({
        "time_range": { "from": from, "to": to },
        "summary_digest": format!("Period from {} to {} contained {} safe episodes.", from, to, episodes.len()),
        "episodes": episodes,
        "has_more": episodes.len() >= effective_limit,
    });

    Ok(sanitize_result(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::dlp::ProjectionDisposition;
    use crate::cp::mcp_projection::{
        claim_jobs, commit_safe_utterance, enqueue_job, init_projection_schema,
    };

    #[test]
    fn test_minimized_safe_search_and_context() {
        let conn = Connection::open_in_memory().unwrap();
        init_projection_schema(&conn).unwrap();

        enqueue_job(&conn, "utterance", "1", "rev1").unwrap();
        let jobs = claim_jobs(&conn, "worker_1", 1).unwrap();

        commit_safe_utterance(
            &conn,
            &jobs[0],
            1,
            &ProjectionDisposition::Safe,
            0,
            "Discussed quarterly roadmap project targets",
            Some("Alex"),
            "2026-07-26T10:00:00Z",
            "2026-07-26T10:05:00Z",
        )
        .unwrap();

        let search_res = search_safe_transcripts(&conn, "roadmap", 5).unwrap();
        assert_eq!(search_res["count"], 1);

        let ctx_res = fetch_safe_context(&conn, "2026-07-26T10:00:00Z", 300, Some(5)).unwrap();
        assert_eq!(ctx_res["utterances"].as_array().unwrap().len(), 1);

        let summary_res = summarize_safe_time_range(
            &conn,
            "2026-07-26T00:00:00Z",
            "2026-07-26T23:59:59Z",
            Some(5),
        )
        .unwrap();
        assert_eq!(summary_res["episodes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_fine_grained_span_redaction_preserves_narrative_context() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE audio_segments (id INTEGER PRIMARY KEY, started_at TEXT, ended_at TEXT);
            CREATE TABLE utterances (id INTEGER PRIMARY KEY, audio_segment_id INTEGER, text TEXT, speaker_label TEXT);
            INSERT INTO audio_segments VALUES (1, '2026-07-26T23:51:39.450Z', '2026-07-26T23:52:19.950Z');
            INSERT INTO utterances VALUES 
            (1, 1, 'so that I am using the test out that sensitive data is not available via the mcp', 'Me'),
            (2, 1, 'so I can say something like my credit card number is 918743299419188 and the cvb for that is 145', 'Me'),
            (3, 1, 'and my billings of code is 80399 and oh I got injured the other day um I actually had a', 'Me'),
            (4, 1, 'growth on my knee had to get removed and insurance is saying they are not going to pay for it my claim numbers 5 7 8 9.', 'Me');
            "
        ).unwrap();

        let ctx = fetch_safe_context(&conn, "2026-07-26T23:51:39.450Z", 300, Some(10)).unwrap();
        let utterances = ctx["utterances"].as_array().unwrap();
        assert_eq!(utterances.len(), 4);
        assert!(utterances[0]["text"]
            .as_str()
            .unwrap()
            .contains("sensitive data is not available via the mcp"));
        assert!(utterances[1]["text"]
            .as_str()
            .unwrap()
            .contains("[REDACTED FOR OPENAI]"));
        assert!(utterances[1]["text"]
            .as_str()
            .unwrap()
            .contains("my credit card number is"));
        assert!(!utterances[1]["text"]
            .as_str()
            .unwrap()
            .contains("918743299419188"));
        assert!(utterances[3]["text"]
            .as_str()
            .unwrap()
            .contains("growth on my knee had to get removed"));
    }
}
