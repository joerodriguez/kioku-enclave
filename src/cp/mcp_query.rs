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
pub fn search_safe_transcripts(conn: &Connection, query: &str, limit: usize) -> SqlResult<Value> {
    let effective_limit = limit.clamp(1, MAX_MINIMIZED_PAGE_SIZE);

    let mut stmt = conn.prepare(
        "
        SELECT u.id, u.sanitized_text, u.speaker_label, u.started_at, u.ended_at
        FROM mcp_safe_utterances u
        JOIN mcp_utterances_fts fts ON fts.rowid = u.id
        WHERE mcp_utterances_fts MATCH ?1 AND u.disposition != 'blocked'
        ORDER BY u.started_at DESC
        LIMIT ?2
        ",
    )?;

    let mut results = Vec::new();
    let rows = stmt.query_map(params![query, effective_limit as i64], |row| {
        let text: String = row.get(1)?;
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "text": text,
            "speaker": row.get::<_, Option<String>>(2)?,
            "started_at": row.get::<_, String>(3)?,
            "ended_at": row.get::<_, String>(4)?,
        }))
    })?;

    for r in rows {
        results.push(r?);
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

    let mut stmt = conn.prepare(
        "
        SELECT id, sanitized_text, speaker_label, started_at, ended_at
        FROM mcp_safe_utterances
        WHERE disposition != 'blocked'
        ORDER BY abs(strftime('%s', started_at) - strftime('%s', ?1)) ASC
        LIMIT ?2
        ",
    )?;

    let mut utterances = Vec::new();
    let rows = stmt.query_map(params![center_time, effective_limit as i64], |row| {
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "text": row.get::<_, String>(1)?,
            "speaker": row.get::<_, Option<String>>(2)?,
            "started_at": row.get::<_, String>(3)?,
            "ended_at": row.get::<_, String>(4)?,
        }))
    })?;

    for r in rows {
        utterances.push(r?);
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

    let mut stmt = conn.prepare(
        "
        SELECT episode_ref, sanitized_title, sanitized_summary, started_at, ended_at
        FROM mcp_safe_episodes
        WHERE disposition != 'blocked' AND started_at >= ?1 AND ended_at <= ?2
        ORDER BY started_at ASC
        LIMIT ?3
        ",
    )?;

    let mut episodes = Vec::new();
    let rows = stmt.query_map(params![from, to, effective_limit as i64], |row| {
        Ok(json!({
            "id": row.get::<_, String>(0)?,
            "title": row.get::<_, String>(1)?,
            "summary": row.get::<_, String>(2)?,
            "started_at": row.get::<_, String>(3)?,
            "ended_at": row.get::<_, String>(4)?,
        }))
    })?;

    for r in rows {
        episodes.push(r?);
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
}
