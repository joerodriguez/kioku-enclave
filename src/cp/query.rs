//! Query surface (ports `cloud/src/mcp.js` + `cloud/src/search.js`): the MCP
//! server (`POST /mcp`, JSON-RPC 2.0, stateless) and the REST mirrors
//! (`/api/search`, `/api/episodes`, `/api/episodes/:id/members`) the debugger
//! uses. All routes are auth-gated; tool logic calls the data-plane query code
//! (`search::search_all`, `timeline::fetch_context`) in-process.

use std::sync::Arc;

use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Extension, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::search::{search_all, SearchRequest};
use crate::timeline::ContextRequest;

use super::auth::AuthUser;
use super::{limits, CpState};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route("/mcp", post(mcp_endpoint))
        .route("/api/search", get(rest_search))
        .route("/api/episodes", get(rest_episodes))
        .route("/api/episodes/{id}", delete(rest_episode_delete))
        .route("/api/episodes/{id}/members", get(rest_episode_members))
        .route("/api/feed", get(rest_feed))
        .route(
            "/api/screenshot-images/plan",
            get(rest_screenshot_upload_plan),
        )
        .route("/api/screenshot-images", post(rest_screenshot_image_upload))
        .route(
            "/api/screenshot-images/{id}/content",
            get(rest_screenshot_image_content),
        )
        .route(
            "/api/preferences/episode-email",
            get(rest_get_preference).post(rest_set_preference),
        )
        .route(
            "/api/preferences/episode-email/connect",
            post(rest_connect_preference),
        )
}

// ── Tool implementations (shared by MCP + REST) ─────────────────────────────────

/// Embed the query text in-enclave for hybrid search. Returns `None` when the
/// engine is absent (FTS-only build) or on any embed error — search degrades
/// to FTS rather than failing. Inference is CPU-bound (~10–50 ms), so it runs
/// on the blocking pool instead of stalling the async worker.
async fn embed_query(s: &CpState, query: &str) -> Option<Vec<f32>> {
    let engine = s.embedding.as_ref()?.clone();
    let text = query.to_string();
    if text.trim().is_empty() {
        return None;
    }
    match tokio::task::spawn_blocking(move || engine.embed(&text)).await {
        Ok(Ok(v)) => Some(v),
        Ok(Err(e)) => {
            tracing::warn!("query embed failed ({e}) — falling back to FTS-only");
            None
        }
        Err(e) => {
            tracing::warn!("query embed task panicked ({e}) — falling back to FTS-only");
            None
        }
    }
}

async fn tool_search_transcripts(s: &CpState, user_id: &str, args: &Value) -> Value {
    let raw_query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let from = args.get("from").and_then(|v| v.as_str()).map(String::from);
    let to = args.get("to").and_then(|v| v.as_str()).map(String::from);

    // Strip a `speaker:Name` token BEFORE embedding so the vector reflects
    // only the content query (ADR-0006 Phase 3).
    let (query, speaker) = crate::search::extract_speaker_filter(&raw_query);
    let query_embedding = if query.trim().is_empty() {
        None
    } else {
        embed_query(s, &query).await
    };
    // Episodes are the PRIMARY result entity (ADR-0004): each carries its
    // exec summary + minute-timeline gists + a matched snippet, so an
    // assistant gets the high-level picture without digesting raw
    // transcripts. Utterance hits follow as `results` (drill-down evidence;
    // shape unchanged for existing clients). Episodes come back in relevance
    // order (rank / RRF), not time order.
    let ep_req = SearchRequest {
        user_id: user_id.to_string(),
        query: query.clone(),
        speaker: speaker.clone(),
        time_start: from.clone(),
        time_end: to.clone(),
        limit,
        offset: 0,
        kinds: vec!["episode".into()],
        query_embedding: query_embedding.clone(),
    };
    let utt_req = SearchRequest {
        user_id: user_id.to_string(),
        query,
        speaker,
        time_start: from,
        time_end: to,
        limit,
        offset: 0,
        kinds: vec!["utterance".into()],
        query_embedding,
    };
    let (episodes, utterances) = s
        .store
        .with_user(user_id, |conn| {
            Ok((
                crate::search::search_episodes(conn, &ep_req)?,
                search_all(conn, &utt_req)?,
            ))
        })
        .await
        .unwrap_or_default();
    json!({
        "episodes": serde_json::to_value(&episodes).unwrap_or_else(|_| json!([])),
        "results": serde_json::to_value(&utterances).unwrap_or_else(|_| json!([])),
    })
}

async fn tool_search_screenshots(s: &CpState, user_id: &str, args: &Value) -> Value {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let query_embedding = embed_query(s, &query).await;
    let req = SearchRequest {
        user_id: user_id.to_string(),
        query,
        speaker: None,
        time_start: args.get("from").and_then(|v| v.as_str()).map(String::from),
        time_end: args.get("to").and_then(|v| v.as_str()).map(String::from),
        limit,
        offset: 0,
        kinds: vec!["screenshot".into()],
        query_embedding,
    };
    let hits = s
        .store
        .with_user(user_id, |conn| search_all(conn, &req))
        .await
        .unwrap_or_default();
    json!({ "results": serde_json::to_value(&hits).unwrap_or_else(|_| json!([])) })
}

async fn tool_get_context(s: &CpState, user_id: &str, args: &Value) -> Value {
    let at = args
        .get("at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let window_secs = args
        .get("window_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);
    let minutes = ((window_secs / 2) / 60).max(1) as u32;
    let req = ContextRequest {
        user_id: user_id.to_string(),
        center: at,
        before_minutes: minutes,
        after_minutes: minutes,
        max_utterances: 200,
        max_screenshots: 100,
    };
    s.store
        .with_user(user_id, |conn| crate::timeline::fetch_context(conn, &req))
        .await
        .unwrap_or_else(|_| json!({ "utterances": [], "screenshots": [] }))
}

async fn tool_summarize_time_range(s: &CpState, user_id: &str, args: &Value) -> Value {
    let from = args
        .get("from")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let to = args
        .get("to")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let max_items = args
        .get("max_items")
        .and_then(|v| v.as_u64())
        .unwrap_or(200) as i64;
    let (f, t) = (from.clone(), to.clone());
    s.store
        .with_user(user_id, move |conn| {
            let utt: i64 = conn.query_row(
                "SELECT count(*) FROM utterances u JOIN audio_segments s ON s.id=u.audio_segment_id \
                 WHERE s.started_at >= ?1 AND s.started_at < ?2",
                rusqlite::params![f, t],
                |r| r.get(0),
            )?;
            let scr: i64 = conn.query_row(
                "SELECT count(*) FROM screenshots WHERE captured_at >= ?1 AND captured_at < ?2",
                rusqlite::params![f, t],
                |r| r.get(0),
            )?;
            let mut langs_stmt = conn.prepare(
                "SELECT DISTINCT language FROM utterances u JOIN audio_segments s ON s.id=u.audio_segment_id \
                 WHERE s.started_at >= ?1 AND s.started_at < ?2 AND language IS NOT NULL",
            )?;
            let languages: Vec<String> = langs_stmt
                .query_map(rusqlite::params![f, t], |r| r.get(0))?
                .filter_map(|x| x.ok())
                .collect();
            let mut apps_stmt = conn.prepare(
                "SELECT DISTINCT active_app FROM screenshots \
                 WHERE captured_at >= ?1 AND captured_at < ?2 AND active_app IS NOT NULL",
            )?;
            let apps: Vec<String> = apps_stmt
                .query_map(rusqlite::params![f, t], |r| r.get(0))?
                .filter_map(|x| x.ok())
                .collect();
            // Chronological digest of utterances.
            let mut dig_stmt = conn.prepare(
                "SELECT s.started_at, u.speaker_label, u.text \
                 FROM utterances u JOIN audio_segments s ON s.id=u.audio_segment_id \
                 WHERE s.started_at >= ?1 AND s.started_at < ?2 \
                 ORDER BY s.started_at ASC LIMIT ?3",
            )?;
            let digest: Vec<Value> = dig_stmt
                .query_map(rusqlite::params![f, t, max_items], |r| {
                    Ok(json!({
                        "at": r.get::<_, String>(0)?,
                        "speaker": r.get::<_, String>(1)?,
                        "text": r.get::<_, String>(2)?,
                    }))
                })?
                .filter_map(|x| x.ok())
                .collect();
            Ok(json!({
                "from": f, "to": t,
                "counts": { "utterances": utt, "screenshots": scr },
                "languages": languages,
                "apps_seen": apps,
                "digest": digest,
            }))
        })
        .await
        .unwrap_or_else(|_| json!({ "error": "range query failed" }))
}

async fn tool_list_episodes(s: &Arc<CpState>, user_id: &str, args: &Value) -> Value {
    // Fire-and-forget freshness (matches the Node maybeTriggerSummarize).
    super::summarizer::maybe_trigger(Arc::clone(s), user_id.to_string());
    let from = args.get("from").and_then(|v| v.as_str()).map(String::from);
    let to = args.get("to").and_then(|v| v.as_str()).map(String::from);
    let max = args
        .get("max_episodes")
        .and_then(|v| v.as_u64())
        .unwrap_or(20) as i64;
    let include_low = args.get("include_low").is_some_and(value_is_truthy);
    list_episodes_value(s, user_id, from, to, max, include_low).await
}

fn value_is_truthy(value: &Value) -> bool {
    value.as_bool().unwrap_or(false)
        || value.as_i64().is_some_and(|v| v == 1)
        || value.as_str().is_some_and(string_is_truthy)
}

fn string_is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Parse a stored JSON-array column (participants/languages/action_items)
/// into a Value, defaulting to an empty array.
fn json_array_column(raw: Option<String>) -> Value {
    raw.and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]))
}

/// Registrable host of a URL for the "top domains" chips (strips `www.`).
fn url_domain(url: &str) -> Option<String> {
    let host = reqwest::Url::parse(url).ok()?.host_str()?.to_lowercase();
    Some(host.strip_prefix("www.").unwrap_or(&host).to_string())
}

async fn list_episodes_value(
    s: &CpState,
    user_id: &str,
    from: Option<String>,
    to: Option<String>,
    max: i64,
    include_low: bool,
) -> Value {
    s.store
        .with_user(user_id, move |conn| {
            // Episodes are the ONLY mode (the Mac's local heuristic grouping is
            // gone) — this response carries everything the debugger card needs:
            // LLM fields (participants/languages/action_items) plus per-type
            // member counts and top apps/domains derived from member
            // screenshots.
            let mut stmt = conn.prepare(
                "SELECT e.id, e.started_at, e.ended_at, e.title, e.summary, e.type, \
                        e.participants, e.languages, e.action_items, \
                        (SELECT count(*) FROM episode_members m \
                          WHERE m.episode_id = e.id AND m.record_type = 'utterance'), \
                        (SELECT count(*) FROM episode_members m \
                          WHERE m.episode_id = e.id AND m.record_type = 'screenshot'), \
                        e.minute_summaries, e.substance, e.visual_evidence, \
                        e.finalized_at, e.finalization_version, \
                        fb.overview, fb.decisions, fb.action_items, fb.important_links, fb.open_questions \
                 FROM episodes e \
                 LEFT JOIN episode_final_briefs fb ON fb.episode_id = e.id \
                 WHERE (?1 IS NULL OR e.ended_at >= ?1) AND (?2 IS NULL OR e.started_at <= ?2) \
                   AND (?3 = 1 OR e.substance != 'none') \
                 ORDER BY e.started_at DESC LIMIT ?4",
            )?;
            let mut episodes: Vec<Value> = stmt
                .query_map(rusqlite::params![from, to, include_low, max], |r| {
                    let utt: i64 = r.get(9)?;
                    let scr: i64 = r.get(10)?;

                    let finalized_at: Option<String> = r.get(14)?;
                    let finalization_version: Option<i32> = r.get(15)?;

                    let final_brief = if let Some(overview) = r.get::<_, Option<String>>(16)? {
                        Some(json!({
                            "overview": overview,
                            "decisions": serde_json::from_str::<Value>(&r.get::<_, String>(17)?).unwrap_or(json!([])),
                            "action_items": serde_json::from_str::<Value>(&r.get::<_, String>(18)?).unwrap_or(json!([])),
                            "important_links": serde_json::from_str::<Value>(&r.get::<_, String>(19)?).unwrap_or(json!([])),
                            "open_questions": serde_json::from_str::<Value>(&r.get::<_, String>(20)?).unwrap_or(json!([])),
                        }))
                    } else {
                        None
                    };

                    Ok(json!({
                        "id": r.get::<_, i64>(0)?,
                        "started_at": r.get::<_, String>(1)?,
                        "ended_at": r.get::<_, String>(2)?,
                        "title": r.get::<_, Option<String>>(3)?,
                        "summary": r.get::<_, Option<String>>(4)?,
                        "type": r.get::<_, Option<String>>(5)?,
                        "participants": json_array_column(r.get::<_, Option<String>>(6)?),
                        "languages": json_array_column(r.get::<_, Option<String>>(7)?),
                        "action_items": json_array_column(r.get::<_, Option<String>>(8)?),
                        // Minute-timeline gists (ADR-0004); the episode page
                        // renders these, falling back to client-derived gists
                        // when empty (pre-feature episodes).
                        "minute_summaries": json_array_column(r.get::<_, Option<String>>(11)?),
                        "substance": r.get::<_, String>(12)?,
                        "visual_evidence": r.get::<_, String>(13)?,
                        "utterance_count": utt,
                        "screenshot_count": scr,
                        "member_count": utt + scr,
                        "source": "summarized",
                        "finalized_at": finalized_at,
                        "finalization_version": finalization_version,
                        "final_brief": final_brief,
                    }))
                })?
                .filter_map(|x| x.ok())
                .collect();

            let hidden_count: i64 = if include_low {
                0
            } else {
                conn.query_row(
                    "SELECT count(*) FROM episodes e \
                     WHERE (?1 IS NULL OR e.ended_at >= ?1) \
                       AND (?2 IS NULL OR e.started_at <= ?2) \
                       AND e.substance = 'none'",
                    rusqlite::params![from, to],
                    |r| r.get(0),
                )?
            };

            // Top apps + domains per episode from member screenshots (top 3
            // each, by frequency). One grouped query, merged in memory.
            {
                let mut apps = conn.prepare(
                    "SELECT m.episode_id, c.active_app, c.url, count(*) AS n \
                     FROM episode_members m JOIN screenshots c ON c.id = m.record_id \
                     WHERE m.record_type = 'screenshot' \
                     GROUP BY m.episode_id, c.active_app, c.url",
                )?;
                use std::collections::HashMap;
                let mut app_counts: HashMap<i64, HashMap<String, i64>> = HashMap::new();
                let mut dom_counts: HashMap<i64, HashMap<String, i64>> = HashMap::new();
                let rows = apps.query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })?;
                for row in rows.filter_map(|x| x.ok()) {
                    let (ep_id, app, url, n) = row;
                    if let Some(app) = app.filter(|a| !a.is_empty()) {
                        *app_counts.entry(ep_id).or_default().entry(app).or_insert(0) += n;
                    }
                    if let Some(dom) = url.as_deref().and_then(url_domain) {
                        *dom_counts.entry(ep_id).or_default().entry(dom).or_insert(0) += n;
                    }
                }
                let top3 = |m: Option<&HashMap<String, i64>>| -> Vec<String> {
                    let mut v: Vec<(&String, &i64)> =
                        m.map(|m| m.iter().collect()).unwrap_or_default();
                    v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                    v.into_iter().take(3).map(|(k, _)| k.clone()).collect()
                };
                for ep in &mut episodes {
                    let id = ep.get("id").and_then(|v| v.as_i64()).unwrap_or(-1);
                    ep["top_apps"] = json!(top3(app_counts.get(&id)));
                    ep["top_domains"] = json!(top3(dom_counts.get(&id)));
                }
            }

            // episode_count is part of the debugger contract: the Episodes tab
            // header renders `${data.episode_count} episodes`.
            Ok(json!({
                "episode_count": episodes.len(),
                "hidden_count": hidden_count,
                "episodes": episodes
            }))
        })
        .await
        .unwrap_or_else(|_| json!({ "episode_count": 0, "hidden_count": 0, "episodes": [] }))
}

async fn tool_get_capture_status(s: &CpState, user_id: &str) -> Value {
    s.store
        .with_user(user_id, |conn| {
            let utt: i64 = conn.query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))?;
            let scr: i64 = conn.query_row("SELECT count(*) FROM screenshots", [], |r| r.get(0))?;
            let eps: i64 = conn.query_row("SELECT count(*) FROM episodes", [], |r| r.get(0))?;
            let last_u: Option<String> = conn
                .query_row("SELECT s.started_at FROM utterances u JOIN audio_segments s ON s.id=u.audio_segment_id ORDER BY s.started_at DESC LIMIT 1", [], |r| r.get(0))
                .ok();
            let last_s: Option<String> = conn
                .query_row("SELECT captured_at FROM screenshots ORDER BY captured_at DESC LIMIT 1", [], |r| r.get(0))
                .ok();
            Ok(json!({
                "total_utterances": utt,
                "total_screenshots": scr,
                "episode_count": eps,
                "last_utterance_at": last_u,
                "last_screenshot_at": last_s,
            }))
        })
        .await
        .unwrap_or_else(|_| json!({ "error": "stats failed" }))
}

// ── MCP JSON-RPC endpoint ───────────────────────────────────────────────────────

fn tool_definitions() -> Value {
    json!([
        {
            "name": "search_transcripts",
            "description": "Search your archive. Returns matching EPISODES first (relevance-ranked, each with its executive summary, minute-by-minute timeline gists, and a matched snippet — usually enough to answer without raw transcripts), then matching utterances as drill-down evidence.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "from": {"type": "string", "description": "ISO-8601 lower bound"},
                    "to": {"type": "string", "description": "ISO-8601 upper bound"},
                    "limit": {"type": "number", "default": 10}
                },
                "required": ["query"]
            }
        },
        {
            "name": "search_screenshots",
            "description": "Full-text search over OCR'd screen text, app names, and window titles.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "limit": {"type": "number", "default": 10}
                },
                "required": ["query"]
            }
        },
        {
            "name": "get_context",
            "description": "Interleaved timeline (utterances + screenshot OCR) centered on a moment.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "at": {"type": "string", "description": "ISO-8601 timestamp"},
                    "window_seconds": {"type": "number", "default": 300}
                },
                "required": ["at"]
            }
        },
        {
            "name": "summarize_time_range",
            "description": "Counts, languages, apps, and a chronological digest for a time range.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "max_items": {"type": "number", "default": 200}
                },
                "required": ["from", "to"]
            }
        },
        {
            "name": "list_episodes",
            "description": "Activity-block overview: summarized episodes newest-first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "gap_minutes": {"type": "number", "default": 15},
                    "max_episodes": {"type": "number", "default": 20},
                    "include_low": {"type": "boolean", "default": false, "description": "Include substance=none episodes normally hidden from browse."}
                }
            }
        },
        {
            "name": "get_capture_status",
            "description": "Per-user totals and latest captured timestamps.",
            "inputSchema": {"type": "object", "properties": {}}
        }
    ])
}

async fn dispatch_tool(s: &Arc<CpState>, user_id: &str, name: &str, args: &Value) -> Option<Value> {
    Some(match name {
        "search_transcripts" => tool_search_transcripts(s, user_id, args).await,
        "search_screenshots" => tool_search_screenshots(s, user_id, args).await,
        "get_context" => tool_get_context(s, user_id, args).await,
        "summarize_time_range" => tool_summarize_time_range(s, user_id, args).await,
        "list_episodes" => tool_list_episodes(s, user_id, args).await,
        "get_capture_status" => tool_get_capture_status(s, user_id).await,
        _ => return None,
    })
}

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

async fn mcp_endpoint(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(rpc): Json<JsonRpcRequest>,
) -> Response {
    let user_id = user.0;

    // MCP-call rate limit / quota (counts tools/call only).
    if rpc.method == "tools/call" {
        if !s.mcp_limiter.consume(&user_id).await {
            return rpc_error(&rpc.id, -32000, "rate_limited");
        }
        let limits = (
            s.config.quota_utterances_per_day,
            s.config.quota_screenshots_per_day,
            s.config.quota_mcp_calls_per_day,
        );
        if let Ok(q) = limits::daily_quota(&s.control, &user_id, 0, 0, 1, limits).await {
            if !q.allowed {
                return rpc_error(&rpc.id, -32000, "quota_exceeded");
            }
        }
    }

    match rpc.method.as_str() {
        "initialize" => rpc_ok(
            &rpc.id,
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "kioku-enclave", "version": env!("CARGO_PKG_VERSION") }
            }),
        ),
        "notifications/initialized" | "notifications/cancelled" => {
            (StatusCode::ACCEPTED, "").into_response()
        }
        "ping" => rpc_ok(&rpc.id, json!({})),
        "tools/list" => rpc_ok(&rpc.id, json!({ "tools": tool_definitions() })),
        "tools/call" => {
            let name = rpc
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = rpc
                .params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let started = std::time::Instant::now();
            match dispatch_tool(&s, &user_id, name, &args).await {
                Some(result) => {
                    let _ = limits::log_query(
                        &s.control,
                        &user_id,
                        "mcp",
                        name,
                        args.get("query").and_then(|v| v.as_str()).map(String::from),
                        result
                            .get("results")
                            .and_then(|r| r.as_array())
                            .map(|a| a.len() as i64)
                            .unwrap_or(0),
                        started.elapsed().as_millis() as i64,
                    )
                    .await;
                    let text = serde_json::to_string(&result).unwrap_or_else(|_| "{}".into());
                    rpc_ok(
                        &rpc.id,
                        json!({ "content": [{ "type": "text", "text": text }] }),
                    )
                }
                None => rpc_error(&rpc.id, -32601, &format!("unknown tool: {name}")),
            }
        }
        other => rpc_error(&rpc.id, -32601, &format!("method not found: {other}")),
    }
}

fn rpc_ok(id: &Value, result: Value) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }))
        .into_response()
}

// ── REST mirrors (debugger) ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<usize>,
}

async fn rest_search(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(p): Query<SearchParams>,
) -> Response {
    let Some(q) = p.q else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "missing_query"})),
        )
            .into_response();
    };
    let args =
        json!({ "query": q, "from": p.from, "to": p.to, "limit": p.limit.unwrap_or(10).min(50) });
    Json(tool_search_transcripts(&s, &user.0, &args).await).into_response()
}

#[derive(Deserialize)]
struct EpisodesParams {
    from: Option<String>,
    to: Option<String>,
    max_episodes: Option<i64>,
    include_low: Option<String>,
}

async fn rest_episodes(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(p): Query<EpisodesParams>,
) -> Response {
    let include_low = p.include_low.as_deref().is_some_and(string_is_truthy);
    Json(
        list_episodes_value(
            &s,
            &user.0,
            p.from,
            p.to,
            p.max_episodes.unwrap_or(50),
            include_low,
        )
        .await,
    )
    .into_response()
}

/// DELETE /api/episodes/{id} — purge an episode AND its member raw records
/// (utterances, screenshots, emptied segments, vectors, FTS entries). The
/// response carries the deleted records' source_keys so the caller (the Mac
/// debugger's local server) can purge the matching LOCAL rows and media files
/// — without that, a forced resync would re-upload the content.
async fn rest_episode_delete(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Response {
    let result = s
        .store
        .with_user(&user.0, move |conn| {
            crate::episodes::purge_episode(conn, id)
        })
        .await;
    match result {
        Ok(Some(p)) => {
            // Persist before answering — a purge that only lives in the
            // cached handle isn't a purge.
            if let Err(e) = s.store.save_user(&user.0).await {
                tracing::error!(error = %e, "episode purge: save failed");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "save_failed"})),
                )
                    .into_response();
            }
            tracing::info!(
                user_id = %user.0,
                episode_id = id,
                utterances = p.deleted_utterances,
                screenshots = p.deleted_screenshots,
                segments = p.deleted_segments,
                "episode purged"
            );
            Json(json!({
                "deleted": true,
                "episode_id": id,
                "deleted_utterances": p.deleted_utterances,
                "deleted_screenshots": p.deleted_screenshots,
                "deleted_segments": p.deleted_segments,
                "utterance_source_keys": p.utterance_source_keys,
                "screenshot_source_keys": p.screenshot_source_keys,
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "episode_not_found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, episode_id = id, "episode purge failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "enclave_unavailable"})),
            )
                .into_response()
        }
    }
}

async fn rest_episode_members(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Response {
    // Returns the episode's member records WITH their content (utterance text,
    // screenshot app/title/URL + OCR excerpt), chronological — the debugger's
    // expanded episode view renders this as the raw evidence behind the
    // summary. The caller is the authenticated owner of the data; these same
    // rows are already reachable via /api/search and /v1/context.
    let result = s
        .store
        .with_user(&user.0, move |conn| {
            // source_key ({device_id}:{segment_local_id}:{local_id} for
            // utterances, {device_id}:{local_id} for screenshots) lets the
            // debugger — running on the Mac beside the local store — join a
            // member back to its local row and serve the actual screenshot
            // image (full-resolution originals stay on the Mac; see ADR-0010 for Cloud Screenshot Evidence).
            let mut us = conn.prepare(
                "SELECT u.id, s.started_at, u.speaker_label, u.language, u.text, u.source_key \
                 FROM episode_members m \
                 JOIN utterances u ON u.id = m.record_id \
                 JOIN audio_segments s ON s.id = u.audio_segment_id \
                 WHERE m.episode_id = ?1 AND m.record_type = 'utterance'",
            )?;
            let mut members: Vec<(String, Value)> = us
                .query_map([id], |r| {
                    let ts: String = r.get(1)?;
                    Ok((
                        ts.clone(),
                        json!({
                            "record_type": "utterance",
                            "record_id": r.get::<_, i64>(0)?,
                            "started_at": ts,
                            "speaker_label": r.get::<_, String>(2)?,
                            "language": r.get::<_, Option<String>>(3)?,
                            "text": r.get::<_, String>(4)?,
                            "source_key": r.get::<_, Option<String>>(5)?,
                        }),
                    ))
                })?
                .filter_map(|x| x.ok())
                .collect();

            let mut ss = conn.prepare(
                "SELECT c.id, c.captured_at, c.active_app, c.window_title, c.url, \
                        substr(c.ocr_text,1,2000), c.source_key, img.id \
                 FROM episode_members m \
                 JOIN screenshots c ON c.id = m.record_id \
                 LEFT JOIN screenshot_images img ON img.source_key = c.source_key \
                 WHERE m.episode_id = ?1 AND m.record_type = 'screenshot' AND c.is_duplicate = 0",
            )?;
            members.extend(
                ss.query_map([id], |r| {
                    let ts: String = r.get(1)?;
                    Ok((
                        ts.clone(),
                        json!({
                            "record_type": "screenshot",
                            "record_id": r.get::<_, i64>(0)?,
                            "captured_at": ts,
                            "active_app": r.get::<_, Option<String>>(2)?,
                            "window_title": r.get::<_, Option<String>>(3)?,
                            "url": r.get::<_, Option<String>>(4)?,
                            "ocr_excerpt": r.get::<_, Option<String>>(5)?,
                            "source_key": r.get::<_, Option<String>>(6)?,
                            "cloud_image_id": r.get::<_, Option<String>>(7)?,
                        }),
                    ))
                })?
                .filter_map(|x| x.ok()),
            );

            members.sort_by(|a, b| a.0.cmp(&b.0));
            let members: Vec<Value> = members.into_iter().map(|(_, v)| v).collect();
            Ok(json!({ "episode_id": id, "member_count": members.len(), "members": members }))
        })
        .await;
    match result {
        Ok(v) => Json(v).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "enclave_unavailable"})),
        )
            .into_response(),
    }
}

#[derive(Debug, serde::Deserialize)]
struct FeedParams {
    from: Option<String>,
    to: Option<String>,
    limit: Option<usize>,
    before: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
struct FeedRecord {
    kind: String, // "utterance" | "screenshot"
    id: i64,
    at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    speaker_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_app: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ocr_excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_key: Option<String>,
    episode_id: Option<i64>,
}

fn query_feed(
    conn: &rusqlite::Connection,
    p: &FeedParams,
) -> crate::error::Result<serde_json::Value> {
    let limit = p.limit.unwrap_or(50).min(200);

    // 1. Fetch utterances
    let mut u_sql = r#"
        WITH utterance_at AS (
            SELECT u.id, u.speaker_label, u.text, u.source_key,
                   strftime('%Y-%m-%dT%H:%M:%fZ', s.started_at, '+' || u.start_offset_seconds || ' seconds') AS at
            FROM utterances u
            JOIN audio_segments s ON s.id = u.audio_segment_id
        )
        SELECT id, speaker_label, text, at, source_key
        FROM utterance_at
        WHERE at IS NOT NULL
    "#.to_string();

    let mut u_params: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(from) = &p.from {
        u_sql.push_str(" AND at >= ?");
        u_params.push(rusqlite::types::Value::Text(from.clone()));
    }
    if let Some(to) = &p.to {
        u_sql.push_str(" AND at <= ?");
        u_params.push(rusqlite::types::Value::Text(to.clone()));
    }
    if let Some(before) = &p.before {
        u_sql.push_str(" AND at < ?");
        u_params.push(rusqlite::types::Value::Text(before.clone()));
    }
    u_sql.push_str(" ORDER BY at DESC LIMIT ?");
    u_params.push(rusqlite::types::Value::Integer(limit as i64));

    let mut stmt = conn.prepare(&u_sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(u_params))?;
    let mut records = Vec::new();

    while let Some(row) = rows.next()? {
        records.push(FeedRecord {
            kind: "utterance".to_string(),
            id: row.get(0)?,
            at: row.get(3)?,
            speaker_label: row.get(1)?,
            text: row.get(2)?,
            active_app: None,
            window_title: None,
            url: None,
            ocr_excerpt: None,
            source_key: row.get(4)?,
            episode_id: None,
        });
    }

    // 2. Fetch screenshots
    let mut s_sql = r#"
        SELECT id, captured_at, active_app, window_title, url, ocr_text, source_key
        FROM screenshots
        WHERE captured_at IS NOT NULL AND is_duplicate = 0
    "#
    .to_string();

    let mut s_params: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(from) = &p.from {
        s_sql.push_str(" AND captured_at >= ?");
        s_params.push(rusqlite::types::Value::Text(from.clone()));
    }
    if let Some(to) = &p.to {
        s_sql.push_str(" AND captured_at <= ?");
        s_params.push(rusqlite::types::Value::Text(to.clone()));
    }
    if let Some(before) = &p.before {
        s_sql.push_str(" AND captured_at < ?");
        s_params.push(rusqlite::types::Value::Text(before.clone()));
    }
    s_sql.push_str(" ORDER BY captured_at DESC LIMIT ?");
    s_params.push(rusqlite::types::Value::Integer(limit as i64));

    let mut stmt = conn.prepare(&s_sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(s_params))?;

    while let Some(row) = rows.next()? {
        let ocr_text: Option<String> = row.get(5)?;
        let ocr_excerpt = ocr_text.map(|t| {
            if t.chars().count() > 300 {
                t.chars().take(300).collect::<String>()
            } else {
                t
            }
        });
        records.push(FeedRecord {
            kind: "screenshot".to_string(),
            id: row.get(0)?,
            at: row.get(1)?,
            speaker_label: None,
            text: None,
            active_app: row.get(2)?,
            window_title: row.get(3)?,
            url: row.get(4)?,
            ocr_excerpt,
            source_key: row.get(6)?,
            episode_id: None,
        });
    }

    // 3. Merge & Sort & Limit
    records.sort_by(|a, b| b.at.cmp(&a.at));
    records.truncate(limit);

    // 4. Lookup episode_id memberships
    if !records.is_empty() {
        let mut u_ids = Vec::new();
        let mut s_ids = Vec::new();
        for r in &records {
            if r.kind == "utterance" {
                u_ids.push(r.id);
            } else {
                s_ids.push(r.id);
            }
        }

        if !u_ids.is_empty() {
            let placeholders = u_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let u_members_sql = format!(
                "SELECT record_id, episode_id FROM episode_members WHERE record_type = 'utterance' AND record_id IN ({})",
                placeholders
            );
            let mut stmt = conn.prepare(&u_members_sql)?;
            let params = u_ids.iter().map(|&id| rusqlite::types::Value::Integer(id));
            let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
            let mut u_map = std::collections::HashMap::new();
            while let Some(row) = rows.next()? {
                u_map.insert(row.get::<_, i64>(0)?, row.get::<_, i64>(1)?);
            }
            for r in &mut records {
                if r.kind == "utterance" {
                    r.episode_id = u_map.get(&r.id).copied();
                }
            }
        }

        if !s_ids.is_empty() {
            let placeholders = s_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let s_members_sql = format!(
                "SELECT record_id, episode_id FROM episode_members WHERE record_type = 'screenshot' AND record_id IN ({})",
                placeholders
            );
            let mut stmt = conn.prepare(&s_members_sql)?;
            let params = s_ids.iter().map(|&id| rusqlite::types::Value::Integer(id));
            let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
            let mut s_map = std::collections::HashMap::new();
            while let Some(row) = rows.next()? {
                s_map.insert(row.get::<_, i64>(0)?, row.get::<_, i64>(1)?);
            }
            for r in &mut records {
                if r.kind == "screenshot" {
                    r.episode_id = s_map.get(&r.id).copied();
                }
            }
        }
    }

    let next_before = if records.len() == limit {
        records.last().map(|r| r.at.clone())
    } else {
        None
    };

    Ok(serde_json::json!({
        "records": records,
        "next_before": next_before,
    }))
}

async fn rest_feed(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(p): Query<FeedParams>,
) -> Response {
    let result = s
        .store
        .with_user(&user.0, move |conn| query_feed(conn, &p))
        .await;

    match result {
        Ok(val) => Json(val).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "feed query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct PlanParams {
    device_id: String,
    after: Option<String>,
}

async fn rest_screenshot_upload_plan(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(p): Query<PlanParams>,
) -> Response {
    if let Err(e) = crate::store::validate_user_id(&user.0) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    let result = s
        .store
        .with_user(&user.0, move |conn| {
            let prefix = format!("{}:", p.device_id);

            let mut stmt = conn.prepare(
                "SELECT e.id, e.started_at, e.ended_at, c.source_key
             FROM episodes e
             JOIN episode_members m ON m.episode_id = e.id AND m.record_type = 'screenshot'
             JOIN screenshots c ON c.id = m.record_id
             WHERE e.substance = 'normal' AND e.visual_evidence = 'useful'
               AND c.source_key LIKE ?1
               AND c.is_duplicate = 0
               AND (?2 IS NULL OR c.captured_at >= ?2)
               AND c.source_key NOT IN (SELECT source_key FROM screenshot_images)
             ORDER BY e.started_at DESC, c.captured_at ASC",
            )?;

            let rows = stmt.query_map(rusqlite::params![format!("{}%", prefix), p.after], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;

            let mut episodes_map = std::collections::BTreeMap::new();
            for r in rows {
                let (ep_id, start, end, sk) = r?;
                let entry = episodes_map.entry(ep_id).or_insert_with(|| {
                    json!({
                        "id": ep_id,
                        "started_at": start,
                        "ended_at": end,
                        "source_keys": Vec::<String>::new()
                    })
                });
                entry.as_object_mut().unwrap()["source_keys"]
                    .as_array_mut()
                    .unwrap()
                    .push(Value::String(sk));
            }

            let episodes_list: Vec<Value> = episodes_map.into_values().collect();
            Ok(json!({ "episodes": episodes_list }))
        })
        .await;

    match result {
        Ok(val) => Json(val).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "screenshot upload plan failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error"})),
            )
                .into_response()
        }
    }
}

async fn rest_screenshot_image_upload(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    mut multipart: Multipart,
) -> Response {
    let user_id = user.0;
    if let Err(e) = crate::store::validate_user_id(&user_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    let mut image_bytes = Vec::new();
    let mut captured_at = None;
    let mut episode_id = None;
    let mut source_key = None;
    let mut width = None;
    let mut height = None;
    let mut req_sha256 = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        if name == "image" {
            let mut stream = field;
            while let Ok(Some(chunk)) = stream.chunk().await {
                if image_bytes.len() + chunk.len() > 153_600 {
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "payload too large (max 150 KiB)",
                    )
                        .into_response();
                }
                image_bytes.extend_from_slice(&chunk);
            }
        } else {
            let value = match field.text().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            match name.as_str() {
                "captured_at" => captured_at = Some(value),
                "episode_id" => episode_id = value.parse::<i64>().ok(),
                "source_key" => source_key = Some(value),
                "width" => width = value.parse::<i32>().ok(),
                "height" => height = value.parse::<i32>().ok(),
                "sha256" => req_sha256 = Some(value),
                _ => {}
            }
        }
    }

    let (
        Some(captured_at),
        Some(episode_id),
        Some(source_key),
        Some(width),
        Some(height),
        Some(req_sha256),
    ) = (
        captured_at,
        episode_id,
        source_key,
        width,
        height,
        req_sha256,
    )
    else {
        return (StatusCode::BAD_REQUEST, "missing fields").into_response();
    };

    if image_bytes.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing image bytes").into_response();
    }

    // Verify SHA-256
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&image_bytes);
    let computed_hash = format!("{:x}", hasher.finalize());
    if computed_hash != req_sha256 {
        return (StatusCode::BAD_REQUEST, "SHA-256 mismatch").into_response();
    }

    // 1. Get wrapped DEK or generate one
    let user_id_cloned = user_id.clone();
    let wrapped_opt_res = s
        .store
        .with_user(&user_id_cloned, |conn| {
            let mut stmt =
                conn.prepare("SELECT value FROM app_metadata WHERE key = 'wrapped_media_dek'")?;
            let val: Option<String> = stmt.query_row([], |r| r.get(0)).ok();
            Ok(val)
        })
        .await;

    let wrapped_opt = match wrapped_opt_res {
        Ok(w) => w,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database query failed: {}", e),
            )
                .into_response()
        }
    };

    let (media_dek, wrapped_b64) = match wrapped_opt {
        Some(wrapped) => match crate::crypto::load_dek(s.store.kms.as_ref(), &wrapped).await {
            Ok(dek) => (dek, wrapped),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Load DEK failed: {}", e),
                )
                    .into_response()
            }
        },
        None => match crate::crypto::generate_and_wrap_dek(s.store.kms.as_ref()).await {
            Ok((dek, wrapped)) => {
                let wrapped_clone = wrapped.clone();
                let user_id_cloned = user_id.clone();
                let save_res = s.store.with_user(&user_id_cloned, move |conn| {
                        conn.execute(
                            "INSERT OR REPLACE INTO app_metadata (key, value) VALUES ('wrapped_media_dek', ?1)",
                            [&wrapped_clone],
                        )?;
                        Ok(())
                    }).await;
                if let Err(e) = save_res {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Save DEK failed: {}", e),
                    )
                        .into_response();
                }
                (dek, wrapped)
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Generate DEK failed: {}", e),
                )
                    .into_response()
            }
        },
    };

    // 2. Encrypt JPEG bytes using media DEK and user_id as AAD
    let encrypted_data =
        match crate::crypto::encrypt_blob_with_aad(&media_dek, &image_bytes, user_id.as_bytes()) {
            Ok(d) => d,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Encryption failed: {}", e),
                )
                    .into_response()
            }
        };

    // 3. Generate random 128-bit hex key as opaque ID
    let mut random_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_bytes);
    let opaque_key: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let object_key = format!("media/{}", opaque_key);

    // 4. Upload to GCS
    if let Err(e) = s
        .store
        .put_media(&object_key, &encrypted_data, &wrapped_b64)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("GCS upload failed: {}", e),
        )
            .into_response();
    }

    // 5. Insert tracking record in SQLite database
    let user_id_cloned = user_id.clone();
    let insert_res = s.store.with_user(&user_id_cloned, {
        let object_key_clone = object_key.clone();
        let source_key_clone = source_key.clone();
        let captured_at_clone = captured_at.clone();
        let sha256_clone = req_sha256.clone();
        let image_len = image_bytes.len() as i64;
        let opaque_key_clone = opaque_key.clone();
        move |conn| {
            let screenshot_id: i64 = conn.query_row(
                "SELECT id FROM screenshots WHERE source_key = ?1",
                [&source_key_clone],
                |r| r.get(0),
            )?;

            conn.execute(
                "INSERT INTO screenshot_images (id, screenshot_id, episode_id, source_key, captured_at, object_key, mime_type, width, height, byte_length, sha256) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'image/jpeg', ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    opaque_key_clone,
                    screenshot_id,
                    episode_id,
                    source_key_clone,
                    captured_at_clone,
                    object_key_clone,
                    width,
                    height,
                    image_len,
                    sha256_clone,
                ],
            )?;
            Ok(())
        }
    }).await;

    if let Err(e) = insert_res {
        let _ = s.store.delete_media(&object_key).await;
        return (
            StatusCode::BAD_REQUEST,
            format!("Database insert failed: {}", e),
        )
            .into_response();
    }

    // Save user SQLite database state
    if let Err(e) = s.store.save_user(&user_id).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database save failed: {}", e),
        )
            .into_response();
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": opaque_key,
            "object_key": object_key,
            "mime_type": "image/jpeg",
            "width": width,
            "height": height,
            "byte_length": image_bytes.len(),
            "sha256": req_sha256,
        })),
    )
        .into_response()
}

async fn rest_screenshot_image_content(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Response {
    let user_id = user.0;
    if let Err(e) = crate::store::validate_user_id(&user_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // 1. Retrieve the object_key from the database
    let user_id_cloned = user_id.clone();
    let query_res = s
        .store
        .with_user(&user_id_cloned, {
            let id_clone = id.clone();
            move |conn| {
                let object_key: String = conn.query_row(
                    "SELECT object_key FROM screenshot_images WHERE id = ?1",
                    [&id_clone],
                    |r| r.get(0),
                )?;
                Ok(object_key)
            }
        })
        .await;

    let object_key = match query_res {
        Ok(ok) => ok,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    // 2. Fetch the encrypted object from GCS
    let gcs_resp = match s.store.get_media(&object_key).await {
        Ok(r) => r,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    // 3. Load user's media DEK
    let user_id_cloned = user_id.clone();
    let wrapped_opt_res = s
        .store
        .with_user(&user_id_cloned, |conn| {
            let mut stmt =
                conn.prepare("SELECT value FROM app_metadata WHERE key = 'wrapped_media_dek'")?;
            let val: Option<String> = stmt.query_row([], |r| r.get(0)).ok();
            Ok(val)
        })
        .await;

    let wrapped_opt = match wrapped_opt_res {
        Ok(w) => w,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database query failed: {}", e),
            )
                .into_response()
        }
    };

    let wrapped_b64 = match wrapped_opt {
        Some(w) => w,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let media_dek = match crate::crypto::load_dek(s.store.kms.as_ref(), &wrapped_b64).await {
        Ok(dek) => dek,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Load DEK failed: {}", e),
            )
                .into_response()
        }
    };

    // 4. Decrypt object using media DEK and user_id as AAD
    let decrypted_bytes = match crate::crypto::decrypt_blob_with_aad(
        &media_dek,
        &gcs_resp.ciphertext,
        user_id.as_bytes(),
    ) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Decryption failed: {}", e),
            )
                .into_response()
        }
    };

    (
        StatusCode::OK,
        [("Content-Type", "image/jpeg")],
        decrypted_bytes,
    )
        .into_response()
}

#[derive(Deserialize)]
struct SetPreferenceRequest {
    enabled: bool,
}

async fn rest_get_preference(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let user_id = user.0;
    let cfg = match s.control.get_gmail_config(&user_id).await {
        Ok(c) => c,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    match cfg {
        Some(c) => Json(json!({
            "enabled": c.enabled,
            "recipient": c.gmail_email,
            "gmail_connected": c.refresh_token.is_some(),
            "reconnect_required": c.reconnect_required,
            "enabled_at": c.enabled_at,
        }))
        .into_response(),
        None => {
            // Check user email
            let email = match s.control.user_email(&user_id).await {
                Ok(Some(e)) => e,
                _ => return StatusCode::UNAUTHORIZED.into_response(),
            };
            Json(json!({
                "enabled": false,
                "recipient": Some(email),
                "gmail_connected": false,
                "reconnect_required": false,
                "enabled_at": None::<String>,
            }))
            .into_response()
        }
    }
}

async fn rest_set_preference(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<SetPreferenceRequest>,
) -> Response {
    let user_id = user.0;

    // Check if configuration exists
    let mut cfg = match s.control.get_gmail_config(&user_id).await {
        Ok(Some(c)) => c,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "reconnect_required", "message": "Gmail account not connected"})),
            )
                .into_response();
        }
    };

    if req.enabled {
        if cfg.refresh_token.is_none() {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error": "reconnect_required", "message": "Gmail credentials missing"}),
                ),
            )
                .into_response();
        }
        cfg.enabled = true;
        let now_iso = crate::cp::isotime::format_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );
        cfg.enabled_at = Some(now_iso);
    } else {
        cfg.enabled = false;
        let refresh_token = cfg.refresh_token.take();

        if let Some(token) = refresh_token {
            tokio::spawn(async move {
                let http = reqwest::Client::new();
                let _ = http
                    .post("https://oauth2.googleapis.com/revoke")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(format!("token={}", token))
                    .send()
                    .await;
            });
        }

        let user_id_cloned = user_id.clone();
        let db_res = s.store.with_user(&user_id_cloned, |conn| {
            conn.execute(
                "UPDATE episode_deliveries SET state = 'cancelled', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE state IN ('pending', 'retry')",
                [],
            )?;
            Ok(())
        }).await;
        if let Err(e) = db_res {
            tracing::warn!(user_id = %user_id, error = %e, "failed to cancel pending deliveries on disable");
        } else {
            let _ = s.store.save_user(&user_id).await;
        }
    }

    if let Err(e) = s.control.upsert_gmail_config(cfg).await {
        tracing::warn!(error = %e, "failed to update preference");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    StatusCode::OK.into_response()
}

async fn rest_connect_preference(
    state: State<Arc<CpState>>,
    user: Extension<AuthUser>,
) -> Response {
    super::oauth::connect_gmail_url(state, user).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{FakeGcs, FakeKms};
    use crate::store::Store;

    #[test]
    fn include_low_accepts_documented_and_mcp_truthy_values() {
        assert!(string_is_truthy("1"));
        assert!(string_is_truthy(" TRUE "));
        assert!(value_is_truthy(&json!(true)));
        assert!(value_is_truthy(&json!(1)));
        assert!(!string_is_truthy("0"));
        assert!(!value_is_truthy(&json!(false)));
    }

    #[tokio::test]
    async fn feed_fuses_kinds_chronologically_newest_first() {
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        store.with_user("user-1", |conn| {
            conn.execute("INSERT INTO audio_segments (id, started_at, ended_at, duration_seconds, source_type) VALUES (1, '2026-01-01T10:00:00.000Z', '2026-01-01T10:10:00.000Z', 600.0, 'mic')", [])?;
            conn.execute("INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label) VALUES (1, 1, 10.0, 15.0, 'hello from mic', 'Me')", [])?;

            conn.execute("INSERT INTO screenshots (id, captured_at, active_app, window_title, ocr_text) VALUES (1, '2026-01-01T10:00:05.000Z', 'Chrome', 'GitHub', 'some ocr')", [])?;
            conn.execute("INSERT INTO screenshots (id, captured_at, active_app, window_title, ocr_text) VALUES (2, '2026-01-01T10:00:15.000Z', 'Safari', 'Docs', 'other ocr')", [])?;

            let p = FeedParams {
                from: None,
                to: None,
                limit: None,
                before: None,
            };
            let val = query_feed(conn, &p).unwrap();
            let records: Vec<FeedRecord> = serde_json::from_value(val.get("records").unwrap().clone()).unwrap();

            assert_eq!(records.len(), 3);
            assert_eq!(records[0].kind, "screenshot");
            assert_eq!(records[0].id, 2);
            assert_eq!(records[0].at, "2026-01-01T10:00:15.000Z");

            assert_eq!(records[1].kind, "utterance");
            assert_eq!(records[1].id, 1);
            assert_eq!(records[1].at, "2026-01-01T10:00:10.000Z");

            assert_eq!(records[2].kind, "screenshot");
            assert_eq!(records[2].id, 1);
            assert_eq!(records[2].at, "2026-01-01T10:00:05.000Z");

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn feed_records_carry_episode_id_when_member_of_episode() {
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        store.with_user("user-1", |conn| {
            conn.execute("INSERT INTO audio_segments (id, started_at, ended_at, duration_seconds, source_type) VALUES (1, '2026-01-01T10:00:00.000Z', '2026-01-01T10:10:00.000Z', 600.0, 'mic')", [])?;
            conn.execute("INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label) VALUES (1, 1, 10.0, 15.0, 'hello', 'Me')", [])?;
            conn.execute("INSERT INTO screenshots (id, captured_at, ocr_text) VALUES (1, '2026-01-01T10:00:05.000Z', 'ocr')", [])?;

            conn.execute("INSERT INTO episodes (id, started_at, ended_at, title, summary) VALUES (99, '2026-01-01T10:00:00.000Z', '2026-01-01T10:10:00.000Z', 'Meeting', 'desc')", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (99, 'utterance', 1)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (99, 'screenshot', 1)", [])?;

            let p = FeedParams {
                from: None,
                to: None,
                limit: None,
                before: None,
            };
            let val = query_feed(conn, &p).unwrap();
            let records: Vec<FeedRecord> = serde_json::from_value(val.get("records").unwrap().clone()).unwrap();

            assert_eq!(records.len(), 2);
            assert_eq!(records[0].episode_id, Some(99));
            assert_eq!(records[1].episode_id, Some(99));

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn feed_pagination_keyset_no_dup_no_gap() {
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        store.with_user("user-1", |conn| {
            conn.execute("INSERT INTO audio_segments (id, started_at, ended_at, duration_seconds, source_type) VALUES (1, '2026-01-01T10:00:00.000Z', '2026-01-01T10:10:00.000Z', 600.0, 'mic')", [])?;
            conn.execute("INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label) VALUES (1, 1, 10.0, 15.0, 'one', 'Me')", [])?;
            conn.execute("INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label) VALUES (2, 1, 20.0, 25.0, 'two', 'Me')", [])?;
            conn.execute("INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label) VALUES (3, 1, 30.0, 35.0, 'three', 'Me')", [])?;

            let p1 = FeedParams {
                from: None,
                to: None,
                limit: Some(2),
                before: None,
            };
            let val1 = query_feed(conn, &p1).unwrap();
            let recs1: Vec<FeedRecord> = serde_json::from_value(val1.get("records").unwrap().clone()).unwrap();
            let next1 = val1.get("next_before").unwrap().as_str().map(|s| s.to_string());

            assert_eq!(recs1.len(), 2);
            assert_eq!(recs1[0].text.as_deref(), Some("three"));
            assert_eq!(recs1[1].text.as_deref(), Some("two"));
            assert!(next1.is_some());

            let p2 = FeedParams {
                from: None,
                to: None,
                limit: Some(2),
                before: next1,
            };
            let val2 = query_feed(conn, &p2).unwrap();
            let recs2: Vec<FeedRecord> = serde_json::from_value(val2.get("records").unwrap().clone()).unwrap();
            let next2 = val2.get("next_before").unwrap();

            assert_eq!(recs2.len(), 1);
            assert_eq!(recs2[0].text.as_deref(), Some("one"));
            assert!(next2.is_null());

            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn feed_respects_time_range_and_limit_cap() {
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        store
            .with_user("user-1", |conn| {
                // 250 screenshots one second apart — enough to exceed the 200 cap.
                for i in 0..250 {
                    conn.execute(
                        "INSERT INTO screenshots (captured_at, ocr_text) VALUES (?1, 'x')",
                        [format!("2026-01-01T10:{:02}:{:02}.000Z", i / 60, i % 60)],
                    )?;
                }

                // limit caps at 200 even when a larger value is requested.
                let p = FeedParams {
                    from: None,
                    to: None,
                    limit: Some(10_000),
                    before: None,
                };
                let val = query_feed(conn, &p).unwrap();
                let recs: Vec<FeedRecord> =
                    serde_json::from_value(val.get("records").unwrap().clone()).unwrap();
                assert_eq!(recs.len(), 200, "limit must cap at 200");

                // from/to bound the window inclusively.
                let p = FeedParams {
                    from: Some("2026-01-01T10:00:10.000Z".into()),
                    to: Some("2026-01-01T10:00:19.000Z".into()),
                    limit: None,
                    before: None,
                };
                let val = query_feed(conn, &p).unwrap();
                let recs: Vec<FeedRecord> =
                    serde_json::from_value(val.get("records").unwrap().clone()).unwrap();
                assert_eq!(recs.len(), 10);
                assert!(recs
                    .iter()
                    .all(|r| r.at.as_str() >= "2026-01-01T10:00:10.000Z"
                        && r.at.as_str() <= "2026-01-01T10:00:19.000Z"));

                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_rest_screenshot_upload_plan() {
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let user_id = "plan_test_user";

        store.with_user(user_id, |conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS screenshots (id INTEGER PRIMARY KEY, captured_at TEXT NOT NULL, source_key TEXT UNIQUE, is_duplicate INTEGER NOT NULL DEFAULT 0);
                 CREATE TABLE IF NOT EXISTS episodes (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, ended_at TEXT NOT NULL, substance TEXT NOT NULL, visual_evidence TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS episode_members (episode_id INTEGER NOT NULL, record_type TEXT NOT NULL, record_id INTEGER NOT NULL, PRIMARY KEY(episode_id, record_type, record_id));
                 CREATE TABLE IF NOT EXISTS screenshot_images (id TEXT PRIMARY KEY, screenshot_id INTEGER NOT NULL, episode_id INTEGER NOT NULL, source_key TEXT UNIQUE, captured_at TEXT NOT NULL, object_key TEXT UNIQUE, mime_type TEXT NOT NULL, width INTEGER NOT NULL, height INTEGER NOT NULL, byte_length INTEGER NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL);"
            )?;

            conn.execute("INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES (1, '2026-01-01T10:00:00Z', 'dev1:1', 0)", [])?;
            conn.execute("INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES (2, '2026-01-01T10:01:00Z', 'dev1:2', 0)", [])?;
            conn.execute("INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES (3, '2026-01-01T10:02:00Z', 'dev1:3', 1)", [])?;
            conn.execute("INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES (4, '2026-01-01T10:03:00Z', 'dev1:4', 0)", [])?;

            conn.execute("INSERT INTO episodes (id, started_at, ended_at, substance, visual_evidence) VALUES (10, '2026-01-01T10:00:00Z', '2026-01-01T10:05:00Z', 'normal', 'useful')", [])?;
            conn.execute("INSERT INTO episodes (id, started_at, ended_at, substance, visual_evidence) VALUES (11, '2026-01-01T10:05:00Z', '2026-01-01T10:10:00Z', 'low', 'useful')", [])?;
            conn.execute("INSERT INTO episodes (id, started_at, ended_at, substance, visual_evidence) VALUES (12, '2026-01-01T10:10:00Z', '2026-01-01T10:15:00Z', 'normal', 'none')", [])?;

            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 1)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 2)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 3)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 4)", [])?;

            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (11, 'screenshot', 2)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (12, 'screenshot', 2)", [])?;

            conn.execute(
                "INSERT INTO screenshot_images (id, screenshot_id, episode_id, source_key, captured_at, object_key, mime_type, width, height, byte_length, sha256, created_at) \
                 VALUES ('img4', 4, 10, 'dev1:4', '2026-01-01T10:03:00Z', 'media/img4', 'image/jpeg', 100, 100, 100, 'sha', '2026-01-01T10:04:00Z')",
                []
            )?;
            Ok(())
        }).await.unwrap();

        let result = store
            .with_user(user_id, |conn| {
                let prefix = "dev1:";
                let mut stmt = conn.prepare(
                    "SELECT e.id, e.started_at, e.ended_at, c.source_key
                 FROM episodes e
                 JOIN episode_members m ON m.episode_id = e.id AND m.record_type = 'screenshot'
                 JOIN screenshots c ON c.id = m.record_id
                 WHERE e.substance = 'normal' AND e.visual_evidence = 'useful'
                   AND c.source_key LIKE ?1
                   AND c.is_duplicate = 0
                   AND c.source_key NOT IN (SELECT source_key FROM screenshot_images)
                 ORDER BY e.started_at DESC, c.captured_at ASC",
                )?;
                let rows = stmt.query_map([format!("{}%", prefix)], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })?;
                let mut list = Vec::new();
                for r in rows {
                    list.push(r?);
                }
                Ok(list)
            })
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, 10);
        assert_eq!(result[0].3, "dev1:1");
        assert_eq!(result[1].3, "dev1:2");
    }
}
