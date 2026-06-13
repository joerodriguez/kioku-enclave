//! Query surface (ports `cloud/src/mcp.js` + `cloud/src/search.js`): the MCP
//! server (`POST /mcp`, JSON-RPC 2.0, stateless) and the REST mirrors
//! (`/api/search`, `/api/episodes`, `/api/episodes/:id/members`) the debugger
//! uses. All routes are auth-gated; tool logic calls the data-plane query code
//! (`search::search_all`, `timeline::fetch_context`) in-process.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
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
        .route("/api/episodes/{id}/members", get(rest_episode_members))
}

// ── Tool implementations (shared by MCP + REST) ─────────────────────────────────

async fn tool_search_transcripts(s: &CpState, user_id: &str, args: &Value) -> Value {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let from = args.get("from").and_then(|v| v.as_str()).map(String::from);
    let to = args.get("to").and_then(|v| v.as_str()).map(String::from);

    let req = SearchRequest {
        user_id: user_id.to_string(),
        query,
        time_start: from,
        time_end: to,
        limit,
        offset: 0,
        kinds: vec!["utterance".into(), "episode".into()],
        query_embedding: None,
    };
    let hits = s
        .store
        .with_user(user_id, |conn| search_all(conn, &req))
        .await
        .unwrap_or_default();
    let results = serde_json::to_value(&hits).unwrap_or_else(|_| json!([]));
    json!({ "results": results })
}

async fn tool_search_screenshots(s: &CpState, user_id: &str, args: &Value) -> Value {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let req = SearchRequest {
        user_id: user_id.to_string(),
        query,
        time_start: args.get("from").and_then(|v| v.as_str()).map(String::from),
        time_end: args.get("to").and_then(|v| v.as_str()).map(String::from),
        limit,
        offset: 0,
        kinds: vec!["screenshot".into()],
        query_embedding: None,
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
    list_episodes_value(s, user_id, from, to, max).await
}

async fn list_episodes_value(
    s: &CpState,
    user_id: &str,
    from: Option<String>,
    to: Option<String>,
    max: i64,
) -> Value {
    s.store
        .with_user(user_id, move |conn| {
            let mut stmt = conn.prepare(
                "SELECT e.id, e.started_at, e.ended_at, e.title, e.summary, e.type, \
                        (SELECT count(*) FROM episode_members m WHERE m.episode_id = e.id) \
                 FROM episodes e \
                 WHERE (?1 IS NULL OR e.ended_at >= ?1) AND (?2 IS NULL OR e.started_at <= ?2) \
                 ORDER BY e.started_at DESC LIMIT ?3",
            )?;
            let episodes: Vec<Value> = stmt
                .query_map(rusqlite::params![from, to, max], |r| {
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?,
                        "started_at": r.get::<_, String>(1)?,
                        "ended_at": r.get::<_, String>(2)?,
                        "title": r.get::<_, Option<String>>(3)?,
                        "summary": r.get::<_, Option<String>>(4)?,
                        "type": r.get::<_, Option<String>>(5)?,
                        "member_count": r.get::<_, i64>(6)?,
                        "source": "summarized",
                    }))
                })?
                .filter_map(|x| x.ok())
                .collect();
            Ok(json!({ "episodes": episodes }))
        })
        .await
        .unwrap_or_else(|_| json!({ "episodes": [] }))
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
            "description": "Full-text search over your transcribed speech (utterances) and episode summaries.",
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
                    "max_episodes": {"type": "number", "default": 20}
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
}

async fn rest_episodes(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(p): Query<EpisodesParams>,
) -> Response {
    Json(list_episodes_value(&s, &user.0, p.from, p.to, p.max_episodes.unwrap_or(50)).await)
        .into_response()
}

async fn rest_episode_members(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Response {
    let result = s
        .store
        .with_user(&user.0, move |conn| {
            let mut stmt = conn.prepare(
                "SELECT m.record_type, m.record_id FROM episode_members m WHERE m.episode_id = ?1",
            )?;
            let members: Vec<Value> = stmt
                .query_map([id], |r| {
                    Ok(json!({ "record_type": r.get::<_, String>(0)?, "record_id": r.get::<_, i64>(1)? }))
                })?
                .filter_map(|x| x.ok())
                .collect();
            Ok(json!({ "episode_id": id, "members": members }))
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
