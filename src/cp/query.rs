//! Query surface: the MCP
//! server (`POST /mcp`, JSON-RPC 2.0, stateless) and the REST mirrors
//! (`/api/search`, `/api/episodes`, `/api/episodes/:id`,
//! `/api/episodes/:id/members`) the debugger
//! uses. All routes are auth-gated; tool logic calls the data-plane query code
//! (`search::search_all`, `timeline::fetch_context`) in-process.

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Router,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::search::{search_all, SearchRequest};
use crate::timeline::ContextRequest;

use super::auth::AuthUser;
use super::{limits, CpState};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const MAX_SCREENSHOT_IMAGE_BYTES: usize = 150 * 1024;
const MAX_SCREENSHOT_MULTIPART_BYTES: usize = MAX_SCREENSHOT_IMAGE_BYTES + 16 * 1024;
const MAX_SCREENSHOT_METADATA_FIELD_BYTES: usize = 512;
const MAX_EPISODE_IMAGE_BYTES: i64 = 4000 * 1024;
const MAX_EPISODE_IMAGES: i64 = 24;
const MAX_SCREENSHOT_LONG_EDGE: u16 = 960;
const MEDIA_DEK_METADATA_KEY: &str = "wrapped_media_dek";

pub fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route("/mcp", post(mcp_endpoint))
        .route("/api/search", get(rest_search))
        .route("/api/episodes", get(rest_episodes))
        .route(
            "/api/episodes/{id}",
            get(rest_episode).delete(rest_episode_delete),
        )
        .route("/api/episodes/{id}/members", get(rest_episode_members))
        .route("/api/feed", get(rest_feed))
        .route(
            "/api/screenshot-images/plan",
            get(rest_screenshot_upload_plan),
        )
        .route(
            "/api/screenshot-images",
            post(rest_screenshot_image_upload)
                .layer(DefaultBodyLimit::max(MAX_SCREENSHOT_MULTIPART_BYTES)),
        )
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
    query_episodes_value(s, user_id, from, to, max, include_low, None)
        .await
        .unwrap_or_else(|_| json!({ "episode_count": 0, "hidden_count": 0, "episodes": [] }))
}

/// Shared list/detail query. Keeping the optional id filter here ensures the
/// direct detail endpoint cannot drift from the list row's fields, visibility
/// rules, derived counts, or final-brief shape.
async fn query_episodes_value(
    s: &CpState,
    user_id: &str,
    from: Option<String>,
    to: Option<String>,
    max: i64,
    include_low: bool,
    episode_id: Option<i64>,
) -> crate::error::Result<Value> {
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
                   AND (?5 IS NULL OR e.id = ?5) \
                 ORDER BY e.started_at DESC LIMIT ?4",
            )?;
            let mut episodes: Vec<Value> = stmt
                .query_map(
                    rusqlite::params![from, to, include_low, max, episode_id],
                    |r| {
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
                    },
                )?
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
                       AND (?1 IS NULL OR m.episode_id = ?1) \
                     GROUP BY m.episode_id, c.active_app, c.url",
                )?;
                use std::collections::HashMap;
                let mut app_counts: HashMap<i64, HashMap<String, i64>> = HashMap::new();
                let mut dom_counts: HashMap<i64, HashMap<String, i64>> = HashMap::new();
                let rows = apps.query_map([episode_id], |r| {
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

#[derive(Deserialize)]
struct EpisodeParams {
    include_low: Option<String>,
}

/// GET /api/episodes/{id} — fetch one episode without depending on its
/// position in the newest-first list. The default visibility matches browse:
/// substance=none is indistinguishable from an absent row unless the caller
/// explicitly opts into `include_low=1`.
async fn rest_episode(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<i64>,
    Query(p): Query<EpisodeParams>,
) -> Response {
    let include_low = p.include_low.as_deref().is_some_and(string_is_truthy);
    match query_episodes_value(&s, &user.0, None, None, 1, include_low, Some(id)).await {
        Ok(data) => match data
            .get("episodes")
            .and_then(Value::as_array)
            .and_then(|episodes| episodes.first())
        {
            Some(episode) => Json(episode.clone()).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "episode_not_found"})),
            )
                .into_response(),
        },
        Err(e) => {
            tracing::error!(error = %e, episode_id = id, "episode detail query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "server_error"})),
            )
                .into_response()
        }
    }
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
    // Remove encrypted media before dropping its durable DB references. If a
    // GCS deletion fails, the operation remains retryable and no orphan is
    // silently left behind.
    let media_keys = match s
        .store
        .with_user(&user.0, |conn| {
            let table_exists: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='screenshot_images'",
                [],
                |row| row.get(0),
            )?;
            if table_exists == 0 {
                return Ok(Vec::new());
            }
            let mut stmt =
                conn.prepare("SELECT object_key FROM screenshot_images WHERE episode_id = ?1")?;
            let keys = stmt
                .query_map([id], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(keys)
        })
        .await
    {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!(error = %e, episode_id = id, "episode purge media lookup failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "enclave_unavailable"})),
            )
                .into_response();
        }
    };
    for object_key in &media_keys {
        if let Err(e) = s.store.delete_media(object_key).await {
            tracing::error!(error = %e, episode_id = id, "episode purge media deletion failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "media_delete_failed"})),
            )
                .into_response();
        }
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredScreenshotImage {
    id: String,
    episode_id: i64,
    captured_at: String,
    object_key: String,
    mime_type: String,
    width: i32,
    height: i32,
    byte_length: i64,
    sha256: String,
}

impl StoredScreenshotImage {
    fn response_json(&self) -> Value {
        json!({
            "id": self.id,
            "object_key": self.object_key,
            "mime_type": self.mime_type,
            "width": self.width,
            "height": self.height,
            "byte_length": self.byte_length,
            "sha256": self.sha256,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScreenshotUploadTarget {
    New {
        screenshot_id: i64,
        captured_at: String,
    },
    Existing(StoredScreenshotImage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScreenshotRecordOutcome {
    Created(StoredScreenshotImage),
    Existing(StoredScreenshotImage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedJpeg {
    width: i32,
    height: i32,
    byte_length: i64,
    sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JpegUploadError {
    PayloadTooLarge,
    UnsupportedMediaType,
    Invalid(&'static str),
}

fn validate_uploaded_jpeg(
    image_bytes: &[u8],
    content_type: Option<&str>,
    claimed_width: i32,
    claimed_height: i32,
    requested_sha256: &str,
) -> std::result::Result<ValidatedJpeg, JpegUploadError> {
    if image_bytes.len() > MAX_SCREENSHOT_IMAGE_BYTES {
        return Err(JpegUploadError::PayloadTooLarge);
    }
    if content_type != Some("image/jpeg") {
        return Err(JpegUploadError::UnsupportedMediaType);
    }

    let requested_sha256 = requested_sha256.trim();
    if requested_sha256.len() != 64
        || !requested_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(JpegUploadError::Invalid("invalid SHA-256"));
    }

    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(image_bytes);
    let computed_sha256 = format!("{:x}", hasher.finalize());
    if !computed_sha256.eq_ignore_ascii_case(requested_sha256) {
        return Err(JpegUploadError::Invalid("SHA-256 mismatch"));
    }

    // Read dimensions before decoding so a tiny compressed file cannot cause
    // an attacker-chosen giant allocation. Decode is still mandatory: a valid
    // SOF header alone is not proof that the JPEG body is valid.
    let mut decoder = jpeg_decoder::Decoder::new(std::io::Cursor::new(image_bytes));
    decoder
        .read_info()
        .map_err(|_| JpegUploadError::Invalid("invalid JPEG"))?;
    let info = decoder
        .info()
        .ok_or(JpegUploadError::Invalid("invalid JPEG"))?;
    if info.width.max(info.height) > MAX_SCREENSHOT_LONG_EDGE {
        return Err(JpegUploadError::Invalid(
            "JPEG long edge exceeds 960 pixels",
        ));
    }
    if i32::from(info.width) != claimed_width || i32::from(info.height) != claimed_height {
        return Err(JpegUploadError::Invalid(
            "JPEG dimensions do not match multipart metadata",
        ));
    }
    decoder.set_max_decoding_buffer_size(
        usize::from(MAX_SCREENSHOT_LONG_EDGE) * usize::from(MAX_SCREENSHOT_LONG_EDGE) * 4,
    );
    decoder
        .decode()
        .map_err(|_| JpegUploadError::Invalid("invalid JPEG"))?;

    Ok(ValidatedJpeg {
        width: i32::from(info.width),
        height: i32::from(info.height),
        byte_length: image_bytes.len() as i64,
        sha256: computed_sha256,
    })
}

fn stored_screenshot_image(
    conn: &Connection,
    source_key: &str,
) -> crate::error::Result<Option<StoredScreenshotImage>> {
    Ok(conn
        .query_row(
            "SELECT id, episode_id, captured_at, object_key, mime_type, width, height, byte_length, sha256 \
             FROM screenshot_images WHERE source_key = ?1",
            [source_key],
            |row| {
                Ok(StoredScreenshotImage {
                    id: row.get(0)?,
                    episode_id: row.get(1)?,
                    captured_at: row.get(2)?,
                    object_key: row.get(3)?,
                    mime_type: row.get(4)?,
                    width: row.get(5)?,
                    height: row.get(6)?,
                    byte_length: row.get(7)?,
                    sha256: row.get(8)?,
                })
            },
        )
        .optional()?)
}

fn validate_screenshot_upload_target(
    conn: &Connection,
    episode_id: i64,
    source_key: &str,
    requested_captured_at: &str,
    sha256: &str,
    byte_length: i64,
) -> crate::error::Result<ScreenshotUploadTarget> {
    let member = conn
        .query_row(
            "SELECT c.id, c.captured_at, c.is_duplicate, e.substance, e.visual_evidence \
             FROM screenshots c \
             JOIN episode_members m \
               ON m.record_type = 'screenshot' AND m.record_id = c.id \
             JOIN episodes e ON e.id = m.episode_id \
             WHERE c.source_key = ?1 AND e.id = ?2",
            rusqlite::params![source_key, episode_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;

    let Some((screenshot_id, captured_at, is_duplicate, substance, visual_evidence)) = member
    else {
        return Err(crate::error::EnclaveError::InvalidRequest(
            "source_key is not a screenshot member of the claimed episode".into(),
        ));
    };
    if is_duplicate != 0 {
        return Err(crate::error::EnclaveError::InvalidRequest(
            "duplicate screenshots are not eligible for cloud evidence".into(),
        ));
    }
    if substance != "normal" || visual_evidence != "useful" {
        return Err(crate::error::EnclaveError::InvalidRequest(
            "episode is not eligible for cloud screenshot evidence".into(),
        ));
    }
    if captured_at != requested_captured_at {
        return Err(crate::error::EnclaveError::InvalidRequest(
            "captured_at does not match the synced screenshot".into(),
        ));
    }

    if let Some(existing) = stored_screenshot_image(conn, source_key)? {
        if existing.episode_id != episode_id {
            return Err(crate::error::EnclaveError::Conflict(
                "source_key is already attached to another episode".into(),
            ));
        }
        if !existing.sha256.eq_ignore_ascii_case(sha256) {
            return Err(crate::error::EnclaveError::Conflict(
                "source_key was already uploaded with different bytes".into(),
            ));
        }
        return Ok(ScreenshotUploadTarget::Existing(existing));
    }

    let (image_count, stored_bytes): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(byte_length), 0) \
         FROM screenshot_images WHERE episode_id = ?1",
        [episode_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if image_count >= MAX_EPISODE_IMAGES {
        return Err(crate::error::EnclaveError::Conflict(
            "episode already has the maximum of four images".into(),
        ));
    }
    if stored_bytes.saturating_add(byte_length) > MAX_EPISODE_IMAGE_BYTES {
        return Err(crate::error::EnclaveError::Conflict(
            "episode image budget exceeds 600 KiB".into(),
        ));
    }

    Ok(ScreenshotUploadTarget::New {
        screenshot_id,
        captured_at,
    })
}

fn install_media_dek_candidate(
    conn: &Connection,
    candidate_wrapped_dek: &str,
) -> crate::error::Result<String> {
    conn.execute(
        "INSERT INTO app_metadata (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO NOTHING",
        rusqlite::params![MEDIA_DEK_METADATA_KEY, candidate_wrapped_dek],
    )?;
    Ok(conn.query_row(
        "SELECT value FROM app_metadata WHERE key = ?1",
        [MEDIA_DEK_METADATA_KEY],
        |row| row.get(0),
    )?)
}

#[allow(clippy::too_many_arguments)]
fn record_screenshot_image(
    conn: &Connection,
    image_id: &str,
    object_key: &str,
    episode_id: i64,
    source_key: &str,
    requested_captured_at: &str,
    jpeg: &ValidatedJpeg,
) -> crate::error::Result<ScreenshotRecordOutcome> {
    let tx = rusqlite::Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let target = validate_screenshot_upload_target(
        &tx,
        episode_id,
        source_key,
        requested_captured_at,
        &jpeg.sha256,
        jpeg.byte_length,
    )?;

    let (screenshot_id, captured_at) = match target {
        ScreenshotUploadTarget::New {
            screenshot_id,
            captured_at,
        } => (screenshot_id, captured_at),
        ScreenshotUploadTarget::Existing(existing) => {
            tx.commit()?;
            return Ok(ScreenshotRecordOutcome::Existing(existing));
        }
    };

    tx.execute(
        "INSERT INTO screenshot_images \
         (id, screenshot_id, episode_id, source_key, captured_at, object_key, mime_type, width, height, byte_length, sha256) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'image/jpeg', ?7, ?8, ?9, ?10)",
        rusqlite::params![
            image_id,
            screenshot_id,
            episode_id,
            source_key,
            captured_at,
            object_key,
            jpeg.width,
            jpeg.height,
            jpeg.byte_length,
            jpeg.sha256,
        ],
    )?;

    let created = StoredScreenshotImage {
        id: image_id.to_string(),
        episode_id,
        captured_at,
        object_key: object_key.to_string(),
        mime_type: "image/jpeg".into(),
        width: jpeg.width,
        height: jpeg.height,
        byte_length: jpeg.byte_length,
        sha256: jpeg.sha256.clone(),
    };
    tx.commit()?;
    Ok(ScreenshotRecordOutcome::Created(created))
}

#[derive(Deserialize)]
struct PlanParams {
    device_id: String,
    after: Option<String>,
}

fn query_screenshot_upload_plan(conn: &Connection, p: &PlanParams) -> crate::error::Result<Value> {
    let prefix = format!("{}:", p.device_id);
    let mut stmt = conn.prepare(
        "SELECT e.id, e.started_at, e.ended_at, c.source_key, e.minute_summaries, \
                COALESCE(usage.image_count, 0), COALESCE(usage.image_bytes, 0) \
         FROM episodes e \
         JOIN episode_members m \
           ON m.episode_id = e.id AND m.record_type = 'screenshot' \
         JOIN screenshots c ON c.id = m.record_id \
         LEFT JOIN ( \
             SELECT episode_id, COUNT(*) AS image_count, \
                    COALESCE(SUM(byte_length), 0) AS image_bytes \
             FROM screenshot_images GROUP BY episode_id \
         ) usage ON usage.episode_id = e.id \
         WHERE e.substance = 'normal' AND e.visual_evidence = 'useful' \
           AND c.source_key LIKE ?1 \
           AND c.is_duplicate = 0 \
           AND (?2 IS NULL OR c.captured_at >= ?2) \
           AND c.source_key NOT IN (SELECT source_key FROM screenshot_images) \
           AND COALESCE(usage.image_count, 0) < ?3 \
           AND COALESCE(usage.image_bytes, 0) < ?4 \
         ORDER BY e.started_at DESC, c.captured_at ASC",
    )?;

    let rows = stmt.query_map(
        rusqlite::params![
            format!("{}%", prefix),
            p.after,
            MAX_EPISODE_IMAGES,
            MAX_EPISODE_IMAGE_BYTES
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        },
    )?;

    #[derive(Debug)]
    struct PlannedEpisode {
        started_at: String,
        ended_at: String,
        remaining_images: i64,
        remaining_bytes: i64,
        gist_boundaries: Vec<String>,
        source_keys: Vec<String>,
    }

    let mut episodes = std::collections::BTreeMap::<i64, PlannedEpisode>::new();
    for row in rows {
        let (
            episode_id,
            started_at,
            ended_at,
            source_key,
            minute_summaries,
            image_count,
            image_bytes,
        ) = row?;
        let remaining_images = (MAX_EPISODE_IMAGES - image_count).max(0);
        let remaining_bytes = (MAX_EPISODE_IMAGE_BYTES - image_bytes).max(0);
        let gist_boundaries = minute_summaries
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Vec<Value>>(raw).ok())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|minute| minute.get("start")?.as_str().map(str::to_owned))
            .collect();
        let episode = episodes
            .entry(episode_id)
            .or_insert_with(|| PlannedEpisode {
                started_at,
                ended_at,
                remaining_images,
                remaining_bytes,
                gist_boundaries,
                source_keys: Vec::new(),
            });
        // Return the full eligible candidate set so the Mac can rank novelty
        // and temporal coverage. The explicit remaining budgets bound how
        // many it may choose; the transactional upload check is authoritative.
        episode.source_keys.push(source_key);
    }

    let episodes = episodes
        .into_iter()
        .filter_map(|(id, episode)| {
            (!episode.source_keys.is_empty()).then(|| {
                json!({
                    "id": id,
                    "started_at": episode.started_at,
                    "ended_at": episode.ended_at,
                    "source_keys": episode.source_keys,
                    "remaining_images": episode.remaining_images,
                    "remaining_bytes": episode.remaining_bytes,
                    "gist_boundaries": episode.gist_boundaries,
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({ "episodes": episodes }))
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
        .with_user(&user.0, move |conn| query_screenshot_upload_plan(conn, &p))
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
    let mut image_content_type = None;
    let mut saw_image = false;
    let mut captured_at = None;
    let mut episode_id = None;
    let mut source_key = None;
    let mut width = None;
    let mut height = None;
    let mut req_sha256 = None;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid multipart body").into_response(),
        };
        let name = field.name().unwrap_or_default().to_string();
        if name == "image" {
            if saw_image {
                return (StatusCode::BAD_REQUEST, "multiple image fields").into_response();
            }
            saw_image = true;
            image_content_type = field.content_type().map(str::to_owned);
            let mut stream = field;
            loop {
                let chunk = match stream.chunk().await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break,
                    Err(_) => {
                        return (StatusCode::BAD_REQUEST, "invalid image field").into_response()
                    }
                };
                if image_bytes.len() + chunk.len() > MAX_SCREENSHOT_IMAGE_BYTES {
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
                Err(_) => {
                    return (StatusCode::BAD_REQUEST, "invalid multipart field").into_response()
                }
            };
            if value.len() > MAX_SCREENSHOT_METADATA_FIELD_BYTES {
                return (StatusCode::BAD_REQUEST, "multipart field too long").into_response();
            }
            match name.as_str() {
                "captured_at" if captured_at.is_none() => captured_at = Some(value),
                "episode_id" if episode_id.is_none() => match value.parse::<i64>() {
                    Ok(value) => episode_id = Some(value),
                    Err(_) => {
                        return (StatusCode::BAD_REQUEST, "invalid episode_id").into_response()
                    }
                },
                "source_key" if source_key.is_none() => source_key = Some(value),
                "width" if width.is_none() => match value.parse::<i32>() {
                    Ok(value) => width = Some(value),
                    Err(_) => return (StatusCode::BAD_REQUEST, "invalid width").into_response(),
                },
                "height" if height.is_none() => match value.parse::<i32>() {
                    Ok(value) => height = Some(value),
                    Err(_) => return (StatusCode::BAD_REQUEST, "invalid height").into_response(),
                },
                "sha256" if req_sha256.is_none() => req_sha256 = Some(value),
                "captured_at" | "episode_id" | "source_key" | "width" | "height" | "sha256" => {
                    return (StatusCode::BAD_REQUEST, "duplicate multipart field").into_response()
                }
                _ => return (StatusCode::BAD_REQUEST, "unknown multipart field").into_response(),
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

    let jpeg = match validate_uploaded_jpeg(
        &image_bytes,
        image_content_type.as_deref(),
        width,
        height,
        &req_sha256,
    ) {
        Ok(jpeg) => jpeg,
        Err(JpegUploadError::PayloadTooLarge) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload too large (max 150 KiB)",
            )
                .into_response()
        }
        Err(JpegUploadError::UnsupportedMediaType) => {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "image must be image/jpeg",
            )
                .into_response()
        }
        Err(JpegUploadError::Invalid(message)) => {
            return (StatusCode::BAD_REQUEST, message).into_response()
        }
    };

    // Reject ineligible bytes before KMS, encryption, or object storage. The
    // same predicate runs again under BEGIN IMMEDIATE when recording the row.
    let user_id_cloned = user_id.clone();
    let source_key_cloned = source_key.clone();
    let captured_at_cloned = captured_at.clone();
    let sha256_cloned = jpeg.sha256.clone();
    let preflight = s
        .store
        .with_user(&user_id_cloned, move |conn| {
            validate_screenshot_upload_target(
                conn,
                episode_id,
                &source_key_cloned,
                &captured_at_cloned,
                &sha256_cloned,
                jpeg.byte_length,
            )
        })
        .await;
    match preflight {
        Ok(ScreenshotUploadTarget::Existing(existing)) => {
            return (StatusCode::OK, Json(existing.response_json())).into_response()
        }
        Ok(ScreenshotUploadTarget::New { .. }) => {}
        Err(
            e @ (crate::error::EnclaveError::InvalidRequest(_)
            | crate::error::EnclaveError::Conflict(_)),
        ) => return e.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "media upload eligibility check failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
        }
    }

    // 1. Load the persisted media DEK. On first upload, insert a candidate
    // with first-writer-wins semantics, then reload/use the persisted winner.
    // Two Macs can therefore never encrypt objects under different DEKs while
    // racing to initialize the same user.
    let user_id_cloned = user_id.clone();
    let wrapped_opt_res: crate::error::Result<Option<String>> = s
        .store
        .with_user(&user_id_cloned, |conn| {
            Ok(conn
                .query_row(
                    "SELECT value FROM app_metadata WHERE key = ?1",
                    [MEDIA_DEK_METADATA_KEY],
                    |row| row.get::<_, String>(0),
                )
                .optional()?)
        })
        .await;

    let wrapped_opt = match wrapped_opt_res {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(error = %e, "media upload database lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
        }
    };

    let (media_dek, wrapped_b64) = match wrapped_opt {
        Some(wrapped) => match crate::crypto::load_dek(s.store.kms.as_ref(), &wrapped).await {
            Ok(dek) => (dek, wrapped),
            Err(e) => {
                tracing::error!(error = %e, "media upload DEK load failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
            }
        },
        None => {
            let (candidate_dek, candidate_wrapped) =
                match crate::crypto::generate_and_wrap_dek(s.store.kms.as_ref()).await {
                    Ok(candidate) => candidate,
                    Err(e) => {
                        tracing::error!(error = %e, "media upload DEK generation failed");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed")
                            .into_response();
                    }
                };
            let user_id_cloned = user_id.clone();
            let candidate_wrapped_cloned = candidate_wrapped.clone();
            let winner = match s
                .store
                .with_user(&user_id_cloned, move |conn| {
                    install_media_dek_candidate(conn, &candidate_wrapped_cloned)
                })
                .await
            {
                Ok(winner) => winner,
                Err(e) => {
                    tracing::error!(error = %e, "media upload DEK persistence failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed")
                        .into_response();
                }
            };

            if winner == candidate_wrapped {
                (candidate_dek, winner)
            } else {
                match crate::crypto::load_dek(s.store.kms.as_ref(), &winner).await {
                    Ok(dek) => (dek, winner),
                    Err(e) => {
                        tracing::error!(error = %e, "media upload winning DEK load failed");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed")
                            .into_response();
                    }
                }
            }
        }
    };

    // 2. Generate a random opaque key before encryption so the AEAD tag can
    // bind the bytes to their exact user and object identity.
    let mut random_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_bytes);
    let opaque_key: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let object_key = format!("media/{}", opaque_key);
    let media_context = crate::store::media_blob_context(&user_id, &object_key);
    let encrypted_data =
        match crate::crypto::encrypt_bound_blob(&media_dek, &image_bytes, &media_context) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "media upload encryption failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
            }
        };

    // 3. Upload to GCS
    if let Err(e) = s
        .store
        .put_media(&object_key, &encrypted_data, &wrapped_b64)
        .await
    {
        tracing::error!(error = %e, "media upload GCS write failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
    }

    // 4. Revalidate eligibility and episode budgets transactionally, then
    // insert. A concurrent identical retry returns the persisted winner.
    let user_id_cloned = user_id.clone();
    let insert_res = s
        .store
        .with_user(&user_id_cloned, {
            let object_key_clone = object_key.clone();
            let source_key_clone = source_key.clone();
            let captured_at_clone = captured_at.clone();
            let opaque_key_clone = opaque_key.clone();
            let jpeg_clone = jpeg.clone();
            move |conn| {
                record_screenshot_image(
                    conn,
                    &opaque_key_clone,
                    &object_key_clone,
                    episode_id,
                    &source_key_clone,
                    &captured_at_clone,
                    &jpeg_clone,
                )
            }
        })
        .await;

    let stored = match insert_res {
        Ok(ScreenshotRecordOutcome::Created(stored)) => stored,
        Ok(ScreenshotRecordOutcome::Existing(existing)) => {
            if let Err(e) = s.store.delete_media(&object_key).await {
                tracing::error!(error = %e, object_key, "failed to clean up redundant media object");
            }
            return (StatusCode::OK, Json(existing.response_json())).into_response();
        }
        Err(e) => {
            if let Err(cleanup_error) = s.store.delete_media(&object_key).await {
                tracing::error!(error = %cleanup_error, object_key, "failed to clean up rejected media object");
            }
            tracing::warn!(error = %e, "media upload database insert failed");
            return match e {
                e @ (crate::error::EnclaveError::InvalidRequest(_)
                | crate::error::EnclaveError::Conflict(_)) => e.into_response(),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response(),
            };
        }
    };

    // Save user SQLite database state
    if let Err(e) = s.store.save_user(&user_id).await {
        tracing::error!(error = %e, "media upload database save failed");
        let rollback = s
            .store
            .with_user(&user_id, |conn| {
                conn.execute("DELETE FROM screenshot_images WHERE id = ?1", [&stored.id])?;
                Ok(())
            })
            .await;
        match rollback {
            Ok(()) => {
                if let Err(rollback_error) = s.store.save_user(&user_id).await {
                    tracing::error!(error = %rollback_error, "failed to durably roll back screenshot image row");
                }
            }
            Err(rollback_error) => {
                tracing::error!(error = %rollback_error, "failed to roll back screenshot image row");
            }
        }
        if let Err(cleanup_error) = s.store.delete_media(&object_key).await {
            tracing::error!(error = %cleanup_error, object_key, "failed to clean up media object after database save failure");
        }
        return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
    }

    (StatusCode::CREATED, Json(stored.response_json())).into_response()
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
            tracing::error!(error = %e, "media download database lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let wrapped_b64 = match wrapped_opt {
        Some(w) => w,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let media_dek = match crate::crypto::load_dek(s.store.kms.as_ref(), &wrapped_b64).await {
        Ok(dek) => dek,
        Err(e) => {
            tracing::error!(error = %e, "media download DEK load failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 4. Bind media to both the authenticated user and exact object key.
    let media_context = crate::store::media_blob_context(&user_id, &object_key);
    let opened =
        match crate::crypto::decrypt_bound_blob(&media_dek, &gcs_resp.ciphertext, &media_context) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "media download authentication failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    (
        StatusCode::OK,
        [("Content-Type", "image/jpeg")],
        opened.plaintext,
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
                let http = super::bounded_http_client();
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

    fn query_test_state() -> Arc<CpState> {
        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        Arc::new(CpState {
            store,
            control: Arc::new(crate::cp::control_store::ControlStore::new(kms, gcs)),
            config: Arc::new(crate::cp::CpConfig {
                base_url: "http://localhost:8080".into(),
                jwt_secrets: vec!["test-secret".into()],
                google_desktop_client_id: "desktop".into(),
                google_web_client_id: "web".into(),
                google_web_client_secret: "secret".into(),
                allowed_emails: None,
                scheduler_sa_email: None,
                vertex_project: "project".into(),
                vertex_location: "location".into(),
                vertex_model: "model".into(),
                quota_utterances_per_day: 1,
                quota_screenshots_per_day: 1,
                quota_mcp_calls_per_day: 1,
                web_origin: "http://localhost:3000".into(),
            }),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            mcp_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            embedding: None,
        })
    }

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
    async fn episode_detail_matches_list_shape_and_visibility() {
        let state = query_test_state();
        let user_id = "episode-detail-user";
        state
            .store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO audio_segments (id, started_at, ended_at, duration_seconds, source_type) \
                     VALUES (1, '2026-07-21T09:00:00Z', '2026-07-21T09:01:00Z', 60, 'mic')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO utterances (id, audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label) \
                     VALUES (1, 1, 0, 10, 'Bring proof of insurance', 'Presenter')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO screenshots (id, captured_at, active_app, window_title, url, ocr_text) \
                     VALUES (1, '2026-07-21T09:00:05Z', 'Chrome', 'Welcome', 'https://welcome.example/apply', 'Apply here')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO episodes (id, started_at, ended_at, title, summary, type, participants, languages, action_items, minute_summaries, substance, visual_evidence, finalized_at, finalization_version) \
                     VALUES (305, '2026-07-21T09:00:00Z', '2026-07-21T09:01:00Z', 'Student welcome', 'Apply online.', 'presentation', '[\"Presenter\"]', '[\"en\"]', '[\"Apply\"]', '[{\"start\":\"2026-07-21T09:00:00Z\",\"gist\":\"Presenter required proof.\"}]', 'normal', 'useful', '2026-07-21T14:00:00Z', 2)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO episodes (id, started_at, ended_at, title, summary, substance) \
                     VALUES (6, '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', 'Hidden noise', 'No substance.', 'none')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (305, 'utterance', 1)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (305, 'screenshot', 1)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO episode_final_briefs (episode_id, overview, decisions, action_items, important_links, open_questions) \
                     VALUES (305, 'Complete the required setup.', '[\"Insurance is required\"]', '[{\"task\":\"Apply\"}]', '[{\"url\":\"https://welcome.example/apply\"}]', '[]')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let listed = query_episodes_value(&state, user_id, None, None, 50, false, None)
            .await
            .unwrap();
        let listed_episode = listed["episodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|episode| episode["id"] == 305)
            .unwrap()
            .clone();

        let response = rest_episode(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.into())),
            Path(305),
            Query(EpisodeParams { include_low: None }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let detail: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            detail, listed_episode,
            "detail must reuse the list row shape"
        );
        assert_eq!(detail["utterance_count"], 1);
        assert_eq!(detail["screenshot_count"], 1);
        assert_eq!(detail["top_apps"], json!(["Chrome"]));
        assert_eq!(detail["top_domains"], json!(["welcome.example"]));
        assert_eq!(
            detail["final_brief"]["overview"],
            "Complete the required setup."
        );

        let hidden = rest_episode(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.into())),
            Path(6),
            Query(EpisodeParams { include_low: None }),
        )
        .await;
        assert_eq!(hidden.status(), StatusCode::NOT_FOUND);

        let included = rest_episode(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.into())),
            Path(6),
            Query(EpisodeParams {
                include_low: Some("1".into()),
            }),
        )
        .await;
        assert_eq!(included.status(), StatusCode::OK);

        let absent = rest_episode(
            State(state),
            Extension(AuthUser(user_id.into())),
            Path(999_999),
            Query(EpisodeParams {
                include_low: Some("1".into()),
            }),
        )
        .await;
        assert_eq!(absent.status(), StatusCode::NOT_FOUND);
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
            conn.execute("INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES (5, '2026-01-01T10:04:00Z', 'dev1:5', 0)", [])?;
            conn.execute("INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES (6, '2026-01-01T10:05:00Z', 'dev1:6', 0)", [])?;
            conn.execute("INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES (7, '2026-01-01T10:06:00Z', 'dev1:7', 0)", [])?;

            conn.execute("INSERT INTO episodes (id, started_at, ended_at, substance, visual_evidence) VALUES (10, '2026-01-01T10:00:00Z', '2026-01-01T10:05:00Z', 'normal', 'useful')", [])?;
            conn.execute("INSERT INTO episodes (id, started_at, ended_at, substance, visual_evidence) VALUES (11, '2026-01-01T10:05:00Z', '2026-01-01T10:10:00Z', 'low', 'useful')", [])?;
            conn.execute("INSERT INTO episodes (id, started_at, ended_at, substance, visual_evidence) VALUES (12, '2026-01-01T10:10:00Z', '2026-01-01T10:15:00Z', 'normal', 'none')", [])?;
            conn.execute(
                "UPDATE episodes SET minute_summaries = '[{\"start\":\"2026-01-01T10:01:00Z\",\"gist\":\"private gist text\"},{\"start\":\"2026-01-01T10:04:00Z\",\"gist\":\"more text\"}]' WHERE id = 10",
                [],
            )?;

            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 1)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 2)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 3)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 4)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 5)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 6)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 7)", [])?;

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
                query_screenshot_upload_plan(
                    conn,
                    &PlanParams {
                        device_id: "dev1".into(),
                        after: None,
                    },
                )
            })
            .await
            .unwrap();

        let episodes = result["episodes"].as_array().unwrap();
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0]["id"], 10);
        assert_eq!(episodes[0]["remaining_images"], 23);
        assert_eq!(
            episodes[0]["remaining_bytes"],
            MAX_EPISODE_IMAGE_BYTES - 100
        );
        assert_eq!(
            episodes[0]["gist_boundaries"],
            json!(["2026-01-01T10:01:00Z", "2026-01-01T10:04:00Z"])
        );
        assert!(!episodes[0].to_string().contains("private gist text"));
        assert_eq!(
            episodes[0]["source_keys"],
            json!(["dev1:1", "dev1:2", "dev1:5", "dev1:6", "dev1:7"]),
            "the Mac receives all candidates plus a separate remaining budget"
        );

        let capped = store
            .with_user(user_id, |conn| {
                for id in 2..=24 {
                    conn.execute(
                        "INSERT INTO screenshot_images \
                         (id, screenshot_id, episode_id, source_key, captured_at, object_key, mime_type, width, height, byte_length, sha256) \
                         VALUES (?1, 1, 10, ?2, '2026-01-01T10:00:00Z', ?3, 'image/jpeg', 10, 10, 100, 'sha')",
                        rusqlite::params![
                            format!("existing-{id}"),
                            format!("already:{id}"),
                            format!("media/existing-{id}"),
                        ],
                    )?;
                }
                query_screenshot_upload_plan(
                    conn,
                    &PlanParams {
                        device_id: "dev1".into(),
                        after: None,
                    },
                )
            })
            .await
            .unwrap();
        assert!(capped["episodes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn uploaded_jpeg_is_decoded_and_metadata_must_match_bytes() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        use sha2::Digest;

        // A tiny 2x2 baseline JPEG fixture. It exercises a real entropy decode rather
        // than accepting a multipart filename, MIME claim, or SOF header.
        const JPEG_2X2_B64: &str = "/9j/4AAQSkZJRgABAQAASABIAAD/4QBMRXhpZgAATU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAAqADAAQAAAABAAAAAgAAAAD/7QA4UGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAAAA4QklNBCUAAAAAABDUHYzZjwCyBOmACZjs+EJ+/8AAEQgAAgACAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm5+jp6vLz9PX29/j5+v/bAEMAAgICAgICAwICAwUDAwMFBgUFBQUGCAYGBgYGCAoICAgICAgKCgoKCgoKCgwMDAwMDA4ODg4ODw8PDw8PDw8PD//bAEMBAgICBAQEBwQEBxALCQsQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEP/dAAQAAf/aAAwDAQACEQMRAD8A/WD9m/wH4H1L9nj4XajqPh3Trq7uvC2iSzTS2kLySSPYwszuzKSzMSSSTknk17R/wrb4d/8AQraV/wCAMH/xFcF+zF/ybZ8Jv+xS0H/0ghr3GgD/2Q==";

        let bytes = B64.decode(JPEG_2X2_B64).unwrap();
        let sha256 = format!("{:x}", sha2::Sha256::digest(&bytes));
        let validated = validate_uploaded_jpeg(&bytes, Some("image/jpeg"), 2, 2, &sha256).unwrap();
        assert_eq!((validated.width, validated.height), (2, 2));
        assert_eq!(validated.byte_length, bytes.len() as i64);

        assert_eq!(
            validate_uploaded_jpeg(&bytes, Some("image/png"), 2, 2, &sha256),
            Err(JpegUploadError::UnsupportedMediaType)
        );
        assert!(matches!(
            validate_uploaded_jpeg(&bytes, Some("image/jpeg"), 3, 2, &sha256),
            Err(JpegUploadError::Invalid(
                "JPEG dimensions do not match multipart metadata"
            ))
        ));

        let truncated = &bytes[..bytes.len() - 8];
        let truncated_sha = format!("{:x}", sha2::Sha256::digest(truncated));
        assert_eq!(
            validate_uploaded_jpeg(truncated, Some("image/jpeg"), 2, 2, &truncated_sha),
            Err(JpegUploadError::Invalid("invalid JPEG"))
        );
        assert_eq!(
            validate_uploaded_jpeg(
                &vec![0; MAX_SCREENSHOT_IMAGE_BYTES + 1],
                Some("image/jpeg"),
                1,
                1,
                &"0".repeat(64),
            ),
            Err(JpegUploadError::PayloadTooLarge)
        );
    }

    #[tokio::test]
    async fn upload_target_enforces_membership_eligibility_and_idempotency() {
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        store
            .with_user("upload-policy-user", |conn| {
                conn.execute(
                    "INSERT INTO episodes (id, started_at, ended_at, title, substance, visual_evidence) \
                     VALUES (10, '2026-01-01T10:00:00Z', '2026-01-01T11:00:00Z', 'eligible', 'normal', 'useful'), \
                            (11, '2026-01-01T11:00:00Z', '2026-01-01T12:00:00Z', 'low', 'low', 'useful'), \
                            (12, '2026-01-01T12:00:00Z', '2026-01-01T13:00:00Z', 'no visual', 'normal', 'none')",
                    [],
                )?;
                for (id, captured_at, source_key, duplicate) in [
                    (1, "2026-01-01T10:01:00Z", "dev:1", 0),
                    (2, "2026-01-01T10:02:00Z", "dev:2", 1),
                    (3, "2026-01-01T11:01:00Z", "dev:3", 0),
                    (4, "2026-01-01T12:01:00Z", "dev:4", 0),
                ] {
                    conn.execute(
                        "INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) \
                         VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![id, captured_at, source_key, duplicate],
                    )?;
                }
                for (episode_id, screenshot_id) in [(10, 1), (10, 2), (11, 3), (12, 4)] {
                    conn.execute(
                        "INSERT INTO episode_members (episode_id, record_type, record_id) \
                         VALUES (?1, 'screenshot', ?2)",
                        rusqlite::params![episode_id, screenshot_id],
                    )?;
                }

                let sha = "a".repeat(64);
                assert!(matches!(
                    validate_screenshot_upload_target(
                        conn,
                        10,
                        "dev:1",
                        "2026-01-01T10:01:00Z",
                        &sha,
                        100,
                    )?,
                    ScreenshotUploadTarget::New { screenshot_id: 1, .. }
                ));
                for result in [
                    validate_screenshot_upload_target(
                        conn,
                        99,
                        "dev:1",
                        "2026-01-01T10:01:00Z",
                        &sha,
                        100,
                    ),
                    validate_screenshot_upload_target(
                        conn,
                        10,
                        "dev:2",
                        "2026-01-01T10:02:00Z",
                        &sha,
                        100,
                    ),
                    validate_screenshot_upload_target(
                        conn,
                        11,
                        "dev:3",
                        "2026-01-01T11:01:00Z",
                        &sha,
                        100,
                    ),
                    validate_screenshot_upload_target(
                        conn,
                        12,
                        "dev:4",
                        "2026-01-01T12:01:00Z",
                        &sha,
                        100,
                    ),
                    validate_screenshot_upload_target(
                        conn,
                        10,
                        "dev:1",
                        "spoofed-time",
                        &sha,
                        100,
                    ),
                ] {
                    assert!(matches!(
                        result,
                        Err(crate::error::EnclaveError::InvalidRequest(_))
                    ));
                }

                conn.execute(
                    "INSERT INTO screenshot_images \
                     (id, screenshot_id, episode_id, source_key, captured_at, object_key, mime_type, width, height, byte_length, sha256) \
                     VALUES ('existing', 1, 10, 'dev:1', '2026-01-01T10:01:00Z', 'media/existing', 'image/jpeg', 2, 3, 100, ?1)",
                    [&sha],
                )?;
                assert!(matches!(
                    validate_screenshot_upload_target(
                        conn,
                        10,
                        "dev:1",
                        "2026-01-01T10:01:00Z",
                        &sha,
                        100,
                    )?,
                    ScreenshotUploadTarget::Existing(StoredScreenshotImage { ref id, .. })
                        if id == "existing"
                ));
                assert!(matches!(
                    validate_screenshot_upload_target(
                        conn,
                        10,
                        "dev:1",
                        "2026-01-01T10:01:00Z",
                        &"b".repeat(64),
                        100,
                    ),
                    Err(crate::error::EnclaveError::Conflict(_))
                ));
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upload_record_transaction_rejects_over_budget_image_but_keeps_retry_idempotent() {
        let user_id = "3668d78a-1b24-5c16-ac8d-0042cd37a743";
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO episodes (id, started_at, ended_at, title, substance, visual_evidence) \
                     VALUES (10, '2026-01-01T10:00:00Z', '2026-01-01T11:00:00Z', 'eligible', 'normal', 'useful')",
                    [],
                )?;
                for id in 1_i64..=25 {
                    let captured_at = format!("2026-01-01T10:{id:02}:00Z");
                    conn.execute(
                        "INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) \
                         VALUES (?1, ?2, ?3, 0)",
                        rusqlite::params![id, captured_at, format!("dev:{id}")],
                    )?;
                    conn.execute(
                        "INSERT INTO episode_members (episode_id, record_type, record_id) \
                         VALUES (10, 'screenshot', ?1)",
                        [id],
                    )?;
                }

                let bytes_per_img = 150_000;
                for id in 1_i64..=MAX_EPISODE_IMAGES {
                    let jpeg = ValidatedJpeg {
                        width: 2,
                        height: 3,
                        byte_length: bytes_per_img,
                        sha256: format!("{id:064x}"),
                    };
                    assert!(matches!(
                        record_screenshot_image(
                            conn,
                            &format!("image-{id}"),
                            &format!("media/image-{id}"),
                            10,
                            &format!("dev:{id}"),
                            &format!("2026-01-01T10:{id:02}:00Z"),
                            &jpeg,
                        )?,
                        ScreenshotRecordOutcome::Created(_)
                    ));
                }

                let first = ValidatedJpeg {
                    width: 2,
                    height: 3,
                    byte_length: bytes_per_img,
                    sha256: format!("{:064x}", 1),
                };
                assert!(matches!(
                    record_screenshot_image(
                        conn,
                        "retry-object-that-will-be-discarded",
                        "media/retry-object-that-will-be-discarded",
                        10,
                        "dev:1",
                        "2026-01-01T10:01:00Z",
                        &first,
                    )?,
                    ScreenshotRecordOutcome::Existing(_)
                ));

                let extra = ValidatedJpeg {
                    width: 2,
                    height: 3,
                    byte_length: 1,
                    sha256: format!("{:064x}", 25),
                };
                assert!(matches!(
                    record_screenshot_image(
                        conn,
                        "image-25",
                        "media/image-25",
                        10,
                        "dev:25",
                        "2026-01-01T10:25:00Z",
                        &extra,
                    ),
                    Err(crate::error::EnclaveError::Conflict(_))
                ));
                let (count, bytes): (i64, i64) = conn.query_row(
                    "SELECT COUNT(*), SUM(byte_length) FROM screenshot_images WHERE episode_id = 10",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                assert_eq!(count, MAX_EPISODE_IMAGES);
                assert_eq!(bytes, MAX_EPISODE_IMAGES * 150_000);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn media_dek_install_is_first_writer_wins() {
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        store
            .with_user("media-dek-user", |conn| {
                assert_eq!(install_media_dek_candidate(conn, "wrapped-a")?, "wrapped-a");
                assert_eq!(install_media_dek_candidate(conn, "wrapped-b")?, "wrapped-a");
                assert_eq!(
                    conn.query_row(
                        "SELECT value FROM app_metadata WHERE key = ?1",
                        [MEDIA_DEK_METADATA_KEY],
                        |row| row.get::<_, String>(0),
                    )?,
                    "wrapped-a"
                );
                Ok(())
            })
            .await
            .unwrap();
    }
}
