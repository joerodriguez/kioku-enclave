//! Query surface: the MCP
//! server (`POST /mcp`, JSON-RPC 2.0, stateless) and the REST mirrors
//! (`/api/search`, `/api/episodes`, `/api/episodes/:id`,
//! `/api/episodes/:id/members`) the debugger
//! uses. All routes are auth-gated; tool logic calls the data-plane query code
//! (`search::search_all`, `timeline::fetch_context`) in-process.
//! `POST /api/episodes/:id/finalize` queues a scoped retry for an incomplete
//! or version-stale canonical brief. `/api/webhooks` manages signed,
//! user-configured finalized-episode event destinations.

pub(crate) mod wal;

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

use super::auth::AuthUser;
use super::CpState;

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

async fn tool_search_transcripts(s: &CpState, user_id: &str, args: &Value) -> Value {
    let raw_query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .clamp(1, 50) as usize;
    let from = args.get("from").and_then(|v| v.as_str()).map(String::from);
    let to = args.get("to").and_then(|v| v.as_str()).map(String::from);

    let (query, speaker) = crate::search::extract_speaker_filter(&raw_query);
    let query_embedding = if query.trim().is_empty() {
        None
    } else {
        embed_query(s, &query).await
    };
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
const MAX_SCREENSHOT_IMAGE_BYTES: usize = 150 * 1024;
const MAX_SCREENSHOT_MULTIPART_BYTES: usize = MAX_SCREENSHOT_IMAGE_BYTES + 16 * 1024;
const MAX_SCREENSHOT_METADATA_FIELD_BYTES: usize = 512;
const MAX_EPISODE_IMAGE_BYTES: i64 = 4000 * 1024;
const MAX_EPISODE_IMAGES: i64 = 24;
const MAX_SCREENSHOT_LONG_EDGE: u16 = 960;
const MEDIA_DEK_METADATA_KEY: &str = "wrapped_media_dek";
const CLOUD_CAPTURE_IMAGE_ID_PREFIX: &str = "capture-v2:";

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
        .route(
            "/api/browser-snapshots/{source_key}",
            get(rest_browser_snapshot),
        )
        .route("/api/episodes/{id}/finalize", post(rest_episode_finalize))
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
            "/api/webhooks",
            get(rest_list_webhooks).post(rest_create_webhook),
        )
        .route(
            "/api/webhooks/{id}",
            axum::routing::delete(rest_delete_webhook),
        )
        .route("/api/webhooks/{id}/test", post(rest_test_webhook))
        .route(
            "/api/preferences/episode-email",
            get(rest_get_episode_email_preference).put(rest_put_episode_email_preference),
        )
        .route(
            "/api/preferences/episode-email/test",
            post(rest_test_episode_email),
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

async fn tool_search_screenshots(s: &CpState, user_id: &str, args: &Value) -> Value {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .clamp(1, 50) as usize;
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

async fn tool_list_episodes(s: &Arc<CpState>, user_id: &str, args: &Value) -> Value {
    let from = args.get("from").and_then(|v| v.as_str()).map(String::from);
    let to = args.get("to").and_then(|v| v.as_str()).map(String::from);
    let max = args
        .get("max_episodes")
        .and_then(|v| v.as_u64())
        .unwrap_or(20)
        .clamp(1, 50) as i64;
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
    // Normalize offset-bearing timestamps (e.g. -04:00) to UTC before SQL.
    // DB stores UTC Z-suffixed strings; after normalization both sides are UTC
    // and simple string comparison works correctly.
    let from = from.map(|s| super::isotime::normalize_to_utc(&s));
    let to = to.map(|s| super::isotime::normalize_to_utc(&s));

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
                        e.finalization_status, e.finalization_attempted_at, \
                        fb.overview, fb.decisions, fb.action_items, fb.important_links, fb.open_questions \
                 FROM episodes e \
                 LEFT JOIN episode_final_briefs fb ON fb.episode_id = e.id \
                 WHERE \
                   (?1 IS NULL OR e.ended_at >= ?1) AND (?2 IS NULL OR e.started_at <= ?2) \
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
                    let finalization_status: String = r.get(16)?;
                    let finalization_attempted_at: Option<String> = r.get(17)?;

                    let final_brief = if let Some(overview) = r.get::<_, Option<String>>(18)? {
                        Some(json!({
                            "overview": overview,
                            "decisions": serde_json::from_str::<Value>(&r.get::<_, String>(19)?).unwrap_or(json!([])),
                            "action_items": serde_json::from_str::<Value>(&r.get::<_, String>(20)?).unwrap_or(json!([])),
                            "important_links": serde_json::from_str::<Value>(&r.get::<_, String>(21)?).unwrap_or(json!([])),
                            "open_questions": serde_json::from_str::<Value>(&r.get::<_, String>(22)?).unwrap_or(json!([])),
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
                        "finalization_status": finalization_status,
                        "finalization_attempted_at": finalization_attempted_at,
                        "finalization_retryable": matches!(
                            finalization_status.as_str(),
                            "retry_wait" | "budget_wait" | "failed_terminal"
                        ),
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

fn project_fields(value: &Value, fields: &[&str]) -> Value {
    let mut projected = serde_json::Map::new();
    for field in fields {
        if let Some(field_value) = value.get(*field) {
            projected.insert((*field).to_string(), field_value.clone());
        }
    }
    Value::Object(projected)
}

fn project_array(value: &Value, fields: &[&str]) -> Value {
    Value::Array(
        value
            .as_array()
            .into_iter()
            .flatten()
            .map(|item| project_fields(item, fields))
            .collect(),
    )
}

/// The REST/debugger surfaces keep operational fields used by Kioku itself.
/// MCP responses deliberately expose only user-relevant evidence: no database
/// ids, hashes, ranking scores, source keys, model confidence, or internal
/// finalization state.
fn project_mcp_result(name: &str, result: Value) -> Value {
    if result.get("error").is_some() {
        return result;
    }
    match name {
        "search_transcripts" => json!({
            "episodes": project_array(
                &result["episodes"],
                &["kind", "started_at", "ended_at", "title", "summary", "minute_summaries", "snippet"],
            ),
            "results": project_array(
                &result["results"],
                &["kind", "text", "speaker_label", "started_at"],
            ),
        }),
        "search_screenshots" => json!({
            "results": project_array(
                &result["results"],
                &["kind", "captured_at", "active_app", "window_title", "ocr_text", "url",
                  "observation_status", "literal_description", "screen_state", "content_type"],
            ),
        }),
        "get_context" => json!({
            "utterances": project_array(
                &result["utterances"],
                &["started_at", "ended_at", "speaker_label", "language", "text", "source_type"],
            ),
            "screenshots": project_array(
                &result["screenshots"],
                &["captured_at", "active_app", "window_title", "ocr_text", "url",
                  "observation_status", "literal_description", "screen_state", "content_type"],
            ),
        }),
        "list_episodes" => json!({
            "episode_count": result["episode_count"],
            "hidden_count": result["hidden_count"],
            "episodes": project_array(
                &result["episodes"],
                &[
                    "started_at",
                    "ended_at",
                    "title",
                    "summary",
                    "type",
                    "participants",
                    "languages",
                    "action_items",
                    "minute_summaries",
                    "utterance_count",
                    "screenshot_count",
                    "top_apps",
                    "top_domains",
                    "final_brief",
                ],
            ),
        }),
        _ => result,
    }
}

fn read_only_annotations() -> Value {
    json!({
        "readOnlyHint": true,
        "openWorldHint": false,
        "destructiveHint": false
    })
}

fn object_array_schema(properties: Value) -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "properties": properties,
            "additionalProperties": false
        }
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "search_transcripts",
            "title": "Search memory",
            "description": "Use this when the user wants to find a topic, person, decision, action item, or spoken moment in their own Kioku memory archive. Returns relevance-ranked episodes first, followed by matching utterances as timestamped evidence. Do not use for general web search, information outside the user's Kioku archive, or restricted data such as payment cards, health information, government identifiers, or access credentials; targeted searches are refused and matching incidental content is redacted.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Natural-language search query. A speaker filter may be included as speaker:Name."},
                    "from": {"type": "string", "description": "Optional inclusive RFC 3339 lower timestamp bound."},
                    "to": {"type": "string", "description": "Optional inclusive RFC 3339 upper timestamp bound."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10, "description": "Maximum episode and utterance matches to return."}
                },
                "required": ["query"],
                "additionalProperties": false
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "episodes": object_array_schema(json!({
                        "kind": {"type": "string"},
                        "started_at": {"type": "string"},
                        "ended_at": {"type": "string"},
                        "title": {"type": ["string", "null"]},
                        "summary": {"type": ["string", "null"]},
                        "minute_summaries": {"type": "array"},
                        "snippet": {"type": "string"}
                    })),
                    "results": object_array_schema(json!({
                        "kind": {"type": "string"},
                        "text": {"type": "string"},
                        "speaker_label": {"type": "string"},
                        "started_at": {"type": "string"}
                    }))
                },
                "required": ["episodes", "results"],
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        },
        {
            "name": "search_screenshots",
            "title": "Search screens",
            "description": "Use this when the user wants to find text, a link, an app, or a window they previously saw on their own Mac. Searches OCR text and screen metadata in the user's Kioku archive. Do not use for live screen access, general web search, or restricted data such as payment cards, health information, government identifiers, or access credentials; targeted searches are refused and matching incidental content is redacted.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Text, application name, window title, or URL to find."},
                    "from": {"type": "string", "description": "Optional inclusive RFC 3339 lower timestamp bound."},
                    "to": {"type": "string", "description": "Optional inclusive RFC 3339 upper timestamp bound."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10, "description": "Maximum matches to return."}
                },
                "required": ["query"],
                "additionalProperties": false
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "results": object_array_schema(json!({
                        "kind": {"type": "string"},
                        "captured_at": {"type": "string"},
                        "active_app": {"type": ["string", "null"]},
                        "window_title": {"type": ["string", "null"]},
                        "ocr_text": {"type": ["string", "null"]},
                        "url": {"type": ["string", "null"]}
                    }))
                },
                "required": ["results"],
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        },
        {
            "name": "get_context",
            "title": "Get moment context",
            "description": "Use this when the user needs the surrounding conversation and screen context around a timestamp from a Kioku search result. Returns a bounded interleaved timeline from the user's archive. Do not use without a concrete timestamp. Matching payment-card data, health information, government identifiers, and access credentials are redacted before output.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "at": {"type": "string", "description": "RFC 3339 timestamp at the center of the requested context."},
                    "window_seconds": {"type": "integer", "minimum": 60, "maximum": 3600, "default": 300, "description": "Total context window in seconds."}
                },
                "required": ["at"],
                "additionalProperties": false
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "utterances": object_array_schema(json!({
                        "started_at": {"type": "string"},
                        "ended_at": {"type": "string"},
                        "speaker_label": {"type": "string"},
                        "language": {"type": ["string", "null"]},
                        "text": {"type": "string"},
                        "source_type": {"type": "string"}
                    })),
                    "screenshots": object_array_schema(json!({
                        "captured_at": {"type": "string"},
                        "active_app": {"type": ["string", "null"]},
                        "window_title": {"type": ["string", "null"]},
                        "ocr_text": {"type": ["string", "null"]},
                        "url": {"type": ["string", "null"]}
                    }))
                },
                "required": ["utterances", "screenshots"],
                "additionalProperties": true
            },
            "annotations": read_only_annotations()
        },
        {
            "name": "summarize_time_range",
            "title": "Summarize a time range",
            "description": "Use this when the user asks what happened during a specific period in their Kioku archive and needs a chronological evidence digest with activity counts, languages, and apps. Do not use when no time range is available. Matching payment-card data, health information, government identifiers, and access credentials are redacted before output.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Inclusive RFC 3339 start timestamp."},
                    "to": {"type": "string", "description": "Exclusive RFC 3339 end timestamp."},
                    "max_items": {"type": "integer", "minimum": 1, "maximum": 500, "default": 200, "description": "Maximum chronological utterance evidence items."}
                },
                "required": ["from", "to"],
                "additionalProperties": false
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "counts": {"type": "object", "additionalProperties": true},
                    "languages": {"type": "array", "items": {"type": "string"}},
                    "apps_seen": {"type": "array", "items": {"type": "string"}},
                    "digest": object_array_schema(json!({
                        "at": {"type": "string"},
                        "speaker": {"type": "string"},
                        "text": {"type": "string"}
                    }))
                },
                "required": ["from", "to", "counts", "languages", "apps_seen", "digest"],
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        },
        {
            "name": "list_episodes",
            "title": "List memory episodes",
            "description": "Use this when the user wants an overview of their day or recent activity in Kioku. Returns summarized activity episodes newest-first with timestamps, participants, actions, and evidence counts. Do not use for a topic search; use search_transcripts instead. Matching payment-card data, health information, government identifiers, and access credentials are redacted before output.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Optional inclusive RFC 3339 lower timestamp bound."},
                    "to": {"type": "string", "description": "Optional inclusive RFC 3339 upper timestamp bound."},
                    "max_episodes": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20, "description": "Maximum episodes to return."},
                    "include_low": {"type": "boolean", "default": false, "description": "Include substance=none episodes normally hidden from browse."}
                },
                "additionalProperties": false
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "episode_count": {"type": "integer"},
                    "hidden_count": {"type": "integer"},
                    "episodes": object_array_schema(json!({
                        "started_at": {"type": "string"},
                        "ended_at": {"type": "string"},
                        "title": {"type": ["string", "null"]},
                        "summary": {"type": ["string", "null"]},
                        "type": {"type": ["string", "null"]},
                        "participants": {"type": "array"},
                        "languages": {"type": "array"},
                        "action_items": {"type": "array"},
                        "minute_summaries": {"type": "array"},
                        "utterance_count": {"type": "integer"},
                        "screenshot_count": {"type": "integer"},
                        "top_apps": {"type": "array", "items": {"type": "string"}},
                        "top_domains": {"type": "array", "items": {"type": "string"}},
                        "final_brief": {"type": ["object", "null"]}
                    }))
                },
                "required": ["episode_count", "hidden_count", "episodes"],
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        },
        {
            "name": "get_capture_status",
            "title": "Get capture status",
            "description": "Use this when the user asks whether Kioku has recent cloud-synced memory data or wants archive totals. Returns per-user counts and the latest synced utterance and screenshot timestamps. Do not use to start, stop, or inspect live capture.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "total_utterances": {"type": "integer"},
                    "total_screenshots": {"type": "integer"},
                    "episode_count": {"type": "integer"},
                    "last_utterance_at": {"type": ["string", "null"]},
                    "last_screenshot_at": {"type": ["string", "null"]}
                },
                "required": ["total_utterances", "total_screenshots", "episode_count", "last_utterance_at", "last_screenshot_at"],
                "additionalProperties": false
            },
            "annotations": read_only_annotations()
        }
    ])
}

async fn dispatch_tool(s: &Arc<CpState>, user_id: &str, name: &str, args: &Value) -> Option<Value> {
    if let Some(refusal) = super::mcp_safety::refusal_for_args(name, args) {
        return Some(refusal);
    }
    let result = match name {
        "search_transcripts" => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let from = args.get("from").and_then(|v| v.as_str());
            let to = args.get("to").and_then(|v| v.as_str());
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            s.store
                .with_user(user_id, |conn| {
                    Ok(super::mcp_query::search_safe_transcripts(
                        conn, query, from, to, limit,
                    )?)
                })
                .await
                .unwrap_or_else(|_| json!({ "results": [] }))
        }
        "get_context" => {
            let at = args.get("at").and_then(|v| v.as_str()).unwrap_or("");
            let window = args
                .get("window_seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(300);
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);
            s.store
                .with_user(user_id, |conn| {
                    Ok(super::mcp_query::fetch_safe_context(
                        conn, at, window, limit,
                    )?)
                })
                .await
                .unwrap_or_else(|_| json!({ "utterances": [] }))
        }
        "summarize_time_range" => {
            let from = args.get("from").and_then(|v| v.as_str()).unwrap_or("");
            let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);
            s.store
                .with_user(user_id, |conn| {
                    Ok(super::mcp_query::summarize_safe_time_range(
                        conn, from, to, limit,
                    )?)
                })
                .await
                .unwrap_or_else(|_| json!({ "episodes": [] }))
        }
        "search_screenshots" => tool_search_screenshots(s, user_id, args).await,
        "list_episodes" => tool_list_episodes(s, user_id, args).await,
        "get_capture_status" => tool_get_capture_status(s, user_id).await,
        _ => return None,
    };
    Some(super::mcp_safety::sanitize_result(project_mcp_result(
        name, result,
    )))
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

    // A volatile rate limit protects the service without making read-only tool
    // calls persist usage or query-log state.
    if rpc.method == "tools/call" && !s.mcp_limiter.consume(&user_id).await {
        return rpc_error(&rpc.id, -32000, "rate_limited");
    }

    match rpc.method.as_str() {
        "initialize" => rpc_ok(
            &rpc.id,
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "kioku",
                    "title": "Kioku",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": "Kioku searches the signed-in user's private personal memory archive. Use it only when the user asks about their own captured days, meetings, lessons, conversations, screens, decisions, action items, or recent activity. Treat returned records as private evidence: ground answers in retrieved content and include timestamps when useful. Never use Kioku to seek payment-card data, health information, government identifiers, passwords, API keys, tokens, or authentication codes; the server refuses targeted searches and redacts matching incidental content from every MCP response. Use search_transcripts for topic or person queries, list_episodes for day or activity overviews, get_context for details around a known timestamp, search_screenshots for text seen on screen, summarize_time_range for a bounded chronological digest, and get_capture_status for cloud archive freshness."
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
            match dispatch_tool(&s, &user_id, name, &args).await {
                Some(result) => {
                    let text = serde_json::to_string(&result).unwrap_or_else(|_| "{}".into());
                    let tool_result = if result.get("error").is_some() {
                        json!({
                            "content": [{ "type": "text", "text": text }],
                            "isError": true
                        })
                    } else {
                        json!({
                            "content": [{ "type": "text", "text": text }],
                            "structuredContent": result
                        })
                    };
                    rpc_ok(&rpc.id, tool_result)
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
            // Legacy source keys let the Mac-selected evidence flow join a
            // member to screenshot_images. Cloud Capture v2 source keys bind
            // canonical screenshots to their retained encrypted media object.
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
                        substr(c.ocr_text,1,4000), substr(c.salient_ocr_text,1,4000), \
                        CASE WHEN length(c.ocr_text) > 4000 THEN 1 ELSE 0 END, \
                        c.source_key, COALESCE(img.id, \
                          CASE WHEN capture_img.asset_id IS NOT NULL \
                               THEN 'capture-v2:' || capture_img.asset_id END), \
                        o.status, o.generation_method, o.literal_description, o.screen_state, \
                        o.content_type, o.visible_text_summary, o.notable_items_json, \
                        i.activity_summary, i.relevance_level, i.relevance_reason, i.key_rank, \
                        i.is_key_screen, i.semantic_group, c.capture_status, c.primary_bundle_id, \
                        c.visible_until, c.browser_snapshot_source_key, i.status, \
                        i.milestone_type, i.base_score \
                 FROM episode_members m \
                 JOIN screenshots c ON c.id = m.record_id \
                 LEFT JOIN screenshot_images img ON img.source_key = c.source_key \
                 LEFT JOIN media_objects capture_img \
                   ON capture_img.event_id = CASE \
                        WHEN c.source_key GLOB 'cloud-v2:*' \
                        THEN substr(c.source_key, length('cloud-v2:') + 1) END \
                  AND capture_img.mime_type = 'image/jpeg' \
                  AND capture_img.processing_state = 'ready' \
                  AND capture_img.deleted_at IS NULL \
                 LEFT JOIN screen_observations o ON o.screenshot_id = c.id \
                 LEFT JOIN episode_screen_interpretations i \
                   ON i.episode_id = m.episode_id AND i.screenshot_id = c.id \
                 WHERE m.episode_id = ?1 AND m.record_type = 'screenshot' AND c.is_duplicate = 0",
            )?;
            members.extend(
                ss.query_map([id], |r| {
                    let ts: String = r.get(1)?;
                    let raw_ocr: Option<String> = r.get(5)?;
                    let supplied_salient: Option<String> = r.get(6)?;
                    let salient = crate::ocr::select_salient_ocr(
                        raw_ocr.as_deref(),
                        supplied_salient.as_deref(),
                    );
                    let screen_facts = salient
                        .as_deref()
                        .map(crate::ocr::extract_screen_facts)
                        .unwrap_or_default();
                    let notable_items: Value = r
                        .get::<_, Option<String>>(16)?
                        .and_then(|raw| serde_json::from_str(&raw).ok())
                        .unwrap_or_else(|| json!([]));
                    Ok((
                        ts.clone(),
                        json!({
                            "record_type": "screenshot",
                            "record_id": r.get::<_, i64>(0)?,
                            "captured_at": ts,
                            "active_app": r.get::<_, Option<String>>(2)?,
                            "window_title": r.get::<_, Option<String>>(3)?,
                            "url": r.get::<_, Option<String>>(4)?,
                            "ocr_excerpt": raw_ocr,
                            "ocr_truncated": r.get::<_, i64>(7)? != 0,
                            "salient_ocr_excerpt": salient,
                            "screen_facts": screen_facts,
                            "source_key": r.get::<_, Option<String>>(8)?,
                            "cloud_image_id": r.get::<_, Option<String>>(9)?,
                            "observation_status": r.get::<_, Option<String>>(10)?,
                            "observation_method": r.get::<_, Option<String>>(11)?,
                            "literal_description": r.get::<_, Option<String>>(12)?,
                            "screen_state": r.get::<_, Option<String>>(13)?,
                            "content_type": r.get::<_, Option<String>>(14)?,
                            "visible_text_summary": r.get::<_, Option<String>>(15)?,
                            "notable_items": notable_items,
                            "activity_summary": r.get::<_, Option<String>>(17)?,
                            "relevance_level": r.get::<_, Option<i64>>(18)?,
                            "relevance_reason": r.get::<_, Option<String>>(19)?,
                            "key_rank": r.get::<_, Option<i64>>(20)?,
                            "is_key_screen": r.get::<_, Option<i64>>(21)?.unwrap_or(0) != 0,
                            "semantic_group": r.get::<_, Option<String>>(22)?,
                            "capture_status": r.get::<_, Option<String>>(23)?,
                            "primary_bundle_id": r.get::<_, Option<String>>(24)?,
                            "visible_until": r.get::<_, Option<String>>(25)?,
                            "browser_snapshot_source_key": r.get::<_, Option<String>>(26)?,
                            "interpretation_status": r.get::<_, Option<String>>(27)?,
                            "milestone_type": r.get::<_, Option<String>>(28)?,
                            "key_score": r.get::<_, Option<i64>>(29)?,
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

async fn rest_browser_snapshot(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(source_key): Path<String>,
) -> Response {
    let result = s
        .store
        .with_user(&user.0, move |conn| {
            let snapshot = conn
                .query_row(
                    "SELECT id, source_key, captured_at, browser_bundle_id, browser_name,
                            permission_status, active_window_index, active_tab_index,
                            reported_tab_count, truncated
                     FROM browser_snapshots WHERE source_key=?1",
                    [&source_key],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, Option<i64>>(6)?,
                            row.get::<_, Option<i64>>(7)?,
                            row.get::<_, i64>(8)?,
                            row.get::<_, i64>(9)? != 0,
                        ))
                    },
                )
                .optional()?;
            let Some(snapshot) = snapshot else {
                return Ok(None);
            };
            let mut statement = conn.prepare(
                "SELECT window_index, tab_index, title, url, url_scheme, is_active, is_loading
                 FROM browser_tabs WHERE browser_snapshot_id=?1
                 ORDER BY window_index, tab_index LIMIT 500",
            )?;
            let tabs: Vec<Value> = statement
                .query_map([snapshot.0], |row| {
                    Ok(json!({
                        "window_index": row.get::<_, i64>(0)?,
                        "tab_index": row.get::<_, i64>(1)?,
                        "title": row.get::<_, Option<String>>(2)?,
                        "url": row.get::<_, Option<String>>(3)?,
                        "url_scheme": row.get::<_, Option<String>>(4)?,
                        "is_active": row.get::<_, i64>(5)? != 0,
                        "is_loading": row.get::<_, Option<i64>>(6)?.map(|value| value != 0),
                    }))
                })?
                .filter_map(std::result::Result::ok)
                .collect();
            Ok(Some(json!({
                "source_key": snapshot.1,
                "captured_at": snapshot.2,
                "browser_bundle_id": snapshot.3,
                "browser_name": snapshot.4,
                "permission_status": snapshot.5,
                "active_window_index": snapshot.6,
                "active_tab_index": snapshot.7,
                "reported_tab_count": snapshot.8,
                "truncated": snapshot.9,
                "tabs": tabs,
            })))
        })
        .await;
    match result {
        Ok(Some(snapshot)) => Json(snapshot).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "enclave_unavailable"})),
        )
            .into_response(),
    }
}

async fn rest_episode_finalize(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Response {
    let eligibility = s
        .store
        .with_user(&user.0, move |conn| {
            conn.query_row(
                "SELECT substance, finalized_at, finalization_version, finalization_status
                 FROM episodes WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i32>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(Into::into)
        })
        .await;
    let Some((substance, finalized_at, version, status)) = (match eligibility {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, episode_id = id, "finalization retry lookup failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "enclave_unavailable"})),
            )
                .into_response();
        }
    }) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "episode_not_found"})),
        )
            .into_response();
    };

    if substance == "none" {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "low_signal_episode"})),
        )
            .into_response();
    }
    if finalized_at.is_some() && version.unwrap_or(1) >= super::finalizer::FINALIZATION_VERSION {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "already_complete", "status": status})),
        )
            .into_response();
    }
    if matches!(status.as_str(), "queued" | "processing") {
        return (
            StatusCode::ACCEPTED,
            Json(json!({"queued": true, "episode_id": id, "status": status})),
        )
            .into_response();
    }

    let user_id = user.0;
    let queued = s
        .store
        .with_user(&user_id, move |conn| {
            conn.execute(
                "UPDATE episodes
                 SET finalization_status = 'queued',
                     finalization_error = NULL,
                     finalization_attempt_count = 0,
                     finalization_next_attempt_at = NULL,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE id = ?1",
                [id],
            )?;
            Ok(())
        })
        .await;
    if let Err(error) = queued {
        tracing::warn!(%error, episode_id = id, "failed to queue episode finalization");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "enclave_unavailable"})),
        )
            .into_response();
    }
    if let Err(error) = s.store.save_user(&user_id).await {
        tracing::warn!(%error, episode_id = id, "failed to persist episode finalization queue");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "save_failed"})),
        )
            .into_response();
    }

    let state = s.clone();
    let worker_user = user_id.clone();
    tokio::spawn(async move {
        if let Err(error) = super::finalizer::finalize_user_episode(&state, &worker_user, id).await
        {
            tracing::warn!(%error, episode_id = id, "scoped episode finalization failed");
        }
    });
    (
        StatusCode::ACCEPTED,
        Json(json!({"queued": true, "episode_id": id, "status": "queued"})),
    )
        .into_response()
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
    observation_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    literal_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    screen_state: Option<String>,
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
            observation_status: None,
            literal_description: None,
            screen_state: None,
            source_key: row.get(4)?,
            episode_id: None,
        });
    }

    // 2. Fetch screenshots
    let mut s_sql = r#"
        SELECT s.id, s.captured_at, s.active_app, s.window_title, s.url, s.ocr_text,
               s.salient_ocr_text, s.source_key, o.status, o.literal_description, o.screen_state
        FROM screenshots s LEFT JOIN screen_observations o ON o.screenshot_id=s.id
        WHERE s.captured_at IS NOT NULL AND s.is_duplicate = 0
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
        let supplied_salient: Option<String> = row.get(6)?;
        let ocr_excerpt =
            crate::ocr::select_salient_ocr(ocr_text.as_deref(), supplied_salient.as_deref()).map(
                |t| {
                    if t.chars().count() > 300 {
                        t.chars().take(300).collect::<String>()
                    } else {
                        t
                    }
                },
            );
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
            observation_status: row.get(8)?,
            literal_description: row.get(9)?,
            screen_state: row.get(10)?,
            source_key: row.get(7)?,
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
        return Err(crate::error::EnclaveError::Conflict(format!(
            "episode already has the maximum of {MAX_EPISODE_IMAGES} images"
        )));
    }
    if stored_bytes.saturating_add(byte_length) > MAX_EPISODE_IMAGE_BYTES {
        return Err(crate::error::EnclaveError::Conflict(format!(
            "episode image budget exceeds {} KiB",
            MAX_EPISODE_IMAGE_BYTES / 1024
        )));
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
    let outcome = record_screenshot_image_in_transaction(
        &tx,
        image_id,
        object_key,
        episode_id,
        source_key,
        requested_captured_at,
        jpeg,
    )?;
    tx.commit()?;
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn record_screenshot_image_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    image_id: &str,
    object_key: &str,
    episode_id: i64,
    source_key: &str,
    requested_captured_at: &str,
    jpeg: &ValidatedJpeg,
) -> crate::error::Result<ScreenshotRecordOutcome> {
    let target = validate_screenshot_upload_target(
        transaction,
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
            return Ok(ScreenshotRecordOutcome::Existing(existing))
        }
    };

    transaction.execute(
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

    // Retain one admission lease from preflight through the durable record.
    // Its owned PUT child prevents cancellation from letting deletion finish
    // before an admitted evidence object has a definite provider outcome.
    let _content_write = match s.store.acquire_content_write(&user_id).await {
        Ok(lease) => lease,
        Err(error) => return error.into_response(),
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
    let object_key = match crate::store::selected_evidence_media_object_key(&user_id, &opaque_key) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "selected evidence media key construction failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
        }
    };
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
    let put_lease = _content_write.child();
    let put_store = Arc::clone(&s.store);
    let put_user_id = user_id.clone();
    let put_object_key = object_key.clone();
    let put_wrapped_b64 = wrapped_b64.clone();
    let put = tokio::spawn(async move {
        let _put_lease = put_lease;
        put_store
            .put_user_media(
                &put_user_id,
                &put_object_key,
                &encrypted_data,
                &put_wrapped_b64,
            )
            .await
    });
    match put.await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            tracing::error!(error = %error, "media upload GCS write failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
        }
        Err(error) => {
            tracing::error!(error = %error, "media upload GCS task failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "media upload failed").into_response();
        }
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
                tracing::error!(error = %e, "failed to clean up redundant selected evidence media");
            }
            return (StatusCode::OK, Json(existing.response_json())).into_response();
        }
        Err(e) => {
            if let Err(cleanup_error) = s.store.delete_media(&object_key).await {
                tracing::error!(error = %cleanup_error, "failed to clean up rejected selected evidence media");
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
            tracing::error!(error = %cleanup_error, "failed to clean up selected evidence media after database save failure");
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

    // 1. Resolve either a legacy selected-evidence ID or a namespaced Cloud
    // Capture v2 asset ID inside this authenticated user's database.
    let user_id_cloned = user_id.clone();
    let query_res = s
        .store
        .with_user(&user_id_cloned, {
            let id_clone = id.clone();
            move |conn| screenshot_image_object_key(conn, &id_clone)
        })
        .await;

    let object_key = match query_res {
        Ok(Some(ok)) => ok,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
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

fn screenshot_image_object_key(
    conn: &Connection,
    id: &str,
) -> crate::error::Result<Option<String>> {
    if let Some(asset_id) = id.strip_prefix(CLOUD_CAPTURE_IMAGE_ID_PREFIX) {
        if asset_id.is_empty() {
            return Ok(None);
        }
        return Ok(conn
            .query_row(
                "SELECT object_key FROM media_objects \
                 WHERE asset_id = ?1 AND mime_type = 'image/jpeg' \
                   AND processing_state = 'ready' AND deleted_at IS NULL",
                [asset_id],
                |row| row.get(0),
            )
            .optional()?);
    }

    Ok(conn
        .query_row(
            "SELECT object_key FROM screenshot_images WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .optional()?)
}

#[derive(Deserialize)]
struct CreateWebhookRequest {
    name: String,
    endpoint_url: String,
    #[serde(default)]
    include_content: bool,
}

fn webhook_json(
    subscription: &crate::cp::control_store::WebhookSubscription,
    signing_secret: Option<&str>,
) -> Value {
    let mut value = json!({
        "id": subscription.id,
        "name": subscription.name,
        "endpoint_display": super::webhook_worker::endpoint_display(&subscription.endpoint_url),
        "include_content": subscription.include_content,
        "enabled": subscription.enabled,
        "created_at": subscription.created_at,
    });
    if let Some(secret) = signing_secret {
        value["signing_secret"] = json!(secret);
    }
    value
}

async fn rest_list_webhooks(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    match s.control.list_webhook_subscriptions(&user.0).await {
        Ok(subscriptions) => Json(json!({
            "webhooks": subscriptions
                .iter()
                .map(|subscription| webhook_json(subscription, None))
                .collect::<Vec<_>>()
        }))
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn rest_create_webhook(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateWebhookRequest>,
) -> Response {
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "name must be between 1 and 80 characters"})),
        )
            .into_response();
    }
    let endpoint_url = req.endpoint_url.trim();
    if let Err(error) = super::webhook_worker::validate_endpoint_syntax(endpoint_url) {
        return error.into_response();
    }

    let now = crate::cp::isotime::format_epoch_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    );
    let subscription = crate::cp::control_store::WebhookSubscription {
        id: super::tokens::new_uuid(),
        user_id: user.0,
        name: name.to_string(),
        endpoint_url: endpoint_url.to_string(),
        signing_secret: super::webhook_worker::new_signing_secret(),
        include_content: req.include_content,
        enabled: true,
        created_at: now,
    };
    match s
        .control
        .create_webhook_subscription(subscription.clone())
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(webhook_json(
                &subscription,
                Some(&subscription.signing_secret),
            )),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn rest_delete_webhook(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(subscription_id): Path<String>,
) -> Response {
    let user_id = user.0;
    match s
        .control
        .delete_webhook_subscription(&user_id, &subscription_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return error.into_response(),
    }
    let user_for_db = user_id.clone();
    let id_for_db = subscription_id.clone();
    match s
        .store
        .with_user(&user_for_db, move |conn| {
            conn.execute(
                "UPDATE webhook_deliveries
                 SET state = 'cancelled', error_code = 'subscription_deleted',
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE subscription_id = ?1 AND state IN ('pending', 'retry')",
                [id_for_db],
            )?;
            Ok(())
        })
        .await
    {
        Ok(()) => {
            if let Err(error) = s.store.save_user(&user_id).await {
                return error.into_response();
            }
        }
        Err(error) => return error.into_response(),
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn rest_test_webhook(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(subscription_id): Path<String>,
) -> Response {
    let subscription = match s
        .control
        .get_webhook_subscription(&user.0, &subscription_id)
        .await
    {
        Ok(Some(subscription)) if subscription.enabled => subscription,
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "webhook is disabled"})),
            )
                .into_response()
        }
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return error.into_response(),
    };
    match super::webhook_worker::send_test_webhook(&subscription).await {
        Ok(status) if (200..300).contains(&status) => {
            Json(json!({"delivered": true, "response_status": status})).into_response()
        }
        Ok(status) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "delivered": false,
                "response_status": status,
                "error": "destination rejected the test event"
            })),
        )
            .into_response(),
        Err(crate::error::EnclaveError::InvalidRequest(message)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"delivered": false, "error": message})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "delivered": false,
                "error": "destination could not be reached"
            })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateEpisodeEmailPreferenceRequest {
    enabled: bool,
    #[serde(default)]
    include_content: bool,
}

async fn rest_get_episode_email_preference(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let available = s.email_transport.is_some();
    match s.control.get_email_preference(&user.0).await {
        Ok(pref) => (
            StatusCode::OK,
            [("cache-control", "no-store")],
            Json(json!({
                "enabled": pref.enabled,
                "include_content": pref.include_content,
                "recipient_email": pref.recipient_email,
                "available": available,
            })),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn rest_put_episode_email_preference(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<UpdateEpisodeEmailPreferenceRequest>,
) -> Response {
    let available = s.email_transport.is_some();
    match s
        .control
        .set_email_preference(&user.0, req.enabled, req.include_content)
        .await
    {
        Ok(pref) => (
            StatusCode::OK,
            [("cache-control", "no-store")],
            Json(json!({
                "enabled": pref.enabled,
                "include_content": pref.include_content,
                "recipient_email": pref.recipient_email,
                "available": available,
            })),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn rest_test_episode_email(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let Some(ref transport) = s.email_transport else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("cache-control", "no-store")],
            Json(json!({
                "error": "native email delivery is unavailable",
                "code": "email_unavailable"
            })),
        )
            .into_response();
    };

    if !s.test_email_limiter.consume(&user.0).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("cache-control", "no-store")],
            Json(json!({
                "error": "rate limit exceeded for test emails",
                "code": "rate_limited"
            })),
        )
            .into_response();
    }

    let pref = match s.control.get_email_preference(&user.0).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let now_iso = crate::cp::isotime::format_epoch_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64,
    );

    let synthetic_episode = crate::cp::delivery::FinalizedEpisode {
        episode_id: 0,
        title: "Test Message".into(),
        started_at: now_iso.clone(),
        ended_at: now_iso.clone(),
        finalized_at: now_iso,
        episode_type: None,
        participants: Vec::new(),
        overview: "".into(),
        decisions: Vec::new(),
        action_items: Vec::new(),
        important_links: Vec::new(),
        open_questions: Vec::new(),
    };

    let subject = super::email_renderer::render_email_subject(&synthetic_episode, false);
    let (text_body, html_body) =
        super::email_renderer::render_email_body(&synthetic_episode, false, &s.config.web_origin);

    let req = super::email_worker::EmailRequest {
        to: pref.recipient_email,
        subject,
        text_body,
        html_body,
        idempotency_key: format!("test_{}", super::tokens::random_token_hex()),
    };

    match transport.send(req).await {
        Ok(_) => (
            StatusCode::OK,
            [("cache-control", "no-store")],
            Json(json!({"ok": true, "message": "Test email sent"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("cache-control", "no-store")],
            Json(json!({
                "error": "failed to send test email",
                "code": "email_unavailable"
            })),
        )
            .into_response(),
    }
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
            billing: Arc::new(crate::cp::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(crate::cp::billing::RecordingLeaseGates::default()),
            config: Arc::new(crate::cp::CpConfig {
                base_url: "http://localhost:8080".into(),
                jwt_secrets: vec!["test-secret".into()],
                google_desktop_client_id: "desktop".into(),
                google_ios_client_id: "ios".into(),
                google_web_client_id: "web".into(),
                google_web_client_secret: "secret".into(),
                apple_sign_in: None,
                allowed_emails: None,
                admin_user_ids: Vec::new(),
                scheduler_sa_email: None,
                vertex_project: "project".into(),
                vertex_location: "location".into(),
                vertex_model: "model".into(),
                quota_utterances_per_day: 1,
                quota_screenshots_per_day: 1,
                quota_mcp_calls_per_day: 1,
                quota_vertex_output_tokens_per_day: 524_288,
                web_origin: "http://localhost:3000".into(),
                reviewer_auth: None,
                billing_enforcement_mode: crate::cp::BillingEnforcementMode::Enforce,
            }),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
            push_transport: None,
            embedding: None,
            voice: None,
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

    #[test]
    fn webhook_list_projection_never_returns_endpoint_credentials() {
        let subscription = crate::cp::control_store::WebhookSubscription {
            id: "hook-1".into(),
            user_id: "user-1".into(),
            name: "Automation".into(),
            endpoint_url: "https://hooks.example.com/path-secret?token=query-secret".into(),
            signing_secret: "whsec_signing-secret".into(),
            include_content: false,
            enabled: true,
            created_at: "2026-07-24T12:00:00.000Z".into(),
        };

        let listed = webhook_json(&subscription, None);
        assert_eq!(listed["endpoint_display"], "https://hooks.example.com/…");
        assert!(listed.get("endpoint_url").is_none());
        assert!(listed.get("signing_secret").is_none());

        let created = webhook_json(&subscription, Some(&subscription.signing_secret));
        assert_eq!(created["signing_secret"], "whsec_signing-secret");
        assert!(created.get("endpoint_url").is_none());
    }

    #[test]
    fn mcp_tool_metadata_is_submission_ready_and_read_only() {
        let tools = tool_definitions();
        let tools = tools.as_array().expect("tool definitions must be an array");
        assert_eq!(tools.len(), 6);
        for tool in tools {
            assert!(tool["title"]
                .as_str()
                .is_some_and(|title| !title.is_empty()));
            assert!(tool["description"]
                .as_str()
                .is_some_and(|description| description.starts_with("Use this when")));
            assert_eq!(tool["annotations"]["readOnlyHint"], true);
            assert_eq!(tool["annotations"]["openWorldHint"], false);
            assert_eq!(tool["annotations"]["destructiveHint"], false);
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            assert_eq!(tool["outputSchema"]["type"], "object");
            for field_schema in tool["outputSchema"]["properties"]
                .as_object()
                .into_iter()
                .flat_map(|properties| properties.values())
            {
                if field_schema["items"]["type"] == "object" {
                    assert_eq!(
                        field_schema["items"]["additionalProperties"], false,
                        "MCP object arrays must enumerate their response fields"
                    );
                }
            }
        }
        let list_episodes = tools
            .iter()
            .find(|tool| tool["name"] == "list_episodes")
            .expect("list_episodes definition");
        assert!(
            list_episodes["inputSchema"]["properties"]
                .get("gap_minutes")
                .is_none(),
            "unused inputs must not be advertised"
        );
    }

    #[test]
    fn mcp_projection_removes_internal_search_and_timeline_fields() {
        let search = project_mcp_result(
            "search_screenshots",
            json!({
                "results": [{
                    "kind": "Screenshot",
                    "id": 42,
                    "captured_at": "2026-07-23T10:00:00Z",
                    "active_app": "Safari",
                    "window_title": "Kioku",
                    "ocr_text": "visible evidence",
                    "url": "https://kiokuu.com",
                    "score": 0.99,
                    "image_hash": "private-hash",
                    "source_key": "device:42",
                    "created_at": "2026-07-23T10:00:01Z"
                }]
            }),
        );
        let hit = &search["results"][0];
        assert_eq!(hit["ocr_text"], "visible evidence");
        for internal in ["id", "score", "image_hash", "source_key", "created_at"] {
            assert!(
                hit.get(internal).is_none(),
                "MCP search output must not expose {internal}"
            );
        }

        let context = project_mcp_result(
            "get_context",
            json!({
                "utterances": [{
                    "id": 7,
                    "audio_segment_id": 3,
                    "started_at": "2026-07-23T10:00:00Z",
                    "ended_at": "2026-07-23T10:01:00Z",
                    "speaker_label": "Me",
                    "language": "en",
                    "text": "bounded context",
                    "source_type": "mic",
                    "confidence": 0.8
                }],
                "screenshots": []
            }),
        );
        let utterance = &context["utterances"][0];
        assert_eq!(utterance["text"], "bounded context");
        assert!(utterance.get("id").is_none());
        assert!(utterance.get("audio_segment_id").is_none());
        assert!(utterance.get("confidence").is_none());
    }

    #[test]
    fn mcp_safety_boundary_covers_projected_content_surfaces() {
        let transcript = crate::cp::mcp_safety::sanitize_result(project_mcp_result(
            "search_transcripts",
            json!({
                "episodes": [{
                    "summary": "The patient discussed a diabetes diagnosis.",
                    "snippet": "safe meeting evidence"
                }],
                "results": [{
                    "text": "API key sk-exampleexampleexample",
                    "started_at": "2026-07-23T10:00:00Z"
                }]
            }),
        ));
        assert_eq!(
            transcript["episodes"][0]["summary"],
            "The patient discussed a diabetes [REDACTED]."
        );
        assert_eq!(transcript["results"][0]["text"], "API key [REDACTED]");

        let screenshot = crate::cp::mcp_safety::sanitize_result(project_mcp_result(
            "search_screenshots",
            json!({
                "results": [{
                    "ocr_text": "Card 4111 1111 1111 1111",
                    "url": "https://example.com/reset?token=secret-value"
                }]
            }),
        ));
        assert_eq!(screenshot["results"][0]["ocr_text"], "Card [REDACTED]");
        assert_eq!(screenshot["results"][0]["url"], "https://example.com/reset");

        let context = crate::cp::mcp_safety::sanitize_result(project_mcp_result(
            "get_context",
            json!({
                "utterances": [{"text": "SSN 123-45-6789"}],
                "screenshots": [{"ocr_text": "safe screen", "url": "https://example.com/renewal?utm_source=archive"}]
            }),
        ));
        assert_eq!(context["utterances"][0]["text"], "SSN [REDACTED]");
        assert_eq!(
            context["screenshots"][0]["url"],
            "https://example.com/renewal"
        );

        let range = crate::cp::mcp_safety::sanitize_result(project_mcp_result(
            "summarize_time_range",
            json!({
                "from": "2026-07-23T10:00:00Z",
                "to": "2026-07-23T11:00:00Z",
                "counts": {},
                "languages": [],
                "apps_seen": [],
                "digest": [{"text": "one-time code 123456"}]
            }),
        ));
        assert_eq!(range["digest"][0]["text"], "one-time [REDACTED]");

        let episodes = crate::cp::mcp_safety::sanitize_result(project_mcp_result(
            "list_episodes",
            json!({
                "episode_count": 1,
                "hidden_count": 0,
                "episodes": [{
                    "summary": "passport number 123456789",
                    "minute_summaries": [{"gist": "safe project update"}],
                    "final_brief": {"overview": "password was shown"}
                }]
            }),
        ));
        assert_eq!(episodes["episodes"][0]["summary"], "passport [REDACTED]");
        assert_eq!(
            episodes["episodes"][0]["final_brief"]["overview"],
            "password was shown"
        );
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
    async fn episode_members_expose_ready_cloud_capture_images_without_regressing_legacy_ids() {
        let state = query_test_state();
        let user_id = "episode-cloud-images-user";
        state
            .store
            .with_user(user_id, |conn| {
                conn.execute_batch(
                    "
                    INSERT INTO capture_sessions
                        (id, device_id, install_id, started_at, last_event_at, schema_version)
                    VALUES
                        ('session-1', 'device-1', 'install-1', '2026-08-01T10:00:00Z',
                         '2026-08-01T10:05:00Z', 2);
                    INSERT INTO capture_streams (id, capture_session_id, device_id, stream_kind)
                    VALUES ('stream-1', 'session-1', 'device-1', 'mac_screen');
                    INSERT INTO episodes (id, started_at, ended_at, title, summary)
                    VALUES (326, '2026-08-01T10:00:00Z', '2026-08-01T10:05:00Z',
                            'Cloud capture', 'Processed screens');

                    INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES
                        (1, '2026-08-01T10:00:01Z', 'cloud-v2:event-ready', 0),
                        (2, '2026-08-01T10:00:02Z', 'cloud-v2:event-processing', 0),
                        (3, '2026-08-01T10:00:03Z', 'cloud-v2:event-deleted', 0),
                        (4, '2026-08-01T10:00:04Z', 'cloud-v2:event-audio', 0),
                        (5, '2026-08-01T10:00:05Z', 'legacy-device:5', 0);
                    INSERT INTO episode_members (episode_id, record_type, record_id) VALUES
                        (326, 'screenshot', 1), (326, 'screenshot', 2),
                        (326, 'screenshot', 3), (326, 'screenshot', 4),
                        (326, 'screenshot', 5);

                    INSERT INTO capture_events
                        (event_id, device_id, install_id, capture_session_id, stream_id,
                         stream_kind, sequence, source_wall_at, source_monotonic_ns,
                         started_at, ended_at, timezone_id, utc_offset_minutes,
                         clock_uncertainty_ms, asset_id, manifest_digest)
                    VALUES
                        ('event-ready', 'device-1', 'install-1', 'session-1', 'stream-1',
                         'mac_screen', 1, '2026-08-01T10:00:01Z', '1',
                         '2026-08-01T10:00:01Z', '2026-08-01T10:00:01Z', 'UTC', 0, 0,
                         'asset-ready', 'digest-ready'),
                        ('event-processing', 'device-1', 'install-1', 'session-1', 'stream-1',
                         'mac_screen', 2, '2026-08-01T10:00:02Z', '2',
                         '2026-08-01T10:00:02Z', '2026-08-01T10:00:02Z', 'UTC', 0, 0,
                         'asset-processing', 'digest-processing'),
                        ('event-deleted', 'device-1', 'install-1', 'session-1', 'stream-1',
                         'mac_screen', 3, '2026-08-01T10:00:03Z', '3',
                         '2026-08-01T10:00:03Z', '2026-08-01T10:00:03Z', 'UTC', 0, 0,
                         'asset-deleted', 'digest-deleted'),
                        ('event-audio', 'device-1', 'install-1', 'session-1', 'stream-1',
                         'mac_screen', 4, '2026-08-01T10:00:04Z', '4',
                         '2026-08-01T10:00:04Z', '2026-08-01T10:00:04Z', 'UTC', 0, 0,
                         'asset-audio', 'digest-audio');
                    INSERT INTO media_objects
                        (asset_id, event_id, object_key, mime_type, codec, byte_length, sha256,
                         processing_state, deleted_at)
                    VALUES
                        ('asset-ready', 'event-ready', 'media/ready', 'image/jpeg', 'jpeg', 10,
                         'sha-ready', 'ready', NULL),
                        ('asset-processing', 'event-processing', 'media/processing', 'image/jpeg',
                         'jpeg', 10, 'sha-processing', 'processing', NULL),
                        ('asset-deleted', 'event-deleted', 'media/deleted', 'image/jpeg', 'jpeg',
                         10, 'sha-deleted', 'ready', '2026-08-02T00:00:00Z'),
                        ('asset-audio', 'event-audio', 'media/audio', 'audio/mp4', 'aac', 10,
                         'sha-audio', 'ready', NULL);
                    INSERT INTO screenshot_images
                        (id, screenshot_id, episode_id, source_key, captured_at, object_key,
                         mime_type, width, height, byte_length, sha256)
                    VALUES
                        ('legacy-image-id', 5, 326, 'legacy-device:5',
                         '2026-08-01T10:00:05Z', 'media/legacy', 'image/jpeg', 2, 2, 10,
                         'sha-legacy');
                    ",
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let response =
            rest_episode_members(State(state), Extension(AuthUser(user_id.into())), Path(326))
                .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let detail: Value = serde_json::from_slice(&body).unwrap();
        let ids: Vec<Option<&str>> = detail["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["cloud_image_id"].as_str())
            .collect();
        assert_eq!(
            ids,
            vec![
                Some("capture-v2:asset-ready"),
                None,
                None,
                None,
                Some("legacy-image-id")
            ]
        );
    }

    #[tokio::test]
    async fn screenshot_content_serves_only_the_owners_ready_cloud_capture_image() {
        let state = query_test_state();
        let user_id = "cloud-image-owner";
        let object_key = "media/cloud-image";
        let legacy_object_key = "media/legacy-image";
        let plaintext = b"test-jpeg-bytes";
        let legacy_plaintext = b"legacy-jpeg-bytes";
        let (dek, wrapped_dek) = crate::crypto::generate_and_wrap_dek(state.store.kms.as_ref())
            .await
            .unwrap();
        let encrypted = crate::crypto::encrypt_bound_blob(
            &dek,
            plaintext,
            &crate::store::media_blob_context(user_id, object_key),
        )
        .unwrap();
        state
            .store
            .put_media(object_key, &encrypted, &wrapped_dek)
            .await
            .unwrap();
        let encrypted_legacy = crate::crypto::encrypt_bound_blob(
            &dek,
            legacy_plaintext,
            &crate::store::media_blob_context(user_id, legacy_object_key),
        )
        .unwrap();
        state
            .store
            .put_media(legacy_object_key, &encrypted_legacy, &wrapped_dek)
            .await
            .unwrap();
        state
            .store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO app_metadata (key, value) VALUES (?1, ?2)",
                    rusqlite::params![MEDIA_DEK_METADATA_KEY, wrapped_dek],
                )?;
                conn.execute_batch(
                    "
                    INSERT INTO capture_sessions
                        (id, device_id, install_id, started_at, last_event_at, schema_version)
                    VALUES ('content-session', 'content-device', 'content-install',
                            '2026-08-01T10:00:00Z', '2026-08-01T10:00:01Z', 2);
                    INSERT INTO capture_streams (id, capture_session_id, device_id, stream_kind)
                    VALUES ('content-stream', 'content-session', 'content-device', 'mac_screen');
                    INSERT INTO capture_events
                        (event_id, device_id, install_id, capture_session_id, stream_id,
                         stream_kind, sequence, source_wall_at, source_monotonic_ns,
                         started_at, ended_at, timezone_id, utc_offset_minutes,
                         clock_uncertainty_ms, asset_id, manifest_digest)
                    VALUES
                        ('content-event', 'content-device', 'content-install', 'content-session',
                         'content-stream', 'mac_screen', 0, '2026-08-01T10:00:00Z', '1',
                         '2026-08-01T10:00:00Z', '2026-08-01T10:00:01Z', 'UTC', 0, 0,
                         'content-asset', 'content-digest'),
                        ('processing-event', 'content-device', 'content-install',
                         'content-session', 'content-stream', 'mac_screen', 1,
                         '2026-08-01T10:00:01Z', '2', '2026-08-01T10:00:01Z',
                         '2026-08-01T10:00:02Z', 'UTC', 0, 0, 'processing-asset',
                         'processing-digest'),
                        ('deleted-event', 'content-device', 'content-install', 'content-session',
                         'content-stream', 'mac_screen', 2, '2026-08-01T10:00:02Z', '3',
                         '2026-08-01T10:00:02Z', '2026-08-01T10:00:03Z', 'UTC', 0, 0,
                         'deleted-asset', 'deleted-digest'),
                        ('audio-event', 'content-device', 'content-install', 'content-session',
                         'content-stream', 'mac_screen', 3, '2026-08-01T10:00:03Z', '4',
                         '2026-08-01T10:00:03Z', '2026-08-01T10:00:04Z', 'UTC', 0, 0,
                         'audio-asset', 'audio-digest');
                    INSERT INTO media_objects
                        (asset_id, event_id, object_key, mime_type, codec, byte_length, sha256,
                         processing_state)
                    VALUES
                        ('content-asset', 'content-event', 'media/cloud-image', 'image/jpeg',
                         'jpeg', 15, 'content-sha', 'ready'),
                        ('processing-asset', 'processing-event', 'media/processing-image',
                         'image/jpeg', 'jpeg', 15, 'processing-sha', 'processing'),
                        ('deleted-asset', 'deleted-event', 'media/deleted-image', 'image/jpeg',
                         'jpeg', 15, 'deleted-sha', 'ready'),
                        ('audio-asset', 'audio-event', 'media/audio', 'audio/mp4', 'aac', 15,
                         'audio-sha', 'ready');
                    UPDATE media_objects SET deleted_at = '2026-08-02T00:00:00Z'
                    WHERE asset_id = 'deleted-asset';
                    INSERT INTO episodes (id, started_at, ended_at, title)
                    VALUES (99, '2026-08-01T10:00:00Z', '2026-08-01T10:00:01Z', 'Legacy');
                    INSERT INTO screenshots (id, captured_at, source_key, is_duplicate)
                    VALUES (99, '2026-08-01T10:00:00Z', 'legacy:99', 0);
                    INSERT INTO screenshot_images
                        (id, screenshot_id, episode_id, source_key, captured_at, object_key,
                         mime_type, width, height, byte_length, sha256)
                    VALUES
                        ('legacy-content-id', 99, 99, 'legacy:99',
                         '2026-08-01T10:00:00Z', 'media/legacy-image', 'image/jpeg', 2, 2,
                         17, 'legacy-content-sha');
                    ",
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let response = rest_screenshot_image_content(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.into())),
            Path("capture-v2:content-asset".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "image/jpeg");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), plaintext);

        let legacy_response = rest_screenshot_image_content(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.into())),
            Path("legacy-content-id".into()),
        )
        .await;
        assert_eq!(legacy_response.status(), StatusCode::OK);
        let legacy_body = axum::body::to_bytes(legacy_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(legacy_body.as_ref(), legacy_plaintext);

        let other_user = rest_screenshot_image_content(
            State(Arc::clone(&state)),
            Extension(AuthUser("different-cloud-image-user".into())),
            Path("capture-v2:content-asset".into()),
        )
        .await;
        assert_eq!(other_user.status(), StatusCode::NOT_FOUND);

        for unavailable_id in [
            "capture-v2:",
            "capture-v2:missing",
            "capture-v2:../content-asset",
            "capture-v2:processing-asset",
            "capture-v2:deleted-asset",
            "capture-v2:audio-asset",
        ] {
            let unavailable = rest_screenshot_image_content(
                State(Arc::clone(&state)),
                Extension(AuthUser(user_id.into())),
                Path(unavailable_id.into()),
            )
            .await;
            assert_eq!(unavailable.status(), StatusCode::NOT_FOUND);
        }
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

    #[tokio::test]
    async fn test_query_episodes_value_timezone_resilience() {
        std::env::set_var("ENCLAVE_TEST_MODE", "1");
        std::env::set_var("ALLOWED_EMAILS", "test@example.com");
        let store = Arc::new(Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new())));
        store
            .with_user("tz-user", |conn| {
                conn.execute_batch(
                    "
                    INSERT INTO episodes (id, started_at, ended_at, title, summary, substance)
                    VALUES (322, '2026-07-26T23:51:39.450Z', '2026-07-26T23:52:21.684Z', 'Test Episode', 'Test Summary', 'normal');
                    "
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let s = Arc::new(CpState {
            store: Arc::clone(&store),
            control: Arc::new(crate::cp::control_store::ControlStore::new(
                Arc::new(FakeKms),
                Arc::new(FakeGcs::new()),
            )),
            billing: Arc::new(crate::cp::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(crate::cp::billing::RecordingLeaseGates::default()),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 0.2),
            reference_batch_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: crate::cp::limits::RateLimiter::new(60.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(120.0, 2.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
            push_transport: None,
            config: Arc::new(
                crate::cp::CpConfig::from_env(vec!["secret".into()], "secret".into()).unwrap(),
            ),
            embedding: None,
            voice: None,
        });

        // Query using correct UTC bounds for 7:30 PM - 8:15 PM EDT
        // 7:30 PM EDT = 23:30 UTC, 8:15 PM EDT = 00:15 next day UTC
        let res = query_episodes_value(
            &s,
            "tz-user",
            Some("2026-07-26T23:30:00Z".into()),
            Some("2026-07-27T00:15:00Z".into()),
            10,
            false,
            None,
        )
        .await
        .unwrap();

        assert_eq!(res["episode_count"], 1);
        assert_eq!(res["episodes"][0]["id"], 322);

        // Also verify that EDT offset notation works identically
        let res2 = query_episodes_value(
            &s,
            "tz-user",
            Some("2026-07-26T19:30:00-04:00".into()),
            Some("2026-07-26T20:15:00-04:00".into()),
            10,
            false,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            res2["episode_count"], 1,
            "EDT offset notation should find the same episode"
        );
        assert_eq!(res2["episodes"][0]["id"], 322);
    }

    #[tokio::test]
    async fn test_query_episodes_with_offset_timestamps() {
        // This is the ACTUAL bug: MCP clients send -04:00 offset timestamps,
        // and the SQL string comparison + hardcoded offset fallbacks both fail.
        std::env::set_var("ENCLAVE_TEST_MODE", "1");
        std::env::set_var("ALLOWED_EMAILS", "test@example.com");
        let store = Arc::new(Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new())));
        store
            .with_user("tz-offset-user", |conn| {
                conn.execute_batch(
                    "\
                    INSERT INTO episodes (id, started_at, ended_at, title, summary, substance) \
                    VALUES (500, '2026-07-26T23:51:39.450Z', '2026-07-26T23:52:21.684Z', \
                            'Offset Test', 'Testing offset queries', 'normal');\
                    ",
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let s = Arc::new(CpState {
            store: Arc::clone(&store),
            control: Arc::new(crate::cp::control_store::ControlStore::new(
                Arc::new(FakeKms),
                Arc::new(FakeGcs::new()),
            )),
            billing: Arc::new(crate::cp::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(crate::cp::billing::RecordingLeaseGates::default()),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 0.2),
            reference_batch_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: crate::cp::limits::RateLimiter::new(60.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(120.0, 2.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: None,
            push_transport: None,
            config: Arc::new(
                crate::cp::CpConfig::from_env(vec!["secret".into()], "secret".into()).unwrap(),
            ),
            embedding: None,
            voice: None,
        });

        // Query with EDT offset timestamps: 7:00 PM to 8:00 PM EDT = 23:00-00:00 UTC
        // Episode at 23:51 UTC should be found
        let res = query_episodes_value(
            &s,
            "tz-offset-user",
            Some("2026-07-26T19:00:00-04:00".into()),
            Some("2026-07-26T20:00:00-04:00".into()),
            10,
            false,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            res["episode_count"], 1,
            "Offset -04:00 query should find the episode at 23:51 UTC"
        );
        assert_eq!(res["episodes"][0]["id"], 500);
    }

    #[tokio::test]
    async fn rest_episode_email_preferences_get_put_test() {
        let store = Arc::new(Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new())));
        let control = Arc::new(crate::cp::control_store::ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));

        let user = control
            .upsert_user("google-sub-query-test", "query_user@example.com")
            .await
            .unwrap();

        let s = Arc::new(CpState {
            store,
            control,
            billing: Arc::new(crate::cp::billing::FakeBillingGateway),
            recording_lease_gate: Arc::new(crate::cp::billing::RecordingLeaseGates::default()),
            config: query_test_state().config.clone(),
            user_verifier: Arc::new(crate::cp::auth::UserIdTokenVerifier::new(vec![])),
            reviewer_verifier: None,
            apple_provider: None,
            sync_limiter: crate::cp::limits::RateLimiter::new(10.0, 0.2),
            reference_batch_limiter: crate::cp::limits::RateLimiter::new(10.0, 1.0),
            reference_batch_concurrency: Arc::new(tokio::sync::Semaphore::new(4)),
            mcp_limiter: crate::cp::limits::RateLimiter::new(60.0, 1.0),
            oauth_limiter: crate::cp::limits::RateLimiter::new(120.0, 2.0),
            test_email_limiter: crate::cp::limits::RateLimiter::new(3.0, 0.05),
            email_transport: Some(Arc::new(crate::cp::email_worker::FakeEmailTransport::new())),
            push_transport: None,
            embedding: None,
            voice: None,
        });

        // 1. GET default preference
        let resp = rest_get_episode_email_preference(
            State(s.clone()),
            Extension(AuthUser(user.id.clone())),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // 2. PUT enable notification-only
        let put_req = UpdateEpisodeEmailPreferenceRequest {
            enabled: true,
            include_content: false,
        };
        let resp_put = rest_put_episode_email_preference(
            State(s.clone()),
            Extension(AuthUser(user.id.clone())),
            Json(put_req),
        )
        .await;
        assert_eq!(resp_put.status(), StatusCode::OK);

        // 3. POST test email
        let resp_test =
            rest_test_episode_email(State(s.clone()), Extension(AuthUser(user.id.clone()))).await;
        assert_eq!(resp_test.status(), StatusCode::OK);
    }
}
