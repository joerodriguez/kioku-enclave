//! Query surface: the MCP
//! server (`POST /mcp`, JSON-RPC 2.0, stateless) and the REST mirrors
//! (`/api/search`, `/api/episodes`, `/api/episodes/:id`,
//! `/api/episodes/:id/members`) the debugger
//! uses. All routes are auth-gated and read through the PostgreSQL repository
//! ports. `get_context` uses the redaction-aware memory-query repository.
//! `POST /api/episodes/:id/finalize` queues a scoped retry for an incomplete
//! or version-stale canonical brief. `/api/webhooks` manages signed,
//! user-configured finalized-episode event destinations.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::persistence::SearchRequest;

use super::auth::AuthUser;
use super::CpState;

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const EPISODE_CURSOR_VERSION: u8 = 1;
const MAX_EPISODE_CURSOR_CHARS: usize = 256;
const MAX_EPISODE_CURSOR_TIMESTAMP_BYTES: usize = 64;

/// The combined episode + utterance search behind `GET /api/search`.
///
/// This returns a `Result` and its caller must keep it that way. It used to be
/// `tool_search_transcripts`, which flattened every read failure into a bare
/// `Value` carrying `{"error": "search is unavailable"}`; `rest_search` handed
/// that straight to `Json(..).into_response()`, so a refusal shipped under HTTP
/// 200 and any client that switches on the status before the body read it as a
/// successful, empty search.
///
/// The name changed with the signature because the `tool_` prefix was already
/// wrong. MCP's own `search_transcripts` is served by
/// the PostgreSQL memory-query repository through `dispatch_tool`; this
/// function had exactly one caller, the REST route, and no MCP path at all.
async fn query_transcripts_value(
    s: &CpState,
    user_id: &str,
    args: &Value,
) -> crate::error::Result<Value> {
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

    let (query, speaker) = crate::persistence::extract_speaker_filter(&raw_query);
    let query_embedding = if query.trim().is_empty() {
        None
    } else {
        embed_query(s, &query).await
    };
    let ep_req = SearchRequest {
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
        query,
        speaker,
        time_start: from,
        time_end: to,
        limit,
        offset: 0,
        kinds: vec!["utterance".into()],
        query_embedding,
    };
    // A failed read must never be reported as "nothing found". An empty
    // payload here is indistinguishable from a true negative, so the assistant
    // would tell the user their data does not exist — while it is present and
    // merely unreadable (a transient DB error, or a routed read whose serving
    // authority is unavailable). Propagating the error is what lets each
    // caller answer loudly in its own idiom.
    //
    let episodes = s
        .repositories
        .memory_queries()
        .search(user_id, &ep_req)
        .await?;
    let utterances = s
        .repositories
        .memory_queries()
        .search(user_id, &utt_req)
        .await?;
    Ok(json!({
        "episodes": serde_json::to_value(&episodes).unwrap_or_else(|_| json!([])),
        "results": serde_json::to_value(&utterances).unwrap_or_else(|_| json!([])),
    }))
}
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
        .route("/api/screenshot-images", post(rest_screenshot_image_upload))
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
        query,
        speaker: None,
        time_start: args.get("from").and_then(|v| v.as_str()).map(String::from),
        time_end: args.get("to").and_then(|v| v.as_str()).map(String::from),
        limit,
        offset: 0,
        kinds: vec!["screenshot".into()],
        query_embedding,
    };
    // See the note in the combined search above: an unavailable PostgreSQL
    // read must not be answered with an authoritative-looking empty result.
    let hits = match s.repositories.memory_queries().search(user_id, &req).await {
        Ok(hits) => hits,
        Err(_) => return json!({ "error": "screenshot search is unavailable" }),
    };
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
    // See `query_episodes_value`: a failed read answers with an `error` key,
    // never with the empty list that reads as "you have no memories".
    match query_episodes_value(s, user_id, from, to, max, include_low, None).await {
        Ok(value) => value,
        Err(_) => json!({ "error": "episode list is unavailable" }),
    }
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

/// Opaque REST continuation key. Clients must round-trip the encoded value
/// rather than inspecting it; the versioned payload lets the server reject an
/// unknown representation instead of silently restarting at the first page.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EpisodeBeforeCursor {
    started_at: String,
    id: i64,
}

enum EpisodeQueryMode {
    Unpaged,
    RestPage { before: Option<EpisodeBeforeCursor> },
}

struct EpisodeRowsQuery {
    from: Option<String>,
    to: Option<String>,
    max: i64,
    include_low: bool,
    episode_id: Option<i64>,
}

fn encode_episode_before_cursor(started_at: &str, id: i64) -> String {
    let mut payload = Vec::with_capacity(1 + std::mem::size_of::<i64>() + started_at.len());
    payload.push(EPISODE_CURSOR_VERSION);
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(started_at.as_bytes());
    BASE64_URL.encode(payload)
}

fn is_valid_episode_cursor_timestamp(timestamp: &str) -> bool {
    if !timestamp.is_ascii()
        || timestamp.len() < 20
        || timestamp.len() > MAX_EPISODE_CURSOR_TIMESTAMP_BYTES
    {
        return false;
    }
    let bytes = timestamp.as_bytes();
    const DIGIT_POSITIONS: [usize; 14] = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last().expect("length checked above") != b'Z'
        || !DIGIT_POSITIONS
            .iter()
            .all(|position| bytes[*position].is_ascii_digit())
    {
        return false;
    }
    if timestamp.len() > 20
        && (bytes[19] != b'.'
            || bytes[20..timestamp.len() - 1].is_empty()
            || !bytes[20..timestamp.len() - 1]
                .iter()
                .all(u8::is_ascii_digit))
    {
        return false;
    }

    let parse = |range: std::ops::Range<usize>| timestamp[range].parse::<u8>().ok();
    let (Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        parse(5..7),
        parse(8..10),
        parse(11..13),
        parse(14..16),
        parse(17..19),
    ) else {
        return false;
    };
    &timestamp[0..4] != "0000"
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60
}

fn decode_episode_before_cursor(encoded: &str) -> Result<EpisodeBeforeCursor, ()> {
    if encoded.is_empty() || encoded.len() > MAX_EPISODE_CURSOR_CHARS {
        return Err(());
    }
    let bytes = BASE64_URL.decode(encoded).map_err(|_| ())?;
    if bytes.len() < 1 + std::mem::size_of::<i64>() + 20
        || bytes.len() > 1 + std::mem::size_of::<i64>() + MAX_EPISODE_CURSOR_TIMESTAMP_BYTES
        || bytes[0] != EPISODE_CURSOR_VERSION
    {
        return Err(());
    }
    let id = i64::from_be_bytes(bytes[1..9].try_into().map_err(|_| ())?);
    let started_at = std::str::from_utf8(&bytes[9..])
        .map_err(|_| ())?
        .to_string();
    if !is_valid_episode_cursor_timestamp(&started_at) {
        return Err(());
    }
    Ok(EpisodeBeforeCursor { started_at, id })
}

/// Shared list/detail query. Keeping the optional id filter here ensures the
/// direct detail endpoint cannot drift from the list row's fields, visibility
/// rules, derived counts, or final-brief shape.
///
/// This returns a `Result` and every caller must keep it that way. The
/// `list_episodes_value` wrapper that used to sit in front of it flattened ANY
/// error into `{"episode_count":0,"hidden_count":0,"episodes":[]}` — an
/// authoritative-looking empty list for a dataset that is fully present and
/// merely unreadable. A transient database error, a routed read whose serving
/// authority is unavailable, and a genuinely empty account were indis-
/// tinguishable, so both callers told the user they had no memories. The
/// wrapper is deleted rather than repaired: there is now no seam that can
/// quietly reintroduce the flattening.
async fn query_episodes_value(
    s: &CpState,
    user_id: &str,
    from: Option<String>,
    to: Option<String>,
    max: i64,
    include_low: bool,
    episode_id: Option<i64>,
) -> crate::error::Result<Value> {
    query_episodes_rows_value(
        s,
        user_id,
        EpisodeRowsQuery {
            from,
            to,
            max,
            include_low,
            episode_id,
        },
        EpisodeQueryMode::Unpaged,
    )
    .await
}

/// REST-capable episode page. Ordering and the continuation predicate use the
/// same `(started_at, id)` tuple, so equal timestamps neither duplicate nor
/// skip rows between pages.
async fn query_episodes_page_value(
    s: &CpState,
    user_id: &str,
    query: EpisodeRowsQuery,
    before: Option<EpisodeBeforeCursor>,
) -> crate::error::Result<Value> {
    let max = query.max.clamp(1, 50);
    query_episodes_rows_value(
        s,
        user_id,
        EpisodeRowsQuery { max, ..query },
        EpisodeQueryMode::RestPage { before },
    )
    .await
}

async fn query_episodes_rows_value(
    s: &CpState,
    user_id: &str,
    query: EpisodeRowsQuery,
    mode: EpisodeQueryMode,
) -> crate::error::Result<Value> {
    let EpisodeRowsQuery {
        from,
        to,
        max,
        include_low,
        episode_id,
    } = query;
    let (before, probe_for_more) = match mode {
        EpisodeQueryMode::Unpaged => (None, false),
        EpisodeQueryMode::RestPage { before } => (before, true),
    };
    let request = crate::persistence::EpisodeListRequest {
        from: from.map(|value| super::isotime::normalize_to_utc(&value)),
        to: to.map(|value| super::isotime::normalize_to_utc(&value)),
        // REST callers clamp before this boundary; the MCP helper's historical
        // zero-limit behavior remains observable and is preserved.
        limit: max,
        include_low,
        episode_id,
        before_started_at: before.as_ref().map(|cursor| cursor.started_at.clone()),
        before_id: before.map(|cursor| cursor.id),
        probe_for_more,
    };
    let page = s
        .repositories
        .memory_queries()
        .list_episodes(user_id, &request)
        .await?;
    let next_before = page.has_more.then(|| {
        page.episodes.last().and_then(|episode| {
            Some(encode_episode_before_cursor(
                episode.get("started_at")?.as_str()?,
                episode.get("id")?.as_i64()?,
            ))
        })
    });
    let mut value = json!({
        "episode_count": page.episodes.len(),
        "hidden_count": page.hidden_count,
        "episodes": page.episodes,
    });
    if probe_for_more {
        value["next_before"] = json!(next_before.flatten());
    }
    Ok(value)
}

async fn tool_get_capture_status(s: &CpState, user_id: &str) -> Value {
    s.repositories
        .memory_queries()
        .capture_status(user_id)
        .await
        .and_then(|status| serde_json::to_value(status).map_err(Into::into))
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

fn project_array_with_aliases(value: &Value, fields: &[&str], aliases: &[(&str, &str)]) -> Value {
    Value::Array(
        value
            .as_array()
            .into_iter()
            .flatten()
            .map(|item| {
                let mut projected = project_fields(item, fields);
                if let Some(projected) = projected.as_object_mut() {
                    for (source, destination) in aliases {
                        if !projected.contains_key(*destination) {
                            if let Some(field_value) =
                                item.get(*source).filter(|value| value.as_str().is_some())
                            {
                                projected.insert((*destination).to_string(), field_value.clone());
                            }
                        }
                    }
                }
                projected
            })
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
            "results": project_array_with_aliases(
                &result["results"],
                &["kind", "text", "speaker_label", "started_at"],
                &[("speaker", "speaker_label")],
            ),
        }),
        "search_screenshots" => json!({
            "results": project_array(
                &result["results"],
                &["kind", "captured_at", "active_app", "window_title", "ocr_text", "url"],
            ),
        }),
        "get_context" => json!({
            "utterances": project_array_with_aliases(
                &result["utterances"],
                &["started_at", "ended_at", "speaker_label", "language", "text", "source_type"],
                &[("speaker", "speaker_label")],
            ),
            "screenshots": project_array(
                &result["screenshots"],
                &["captured_at", "active_app", "window_title", "ocr_text", "url"],
            ),
        }),
        "summarize_time_range" => json!({
            "from": result["from"],
            "to": result["to"],
            "counts": result["counts"],
            "languages": result["languages"],
            "apps_seen": result["apps_seen"],
            "digest": project_array(&result["digest"], &["at", "speaker", "text"]),
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

fn minimized_page_size(args: &Value, field: &str) -> usize {
    args.get(field)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(super::mcp_safety::DEFAULT_MINIMIZED_PAGE_SIZE)
        .clamp(1, super::mcp_safety::MAX_MINIMIZED_PAGE_SIZE)
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
                    "limit": {"type": "integer", "minimum": 1, "maximum": super::mcp_safety::MAX_MINIMIZED_PAGE_SIZE, "default": super::mcp_safety::DEFAULT_MINIMIZED_PAGE_SIZE, "description": "Maximum episode and utterance matches to return."}
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
                "additionalProperties": false
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
                    "max_items": {"type": "integer", "minimum": 1, "maximum": super::mcp_safety::MAX_MINIMIZED_PAGE_SIZE, "default": super::mcp_safety::DEFAULT_MINIMIZED_PAGE_SIZE, "description": "Maximum chronological utterance evidence items."}
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
    // All six tools read through the PostgreSQL memory-query repository and
    // bind every query to the authenticated account. A failure must surface an
    // `error` key: that is
    // what sets `isError` on the tool result, and it is the only thing that
    // distinguishes "unreadable" from "you have no data".
    let result = match name {
        "search_transcripts" => {
            let query = args
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let from = args.get("from").and_then(|v| v.as_str()).map(String::from);
            let to = args.get("to").and_then(|v| v.as_str()).map(String::from);
            let limit = minimized_page_size(args, "limit");
            s.repositories
                .memory_queries()
                .mcp_search_transcripts(
                    user_id,
                    &crate::persistence::McpTranscriptSearchRequest {
                        query,
                        from,
                        to,
                        limit,
                    },
                )
                .await
                .unwrap_or_else(|_| json!({ "error": "transcript search is unavailable" }))
        }
        "get_context" => {
            let at = args
                .get("at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let window = args
                .get("window_seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(300);
            let limit = None;
            s.repositories
                .memory_queries()
                .mcp_context(
                    user_id,
                    &crate::persistence::McpContextRequest {
                        at,
                        window_seconds: window,
                        limit,
                    },
                )
                .await
                .unwrap_or_else(|_| json!({ "error": "context lookup is unavailable" }))
        }
        "summarize_time_range" => {
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
            let limit = Some(minimized_page_size(args, "max_items"));
            s.repositories
                .memory_queries()
                .mcp_time_range(
                    user_id,
                    &crate::persistence::McpTimeRangeRequest { from, to, limit },
                )
                .await
                .unwrap_or_else(|_| json!({ "error": "time-range summary is unavailable" }))
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

    if rpc.method == "tools/call" {
        // Every tool reaches PostgreSQL through the selected user's repository
        // boundary. Safety refusal runs before any tool dispatch.
        //
        // A volatile rate limit protects the service without making read-only
        // tool calls persist usage or query-log state.
        if !s
            .mcp_limiter
            .consume_scoped(&s.repositories, "mcp-tool", &user_id)
            .await
        {
            return rpc_error(&rpc.id, -32000, "rate_limited");
        }
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
    // PostgreSQL is authoritative for both episode and utterance results, so
    // an empty successful result is truthful for this account.
    let args =
        json!({ "query": q, "from": p.from, "to": p.to, "limit": p.limit.unwrap_or(10).min(50) });
    // The same treatment `rest_episodes` gets, and for the same reason: this
    // route used to call the MCP wrapper and hand its flattened `Value`
    // straight to `Json(..).into_response()`, an unconditional 200. A failed
    // read shipped `{"error": "search is unavailable"}` under a success
    // status, so a client that switches on the status read a refusal as an
    // empty result set.
    match query_transcripts_value(&s, &user.0, &args).await {
        Ok(data) => Json(data).into_response(),
        Err(e) => super::routed_read_unavailable("api.search", &e),
    }
}

#[derive(Deserialize)]
struct EpisodesParams {
    from: Option<String>,
    to: Option<String>,
    max_episodes: Option<i64>,
    include_low: Option<String>,
    before: Option<String>,
}

async fn rest_episodes(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(p): Query<EpisodesParams>,
) -> Response {
    let include_low = p.include_low.as_deref().is_some_and(string_is_truthy);
    let before = match p
        .before
        .as_deref()
        .map(decode_episode_before_cursor)
        .transpose()
    {
        Ok(before) => before,
        Err(()) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_before"})),
            )
                .into_response();
        }
    };
    // A read that fails answers 503, never 200 with an empty list: "no
    // episodes" and "your episodes are unreadable" are different facts, and
    // the debugger renders the first as an account with no memories.
    match query_episodes_page_value(
        &s,
        &user.0,
        EpisodeRowsQuery {
            from: p.from,
            to: p.to,
            max: p.max_episodes.unwrap_or(50).clamp(1, 50),
            include_low,
            episode_id: None,
        },
        before,
    )
    .await
    {
        Ok(data) => Json(data).into_response(),
        Err(e) => super::routed_read_unavailable("api.episodes", &e),
    }
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
    // The `NotFound` arm below stays a 404 and is not funnelled into the
    // unavailable-read 503: an id that is
    // absent from readable state is a different fact from state that
    // could not be read, and only the second is retryable.
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
        Err(e) => super::routed_read_unavailable("api.episode", &e),
    }
}

/// DELETE /api/episodes/{id} — purge an episode AND its member raw records
/// (utterances, screenshots, emptied segments, vectors, FTS entries). The
/// response carries the deleted records' source_keys so the caller (the Mac
/// debugger's local server) can purge the matching LOCAL rows and media files
/// — without that, a forced resync would re-upload the content.
async fn advance_episode_deletion(
    repository: &dyn crate::persistence::EpisodeDeletionRepository,
    media_objects: &dyn crate::persistence::MediaObjectStore,
    account_id: &str,
    plan: &crate::persistence::EpisodeDeletionPlan,
) -> crate::error::Result<crate::persistence::EpisodePurge> {
    for object_key in &plan.media_object_keys {
        media_objects.delete_current(object_key).await?;
    }
    repository.complete_episode_deletion(account_id, plan).await
}

async fn rest_episode_delete(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(episode_id): Path<i64>,
) -> Response {
    let repository = state.repositories.episode_deletions();
    let plan = match repository.begin_episode_deletion(&user.0, episode_id).await {
        Ok(crate::persistence::EpisodeDeletionStart::NotFound) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "episode_not_found"})),
            )
                .into_response();
        }
        Ok(crate::persistence::EpisodeDeletionStart::Complete(purge)) => {
            return episode_purge_response(episode_id, purge);
        }
        Ok(crate::persistence::EpisodeDeletionStart::Pending(plan)) => plan,
        Err(error) => {
            tracing::error!(%error, episode_id, "episode deletion preparation failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "enclave_unavailable"})),
            )
                .into_response();
        }
    };
    match advance_episode_deletion(
        state.repositories.episode_deletions(),
        state.repositories.media_objects(),
        &user.0,
        &plan,
    )
    .await
    {
        Ok(purge) => episode_purge_response(episode_id, purge),
        Err(error) => {
            tracing::error!(%error, episode_id, "episode deletion remains pending");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "media_delete_failed",
                    "deletion_pending": true,
                })),
            )
                .into_response()
        }
    }
}

fn episode_purge_response(episode_id: i64, purge: crate::persistence::EpisodePurge) -> Response {
    Json(json!({
        "deleted": true,
        "episode_id": episode_id,
        "deleted_utterances": purge.deleted_utterances,
        "deleted_screenshots": purge.deleted_screenshots,
        "deleted_segments": purge.deleted_segments,
        "utterance_source_keys": purge.utterance_source_keys,
        "screenshot_source_keys": purge.screenshot_source_keys,
    }))
    .into_response()
}

const EPISODE_DELETE_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const EPISODE_DELETE_RECONCILE_BATCH: usize = 32;

async fn reconcile_pending_episode_deletions(
    repository: &dyn crate::persistence::EpisodeDeletionRepository,
    media_objects: &dyn crate::persistence::MediaObjectStore,
) -> crate::error::Result<()> {
    let pending = repository
        .pending_episode_deletions(EPISODE_DELETE_RECONCILE_BATCH)
        .await?;
    for (account_id, plan) in pending {
        if let Err(error) =
            advance_episode_deletion(repository, media_objects, &account_id, &plan).await
        {
            tracing::warn!(
                episode_id = plan.episode_id,
                error = %error,
                "episode deletion remains pending"
            );
        }
    }
    Ok(())
}

pub(crate) fn spawn_episode_delete_worker(state: Arc<CpState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(EPISODE_DELETE_RECONCILE_INTERVAL);
        loop {
            interval.tick().await;
            if let Err(error) = reconcile_pending_episode_deletions(
                state.repositories.episode_deletions(),
                state.repositories.media_objects(),
            )
            .await
            {
                tracing::warn!(error = %error, "episode deletion reconciliation failed");
            }
        }
    });
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
    // PostgreSQL owns every table that decides the answer. LEFT JOINed identity
    // and image tables only widen a member row; they cannot create or suppress
    // one.
    let result = s
        .repositories
        .memory_queries()
        .episode_members(&user.0, id)
        .await;
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => super::routed_read_unavailable("api.episode_members", &e),
    }
}

async fn rest_browser_snapshot(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(source_key): Path<String>,
) -> Response {
    let result = s
        .repositories
        .memory_queries()
        .browser_snapshot(&user.0, &source_key)
        .await;
    match result {
        Ok(Some(snapshot)) => Json(snapshot).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        Err(e) => super::routed_read_unavailable("api.browser_snapshot", &e),
    }
}

async fn rest_episode_finalize(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(episode_id): Path<i64>,
) -> Response {
    let outcome = state
        .repositories
        .finalization()
        .request_finalization(
            &user.0,
            episode_id,
            i64::from(super::finalizer::FINALIZATION_VERSION),
        )
        .await;
    match outcome {
        Ok(crate::persistence::FinalizationRequest::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "episode_not_found"})),
        )
            .into_response(),
        Ok(crate::persistence::FinalizationRequest::LowSignal) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "low_signal_episode"})),
        )
            .into_response(),
        Ok(crate::persistence::FinalizationRequest::AlreadyComplete { status }) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "already_complete", "status": status})),
        )
            .into_response(),
        Ok(crate::persistence::FinalizationRequest::AlreadyQueued { status }) => (
            StatusCode::ACCEPTED,
            Json(json!({"queued": true, "episode_id": episode_id, "status": status})),
        )
            .into_response(),
        Ok(crate::persistence::FinalizationRequest::Queued) => {
            let worker_state = Arc::clone(&state);
            let worker_user = user.0;
            tokio::spawn(async move {
                if let Err(error) =
                    super::finalizer::finalize_user_episode(&worker_state, &worker_user, episode_id)
                        .await
                {
                    tracing::warn!(
                        %error,
                        episode_id,
                        "scoped episode finalization failed"
                    );
                }
            });
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "queued": true,
                    "episode_id": episode_id,
                    "status": "queued",
                })),
            )
                .into_response()
        }
        Err(error) => {
            tracing::warn!(%error, episode_id, "failed to queue episode finalization");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "enclave_unavailable"})),
            )
                .into_response()
        }
    }
}

async fn rest_feed(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(p): Query<FeedParams>,
) -> Response {
    // The feed merges PostgreSQL utterances and screenshots and annotates them
    // from the selected account's episode membership.
    let request = crate::persistence::MemoryFeedRequest {
        from: p.from,
        to: p.to,
        limit: p.limit.unwrap_or(50).min(200),
        before: p.before,
    };
    let result = s
        .repositories
        .memory_queries()
        .feed(&user.0, &request)
        .await;

    match result {
        Ok(page) => Json(page).into_response(),
        Err(e) => super::routed_read_unavailable("api.feed", &e),
    }
}

#[derive(Debug, Deserialize)]
struct FeedParams {
    from: Option<String>,
    to: Option<String>,
    limit: Option<usize>,
    before: Option<String>,
}

async fn rest_screenshot_upload_plan(
    State(_state): State<Arc<CpState>>,
    Extension(_user): Extension<AuthUser>,
) -> Response {
    selected_screenshot_upload_retired()
}

async fn rest_screenshot_image_upload(
    State(_state): State<Arc<CpState>>,
    Extension(_user): Extension<AuthUser>,
) -> Response {
    selected_screenshot_upload_retired()
}

fn selected_screenshot_upload_retired() -> Response {
    (
        StatusCode::GONE,
        Json(serde_json::json!({"error": "screenshot_upload_retired"})),
    )
        .into_response()
}

async fn rest_screenshot_image_content(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Response {
    let user_id = user.0;
    if let Err(e) = crate::gcs::validate_user_id(&user_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // 1. Resolve a namespaced Cloud Capture v2 asset inside this authenticated
    // user's PostgreSQL state. The result is the complete immutable media
    // identity; object_key alone is not authority to read a provider generation.
    let query_res = s
        .repositories
        .memory_queries()
        .screenshot_media(&user_id, &id)
        .await;

    let locator = match query_res {
        Ok(Some(ok)) => ok,
        // A failed read is NOT an absence. This arm used to be byte-identical
        // to the `Ok(None)` arm below and unlogged, so an unavailable database
        // told the caller their screenshot does not exist and nothing recorded
        // that it had happened. The DEK read further down already answered
        // loudly; this one now matches it.
        Err(crate::error::EnclaveError::InvalidRequest(_)) => {
            tracing::error!("canonical screenshot identity is malformed at rest");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => return super::routed_read_unavailable("api.screenshot_image_content.lookup", &e),
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
    };

    // 2. Fetch the exact encrypted capture generation.
    let crate::persistence::ScreenshotMediaLocator::Canonical {
        object_key,
        generation,
        byte_length,
        sha256,
    } = &locator;
    let gcs_resp = match s
        .repositories
        .media_objects()
        .get_current_generation(object_key, *generation)
        .await
    {
        Ok(response) => response,
        Err(crate::error::EnclaveError::NotFound) => {
            // Retention deletes the provider generation before it
            // settles the row. Re-read authority: a now-ineligible row
            // is a truthful 404; an unchanged ready tuple means storage
            // is unavailable and must not masquerade as absence.
            return match s
                .repositories
                .memory_queries()
                .screenshot_media(&user_id, &id)
                .await
            {
                Ok(None) => StatusCode::NOT_FOUND.into_response(),
                Ok(Some(_)) | Err(_) => super::routed_read_unavailable(
                    "api.screenshot_image_content.object_missing",
                    &crate::error::EnclaveError::Store(
                        "sealed screenshot generation is unavailable".into(),
                    ),
                ),
            };
        }
        Err(error) => {
            return super::routed_read_unavailable("api.screenshot_image_content.object", &error)
        }
    };

    // 3. Load user's media DEK
    let wrapped_opt_res = s.repositories.captures().media_dek_wrapped(&user_id).await;

    let wrapped_opt = match wrapped_opt_res {
        Ok(w) => w,
        // Was a 500. It is a routed-read failure like any other and moves to
        // the lane's 503 under `super::routed_read_unavailable`'s rule; the
        // two crypto arms below keep 500 because they are not retryable.
        Err(e) => return super::routed_read_unavailable("api.screenshot_image_content.dek", &e),
    };

    let wrapped_b64 = match wrapped_opt {
        Some(w) => w,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let media_dek = match crate::crypto::load_dek(s.kms.as_ref(), &wrapped_b64).await {
        Ok(dek) => dek,
        Err(
            error @ (crate::error::EnclaveError::Http(_)
            | crate::error::EnclaveError::Attestation(_)),
        ) => return super::routed_read_unavailable("api.screenshot_image_content.kms", &error),
        Err(e) => {
            tracing::error!(error = %e, "media download DEK load failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 4. Bind media to both the authenticated user and exact object key.
    let media_context = crate::gcs::media_blob_context(&user_id, object_key);
    if gcs_resp.generation != *generation || gcs_resp.wrapped_dek_b64 != wrapped_b64 {
        tracing::error!("canonical screenshot provider identity mismatch");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let opened = match crate::crypto::decrypt_bound_blob_v2(
        &media_dek,
        &gcs_resp.ciphertext,
        &media_context,
    ) {
        Ok(opened) => opened,
        Err(error) => {
            tracing::error!(error = %error, "media download authentication failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let actual_sha256 = format!("{:x}", Sha256::digest(&opened.plaintext));
    if opened.plaintext.len() as i64 != *byte_length || !actual_sha256.eq_ignore_ascii_case(sha256)
    {
        tracing::error!("canonical screenshot plaintext commitment mismatch");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (
        StatusCode::OK,
        [("Content-Type", "image/jpeg")],
        opened.plaintext,
    )
        .into_response()
}

async fn rest_list_webhooks(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    match s
        .repositories
        .notifications()
        .list_webhook_subscriptions(&user.0)
        .await
    {
        Ok(subscriptions) => {
            let mut webhooks = Vec::with_capacity(subscriptions.len());
            for subscription in &subscriptions {
                let status = match super::webhook_worker::webhook_delivery_status(
                    &s,
                    &user.0,
                    &subscription.id,
                )
                .await
                {
                    Ok(status) => status,
                    Err(error) => {
                        return super::routed_read_unavailable(
                            "api.webhooks.delivery_status",
                            &error,
                        )
                    }
                };
                webhooks.push(webhook_json(subscription, None, Some(&status)));
            }
            Json(json!({"webhooks": webhooks})).into_response()
        }
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize)]
struct CreateWebhookRequest {
    name: String,
    endpoint_url: String,
    #[serde(default)]
    include_content: bool,
}

fn webhook_json(
    subscription: &crate::persistence::WebhookSubscription,
    signing_secret: Option<&str>,
    delivery_status: Option<&super::webhook_worker::WebhookDeliveryStatusSummary>,
) -> Value {
    let mut value = json!({
        "id": subscription.id,
        "name": subscription.name,
        "endpoint_display": super::webhook_worker::endpoint_display(&subscription.endpoint_url),
        "include_content": subscription.include_content,
        "enabled": subscription.enabled,
        "created_at": subscription.created_at,
        "delivery_status": delivery_status.cloned().unwrap_or_default(),
    });
    if let Some(secret) = signing_secret {
        value["signing_secret"] = json!(secret);
    }
    value
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
    let subscription = crate::persistence::WebhookSubscription {
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
        .repositories
        .notifications()
        .create_webhook_subscription(subscription.clone())
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(webhook_json(
                &subscription,
                Some(&subscription.signing_secret),
                None,
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
        .repositories
        .notifications()
        .get_webhook_subscription(&user_id, &subscription_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return error.into_response(),
    }
    if let Err(error) = s
        .repositories
        .notifications()
        .disable_webhook_subscription(&user_id, &subscription_id)
        .await
    {
        return error.into_response();
    }
    if let Err(error) =
        super::webhook_worker::cancel_subscription_deliveries(&s, &user_id, &subscription_id).await
    {
        return error.into_response();
    }
    match s
        .repositories
        .notifications()
        .delete_webhook_subscription(&user_id, &subscription_id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn rest_test_webhook(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(subscription_id): Path<String>,
) -> Response {
    let subscription = match s
        .repositories
        .notifications()
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
    match s
        .repositories
        .notifications()
        .get_email_preference(&user.0)
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

async fn rest_put_episode_email_preference(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<UpdateEpisodeEmailPreferenceRequest>,
) -> Response {
    let available = s.email_transport.is_some();
    match s
        .repositories
        .notifications()
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

    if !s
        .test_email_limiter
        .consume_scoped(&s.repositories, "test-email", &user.0)
        .await
    {
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

    let pref = match s
        .repositories
        .notifications()
        .get_email_preference(&user.0)
        .await
    {
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
mod mcp_contract_tests {
    use serde_json::{json, Value};

    use super::{project_mcp_result, tool_definitions};

    fn schema_for<'a>(definitions: &'a Value, name: &str) -> &'a Value {
        definitions
            .as_array()
            .expect("tool definitions")
            .iter()
            .find(|tool| tool["name"] == name)
            .map(|tool| &tool["outputSchema"])
            .expect("named output schema")
    }

    fn type_matches(value: &Value, expected: &str) -> bool {
        match expected {
            "array" => value.is_array(),
            "boolean" => value.is_boolean(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "null" => value.is_null(),
            "number" => value.is_number(),
            "object" => value.is_object(),
            "string" => value.is_string(),
            _ => false,
        }
    }

    fn assert_schema_valid(value: &Value, schema: &Value, path: &str) {
        if let Some(expected) = schema.get("type") {
            let valid = match expected {
                Value::String(expected) => type_matches(value, expected),
                Value::Array(expected) => expected
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|expected| type_matches(value, expected)),
                _ => false,
            };
            assert!(valid, "{path}: {value} does not match type {expected}");
        }

        if let Some(object) = value.as_object() {
            let properties = schema.get("properties").and_then(Value::as_object);
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                for key in required.iter().filter_map(Value::as_str) {
                    assert!(
                        object.contains_key(key),
                        "{path}: missing required key {key}"
                    );
                }
            }
            if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                let properties = properties.expect("closed object properties");
                for key in object.keys() {
                    assert!(properties.contains_key(key), "{path}: undeclared key {key}");
                }
            }
            if let Some(properties) = properties {
                for (key, child) in object {
                    if let Some(child_schema) = properties.get(key) {
                        assert_schema_valid(child, child_schema, &format!("{path}.{key}"));
                    }
                }
            }
        }

        if let (Some(items), Some(values)) = (schema.get("items"), value.as_array()) {
            for (index, child) in values.iter().enumerate() {
                assert_schema_valid(child, items, &format!("{path}[{index}]"));
            }
        }
    }

    #[test]
    fn successful_mcp_projections_match_every_advertised_output_schema() {
        let definitions = tool_definitions();
        let cases = [
            (
                "search_transcripts",
                json!({
                    "episodes": [{
                        "id": 1,
                        "kind": "episode",
                        "started_at": "2026-07-22T09:00:00Z",
                        "ended_at": "2026-07-22T09:35:00Z",
                        "title": null,
                        "summary": "Launch planning",
                        "minute_summaries": [],
                        "snippet": "August 19"
                    }],
                    "results": [{
                        "id": 2,
                        "kind": "utterance",
                        "text": "Move the launch to August 19.",
                        "speaker": "Maya",
                        "started_at": "2026-07-22T09:01:30Z",
                        "ended_at": "2026-07-22T09:01:44Z"
                    }]
                }),
            ),
            (
                "search_screenshots",
                json!({"results": [{
                    "kind": "Screenshot",
                    "captured_at": "2026-07-22T11:20:00Z",
                    "active_app": "Google Chrome",
                    "window_title": "Vendor renewal checklist",
                    "ocr_text": "Renewal checklist",
                    "url": "https://example.com/renewal",
                    "observation_status": "observed",
                    "literal_description": "internal",
                    "screen_state": "internal",
                    "content_type": "internal",
                    "score": 1.0
                }]}),
            ),
            (
                "get_context",
                json!({
                    "summary_digest": "internal",
                    "window_seconds": 300,
                    "utterances": [{
                        "id": 3,
                        "text": "Alex owns the launch checklist.",
                        "speaker": "Maya",
                        "language": "en",
                        "source_type": "mic",
                        "started_at": "2026-07-22T09:01:58Z",
                        "ended_at": "2026-07-22T09:02:14Z"
                    }],
                    "screenshots": [{
                        "captured_at": "2026-07-22T09:02:00Z",
                        "active_app": null,
                        "window_title": null,
                        "ocr_text": null,
                        "url": null,
                        "observation_status": "internal"
                    }],
                    "page_token": null
                }),
            ),
            (
                "summarize_time_range",
                json!({
                    "from": "2026-07-22T14:00:00Z",
                    "to": "2026-07-22T15:00:00Z",
                    "counts": {"utterances": 2, "screenshots": 0},
                    "languages": ["en"],
                    "apps_seen": [],
                    "digest": [{
                        "at": "2026-07-22T14:05:00Z",
                        "speaker": "Camille",
                        "text": "Use depuis.",
                        "id": 4
                    }],
                    "internal_summary": "drop me"
                }),
            ),
            (
                "list_episodes",
                json!({
                    "episode_count": 1,
                    "hidden_count": 0,
                    "episodes": [{
                        "id": 5,
                        "started_at": "2026-07-22T09:00:00Z",
                        "ended_at": "2026-07-22T09:35:00Z",
                        "title": "Launch planning",
                        "summary": null,
                        "type": "meeting",
                        "participants": ["Maya"],
                        "languages": ["en"],
                        "action_items": [],
                        "minute_summaries": [],
                        "utterance_count": 2,
                        "screenshot_count": 0,
                        "top_apps": [],
                        "top_domains": [],
                        "final_brief": null
                    }]
                }),
            ),
            (
                "get_capture_status",
                json!({
                    "total_utterances": 6,
                    "total_screenshots": 1,
                    "episode_count": 4,
                    "last_utterance_at": "2026-07-22T14:11:54Z",
                    "last_screenshot_at": null
                }),
            ),
        ];

        for (name, raw) in cases {
            let projected = project_mcp_result(name, raw);
            assert_schema_valid(&projected, schema_for(&definitions, name), name);
        }
    }

    #[test]
    fn mcp_projection_is_exact_and_drops_internal_or_invalid_alias_fields() {
        assert_eq!(
            project_mcp_result(
                "search_screenshots",
                json!({"results": [{
                    "kind": "Screenshot",
                    "captured_at": "2026-07-22T11:20:00Z",
                    "active_app": "Google Chrome",
                    "window_title": "Vendor renewal checklist",
                    "ocr_text": "Renewal checklist",
                    "url": "https://example.com/renewal",
                    "observation_status": "internal",
                    "literal_description": "internal",
                    "screen_state": "internal",
                    "content_type": "internal"
                }]}),
            ),
            json!({"results": [{
                "kind": "Screenshot",
                "captured_at": "2026-07-22T11:20:00Z",
                "active_app": "Google Chrome",
                "window_title": "Vendor renewal checklist",
                "ocr_text": "Renewal checklist",
                "url": "https://example.com/renewal"
            }]})
        );

        let transcript = project_mcp_result(
            "search_transcripts",
            json!({"episodes": [], "results": [
                {"text": "first", "speaker": "Maya", "started_at": "2026-07-22T09:00:00Z"},
                {"text": "second", "speaker": null, "started_at": "2026-07-22T09:01:00Z"}
            ]}),
        );
        assert_eq!(transcript["results"][0]["speaker_label"], "Maya");
        assert!(transcript["results"][1].get("speaker_label").is_none());

        assert_eq!(
            project_mcp_result(
                "summarize_time_range",
                json!({
                    "from": "2026-07-22T14:00:00Z",
                    "to": "2026-07-22T15:00:00Z",
                    "counts": {"utterances": 2, "screenshots": 0},
                    "languages": ["en"],
                    "apps_seen": [],
                    "digest": [{"at": "2026-07-22T14:05:00Z", "speaker": "Camille", "text": "depuis", "id": 4}],
                    "internal": true
                }),
            ),
            json!({
                "from": "2026-07-22T14:00:00Z",
                "to": "2026-07-22T15:00:00Z",
                "counts": {"utterances": 2, "screenshots": 0},
                "languages": ["en"],
                "apps_seen": [],
                "digest": [{"at": "2026-07-22T14:05:00Z", "speaker": "Camille", "text": "depuis"}]
            })
        );
    }

    #[test]
    fn public_mcp_limits_match_the_minimized_egress_policy() {
        let definitions = tool_definitions();
        let search = definitions
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "search_transcripts")
            .unwrap();
        let range = definitions
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "summarize_time_range")
            .unwrap();
        for input in [
            &search["inputSchema"]["properties"]["limit"],
            &range["inputSchema"]["properties"]["max_items"],
        ] {
            assert_eq!(
                input["maximum"],
                crate::cp::mcp_safety::MAX_MINIMIZED_PAGE_SIZE
            );
            assert_eq!(
                input["default"],
                crate::cp::mcp_safety::DEFAULT_MINIMIZED_PAGE_SIZE
            );
        }
    }
}

#[cfg(test)]
mod episode_deletion_tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };

    use async_trait::async_trait;

    use super::{advance_episode_deletion, reconcile_pending_episode_deletions};
    use crate::{
        error::{EnclaveError, Result},
        gcs::GcsGetResponse,
        persistence::{
            EpisodeDeletionPlan, EpisodeDeletionRepository, EpisodeDeletionStart, EpisodePurge,
            MediaObjectStore,
        },
    };

    struct FakeEpisodeDeletionRepository {
        pending: Mutex<Vec<(String, EpisodeDeletionPlan)>>,
        complete_calls: AtomicUsize,
    }

    impl FakeEpisodeDeletionRepository {
        fn new(account_id: &str, plan: EpisodeDeletionPlan) -> Self {
            Self {
                pending: Mutex::new(vec![(account_id.to_owned(), plan)]),
                complete_calls: AtomicUsize::new(0),
            }
        }

        fn pending_count(&self) -> usize {
            self.pending.lock().expect("pending lock").len()
        }
    }

    #[async_trait]
    impl EpisodeDeletionRepository for FakeEpisodeDeletionRepository {
        async fn begin_episode_deletion(
            &self,
            account_id: &str,
            episode_id: i64,
        ) -> Result<EpisodeDeletionStart> {
            let pending = self.pending.lock().expect("pending lock");
            Ok(pending
                .iter()
                .find(|(owner, plan)| owner == account_id && plan.episode_id == episode_id)
                .map(|(_, plan)| EpisodeDeletionStart::Pending(plan.clone()))
                .unwrap_or(EpisodeDeletionStart::NotFound))
        }

        async fn pending_episode_deletions(
            &self,
            limit: usize,
        ) -> Result<Vec<(String, EpisodeDeletionPlan)>> {
            Ok(self
                .pending
                .lock()
                .expect("pending lock")
                .iter()
                .take(limit)
                .cloned()
                .collect())
        }

        async fn complete_episode_deletion(
            &self,
            account_id: &str,
            plan: &EpisodeDeletionPlan,
        ) -> Result<EpisodePurge> {
            let mut pending = self.pending.lock().expect("pending lock");
            let Some(index) = pending
                .iter()
                .position(|(owner, candidate)| owner == account_id && candidate == plan)
            else {
                return Err(EnclaveError::Conflict(
                    "episode deletion was not pending".into(),
                ));
            };
            pending.remove(index);
            self.complete_calls.fetch_add(1, Ordering::SeqCst);
            Ok(plan.purge.clone())
        }
    }

    struct FakeMediaObjectStore {
        fail_second_once: AtomicBool,
        delete_calls: Mutex<Vec<String>>,
    }

    impl FakeMediaObjectStore {
        fn failing_once() -> Self {
            Self {
                fail_second_once: AtomicBool::new(true),
                delete_calls: Mutex::new(Vec::new()),
            }
        }

        fn delete_calls(&self) -> Vec<String> {
            self.delete_calls.lock().expect("delete calls lock").clone()
        }
    }

    #[async_trait]
    impl MediaObjectStore for FakeMediaObjectStore {
        async fn put_current(
            &self,
            _account_id: &str,
            _object_name: &str,
            _ciphertext: &[u8],
            _wrapped_dek_b64: &str,
        ) -> Result<i64> {
            Err(EnclaveError::Store("unexpected media put".into()))
        }

        async fn get_current(&self, _object_name: &str) -> Result<GcsGetResponse> {
            Err(EnclaveError::Store("unexpected media get".into()))
        }

        async fn get_current_generation(
            &self,
            _object_name: &str,
            _generation: i64,
        ) -> Result<GcsGetResponse> {
            Err(EnclaveError::Store(
                "unexpected media generation get".into(),
            ))
        }

        async fn delete_current(&self, object_name: &str) -> Result<()> {
            self.delete_calls
                .lock()
                .expect("delete calls lock")
                .push(object_name.to_owned());
            if object_name.ends_with("/second.enc")
                && self.fail_second_once.swap(false, Ordering::SeqCst)
            {
                return Err(EnclaveError::Gcs("injected delete failure".into()));
            }
            Ok(())
        }

        async fn purge_recordings(&self, _account_id: &str) -> Result<()> {
            Err(EnclaveError::Store("unexpected recording purge".into()))
        }

        async fn purge_account(&self, _account_id: &str) -> Result<()> {
            Err(EnclaveError::Store("unexpected account purge".into()))
        }
    }

    #[tokio::test]
    async fn provider_failure_keeps_episode_pending_and_restart_reconciles_idempotently() {
        let account_id = "account-1";
        let plan = EpisodeDeletionPlan {
            episode_id: 41,
            purge: EpisodePurge {
                deleted_utterances: 2,
                deleted_screenshots: 1,
                deleted_segments: 1,
                utterance_source_keys: vec!["utterance-1".into(), "utterance-2".into()],
                screenshot_source_keys: vec!["screenshot-1".into()],
            },
            media_object_keys: vec![
                "raw/account-1/first.enc".into(),
                "raw/account-1/second.enc".into(),
            ],
        };
        let repository = FakeEpisodeDeletionRepository::new(account_id, plan.clone());
        let media_objects = FakeMediaObjectStore::failing_once();

        let error = advance_episode_deletion(&repository, &media_objects, account_id, &plan)
            .await
            .expect_err("the injected GCS failure must keep deletion pending");
        assert!(matches!(error, EnclaveError::Gcs(_)));
        assert_eq!(repository.complete_calls.load(Ordering::SeqCst), 0);
        assert_eq!(repository.pending_count(), 1);

        // A restarted worker discovers the durable plan. Re-deleting the first
        // object is harmless; structured completion occurs only after both
        // exact object deletions have succeeded.
        reconcile_pending_episode_deletions(&repository, &media_objects)
            .await
            .expect("restart reconciliation");
        assert_eq!(repository.complete_calls.load(Ordering::SeqCst), 1);
        assert_eq!(repository.pending_count(), 0);
        assert_eq!(
            media_objects.delete_calls(),
            vec![
                "raw/account-1/first.enc",
                "raw/account-1/second.enc",
                "raw/account-1/first.enc",
                "raw/account-1/second.enc",
            ]
        );

        reconcile_pending_episode_deletions(&repository, &media_objects)
            .await
            .expect("completed reconciliation is a no-op");
        assert_eq!(repository.complete_calls.load(Ordering::SeqCst), 1);
        assert_eq!(media_objects.delete_calls().len(), 4);
    }
}
