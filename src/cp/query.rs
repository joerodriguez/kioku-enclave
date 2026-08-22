//! Query surface: the MCP
//! server (`POST /mcp`, JSON-RPC 2.0, stateless) and the REST mirrors
//! (`/api/search`, `/api/episodes`, `/api/episodes/:id`,
//! `/api/episodes/:id/members`) the debugger
//! uses. All routes are auth-gated; tool logic calls the data-plane query code
//! (`search::search_all`, `search::search_episodes`, `episodes::purge_episode`)
//! in-process. Note `timeline::fetch_context` is NOT among them despite a
//! long-standing claim here: `get_context` is served by this module's own
//! redaction-aware `mcp_query::fetch_safe_context`. That stale claim was the
//! stated reason `timeline::fetch_context` survived the /v1 retirement, so it
//! is corrected rather than carried.
//! `POST /api/episodes/:id/finalize` queues a scoped retry for an incomplete
//! or version-stale canonical brief. `/api/webhooks` manages signed,
//! user-configured finalized-episode event destinations.

pub(crate) mod wal;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

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
use sha2::{Digest, Sha256};

use crate::search::{search_all, SearchRequest};

use super::auth::AuthUser;
use super::CpState;

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

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
/// `mcp_query::search_safe_transcripts` through `dispatch_tool`; this function
/// had exactly one caller, the REST route, and no MCP path at all.
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
    // A failed read must never be reported as "nothing found". An empty
    // payload here is indistinguishable from a true negative, so the assistant
    // would tell the user their data does not exist — while it is present and
    // merely unreadable (a transient DB error, or a routed read whose serving
    // authority is unavailable). Propagating the error is what lets each
    // caller answer loudly in its own idiom.
    //
    // ADR-0022: the routed read serves both branches — a WAL-authoritative
    // user reads through their serving authority's settled-only lane, and an
    // unselected user falls through to the ordinary guarded legacy read.
    let (episodes, utterances) = s
        .store
        .wal_authoritative_read(user_id, move |conn| {
            Ok((
                crate::search::search_episodes(conn, &ep_req)?,
                search_all(conn, &utt_req)?,
            ))
        })
        .await?;
    Ok(json!({
        "episodes": serde_json::to_value(&episodes).unwrap_or_else(|_| json!([])),
        "results": serde_json::to_value(&utterances).unwrap_or_else(|_| json!([])),
    }))
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
    // See the note in the combined search above: an unreadable archive must
    // not be answered with an authoritative-looking empty result set. The
    // routed read serves the WAL-authoritative and legacy branches alike.
    let hits = match s
        .store
        .wal_authoritative_read(user_id, move |conn| search_all(conn, &req))
        .await
    {
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

/// Shared list/detail query. Keeping the optional id filter here ensures the
/// direct detail endpoint cannot drift from the list row's fields, visibility
/// rules, derived counts, or final-brief shape.
///
/// This returns a `Result` and every caller must keep it that way. The
/// `list_episodes_value` wrapper that used to sit in front of it flattened ANY
/// error into `{"episode_count":0,"hidden_count":0,"episodes":[]}` — an
/// authoritative-looking empty list for an archive that is fully present and
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
    // Normalize offset-bearing timestamps (e.g. -04:00) to UTC before SQL.
    // DB stores UTC Z-suffixed strings; after normalization both sides are UTC
    // and simple string comparison works correctly.
    let from = from.map(|s| super::isotime::normalize_to_utc(&s));
    let to = to.map(|s| super::isotime::normalize_to_utc(&s));

    s.store
        .wal_authoritative_read(user_id, move |conn| {
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
                        fb.overview, fb.decisions, fb.action_items, fb.important_links, fb.open_questions, \
                        CASE \
                            WHEN EXISTS ( \
                                SELECT 1 FROM episode_members m \
                                JOIN utterances u ON u.id = m.record_id AND m.record_type = 'utterance' \
                                JOIN voice_embedding_jobs j ON j.speaker_observation_id = u.speaker_observation_id \
                                WHERE m.episode_id = e.id AND j.state IN ('pending', 'processing', 'retry_wait') \
                            ) THEN 'pending' \
                            WHEN EXISTS ( \
                                SELECT 1 FROM episode_members m \
                                JOIN utterances u ON u.id = m.record_id AND m.record_type = 'utterance' \
                                JOIN voice_embedding_jobs j ON j.speaker_observation_id = u.speaker_observation_id \
                                WHERE m.episode_id = e.id AND j.state = 'failed' \
                            ) THEN 'degraded' \
                            ELSE 'ready' \
                        END \
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

                    let speaker_processing_status: String = r.get(23)?;

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
                        "speaker_processing_status": speaker_processing_status,
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
        .wal_authoritative_read(user_id, |conn| {
            let utt: i64 = conn.query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))?;
            let scr: i64 = conn.query_row("SELECT count(*) FROM screenshots", [], |r| r.get(0))?;
            let eps: i64 = conn.query_row("SELECT count(*) FROM episodes", [], |r| r.get(0))?;
            // `.optional()`, never `.ok()`. `.ok()` collapses EVERY error into
            // `None`, so a corrupt index or a failed statement reported the
            // same "no captures yet" as a genuinely empty archive — the exact
            // absence-for-a-refusal this whole surface exists to prevent. Only
            // "no rows" and a NULL timestamp are absences; anything else is a
            // read failure and must reach the caller's failure arm.
            let last_u: Option<String> = conn
                .query_row("SELECT s.started_at FROM utterances u JOIN audio_segments s ON s.id=u.audio_segment_id ORDER BY s.started_at DESC LIMIT 1", [], |r| r.get::<_, Option<String>>(0))
                .optional()?
                .flatten();
            let last_s: Option<String> = conn
                .query_row("SELECT captured_at FROM screenshots ORDER BY captured_at DESC LIMIT 1", [], |r| r.get::<_, Option<String>>(0))
                .optional()?
                .flatten();
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

/// Every tool name `dispatch_tool` answers, in `tool_definitions()` order.
///
/// It is `#[cfg(test)]` because the ADR-0022 D4 `mcp.tools` gate that used to
/// consult it in `mcp_endpoint` is gone: dispatch is keyed on the `match` in
/// `dispatch_tool`, and an unknown name has always fallen through it to the
/// JSON-RPC "unknown tool" error. What is left is a roster the tests sweep, and
/// a seventh tool cannot silently escape any of them:
///
/// * `mcp_tool_names_match_the_published_definitions` compares this list to
///   `tool_definitions()` in both directions, so a published tool must appear
///   here.
/// * `mcp_reads_report_an_unreadable_archive_instead_of_empty_results` sweeps
///   this list through `dispatch_tool` and its
///   `unwrap_or_else(|| panic!("{tool} should dispatch"))` fails on any name
///   here that has no dispatch arm. That assertion — not a separate
///   `every_published_tool_dispatches`, which does not exist — is what pins
///   this list against `dispatch_tool`.
/// * `every_mcp_tool_answers_a_selected_user_with_real_content` counts its own
///   expectation table against this list, so a seventh tool must be proven to
///   ANSWER, not merely proven to refuse cleanly.
#[cfg(test)]
const MCP_TOOL_NAMES: &[&str] = &[
    "search_transcripts",
    "search_screenshots",
    "get_context",
    "summarize_time_range",
    "list_episodes",
    "get_capture_status",
];

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
    // ADR-0022: every one of the six tools now reads through the routed
    // `wal_authoritative_read`, which serves a WAL-authoritative user from
    // their serving authority's settled-only lane and falls through to the
    // ordinary guarded legacy read for everyone else. The D4 `mcp.tools` gate
    // that stood here is retired with the migration.
    //
    // Whichever lane answers, a failure must surface an `error` key: that is
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
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            s.store
                .wal_authoritative_read(user_id, move |conn| {
                    Ok(super::mcp_query::search_safe_transcripts(
                        conn,
                        &query,
                        from.as_deref(),
                        to.as_deref(),
                        limit,
                    )?)
                })
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
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);
            s.store
                .wal_authoritative_read(user_id, move |conn| {
                    Ok(super::mcp_query::fetch_safe_context(
                        conn, &at, window, limit,
                    )?)
                })
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
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);
            s.store
                .wal_authoritative_read(user_id, move |conn| {
                    Ok(super::mcp_query::summarize_safe_time_range(
                        conn, &from, &to, limit,
                    )?)
                })
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
        // ADR-0022 D4: the `mcp.tools` gate that stood here is GONE. All six
        // tools read through `wal_authoritative_read` (the mechanical half),
        // and the evidence chain behind every table they touch is live for a
        // selected user (the answerability half) — capture ingest through the
        // sealed audio/screen result families to `utterances`/`screenshots`,
        // and the sealed episode-window upsert to `episodes`/`episode_members`.
        //
        // With the gate gone, `mcp_safety::refusal_for_args` inside
        // `dispatch_tool` is no longer preempted for a selected user, so the
        // safety boundary now runs on every request again rather than on every
        // request that got past the deferral.
        //
        // A volatile rate limit protects the service without making read-only
        // tool calls persist usage or query-log state.
        if !s.mcp_limiter.consume(&user_id).await {
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
    // ADR-0022 D4: the `query.search` gate is GONE. Both tables this read
    // decides on have live sealed writers for a selected user — `episodes`
    // from `summarizer/wal/window.rs`, `utterances` from
    // `media_worker/wal/audio_result.rs` — and the read below is routed, so
    // an empty result set is now a truthful one.
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
}

async fn rest_episodes(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Query(p): Query<EpisodesParams>,
) -> Response {
    let include_low = p.include_low.as_deref().is_some_and(string_is_truthy);
    // ADR-0022 D4: the `query.episodes` gate is GONE. `episodes` and
    // `episode_members` are both written inside
    // `summarizer/wal/window.rs::apply` for a selected user, and
    // `episode_final_briefs` by `finalizer/wal.rs::write_brief`.
    //
    // A read that fails answers 503, never 200 with an empty list: "no
    // episodes" and "your episodes are unreadable" are different facts, and
    // the debugger renders the first as an account with no memories. The gate
    // above covers the deferred population; this arm covers the legacy lane,
    // where a transient database error produced the same false empty and no
    // gate was ever going to catch it.
    match query_episodes_value(
        &s,
        &user.0,
        p.from,
        p.to,
        p.max_episodes.unwrap_or(50),
        include_low,
        None,
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
    // ADR-0022 D4: gate GONE with `rest_episodes`'. The `NotFound` arm below
    // stays a 404 and is NOT funnelled into the routed-read 503: an id that is
    // absent from a readable archive is a different fact from an archive that
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
async fn rest_episode_delete(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Response {
    // ADR-0022 D4: selected archives use the exact sealed deletion family;
    // unselected archives retain the existing snapshot transaction below.
    if s.store.is_wal_authoritative(&user.0) {
        return rest_selected_episode_delete(&s, &user.0, id).await;
    }
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

async fn rest_selected_episode_delete(s: &CpState, user_id: &str, id: i64) -> Response {
    // Finalization uses this same per-user gate around its Control snapshot and
    // archive submit. Holding it through the bounded provider cleanup prevents
    // a stale finalizer snapshot from recreating rows after the logical purge.
    let _lifecycle_guard = match s.store.lock_user_lifecycle(user_id).await {
        Ok(guard) => guard,
        Err(error) => {
            return super::routed_read_unavailable("api.episode_delete", &error);
        }
    };
    let read_user = user_id.to_owned();
    let start = s
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_episode_delete_start(connection, &read_user, id).map_err(|_| {
                crate::error::EnclaveError::Store("episode deletion state is unavailable".into())
            })
        })
        .await;
    let _preparation = match start {
        Ok(wal::EpisodeDeleteStart::Complete(receipt)) => {
            return episode_delete_response(receipt);
        }
        Ok(wal::EpisodeDeleteStart::Prepared(preparation)) => preparation,
        Ok(wal::EpisodeDeleteStart::Evidence(evidence)) => {
            let plan = match wal::EpisodeDeletePreparePlan::new(user_id.to_owned(), evidence)
                .and_then(crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare)
            {
                Ok(plan) => plan,
                Err(error) => {
                    tracing::error!(
                        episode_id = id,
                        ?error,
                        "episode deletion preparation failed"
                    );
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error": "enclave_unavailable"})),
                    )
                        .into_response();
                }
            };
            match s.store.wal_authoritative_submit(user_id, plan).await {
                Ok(preparation) => preparation,
                Err(error) => {
                    tracing::error!(episode_id = id, error = %error, "episode deletion reservation failed");
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error": "enclave_unavailable"})),
                    )
                        .into_response();
                }
            }
        }
        Ok(wal::EpisodeDeleteStart::Absent) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "episode_not_found"})),
            )
                .into_response();
        }
        Err(error) => {
            return super::routed_read_unavailable("api.episode_delete", &error);
        }
    };

    const DELETE_STEPS_PER_REQUEST: usize = 8;
    for _ in 0..DELETE_STEPS_PER_REQUEST {
        let read_user = user_id.to_owned();
        let work = match s
            .store
            .wal_authoritative_read(user_id, move |connection| {
                wal::load_episode_delete_work(connection, &read_user, id).map_err(|_| {
                    crate::error::EnclaveError::Store(
                        "episode deletion progress is unavailable".into(),
                    )
                })
            })
            .await
        {
            Ok(work) => work,
            Err(error) => {
                return super::routed_read_unavailable("api.episode_delete", &error);
            }
        };
        let Some(work) = work else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "enclave_unavailable"})),
            )
                .into_response();
        };
        match work {
            wal::EpisodeDeleteWork::Complete(plan) => {
                let plan =
                    match crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
                    {
                        Ok(plan) => plan,
                        Err(error) => {
                            tracing::error!(
                                episode_id = id,
                                ?error,
                                "episode deletion completion construction failed"
                            );
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({"error": "enclave_unavailable"})),
                            )
                                .into_response();
                        }
                    };
                return match s.store.wal_authoritative_submit(user_id, plan).await {
                    Ok(receipt) => episode_delete_response(receipt),
                    Err(error) => {
                        tracing::error!(episode_id = id, error = %error, "episode deletion completion failed");
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({"error": "enclave_unavailable"})),
                        )
                            .into_response()
                    }
                };
            }
            wal::EpisodeDeleteWork::Expand(plan) | wal::EpisodeDeleteWork::FinishSelector(plan) => {
                let prepared =
                    match crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(plan)
                    {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            tracing::error!(
                                episode_id = id,
                                ?error,
                                "episode deletion progress construction failed"
                            );
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({"error": "enclave_unavailable"})),
                            )
                                .into_response();
                        }
                    };
                if let Err(error) = s.store.wal_authoritative_submit(user_id, prepared).await {
                    tracing::error!(episode_id = id, error = %error, "episode deletion progress settlement failed");
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error": "enclave_unavailable", "deletion_pending": true})),
                    )
                        .into_response();
                }
            }
            wal::EpisodeDeleteWork::Provider(item) => {
                let provider_result = match item.target() {
                    wal::EpisodeDeleteCleanupTarget::Retained(media) => {
                        s.store
                            .delete_retained_media(
                                user_id,
                                &media.object_key,
                                media.object_generation,
                                media.object_backend.as_deref(),
                                &media.sha256,
                            )
                            .await
                    }
                    wal::EpisodeDeleteCleanupTarget::Legacy(object_key) => {
                        match s.store.delete_media(object_key).await {
                            Ok(()) | Err(crate::error::EnclaveError::NotFound) => Ok(()),
                            Err(error) => Err(error),
                        }
                    }
                };
                if let Err(error) = provider_result {
                    tracing::error!(episode_id = id, error = %error, "episode media deletion step failed");
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error": "media_delete_failed", "deletion_pending": true})),
                    )
                        .into_response();
                }
                let plan = match wal::EpisodeDeleteCleanupPlan::new(item)
                    .and_then(crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare)
                {
                    Ok(plan) => plan,
                    Err(error) => {
                        tracing::error!(
                            episode_id = id,
                            ?error,
                            "episode deletion progress construction failed"
                        );
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({"error": "enclave_unavailable"})),
                        )
                            .into_response();
                    }
                };
                if let Err(error) = s.store.wal_authoritative_submit(user_id, plan).await {
                    tracing::error!(episode_id = id, error = %error, "episode deletion progress settlement failed");
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error": "enclave_unavailable", "deletion_pending": true})),
                    )
                        .into_response();
                }
            }
        }
    }

    kick_episode_deletion(user_id);
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "deleted": false,
            "deletion_pending": true,
            "episode_id": id,
        })),
    )
        .into_response()
}

fn episode_delete_response(receipt: wal::EpisodeDeleteReceipt) -> Response {
    let purge = receipt.purge;
    Json(json!({
        "deleted": true,
        "episode_id": receipt.episode_id,
        "deleted_utterances": purge.deleted_utterances,
        "deleted_screenshots": purge.deleted_screenshots,
        "deleted_segments": purge.deleted_segments,
        "utterance_source_keys": purge.utterance_source_keys,
        "screenshot_source_keys": purge.screenshot_source_keys,
    }))
    .into_response()
}

/// Advance a bounded number of already-prepared selected-archive deletion
/// jobs.  The dedicated immediate/recurring worker is the correctness owner;
/// the summarizer sweep and a client retry are redundant wakeups, never the
/// only progress mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EpisodeDeleteResumeOutcome {
    has_work: bool,
    had_failure: bool,
}

pub(crate) async fn resume_user_episode_deletions(
    state: &CpState,
    user_id: &str,
) -> crate::error::Result<EpisodeDeleteResumeOutcome> {
    if !state.store.is_wal_authoritative(user_id) {
        return Ok(EpisodeDeleteResumeOutcome {
            has_work: false,
            had_failure: false,
        });
    }
    let read_user = user_id.to_owned();
    let batch = state
        .store
        .wal_authoritative_read(user_id, move |connection| {
            wal::load_pending_episode_delete_batch(connection, &read_user).map_err(|_| {
                crate::error::EnclaveError::Store(
                    "episode deletion work inventory is unavailable".into(),
                )
            })
        })
        .await?;
    let Some(batch) = batch else {
        return Ok(EpisodeDeleteResumeOutcome {
            has_work: false,
            had_failure: false,
        });
    };
    state
        .store
        .wal_authoritative_submit(
            user_id,
            crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(batch.plan)
                .map_err(|_| {
                    crate::error::EnclaveError::Store(
                        "episode deletion scheduler state is invalid".into(),
                    )
                })?,
        )
        .await?;
    let mut had_failure = false;
    for episode_id in batch.episode_ids {
        let response = rest_selected_episode_delete(state, user_id, episode_id).await;
        if response.status().is_server_error() {
            had_failure = true;
            tracing::warn!("episode deletion worker step failed; continuing independent work");
        }
    }
    Ok(EpisodeDeleteResumeOutcome {
        has_work: true,
        had_failure,
    })
}

const EPISODE_DELETE_WAKE_CAPACITY: usize = 1_024;
const EPISODE_DELETE_MAX_RETRY_SECONDS: u64 = 30;

static EPISODE_DELETE_KICKS: OnceLock<tokio::sync::mpsc::Sender<String>> = OnceLock::new();

fn kick_episode_deletion(user_id: &str) {
    if let Some(sender) = EPISODE_DELETE_KICKS.get() {
        let _ = sender.try_send(user_id.to_owned());
    }
}

fn episode_delete_retry_delay(consecutive_failures: u32) -> Duration {
    let exponent = consecutive_failures.saturating_sub(1).min(5);
    Duration::from_secs(
        1u64.checked_shl(exponent)
            .unwrap_or(EPISODE_DELETE_MAX_RETRY_SECONDS)
            .min(EPISODE_DELETE_MAX_RETRY_SECONDS),
    )
}

fn episode_delete_worker_wait(
    queue: &VecDeque<String>,
    retry_at: &HashMap<String, Instant>,
    now: Instant,
) -> Duration {
    let mut minimum = None;
    for id in queue {
        match retry_at.get(id).copied() {
            None => return Duration::from_millis(1),
            Some(deadline) if deadline <= now => return Duration::from_millis(1),
            Some(deadline) => {
                minimum = Some(minimum.map_or(deadline, |current: Instant| current.min(deadline)));
            }
        }
    }
    minimum
        .and_then(|deadline| deadline.checked_duration_since(now))
        .unwrap_or(Duration::from_millis(1))
}

fn pop_ready_episode_delete_account(
    queue: &mut VecDeque<String>,
    queued: &mut HashSet<String>,
    retry_at: &HashMap<String, Instant>,
    now: Instant,
) -> Option<String> {
    for _ in 0..queue.len() {
        let id = queue.pop_front()?;
        if retry_at.get(&id).is_none_or(|deadline| *deadline <= now) {
            queued.remove(&id);
            return Some(id);
        }
        queue.push_back(id);
    }
    None
}

/// Run selected-archive deletion as a dedicated fair correctness owner.  The
/// durable archive cursor rotates the next four episodes before any provider
/// work, so one unavailable object cannot pin later jobs.  The in-memory queue
/// is only a wakeup optimization: the immediate and recurring account scans
/// rebuild it after every restart.
pub(crate) fn spawn_episode_delete_worker(state: Arc<CpState>) {
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<String>(EPISODE_DELETE_WAKE_CAPACITY);
    if EPISODE_DELETE_KICKS.set(sender).is_err() {
        return;
    }
    tokio::spawn(async move {
        let mut scan = tokio::time::interval(Duration::from_secs(30));
        let mut queue = VecDeque::<String>::new();
        let mut queued = HashSet::<String>::new();
        let mut failure_counts = HashMap::<String, u32>::new();
        let mut retry_at = HashMap::<String, Instant>::new();
        loop {
            if queue.is_empty() {
                tokio::select! {
                    _ = scan.tick() => {
                        match state.control.all_user_ids().await {
                            Ok(ids) => {
                                for id in ids {
                                    if queued.insert(id.clone()) {
                                        queue.push_back(id);
                                    }
                                }
                            }
                            Err(error) => tracing::warn!(error = %error, "episode deletion account scan failed"),
                        }
                    }
                    Some(id) = receiver.recv() => {
                        if queued.insert(id.clone()) {
                            queue.push_back(id);
                        }
                    }
                }
                continue;
            }

            let worker_wait = episode_delete_worker_wait(&queue, &retry_at, Instant::now());
            tokio::select! {
                Some(id) = receiver.recv() => {
                    if queued.insert(id.clone()) {
                        queue.push_back(id);
                    }
                }
                _ = scan.tick() => {
                    match state.control.all_user_ids().await {
                        Ok(ids) => {
                            for id in ids {
                                if queued.insert(id.clone()) {
                                    queue.push_back(id);
                                }
                            }
                        }
                        Err(error) => tracing::warn!(error = %error, "episode deletion account scan failed"),
                    }
                }
                _ = tokio::time::sleep(worker_wait) => {
                    let Some(id) = pop_ready_episode_delete_account(
                        &mut queue,
                        &mut queued,
                        &retry_at,
                        Instant::now(),
                    ) else { continue; };
                    match resume_user_episode_deletions(&state, &id).await {
                        Ok(outcome) if outcome.has_work => {
                            if outcome.had_failure {
                                let failures = failure_counts
                                    .entry(id.clone())
                                    .and_modify(|value| *value = value.saturating_add(1))
                                    .or_insert(1);
                                retry_at.insert(
                                    id.clone(),
                                    Instant::now() + episode_delete_retry_delay(*failures),
                                );
                            } else {
                                failure_counts.remove(&id);
                                retry_at.remove(&id);
                            }
                            if queued.insert(id.clone()) {
                                queue.push_back(id);
                            }
                        }
                        Ok(_) => {
                            failure_counts.remove(&id);
                            retry_at.remove(&id);
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "episode deletion owner pass failed");
                            let failures = failure_counts
                                .entry(id.clone())
                                .and_modify(|value| *value = value.saturating_add(1))
                                .or_insert(1);
                            retry_at.insert(
                                id.clone(),
                                Instant::now() + episode_delete_retry_delay(*failures),
                            );
                            if queued.insert(id.clone()) {
                                queue.push_back(id);
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
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
    // ADR-0022 D4: the `query.episode_members` gate is GONE. Every table that
    // decides this answer has a live sealed writer for a selected user —
    // `episode_members` from `summarizer/wal/window.rs::apply`, `utterances`
    // and `audio_segments` from `media_worker/wal/audio_result.rs::write_turns`,
    // `screenshots` and `screen_observations` from
    // `media_worker/wal/result.rs::write_frame`. The `LEFT JOIN`ed identity
    // and image tables do not decide it: they widen a member row, they cannot
    // create or suppress one.
    let result = s
        .store
        .wal_authoritative_read(&user.0, move |conn| {
            // Legacy source keys let the Mac-selected evidence flow join a
            // member to screenshot_images. Cloud Capture v2 source keys bind
            // canonical screenshots to their retained encrypted media object.
            let mut us = conn.prepare(
                "SELECT u.id, s.started_at, u.speaker_label, u.language, u.text, u.source_key, u.speaker_observation_id \
                 FROM episode_members m \
                 JOIN utterances u ON u.id = m.record_id \
                 JOIN audio_segments s ON s.id = u.audio_segment_id \
                 WHERE m.episode_id = ?1 AND m.record_type = 'utterance'",
            )?;
            let mut members: Vec<(String, Value)> = us
                .query_map([id], |r| {
                    let ts: String = r.get(1)?;
                    let obs_id: Option<i64> = r.get(6)?;
                    let raw_label: String = r.get(2)?;
                    let (resolved_label, attribution_kind) = if let Some(oid) = obs_id {
                        if let Ok(attr) = crate::cp::identity::resolve_speaker_attribution(conn, oid, Some(id)) {
                            (attr.display_label, Some(serde_json::to_value(attr.attribution_kind).unwrap_or(Value::Null)))
                        } else {
                            (raw_label, None)
                        }
                    } else {
                        (raw_label, None)
                    };

                    Ok((
                        ts.clone(),
                        json!({
                            "record_type": "utterance",
                            "record_id": r.get::<_, i64>(0)?,
                            "started_at": ts,
                            "speaker_label": resolved_label,
                            "attribution_kind": attribution_kind,
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

            let mut part_stmt = conn.prepare(
                "SELECT p.participant_key, p.person_id, p.attribution_kind, p.state, \
                        pe.display_name, p.source_claimed_name, s.slot_ordinal \
                 FROM episode_participants p \
                 LEFT JOIN people pe ON pe.id = p.person_id \
                 LEFT JOIN episode_speaker_slots s ON s.id = p.speaker_slot_id \
                 WHERE p.episode_id = ?1 AND p.state = 'active' \
                 ORDER BY p.id ASC",
            )?;
            let participant_details: Vec<Value> = part_stmt
                .query_map([id], |r| {
                    let participant_key: String = r.get(0)?;
                    let person_id: Option<i64> = r.get(1)?;
                    let attribution_kind: String = r.get(2)?;
                    let state: String = r.get(3)?;
                    let pe_display_name: Option<String> = r.get(4)?;
                    let source_claimed_name: Option<String> = r.get(5)?;
                    let slot_ordinal: Option<i32> = r.get(6)?;

                    let display_name = if participant_key == "owner"
                        || attribution_kind == "owner_presentation"
                        || attribution_kind == "owner_source_role"
                    {
                        "Me".to_string()
                    } else if let Some(dn) = pe_display_name {
                        dn
                    } else if let Some(claimed) = source_claimed_name {
                        claimed
                    } else if let Some(ord) = slot_ordinal {
                        let letter = crate::cp::identity::format_slot_ordinal(ord);
                        format!("Unknown speaker {letter}")
                    } else {
                        "Unknown speaker".to_string()
                    };

                    Ok(json!({
                        "participant_key": participant_key,
                        "display_name": display_name,
                        "person_id": person_id,
                        "attribution_kind": attribution_kind,
                        "state": state,
                    }))
                })?
                .filter_map(|x| x.ok())
                .collect();

            Ok(json!({
                "episode_id": id,
                "member_count": members.len(),
                "participant_details": participant_details,
                "members": members,
            }))
        })
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
        .store
        .wal_authoritative_read(&user.0, move |conn| {
            load_browser_snapshot(conn, &source_key)
        })
        .await;
    match result {
        Ok(Some(snapshot)) => Json(snapshot).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        Err(e) => super::routed_read_unavailable("api.browser_snapshot", &e),
    }
}

const CAPTURE_V2_BROWSER_SOURCE_PREFIX: &str = "capture-v2-browser:";

fn load_browser_snapshot(
    conn: &Connection,
    source_key: &str,
) -> crate::error::Result<Option<Value>> {
    if let Some(event_id) = source_key.strip_prefix(CAPTURE_V2_BROWSER_SOURCE_PREFIX) {
        return load_browser_v2_snapshot(conn, source_key, event_id);
    }
    let snapshot = conn
        .query_row(
            "SELECT b.id,b.source_key,b.captured_at,b.browser_bundle_id,b.browser_name,
                    b.permission_status,b.active_window_index,b.active_tab_index,
                    b.reported_tab_count,b.truncated
             FROM browser_snapshots b
             WHERE b.source_key=?1
               AND EXISTS (
                   SELECT 1 FROM screenshots c
                   JOIN episode_members m ON m.record_type='screenshot' AND m.record_id=c.id
                   JOIN episodes e ON e.id=m.episode_id
                   WHERE c.browser_snapshot_source_key=b.source_key
               )",
            [source_key],
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
        "SELECT window_index,tab_index,title,url,url_scheme,is_active,is_loading
         FROM browser_tabs WHERE browser_snapshot_id=?1
         ORDER BY window_index,tab_index LIMIT 500",
    )?;
    let tabs = statement
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
        .collect::<rusqlite::Result<Vec<_>>>()?;
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
}

fn load_browser_v2_snapshot(
    conn: &Connection,
    source_key: &str,
    event_id: &str,
) -> crate::error::Result<Option<Value>> {
    if event_id.is_empty() || event_id.len() > 512 || event_id.contains('\0') {
        return Ok(None);
    }
    let live_screenshot_count: i64 = conn.query_row(
        "SELECT COUNT(*)
         FROM screenshots c
         WHERE c.browser_snapshot_source_key=?1
           AND EXISTS (
               SELECT 1 FROM episode_members m
               JOIN episodes episode ON episode.id=m.episode_id
               WHERE m.record_type='screenshot' AND m.record_id=c.id
           )",
        [source_key],
        |row| row.get(0),
    )?;
    if live_screenshot_count == 0 {
        return Ok(None);
    }
    if live_screenshot_count != 1 {
        return Err(crate::error::EnclaveError::Store(
            "browser-v2 screenshot association is ambiguous".into(),
        ));
    }
    let screenshot = conn
        .query_row(
            "SELECT c.captured_at,c.source_key
             FROM screenshots c
             WHERE c.browser_snapshot_source_key=?1
               AND EXISTS (
                   SELECT 1 FROM episode_members m
                   JOIN episodes episode ON episode.id=m.episode_id
                   WHERE m.record_type='screenshot' AND m.record_id=c.id
               )",
            [source_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()?;
    let (captured_at, screenshot_source_key) = screenshot.ok_or_else(|| {
        crate::error::EnclaveError::Store("browser-v2 screenshot association changed".into())
    })?;
    let expected_screenshot_source_key = format!("cloud-v2:{event_id}");
    if screenshot_source_key.as_deref() != Some(expected_screenshot_source_key.as_str()) {
        return Err(crate::error::EnclaveError::Store(
            "browser-v2 screenshot source is inconsistent".into(),
        ));
    }
    let event = conn
        .query_row(
            "SELECT device_id,context_json,started_at,source_wall_at
             FROM capture_events WHERE event_id=?1",
            [event_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            crate::error::EnclaveError::Store("browser-v2 capture event is missing".into())
        })?;
    let observation = conn
        .query_row(
            "SELECT observation_id,observed_at,state_key,context_status,active_url,active_title
             FROM browser_observations_v2 WHERE event_id=?1",
            [event_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            crate::error::EnclaveError::Store("browser-v2 observation is missing".into())
        })?;
    let state_key = observation.2.as_deref().ok_or_else(|| {
        crate::error::EnclaveError::Store("browser-v2 observation is missing state".into())
    })?;
    let state = conn
        .query_row(
            "SELECT browser_bundle_id,browser_name,permission_status,content_hash,tabs_json
             FROM browser_states_v2 WHERE state_key=?1",
            [state_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| crate::error::EnclaveError::Store("browser-v2 state is missing".into()))?;
    let context: super::media::CaptureContext = serde_json::from_str(&event.1)
        .map_err(|_| crate::error::EnclaveError::Store("browser-v2 context is corrupt".into()))?;
    let snapshot = super::media::validate_browser_v2_persisted_evidence(
        &context,
        super::media::BrowserV2PersistedEvidence {
            event_id,
            device_id: &event.0,
            source_wall_at: &event.3,
            observation_id: &observation.0,
            observed_at: &observation.1,
            state_key: observation.2.as_deref(),
            context_status: &observation.3,
            active_url: observation.4.as_deref(),
            active_title: observation.5.as_deref(),
            browser_bundle_id: &state.0,
            browser_name: &state.1,
            permission_status: &state.2,
            content_hash: &state.3,
            tabs_json: &state.4,
        },
    )?;
    if captured_at != event.2 {
        return Err(crate::error::EnclaveError::Store(
            "browser-v2 evidence is inconsistent".into(),
        ));
    }
    Ok(Some(json!({
        "source_key": source_key,
        "captured_at": captured_at,
        "observed_at": observation.1,
        "browser_bundle_id": snapshot.browser_bundle_id,
        "browser_name": snapshot.browser_name,
        "permission_status": snapshot.permission_status,
        "active_window_index": snapshot.active_window_index,
        "active_tab_index": snapshot.active_tab_index,
        "reported_tab_count": snapshot.reported_tab_count,
        "truncated": snapshot.truncated,
        "ambient_tab_collection_enabled": snapshot.ambient_tab_collection_enabled,
        "tabs": snapshot.tabs,
    })))
}

async fn rest_episode_finalize(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Response {
    // ADR-0022: the routed read serves both branches (it falls through to
    // the legacy read lane for unselected users) and fetches the full
    // predecessor row the sealed queue plan pins.
    let eligibility = s
        .store
        .wal_authoritative_read(&user.0, move |conn| {
            conn.query_row(
                "SELECT substance, finalized_at, finalization_version, finalization_status,
                        finalization_error, finalization_attempted_at,
                        finalization_attempt_count, finalization_next_attempt_at, updated_at
                 FROM episodes WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i32>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(Into::into)
        })
        .await;
    let Some((
        substance,
        finalized_at,
        version,
        status,
        finalization_error,
        attempted_at,
        attempt_count,
        next_attempt_at,
        row_updated_at,
    )) = (match eligibility {
        Ok(value) => value,
        Err(error) => return super::routed_read_unavailable("api.episode_finalize", &error),
    })
    else {
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
    if s.store.is_wal_authoritative(&user_id) {
        // ADR-0022: the queue transition settles as the sealed
        // FinalizationQueuePlan. The caller-stable request id is the
        // predecessor commitment — re-queueing the same eligible row retries
        // the same operation; once queued, the 202 short-circuit above
        // answers instead, so a settled transition is never re-derived.
        let queued_at = crate::cp::isotime::format_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );
        let queue_request_id = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            for part in [
                b"finalization-queue-request-v1".as_slice(),
                user_id.as_bytes(),
                &id.to_be_bytes(),
                substance.as_bytes(),
                finalized_at.as_deref().unwrap_or("").as_bytes(),
                &i64::from(version.unwrap_or(0)).to_be_bytes(),
                status.as_bytes(),
                finalization_error.as_deref().unwrap_or("").as_bytes(),
                attempted_at.as_deref().unwrap_or("").as_bytes(),
                &attempt_count.to_be_bytes(),
                next_attempt_at.as_deref().unwrap_or("").as_bytes(),
                row_updated_at.as_deref().unwrap_or("").as_bytes(),
            ] {
                hasher.update((part.len() as u64).to_be_bytes());
                hasher.update(part);
            }
            hasher
                .finalize()
                .iter()
                .take(16)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let prepared = wal::FinalizationQueuePredecessor::new(
            substance,
            finalized_at,
            version,
            status,
            finalization_error,
            attempted_at,
            attempt_count,
            next_attempt_at,
            row_updated_at,
        )
        .and_then(|predecessor| {
            wal::FinalizationQueuePlan::new(
                user_id.clone(),
                queue_request_id,
                id,
                queued_at,
                predecessor,
            )
        })
        .and_then(crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare);
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    episode_id = id,
                    "finalization queue plan construction failed"
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "enclave_unavailable"})),
                )
                    .into_response();
            }
        };
        if let Err(error) = s.store.wal_authoritative_submit(&user_id, prepared).await {
            tracing::warn!(%error, episode_id = id, "failed to queue episode finalization");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "enclave_unavailable"})),
            )
                .into_response();
        }
    } else {
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
    // ADR-0022 D4: the `query.feed` gate is GONE. The feed merges
    // `utterances`+`audio_segments` with `screenshots`+`screen_observations`
    // and annotates from `episode_members`; all five are written by live
    // sealed families for a selected user.
    let result = s
        .store
        .wal_authoritative_read(&user.0, move |conn| query_feed(conn, &p))
        .await;

    match result {
        Ok(val) => Json(val).into_response(),
        Err(e) => super::routed_read_unavailable("api.feed", &e),
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

fn legacy_screenshot_source_pattern(device_id: &str) -> crate::error::Result<String> {
    let valid = !device_id.is_empty()
        && device_id.len() <= 128
        && device_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid {
        return Err(crate::error::EnclaveError::InvalidRequest(
            "device_id has an invalid format".into(),
        ));
    }

    // The historical source-key namespace is `<device_id>:...`. Underscore
    // is valid in a device id but is a LIKE wildcard, so escape it even after
    // the grammar check. Percent and the escape byte are rejected above.
    let mut pattern = String::with_capacity(device_id.len() + 3);
    for byte in device_id.bytes() {
        if byte == b'_' {
            pattern.push('\\');
        }
        pattern.push(char::from(byte));
    }
    pattern.push_str(":%");
    Ok(pattern)
}

fn query_screenshot_upload_plan(conn: &Connection, p: &PlanParams) -> crate::error::Result<Value> {
    let source_pattern = legacy_screenshot_source_pattern(&p.device_id)?;
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
           AND c.source_key LIKE ?1 ESCAPE '\\' \
           AND c.is_duplicate = 0 \
           AND (?2 IS NULL OR c.captured_at >= ?2) \
           AND c.source_key NOT IN (SELECT source_key FROM screenshot_images) \
           AND COALESCE(usage.image_count, 0) < ?3 \
           AND COALESCE(usage.image_bytes, 0) < ?4 \
         ORDER BY e.started_at DESC, c.captured_at ASC",
    )?;

    let rows = stmt.query_map(
        rusqlite::params![
            source_pattern,
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
    query: Result<Query<PlanParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if let Err(e) = crate::store::validate_user_id(&user.0) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // Genesis capture already uploads canonical image bytes before the screen
    // result is planned, and the native client no longer owns a local source
    // for those cloud-v2 rows. Reusing this retired device-prefix plan would
    // either return a false empty archive or ask the client to upload bytes it
    // no longer has. Keep only the guarded legacy compatibility lane.
    if s.store.is_wal_authoritative(&user.0) {
        return selected_screenshot_upload_retired();
    }
    let Query(p) = match query {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let result = s
        .store
        .with_user(&user.0, move |conn| query_screenshot_upload_plan(conn, &p))
        .await;

    match result {
        Ok(val) => Json(val).into_response(),
        Err(error @ crate::error::EnclaveError::InvalidRequest(_)) => error.into_response(),
        Err(e) => super::routed_read_unavailable("api.screenshot_upload_plan", &e),
    }
}

fn selected_screenshot_upload_retired() -> Response {
    (
        StatusCode::GONE,
        Json(serde_json::json!({"error": "screenshot_upload_retired"})),
    )
        .into_response()
}

async fn rest_screenshot_image_upload(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    multipart: Result<Multipart, axum::extract::multipart::MultipartRejection>,
) -> Response {
    let user_id = user.0;
    if let Err(e) = crate::store::validate_user_id(&user_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // Canonical Cloud Capture v2 already owns the selected archive's image
    // bytes. The historical multipart endpoint is device-sync compatibility,
    // not a second upload path: retire it before reading the multipart body,
    // taking a content-write lease, touching KMS, or calling a provider.
    if s.store.is_wal_authoritative(&user_id) {
        return selected_screenshot_upload_retired();
    }
    let mut multipart = match multipart {
        Ok(multipart) => multipart,
        Err(error) => return error.into_response(),
    };

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
    // Capture v2 asset ID inside this authenticated user's database. The v2
    // arm returns the complete immutable media identity; object_key alone is
    // not authority to read a current provider generation.
    let user_id_cloned = user_id.clone();
    let query_res = s
        .store
        .wal_authoritative_read(&user_id_cloned, {
            let id_clone = id.clone();
            let lookup_user = user_id_cloned.clone();
            move |conn| screenshot_image_object_key(conn, &lookup_user, &id_clone)
        })
        .await;

    let locator = match query_res {
        Ok(Some(ok)) => ok,
        // A failed read is NOT an absence. This arm used to be byte-identical
        // to the `Ok(None)` arm below and unlogged, so an unreadable archive
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

    // 2. Fetch the encrypted object. Capture-v2 is exact-current only; legacy
    // screenshot evidence preserves its compatibility fallback.
    let gcs_resp = match &locator {
        ScreenshotImageLocator::CaptureV2(identity) => {
            match s
                .store
                .get_current_media_generation(&identity.object_key, identity.generation)
                .await
            {
                Ok(response) => response,
                Err(crate::error::EnclaveError::NotFound) => {
                    // Retention deletes the provider generation before it
                    // settles the row. Re-read authority: a now-ineligible row
                    // is a truthful 404; an unchanged ready tuple means storage
                    // is unavailable and must not masquerade as absence.
                    let reread_user = user_id.clone();
                    let lookup_user = reread_user.clone();
                    let reread_id = id.clone();
                    return match s
                        .store
                        .wal_authoritative_read(&reread_user, move |conn| {
                            screenshot_image_object_key(conn, &lookup_user, &reread_id)
                        })
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
                    return super::routed_read_unavailable(
                        "api.screenshot_image_content.object",
                        &error,
                    )
                }
            }
        }
        ScreenshotImageLocator::Legacy { object_key } => {
            match s.store.get_media(object_key).await {
                Ok(response) => response,
                Err(crate::error::EnclaveError::NotFound) => {
                    return StatusCode::NOT_FOUND.into_response()
                }
                Err(error) => {
                    return super::routed_read_unavailable(
                        "api.screenshot_image_content.legacy_object",
                        &error,
                    )
                }
            }
        }
    };

    // 3. Load user's media DEK
    let user_id_cloned = user_id.clone();
    let wrapped_opt_res = s
        .store
        .wal_authoritative_read(&user_id_cloned, |conn| {
            let mut stmt =
                conn.prepare("SELECT value FROM app_metadata WHERE key = 'wrapped_media_dek'")?;
            // `.optional()`, never `.ok()`. This is not a timestamp whose
            // absence is cosmetic: `None` becomes a 404 four lines below, so
            // `.ok()` turned every read error into "that screenshot does not
            // exist". Only a missing row (or a NULL value) is an absence; a
            // read failure falls through to the failure arm.
            let val: Option<String> = stmt
                .query_row([], |r| r.get::<_, Option<String>>(0))
                .optional()?
                .flatten();
            Ok(val)
        })
        .await;

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

    let media_dek = match crate::crypto::load_dek(s.store.kms.as_ref(), &wrapped_b64).await {
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
    let object_key = locator.object_key();
    let media_context = crate::store::media_blob_context(&user_id, &object_key);
    let opened = match &locator {
        ScreenshotImageLocator::CaptureV2(identity) => {
            if gcs_resp.generation != identity.generation || gcs_resp.wrapped_dek_b64 != wrapped_b64
            {
                tracing::error!("canonical screenshot provider identity mismatch");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            match crate::crypto::decrypt_bound_blob_v2(
                &media_dek,
                &gcs_resp.ciphertext,
                &media_context,
            ) {
                Ok(opened) => opened,
                Err(error) => {
                    tracing::error!(error = %error, "media download authentication failed");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        }
        ScreenshotImageLocator::Legacy { .. } => {
            match crate::crypto::decrypt_bound_blob(
                &media_dek,
                &gcs_resp.ciphertext,
                &media_context,
            ) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(error = %e, "media download authentication failed");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        }
    };

    if let ScreenshotImageLocator::CaptureV2(identity) = &locator {
        let actual_sha256 = format!("{:x}", Sha256::digest(&opened.plaintext));
        if opened.plaintext.len() as i64 != identity.byte_length
            || !actual_sha256.eq_ignore_ascii_case(&identity.sha256)
        {
            tracing::error!("canonical screenshot plaintext commitment mismatch");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    (
        StatusCode::OK,
        [("Content-Type", "image/jpeg")],
        opened.plaintext,
    )
        .into_response()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CaptureV2ScreenshotIdentity {
    object_key: String,
    generation: i64,
    byte_length: i64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ScreenshotImageLocator {
    CaptureV2(CaptureV2ScreenshotIdentity),
    Legacy { object_key: String },
}

impl ScreenshotImageLocator {
    fn object_key(&self) -> String {
        match self {
            Self::CaptureV2(identity) => identity.object_key.clone(),
            Self::Legacy { object_key } => object_key.clone(),
        }
    }
}

fn screenshot_image_object_key(
    conn: &Connection,
    user_id: &str,
    id: &str,
) -> crate::error::Result<Option<ScreenshotImageLocator>> {
    if let Some(asset_id) = id.strip_prefix(CLOUD_CAPTURE_IMAGE_ID_PREFIX) {
        let expected_object_key =
            match crate::store::canonical_capture_media_object_key(user_id, asset_id) {
                Ok(key) => key,
                Err(_) => return Ok(None),
            };
        let row = conn
            .query_row(
                "SELECT object_key,object_generation,object_backend,byte_length,sha256 FROM media_objects \
                 WHERE asset_id = ?1 AND mime_type = 'image/jpeg' \
                   AND processing_state = 'ready' AND deleted_at IS NULL",
                [asset_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((object_key, generation, backend, byte_length, sha256)) = row else {
            return Ok(None);
        };
        let generation = generation.ok_or_else(|| {
            crate::error::EnclaveError::InvalidRequest(
                "canonical screenshot is missing its generation".into(),
            )
        })?;
        if generation <= 0
            || backend.as_deref() != Some("current")
            || object_key != expected_object_key
            || byte_length <= 0
            || byte_length > super::media::MAX_SCREENSHOT_BYTES
            || sha256.len() != 64
            || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(crate::error::EnclaveError::InvalidRequest(
                "canonical screenshot identity is malformed".into(),
            ));
        }
        return Ok(Some(ScreenshotImageLocator::CaptureV2(
            CaptureV2ScreenshotIdentity {
                object_key,
                generation,
                byte_length,
                sha256,
            },
        )));
    }

    Ok(conn
        .query_row(
            "SELECT object_key FROM screenshot_images WHERE id = ?1",
            [id],
            |row| {
                Ok(ScreenshotImageLocator::Legacy {
                    object_key: row.get(0)?,
                })
            },
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

async fn rest_list_webhooks(
    State(s): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    match s.control.list_webhook_subscriptions(&user.0).await {
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
    // Linearize Control snapshot + archive enqueue in the finalizer against
    // disable + exact archive drain + Control deletion here. Never replace
    // this with a final unprotected scan: a paused finalizer could enqueue
    // after the route returned 204.
    let _webhook_lifecycle_guard = match s.store.lock_user_lifecycle(&user_id).await {
        Ok(guard) => guard,
        Err(error) => return error.into_response(),
    };
    match s
        .control
        .get_webhook_subscription(&user_id, &subscription_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return error.into_response(),
    }
    if let Err(error) = s
        .control
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
        .control
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
    use crate::store::{GcsClient, Store};

    /// A read that fails must never present as "nothing found".
    ///
    /// All six tools now read through `wal_authoritative_read`. The D4
    /// `mcp.tools` gate that used to stand in front of `dispatch_tool` is
    /// gone, so this property is no longer held up by a gate — it is held up
    /// by each tool's own failure handler, which is exactly why it is pinned
    /// here. The harness selects the user WITHOUT registering a serving
    /// authority, so the routed read refuses: the same shape as an authority
    /// that is unavailable or quarantined, and the same shape a transient
    /// database error takes on the legacy lane.
    ///
    /// Every tool must answer with an `error` key — that is what sets
    /// `isError` on the tool result — and must NOT also answer an empty
    /// evidence payload. `list_episodes` is the one that used to fail this:
    /// the deleted `list_episodes_value` wrapper flattened any error into
    /// `{"episode_count":0,"hidden_count":0,"episodes":[]}`, so the assistant
    /// told the user their archive was empty while it was fully present.
    #[tokio::test]
    async fn mcp_reads_report_an_unreadable_archive_instead_of_empty_results() {
        let state = query_test_state();
        let user_id = "mcp-selected-user";
        state
            .store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    user_id,
                    crate::archive_v3::ArchiveId::from_bytes([0x7c; 16]),
                ),
            )
            .unwrap();

        for tool in MCP_TOOL_NAMES {
            let args = json!({"query": "invoice total", "at": "2026-08-20T00:00:00Z",
                              "from": "2026-08-19T00:00:00Z", "to": "2026-08-20T00:00:00Z"});
            let result = dispatch_tool(&state, user_id, tool, &args)
                .await
                .unwrap_or_else(|| panic!("{tool} should dispatch"));
            assert!(
                result
                    .get("error")
                    .and_then(Value::as_str)
                    .is_some_and(|reason| !reason.is_empty()),
                "{tool} answered an unreadable archive without an error key: {result}"
            );
            for empty_shape in [
                "episodes",
                "results",
                "utterances",
                "screenshots",
                "episode_count",
                "total_utterances",
            ] {
                assert!(
                    result.get(empty_shape).is_none(),
                    "{tool} must not also answer an empty {empty_shape} payload: {result}"
                );
            }
        }

        // An unknown name still falls through to the JSON-RPC error.
        assert!(dispatch_tool(&state, user_id, "not_a_tool", &json!({}))
            .await
            .is_none());
    }

    /// Every routed tool read is served identically for an unselected user:
    /// `wal_authoritative_read` falls through to the ordinary guarded legacy
    /// read, so the legacy lane keeps answering with the same rows. Paired
    /// with the refusal test above, this is the dual-path contract.
    ///
    /// It also pins the redaction boundary end to end. `dispatch_tool`
    /// applies `mcp_safety::sanitize_result(project_mcp_result(..))` at a
    /// single tail, AFTER the match that produced the value, so both lanes of
    /// the routed read are sanitised by construction. The retired D4 gate
    /// used to `return` before that tail; nothing does now, and the seeded
    /// credential below must come back redacted through the routed read.
    #[tokio::test]
    async fn mcp_reads_still_serve_an_unselected_user_from_the_legacy_lane() {
        let state = query_test_state();
        let user_id = "mcp-legacy-user";
        state
            .store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, active_app, ocr_text, is_duplicate) \
                     VALUES (?1, ?2, ?3, 0)",
                    rusqlite::params![
                        "2026-08-20T10:00:00Z",
                        "Ledger",
                        "quarterly invoice total, api key sk-exampleexampleexample"
                    ],
                )?;
                conn.execute(
                    "INSERT INTO episodes (started_at, ended_at, title, substance, \
                     visual_evidence, finalization_status) \
                     VALUES (?1, ?2, ?3, 'normal', 'useful', 'none')",
                    rusqlite::params![
                        "2026-08-20T09:00:00Z",
                        "2026-08-20T11:00:00Z",
                        "Quarterly review"
                    ],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let status = dispatch_tool(&state, user_id, "get_capture_status", &json!({}))
            .await
            .expect("get_capture_status dispatches");
        assert!(status.get("error").is_none(), "{status}");
        assert_eq!(status["total_screenshots"], 1);

        let listed = dispatch_tool(&state, user_id, "list_episodes", &json!({}))
            .await
            .expect("list_episodes dispatches");
        assert!(listed.get("error").is_none(), "{listed}");
        assert_eq!(listed["episode_count"], 1);
        assert_eq!(listed["episodes"][0]["title"], "Quarterly review");

        let hits = dispatch_tool(
            &state,
            user_id,
            "search_screenshots",
            &json!({"query": "invoice"}),
        )
        .await
        .expect("search_screenshots dispatches");
        assert!(hits.get("error").is_none(), "{hits}");
        let results = hits["results"].as_array().expect("search answers an array");
        assert_eq!(results.len(), 1);
        // The routed read is sanitised by exactly the boundary the legacy
        // read went through: the stored bytes are untouched, but the
        // credential never reaches the assistant.
        let ocr = results[0]["ocr_text"]
            .as_str()
            .expect("the hit carries its OCR text");
        assert!(
            ocr.contains("[REDACTED") && !ocr.contains("sk-exampleexampleexample"),
            "a routed MCP read must be redacted like the legacy read: {ocr}"
        );
        let stored: String = state
            .store
            .with_user(user_id, |conn| {
                Ok(conn.query_row("SELECT ocr_text FROM screenshots", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert!(
            stored.contains("sk-exampleexampleexample"),
            "redaction is a response boundary, never a rewrite of the archive"
        );
    }

    /// `MCP_TOOL_NAMES` is the roster the tests above sweep, so a seventh
    /// published tool that is not listed there would never be swept for the
    /// empty-result property.
    #[test]
    fn mcp_tool_names_match_the_published_definitions() {
        let tools = tool_definitions();
        let published: Vec<&str> = tools
            .as_array()
            .expect("tool definitions must be an array")
            .iter()
            .map(|tool| tool["name"].as_str().expect("every tool is named"))
            .collect();
        assert_eq!(published, MCP_TOOL_NAMES);
    }

    fn query_test_state() -> Arc<CpState> {
        let gcs = Arc::new(FakeGcs::new());
        query_test_state_with_media(Arc::clone(&gcs), Arc::clone(&gcs), gcs)
    }

    #[test]
    fn browser_v2_loader_requires_exact_evidence_and_a_live_episode_member() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE screenshots (
                 id INTEGER PRIMARY KEY,source_key TEXT,browser_snapshot_source_key TEXT,
                 captured_at TEXT NOT NULL
             );
             CREATE TABLE capture_events (
                 event_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,context_json TEXT NOT NULL,
                 started_at TEXT NOT NULL,source_wall_at TEXT NOT NULL
             );
             CREATE TABLE browser_states_v2 (
                 state_key TEXT PRIMARY KEY,browser_bundle_id TEXT NOT NULL,
                 browser_name TEXT NOT NULL,permission_status TEXT NOT NULL,
                 content_hash TEXT NOT NULL,tabs_json TEXT NOT NULL,created_at TEXT NOT NULL
             );
             CREATE TABLE browser_observations_v2 (
                 observation_id TEXT PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,
                 observed_at TEXT NOT NULL,state_key TEXT,context_status TEXT NOT NULL,
                 active_url TEXT,active_title TEXT,created_at TEXT NOT NULL
             );
             CREATE TABLE episodes (id INTEGER PRIMARY KEY);
             CREATE TABLE episode_members (
                 episode_id INTEGER NOT NULL,record_type TEXT NOT NULL,record_id INTEGER NOT NULL
             );",
        )
        .unwrap();
        let hash = "43206e42c20fd24a9372605a13b6792245ed53e50edf6c1735cfba4053be30f3";
        let state_key = format!("device-1:browser-v2:{hash}");
        let tabs = json!([
            {
                "window_index":1,
                "tab_index":1,
                "title":"Meeting",
                "url":"https://meet.google.com/abc?authuser=0#frag",
                "url_scheme":"https",
                "is_active":true,
                "is_loading":null
            },
            {
                "window_index":1,
                "tab_index":2,
                "title":"Document",
                "url":"https://docs.google.com/document/d/exact/edit?tab=t.0",
                "url_scheme":"https",
                "is_active":false,
                "is_loading":null
            }
        ]);
        let context = json!({
            "capture_status":"stable",
            "active_app":"Safari",
            "primary_bundle_id":"com.apple.Safari",
            "primary_window_id":7,
            "window_title":"Meeting",
            "display_id":1,
            "active_url":"https://meet.google.com/abc?authuser=0#frag",
            "active_url_title":"Meeting",
            "browser_permission_status":"granted",
            "browser_state_key":state_key,
            "browser_snapshot":{
                "state_key":state_key,
                "browser_bundle_id":"com.apple.Safari",
                "browser_name":"Safari",
                "permission_status":"granted",
                "active_window_index":1,
                "active_tab_index":1,
                "reported_tab_count":2,
                "truncated":false,
                "ambient_tab_collection_enabled":true,
                "content_hash":hash,
                "tabs":tabs
            },
            "visible_windows":[],
            "visible_windows_truncated":false
        });
        let envelope = json!({
            "schema_version":2,
            "active_window_index":1,
            "active_tab_index":1,
            "reported_tab_count":2,
            "truncated":false,
            "ambient_tab_collection_enabled":true,
            "tabs":tabs
        });
        conn.execute(
            "INSERT INTO capture_events VALUES (
             'event-1','device-1',?1,'2026-08-22T12:00:01.000Z','2026-08-22T12:00:01.000Z')",
            [context.to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO browser_states_v2 VALUES (?1,'com.apple.Safari','Safari',
             'granted',?2,?3,'2026-08-22T12:00:00.000Z')",
            rusqlite::params![state_key, hash, envelope.to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO browser_observations_v2 VALUES (
             'event-1','event-1','2026-08-22T12:00:01.000Z',?1,'stable',
             'https://meet.google.com/abc?authuser=0#frag','Meeting',
             '2026-08-22T12:00:01.000Z')",
            [&state_key],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO screenshots VALUES (
             1,'cloud-v2:event-1','capture-v2-browser:event-1','2026-08-22T12:00:01.000Z')",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO episodes VALUES (1)", []).unwrap();
        conn.execute("INSERT INTO episode_members VALUES (1,'screenshot',1)", [])
            .unwrap();

        let loaded = load_browser_snapshot(&conn, "capture-v2-browser:event-1")
            .unwrap()
            .unwrap();
        assert_eq!(loaded["ambient_tab_collection_enabled"], true);
        assert_eq!(
            loaded["tabs"][1]["url"],
            "https://docs.google.com/document/d/exact/edit?tab=t.0"
        );

        conn.execute(
            "INSERT INTO screenshots VALUES (
             2,'cloud-v2:event-1','capture-v2-browser:event-1','2026-08-22T12:00:01.000Z')",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO episode_members VALUES (1,'screenshot',2)", [])
            .unwrap();
        assert!(load_browser_snapshot(&conn, "capture-v2-browser:event-1").is_err());
        conn.execute("DELETE FROM episode_members WHERE record_id=2", [])
            .unwrap();
        conn.execute("DELETE FROM screenshots WHERE id=2", [])
            .unwrap();

        let mut key_only = context;
        key_only.as_object_mut().unwrap().remove("browser_snapshot");
        conn.execute(
            "UPDATE capture_events SET context_json=?1 WHERE event_id='event-1'",
            [key_only.to_string()],
        )
        .unwrap();
        assert_eq!(
            load_browser_snapshot(&conn, "capture-v2-browser:event-1")
                .unwrap()
                .unwrap()["tabs"][0]["title"],
            "Meeting",
            "an unchanged key-only browser-v2 event reconstructs the exact persisted state"
        );

        conn.execute(
            "UPDATE capture_events SET started_at='2026-08-22T12:00:02.000Z'
             WHERE event_id='event-1'",
            [],
        )
        .unwrap();
        assert!(load_browser_snapshot(&conn, "capture-v2-browser:event-1").is_err());
        conn.execute(
            "UPDATE capture_events SET started_at='2026-08-22T12:00:01.000Z'
             WHERE event_id='event-1'",
            [],
        )
        .unwrap();

        conn.execute(
            "UPDATE browser_observations_v2 SET context_status='unstable'",
            [],
        )
        .unwrap();
        assert!(load_browser_snapshot(&conn, "capture-v2-browser:event-1").is_err());
        conn.execute(
            "UPDATE browser_observations_v2 SET context_status='stable'",
            [],
        )
        .unwrap();

        conn.execute("DELETE FROM browser_observations_v2", [])
            .unwrap();
        assert!(load_browser_snapshot(&conn, "capture-v2-browser:event-1").is_err());
        conn.execute(
            "INSERT INTO browser_observations_v2 VALUES (
             'event-1','event-1','2026-08-22T12:00:01.000Z',?1,'stable',
             'https://meet.google.com/abc?authuser=0#frag','Meeting',
             '2026-08-22T12:00:01.000Z')",
            [&state_key],
        )
        .unwrap();

        conn.execute("DELETE FROM browser_states_v2", []).unwrap();
        assert!(load_browser_snapshot(&conn, "capture-v2-browser:event-1").is_err());
        conn.execute(
            "INSERT INTO browser_states_v2 VALUES (?1,'com.apple.Safari','Safari',
             'granted',?2,?3,'2026-08-22T12:00:00.000Z')",
            rusqlite::params![state_key, hash, envelope.to_string()],
        )
        .unwrap();

        conn.execute(
            "UPDATE screenshots SET source_key='cloud-v2:other-event'",
            [],
        )
        .unwrap();
        assert!(load_browser_snapshot(&conn, "capture-v2-browser:event-1").is_err());
        conn.execute("UPDATE screenshots SET source_key='cloud-v2:event-1'", [])
            .unwrap();

        conn.execute("DELETE FROM episode_members", []).unwrap();
        assert!(load_browser_snapshot(&conn, "capture-v2-browser:event-1")
            .unwrap()
            .is_none());
        conn.execute("INSERT INTO episode_members VALUES (1,'screenshot',1)", [])
            .unwrap();
        conn.execute("UPDATE browser_states_v2 SET tabs_json='[]'", [])
            .unwrap();
        assert!(load_browser_snapshot(&conn, "capture-v2-browser:event-1").is_err());
    }

    fn query_test_state_with_media(
        index_gcs: Arc<FakeGcs>,
        current_media_gcs: Arc<FakeGcs>,
        legacy_media_gcs: Arc<FakeGcs>,
    ) -> Arc<CpState> {
        let kms = Arc::new(FakeKms);
        let store = Arc::new(Store::new_with_media_and_legacy(
            kms.clone(),
            index_gcs.clone(),
            current_media_gcs,
            legacy_media_gcs,
        ));
        Arc::new(CpState {
            store,
            control: Arc::new(crate::cp::control_store::ControlStore::new(kms, index_gcs)),
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
                admin_user_ids: Vec::new(),
                signup_limit_per_day: crate::cp::control_store::TEST_SIGNUP_LIMIT,
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

    async fn seed_capture_v2_screenshot_identity(
        state: &CpState,
        user_id: &str,
        asset_id: &str,
        object_key: &str,
        generation: i64,
        byte_length: i64,
        sha256: &str,
    ) {
        let event_id = format!("event-{asset_id}");
        let asset_id = asset_id.to_string();
        let object_key = object_key.to_string();
        let sha256 = sha256.to_string();
        state
            .store
            .with_user(user_id, move |conn| {
                conn.execute_batch(
                    "INSERT OR IGNORE INTO capture_sessions
                        (id, device_id, install_id, started_at, last_event_at, schema_version)
                     VALUES ('content-session', 'content-device', 'content-install',
                             '2026-08-01T10:00:00Z', '2026-08-01T10:05:00Z', 2);
                     INSERT OR IGNORE INTO capture_streams
                        (id, capture_session_id, device_id, stream_kind)
                     VALUES ('content-stream', 'content-session', 'content-device', 'mac_screen');",
                )?;
                conn.execute(
                    "INSERT INTO capture_events
                        (event_id, device_id, install_id, capture_session_id, stream_id,
                         stream_kind, sequence, source_wall_at, source_monotonic_ns,
                         started_at, ended_at, timezone_id, utc_offset_minutes,
                         clock_uncertainty_ms, asset_id, manifest_digest)
                     VALUES (?1, 'content-device', 'content-install', 'content-session',
                             'content-stream', 'mac_screen',
                             (SELECT COUNT(*) FROM capture_events),
                             '2026-08-01T10:00:00Z', '1', '2026-08-01T10:00:00Z',
                             '2026-08-01T10:00:01Z', 'UTC', 0, 0, ?2, ?3)",
                    rusqlite::params![event_id, asset_id, format!("digest-{asset_id}")],
                )?;
                conn.execute(
                    "INSERT INTO media_objects
                        (asset_id,event_id,object_key,object_generation,object_backend,mime_type,
                         codec,byte_length,sha256,processing_state)
                     VALUES (?1,?2,?3,?4,'current','image/jpeg','jpeg',?5,?6,'ready')",
                    rusqlite::params![
                        asset_id,
                        event_id,
                        object_key,
                        generation,
                        byte_length,
                        sha256
                    ],
                )?;
                Ok(())
            })
            .await
            .unwrap();
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

        let listed = webhook_json(&subscription, None, None);
        assert_eq!(listed["endpoint_display"], "https://hooks.example.com/…");
        assert!(listed.get("endpoint_url").is_none());
        assert!(listed.get("signing_secret").is_none());
        assert_eq!(listed["delivery_status"]["pending"], 0);
        assert_eq!(listed["delivery_status"]["retry"], 0);
        assert_eq!(listed["delivery_status"]["sent"], 0);
        assert_eq!(listed["delivery_status"]["failed"], 0);
        assert_eq!(listed["delivery_status"]["ambiguous"], 0);
        assert_eq!(listed["delivery_status"]["cancelled"], 0);
        assert!(listed["delivery_status"]["latest"].is_null());

        let created = webhook_json(&subscription, Some(&subscription.signing_secret), None);
        assert_eq!(created["signing_secret"], "whsec_signing-secret");
        assert!(created.get("endpoint_url").is_none());
    }

    #[tokio::test]
    async fn webhook_list_reports_selected_status_authority_failure_as_503() {
        use crate::cp::wal_gate_test_support::{select_wal_authoritative, state};

        let state = state();
        let user = state
            .control
            .upsert_user(
                "webhook-status-unavailable-subject",
                "webhook-status-unavailable@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let user_id = user.id;
        state
            .control
            .create_webhook_subscription(crate::cp::control_store::WebhookSubscription {
                id: "c1000000-0000-4000-8000-000000000022".into(),
                user_id: user_id.clone(),
                name: "Unavailable status fixture".into(),
                endpoint_url: "https://hooks.example.com/status".into(),
                signing_secret: crate::cp::webhook_worker::new_signing_secret(),
                include_content: false,
                enabled: true,
                created_at: "2026-08-20T19:00:00.000Z".into(),
            })
            .await
            .unwrap();
        select_wal_authoritative(&state.store, &user_id);

        let response = rest_list_webhooks(State(state), Extension(AuthUser(user_id))).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4 * 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "enclave_unavailable"})
        );
    }

    #[tokio::test]
    async fn webhook_delete_waits_for_snapshotted_finalization_then_purges_its_commit() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("c0000000-0000-4000-8000-000000000023").await;
        let subscription_id = "c1000000-0000-4000-8000-000000000023";
        archive
            .state
            .control
            .create_webhook_subscription(crate::cp::control_store::WebhookSubscription {
                id: subscription_id.into(),
                user_id: archive.user_id.clone(),
                name: "Finalizer deletion race fixture".into(),
                endpoint_url: "https://hooks.example.com/finalizer-delete".into(),
                signing_secret: crate::cp::webhook_worker::new_signing_secret(),
                include_content: true,
                enabled: true,
                created_at: "2026-08-20T19:00:00.000Z".into(),
            })
            .await
            .unwrap();

        // This guard is the production finalizer's boundary immediately
        // before its Control snapshot. Hold it while the real sealed
        // finalization fixture commits, exactly modeling a pause after that
        // snapshot and before archive publication.
        let finalizer_guard = archive
            .state
            .store
            .lock_user_lifecycle(&archive.user_id)
            .await
            .unwrap();
        let snapshot = archive
            .state
            .control
            .list_webhook_subscriptions(&archive.user_id)
            .await
            .unwrap();
        assert!(snapshot.iter().any(|entry| entry.id == subscription_id));

        let delete_state = Arc::clone(&archive.state);
        let delete_user = archive.user_id.clone();
        let delete_subscription = subscription_id.to_owned();
        let deletion = tokio::spawn(async move {
            rest_delete_webhook(
                State(delete_state),
                Extension(AuthUser(delete_user)),
                Path(delete_subscription),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(
            !deletion.is_finished(),
            "DELETE must wait for the finalizer's snapshot/commit boundary"
        );

        crate::cp::finalizer::enqueue_webhook_delivery_for_activation_test(
            &archive.state,
            &archive.user_id,
            subscription_id,
            &crate::cp::webhook_worker::new_event_id(),
        )
        .await
        .unwrap();
        drop(finalizer_guard);

        let response = tokio::time::timeout(std::time::Duration::from_secs(30), deletion)
            .await
            .expect("DELETE resumes after finalization")
            .expect("DELETE task does not panic");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let residue = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, |connection| {
                let claim_sidecars: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='table' AND name IN (
                       'archive_v3_wal_webhook_frozen_requests',
                       'archive_v3_wal_webhook_send_claims'
                     )",
                    [],
                    |row| row.get(0),
                )?;
                let (frozen, claims) = if claim_sidecars == 2 {
                    (
                        connection.query_row(
                            "SELECT COUNT(*) FROM archive_v3_wal_webhook_frozen_requests",
                            [],
                            |row| row.get::<_, i64>(0),
                        )?,
                        connection.query_row(
                            "SELECT COUNT(*) FROM archive_v3_wal_webhook_send_claims",
                            [],
                            |row| row.get::<_, i64>(0),
                        )?,
                    )
                } else {
                    (0, 0)
                };
                Ok((
                    connection.query_row("SELECT COUNT(*) FROM webhook_deliveries", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                    frozen,
                    claims,
                ))
            })
            .await
            .unwrap();
        assert_eq!(residue, (0, 0, 0));
        assert!(archive
            .state
            .control
            .get_webhook_subscription(&archive.user_id, subscription_id)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn webhook_finalization_and_delete_share_one_complete_lifecycle_boundary() {
        let finalizer = include_str!("finalizer.rs");
        let lock = finalizer
            .find("let webhook_lifecycle_guard = state.store.lock_user_lifecycle(user_id).await?")
            .expect("selected finalization acquires the webhook lifecycle guard");
        let snapshot = finalizer[lock..]
            .find(".list_webhook_subscriptions(user_id)")
            .map(|offset| lock + offset)
            .expect("the Control snapshot is inside the lifecycle guard");
        let commit = finalizer[snapshot..]
            .find("let commit_res: Result<usize>")
            .map(|offset| snapshot + offset)
            .expect("the archive commit follows the destination snapshot");
        let release = finalizer[commit..]
            .find("drop(webhook_lifecycle_guard)")
            .map(|offset| commit + offset)
            .expect("the finalizer explicitly releases after commit");
        assert!(lock < snapshot && snapshot < commit && commit < release);

        let query = include_str!("query.rs");
        let owner = query
            .find("async fn rest_delete_webhook(")
            .expect("webhook DELETE owner exists");
        let next_owner = query[owner..]
            .find("async fn rest_test_webhook(")
            .map(|offset| owner + offset)
            .expect("webhook DELETE owner has a bounded source body");
        let body = &query[owner..next_owner];
        let delete_lock = body
            .find("s.store.lock_user_lifecycle(&user_id).await")
            .expect("DELETE acquires the same lifecycle guard");
        let disable = body
            .find(".disable_webhook_subscription(&user_id, &subscription_id)")
            .expect("DELETE disables Control under the guard");
        let archive_drain = body
            .find("cancel_subscription_deliveries(&s, &user_id, &subscription_id)")
            .expect("DELETE drains the archive under the guard");
        let control_delete = body
            .find(".delete_webhook_subscription(&user_id, &subscription_id)")
            .expect("DELETE removes Control only after the archive drain");
        assert!(delete_lock < disable && disable < archive_drain && archive_drain < control_delete);
    }

    #[test]
    fn episode_deletion_and_finalization_share_the_complete_lifecycle_boundary() {
        let finalizer = include_str!("finalizer.rs");
        let finalizer_lock = finalizer
            .find("let webhook_lifecycle_guard = state.store.lock_user_lifecycle(user_id).await?")
            .expect("selected finalization acquires the per-user lifecycle guard");
        let archive_commit = finalizer[finalizer_lock..]
            .find("let commit_res: Result<usize>")
            .map(|offset| finalizer_lock + offset)
            .expect("selected finalization submits while holding the lifecycle guard");
        let finalizer_release = finalizer[archive_commit..]
            .find("drop(webhook_lifecycle_guard)")
            .map(|offset| archive_commit + offset)
            .expect("selected finalization releases only after its archive commit");
        assert!(finalizer_lock < archive_commit && archive_commit < finalizer_release);

        let query = include_str!("query.rs");
        let owner = query
            .find("async fn rest_selected_episode_delete(")
            .expect("selected episode-delete owner exists");
        let end = query[owner..]
            .find("fn episode_delete_response(")
            .map(|offset| owner + offset)
            .expect("selected episode-delete owner has a bounded body");
        let body = &query[owner..end];
        let delete_lock = body
            .find("s.store.lock_user_lifecycle(user_id).await")
            .expect("selected deletion acquires the same per-user lifecycle guard");
        let prepare = body
            .find("EpisodeDeletePreparePlan::new(")
            .expect("logical purge and capacity reservation precede provider cleanup");
        let work = body
            .find("wal::load_episode_delete_work(")
            .expect("the owner reloads durable work before each bounded step");
        let provider = body
            .find(".delete_retained_media(")
            .expect("provider cleanup follows durable preparation");
        let cleanup_submit = body[provider..]
            .find("EpisodeDeleteCleanupPlan::new(")
            .map(|offset| provider + offset)
            .expect("each provider result is durably settled before another step");
        assert!(delete_lock < prepare && prepare < work && work < provider);
        assert!(provider < cleanup_submit);

        let ledger = include_str!("query/wal/episode_delete.rs");
        let completion = ledger
            .find("impl WalLogicalDomainLedger<EpisodeDeletePlan>")
            .expect("sealed completion ledger exists");
        let completion = &ledger[completion..];
        assert!(completion.contains("final_selector_cleanup_commitment("));
        assert!(completion.contains("cleanup_items_commitment"));
        assert!(completion.contains("SELECT COUNT(*) FROM archive_v3_wal_episode_delete_cleanup"));
        assert!(completion.contains("selector_state<>'complete'"));

        let startup = include_str!("../main.rs");
        assert!(startup.contains("cp::query::spawn_episode_delete_worker(Arc::clone(&cp_state))"));
        let resume = query
            .find("pub(crate) async fn resume_user_episode_deletions(")
            .expect("durable deletion resume owner exists");
        let worker = query[resume..]
            .find("pub(crate) fn spawn_episode_delete_worker(")
            .map(|offset| resume + offset)
            .expect("dedicated deletion worker follows the bounded resume owner");
        let resume_body = &query[resume..worker];
        let read = resume_body
            .find("wal::load_pending_episode_delete_batch")
            .expect("the owner reads a durable rotated batch");
        let cursor_submit = resume_body
            .find("wal_authoritative_submit")
            .expect("the cursor advances durably before provider work");
        let route_step = resume_body
            .find("rest_selected_episode_delete")
            .expect("the owner performs bounded route steps after cursor advance");
        assert!(read < cursor_submit && cursor_submit < route_step);
        assert!(resume_body.contains("if response.status().is_server_error()"));
        assert!(!resume_body.contains("return Err"));
        let worker_end = query[worker..]
            .find("async fn rest_episode_members(")
            .map(|offset| worker + offset)
            .expect("the dedicated worker has a bounded source body");
        let worker_body = &query[worker..worker_end];
        assert!(worker_body.contains("Duration::from_secs(30)"));
        assert!(worker_body.contains("queue.push_back(id)"));
        assert!(worker_body.contains("Duration::from_millis(25)"));
        assert!(worker_body.contains("mpsc::channel::<String>(EPISODE_DELETE_WAKE_CAPACITY)"));
        assert!(query.contains("sender.try_send"));
        assert!(!worker_body.contains("unbounded_channel"));
        assert!(!worker_body.contains("biased;"));
        assert!(worker_body.contains("episode_delete_retry_delay"));
    }

    #[test]
    fn episode_delete_worker_bounds_retry_and_rotates_around_delayed_accounts() {
        assert_eq!(EPISODE_DELETE_WAKE_CAPACITY, 1_024);
        assert_eq!(episode_delete_retry_delay(1), Duration::from_secs(1));
        assert_eq!(episode_delete_retry_delay(2), Duration::from_secs(2));
        assert_eq!(episode_delete_retry_delay(5), Duration::from_secs(16));
        assert_eq!(episode_delete_retry_delay(6), Duration::from_secs(30));
        assert_eq!(
            episode_delete_retry_delay(u32::MAX),
            Duration::from_secs(30)
        );

        let now = Instant::now();
        let mut queue = VecDeque::from(["delayed".to_owned(), "ready".to_owned()]);
        let mut queued = HashSet::from(["delayed".to_owned(), "ready".to_owned()]);
        let retry_at = HashMap::from([("delayed".to_owned(), now + Duration::from_secs(30))]);
        assert_eq!(
            pop_ready_episode_delete_account(&mut queue, &mut queued, &retry_at, now).as_deref(),
            Some("ready")
        );
        assert_eq!(queue, VecDeque::from(["delayed".to_owned()]));
        assert!(queued.contains("delayed"));
        assert!(!queued.contains("ready"));
        assert!(episode_delete_worker_wait(&queue, &retry_at, now) >= Duration::from_secs(29));
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
        let object_key = "raw/cloud-image-owner/content-asset.enc";
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
        let object_generation = state
            .store
            .put_media(object_key, &encrypted, &wrapped_dek)
            .await
            .unwrap();
        let plaintext_sha256 = format!("{:x}", Sha256::digest(plaintext));
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
            .with_user(user_id, move |conn| {
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
                conn.execute(
                    "INSERT INTO media_objects
                        (asset_id,event_id,object_key,object_generation,object_backend,mime_type,
                         codec,byte_length,sha256,processing_state)
                     VALUES ('content-asset','content-event',?1,?2,'current','image/jpeg','jpeg',
                             ?3,?4,'ready')",
                    rusqlite::params![
                        object_key,
                        object_generation,
                        plaintext.len() as i64,
                        plaintext_sha256
                    ],
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

    /// `query.screenshot_image_content` is lifted only on bytes produced by
    /// the selected production chain: canonical capture upload + sealed
    /// capture receipt + sealed media claim/attempt/usage/storyboard result.
    /// A direct table seed would not prove the route's GCS/DEK/AAD boundary.
    #[tokio::test]
    async fn selected_capture_and_storyboard_serve_exact_screenshot_bytes() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;

        let archive = answerable_wal_archive("a0000000-0000-4000-8000-000000000006").await;
        let plaintext = vec![
            0xff, 0xd8, 0xff, b'K', b'I', b'O', b'K', b'U', b'-', b'J', b'P', b'E', b'G', 0xff,
            0xd9,
        ];
        let sha256 = format!("{:x}", Sha256::digest(&plaintext));
        let mut manifest: super::super::media::CaptureEventManifest =
            serde_json::from_value(json!({
                "schema_version": 2,
                "event_id": "selected-screen-event",
                "device_id": "selected-device",
                "install_id": "selected-install",
                "capture_session_id": "selected-session",
                "stream_id": "selected-screen-stream",
                "stream_kind": "mac_screen",
                "sequence": 0,
                "source_wall_at": "2026-08-22T10:00:00.000Z",
                "source_monotonic_ns": 1,
                "started_at": "2026-08-22T10:00:00.000Z",
                "ended_at": "2026-08-22T10:00:00.001Z",
                "timezone_id": "UTC",
                "utc_offset_minutes": 0,
                "clock_uncertainty_ms": 1,
                "media": {
                    "asset_id": "selected-screen-asset",
                    "mime_type": "image/jpeg",
                    "codec": "jpeg",
                    "byte_length": plaintext.len(),
                    "sha256": sha256,
                    "width": 1,
                    "height": 1,
                    "scale": 1,
                    "orientation": "up"
                },
                "context": {
                    "capture_status": "stable",
                    "active_app": "Safari",
                    "primary_bundle_id": "com.apple.Safari",
                    "primary_window_id": 1,
                    "window_title": "Meeting",
                    "display_id": 1,
                    "active_url": "https://meet.google.com/abc?authuser=0#frag",
                    "active_url_title": "Meeting",
                    "browser_permission_status": "granted",
                    "browser_state_key": null,
                    "browser_snapshot": null,
                    "visible_windows": [],
                    "visible_windows_truncated": false
                }
            }))
            .unwrap();
        let browser_hash = "43206e42c20fd24a9372605a13b6792245ed53e50edf6c1735cfba4053be30f3";
        let browser_state_key = format!("selected-device:browser-v2:{browser_hash}");
        let context = manifest.context.as_mut().unwrap();
        context.browser_state_key = Some(browser_state_key.clone());
        context.browser_snapshot = Some(super::super::media::BrowserSnapshot {
            state_key: browser_state_key,
            browser_bundle_id: "com.apple.Safari".into(),
            browser_name: "Safari".into(),
            permission_status: "granted".into(),
            active_window_index: Some(1),
            active_tab_index: Some(1),
            reported_tab_count: 2,
            truncated: false,
            ambient_tab_collection_enabled: Some(true),
            content_hash: browser_hash.into(),
            tabs: vec![
                super::super::media::BrowserTab {
                    window_index: 1,
                    tab_index: 1,
                    title: Some("Meeting".into()),
                    url: Some("https://meet.google.com/abc?authuser=0#frag".into()),
                    url_scheme: Some("https".into()),
                    is_active: true,
                    is_loading: None,
                },
                super::super::media::BrowserTab {
                    window_index: 1,
                    tab_index: 2,
                    title: Some("Document".into()),
                    url: Some("https://docs.google.com/document/d/exact/edit?tab=t.0".into()),
                    url_scheme: Some("https".into()),
                    is_active: false,
                    is_loading: None,
                },
            ],
        });
        let asset_id = super::super::media::submit_selected_screen_capture_fixture(
            &archive.state,
            &archive.user_id,
            manifest,
            &plaintext,
        )
        .await
        .unwrap();
        super::super::media_worker::settle_selected_screen_result_fixture(
            &archive.state,
            &archive.user_id,
        )
        .await
        .unwrap();
        let browser_source_key = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, |conn| {
                conn.query_row(
                    "SELECT browser_snapshot_source_key FROM screenshots
                     WHERE source_key='cloud-v2:selected-screen-event'",
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            browser_source_key.as_deref(),
            Some("capture-v2-browser:selected-screen-event")
        );

        let response = rest_screenshot_image_content(
            State(Arc::clone(&archive.state)),
            Extension(AuthUser(archive.user_id)),
            Path(format!("{CLOUD_CAPTURE_IMAGE_ID_PREFIX}{asset_id}")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "image/jpeg");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), plaintext.as_slice());
    }

    #[tokio::test]
    async fn capture_v2_content_enforces_the_committed_provider_and_plaintext_identity() {
        let index = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let state = query_test_state_with_media(index, Arc::clone(&current), Arc::clone(&legacy));
        let user_id = "capture-content-integrity";
        let (dek, wrapped_dek) = crate::crypto::generate_and_wrap_dek(state.store.kms.as_ref())
            .await
            .unwrap();
        let wrapped_for_db = wrapped_dek.clone();
        state
            .store
            .with_user(user_id, move |conn| {
                conn.execute(
                    "INSERT INTO app_metadata (key, value) VALUES (?1, ?2)",
                    rusqlite::params![MEDIA_DEK_METADATA_KEY, wrapped_for_db],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        // A later live provider version and a poison object in the legacy
        // provider must not replace the exact committed current generation.
        let pinned_asset = "pinned-asset";
        let pinned_key =
            crate::store::canonical_capture_media_object_key(user_id, pinned_asset).unwrap();
        let pinned_plaintext = b"pinned jpeg bytes";
        let pinned_context = crate::store::media_blob_context(user_id, &pinned_key);
        let pinned_blob =
            crate::crypto::encrypt_bound_blob(&dek, pinned_plaintext, &pinned_context).unwrap();
        let pinned_generation = current
            .put_object(&pinned_key, &pinned_blob, &wrapped_dek, 0)
            .await
            .unwrap();
        let legacy_poison =
            crate::crypto::encrypt_bound_blob(&dek, b"legacy poison", &pinned_context).unwrap();
        legacy
            .put_object(&pinned_key, &legacy_poison, &wrapped_dek, 0)
            .await
            .unwrap();
        let newer_blob =
            crate::crypto::encrypt_bound_blob(&dek, b"newer wrong bytes", &pinned_context).unwrap();
        current
            .put_object(&pinned_key, &newer_blob, &wrapped_dek, pinned_generation)
            .await
            .unwrap();
        seed_capture_v2_screenshot_identity(
            &state,
            user_id,
            pinned_asset,
            &pinned_key,
            pinned_generation,
            pinned_plaintext.len() as i64,
            &format!("{:x}", Sha256::digest(pinned_plaintext)),
        )
        .await;
        let pinned = rest_screenshot_image_content(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.into())),
            Path(format!("{CLOUD_CAPTURE_IMAGE_ID_PREFIX}{pinned_asset}")),
        )
        .await;
        assert_eq!(pinned.status(), StatusCode::OK);
        let pinned_body = axum::body::to_bytes(pinned.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(pinned_body.as_ref(), pinned_plaintext);
        assert_eq!(
            legacy.live_get_count(),
            0,
            "capture-v2 must never fall back"
        );

        current.fail_next_exact_get(crate::error::EnclaveError::Gcs(
            "injected current-provider outage".into(),
        ));
        let provider_unavailable = rest_screenshot_image_content(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.into())),
            Path(format!("{CLOUD_CAPTURE_IMAGE_ID_PREFIX}{pinned_asset}")),
        )
        .await;
        assert_eq!(
            provider_unavailable.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            legacy.live_get_count(),
            0,
            "outage must not trigger fallback"
        );

        // Canonical rows refuse both historical ciphertext encodings even
        // though the separate legacy screenshot-id arm remains compatible.
        let unbound_asset = "unbound-asset";
        let unbound_key =
            crate::store::canonical_capture_media_object_key(user_id, unbound_asset).unwrap();
        let unbound_plaintext = b"unbound historical bytes";
        let unbound_blob = crate::crypto::encrypt_blob(&dek, unbound_plaintext).unwrap();
        let unbound_generation = current
            .put_object(&unbound_key, &unbound_blob, &wrapped_dek, 0)
            .await
            .unwrap();
        seed_capture_v2_screenshot_identity(
            &state,
            user_id,
            unbound_asset,
            &unbound_key,
            unbound_generation,
            unbound_plaintext.len() as i64,
            &format!("{:x}", Sha256::digest(unbound_plaintext)),
        )
        .await;

        // Plaintext size/hash and installed-wrapped-key commitments are all
        // independently enforced; every mismatch is a fault, never bytes.
        let length_asset = "length-asset";
        let length_key =
            crate::store::canonical_capture_media_object_key(user_id, length_asset).unwrap();
        let length_plaintext = b"length committed bytes";
        let length_blob = crate::crypto::encrypt_bound_blob(
            &dek,
            length_plaintext,
            &crate::store::media_blob_context(user_id, &length_key),
        )
        .unwrap();
        let length_generation = current
            .put_object(&length_key, &length_blob, &wrapped_dek, 0)
            .await
            .unwrap();
        seed_capture_v2_screenshot_identity(
            &state,
            user_id,
            length_asset,
            &length_key,
            length_generation,
            length_plaintext.len() as i64 + 1,
            &format!("{:x}", Sha256::digest(length_plaintext)),
        )
        .await;

        let hash_asset = "hash-asset";
        let hash_key =
            crate::store::canonical_capture_media_object_key(user_id, hash_asset).unwrap();
        let hash_plaintext = b"hash committed bytes";
        let hash_blob = crate::crypto::encrypt_bound_blob(
            &dek,
            hash_plaintext,
            &crate::store::media_blob_context(user_id, &hash_key),
        )
        .unwrap();
        let hash_generation = current
            .put_object(&hash_key, &hash_blob, &wrapped_dek, 0)
            .await
            .unwrap();
        seed_capture_v2_screenshot_identity(
            &state,
            user_id,
            hash_asset,
            &hash_key,
            hash_generation,
            hash_plaintext.len() as i64,
            &"0".repeat(64),
        )
        .await;

        let wrong_key_asset = "wrong-wrapped-key-asset";
        let wrong_key =
            crate::store::canonical_capture_media_object_key(user_id, wrong_key_asset).unwrap();
        let wrong_key_plaintext = b"wrong wrapped key bytes";
        let (other_dek, other_wrapped_dek) =
            crate::crypto::generate_and_wrap_dek(state.store.kms.as_ref())
                .await
                .unwrap();
        let wrong_key_blob = crate::crypto::encrypt_bound_blob(
            &other_dek,
            wrong_key_plaintext,
            &crate::store::media_blob_context(user_id, &wrong_key),
        )
        .unwrap();
        let wrong_key_generation = current
            .put_object(&wrong_key, &wrong_key_blob, &other_wrapped_dek, 0)
            .await
            .unwrap();
        seed_capture_v2_screenshot_identity(
            &state,
            user_id,
            wrong_key_asset,
            &wrong_key,
            wrong_key_generation,
            wrong_key_plaintext.len() as i64,
            &format!("{:x}", Sha256::digest(wrong_key_plaintext)),
        )
        .await;

        let wrong_object_asset = "wrong-object-key-asset";
        let substituted_object_key =
            crate::store::canonical_capture_media_object_key(user_id, "different-asset").unwrap();
        seed_capture_v2_screenshot_identity(
            &state,
            user_id,
            wrong_object_asset,
            &substituted_object_key,
            1,
            1,
            &"a".repeat(64),
        )
        .await;

        for asset in [
            unbound_asset,
            length_asset,
            hash_asset,
            wrong_key_asset,
            wrong_object_asset,
        ] {
            let refused = rest_screenshot_image_content(
                State(Arc::clone(&state)),
                Extension(AuthUser(user_id.into())),
                Path(format!("{CLOUD_CAPTURE_IMAGE_ID_PREFIX}{asset}")),
            )
            .await;
            assert_eq!(
                refused.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{asset}"
            );
        }
        assert_eq!(legacy.live_get_count(), 0, "capture-v2 never probes legacy");

        // Exact-generation NotFound is ambiguous while the sealed ready row
        // remains. Once retention settles deleted_at, the same logical lookup
        // becomes a truthful absence.
        let missing_asset = "missing-generation-asset";
        let missing_key =
            crate::store::canonical_capture_media_object_key(user_id, missing_asset).unwrap();
        let missing_plaintext = b"vanishing exact generation";
        let missing_blob = crate::crypto::encrypt_bound_blob(
            &dek,
            missing_plaintext,
            &crate::store::media_blob_context(user_id, &missing_key),
        )
        .unwrap();
        let missing_generation = current
            .put_object(&missing_key, &missing_blob, &wrapped_dek, 0)
            .await
            .unwrap();
        seed_capture_v2_screenshot_identity(
            &state,
            user_id,
            missing_asset,
            &missing_key,
            missing_generation,
            missing_plaintext.len() as i64,
            &format!("{:x}", Sha256::digest(missing_plaintext)),
        )
        .await;
        current.vanish_next_exact_generation_get(&missing_key, missing_generation);
        let unavailable = rest_screenshot_image_content(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.into())),
            Path(format!("{CLOUD_CAPTURE_IMAGE_ID_PREFIX}{missing_asset}")),
        )
        .await;
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        state
            .store
            .with_user(user_id, |conn| {
                conn.execute(
                    "UPDATE media_objects SET deleted_at='2026-08-22T12:00:00Z' WHERE asset_id=?1",
                    [missing_asset],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let deleted = rest_screenshot_image_content(
            State(state),
            Extension(AuthUser(user_id.into())),
            Path(format!("{CLOUD_CAPTURE_IMAGE_ID_PREFIX}{missing_asset}")),
        )
        .await;
        assert_eq!(deleted.status(), StatusCode::NOT_FOUND);
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
            conn.execute("INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES (8, '2026-01-01T10:07:00Z', 'dev_1:8', 0)", [])?;
            conn.execute("INSERT INTO screenshots (id, captured_at, source_key, is_duplicate) VALUES (9, '2026-01-01T10:08:00Z', 'devA1:9', 0)", [])?;

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
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 8)", [])?;
            conn.execute("INSERT INTO episode_members (episode_id, record_type, record_id) VALUES (10, 'screenshot', 9)", [])?;

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

        let underscore = store
            .with_user(user_id, |conn| {
                query_screenshot_upload_plan(
                    conn,
                    &PlanParams {
                        device_id: "dev_1".into(),
                        after: None,
                    },
                )
            })
            .await
            .unwrap();
        assert_eq!(underscore["episodes"][0]["source_keys"], json!(["dev_1:8"]));
        assert!(legacy_screenshot_source_pattern("dev%").is_err());
        assert!(legacy_screenshot_source_pattern("").is_err());
        assert!(legacy_screenshot_source_pattern(&"d".repeat(129)).is_err());

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
            .upsert_user(
                "google-sub-query-test",
                "query_user@example.com",
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
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

    #[test]
    fn selected_screenshot_upload_retirement_precedes_every_work_boundary() {
        let source = include_str!("query.rs");

        let plan_start = source
            .find(concat!("async fn rest_screenshot_upload_", "plan"))
            .unwrap();
        let plan_end = source
            .find(concat!("fn selected_screenshot_upload_", "retired"))
            .unwrap();
        let plan = &source[plan_start..plan_end];
        let plan_selection = plan.find(concat!("is_wal_", "authoritative(")).unwrap();
        let legacy_read = plan.find(concat!(".with_", "user(")).unwrap();
        assert!(plan_selection < legacy_read);
        assert!(
            plan.contains("StatusCode::GONE")
                || source[plan_end..].starts_with("fn selected_screenshot_upload_retired")
        );

        let upload_start = source
            .find(concat!("async fn rest_screenshot_", "image_upload"))
            .unwrap();
        let upload_end = source
            .find(concat!("async fn rest_screenshot_", "image_content"))
            .unwrap();
        let upload = &source[upload_start..upload_end];
        let upload_selection = upload.find(concat!("is_wal_", "authoritative(")).unwrap();
        let multipart_read = upload.find("multipart.next_field()").unwrap();
        let content_lease = upload.find(concat!("acquire_content_", "write(")).unwrap();
        let provider_put = upload.find(concat!("put_user_", "media(")).unwrap();
        assert!(upload_selection < multipart_read);
        assert!(upload_selection < content_lease);
        assert!(upload_selection < provider_put);
        assert!(!upload.contains(concat!("wal_selected_screenshot_", "image_upload")));
        assert!(!upload.contains(concat!("wal_authoritative_", "read(")));
        assert!(!upload.contains(concat!("wal_authoritative_", "submit(")));

        // The unselected compatibility arm retains its exact legacy mutation
        // shape after the early Genesis tombstone.
        assert_eq!(upload.matches(concat!(".with_", "user(")).count(), 5);
        assert_eq!(upload.matches(concat!(".save_", "user(")).count(), 2);
        assert_eq!(upload.matches(concat!("put_user_", "media(")).count(), 1);
    }

    #[tokio::test]
    async fn selected_screenshot_plan_and_upload_are_explicit_gone_tombstones() {
        use crate::cp::wal_gate_test_support::select_wal_authoritative;
        use axum::body::Body;
        use axum::extract::{FromRequest, FromRequestParts};
        use axum::http::Request;

        let state = query_test_state();
        let user_id = "selected-retired-screenshot-upload";
        select_wal_authoritative(&state.store, user_id);

        let request = Request::builder()
            .uri("/api/screenshot-images/plan")
            .body(Body::empty())
            .unwrap();
        let (mut parts, _) = request.into_parts();
        let query = Query::<PlanParams>::from_request_parts(&mut parts, &()).await;
        assert!(query.is_err());
        let plan = rest_screenshot_upload_plan(
            State(Arc::clone(&state)),
            Extension(AuthUser(user_id.into())),
            query,
        )
        .await;
        assert_eq!(plan.status(), StatusCode::GONE);
        let body = axum::body::to_bytes(plan.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "screenshot_upload_retired"})
        );

        let request = Request::builder().body(Body::empty()).unwrap();
        let multipart = Multipart::from_request(request, &()).await;
        assert!(multipart.is_err());
        let upload = rest_screenshot_image_upload(
            State(state),
            Extension(AuthUser(user_id.into())),
            multipart,
        )
        .await;
        assert_eq!(upload.status(), StatusCode::GONE);
        let body = axum::body::to_bytes(upload.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "screenshot_upload_retired"})
        );
    }

    #[tokio::test]
    async fn selected_episode_delete_settles_and_replays_from_its_content_free_receipt() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;
        use axum::body::to_bytes;

        let archive = answerable_wal_archive("8b6fc0a8-68a2-4a91-bd71-f22a8d13a34d").await;
        let episode_id = archive
            .state
            .store
            .wal_authoritative_read(&archive.user_id, |connection| {
                connection
                    .query_row("SELECT id FROM episodes ORDER BY id LIMIT 1", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .map_err(Into::into)
            })
            .await
            .unwrap();

        let first = rest_episode_delete(
            State(Arc::clone(&archive.state)),
            Extension(AuthUser(archive.user_id.clone())),
            Path(episode_id),
        )
        .await;
        let first_status = first.status();
        let first_body = to_bytes(first.into_body(), 1024 * 1024).await.unwrap();
        assert_eq!(
            first_status,
            StatusCode::OK,
            "unexpected delete response: {}",
            String::from_utf8_lossy(&first_body)
        );
        let first_json: Value = serde_json::from_slice(&first_body).unwrap();
        assert_eq!(first_json["deleted"], true);
        assert_eq!(first_json["episode_id"], episode_id);

        let replay = rest_episode_delete(
            State(Arc::clone(&archive.state)),
            Extension(AuthUser(archive.user_id.clone())),
            Path(episode_id),
        )
        .await;
        assert_eq!(replay.status(), StatusCode::OK);
        let replay_body = to_bytes(replay.into_body(), 1024 * 1024).await.unwrap();
        assert_eq!(first_body, replay_body);

        let absent = rest_episode(
            State(archive.state),
            Extension(AuthUser(archive.user_id)),
            Path(episode_id),
            Query(EpisodeParams { include_low: None }),
        )
        .await;
        assert_eq!(absent.status(), StatusCode::NOT_FOUND);
    }

    /// **Every routed REST read in this module, as one table.**
    ///
    /// The property: when the archive behind a read cannot be read, the route
    /// answers a non-2xx that carries no data-shaped key. Not a 200 with an
    /// error body, not a 404, not an empty collection. See
    /// `wal_gate_test_support::assert_refuses_without_data`, which is
    /// deliberately status-agnostic — a D4 deferral and a store fault are both
    /// legitimate answers here and each surface picks its own.
    ///
    /// This exists because the read-lane review found TWO regressions, and
    /// both lived in the six surfaces that had no failure-arm test at all:
    /// `/api/search` shipped `{"error": ...}` under HTTP 200, and
    /// `/api/screenshot-images/{id}/content` collapsed a failed lookup into a
    /// bare unlogged 404 byte-identical to genuine absence. Per-route tests
    /// get written for the routes someone was already thinking about; a table
    /// is what covers the ones nobody was.
    ///
    /// Two lanes, and BOTH are load-bearing:
    ///
    /// * **selected** — the archive is WAL-authoritative with no serving
    ///   authority, the shape of an authority that is unavailable or
    ///   quarantined. On a gated surface the D4 gate answers; on an ungated
    ///   one (`/api/episodes/{id}/finalize`) the routed read's own arm does.
    /// * **unreadable legacy** — the archive is NOT selected, so no gate can
    ///   fire, and the guarded legacy load that `wal_authoritative_read` falls
    ///   through to cannot open it. This is the lane that sees a failure arm
    ///   hiding behind a gate, and it is the lane both blockers were in. A
    ///   selected-only test would have passed with both defects present.
    #[tokio::test]
    async fn every_routed_rest_read_refuses_without_reporting_an_empty_archive() {
        use crate::cp::wal_gate_test_support::{
            assert_refuses_without_data, make_legacy_archive_unreadable, select_wal_authoritative,
        };
        use axum::extract::{Path, Query, State};
        use axum::Extension;

        async fn routed_rest_reads(
            state: &Arc<CpState>,
            user_id: &str,
        ) -> Vec<(&'static str, Response)> {
            let user = || crate::cp::auth::AuthUser(user_id.to_string());
            vec![
                (
                    "GET /api/search",
                    rest_search(
                        State(Arc::clone(state)),
                        Extension(user()),
                        Query(SearchParams {
                            q: Some("invoice".into()),
                            from: None,
                            to: None,
                            limit: None,
                        }),
                    )
                    .await,
                ),
                (
                    "GET /api/episodes",
                    rest_episodes(
                        State(Arc::clone(state)),
                        Extension(user()),
                        Query(EpisodesParams {
                            from: None,
                            to: None,
                            max_episodes: None,
                            include_low: None,
                        }),
                    )
                    .await,
                ),
                (
                    "GET /api/episodes/{id}",
                    rest_episode(
                        State(Arc::clone(state)),
                        Extension(user()),
                        Path(1),
                        Query(EpisodeParams { include_low: None }),
                    )
                    .await,
                ),
                (
                    "GET /api/episodes/{id}/members",
                    rest_episode_members(State(Arc::clone(state)), Extension(user()), Path(1))
                        .await,
                ),
                (
                    "GET /api/browser-snapshots/{key}",
                    rest_browser_snapshot(
                        State(Arc::clone(state)),
                        Extension(user()),
                        Path("device:1".to_string()),
                    )
                    .await,
                ),
                (
                    "POST /api/episodes/{id}/finalize",
                    rest_episode_finalize(State(Arc::clone(state)), Extension(user()), Path(1))
                        .await,
                ),
                (
                    "GET /api/feed",
                    rest_feed(
                        State(Arc::clone(state)),
                        Extension(user()),
                        Query(FeedParams {
                            from: None,
                            to: None,
                            limit: None,
                            before: None,
                        }),
                    )
                    .await,
                ),
                (
                    "GET /api/screenshot-images/{id}/content",
                    rest_screenshot_image_content(
                        State(Arc::clone(state)),
                        Extension(user()),
                        Path("abc123".to_string()),
                    )
                    .await,
                ),
            ]
        }

        let state = query_test_state();

        // The table must stay complete. If a tenth routed read is bound in
        // `router()` and nobody adds it here, this fails rather than letting
        // the next `/api/search` ship untested.
        let source = include_str!("query.rs");
        let router_body = source
            .split_once("pub fn router()")
            .expect("router() is defined in this module")
            .1
            .split_once("\n}\n")
            .expect("router() has a body")
            .0;
        let routed_read_handlers = [
            "rest_search",
            "rest_episodes",
            "rest_episode)",
            "rest_episode_members",
            "rest_browser_snapshot",
            "rest_episode_finalize",
            "rest_feed",
            "rest_screenshot_image_content",
        ];
        for handler in routed_read_handlers {
            assert!(
                router_body.contains(handler),
                "{handler} is in the table but no longer bound by router()"
            );
        }
        assert_eq!(
            routed_rest_reads(&state, "coverage-probe").await.len(),
            routed_read_handlers.len(),
            "the table and the routed-read handler roster disagree"
        );

        let selected = "table-selected-user";
        select_wal_authoritative(&state.store, selected);
        for (label, response) in routed_rest_reads(&state, selected).await {
            assert_refuses_without_data(&format!("{label} [selected]"), response).await;
        }

        let unreadable = "table-unreadable-user";
        make_legacy_archive_unreadable(&state.store, unreadable).await;
        for (label, response) in routed_rest_reads(&state, unreadable).await {
            assert_refuses_without_data(&format!("{label} [unreadable legacy]"), response).await;
        }
    }

    /// The other half of the dual-path contract for the REST lane: an
    /// unselected user with a readable archive is served by exactly the same
    /// routed call, through the guarded legacy read, and gets the same rows.
    /// Without this, the table above could be satisfied by a route that
    /// refuses everyone.
    #[tokio::test]
    async fn the_routed_feed_still_serves_an_unselected_user_from_the_legacy_lane() {
        use axum::extract::{Query, State};
        use axum::Extension;

        let state = query_test_state();
        let legacy_user = "feed-legacy-user";
        state
            .store
            .with_user(legacy_user, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, active_app, is_duplicate) \
                     VALUES (?1, ?2, 0)",
                    rusqlite::params!["2026-08-20T12:00:00Z", "Ledger"],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let served = rest_feed(
            State(Arc::clone(&state)),
            Extension(crate::cp::auth::AuthUser(legacy_user.to_string())),
            Query(FeedParams {
                from: None,
                to: None,
                limit: None,
                before: None,
            }),
        )
        .await;
        assert_eq!(served.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(served.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let records = body["records"]
            .as_array()
            .expect("the feed carries records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["active_app"], "Ledger");
    }

    /// **ADR-0022 D4, `mcp.tools` LIFTED: every tool ANSWERS.**
    ///
    /// The gate this replaces asserted that all six tools refuse a selected
    /// user. Deleting it is only correct if the tools now answer with real
    /// content, and "no longer 503" is not that: `dispatch_tool` degrades a
    /// failed read into `{"error": ...}` under HTTP 200, so a broken read
    /// would sail past any assertion that only checked the status.
    ///
    /// So this asserts, per tool: no `error` key, the tool's own payload key
    /// present, and a FIXTURE STRING inside it. The archive is a real
    /// converged genesis archive seeded through `wal_authoritative_submit`
    /// (see `wal_gate_test_support::answerable_wal_archive`), so every row
    /// read here arrived on the WAL lane — `with_user` cannot write to a
    /// selected user at all.
    #[tokio::test]
    async fn every_mcp_tool_answers_a_selected_user_with_real_content() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;
        use axum::extract::State;
        use axum::Extension;

        let archive = answerable_wal_archive("a0000000-0000-4000-8000-000000000001").await;
        let state = &archive.state;

        // (tool, arguments, payload key that must be present, substring the
        // fixture guarantees is inside it).
        let expectations: [(&str, Value, &str, &str); 6] = [
            (
                "search_transcripts",
                json!({"query": "depuis"}),
                "results",
                "depuis",
            ),
            (
                "search_screenshots",
                json!({"query": "renewal"}),
                "results",
                "Vendor renewal checklist",
            ),
            (
                "get_context",
                json!({"at": "2026-07-22T09:00:00Z", "window_seconds": 600}),
                "utterances",
                "August 19",
            ),
            (
                "summarize_time_range",
                json!({"from": "2026-07-22T00:00:00Z", "to": "2026-07-23T00:00:00Z"}),
                "episodes",
                "Launch planning and QA decision",
            ),
            (
                "list_episodes",
                json!({}),
                "episodes",
                "Dashboard cache invalidation fix",
            ),
            ("get_capture_status", json!({}), "total_utterances", ""),
        ];
        assert_eq!(
            expectations.len(),
            MCP_TOOL_NAMES.len(),
            "a seventh tool must be given an ANSWERS expectation here, not just \
             an unreadable-archive one"
        );

        for (tool, arguments, payload_key, must_contain) in expectations {
            let response = mcp_endpoint(
                State(Arc::clone(state)),
                Extension(crate::cp::auth::AuthUser(archive.user_id.clone())),
                Json(JsonRpcRequest {
                    id: json!(1),
                    method: "tools/call".into(),
                    params: json!({"name": tool, "arguments": arguments}),
                }),
            )
            .await;
            let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_ne!(
                body["result"]["isError"],
                json!(true),
                "{tool} still refuses a selected user: {body}"
            );
            let text = body["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or_else(|| panic!("{tool} answered no content: {body}"));
            let payload: Value = serde_json::from_str(text)
                .unwrap_or_else(|_| panic!("{tool} answered non-JSON content: {text}"));
            assert!(
                payload.get("error").is_none(),
                "{tool} answered a degraded error payload under HTTP 200: {payload}"
            );
            let carried = payload
                .get(payload_key)
                .unwrap_or_else(|| panic!("{tool} answered without {payload_key}: {payload}"));
            if must_contain.is_empty() {
                // `get_capture_status` carries counts, not prose.
                assert_eq!(
                    carried.as_i64(),
                    Some(6),
                    "get_capture_status must count the six fixture utterances: {payload}"
                );
                assert_eq!(payload["total_screenshots"].as_i64(), Some(1), "{payload}");
                assert_eq!(payload["episode_count"].as_i64(), Some(4), "{payload}");
            } else {
                let rendered = carried.to_string();
                assert!(
                    rendered.contains(must_contain),
                    "{tool} answered {payload_key} without the fixture's own \
                     content ({must_contain:?}): {rendered}"
                );
            }
        }
    }

    /// **`query.search` LIFTED.** `/api/search` answers a selected user with
    /// both halves of its payload carrying fixture rows: `episodes` from the
    /// sealed episode-window family's table and `results` from the sealed
    /// transcript family's. The FTS shadow tables are trigger-maintained, so a
    /// hit here also proves the WAL capture carried the trigger writes.
    #[tokio::test]
    async fn the_lifted_search_route_answers_a_selected_user_with_rows() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;
        use axum::extract::{Query, State};
        use axum::Extension;

        let archive = answerable_wal_archive("a0000000-0000-4000-8000-000000000002").await;
        let response = rest_search(
            State(Arc::clone(&archive.state)),
            Extension(crate::cp::auth::AuthUser(archive.user_id.clone())),
            Query(SearchParams {
                q: Some("depuis".into()),
                from: None,
                to: None,
                limit: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let results = body["results"]
            .as_array()
            .unwrap_or_else(|| panic!("the search answers a results array: {body}"));
        assert!(
            results
                .iter()
                .any(|hit| hit["text"].as_str().is_some_and(|t| t.contains("depuis"))),
            "the utterance half must carry the fixture transcript: {body}"
        );
        let episodes = body["episodes"]
            .as_array()
            .unwrap_or_else(|| panic!("the search answers an episodes array: {body}"));
        assert!(
            episodes
                .iter()
                .any(|hit| hit["title"].as_str().is_some_and(|t| t.contains("depuis"))),
            "the episode half must carry the fixture episode: {body}"
        );
    }

    /// **`query.episodes` LIFTED**, both routes. The list carries all four
    /// fixture episodes with their member counts and final briefs; the detail
    /// route resolves one by id. The detail route's `NotFound` -> 404 arm is
    /// asserted here too, because lifting the gate above it must not have
    /// funnelled a genuine absence into the routed-read 503.
    #[tokio::test]
    async fn the_lifted_episode_routes_answer_a_selected_user_with_rows() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;
        use axum::extract::{Path, Query, State};
        use axum::Extension;

        let archive = answerable_wal_archive("a0000000-0000-4000-8000-000000000003").await;
        let user = || crate::cp::auth::AuthUser(archive.user_id.clone());

        let listed = rest_episodes(
            State(Arc::clone(&archive.state)),
            Extension(user()),
            Query(EpisodesParams {
                from: None,
                to: None,
                max_episodes: None,
                include_low: None,
            }),
        )
        .await;
        assert_eq!(listed.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(listed.into_body(), 512 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["episode_count"].as_i64(), Some(4), "{body}");
        let episodes = body["episodes"]
            .as_array()
            .unwrap_or_else(|| panic!("the list answers an episodes array: {body}"));
        assert_eq!(episodes.len(), 4, "{body}");
        let launch = episodes
            .iter()
            .find(|e| e["id"].as_i64() == Some(940001))
            .unwrap_or_else(|| panic!("the fixture's launch episode must be listed: {body}"));
        assert_eq!(launch["title"], "Launch planning and QA decision");
        // `episode_members` and `episode_final_briefs` are separate sealed
        // writes; asserting them here is what keeps this from passing on an
        // `episodes` table that happens to have rows and nothing else.
        assert_eq!(launch["utterance_count"].as_i64(), Some(2), "{launch}");
        assert!(
            launch["final_brief"]["overview"]
                .as_str()
                .is_some_and(|o| o.contains("delayed the Kioku launch")),
            "the final brief must join: {launch}"
        );

        let detail = rest_episode(
            State(Arc::clone(&archive.state)),
            Extension(user()),
            Path(940002),
            Query(EpisodeParams { include_low: None }),
        )
        .await;
        assert_eq!(detail.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(detail.into_body(), 512 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["title"], "Dashboard cache invalidation fix");

        // The neighbouring meaning the lift must preserve: absent id is 404,
        // not the routed read's 503.
        let missing = rest_episode(
            State(Arc::clone(&archive.state)),
            Extension(user()),
            Path(7),
            Query(EpisodeParams { include_low: None }),
        )
        .await;
        assert_eq!(
            missing.status(),
            StatusCode::NOT_FOUND,
            "an absent episode in a READABLE archive is an absence, not a deferral"
        );
    }

    /// **`query.episode_members` LIFTED.** The members route joins
    /// `episode_members` to `utterances` and `audio_segments`, so it answers
    /// only if all three sealed writes landed and the join holds.
    #[tokio::test]
    async fn the_lifted_episode_members_route_answers_a_selected_user_with_rows() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;
        use axum::extract::{Path, State};
        use axum::Extension;

        let archive = answerable_wal_archive("a0000000-0000-4000-8000-000000000004").await;
        let response = rest_episode_members(
            State(Arc::clone(&archive.state)),
            Extension(crate::cp::auth::AuthUser(archive.user_id.clone())),
            Path(940001),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["member_count"].as_i64(), Some(2), "{body}");
        let members = body["members"]
            .as_array()
            .unwrap_or_else(|| panic!("the route answers a members array: {body}"));
        assert!(
            members
                .iter()
                .any(|m| m["text"].as_str().is_some_and(|t| t.contains("August 19"))),
            "a member must carry its utterance TEXT, not just an id: {body}"
        );
        assert!(
            members
                .iter()
                .all(|m| m["started_at"].as_str().is_some_and(|t| !t.is_empty())),
            "every member's timestamp comes from the audio_segments join: {body}"
        );
    }

    /// **`query.feed` LIFTED.** The feed is the one lifted read that merges
    /// the audio and screen families in a single answer, so it asserts one
    /// record from each.
    #[tokio::test]
    async fn the_lifted_feed_route_answers_a_selected_user_with_rows() {
        use crate::cp::wal_gate_test_support::answerable_wal_archive;
        use axum::extract::{Query, State};
        use axum::Extension;

        let archive = answerable_wal_archive("a0000000-0000-4000-8000-000000000005").await;
        let response = rest_feed(
            State(Arc::clone(&archive.state)),
            Extension(crate::cp::auth::AuthUser(archive.user_id.clone())),
            Query(FeedParams {
                from: None,
                to: None,
                limit: None,
                before: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 512 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let records = body["records"]
            .as_array()
            .unwrap_or_else(|| panic!("the feed answers a records array: {body}"));
        assert_eq!(
            records.len(),
            7,
            "six utterances and one screenshot: {body}"
        );
        assert!(
            records.iter().any(|r| r["kind"] == "utterance"
                && r["text"]
                    .as_str()
                    .is_some_and(|t| t.contains("cache invalidation bug"))),
            "the audio family's rows must reach the feed: {body}"
        );
        let screen = records
            .iter()
            .find(|r| r["kind"] == "screenshot")
            .unwrap_or_else(|| panic!("the screen family's row must reach the feed: {body}"));
        assert_eq!(screen["active_app"], "Google Chrome", "{screen}");
        assert_eq!(
            screen["episode_id"].as_i64(),
            Some(940003),
            "the episode_members annotation must resolve: {screen}"
        );
    }
}
