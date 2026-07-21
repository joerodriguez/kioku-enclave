//! Episode handlers — write/read summarised episodes.
//!
//! Episodes are the output of the LLM summariser that runs over each user's
//! utterance+screenshot timeline.  They are unique per `started_at` timestamp
//! (per-user SQLite blob); the summariser sends an upsert so re-runs simply
//! overwrite the previous result without creating duplicates.
//!
//! # Routes
//! - `POST /v1/episodes/upsert`       — write/replace episodes
//! - `POST /v1/episodes/list`         — newest-first listing with optional time range
//! - `POST /v1/episodes/delete_range` — delete episodes in `[from, to)` (summariser rewind)

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::info;

use crate::{error::Result, AppState};

// ── Shared row type ───────────────────────────────────────────────────────────

/// A fully-hydrated episode row returned by list / upsert.
#[derive(Debug, Serialize)]
pub struct EpisodeRow {
    pub id: i64,
    pub started_at: String,
    pub ended_at: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub episode_type: Option<String>,
    pub title: Option<String>,
    pub summary: Option<String>,
    /// Parsed back from JSON text stored in the DB.
    pub participants: Value,
    pub languages: Value,
    pub action_items: Value,
    /// Minute-timeline gists (ADR-0004): JSON array of {start, gist}, time
    /// ascending. Empty array for episodes summarized before the feature.
    pub minute_summaries: Value,
    /// ADR-0009 visibility tier: none (hidden), low, or normal.
    pub substance: String,
    pub model: Option<String>,
    pub created_at: String,
    /// Member counts (v2) — number of utterances / screenshots bound to this
    /// episode via episode_members. Lets the debugger and list_episodes show
    /// "N utterances, M screenshots" without a second round-trip.
    pub utterance_count: i64,
    pub screenshot_count: i64,
}

/// One minute-timeline bucket (ADR-0004): a one-line gist of what happened in
/// the minutes starting at `start`. Stored on the episode row as a JSON array
/// sorted by start time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinuteBucket {
    /// ISO-8601 UTC bucket start.
    pub start: String,
    pub gist: String,
}

/// MERGE minute buckets on episode extension (ADR-0004 §G.1).
///
/// The summarizer is incremental: on extension the LLM sees only the NEW
/// window, so its buckets cover only new minutes — a whole-column replace
/// would wipe the earlier timeline. Union `new` into `existing_json` keyed by
/// bucket start (minute precision); a bucket from a newer window replaces an
/// overlapping older one. Returns `None` when the union is empty, else the
/// merged JSON array plus the plain-text gist projection for episodes_fts.
fn merge_minute_summaries(
    existing_json: Option<&str>,
    new: &[MinuteBucket],
) -> Option<(String, String)> {
    use std::collections::BTreeMap;
    let mut by_start: BTreeMap<i64, MinuteBucket> = BTreeMap::new();
    let minute_key =
        |b: &MinuteBucket| crate::cp::isotime::parse_epoch_millis(&b.start).map(|ms| ms / 60_000);
    let existing: Vec<MinuteBucket> = existing_json
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    for bucket in existing.into_iter().chain(new.iter().cloned()) {
        // Buckets with an unparseable start are dropped (the responseSchema
        // constrains starts to strings; defensive against a malformed one).
        if bucket.gist.trim().is_empty() {
            continue;
        }
        if let Some(key) = minute_key(&bucket) {
            by_start.insert(key, bucket);
        }
    }
    if by_start.is_empty() {
        return None;
    }
    let merged: Vec<&MinuteBucket> = by_start.values().collect();
    let json = serde_json::to_string(&merged).unwrap_or_else(|_| "[]".into());
    let text = merged
        .iter()
        .map(|b| b.gist.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    Some((json, text))
}

/// Store an episode's in-enclave-computed embedding in `vec_episodes`.
/// vec0 does not honour ON CONFLICT, so upsert is spelled DELETE + INSERT
/// (same pattern as the ingest backfill path).
pub(crate) fn write_episode_embedding(
    conn: &rusqlite::Connection,
    episode_id: i64,
    embedding: &[f32],
) -> Result<()> {
    let bytes: Vec<u8> = embedding.iter().flat_map(|f| f.to_le_bytes()).collect();
    conn.execute(
        "DELETE FROM vec_episodes WHERE episode_id = ?1",
        [episode_id],
    )?;
    conn.execute(
        "INSERT INTO vec_episodes (episode_id, embedding) VALUES (?1, ?2)",
        rusqlite::params![episode_id, bytes.as_slice()],
    )?;
    Ok(())
}

// ── Upsert ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EpisodeInput {
    /// Stable episode id (v2). When present and the row exists, the episode is
    /// UPDATED in place (id preserved). When absent (or stale), a new row is
    /// INSERTed and its id returned in the response — the control plane reuses
    /// that id as `episode_ref` on the next run to extend rather than duplicate.
    #[serde(default)]
    pub id: Option<i64>,
    pub started_at: String,
    pub ended_at: String,
    #[serde(rename = "type")]
    pub episode_type: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    /// Array of participant display-names.
    pub participants: Option<Vec<String>>,
    /// Array of BCP-47 language codes.
    pub languages: Option<Vec<String>>,
    /// Array of action-item strings.
    pub action_items: Option<Vec<String>>,
    /// ADR-0009 visibility tier. Missing or invalid values default to `normal`
    /// so an uncertain model result never silently hides an episode.
    #[serde(default)]
    pub substance: Option<String>,
    /// ADR-0010 visual evidence eligibility. Defaults to `none`.
    #[serde(default)]
    pub visual_evidence: Option<String>,
    /// Minute-timeline gists for the window this upsert covers (ADR-0004).
    /// MERGED into the stored buckets on extension — never a whole-column
    /// replace (§G.1). Absent/empty leaves the stored buckets untouched.
    #[serde(default)]
    pub minute_summaries: Option<Vec<MinuteBucket>>,
    /// Model identifier used to produce this episode.
    pub model: Option<String>,
    /// Member utterance ids to bind to this episode (additive: INSERT OR IGNORE).
    #[serde(default)]
    pub member_utterance_ids: Vec<i64>,
    /// Member screenshot ids to bind to this episode (additive: INSERT OR IGNORE).
    #[serde(default)]
    pub member_screenshot_ids: Vec<i64>,
}

/// Return the canonical ADR-0009 substance value, if valid.
pub(crate) fn validate_substance(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" => Some("none"),
        "low" => Some("low"),
        "normal" => Some("normal"),
        _ => None,
    }
}

fn normalized_substance(value: Option<&str>) -> &'static str {
    value.and_then(validate_substance).unwrap_or("normal")
}

/// Episode extensions can only increase visibility. One substantive window
/// makes the whole accumulated episode substantive; later sparse windows must
/// not downgrade it.
pub(crate) fn merge_substance(existing: Option<&str>, incoming: Option<&str>) -> &'static str {
    let rank = |value: &str| match value {
        "none" => 0,
        "low" => 1,
        _ => 2,
    };
    let existing = normalized_substance(existing);
    let incoming = normalized_substance(incoming);
    if rank(incoming) > rank(existing) {
        incoming
    } else {
        existing
    }
}

pub(crate) fn validate_visual_evidence(value: &str) -> Option<&'static str> {
    match value {
        "none" => Some("none"),
        "useful" => Some("useful"),
        _ => None,
    }
}

fn normalized_visual_evidence(value: Option<&str>) -> &'static str {
    value.and_then(validate_visual_evidence).unwrap_or("none")
}

/// Episode visual_evidence can only upgrade.
pub(crate) fn merge_visual_evidence(
    existing: Option<&str>,
    incoming: Option<&str>,
) -> &'static str {
    let rank = |value: &str| match value {
        "none" => 0,
        _ => 1,
    };
    let existing = normalized_visual_evidence(existing);
    let incoming = normalized_visual_evidence(incoming);
    if rank(incoming) > rank(existing) {
        incoming
    } else {
        existing
    }
}

#[derive(Debug, Deserialize)]
pub struct EpisodesUpsertRequest {
    pub user_id: String,
    pub episodes: Vec<EpisodeInput>,
}

#[derive(Debug, Serialize)]
pub struct EpisodesUpsertResponse {
    pub upserted: usize,
    /// Resulting episode ids, in the same order as the request's `episodes`.
    /// New episodes carry their freshly-assigned id; updated ones echo theirs.
    pub ids: Vec<i64>,
}

pub async fn handle_episodes_upsert(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EpisodesUpsertRequest>,
) -> Result<Json<EpisodesUpsertResponse>> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, count = req.episodes.len(), "episodes upsert request");

    let ids = state
        .store
        .with_user(&user_id, |conn| upsert_episodes(conn, &req.episodes))
        .await?;

    state.store.save_user(&user_id).await?;
    Ok(Json(EpisodesUpsertResponse {
        upserted: ids.len(),
        ids,
    }))
}

/// Upsert episodes by id and (additively) bind their members.
///
/// Per episode:
///   - `id` present and the row exists → UPDATE in place (id preserved). The
///     AFTER UPDATE trigger keeps episodes_fts in sync.
///   - `id` absent (or stale/not-found) → INSERT; the new rowid is the id.
///   - then INSERT OR IGNORE each member (utterance/screenshot) — additive, so
///     extending an episode across runs accumulates members idempotently.
///
/// Returns the resulting id for each input episode, in order.
pub(crate) fn upsert_episodes(
    conn: &rusqlite::Connection,
    items: &[EpisodeInput],
) -> Result<Vec<i64>> {
    let mut ids = Vec::with_capacity(items.len());
    for ep in items {
        let participants_json = ep
            .participants
            .as_deref()
            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let languages_json = ep
            .languages
            .as_deref()
            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
        let action_items_json = ep
            .action_items
            .as_deref()
            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));

        // Decide UPDATE vs INSERT. We avoid INSERT … ON CONFLICT DO UPDATE for
        // the FTS-divergence reasons noted historically; a plain UPDATE fires the
        // AFTER UPDATE trigger which re-indexes episodes_fts correctly.
        let existing_id: Option<i64> = match ep.id {
            Some(id) => conn
                .query_row("SELECT id FROM episodes WHERE id = ?1", [id], |r| r.get(0))
                .ok(),
            None => None,
        };

        // §G.1: union this window's minute buckets into the stored ones —
        // the LLM never re-sees earlier minutes, so replacing the column
        // would wipe the earlier timeline on every extension.
        let (existing_minutes, existing_substance, existing_visual): (Option<String>, Option<String>, Option<String>) = existing_id
            .and_then(|id| {
                conn.query_row(
                    "SELECT minute_summaries, substance, visual_evidence FROM episodes WHERE id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .ok()
            })
            .unwrap_or((None, None, None));
        let merged = merge_minute_summaries(
            existing_minutes.as_deref(),
            ep.minute_summaries.as_deref().unwrap_or(&[]),
        );
        let (minutes_json, minutes_text) = match &merged {
            Some((j, t)) => (Some(j.as_str()), Some(t.as_str())),
            None => (None, None),
        };
        let substance = if existing_id.is_some() {
            merge_substance(existing_substance.as_deref(), ep.substance.as_deref())
        } else {
            normalized_substance(ep.substance.as_deref())
        };
        let visual_evidence = if existing_id.is_some() {
            merge_visual_evidence(existing_visual.as_deref(), ep.visual_evidence.as_deref())
        } else {
            normalized_visual_evidence(ep.visual_evidence.as_deref())
        };

        let episode_id = if let Some(id) = existing_id {
            conn.execute(
                r#"UPDATE episodes SET
                       started_at = ?2, ended_at = ?3, type = ?4, title = ?5,
                       summary = ?6, participants = ?7, languages = ?8,
                       action_items = ?9, model = ?10,
                       minute_summaries = ?11, minutes_text = ?12,
                       substance = ?13, visual_evidence = ?14,
                       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                   WHERE id = ?1"#,
                rusqlite::params![
                    id,
                    ep.started_at,
                    ep.ended_at,
                    ep.episode_type,
                    ep.title,
                    ep.summary,
                    participants_json,
                    languages_json,
                    action_items_json,
                    ep.model,
                    minutes_json,
                    minutes_text,
                    substance,
                    visual_evidence,
                ],
            )?;
            id
        } else {
            conn.execute(
                r#"INSERT INTO episodes
                   (started_at, ended_at, type, title, summary, participants,
                    languages, action_items, model, minute_summaries,
                    minutes_text, substance, visual_evidence, updated_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                           ?12, ?13, strftime('%Y-%m-%dT%H:%M:%fZ','now'))"#,
                rusqlite::params![
                    ep.started_at,
                    ep.ended_at,
                    ep.episode_type,
                    ep.title,
                    ep.summary,
                    participants_json,
                    languages_json,
                    action_items_json,
                    ep.model,
                    minutes_json,
                    minutes_text,
                    substance,
                    visual_evidence,
                ],
            )?;
            conn.last_insert_rowid()
        };

        // Bind members (additive). INSERT OR IGNORE makes re-runs idempotent and
        // tolerates a record already claimed by this episode.
        {
            let mut stmt = conn.prepare_cached(
                "INSERT OR IGNORE INTO episode_members (episode_id, record_type, record_id)
                 VALUES (?1, ?2, ?3)",
            )?;
            for uid in &ep.member_utterance_ids {
                stmt.execute(rusqlite::params![episode_id, "utterance", uid])?;
            }
            for sid in &ep.member_screenshot_ids {
                stmt.execute(rusqlite::params![episode_id, "screenshot", sid])?;
            }
        }

        ids.push(episode_id);
    }
    Ok(ids)
}

// ── List ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EpisodesListRequest {
    pub user_id: String,
    pub time_start: Option<String>,
    pub time_end: Option<String>,
    #[serde(default = "default_list_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_list_limit() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct EpisodesListResponse {
    pub episodes: Vec<EpisodeRow>,
}

pub async fn handle_episodes_list(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EpisodesListRequest>,
) -> Result<Json<EpisodesListResponse>> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, "episodes list request");

    let episodes = state
        .store
        .with_user(&user_id, |conn| list_episodes(conn, &req))
        .await?;

    Ok(Json(EpisodesListResponse { episodes }))
}

fn list_episodes(
    conn: &rusqlite::Connection,
    req: &EpisodesListRequest,
) -> Result<Vec<EpisodeRow>> {
    let mut stmt = conn.prepare(
        r#"SELECT e.id, e.started_at, e.ended_at, e.type, e.title, e.summary,
                  e.participants, e.languages, e.action_items, e.model, e.created_at,
                  (SELECT COUNT(*) FROM episode_members m
                     WHERE m.episode_id = e.id AND m.record_type = 'utterance')  AS utterance_count,
                  (SELECT COUNT(*) FROM episode_members m
                     WHERE m.episode_id = e.id AND m.record_type = 'screenshot') AS screenshot_count,
                  e.minute_summaries, e.substance
           FROM episodes e
           WHERE (?1 IS NULL OR e.started_at >= ?1)
             AND (?2 IS NULL OR e.started_at < ?2)
           ORDER BY e.started_at DESC
           LIMIT ?3 OFFSET ?4"#,
    )?;

    let rows = stmt.query_map(
        rusqlite::params![
            req.time_start,
            req.time_end,
            req.limit as i64,
            req.offset as i64,
        ],
        parse_episode_row,
    )?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

// ── Delete range ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EpisodesDeleteRangeRequest {
    pub user_id: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Serialize)]
pub struct EpisodesDeleteRangeResponse {
    pub deleted: usize,
}

pub async fn handle_episodes_delete_range(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EpisodesDeleteRangeRequest>,
) -> Result<Json<EpisodesDeleteRangeResponse>> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, from = %req.from, to = %req.to, "episodes delete_range request");

    let deleted = state
        .store
        .with_user(&user_id, |conn| {
            conn.execute(
                "DELETE FROM episodes WHERE started_at >= ?1 AND started_at < ?2",
                rusqlite::params![req.from, req.to],
            )?;
            let deleted = conn.changes() as usize;
            // vec0 has no FK/trigger support — sweep vectors orphaned by the
            // delete (stale entries would only waste KNN slots, but keep tidy).
            conn.execute(
                "DELETE FROM vec_episodes WHERE episode_id NOT IN (SELECT id FROM episodes)",
                [],
            )?;
            Ok(deleted)
        })
        .await?;

    state.store.save_user(&user_id).await?;
    Ok(Json(EpisodesDeleteRangeResponse { deleted }))
}

// ── Purge (episode + member raw data) ────────────────────────────────────────

/// Result of purging one episode: counts plus the `source_key`s of the
/// deleted records, so the Mac debugger can purge the matching LOCAL rows and
/// media files (a cloud-only delete would resurrect on a forced resync).
#[derive(Debug, Serialize, Default)]
pub struct EpisodePurge {
    pub deleted_utterances: usize,
    pub deleted_screenshots: usize,
    pub deleted_segments: usize,
    pub utterance_source_keys: Vec<String>,
    pub screenshot_source_keys: Vec<String>,
}

/// Delete an episode AND the raw records behind it (user-initiated purge;
/// PRODUCT-SPEC §4.4: delete must be complete). Removes:
/// - member utterances + screenshots (fixed 'delete'-command triggers keep
///   the external-content FTS indexes consistent), their vec0 vectors, and
///   any episode_members rows referencing them from OTHER episodes;
/// - audio_segments left with no utterances;
/// - the episode row (FTS trigger + episode_members cascade) and its
///   vec_episodes vector.
///
/// Records shared with other episodes are deleted too — the user asked for
/// the content to be gone, not merely unlinked. Returns `None` when the
/// episode does not exist.
pub(crate) fn purge_episode(
    conn: &rusqlite::Connection,
    episode_id: i64,
) -> Result<Option<EpisodePurge>> {
    let exists: bool = conn
        .query_row("SELECT 1 FROM episodes WHERE id = ?1", [episode_id], |_| {
            Ok(true)
        })
        .unwrap_or(false);
    if !exists {
        return Ok(None);
    }

    let collect = |sql: &str| -> Result<Vec<(i64, Option<String>)>> {
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map([episode_id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    };
    let utts = collect(
        "SELECT u.id, u.source_key FROM episode_members m \
         JOIN utterances u ON u.id = m.record_id \
         WHERE m.episode_id = ?1 AND m.record_type = 'utterance'",
    )?;
    let scrs = collect(
        "SELECT s.id, s.source_key FROM episode_members m \
         JOIN screenshots s ON s.id = m.record_id \
         WHERE m.episode_id = ?1 AND m.record_type = 'screenshot'",
    )?;

    let id_list = |rows: &[(i64, Option<String>)]| {
        rows.iter()
            .map(|(id, _)| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut purge = EpisodePurge {
        utterance_source_keys: utts.iter().filter_map(|(_, k)| k.clone()).collect(),
        screenshot_source_keys: scrs.iter().filter_map(|(_, k)| k.clone()).collect(),
        ..Default::default()
    };

    if !utts.is_empty() {
        let ids = id_list(&utts);
        // Segments touched by these utterances, checked for emptiness after.
        let seg_ids: Vec<i64> = {
            let mut stmt = conn.prepare(&format!(
                "SELECT DISTINCT audio_segment_id FROM utterances WHERE id IN ({ids})"
            ))?;
            let rows = stmt
                .query_map([], |r| r.get(0))?
                .collect::<std::result::Result<Vec<i64>, _>>()?;
            rows
        };
        conn.execute_batch(&format!(
            "DELETE FROM vec_utterances WHERE utterance_id IN ({ids});
             DELETE FROM episode_members WHERE record_type='utterance' AND record_id IN ({ids});
             DELETE FROM utterances WHERE id IN ({ids});"
        ))?;
        purge.deleted_utterances = utts.len();
        if !seg_ids.is_empty() {
            let segs = seg_ids
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            conn.execute(
                &format!(
                    "DELETE FROM audio_segments WHERE id IN ({segs}) \
                     AND NOT EXISTS (SELECT 1 FROM utterances u WHERE u.audio_segment_id = audio_segments.id)"
                ),
                [],
            )?;
            purge.deleted_segments = conn.changes() as usize;
        }
    }

    if !scrs.is_empty() {
        let ids = id_list(&scrs);
        conn.execute_batch(&format!(
            "DELETE FROM vec_screenshots WHERE screenshot_id IN ({ids});
             DELETE FROM episode_members WHERE record_type='screenshot' AND record_id IN ({ids});
             DELETE FROM screenshots WHERE id IN ({ids});"
        ))?;
        purge.deleted_screenshots = scrs.len();
    }

    conn.execute("DELETE FROM episodes WHERE id = ?1", [episode_id])?;
    conn.execute(
        "DELETE FROM vec_episodes WHERE episode_id = ?1",
        [episode_id],
    )?;

    Ok(Some(purge))
}

// ── Members (drill-in) ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EpisodesMembersRequest {
    pub user_id: String,
    pub episode_id: i64,
}

/// Return the records bound to one episode (debugger drill-in). Utterances are
/// joined to audio_segments for their absolute timestamp; both lists come back
/// time-ascending.
pub async fn handle_episodes_members(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EpisodesMembersRequest>,
) -> Result<Json<Value>> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, episode_id = req.episode_id, "episodes members request");

    let result = state
        .store
        .with_user(&user_id, |conn| fetch_members(conn, req.episode_id))
        .await?;

    Ok(Json(result))
}

fn fetch_members(conn: &rusqlite::Connection, episode_id: i64) -> Result<Value> {
    let mut ustmt = conn.prepare(
        r#"SELECT u.id, u.text, u.language, u.speaker_label, s.started_at, u.source_key
           FROM episode_members m
           JOIN utterances u     ON u.id = m.record_id
           JOIN audio_segments s ON s.id = u.audio_segment_id
           WHERE m.episode_id = ?1 AND m.record_type = 'utterance'
           ORDER BY s.started_at ASC, u.start_offset_seconds ASC"#,
    )?;
    let utterances: Vec<Value> = ustmt
        .query_map([episode_id], |row| {
            Ok(json!({
                "id":            row.get::<_, i64>(0)?,
                "text":          row.get::<_, String>(1)?,
                "language":      row.get::<_, Option<String>>(2)?,
                "speaker_label": row.get::<_, String>(3)?,
                "started_at":    row.get::<_, String>(4)?,
                "source_key":    row.get::<_, Option<String>>(5)?,
            }))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut sstmt = conn.prepare(
        r#"SELECT sc.id, sc.captured_at, sc.active_app, sc.window_title, sc.url, sc.ocr_text,
                  sc.source_key
           FROM episode_members m
           JOIN screenshots sc ON sc.id = m.record_id
           WHERE m.episode_id = ?1 AND m.record_type = 'screenshot'
           ORDER BY sc.captured_at ASC"#,
    )?;
    let screenshots: Vec<Value> = sstmt
        .query_map([episode_id], |row| {
            Ok(json!({
                "id":           row.get::<_, i64>(0)?,
                "captured_at":  row.get::<_, String>(1)?,
                "active_app":   row.get::<_, Option<String>>(2)?,
                "window_title": row.get::<_, Option<String>>(3)?,
                "url":          row.get::<_, Option<String>>(4)?,
                "ocr_text":     row.get::<_, Option<String>>(5)?,
                "source_key":   row.get::<_, Option<String>>(6)?,
            }))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(json!({ "utterances": utterances, "screenshots": screenshots }))
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

/// Parse a JSON-text column into a [`serde_json::Value`] array.
/// Returns `Value::Array([])` on NULL or parse failure so the response is
/// always a JSON array rather than null.
fn parse_json_array(raw: Option<String>) -> Value {
    raw.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Array(vec![]))
}

fn parse_episode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EpisodeRow> {
    Ok(EpisodeRow {
        id: row.get(0)?,
        started_at: row.get(1)?,
        ended_at: row.get(2)?,
        episode_type: row.get(3)?,
        title: row.get(4)?,
        summary: row.get(5)?,
        participants: parse_json_array(row.get(6)?),
        languages: parse_json_array(row.get(7)?),
        action_items: parse_json_array(row.get(8)?),
        model: row.get(9)?,
        created_at: row.get(10)?,
        utterance_count: row.get(11)?,
        screenshot_count: row.get(12)?,
        minute_summaries: parse_json_array(row.get(13)?),
        substance: row.get(14)?,
    })
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

    fn sample_episode(started_at: &str, ended_at: &str) -> EpisodeInput {
        EpisodeInput {
            id: None,
            started_at: started_at.to_string(),
            ended_at: ended_at.to_string(),
            episode_type: Some("work".to_string()),
            title: "Stand-up".to_string(),
            summary: Some("Daily stand-up".to_string()),
            participants: Some(vec!["alice".to_string(), "bob".to_string()]),
            languages: Some(vec!["en".to_string()]),
            action_items: Some(vec!["Ship it".to_string()]),
            substance: None,
            visual_evidence: None,
            minute_summaries: None,
            model: Some("claude-3".to_string()),
            member_utterance_ids: vec![],
            member_screenshot_ids: vec![],
        }
    }

    fn bucket(start: &str, gist: &str) -> MinuteBucket {
        MinuteBucket {
            start: start.to_string(),
            gist: gist.to_string(),
        }
    }

    #[test]
    fn substance_validation_and_merge_are_conservative() {
        assert_eq!(validate_substance("LOW"), Some("low"));
        assert_eq!(validate_substance("unknown"), None);
        assert_eq!(merge_substance(Some("none"), Some("low")), "low");
        assert_eq!(merge_substance(Some("low"), Some("normal")), "normal");
        assert_eq!(merge_substance(Some("normal"), Some("none")), "normal");
        assert_eq!(merge_substance(Some("low"), Some("none")), "low");
        assert_eq!(merge_substance(Some("none"), Some("invalid")), "normal");
    }

    #[tokio::test]
    async fn upsert_substance_only_upgrades() {
        let store = make_store();
        let initial = EpisodeInput {
            substance: Some("none".into()),
            ..sample_episode("2026-07-09T09:00:00Z", "2026-07-09T09:30:00Z")
        };
        let id = store
            .with_user("substance_user", |conn| upsert_episodes(conn, &[initial]))
            .await
            .unwrap()[0];

        for incoming in ["low", "none", "normal", "low"] {
            let extension = EpisodeInput {
                id: Some(id),
                substance: Some(incoming.into()),
                ..sample_episode("2026-07-09T09:00:00Z", "2026-07-09T10:00:00Z")
            };
            store
                .with_user("substance_user", |conn| upsert_episodes(conn, &[extension]))
                .await
                .unwrap();
        }

        let stored: String = store
            .with_user("substance_user", |conn| {
                Ok(
                    conn.query_row("SELECT substance FROM episodes WHERE id = ?1", [id], |r| {
                        r.get(0)
                    })?,
                )
            })
            .await
            .unwrap();
        assert_eq!(
            stored, "normal",
            "later low windows cannot downgrade normal"
        );
    }

    /// §G.1 — the merge case: an EXTENDED episode must retain the minute
    /// buckets from earlier windows the LLM no longer sees; a bucket from a
    /// newer window replaces an overlapping older one.
    #[tokio::test]
    async fn extension_merges_minute_summaries_never_replaces() {
        let store = make_store();

        // Window 1: episode is born with two minute buckets.
        let ep1 = EpisodeInput {
            minute_summaries: Some(vec![
                bucket("2026-07-05T20:56:00Z", "Talking about baby boys"),
                bucket("2026-07-05T20:57:00Z", "Kate & Sean arrival plans"),
            ]),
            ..sample_episode("2026-07-05T20:56:00Z", "2026-07-05T20:58:00Z")
        };
        let ids = store
            .with_user("merge_user", |conn| upsert_episodes(conn, &[ep1]))
            .await
            .unwrap();
        let id = ids[0];

        // Window 2: extension — the LLM only saw the NEW window, so it only
        // emits buckets for the new minutes (plus a refined overlap bucket).
        let ep2 = EpisodeInput {
            id: Some(id),
            minute_summaries: Some(vec![
                bucket("2026-07-05T20:57:30Z", "Kate & Sean plans firmed up"), // overlaps 20:57
                bucket("2026-07-05T20:58:00Z", "Pesto, lobster question"),
            ]),
            ..sample_episode("2026-07-05T20:56:00Z", "2026-07-05T21:01:00Z")
        };
        store
            .with_user("merge_user", |conn| upsert_episodes(conn, &[ep2]))
            .await
            .unwrap();

        let stored: String = store
            .with_user("merge_user", |conn| {
                Ok(conn.query_row(
                    "SELECT minute_summaries FROM episodes WHERE id = ?1",
                    [id],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        let buckets: Vec<MinuteBucket> = serde_json::from_str(&stored).unwrap();
        let gists: Vec<&str> = buckets.iter().map(|b| b.gist.as_str()).collect();
        assert_eq!(
            gists,
            vec![
                "Talking about baby boys",     // retained from window 1
                "Kate & Sean plans firmed up", // window-2 bucket replaced the overlapping 20:57 one
                "Pesto, lobster question",     // new minute appended
            ],
            "extension must union buckets by start, retaining earlier minutes"
        );

        // The plain-text FTS projection covers old AND new gists.
        let hits: i64 = store
            .with_user("merge_user", |conn| {
                Ok(conn.query_row(
                    "SELECT count(*) FROM episodes_fts WHERE episodes_fts MATCH 'baby AND lobster'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(hits, 1, "gists from both windows must be FTS-searchable");
    }

    /// An extension upsert that carries NO minute buckets (e.g. a metadata-only
    /// re-run) must leave the stored buckets untouched.
    #[tokio::test]
    async fn upsert_without_minutes_keeps_stored_buckets() {
        let store = make_store();
        let ep1 = EpisodeInput {
            minute_summaries: Some(vec![bucket("2026-07-05T09:00:00Z", "Stand-up recap")]),
            ..sample_episode("2026-07-05T09:00:00Z", "2026-07-05T09:30:00Z")
        };
        let ids = store
            .with_user("keep_user", |conn| upsert_episodes(conn, &[ep1]))
            .await
            .unwrap();
        let ep2 = EpisodeInput {
            id: Some(ids[0]),
            minute_summaries: None,
            ..sample_episode("2026-07-05T09:00:00Z", "2026-07-05T09:45:00Z")
        };
        store
            .with_user("keep_user", |conn| upsert_episodes(conn, &[ep2]))
            .await
            .unwrap();
        let stored: String = store
            .with_user("keep_user", |conn| {
                Ok(conn.query_row(
                    "SELECT minute_summaries FROM episodes WHERE id = ?1",
                    [ids[0]],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert!(
            stored.contains("Stand-up recap"),
            "minute buckets must survive a bucket-less upsert"
        );
    }

    #[tokio::test]
    async fn episode_embedding_upsert_replaces() {
        let store = make_store();
        let ids = store
            .with_user("vec_ep_user", |conn| {
                let ids = upsert_episodes(
                    conn,
                    &[sample_episode(
                        "2026-07-05T09:00:00Z",
                        "2026-07-05T09:30:00Z",
                    )],
                )?;
                write_episode_embedding(conn, ids[0], &[0.5f32; 384])?;
                // Second write for the same id must replace, not duplicate.
                write_episode_embedding(conn, ids[0], &[0.25f32; 384])?;
                Ok(ids)
            })
            .await
            .unwrap();
        let count: i64 = store
            .with_user("vec_ep_user", |conn| {
                Ok(conn.query_row(
                    "SELECT count(*) FROM vec_episodes WHERE episode_id = ?1",
                    [ids[0]],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(count, 1, "episode embedding upsert must replace in place");
    }

    #[tokio::test]
    async fn upsert_by_id_updates_in_place() {
        let store = make_store();
        let ep1 = sample_episode("2026-01-01T09:00:00Z", "2026-01-01T09:30:00Z");

        // First upsert (no id) → INSERT, returns the new id
        let ids = store
            .with_user("ep_user", |conn| upsert_episodes(conn, &[ep1]))
            .await
            .unwrap();
        assert_eq!(ids.len(), 1);
        let id = ids[0];

        // Second upsert WITH that id and a different title → UPDATE in place
        let ep2 = EpisodeInput {
            id: Some(id),
            title: "Stand-up updated".to_string(),
            ..sample_episode("2026-01-01T09:00:00Z", "2026-01-01T09:30:00Z")
        };
        let ids2 = store
            .with_user("ep_user", |conn| upsert_episodes(conn, &[ep2]))
            .await
            .unwrap();
        assert_eq!(ids2, vec![id], "same id echoed back on update");

        // Exactly 1 row, id preserved, title updated.
        let (count, title): (i64, String) = store
            .with_user("ep_user", |conn| {
                Ok(
                    conn.query_row("SELECT count(*), title FROM episodes", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })?,
                )
            })
            .await
            .unwrap();
        assert_eq!(count, 1, "id-keyed upsert must not duplicate");
        assert_eq!(title, "Stand-up updated");
    }

    #[tokio::test]
    async fn upsert_without_id_inserts_distinct_rows() {
        // v2: started_at is no longer unique — two no-id upserts at the same
        // start are two distinct episodes (e.g. nesting), keyed by id.
        let store = make_store();
        let a = sample_episode("2026-01-01T09:00:00Z", "2026-01-01T09:30:00Z");
        let b = sample_episode("2026-01-01T09:00:00Z", "2026-01-01T09:10:00Z");
        let ids = store
            .with_user("ep_distinct", |conn| upsert_episodes(conn, &[a, b]))
            .await
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1], "distinct ids");
    }

    #[tokio::test]
    async fn update_keeps_fts_in_sync() {
        // The id-keyed UPDATE path relies on the AFTER UPDATE trigger to keep the
        // external-content episodes_fts table correct. Verify a renamed episode
        // is found by its NEW title and not its old one.
        let store = make_store();
        let ids = store
            .with_user("fts_user", |conn| {
                upsert_episodes(
                    conn,
                    &[sample_episode(
                        "2026-03-01T09:00:00Z",
                        "2026-03-01T09:30:00Z",
                    )],
                )
            })
            .await
            .unwrap();
        let ep = EpisodeInput {
            id: Some(ids[0]),
            title: "Zebra synchronization meeting".to_string(),
            ..sample_episode("2026-03-01T09:00:00Z", "2026-03-01T09:30:00Z")
        };
        store
            .with_user("fts_user", |conn| upsert_episodes(conn, &[ep]))
            .await
            .unwrap();

        let (hits_new, hits_old): (i64, i64) = store
            .with_user("fts_user", |conn| {
                let n: i64 = conn.query_row(
                    "SELECT count(*) FROM episodes_fts WHERE episodes_fts MATCH 'Zebra'",
                    [],
                    |r| r.get(0),
                )?;
                let o: i64 = conn.query_row(
                    "SELECT count(*) FROM episodes_fts WHERE episodes_fts MATCH 'Standup'",
                    [],
                    |r| r.get(0),
                )?;
                Ok((n, o))
            })
            .await
            .unwrap();
        assert_eq!(hits_new, 1, "new title must be searchable after UPDATE");
        assert_eq!(hits_old, 0, "old title must be gone from FTS after UPDATE");
    }

    #[tokio::test]
    async fn members_bound_and_counted_and_listed() {
        let store = make_store();
        // Seed an audio segment + utterance and a screenshot so the FK targets exist.
        let (utt_id, scr_id) = store
            .with_user("mem_user", |conn| {
                conn.execute(
                    r#"INSERT INTO audio_segments (started_at, ended_at, duration_seconds, source_type)
                       VALUES ('2026-04-01T09:00:00Z', '2026-04-01T09:01:00Z', 60.0, 'mic')"#,
                    [],
                )?;
                let seg_id = conn.last_insert_rowid();
                conn.execute(
                    r#"INSERT INTO utterances (audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label)
                       VALUES (?1, 0.0, 5.0, 'hello world', 'Me')"#,
                    [seg_id],
                )?;
                let utt_id = conn.last_insert_rowid();
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES ('2026-04-01T09:00:30Z', 'screen')",
                    [],
                )?;
                let scr_id = conn.last_insert_rowid();
                Ok((utt_id, scr_id))
            })
            .await
            .unwrap();

        let ep = EpisodeInput {
            member_utterance_ids: vec![utt_id],
            member_screenshot_ids: vec![scr_id],
            ..sample_episode("2026-04-01T09:00:00Z", "2026-04-01T09:30:00Z")
        };
        let ids = store
            .with_user("mem_user", |conn| upsert_episodes(conn, &[ep]))
            .await
            .unwrap();
        let ep_id = ids[0];

        // List returns the member counts.
        let req = EpisodesListRequest {
            user_id: "mem_user".to_string(),
            time_start: None,
            time_end: None,
            limit: 10,
            offset: 0,
        };
        let rows = store
            .with_user("mem_user", |conn| list_episodes(conn, &req))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].utterance_count, 1);
        assert_eq!(rows[0].screenshot_count, 1);

        // Members drill-in returns the records.
        let members = store
            .with_user("mem_user", |conn| fetch_members(conn, ep_id))
            .await
            .unwrap();
        assert_eq!(members["utterances"].as_array().unwrap().len(), 1);
        assert_eq!(members["screenshots"].as_array().unwrap().len(), 1);
        assert_eq!(members["utterances"][0]["text"], "hello world");

        // Re-binding the same members is idempotent (INSERT OR IGNORE).
        let ep_again = EpisodeInput {
            id: Some(ep_id),
            member_utterance_ids: vec![utt_id],
            member_screenshot_ids: vec![scr_id],
            ..sample_episode("2026-04-01T09:00:00Z", "2026-04-01T09:30:00Z")
        };
        store
            .with_user("mem_user", |conn| upsert_episodes(conn, &[ep_again]))
            .await
            .unwrap();
        let count: i64 = store
            .with_user("mem_user", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM episode_members", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(count, 2, "re-binding same members must not duplicate");
    }

    /// Purge: the episode, its member rows, their FTS + vec entries, emptied
    /// segments, and cross-episode member references all go; unrelated
    /// records survive; the external-content FTS indexes stay consistent
    /// (integrity-check passes — this is what the trigger fix is for).
    #[tokio::test]
    async fn purge_episode_removes_members_and_keeps_fts_consistent() {
        let store = make_store();
        let (ep_id, other_ep, keep_utt) = store
            .with_user("purge_user", |conn| {
                conn.execute(
                    r#"INSERT INTO audio_segments (started_at, ended_at, duration_seconds, source_type)
                       VALUES ('2026-07-06T09:00:00Z', '2026-07-06T09:01:00Z', 60.0, 'mic')"#,
                    [],
                )?;
                let seg = conn.last_insert_rowid();
                conn.execute(
                    r#"INSERT INTO utterances (audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label, source_key)
                       VALUES (?1, 0.0, 5.0, 'secret lobster recipe', 'Me', 'dev:1:11')"#,
                    [seg],
                )?;
                let utt = conn.last_insert_rowid();
                conn.execute(
                    "INSERT INTO vec_utterances (utterance_id, embedding) VALUES (?1, ?2)",
                    rusqlite::params![utt, vec![0u8; 384 * 4]],
                )?;
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text, source_key) VALUES ('2026-07-06T09:00:30Z', 'zanzibar dashboard', 'dev:21')",
                    [],
                )?;
                let scr = conn.last_insert_rowid();
                // A second, UNRELATED segment+utterance that must survive.
                conn.execute(
                    r#"INSERT INTO audio_segments (started_at, ended_at, duration_seconds, source_type)
                       VALUES ('2026-07-06T10:00:00Z', '2026-07-06T10:01:00Z', 60.0, 'mic')"#,
                    [],
                )?;
                let seg2 = conn.last_insert_rowid();
                conn.execute(
                    r#"INSERT INTO utterances (audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label)
                       VALUES (?1, 0.0, 5.0, 'unrelated survivor', 'Me')"#,
                    [seg2],
                )?;
                let keep_utt = conn.last_insert_rowid();

                let ids = upsert_episodes(
                    conn,
                    &[EpisodeInput {
                        member_utterance_ids: vec![utt],
                        member_screenshot_ids: vec![scr],
                        ..sample_episode("2026-07-06T09:00:00Z", "2026-07-06T09:30:00Z")
                    }],
                )?;
                write_episode_embedding(conn, ids[0], &[0.5f32; 384])?;
                // A second episode also referencing the screenshot (shared record).
                let other = upsert_episodes(
                    conn,
                    &[EpisodeInput {
                        member_screenshot_ids: vec![scr],
                        ..sample_episode("2026-07-06T09:10:00Z", "2026-07-06T09:20:00Z")
                    }],
                )?;
                Ok((ids[0], other[0], keep_utt))
            })
            .await
            .unwrap();

        let purge = store
            .with_user("purge_user", |conn| purge_episode(conn, ep_id))
            .await
            .unwrap()
            .expect("episode exists");
        assert_eq!(purge.deleted_utterances, 1);
        assert_eq!(purge.deleted_screenshots, 1);
        assert_eq!(purge.deleted_segments, 1, "emptied segment removed");
        assert_eq!(purge.utterance_source_keys, vec!["dev:1:11"]);
        assert_eq!(purge.screenshot_source_keys, vec!["dev:21"]);

        store
            .with_user("purge_user", |conn| {
                let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
                assert_eq!(count("SELECT count(*) FROM episodes WHERE id = 1"), 0);
                assert_eq!(count("SELECT count(*) FROM utterances WHERE source_key='dev:1:11'"), 0);
                assert_eq!(count("SELECT count(*) FROM screenshots"), 0);
                assert_eq!(count("SELECT count(*) FROM vec_utterances"), 0);
                assert_eq!(count("SELECT count(*) FROM vec_episodes WHERE episode_id = 1"), 0);
                // Cross-episode reference to the shared screenshot is gone,
                // but the other episode itself survives.
                assert_eq!(
                    conn.query_row(
                        "SELECT count(*) FROM episode_members WHERE episode_id = ?1",
                        [other_ep],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap(),
                    0
                );
                assert_eq!(count("SELECT count(*) FROM episodes"), 1);
                // Unrelated records survive.
                assert_eq!(
                    conn.query_row(
                        "SELECT count(*) FROM utterances WHERE id = ?1",
                        [keep_utt],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap(),
                    1
                );
                // FTS indexes are CONSISTENT after the deletes (the whole
                // point of the 'delete'-command trigger fix): integrity-check
                // errors out on a corrupted external-content index.
                conn.execute_batch(
                    "INSERT INTO utterances_fts(utterances_fts) VALUES('integrity-check');
                     INSERT INTO screenshots_fts(screenshots_fts) VALUES('integrity-check');
                     INSERT INTO episodes_fts(episodes_fts) VALUES('integrity-check');",
                )?;
                // And the deleted text is gone from search while the survivor is found.
                assert_eq!(
                    count("SELECT count(*) FROM utterances_fts WHERE utterances_fts MATCH 'lobster'"),
                    0
                );
                assert_eq!(
                    count("SELECT count(*) FROM utterances_fts WHERE utterances_fts MATCH 'survivor'"),
                    1
                );
                assert_eq!(
                    count("SELECT count(*) FROM screenshots_fts WHERE screenshots_fts MATCH 'zanzibar'"),
                    0
                );
                Ok(())
            })
            .await
            .unwrap();

        // Purging a nonexistent episode is a clean None.
        let missing = store
            .with_user("purge_user", |conn| purge_episode(conn, 9999))
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn delete_episode_cascades_members() {
        let store = make_store();
        let ep_id = store
            .with_user("cascade_user", |conn| {
                conn.execute(
                    r#"INSERT INTO audio_segments (started_at, ended_at, duration_seconds, source_type)
                       VALUES ('2026-05-01T09:00:00Z', '2026-05-01T09:01:00Z', 60.0, 'mic')"#,
                    [],
                )?;
                let seg_id = conn.last_insert_rowid();
                conn.execute(
                    r#"INSERT INTO utterances (audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label)
                       VALUES (?1, 0.0, 5.0, 'x', 'Me')"#,
                    [seg_id],
                )?;
                let utt_id = conn.last_insert_rowid();
                let ids = upsert_episodes(
                    conn,
                    &[EpisodeInput {
                        member_utterance_ids: vec![utt_id],
                        ..sample_episode("2026-05-01T09:00:00Z", "2026-05-01T09:30:00Z")
                    }],
                )?;
                Ok(ids[0])
            })
            .await
            .unwrap();

        // delete_range over the episode's started_at should remove it AND cascade
        // its episode_members rows (FK ON DELETE CASCADE, foreign_keys=ON).
        store
            .with_user("cascade_user", |conn| {
                conn.execute(
                    "DELETE FROM episodes WHERE started_at >= ?1 AND started_at < ?2",
                    rusqlite::params!["2026-05-01T00:00:00Z", "2026-05-02T00:00:00Z"],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let (eps, mems): (i64, i64) = store
            .with_user("cascade_user", |conn| {
                Ok((
                    conn.query_row("SELECT count(*) FROM episodes", [], |r| r.get(0))?,
                    conn.query_row(
                        "SELECT count(*) FROM episode_members WHERE episode_id = ?1",
                        [ep_id],
                        |r| r.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(eps, 0);
        assert_eq!(mems, 0, "members must cascade-delete with their episode");
    }

    #[tokio::test]
    async fn list_ordering_and_limit() {
        let store = make_store();
        let eps = vec![
            sample_episode("2026-01-01T08:00:00Z", "2026-01-01T08:30:00Z"),
            sample_episode("2026-01-01T09:00:00Z", "2026-01-01T09:30:00Z"),
            sample_episode("2026-01-01T10:00:00Z", "2026-01-01T10:30:00Z"),
        ];
        store
            .with_user("list_user", |conn| upsert_episodes(conn, &eps))
            .await
            .unwrap();

        let req = EpisodesListRequest {
            user_id: "list_user".to_string(),
            time_start: None,
            time_end: None,
            limit: 2,
            offset: 0,
        };
        let rows = store
            .with_user("list_user", |conn| list_episodes(conn, &req))
            .await
            .unwrap();

        assert_eq!(rows.len(), 2);
        // Newest first
        assert!(rows[0].started_at > rows[1].started_at);
    }

    #[tokio::test]
    async fn delete_range_only_deletes_in_range() {
        let store = make_store();
        let eps = vec![
            sample_episode("2026-01-01T08:00:00Z", "2026-01-01T08:30:00Z"),
            sample_episode("2026-01-01T09:00:00Z", "2026-01-01T09:30:00Z"),
            sample_episode("2026-01-01T10:00:00Z", "2026-01-01T10:30:00Z"),
        ];
        store
            .with_user("del_user", |conn| upsert_episodes(conn, &eps))
            .await
            .unwrap();

        // Delete [08:00, 10:00) — should remove the first two
        let deleted = store
            .with_user("del_user", |conn| {
                conn.execute(
                    "DELETE FROM episodes WHERE started_at >= ?1 AND started_at < ?2",
                    rusqlite::params!["2026-01-01T08:00:00Z", "2026-01-01T10:00:00Z"],
                )?;
                Ok(conn.changes() as usize)
            })
            .await
            .unwrap();

        assert_eq!(deleted, 2);

        let remaining: i64 = store
            .with_user("del_user", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM episodes", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[tokio::test]
    async fn participants_roundtrip_as_json_array() {
        let store = make_store();
        let ep = sample_episode("2026-02-01T09:00:00Z", "2026-02-01T09:30:00Z");
        store
            .with_user("json_user", |conn| upsert_episodes(conn, &[ep]))
            .await
            .unwrap();

        let req = EpisodesListRequest {
            user_id: "json_user".to_string(),
            time_start: None,
            time_end: None,
            limit: 10,
            offset: 0,
        };
        let rows = store
            .with_user("json_user", |conn| list_episodes(conn, &req))
            .await
            .unwrap();

        assert_eq!(rows.len(), 1);
        let p = &rows[0].participants;
        assert!(p.is_array());
        let arr = p.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], "alice");
        assert_eq!(arr[1], "bob");
    }
}
