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
use serde_json::Value;
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
    pub model: Option<String>,
    pub created_at: String,
}

// ── Upsert ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EpisodeInput {
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
    /// Model identifier used to produce this episode.
    pub model: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EpisodesUpsertRequest {
    pub user_id: String,
    pub episodes: Vec<EpisodeInput>,
}

#[derive(Debug, Serialize)]
pub struct EpisodesUpsertResponse {
    pub upserted: usize,
}

pub async fn handle_episodes_upsert(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EpisodesUpsertRequest>,
) -> Result<Json<EpisodesUpsertResponse>> {
    let user_id = req.user_id.clone();
    crate::store::validate_user_id(&user_id)?;
    info!(user_id = %user_id, count = req.episodes.len(), "episodes upsert request");

    let upserted = state
        .store
        .with_user(&user_id, |conn| upsert_episodes(conn, &req.episodes))
        .await?;

    state.store.save_user(&user_id).await?;
    Ok(Json(EpisodesUpsertResponse { upserted }))
}

fn upsert_episodes(conn: &rusqlite::Connection, items: &[EpisodeInput]) -> Result<usize> {
    let mut count = 0usize;
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

        // FTS5 content tables do not update correctly via the UPDATE trigger when
        // `ON CONFLICT … DO UPDATE` fires (the FTS shadow tables can diverge).
        // Instead we: (1) delete the existing row if present (DELETE trigger keeps
        // FTS clean), then (2) do a plain INSERT (INSERT trigger re-indexes it).
        conn.execute(
            "DELETE FROM episodes WHERE started_at = ?1",
            [&ep.started_at],
        )?;

        conn.execute(
            r#"INSERT INTO episodes
               (started_at, ended_at, type, title, summary, participants, languages,
                action_items, model)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
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
            ],
        )?;
        count += 1;
    }
    Ok(count)
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
        r#"SELECT id, started_at, ended_at, type, title, summary,
                  participants, languages, action_items, model, created_at
           FROM episodes
           WHERE (?1 IS NULL OR started_at >= ?1)
             AND (?2 IS NULL OR started_at < ?2)
           ORDER BY started_at DESC
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
            Ok(conn.changes() as usize)
        })
        .await?;

    state.store.save_user(&user_id).await?;
    Ok(Json(EpisodesDeleteRangeResponse { deleted }))
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
            started_at: started_at.to_string(),
            ended_at: ended_at.to_string(),
            episode_type: Some("work".to_string()),
            title: "Stand-up".to_string(),
            summary: Some("Daily stand-up".to_string()),
            participants: Some(vec!["alice".to_string(), "bob".to_string()]),
            languages: Some(vec!["en".to_string()]),
            action_items: Some(vec!["Ship it".to_string()]),
            model: Some("claude-3".to_string()),
        }
    }

    #[tokio::test]
    async fn upsert_same_started_at_does_not_duplicate() {
        let store = make_store();
        let ep1 = sample_episode("2026-01-01T09:00:00Z", "2026-01-01T09:30:00Z");
        let ep2 = EpisodeInput {
            title: "Stand-up updated".to_string(),
            ..sample_episode("2026-01-01T09:00:00Z", "2026-01-01T09:30:00Z")
        };

        // First upsert
        store
            .with_user("ep_user", |conn| upsert_episodes(conn, &[ep1]))
            .await
            .unwrap();

        // Second upsert with same started_at but different title
        store
            .with_user("ep_user", |conn| upsert_episodes(conn, &[ep2]))
            .await
            .unwrap();

        // Should be exactly 1 row, with the updated title
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

        assert_eq!(count, 1, "expected exactly 1 episode row");
        assert_eq!(title, "Stand-up updated", "title should reflect the update");
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
