use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

use crate::error::Result;
use crate::persistence::{
    CaptureStatus, EpisodeListPage, EpisodeListRequest, MemoryFeedPage, MemoryFeedRecord,
    MemoryFeedRequest, MemoryQueryRepository,
};
use crate::search::{search_all, SearchHit, SearchRequest};
use crate::store::Store;

pub(crate) struct LegacyMemoryQueryRepository {
    store: Arc<Store>,
}

impl LegacyMemoryQueryRepository {
    pub(crate) fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl MemoryQueryRepository for LegacyMemoryQueryRepository {
    async fn search(&self, account_id: &str, request: &SearchRequest) -> Result<Vec<SearchHit>> {
        let request = request.clone();
        self.store
            .wal_authoritative_read(account_id, move |connection| {
                search_all(connection, &request)
            })
            .await
    }

    async fn list_episodes(
        &self,
        account_id: &str,
        request: &EpisodeListRequest,
    ) -> Result<EpisodeListPage> {
        let request = request.clone();
        self.store
            .wal_authoritative_read(account_id, move |connection| {
                let fetch_limit = request.limit + i64::from(request.probe_for_more);
                let mut statement = connection.prepare(
                    "SELECT e.id,e.started_at,e.ended_at,e.title,e.summary,e.type, \
                            e.participants,e.languages,e.action_items, \
                            (SELECT count(*) FROM episode_members m WHERE m.episode_id=e.id AND m.record_type='utterance'), \
                            (SELECT count(*) FROM episode_members m WHERE m.episode_id=e.id AND m.record_type='screenshot'), \
                            e.minute_summaries,e.substance,e.visual_evidence,e.finalized_at, \
                            e.finalization_version,e.finalization_status,e.finalization_attempted_at, \
                            fb.overview,fb.decisions,fb.action_items,fb.important_links,fb.open_questions, \
                            CASE \
                              WHEN EXISTS (SELECT 1 FROM episode_members m \
                                JOIN utterances u ON u.id=m.record_id AND m.record_type='utterance' \
                                JOIN voice_embedding_jobs j ON j.speaker_observation_id=u.speaker_observation_id \
                                WHERE m.episode_id=e.id AND j.state IN ('pending','processing','retry_wait')) THEN 'pending' \
                              WHEN EXISTS (SELECT 1 FROM episode_members m \
                                JOIN utterances u ON u.id=m.record_id AND m.record_type='utterance' \
                                JOIN voice_embedding_jobs j ON j.speaker_observation_id=u.speaker_observation_id \
                                WHERE m.episode_id=e.id AND j.state='failed') THEN 'degraded' \
                              ELSE 'ready' END \
                       FROM episodes e LEFT JOIN episode_final_briefs fb ON fb.episode_id=e.id \
                      WHERE (?1 IS NULL OR e.ended_at>=?1) AND (?2 IS NULL OR e.started_at<=?2) \
                        AND (?3=1 OR e.substance!='none') AND (?5 IS NULL OR e.id=?5) \
                        AND (?6 IS NULL OR e.started_at<?6 OR (e.started_at=?6 AND e.id<?7)) \
                      ORDER BY e.started_at DESC,e.id DESC LIMIT ?4",
                )?;
                let mut episodes = statement
                    .query_map(
                        params![
                            request.from,
                            request.to,
                            request.include_low,
                            fetch_limit,
                            request.episode_id,
                            request.before_started_at,
                            request.before_id,
                        ],
                        |row| {
                            let utterance_count: i64 = row.get(9)?;
                            let screenshot_count: i64 = row.get(10)?;
                            let finalization_status: String = row.get(16)?;
                            let final_brief = row.get::<_, Option<String>>(18)?.map(|overview| {
                                json!({
                                    "overview": overview,
                                    "decisions": json_array(row.get::<_, Option<String>>(19).ok().flatten()),
                                    "action_items": json_array(row.get::<_, Option<String>>(20).ok().flatten()),
                                    "important_links": json_array(row.get::<_, Option<String>>(21).ok().flatten()),
                                    "open_questions": json_array(row.get::<_, Option<String>>(22).ok().flatten()),
                                })
                            });
                            Ok(json!({
                                "id": row.get::<_, i64>(0)?,
                                "started_at": row.get::<_, String>(1)?,
                                "ended_at": row.get::<_, String>(2)?,
                                "title": row.get::<_, Option<String>>(3)?,
                                "summary": row.get::<_, Option<String>>(4)?,
                                "type": row.get::<_, Option<String>>(5)?,
                                "participants": json_array(row.get::<_, Option<String>>(6)?),
                                "languages": json_array(row.get::<_, Option<String>>(7)?),
                                "action_items": json_array(row.get::<_, Option<String>>(8)?),
                                "minute_summaries": json_array(row.get::<_, Option<String>>(11)?),
                                "substance": row.get::<_, String>(12)?,
                                "visual_evidence": row.get::<_, String>(13)?,
                                "utterance_count": utterance_count,
                                "screenshot_count": screenshot_count,
                                "member_count": utterance_count + screenshot_count,
                                "source": "summarized",
                                "finalized_at": row.get::<_, Option<String>>(14)?,
                                "finalization_version": row.get::<_, Option<i64>>(15)?,
                                "finalization_status": finalization_status,
                                "finalization_attempted_at": row.get::<_, Option<String>>(17)?,
                                "finalization_retryable": matches!(finalization_status.as_str(), "retry_wait" | "budget_wait" | "failed_terminal"),
                                "final_brief": final_brief,
                                "speaker_processing_status": row.get::<_, String>(23)?,
                            }))
                        },
                    )?
                    .collect::<std::result::Result<Vec<_>, _>>()?;

                let has_more = request.probe_for_more
                    && episodes.len() > usize::try_from(request.limit).unwrap_or(usize::MAX);
                if request.probe_for_more {
                    episodes.truncate(usize::try_from(request.limit).unwrap_or(usize::MAX));
                }
                let hidden_count = if request.include_low {
                    0
                } else {
                    connection.query_row(
                        "SELECT count(*) FROM episodes WHERE (?1 IS NULL OR ended_at>=?1) \
                         AND (?2 IS NULL OR started_at<=?2) AND substance='none'",
                        params![request.from, request.to],
                        |row| row.get(0),
                    )?
                };
                add_episode_facets(connection, &mut episodes)?;
                Ok(EpisodeListPage {
                    episodes,
                    hidden_count,
                    has_more,
                })
            })
            .await
    }

    async fn capture_status(&self, account_id: &str) -> Result<CaptureStatus> {
        self.store
            .wal_authoritative_read(account_id, |connection| {
                let total_utterances =
                    connection.query_row("SELECT count(*) FROM utterances", [], |row| row.get(0))?;
                let total_screenshots =
                    connection.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?;
                let episode_count =
                    connection.query_row("SELECT count(*) FROM episodes", [], |row| row.get(0))?;
                let last_utterance_at = connection
                    .query_row(
                        "SELECT s.started_at FROM utterances u JOIN audio_segments s ON s.id=u.audio_segment_id ORDER BY s.started_at DESC LIMIT 1",
                        [],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .optional()?
                    .flatten();
                let last_screenshot_at = connection
                    .query_row(
                        "SELECT captured_at FROM screenshots ORDER BY captured_at DESC LIMIT 1",
                        [],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .optional()?
                    .flatten();
                Ok(CaptureStatus {
                    total_utterances,
                    total_screenshots,
                    episode_count,
                    last_utterance_at,
                    last_screenshot_at,
                })
            })
            .await
    }

    async fn feed(&self, account_id: &str, request: &MemoryFeedRequest) -> Result<MemoryFeedPage> {
        let request = request.clone();
        self.store
            .wal_authoritative_read(account_id, move |connection| {
                legacy_feed(connection, &request)
            })
            .await
    }
}

fn legacy_feed(
    connection: &rusqlite::Connection,
    request: &MemoryFeedRequest,
) -> Result<MemoryFeedPage> {
    let limit = request.limit.min(200);
    let mut records = Vec::new();
    let mut utterances = connection.prepare(
        "WITH rows AS ( \
           SELECT u.id,u.speaker_label,u.text,u.source_key, \
                  strftime('%Y-%m-%dT%H:%M:%fZ',s.started_at,'+'||u.start_offset_seconds||' seconds') AS at \
             FROM utterances u JOIN audio_segments s ON s.id=u.audio_segment_id) \
         SELECT id,speaker_label,text,source_key,at FROM rows WHERE at IS NOT NULL \
          AND (?1 IS NULL OR at>=?1) AND (?2 IS NULL OR at<=?2) AND (?3 IS NULL OR at<?3) \
         ORDER BY at DESC LIMIT ?4",
    )?;
    let rows = utterances.query_map(
        params![request.from, request.to, request.before, limit as i64],
        |row| {
            Ok(MemoryFeedRecord {
                kind: "utterance".into(),
                id: row.get(0)?,
                speaker_label: row.get(1)?,
                text: row.get(2)?,
                source_key: row.get(3)?,
                at: row.get(4)?,
                active_app: None,
                window_title: None,
                url: None,
                ocr_excerpt: None,
                observation_status: None,
                literal_description: None,
                screen_state: None,
                episode_id: None,
            })
        },
    )?;
    records.extend(rows.collect::<std::result::Result<Vec<_>, _>>()?);

    let mut screenshots = connection.prepare(
        "SELECT s.id,s.captured_at,s.active_app,s.window_title,s.url,s.ocr_text, \
                s.salient_ocr_text,s.source_key,o.status,o.literal_description,o.screen_state \
           FROM screenshots s LEFT JOIN screen_observations o ON o.screenshot_id=s.id \
          WHERE s.captured_at IS NOT NULL AND s.is_duplicate=0 \
            AND (?1 IS NULL OR s.captured_at>=?1) AND (?2 IS NULL OR s.captured_at<=?2) \
            AND (?3 IS NULL OR s.captured_at<?3) ORDER BY s.captured_at DESC LIMIT ?4",
    )?;
    let rows = screenshots.query_map(
        params![request.from, request.to, request.before, limit as i64],
        |row| {
            let raw: Option<String> = row.get(5)?;
            let salient: Option<String> = row.get(6)?;
            let excerpt =
                crate::ocr::select_salient_ocr(raw.as_deref(), salient.as_deref()).map(|value| {
                    if value.chars().count() > 300 {
                        value.chars().take(300).collect()
                    } else {
                        value
                    }
                });
            Ok(MemoryFeedRecord {
                kind: "screenshot".into(),
                id: row.get(0)?,
                at: row.get(1)?,
                active_app: row.get(2)?,
                window_title: row.get(3)?,
                url: row.get(4)?,
                ocr_excerpt: excerpt,
                source_key: row.get(7)?,
                observation_status: row.get(8)?,
                literal_description: row.get(9)?,
                screen_state: row.get(10)?,
                speaker_label: None,
                text: None,
                episode_id: None,
            })
        },
    )?;
    records.extend(rows.collect::<std::result::Result<Vec<_>, _>>()?);
    records.sort_by(|left, right| right.at.cmp(&left.at));
    records.truncate(limit);

    for record in &mut records {
        record.episode_id = connection
            .query_row(
                "SELECT episode_id FROM episode_members WHERE record_type=?1 AND record_id=?2 \
                 ORDER BY episode_id DESC LIMIT 1",
                params![record.kind, record.id],
                |row| row.get(0),
            )
            .optional()?;
    }
    let next_before = (records.len() == limit)
        .then(|| records.last().map(|record| record.at.clone()))
        .flatten();
    Ok(MemoryFeedPage {
        records,
        next_before,
    })
}

fn json_array(raw: Option<String>) -> Value {
    raw.and_then(|value| serde_json::from_str(&value).ok())
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]))
}

fn url_domain(value: &str) -> Option<String> {
    let host = reqwest::Url::parse(value).ok()?.host_str()?.to_lowercase();
    Some(host.strip_prefix("www.").unwrap_or(&host).to_owned())
}

fn add_episode_facets(connection: &rusqlite::Connection, episodes: &mut [Value]) -> Result<()> {
    let ids = episodes
        .iter()
        .map(|episode| episode.get("id").and_then(Value::as_i64))
        .collect::<Option<Vec<_>>>()
        .ok_or(rusqlite::Error::InvalidQuery)?;
    let mut app_counts: HashMap<i64, HashMap<String, i64>> = HashMap::new();
    let mut domain_counts: HashMap<i64, HashMap<String, i64>> = HashMap::new();
    if !ids.is_empty() {
        let placeholders = vec!["?"; ids.len()].join(",");
        let query = format!(
            "SELECT m.episode_id,s.active_app,s.url,count(*) FROM episode_members m \
             JOIN screenshots s ON s.id=m.record_id WHERE m.record_type='screenshot' \
             AND m.episode_id IN ({placeholders}) GROUP BY m.episode_id,s.active_app,s.url"
        );
        let mut statement = connection.prepare(&query)?;
        let rows = statement.query_map(rusqlite::params_from_iter(ids.iter()), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (episode_id, app, url, count) = row?;
            if let Some(app) = app.filter(|value| !value.is_empty()) {
                *app_counts
                    .entry(episode_id)
                    .or_default()
                    .entry(app)
                    .or_default() += count;
            }
            if let Some(domain) = url.as_deref().and_then(url_domain) {
                *domain_counts
                    .entry(episode_id)
                    .or_default()
                    .entry(domain)
                    .or_default() += count;
            }
        }
    }
    let top_three = |counts: Option<&HashMap<String, i64>>| {
        let mut values = counts
            .map(|counts| counts.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        values.sort_by(|left, right| right.1.cmp(left.1).then_with(|| left.0.cmp(right.0)));
        values
            .into_iter()
            .take(3)
            .map(|(value, _)| value.clone())
            .collect::<Vec<_>>()
    };
    for episode in episodes {
        let id = episode.get("id").and_then(Value::as_i64).unwrap_or(-1);
        episode["top_apps"] = json!(top_three(app_counts.get(&id)));
        episode["top_domains"] = json!(top_three(domain_counts.get(&id)));
    }
    Ok(())
}
