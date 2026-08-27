use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::{json, Value};
use sqlx::Row;

use crate::{
    cp::isotime,
    error::{EnclaveError, Result},
    persistence::{
        CaptureStatus, EpisodeListPage, EpisodeListRequest, McpContextRequest, McpTimeRangeRequest,
        McpTranscriptSearchRequest, MemoryFeedPage, MemoryFeedRecord, MemoryFeedRequest,
        MemoryQueryRepository,
    },
    search::{extract_speaker_filter, rrf_merge, SearchHit, SearchRequest},
};

use super::PostgresPersistence;

fn bound(value: &Option<String>) -> Result<Option<i64>> {
    value
        .as_deref()
        .map(|value| {
            isotime::parse_epoch_millis(value)
                .ok_or_else(|| EnclaveError::InvalidRequest("invalid search timestamp".into()))
        })
        .transpose()
}

fn limit(value: usize) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| EnclaveError::InvalidRequest("search limit is too large".into()))
}

fn vector_literal(values: &[f32]) -> Result<String> {
    if values.len() != 384 || values.iter().any(|value| !value.is_finite()) {
        return Err(EnclaveError::InvalidRequest(
            "query embedding must contain 384 finite values".into(),
        ));
    }
    let mut output = String::with_capacity(values.len() * 12 + 2);
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(&value.to_string());
    }
    output.push(']');
    Ok(output)
}

fn required_timestamp(row: &sqlx::postgres::PgRow, name: &str) -> Result<String> {
    Ok(isotime::format_epoch_millis(row.try_get::<i64, _>(name)?))
}

fn timestamp(hit: &SearchHit) -> &str {
    match hit {
        SearchHit::Utterance { started_at, .. } => started_at,
        SearchHit::Screenshot { captured_at, .. } => captured_at,
        SearchHit::Episode { started_at, .. } => started_at,
    }
}

fn episode_from_row(
    row: &sqlx::postgres::PgRow,
    snippet: Option<String>,
    score: Option<f64>,
) -> Result<SearchHit> {
    let minute_summaries = row
        .try_get::<String, _>("minute_summaries")
        .ok()
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
    Ok(SearchHit::Episode {
        id: row.try_get("id")?,
        started_at: required_timestamp(row, "started_at_ms")?,
        ended_at: required_timestamp(row, "ended_at_ms")?,
        title: row.try_get("title")?,
        summary: row.try_get("summary")?,
        minute_summaries,
        snippet,
        score,
    })
}

fn utterance_from_row(row: &sqlx::postgres::PgRow, score: Option<f64>) -> Result<SearchHit> {
    Ok(SearchHit::Utterance {
        id: row.try_get("id")?,
        text: row.try_get("text")?,
        speaker_label: row.try_get("speaker_label")?,
        started_at: required_timestamp(row, "started_at_ms")?,
        start_offset_seconds: row.try_get("start_offset_seconds")?,
        end_offset_seconds: row.try_get("end_offset_seconds")?,
        score,
    })
}

fn screenshot_from_row(row: &sqlx::postgres::PgRow, score: Option<f64>) -> Result<SearchHit> {
    Ok(SearchHit::Screenshot {
        id: row.try_get("id")?,
        captured_at: required_timestamp(row, "captured_at_ms")?,
        active_app: row.try_get("active_app")?,
        window_title: row.try_get("window_title")?,
        ocr_text: row.try_get("ocr_text")?,
        url: row.try_get("url")?,
        observation_status: row.try_get("observation_status")?,
        literal_description: row.try_get("literal_description")?,
        screen_state: row.try_get("screen_state")?,
        content_type: row.try_get("content_type")?,
        score,
    })
}

impl PostgresPersistence {
    async fn search_utterances(
        &self,
        account_id: &str,
        request: &SearchRequest,
    ) -> Result<Vec<SearchHit>> {
        let from = bound(&request.time_start)?;
        let to = bound(&request.time_end)?;
        let row_limit = limit(request.limit)?;
        let offset = limit(request.offset)?;

        if request.query.trim().is_empty() {
            let Some(speaker) = request.speaker.as_deref() else {
                return Ok(Vec::new());
            };
            let rows = sqlx::query(
                "SELECT u.id,u.text,u.speaker_label,u.start_offset_seconds,u.end_offset_seconds, \
                        floor(extract(epoch FROM s.started_at)*1000)::bigint AS started_at_ms \
                   FROM utterances u JOIN audio_segments s \
                     ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
                  WHERE u.account_id=$1 AND lower(u.speaker_label)=lower($2) \
                    AND ($3::bigint IS NULL OR s.started_at >= to_timestamp($3::double precision/1000.0)) \
                    AND ($4::bigint IS NULL OR s.started_at <= to_timestamp($4::double precision/1000.0)) \
                  ORDER BY s.started_at DESC LIMIT $5 OFFSET $6",
            )
            .bind(account_id)
            .bind(speaker)
            .bind(from)
            .bind(to)
            .bind(row_limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await?;
            return rows
                .iter()
                .map(|row| utterance_from_row(row, None))
                .collect();
        }

        let Some(embedding) = request.query_embedding.as_deref() else {
            let rows = sqlx::query(
                "WITH q AS (SELECT websearch_to_tsquery('simple',$2) AS value) \
                 SELECT u.id,u.text,u.speaker_label,u.start_offset_seconds,u.end_offset_seconds, \
                        floor(extract(epoch FROM s.started_at)*1000)::bigint AS started_at_ms \
                   FROM utterances u JOIN audio_segments s \
                     ON s.account_id=u.account_id AND s.id=u.audio_segment_id CROSS JOIN q \
                  WHERE u.account_id=$1 AND u.search_document @@ q.value \
                    AND ($3::bigint IS NULL OR s.started_at >= to_timestamp($3::double precision/1000.0)) \
                    AND ($4::bigint IS NULL OR s.started_at <= to_timestamp($4::double precision/1000.0)) \
                    AND ($5::text IS NULL OR lower(u.speaker_label)=lower($5)) \
                  ORDER BY s.started_at DESC LIMIT $6 OFFSET $7",
            )
            .bind(account_id)
            .bind(&request.query)
            .bind(from)
            .bind(to)
            .bind(request.speaker.as_deref())
            .bind(row_limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await?;
            return rows
                .iter()
                .map(|row| utterance_from_row(row, None))
                .collect();
        };

        let candidate_limit = i64::try_from((request.limit * 3).max(60))
            .map_err(|_| EnclaveError::InvalidRequest("search limit is too large".into()))?;
        let fts = sqlx::query_scalar::<_, i64>(
            "WITH q AS (SELECT websearch_to_tsquery('simple',$2) AS value) \
             SELECT id FROM utterances,q WHERE account_id=$1 AND search_document @@ q.value \
              ORDER BY ts_rank_cd(search_document,q.value) DESC,id LIMIT $3",
        )
        .bind(account_id)
        .bind(&request.query)
        .bind(candidate_limit)
        .fetch_all(self.pool())
        .await?;
        let vector = vector_literal(embedding)?;
        let nearest = sqlx::query(
            "SELECT id,(embedding <=> $2::vector)::double precision AS distance \
               FROM utterances WHERE account_id=$1 AND embedding IS NOT NULL \
              ORDER BY embedding <=> $2::vector,id LIMIT $3",
        )
        .bind(account_id)
        .bind(vector)
        .bind(candidate_limit)
        .fetch_all(self.pool())
        .await?
        .into_iter()
        .map(|row| Ok((row.try_get("id")?, row.try_get("distance")?)))
        .collect::<Result<Vec<(i64, f64)>>>()?;
        let ranked: Vec<(i64, f64)> = rrf_merge(&fts, &nearest)
            .into_iter()
            .skip(request.offset)
            .take(request.limit)
            .collect();
        if ranked.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<i64> = ranked.iter().map(|(id, _)| *id).collect();
        let scores: HashMap<i64, f64> = ranked.into_iter().collect();
        let rows = sqlx::query(
            "SELECT u.id,u.text,u.speaker_label,u.start_offset_seconds,u.end_offset_seconds, \
                    floor(extract(epoch FROM s.started_at)*1000)::bigint AS started_at_ms \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
              WHERE u.account_id=$1 AND u.id=ANY($2) \
                AND ($3::bigint IS NULL OR s.started_at >= to_timestamp($3::double precision/1000.0)) \
                AND ($4::bigint IS NULL OR s.started_at <= to_timestamp($4::double precision/1000.0)) \
                AND ($5::text IS NULL OR lower(u.speaker_label)=lower($5))",
        )
        .bind(account_id)
        .bind(ids)
        .bind(from)
        .bind(to)
        .bind(request.speaker.as_deref())
        .fetch_all(self.pool())
        .await?;
        let mut hits = rows
            .iter()
            .map(|row| {
                let id: i64 = row.try_get("id")?;
                utterance_from_row(row, scores.get(&id).copied())
            })
            .collect::<Result<Vec<_>>>()?;
        hits.sort_by(|left, right| {
            let score = |hit: &SearchHit| match hit {
                SearchHit::Utterance { score, .. } => score.unwrap_or_default(),
                _ => 0.0,
            };
            score(right).total_cmp(&score(left))
        });
        Ok(hits)
    }

    async fn search_screenshots(
        &self,
        account_id: &str,
        request: &SearchRequest,
    ) -> Result<Vec<SearchHit>> {
        if request.query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let from = bound(&request.time_start)?;
        let to = bound(&request.time_end)?;
        let row_limit = limit(request.limit)?;
        let offset = limit(request.offset)?;

        let Some(embedding) = request.query_embedding.as_deref() else {
            let rows = sqlx::query(
                "WITH q AS (SELECT websearch_to_tsquery('simple',$2) AS value) \
                 SELECT s.id,s.active_app,s.window_title,s.ocr_text,s.url, \
                        o.status AS observation_status,o.literal_description,o.screen_state,o.content_type, \
                        floor(extract(epoch FROM s.captured_at)*1000)::bigint AS captured_at_ms \
                   FROM screenshots s LEFT JOIN screen_observations o \
                     ON o.account_id=s.account_id AND o.screenshot_id=s.id CROSS JOIN q \
                  WHERE s.account_id=$1 AND NOT s.is_duplicate \
                    AND (s.search_document @@ q.value OR o.literal_description ILIKE '%'||$2||'%' \
                         OR o.visible_text_summary ILIKE '%'||$2||'%' OR s.url ILIKE '%'||$2||'%') \
                    AND ($3::bigint IS NULL OR s.captured_at >= to_timestamp($3::double precision/1000.0)) \
                    AND ($4::bigint IS NULL OR s.captured_at <= to_timestamp($4::double precision/1000.0)) \
                  ORDER BY s.captured_at DESC LIMIT $5 OFFSET $6",
            )
            .bind(account_id)
            .bind(&request.query)
            .bind(from)
            .bind(to)
            .bind(row_limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await?;
            return rows
                .iter()
                .map(|row| screenshot_from_row(row, None))
                .collect();
        };

        let candidate_limit = i64::try_from((request.limit * 3).max(60))
            .map_err(|_| EnclaveError::InvalidRequest("search limit is too large".into()))?;
        let fts = sqlx::query_scalar::<_, i64>(
            "WITH q AS (SELECT websearch_to_tsquery('simple',$2) AS value) \
             SELECT id FROM screenshots,q WHERE account_id=$1 AND search_document @@ q.value \
              ORDER BY ts_rank_cd(search_document,q.value) DESC,id LIMIT $3",
        )
        .bind(account_id)
        .bind(&request.query)
        .bind(candidate_limit)
        .fetch_all(self.pool())
        .await?;
        let vector = vector_literal(embedding)?;
        let nearest = sqlx::query(
            "SELECT id,(embedding <=> $2::vector)::double precision AS distance \
               FROM screenshots WHERE account_id=$1 AND embedding IS NOT NULL \
              ORDER BY embedding <=> $2::vector,id LIMIT $3",
        )
        .bind(account_id)
        .bind(vector)
        .bind(candidate_limit)
        .fetch_all(self.pool())
        .await?
        .into_iter()
        .map(|row| Ok((row.try_get("id")?, row.try_get("distance")?)))
        .collect::<Result<Vec<(i64, f64)>>>()?;
        let ranked: Vec<(i64, f64)> = rrf_merge(&fts, &nearest)
            .into_iter()
            .skip(request.offset)
            .take(request.limit)
            .collect();
        if ranked.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<i64> = ranked.iter().map(|(id, _)| *id).collect();
        let scores: HashMap<i64, f64> = ranked.into_iter().collect();
        let rows = sqlx::query(
            "SELECT s.id,s.active_app,s.window_title,s.ocr_text,s.url, \
                    o.status AS observation_status,o.literal_description,o.screen_state,o.content_type, \
                    floor(extract(epoch FROM s.captured_at)*1000)::bigint AS captured_at_ms \
               FROM screenshots s LEFT JOIN screen_observations o \
                 ON o.account_id=s.account_id AND o.screenshot_id=s.id \
              WHERE s.account_id=$1 AND s.id=ANY($2) AND NOT s.is_duplicate \
                AND ($3::bigint IS NULL OR s.captured_at >= to_timestamp($3::double precision/1000.0)) \
                AND ($4::bigint IS NULL OR s.captured_at <= to_timestamp($4::double precision/1000.0))",
        )
        .bind(account_id)
        .bind(ids)
        .bind(from)
        .bind(to)
        .fetch_all(self.pool())
        .await?;
        let mut hits = rows
            .iter()
            .map(|row| {
                let id: i64 = row.try_get("id")?;
                screenshot_from_row(row, scores.get(&id).copied())
            })
            .collect::<Result<Vec<_>>>()?;
        hits.sort_by(|left, right| {
            let score = |hit: &SearchHit| match hit {
                SearchHit::Screenshot { score, .. } => score.unwrap_or_default(),
                _ => 0.0,
            };
            score(right).total_cmp(&score(left))
        });
        Ok(hits)
    }

    async fn search_episodes(
        &self,
        account_id: &str,
        request: &SearchRequest,
    ) -> Result<Vec<SearchHit>> {
        let from = bound(&request.time_start)?;
        let to = bound(&request.time_end)?;
        let row_limit = limit(request.limit)?;
        let offset = limit(request.offset)?;

        if request.query.trim().is_empty() {
            let Some(speaker) = request.speaker.as_deref() else {
                return Ok(Vec::new());
            };
            let rows = sqlx::query(
                "SELECT e.id,e.title,e.summary,e.minute_summaries::text AS minute_summaries, \
                        floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
                        floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms \
                   FROM episodes e WHERE e.account_id=$1 AND e.substance!='none' \
                    AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(e.participants) AS p(value) \
                                 WHERE lower(p.value)=lower($2) OR lower(p.value) LIKE lower($2)||' (%)') \
                    AND ($3::bigint IS NULL OR e.started_at >= to_timestamp($3::double precision/1000.0)) \
                    AND ($4::bigint IS NULL OR e.started_at <= to_timestamp($4::double precision/1000.0)) \
                  ORDER BY e.started_at DESC LIMIT $5 OFFSET $6",
            )
            .bind(account_id)
            .bind(speaker)
            .bind(from)
            .bind(to)
            .bind(row_limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await?;
            return rows
                .iter()
                .map(|row| episode_from_row(row, None, None))
                .collect();
        }

        let Some(embedding) = request.query_embedding.as_deref() else {
            let rows = sqlx::query(
                "WITH q AS (SELECT websearch_to_tsquery('simple',$2) AS value) \
                 SELECT e.id,e.title,e.summary,e.minute_summaries::text AS minute_summaries, \
                        floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
                        floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms, \
                        ts_headline('simple',coalesce(e.title,'')||' '||coalesce(e.summary,'')||' '||coalesce(e.minutes_text,''),q.value, \
                                    'StartSel=[, StopSel=], MaxWords=12, MinWords=6, FragmentDelimiter= … ') AS snippet \
                   FROM episodes e CROSS JOIN q \
                  WHERE e.account_id=$1 AND e.substance!='none' AND e.search_document @@ q.value \
                    AND ($3::bigint IS NULL OR e.started_at >= to_timestamp($3::double precision/1000.0)) \
                    AND ($4::bigint IS NULL OR e.started_at <= to_timestamp($4::double precision/1000.0)) \
                    AND ($5::text IS NULL OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(e.participants) AS p(value) \
                         WHERE lower(p.value)=lower($5) OR lower(p.value) LIKE lower($5)||' (%)')) \
                  ORDER BY ts_rank_cd(e.search_document,q.value) DESC,e.id LIMIT $6 OFFSET $7",
            )
            .bind(account_id)
            .bind(&request.query)
            .bind(from)
            .bind(to)
            .bind(request.speaker.as_deref())
            .bind(row_limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await?;
            return rows
                .iter()
                .map(|row| episode_from_row(row, row.try_get("snippet")?, None))
                .collect();
        };

        let candidate_limit = i64::try_from((request.limit * 3).max(60))
            .map_err(|_| EnclaveError::InvalidRequest("search limit is too large".into()))?;
        let fts_rows = sqlx::query(
            "WITH q AS (SELECT websearch_to_tsquery('simple',$2) AS value) \
             SELECT id,ts_headline('simple',coalesce(title,'')||' '||coalesce(summary,'')||' '||coalesce(minutes_text,''),q.value, \
                                   'StartSel=[, StopSel=], MaxWords=12, MinWords=6, FragmentDelimiter= … ') AS snippet \
               FROM episodes,q WHERE account_id=$1 AND substance!='none' AND search_document @@ q.value \
              ORDER BY ts_rank_cd(search_document,q.value) DESC,id LIMIT $3",
        )
        .bind(account_id)
        .bind(&request.query)
        .bind(candidate_limit)
        .fetch_all(self.pool())
        .await?;
        let fts: Vec<i64> = fts_rows.iter().map(|row| row.get("id")).collect();
        let snippets: HashMap<i64, String> = fts_rows
            .iter()
            .map(|row| (row.get("id"), row.get("snippet")))
            .collect();
        let vector = vector_literal(embedding)?;
        let nearest = sqlx::query(
            "SELECT id,(embedding <=> $2::vector)::double precision AS distance \
               FROM episodes WHERE account_id=$1 AND substance!='none' AND embedding IS NOT NULL \
              ORDER BY embedding <=> $2::vector,id LIMIT $3",
        )
        .bind(account_id)
        .bind(vector)
        .bind(candidate_limit)
        .fetch_all(self.pool())
        .await?
        .into_iter()
        .map(|row| Ok((row.try_get("id")?, row.try_get("distance")?)))
        .collect::<Result<Vec<(i64, f64)>>>()?;
        let ranked: Vec<(i64, f64)> = rrf_merge(&fts, &nearest)
            .into_iter()
            .skip(request.offset)
            .take(request.limit)
            .collect();
        if ranked.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<i64> = ranked.iter().map(|(id, _)| *id).collect();
        let scores: HashMap<i64, f64> = ranked.into_iter().collect();
        let rows = sqlx::query(
            "SELECT e.id,e.title,e.summary,e.minute_summaries::text AS minute_summaries, \
                    floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms \
               FROM episodes e WHERE e.account_id=$1 AND e.id=ANY($2) AND e.substance!='none' \
                AND ($3::bigint IS NULL OR e.started_at >= to_timestamp($3::double precision/1000.0)) \
                AND ($4::bigint IS NULL OR e.started_at <= to_timestamp($4::double precision/1000.0)) \
                AND ($5::text IS NULL OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(e.participants) AS p(value) \
                     WHERE lower(p.value)=lower($5) OR lower(p.value) LIKE lower($5)||' (%)'))",
        )
        .bind(account_id)
        .bind(ids)
        .bind(from)
        .bind(to)
        .bind(request.speaker.as_deref())
        .fetch_all(self.pool())
        .await?;
        let mut hits = rows
            .iter()
            .map(|row| {
                let id: i64 = row.try_get("id")?;
                episode_from_row(row, snippets.get(&id).cloned(), scores.get(&id).copied())
            })
            .collect::<Result<Vec<_>>>()?;
        hits.sort_by(|left, right| {
            let score = |hit: &SearchHit| match hit {
                SearchHit::Episode { score, .. } => score.unwrap_or_default(),
                _ => 0.0,
            };
            score(right).total_cmp(&score(left))
        });
        Ok(hits)
    }
}

fn postgres_json_array(row: &sqlx::postgres::PgRow, name: &str) -> Result<Value> {
    let raw: String = row.try_get(name)?;
    let value: Value = serde_json::from_str(&raw)?;
    Ok(if value.is_array() { value } else { json!([]) })
}

fn postgres_url_domain(value: &str) -> Option<String> {
    let host = reqwest::Url::parse(value).ok()?.host_str()?.to_lowercase();
    Some(host.strip_prefix("www.").unwrap_or(&host).to_owned())
}

fn top_three(counts: Option<&HashMap<String, i64>>) -> Vec<String> {
    let mut values = counts
        .map(|counts| counts.iter().collect::<Vec<_>>())
        .unwrap_or_default();
    values.sort_by(|left, right| right.1.cmp(left.1).then_with(|| left.0.cmp(right.0)));
    values
        .into_iter()
        .take(3)
        .map(|(value, _)| value.clone())
        .collect()
}

#[async_trait]
impl MemoryQueryRepository for PostgresPersistence {
    async fn search(&self, account_id: &str, request: &SearchRequest) -> Result<Vec<SearchHit>> {
        let (query, inline_speaker) = extract_speaker_filter(&request.query);
        let mut request = request.clone();
        request.query = query;
        request.speaker = request.speaker.or(inline_speaker);
        let want_all = request.kinds.is_empty();
        let wants = |kind: &str| {
            want_all
                || request
                    .kinds
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(kind))
        };

        let mut hits = Vec::new();
        if wants("utterance") {
            hits.extend(self.search_utterances(account_id, &request).await?);
        }
        if wants("screenshot") && request.speaker.is_none() {
            hits.extend(self.search_screenshots(account_id, &request).await?);
        }
        if wants("episode") {
            hits.extend(self.search_episodes(account_id, &request).await?);
        }
        hits.sort_by(|left, right| timestamp(right).cmp(timestamp(left)));
        hits.truncate(request.limit);
        Ok(hits)
    }

    async fn list_episodes(
        &self,
        account_id: &str,
        request: &EpisodeListRequest,
    ) -> Result<EpisodeListPage> {
        if request.limit < 0 || request.limit > 50 {
            return Err(EnclaveError::InvalidRequest(
                "episode limit must be between 0 and 50".into(),
            ));
        }
        let from = bound(&request.from)?;
        let to = bound(&request.to)?;
        let before = bound(&request.before_started_at)?;
        if before.is_some() != request.before_id.is_some() {
            return Err(EnclaveError::InvalidRequest(
                "episode continuation is incomplete".into(),
            ));
        }
        let fetch_limit = request.limit + i64::from(request.probe_for_more);
        let rows = sqlx::query(
            "SELECT e.id,e.title,e.summary,e.type,e.participants::text AS participants, \
                    e.languages::text AS languages,e.action_items::text AS action_items, \
                    e.minute_summaries::text AS minute_summaries,e.substance,e.visual_evidence,e.finalization_version, \
                    e.finalization_status,e.speaker_processing_status, \
                    floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms, \
                    floor(extract(epoch FROM e.finalized_at)*1000)::bigint AS finalized_at_ms, \
                    floor(extract(epoch FROM e.finalization_attempted_at)*1000)::bigint AS finalization_attempted_at_ms, \
                    (SELECT count(*) FROM episode_members m WHERE m.account_id=e.account_id \
                       AND m.episode_id=e.id AND m.record_type='utterance') AS utterance_count, \
                    (SELECT count(*) FROM episode_members m WHERE m.account_id=e.account_id \
                       AND m.episode_id=e.id AND m.record_type='screenshot') AS screenshot_count, \
                    fb.overview,fb.decisions::text AS decisions, \
                    fb.action_items::text AS brief_action_items, \
                    fb.important_links::text AS important_links,fb.open_questions::text AS open_questions \
               FROM episodes e LEFT JOIN episode_final_briefs fb \
                 ON fb.account_id=e.account_id AND fb.episode_id=e.id \
              WHERE e.account_id=$1 \
                AND ($2::bigint IS NULL OR e.ended_at>=to_timestamp($2::double precision/1000.0)) \
                AND ($3::bigint IS NULL OR e.started_at<=to_timestamp($3::double precision/1000.0)) \
                AND ($4 OR e.substance!='none') AND ($5::bigint IS NULL OR e.id=$5) \
                AND ($6::bigint IS NULL OR e.started_at<to_timestamp($6::double precision/1000.0) \
                     OR (e.started_at=to_timestamp($6::double precision/1000.0) AND e.id<$7)) \
              ORDER BY e.started_at DESC,e.id DESC LIMIT $8",
        )
        .bind(account_id)
        .bind(from)
        .bind(to)
        .bind(request.include_low)
        .bind(request.episode_id)
        .bind(before)
        .bind(request.before_id)
        .bind(fetch_limit)
        .fetch_all(self.pool())
        .await?;

        let mut episodes = Vec::with_capacity(rows.len());
        for row in &rows {
            let utterance_count: i64 = row.try_get("utterance_count")?;
            let screenshot_count: i64 = row.try_get("screenshot_count")?;
            let finalization_status: String = row.try_get("finalization_status")?;
            let final_brief = row
                .try_get::<Option<String>, _>("overview")?
                .map(|overview| {
                    Ok::<_, EnclaveError>(json!({
                        "overview": overview,
                        "decisions": postgres_json_array(row, "decisions")?,
                        "action_items": postgres_json_array(row, "brief_action_items")?,
                        "important_links": postgres_json_array(row, "important_links")?,
                        "open_questions": postgres_json_array(row, "open_questions")?,
                    }))
                })
                .transpose()?;
            let timestamp = |name: &str| -> Result<Option<String>> {
                Ok(row
                    .try_get::<Option<i64>, _>(name)?
                    .map(isotime::format_epoch_millis))
            };
            episodes.push(json!({
                "id": row.try_get::<i64, _>("id")?,
                "started_at": required_timestamp(row, "started_at_ms")?,
                "ended_at": required_timestamp(row, "ended_at_ms")?,
                "title": row.try_get::<Option<String>, _>("title")?,
                "summary": row.try_get::<Option<String>, _>("summary")?,
                "type": row.try_get::<Option<String>, _>("type")?,
                "participants": postgres_json_array(row, "participants")?,
                "languages": postgres_json_array(row, "languages")?,
                "action_items": postgres_json_array(row, "action_items")?,
                "minute_summaries": postgres_json_array(row, "minute_summaries")?,
                "substance": row.try_get::<String, _>("substance")?,
                "visual_evidence": row.try_get::<String, _>("visual_evidence")?,
                "utterance_count": utterance_count,
                "screenshot_count": screenshot_count,
                "member_count": utterance_count + screenshot_count,
                "source": "summarized",
                "finalized_at": timestamp("finalized_at_ms")?,
                "finalization_version": row.try_get::<Option<i64>, _>("finalization_version")?,
                "finalization_status": finalization_status,
                "finalization_attempted_at": timestamp("finalization_attempted_at_ms")?,
                "finalization_retryable": matches!(finalization_status.as_str(), "retry_wait" | "budget_wait" | "failed_terminal"),
                "final_brief": final_brief,
                "speaker_processing_status": row.try_get::<String, _>("speaker_processing_status")?,
            }));
        }
        let has_more = request.probe_for_more
            && episodes.len() > usize::try_from(request.limit).unwrap_or(usize::MAX);
        if request.probe_for_more {
            episodes.truncate(usize::try_from(request.limit).unwrap_or(usize::MAX));
        }

        let ids = episodes
            .iter()
            .filter_map(|episode| episode.get("id").and_then(Value::as_i64))
            .collect::<Vec<_>>();
        let facet_rows = if ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query(
                "SELECT m.episode_id,s.active_app,s.url,count(*)::bigint AS count \
                   FROM episode_members m JOIN screenshots s \
                     ON s.account_id=m.account_id AND s.id=m.record_id \
                  WHERE m.account_id=$1 AND m.record_type='screenshot' AND m.episode_id=ANY($2) \
                  GROUP BY m.episode_id,s.active_app,s.url",
            )
            .bind(account_id)
            .bind(&ids)
            .fetch_all(self.pool())
            .await?
        };
        let mut app_counts: HashMap<i64, HashMap<String, i64>> = HashMap::new();
        let mut domain_counts: HashMap<i64, HashMap<String, i64>> = HashMap::new();
        for row in facet_rows {
            let episode_id: i64 = row.try_get("episode_id")?;
            let count: i64 = row.try_get("count")?;
            if let Some(app) = row
                .try_get::<Option<String>, _>("active_app")?
                .filter(|value| !value.is_empty())
            {
                *app_counts
                    .entry(episode_id)
                    .or_default()
                    .entry(app)
                    .or_default() += count;
            }
            if let Some(domain) = row
                .try_get::<Option<String>, _>("url")?
                .as_deref()
                .and_then(postgres_url_domain)
            {
                *domain_counts
                    .entry(episode_id)
                    .or_default()
                    .entry(domain)
                    .or_default() += count;
            }
        }
        for episode in &mut episodes {
            let id = episode.get("id").and_then(Value::as_i64).unwrap_or(-1);
            episode["top_apps"] = json!(top_three(app_counts.get(&id)));
            episode["top_domains"] = json!(top_three(domain_counts.get(&id)));
        }

        let hidden_count = if request.include_low {
            0
        } else {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM episodes WHERE account_id=$1 AND substance='none' \
                 AND ($2::bigint IS NULL OR ended_at>=to_timestamp($2::double precision/1000.0)) \
                 AND ($3::bigint IS NULL OR started_at<=to_timestamp($3::double precision/1000.0))",
            )
            .bind(account_id)
            .bind(from)
            .bind(to)
            .fetch_one(self.pool())
            .await?
        };
        Ok(EpisodeListPage {
            episodes,
            hidden_count,
            has_more,
        })
    }

    async fn capture_status(&self, account_id: &str) -> Result<CaptureStatus> {
        let row = sqlx::query(
            "SELECT (SELECT count(*) FROM utterances WHERE account_id=$1)::bigint AS utterances, \
                    (SELECT count(*) FROM screenshots WHERE account_id=$1)::bigint AS screenshots, \
                    (SELECT count(*) FROM episodes WHERE account_id=$1)::bigint AS episodes, \
                    (SELECT floor(extract(epoch FROM s.started_at)*1000)::bigint \
                       FROM utterances u JOIN audio_segments s \
                         ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
                      WHERE u.account_id=$1 ORDER BY s.started_at DESC LIMIT 1) AS last_utterance_ms, \
                    (SELECT floor(extract(epoch FROM captured_at)*1000)::bigint \
                       FROM screenshots WHERE account_id=$1 ORDER BY captured_at DESC LIMIT 1) AS last_screenshot_ms",
        )
        .bind(account_id)
        .fetch_one(self.pool())
        .await?;
        Ok(CaptureStatus {
            total_utterances: row.try_get("utterances")?,
            total_screenshots: row.try_get("screenshots")?,
            episode_count: row.try_get("episodes")?,
            last_utterance_at: row
                .try_get::<Option<i64>, _>("last_utterance_ms")?
                .map(isotime::format_epoch_millis),
            last_screenshot_at: row
                .try_get::<Option<i64>, _>("last_screenshot_ms")?
                .map(isotime::format_epoch_millis),
        })
    }

    async fn feed(&self, account_id: &str, request: &MemoryFeedRequest) -> Result<MemoryFeedPage> {
        let limit = request.limit.min(200);
        let row_limit = i64::try_from(limit)
            .map_err(|_| EnclaveError::InvalidRequest("feed limit is too large".into()))?;
        let from = bound(&request.from)?;
        let to = bound(&request.to)?;
        let before = bound(&request.before)?;
        let utterance_rows = sqlx::query(
            "SELECT u.id,u.speaker_label,u.text,u.source_key, \
                    floor(extract(epoch FROM (s.started_at + make_interval(secs => u.start_offset_seconds)))*1000)::bigint AS at_ms \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
              WHERE u.account_id=$1 \
                AND ($2::bigint IS NULL OR s.started_at + make_interval(secs => u.start_offset_seconds)>=to_timestamp($2::double precision/1000.0)) \
                AND ($3::bigint IS NULL OR s.started_at + make_interval(secs => u.start_offset_seconds)<=to_timestamp($3::double precision/1000.0)) \
                AND ($4::bigint IS NULL OR s.started_at + make_interval(secs => u.start_offset_seconds)<to_timestamp($4::double precision/1000.0)) \
              ORDER BY at_ms DESC LIMIT $5",
        )
        .bind(account_id)
        .bind(from)
        .bind(to)
        .bind(before)
        .bind(row_limit)
        .fetch_all(self.pool())
        .await?;
        let mut records = utterance_rows
            .iter()
            .map(|row| {
                Ok(MemoryFeedRecord {
                    kind: "utterance".into(),
                    id: row.try_get("id")?,
                    at: required_timestamp(row, "at_ms")?,
                    speaker_label: row.try_get("speaker_label")?,
                    text: row.try_get("text")?,
                    source_key: row.try_get("source_key")?,
                    active_app: None,
                    window_title: None,
                    url: None,
                    ocr_excerpt: None,
                    observation_status: None,
                    literal_description: None,
                    screen_state: None,
                    episode_id: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let screenshot_rows = sqlx::query(
            "SELECT s.id,s.active_app,s.window_title,s.url,s.ocr_text,s.salient_ocr_text, \
                    s.source_key,o.status AS observation_status,o.literal_description,o.screen_state, \
                    floor(extract(epoch FROM s.captured_at)*1000)::bigint AS at_ms \
               FROM screenshots s LEFT JOIN screen_observations o \
                 ON o.account_id=s.account_id AND o.screenshot_id=s.id \
              WHERE s.account_id=$1 AND NOT s.is_duplicate \
                AND ($2::bigint IS NULL OR s.captured_at>=to_timestamp($2::double precision/1000.0)) \
                AND ($3::bigint IS NULL OR s.captured_at<=to_timestamp($3::double precision/1000.0)) \
                AND ($4::bigint IS NULL OR s.captured_at<to_timestamp($4::double precision/1000.0)) \
              ORDER BY s.captured_at DESC LIMIT $5",
        )
        .bind(account_id)
        .bind(from)
        .bind(to)
        .bind(before)
        .bind(row_limit)
        .fetch_all(self.pool())
        .await?;
        for row in &screenshot_rows {
            let raw: Option<String> = row.try_get("ocr_text")?;
            let salient: Option<String> = row.try_get("salient_ocr_text")?;
            let excerpt =
                crate::ocr::select_salient_ocr(raw.as_deref(), salient.as_deref()).map(|value| {
                    if value.chars().count() > 300 {
                        value.chars().take(300).collect()
                    } else {
                        value
                    }
                });
            records.push(MemoryFeedRecord {
                kind: "screenshot".into(),
                id: row.try_get("id")?,
                at: required_timestamp(row, "at_ms")?,
                active_app: row.try_get("active_app")?,
                window_title: row.try_get("window_title")?,
                url: row.try_get("url")?,
                ocr_excerpt: excerpt,
                source_key: row.try_get("source_key")?,
                observation_status: row.try_get("observation_status")?,
                literal_description: row.try_get("literal_description")?,
                screen_state: row.try_get("screen_state")?,
                speaker_label: None,
                text: None,
                episode_id: None,
            });
        }
        records.sort_by(|left, right| right.at.cmp(&left.at));
        records.truncate(limit);

        let utterance_ids = records
            .iter()
            .filter(|record| record.kind == "utterance")
            .map(|record| record.id)
            .collect::<Vec<_>>();
        let screenshot_ids = records
            .iter()
            .filter(|record| record.kind == "screenshot")
            .map(|record| record.id)
            .collect::<Vec<_>>();
        let membership_rows = sqlx::query(
            "SELECT record_type,record_id,max(episode_id)::bigint AS episode_id \
               FROM episode_members WHERE account_id=$1 \
                AND ((record_type='utterance' AND record_id=ANY($2)) \
                  OR (record_type='screenshot' AND record_id=ANY($3))) \
              GROUP BY record_type,record_id",
        )
        .bind(account_id)
        .bind(&utterance_ids)
        .bind(&screenshot_ids)
        .fetch_all(self.pool())
        .await?;
        let memberships = membership_rows
            .iter()
            .map(|row| {
                Ok((
                    (
                        row.try_get::<String, _>("record_type")?,
                        row.try_get::<i64, _>("record_id")?,
                    ),
                    row.try_get::<i64, _>("episode_id")?,
                ))
            })
            .collect::<Result<HashMap<(String, i64), i64>>>()?;
        for record in &mut records {
            record.episode_id = memberships.get(&(record.kind.clone(), record.id)).copied();
        }
        let next_before = (records.len() == limit)
            .then(|| records.last().map(|record| record.at.clone()))
            .flatten();
        Ok(MemoryFeedPage {
            records,
            next_before,
        })
    }

    async fn mcp_search_transcripts(
        &self,
        account_id: &str,
        request: &McpTranscriptSearchRequest,
    ) -> Result<Value> {
        let effective_limit = request
            .limit
            .clamp(1, crate::cp::mcp_query::MAX_MINIMIZED_PAGE_SIZE);
        let from = bound(&request.from)?;
        let to = bound(&request.to)?;
        let rows = sqlx::query(
            "SELECT u.id,u.text,u.speaker_label, \
                    floor(extract(epoch FROM s.started_at)*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM s.ended_at)*1000)::bigint AS ended_at_ms \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
              WHERE u.account_id=$1 AND strpos(lower(u.text),lower($2))>0 \
                AND ($3::bigint IS NULL OR s.started_at>=to_timestamp($3::double precision/1000.0)) \
                AND ($4::bigint IS NULL OR s.started_at<=to_timestamp($4::double precision/1000.0)) \
              ORDER BY s.started_at DESC,u.id DESC LIMIT $5",
        )
        .bind(account_id)
        .bind(&request.query)
        .bind(from)
        .bind(to)
        .bind(limit(effective_limit)?)
        .fetch_all(self.pool())
        .await?;
        let raw = rows
            .iter()
            .map(|row| {
                Ok((
                    row.try_get::<i64, _>("id")?,
                    row.try_get::<String, _>("text")?,
                    row.try_get::<Option<String>, _>("speaker_label")?,
                    required_timestamp(row, "started_at_ms")?,
                    required_timestamp(row, "ended_at_ms")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let redacted = crate::cp::dlp::redact_utterance_window(
            &raw.iter()
                .map(|(id, text, _, _, _)| (*id, text.clone()))
                .collect::<Vec<_>>(),
        )
        .into_iter()
        .map(|(id, value)| (id, value.text))
        .collect::<HashMap<_, _>>();
        let results = raw
            .into_iter()
            .map(|(id, _, speaker, started_at, ended_at)| {
                json!({
                    "id": id,
                    "text": redacted.get(&id).cloned().unwrap_or_default(),
                    "speaker": speaker,
                    "started_at": started_at,
                    "ended_at": ended_at,
                })
            })
            .collect::<Vec<_>>();
        Ok(crate::cp::mcp_safety::sanitize_result(json!({
            "summary": format!("Found {} relevant safe transcript matches for query", results.len()),
            "count": results.len(),
            "results": results,
        })))
    }

    async fn mcp_context(&self, account_id: &str, request: &McpContextRequest) -> Result<Value> {
        let effective_limit = request
            .limit
            .unwrap_or(crate::cp::mcp_query::DEFAULT_MINIMIZED_PAGE_SIZE)
            .clamp(1, crate::cp::mcp_query::MAX_MINIMIZED_PAGE_SIZE);
        let center_ms = isotime::parse_epoch_millis(&request.at)
            .ok_or_else(|| EnclaveError::InvalidRequest("invalid MCP context timestamp".into()))?;
        let window_ms = i64::try_from(request.window_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .ok_or_else(|| {
                EnclaveError::InvalidRequest("MCP context window is too large".into())
            })?;
        let rows = sqlx::query(
            "SELECT u.id,u.text,u.speaker_label, \
                    floor(extract(epoch FROM s.started_at)*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM s.ended_at)*1000)::bigint AS ended_at_ms \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
              WHERE u.account_id=$1 \
                AND abs(floor(extract(epoch FROM s.started_at)*1000)::bigint-$2)<=$3 \
              ORDER BY abs(floor(extract(epoch FROM s.started_at)*1000)::bigint-$2),u.id \
              LIMIT $4",
        )
        .bind(account_id)
        .bind(center_ms)
        .bind(window_ms)
        .bind(limit(effective_limit)?)
        .fetch_all(self.pool())
        .await?;
        let raw = rows
            .iter()
            .map(|row| {
                Ok((
                    row.try_get::<i64, _>("id")?,
                    row.try_get::<String, _>("text")?,
                    row.try_get::<Option<String>, _>("speaker_label")?,
                    required_timestamp(row, "started_at_ms")?,
                    required_timestamp(row, "ended_at_ms")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let redacted = crate::cp::dlp::redact_utterance_window(
            &raw.iter()
                .map(|(id, text, _, _, _)| (*id, text.clone()))
                .collect::<Vec<_>>(),
        )
        .into_iter()
        .map(|(id, value)| (id, value.text))
        .collect::<HashMap<_, _>>();
        let utterances = raw
            .into_iter()
            .map(|(id, _, speaker, started_at, ended_at)| {
                json!({
                    "id": id,
                    "text": redacted.get(&id).cloned().unwrap_or_default(),
                    "speaker": speaker,
                    "started_at": started_at,
                    "ended_at": ended_at,
                })
            })
            .collect::<Vec<_>>();
        let center = isotime::format_epoch_millis(center_ms);
        Ok(crate::cp::mcp_safety::sanitize_result(json!({
            "summary_digest": format!("Context around {}: {} safe items retrieved.", center, utterances.len()),
            "window_seconds": request.window_seconds,
            "utterances": utterances,
            "page_token": None::<String>,
        })))
    }

    async fn mcp_time_range(
        &self,
        account_id: &str,
        request: &McpTimeRangeRequest,
    ) -> Result<Value> {
        let effective_limit = request
            .limit
            .unwrap_or(crate::cp::mcp_query::DEFAULT_MINIMIZED_PAGE_SIZE)
            .clamp(1, crate::cp::mcp_query::MAX_MINIMIZED_PAGE_SIZE);
        let from_ms = isotime::parse_epoch_millis(&request.from)
            .ok_or_else(|| EnclaveError::InvalidRequest("invalid MCP range start".into()))?;
        let to_ms = isotime::parse_epoch_millis(&request.to)
            .ok_or_else(|| EnclaveError::InvalidRequest("invalid MCP range end".into()))?;
        let rows = sqlx::query(
            "SELECT id,title,summary, \
                    floor(extract(epoch FROM started_at)*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM ended_at)*1000)::bigint AS ended_at_ms \
               FROM episodes WHERE account_id=$1 AND substance!='none' \
                AND started_at<=to_timestamp($3::double precision/1000.0) \
                AND ended_at>=to_timestamp($2::double precision/1000.0) \
              ORDER BY started_at,id LIMIT $4",
        )
        .bind(account_id)
        .bind(from_ms)
        .bind(to_ms)
        .bind(limit(effective_limit)?)
        .fetch_all(self.pool())
        .await?;
        let episodes = rows
            .iter()
            .map(|row| {
                let title = crate::cp::dlp::local_deterministic_redact(
                    row.try_get::<Option<String>, _>("title")?
                        .as_deref()
                        .unwrap_or_default(),
                );
                let summary = crate::cp::dlp::local_deterministic_redact(
                    row.try_get::<Option<String>, _>("summary")?
                        .as_deref()
                        .unwrap_or_default(),
                );
                Ok(json!({
                    "id": row.try_get::<i64, _>("id")?.to_string(),
                    "title": title.text,
                    "summary": summary.text,
                    "started_at": required_timestamp(row, "started_at_ms")?,
                    "ended_at": required_timestamp(row, "ended_at_ms")?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let from = isotime::format_epoch_millis(from_ms);
        let to = isotime::format_epoch_millis(to_ms);
        Ok(crate::cp::mcp_safety::sanitize_result(json!({
            "time_range": { "from": from, "to": to },
            "summary_digest": format!("Period from {} to {} contained {} safe episodes.", from, to, episodes.len()),
            "has_more": episodes.len() >= effective_limit,
            "episodes": episodes,
        })))
    }
}
