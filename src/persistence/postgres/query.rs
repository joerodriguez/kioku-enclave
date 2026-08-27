use std::collections::HashMap;

use async_trait::async_trait;
use sqlx::Row;

use crate::{
    cp::isotime,
    error::{EnclaveError, Result},
    persistence::MemoryQueryRepository,
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
}
