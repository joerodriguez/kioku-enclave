use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::{json, Value};
use sqlx::Row;

use crate::{
    cp::isotime,
    error::{EnclaveError, Result},
    persistence::{
        extract_speaker_filter, rrf_merge, CaptureStatus, EpisodeListPage, EpisodeListRequest,
        McpContextRequest, McpTimeRangeRequest, McpTranscriptSearchRequest, MemoryFeedPage,
        MemoryFeedRecord, MemoryFeedRequest, MemoryQueryRepository, PeopleListPage,
        PeopleListRequest, PersonEvidencePage, PersonEvidenceView, PersonFactView, PersonNameView,
        PersonProfile, PersonStatementPage, PersonStatementView, PersonSummary,
        ScreenshotMediaLocator, SearchHit, SearchRequest,
    },
};

use super::PostgresPersistence;

const EXPORT_TABLES: &[(&str, &str, &str)] = &[
    ("utterances", "utterances", "id"),
    ("screenshots", "screenshots", "id"),
    ("screenshot_images", "screenshot_images", "id"),
    ("episodes", "episodes", "id"),
    (
        "episode_members",
        "episode_members",
        "episode_id,record_type,record_id",
    ),
    ("episode_final_briefs", "episode_final_briefs", "episode_id"),
    ("memory_archive_state", "memory_archive_state", "account_id"),
    ("memory_handles", "memory_handles", "episode_id"),
    (
        "memory_reconciliations",
        "memory_reconciliations",
        "committed_at,id",
    ),
    (
        "memory_lineage_edges",
        "memory_lineage_edges",
        "predecessor_episode_id,ordinal",
    ),
    (
        "memory_reconciliation_sources",
        "memory_reconciliation_sources",
        "reconciliation_id,record_type,record_id",
    ),
    ("capture_sessions", "capture_sessions", "created_at,id"),
    ("capture_streams", "capture_streams", "created_at,id"),
    ("capture_events", "capture_events", "started_at,event_id"),
    (
        "browser_states_v2",
        "browser_states_v2",
        "created_at,state_key",
    ),
    (
        "browser_observations_v2",
        "browser_observations_v2",
        "observed_at,event_id",
    ),
    (
        "media_objects",
        "media_objects",
        "created_at,event_id,asset_id",
    ),
    (
        "speaker_observations",
        "speaker_observations",
        "started_at,event_id,id",
    ),
    ("people", "people", "display_name,id"),
    ("voice_profiles", "voice_profiles", "person_id,id"),
    (
        "voice_samples",
        "voice_samples",
        "speaker_observation_id,id",
    ),
    (
        "speaker_clusters",
        "speaker_clusters",
        "work_unit_id,speaker_local_id,id",
    ),
    (
        "episode_speaker_slots",
        "episode_speaker_slots",
        "episode_id,slot_ordinal,id",
    ),
    (
        "voice_profile_representatives",
        "voice_profile_representatives",
        "profile_id,channel_domain,id",
    ),
    (
        "voice_embedding_jobs",
        "voice_embedding_jobs",
        "speaker_observation_id,embedding_space,processor_version,id",
    ),
    (
        "episode_participants",
        "episode_participants",
        "episode_id,participant_key,id",
    ),
    (
        "visual_speaker_observations",
        "visual_speaker_observations",
        "observed_at,event_id,id",
    ),
    (
        "profile_identity_bindings",
        "profile_identity_bindings",
        "voice_profile_id,id",
    ),
    ("person_name_claims", "person_name_claims", "observed_at,id"),
    ("identity_evidence", "identity_evidence", "observed_at,id"),
    (
        "voice_profile_revisions",
        "voice_profile_revisions",
        "profile_id,id",
    ),
    (
        "voice_sample_profile_assignments",
        "voice_sample_profile_assignments",
        "sample_id,profile_id,id",
    ),
    (
        "speaker_observation_sources",
        "speaker_observation_sources",
        "speaker_observation_id,event_id,window_start_ms",
    ),
    ("person_facts", "person_facts", "person_id,id"),
];

async fn postgres_export(persistence: &PostgresPersistence, account_id: &str) -> Result<Value> {
    let mut export = serde_json::Map::new();
    let mut transaction = persistence.pool().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await?;
    for (response_field, table, order) in EXPORT_TABLES {
        // Identifiers come only from the reviewed static table above. Product
        // rows lose the shared-database tenant key and backend-only generated
        // search projection before they cross the public export boundary.
        let statement = format!(
            "SELECT (to_jsonb(export_row)-'account_id'-'search_document')::text AS row_json \
               FROM (SELECT * FROM {table} WHERE account_id=$1 ORDER BY {order}) export_row"
        );
        let rows = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(statement))
            .bind(account_id)
            .fetch_all(&mut *transaction)
            .await?;
        let values = rows
            .into_iter()
            .map(|row| serde_json::from_str(&row).map_err(Into::into))
            .collect::<Result<Vec<Value>>>()?;
        export.insert((*response_field).to_owned(), Value::Array(values));
    }
    transaction.commit().await?;
    Ok(Value::Object(export))
}

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

fn candidate_limit(request: &SearchRequest) -> Result<i64> {
    let value = request
        .offset
        .saturating_add(request.limit)
        .saturating_mul(3)
        .max(60);
    limit(value)
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

fn search_hit_id(hit: &SearchHit) -> i64 {
    match hit {
        SearchHit::Utterance { id, .. }
        | SearchHit::Screenshot { id, .. }
        | SearchHit::Episode { id, .. } => *id,
    }
}

fn order_hits(mut hits: Vec<SearchHit>, ids: &[i64]) -> Vec<SearchHit> {
    let positions = ids
        .iter()
        .enumerate()
        .map(|(position, id)| (*id, position))
        .collect::<HashMap<_, _>>();
    hits.sort_by_key(|hit| {
        positions
            .get(&search_hit_id(hit))
            .copied()
            .unwrap_or(usize::MAX)
    });
    hits
}

fn finalize_search_order(
    mut hits: Vec<SearchHit>,
    branch_count: usize,
    limit: usize,
) -> Vec<SearchHit> {
    if branch_count > 1 {
        hits.sort_by(|left, right| timestamp(right).cmp(timestamp(left)));
    }
    hits.truncate(limit);
    hits
}

fn json_array_from_text(raw: &str, name: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(raw)?;
    if !value.is_array() {
        return Err(EnclaveError::Store(format!(
            "PostgreSQL {name} projection is not a JSON array"
        )));
    }
    Ok(value)
}

fn optional_json_array(row: &sqlx::postgres::PgRow, name: &str) -> Result<Value> {
    let raw = row
        .try_get::<Option<String>, _>(name)?
        .ok_or_else(|| EnclaveError::Store(format!("PostgreSQL final brief is missing {name}")))?;
    json_array_from_text(&raw, name)
}

fn final_brief_from_row(row: &sqlx::postgres::PgRow) -> Result<Option<Value>> {
    row.try_get::<Option<String>, _>("brief_overview")?
        .map(|overview| {
            Ok(json!({
                "overview": overview,
                "decisions": optional_json_array(row, "brief_decisions")?,
                "action_items": optional_json_array(row, "brief_action_items")?,
                "important_links": optional_json_array(row, "brief_important_links")?,
                "open_questions": optional_json_array(row, "brief_open_questions")?,
            }))
        })
        .transpose()
}

fn episode_from_row(
    row: &sqlx::postgres::PgRow,
    snippet: Option<String>,
    match_source: Option<String>,
    score: Option<f64>,
) -> Result<SearchHit> {
    let raw_minute_summaries: String = row.try_get("minute_summaries")?;
    let minute_summaries = json_array_from_text(&raw_minute_summaries, "minute_summaries")?;
    let id = row.try_get("id")?;
    Ok(SearchHit::Episode {
        id,
        memory_id: id,
        started_at: required_timestamp(row, "started_at_ms")?,
        ended_at: required_timestamp(row, "ended_at_ms")?,
        title: row.try_get("title")?,
        summary: row.try_get("summary")?,
        minute_summaries,
        final_brief: final_brief_from_row(row)?,
        snippet,
        match_source,
        score,
    })
}

fn utterance_from_row(row: &sqlx::postgres::PgRow, score: Option<f64>) -> Result<SearchHit> {
    Ok(SearchHit::Utterance {
        id: row.try_get("id")?,
        text: row.try_get("text")?,
        speaker_label: row.try_get("speaker_label")?,
        person_id: row.try_get("person_id")?,
        attribution_kind: row.try_get("attribution_kind")?,
        started_at: required_timestamp(row, "started_at_ms")?,
        start_offset_seconds: row.try_get("start_offset_seconds")?,
        end_offset_seconds: row.try_get("end_offset_seconds")?,
        source_at: required_timestamp(row, "source_at_ms")?,
        memory_id: row.try_get("memory_id")?,
        episode_id: row.try_get("episode_id")?,
        episode_title: row.try_get("episode_title")?,
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
        source_at: required_timestamp(row, "source_at_ms")?,
        memory_id: row.try_get("memory_id")?,
        episode_id: row.try_get("episode_id")?,
        episode_title: row.try_get("episode_title")?,
        match_source: row.try_get("match_source")?,
        match_text: row.try_get("match_text")?,
        score,
    })
}

impl PostgresPersistence {
    async fn enrich_utterance_hits(
        &self,
        account_id: &str,
        ids: &[i64],
        scores: &HashMap<i64, f64>,
    ) -> Result<Vec<SearchHit>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"WITH latest_episode AS (
                   SELECT DISTINCT ON (m.account_id,m.record_id)
                          m.account_id,m.record_id,e.id AS episode_id,e.title
                     FROM episode_members m
                     JOIN episodes e
                       ON e.account_id=m.account_id AND e.id=m.episode_id
                    WHERE m.account_id=$1 AND m.record_type='utterance'
                      AND m.record_id=ANY($2) AND e.substance!='none'
                    ORDER BY m.account_id,m.record_id,e.started_at DESC,e.id DESC
               )
               SELECT u.id,u.text,
                      CASE WHEN c.attribution_state='owner_transmit' THEN 'Me'
                           ELSE coalesce(p.display_name,u.speaker_label) END AS speaker_label,
                      u.start_offset_seconds,u.end_offset_seconds,
                      floor(extract(epoch FROM coalesce(
                          o.started_at,
                          s.started_at + u.start_offset_seconds * interval '1 second'
                      ))*1000)::bigint AS started_at_ms,
                      floor(extract(epoch FROM coalesce(
                          o.started_at,
                          s.started_at + u.start_offset_seconds * interval '1 second'
                      ))*1000)::bigint AS source_at_ms,
                      CASE WHEN c.attribution_state='owner_transmit' THEN NULL
                           ELSE p.id END AS person_id,
                      CASE
                        WHEN c.attribution_state='owner_transmit' THEN 'owner_source_role'
                        WHEN p.id IS NOT NULL THEN 'direct_identity_evidence'
                        WHEN c.attribution_state='anonymous_profile' THEN 'verified_voice'
                        WHEN c.attribution_state IN ('request_local','unsegmented') THEN 'context_inferred'
                        ELSE NULL
                      END AS attribution_kind,
                      linked.episode_id AS memory_id,linked.episode_id,
                      linked.title AS episode_title
                 FROM utterances u
                 JOIN audio_segments s
                   ON s.account_id=u.account_id AND s.id=u.audio_segment_id
                 LEFT JOIN speaker_observations o
                   ON o.account_id=u.account_id AND o.id=u.speaker_observation_id
                 LEFT JOIN speaker_clusters c
                   ON c.account_id=o.account_id AND c.id=o.cluster_id
                 LEFT JOIN people p
                   ON p.account_id=u.account_id
                  AND p.id=coalesce(o.person_id,c.person_id)
                  AND p.status='identified'
                 LEFT JOIN latest_episode linked
                   ON linked.account_id=u.account_id AND linked.record_id=u.id
                WHERE u.account_id=$1 AND u.id=ANY($2)"#,
        )
        .bind(account_id)
        .bind(ids)
        .fetch_all(self.pool())
        .await?;
        let hits = rows
            .iter()
            .map(|row| {
                let id: i64 = row.try_get("id")?;
                utterance_from_row(row, scores.get(&id).copied())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(order_hits(hits, ids))
    }

    async fn utterance_fts_ids(
        &self,
        account_id: &str,
        request: &SearchRequest,
        row_limit: i64,
        offset: i64,
    ) -> Result<Vec<i64>> {
        let from = bound(&request.time_start)?;
        let to = bound(&request.time_end)?;
        Ok(sqlx::query_scalar::<_, i64>(
            r#"WITH q AS (
                   SELECT websearch_to_tsquery('simple',$2) AS exact,
                          to_tsquery('simple',coalesce((
                              SELECT string_agg(quote_literal(term)||':*',' | ' ORDER BY term)
                                FROM unnest(tsvector_to_array(to_tsvector('simple',$2))) AS terms(term)
                               WHERE char_length(term)>1 AND term NOT IN
                                     ('a','an','about','are','at','did','do','does','find','for',
                                      'from','how','in','is','me','my','of','on','show','that','the',
                                      'this','to','was','were','what','when','where','who','with')
                          ),'')) AS broad
               )
               SELECT u.id
                 FROM utterances u
                 JOIN audio_segments s
                   ON s.account_id=u.account_id AND s.id=u.audio_segment_id
                 LEFT JOIN speaker_observations o
                   ON o.account_id=u.account_id AND o.id=u.speaker_observation_id
                 LEFT JOIN speaker_clusters c
                   ON c.account_id=o.account_id AND c.id=o.cluster_id
                 LEFT JOIN people p
                   ON p.account_id=u.account_id
                  AND p.id=coalesce(o.person_id,c.person_id)
                  AND p.status='identified'
                 CROSS JOIN q
                WHERE u.account_id=$1 AND u.search_document @@ q.broad
                  AND ($3::bigint IS NULL OR
                       coalesce(o.started_at,
                           s.started_at + u.start_offset_seconds * interval '1 second')
                         >=to_timestamp($3::double precision/1000.0))
                  AND ($4::bigint IS NULL OR
                       coalesce(o.started_at,
                           s.started_at + u.start_offset_seconds * interval '1 second')
                         <=to_timestamp($4::double precision/1000.0))
                  AND ($5::text IS NULL OR lower(CASE
                       WHEN c.attribution_state='owner_transmit' THEN 'Me'
                       ELSE coalesce(p.display_name,u.speaker_label) END)=lower($5))
                ORDER BY (u.search_document @@ q.exact) DESC,
                         ts_rank_cd(u.search_document,q.exact) DESC,
                         ts_rank_cd(u.search_document,q.broad) DESC,
                         coalesce(o.started_at,
                             s.started_at + u.start_offset_seconds * interval '1 second') DESC,
                         u.id DESC
                LIMIT $6 OFFSET $7"#,
        )
        .bind(account_id)
        .bind(&request.query)
        .bind(from)
        .bind(to)
        .bind(request.speaker.as_deref())
        .bind(row_limit)
        .bind(offset)
        .fetch_all(self.pool())
        .await?)
    }

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
            let ids = sqlx::query_scalar::<_, i64>(
                r#"SELECT u.id
                     FROM utterances u
                     JOIN audio_segments s
                       ON s.account_id=u.account_id AND s.id=u.audio_segment_id
                     LEFT JOIN speaker_observations o
                       ON o.account_id=u.account_id AND o.id=u.speaker_observation_id
                     LEFT JOIN speaker_clusters c
                       ON c.account_id=o.account_id AND c.id=o.cluster_id
                     LEFT JOIN people p
                       ON p.account_id=u.account_id
                      AND p.id=coalesce(o.person_id,c.person_id)
                      AND p.status='identified'
                    WHERE u.account_id=$1 AND lower(CASE
                          WHEN c.attribution_state='owner_transmit' THEN 'Me'
                          ELSE coalesce(p.display_name,u.speaker_label) END)=lower($2)
                      AND ($3::bigint IS NULL OR
                           coalesce(o.started_at,
                               s.started_at + u.start_offset_seconds * interval '1 second')
                             >=to_timestamp($3::double precision/1000.0))
                      AND ($4::bigint IS NULL OR
                           coalesce(o.started_at,
                               s.started_at + u.start_offset_seconds * interval '1 second')
                             <=to_timestamp($4::double precision/1000.0))
                    ORDER BY coalesce(o.started_at,
                                 s.started_at + u.start_offset_seconds * interval '1 second') DESC,
                             u.id DESC
                    LIMIT $5 OFFSET $6"#,
            )
            .bind(account_id)
            .bind(speaker)
            .bind(from)
            .bind(to)
            .bind(row_limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await?;
            return self
                .enrich_utterance_hits(account_id, &ids, &HashMap::new())
                .await;
        }

        let Some(embedding) = request.query_embedding.as_deref() else {
            let ids = self
                .utterance_fts_ids(account_id, request, row_limit, offset)
                .await?;
            return self
                .enrich_utterance_hits(account_id, &ids, &HashMap::new())
                .await;
        };

        let candidate_limit = candidate_limit(request)?;
        let fts = self
            .utterance_fts_ids(account_id, request, candidate_limit, 0)
            .await?;
        let vector = vector_literal(embedding)?;
        let nearest = sqlx::query(
            r#"SELECT u.id,(u.embedding <=> $2::vector)::double precision AS distance
                 FROM utterances u
                 JOIN audio_segments s
                   ON s.account_id=u.account_id AND s.id=u.audio_segment_id
                 LEFT JOIN speaker_observations o
                   ON o.account_id=u.account_id AND o.id=u.speaker_observation_id
                 LEFT JOIN speaker_clusters c
                   ON c.account_id=o.account_id AND c.id=o.cluster_id
                 LEFT JOIN people p
                   ON p.account_id=u.account_id
                  AND p.id=coalesce(o.person_id,c.person_id)
                  AND p.status='identified'
                WHERE u.account_id=$1 AND u.embedding IS NOT NULL
                  AND ($3::bigint IS NULL OR
                       coalesce(o.started_at,
                           s.started_at + u.start_offset_seconds * interval '1 second')
                         >=to_timestamp($3::double precision/1000.0))
                  AND ($4::bigint IS NULL OR
                       coalesce(o.started_at,
                           s.started_at + u.start_offset_seconds * interval '1 second')
                         <=to_timestamp($4::double precision/1000.0))
                  AND ($5::text IS NULL OR lower(CASE
                       WHEN c.attribution_state='owner_transmit' THEN 'Me'
                       ELSE coalesce(p.display_name,u.speaker_label) END)=lower($5))
                ORDER BY u.embedding <=> $2::vector,u.id
                LIMIT $6"#,
        )
        .bind(account_id)
        .bind(vector)
        .bind(from)
        .bind(to)
        .bind(request.speaker.as_deref())
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
        self.enrich_utterance_hits(account_id, &ids, &scores).await
    }

    async fn screenshot_fts_ids(
        &self,
        account_id: &str,
        request: &SearchRequest,
        row_limit: i64,
        offset: i64,
    ) -> Result<Vec<i64>> {
        let from = bound(&request.time_start)?;
        let to = bound(&request.time_end)?;
        Ok(sqlx::query_scalar::<_, i64>(
            r#"WITH q AS (
                   SELECT websearch_to_tsquery('simple',$2) AS exact,
                          to_tsquery('simple',coalesce((
                              SELECT string_agg(quote_literal(term)||':*',' | ' ORDER BY term)
                                FROM unnest(tsvector_to_array(to_tsvector('simple',$2))) AS terms(term)
                               WHERE char_length(term)>1 AND term NOT IN
                                     ('a','an','about','are','at','did','do','does','find','for',
                                      'from','how','in','is','me','my','of','on','show','that','the',
                                      'this','to','was','were','what','when','where','who','with')
                          ),'')) AS broad
               ), latest_episode AS (
                   SELECT DISTINCT ON (m.account_id,m.record_id)
                          m.account_id,m.record_id,e.id AS episode_id,e.title
                     FROM episode_members m
                     JOIN episodes e
                       ON e.account_id=m.account_id AND e.id=m.episode_id
                    WHERE m.account_id=$1 AND m.record_type='screenshot'
                      AND e.substance!='none'
                    ORDER BY m.account_id,m.record_id,e.started_at DESC,e.id DESC
               ), searchable AS (
                   SELECT s.id,s.captured_at,s.ocr_text,s.salient_ocr_text,
                          s.active_app,s.window_title,s.url,
                          concat_ws(' ',o.literal_description,o.visible_text_summary,
                              o.screen_state,o.content_type,coalesce((
                                  SELECT string_agg(item.value #>> '{}',' ' ORDER BY item.ordinality)
                                    FROM jsonb_array_elements(CASE
                                             WHEN jsonb_typeof(o.notable_items)='array'
                                             THEN o.notable_items ELSE '[]'::jsonb END)
                                         WITH ORDINALITY AS item(value,ordinality)
                                   WHERE jsonb_typeof(item.value)='string'
                              ),'')) AS observation_text,
                          concat_ws(' ',i.activity_summary,i.relevance_reason,
                              i.semantic_group,i.milestone_type) AS interpretation_text
                     FROM screenshots s
                     LEFT JOIN screen_observations o
                       ON o.account_id=s.account_id AND o.screenshot_id=s.id
                     LEFT JOIN latest_episode linked
                       ON linked.account_id=s.account_id AND linked.record_id=s.id
                     LEFT JOIN episode_screen_interpretations i
                       ON i.account_id=s.account_id AND i.episode_id=linked.episode_id
                      AND i.screenshot_id=s.id
                    WHERE s.account_id=$1 AND NOT s.is_duplicate
                      AND ($3::bigint IS NULL OR
                           s.captured_at>=to_timestamp($3::double precision/1000.0))
                      AND ($4::bigint IS NULL OR
                           s.captured_at<=to_timestamp($4::double precision/1000.0))
               ), vectors AS (
                   SELECT searchable.*,
                          to_tsvector('simple',concat_ws(' ',ocr_text,salient_ocr_text,
                              active_app,window_title,url,observation_text,
                              interpretation_text)) AS search_vector
                     FROM searchable
               )
               SELECT v.id
                 FROM vectors v CROSS JOIN q
                WHERE v.search_vector @@ q.broad
                ORDER BY (v.search_vector @@ q.exact) DESC,
                         ts_rank_cd(v.search_vector,q.exact) DESC,
                         ts_rank_cd(v.search_vector,q.broad) DESC,
                         v.captured_at DESC,v.id DESC
                LIMIT $5 OFFSET $6"#,
        )
        .bind(account_id)
        .bind(&request.query)
        .bind(from)
        .bind(to)
        .bind(row_limit)
        .bind(offset)
        .fetch_all(self.pool())
        .await?)
    }

    async fn enrich_screenshot_hits(
        &self,
        account_id: &str,
        query: &str,
        ids: &[i64],
        scores: &HashMap<i64, f64>,
    ) -> Result<Vec<SearchHit>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"WITH q AS (
                   SELECT websearch_to_tsquery('simple',$2) AS exact,
                          to_tsquery('simple',coalesce((
                              SELECT string_agg(quote_literal(term)||':*',' | ' ORDER BY term)
                                FROM unnest(tsvector_to_array(to_tsvector('simple',$2))) AS terms(term)
                               WHERE char_length(term)>1 AND term NOT IN
                                     ('a','an','about','are','at','did','do','does','find','for',
                                      'from','how','in','is','me','my','of','on','show','that','the',
                                      'this','to','was','were','what','when','where','who','with')
                          ),'')) AS broad
               ), latest_episode AS (
                   SELECT DISTINCT ON (m.account_id,m.record_id)
                          m.account_id,m.record_id,e.id AS episode_id,e.title
                     FROM episode_members m
                     JOIN episodes e
                       ON e.account_id=m.account_id AND e.id=m.episode_id
                    WHERE m.account_id=$1 AND m.record_type='screenshot'
                      AND m.record_id=ANY($3) AND e.substance!='none'
                    ORDER BY m.account_id,m.record_id,e.started_at DESC,e.id DESC
               ), searchable AS (
                   SELECT s.id,s.captured_at,s.active_app,s.window_title,s.ocr_text,
                          s.salient_ocr_text,s.url,o.status AS observation_status,
                          o.literal_description,o.screen_state,o.content_type,
                          linked.episode_id AS memory_id,linked.episode_id,
                          linked.title AS episode_title,
                          concat_ws(' ',o.literal_description,o.visible_text_summary,
                              o.screen_state,o.content_type,coalesce((
                                  SELECT string_agg(item.value #>> '{}',' ' ORDER BY item.ordinality)
                                    FROM jsonb_array_elements(CASE
                                             WHEN jsonb_typeof(o.notable_items)='array'
                                             THEN o.notable_items ELSE '[]'::jsonb END)
                                         WITH ORDINALITY AS item(value,ordinality)
                                   WHERE jsonb_typeof(item.value)='string'
                              ),'')) AS observation_text,
                          concat_ws(' ',i.activity_summary,i.relevance_reason,
                              i.semantic_group,i.milestone_type) AS interpretation_text
                     FROM screenshots s
                     LEFT JOIN screen_observations o
                       ON o.account_id=s.account_id AND o.screenshot_id=s.id
                     LEFT JOIN latest_episode linked
                       ON linked.account_id=s.account_id AND linked.record_id=s.id
                     LEFT JOIN episode_screen_interpretations i
                       ON i.account_id=s.account_id AND i.episode_id=linked.episode_id
                      AND i.screenshot_id=s.id
                    WHERE s.account_id=$1 AND s.id=ANY($3) AND NOT s.is_duplicate
               ), vectors AS (
                   SELECT searchable.*,
                          to_tsvector('simple',coalesce(interpretation_text,'')) AS interpretation_vector,
                          to_tsvector('simple',coalesce(observation_text,'')) AS observation_vector,
                          to_tsvector('simple',coalesce(salient_ocr_text,'')) AS salient_ocr_vector,
                          to_tsvector('simple',coalesce(window_title,'')) AS window_vector,
                          to_tsvector('simple',coalesce(active_app,'')) AS app_vector,
                          to_tsvector('simple',coalesce(url,'')) AS url_vector,
                          to_tsvector('simple',coalesce(ocr_text,'')) AS ocr_vector
                     FROM searchable
               )
               SELECT v.id,v.active_app,v.window_title,v.ocr_text,v.url,
                      v.observation_status,v.literal_description,v.screen_state,v.content_type,
                      floor(extract(epoch FROM v.captured_at)*1000)::bigint AS captured_at_ms,
                      floor(extract(epoch FROM v.captured_at)*1000)::bigint AS source_at_ms,
                      v.memory_id,v.episode_id,v.episode_title,
                      coalesce(matched.source,'semantic') AS match_source,
                      left(regexp_replace(CASE
                          WHEN matched.value IS NOT NULL THEN
                              ts_headline('simple',matched.value,q.broad,
                                  'StartSel=[, StopSel=], MaxWords=24, MinWords=6, MaxFragments=1, FragmentDelimiter= … ')
                          ELSE coalesce(nullif(v.interpretation_text,''),
                                        nullif(v.observation_text,''),
                                        nullif(v.salient_ocr_text,''),
                                        nullif(v.window_title,''),
                                        nullif(v.active_app,''),nullif(v.url,''),
                                        nullif(v.ocr_text,''))
                      END,'[[:space:]]+',' ','g'),400) AS match_text
                 FROM vectors v CROSS JOIN q
                 LEFT JOIN LATERAL (
                     SELECT field.source,field.value
                       FROM (VALUES
                           ('episode_interpretation'::text,v.interpretation_text,70),
                           ('screen_observation'::text,v.observation_text,60),
                           ('salient_ocr'::text,v.salient_ocr_text,50),
                           ('window_title'::text,v.window_title,40),
                           ('active_app'::text,v.active_app,30),
                           ('url'::text,v.url,20),
                           ('ocr'::text,v.ocr_text,10)
                       ) AS field(source,value,quality)
                      WHERE nullif(btrim(field.value),'') IS NOT NULL
                        AND to_tsvector('simple',field.value) @@ q.broad
                      ORDER BY (to_tsvector('simple',field.value) @@ q.exact) DESC,
                               ts_rank_cd(to_tsvector('simple',field.value),q.exact) DESC,
                               ts_rank_cd(to_tsvector('simple',field.value),q.broad) DESC,
                               field.quality DESC,field.source
                      LIMIT 1
                 ) matched ON true
                WHERE v.id=ANY($3)"#,
        )
        .bind(account_id)
        .bind(query)
        .bind(ids)
        .fetch_all(self.pool())
        .await?;
        let hits = rows
            .iter()
            .map(|row| {
                let id: i64 = row.try_get("id")?;
                screenshot_from_row(row, scores.get(&id).copied())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(order_hits(hits, ids))
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
            let ids = self
                .screenshot_fts_ids(account_id, request, row_limit, offset)
                .await?;
            return self
                .enrich_screenshot_hits(account_id, &request.query, &ids, &HashMap::new())
                .await;
        };

        let candidate_limit = candidate_limit(request)?;
        let fts = self
            .screenshot_fts_ids(account_id, request, candidate_limit, 0)
            .await?;
        let vector = vector_literal(embedding)?;
        let nearest = sqlx::query(
            r#"SELECT s.id,(s.embedding <=> $2::vector)::double precision AS distance
                 FROM screenshots s
                WHERE s.account_id=$1 AND s.embedding IS NOT NULL AND NOT s.is_duplicate
                  AND ($3::bigint IS NULL OR
                       s.captured_at>=to_timestamp($3::double precision/1000.0))
                  AND ($4::bigint IS NULL OR
                       s.captured_at<=to_timestamp($4::double precision/1000.0))
                ORDER BY s.embedding <=> $2::vector,s.id
                LIMIT $5"#,
        )
        .bind(account_id)
        .bind(vector)
        .bind(from)
        .bind(to)
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
        let ids = ranked.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let scores = ranked.into_iter().collect::<HashMap<_, _>>();
        self.enrich_screenshot_hits(account_id, &request.query, &ids, &scores)
            .await
    }

    async fn episode_fts_ids(
        &self,
        account_id: &str,
        request: &SearchRequest,
        row_limit: i64,
        offset: i64,
    ) -> Result<Vec<i64>> {
        let from = bound(&request.time_start)?;
        let to = bound(&request.time_end)?;
        Ok(sqlx::query_scalar::<_, i64>(
            r#"WITH q AS (
                   SELECT websearch_to_tsquery('simple',$2) AS exact,
                          to_tsquery('simple',coalesce((
                              SELECT string_agg(quote_literal(term)||':*',' | ' ORDER BY term)
                                FROM unnest(tsvector_to_array(to_tsvector('simple',$2))) AS terms(term)
                               WHERE char_length(term)>1 AND term NOT IN
                                     ('a','an','about','are','at','did','do','does','find','for',
                                      'from','how','in','is','me','my','of','on','show','that','the',
                                      'this','to','was','were','what','when','where','who','with')
                          ),'')) AS broad
               ), searchable AS (
                   SELECT e.id,e.started_at,e.search_document AS memory_vector,
                          concat_ws(' ',e.title,e.summary,e.minutes_text) AS memory_text,
                          concat_ws(' ',fb.overview,coalesce((
                              SELECT string_agg(value #>> '{}',' ' ORDER BY ordinal)
                                FROM jsonb_path_query(
                                    fb.decisions||fb.action_items||fb.important_links||fb.open_questions,
                                    'strict $.** ? (@.type() == "string")')
                                     WITH ORDINALITY AS strings(value,ordinal)
                          ),'')) AS brief_text
                     FROM episodes e
                     LEFT JOIN episode_final_briefs fb
                       ON fb.account_id=e.account_id AND fb.episode_id=e.id
                    WHERE e.account_id=$1 AND e.substance!='none'
                      AND ($3::bigint IS NULL OR
                           e.started_at>=to_timestamp($3::double precision/1000.0))
                      AND ($4::bigint IS NULL OR
                           e.started_at<=to_timestamp($4::double precision/1000.0))
                      AND ($5::text IS NULL OR EXISTS (
                           SELECT 1 FROM jsonb_array_elements_text(e.participants) AS p(value)
                            WHERE lower(p.value)=lower($5)
                               OR lower(p.value) LIKE lower($5)||' (%)'))
               ), vectors AS (
                   SELECT searchable.*,
                          to_tsvector('simple',coalesce(brief_text,'')) AS brief_vector,
                          memory_vector || to_tsvector('simple',coalesce(brief_text,'')) AS search_vector
                     FROM searchable
               )
               SELECT v.id
                 FROM vectors v CROSS JOIN q
                WHERE v.search_vector @@ q.broad
                ORDER BY (v.search_vector @@ q.exact) DESC,
                         ts_rank_cd(v.search_vector,q.exact) DESC,
                         ts_rank_cd(v.search_vector,q.broad) DESC,
                         v.started_at DESC,v.id DESC
                LIMIT $6 OFFSET $7"#,
        )
        .bind(account_id)
        .bind(&request.query)
        .bind(from)
        .bind(to)
        .bind(request.speaker.as_deref())
        .bind(row_limit)
        .bind(offset)
        .fetch_all(self.pool())
        .await?)
    }

    async fn enrich_episode_hits(
        &self,
        account_id: &str,
        query: &str,
        ids: &[i64],
        scores: &HashMap<i64, f64>,
    ) -> Result<Vec<SearchHit>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            r#"WITH q AS (
                   SELECT websearch_to_tsquery('simple',$2) AS exact,
                          to_tsquery('simple',coalesce((
                              SELECT string_agg(quote_literal(term)||':*',' | ' ORDER BY term)
                                FROM unnest(tsvector_to_array(to_tsvector('simple',$2))) AS terms(term)
                               WHERE char_length(term)>1 AND term NOT IN
                                     ('a','an','about','are','at','did','do','does','find','for',
                                      'from','how','in','is','me','my','of','on','show','that','the',
                                      'this','to','was','were','what','when','where','who','with')
                          ),'')) AS broad
               ), searchable AS (
                   SELECT e.id,e.started_at,e.ended_at,e.title,e.summary,e.minute_summaries,
                          e.search_document AS memory_vector,
                          concat_ws(' ',e.title,e.summary,e.minutes_text) AS memory_text,
                          fb.overview AS brief_overview,
                          fb.decisions::text AS brief_decisions,
                          fb.action_items::text AS brief_action_items,
                          fb.important_links::text AS brief_important_links,
                          fb.open_questions::text AS brief_open_questions,
                          concat_ws(' ',fb.overview,coalesce((
                              SELECT string_agg(value #>> '{}',' ' ORDER BY ordinal)
                                FROM jsonb_path_query(
                                    fb.decisions||fb.action_items||fb.important_links||fb.open_questions,
                                    'strict $.** ? (@.type() == "string")')
                                     WITH ORDINALITY AS strings(value,ordinal)
                          ),'')) AS brief_text
                     FROM episodes e
                     LEFT JOIN episode_final_briefs fb
                       ON fb.account_id=e.account_id AND fb.episode_id=e.id
                    WHERE e.account_id=$1 AND e.id=ANY($3) AND e.substance!='none'
               ), vectors AS (
                   SELECT searchable.*,
                          to_tsvector('simple',coalesce(brief_text,'')) AS brief_vector
                     FROM searchable
               )
               SELECT v.id,v.title,v.summary,v.minute_summaries::text AS minute_summaries,
                      floor(extract(epoch FROM v.started_at)*1000)::bigint AS started_at_ms,
                      floor(extract(epoch FROM v.ended_at)*1000)::bigint AS ended_at_ms,
                      v.brief_overview,v.brief_decisions,v.brief_action_items,
                      v.brief_important_links,v.brief_open_questions,
                      CASE WHEN btrim($2)='' THEN 'memory'
                           ELSE coalesce(matched.source,'semantic') END AS match_source,
                      CASE WHEN matched.value IS NULL THEN NULL
                           ELSE left(ts_headline('simple',matched.value,q.broad,
                               'StartSel=[, StopSel=], MaxWords=24, MinWords=6, MaxFragments=1, FragmentDelimiter= … '),500)
                      END AS snippet
                 FROM vectors v CROSS JOIN q
                 LEFT JOIN LATERAL (
                     SELECT field.source,field.value
                       FROM (VALUES
                           ('brief'::text,v.brief_text,20),
                           ('memory'::text,v.memory_text,10)
                       ) AS field(source,value,quality)
                      WHERE nullif(btrim(field.value),'') IS NOT NULL
                        AND to_tsvector('simple',field.value) @@ q.broad
                      ORDER BY (to_tsvector('simple',field.value) @@ q.exact) DESC,
                               ts_rank_cd(to_tsvector('simple',field.value),q.exact) DESC,
                               ts_rank_cd(to_tsvector('simple',field.value),q.broad) DESC,
                               field.quality DESC,field.source
                      LIMIT 1
                 ) matched ON true
                WHERE v.id=ANY($3)"#,
        )
        .bind(account_id)
        .bind(query)
        .bind(ids)
        .fetch_all(self.pool())
        .await?;
        let hits = rows
            .iter()
            .map(|row| {
                let id: i64 = row.try_get("id")?;
                episode_from_row(
                    row,
                    row.try_get("snippet")?,
                    row.try_get("match_source")?,
                    scores.get(&id).copied(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(order_hits(hits, ids))
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
            let ids = sqlx::query_scalar::<_, i64>(
                r#"SELECT e.id
                     FROM episodes e
                    WHERE e.account_id=$1 AND e.substance!='none'
                      AND EXISTS (
                          SELECT 1 FROM jsonb_array_elements_text(e.participants) AS p(value)
                           WHERE lower(p.value)=lower($2)
                              OR lower(p.value) LIKE lower($2)||' (%)')
                      AND ($3::bigint IS NULL OR
                           e.started_at>=to_timestamp($3::double precision/1000.0))
                      AND ($4::bigint IS NULL OR
                           e.started_at<=to_timestamp($4::double precision/1000.0))
                    ORDER BY e.started_at DESC,e.id DESC
                    LIMIT $5 OFFSET $6"#,
            )
            .bind(account_id)
            .bind(speaker)
            .bind(from)
            .bind(to)
            .bind(row_limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await?;
            return self
                .enrich_episode_hits(account_id, "", &ids, &HashMap::new())
                .await;
        }

        let Some(embedding) = request.query_embedding.as_deref() else {
            let ids = self
                .episode_fts_ids(account_id, request, row_limit, offset)
                .await?;
            return self
                .enrich_episode_hits(account_id, &request.query, &ids, &HashMap::new())
                .await;
        };

        let candidate_limit = candidate_limit(request)?;
        let fts = self
            .episode_fts_ids(account_id, request, candidate_limit, 0)
            .await?;
        let vector = vector_literal(embedding)?;
        let nearest = sqlx::query(
            r#"SELECT e.id,(e.embedding <=> $2::vector)::double precision AS distance
                 FROM episodes e
                WHERE e.account_id=$1 AND e.substance!='none' AND e.embedding IS NOT NULL
                  AND ($3::bigint IS NULL OR
                       e.started_at>=to_timestamp($3::double precision/1000.0))
                  AND ($4::bigint IS NULL OR
                       e.started_at<=to_timestamp($4::double precision/1000.0))
                  AND ($5::text IS NULL OR EXISTS (
                       SELECT 1 FROM jsonb_array_elements_text(e.participants) AS p(value)
                        WHERE lower(p.value)=lower($5)
                           OR lower(p.value) LIKE lower($5)||' (%)'))
                ORDER BY e.embedding <=> $2::vector,e.id
                LIMIT $6"#,
        )
        .bind(account_id)
        .bind(vector)
        .bind(from)
        .bind(to)
        .bind(request.speaker.as_deref())
        .bind(candidate_limit)
        .fetch_all(self.pool())
        .await?
        .into_iter()
        .map(|row| Ok((row.try_get("id")?, row.try_get("distance")?)))
        .collect::<Result<Vec<(i64, f64)>>>()?;
        let ranked = rrf_merge(&fts, &nearest)
            .into_iter()
            .skip(request.offset)
            .take(request.limit)
            .collect::<Vec<_>>();
        let ids = ranked.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let scores = ranked.into_iter().collect::<HashMap<_, _>>();
        self.enrich_episode_hits(account_id, &request.query, &ids, &scores)
            .await
    }
}

fn postgres_json_array(row: &sqlx::postgres::PgRow, name: &str) -> Result<Value> {
    let raw: String = row.try_get(name)?;
    json_array_from_text(&raw, name)
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

fn participant_detail_from_row(row: &sqlx::postgres::PgRow) -> Result<Value> {
    let participant_key: String = row.try_get("participant_key")?;
    let attribution_kind: String = row.try_get("attribution_kind")?;
    let person_name: Option<String> = row.try_get("display_name")?;
    let claimed_name: Option<String> = row.try_get("source_claimed_name")?;
    let slot = row.try_get::<Option<i64>, _>("slot_ordinal")?;
    let owner = participant_key == "owner"
        || matches!(
            attribution_kind.as_str(),
            "owner" | "owner_presentation" | "owner_source_role"
        );
    let display_name = if owner {
        "Me".to_owned()
    } else if let Some(name) = person_name {
        name
    } else if let Some(name) = claimed_name {
        name
    } else if let Some(slot) = slot {
        let slot = i32::try_from(slot)
            .map_err(|_| EnclaveError::Store("episode speaker slot is out of range".into()))?;
        format!(
            "Unknown speaker {}",
            crate::cp::identity::format_slot_ordinal(slot)
        )
    } else {
        "Unknown speaker".to_owned()
    };
    Ok(json!({
        "participant_key": participant_key,
        "display_name": display_name,
        "person_id": if owner { None } else { row.try_get::<Option<i64>, _>("public_person_id")? },
        "attribution_kind": attribution_kind,
        "state": row.try_get::<String, _>("state")?,
    }))
}

async fn require_identified_person(
    persistence: &PostgresPersistence,
    account_id: &str,
    person_id: i64,
) -> Result<()> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM people \
          WHERE account_id=$1 AND id=$2 AND status='identified')",
    )
    .bind(account_id)
    .bind(person_id)
    .fetch_one(persistence.pool())
    .await?;
    if exists {
        Ok(())
    } else {
        Err(EnclaveError::NotFound)
    }
}

async fn postgres_person_evidence(
    persistence: &PostgresPersistence,
    account_id: &str,
    person_id: i64,
    before_id: Option<i64>,
    limit: usize,
) -> Result<PersonEvidencePage> {
    let row_limit = i64::try_from(limit.saturating_add(1))
        .map_err(|_| EnclaveError::InvalidRequest("people page limit is too large".into()))?;
    let rows = sqlx::query(
        "SELECT id,kind,claimed_name,score,status, \
                floor(extract(epoch FROM observed_at)*1000)::bigint AS observed_at_ms, \
                source_event_id,speaker_observation_id,evidence::text AS evidence_json \
           FROM identity_evidence WHERE account_id=$1 AND person_id=$2 \
            AND ($3::bigint IS NULL OR id<$3) ORDER BY id DESC LIMIT $4",
    )
    .bind(account_id)
    .bind(person_id)
    .bind(before_id)
    .bind(row_limit)
    .fetch_all(persistence.pool())
    .await?;
    let mut evidence = rows
        .iter()
        .map(|row| {
            let raw: String = row.try_get("evidence_json")?;
            Ok(PersonEvidenceView {
                id: row.try_get("id")?,
                kind: row.try_get("kind")?,
                claimed_name: row.try_get("claimed_name")?,
                score: row.try_get("score")?,
                status: row.try_get("status")?,
                observed_at: row
                    .try_get::<Option<i64>, _>("observed_at_ms")?
                    .map(isotime::format_epoch_millis),
                source_event_id: row.try_get("source_event_id")?,
                speaker_observation_id: row.try_get("speaker_observation_id")?,
                evidence: serde_json::from_str(&raw).unwrap_or(Value::Null),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let next_cursor = (evidence.len() > limit).then(|| evidence[limit - 1].id);
    evidence.truncate(limit);
    Ok(PersonEvidencePage {
        evidence,
        next_cursor,
    })
}

async fn postgres_person_statements(
    persistence: &PostgresPersistence,
    account_id: &str,
    person_id: i64,
    before_id: Option<i64>,
    limit: usize,
) -> Result<PersonStatementPage> {
    let row_limit = i64::try_from(limit.saturating_add(1))
        .map_err(|_| EnclaveError::InvalidRequest("people page limit is too large".into()))?;
    let rows = sqlx::query(
        "SELECT s.id,s.transcript_text,s.event_id, \
                floor(extract(epoch FROM s.started_at)*1000)::bigint AS started_at_ms, \
                floor(extract(epoch FROM s.ended_at)*1000)::bigint AS ended_at_ms, \
                linked.id AS episode_id,linked.title AS episode_title \
           FROM speaker_observations s LEFT JOIN LATERAL ( \
                SELECT e.id,e.title FROM utterances u JOIN episode_members m \
                  ON m.account_id=u.account_id AND m.record_type='utterance' AND m.record_id=u.id \
                 JOIN episodes e ON e.account_id=m.account_id AND e.id=m.episode_id \
                 WHERE u.account_id=s.account_id \
                   AND u.source_key='cloud-v2:'||s.event_id||':'||s.turn_id \
                   AND e.substance!='none' \
                 ORDER BY e.started_at DESC,e.id DESC LIMIT 1) linked ON true \
          WHERE s.account_id=$1 AND s.person_id=$2 \
            AND ($3::bigint IS NULL OR s.id<$3) ORDER BY s.id DESC LIMIT $4",
    )
    .bind(account_id)
    .bind(person_id)
    .bind(before_id)
    .bind(row_limit)
    .fetch_all(persistence.pool())
    .await?;
    let mut statements = rows
        .iter()
        .map(|row| {
            Ok(PersonStatementView {
                speaker_observation_id: row.try_get("id")?,
                started_at: required_timestamp(row, "started_at_ms")?,
                ended_at: required_timestamp(row, "ended_at_ms")?,
                text: row.try_get("transcript_text")?,
                source_event_id: row.try_get("event_id")?,
                episode_id: row.try_get("episode_id")?,
                episode_title: row.try_get("episode_title")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let next_cursor =
        (statements.len() > limit).then(|| statements[limit - 1].speaker_observation_id);
    statements.truncate(limit);
    Ok(PersonStatementPage {
        statements,
        next_cursor,
    })
}

#[async_trait]
impl MemoryQueryRepository for PostgresPersistence {
    async fn export(&self, account_id: &str) -> Result<Value> {
        postgres_export(self, account_id).await
    }

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

        let wants_utterances = wants("utterance");
        let wants_screenshots = wants("screenshot") && request.speaker.is_none();
        let wants_episodes = wants("episode");
        let branch_count = usize::from(wants_utterances)
            + usize::from(wants_screenshots)
            + usize::from(wants_episodes);
        let mut hits = Vec::new();
        if wants_utterances {
            hits.extend(self.search_utterances(account_id, &request).await?);
        }
        if wants_screenshots {
            hits.extend(self.search_screenshots(account_id, &request).await?);
        }
        if wants_episodes {
            hits.extend(self.search_episodes(account_id, &request).await?);
        }
        Ok(finalize_search_order(hits, branch_count, request.limit))
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
        // A topology publish may replace several episode rows at once. Keep
        // the page, its screenshot facets, low-signal count, and the revision
        // fence on one repeatable PostgreSQL snapshot so clients can safely
        // discard a continuation fetched from a different archive epoch.
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let archive_revision = sqlx::query_scalar::<_, i64>(
            "SELECT coalesce((SELECT revision FROM memory_archive_state WHERE account_id=$1),0)",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
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
        .fetch_all(&mut *transaction)
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
        let participant_rows = if ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query(
                "SELECT p.episode_id,p.participant_key,p.attribution_kind,p.state, \
                        CASE WHEN p.participant_key='owner' OR p.attribution_kind IN \
                             ('owner','owner_presentation','owner_source_role') \
                             THEN NULL ELSE pe.id END AS public_person_id, \
                        pe.display_name,p.source_claimed_name,s.slot_ordinal \
                   FROM episode_participants p LEFT JOIN people pe \
                     ON pe.account_id=p.account_id AND pe.id=p.person_id \
                    AND pe.status='identified' \
                   LEFT JOIN episode_speaker_slots s \
                     ON s.account_id=p.account_id AND s.id=p.speaker_slot_id \
                  WHERE p.account_id=$1 AND p.episode_id=ANY($2) \
                    AND p.state='active' ORDER BY p.episode_id,p.id",
            )
            .bind(account_id)
            .bind(&ids)
            .fetch_all(&mut *transaction)
            .await?
        };
        let mut participant_details: HashMap<i64, Vec<Value>> = HashMap::new();
        for row in &participant_rows {
            participant_details
                .entry(row.try_get("episode_id")?)
                .or_default()
                .push(participant_detail_from_row(row)?);
        }
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
            .fetch_all(&mut *transaction)
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
            episode["participant_details"] =
                json!(participant_details.remove(&id).unwrap_or_default());
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
            .fetch_one(&mut *transaction)
            .await?
        };
        transaction.commit().await?;
        Ok(EpisodeListPage {
            episodes,
            hidden_count,
            has_more,
            archive_revision,
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
            "SELECT u.id,CASE WHEN c.attribution_state='owner_transmit' THEN 'Me' \
                              ELSE coalesce(p.display_name,u.speaker_label) END AS speaker_label, \
                    u.text,u.source_key, \
                    CASE WHEN c.attribution_state='owner_transmit' THEN NULL ELSE p.id END AS person_id, \
                    CASE WHEN c.attribution_state='owner_transmit' THEN 'owner_source_role' \
                         WHEN p.id IS NOT NULL THEN 'direct_identity_evidence' \
                         WHEN c.attribution_state='anonymous_profile' THEN 'verified_voice' \
                         WHEN c.attribution_state IN ('request_local','unsegmented') THEN 'context_inferred' \
                         ELSE NULL END AS attribution_kind, \
                    floor(extract(epoch FROM (s.started_at + make_interval(secs => u.start_offset_seconds)))*1000)::bigint AS at_ms \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
               LEFT JOIN speaker_observations o \
                 ON o.account_id=u.account_id AND o.id=u.speaker_observation_id \
               LEFT JOIN speaker_clusters c \
                 ON c.account_id=o.account_id AND c.id=o.cluster_id \
               LEFT JOIN people p \
                 ON p.account_id=u.account_id AND p.id=coalesce(o.person_id,c.person_id) \
                AND p.status='identified' \
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
                    person_id: row.try_get("person_id")?,
                    attribution_kind: row.try_get("attribution_kind")?,
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
                person_id: None,
                attribution_kind: None,
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
            "SELECT DISTINCT ON (m.account_id,m.record_type,m.record_id) \
                    m.record_type,m.record_id,e.id AS episode_id \
               FROM episode_members m JOIN episodes e \
                 ON e.account_id=m.account_id AND e.id=m.episode_id \
              WHERE m.account_id=$1 AND e.substance!='none' \
                AND ((m.record_type='utterance' AND m.record_id=ANY($2)) \
                  OR (m.record_type='screenshot' AND m.record_id=ANY($3))) \
              ORDER BY m.account_id,m.record_type,m.record_id,e.started_at DESC,e.id DESC",
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
            .clamp(1, crate::cp::mcp_safety::MAX_MINIMIZED_PAGE_SIZE);
        let from = bound(&request.from)?;
        let to = bound(&request.to)?;
        let rows = sqlx::query(
            "SELECT u.id,u.text,u.speaker_label, \
                    floor(extract(epoch FROM (s.started_at + \
                        u.start_offset_seconds * interval '1 second'))*1000)::bigint \
                        AS started_at_ms, \
                    floor(extract(epoch FROM (s.started_at + \
                        u.end_offset_seconds * interval '1 second'))*1000)::bigint \
                        AS ended_at_ms \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
              WHERE u.account_id=$1 AND strpos(lower(u.text),lower($2))>0 \
                AND ($3::bigint IS NULL OR (s.started_at + \
                    u.start_offset_seconds * interval '1 second') \
                    >=to_timestamp($3::double precision/1000.0)) \
                AND ($4::bigint IS NULL OR (s.started_at + \
                    u.start_offset_seconds * interval '1 second') \
                    <=to_timestamp($4::double precision/1000.0)) \
              ORDER BY (s.started_at + u.start_offset_seconds * interval '1 second') DESC, \
                       u.id DESC LIMIT $5",
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
                    row.try_get::<String, _>("speaker_label")?,
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
            .map(|(id, _, speaker, started_at, _ended_at)| {
                json!({
                    "kind": "utterance",
                    "text": redacted.get(&id).cloned().unwrap_or_default(),
                    "speaker_label": speaker,
                    "started_at": started_at,
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
            .unwrap_or(crate::cp::mcp_safety::DEFAULT_MINIMIZED_PAGE_SIZE)
            .clamp(1, crate::cp::mcp_safety::MAX_MINIMIZED_PAGE_SIZE);
        let center_ms = isotime::parse_epoch_millis(&request.at)
            .ok_or_else(|| EnclaveError::InvalidRequest("invalid MCP context timestamp".into()))?;
        let window_ms = i64::try_from(request.window_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .ok_or_else(|| {
                EnclaveError::InvalidRequest("MCP context window is too large".into())
            })?;
        let half_window_ms = window_ms / 2;
        let rows = sqlx::query(
            "SELECT u.id,u.text,u.speaker_label,u.language,s.source_type, \
                    floor(extract(epoch FROM (s.started_at + \
                        u.start_offset_seconds * interval '1 second'))*1000)::bigint \
                        AS started_at_ms, \
                    floor(extract(epoch FROM (s.started_at + \
                        u.end_offset_seconds * interval '1 second'))*1000)::bigint \
                        AS ended_at_ms \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
              WHERE u.account_id=$1 \
                AND abs(floor(extract(epoch FROM (s.started_at + \
                    u.start_offset_seconds * interval '1 second'))*1000)::bigint-$2)<=$3 \
              ORDER BY abs(floor(extract(epoch FROM (s.started_at + \
                    u.start_offset_seconds * interval '1 second'))*1000)::bigint-$2),u.id \
              LIMIT $4",
        )
        .bind(account_id)
        .bind(center_ms)
        .bind(half_window_ms)
        .bind(limit(effective_limit)?)
        .fetch_all(self.pool())
        .await?;
        let raw = rows
            .iter()
            .map(|row| {
                Ok((
                    row.try_get::<i64, _>("id")?,
                    row.try_get::<String, _>("text")?,
                    row.try_get::<String, _>("speaker_label")?,
                    row.try_get::<Option<String>, _>("language")?,
                    row.try_get::<String, _>("source_type")?,
                    required_timestamp(row, "started_at_ms")?,
                    required_timestamp(row, "ended_at_ms")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let redacted = crate::cp::dlp::redact_utterance_window(
            &raw.iter()
                .map(|(id, text, _, _, _, _, _)| (*id, text.clone()))
                .collect::<Vec<_>>(),
        )
        .into_iter()
        .map(|(id, value)| (id, value.text))
        .collect::<HashMap<_, _>>();
        let utterances = raw
            .into_iter()
            .map(
                |(id, _, speaker, language, source_type, started_at, ended_at)| {
                    json!({
                        "text": redacted.get(&id).cloned().unwrap_or_default(),
                        "speaker_label": speaker,
                        "language": language,
                        "source_type": source_type,
                        "started_at": started_at,
                        "ended_at": ended_at,
                    })
                },
            )
            .collect::<Vec<_>>();
        let center = isotime::format_epoch_millis(center_ms);
        Ok(crate::cp::mcp_safety::sanitize_result(json!({
            "summary_digest": format!("Context around {}: {} safe items retrieved.", center, utterances.len()),
            "window_seconds": request.window_seconds,
            "utterances": utterances,
            "screenshots": [],
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
            .unwrap_or(crate::cp::mcp_safety::DEFAULT_MINIMIZED_PAGE_SIZE)
            .clamp(1, crate::cp::mcp_safety::MAX_MINIMIZED_PAGE_SIZE);
        let from_ms = isotime::parse_epoch_millis(&request.from)
            .ok_or_else(|| EnclaveError::InvalidRequest("invalid MCP range start".into()))?;
        let to_ms = isotime::parse_epoch_millis(&request.to)
            .ok_or_else(|| EnclaveError::InvalidRequest("invalid MCP range end".into()))?;
        if to_ms <= from_ms {
            return Err(EnclaveError::InvalidRequest(
                "MCP range end must be after its start".into(),
            ));
        }

        let counts = sqlx::query(
            "SELECT \
                (SELECT count(*) FROM utterances u JOIN audio_segments s \
                   ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
                  WHERE u.account_id=$1 \
                    AND (s.started_at + u.start_offset_seconds * interval '1 second') \
                        >=to_timestamp($2::double precision/1000.0) \
                    AND (s.started_at + u.start_offset_seconds * interval '1 second') \
                        <to_timestamp($3::double precision/1000.0)) AS utterance_count, \
                (SELECT count(*) FROM screenshots c \
                  WHERE c.account_id=$1 \
                    AND c.captured_at>=to_timestamp($2::double precision/1000.0) \
                    AND c.captured_at<to_timestamp($3::double precision/1000.0)) \
                    AS screenshot_count",
        )
        .bind(account_id)
        .bind(from_ms)
        .bind(to_ms)
        .fetch_one(self.pool())
        .await?;
        let utterance_count = counts.try_get::<i64, _>("utterance_count")?;
        let screenshot_count = counts.try_get::<i64, _>("screenshot_count")?;

        let language_rows = sqlx::query(
            "SELECT DISTINCT u.language AS language \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
              WHERE u.account_id=$1 AND u.language IS NOT NULL AND btrim(u.language)<>'' \
                AND (s.started_at + u.start_offset_seconds * interval '1 second') \
                    >=to_timestamp($2::double precision/1000.0) \
                AND (s.started_at + u.start_offset_seconds * interval '1 second') \
                    <to_timestamp($3::double precision/1000.0) \
              ORDER BY u.language",
        )
        .bind(account_id)
        .bind(from_ms)
        .bind(to_ms)
        .fetch_all(self.pool())
        .await?;
        let languages = language_rows
            .iter()
            .map(|row| row.try_get::<String, _>("language").map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;

        let app_rows = sqlx::query(
            "SELECT DISTINCT c.active_app AS active_app FROM screenshots c \
              WHERE c.account_id=$1 AND c.active_app IS NOT NULL AND btrim(c.active_app)<>'' \
                AND c.captured_at>=to_timestamp($2::double precision/1000.0) \
                AND c.captured_at<to_timestamp($3::double precision/1000.0) \
              ORDER BY c.active_app",
        )
        .bind(account_id)
        .bind(from_ms)
        .bind(to_ms)
        .fetch_all(self.pool())
        .await?;
        let apps_seen = app_rows
            .iter()
            .map(|row| row.try_get::<String, _>("active_app").map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;

        let rows = sqlx::query(
            "SELECT u.id,u.text,u.speaker_label, \
                    floor(extract(epoch FROM (s.started_at + \
                        u.start_offset_seconds * interval '1 second'))*1000)::bigint AS at_ms \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
              WHERE u.account_id=$1 \
                AND (s.started_at + u.start_offset_seconds * interval '1 second') \
                    >=to_timestamp($2::double precision/1000.0) \
                AND (s.started_at + u.start_offset_seconds * interval '1 second') \
                    <to_timestamp($3::double precision/1000.0) \
              ORDER BY (s.started_at + u.start_offset_seconds * interval '1 second'),u.id \
              LIMIT $4",
        )
        .bind(account_id)
        .bind(from_ms)
        .bind(to_ms)
        .bind(limit(effective_limit)?)
        .fetch_all(self.pool())
        .await?;
        let raw = rows
            .iter()
            .map(|row| {
                Ok((
                    row.try_get::<i64, _>("id")?,
                    row.try_get::<String, _>("text")?,
                    row.try_get::<String, _>("speaker_label")?,
                    required_timestamp(row, "at_ms")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let redacted = crate::cp::dlp::redact_utterance_window(
            &raw.iter()
                .map(|(id, text, _, _)| (*id, text.clone()))
                .collect::<Vec<_>>(),
        )
        .into_iter()
        .map(|(id, value)| (id, value.text))
        .collect::<HashMap<_, _>>();
        let digest = raw
            .into_iter()
            .map(|(id, _, speaker, at)| {
                json!({
                    "at": at,
                    "speaker": speaker,
                    "text": redacted.get(&id).cloned().unwrap_or_default(),
                })
            })
            .collect::<Vec<_>>();
        let from = isotime::format_epoch_millis(from_ms);
        let to = isotime::format_epoch_millis(to_ms);
        Ok(crate::cp::mcp_safety::sanitize_result(json!({
            "from": from,
            "to": to,
            "counts": {
                "utterances": utterance_count,
                "screenshots": screenshot_count,
            },
            "languages": languages,
            "apps_seen": apps_seen,
            "digest": digest,
        })))
    }

    async fn browser_snapshot(&self, account_id: &str, source_key: &str) -> Result<Option<Value>> {
        const CAPTURE_V2_BROWSER_SOURCE_PREFIX: &str = "capture-v2-browser:";
        if let Some(event_id) = source_key.strip_prefix(CAPTURE_V2_BROWSER_SOURCE_PREFIX) {
            if event_id.is_empty() || event_id.len() > 512 || event_id.contains('\0') {
                return Ok(None);
            }
            let screenshots = sqlx::query(
                "SELECT c.source_key, \
                        floor(extract(epoch FROM c.captured_at)*1000)::bigint AS captured_at_ms \
                   FROM screenshots c WHERE c.account_id=$1 AND c.browser_snapshot_source_key=$2 \
                    AND EXISTS (SELECT 1 FROM episode_members m JOIN episodes e \
                         ON e.account_id=m.account_id AND e.id=m.episode_id \
                         WHERE m.account_id=c.account_id AND m.record_type='screenshot' \
                           AND m.record_id=c.id)",
            )
            .bind(account_id)
            .bind(source_key)
            .fetch_all(self.pool())
            .await?;
            if screenshots.is_empty() {
                return Ok(None);
            }
            if screenshots.len() != 1 {
                return Err(EnclaveError::Store(
                    "browser-v2 screenshot association is ambiguous".into(),
                ));
            }
            let screenshot = &screenshots[0];
            let expected_screenshot_source_key = format!("cloud-v2:{event_id}");
            if screenshot
                .try_get::<Option<String>, _>("source_key")?
                .as_deref()
                != Some(expected_screenshot_source_key.as_str())
            {
                return Err(EnclaveError::Store(
                    "browser-v2 screenshot source is inconsistent".into(),
                ));
            }
            let event = sqlx::query(
                "SELECT device_id,context_json::text AS context_json, \
                        floor(extract(epoch FROM started_at)*1000)::bigint AS started_at_ms, \
                        floor(extract(epoch FROM source_wall_at)*1000)::bigint AS source_wall_at_ms \
                   FROM capture_events WHERE account_id=$1 AND event_id=$2",
            )
            .bind(account_id)
            .bind(event_id)
            .fetch_optional(self.pool())
            .await?
            .ok_or_else(|| EnclaveError::Store("browser-v2 capture event is missing".into()))?;
            let observation = sqlx::query(
                "SELECT observation_id,state_key,context_status,active_url,active_title, \
                        floor(extract(epoch FROM observed_at)*1000)::bigint AS observed_at_ms \
                   FROM browser_observations_v2 WHERE account_id=$1 AND event_id=$2",
            )
            .bind(account_id)
            .bind(event_id)
            .fetch_optional(self.pool())
            .await?
            .ok_or_else(|| EnclaveError::Store("browser-v2 observation is missing".into()))?;
            let state_key = observation
                .try_get::<Option<String>, _>("state_key")?
                .ok_or_else(|| {
                    EnclaveError::Store("browser-v2 observation is missing state".into())
                })?;
            let state = sqlx::query(
                "SELECT browser_bundle_id,browser_name,permission_status,content_hash, \
                        tabs_json::text AS tabs_json FROM browser_states_v2 \
                  WHERE account_id=$1 AND state_key=$2",
            )
            .bind(account_id)
            .bind(&state_key)
            .fetch_optional(self.pool())
            .await?
            .ok_or_else(|| EnclaveError::Store("browser-v2 state is missing".into()))?;
            let context: crate::cp::media::CaptureContext = serde_json::from_str(
                event
                    .try_get::<Option<String>, _>("context_json")?
                    .as_deref()
                    .ok_or_else(|| EnclaveError::Store("browser-v2 context is missing".into()))?,
            )
            .map_err(|_| EnclaveError::Store("browser-v2 context is corrupt".into()))?;
            let observed_at = required_timestamp(&observation, "observed_at_ms")?;
            let source_wall_at = required_timestamp(&event, "source_wall_at_ms")?;
            let tabs_json: String = state.try_get("tabs_json")?;
            let browser_bundle_id: String = state.try_get("browser_bundle_id")?;
            let browser_name: String = state.try_get("browser_name")?;
            let permission_status: String = state.try_get("permission_status")?;
            let content_hash: String = state.try_get("content_hash")?;
            let observation_id: String = observation.try_get("observation_id")?;
            let context_status: String = observation.try_get("context_status")?;
            let active_url: Option<String> = observation.try_get("active_url")?;
            let active_title: Option<String> = observation.try_get("active_title")?;
            let device_id: String = event.try_get("device_id")?;
            let snapshot = crate::cp::media::validate_browser_v2_persisted_evidence(
                &context,
                crate::cp::media::BrowserV2PersistedEvidence {
                    event_id,
                    device_id: &device_id,
                    source_wall_at: &source_wall_at,
                    observation_id: &observation_id,
                    observed_at: &observed_at,
                    state_key: Some(&state_key),
                    context_status: &context_status,
                    active_url: active_url.as_deref(),
                    active_title: active_title.as_deref(),
                    browser_bundle_id: &browser_bundle_id,
                    browser_name: &browser_name,
                    permission_status: &permission_status,
                    content_hash: &content_hash,
                    tabs_json: &tabs_json,
                },
            )?;
            let captured_at_ms: i64 = screenshot.try_get("captured_at_ms")?;
            if captured_at_ms != event.try_get::<i64, _>("started_at_ms")? {
                return Err(EnclaveError::Store(
                    "browser-v2 evidence is inconsistent".into(),
                ));
            }
            return Ok(Some(json!({
                "source_key": source_key,
                "captured_at": isotime::format_epoch_millis(captured_at_ms),
                "observed_at": observed_at,
                "browser_bundle_id": snapshot.browser_bundle_id,
                "browser_name": snapshot.browser_name,
                "permission_status": snapshot.permission_status,
                "active_window_index": snapshot.active_window_index,
                "active_tab_index": snapshot.active_tab_index,
                "reported_tab_count": snapshot.reported_tab_count,
                "truncated": snapshot.truncated,
                "ambient_tab_collection_enabled": snapshot.ambient_tab_collection_enabled,
                "tabs": snapshot.tabs,
            })));
        }

        let snapshot = sqlx::query(
            "SELECT b.id,b.browser_bundle_id,b.browser_name,b.permission_status, \
                    b.active_window_index,b.active_tab_index,b.reported_tab_count,b.truncated, \
                    floor(extract(epoch FROM b.captured_at)*1000)::bigint AS captured_at_ms \
               FROM browser_snapshots b WHERE b.account_id=$1 AND b.source_key=$2 \
                AND EXISTS (SELECT 1 FROM screenshots c JOIN episode_members m \
                     ON m.account_id=c.account_id AND m.record_type='screenshot' AND m.record_id=c.id \
                     JOIN episodes e ON e.account_id=m.account_id AND e.id=m.episode_id \
                     WHERE c.account_id=b.account_id AND c.browser_snapshot_source_key=b.source_key)",
        )
        .bind(account_id)
        .bind(source_key)
        .fetch_optional(self.pool())
        .await?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        let snapshot_id: i64 = snapshot.try_get("id")?;
        let tab_rows = sqlx::query(
            "SELECT window_index,tab_index,title,url,url_scheme,is_active,is_loading \
               FROM browser_tabs WHERE account_id=$1 AND browser_snapshot_id=$2 \
              ORDER BY window_index,tab_index LIMIT 500",
        )
        .bind(account_id)
        .bind(snapshot_id)
        .fetch_all(self.pool())
        .await?;
        let tabs = tab_rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "window_index": row.try_get::<i64, _>("window_index")?,
                    "tab_index": row.try_get::<i64, _>("tab_index")?,
                    "title": row.try_get::<Option<String>, _>("title")?,
                    "url": row.try_get::<Option<String>, _>("url")?,
                    "url_scheme": row.try_get::<Option<String>, _>("url_scheme")?,
                    "is_active": row.try_get::<bool, _>("is_active")?,
                    "is_loading": row.try_get::<Option<bool>, _>("is_loading")?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(json!({
            "source_key": source_key,
            "captured_at": required_timestamp(&snapshot, "captured_at_ms")?,
            "browser_bundle_id": snapshot.try_get::<String, _>("browser_bundle_id")?,
            "browser_name": snapshot.try_get::<String, _>("browser_name")?,
            "permission_status": snapshot.try_get::<String, _>("permission_status")?,
            "active_window_index": snapshot.try_get::<Option<i64>, _>("active_window_index")?,
            "active_tab_index": snapshot.try_get::<Option<i64>, _>("active_tab_index")?,
            "reported_tab_count": snapshot.try_get::<i64, _>("reported_tab_count")?,
            "truncated": snapshot.try_get::<bool, _>("truncated")?,
            "tabs": tabs,
        })))
    }

    async fn episode_members(&self, account_id: &str, episode_id: i64) -> Result<Value> {
        let utterance_rows = sqlx::query(
            "SELECT u.id,u.speaker_label,u.language,u.text,u.source_key, \
                    floor(extract(epoch FROM coalesce( \
                        o.started_at, \
                        s.started_at + (u.start_offset_seconds * interval '1 second') \
                    ))*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM coalesce( \
                        o.ended_at, \
                        s.started_at + (u.end_offset_seconds * interval '1 second') \
                    ))*1000)::bigint AS ended_at_ms, \
                    CASE WHEN c.attribution_state='owner_transmit' THEN NULL ELSE p.id END AS person_id, \
                    CASE WHEN c.attribution_state='owner_transmit' THEN NULL ELSE p.display_name END AS display_name, \
                    c.attribution_state \
               FROM episode_members m JOIN utterances u \
                 ON u.account_id=m.account_id AND u.id=m.record_id \
               JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
               LEFT JOIN speaker_observations o \
                 ON o.account_id=u.account_id AND o.id=u.speaker_observation_id \
               LEFT JOIN speaker_clusters c \
                 ON c.account_id=o.account_id AND c.id=o.cluster_id \
               LEFT JOIN people p \
                 ON p.account_id=u.account_id AND p.id=coalesce(o.person_id,c.person_id) \
                AND p.status='identified' \
              WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='utterance'",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(self.pool())
        .await?;
        let mut members = utterance_rows
            .iter()
            .map(|row| {
                let timestamp = required_timestamp(row, "started_at_ms")?;
                let speaker_label: String = row.try_get("speaker_label")?;
                let person_id: Option<i64> = row.try_get("person_id")?;
                let person_name: Option<String> = row.try_get("display_name")?;
                let attribution = row.try_get::<Option<String>, _>("attribution_state")?;
                let display_name =
                    if person_id.is_none() && attribution.as_deref() == Some("owner_transmit") {
                        "Me".to_owned()
                    } else {
                        person_name.unwrap_or_else(|| speaker_label.clone())
                    };
                let attribution_kind = if person_id.is_some() {
                    "direct_identity_evidence"
                } else {
                    match attribution.as_deref() {
                        Some("owner_transmit") => "owner_source_role",
                        Some("anonymous_profile") => "verified_voice",
                        Some("request_local" | "unsegmented") => "context_inferred",
                        _ => "unavailable",
                    }
                };
                Ok((
                    timestamp.clone(),
                    json!({
                        "record_type": "utterance",
                        "record_id": row.try_get::<i64, _>("id")?,
                        "started_at": timestamp,
                        "ended_at": required_timestamp(row, "ended_at_ms")?,
                        "speaker_label": speaker_label,
                        "display_name": display_name,
                        "person_id": person_id,
                        "attribution_kind": attribution_kind,
                        "language": row.try_get::<Option<String>, _>("language")?,
                        "text": row.try_get::<String, _>("text")?,
                        "source_key": row.try_get::<Option<String>, _>("source_key")?,
                    }),
                ))
            })
            .collect::<Result<Vec<(String, Value)>>>()?;

        let screenshot_rows = sqlx::query(
            "SELECT c.id,c.active_app,c.window_title,c.url,left(c.ocr_text,4000) AS ocr_excerpt, \
                    left(c.salient_ocr_text,4000) AS salient_ocr_excerpt, \
                    coalesce(char_length(c.ocr_text)>4000,false) AS ocr_truncated,c.source_key, \
                    coalesce(img.id,CASE WHEN capture_img.asset_id IS NOT NULL \
                         THEN 'capture-v2:'||capture_img.asset_id END) AS cloud_image_id, \
                    o.status AS observation_status,o.generation_method AS observation_method, \
                    o.literal_description,o.screen_state,o.content_type,o.visible_text_summary, \
                    o.notable_items::text AS notable_items, \
                    i.activity_summary,i.relevance_level,i.relevance_reason,i.key_rank, \
                    i.is_key_screen,i.semantic_group,c.capture_status,c.primary_bundle_id, \
                    floor(extract(epoch FROM c.captured_at)*1000)::bigint AS captured_at_ms, \
                    floor(extract(epoch FROM c.visible_until)*1000)::bigint AS visible_until_ms, \
                    c.browser_snapshot_source_key,i.status AS interpretation_status, \
                    i.milestone_type,i.base_score AS key_score \
               FROM episode_members m JOIN screenshots c \
                 ON c.account_id=m.account_id AND c.id=m.record_id \
               LEFT JOIN screenshot_images img \
                 ON img.account_id=c.account_id AND img.source_key=c.source_key \
               LEFT JOIN media_objects capture_img \
                 ON capture_img.account_id=c.account_id \
                AND c.source_key LIKE 'cloud-v2:%' \
                AND capture_img.event_id=substring(c.source_key from length('cloud-v2:')+1) \
                AND capture_img.mime_type='image/jpeg' \
                AND capture_img.processing_state='ready' AND capture_img.deleted_at IS NULL \
               LEFT JOIN screen_observations o \
                 ON o.account_id=c.account_id AND o.screenshot_id=c.id \
               LEFT JOIN episode_screen_interpretations i \
                 ON i.account_id=m.account_id AND i.episode_id=m.episode_id \
                AND i.screenshot_id=c.id \
              WHERE m.account_id=$1 AND m.episode_id=$2 \
                AND m.record_type='screenshot' AND NOT c.is_duplicate",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(self.pool())
        .await?;
        for row in &screenshot_rows {
            let timestamp = required_timestamp(row, "captured_at_ms")?;
            let raw_ocr: Option<String> = row.try_get("ocr_excerpt")?;
            let supplied_salient: Option<String> = row.try_get("salient_ocr_excerpt")?;
            let salient =
                crate::ocr::select_salient_ocr(raw_ocr.as_deref(), supplied_salient.as_deref());
            let screen_facts = salient
                .as_deref()
                .map(crate::ocr::extract_screen_facts)
                .unwrap_or_default();
            let notable_items = row
                .try_get::<Option<String>, _>("notable_items")?
                .and_then(|raw| serde_json::from_str(&raw).ok())
                .unwrap_or_else(|| json!([]));
            let visible_until = row
                .try_get::<Option<i64>, _>("visible_until_ms")?
                .map(isotime::format_epoch_millis);
            members.push((
                timestamp.clone(),
                json!({
                    "record_type": "screenshot",
                    "record_id": row.try_get::<i64, _>("id")?,
                    "captured_at": timestamp,
                    "active_app": row.try_get::<Option<String>, _>("active_app")?,
                    "window_title": row.try_get::<Option<String>, _>("window_title")?,
                    "url": row.try_get::<Option<String>, _>("url")?,
                    "ocr_excerpt": raw_ocr,
                    "ocr_truncated": row.try_get::<bool, _>("ocr_truncated")?,
                    "salient_ocr_excerpt": salient,
                    "screen_facts": screen_facts,
                    "source_key": row.try_get::<Option<String>, _>("source_key")?,
                    "cloud_image_id": row.try_get::<Option<String>, _>("cloud_image_id")?,
                    "observation_status": row.try_get::<Option<String>, _>("observation_status")?,
                    "observation_method": row.try_get::<Option<String>, _>("observation_method")?,
                    "literal_description": row.try_get::<Option<String>, _>("literal_description")?,
                    "screen_state": row.try_get::<Option<String>, _>("screen_state")?,
                    "content_type": row.try_get::<Option<String>, _>("content_type")?,
                    "visible_text_summary": row.try_get::<Option<String>, _>("visible_text_summary")?,
                    "notable_items": notable_items,
                    "activity_summary": row.try_get::<Option<String>, _>("activity_summary")?,
                    "relevance_level": row.try_get::<Option<i64>, _>("relevance_level")?,
                    "relevance_reason": row.try_get::<Option<String>, _>("relevance_reason")?,
                    "key_rank": row.try_get::<Option<i64>, _>("key_rank")?,
                    "is_key_screen": row.try_get::<Option<bool>, _>("is_key_screen")?.unwrap_or(false),
                    "semantic_group": row.try_get::<Option<String>, _>("semantic_group")?,
                    "capture_status": row.try_get::<Option<String>, _>("capture_status")?,
                    "primary_bundle_id": row.try_get::<Option<String>, _>("primary_bundle_id")?,
                    "visible_until": visible_until,
                    "browser_snapshot_source_key": row.try_get::<Option<String>, _>("browser_snapshot_source_key")?,
                    "interpretation_status": row.try_get::<Option<String>, _>("interpretation_status")?,
                    "milestone_type": row.try_get::<Option<String>, _>("milestone_type")?,
                    "key_score": row.try_get::<Option<i64>, _>("key_score")?,
                }),
            ));
        }
        members.sort_by(|left, right| left.0.cmp(&right.0));
        let members = members
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>();

        let participant_rows = sqlx::query(
            "SELECT p.participant_key,p.attribution_kind,p.state, \
                    CASE WHEN p.participant_key='owner' OR p.attribution_kind IN \
                         ('owner','owner_presentation','owner_source_role') \
                         THEN NULL ELSE pe.id END AS public_person_id, \
                    pe.display_name,p.source_claimed_name,s.slot_ordinal \
               FROM episode_participants p LEFT JOIN people pe \
                 ON pe.account_id=p.account_id AND pe.id=p.person_id \
                AND pe.status='identified' \
               LEFT JOIN episode_speaker_slots s \
                 ON s.account_id=p.account_id AND s.id=p.speaker_slot_id \
              WHERE p.account_id=$1 AND p.episode_id=$2 AND p.state='active' ORDER BY p.id",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(self.pool())
        .await?;
        let participant_details = participant_rows
            .iter()
            .map(participant_detail_from_row)
            .collect::<Result<Vec<_>>>()?;

        Ok(json!({
            "episode_id": episode_id,
            "member_count": members.len(),
            "participant_details": participant_details,
            "members": members,
        }))
    }

    async fn screenshot_media(
        &self,
        account_id: &str,
        public_id: &str,
    ) -> Result<Option<ScreenshotMediaLocator>> {
        let Some(asset_id) = public_id.strip_prefix("capture-v2:") else {
            // The retired multipart image namespace is intentionally not part
            // of a fresh PostgreSQL deployment.
            return Ok(None);
        };
        let expected_object_key =
            crate::gcs::canonical_capture_media_object_key(account_id, asset_id)?;
        let row = sqlx::query(
            "SELECT object_key,object_generation,object_backend,byte_length,sha256 \
               FROM media_objects WHERE account_id=$1 AND asset_id=$2 \
                AND mime_type='image/jpeg' AND processing_state='ready' AND deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(asset_id)
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let object_key: String = row.try_get("object_key")?;
        let generation: Option<i64> = row.try_get("object_generation")?;
        let backend: Option<String> = row.try_get("object_backend")?;
        let byte_length: i64 = row.try_get("byte_length")?;
        let sha256: String = row.try_get("sha256")?;
        let generation = generation.ok_or_else(|| {
            EnclaveError::InvalidRequest("canonical screenshot is missing its generation".into())
        })?;
        if generation <= 0
            || backend.as_deref() != Some("current")
            || object_key != expected_object_key
            || byte_length <= 0
            || byte_length > crate::cp::media::MAX_SCREENSHOT_BYTES
            || sha256.len() != 64
            || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(EnclaveError::InvalidRequest(
                "canonical screenshot identity is malformed".into(),
            ));
        }
        Ok(Some(ScreenshotMediaLocator::Canonical {
            object_key,
            generation,
            byte_length,
            sha256,
        }))
    }

    async fn list_people(
        &self,
        account_id: &str,
        request: &PeopleListRequest,
    ) -> Result<PeopleListPage> {
        if request.limit == 0 || request.limit > 100 || request.after_id < 0 {
            return Err(EnclaveError::InvalidRequest(
                "people page bounds are invalid".into(),
            ));
        }
        let row_limit = i64::try_from(request.limit + 1)
            .map_err(|_| EnclaveError::InvalidRequest("people page limit is too large".into()))?;
        let query = request
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let rows = sqlx::query(
            "SELECT p.id,p.display_name, \
                    count(DISTINCT v.id)::bigint AS voice_profile_count, \
                    count(DISTINCT f.id)::bigint AS fact_count, \
                    floor(extract(epoch FROM p.updated_at)*1000)::bigint AS updated_at_ms \
               FROM people p LEFT JOIN voice_profiles v \
                 ON v.account_id=p.account_id AND v.person_id=p.id \
                AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
                     WHERE r.account_id=v.account_id AND r.profile_id=v.id AND r.active \
                       AND r.status IN ('quarantined','superseded','split')) \
               LEFT JOIN person_facts f ON f.account_id=p.account_id \
                 AND f.person_id=p.id AND f.status='active' \
              WHERE p.account_id=$1 AND p.status='identified' \
                AND p.display_name IS NOT NULL AND p.id>$2 \
                AND ($3::text IS NULL OR lower(p.display_name) LIKE '%'||lower($3)||'%' \
                  OR EXISTS (SELECT 1 FROM person_name_claims n \
                       WHERE n.account_id=p.account_id AND n.person_id=p.id \
                         AND n.status IN ('accepted','probationary') \
                         AND lower(n.name) LIKE '%'||lower($3)||'%')) \
              GROUP BY p.account_id,p.id ORDER BY p.id LIMIT $4",
        )
        .bind(account_id)
        .bind(request.after_id)
        .bind(query)
        .bind(row_limit)
        .fetch_all(self.pool())
        .await?;
        let mut people = rows
            .iter()
            .map(|row| {
                Ok(PersonSummary {
                    id: row.try_get("id")?,
                    display_name: row.try_get("display_name")?,
                    voice_profile_count: row.try_get("voice_profile_count")?,
                    fact_count: row.try_get("fact_count")?,
                    updated_at: required_timestamp(row, "updated_at_ms")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = (people.len() > request.limit).then(|| people[request.limit - 1].id);
        people.truncate(request.limit);
        Ok(PeopleListPage {
            people,
            next_cursor,
        })
    }

    async fn person_profile(&self, account_id: &str, person_id: i64) -> Result<PersonProfile> {
        let row = sqlx::query(
            "SELECT p.id,p.display_name, \
                    count(DISTINCT v.id)::bigint AS voice_profile_count, \
                    count(DISTINCT f.id)::bigint AS fact_count, \
                    floor(extract(epoch FROM p.updated_at)*1000)::bigint AS updated_at_ms \
               FROM people p LEFT JOIN voice_profiles v \
                 ON v.account_id=p.account_id AND v.person_id=p.id \
                AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
                     WHERE r.account_id=v.account_id AND r.profile_id=v.id AND r.active \
                       AND r.status IN ('quarantined','superseded','split')) \
               LEFT JOIN person_facts f ON f.account_id=p.account_id \
                 AND f.person_id=p.id AND f.status='active' \
              WHERE p.account_id=$1 AND p.id=$2 AND p.status='identified' \
              GROUP BY p.account_id,p.id",
        )
        .bind(account_id)
        .bind(person_id)
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else {
            return Err(EnclaveError::NotFound);
        };
        let person = PersonSummary {
            id: row.try_get("id")?,
            display_name: row.try_get("display_name")?,
            voice_profile_count: row.try_get("voice_profile_count")?,
            fact_count: row.try_get("fact_count")?,
            updated_at: required_timestamp(&row, "updated_at_ms")?,
        };

        let voice_labels = sqlx::query_scalar::<_, String>(
            "SELECT v.label FROM voice_profiles v \
              WHERE v.account_id=$1 AND v.person_id=$2 AND v.status<>'quarantined' \
                AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
                     WHERE r.account_id=v.account_id AND r.profile_id=v.id AND r.active \
                       AND r.status IN ('quarantined','superseded','split')) ORDER BY v.id",
        )
        .bind(account_id)
        .bind(person_id)
        .fetch_all(self.pool())
        .await?;
        let coverage = sqlx::query(
            "SELECT (SELECT count(*)::bigint FROM voice_profiles v \
                       WHERE v.account_id=$1 AND v.person_id=$2 AND v.status='stable' \
                         AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
                              WHERE r.account_id=v.account_id AND r.profile_id=v.id AND r.active \
                                AND r.status IN ('quarantined','superseded','split'))) AS stable_profiles, \
                    (SELECT count(*)::bigint FROM voice_samples s \
                       JOIN voice_sample_profile_assignments a \
                         ON a.account_id=s.account_id AND a.sample_id=s.id AND a.active \
                       JOIN voice_profiles v \
                         ON v.account_id=a.account_id AND v.id=a.profile_id \
                      WHERE v.account_id=$1 AND v.person_id=$2 AND s.accepted \
                        AND s.eligibility='enroll' AND NOT s.outlier \
                        AND NOT EXISTS (SELECT 1 FROM voice_profile_revisions r \
                             WHERE r.account_id=v.account_id AND r.profile_id=v.id AND r.active \
                               AND r.status IN ('quarantined','superseded','split'))) AS accepted_samples",
        )
        .bind(account_id)
        .bind(person_id)
        .fetch_one(self.pool())
        .await?;
        let stable_profiles: i64 = coverage.try_get("stable_profiles")?;
        let accepted_samples: i64 = coverage.try_get("accepted_samples")?;
        let voice_coverage = if stable_profiles > 0 {
            format!(
                "Recognized from {accepted_samples} high-quality samples across {stable_profiles} stable acoustic profiles"
            )
        } else if accepted_samples > 0 {
            format!("Learning from {accepted_samples} high-quality voice samples")
        } else {
            "No stable voice recognition profile yet".into()
        };

        let alias_rows = sqlx::query(
            "SELECT id,name,status,evidence_kind,confidence,source_event_id, \
                    floor(extract(epoch FROM observed_at)*1000)::bigint AS observed_at_ms \
               FROM person_name_claims WHERE account_id=$1 AND person_id=$2 \
                AND status<>'rejected' ORDER BY observed_at DESC,id DESC LIMIT 100",
        )
        .bind(account_id)
        .bind(person_id)
        .fetch_all(self.pool())
        .await?;
        let aliases = alias_rows
            .iter()
            .map(|row| {
                Ok(PersonNameView {
                    id: row.try_get("id")?,
                    name: row.try_get("name")?,
                    status: row.try_get("status")?,
                    evidence_kind: row.try_get("evidence_kind")?,
                    confidence: row.try_get("confidence")?,
                    observed_at: required_timestamp(row, "observed_at_ms")?,
                    source_event_id: row.try_get("source_event_id")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let fact_rows = sqlx::query(
            "SELECT id,predicate,value,status,evidence::text AS evidence_json,source_event_id, \
                    speaker_observation_id, \
                    floor(extract(epoch FROM observed_at)*1000)::bigint AS observed_at_ms, \
                    literal_evidence,confidence,supersedes_id, \
                    floor(extract(epoch FROM created_at)*1000)::bigint AS created_at_ms \
               FROM person_facts WHERE account_id=$1 AND person_id=$2 \
              ORDER BY coalesce(observed_at,created_at) DESC,id DESC LIMIT 200",
        )
        .bind(account_id)
        .bind(person_id)
        .fetch_all(self.pool())
        .await?;
        let facts = fact_rows
            .iter()
            .map(|row| {
                let raw: String = row.try_get("evidence_json")?;
                Ok(PersonFactView {
                    id: row.try_get("id")?,
                    predicate: row.try_get("predicate")?,
                    value: row.try_get("value")?,
                    status: row.try_get("status")?,
                    evidence: serde_json::from_str(&raw).unwrap_or(Value::Null),
                    source_event_id: row.try_get("source_event_id")?,
                    speaker_observation_id: row.try_get("speaker_observation_id")?,
                    observed_at: row
                        .try_get::<Option<i64>, _>("observed_at_ms")?
                        .map(isotime::format_epoch_millis),
                    literal_evidence: row.try_get("literal_evidence")?,
                    confidence: row.try_get("confidence")?,
                    supersedes_id: row.try_get("supersedes_id")?,
                    created_at: required_timestamp(row, "created_at_ms")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let evidence = postgres_person_evidence(self, account_id, person_id, None, 100)
            .await?
            .evidence;
        let recent_statements = postgres_person_statements(self, account_id, person_id, None, 100)
            .await?
            .statements;
        Ok(PersonProfile {
            person,
            voice_labels,
            voice_coverage,
            aliases,
            facts,
            evidence,
            recent_statements,
        })
    }

    async fn person_evidence(
        &self,
        account_id: &str,
        person_id: i64,
        before_id: Option<i64>,
        limit: usize,
    ) -> Result<PersonEvidencePage> {
        if limit == 0 || limit > 100 {
            return Err(EnclaveError::InvalidRequest(
                "people page bounds are invalid".into(),
            ));
        }
        require_identified_person(self, account_id, person_id).await?;
        postgres_person_evidence(self, account_id, person_id, before_id, limit).await
    }

    async fn person_statements(
        &self,
        account_id: &str,
        person_id: i64,
        before_id: Option<i64>,
        limit: usize,
    ) -> Result<PersonStatementPage> {
        if limit == 0 || limit > 100 {
            return Err(EnclaveError::InvalidRequest(
                "people page bounds are invalid".into(),
            ));
        }
        require_identified_person(self, account_id, person_id).await?;
        postgres_person_statements(self, account_id, person_id, before_id, limit).await
    }
}

#[cfg(test)]
mod search_projection_tests {
    use super::*;

    fn episode_hit(id: i64, started_at: &str) -> SearchHit {
        SearchHit::Episode {
            id,
            memory_id: id,
            started_at: started_at.to_owned(),
            ended_at: started_at.to_owned(),
            title: None,
            summary: None,
            minute_summaries: json!([]),
            final_brief: None,
            snippet: None,
            match_source: Some("memory".into()),
            score: None,
        }
    }

    #[test]
    fn single_kind_search_preserves_relevance_order() {
        let hits = vec![
            episode_hit(1, "2026-01-01T00:00:00.000Z"),
            episode_hit(2, "2026-02-01T00:00:00.000Z"),
        ];
        let ordered = finalize_search_order(hits, 1, 10);
        assert_eq!(
            ordered.iter().map(search_hit_id).collect::<Vec<_>>(),
            [1, 2]
        );
    }
}
