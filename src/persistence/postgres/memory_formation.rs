use async_trait::async_trait;
use sqlx::Row;

use crate::{
    cp::{isotime, tokens},
    error::{EnclaveError, Result},
    persistence::{
        merge_minute_summaries, merge_substance, merge_visual_evidence, normalized_substance,
        normalized_visual_evidence, EpisodeEmbeddingSource, EpisodeEmbeddingWrite,
        MemoryFormationRepository, OpenEpisode, SummaryScreenshot, SummaryUtterance,
        SummaryWindowClaim, SummaryWindowSettlement,
    },
};

use super::{
    advisory_transaction_lock, allocate_content_id, duration_seconds, PostgresPersistence,
};

const OPEN_EPISODES_SQL: &str =
    "SELECT e.id,floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms,\
            floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms,\
            e.type,e.title,e.summary,e.participants::text AS participants,\
            e.action_items::text AS action_items,e.minutes_text,\
            count(*) FILTER (WHERE m.record_type='utterance')::bigint AS utterance_count,\
            count(*) FILTER (WHERE m.record_type='screenshot')::bigint AS screenshot_count \
       FROM episodes e JOIN memory_handles h \
         ON h.account_id=e.account_id AND h.episode_id=e.id AND h.state='active' \
       LEFT JOIN episode_members m \
         ON m.account_id=e.account_id AND m.episode_id=e.id \
      WHERE e.account_id=$1 AND e.structure_state='draft' AND e.finalized_at IS NULL \
        AND e.finalization_claim_token IS NULL \
        AND e.finalization_status NOT IN ('processing','deleting') \
        AND e.ended_at>=to_timestamp($2::double precision/1000.0) \
        AND e.started_at<=to_timestamp($3::double precision/1000.0) \
      GROUP BY e.account_id,e.id ORDER BY e.ended_at,e.id LIMIT $4";

const EXTENDABLE_EPISODE_SQL: &str =
    "SELECT e.id,e.minute_summaries::text AS minutes,e.substance,e.visual_evidence \
       FROM episodes e JOIN memory_handles h \
         ON h.account_id=e.account_id AND h.episode_id=e.id AND h.state='active' \
      WHERE e.account_id=$1 AND e.id=$2 AND e.structure_state='draft' \
        AND e.finalized_at IS NULL AND e.finalization_claim_token IS NULL \
        AND e.finalization_status NOT IN ('processing','deleting') \
      FOR UPDATE OF e,h";

fn timestamp(value: &str, field: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .ok_or_else(|| EnclaveError::InvalidRequest(format!("{field} is invalid")))
}

fn vector_literal(values: &[f32]) -> Result<String> {
    if values.len() != 384 || values.iter().any(|value| !value.is_finite()) {
        return Err(EnclaveError::Store(
            "episode embedding must contain 384 finite values".into(),
        ));
    }
    let mut output = String::with_capacity(values.len() * 12 + 2);
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&value.to_string());
    }
    output.push(']');
    Ok(output)
}

fn string_array(raw: Option<String>) -> Vec<String> {
    raw.and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default()
}

#[async_trait]
impl MemoryFormationRepository for PostgresPersistence {
    async fn ensure_reviewer_fixture(&self, account_id: &str) -> Result<bool> {
        let mut transaction = self.pool.begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND status='active')",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !active {
            return Err(EnclaveError::Auth("account inactive".into()));
        }
        let inserted = sqlx::query_scalar::<_, String>(
            "INSERT INTO reviewer_fixtures(account_id,fixture_version) VALUES($1,1) \
             ON CONFLICT(account_id) DO NOTHING RETURNING account_id",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !inserted {
            transaction.commit().await?;
            return Ok(false);
        }

        sqlx::query(
            "INSERT INTO audio_segments \
                (account_id,id,started_at,ended_at,duration_seconds,source_type,transcription_status) VALUES \
             ($1,910001,'2026-07-22T09:00:00Z','2026-07-22T09:35:00Z',2100,'mic','done'), \
             ($1,910002,'2026-07-22T10:15:00Z','2026-07-22T10:50:00Z',2100,'system','done'), \
             ($1,910003,'2026-07-22T14:00:00Z','2026-07-22T15:00:00Z',3600,'mic','done')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO utterances \
                (account_id,id,audio_segment_id,start_offset_seconds,end_offset_seconds,text,language,confidence,speaker_label,source_key) VALUES \
             ($1,920001,910001,90,104,'We agreed to move the Kioku launch from August 12 to August 19 so QA can finish the release checks.','en',0.99,'Maya','review:launch:decision'), \
             ($1,920002,910001,118,134,'Alex owns the launch checklist and will confirm the migration rehearsal by Friday.','en',0.99,'Maya','review:launch:action'), \
             ($1,920003,910002,240,263,'The stale dashboard came from a cache invalidation bug: the episode detail key was not cleared after an update.','en',0.99,'Me','review:cache:diagnosis'), \
             ($1,920004,910002,284,302,'The fix is to invalidate both the episode list and episode detail cache keys after a successful write.','en',0.99,'Me','review:cache:fix'), \
             ($1,920005,910003,300,326,'Use depuis for an action that began in the past and continues now; depuis is followed by the starting point or duration.','en',0.99,'Camille','review:french:depuis'), \
             ($1,920006,910003,690,714,'Use pendant for a completed duration. Practice contrasting depuis deux ans with pendant deux ans.','en',0.99,'Camille','review:french:pendant')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO screenshots \
                (account_id,id,captured_at,active_app,window_title,ocr_text,salient_ocr_text,url,image_hash,is_duplicate,source_key) VALUES \
             ($1,930001,'2026-07-22T11:20:00Z','Google Chrome','Vendor renewal checklist', \
              'Renewal checklist: review the synthetic agreement at https://example.com/renewal before August 1.', \
              'Renewal checklist at example.com/renewal','https://example.com/renewal', \
              'review-synthetic-renewal',false,'review:screen:renewal')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO episodes \
                (account_id,id,started_at,ended_at,type,title,summary,participants,languages,action_items,model,minute_summaries,minutes_text,substance,visual_evidence,finalized_at,finalization_version,finalization_status) VALUES \
             ($1,940001,'2026-07-22T09:00:00Z','2026-07-22T09:35:00Z','meeting','Launch planning and QA decision', \
              'The team moved the Kioku launch from August 12 to August 19 so QA could complete release checks. Alex owns the launch checklist.', \
              '[\"Maya\",\"Alex\",\"Me\"]','[\"en\"]','[\"Alex: confirm the migration rehearsal by Friday\",\"Complete the launch checklist before August 19\"]','synthetic-review','[]','Reviewed QA readiness. Moved launch to August 19. Assigned the checklist to Alex.','normal','none','2026-07-22T16:00:00Z',3,'complete'), \
             ($1,940002,'2026-07-22T10:15:00Z','2026-07-22T10:50:00Z','coding','Dashboard cache invalidation fix', \
              'Diagnosed stale episode details as an invalidation bug and updated the write path to clear list and detail cache keys.', \
              '[\"Me\"]','[\"en\"]','[\"Add a regression test for episode detail invalidation\"]','synthetic-review','[]','Reproduced stale dashboard state. Found the missing detail-key invalidation. Implemented the cache fix.','normal','none','2026-07-22T16:00:00Z',3,'complete'), \
             ($1,940003,'2026-07-22T11:18:00Z','2026-07-22T11:24:00Z','browsing','Vendor renewal page', \
              'Reviewed a synthetic vendor renewal checklist and its example.com renewal link.', \
              '[\"Me\"]','[\"en\"]','[\"Review the renewal checklist before August 1\"]','synthetic-review','[]','Opened the vendor renewal checklist at example.com/renewal.','normal','useful','2026-07-22T16:00:00Z',3,'complete'), \
             ($1,940004,'2026-07-22T14:00:00Z','2026-07-22T15:00:00Z','lesson','French lesson: depuis and pendant', \
              'Practiced the difference between depuis for continuing situations and pendant for completed durations.', \
              '[\"Camille\",\"Me\"]','[\"fr\",\"en\"]','[\"Practice five sentence pairs contrasting depuis and pendant\"]','synthetic-review','[]','Reviewed depuis for continuing actions. Contrasted depuis with pendant. Assigned practice.','normal','none','2026-07-22T16:00:00Z',3,'complete')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) VALUES \
             ($1,940001,'utterance',920001),($1,940001,'utterance',920002), \
             ($1,940002,'utterance',920003),($1,940002,'utterance',920004), \
             ($1,940003,'screenshot',930001),($1,940004,'utterance',920005), \
             ($1,940004,'utterance',920006)",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO episode_final_briefs \
                (account_id,episode_id,overview,decisions,action_items,important_links,open_questions) VALUES \
             ($1,940001,'The team delayed the Kioku launch by one week to finish QA.','[\"Move the launch from August 12 to August 19\"]','[{\"owner\":\"Alex\",\"task\":\"Confirm the migration rehearsal by Friday\"}]','[]','[]'), \
             ($1,940002,'The stale dashboard was traced to incomplete cache invalidation.','[\"Invalidate both episode list and detail keys after writes\"]','[{\"owner\":\"Me\",\"task\":\"Add a regression test for episode detail invalidation\"}]','[]','[]'), \
             ($1,940003,'Reviewed the synthetic vendor renewal checklist.','[]','[{\"owner\":\"Me\",\"task\":\"Review the renewal checklist before August 1\"}]','[{\"url\":\"https://example.com/renewal\",\"label\":\"Synthetic renewal checklist\"}]','[]'), \
             ($1,940004,'Practiced choosing depuis for continuing situations and pendant for completed durations.','[]','[{\"owner\":\"Me\",\"task\":\"Write five sentence pairs contrasting depuis and pendant\"}]','[]','[]')",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO content_id_counters(account_id,entity_kind,next_id) VALUES \
             ($1,'audio_segment',910004),($1,'utterance',920007), \
             ($1,'screenshot',930002),($1,'episodes',940005) \
             ON CONFLICT(account_id,entity_kind) DO UPDATE SET \
             next_id=greatest(content_id_counters.next_id,excluded.next_id)",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    async fn claim_summary_window(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        claimed_at: &str,
        lease_seconds: i64,
    ) -> Result<Option<SummaryWindowClaim>> {
        let from_ms = timestamp(from, "summary window start")?;
        let to_ms = timestamp(to, "summary window end")?;
        let claimed_ms = timestamp(claimed_at, "summary claim time")?;
        if to_ms <= from_ms || !(1..=3_600).contains(&lease_seconds) {
            return Err(EnclaveError::InvalidRequest(
                "summary window or lease is invalid".into(),
            ));
        }
        let claim_token = tokens::new_uuid();
        let row = sqlx::query(
            "INSERT INTO summary_window_claims(\
                 account_id,window_from,window_to,state,claim_token,claim_until,attempt_count,updated_at) \
             VALUES($1,to_timestamp($2::double precision/1000.0),\
                       to_timestamp($3::double precision/1000.0),'processing',$4,\
                       to_timestamp($5::double precision/1000.0)+make_interval(secs=>$6),1,\
                       to_timestamp($5::double precision/1000.0)) \
             ON CONFLICT(account_id) DO UPDATE SET \
                 window_from=excluded.window_from,window_to=excluded.window_to,state='processing',\
                 claim_token=excluded.claim_token,claim_until=excluded.claim_until,\
                 attempt_count=summary_window_claims.attempt_count+1,error_code=NULL,\
                 completed_claim_token=NULL,completed_at=NULL,updated_at=excluded.updated_at \
             WHERE summary_window_claims.state='retry_wait' \
                OR summary_window_claims.claim_until <= to_timestamp($5::double precision/1000.0) \
                OR (summary_window_claims.state='succeeded' AND \
                    (summary_window_claims.window_from<>excluded.window_from OR \
                     summary_window_claims.window_to<>excluded.window_to)) \
             RETURNING claim_token",
        )
        .bind(account_id)
        .bind(from_ms)
        .bind(to_ms)
        .bind(&claim_token)
        .bind(claimed_ms)
        .bind(duration_seconds(std::time::Duration::from_secs(
            u64::try_from(lease_seconds).map_err(|_| {
                EnclaveError::InvalidRequest("summary lease is invalid".into())
            })?,
        ))?)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|_| SummaryWindowClaim {
            account_id: account_id.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
            claim_token,
        }))
    }

    async fn release_summary_window(
        &self,
        claim: &SummaryWindowClaim,
        released_at: &str,
        error_code: Option<&str>,
    ) -> Result<()> {
        let released_ms = timestamp(released_at, "summary release time")?;
        let result = sqlx::query(
            "UPDATE summary_window_claims SET state='retry_wait',claim_token=NULL,\
                    claim_until=NULL,error_code=$3,updated_at=\
                    to_timestamp($4::double precision/1000.0) \
              WHERE account_id=$1 AND claim_token=$2 AND state='processing'",
        )
        .bind(&claim.account_id)
        .bind(&claim.claim_token)
        .bind(error_code)
        .bind(released_ms)
        .execute(self.pool())
        .await?;
        if result.rows_affected() != 1 {
            return Err(EnclaveError::Conflict(
                "summary window claim is no longer authoritative".into(),
            ));
        }
        Ok(())
    }

    async fn summary_evidence(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        utterance_limit: i64,
        screenshot_limit: i64,
    ) -> Result<(Vec<SummaryUtterance>, Vec<SummaryScreenshot>)> {
        let from_ms = timestamp(from, "summary evidence start")?;
        let to_ms = timestamp(to, "summary evidence end")?;
        if to_ms <= from_ms || utterance_limit <= 0 || screenshot_limit <= 0 {
            return Err(EnclaveError::InvalidRequest(
                "summary evidence bounds are invalid".into(),
            ));
        }
        let utterances = sqlx::query(
            "SELECT u.id,floor(extract(epoch FROM coalesce(\
                        o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')\
                    ))*1000)::bigint AS started_at_ms,\
                    u.speaker_label,u.language,u.text \
               FROM utterances u JOIN audio_segments s \
                 ON s.account_id=u.account_id AND s.id=u.audio_segment_id \
               LEFT JOIN speaker_observations o \
                 ON o.account_id=u.account_id AND o.id=u.speaker_observation_id \
              WHERE u.account_id=$1 \
                AND coalesce(o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')) \
                    >=to_timestamp($2::double precision/1000.0) \
                AND coalesce(o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')) \
                    <to_timestamp($3::double precision/1000.0) \
              ORDER BY coalesce(o.started_at,s.started_at + (u.start_offset_seconds * interval '1 second')),u.id \
              LIMIT $4",
        )
        .bind(account_id)
        .bind(from_ms)
        .bind(to_ms)
        .bind(utterance_limit)
        .fetch_all(self.pool())
        .await?
        .into_iter()
        .map(|row| {
            Ok(SummaryUtterance {
                id: row.try_get("id")?,
                started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
                speaker_label: row.try_get("speaker_label")?,
                language: row.try_get("language")?,
                text: row.try_get("text")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
        let screenshots = sqlx::query(
            "SELECT id,floor(extract(epoch FROM captured_at)*1000)::bigint AS captured_at_ms,\
                    active_app,window_title,left(ocr_text,4000) AS ocr_text,\
                    left(salient_ocr_text,4000) AS salient_ocr_text,url,is_duplicate \
               FROM screenshots WHERE account_id=$1 \
                AND captured_at>=to_timestamp($2::double precision/1000.0) \
                AND captured_at<to_timestamp($3::double precision/1000.0) \
              ORDER BY captured_at,id LIMIT $4",
        )
        .bind(account_id)
        .bind(from_ms)
        .bind(to_ms)
        .bind(screenshot_limit)
        .fetch_all(self.pool())
        .await?
        .into_iter()
        .map(|row| {
            Ok(SummaryScreenshot {
                id: row.try_get("id")?,
                captured_at: isotime::format_epoch_millis(row.try_get("captured_at_ms")?),
                active_app: row.try_get("active_app")?,
                window_title: row.try_get("window_title")?,
                ocr_text: row.try_get("ocr_text")?,
                salient_ocr_text: row.try_get("salient_ocr_text")?,
                url: row.try_get("url")?,
                is_duplicate: i64::from(row.try_get::<bool, _>("is_duplicate")?),
            })
        })
        .collect::<Result<Vec<_>>>()?;
        Ok((utterances, screenshots))
    }

    async fn open_episodes(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        limit: i64,
    ) -> Result<Vec<OpenEpisode>> {
        let from_ms = timestamp(from, "open episode start")?;
        let to_ms = timestamp(to, "open episode end")?;
        let rows = sqlx::query(OPEN_EPISODES_SQL)
            .bind(account_id)
            .bind(from_ms)
            .bind(to_ms)
            .bind(limit)
            .fetch_all(self.pool())
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(OpenEpisode {
                    id: row.try_get("id")?,
                    started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
                    ended_at: isotime::format_epoch_millis(row.try_get("ended_at_ms")?),
                    episode_type: row.try_get("type")?,
                    title: row
                        .try_get::<Option<String>, _>("title")?
                        .unwrap_or_else(|| "untitled".into()),
                    summary: row.try_get("summary")?,
                    participants: string_array(row.try_get("participants")?),
                    action_items: string_array(row.try_get("action_items")?),
                    recent_minutes: row.try_get("minutes_text")?,
                    utt_count: row.try_get("utterance_count")?,
                    scr_count: row.try_get("screenshot_count")?,
                })
            })
            .collect()
    }

    async fn settle_summary_window(&self, settlement: SummaryWindowSettlement) -> Result<Vec<i64>> {
        let mut transaction = self.pool().begin().await?;
        // The model may have selected an open draft before reconciliation
        // published. Share the account-local topology lock so the state check
        // below observes either the complete old topology or the complete new
        // one. A stale episode reference then allocates a fresh draft instead
        // of reopening a reconciled (or already finalized) memory.
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &settlement.claim.account_id,
        )
        .await?;
        let claimed = sqlx::query_scalar::<_, bool>(
            "SELECT true FROM summary_window_claims WHERE account_id=$1 \
              AND claim_token=$2 AND state='processing' FOR UPDATE",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.claim_token)
        .fetch_optional(&mut *transaction)
        .await?
        .unwrap_or(false);
        if !claimed {
            let from_ms = timestamp(&settlement.claim.from, "summary window start")?;
            let to_ms = timestamp(&settlement.claim.to, "summary window end")?;
            let replay_succeeded = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM summary_window_claims c \
                  WHERE c.account_id=$1 AND c.state='succeeded' \
                    AND c.completed_claim_token=$2 \
                    AND c.window_from=to_timestamp($3::double precision/1000.0) \
                    AND c.window_to=to_timestamp($4::double precision/1000.0))",
            )
            .bind(&settlement.claim.account_id)
            .bind(&settlement.claim.claim_token)
            .bind(from_ms)
            .bind(to_ms)
            .fetch_one(&mut *transaction)
            .await?;
            if replay_succeeded {
                let replay = sqlx::query_scalar::<_, i64>(
                    "SELECT episode_id FROM summary_window_results \
                      WHERE account_id=$1 \
                        AND window_from=to_timestamp($2::double precision/1000.0) \
                        AND window_to=to_timestamp($3::double precision/1000.0) \
                      ORDER BY ordinal",
                )
                .bind(&settlement.claim.account_id)
                .bind(from_ms)
                .bind(to_ms)
                .fetch_all(&mut *transaction)
                .await?;
                transaction.rollback().await?;
                return Ok(replay);
            }
            return Err(EnclaveError::Conflict(
                "summary window claim is no longer authoritative".into(),
            ));
        }

        let mut ids = Vec::with_capacity(settlement.episodes.len());
        for episode in &settlement.episodes {
            let existing = if let Some(id) = episode.id {
                sqlx::query(EXTENDABLE_EPISODE_SQL)
                    .bind(&settlement.claim.account_id)
                    .bind(id)
                    .fetch_optional(&mut *transaction)
                    .await?
            } else {
                None
            };
            let existing_id = existing.as_ref().map(|row| row.get::<i64, _>("id"));
            let existing_minutes = existing
                .as_ref()
                .and_then(|row| row.try_get::<Option<String>, _>("minutes").ok().flatten());
            let existing_substance = existing
                .as_ref()
                .and_then(|row| row.try_get::<String, _>("substance").ok());
            let existing_visual = existing
                .as_ref()
                .and_then(|row| row.try_get::<String, _>("visual_evidence").ok());
            let merged_minutes = merge_minute_summaries(
                existing_minutes.as_deref(),
                episode.minute_summaries.as_deref().unwrap_or(&[]),
            );
            let (minutes_json, minutes_text) =
                merged_minutes.unwrap_or_else(|| ("[]".into(), String::new()));
            let substance = if existing_id.is_some() {
                merge_substance(existing_substance.as_deref(), episode.substance.as_deref())
            } else {
                normalized_substance(episode.substance.as_deref())
            };
            let visual_evidence = if existing_id.is_some() {
                merge_visual_evidence(
                    existing_visual.as_deref(),
                    episode.visual_evidence.as_deref(),
                )
            } else {
                normalized_visual_evidence(episode.visual_evidence.as_deref())
            };
            let id = existing_id.unwrap_or(
                allocate_content_id(&mut transaction, &settlement.claim.account_id, "episodes")
                    .await?,
            );
            let started_ms = timestamp(&episode.started_at, "episode start")?;
            let ended_ms = timestamp(&episode.ended_at, "episode end")?;
            if ended_ms < started_ms {
                return Err(EnclaveError::InvalidRequest(
                    "episode end precedes its start".into(),
                ));
            }
            let participants =
                serde_json::to_string(episode.participants.as_deref().unwrap_or_default())?;
            let languages =
                serde_json::to_string(episode.languages.as_deref().unwrap_or_default())?;
            let action_items =
                serde_json::to_string(episode.action_items.as_deref().unwrap_or_default())?;
            sqlx::query(
                "INSERT INTO episodes(\
                    account_id,id,started_at,ended_at,type,title,summary,participants,languages,\
                    action_items,model,minute_summaries,minutes_text,substance,visual_evidence,updated_at) \
                 VALUES($1,$2,to_timestamp($3::double precision/1000.0),\
                        to_timestamp($4::double precision/1000.0),$5,$6,$7,$8::jsonb,$9::jsonb,\
                        $10::jsonb,$11,$12::jsonb,$13,$14,$15,now()) \
                 ON CONFLICT(account_id,id) DO UPDATE SET started_at=excluded.started_at,\
                    ended_at=excluded.ended_at,type=excluded.type,title=excluded.title,\
                    summary=excluded.summary,participants=excluded.participants,\
                    languages=excluded.languages,action_items=excluded.action_items,\
                    model=excluded.model,minute_summaries=excluded.minute_summaries,\
                    minutes_text=excluded.minutes_text,substance=excluded.substance,\
                    visual_evidence=excluded.visual_evidence,updated_at=now()",
            )
            .bind(&settlement.claim.account_id)
            .bind(id)
            .bind(started_ms)
            .bind(ended_ms)
            .bind(&episode.episode_type)
            .bind(&episode.title)
            .bind(&episode.summary)
            .bind(participants)
            .bind(languages)
            .bind(action_items)
            .bind(&episode.model)
            .bind(minutes_json)
            .bind(minutes_text)
            .bind(substance)
            .bind(visual_evidence)
            .execute(&mut *transaction)
            .await?;
            for member_id in &episode.member_utterance_ids {
                sqlx::query(
                    "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
                     SELECT $1,$2,'utterance',$3 WHERE EXISTS(\
                       SELECT 1 FROM utterances WHERE account_id=$1 AND id=$3) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&settlement.claim.account_id)
                .bind(id)
                .bind(member_id)
                .execute(&mut *transaction)
                .await?;
            }
            for member_id in &episode.member_screenshot_ids {
                sqlx::query(
                    "INSERT INTO episode_members(account_id,episode_id,record_type,record_id) \
                     SELECT $1,$2,'screenshot',$3 WHERE EXISTS(\
                       SELECT 1 FROM screenshots WHERE account_id=$1 AND id=$3) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&settlement.claim.account_id)
                .bind(id)
                .bind(member_id)
                .execute(&mut *transaction)
                .await?;
            }
            ids.push(id);
        }
        let window_from_ms = timestamp(&settlement.claim.from, "summary window start")?;
        let window_to_ms = timestamp(&settlement.claim.to, "summary window end")?;
        for (ordinal, episode_id) in ids.iter().enumerate() {
            sqlx::query(
                "INSERT INTO summary_window_results(\
                    account_id,window_from,window_to,ordinal,episode_id) \
                 VALUES($1,to_timestamp($2::double precision/1000.0),\
                        to_timestamp($3::double precision/1000.0),$4,$5)",
            )
            .bind(&settlement.claim.account_id)
            .bind(window_from_ms)
            .bind(window_to_ms)
            .bind(
                i64::try_from(ordinal)
                    .map_err(|_| EnclaveError::Store("summary result ordinal overflow".into()))?,
            )
            .bind(episode_id)
            .execute(&mut *transaction)
            .await?;
        }
        if let Some(cursor) = settlement.cursor.as_deref() {
            let cursor_ms = timestamp(cursor, "summary cursor")?;
            sqlx::query(
                "UPDATE accounts SET summarized_until=GREATEST(\
                    coalesce(summarized_until,'epoch'::timestamptz),\
                    to_timestamp($2::double precision/1000.0)),updated_at=now() WHERE id=$1",
            )
            .bind(&settlement.claim.account_id)
            .bind(cursor_ms)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE summary_window_claims SET state='succeeded',\
                    completed_claim_token=claim_token,claim_token=NULL,claim_until=NULL,\
                    error_code=NULL,completed_at=now(),updated_at=now() \
              WHERE account_id=$1 AND claim_token=$2",
        )
        .bind(&settlement.claim.account_id)
        .bind(&settlement.claim.claim_token)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ids)
    }

    async fn episode_embedding_sources(
        &self,
        account_id: &str,
        ids: &[i64],
    ) -> Result<Vec<EpisodeEmbeddingSource>> {
        let rows = sqlx::query(
            "SELECT e.id,concat_ws(E'\\n',e.title,e.summary,e.minutes_text,fb.overview, \
                    (SELECT string_agg(value #>> '{}',E'\\n' ORDER BY ordinal) \
                       FROM jsonb_path_query( \
                         fb.decisions||fb.action_items||fb.important_links||fb.open_questions, \
                         'strict $.** ? (@.type() == \"string\")' \
                       ) WITH ORDINALITY AS strings(value,ordinal))) AS text \
               FROM episodes e LEFT JOIN episode_final_briefs fb \
                 ON fb.account_id=e.account_id AND fb.episode_id=e.id \
              WHERE e.account_id=$1 AND e.id=ANY($2) ORDER BY e.id",
        )
        .bind(account_id)
        .bind(ids)
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .filter_map(|row| {
                let text = row.try_get::<String, _>("text").ok()?;
                if text.trim().is_empty() {
                    return None;
                }
                Some(Ok(EpisodeEmbeddingSource {
                    id: row.get("id"),
                    text,
                }))
            })
            .collect()
    }

    async fn write_episode_embeddings(
        &self,
        account_id: &str,
        writes: &[EpisodeEmbeddingWrite],
    ) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        for write in writes {
            sqlx::query("UPDATE episodes SET embedding=$3::vector,updated_at=now() WHERE account_id=$1 AND id=$2")
                .bind(account_id)
                .bind(write.id)
                .bind(vector_literal(&write.embedding)?)
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn session_tail_is_settled(&self, account_id: &str, recent_after: &str) -> Result<bool> {
        let recent_after_ms = timestamp(recent_after, "recent session cutoff")?;
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT NOT EXISTS(SELECT 1 FROM capture_sessions WHERE account_id=$1 \
                    AND ended_at IS NULL AND last_event_at>=to_timestamp($2::double precision/1000.0)) \
                AND NOT EXISTS(SELECT 1 FROM media_objects WHERE account_id=$1 \
                    AND processing_state IN ('queued','processing','retry_wait') AND deleted_at IS NULL)",
        )
        .bind(account_id)
        .bind(recent_after_ms)
        .fetch_one(self.pool())
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{EXTENDABLE_EPISODE_SQL, OPEN_EPISODES_SQL};

    fn requires_active_unfinalized_draft(query: &str) {
        assert!(query.contains("JOIN memory_handles h"));
        assert!(query.contains("h.state='active'"));
        assert!(query.contains("structure_state='draft'"));
        assert!(query.contains("finalized_at IS NULL"));
        assert!(query.contains("finalization_claim_token IS NULL"));
        assert!(query.contains("finalization_status NOT IN ('processing','deleting')"));
    }

    #[test]
    fn open_episode_projection_exposes_only_extendable_drafts() {
        requires_active_unfinalized_draft(OPEN_EPISODES_SQL);
    }

    #[test]
    fn stale_episode_reference_cannot_reopen_reconciled_memory() {
        requires_active_unfinalized_draft(EXTENDABLE_EPISODE_SQL);
        assert!(EXTENDABLE_EPISODE_SQL.contains("FOR UPDATE OF e,h"));
    }
}
