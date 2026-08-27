use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::{json, Value};
use sqlx::Row;

use crate::{
    cp::{isotime, tokens},
    error::{EnclaveError, Result},
    persistence::{
        FinalizationClaim, FinalizationEpisode, FinalizationRepository, FinalizationScreenshot,
        FinalizationSettlement, FinalizationUtterance,
    },
};

use super::{duration_seconds, PostgresPersistence};

fn timestamp(value: &str, field: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .ok_or_else(|| EnclaveError::InvalidRequest(format!("{field} is invalid")))
}

fn json_value(raw: Option<String>) -> Value {
    raw.and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or(Value::Null)
}

fn optional_timestamp(row: &sqlx::postgres::PgRow, name: &str) -> Result<Option<String>> {
    Ok(row
        .try_get::<Option<i64>, _>(name)?
        .map(isotime::format_epoch_millis))
}

async fn replay_delivery_count(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    episode_id: i64,
    version: i64,
) -> Result<usize> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT (SELECT count(*) FROM webhook_deliveries WHERE account_id=$1 \
                    AND episode_id=$2 AND delivery_version=$3) + \
                (SELECT count(*) FROM email_deliveries WHERE account_id=$1 \
                    AND episode_id=$2 AND delivery_version=$3) + \
                (SELECT count(*) FROM push_deliveries WHERE account_id=$1 \
                    AND episode_id=$2 AND delivery_version=$3)",
    )
    .bind(account_id)
    .bind(episode_id)
    .bind(version)
    .fetch_one(&mut **transaction)
    .await?;
    usize::try_from(count)
        .map_err(|_| EnclaveError::Store("finalization delivery count overflow".into()))
}

#[async_trait]
impl FinalizationRepository for PostgresPersistence {
    async fn claim_finalization(
        &self,
        account_id: &str,
        target_episode_id: Option<i64>,
        now: &str,
        horizon_before: &str,
        finalization_version: i64,
        lease_seconds: i64,
    ) -> Result<Option<FinalizationClaim>> {
        let now_ms = timestamp(now, "finalization claim time")?;
        let horizon_ms = timestamp(horizon_before, "finalization horizon")?;
        if finalization_version <= 0 || !(1..=3_600).contains(&lease_seconds) {
            return Err(EnclaveError::InvalidRequest(
                "finalization version or lease is invalid".into(),
            ));
        }
        let token = tokens::new_uuid();
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "WITH candidate AS (\
                SELECT e.id FROM episodes e JOIN accounts a ON a.id=e.account_id \
                 WHERE e.account_id=$1 AND a.status='active' AND e.substance!='none' \
                   AND ($2::bigint IS NULL OR e.id=$2) \
                   AND e.ended_at<to_timestamp($3::double precision/1000.0) \
                   AND a.summarized_until>=e.ended_at+interval '4 hours' \
                   AND (e.finalization_claim_token IS NULL \
                        OR e.finalization_claim_until<=to_timestamp($4::double precision/1000.0)) \
                   AND (e.finalized_at IS NULL \
                        OR coalesce(e.finalization_version,0)<$5 \
                        OR e.finalized_identity_revision<e.identity_revision) \
                   AND ($2::bigint IS NOT NULL OR (e.finalization_status!='failed_terminal' \
                        AND (e.finalization_next_attempt_at IS NULL \
                             OR e.finalization_next_attempt_at<=to_timestamp($4::double precision/1000.0)))) \
                 ORDER BY e.ended_at,e.id FOR UPDATE SKIP LOCKED LIMIT 1) \
             UPDATE episodes e SET finalization_claim_token=$6,\
                    finalization_claim_until=to_timestamp($4::double precision/1000.0)+\
                        make_interval(secs=>$7),finalization_status='processing',\
                    finalization_error=NULL,finalization_attempted_at=\
                        to_timestamp($4::double precision/1000.0),updated_at=\
                        to_timestamp($4::double precision/1000.0) \
               FROM candidate c WHERE e.account_id=$1 AND e.id=c.id \
             RETURNING e.id,floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms,\
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms,\
                    e.type,e.title,e.summary,e.participants::text AS participants,\
                    e.languages::text AS languages,e.action_items::text AS action_items,e.model,\
                    e.identity_revision,e.finalization_attempt_count",
        )
        .bind(account_id)
        .bind(target_episode_id)
        .bind(horizon_ms)
        .bind(now_ms)
        .bind(finalization_version)
        .bind(&token)
        .bind(duration_seconds(std::time::Duration::from_secs(
            u64::try_from(lease_seconds).map_err(|_| {
                EnclaveError::InvalidRequest("finalization lease is invalid".into())
            })?,
        ))?)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let episode_id: i64 = row.try_get("id")?;
        let episode = FinalizationEpisode {
            id: episode_id,
            started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
            ended_at: isotime::format_epoch_millis(row.try_get("ended_at_ms")?),
            episode_type: row.try_get("type")?,
            title: row
                .try_get::<Option<String>, _>("title")?
                .unwrap_or_default(),
            summary: row.try_get("summary")?,
            participants: row.try_get("participants")?,
            languages: row.try_get("languages")?,
            action_items: row.try_get("action_items")?,
            model: row.try_get("model")?,
        };
        let input_identity_revision: i64 = row.try_get("identity_revision")?;
        let attempt_count: i64 = row.try_get("finalization_attempt_count")?;
        let utterances = sqlx::query(
            "SELECT u.id,\
                    floor(extract(epoch FROM (a.started_at + \
                        make_interval(secs=>u.start_offset_seconds)))*1000)::bigint AS at_ms,\
                    u.speaker_label,a.source_type,u.text \
               FROM episode_members m JOIN utterances u \
                 ON u.account_id=m.account_id AND u.id=m.record_id \
               JOIN audio_segments a ON a.account_id=u.account_id AND a.id=u.audio_segment_id \
              WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='utterance' \
              ORDER BY a.started_at,u.start_offset_seconds,u.id",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| {
            let at_ms = row.try_get("at_ms")?;
            Ok(FinalizationUtterance {
                id: row.try_get("id")?,
                at: isotime::format_epoch_millis(at_ms),
                at_ms,
                speaker: row.try_get("speaker_label")?,
                source_type: row.try_get("source_type")?,
                text: row.try_get("text")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
        let screenshots = sqlx::query(
            "SELECT s.id,floor(extract(epoch FROM s.captured_at)*1000)::bigint AS captured_at_ms,\
                    s.active_app,s.window_title,s.url,s.ocr_text,s.salient_ocr_text,s.is_duplicate,\
                    s.source_key,s.capture_status,\
                    floor(extract(epoch FROM s.visible_until)*1000)::bigint AS visible_until_ms,\
                    s.display_id,s.primary_bundle_id,s.visible_windows::text AS visible_windows,\
                    s.visual_signals::text AS visual_signals,bs.tabs_json::text AS browser_tabs,\
                    bs.browser_name,bs.permission_status \
               FROM episode_members m JOIN screenshots s \
                 ON s.account_id=m.account_id AND s.id=m.record_id \
               LEFT JOIN browser_states_v2 bs ON bs.account_id=s.account_id \
                 AND bs.state_key=s.browser_snapshot_source_key \
              WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='screenshot' \
              ORDER BY s.captured_at,s.id",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| {
            let screenshot_id: i64 = row.try_get("id")?;
            let captured_at_ms = row.try_get("captured_at_ms")?;
            let browser_tabs = json_value(row.try_get("browser_tabs")?);
            let browser_context = if browser_tabs.is_null() {
                Value::Null
            } else {
                json!({
                    "browser_name": row.try_get::<Option<String>, _>("browser_name")?,
                    "permission_status": row.try_get::<Option<String>, _>("permission_status")?,
                    "tabs": browser_tabs,
                })
            };
            Ok(FinalizationScreenshot {
                id: screenshot_id,
                captured_at: isotime::format_epoch_millis(captured_at_ms),
                captured_at_ms,
                active_app: row.try_get("active_app")?,
                window_title: row.try_get("window_title")?,
                url: row.try_get("url")?,
                ocr_text: row.try_get("ocr_text")?,
                salient_ocr_text: row.try_get("salient_ocr_text")?,
                is_duplicate: row.try_get("is_duplicate")?,
                elided: false,
                source_key: row
                    .try_get::<Option<String>, _>("source_key")?
                    .unwrap_or_else(|| format!("postgres:{episode_id}:{screenshot_id}")),
                capture_status: row
                    .try_get::<Option<String>, _>("capture_status")?
                    .unwrap_or_else(|| "stable".into()),
                visible_until: optional_timestamp(&row, "visible_until_ms")?,
                display_id: row.try_get("display_id")?,
                primary_bundle_id: row.try_get("primary_bundle_id")?,
                visible_windows: json_value(row.try_get("visible_windows")?),
                browser_context,
                visual_signals: json_value(row.try_get("visual_signals")?),
                literal_description: None,
                activity_summary: None,
                relevance_reason: None,
                milestone_type: None,
                key_rank: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
        transaction.commit().await?;
        Ok(Some(FinalizationClaim {
            account_id: account_id.to_owned(),
            claim_token: token,
            episode,
            utterances,
            screenshots,
            input_identity_revision,
            attempt_count,
        }))
    }

    async fn defer_finalization(
        &self,
        claim: &FinalizationClaim,
        status: &str,
        error_code: Option<&str>,
        retry_at: Option<&str>,
        deferred_at: &str,
        count_attempt: bool,
    ) -> Result<()> {
        let allowed = [
            "retry_wait",
            "budget_wait",
            "failed_terminal",
            "pending_watermark",
        ];
        if !allowed.contains(&status) {
            return Err(EnclaveError::InvalidRequest(
                "finalization defer status is invalid".into(),
            ));
        }
        let deferred_ms = timestamp(deferred_at, "finalization defer time")?;
        let retry_ms = retry_at
            .map(|value| timestamp(value, "finalization retry time"))
            .transpose()?;
        let changed = sqlx::query(
            "UPDATE episodes SET finalization_status=$3,finalization_error=$4,\
                    finalization_attempt_count=finalization_attempt_count+\
                        CASE WHEN $8 THEN 1 ELSE 0 END,\
                    finalization_next_attempt_at=CASE WHEN $5::bigint IS NULL THEN NULL \
                        ELSE to_timestamp($5::double precision/1000.0) END,\
                    finalization_claim_token=NULL,finalization_claim_until=NULL,\
                    updated_at=to_timestamp($6::double precision/1000.0) \
              WHERE account_id=$1 AND id=$2 AND finalization_claim_token=$7",
        )
        .bind(&claim.account_id)
        .bind(claim.episode.id)
        .bind(status)
        .bind(error_code.map(|value| value.chars().take(1_000).collect::<String>()))
        .bind(retry_ms)
        .bind(deferred_ms)
        .bind(&claim.claim_token)
        .bind(count_attempt)
        .execute(self.pool())
        .await?;
        if changed.rows_affected() != 1 {
            return Err(EnclaveError::Conflict(
                "finalization claim is no longer authoritative".into(),
            ));
        }
        Ok(())
    }

    async fn settle_finalization(&self, result: FinalizationSettlement) -> Result<usize> {
        let mut transaction = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT finalized_at IS NULL AS is_initial,finalization_version,identity_revision,\
                    finalization_claim_token,finalization_completed_claim_token \
               FROM episodes WHERE account_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(&result.claim.account_id)
        .bind(result.claim.episode.id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Store("episode disappeared during finalization".into()))?;
        let completed_token: Option<String> = row.try_get("finalization_completed_claim_token")?;
        if completed_token.as_deref() == Some(result.claim.claim_token.as_str()) {
            let count = replay_delivery_count(
                &mut transaction,
                &result.claim.account_id,
                result.claim.episode.id,
                result.finalization_version,
            )
            .await?;
            transaction.rollback().await?;
            return Ok(count);
        }
        let current_token: Option<String> = row.try_get("finalization_claim_token")?;
        if current_token.as_deref() != Some(result.claim.claim_token.as_str()) {
            return Err(EnclaveError::Conflict(
                "finalization claim is no longer authoritative".into(),
            ));
        }
        let identity_revision: i64 = row.try_get("identity_revision")?;
        if identity_revision != result.claim.input_identity_revision {
            sqlx::query(
                "UPDATE episodes SET identity_refresh_status='queued',\
                    finalization_status='pending_identity',finalization_claim_token=NULL,\
                    finalization_claim_until=NULL,updated_at=now() WHERE account_id=$1 AND id=$2",
            )
            .bind(&result.claim.account_id)
            .bind(result.claim.episode.id)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(0);
        }
        let current_utterances: HashSet<i64> = sqlx::query_scalar(
            "SELECT record_id FROM episode_members WHERE account_id=$1 AND episode_id=$2 \
                AND record_type='utterance'",
        )
        .bind(&result.claim.account_id)
        .bind(result.claim.episode.id)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .collect();
        let current_screenshots: HashSet<i64> = sqlx::query_scalar(
            "SELECT record_id FROM episode_members WHERE account_id=$1 AND episode_id=$2 \
                AND record_type='screenshot'",
        )
        .bind(&result.claim.account_id)
        .bind(result.claim.episode.id)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .collect();
        let claimed_utterances = result
            .claim
            .utterances
            .iter()
            .map(|row| row.id)
            .collect::<HashSet<_>>();
        let claimed_screenshots = result
            .claim
            .screenshots
            .iter()
            .map(|row| row.id)
            .collect::<HashSet<_>>();
        if current_utterances != claimed_utterances || current_screenshots != claimed_screenshots {
            return Err(EnclaveError::Conflict(
                "episode membership changed during finalization".into(),
            ));
        }
        let initial: bool = row.try_get("is_initial")?;

        sqlx::query(
            "DELETE FROM episode_screen_interpretations WHERE account_id=$1 AND episode_id=$2",
        )
        .bind(&result.claim.account_id)
        .bind(result.claim.episode.id)
        .execute(&mut *transaction)
        .await?;
        for screen in &result.ranked_screens {
            sqlx::query(
                "INSERT INTO screen_observations(\
                    account_id,screenshot_id,input_revision,observation_version,status,\
                    generation_method,literal_description,screen_state,content_type,\
                    visible_text_summary,notable_items,model_name,prompt_version,completed_at) \
                 VALUES($1,$2,$3,$4,'ready','episode_model',$5,$6,$7,$8,$9::jsonb,$10,$11,now()) \
                 ON CONFLICT(account_id,screenshot_id) DO UPDATE SET \
                    input_revision=excluded.input_revision,observation_version=excluded.observation_version,\
                    status='ready',generation_method='episode_model',\
                    literal_description=excluded.literal_description,screen_state=excluded.screen_state,\
                    content_type=excluded.content_type,visible_text_summary=excluded.visible_text_summary,\
                    notable_items=excluded.notable_items,model_name=excluded.model_name,\
                    prompt_version=excluded.prompt_version,completed_at=now()",
            )
            .bind(&result.claim.account_id)
            .bind(screen.screenshot_id)
            .bind(&screen.observation_revision)
            .bind(result.observation_version)
            .bind(&screen.literal_description)
            .bind(&screen.screen_state)
            .bind(&screen.content_type)
            .bind(&screen.visible_text_summary)
            .bind(&screen.notable_items_json)
            .bind(&result.model_name)
            .bind(result.observation_prompt_version)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO episode_screen_interpretations(\
                    account_id,episode_id,screenshot_id,episode_revision,interpretation_version,\
                    status,activity_summary,relevance_level,relevance_reason,milestone_type,\
                    base_score,key_rank,is_key_screen,semantic_group,model_name,prompt_version,\
                    completed_at,updated_at) \
                 VALUES($1,$2,$3,$4,$5,'ready',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now(),now())",
            )
            .bind(&result.claim.account_id)
            .bind(result.claim.episode.id)
            .bind(screen.screenshot_id)
            .bind(&result.analysis_revision)
            .bind(result.interpretation_version)
            .bind(&screen.activity_summary)
            .bind(screen.relevance_level)
            .bind(&screen.relevance_reason)
            .bind(&screen.milestone_type)
            .bind(screen.base_score)
            .bind(screen.key_rank)
            .bind(screen.is_key_screen)
            .bind(&screen.semantic_group)
            .bind(&result.model_name)
            .bind(result.interpretation_prompt_version)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO episode_final_briefs(\
                account_id,episode_id,overview,decisions,action_items,important_links,open_questions) \
             VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7::jsonb) \
             ON CONFLICT(account_id,episode_id) DO UPDATE SET overview=excluded.overview,\
                decisions=excluded.decisions,action_items=excluded.action_items,\
                important_links=excluded.important_links,open_questions=excluded.open_questions,\
                created_at=now()",
        )
        .bind(&result.claim.account_id)
        .bind(result.claim.episode.id)
        .bind(&result.overview)
        .bind(&result.decisions_json)
        .bind(&result.action_items_json)
        .bind(&result.important_links_json)
        .bind(&result.open_questions_json)
        .execute(&mut *transaction)
        .await?;

        let mut deliveries = 0usize;
        if initial {
            for (subscription_id, event_id) in &result.webhook_destinations {
                deliveries += usize::from(
                    sqlx::query(
                        "INSERT INTO webhook_deliveries(\
                            account_id,episode_id,subscription_id,delivery_version,event_id,state) \
                         VALUES($1,$2,$3,$4,$5,'pending') ON CONFLICT DO NOTHING",
                    )
                    .bind(&result.claim.account_id)
                    .bind(result.claim.episode.id)
                    .bind(subscription_id)
                    .bind(result.finalization_version)
                    .bind(event_id)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
                        > 0,
                );
            }
            if let Some(include_content) = result.email_preference_include_content {
                let delivery_id = format!("deliv_{}", tokens::random_token_hex());
                deliveries += usize::from(
                    sqlx::query(
                        "INSERT INTO email_deliveries(\
                            account_id,episode_id,delivery_version,delivery_id,include_content,state) \
                         VALUES($1,$2,$3,$4,$5,'pending') ON CONFLICT DO NOTHING",
                    )
                    .bind(&result.claim.account_id)
                    .bind(result.claim.episode.id)
                    .bind(result.finalization_version)
                    .bind(delivery_id)
                    .bind(include_content)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
                        > 0,
                );
            }
            for (binding, delivery_id, handoff_handle, collapse_id) in &result.push_destinations {
                deliveries += usize::from(
                    sqlx::query(
                        "INSERT INTO push_deliveries(\
                            account_id,episode_id,installation_binding,delivery_version,delivery_id,\
                            handoff_handle,collapse_id,state) \
                         VALUES($1,$2,$3,$4,$5,$6,$7,'pending') ON CONFLICT DO NOTHING",
                    )
                    .bind(&result.claim.account_id)
                    .bind(result.claim.episode.id)
                    .bind(binding)
                    .bind(result.finalization_version)
                    .bind(delivery_id)
                    .bind(handoff_handle)
                    .bind(collapse_id)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
                        > 0,
                );
            }
        }
        sqlx::query(
            "UPDATE episodes SET title=CASE WHEN length($3)>0 THEN $3 ELSE title END,\
                    summary=CASE WHEN length($4)>0 THEN $4 ELSE summary END,\
                    minute_summaries=$5::jsonb,minutes_text=$6,action_items=$7::jsonb,\
                    finalized_at=coalesce(finalized_at,now()),finalization_version=$8,\
                    finalization_status='complete',finalization_error=NULL,\
                    finalization_attempt_count=0,finalization_next_attempt_at=NULL,\
                    finalized_identity_revision=$9,identity_refresh_status='ready',\
                    finalization_completed_claim_token=finalization_claim_token,\
                    finalization_claim_token=NULL,finalization_claim_until=NULL,\
                    finalization_vertex_event_id=$10,finalization_analysis_revision=$11,updated_at=now() \
              WHERE account_id=$1 AND id=$2",
        )
        .bind(&result.claim.account_id)
        .bind(result.claim.episode.id)
        .bind(&result.title)
        .bind(&result.summary)
        .bind(&result.minute_summaries_json)
        .bind(&result.minutes_text)
        .bind(&result.action_items_json)
        .bind(result.finalization_version)
        .bind(result.claim.input_identity_revision)
        .bind(&result.vertex_event_id)
        .bind(&result.analysis_revision)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(deliveries)
    }
}
