use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};

use crate::{
    cp::{isotime, tokens},
    error::{EnclaveError, Result},
    persistence::{
        FinalizationClaim, FinalizationClaimRequest, FinalizationEgressGuard, FinalizationEpisode,
        FinalizationRepository, FinalizationRequest, FinalizationScreenshot,
        FinalizationSettlement, FinalizationUtterance,
    },
};

use super::{
    activation::finalization_requires_reconciled, advisory_transaction_lock, duration_seconds,
    PostgresPersistence,
};

struct PostgresFinalizationEgressGuard {
    transaction: Option<Transaction<'static, Postgres>>,
}

#[async_trait]
impl FinalizationEgressGuard for PostgresFinalizationEgressGuard {
    async fn release(mut self: Box<Self>) -> Result<()> {
        let transaction = self.transaction.take().ok_or_else(|| {
            EnclaveError::Store("finalization egress guard was already released".into())
        })?;
        transaction.commit().await?;
        Ok(())
    }
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
    async fn request_finalization(
        &self,
        account_id: &str,
        episode_id: i64,
        finalization_version: i64,
    ) -> Result<FinalizationRequest> {
        if finalization_version <= 0 {
            return Err(EnclaveError::InvalidRequest(
                "finalization version is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let require_reconciled =
            finalization_requires_reconciled(&mut transaction, account_id).await?;
        let row = sqlx::query(
            "SELECT substance,structure_state,finalized_at IS NOT NULL AS finalized,\
                    coalesce(finalization_version,0) AS version,finalization_status \
               FROM episodes WHERE account_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.rollback().await?;
            return Ok(FinalizationRequest::NotFound);
        };
        let status: String = row.try_get("finalization_status")?;
        if require_reconciled && row.try_get::<String, _>("structure_state")? != "reconciled" {
            transaction.rollback().await?;
            return Ok(FinalizationRequest::AwaitingReconciliation);
        }
        if row.try_get::<String, _>("substance")? == "none" {
            transaction.rollback().await?;
            return Ok(FinalizationRequest::LowSignal);
        }
        if row.try_get::<bool, _>("finalized")?
            && row.try_get::<i64, _>("version")? >= finalization_version
        {
            transaction.rollback().await?;
            return Ok(FinalizationRequest::AlreadyComplete { status });
        }
        if matches!(status.as_str(), "queued" | "processing") {
            transaction.rollback().await?;
            return Ok(FinalizationRequest::AlreadyQueued { status });
        }
        sqlx::query(
            "UPDATE episodes SET finalization_status='queued',finalization_error=NULL,\
                    finalization_attempt_count=0,finalization_next_attempt_at=NULL,\
                    finalization_claim_token=NULL,finalization_claim_until=NULL,updated_at=clock_timestamp() \
              WHERE account_id=$1 AND id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(FinalizationRequest::Queued)
    }

    async fn claim_finalization(
        &self,
        request: FinalizationClaimRequest<'_>,
    ) -> Result<Option<FinalizationClaim>> {
        let FinalizationClaimRequest {
            account_id,
            target_episode_id,
            quiet_horizon_seconds,
            finalization_version,
            lease_seconds,
        } = request;
        if finalization_version <= 0
            || !(1..=7 * 24 * 60 * 60).contains(&quiet_horizon_seconds)
            || !(1..=3_600).contains(&lease_seconds)
        {
            return Err(EnclaveError::InvalidRequest(
                "finalization version, quiet horizon, or lease is invalid".into(),
            ));
        }
        let token = tokens::new_uuid();
        let mut transaction = self.pool().begin().await?;
        let require_reconciled =
            finalization_requires_reconciled(&mut transaction, account_id).await?;
        let row = sqlx::query(
            "WITH candidate AS (\
                SELECT e.id FROM episodes e JOIN accounts a ON a.id=e.account_id \
                 WHERE e.account_id=$1 AND a.status='active' AND e.substance!='none' \
                   AND e.finalization_status!='deleting' \
                   AND (NOT $7::bool OR e.structure_state='reconciled') \
                   AND ($2::bigint IS NULL OR e.id=$2) \
                   AND e.ended_at<clock_timestamp()-make_interval(secs=>$3) \
                   AND a.summarized_until>=e.ended_at+interval '4 hours' \
                   AND (e.finalization_claim_token IS NULL \
                        OR e.finalization_claim_until<=clock_timestamp()) \
                   AND (e.finalized_at IS NULL \
                        OR coalesce(e.finalization_version,0)<$4 \
                        OR e.finalized_identity_revision<e.identity_revision) \
                   AND ($2::bigint IS NOT NULL OR (e.finalization_status!='failed_terminal' \
                        AND (e.finalization_next_attempt_at IS NULL \
                             OR e.finalization_next_attempt_at<=clock_timestamp()))) \
                 ORDER BY e.ended_at,e.id FOR UPDATE SKIP LOCKED LIMIT 1) \
             UPDATE episodes e SET finalization_claim_token=$5,\
                    finalization_claim_until=clock_timestamp()+\
                        make_interval(secs=>$6),finalization_status='processing',\
                    finalization_error=NULL,finalization_attempted_at=\
                        clock_timestamp(),updated_at=clock_timestamp() \
               FROM candidate c WHERE e.account_id=$1 AND e.id=c.id \
             RETURNING e.id,floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms,\
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms,\
                    e.type,e.title,e.summary,e.participants::text AS participants,\
                    e.languages::text AS languages,e.action_items::text AS action_items,\
                    e.structure_state,e.minute_summaries::text AS stored_minute_summaries,\
                    e.minutes_text,\
                    e.identity_revision,e.finalization_attempt_count",
        )
        .bind(account_id)
        .bind(target_episode_id)
        .bind(quiet_horizon_seconds)
        .bind(finalization_version)
        .bind(&token)
        .bind(duration_seconds(std::time::Duration::from_secs(
            u64::try_from(lease_seconds).map_err(|_| {
                EnclaveError::InvalidRequest("finalization lease is invalid".into())
            })?,
        ))?)
        .bind(require_reconciled)
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
            structure_state: row.try_get("structure_state")?,
            minute_summaries: json_value(row.try_get("stored_minute_summaries")?),
            minutes_text: row.try_get("minutes_text")?,
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

    async fn acquire_finalization_egress_guard(
        &self,
        claim: &FinalizationClaim,
    ) -> Result<Option<Box<dyn FinalizationEgressGuard>>> {
        if claim.account_id.trim().is_empty()
            || claim.claim_token.trim().is_empty()
            || claim.episode.id <= 0
            || claim.input_identity_revision < 0
        {
            return Err(EnclaveError::InvalidRequest(
                "finalization provider-egress claim is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let require_reconciled =
            finalization_requires_reconciled(&mut transaction, &claim.account_id).await?;
        // Match every topology/source mutation: activation contract first,
        // then the account advisory lock, then the exact episode row. This
        // transaction remains open through provider usage settlement.
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", &claim.account_id)
            .await?;
        let authoritative = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM episodes \
              WHERE account_id=$1 AND id=$2 AND finalization_status='processing' \
                AND finalization_claim_token=$3 \
                AND finalization_claim_until>clock_timestamp() \
                AND identity_revision=$4 AND substance!='none' \
                AND (NOT $5::bool OR structure_state='reconciled') \
              FOR UPDATE",
        )
        .bind(&claim.account_id)
        .bind(claim.episode.id)
        .bind(&claim.claim_token)
        .bind(claim.input_identity_revision)
        .bind(require_reconciled)
        .fetch_optional(&mut *transaction)
        .await?;
        if authoritative.is_none() {
            transaction.rollback().await?;
            return Ok(None);
        }
        Ok(Some(Box::new(PostgresFinalizationEgressGuard {
            transaction: Some(transaction),
        })))
    }

    async fn defer_finalization(
        &self,
        claim: &FinalizationClaim,
        status: &str,
        error_code: Option<&str>,
        retry_delay_seconds: Option<i64>,
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
        if retry_delay_seconds.is_some_and(|seconds| !(0..=7 * 24 * 60 * 60).contains(&seconds)) {
            return Err(EnclaveError::InvalidRequest(
                "finalization retry delay is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let require_reconciled =
            finalization_requires_reconciled(&mut transaction, &claim.account_id).await?;
        let changed = sqlx::query(
            "UPDATE episodes SET finalization_status=$3,finalization_error=$4,\
                    finalization_attempt_count=finalization_attempt_count+\
                        CASE WHEN $7 THEN 1 ELSE 0 END,\
                    finalization_next_attempt_at=CASE WHEN $5::bigint IS NULL THEN NULL \
                        ELSE clock_timestamp()+make_interval(secs=>$5) END,\
                    finalization_claim_token=NULL,finalization_claim_until=NULL,\
                    updated_at=clock_timestamp() \
              WHERE account_id=$1 AND id=$2 AND finalization_claim_token=$6 \
                AND (NOT $8::bool OR structure_state='reconciled')",
        )
        .bind(&claim.account_id)
        .bind(claim.episode.id)
        .bind(status)
        .bind(error_code.map(|value| value.chars().take(1_000).collect::<String>()))
        .bind(retry_delay_seconds)
        .bind(&claim.claim_token)
        .bind(count_attempt)
        .bind(require_reconciled)
        .execute(&mut *transaction)
        .await?;
        if changed.rows_affected() != 1 {
            return Err(EnclaveError::Conflict(
                "finalization claim is no longer authoritative".into(),
            ));
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn settle_finalization(&self, result: FinalizationSettlement) -> Result<usize> {
        let mut transaction = self.pool().begin().await?;
        let require_reconciled =
            finalization_requires_reconciled(&mut transaction, &result.claim.account_id).await?;
        let row = sqlx::query(
            "SELECT finalized_at IS NULL AS is_initial,finalization_version,identity_revision,\
                    finalization_claim_token,finalization_completed_claim_token,structure_state \
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
        if require_reconciled && row.try_get::<String, _>("structure_state")? != "reconciled" {
            return Err(EnclaveError::Conflict(
                "assigned account draft finalization requires reconciliation".into(),
            ));
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
                    finalization_claim_until=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2",
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
                 VALUES($1,$2,$3,$4,'ready','episode_model',$5,$6,$7,$8,$9::jsonb,$10,$11,clock_timestamp()) \
                 ON CONFLICT(account_id,screenshot_id) DO UPDATE SET \
                    input_revision=excluded.input_revision,observation_version=excluded.observation_version,\
                    status='ready',generation_method='episode_model',\
                    literal_description=excluded.literal_description,screen_state=excluded.screen_state,\
                    content_type=excluded.content_type,visible_text_summary=excluded.visible_text_summary,\
                    notable_items=excluded.notable_items,model_name=excluded.model_name,\
                    prompt_version=excluded.prompt_version,completed_at=clock_timestamp()",
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
                 VALUES($1,$2,$3,$4,$5,'ready',$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,clock_timestamp(),clock_timestamp())",
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
                created_at=clock_timestamp()",
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
                    finalized_at=coalesce(finalized_at,clock_timestamp()),finalization_version=$8,\
                    finalization_status='complete',finalization_error=NULL,\
                    finalization_attempt_count=0,finalization_next_attempt_at=NULL,\
                    finalized_identity_revision=$9,identity_refresh_status='ready',\
                    finalization_completed_claim_token=finalization_claim_token,\
                    finalization_claim_token=NULL,finalization_claim_until=NULL,\
                    finalization_vertex_event_id=$10,finalization_analysis_revision=$11,updated_at=clock_timestamp() \
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

#[cfg(test)]
mod tests {
    #[test]
    fn scheduling_authority_is_database_relative() {
        let adapter = include_str!("finalization.rs");
        let port = include_str!("../finalization.rs");
        let production = adapter.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("e.ended_at<clock_timestamp()-make_interval(secs=>$3)"));
        assert!(production.contains("finalization_claim_until=clock_timestamp()+"));
        assert!(production.contains("e.finalization_next_attempt_at<=clock_timestamp()"));
        assert!(production.contains("clock_timestamp()+make_interval(secs=>$5)"));
        assert!(!production.contains("finalization claim time"));
        assert!(!production.contains("finalization horizon"));
        assert!(!production.contains("finalization defer time"));
        assert!(!port.contains("pub(crate) now:"));
        assert!(!port.contains("horizon_before"));
        assert!(!port.contains("retry_at:"));
        assert!(!port.contains("deferred_at:"));
    }
}
