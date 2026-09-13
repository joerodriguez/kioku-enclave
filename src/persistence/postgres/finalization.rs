use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};

use crate::{
    cp::{isotime, tokens},
    error::{EnclaveError, Result},
    persistence::{
        FinalizationClaim, FinalizationClaimRequest, FinalizationEgressGuard, FinalizationEpisode,
        FinalizationReason, FinalizationRepository, FinalizationRequest, FinalizationScreenshot,
        FinalizationSettlement, FinalizationUtterance,
    },
};

use super::{
    activation::finalization_requires_reconciled, advisory_transaction_lock, duration_seconds,
    memory_reconciliation::brief_sources_are_settled, PostgresPersistence,
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
                    coalesce(finalization_version,0) AS version,finalization_status,\
                    finalized_identity_revision<identity_revision AS identity_pending \
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
            return Ok(if row.try_get::<bool, _>("identity_pending")? {
                FinalizationRequest::AlreadyQueued {
                    status: "pending_identity".into(),
                }
            } else {
                FinalizationRequest::AlreadyComplete { status }
            });
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
        advisory_transaction_lock(&mut transaction, "memory-reconciliation", account_id).await?;
        // PostgreSQL resolves table names even in a false OR branch. The
        // dormant v26 path must not parse the v27-only formation receipt table.
        let settled_session_filter = if require_reconciled {
            "AND NOT EXISTS( \
                       SELECT 1 FROM capture_sessions session \
                       LEFT JOIN capture_formation_receipts receipt \
                         ON receipt.account_id=session.account_id AND receipt.capture_session_id=session.id \
                       WHERE session.account_id=e.account_id \
                         AND session.started_at<=e.ended_at+interval '8 hours' \
                         AND greatest(session.last_event_at,session.ended_at)>=e.started_at-interval '8 hours' \
                         AND (receipt.seal_finalized_at IS NULL OR receipt.state<>'complete' \
                              OR receipt.completed_revision IS DISTINCT FROM receipt.source_revision \
                              OR greatest(session.created_at,session.ended_at)>clock_timestamp()-interval '4 hours'))"
        } else {
            ""
        };
        let claim_query = format!(
            "WITH candidate AS (\
                SELECT e.id FROM episodes e JOIN accounts a ON a.id=e.account_id \
                 JOIN memory_handles h ON h.account_id=e.account_id AND h.episode_id=e.id AND h.state='active' \
                 WHERE e.account_id=$1 AND a.status='active' AND e.substance!='none' \
                   AND e.finalization_status!='deleting' \
                   AND (NOT $7::bool OR e.structure_state='reconciled') \
                   {settled_session_filter} \
                   AND ($2::bigint IS NULL OR e.id=$2) \
                   AND e.ended_at<clock_timestamp()-make_interval(secs=>$3) \
                   AND a.summarized_until>=e.ended_at+interval '4 hours' \
                   AND (e.finalization_claim_token IS NULL \
                        OR e.finalization_claim_until<=clock_timestamp()) \
                   AND (e.finalized_at IS NULL \
                        OR coalesce(e.finalization_version,0)<$4 \
                        OR (e.finalized_identity_revision<e.identity_revision \
                            AND (e.identity_refinalized_at IS NULL \
                                OR e.identity_refinalized_at<=clock_timestamp()-interval '24 hours'))) \
                   AND ($2::bigint IS NOT NULL OR (e.finalization_status!='failed_terminal' \
                        AND (e.finalization_next_attempt_at IS NULL \
                             OR e.finalization_next_attempt_at<=clock_timestamp()))) \
                 ORDER BY e.ended_at,e.id FOR UPDATE SKIP LOCKED LIMIT 1) \
             UPDATE episodes e SET finalization_claim_token=$5,\
                    finalization_claim_until=clock_timestamp()+\
                        make_interval(secs=>$6),finalization_status='processing',\
                    finalization_error=NULL,finalization_attempted_at=\
                        clock_timestamp() \
               FROM candidate c WHERE e.account_id=$1 AND e.id=c.id \
             RETURNING e.id,floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms,\
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms,\
                    e.type,e.title,e.summary,e.participants::text AS participants,\
                    e.languages::text AS languages,e.action_items::text AS action_items,\
                    e.structure_state,e.minute_summaries::text AS stored_minute_summaries,\
                    e.minutes_text,\
                    e.identity_revision,e.finalization_attempt_count,\
                    e.finalized_at IS NULL AS initial,coalesce(e.finalization_version,0) AS prior_version",
        );
        // Only the audited static predicate above is interpolated; all data stays bound.
        let row = sqlx::query(sqlx::AssertSqlSafe(claim_query))
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
        if require_reconciled
            && !brief_sources_are_settled(&mut transaction, account_id, episode_id).await?
        {
            transaction.rollback().await?;
            return Ok(None);
        }
        let mut episode = FinalizationEpisode {
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
        let reason = if row.try_get::<bool, _>("initial")? {
            FinalizationReason::Initial
        } else if row.try_get::<i64, _>("prior_version")? < finalization_version {
            FinalizationReason::Version
        } else {
            FinalizationReason::Identity
        };
        let attempt_count: i64 = row.try_get("finalization_attempt_count")?;
        super::speaker_identity::refresh_episode_speaker_projections(
            &mut transaction,
            account_id,
            &[super::speaker_identity::SpeakerProjectionTarget::current(
                episode_id,
            )],
            &[],
        )
        .await?;
        // Preparation may accept a name or repair owner/recurring meaning.
        // Freeze the claim revision only after those same-transaction changes.
        let input_identity_revision: i64 = sqlx::query_scalar(
            "SELECT identity_revision FROM episodes WHERE account_id=$1 AND id=$2",
        )
        .bind(account_id)
        .bind(episode_id)
        .fetch_one(&mut *transaction)
        .await?;
        let identity = super::speaker_identity::speaker_identity_join(
            super::speaker_identity::SpeakerUtteranceAlias::U,
            super::speaker_identity::SpeakerMemoryScope::Episode("$2"),
        );
        let utterance_query = format!(
            "SELECT u.id,\
                    floor(extract(epoch FROM (a.started_at + \
                        make_interval(secs=>u.start_offset_seconds)))*1000)::bigint AS at_ms,\
                    speaker_identity.speaker_label,a.source_type,u.text \
               FROM episode_members m JOIN utterances u \
                 ON u.account_id=m.account_id AND u.id=m.record_id \
               JOIN audio_segments a ON a.account_id=u.account_id AND a.id=u.audio_segment_id \
               {identity} \
              WHERE m.account_id=$1 AND m.episode_id=$2 AND m.record_type='utterance' \
              ORDER BY a.started_at,u.start_offset_seconds,u.id",
        );
        let mut utterances = sqlx::query(sqlx::AssertSqlSafe(utterance_query))
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
        let authored_labels = super::identity_presentation::authored_labels(
            &mut transaction,
            account_id,
            Some(episode_id),
            &utterances.iter().map(|u| u.id).collect::<Vec<_>>(),
        )
        .await?;
        for utterance in &mut utterances {
            if let Some(label) = authored_labels
                .labels
                .iter()
                .find(|label| label.utterance_ids.contains(&utterance.id))
            {
                utterance.speaker.clone_from(&label.label);
            }
        }
        let mut participants = Vec::new();
        for utterance in &utterances {
            if !participants.contains(&utterance.speaker) {
                participants.push(utterance.speaker.clone());
            }
        }
        episode.participants = Some(serde_json::to_string(&participants)?);
        let presentation = super::identity_presentation::episode_presentation(
            &mut transaction,
            account_id,
            episode_id,
        )
        .await?;
        transaction.commit().await?;
        Ok(Some(FinalizationClaim {
            account_id: account_id.to_owned(),
            claim_token: token,
            episode,
            utterances,
            screenshots,
            input_identity_revision,
            reason,
            authored_labels,
            presentation,
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
        if authoritative.is_none()
            || (require_reconciled
                && !brief_sources_are_settled(
                    &mut transaction,
                    &claim.account_id,
                    claim.episode.id,
                )
                .await?)
        {
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
                    finalization_claim_token=NULL,finalization_claim_until=NULL \
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
        advisory_transaction_lock(
            &mut transaction,
            "memory-reconciliation",
            &result.claim.account_id,
        )
        .await?;
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
        if require_reconciled
            && !brief_sources_are_settled(
                &mut transaction,
                &result.claim.account_id,
                result.claim.episode.id,
            )
            .await?
        {
            return Err(EnclaveError::Conflict(
                "brief source revision is no longer settled".into(),
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
                    finalization_claim_until=NULL WHERE account_id=$1 AND id=$2",
            )
            .bind(&result.claim.account_id)
            .bind(result.claim.episode.id)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(0);
        }
        if result.reused_timeline {
            if result.title != result.claim.episode.title
                || Some(result.summary.as_str()) != result.claim.episode.summary.as_deref()
                || serde_json::from_str::<Value>(&result.minute_summaries_json)?
                    != result.claim.episode.minute_summaries
                || Some(result.minutes_text.as_str())
                    != result.claim.episode.minutes_text.as_deref()
            {
                return Err(EnclaveError::Conflict(
                    "retained authored timeline changed during finalization".into(),
                ));
            }
        } else if result.title.trim().is_empty() || result.summary.trim().is_empty() {
            return Err(EnclaveError::InvalidRequest(
                "new finalization timeline is incomplete".into(),
            ));
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
        let initial = initial
            && (!require_reconciled
                || !sqlx::query_scalar::<_, bool>(
                    "WITH RECURSIVE ancestors(id) AS ( \
                 SELECT predecessor_episode_id FROM memory_lineage_edges \
                  WHERE account_id=$1 AND successor_episode_id=$2 \
                 UNION SELECT edge.predecessor_episode_id FROM memory_lineage_edges edge \
                  JOIN ancestors parent ON parent.id=edge.successor_episode_id \
                  WHERE edge.account_id=$1) \
             SELECT EXISTS(SELECT 1 FROM ancestors JOIN episodes e \
                 ON e.account_id=$1 AND e.id=ancestors.id WHERE e.finalized_at IS NOT NULL)",
                )
                .bind(&result.claim.account_id)
                .bind(result.claim.episode.id)
                .fetch_one(&mut *transaction)
                .await?);

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
                account_id,episode_id,overview,decisions,action_items,important_links,open_questions,sections) \
             VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb) \
             ON CONFLICT(account_id,episode_id) DO UPDATE SET overview=excluded.overview,\
                decisions=excluded.decisions,action_items=excluded.action_items,\
                important_links=excluded.important_links,open_questions=excluded.open_questions,\
                sections=excluded.sections,created_at=clock_timestamp()",
        )
        .bind(&result.claim.account_id)
        .bind(result.claim.episode.id)
        .bind(&result.overview)
        .bind(&result.decisions_json)
        .bind(&result.action_items_json)
        .bind(&result.important_links_json)
        .bind(&result.open_questions_json)
        .bind(&result.sections_json)
        .execute(&mut *transaction)
        .await?;

        // A retained timeline keeps its original maps. New tasks and brief
        // fields always use the labels frozen with this exact authoring claim.
        let labels = serde_json::to_value(&result.claim.authored_labels)?;
        let minute_summaries: Value = serde_json::from_str(&result.minute_summaries_json)?;
        let minute_labels = minute_summaries
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|minute| minute.get("start").and_then(Value::as_str))
            .map(|start| (start.to_owned(), labels.clone()))
            .collect::<serde_json::Map<_, _>>();
        sqlx::query("INSERT INTO episode_identity_presentations(account_id,episode_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(&result.claim.account_id).bind(result.claim.episode.id).execute(&mut *transaction).await?;
        sqlx::query("UPDATE episode_identity_presentations SET brief_labels=$3::jsonb,action_labels=$3::jsonb,timeline_labels=CASE WHEN $5 THEN timeline_labels ELSE $3::jsonb END,minute_labels=CASE WHEN $5 THEN minute_labels ELSE $4::jsonb END WHERE account_id=$1 AND episode_id=$2")
            .bind(&result.claim.account_id).bind(result.claim.episode.id).bind(labels.to_string())
            .bind(Value::Object(minute_labels).to_string()).bind(result.reused_timeline).execute(&mut *transaction).await?;

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
                    identity_refinalized_at=CASE WHEN $12 THEN clock_timestamp() ELSE identity_refinalized_at END,\
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
        .bind(result.claim.reason == FinalizationReason::Identity)
        .execute(&mut *transaction)
        .await?;
        if let Some(include_content) = result.email_preference_include_content.filter(|_| initial) {
            super::morning_email::enqueue_brief(
                &mut transaction,
                &result.claim.account_id,
                result.claim.episode.id,
                include_content,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(deliveries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn identity_fixture() -> Option<super::super::tests::ControlPlaneContractFixture> {
        use super::super::voice_identity::tests::{seed_voice_memory, seed_voice_observation};
        let fixture = super::super::tests::test_persistence().await?;
        let repo = &fixture.persistence;
        let account = "identity-finalizer";
        seed_voice_observation(repo, account, "session", "event", 1, 1).await;
        seed_voice_memory(repo, account, 1, 1).await;
        sqlx::query("UPDATE accounts SET summarized_until=clock_timestamp() WHERE id=$1")
            .bind(account)
            .execute(repo.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE episodes SET started_at=clock_timestamp()-interval '2 days',ended_at=clock_timestamp()-interval '1 day',substance='normal',title='Speaker A spoke',summary='Speaker A planned work',minute_summaries='[]',minutes_text='',finalized_at=clock_timestamp()-interval '12 hours',finalization_version=6,finalized_identity_revision=7,finalization_status='complete' WHERE account_id=$1 AND id=1").bind(account).execute(repo.pool()).await.unwrap();

        sqlx::query("INSERT INTO people(account_id,id,display_name,status) VALUES($1,20,'Sarah','identified'),($1,21,'Ana','identified'),($1,22,'Bao','identified')").bind(account).execute(repo.pool()).await.unwrap();
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(super::super::voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        super::super::speaker_identity::refresh_episode_speaker_projections(
            &mut tx,
            account,
            &[super::super::speaker_identity::SpeakerProjectionTarget::current(1)],
            &[],
        )
        .await
        .unwrap();
        let labels =
            super::super::identity_presentation::authored_labels(&mut tx, account, Some(1), &[1])
                .await
                .unwrap();
        sqlx::query("UPDATE episode_identity_presentations SET timeline_labels=$2::jsonb,action_labels=$2::jsonb WHERE account_id=$1 AND episode_id=1").bind(account).bind(serde_json::to_string(&labels).unwrap()).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        Some(fixture)
    }

    async fn change_identity(repo: &PostgresPersistence, person: i64, refresh: bool) {
        let account = "identity-finalizer";
        let mut tx = repo.pool().begin().await.unwrap();
        assert!(super::super::voice_identity::lock_account(&mut tx, account)
            .await
            .unwrap());
        sqlx::query("UPDATE speaker_clusters SET person_id=$2,attribution_state='person_bound' WHERE account_id=$1 AND id=1").bind(account).bind(person).execute(&mut *tx).await.unwrap();
        if refresh {
            super::super::speaker_identity::refresh_episode_speaker_projections(
                &mut tx,
                account,
                &[super::super::speaker_identity::SpeakerProjectionTarget::current(1)],
                &[],
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }

    async fn claim_identity(repo: &PostgresPersistence, version: i64) -> Option<FinalizationClaim> {
        repo.claim_finalization(FinalizationClaimRequest {
            account_id: "identity-finalizer",
            target_episode_id: Some(1),
            quiet_horizon_seconds: 3600,
            finalization_version: version,
            lease_seconds: 900,
        })
        .await
        .unwrap()
    }

    async fn identity_result(
        repo: &PostgresPersistence,
        claim: FinalizationClaim,
    ) -> FinalizationSettlement {
        use crate::persistence::ModelUsageRepository;
        let event = repo
            .begin_invocation(
                &claim.account_id,
                crate::cp::vertex::VertexOperation::FinalEpisodeAnalysis,
                "synthetic-model",
                "us-central1",
                &[17; 32],
            )
            .await
            .unwrap();
        repo.settle_response(
            &claim.account_id,
            &event,
            &crate::cp::vertex::VertexMetadata {
                usage: None,
                model_version: Some("synthetic-model".into()),
                traffic_type: None,
            },
        )
        .await
        .unwrap();
        let speaker = claim.utterances[0].speaker.clone();
        FinalizationSettlement {
            title: claim.episode.title.clone(),
            summary: claim.episode.summary.clone().unwrap(),
            minute_summaries_json: claim.episode.minute_summaries.to_string(),
            minutes_text: claim.episode.minutes_text.clone().unwrap(),
            claim,
            vertex_event_id: event,
            model_name: "synthetic-model".into(),
            analysis_revision: "synthetic-analysis".into(),
            reused_timeline: true,
            action_items_json:
                json!([{"text":format!("{speaker} will follow up"),"owner":speaker}]).to_string(),
            overview: format!("{speaker} planned work"),
            sections_json: Some("[]".into()),
            decisions_json: "[]".into(),
            important_links_json: "[]".into(),
            open_questions_json: "[]".into(),
            ranked_screens: vec![],
            webhook_destinations: vec![("synthetic-subscription".into(), "synthetic-event".into())],
            email_preference_include_content: Some(true),
            push_destinations: vec![(
                "synthetic-installation".into(),
                "synthetic-delivery".into(),
                "synthetic-handoff".into(),
                "synthetic-collapse".into(),
            )],
            finalization_version: 6,
            observation_version: 2,
            observation_prompt_version: 2,
            interpretation_version: 2,
            interpretation_prompt_version: 2,
        }
    }

    #[tokio::test]
    async fn identity_presentation_finalizer_freezes_prepared_revision_and_preserves_reused_maps() {
        let Some(fixture) = identity_fixture().await else {
            return;
        };
        let repo = &fixture.persistence;
        let account = "identity-finalizer";
        let original: String=sqlx::query_scalar("SELECT jsonb_build_array(title,summary,minute_summaries,minutes_text,finalized_at)::text FROM episodes WHERE account_id=$1 AND id=1").bind(account).fetch_one(repo.pool()).await.unwrap();
        let old_map: String=sqlx::query_scalar("SELECT timeline_labels::text FROM episode_identity_presentations WHERE account_id=$1 AND episode_id=1").bind(account).fetch_one(repo.pool()).await.unwrap();
        change_identity(repo, 20, true).await;
        // Repair a graph change during claim preparation, after candidate selection.
        change_identity(repo, 21, false).await;
        let claim = claim_identity(repo, 6).await.unwrap();
        let revision: i64 = sqlx::query_scalar(
            "SELECT identity_revision FROM episodes WHERE account_id=$1 AND id=1",
        )
        .bind(account)
        .fetch_one(repo.pool())
        .await
        .unwrap();
        assert_eq!(
            claim.input_identity_revision, revision,
            "finalizer must freeze identity revision after same-transaction speaker preparation"
        );
        assert_eq!(revision, 9);
        assert_eq!(claim.reason, FinalizationReason::Identity);
        assert_eq!(
            claim.episode.presented(&claim.presentation).title,
            "Ana spoke",
            "provider context must use current labels without rewriting retained authored text"
        );
        assert_eq!(claim.episode.title, "Speaker A spoke");
        assert_eq!(claim.utterances[0].speaker, "Ana");
        change_identity(repo, 22, true).await;
        assert!(
            repo.acquire_finalization_egress_guard(&claim)
                .await
                .unwrap()
                .is_none(),
            "stale identity claims must be denied before provider disclosure"
        );
        let stale = identity_result(repo, claim).await;
        assert_eq!(repo.settle_finalization(stale).await.unwrap(), 0);
        let untouched: bool=sqlx::query_scalar("SELECT e.identity_refinalized_at IS NULL AND NOT EXISTS(SELECT 1 FROM episode_final_briefs b WHERE b.account_id=e.account_id) AND NOT EXISTS(SELECT 1 FROM webhook_deliveries d WHERE d.account_id=e.account_id) AND p.brief_labels='{\"labels\":[]}'::jsonb FROM episodes e JOIN episode_identity_presentations p ON p.account_id=e.account_id AND p.episode_id=e.id WHERE e.account_id=$1 AND e.id=1").bind(account).fetch_one(repo.pool()).await.unwrap();
        assert!(untouched,"stale identity settlement must write no brief, authoring map, delivery or successful refresh timestamp");
        let claim = claim_identity(repo, 6).await.unwrap();
        repo.acquire_finalization_egress_guard(&claim)
            .await
            .unwrap()
            .unwrap()
            .release()
            .await
            .unwrap();
        let result = identity_result(repo, claim).await;
        assert_eq!(
            repo.settle_finalization(result.clone()).await.unwrap(),
            0,
            "identity re-finalization must not create new outbound deliveries"
        );
        assert_eq!(repo.settle_finalization(result).await.unwrap(), 0);
        let kept: String=sqlx::query_scalar("SELECT jsonb_build_array(title,summary,minute_summaries,minutes_text,finalized_at)::text FROM episodes WHERE account_id=$1 AND id=1").bind(account).fetch_one(repo.pool()).await.unwrap();
        assert_eq!(kept,original,"identity brief refresh must preserve reused timeline bytes and original completion time");
        let row=sqlx::query("SELECT p.timeline_labels::text,p.brief_labels::text,p.action_labels::text,e.identity_refinalized_at IS NOT NULL AS refreshed FROM episode_identity_presentations p JOIN episodes e ON e.account_id=p.account_id AND e.id=p.episode_id WHERE p.account_id=$1 AND p.episode_id=1").bind(account).fetch_one(repo.pool()).await.unwrap();
        assert_eq!(
            row.get::<String, _>("timeline_labels"),
            old_map,
            "a reused timeline must keep its original authoring map"
        );
        let brief: Value = serde_json::from_str(&row.get::<String, _>("brief_labels")).unwrap();
        assert_eq!(
            brief["labels"][0]["label"], "Bao",
            "new brief mapping must match the actual frozen provider speaker labels"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&row.get::<String, _>("action_labels")).unwrap(),
            brief
        );
        assert!(row.get::<bool, _>("refreshed"));
        let outbound: i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM webhook_deliveries WHERE account_id=$1)+(SELECT count(*) FROM push_deliveries WHERE account_id=$1)+(SELECT count(*) FROM morning_email_sources WHERE account_id=$1)").bind(account).fetch_one(repo.pool()).await.unwrap();
        assert_eq!(
            outbound, 0,
            "identity-only authoring must not enqueue webhook, push or morning email work"
        );
        cleanup_identity(fixture).await;
    }

    #[tokio::test]
    async fn identity_presentation_finalizer_throttles_success_only_without_blocking_initial_or_version_work(
    ) {
        let Some(fixture) = identity_fixture().await else {
            return;
        };
        let repo = &fixture.persistence;
        let account = "identity-finalizer";
        change_identity(repo, 20, true).await;
        sqlx::query("UPDATE episodes SET identity_refinalized_at=clock_timestamp()-interval '23 hours 59 minutes' WHERE account_id=$1 AND id=1").bind(account).execute(repo.pool()).await.unwrap();
        assert!(
            claim_identity(repo, 6).await.is_none(),
            "even a targeted identity claim must respect the 24-hour successful refresh limit"
        );
        assert!(
            matches!(repo.request_finalization(account,1,6).await.unwrap(),FinalizationRequest::AlreadyQueued{status} if status=="pending_identity")
        );
        let version = claim_identity(repo, 7)
            .await
            .expect("version work is independent of identity throttle");
        assert_eq!(version.reason, FinalizationReason::Version);
        repo.defer_finalization(&version, "retry_wait", None, Some(0), false)
            .await
            .unwrap();
        sqlx::query("UPDATE episodes SET identity_refinalized_at=clock_timestamp()-interval '24 hours 1 second' WHERE account_id=$1 AND id=1").bind(account).execute(repo.pool()).await.unwrap();
        let identity = claim_identity(repo, 6)
            .await
            .expect("identity work is eligible after 24 hours");
        assert_eq!(identity.reason, FinalizationReason::Identity);
        repo.defer_finalization(&identity, "retry_wait", None, Some(0), false)
            .await
            .unwrap();
        assert!(
            claim_identity(repo, 6).await.is_some(),
            "failed identity work must not consume a successful refresh timestamp"
        );
        sqlx::query("UPDATE episodes SET finalization_claim_token=NULL,finalization_claim_until=NULL,finalized_at=NULL,identity_refinalized_at=clock_timestamp() WHERE account_id=$1 AND id=1").bind(account).execute(repo.pool()).await.unwrap();
        assert_eq!(
            claim_identity(repo, 6).await.unwrap().reason,
            FinalizationReason::Initial,
            "initial finalization must not be throttled by identity refresh history"
        );
        cleanup_identity(fixture).await;
    }

    async fn cleanup_identity(fixture: super::super::tests::ControlPlaneContractFixture) {
        fixture.persistence.pool().close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            fixture.schema
        )))
        .execute(fixture.base.pool())
        .await
        .unwrap();
        fixture.base.pool().close().await;
    }
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
