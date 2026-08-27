use async_trait::async_trait;
use sqlx::Row;

use crate::{
    cp::{
        delivery::{ActionItemDetail, DecisionDetail, FinalizedEpisode, LinkDetail},
        isotime, tokens,
    },
    error::{EnclaveError, Result},
    persistence::{
        DeliveryRepository, EmailDeliveryCandidate, EmailDeliveryClaim, EmailProviderOutcome,
        FrozenEmailDelivery, FrozenPushDelivery, FrozenWebhookDelivery, PushDeliveryCandidate,
        PushDeliveryClaim, PushProviderOutcome, WebhookDeliveryCandidate, WebhookDeliveryClaim,
        WebhookProviderOutcome,
    },
};

use super::{advisory_transaction_lock, duration_seconds, PostgresPersistence};

const MAX_DELIVERY_AGE_SECONDS: i64 = 24 * 60 * 60;
const PROVIDER_PACE_MILLIS: i64 = 250;

fn bounded(value: &str, maximum: usize, name: &str) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.bytes().any(|byte| byte == 0) {
        return Err(EnclaveError::Store(format!(
            "frozen email {name} is invalid"
        )));
    }
    Ok(())
}

fn timestamp(value: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .ok_or_else(|| EnclaveError::Store("email outcome timestamp is invalid".into()))
}

fn parse_json<T: serde::de::DeserializeOwned>(raw: String, name: &str) -> Result<T> {
    serde_json::from_str(&raw)
        .map_err(|_| EnclaveError::Store(format!("finalized episode {name} is malformed")))
}

fn episode_from_row(row: &sqlx::postgres::PgRow) -> Result<FinalizedEpisode> {
    Ok(FinalizedEpisode {
        episode_id: row.try_get("episode_id")?,
        title: row
            .try_get::<Option<String>, _>("title")?
            .unwrap_or_default(),
        started_at: isotime::format_epoch_millis(row.try_get("started_at_ms")?),
        ended_at: isotime::format_epoch_millis(row.try_get("ended_at_ms")?),
        finalized_at: isotime::format_epoch_millis(row.try_get("finalized_at_ms")?),
        episode_type: row.try_get("episode_type")?,
        participants: parse_json(row.try_get("participants")?, "participants")?,
        overview: row.try_get("overview")?,
        decisions: parse_json::<Vec<DecisionDetail>>(row.try_get("decisions")?, "decisions")?,
        action_items: parse_json::<Vec<ActionItemDetail>>(
            row.try_get("action_items")?,
            "action_items",
        )?,
        important_links: parse_json::<Vec<LinkDetail>>(
            row.try_get("important_links")?,
            "important_links",
        )?,
        open_questions: parse_json::<Vec<String>>(
            row.try_get("open_questions")?,
            "open_questions",
        )?,
    })
}

async fn recover_expired_email_claims(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    let expired = sqlx::query(
        "SELECT d.delivery_id,d.claim_token,EXISTS( \
             SELECT 1 FROM email_send_fences f WHERE f.account_id=d.account_id \
               AND f.delivery_id=d.delivery_id AND f.claim_id=d.claim_token) AS disclosed \
           FROM email_deliveries d WHERE d.account_id=$1 AND d.state='processing' \
            AND d.claim_until<=clock_timestamp() FOR UPDATE",
    )
    .bind(account_id)
    .fetch_all(&mut **transaction)
    .await?;
    for row in expired {
        let delivery_id: String = row.try_get("delivery_id")?;
        let claim_token: String = row.try_get("claim_token")?;
        let disclosed: bool = row.try_get("disclosed")?;
        sqlx::query(
            "UPDATE email_deliveries SET state=$1,completed_claim_token=claim_token, \
                    claim_token=NULL,claim_until=NULL,last_error=$2,error_code=$2,updated_at=now() \
              WHERE account_id=$3 AND delivery_id=$4 AND claim_token=$5",
        )
        .bind(if disclosed { "ambiguous" } else { "retry_wait" })
        .bind(if disclosed {
            "claim_expired_after_disclosure"
        } else {
            "claim_expired_before_disclosure"
        })
        .bind(account_id)
        .bind(&delivery_id)
        .bind(&claim_token)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            "DELETE FROM email_send_fences WHERE account_id=$1 AND delivery_id=$2 AND claim_id=$3",
        )
        .bind(account_id)
        .bind(&delivery_id)
        .bind(&claim_token)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL,updated_at=now() \
              WHERE provider='email' AND owner_token=$1",
        )
        .bind(&claim_token)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn recover_expired_webhook_claims(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    let expired = sqlx::query(
        "SELECT d.event_id,d.claim_token,EXISTS( \
             SELECT 1 FROM webhook_send_fences f WHERE f.account_id=d.account_id \
               AND f.event_id=d.event_id AND f.claim_id=d.claim_token) AS disclosed \
           FROM webhook_deliveries d WHERE d.account_id=$1 AND d.state='processing' \
            AND d.claim_until<=clock_timestamp() FOR UPDATE",
    )
    .bind(account_id)
    .fetch_all(&mut **transaction)
    .await?;
    for row in expired {
        let event_id: String = row.try_get("event_id")?;
        let claim_token: String = row.try_get("claim_token")?;
        let disclosed: bool = row.try_get("disclosed")?;
        sqlx::query(
            "UPDATE webhook_deliveries SET state=$1,completed_claim_token=claim_token, \
                    claim_token=NULL,claim_until=NULL,last_error=$2,error_code=$2,updated_at=now() \
              WHERE account_id=$3 AND event_id=$4 AND claim_token=$5",
        )
        .bind(if disclosed { "ambiguous" } else { "retry_wait" })
        .bind(if disclosed {
            "claim_expired_after_disclosure"
        } else {
            "claim_expired_before_disclosure"
        })
        .bind(account_id)
        .bind(&event_id)
        .bind(&claim_token)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            "DELETE FROM webhook_send_fences WHERE account_id=$1 AND event_id=$2 AND claim_id=$3",
        )
        .bind(account_id)
        .bind(&event_id)
        .bind(&claim_token)
        .execute(&mut **transaction)
        .await?;
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL,updated_at=now() \
              WHERE provider='webhook' AND owner_token=$1",
        )
        .bind(&claim_token)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn recover_expired_push_claims(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    let expired = sqlx::query(
        "SELECT d.delivery_id,d.claim_token,EXISTS( \
             SELECT 1 FROM push_send_fences f WHERE f.account_id=d.account_id \
               AND f.claim_id=d.claim_token) AS disclosed \
           FROM push_deliveries d WHERE d.account_id=$1 AND d.state='processing' \
            AND d.claim_until<=clock_timestamp() FOR UPDATE",
    )
    .bind(account_id)
    .fetch_all(&mut **transaction)
    .await?;
    for row in expired {
        let delivery_id: String = row.try_get("delivery_id")?;
        let claim_token: String = row.try_get("claim_token")?;
        let disclosed: bool = row.try_get("disclosed")?;
        sqlx::query(
            "UPDATE push_deliveries SET state=$1,completed_claim_token=claim_token, \
                    claim_token=NULL,claim_until=NULL,last_error=$2,error_code=$2,updated_at=now() \
              WHERE account_id=$3 AND delivery_id=$4 AND claim_token=$5",
        )
        .bind(if disclosed { "ambiguous" } else { "retry_wait" })
        .bind(if disclosed {
            "claim_expired_after_disclosure"
        } else {
            "claim_expired_before_disclosure"
        })
        .bind(account_id)
        .bind(&delivery_id)
        .bind(&claim_token)
        .execute(&mut **transaction)
        .await?;
        sqlx::query("DELETE FROM push_send_fences WHERE account_id=$1 AND claim_id=$2")
            .bind(account_id)
            .bind(&claim_token)
            .execute(&mut **transaction)
            .await?;
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL,updated_at=now() \
              WHERE provider='push' AND owner_token=$1",
        )
        .bind(&claim_token)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

#[async_trait]
impl DeliveryRepository for PostgresPersistence {
    async fn next_email_candidate(
        &self,
        account_id: &str,
    ) -> Result<Option<EmailDeliveryCandidate>> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        advisory_transaction_lock(&mut transaction, "email-preference", account_id).await?;
        recover_expired_email_claims(&mut transaction, account_id).await?;

        sqlx::query(
            "UPDATE email_deliveries d SET state='cancelled',last_error='delivery_expired', \
                    error_code='delivery_expired',updated_at=now() \
              WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') \
                AND d.created_at<=clock_timestamp()-make_interval(secs=>$2)",
        )
        .bind(account_id)
        .bind(MAX_DELIVERY_AGE_SECONDS as f64)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE email_deliveries d SET state='cancelled',last_error='email_not_authorized', \
                    error_code='email_not_authorized',updated_at=now() \
              WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') AND NOT EXISTS ( \
                SELECT 1 FROM accounts a JOIN episode_email_preferences p ON p.account_id=a.id \
                 WHERE a.id=d.account_id AND a.status='active' AND p.enabled)",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE email_deliveries d SET state='failed',last_error='missing_final_brief', \
                    error_code='missing_final_brief',updated_at=now() \
              WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') AND NOT EXISTS ( \
                SELECT 1 FROM episodes e JOIN episode_final_briefs b \
                  ON b.account_id=e.account_id AND b.episode_id=e.id \
                 WHERE e.account_id=d.account_id AND e.id=d.episode_id \
                   AND e.finalization_status='complete' AND e.finalized_at IS NOT NULL)",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;

        let row = sqlx::query(
            "SELECT d.account_id,d.episode_id,d.delivery_version,d.delivery_id,d.attempt_count, \
                    (d.include_content AND p.include_content) AS include_content,a.email, \
                    floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms, \
                    floor(extract(epoch FROM e.finalized_at)*1000)::bigint AS finalized_at_ms, \
                    e.type AS episode_type,e.title,e.participants::text AS participants, \
                    b.overview,b.decisions::text AS decisions,b.action_items::text AS action_items, \
                    b.important_links::text AS important_links,b.open_questions::text AS open_questions \
               FROM email_deliveries d JOIN accounts a ON a.id=d.account_id \
               JOIN episode_email_preferences p ON p.account_id=d.account_id \
               JOIN episodes e ON e.account_id=d.account_id AND e.id=d.episode_id \
               JOIN episode_final_briefs b ON b.account_id=e.account_id AND b.episode_id=e.id \
              WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') \
                AND d.next_attempt_at<=clock_timestamp() AND a.status='active' AND p.enabled \
              ORDER BY d.created_at,d.episode_id LIMIT 1",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let candidate = row
            .as_ref()
            .map(|row| -> Result<EmailDeliveryCandidate> {
                Ok(EmailDeliveryCandidate {
                    account_id: row.try_get("account_id")?,
                    episode_id: row.try_get("episode_id")?,
                    delivery_version: row.try_get("delivery_version")?,
                    delivery_id: row.try_get("delivery_id")?,
                    attempt_count: row.try_get("attempt_count")?,
                    include_content: row.try_get("include_content")?,
                    recipient_email: row.try_get("email")?,
                    episode: episode_from_row(row)?,
                })
            })
            .transpose()?;
        transaction.commit().await?;
        Ok(candidate)
    }

    async fn claim_email(
        &self,
        candidate: &EmailDeliveryCandidate,
        request: FrozenEmailDelivery,
        lease_seconds: i64,
    ) -> Result<Option<EmailDeliveryClaim>> {
        if !(1..=120).contains(&lease_seconds)
            || candidate.attempt_count < 0
            || candidate.attempt_count >= 10
            || request.recipient_email != candidate.recipient_email
            || request.include_content != candidate.include_content
            || !request.recipient_email.contains('@')
        {
            return Err(EnclaveError::Store(
                "email delivery candidate is invalid".into(),
            ));
        }
        bounded(&request.recipient_email, 320, "recipient")?;
        bounded(&request.subject, 998, "subject")?;
        bounded(&request.text_body, 256 * 1024, "text body")?;
        bounded(&request.html_body, 512 * 1024, "HTML body")?;

        let token = tokens::new_uuid();
        let lease = duration_seconds(std::time::Duration::from_secs(
            u64::try_from(lease_seconds)
                .map_err(|_| EnclaveError::Store("email lease is invalid".into()))?,
        ))?;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", &candidate.account_id)
            .await?;
        advisory_transaction_lock(&mut transaction, "email-preference", &candidate.account_id)
            .await?;
        recover_expired_email_claims(&mut transaction, &candidate.account_id).await?;

        let lane_available = sqlx::query_scalar::<_, bool>(
            "SELECT owner_token IS NULL AND next_send_at<=clock_timestamp() \
                    AND (circuit_until IS NULL OR circuit_until<=clock_timestamp()) \
               FROM provider_send_lanes WHERE provider='email' FOR UPDATE",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if !lane_available {
            transaction.rollback().await?;
            return Ok(None);
        }
        let current = sqlx::query(
            "SELECT d.attempt_count,d.include_content AS snapshot_include_content,a.email,p.enabled, \
                    p.include_content AS preference_include_content,a.status \
               FROM email_deliveries d JOIN accounts a ON a.id=d.account_id \
               JOIN episode_email_preferences p ON p.account_id=d.account_id \
              WHERE d.account_id=$1 AND d.episode_id=$2 AND d.delivery_version=$3 \
                AND d.delivery_id=$4 AND d.state IN ('pending','retry_wait') \
                AND d.next_attempt_at<=clock_timestamp() FOR UPDATE OF d",
        )
        .bind(&candidate.account_id)
        .bind(candidate.episode_id)
        .bind(candidate.delivery_version)
        .bind(&candidate.delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(current) = current else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let authorized = current.try_get::<String, _>("status")? == "active"
            && current.try_get::<bool, _>("enabled")?
            && current.try_get::<String, _>("email")? == request.recipient_email
            && (!request.include_content
                || current.try_get::<bool, _>("preference_include_content")?)
            && current.try_get::<i64, _>("attempt_count")? == candidate.attempt_count
            && (current.try_get::<bool, _>("snapshot_include_content")?
                && current.try_get::<bool, _>("preference_include_content")?)
                == candidate.include_content;
        if !authorized {
            transaction.rollback().await?;
            return Ok(None);
        }
        let new_attempt = candidate
            .attempt_count
            .checked_add(1)
            .ok_or_else(|| EnclaveError::Store("email attempt count overflow".into()))?;
        let lease_expires_at_ms = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM (clock_timestamp()+make_interval(secs=>$1)))*1000)::bigint",
        )
        .bind(lease)
        .fetch_one(&mut *transaction)
        .await?;
        let changed = sqlx::query(
            "UPDATE email_deliveries SET state='processing',attempt_count=$1,claim_token=$2, \
                    claim_until=to_timestamp($3::double precision/1000.0), \
                    frozen_recipient_email=$4,frozen_include_content=$5,frozen_subject=$6, \
                    frozen_text_body=$7,frozen_html_body=$8,send_started_at=clock_timestamp(), \
                    last_error=NULL,error_code=NULL,updated_at=now() \
              WHERE account_id=$9 AND episode_id=$10 AND delivery_version=$11 \
                AND delivery_id=$12 AND state IN ('pending','retry_wait')",
        )
        .bind(new_attempt)
        .bind(&token)
        .bind(lease_expires_at_ms)
        .bind(&request.recipient_email)
        .bind(request.include_content)
        .bind(&request.subject)
        .bind(&request.text_body)
        .bind(&request.html_body)
        .bind(&candidate.account_id)
        .bind(candidate.episode_id)
        .bind(candidate.delivery_version)
        .bind(&candidate.delivery_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }
        sqlx::query(
            "INSERT INTO email_send_fences(account_id,delivery_id,claim_id,lease_expires_at, \
                                            recipient_email,include_content) \
             VALUES($1,$2,$3,to_timestamp($4::double precision/1000.0),$5,$6)",
        )
        .bind(&candidate.account_id)
        .bind(&candidate.delivery_id)
        .bind(&token)
        .bind(lease_expires_at_ms)
        .bind(&request.recipient_email)
        .bind(request.include_content)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=$1, \
                    lease_until=to_timestamp($2::double precision/1000.0),updated_at=now() \
              WHERE provider='email'",
        )
        .bind(&token)
        .bind(lease_expires_at_ms)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Some(EmailDeliveryClaim {
            account_id: candidate.account_id.clone(),
            episode_id: candidate.episode_id,
            delivery_version: candidate.delivery_version,
            delivery_id: candidate.delivery_id.clone(),
            claim_token: token,
            lease_expires_at: isotime::format_epoch_millis(lease_expires_at_ms),
            attempt_count: new_attempt,
            request,
        }))
    }

    async fn settle_email(
        &self,
        claim: &EmailDeliveryClaim,
        outcome: EmailProviderOutcome,
        circuit_seconds: Option<i64>,
    ) -> Result<()> {
        if !outcome.is_valid()
            || circuit_seconds.is_some_and(|seconds| !(1..=6 * 60 * 60).contains(&seconds))
        {
            return Err(EnclaveError::Store(
                "email delivery settlement is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "email-preference", &claim.account_id).await?;
        let row = sqlx::query(
            "SELECT state,claim_token,completed_claim_token FROM email_deliveries \
              WHERE account_id=$1 AND episode_id=$2 AND delivery_version=$3 AND delivery_id=$4 \
              FOR UPDATE",
        )
        .bind(&claim.account_id)
        .bind(claim.episode_id)
        .bind(claim.delivery_version)
        .bind(&claim.delivery_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("email delivery disappeared".into()))?;
        if row
            .try_get::<Option<String>, _>("completed_claim_token")?
            .as_deref()
            == Some(&claim.claim_token)
        {
            transaction.commit().await?;
            return Ok(());
        }
        if row.try_get::<String, _>("state")? != "processing"
            || row.try_get::<Option<String>, _>("claim_token")?.as_deref()
                != Some(&claim.claim_token)
        {
            return Err(EnclaveError::Conflict(
                "email delivery claim is no longer authoritative".into(),
            ));
        }
        let fence_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM email_send_fences WHERE account_id=$1 \
                    AND delivery_id=$2 AND claim_id=$3 AND recipient_email=$4 \
                    AND include_content=$5)",
        )
        .bind(&claim.account_id)
        .bind(&claim.delivery_id)
        .bind(&claim.claim_token)
        .bind(&claim.request.recipient_email)
        .bind(claim.request.include_content)
        .fetch_one(&mut *transaction)
        .await?;
        if !fence_exists {
            return Err(EnclaveError::Conflict(
                "email disclosure fence disappeared".into(),
            ));
        }
        let (state, status, provider_message_id, error_code, retry_at) = match &outcome {
            EmailProviderOutcome::Accepted {
                status,
                provider_message_id,
            } => (
                "delivered",
                Some(*status),
                Some(provider_message_id.as_str()),
                None,
                None,
            ),
            EmailProviderOutcome::Retry {
                status,
                code,
                retry_at,
            } => (
                "retry_wait",
                *status,
                None,
                Some(code.as_str()),
                Some(timestamp(retry_at)?),
            ),
            EmailProviderOutcome::Ambiguous => {
                ("ambiguous", None, None, Some("outcome_unknown"), None)
            }
            EmailProviderOutcome::Failed { status, code } => {
                ("failed", *status, None, Some(code.as_str()), None)
            }
        };
        let changed = sqlx::query(
            "UPDATE email_deliveries SET state=$1,completed_claim_token=$2,claim_token=NULL, \
                    claim_until=NULL,next_attempt_at=CASE WHEN $3::bigint IS NULL THEN next_attempt_at \
                      ELSE to_timestamp($3::double precision/1000.0) END,provider_message_id=$4, \
                    response_status=$5,error_code=$6,last_error=$6,updated_at=now() \
              WHERE account_id=$7 AND episode_id=$8 AND delivery_version=$9 AND delivery_id=$10 \
                AND state='processing' AND claim_token=$2",
        )
        .bind(state)
        .bind(&claim.claim_token)
        .bind(retry_at)
        .bind(provider_message_id)
        .bind(status)
        .bind(error_code)
        .bind(&claim.account_id)
        .bind(claim.episode_id)
        .bind(claim.delivery_version)
        .bind(&claim.delivery_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "email delivery was not settled exactly once".into(),
            ));
        }
        sqlx::query(
            "DELETE FROM email_send_fences WHERE account_id=$1 AND delivery_id=$2 AND claim_id=$3",
        )
        .bind(&claim.account_id)
        .bind(&claim.delivery_id)
        .bind(&claim.claim_token)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL, \
                    next_send_at=clock_timestamp()+make_interval(secs=>$1), \
                    circuit_until=CASE WHEN $2::double precision IS NULL THEN circuit_until \
                      ELSE clock_timestamp()+make_interval(secs=>$2) END,updated_at=now() \
              WHERE provider='email' AND owner_token=$3",
        )
        .bind(PROVIDER_PACE_MILLIS as f64 / 1_000.0)
        .bind(circuit_seconds.map(|seconds| seconds as f64))
        .bind(&claim.claim_token)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn next_webhook_candidate(
        &self,
        account_id: &str,
    ) -> Result<Option<WebhookDeliveryCandidate>> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        advisory_transaction_lock(&mut transaction, "webhook-registry", account_id).await?;
        recover_expired_webhook_claims(&mut transaction, account_id).await?;
        sqlx::query(
            "UPDATE webhook_deliveries SET state='cancelled',last_error='delivery_expired', \
                    error_code='delivery_expired',updated_at=now() \
              WHERE account_id=$1 AND state IN ('pending','retry_wait') \
                AND created_at<=clock_timestamp()-make_interval(secs=>$2)",
        )
        .bind(account_id)
        .bind(MAX_DELIVERY_AGE_SECONDS as f64)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE webhook_deliveries d SET state='cancelled',last_error='webhook_not_authorized', \
                    error_code='webhook_not_authorized',updated_at=now() \
              WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') AND NOT EXISTS ( \
                SELECT 1 FROM accounts a JOIN webhook_subscriptions s ON s.account_id=a.id \
                 WHERE a.id=d.account_id AND a.status='active' AND s.id=d.subscription_id \
                   AND s.enabled)",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE webhook_deliveries d SET state='failed',last_error='missing_final_brief', \
                    error_code='missing_final_brief',updated_at=now() \
              WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') AND NOT EXISTS ( \
                SELECT 1 FROM episodes e JOIN episode_final_briefs b \
                  ON b.account_id=e.account_id AND b.episode_id=e.id \
                 WHERE e.account_id=d.account_id AND e.id=d.episode_id \
                   AND e.finalization_status='complete' AND e.finalized_at IS NOT NULL)",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        let row = sqlx::query(
            "SELECT d.account_id,d.episode_id,d.subscription_id,d.delivery_version,d.event_id, \
                    d.attempt_count,s.include_content,s.endpoint_url,s.signing_secret, \
                    floor(extract(epoch FROM e.started_at)*1000)::bigint AS started_at_ms, \
                    floor(extract(epoch FROM e.ended_at)*1000)::bigint AS ended_at_ms, \
                    floor(extract(epoch FROM e.finalized_at)*1000)::bigint AS finalized_at_ms, \
                    e.type AS episode_type,e.title,e.participants::text AS participants, \
                    b.overview,b.decisions::text AS decisions,b.action_items::text AS action_items, \
                    b.important_links::text AS important_links,b.open_questions::text AS open_questions \
               FROM webhook_deliveries d JOIN accounts a ON a.id=d.account_id \
               JOIN webhook_subscriptions s ON s.account_id=d.account_id AND s.id=d.subscription_id \
               JOIN episodes e ON e.account_id=d.account_id AND e.id=d.episode_id \
               JOIN episode_final_briefs b ON b.account_id=e.account_id AND b.episode_id=e.id \
              WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') \
                AND d.next_attempt_at<=clock_timestamp() AND a.status='active' AND s.enabled \
                AND NOT EXISTS(SELECT 1 FROM webhook_deliveries earlier \
                    WHERE earlier.account_id=d.account_id \
                      AND earlier.subscription_id=d.subscription_id \
                      AND earlier.state IN ('pending','processing','retry_wait') \
                      AND (earlier.created_at<d.created_at OR \
                           (earlier.created_at=d.created_at AND earlier.event_id<d.event_id))) \
              ORDER BY d.created_at,d.subscription_id,d.event_id LIMIT 1",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let candidate = row
            .as_ref()
            .map(|row| -> Result<WebhookDeliveryCandidate> {
                Ok(WebhookDeliveryCandidate {
                    account_id: row.try_get("account_id")?,
                    episode_id: row.try_get("episode_id")?,
                    subscription_id: row.try_get("subscription_id")?,
                    delivery_version: row.try_get("delivery_version")?,
                    event_id: row.try_get("event_id")?,
                    attempt_count: row.try_get("attempt_count")?,
                    include_content: row.try_get("include_content")?,
                    endpoint_url: row.try_get("endpoint_url")?,
                    signing_secret: row.try_get("signing_secret")?,
                    episode: episode_from_row(row)?,
                })
            })
            .transpose()?;
        transaction.commit().await?;
        Ok(candidate)
    }

    async fn claim_webhook(
        &self,
        candidate: &WebhookDeliveryCandidate,
        request: FrozenWebhookDelivery,
        lease_seconds: i64,
    ) -> Result<Option<WebhookDeliveryClaim>> {
        if !(1..=120).contains(&lease_seconds)
            || candidate.attempt_count < 0
            || candidate.attempt_count >= 10
            || request.endpoint_url != candidate.endpoint_url
            || request.signing_secret != candidate.signing_secret
            || request.include_content != candidate.include_content
        {
            return Err(EnclaveError::Store(
                "webhook delivery candidate is invalid".into(),
            ));
        }
        bounded(&request.endpoint_url, 2_048, "webhook endpoint")?;
        bounded(&request.signing_secret, 512, "webhook signing secret")?;
        bounded(&request.event_body, 512 * 1024, "webhook event body")?;
        let token = tokens::new_uuid();
        let lease = duration_seconds(std::time::Duration::from_secs(
            u64::try_from(lease_seconds)
                .map_err(|_| EnclaveError::Store("webhook lease is invalid".into()))?,
        ))?;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", &candidate.account_id)
            .await?;
        advisory_transaction_lock(&mut transaction, "webhook-registry", &candidate.account_id)
            .await?;
        recover_expired_webhook_claims(&mut transaction, &candidate.account_id).await?;
        let lane_available = sqlx::query_scalar::<_, bool>(
            "SELECT owner_token IS NULL AND next_send_at<=clock_timestamp() \
                    AND (circuit_until IS NULL OR circuit_until<=clock_timestamp()) \
               FROM provider_send_lanes WHERE provider='webhook' FOR UPDATE",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if !lane_available {
            transaction.rollback().await?;
            return Ok(None);
        }
        let current = sqlx::query(
            "SELECT d.attempt_count,a.status,s.enabled,s.endpoint_url,s.signing_secret,s.include_content \
               FROM webhook_deliveries d JOIN accounts a ON a.id=d.account_id \
               JOIN webhook_subscriptions s ON s.account_id=d.account_id AND s.id=d.subscription_id \
              WHERE d.account_id=$1 AND d.episode_id=$2 AND d.subscription_id=$3 \
                AND d.delivery_version=$4 AND d.event_id=$5 AND d.state IN ('pending','retry_wait') \
                AND d.next_attempt_at<=clock_timestamp() FOR UPDATE OF d",
        )
        .bind(&candidate.account_id)
        .bind(candidate.episode_id)
        .bind(&candidate.subscription_id)
        .bind(candidate.delivery_version)
        .bind(&candidate.event_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(current) = current else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let authorized = current.try_get::<String, _>("status")? == "active"
            && current.try_get::<bool, _>("enabled")?
            && current.try_get::<String, _>("endpoint_url")? == request.endpoint_url
            && current.try_get::<String, _>("signing_secret")? == request.signing_secret
            && current.try_get::<bool, _>("include_content")? == request.include_content
            && current.try_get::<i64, _>("attempt_count")? == candidate.attempt_count;
        if !authorized {
            transaction.rollback().await?;
            return Ok(None);
        }
        let new_attempt = candidate
            .attempt_count
            .checked_add(1)
            .ok_or_else(|| EnclaveError::Store("webhook attempt count overflow".into()))?;
        let lease_expires_at_ms = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM (clock_timestamp()+make_interval(secs=>$1)))*1000)::bigint",
        )
        .bind(lease)
        .fetch_one(&mut *transaction)
        .await?;
        let changed = sqlx::query(
            "UPDATE webhook_deliveries SET state='processing',attempt_count=$1,claim_token=$2, \
                    claim_until=to_timestamp($3::double precision/1000.0),frozen_endpoint_url=$4, \
                    frozen_signing_secret=$5,frozen_include_content=$6,frozen_event_body=$7, \
                    send_started_at=clock_timestamp(),last_error=NULL,error_code=NULL,updated_at=now() \
              WHERE account_id=$8 AND episode_id=$9 AND subscription_id=$10 \
                AND delivery_version=$11 AND event_id=$12 AND state IN ('pending','retry_wait')",
        )
        .bind(new_attempt)
        .bind(&token)
        .bind(lease_expires_at_ms)
        .bind(&request.endpoint_url)
        .bind(&request.signing_secret)
        .bind(request.include_content)
        .bind(&request.event_body)
        .bind(&candidate.account_id)
        .bind(candidate.episode_id)
        .bind(&candidate.subscription_id)
        .bind(candidate.delivery_version)
        .bind(&candidate.event_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }
        sqlx::query(
            "INSERT INTO webhook_send_fences(account_id,event_id,subscription_id,claim_id, \
                    lease_expires_at,endpoint_url,signing_secret,include_content) \
             VALUES($1,$2,$3,$4,to_timestamp($5::double precision/1000.0),$6,$7,$8)",
        )
        .bind(&candidate.account_id)
        .bind(&candidate.event_id)
        .bind(&candidate.subscription_id)
        .bind(&token)
        .bind(lease_expires_at_ms)
        .bind(&request.endpoint_url)
        .bind(&request.signing_secret)
        .bind(request.include_content)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=$1, \
                    lease_until=to_timestamp($2::double precision/1000.0),updated_at=now() \
              WHERE provider='webhook'",
        )
        .bind(&token)
        .bind(lease_expires_at_ms)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Some(WebhookDeliveryClaim {
            account_id: candidate.account_id.clone(),
            episode_id: candidate.episode_id,
            subscription_id: candidate.subscription_id.clone(),
            delivery_version: candidate.delivery_version,
            event_id: candidate.event_id.clone(),
            claim_token: token,
            lease_expires_at: isotime::format_epoch_millis(lease_expires_at_ms),
            attempt_count: new_attempt,
            request,
        }))
    }

    async fn settle_webhook(
        &self,
        claim: &WebhookDeliveryClaim,
        outcome: WebhookProviderOutcome,
        circuit_seconds: Option<i64>,
    ) -> Result<()> {
        if !outcome.is_valid()
            || circuit_seconds.is_some_and(|seconds| !(1..=6 * 60 * 60).contains(&seconds))
        {
            return Err(EnclaveError::Store(
                "webhook delivery settlement is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "webhook-registry", &claim.account_id).await?;
        let row = sqlx::query(
            "SELECT state,claim_token,completed_claim_token FROM webhook_deliveries \
              WHERE account_id=$1 AND episode_id=$2 AND subscription_id=$3 \
                AND delivery_version=$4 AND event_id=$5 FOR UPDATE",
        )
        .bind(&claim.account_id)
        .bind(claim.episode_id)
        .bind(&claim.subscription_id)
        .bind(claim.delivery_version)
        .bind(&claim.event_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("webhook delivery disappeared".into()))?;
        if row
            .try_get::<Option<String>, _>("completed_claim_token")?
            .as_deref()
            == Some(&claim.claim_token)
        {
            transaction.commit().await?;
            return Ok(());
        }
        if row.try_get::<String, _>("state")? != "processing"
            || row.try_get::<Option<String>, _>("claim_token")?.as_deref()
                != Some(&claim.claim_token)
        {
            return Err(EnclaveError::Conflict(
                "webhook delivery claim is no longer authoritative".into(),
            ));
        }
        let fence_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM webhook_send_fences WHERE account_id=$1 \
                    AND event_id=$2 AND subscription_id=$3 AND claim_id=$4 \
                    AND endpoint_url=$5 AND signing_secret=$6 AND include_content=$7)",
        )
        .bind(&claim.account_id)
        .bind(&claim.event_id)
        .bind(&claim.subscription_id)
        .bind(&claim.claim_token)
        .bind(&claim.request.endpoint_url)
        .bind(&claim.request.signing_secret)
        .bind(claim.request.include_content)
        .fetch_one(&mut *transaction)
        .await?;
        if !fence_exists {
            return Err(EnclaveError::Conflict(
                "webhook disclosure fence disappeared".into(),
            ));
        }
        let (state, status, error_code, retry_at) = match &outcome {
            WebhookProviderOutcome::Sent { status } => ("delivered", Some(*status), None, None),
            WebhookProviderOutcome::Retry {
                status,
                code,
                retry_at,
            } => (
                "retry_wait",
                *status,
                Some(code.as_str()),
                Some(timestamp(retry_at)?),
            ),
            WebhookProviderOutcome::Ambiguous => ("ambiguous", None, Some("outcome_unknown"), None),
            WebhookProviderOutcome::Failed { status, code } => {
                ("failed", *status, Some(code.as_str()), None)
            }
        };
        let changed = sqlx::query(
            "UPDATE webhook_deliveries SET state=$1,completed_claim_token=$2,claim_token=NULL, \
                    claim_until=NULL,next_attempt_at=CASE WHEN $3::bigint IS NULL THEN next_attempt_at \
                      ELSE to_timestamp($3::double precision/1000.0) END,response_status=$4, \
                    error_code=$5,last_error=$5,updated_at=now() \
              WHERE account_id=$6 AND episode_id=$7 AND subscription_id=$8 \
                AND delivery_version=$9 AND event_id=$10 AND state='processing' AND claim_token=$2",
        )
        .bind(state)
        .bind(&claim.claim_token)
        .bind(retry_at)
        .bind(status)
        .bind(error_code)
        .bind(&claim.account_id)
        .bind(claim.episode_id)
        .bind(&claim.subscription_id)
        .bind(claim.delivery_version)
        .bind(&claim.event_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "webhook delivery was not settled exactly once".into(),
            ));
        }
        sqlx::query(
            "DELETE FROM webhook_send_fences WHERE account_id=$1 AND event_id=$2 AND claim_id=$3",
        )
        .bind(&claim.account_id)
        .bind(&claim.event_id)
        .bind(&claim.claim_token)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL, \
                    next_send_at=clock_timestamp()+make_interval(secs=>$1), \
                    circuit_until=CASE WHEN $2::double precision IS NULL THEN circuit_until \
                      ELSE clock_timestamp()+make_interval(secs=>$2) END,updated_at=now() \
              WHERE provider='webhook' AND owner_token=$3",
        )
        .bind(PROVIDER_PACE_MILLIS as f64 / 1_000.0)
        .bind(circuit_seconds.map(|seconds| seconds as f64))
        .bind(&claim.claim_token)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn next_push_candidate(&self, account_id: &str) -> Result<Option<PushDeliveryCandidate>> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        advisory_transaction_lock(&mut transaction, "push-registry", "global").await?;
        recover_expired_push_claims(&mut transaction, account_id).await?;
        sqlx::query(
            "UPDATE push_deliveries SET state='cancelled',last_error='delivery_expired', \
                    error_code='delivery_expired',updated_at=now() \
              WHERE account_id=$1 AND state IN ('pending','retry_wait') \
                AND created_at<=clock_timestamp()-make_interval(secs=>$2)",
        )
        .bind(account_id)
        .bind(MAX_DELIVERY_AGE_SECONDS as f64)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE push_deliveries d SET state='cancelled',last_error='push_not_authorized', \
                    error_code='push_not_authorized',updated_at=now() \
              WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') AND NOT EXISTS ( \
                SELECT 1 FROM accounts a JOIN push_installations p ON p.account_id=a.id \
                 WHERE a.id=d.account_id AND a.status='active' AND p.enabled \
                   AND d.installation_binding=('p1:'||p.id||':'||p.token_generation::text))",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
        let row = sqlx::query(
            "SELECT d.account_id,d.episode_id,d.installation_binding,p.id AS installation_id, \
                    d.delivery_version,d.delivery_id,d.handoff_handle,d.collapse_id,d.attempt_count, \
                    floor(extract(epoch FROM d.created_at)*1000)::bigint AS created_at_ms, \
                    p.topic,p.environment,p.device_token,p.token_generation \
               FROM push_deliveries d JOIN accounts a ON a.id=d.account_id \
               JOIN push_installations p ON p.account_id=d.account_id \
                    AND d.installation_binding=('p1:'||p.id||':'||p.token_generation::text) \
              WHERE d.account_id=$1 AND d.state IN ('pending','retry_wait') \
                AND d.next_attempt_at<=clock_timestamp() AND a.status='active' AND p.enabled \
                AND NOT EXISTS(SELECT 1 FROM push_deliveries earlier \
                    WHERE earlier.account_id=d.account_id \
                      AND earlier.installation_binding=d.installation_binding \
                      AND earlier.state IN ('pending','processing','retry_wait') \
                      AND (earlier.created_at<d.created_at OR \
                           (earlier.created_at=d.created_at AND earlier.delivery_id<d.delivery_id))) \
              ORDER BY d.created_at,d.installation_binding,d.delivery_id LIMIT 1",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let candidate = row
            .as_ref()
            .map(|row| -> Result<PushDeliveryCandidate> {
                Ok(PushDeliveryCandidate {
                    account_id: row.try_get("account_id")?,
                    episode_id: row.try_get("episode_id")?,
                    installation_binding: row.try_get("installation_binding")?,
                    installation_id: row.try_get("installation_id")?,
                    delivery_version: row.try_get("delivery_version")?,
                    delivery_id: row.try_get("delivery_id")?,
                    handoff_handle: row.try_get("handoff_handle")?,
                    collapse_id: row.try_get("collapse_id")?,
                    attempt_count: row.try_get("attempt_count")?,
                    created_at: isotime::format_epoch_millis(row.try_get("created_at_ms")?),
                    topic: row.try_get("topic")?,
                    environment: row.try_get("environment")?,
                    device_token: row.try_get("device_token")?,
                    token_generation: row.try_get("token_generation")?,
                })
            })
            .transpose()?;
        transaction.commit().await?;
        Ok(candidate)
    }

    async fn claim_push(
        &self,
        candidate: &PushDeliveryCandidate,
        request: FrozenPushDelivery,
        lease_seconds: i64,
    ) -> Result<Option<PushDeliveryClaim>> {
        if !(1..=120).contains(&lease_seconds)
            || candidate.attempt_count < 0
            || candidate.attempt_count >= 10
            || request.topic != candidate.topic
            || request.environment != candidate.environment
            || request.device_token != candidate.device_token
            || request.token_generation != candidate.token_generation
            || request.token_generation <= 0
        {
            return Err(EnclaveError::Store(
                "push delivery candidate is invalid".into(),
            ));
        }
        bounded(&request.topic, 256, "push topic")?;
        bounded(&request.environment, 32, "push environment")?;
        bounded(&request.device_token, 512, "push device token")?;
        let token = tokens::new_uuid();
        let lease = duration_seconds(std::time::Duration::from_secs(
            u64::try_from(lease_seconds)
                .map_err(|_| EnclaveError::Store("push lease is invalid".into()))?,
        ))?;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", &candidate.account_id)
            .await?;
        advisory_transaction_lock(&mut transaction, "push-registry", "global").await?;
        recover_expired_push_claims(&mut transaction, &candidate.account_id).await?;
        let lane_available = sqlx::query_scalar::<_, bool>(
            "SELECT owner_token IS NULL AND next_send_at<=clock_timestamp() \
                    AND (circuit_until IS NULL OR circuit_until<=clock_timestamp()) \
               FROM provider_send_lanes WHERE provider='push' FOR UPDATE",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if !lane_available {
            transaction.rollback().await?;
            return Ok(None);
        }
        let current = sqlx::query(
            "SELECT d.attempt_count,a.status,p.enabled,p.topic,p.environment,p.device_token, \
                    p.token_generation \
               FROM push_deliveries d JOIN accounts a ON a.id=d.account_id \
               JOIN push_installations p ON p.account_id=d.account_id AND p.id=$5 \
              WHERE d.account_id=$1 AND d.episode_id=$2 AND d.delivery_version=$3 \
                AND d.delivery_id=$4 AND d.installation_binding=$6 \
                AND d.state IN ('pending','retry_wait') AND d.next_attempt_at<=clock_timestamp() \
              FOR UPDATE OF d",
        )
        .bind(&candidate.account_id)
        .bind(candidate.episode_id)
        .bind(candidate.delivery_version)
        .bind(&candidate.delivery_id)
        .bind(&candidate.installation_id)
        .bind(&candidate.installation_binding)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(current) = current else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let authorized = current.try_get::<String, _>("status")? == "active"
            && current.try_get::<bool, _>("enabled")?
            && current.try_get::<String, _>("topic")? == request.topic
            && current.try_get::<String, _>("environment")? == request.environment
            && current.try_get::<String, _>("device_token")? == request.device_token
            && current.try_get::<i64, _>("token_generation")? == request.token_generation
            && current.try_get::<i64, _>("attempt_count")? == candidate.attempt_count;
        if !authorized {
            transaction.rollback().await?;
            return Ok(None);
        }
        let new_attempt = candidate
            .attempt_count
            .checked_add(1)
            .ok_or_else(|| EnclaveError::Store("push attempt count overflow".into()))?;
        let lease_expires_at_ms = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM (clock_timestamp()+make_interval(secs=>$1)))*1000)::bigint",
        )
        .bind(lease)
        .fetch_one(&mut *transaction)
        .await?;
        let changed = sqlx::query(
            "UPDATE push_deliveries SET state='processing',attempt_count=$1,claim_token=$2, \
                    claim_until=to_timestamp($3::double precision/1000.0),frozen_topic=$4, \
                    frozen_environment=$5,frozen_device_token=$6,frozen_token_generation=$7, \
                    send_started_at=clock_timestamp(),last_error=NULL,error_code=NULL,updated_at=now() \
              WHERE account_id=$8 AND episode_id=$9 AND installation_binding=$10 \
                AND delivery_version=$11 AND delivery_id=$12 AND state IN ('pending','retry_wait')",
        )
        .bind(new_attempt)
        .bind(&token)
        .bind(lease_expires_at_ms)
        .bind(&request.topic)
        .bind(&request.environment)
        .bind(&request.device_token)
        .bind(request.token_generation)
        .bind(&candidate.account_id)
        .bind(candidate.episode_id)
        .bind(&candidate.installation_binding)
        .bind(candidate.delivery_version)
        .bind(&candidate.delivery_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }
        sqlx::query(
            "INSERT INTO push_send_fences(account_id,installation_id,token_generation,claim_id, \
                                          lease_expires_at) \
             VALUES($1,$2,$3,$4,to_timestamp($5::double precision/1000.0))",
        )
        .bind(&candidate.account_id)
        .bind(&candidate.installation_id)
        .bind(request.token_generation)
        .bind(&token)
        .bind(lease_expires_at_ms)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=$1, \
                    lease_until=to_timestamp($2::double precision/1000.0),updated_at=now() \
              WHERE provider='push'",
        )
        .bind(&token)
        .bind(lease_expires_at_ms)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Some(PushDeliveryClaim {
            account_id: candidate.account_id.clone(),
            episode_id: candidate.episode_id,
            installation_binding: candidate.installation_binding.clone(),
            installation_id: candidate.installation_id.clone(),
            delivery_version: candidate.delivery_version,
            delivery_id: candidate.delivery_id.clone(),
            handoff_handle: candidate.handoff_handle.clone(),
            collapse_id: candidate.collapse_id.clone(),
            claim_token: token,
            lease_expires_at: isotime::format_epoch_millis(lease_expires_at_ms),
            attempt_count: new_attempt,
            created_at: candidate.created_at.clone(),
            request,
        }))
    }

    async fn settle_push(
        &self,
        claim: &PushDeliveryClaim,
        outcome: PushProviderOutcome,
        circuit_seconds: Option<i64>,
    ) -> Result<()> {
        if !outcome.is_valid()
            || circuit_seconds.is_some_and(|seconds| !(1..=6 * 60 * 60).contains(&seconds))
        {
            return Err(EnclaveError::Store(
                "push delivery settlement is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "push-registry", "global").await?;
        let row = sqlx::query(
            "SELECT state,claim_token,completed_claim_token FROM push_deliveries \
              WHERE account_id=$1 AND episode_id=$2 AND installation_binding=$3 \
                AND delivery_version=$4 AND delivery_id=$5 FOR UPDATE",
        )
        .bind(&claim.account_id)
        .bind(claim.episode_id)
        .bind(&claim.installation_binding)
        .bind(claim.delivery_version)
        .bind(&claim.delivery_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| EnclaveError::Conflict("push delivery disappeared".into()))?;
        if row
            .try_get::<Option<String>, _>("completed_claim_token")?
            .as_deref()
            == Some(&claim.claim_token)
        {
            transaction.commit().await?;
            return Ok(());
        }
        if row.try_get::<String, _>("state")? != "processing"
            || row.try_get::<Option<String>, _>("claim_token")?.as_deref()
                != Some(&claim.claim_token)
        {
            return Err(EnclaveError::Conflict(
                "push delivery claim is no longer authoritative".into(),
            ));
        }
        let fence_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM push_send_fences WHERE account_id=$1 \
                    AND installation_id=$2 AND token_generation=$3 AND claim_id=$4)",
        )
        .bind(&claim.account_id)
        .bind(&claim.installation_id)
        .bind(claim.request.token_generation)
        .bind(&claim.claim_token)
        .fetch_one(&mut *transaction)
        .await?;
        if !fence_exists {
            return Err(EnclaveError::Conflict(
                "push disclosure fence disappeared".into(),
            ));
        }
        let (state, status, error_code, retry_at) = match &outcome {
            PushProviderOutcome::Accepted { status } => ("delivered", Some(*status), None, None),
            PushProviderOutcome::Retry {
                status,
                code,
                retry_at,
            } => (
                "retry_wait",
                *status,
                Some(code.as_str()),
                Some(timestamp(retry_at)?),
            ),
            PushProviderOutcome::Ambiguous => ("ambiguous", None, Some("outcome_unknown"), None),
            PushProviderOutcome::Failed { status, code } => {
                ("failed", *status, Some(code.as_str()), None)
            }
            PushProviderOutcome::TokenTerminal { status, code } => {
                ("failed", Some(*status), Some(code.as_str()), None)
            }
        };
        let changed = sqlx::query(
            "UPDATE push_deliveries SET state=$1,completed_claim_token=$2,claim_token=NULL, \
                    claim_until=NULL,next_attempt_at=CASE WHEN $3::bigint IS NULL THEN next_attempt_at \
                      ELSE to_timestamp($3::double precision/1000.0) END,response_status=$4, \
                    error_code=$5,last_error=$5,updated_at=now() \
              WHERE account_id=$6 AND episode_id=$7 AND installation_binding=$8 \
                AND delivery_version=$9 AND delivery_id=$10 AND state='processing' AND claim_token=$2",
        )
        .bind(state)
        .bind(&claim.claim_token)
        .bind(retry_at)
        .bind(status)
        .bind(error_code)
        .bind(&claim.account_id)
        .bind(claim.episode_id)
        .bind(&claim.installation_binding)
        .bind(claim.delivery_version)
        .bind(&claim.delivery_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "push delivery was not settled exactly once".into(),
            ));
        }
        if matches!(outcome, PushProviderOutcome::TokenTerminal { .. }) {
            sqlx::query(
                "UPDATE push_installations SET enabled=false,updated_at=now() \
                  WHERE account_id=$1 AND id=$2 AND token_generation=$3",
            )
            .bind(&claim.account_id)
            .bind(&claim.installation_id)
            .bind(claim.request.token_generation)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query("DELETE FROM push_send_fences WHERE account_id=$1 AND claim_id=$2")
            .bind(&claim.account_id)
            .bind(&claim.claim_token)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE provider_send_lanes SET owner_token=NULL,lease_until=NULL, \
                    next_send_at=clock_timestamp()+make_interval(secs=>$1), \
                    circuit_until=CASE WHEN $2::double precision IS NULL THEN circuit_until \
                      ELSE clock_timestamp()+make_interval(secs=>$2) END,updated_at=now() \
              WHERE provider='push' AND owner_token=$3",
        )
        .bind(PROVIDER_PACE_MILLIS as f64 / 1_000.0)
        .bind(circuit_seconds.map(|seconds| seconds as f64))
        .bind(&claim.claim_token)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}
