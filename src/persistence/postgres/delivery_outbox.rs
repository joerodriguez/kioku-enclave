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
        FrozenEmailDelivery,
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
}
