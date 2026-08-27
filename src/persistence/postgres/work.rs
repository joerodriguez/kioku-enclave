use async_trait::async_trait;
use sqlx::Row;

use crate::{
    cp::isotime,
    error::{EnclaveError, Result},
    persistence::{
        work::{valid_claim_id, valid_fence_text, valid_fence_timestamp},
        EmailControlCancellation, EmailFenceOutcome, EmailProviderOutcome, EmailSendFence,
        EmailSendFenceDisposition, EpisodeEmailPreference, PushControlCancellation,
        PushFenceOutcome, PushInstallation, PushProviderOutcome, PushProviderReceipt,
        PushSendFence, PushSendFenceDisposition, WebhookControlCancellation, WebhookFenceOutcome,
        WebhookProviderOutcome, WebhookSendFence, WebhookSendFenceDisposition, WebhookSubscription,
        WorkRepository,
    },
};

use super::{advisory_transaction_lock, PostgresPersistence};

fn parse_timestamp(value: &str) -> Result<i64> {
    isotime::parse_epoch_millis(value)
        .filter(|millis| isotime::format_epoch_millis(*millis) == value)
        .ok_or_else(|| EnclaveError::Store("provider fence timestamp is invalid".into()))
}

fn required_timestamp(row: &sqlx::postgres::PgRow, name: &str) -> Result<String> {
    Ok(isotime::format_epoch_millis(row.try_get::<i64, _>(name)?))
}

fn optional_timestamp(row: &sqlx::postgres::PgRow, name: &str) -> Result<Option<String>> {
    Ok(row
        .try_get::<Option<i64>, _>(name)?
        .map(isotime::format_epoch_millis))
}

async fn account_status(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT status FROM accounts WHERE id=$1")
            .bind(account_id)
            .fetch_optional(&mut **transaction)
            .await?,
    )
}

async fn deletion_owned(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND status='deleting') OR \
                (NOT EXISTS(SELECT 1 FROM accounts WHERE id=$1) AND \
                 EXISTS(SELECT 1 FROM deleted_accounts WHERE account_id=$1))",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await?)
}

fn webhook_subscription_from_row(row: &sqlx::postgres::PgRow) -> Result<WebhookSubscription> {
    Ok(WebhookSubscription {
        id: row.try_get("id")?,
        user_id: row.try_get("account_id")?,
        name: row.try_get("name")?,
        endpoint_url: row.try_get("endpoint_url")?,
        signing_secret: row.try_get("signing_secret")?,
        include_content: row.try_get("include_content")?,
        enabled: row.try_get("enabled")?,
        created_at: required_timestamp(row, "created_at_ms")?,
    })
}

async fn load_webhook_subscription(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    subscription_id: &str,
) -> Result<Option<WebhookSubscription>> {
    let row = sqlx::query(
        "SELECT account_id,id,name,endpoint_url,signing_secret,include_content,enabled, \
                floor(extract(epoch FROM created_at) * 1000)::bigint AS created_at_ms \
           FROM webhook_subscriptions WHERE account_id=$1 AND id=$2",
    )
    .bind(account_id)
    .bind(subscription_id)
    .fetch_optional(&mut **transaction)
    .await?;
    row.as_ref().map(webhook_subscription_from_row).transpose()
}

fn webhook_fence_from_row(row: &sqlx::postgres::PgRow) -> Result<WebhookSendFence> {
    let kind: Option<String> = row.try_get("outcome_kind")?;
    let status: Option<i64> = row.try_get("provider_status")?;
    let error: Option<String> = row.try_get("provider_error")?;
    let retry_at = optional_timestamp(row, "retry_at_ms")?;
    let outcome_at = optional_timestamp(row, "outcome_at_ms")?;
    let outcome = match kind.as_deref() {
        None if status.is_none()
            && error.is_none()
            && retry_at.is_none()
            && outcome_at.is_none() =>
        {
            None
        }
        Some("sent")
            if status.is_some()
                && error.is_none()
                && retry_at.is_none()
                && outcome_at.is_some() =>
        {
            Some(WebhookFenceOutcome::Provider(
                WebhookProviderOutcome::Sent {
                    status: status
                        .ok_or_else(|| EnclaveError::Store("missing webhook status".into()))?,
                },
            ))
        }
        Some("retry") if error.is_some() && retry_at.is_some() && outcome_at.is_some() => Some(
            WebhookFenceOutcome::Provider(WebhookProviderOutcome::Retry {
                status,
                code: error.ok_or_else(|| EnclaveError::Store("missing webhook error".into()))?,
                retry_at: retry_at
                    .ok_or_else(|| EnclaveError::Store("missing webhook retry time".into()))?,
            }),
        ),
        Some("ambiguous")
            if status.is_none()
                && error.is_none()
                && retry_at.is_none()
                && outcome_at.is_some() =>
        {
            Some(WebhookFenceOutcome::Provider(
                WebhookProviderOutcome::Ambiguous,
            ))
        }
        Some("failed") if error.is_some() && retry_at.is_none() && outcome_at.is_some() => Some(
            WebhookFenceOutcome::Provider(WebhookProviderOutcome::Failed {
                status,
                code: error.ok_or_else(|| EnclaveError::Store("missing webhook error".into()))?,
            }),
        ),
        Some(kind)
            if status.is_none()
                && error.is_none()
                && retry_at.is_none()
                && outcome_at.is_some() =>
        {
            Some(WebhookFenceOutcome::Cancellation(
                WebhookControlCancellation::from_kind(kind).ok_or_else(|| {
                    EnclaveError::Store("invalid webhook cancellation outcome".into())
                })?,
            ))
        }
        _ => return Err(EnclaveError::Store("malformed webhook send fence".into())),
    };
    let fence = WebhookSendFence {
        user_id: row.try_get("account_id")?,
        event_id: row.try_get("event_id")?,
        subscription_id: row.try_get("subscription_id")?,
        claim_id: row.try_get("claim_id")?,
        lease_expires_at: required_timestamp(row, "lease_expires_at_ms")?,
        endpoint_url: row.try_get("endpoint_url")?,
        signing_secret: row.try_get("signing_secret")?,
        include_content: row.try_get("include_content")?,
        outcome,
        outcome_at,
    };
    if !valid_claim_id(&fence.claim_id)
        || !valid_fence_text(&fence.event_id, 68)
        || !valid_fence_text(&fence.subscription_id, 36)
        || !valid_fence_timestamp(&fence.lease_expires_at)
        || !valid_fence_text(&fence.endpoint_url, 2_048)
        || !valid_fence_text(&fence.signing_secret, 256)
        || !fence.outcome.as_ref().is_none_or(|outcome| match outcome {
            WebhookFenceOutcome::Provider(outcome) => outcome.is_valid(),
            WebhookFenceOutcome::Cancellation(_) => true,
        })
        || !fence
            .outcome_at
            .as_deref()
            .is_none_or(valid_fence_timestamp)
    {
        return Err(EnclaveError::Store("malformed webhook send fence".into()));
    }
    Ok(fence)
}

async fn load_webhook_fence(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    event_id: &str,
    for_update: bool,
) -> Result<Option<WebhookSendFence>> {
    let row = if for_update {
        sqlx::query(
            "SELECT account_id,event_id,subscription_id,claim_id, \
                    floor(extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, \
                    endpoint_url,signing_secret,include_content,outcome_kind,provider_status,provider_error, \
                    floor(extract(epoch FROM retry_at) * 1000)::bigint AS retry_at_ms, \
                    floor(extract(epoch FROM outcome_at) * 1000)::bigint AS outcome_at_ms \
               FROM webhook_send_fences WHERE account_id=$1 AND event_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(event_id)
        .fetch_optional(&mut **transaction)
        .await?
    } else {
        sqlx::query(
            "SELECT account_id,event_id,subscription_id,claim_id, \
                    floor(extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, \
                    endpoint_url,signing_secret,include_content,outcome_kind,provider_status,provider_error, \
                    floor(extract(epoch FROM retry_at) * 1000)::bigint AS retry_at_ms, \
                    floor(extract(epoch FROM outcome_at) * 1000)::bigint AS outcome_at_ms \
               FROM webhook_send_fences WHERE account_id=$1 AND event_id=$2",
        )
        .bind(account_id)
        .bind(event_id)
        .fetch_optional(&mut **transaction)
        .await?
    };
    row.as_ref().map(webhook_fence_from_row).transpose()
}

async fn email_preference(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<EpisodeEmailPreference> {
    let account = sqlx::query("SELECT email FROM accounts WHERE id=$1")
        .bind(account_id)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(account) = account else {
        return Ok(EpisodeEmailPreference {
            enabled: false,
            include_content: false,
            recipient_email: "missing-account@invalid.invalid".into(),
            consented_at: None,
            updated_at: "1970-01-01T00:00:00.000Z".into(),
        });
    };
    let email: String = account.try_get("email")?;
    let row = sqlx::query(
        "SELECT enabled,include_content, \
                floor(extract(epoch FROM consented_at) * 1000)::bigint AS consented_at_ms, \
                floor(extract(epoch FROM updated_at) * 1000)::bigint AS updated_at_ms \
           FROM episode_email_preferences WHERE account_id=$1",
    )
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await?;
    match row {
        Some(row) => Ok(EpisodeEmailPreference {
            enabled: row.try_get("enabled")?,
            include_content: row.try_get("include_content")?,
            recipient_email: email,
            consented_at: optional_timestamp(&row, "consented_at_ms")?,
            updated_at: required_timestamp(&row, "updated_at_ms")?,
        }),
        None => Ok(EpisodeEmailPreference {
            enabled: false,
            include_content: false,
            recipient_email: email,
            consented_at: None,
            updated_at: "1970-01-01T00:00:00.000Z".into(),
        }),
    }
}

fn email_fence_from_row(row: &sqlx::postgres::PgRow) -> Result<EmailSendFence> {
    let kind: Option<String> = row.try_get("outcome_kind")?;
    let status: Option<i64> = row.try_get("provider_status")?;
    let provider_message_id: Option<String> = row.try_get("provider_message_id")?;
    let error: Option<String> = row.try_get("provider_error")?;
    let retry_at = optional_timestamp(row, "retry_at_ms")?;
    let outcome_at = optional_timestamp(row, "outcome_at_ms")?;
    let outcome = match kind.as_deref() {
        None if status.is_none()
            && provider_message_id.is_none()
            && error.is_none()
            && retry_at.is_none()
            && outcome_at.is_none() =>
        {
            None
        }
        Some("accepted")
            if status.is_some()
                && provider_message_id.is_some()
                && error.is_none()
                && retry_at.is_none()
                && outcome_at.is_some() =>
        {
            Some(EmailFenceOutcome::Provider(
                EmailProviderOutcome::Accepted {
                    status: status
                        .ok_or_else(|| EnclaveError::Store("missing email status".into()))?,
                    provider_message_id: provider_message_id
                        .ok_or_else(|| EnclaveError::Store("missing email provider id".into()))?,
                },
            ))
        }
        Some("retry")
            if provider_message_id.is_none()
                && error.is_some()
                && retry_at.is_some()
                && outcome_at.is_some() =>
        {
            Some(EmailFenceOutcome::Provider(EmailProviderOutcome::Retry {
                status,
                code: error.ok_or_else(|| EnclaveError::Store("missing email error".into()))?,
                retry_at: retry_at
                    .ok_or_else(|| EnclaveError::Store("missing email retry time".into()))?,
            }))
        }
        Some("ambiguous")
            if status.is_none()
                && provider_message_id.is_none()
                && error.is_none()
                && retry_at.is_none()
                && outcome_at.is_some() =>
        {
            Some(EmailFenceOutcome::Provider(EmailProviderOutcome::Ambiguous))
        }
        Some("failed")
            if provider_message_id.is_none()
                && error.is_some()
                && retry_at.is_none()
                && outcome_at.is_some() =>
        {
            Some(EmailFenceOutcome::Provider(EmailProviderOutcome::Failed {
                status,
                code: error.ok_or_else(|| EnclaveError::Store("missing email error".into()))?,
            }))
        }
        Some(kind)
            if status.is_none()
                && provider_message_id.is_none()
                && error.is_none()
                && retry_at.is_none()
                && outcome_at.is_some() =>
        {
            Some(EmailFenceOutcome::Cancellation(
                EmailControlCancellation::from_kind(kind).ok_or_else(|| {
                    EnclaveError::Store("invalid email cancellation outcome".into())
                })?,
            ))
        }
        _ => return Err(EnclaveError::Store("malformed email send fence".into())),
    };
    let fence = EmailSendFence {
        user_id: row.try_get("account_id")?,
        delivery_id: row.try_get("delivery_id")?,
        claim_id: row.try_get("claim_id")?,
        lease_expires_at: required_timestamp(row, "lease_expires_at_ms")?,
        recipient_email: row.try_get("recipient_email")?,
        include_content: row.try_get("include_content")?,
        outcome,
        outcome_at,
    };
    if !valid_claim_id(&fence.claim_id)
        || !valid_fence_text(&fence.delivery_id, 96)
        || !valid_fence_timestamp(&fence.lease_expires_at)
        || !valid_fence_text(&fence.recipient_email, 320)
        || !fence.recipient_email.contains('@')
        || !fence.outcome.as_ref().is_none_or(|outcome| match outcome {
            EmailFenceOutcome::Provider(outcome) => outcome.is_valid(),
            EmailFenceOutcome::Cancellation(_) => true,
        })
        || !fence
            .outcome_at
            .as_deref()
            .is_none_or(valid_fence_timestamp)
    {
        return Err(EnclaveError::Store("malformed email send fence".into()));
    }
    Ok(fence)
}

async fn load_email_fence(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    delivery_id: &str,
    for_update: bool,
) -> Result<Option<EmailSendFence>> {
    let row = if for_update {
        sqlx::query(
            "SELECT account_id,delivery_id,claim_id, \
                    floor(extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, \
                    recipient_email,include_content,outcome_kind,provider_status,provider_message_id, \
                    provider_error,floor(extract(epoch FROM retry_at) * 1000)::bigint AS retry_at_ms, \
                    floor(extract(epoch FROM outcome_at) * 1000)::bigint AS outcome_at_ms \
               FROM email_send_fences WHERE account_id=$1 AND delivery_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(delivery_id)
        .fetch_optional(&mut **transaction)
        .await?
    } else {
        sqlx::query(
            "SELECT account_id,delivery_id,claim_id, \
                    floor(extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, \
                    recipient_email,include_content,outcome_kind,provider_status,provider_message_id, \
                    provider_error,floor(extract(epoch FROM retry_at) * 1000)::bigint AS retry_at_ms, \
                    floor(extract(epoch FROM outcome_at) * 1000)::bigint AS outcome_at_ms \
               FROM email_send_fences WHERE account_id=$1 AND delivery_id=$2",
        )
        .bind(account_id)
        .bind(delivery_id)
        .fetch_optional(&mut **transaction)
        .await?
    };
    row.as_ref().map(email_fence_from_row).transpose()
}

fn push_installation_from_row(row: &sqlx::postgres::PgRow) -> Result<PushInstallation> {
    Ok(PushInstallation {
        id: row.try_get("id")?,
        user_id: row.try_get("account_id")?,
        platform: row.try_get("platform")?,
        topic: row.try_get("topic")?,
        environment: row.try_get("environment")?,
        device_token: row.try_get("device_token")?,
        token_generation: row.try_get("token_generation")?,
        enabled: row.try_get("enabled")?,
    })
}

async fn load_push_installation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    installation_id: &str,
) -> Result<Option<PushInstallation>> {
    let row = sqlx::query(
        "SELECT account_id,id,platform,topic,environment,device_token,token_generation,enabled \
           FROM push_installations WHERE account_id=$1 AND id=$2",
    )
    .bind(account_id)
    .bind(installation_id)
    .fetch_optional(&mut **transaction)
    .await?;
    row.as_ref().map(push_installation_from_row).transpose()
}

fn push_fence_from_row(row: &sqlx::postgres::PgRow) -> Result<PushSendFence> {
    let kind: Option<String> = row.try_get("outcome_kind")?;
    let status: Option<i64> = row.try_get("provider_status")?;
    let error: Option<String> = row.try_get("provider_error")?;
    let retry_at = optional_timestamp(row, "retry_at_ms")?;
    let outcome_at = optional_timestamp(row, "outcome_at_ms")?;
    let outcome = match kind.as_deref() {
        None if status.is_none()
            && error.is_none()
            && retry_at.is_none()
            && outcome_at.is_none() =>
        {
            None
        }
        Some("accepted") if error.is_none() && retry_at.is_none() && outcome_at.is_some() => {
            Some(PushFenceOutcome::Provider(PushProviderOutcome::Accepted {
                status: status.ok_or_else(|| EnclaveError::Store("missing push status".into()))?,
            }))
        }
        Some("retry") if error.is_some() && retry_at.is_some() && outcome_at.is_some() => {
            Some(PushFenceOutcome::Provider(PushProviderOutcome::Retry {
                status,
                code: error.ok_or_else(|| EnclaveError::Store("missing push error".into()))?,
                retry_at: retry_at
                    .ok_or_else(|| EnclaveError::Store("missing push retry time".into()))?,
            }))
        }
        Some("ambiguous")
            if status.is_none()
                && error.is_none()
                && retry_at.is_none()
                && outcome_at.is_some() =>
        {
            Some(PushFenceOutcome::Provider(PushProviderOutcome::Ambiguous))
        }
        Some("failed") if error.is_some() && retry_at.is_none() && outcome_at.is_some() => {
            Some(PushFenceOutcome::Provider(PushProviderOutcome::Failed {
                status,
                code: error.ok_or_else(|| EnclaveError::Store("missing push error".into()))?,
            }))
        }
        Some("token_terminal") if error.is_some() && retry_at.is_none() && outcome_at.is_some() => {
            Some(PushFenceOutcome::Provider(
                PushProviderOutcome::TokenTerminal {
                    status: status
                        .ok_or_else(|| EnclaveError::Store("missing push status".into()))?,
                    code: error.ok_or_else(|| EnclaveError::Store("missing push error".into()))?,
                },
            ))
        }
        Some(kind)
            if status.is_none()
                && error.is_none()
                && retry_at.is_none()
                && outcome_at.is_some() =>
        {
            Some(PushFenceOutcome::Cancellation(
                PushControlCancellation::from_kind(kind).ok_or_else(|| {
                    EnclaveError::Store("invalid push cancellation outcome".into())
                })?,
            ))
        }
        _ => return Err(EnclaveError::Store("malformed push send fence".into())),
    };
    let fence = PushSendFence {
        user_id: row.try_get("account_id")?,
        installation_id: row.try_get("installation_id")?,
        token_generation: row.try_get("token_generation")?,
        claim_id: row.try_get("claim_id")?,
        lease_expires_at: required_timestamp(row, "lease_expires_at_ms")?,
        outcome,
        outcome_at,
    };
    if fence.token_generation <= 0
        || !valid_claim_id(&fence.installation_id)
        || !valid_claim_id(&fence.claim_id)
        || !valid_fence_timestamp(&fence.lease_expires_at)
        || !fence.outcome.as_ref().is_none_or(|outcome| match outcome {
            PushFenceOutcome::Provider(outcome) => outcome.is_valid(),
            PushFenceOutcome::Cancellation(_) => true,
        })
        || !fence
            .outcome_at
            .as_deref()
            .is_none_or(valid_fence_timestamp)
    {
        return Err(EnclaveError::Store("malformed push send fence".into()));
    }
    Ok(fence)
}

async fn load_push_fence(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    installation_id: &str,
    for_update: bool,
) -> Result<Option<PushSendFence>> {
    let row = if for_update {
        sqlx::query(
            "SELECT account_id,installation_id,token_generation,claim_id, \
                    floor(extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, \
                    outcome_kind,provider_status,provider_error, \
                    floor(extract(epoch FROM retry_at) * 1000)::bigint AS retry_at_ms, \
                    floor(extract(epoch FROM outcome_at) * 1000)::bigint AS outcome_at_ms \
               FROM push_send_fences WHERE account_id=$1 AND installation_id=$2 FOR UPDATE",
        )
        .bind(account_id)
        .bind(installation_id)
        .fetch_optional(&mut **transaction)
        .await?
    } else {
        sqlx::query(
            "SELECT account_id,installation_id,token_generation,claim_id, \
                    floor(extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, \
                    outcome_kind,provider_status,provider_error, \
                    floor(extract(epoch FROM retry_at) * 1000)::bigint AS retry_at_ms, \
                    floor(extract(epoch FROM outcome_at) * 1000)::bigint AS outcome_at_ms \
               FROM push_send_fences WHERE account_id=$1 AND installation_id=$2",
        )
        .bind(account_id)
        .bind(installation_id)
        .fetch_optional(&mut **transaction)
        .await?
    };
    row.as_ref().map(push_fence_from_row).transpose()
}

#[async_trait]
impl WorkRepository for PostgresPersistence {
    async fn active_account_ids(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT id FROM accounts WHERE status='active' ORDER BY created_at,id",
        )
        .fetch_all(self.pool())
        .await?)
    }

    async fn summarized_until(&self, account_id: &str) -> Result<Option<String>> {
        let value = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT floor(extract(epoch FROM summarized_until) * 1000)::bigint \
             FROM accounts WHERE id=$1",
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?
        .flatten();
        Ok(value.map(isotime::format_epoch_millis))
    }

    async fn set_summarized_until(&self, account_id: &str, value: &str) -> Result<()> {
        let millis = parse_timestamp(value)?;
        sqlx::query(
            "UPDATE accounts SET summarized_until=to_timestamp($2::double precision/1000.0), \
                    updated_at=now() WHERE id=$1",
        )
        .bind(account_id)
        .bind(millis)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    async fn webhook_outbox_deletion_owned(&self, account_id: &str) -> Result<bool> {
        let mut transaction = self.pool().begin().await?;
        deletion_owned(&mut transaction, account_id).await
    }

    async fn begin_webhook_send_fence(
        &self,
        requested: &WebhookSendFence,
        decision_at: &str,
    ) -> Result<WebhookSendFenceDisposition> {
        if !valid_claim_id(&requested.claim_id)
            || !valid_fence_text(&requested.event_id, 68)
            || !valid_fence_text(&requested.subscription_id, 36)
            || !valid_fence_timestamp(&requested.lease_expires_at)
            || !valid_fence_text(&requested.endpoint_url, 2_048)
            || !valid_fence_text(&requested.signing_secret, 256)
            || !valid_fence_timestamp(decision_at)
            || requested.outcome.is_some()
            || requested.outcome_at.is_some()
        {
            return Err(EnclaveError::Store(
                "webhook send fence identity is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", &requested.user_id)
            .await?;
        advisory_transaction_lock(&mut transaction, "webhook-registry", &requested.user_id).await?;
        if let Some(current) = load_webhook_fence(
            &mut transaction,
            &requested.user_id,
            &requested.event_id,
            true,
        )
        .await?
        {
            if current.claim_id != requested.claim_id
                || current.subscription_id != requested.subscription_id
                || current.lease_expires_at != requested.lease_expires_at
                || current.endpoint_url != requested.endpoint_url
                || current.signing_secret != requested.signing_secret
                || current.include_content != requested.include_content
            {
                return Err(EnclaveError::Conflict(
                    "webhook delivery already has an in-flight send".into(),
                ));
            }
            if current.outcome.is_some() {
                transaction.commit().await?;
                return Ok(WebhookSendFenceDisposition::Recorded(current));
            }
            let subscription = load_webhook_subscription(
                &mut transaction,
                &requested.user_id,
                &requested.subscription_id,
            )
            .await?
            .ok_or_else(|| {
                EnclaveError::Conflict("live webhook fence lost its subscription".into())
            })?;
            if account_status(&mut transaction, &requested.user_id)
                .await?
                .as_deref()
                != Some("active")
                || !subscription.enabled
                || subscription.endpoint_url != requested.endpoint_url
                || subscription.signing_secret != requested.signing_secret
                || subscription.include_content != requested.include_content
            {
                return Err(EnclaveError::Conflict(
                    "live webhook fence lost its exact destination".into(),
                ));
            }
            transaction.commit().await?;
            return Ok(WebhookSendFenceDisposition::Authorized(subscription));
        }
        if deletion_owned(&mut transaction, &requested.user_id).await? {
            transaction.commit().await?;
            return Ok(WebhookSendFenceDisposition::DeletionOwned);
        }
        let status = account_status(&mut transaction, &requested.user_id).await?;
        let subscription = load_webhook_subscription(
            &mut transaction,
            &requested.user_id,
            &requested.subscription_id,
        )
        .await?;
        let cancellation = if status.as_deref() != Some("active") {
            Some(WebhookControlCancellation::AccountInactive)
        } else if subscription.is_none() {
            Some(WebhookControlCancellation::SubscriptionMissing)
        } else if !subscription.as_ref().is_some_and(|value| value.enabled) {
            Some(WebhookControlCancellation::SubscriptionDisabled)
        } else if subscription.as_ref().is_some_and(|value| {
            value.endpoint_url != requested.endpoint_url
                || value.signing_secret != requested.signing_secret
                || value.include_content != requested.include_content
        }) {
            Some(WebhookControlCancellation::DestinationChanged)
        } else {
            None
        };
        let lease_ms = parse_timestamp(&requested.lease_expires_at)?;
        let decision_ms = parse_timestamp(decision_at)?;
        sqlx::query(
            "INSERT INTO webhook_send_fences \
                (account_id,event_id,subscription_id,claim_id,lease_expires_at,endpoint_url, \
                 signing_secret,include_content,outcome_kind,outcome_at) \
             VALUES ($1,$2,$3,$4,to_timestamp($5::double precision/1000.0),$6,$7,$8,$9, \
                     CASE WHEN $9::text IS NULL THEN NULL \
                          ELSE to_timestamp($10::double precision/1000.0) END)",
        )
        .bind(&requested.user_id)
        .bind(&requested.event_id)
        .bind(&requested.subscription_id)
        .bind(&requested.claim_id)
        .bind(lease_ms)
        .bind(&requested.endpoint_url)
        .bind(&requested.signing_secret)
        .bind(requested.include_content)
        .bind(cancellation.as_ref().map(WebhookControlCancellation::kind))
        .bind(decision_ms)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        if let Some(cancellation) = cancellation {
            let mut recorded = requested.clone();
            recorded.outcome = Some(WebhookFenceOutcome::Cancellation(cancellation));
            recorded.outcome_at = Some(decision_at.to_owned());
            Ok(WebhookSendFenceDisposition::Recorded(recorded))
        } else {
            Ok(WebhookSendFenceDisposition::Authorized(
                subscription.ok_or_else(|| EnclaveError::Store("subscription vanished".into()))?,
            ))
        }
    }

    async fn get_webhook_send_fence(
        &self,
        account_id: &str,
        event_id: &str,
    ) -> Result<Option<WebhookSendFence>> {
        let mut transaction = self.pool().begin().await?;
        load_webhook_fence(&mut transaction, account_id, event_id, false).await
    }

    async fn list_webhook_send_fences(&self, account_id: &str) -> Result<Vec<WebhookSendFence>> {
        let rows = sqlx::query(
            "SELECT account_id,event_id,subscription_id,claim_id, \
                    floor(extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, \
                    endpoint_url,signing_secret,include_content,outcome_kind,provider_status,provider_error, \
                    floor(extract(epoch FROM retry_at) * 1000)::bigint AS retry_at_ms, \
                    floor(extract(epoch FROM outcome_at) * 1000)::bigint AS outcome_at_ms \
               FROM webhook_send_fences WHERE account_id=$1 ORDER BY event_id",
        )
            .bind(account_id)
            .fetch_all(self.pool())
            .await?;
        rows.iter().map(webhook_fence_from_row).collect()
    }

    async fn validate_webhook_send_fence(
        &self,
        fence: &WebhookSendFence,
        minimum_valid_at_millis: i64,
    ) -> Result<bool> {
        let mut transaction = self.pool().begin().await?;
        let current =
            load_webhook_fence(&mut transaction, &fence.user_id, &fence.event_id, false).await?;
        Ok(current.is_some_and(|current| {
            current == *fence
                && current.outcome.is_none()
                && isotime::parse_epoch_millis(&current.lease_expires_at)
                    .is_some_and(|expires| expires >= minimum_valid_at_millis)
        }))
    }

    async fn record_webhook_send_outcome(
        &self,
        fence: &WebhookSendFence,
        outcome: WebhookProviderOutcome,
        outcome_at: &str,
    ) -> Result<()> {
        if !outcome.is_valid() || !valid_fence_timestamp(outcome_at) {
            return Err(EnclaveError::Store(
                "webhook provider outcome is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let current = load_webhook_fence(&mut transaction, &fence.user_id, &fence.event_id, true)
            .await?
            .ok_or_else(|| EnclaveError::Conflict("webhook send fence is absent".into()))?;
        if current.user_id != fence.user_id
            || current.event_id != fence.event_id
            || current.subscription_id != fence.subscription_id
            || current.claim_id != fence.claim_id
            || current.lease_expires_at != fence.lease_expires_at
            || current.endpoint_url != fence.endpoint_url
            || current.signing_secret != fence.signing_secret
            || current.include_content != fence.include_content
        {
            return Err(EnclaveError::Conflict("webhook send fence changed".into()));
        }
        if let Some(existing) = current.outcome {
            return if existing == WebhookFenceOutcome::Provider(outcome)
                && current.outcome_at.as_deref() == Some(outcome_at)
            {
                Ok(())
            } else {
                Err(EnclaveError::Conflict(
                    "webhook send outcome conflicts with durable evidence".into(),
                ))
            };
        }
        if fence.outcome.is_some() || fence.outcome_at.is_some() {
            return Err(EnclaveError::Conflict(
                "webhook outcome requires the open fence predecessor".into(),
            ));
        }
        let (status, error, retry_at) = outcome.fields();
        let retry_ms = retry_at.map(parse_timestamp).transpose()?;
        let outcome_ms = parse_timestamp(outcome_at)?;
        let changed = sqlx::query(
            "UPDATE webhook_send_fences SET outcome_kind=$1,provider_status=$2,provider_error=$3, \
                    retry_at=CASE WHEN $4::bigint IS NULL THEN NULL \
                                  ELSE to_timestamp($4::double precision/1000.0) END, \
                    outcome_at=to_timestamp($5::double precision/1000.0) \
              WHERE account_id=$6 AND event_id=$7 AND subscription_id=$8 AND claim_id=$9 \
                AND lease_expires_at=to_timestamp($10::double precision/1000.0) \
                AND endpoint_url=$11 AND signing_secret=$12 AND include_content=$13 \
                AND outcome_kind IS NULL",
        )
        .bind(outcome.kind())
        .bind(status)
        .bind(error)
        .bind(retry_ms)
        .bind(outcome_ms)
        .bind(&fence.user_id)
        .bind(&fence.event_id)
        .bind(&fence.subscription_id)
        .bind(&fence.claim_id)
        .bind(parse_timestamp(&fence.lease_expires_at)?)
        .bind(&fence.endpoint_url)
        .bind(&fence.signing_secret)
        .bind(fence.include_content)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict("webhook outcome CAS failed".into()));
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn close_webhook_send_fence(&self, fence: &WebhookSendFence) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "webhook-registry", &fence.user_id).await?;
        let Some(current) =
            load_webhook_fence(&mut transaction, &fence.user_id, &fence.event_id, true).await?
        else {
            transaction.commit().await?;
            return Ok(());
        };
        if current != *fence || current.outcome.is_none() {
            return Err(EnclaveError::Conflict(
                "webhook send fence is not exactly reconciled".into(),
            ));
        }
        if matches!(
            current.outcome,
            Some(WebhookFenceOutcome::Provider(
                WebhookProviderOutcome::Failed {
                    status: Some(301..=399 | 401 | 403 | 404 | 410),
                    ..
                }
            ))
        ) || matches!(
            current.outcome,
            Some(WebhookFenceOutcome::Provider(WebhookProviderOutcome::Failed {
                ref code,
                ..
            })) if code == "invalid_endpoint"
        ) {
            sqlx::query(
                "UPDATE webhook_subscriptions SET enabled=false,updated_at=now() \
                  WHERE account_id=$1 AND id=$2 AND endpoint_url=$3 AND signing_secret=$4 \
                    AND include_content=$5 AND enabled=true",
            )
            .bind(&current.user_id)
            .bind(&current.subscription_id)
            .bind(&current.endpoint_url)
            .bind(&current.signing_secret)
            .bind(current.include_content)
            .execute(&mut *transaction)
            .await?;
        }
        let changed = sqlx::query(
            "DELETE FROM webhook_send_fences WHERE account_id=$1 AND event_id=$2 AND claim_id=$3",
        )
        .bind(&fence.user_id)
        .bind(&fence.event_id)
        .bind(&fence.claim_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict("webhook fence close failed".into()));
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn email_outbox_deletion_owned(&self, account_id: &str) -> Result<bool> {
        let mut transaction = self.pool().begin().await?;
        deletion_owned(&mut transaction, account_id).await
    }

    async fn begin_email_send_fence(
        &self,
        requested: &EmailSendFence,
        decision_at: &str,
    ) -> Result<EmailSendFenceDisposition> {
        if !valid_claim_id(&requested.claim_id)
            || !valid_fence_text(&requested.delivery_id, 96)
            || !valid_fence_timestamp(&requested.lease_expires_at)
            || !valid_fence_text(&requested.recipient_email, 320)
            || !requested.recipient_email.contains('@')
            || !valid_fence_timestamp(decision_at)
            || requested.outcome.is_some()
            || requested.outcome_at.is_some()
        {
            return Err(EnclaveError::Store(
                "email send fence identity is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", &requested.user_id)
            .await?;
        advisory_transaction_lock(&mut transaction, "email-preference", &requested.user_id).await?;
        if let Some(current) = load_email_fence(
            &mut transaction,
            &requested.user_id,
            &requested.delivery_id,
            true,
        )
        .await?
        {
            if current.claim_id != requested.claim_id
                || current.lease_expires_at != requested.lease_expires_at
                || current.recipient_email != requested.recipient_email
                || current.include_content != requested.include_content
            {
                return Err(EnclaveError::Conflict(
                    "email delivery already has an in-flight send".into(),
                ));
            }
            if current.outcome.is_some() {
                transaction.commit().await?;
                return Ok(EmailSendFenceDisposition::Recorded(current));
            }
            let status = account_status(&mut transaction, &requested.user_id).await?;
            let preference = email_preference(&mut transaction, &requested.user_id).await?;
            if status.as_deref() != Some("active")
                || !preference.enabled
                || preference.recipient_email != requested.recipient_email
                || (requested.include_content && !preference.include_content)
            {
                return Err(EnclaveError::Conflict(
                    "live email fence lost its exact preference".into(),
                ));
            }
            transaction.commit().await?;
            return Ok(EmailSendFenceDisposition::Authorized(preference));
        }
        if deletion_owned(&mut transaction, &requested.user_id).await? {
            transaction.commit().await?;
            return Ok(EmailSendFenceDisposition::DeletionOwned);
        }
        let status = account_status(&mut transaction, &requested.user_id).await?;
        let preference = email_preference(&mut transaction, &requested.user_id).await?;
        let cancellation = if status.as_deref() != Some("active") {
            Some(EmailControlCancellation::AccountInactive)
        } else if !preference.enabled {
            Some(EmailControlCancellation::PreferenceDisabled)
        } else if preference.recipient_email != requested.recipient_email {
            Some(EmailControlCancellation::RecipientChanged)
        } else if requested.include_content && !preference.include_content {
            Some(EmailControlCancellation::ContentConsentChanged)
        } else {
            None
        };
        let lease_ms = parse_timestamp(&requested.lease_expires_at)?;
        let decision_ms = parse_timestamp(decision_at)?;
        sqlx::query(
            "INSERT INTO email_send_fences \
                (account_id,delivery_id,claim_id,lease_expires_at,recipient_email,include_content, \
                 outcome_kind,outcome_at) \
             VALUES ($1,$2,$3,to_timestamp($4::double precision/1000.0),$5,$6,$7, \
                     CASE WHEN $7::text IS NULL THEN NULL \
                          ELSE to_timestamp($8::double precision/1000.0) END)",
        )
        .bind(&requested.user_id)
        .bind(&requested.delivery_id)
        .bind(&requested.claim_id)
        .bind(lease_ms)
        .bind(&requested.recipient_email)
        .bind(requested.include_content)
        .bind(cancellation.as_ref().map(EmailControlCancellation::kind))
        .bind(decision_ms)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        if let Some(cancellation) = cancellation {
            let mut recorded = requested.clone();
            recorded.outcome = Some(EmailFenceOutcome::Cancellation(cancellation));
            recorded.outcome_at = Some(decision_at.to_owned());
            Ok(EmailSendFenceDisposition::Recorded(recorded))
        } else {
            Ok(EmailSendFenceDisposition::Authorized(preference))
        }
    }

    async fn get_email_send_fence(
        &self,
        account_id: &str,
        delivery_id: &str,
    ) -> Result<Option<EmailSendFence>> {
        let mut transaction = self.pool().begin().await?;
        load_email_fence(&mut transaction, account_id, delivery_id, false).await
    }

    async fn list_email_send_fences(&self, account_id: &str) -> Result<Vec<EmailSendFence>> {
        let rows = sqlx::query(
            "SELECT account_id,delivery_id,claim_id, \
                    floor(extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, \
                    recipient_email,include_content,outcome_kind,provider_status,provider_message_id, \
                    provider_error,floor(extract(epoch FROM retry_at) * 1000)::bigint AS retry_at_ms, \
                    floor(extract(epoch FROM outcome_at) * 1000)::bigint AS outcome_at_ms \
               FROM email_send_fences WHERE account_id=$1 ORDER BY delivery_id",
        )
            .bind(account_id)
            .fetch_all(self.pool())
            .await?;
        rows.iter().map(email_fence_from_row).collect()
    }

    async fn validate_email_send_fence(
        &self,
        fence: &EmailSendFence,
        minimum_valid_at_millis: i64,
    ) -> Result<bool> {
        let mut transaction = self.pool().begin().await?;
        let current =
            load_email_fence(&mut transaction, &fence.user_id, &fence.delivery_id, false).await?;
        Ok(current.is_some_and(|current| {
            current == *fence
                && current.outcome.is_none()
                && isotime::parse_epoch_millis(&current.lease_expires_at)
                    .is_some_and(|expires| expires >= minimum_valid_at_millis)
        }))
    }

    async fn record_email_send_outcome(
        &self,
        fence: &EmailSendFence,
        outcome: EmailProviderOutcome,
        outcome_at: &str,
    ) -> Result<()> {
        if !outcome.is_valid() || !valid_fence_timestamp(outcome_at) {
            return Err(EnclaveError::Store(
                "email provider outcome is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let current = load_email_fence(&mut transaction, &fence.user_id, &fence.delivery_id, true)
            .await?
            .ok_or_else(|| {
                EnclaveError::Conflict("email send fence disappeared before outcome".into())
            })?;
        if current.claim_id != fence.claim_id
            || current.lease_expires_at != fence.lease_expires_at
            || current.recipient_email != fence.recipient_email
            || current.include_content != fence.include_content
        {
            return Err(EnclaveError::Conflict(
                "email send fence identity changed".into(),
            ));
        }
        if let Some(existing) = current.outcome {
            return if existing == EmailFenceOutcome::Provider(outcome)
                && current.outcome_at.as_deref() == Some(outcome_at)
            {
                Ok(())
            } else {
                Err(EnclaveError::Conflict(
                    "email send outcome conflicts with durable evidence".into(),
                ))
            };
        }
        let (status, provider_message_id, error, retry_at) = outcome.fields();
        let retry_ms = retry_at.map(parse_timestamp).transpose()?;
        let changed = sqlx::query(
            "UPDATE email_send_fences SET outcome_kind=$1,provider_status=$2, \
                    provider_message_id=$3,provider_error=$4, \
                    retry_at=CASE WHEN $5::bigint IS NULL THEN NULL \
                                  ELSE to_timestamp($5::double precision/1000.0) END, \
                    outcome_at=to_timestamp($6::double precision/1000.0) \
              WHERE account_id=$7 AND delivery_id=$8 AND claim_id=$9 \
                AND lease_expires_at=to_timestamp($10::double precision/1000.0) \
                AND recipient_email=$11 AND include_content=$12 AND outcome_kind IS NULL",
        )
        .bind(outcome.kind())
        .bind(status)
        .bind(provider_message_id)
        .bind(error)
        .bind(retry_ms)
        .bind(parse_timestamp(outcome_at)?)
        .bind(&fence.user_id)
        .bind(&fence.delivery_id)
        .bind(&fence.claim_id)
        .bind(parse_timestamp(&fence.lease_expires_at)?)
        .bind(&fence.recipient_email)
        .bind(fence.include_content)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "email provider outcome was not recorded exactly once".into(),
            ));
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn finish_email_send_fence(
        &self,
        fence: &EmailSendFence,
        archive_outcome: EmailFenceOutcome,
    ) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        let Some(current) =
            load_email_fence(&mut transaction, &fence.user_id, &fence.delivery_id, true).await?
        else {
            transaction.commit().await?;
            return Ok(());
        };
        if current.claim_id != fence.claim_id
            || current.lease_expires_at != fence.lease_expires_at
            || current.recipient_email != fence.recipient_email
            || current.include_content != fence.include_content
            || fence
                .outcome
                .as_ref()
                .is_some_and(|value| value != &archive_outcome)
            || current
                .outcome
                .as_ref()
                .is_some_and(|value| value != &archive_outcome)
            || (current.outcome.is_some() && current.outcome_at != fence.outcome_at)
        {
            return Err(EnclaveError::Conflict(
                "email send fence cannot adopt archive outcome".into(),
            ));
        }
        let changed = sqlx::query(
            "DELETE FROM email_send_fences WHERE account_id=$1 AND delivery_id=$2 AND claim_id=$3 \
                AND lease_expires_at=to_timestamp($4::double precision/1000.0) \
                AND recipient_email=$5 AND include_content=$6",
        )
        .bind(&fence.user_id)
        .bind(&fence.delivery_id)
        .bind(&fence.claim_id)
        .bind(parse_timestamp(&fence.lease_expires_at)?)
        .bind(&fence.recipient_email)
        .bind(fence.include_content)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "email send fence was not finished exactly once".into(),
            ));
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn push_outbox_deletion_owned(&self, account_id: &str) -> Result<bool> {
        let mut transaction = self.pool().begin().await?;
        deletion_owned(&mut transaction, account_id).await
    }

    async fn begin_push_send_fence(
        &self,
        account_id: &str,
        installation_id: &str,
        token_generation: i64,
        claim_id: &str,
        lease_expires_at: &str,
        decision_at: &str,
    ) -> Result<PushSendFenceDisposition> {
        if token_generation <= 0
            || !valid_claim_id(installation_id)
            || !valid_claim_id(claim_id)
            || !valid_fence_timestamp(lease_expires_at)
            || !valid_fence_timestamp(decision_at)
        {
            return Err(EnclaveError::Store(
                "push send fence identity is invalid".into(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        advisory_transaction_lock(&mut transaction, "push-registry", "global").await?;
        if let Some(current) =
            load_push_fence(&mut transaction, account_id, installation_id, true).await?
        {
            if current.token_generation != token_generation
                || current.claim_id != claim_id
                || current.lease_expires_at != lease_expires_at
            {
                return Err(EnclaveError::Conflict(
                    "push installation already has an in-flight send".into(),
                ));
            }
            if current.outcome.is_some() {
                transaction.commit().await?;
                return Ok(PushSendFenceDisposition::Recorded(current));
            }
            let installation =
                load_push_installation(&mut transaction, account_id, installation_id)
                    .await?
                    .filter(|installation| {
                        installation.enabled && installation.token_generation == token_generation
                    })
                    .ok_or_else(|| {
                        EnclaveError::Conflict(
                            "live push send fence lost its exact installation".into(),
                        )
                    })?;
            transaction.commit().await?;
            return Ok(PushSendFenceDisposition::Authorized(installation));
        }
        if deletion_owned(&mut transaction, account_id).await? {
            transaction.commit().await?;
            return Ok(PushSendFenceDisposition::DeletionOwned);
        }
        let status = account_status(&mut transaction, account_id).await?;
        let installation =
            load_push_installation(&mut transaction, account_id, installation_id).await?;
        let cancellation = if status.as_deref() != Some("active") {
            Some(PushControlCancellation::AccountInactive)
        } else if installation.is_none() {
            Some(PushControlCancellation::InstallationMissing)
        } else if installation.as_ref().is_some_and(|value| !value.enabled) {
            Some(PushControlCancellation::InstallationDisabled)
        } else if installation
            .as_ref()
            .is_some_and(|value| value.token_generation != token_generation)
        {
            Some(PushControlCancellation::TokenGenerationChanged)
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO push_send_fences \
                (account_id,installation_id,token_generation,claim_id,lease_expires_at, \
                 outcome_kind,outcome_at) \
             VALUES ($1,$2,$3,$4,to_timestamp($5::double precision/1000.0),$6, \
                     CASE WHEN $6::text IS NULL THEN NULL \
                          ELSE to_timestamp($7::double precision/1000.0) END)",
        )
        .bind(account_id)
        .bind(installation_id)
        .bind(token_generation)
        .bind(claim_id)
        .bind(parse_timestamp(lease_expires_at)?)
        .bind(cancellation.map(PushControlCancellation::kind))
        .bind(parse_timestamp(decision_at)?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        if let Some(cancellation) = cancellation {
            Ok(PushSendFenceDisposition::Recorded(PushSendFence {
                user_id: account_id.to_owned(),
                installation_id: installation_id.to_owned(),
                token_generation,
                claim_id: claim_id.to_owned(),
                lease_expires_at: lease_expires_at.to_owned(),
                outcome: Some(PushFenceOutcome::Cancellation(cancellation)),
                outcome_at: Some(decision_at.to_owned()),
            }))
        } else {
            Ok(PushSendFenceDisposition::Authorized(
                installation
                    .ok_or_else(|| EnclaveError::Store("push installation disappeared".into()))?,
            ))
        }
    }

    async fn get_push_send_fence(
        &self,
        account_id: &str,
        installation_id: &str,
    ) -> Result<Option<PushSendFence>> {
        let mut transaction = self.pool().begin().await?;
        load_push_fence(&mut transaction, account_id, installation_id, false).await
    }

    async fn list_push_send_fences(&self, account_id: &str) -> Result<Vec<PushSendFence>> {
        let rows = sqlx::query(
            "SELECT account_id,installation_id,token_generation,claim_id, \
                    floor(extract(epoch FROM lease_expires_at) * 1000)::bigint AS lease_expires_at_ms, \
                    outcome_kind,provider_status,provider_error, \
                    floor(extract(epoch FROM retry_at) * 1000)::bigint AS retry_at_ms, \
                    floor(extract(epoch FROM outcome_at) * 1000)::bigint AS outcome_at_ms \
               FROM push_send_fences WHERE account_id=$1 ORDER BY installation_id",
        )
            .bind(account_id)
            .fetch_all(self.pool())
            .await?;
        rows.iter().map(push_fence_from_row).collect()
    }

    async fn validate_push_send_fence(
        &self,
        account_id: &str,
        installation_id: &str,
        token_generation: i64,
        claim_id: &str,
        lease_expires_at: &str,
        minimum_valid_at_millis: i64,
    ) -> Result<bool> {
        let mut transaction = self.pool().begin().await?;
        let current = load_push_fence(&mut transaction, account_id, installation_id, false).await?;
        Ok(current.is_some_and(|fence| {
            fence.token_generation == token_generation
                && fence.claim_id == claim_id
                && fence.lease_expires_at == lease_expires_at
                && fence.outcome.is_none()
                && isotime::parse_epoch_millis(&fence.lease_expires_at)
                    .is_some_and(|expires| expires >= minimum_valid_at_millis)
        }))
    }

    async fn record_push_send_outcome(
        &self,
        account_id: &str,
        installation_id: &str,
        token_generation: i64,
        claim_id: &str,
        lease_expires_at: &str,
        receipt: PushProviderReceipt,
    ) -> Result<()> {
        if token_generation <= 0
            || !valid_claim_id(claim_id)
            || !valid_fence_timestamp(lease_expires_at)
        {
            return Err(EnclaveError::Store(
                "push send outcome identity is invalid".into(),
            ));
        }
        let PushProviderReceipt {
            outcome,
            outcome_at,
        } = receipt;
        let mut transaction = self.pool().begin().await?;
        let current = load_push_fence(&mut transaction, account_id, installation_id, true)
            .await?
            .ok_or_else(|| {
                EnclaveError::Conflict("push send fence disappeared before outcome".into())
            })?;
        if current.token_generation != token_generation
            || current.claim_id != claim_id
            || current.lease_expires_at != lease_expires_at
        {
            return Err(EnclaveError::Conflict(
                "push send fence identity changed".into(),
            ));
        }
        if let Some(existing) = current.outcome {
            return if existing == PushFenceOutcome::Provider(outcome)
                && current.outcome_at.as_deref() == Some(&outcome_at)
            {
                Ok(())
            } else {
                Err(EnclaveError::Conflict(
                    "push send outcome conflicts with durable evidence".into(),
                ))
            };
        }
        let (status, error, retry_at) = outcome.fields();
        let retry_ms = retry_at.map(parse_timestamp).transpose()?;
        let changed = sqlx::query(
            "UPDATE push_send_fences SET outcome_kind=$1,provider_status=$2,provider_error=$3, \
                    retry_at=CASE WHEN $4::bigint IS NULL THEN NULL \
                                  ELSE to_timestamp($4::double precision/1000.0) END, \
                    outcome_at=to_timestamp($5::double precision/1000.0) \
              WHERE account_id=$6 AND installation_id=$7 AND token_generation=$8 \
                AND claim_id=$9 AND lease_expires_at=to_timestamp($10::double precision/1000.0) \
                AND outcome_kind IS NULL",
        )
        .bind(outcome.kind())
        .bind(status)
        .bind(error)
        .bind(retry_ms)
        .bind(parse_timestamp(&outcome_at)?)
        .bind(account_id)
        .bind(installation_id)
        .bind(token_generation)
        .bind(claim_id)
        .bind(parse_timestamp(lease_expires_at)?)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "push send outcome was not recorded exactly once".into(),
            ));
        }
        if matches!(outcome, PushProviderOutcome::TokenTerminal { .. }) {
            sqlx::query(
                "UPDATE push_installations SET enabled=false,updated_at=now() \
                  WHERE account_id=$1 AND id=$2 AND token_generation=$3 AND enabled=true",
            )
            .bind(account_id)
            .bind(installation_id)
            .bind(token_generation)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn finish_push_send_fence(
        &self,
        fence: &PushSendFence,
        archive_outcome: PushProviderOutcome,
    ) -> Result<()> {
        self.finish_push_fence(fence, PushFenceOutcome::Provider(archive_outcome))
            .await
    }

    async fn finish_push_cancellation_fence(
        &self,
        fence: &PushSendFence,
        cancellation: PushControlCancellation,
    ) -> Result<()> {
        self.finish_push_fence(fence, PushFenceOutcome::Cancellation(cancellation))
            .await
    }
}

impl PostgresPersistence {
    async fn finish_push_fence(
        &self,
        fence: &PushSendFence,
        archive_outcome: PushFenceOutcome,
    ) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "push-registry", "global").await?;
        let Some(current) = load_push_fence(
            &mut transaction,
            &fence.user_id,
            &fence.installation_id,
            true,
        )
        .await?
        else {
            transaction.commit().await?;
            return Ok(());
        };
        if current.token_generation != fence.token_generation
            || current.claim_id != fence.claim_id
            || current.lease_expires_at != fence.lease_expires_at
            || fence
                .outcome
                .as_ref()
                .is_some_and(|value| value != &archive_outcome)
            || current
                .outcome
                .as_ref()
                .is_some_and(|value| value != &archive_outcome)
            || (current.outcome.is_some() && current.outcome_at != fence.outcome_at)
        {
            return Err(EnclaveError::Conflict(
                "push send fence cannot adopt archive outcome".into(),
            ));
        }
        if matches!(
            archive_outcome,
            PushFenceOutcome::Provider(PushProviderOutcome::TokenTerminal { .. })
        ) {
            sqlx::query(
                "UPDATE push_installations SET enabled=false,updated_at=now() \
                  WHERE account_id=$1 AND id=$2 AND token_generation=$3 AND enabled=true",
            )
            .bind(&fence.user_id)
            .bind(&fence.installation_id)
            .bind(fence.token_generation)
            .execute(&mut *transaction)
            .await?;
        }
        let changed = sqlx::query(
            "DELETE FROM push_send_fences WHERE account_id=$1 AND installation_id=$2 \
                AND token_generation=$3 AND claim_id=$4 \
                AND lease_expires_at=to_timestamp($5::double precision/1000.0)",
        )
        .bind(&fence.user_id)
        .bind(&fence.installation_id)
        .bind(fence.token_generation)
        .bind(&fence.claim_id)
        .bind(parse_timestamp(&fence.lease_expires_at)?)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "push send fence was not finished exactly once".into(),
            ));
        }
        transaction.commit().await?;
        Ok(())
    }
}
