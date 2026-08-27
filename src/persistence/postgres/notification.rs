use async_trait::async_trait;
use sqlx::Row;

use crate::cp::isotime;
use crate::error::{EnclaveError, Result};

use super::super::notification::{
    EpisodeEmailPreference, NotificationRepository, PushInstallation, WebhookSubscription,
};
use super::{advisory_transaction_lock, PostgresPersistence};

fn timestamp_millis(row: &sqlx::postgres::PgRow, name: &str) -> Result<String> {
    Ok(isotime::format_epoch_millis(row.try_get::<i64, _>(name)?))
}

fn optional_timestamp_millis(row: &sqlx::postgres::PgRow, name: &str) -> Result<Option<String>> {
    Ok(row
        .try_get::<Option<i64>, _>(name)?
        .map(isotime::format_epoch_millis))
}

fn webhook_from_row(row: &sqlx::postgres::PgRow) -> Result<WebhookSubscription> {
    Ok(WebhookSubscription {
        id: row.try_get("id")?,
        user_id: row.try_get("account_id")?,
        name: row.try_get("name")?,
        endpoint_url: row.try_get("endpoint_url")?,
        signing_secret: row.try_get("signing_secret")?,
        include_content: row.try_get("include_content")?,
        enabled: row.try_get("enabled")?,
        created_at: timestamp_millis(row, "created_at_ms")?,
    })
}

fn push_from_row(row: &sqlx::postgres::PgRow) -> Result<PushInstallation> {
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

async fn require_active_account(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<String> {
    let row = sqlx::query("SELECT email, status FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| EnclaveError::Auth("unknown user".into()))?;
    if row.try_get::<String, _>("status")? != "active" {
        return Err(EnclaveError::Auth("account inactive or deleting".into()));
    }
    Ok(row.try_get("email")?)
}

#[async_trait]
impl NotificationRepository for PostgresPersistence {
    async fn list_webhook_subscriptions(
        &self,
        account_id: &str,
    ) -> Result<Vec<WebhookSubscription>> {
        let rows = sqlx::query(
            "SELECT account_id,id,name,endpoint_url,signing_secret,include_content,enabled, \
                    floor(extract(epoch FROM created_at) * 1000)::bigint AS created_at_ms \
               FROM webhook_subscriptions WHERE account_id=$1 ORDER BY created_at,id",
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(webhook_from_row).collect()
    }

    async fn get_webhook_subscription(
        &self,
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
        .fetch_optional(self.pool())
        .await?;
        row.as_ref().map(webhook_from_row).transpose()
    }

    async fn create_webhook_subscription(&self, subscription: WebhookSubscription) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "webhook-registry", &subscription.user_id)
            .await?;
        require_active_account(&mut transaction, &subscription.user_id).await?;
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM webhook_subscriptions WHERE account_id=$1",
        )
        .bind(&subscription.user_id)
        .fetch_one(&mut *transaction)
        .await?;
        if count >= 5 {
            return Err(EnclaveError::Conflict(
                "at most five webhook destinations are allowed".into(),
            ));
        }
        let created_at = isotime::parse_epoch_millis(&subscription.created_at)
            .ok_or_else(|| EnclaveError::InvalidRequest("invalid webhook timestamp".into()))?;
        let result = sqlx::query(
            "INSERT INTO webhook_subscriptions \
                (account_id,id,name,endpoint_url,signing_secret,include_content,enabled,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,to_timestamp($8::double precision / 1000.0))",
        )
        .bind(&subscription.user_id)
        .bind(&subscription.id)
        .bind(&subscription.name)
        .bind(&subscription.endpoint_url)
        .bind(&subscription.signing_secret)
        .bind(subscription.include_content)
        .bind(subscription.enabled)
        .bind(created_at)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = result {
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("23505")
            {
                return Err(EnclaveError::Conflict(
                    "webhook subscription already exists".into(),
                ));
            }
            return Err(error.into());
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn disable_webhook_subscription(
        &self,
        account_id: &str,
        subscription_id: &str,
    ) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "webhook-registry", account_id).await?;
        let in_flight = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM webhook_send_fences \
                            WHERE account_id=$1 AND subscription_id=$2)",
        )
        .bind(account_id)
        .bind(subscription_id)
        .fetch_one(&mut *transaction)
        .await?;
        if in_flight {
            return Err(EnclaveError::Conflict(
                "webhook subscription has an in-flight send".into(),
            ));
        }
        sqlx::query(
            "UPDATE webhook_subscriptions SET enabled=false,updated_at=now() \
             WHERE account_id=$1 AND id=$2",
        )
        .bind(account_id)
        .bind(subscription_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn delete_webhook_subscription(
        &self,
        account_id: &str,
        subscription_id: &str,
    ) -> Result<bool> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "webhook-registry", account_id).await?;
        let in_flight = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM webhook_send_fences \
                            WHERE account_id=$1 AND subscription_id=$2)",
        )
        .bind(account_id)
        .bind(subscription_id)
        .fetch_one(&mut *transaction)
        .await?;
        if in_flight {
            return Err(EnclaveError::Conflict(
                "webhook subscription has an in-flight send".into(),
            ));
        }
        let deleted =
            sqlx::query("DELETE FROM webhook_subscriptions WHERE account_id=$1 AND id=$2")
                .bind(account_id)
                .bind(subscription_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected()
                == 1;
        transaction.commit().await?;
        Ok(deleted)
    }

    async fn get_email_preference(&self, account_id: &str) -> Result<EpisodeEmailPreference> {
        let account = sqlx::query("SELECT email,status FROM accounts WHERE id=$1")
            .bind(account_id)
            .fetch_optional(self.pool())
            .await?
            .ok_or_else(|| EnclaveError::Auth("unknown user".into()))?;
        if account.try_get::<String, _>("status")? != "active" {
            return Err(EnclaveError::Auth("account inactive or deleting".into()));
        }
        let email: String = account.try_get("email")?;
        let preference = sqlx::query(
            "SELECT enabled,include_content, \
                    floor(extract(epoch FROM consented_at) * 1000)::bigint AS consented_at_ms, \
                    floor(extract(epoch FROM updated_at) * 1000)::bigint AS updated_at_ms \
             FROM episode_email_preferences WHERE account_id=$1",
        )
        .bind(account_id)
        .fetch_optional(self.pool())
        .await?;
        match preference {
            Some(row) => Ok(EpisodeEmailPreference {
                enabled: row.try_get("enabled")?,
                include_content: row.try_get("include_content")?,
                recipient_email: email,
                consented_at: optional_timestamp_millis(&row, "consented_at_ms")?,
                updated_at: timestamp_millis(&row, "updated_at_ms")?,
            }),
            None => {
                let now_ms = sqlx::query_scalar::<_, i64>(
                    "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
                )
                .fetch_one(self.pool())
                .await?;
                Ok(EpisodeEmailPreference {
                    enabled: false,
                    include_content: false,
                    recipient_email: email,
                    consented_at: None,
                    updated_at: isotime::format_epoch_millis(now_ms),
                })
            }
        }
    }

    async fn set_email_preference(
        &self,
        account_id: &str,
        enabled: bool,
        mut include_content: bool,
    ) -> Result<EpisodeEmailPreference> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "email-preference", account_id).await?;
        let in_flight = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM email_send_fences WHERE account_id=$1)",
        )
        .bind(account_id)
        .fetch_one(&mut *transaction)
        .await?;
        if in_flight {
            return Err(EnclaveError::Conflict(
                "email preference has an in-flight send".into(),
            ));
        }
        let email = require_active_account(&mut transaction, account_id)
            .await
            .map_err(|error| match error {
                EnclaveError::Auth(_) => EnclaveError::InvalidRequest(
                    "cannot update email preferences for inactive or deleting user".into(),
                ),
                other => other,
            })?;
        if !enabled {
            include_content = false;
        }
        let existing_consent = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT floor(extract(epoch FROM consented_at) * 1000)::bigint \
             FROM episode_email_preferences WHERE account_id=$1",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?
        .flatten();
        let now_ms = sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let consented_at_ms = match (enabled, include_content) {
            (false, _) => None,
            (true, true) => Some(existing_consent.unwrap_or(now_ms)),
            (true, false) => existing_consent,
        };
        sqlx::query(
            "INSERT INTO episode_email_preferences \
                (account_id,enabled,include_content,consented_at,updated_at) \
             VALUES ($1,$2,$3, \
                     CASE WHEN $4::bigint IS NULL THEN NULL \
                          ELSE to_timestamp($4::double precision / 1000.0) END, \
                     to_timestamp($5::double precision / 1000.0)) \
             ON CONFLICT (account_id) DO UPDATE SET \
                enabled=EXCLUDED.enabled,include_content=EXCLUDED.include_content, \
                consented_at=EXCLUDED.consented_at,updated_at=EXCLUDED.updated_at",
        )
        .bind(account_id)
        .bind(enabled)
        .bind(include_content)
        .bind(consented_at_ms)
        .bind(now_ms)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(EpisodeEmailPreference {
            enabled,
            include_content,
            recipient_email: email,
            consented_at: consented_at_ms.map(isotime::format_epoch_millis),
            updated_at: isotime::format_epoch_millis(now_ms),
        })
    }

    async fn upsert_push_installation(
        &self,
        installation: PushInstallation,
    ) -> Result<PushInstallation> {
        let mut transaction = self.pool().begin().await?;
        // Registrations are infrequent. A single fleet-wide lock makes token
        // displacement, bounded eviction, and generation allocation one
        // simple serializable operation across all app replicas.
        advisory_transaction_lock(&mut transaction, "push-registry", "global").await?;
        require_active_account(&mut transaction, &installation.user_id).await?;
        let fenced = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS( \
                 SELECT 1 FROM push_send_fences f \
                 LEFT JOIN push_installations p \
                   ON p.account_id=f.account_id AND p.id=f.installation_id \
                 WHERE f.installation_id=$1 \
                    OR (p.topic=$2 AND p.environment=$3 AND p.device_token=$4))",
        )
        .bind(&installation.id)
        .bind(&installation.topic)
        .bind(&installation.environment)
        .bind(&installation.device_token)
        .fetch_one(&mut *transaction)
        .await?;
        if fenced {
            return Err(EnclaveError::Conflict(
                "push installation has an in-flight send".into(),
            ));
        }
        let existing = sqlx::query(
            "SELECT account_id,topic,environment,device_token,token_generation,enabled \
             FROM push_installations WHERE account_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(&installation.user_id)
        .bind(&installation.id)
        .fetch_optional(&mut *transaction)
        .await?;
        let token_generation = match existing {
            Some(row)
                if row.try_get::<bool, _>("enabled")?
                    && row.try_get::<String, _>("account_id")? == installation.user_id
                    && row.try_get::<String, _>("topic")? == installation.topic
                    && row.try_get::<String, _>("environment")? == installation.environment
                    && row.try_get::<String, _>("device_token")? == installation.device_token =>
            {
                row.try_get("token_generation")?
            }
            _ => {
                sqlx::query_scalar::<_, i64>("SELECT nextval('push_token_generation_seq')")
                    .fetch_one(&mut *transaction)
                    .await?
            }
        };
        sqlx::query(
            "DELETE FROM push_installations \
             WHERE topic=$1 AND environment=$2 AND device_token=$3 \
               AND NOT (account_id=$4 AND id=$5)",
        )
        .bind(&installation.topic)
        .bind(&installation.environment)
        .bind(&installation.device_token)
        .bind(&installation.user_id)
        .bind(&installation.id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO push_installations \
                (account_id,id,platform,topic,environment,device_token,token_generation,enabled) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,true) \
             ON CONFLICT (account_id,id) DO UPDATE SET \
                platform=EXCLUDED.platform,topic=EXCLUDED.topic, \
                environment=EXCLUDED.environment,device_token=EXCLUDED.device_token, \
                token_generation=EXCLUDED.token_generation,enabled=true, \
                updated_at=now(),last_seen_at=now()",
        )
        .bind(&installation.user_id)
        .bind(&installation.id)
        .bind(&installation.platform)
        .bind(&installation.topic)
        .bind(&installation.environment)
        .bind(&installation.device_token)
        .bind(token_generation)
        .execute(&mut *transaction)
        .await?;
        let excess = sqlx::query_scalar::<_, i64>(
            "SELECT GREATEST(0,count(*)-10) FROM push_installations \
             WHERE account_id=$1 AND enabled=true",
        )
        .bind(&installation.user_id)
        .fetch_one(&mut *transaction)
        .await?;
        if excess > 0 {
            let evicting_fenced = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS( \
                   SELECT 1 FROM push_send_fences f \
                   JOIN (SELECT id FROM push_installations \
                         WHERE account_id=$1 AND enabled=true AND id<>$2 \
                         ORDER BY last_seen_at,id LIMIT $3) victim \
                     ON victim.id=f.installation_id \
                   WHERE f.account_id=$1)",
            )
            .bind(&installation.user_id)
            .bind(&installation.id)
            .bind(excess)
            .fetch_one(&mut *transaction)
            .await?;
            if evicting_fenced {
                return Err(EnclaveError::Conflict(
                    "push installation eviction would cross an in-flight send".into(),
                ));
            }
            sqlx::query(
                "DELETE FROM push_installations WHERE (account_id,id) IN ( \
                   SELECT account_id,id FROM push_installations \
                   WHERE account_id=$1 AND enabled=true AND id<>$2 \
                   ORDER BY last_seen_at,id LIMIT $3)",
            )
            .bind(&installation.user_id)
            .bind(&installation.id)
            .bind(excess)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "DELETE FROM push_installations p \
             WHERE p.account_id=$1 AND p.enabled=false AND NOT EXISTS( \
               SELECT 1 FROM push_send_fences f \
               WHERE f.account_id=p.account_id AND f.installation_id=p.id)",
        )
        .bind(&installation.user_id)
        .execute(&mut *transaction)
        .await?;
        let row = sqlx::query(
            "SELECT account_id,id,platform,topic,environment,device_token,token_generation,enabled \
             FROM push_installations WHERE account_id=$1 AND id=$2",
        )
        .bind(&installation.user_id)
        .bind(&installation.id)
        .fetch_one(&mut *transaction)
        .await?;
        let installed = push_from_row(&row)?;
        transaction.commit().await?;
        Ok(installed)
    }

    async fn list_push_installations(&self, account_id: &str) -> Result<Vec<PushInstallation>> {
        let rows = sqlx::query(
            "SELECT account_id,id,platform,topic,environment,device_token,token_generation,enabled \
             FROM push_installations WHERE account_id=$1 AND enabled=true ORDER BY id",
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(push_from_row).collect()
    }

    async fn delete_push_installation(
        &self,
        account_id: &str,
        installation_id: &str,
    ) -> Result<bool> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "push-registry", "global").await?;
        let in_flight = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM push_send_fences \
                            WHERE account_id=$1 AND installation_id=$2)",
        )
        .bind(account_id)
        .bind(installation_id)
        .fetch_one(&mut *transaction)
        .await?;
        if in_flight {
            return Err(EnclaveError::Conflict(
                "push installation has an in-flight send".into(),
            ));
        }
        let changed = sqlx::query(
            "UPDATE push_installations SET enabled=false,updated_at=now() \
             WHERE account_id=$1 AND id=$2 AND enabled=true",
        )
        .bind(account_id)
        .bind(installation_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        transaction.commit().await?;
        Ok(changed)
    }
}
