use async_trait::async_trait;
use sqlx::Row;

use crate::{
    cp::isotime,
    error::{EnclaveError, Result},
    persistence::{AccountDeletionOperation, AccountLifecycleRepository},
};

use super::{advisory_transaction_lock, PostgresPersistence};

fn optional_timestamp(row: &sqlx::postgres::PgRow, name: &str) -> Result<Option<String>> {
    Ok(row
        .try_get::<Option<i64>, _>(name)?
        .map(isotime::format_epoch_millis))
}

fn deletion_operation_from_row(row: &sqlx::postgres::PgRow) -> Result<AccountDeletionOperation> {
    let retry = row
        .try_get::<Option<i64>, _>("retry_after_seconds")?
        .map(u64::try_from)
        .transpose()
        .map_err(|_| {
            EnclaveError::Store("invalid persisted account-deletion retry delay".into())
        })?;
    Ok(AccountDeletionOperation {
        operation_id: row.try_get("operation_id")?,
        status: row.try_get("status")?,
        reason: row.try_get("reason")?,
        retry_after_seconds: retry,
        hard_delete_time: optional_timestamp(row, "hard_delete_time_ms")?,
    })
}

const DELETION_OPERATION_SELECT: &str = "SELECT operation_id,status,reason,retry_after_seconds, \
            floor(extract(epoch FROM hard_delete_time) * 1000)::bigint AS hard_delete_time_ms \
       FROM account_deletion_operations WHERE account_id=$1";

async fn load_operation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    for_update: bool,
) -> Result<Option<AccountDeletionOperation>> {
    let row = if for_update {
        sqlx::query(
            "SELECT operation_id,status,reason,retry_after_seconds, \
                    floor(extract(epoch FROM hard_delete_time) * 1000)::bigint AS hard_delete_time_ms \
               FROM account_deletion_operations WHERE account_id=$1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut **transaction)
        .await?
    } else {
        sqlx::query(DELETION_OPERATION_SELECT)
            .bind(account_id)
            .fetch_optional(&mut **transaction)
            .await?
    };
    row.as_ref().map(deletion_operation_from_row).transpose()
}

async fn refuse_open_provider_fences(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT EXISTS(SELECT 1 FROM email_send_fences WHERE account_id=$1) AS email, \
                EXISTS(SELECT 1 FROM webhook_send_fences WHERE account_id=$1) AS webhook, \
                EXISTS(SELECT 1 FROM push_send_fences WHERE account_id=$1) AS push",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await?;
    if row.try_get::<bool, _>("email")? {
        return Err(EnclaveError::Conflict(
            "account has an in-flight email send".into(),
        ));
    }
    if row.try_get::<bool, _>("webhook")? {
        return Err(EnclaveError::Conflict(
            "account has an in-flight webhook send".into(),
        ));
    }
    if row.try_get::<bool, _>("push")? {
        return Err(EnclaveError::Conflict(
            "account has an in-flight push send".into(),
        ));
    }
    Ok(())
}

async fn refuse_active_media_uploads(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM capture_upload_intents WHERE account_id=$1 AND expires_at<=now()")
        .bind(account_id)
        .execute(&mut **transaction)
        .await?;
    let active = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM capture_upload_intents WHERE account_id=$1)",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await?;
    if active {
        return Err(EnclaveError::Conflict(
            "account has an in-flight media upload".into(),
        ));
    }
    Ok(())
}

fn deletion_status_for_reason(reason: &str) -> &'static str {
    match reason {
        "legacy_generation_unavailable"
        | "legacy_snapshot_too_large"
        | "archive_v3_manual_required" => "failed_retryable",
        _ => "pending",
    }
}

#[async_trait]
impl AccountLifecycleRepository for PostgresPersistence {
    async fn account_deletion_operation(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountDeletionOperation>> {
        let mut transaction = self.pool().begin().await?;
        load_operation(&mut transaction, account_id, false).await
    }

    async fn begin_account_deletion(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountDeletionOperation>> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        refuse_open_provider_fences(&mut transaction, account_id).await?;

        let account = sqlx::query("SELECT status FROM accounts WHERE id=$1 FOR UPDATE")
            .bind(account_id)
            .fetch_optional(&mut *transaction)
            .await?;
        let tombstoned = account.is_none()
            && sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM deleted_accounts WHERE account_id=$1)",
            )
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await?;
        let status = account
            .as_ref()
            .map(|row| row.try_get::<String, _>("status"))
            .transpose()?;
        refuse_active_media_uploads(&mut transaction, account_id).await?;
        if !tombstoned && !matches!(status.as_deref(), Some("active" | "deleting")) {
            transaction.commit().await?;
            return Ok(None);
        }

        if status.as_deref() == Some("active") {
            sqlx::query("UPDATE accounts SET status='deleting',updated_at=now() WHERE id=$1")
                .bind(account_id)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM oauth_authorization_codes WHERE account_id=$1")
                .bind(account_id)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM oauth_consents WHERE account_id=$1")
                .bind(account_id)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM refresh_tokens WHERE account_id=$1")
                .bind(account_id)
                .execute(&mut *transaction)
                .await?;
            sqlx::query(
                "UPDATE webhook_subscriptions SET enabled=false,updated_at=now() \
                  WHERE account_id=$1",
            )
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE episode_email_preferences SET enabled=false,include_content=false, \
                        consented_at=NULL,updated_at=now() WHERE account_id=$1",
            )
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE push_installations SET enabled=false,updated_at=now() WHERE account_id=$1",
            )
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
        }

        let operation_id = format!("del_{}", crate::cp::tokens::random_token_hex());
        sqlx::query(
            "INSERT INTO account_deletion_operations \
                (account_id,operation_id,status,reason,retry_after_seconds) \
             VALUES ($1,$2,'pending','content_deletion_in_progress',30) \
             ON CONFLICT (account_id) DO NOTHING",
        )
        .bind(account_id)
        .bind(operation_id)
        .execute(&mut *transaction)
        .await?;
        let operation = load_operation(&mut transaction, account_id, true)
            .await?
            .ok_or_else(|| {
                EnclaveError::Store("failed to initialize account deletion operation".into())
            })?;
        if !tombstoned && operation.status == "physical_complete" {
            return Err(EnclaveError::Conflict(
                "physically complete deletion operation still has an identity row".into(),
            ));
        }
        transaction.commit().await?;
        Ok(Some(operation))
    }

    async fn update_account_deletion_status(
        &self,
        account_id: &str,
        reason: &str,
        retry_after_seconds: Option<u64>,
        hard_delete_time: Option<&str>,
    ) -> Result<AccountDeletionOperation> {
        let retry_after_seconds = retry_after_seconds
            .map(i64::try_from)
            .transpose()
            .map_err(|_| EnclaveError::Store("account-deletion retry delay is too large".into()))?;
        let hard_delete_millis = hard_delete_time
            .map(|value| {
                isotime::parse_epoch_millis(value).ok_or_else(|| {
                    EnclaveError::Store("account-deletion hard-delete time is invalid".into())
                })
            })
            .transpose()?;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        let changed = sqlx::query(
            "UPDATE account_deletion_operations SET status=$2,reason=$3,retry_after_seconds=$4, \
                    hard_delete_time=CASE WHEN $5::bigint IS NULL THEN NULL \
                                          ELSE to_timestamp($5::double precision/1000.0) END, \
                    updated_at=now() WHERE account_id=$1",
        )
        .bind(account_id)
        .bind(deletion_status_for_reason(reason))
        .bind(reason)
        .bind(retry_after_seconds)
        .bind(hard_delete_millis)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "account deletion operation was not initialized".into(),
            ));
        }
        let operation = load_operation(&mut transaction, account_id, true)
            .await?
            .ok_or_else(|| EnclaveError::Store("account deletion operation disappeared".into()))?;
        transaction.commit().await?;
        Ok(operation)
    }

    async fn finalize_account_deletion(
        &self,
        account_id: &str,
    ) -> Result<AccountDeletionOperation> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "account-lifecycle", account_id).await?;
        refuse_open_provider_fences(&mut transaction, account_id).await?;
        let account = sqlx::query("SELECT status FROM accounts WHERE id=$1 FOR UPDATE")
            .bind(account_id)
            .fetch_optional(&mut *transaction)
            .await?;
        refuse_active_media_uploads(&mut transaction, account_id).await?;
        if account.is_none() {
            let tombstoned = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM deleted_accounts WHERE account_id=$1)",
            )
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !tombstoned {
                return Err(EnclaveError::Conflict("account is unavailable".into()));
            }
        } else {
            let status: String = account
                .as_ref()
                .ok_or_else(|| EnclaveError::Store("account disappeared".into()))?
                .try_get("status")?;
            if status != "deleting" {
                return Err(EnclaveError::Conflict(
                    "account deletion was not initialized".into(),
                ));
            }
            let unrevoked_apple = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM apple_credentials \
                                WHERE account_id=$1 AND revoked_at IS NULL)",
            )
            .bind(account_id)
            .fetch_one(&mut *transaction)
            .await?;
            if unrevoked_apple {
                return Err(EnclaveError::Conflict(
                    "Apple credential revocation is incomplete".into(),
                ));
            }
            sqlx::query(
                "INSERT INTO deleted_identities (provider,subject) \
                 SELECT provider,subject FROM auth_identities WHERE account_id=$1 \
                 ON CONFLICT (provider,subject) DO NOTHING",
            )
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO deleted_accounts (account_id) VALUES ($1) \
                 ON CONFLICT (account_id) DO NOTHING",
            )
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO billing_detach_outbox (billing_account_id) \
                 SELECT billing_account_id FROM billing_accounts WHERE account_id=$1 \
                 ON CONFLICT (billing_account_id) DO NOTHING",
            )
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
            let deleted = sqlx::query("DELETE FROM accounts WHERE id=$1")
                .bind(account_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
            if deleted != 1 {
                return Err(EnclaveError::Store(
                    "account identity deletion affected an unexpected row count".into(),
                ));
            }
        }
        let changed = sqlx::query(
            "UPDATE account_deletion_operations SET status='physical_complete', \
                    reason='content_deleted',retry_after_seconds=NULL,hard_delete_time=NULL, \
                    updated_at=now() WHERE account_id=$1",
        )
        .bind(account_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "account deletion operation was not initialized".into(),
            ));
        }
        let operation = load_operation(&mut transaction, account_id, true)
            .await?
            .ok_or_else(|| EnclaveError::Store("account deletion operation disappeared".into()))?;
        transaction.commit().await?;
        Ok(operation)
    }

    async fn deleting_account_ids(&self, limit: usize) -> Result<Vec<String>> {
        let limit = i64::try_from(limit)
            .map_err(|_| EnclaveError::Store("account-deletion sweep limit is too large".into()))?;
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT a.id FROM accounts a \
             LEFT JOIN account_deletion_operations d ON d.account_id=a.id \
             WHERE a.status='deleting' AND COALESCE(d.status,'pending')='pending' \
             ORDER BY COALESCE(d.updated_at,a.created_at),a.id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(self.pool())
        .await?)
    }

    async fn apple_refresh_credentials(&self, account_id: &str) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(
            "SELECT client_id,refresh_token FROM apple_credentials \
             WHERE account_id=$1 AND revoked_at IS NULL ORDER BY client_id",
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|row| Ok((row.try_get("client_id")?, row.try_get("refresh_token")?)))
            .collect()
    }

    async fn mark_apple_credential_revoked(&self, account_id: &str, client_id: &str) -> Result<()> {
        let changed = sqlx::query(
            "UPDATE apple_credentials SET revoked_at=COALESCE(revoked_at,now()) \
             WHERE account_id=$1 AND client_id=$2",
        )
        .bind(account_id)
        .bind(client_id)
        .execute(self.pool())
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "Apple credential disappeared before revocation settlement".into(),
            ));
        }
        Ok(())
    }
}
