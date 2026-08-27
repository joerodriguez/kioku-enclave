use async_trait::async_trait;
use sqlx::Row;

use crate::error::{EnclaveError, Result};

use super::super::identity::{
    Account, AccountSession, AccountStatus, AppleAccountGrant, IdentitySessionRepository,
};
use super::{advisory_transaction_lock, PostgresPersistence};

async fn deleted_account_or_identity(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: &str,
    provider: &str,
    subject: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM deleted_accounts WHERE account_id = $1) \
             OR EXISTS(SELECT 1 FROM deleted_identities WHERE provider = $2 AND subject = $3)",
    )
    .bind(account_id)
    .bind(provider)
    .bind(subject)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn reserve_signup(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    signup_limit: i64,
) -> Result<i64> {
    if signup_limit <= 0 {
        return Err(EnclaveError::SignupLimited);
    }
    let reserved = sqlx::query_scalar::<_, i64>(
        "INSERT INTO signup_daily (day, accounts) VALUES (CURRENT_DATE, 1) \
         ON CONFLICT (day) DO UPDATE \
            SET accounts = signup_daily.accounts + 1, updated_at = now() \
          WHERE signup_daily.accounts < $1 \
         RETURNING accounts",
    )
    .bind(signup_limit)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(accounts_today) = reserved else {
        return Err(EnclaveError::SignupLimited);
    };
    sqlx::query("DELETE FROM signup_daily WHERE day < CURRENT_DATE - 30")
        .execute(&mut **transaction)
        .await?;
    Ok(accounts_today)
}

#[async_trait]
impl IdentitySessionRepository for PostgresPersistence {
    async fn account_status(&self, account_id: &str) -> Result<Option<AccountStatus>> {
        let status = sqlx::query_scalar::<_, String>("SELECT status FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(self.pool())
            .await?;
        Ok(status.as_deref().map(AccountStatus::from_legacy))
    }

    async fn upsert_subject_account(
        &self,
        subject: &str,
        email: &str,
        signup_limit_per_day: i64,
    ) -> Result<Account> {
        let provider = "google";
        let stable_id = crate::cp::tokens::derive_stable_uuid(subject);
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, provider, subject).await?;

        if deleted_account_or_identity(&mut transaction, &stable_id, provider, subject).await? {
            return Err(EnclaveError::Auth("account deleted".into()));
        }

        let existing = sqlx::query(
            "SELECT a.id, a.email, a.status \
               FROM auth_identities i \
               JOIN accounts a ON a.id = i.account_id \
              WHERE i.provider = $1 AND i.subject = $2 \
              FOR UPDATE OF i, a",
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&mut *transaction)
        .await?;

        if let Some(row) = existing {
            let account_id: String = row.try_get("id")?;
            let status: String = row.try_get("status")?;
            if status != "active" {
                return Err(EnclaveError::Auth("account inactive".into()));
            }
            if account_id != stable_id {
                return Err(EnclaveError::Conflict(
                    "provider identity resolved to an unexpected account".into(),
                ));
            }
            sqlx::query(
                "UPDATE auth_identities \
                    SET email = $1, last_seen_at = now() \
                  WHERE provider = $2 AND subject = $3",
            )
            .bind(email)
            .bind(provider)
            .bind(subject)
            .execute(&mut *transaction)
            .await?;
            sqlx::query("UPDATE accounts SET email = $1, updated_at = now() WHERE id = $2")
                .bind(email)
                .bind(&account_id)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            return Ok(Account {
                id: account_id,
                email: email.to_string(),
            });
        }

        reserve_signup(&mut transaction, signup_limit_per_day).await?;
        sqlx::query(
            "INSERT INTO accounts \
                (id, email, status, primary_provider, primary_subject) \
             VALUES ($1, $2, 'active', $3, $4)",
        )
        .bind(&stable_id)
        .bind(email)
        .bind(provider)
        .bind(subject)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO auth_identities (provider, subject, account_id, email) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(provider)
        .bind(subject)
        .bind(&stable_id)
        .bind(email)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Account {
            id: stable_id,
            email: email.to_string(),
        })
    }

    async fn upsert_apple_account(
        &self,
        grant: AppleAccountGrant,
        signup_limit_per_day: i64,
    ) -> Result<Account> {
        let provider = "apple";
        let email = grant.email.to_lowercase();
        let stable_id = crate::cp::tokens::derive_provider_uuid(provider, &grant.subject);
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, provider, &grant.subject).await?;

        if deleted_account_or_identity(&mut transaction, &stable_id, provider, &grant.subject)
            .await?
        {
            return Err(EnclaveError::Auth("account deleted".into()));
        }

        let existing = sqlx::query(
            "SELECT a.id, a.email, a.status, a.primary_provider, a.primary_subject \
               FROM auth_identities i \
               JOIN accounts a ON a.id = i.account_id \
              WHERE i.provider = 'apple' AND i.subject = $1 \
              FOR UPDATE OF i, a",
        )
        .bind(&grant.subject)
        .fetch_optional(&mut *transaction)
        .await?;

        let (account_id, primary_email) = if let Some(row) = existing {
            let status: String = row.try_get("status")?;
            if status != "active" {
                return Err(EnclaveError::Auth("account inactive".into()));
            }
            let account_id: String = row.try_get("id")?;
            let mut primary_email: String = row.try_get("email")?;
            let primary_provider: String = row.try_get("primary_provider")?;
            let primary_subject: String = row.try_get("primary_subject")?;
            sqlx::query(
                "UPDATE auth_identities SET email = $1, last_seen_at = now() \
                  WHERE provider = 'apple' AND subject = $2",
            )
            .bind(&email)
            .bind(&grant.subject)
            .execute(&mut *transaction)
            .await?;
            if primary_provider == provider && primary_subject == grant.subject {
                sqlx::query("UPDATE accounts SET email = $1, updated_at = now() WHERE id = $2")
                    .bind(&email)
                    .bind(&account_id)
                    .execute(&mut *transaction)
                    .await?;
                primary_email = email.clone();
            }
            (account_id, primary_email)
        } else {
            let collision = sqlx::query(
                "SELECT primary_provider, primary_subject, status \
                   FROM accounts WHERE id = $1 FOR UPDATE",
            )
            .bind(&stable_id)
            .fetch_optional(&mut *transaction)
            .await?;
            if collision.is_some() {
                return Err(EnclaveError::Conflict("provider identity collision".into()));
            }
            reserve_signup(&mut transaction, signup_limit_per_day).await?;
            sqlx::query(
                "INSERT INTO accounts \
                    (id, email, status, primary_provider, primary_subject) \
                 VALUES ($1, $2, 'active', 'apple', $3)",
            )
            .bind(&stable_id)
            .bind(&email)
            .bind(&grant.subject)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO auth_identities (provider, subject, account_id, email) \
                 VALUES ('apple', $1, $2, $3)",
            )
            .bind(&grant.subject)
            .bind(&stable_id)
            .bind(&email)
            .execute(&mut *transaction)
            .await?;
            (stable_id, email.clone())
        };

        sqlx::query(
            "INSERT INTO apple_credentials \
                (account_id, client_id, refresh_token, revoked_at) \
             VALUES ($1, $2, $3, NULL) \
             ON CONFLICT (account_id, client_id) DO UPDATE \
               SET refresh_token = EXCLUDED.refresh_token, \
                   last_validated_at = now(), revoked_at = NULL",
        )
        .bind(&account_id)
        .bind(&grant.client_id)
        .bind(&grant.refresh_token)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Account {
            id: account_id,
            email: primary_email,
        })
    }

    async fn link_apple_identity(&self, account_id: &str, grant: AppleAccountGrant) -> Result<()> {
        let email = grant.email.to_lowercase();
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "apple", &grant.subject).await?;
        advisory_transaction_lock(&mut transaction, "account", account_id).await?;

        let status =
            sqlx::query_scalar::<_, String>("SELECT status FROM accounts WHERE id = $1 FOR UPDATE")
                .bind(account_id)
                .fetch_optional(&mut *transaction)
                .await?;
        if status.as_deref() != Some("active") {
            return Err(EnclaveError::Auth("account inactive".into()));
        }
        let identity_deleted = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM deleted_identities \
                            WHERE provider = 'apple' AND subject = $1)",
        )
        .bind(&grant.subject)
        .fetch_one(&mut *transaction)
        .await?;
        if identity_deleted {
            return Err(EnclaveError::Auth("identity deleted".into()));
        }

        let owner = sqlx::query_scalar::<_, String>(
            "SELECT account_id FROM auth_identities \
              WHERE provider = 'apple' AND subject = $1 FOR UPDATE",
        )
        .bind(&grant.subject)
        .fetch_optional(&mut *transaction)
        .await?;
        if owner.as_deref().is_some_and(|owner| owner != account_id) {
            return Err(EnclaveError::Conflict(
                "Apple identity is linked to another account".into(),
            ));
        }
        let other = sqlx::query_scalar::<_, String>(
            "SELECT subject FROM auth_identities \
              WHERE provider = 'apple' AND account_id = $1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if other
            .as_deref()
            .is_some_and(|linked| linked != grant.subject)
        {
            return Err(EnclaveError::Conflict(
                "account already has a different Apple identity".into(),
            ));
        }

        sqlx::query(
            "INSERT INTO auth_identities (provider, subject, account_id, email) \
             VALUES ('apple', $1, $2, $3) \
             ON CONFLICT (provider, subject) DO UPDATE \
               SET email = EXCLUDED.email, last_seen_at = now()",
        )
        .bind(&grant.subject)
        .bind(account_id)
        .bind(&email)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO apple_credentials \
                (account_id, client_id, refresh_token, revoked_at) \
             VALUES ($1, $2, $3, NULL) \
             ON CONFLICT (account_id, client_id) DO UPDATE \
               SET refresh_token = EXCLUDED.refresh_token, \
                   last_validated_at = now(), revoked_at = NULL",
        )
        .bind(account_id)
        .bind(&grant.client_id)
        .bind(&grant.refresh_token)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn account_session(&self, account_id: &str) -> Result<Option<AccountSession>> {
        let account =
            sqlx::query("SELECT id, email FROM accounts WHERE id = $1 AND status = 'active'")
                .bind(account_id)
                .fetch_optional(self.pool())
                .await?;
        let Some(account) = account else {
            return Ok(None);
        };
        let providers = sqlx::query_scalar::<_, String>(
            "SELECT provider FROM auth_identities WHERE account_id = $1 ORDER BY provider",
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await?;
        Ok(Some(AccountSession {
            account: Account {
                id: account.try_get("id")?,
                email: account.try_get("email")?,
            },
            providers,
        }))
    }
}
