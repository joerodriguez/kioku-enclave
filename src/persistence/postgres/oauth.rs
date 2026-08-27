use async_trait::async_trait;
use sqlx::Row;

use crate::error::{EnclaveError, Result};

use super::super::oauth::{
    AuthorizationCodeExchange, ConsentApproval, DirectAuthorizationCode, NativeSessionRefresh,
    OAuthClient, OAuthClientDefinition, OAuthClientRegistration, OAuthClientRegistrationRequest,
    OAuthRepository, PendingConsent, RefreshTokenRotation,
};
use super::{advisory_transaction_lock, duration_seconds, PostgresPersistence};

#[async_trait]
impl OAuthRepository for PostgresPersistence {
    async fn ensure_client(&self, client: OAuthClientDefinition) -> Result<()> {
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "oauth-client", &client.id).await?;
        let existing = sqlx::query(
            "SELECT client_name, redirect_uris FROM oauth_clients \
              WHERE client_id = $1 FOR UPDATE",
        )
        .bind(&client.id)
        .fetch_optional(&mut *transaction)
        .await?;
        match existing {
            Some(row) => {
                let name: Option<String> = row.try_get("client_name")?;
                let redirects: Vec<String> = row.try_get("redirect_uris")?;
                if name.as_deref() == Some(client.name.as_str())
                    && redirects == client.redirect_uris
                {
                    transaction.commit().await?;
                    return Ok(());
                }
                if client.allow_empty_redirect_upgrade
                    && name.as_deref() == Some(client.name.as_str())
                    && redirects.is_empty()
                {
                    sqlx::query("UPDATE oauth_clients SET redirect_uris = $1 WHERE client_id = $2")
                        .bind(&client.redirect_uris)
                        .bind(&client.id)
                        .execute(&mut *transaction)
                        .await?;
                    transaction.commit().await?;
                    return Ok(());
                }
                Err(EnclaveError::Conflict(
                    "first-party OAuth client configuration mismatch".into(),
                ))
            }
            None => {
                sqlx::query(
                    "INSERT INTO oauth_clients \
                        (client_id, client_name, redirect_uris) VALUES ($1, $2, $3)",
                )
                .bind(&client.id)
                .bind(&client.name)
                .bind(&client.redirect_uris)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    async fn register_client(
        &self,
        request: OAuthClientRegistrationRequest,
    ) -> Result<OAuthClientRegistration> {
        let unused_seconds = duration_seconds(request.unused_ttl)?;
        let [first_protected, second_protected] = request.protected_client_ids;
        let mut transaction = self.pool().begin().await?;
        advisory_transaction_lock(&mut transaction, "oauth-client", "dynamic-registration").await?;

        let existing = sqlx::query_scalar::<_, String>(
            "SELECT client_id FROM oauth_clients WHERE redirect_uris = $1 LIMIT 1",
        )
        .bind(&request.redirect_uris)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(client_id) = existing {
            transaction.commit().await?;
            return Ok(OAuthClientRegistration::Existing(client_id));
        }

        let mut count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oauth_clients WHERE client_id NOT IN ($1, $2)",
        )
        .bind(&first_protected)
        .bind(&second_protected)
        .fetch_one(&mut *transaction)
        .await?;
        if count >= request.capacity {
            sqlx::query(
                "DELETE FROM oauth_clients c \
                  WHERE c.client_id NOT IN ($1, $2) \
                    AND c.created_at <= now() - make_interval(secs => $3) \
                    AND NOT EXISTS (SELECT 1 FROM oauth_consents p \
                                     WHERE p.client_id = c.client_id AND p.expires_at > now()) \
                    AND NOT EXISTS (SELECT 1 FROM oauth_authorization_codes a \
                                     WHERE a.client_id = c.client_id AND a.expires_at > now()) \
                    AND NOT EXISTS (SELECT 1 FROM refresh_tokens r \
                                     WHERE r.client_id = c.client_id \
                                       AND r.revoked_at IS NULL AND r.expires_at > now())",
            )
            .bind(&first_protected)
            .bind(&second_protected)
            .bind(unused_seconds)
            .execute(&mut *transaction)
            .await?;
            count = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM oauth_clients WHERE client_id NOT IN ($1, $2)",
            )
            .bind(&first_protected)
            .bind(&second_protected)
            .fetch_one(&mut *transaction)
            .await?;
        }
        if count >= request.capacity {
            transaction.commit().await?;
            return Ok(OAuthClientRegistration::AtCapacity);
        }

        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) \
             VALUES ($1, $2, $3)",
        )
        .bind(&request.proposed_id)
        .bind(&request.name)
        .bind(&request.redirect_uris)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(OAuthClientRegistration::Created(request.proposed_id))
    }

    async fn client(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        let row = sqlx::query(
            "SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            Ok(OAuthClient {
                id: client_id.to_string(),
                name: row.try_get("client_name")?,
                redirect_uris: row.try_get("redirect_uris")?,
            })
        })
        .transpose()
    }

    async fn store_pending_consent(&self, consent: PendingConsent) -> Result<bool> {
        let ttl_seconds = duration_seconds(consent.ttl)?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query("DELETE FROM oauth_consents WHERE expires_at <= now()")
            .execute(&mut *transaction)
            .await?;
        let inserted = sqlx::query(
            "INSERT INTO oauth_consents \
                (consent_hash, account_id, client_id, redirect_uri, expires_at) \
             SELECT $1, $2, $3, $4, now() + make_interval(secs => $5) \
              WHERE EXISTS (SELECT 1 FROM accounts WHERE id = $2 AND status = 'active') \
                AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = $3) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&consent.consent_hash)
        .bind(&consent.account_id)
        .bind(&consent.client_id)
        .bind(&consent.redirect_uri)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if inserted != 1 {
            return Ok(false);
        }
        transaction.commit().await?;
        Ok(true)
    }

    async fn approve_consent(&self, approval: ConsentApproval) -> Result<bool> {
        let ttl_seconds = duration_seconds(approval.code_ttl)?;
        let mut transaction = self.pool().begin().await?;
        let consumed = sqlx::query(
            "DELETE FROM oauth_consents c \
              USING accounts a, oauth_clients oc \
              WHERE c.consent_hash = $1 AND c.account_id = $2 \
                AND c.client_id = $3 AND c.redirect_uri = $4 \
                AND c.expires_at > now() \
                AND a.id = c.account_id AND a.status = 'active' \
                AND oc.client_id = c.client_id",
        )
        .bind(&approval.consent_hash)
        .bind(&approval.account_id)
        .bind(&approval.client_id)
        .bind(&approval.redirect_uri)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if consumed != 1 {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO oauth_authorization_codes \
                (code_hash, account_id, client_id, expires_at) \
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(&approval.authorization_code_hash)
        .bind(&approval.account_id)
        .bind(&approval.client_id)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    async fn store_direct_authorization_code(&self, code: DirectAuthorizationCode) -> Result<bool> {
        let ttl_seconds = duration_seconds(code.ttl)?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query("DELETE FROM oauth_authorization_codes WHERE expires_at <= now()")
            .execute(&mut *transaction)
            .await?;
        let inserted = sqlx::query(
            "INSERT INTO oauth_authorization_codes \
                (code_hash, account_id, client_id, expires_at) \
             SELECT $1, $2, $3, now() + make_interval(secs => $4) \
              WHERE EXISTS (SELECT 1 FROM accounts WHERE id = $2 AND status = 'active') \
                AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = $3) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&code.authorization_code_hash)
        .bind(&code.account_id)
        .bind(&code.client_id)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if inserted != 1 {
            return Ok(false);
        }
        transaction.commit().await?;
        Ok(true)
    }

    async fn exchange_authorization_code(
        &self,
        exchange: AuthorizationCodeExchange,
    ) -> Result<bool> {
        let ttl_seconds = duration_seconds(exchange.refresh_ttl)?;
        let mut transaction = self.pool().begin().await?;
        let consumed = sqlx::query(
            "DELETE FROM oauth_authorization_codes c \
              USING accounts a, oauth_clients oc \
              WHERE c.code_hash = $1 AND c.account_id = $2 AND c.client_id = $3 \
                AND c.expires_at > now() \
                AND a.id = c.account_id AND a.status = 'active' \
                AND oc.client_id = c.client_id",
        )
        .bind(&exchange.authorization_code_hash)
        .bind(&exchange.account_id)
        .bind(&exchange.client_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if consumed != 1 {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO refresh_tokens \
                (token_hash, account_id, client_id, expires_at) \
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(&exchange.refresh_token_hash)
        .bind(&exchange.account_id)
        .bind(&exchange.client_id)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    async fn rotate_refresh_token(&self, rotation: RefreshTokenRotation) -> Result<Option<String>> {
        let ttl_seconds = duration_seconds(rotation.refresh_ttl)?;
        let mut transaction = self.pool().begin().await?;
        let account_id = sqlx::query_scalar::<_, String>(
            "SELECT r.account_id \
               FROM refresh_tokens r \
               JOIN accounts a ON a.id = r.account_id AND a.status = 'active' \
               JOIN oauth_clients c ON c.client_id = r.client_id \
              WHERE r.token_hash = $1 AND r.client_id = $2 \
                AND r.revoked_at IS NULL AND r.expires_at > now() \
              FOR UPDATE OF r",
        )
        .bind(&rotation.old_token_hash)
        .bind(&rotation.client_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(account_id) = account_id else {
            return Ok(None);
        };
        let updated = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now() \
              WHERE token_hash = $1 AND client_id = $2 AND revoked_at IS NULL",
        )
        .bind(&rotation.old_token_hash)
        .bind(&rotation.client_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if updated != 1 {
            return Ok(None);
        }
        sqlx::query(
            "INSERT INTO refresh_tokens \
                (token_hash, account_id, client_id, expires_at) \
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(&rotation.new_token_hash)
        .bind(&account_id)
        .bind(&rotation.client_id)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Some(account_id))
    }

    async fn create_native_session_refresh(&self, session: NativeSessionRefresh) -> Result<()> {
        let ttl_seconds = duration_seconds(session.refresh_ttl)?;
        let mut transaction = self.pool().begin().await?;
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1 AND status = 'active')",
        )
        .bind(&session.account_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !active {
            return Err(EnclaveError::Auth("account inactive".into()));
        }
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) \
             VALUES ($1, $2, $3) ON CONFLICT (client_id) DO NOTHING",
        )
        .bind(&session.client.id)
        .bind(&session.client.name)
        .bind(&session.client.redirect_uris)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO refresh_tokens \
                (token_hash, account_id, client_id, expires_at) \
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(&session.refresh_token_hash)
        .bind(&session.account_id)
        .bind(&session.client.id)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}
