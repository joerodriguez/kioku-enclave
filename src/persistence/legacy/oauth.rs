use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rusqlite::OptionalExtension;

use crate::cp::control_store::ControlStore;
use crate::error::{EnclaveError, Result};

use super::super::oauth::{
    AuthorizationCodeExchange, ConsentApproval, DirectAuthorizationCode, NativeSessionRefresh,
    OAuthClient, OAuthClientDefinition, OAuthClientRegistration, OAuthClientRegistrationRequest,
    OAuthRepository, PendingConsent, RefreshTokenRotation,
};

pub(crate) struct LegacyOAuthRepository {
    control: Arc<ControlStore>,
}

impl LegacyOAuthRepository {
    pub(crate) fn new(control: Arc<ControlStore>) -> Self {
        Self { control }
    }
}

fn duration_seconds(duration: Duration) -> Result<i64> {
    i64::try_from(duration.as_secs())
        .map_err(|_| EnclaveError::Store("OAuth duration exceeds database range".into()))
}

#[async_trait]
impl OAuthRepository for LegacyOAuthRepository {
    async fn ensure_client(&self, client: OAuthClientDefinition) -> Result<()> {
        let redirect_uris = serde_json::to_string(&client.redirect_uris)?;
        self.control
            .write_if_changed(move |connection| {
                let existing: Option<(Option<String>, String)> = connection
                    .query_row(
                        "SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = ?1",
                        [&client.id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                match existing {
                    Some((name, stored_redirects))
                        if name.as_deref() == Some(client.name.as_str())
                            && stored_redirects == redirect_uris =>
                    {
                        Ok(((), false))
                    }
                    Some((name, stored_redirects))
                        if client.allow_empty_redirect_upgrade
                            && name.as_deref() == Some(client.name.as_str())
                            && stored_redirects == "[]" =>
                    {
                        connection.execute(
                            "UPDATE oauth_clients SET redirect_uris = ?1 WHERE client_id = ?2",
                            rusqlite::params![redirect_uris, client.id],
                        )?;
                        Ok(((), true))
                    }
                    Some(_) => Err(EnclaveError::Conflict(
                        "first-party OAuth client configuration mismatch".into(),
                    )),
                    None => {
                        connection.execute(
                            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) \
                             VALUES (?1, ?2, ?3)",
                            rusqlite::params![client.id, client.name, redirect_uris],
                        )?;
                        Ok(((), true))
                    }
                }
            })
            .await
    }

    async fn register_client(
        &self,
        request: OAuthClientRegistrationRequest,
    ) -> Result<OAuthClientRegistration> {
        let redirect_uris = serde_json::to_string(&request.redirect_uris)?;
        let unused_ttl_seconds = duration_seconds(request.unused_ttl)?;
        self.control
            .write_if_changed(move |connection| {
                let transaction = connection.unchecked_transaction()?;
                let existing: Option<String> = transaction
                    .query_row(
                        "SELECT client_id FROM oauth_clients WHERE redirect_uris = ?1 LIMIT 1",
                        [&redirect_uris],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(client_id) = existing {
                    transaction.rollback()?;
                    return Ok((OAuthClientRegistration::Existing(client_id), false));
                }

                let [first_protected, second_protected] = request.protected_client_ids;
                let mut count: i64 = transaction.query_row(
                    "SELECT count(*) FROM oauth_clients WHERE client_id NOT IN (?1, ?2)",
                    rusqlite::params![first_protected, second_protected],
                    |row| row.get(0),
                )?;
                let mut reclaimed = 0;
                if count >= request.capacity {
                    reclaimed = transaction.execute(
                        "DELETE FROM oauth_clients \
                         WHERE client_id NOT IN (?2, ?3) \
                           AND created_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?1) \
                           AND NOT EXISTS (SELECT 1 FROM oauth_consents p \
                                           WHERE p.client_id = oauth_clients.client_id \
                                             AND p.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
                           AND NOT EXISTS (SELECT 1 FROM oauth_authorization_codes a \
                                           WHERE a.client_id = oauth_clients.client_id \
                                             AND a.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
                           AND NOT EXISTS (SELECT 1 FROM refresh_tokens r \
                                           WHERE r.client_id = oauth_clients.client_id \
                                             AND r.revoked = 0 \
                                             AND r.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                        rusqlite::params![
                            format!("-{unused_ttl_seconds} seconds"),
                            first_protected,
                            second_protected
                        ],
                    )?;
                    count = transaction.query_row(
                        "SELECT count(*) FROM oauth_clients WHERE client_id NOT IN (?1, ?2)",
                        rusqlite::params![first_protected, second_protected],
                        |row| row.get(0),
                    )?;
                }
                if count >= request.capacity {
                    if reclaimed == 0 {
                        transaction.rollback()?;
                    } else {
                        transaction.commit()?;
                    }
                    return Ok((OAuthClientRegistration::AtCapacity, reclaimed != 0));
                }

                transaction.execute(
                    "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) \
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![request.proposed_id, request.name, redirect_uris],
                )?;
                transaction.commit()?;
                Ok((
                    OAuthClientRegistration::Created(request.proposed_id),
                    true,
                ))
            })
            .await
    }

    async fn client(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        let client_id = client_id.to_string();
        self.control
            .read(move |connection| {
                let row: Option<(Option<String>, String)> = connection
                    .query_row(
                        "SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = ?1",
                        [&client_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                row.map(|(name, redirect_uris)| {
                    Ok(OAuthClient {
                        id: client_id,
                        name,
                        redirect_uris: serde_json::from_str(&redirect_uris)?,
                    })
                })
                .transpose()
            })
            .await
    }

    async fn store_pending_consent(&self, consent: PendingConsent) -> Result<bool> {
        let ttl_seconds = duration_seconds(consent.ttl)?;
        self.control
            .write_if_changed(move |connection| {
                let transaction = connection.unchecked_transaction()?;
                transaction.execute(
                    "DELETE FROM oauth_consents \
                     WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                    [],
                )?;
                let inserted = transaction.execute(
                    "INSERT INTO oauth_consents (consent_hash, user_id, client_id, redirect_uri, expires_at) \
                     SELECT ?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?5) \
                     WHERE EXISTS (SELECT 1 FROM users WHERE id = ?2 AND status = 'active') \
                       AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = ?3)",
                    rusqlite::params![
                        consent.consent_hash,
                        consent.account_id,
                        consent.client_id,
                        consent.redirect_uri,
                        format!("+{ttl_seconds} seconds")
                    ],
                )?;
                if inserted != 1 {
                    transaction.rollback()?;
                    return Ok((false, false));
                }
                transaction.commit()?;
                Ok((true, true))
            })
            .await
    }

    async fn approve_consent(&self, approval: ConsentApproval) -> Result<bool> {
        let ttl_seconds = duration_seconds(approval.code_ttl)?;
        self.control
            .write_if_changed(move |connection| {
                let transaction = connection.unchecked_transaction()?;
                let consumed = transaction.execute(
                    "DELETE FROM oauth_consents \
                     WHERE consent_hash = ?1 AND user_id = ?2 AND client_id = ?3 AND redirect_uri = ?4 \
                       AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') \
                       AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND status = 'active') \
                       AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = ?3)",
                    rusqlite::params![
                        approval.consent_hash,
                        approval.account_id,
                        approval.client_id,
                        approval.redirect_uri
                    ],
                )?;
                if consumed != 1 {
                    transaction.rollback()?;
                    return Ok((false, false));
                }
                transaction.execute(
                    "INSERT INTO oauth_authorization_codes (code_hash, user_id, client_id, expires_at) \
                     VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4))",
                    rusqlite::params![
                        approval.authorization_code_hash,
                        approval.account_id,
                        approval.client_id,
                        format!("+{ttl_seconds} seconds")
                    ],
                )?;
                transaction.commit()?;
                Ok((true, true))
            })
            .await
    }

    async fn store_direct_authorization_code(&self, code: DirectAuthorizationCode) -> Result<bool> {
        let ttl_seconds = duration_seconds(code.ttl)?;
        self.control
            .write_if_changed(move |connection| {
                let transaction = connection.unchecked_transaction()?;
                transaction.execute(
                    "DELETE FROM oauth_authorization_codes \
                     WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                    [],
                )?;
                let inserted = transaction.execute(
                    "INSERT INTO oauth_authorization_codes (code_hash, user_id, client_id, expires_at) \
                     SELECT ?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4) \
                     WHERE EXISTS (SELECT 1 FROM users WHERE id = ?2 AND status = 'active') \
                       AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = ?3)",
                    rusqlite::params![
                        code.authorization_code_hash,
                        code.account_id,
                        code.client_id,
                        format!("+{ttl_seconds} seconds")
                    ],
                )?;
                if inserted != 1 {
                    transaction.rollback()?;
                    return Ok((false, false));
                }
                transaction.commit()?;
                Ok((true, true))
            })
            .await
    }

    async fn exchange_authorization_code(
        &self,
        exchange: AuthorizationCodeExchange,
    ) -> Result<bool> {
        let ttl_seconds = duration_seconds(exchange.refresh_ttl)?;
        self.control
            .write_if_changed(move |connection| {
                let transaction = connection.unchecked_transaction()?;
                let consumed = transaction.execute(
                    "DELETE FROM oauth_authorization_codes \
                     WHERE code_hash = ?1 AND user_id = ?2 AND client_id = ?3 \
                       AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') \
                       AND EXISTS (SELECT 1 FROM users WHERE id = ?2 AND status = 'active') \
                       AND EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = ?3)",
                    rusqlite::params![
                        exchange.authorization_code_hash,
                        exchange.account_id,
                        exchange.client_id
                    ],
                )?;
                if consumed != 1 {
                    transaction.rollback()?;
                    return Ok((false, false));
                }
                transaction.execute(
                    "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
                     VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4))",
                    rusqlite::params![
                        exchange.refresh_token_hash,
                        exchange.account_id,
                        exchange.client_id,
                        format!("+{ttl_seconds} seconds")
                    ],
                )?;
                transaction.commit()?;
                Ok((true, true))
            })
            .await
    }

    async fn rotate_refresh_token(&self, rotation: RefreshTokenRotation) -> Result<Option<String>> {
        let ttl_seconds = duration_seconds(rotation.refresh_ttl)?;
        self.control
            .write_if_changed(move |connection| {
                let transaction = connection.unchecked_transaction()?;
                let account_id: Option<String> = transaction
                    .query_row(
                        "SELECT r.user_id FROM refresh_tokens r \
                         JOIN users u ON u.id = r.user_id AND u.status = 'active' \
                         JOIN oauth_clients c ON c.client_id = r.client_id \
                         WHERE r.token_hash = ?1 AND r.client_id = ?2 AND r.revoked = 0 \
                           AND r.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                        rusqlite::params![rotation.old_token_hash, rotation.client_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                let Some(account_id) = account_id else {
                    transaction.rollback()?;
                    return Ok((None, false));
                };
                let updated = transaction.execute(
                    "UPDATE refresh_tokens SET revoked = 1 \
                     WHERE token_hash = ?1 AND client_id = ?2 AND revoked = 0",
                    rusqlite::params![rotation.old_token_hash, rotation.client_id],
                )?;
                if updated != 1 {
                    transaction.rollback()?;
                    return Ok((None, false));
                }
                transaction.execute(
                    "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
                     VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4))",
                    rusqlite::params![
                        rotation.new_token_hash,
                        account_id,
                        rotation.client_id,
                        format!("+{ttl_seconds} seconds")
                    ],
                )?;
                transaction.commit()?;
                Ok((Some(account_id), true))
            })
            .await
    }

    async fn create_native_session_refresh(&self, session: NativeSessionRefresh) -> Result<()> {
        let ttl_seconds = duration_seconds(session.refresh_ttl)?;
        let redirect_uris = serde_json::to_string(&session.client.redirect_uris)?;
        self.control
            .write(move |connection| {
                let transaction = connection.unchecked_transaction()?;
                let active: i64 = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND status = 'active')",
                    [&session.account_id],
                    |row| row.get(0),
                )?;
                if active == 0 {
                    transaction.rollback()?;
                    return Err(EnclaveError::Auth("account inactive".into()));
                }
                transaction.execute(
                    "INSERT OR IGNORE INTO oauth_clients (client_id, client_name, redirect_uris) \
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![session.client.id, session.client.name, redirect_uris],
                )?;
                transaction.execute(
                    "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
                     VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now', ?4))",
                    rusqlite::params![
                        session.refresh_token_hash,
                        session.account_id,
                        session.client.id,
                        format!("+{ttl_seconds} seconds")
                    ],
                )?;
                transaction.commit()?;
                Ok(())
            })
            .await
    }
}
