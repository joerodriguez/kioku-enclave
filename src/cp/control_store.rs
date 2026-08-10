//! Control-plane state store: identity and accounting in an encrypted SQLite
//! blob in GCS, replacing the legacy managed SQL store.
//!
//! Tables: `users`, provider-neutral `auth_identities`, provider credentials,
//! content-free deletion operations/tombstones, `usage_daily`, `oauth_clients`,
//! `refresh_tokens`, `query_log`, and user-configured webhook destinations. No captured user
//! *content* — that stays in the per-user index blobs ([`crate::store`]). One small control blob,
//! `control/control.db.enc`, encrypted under its own KMS-wrapped DEK exactly like
//! a user index, so identity state survives VM rolls without a managed database.
//!
//! Write volume here is tiny (sign-ins, token rotation, daily counters), so
//! whole-blob persist-on-write is fine — unlike user indexes (see ADR-0002).

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use rusqlite::{Connection, OptionalExtension};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::info;

use crate::{
    cp::isotime,
    crypto::{decrypt_bound_blob, encrypt_bound_blob, generate_and_wrap_dek, load_dek, KmsClient},
    error::{EnclaveError, Result},
    store::GcsClient,
};

const CONTROL_OBJECT: &str = "control/control.db.enc";
const CONTROL_CONTEXT: &[u8] = b"control-db\0control/control.db.enc";

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users (
    id               TEXT PRIMARY KEY,
    google_sub       TEXT UNIQUE NOT NULL,
    email            TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    summarized_until TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
-- Provider identities are separate from the canonical Kioku account; mutable
-- email claims never link accounts.
CREATE TABLE IF NOT EXISTS auth_identities (
    provider       TEXT NOT NULL,
    subject        TEXT NOT NULL,
    user_id        TEXT NOT NULL REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
    email          TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (provider, subject),
    UNIQUE (user_id, provider)
);
CREATE INDEX IF NOT EXISTS auth_identities_user_idx ON auth_identities(user_id);
-- Existing rows predate provider-neutral identities and are Google accounts.
INSERT OR IGNORE INTO auth_identities (provider, subject, user_id, email)
SELECT 'google', u.google_sub, u.id, u.email FROM users u
WHERE NOT EXISTS (SELECT 1 FROM auth_identities i WHERE i.user_id = u.id);
CREATE TABLE IF NOT EXISTS apple_credentials (
    user_id           TEXT PRIMARY KEY REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
    refresh_token     TEXT NOT NULL,
    last_validated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    revoked_at        TEXT
);
CREATE TABLE IF NOT EXISTS usage_daily (
    user_id              TEXT NOT NULL,
    day                  TEXT NOT NULL,
    utterances           INTEGER NOT NULL DEFAULT 0,
    screenshots          INTEGER NOT NULL DEFAULT 0,
    mcp_calls            INTEGER NOT NULL DEFAULT 0,
    vertex_requests      INTEGER NOT NULL DEFAULT 0,
    vertex_output_tokens INTEGER NOT NULL DEFAULT 0,
    vertex_audio_output_tokens INTEGER NOT NULL DEFAULT 0,
    vertex_screen_output_tokens INTEGER NOT NULL DEFAULT 0,
    vertex_derived_output_tokens INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT,
    redirect_uris TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code_hash  TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS oauth_authorization_codes_expires_idx
    ON oauth_authorization_codes(expires_at);
CREATE TABLE IF NOT EXISTS oauth_consents (
    consent_hash TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    client_id    TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS oauth_consents_expires_idx ON oauth_consents(expires_at);
-- A deletion tombstone is deliberately non-content-bearing. It prevents a
-- still-valid Google ID token from silently recreating an account immediately
-- after deletion while allowing the identity row (including email) to go away.
CREATE TABLE IF NOT EXISTS deleted_users (
    user_id    TEXT PRIMARY KEY,
    deleted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
-- Provider tombstones prevent a deleted linked identity from creating a fresh
-- account after its mapping row has been erased.
CREATE TABLE IF NOT EXISTS deleted_identities (
    provider   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    deleted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (provider, subject)
);
-- Stable, opaque status for an authenticated account-deletion retry/poll.
-- This deliberately contains no email, object name, media key, or user content
-- and remains after identity deletion alongside the stable tombstone.
CREATE TABLE IF NOT EXISTS account_deletion_operations (
    user_id             TEXT PRIMARY KEY,
    operation_id        TEXT UNIQUE NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('pending', 'failed_retryable', 'physical_complete')),
    reason              TEXT NOT NULL,
    retry_after_seconds INTEGER CHECK (retry_after_seconds IS NULL OR retry_after_seconds >= 0),
    hard_delete_time    TEXT,
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS query_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT,
    ts          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    source      TEXT NOT NULL,
    tool        TEXT,
    query_text  TEXT,
    result_count INTEGER,
    duration_ms INTEGER
);
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    endpoint_url    TEXT NOT NULL,
    signing_secret  TEXT NOT NULL,
    include_content INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS webhook_subscriptions_user_idx
    ON webhook_subscriptions(user_id);
CREATE TABLE IF NOT EXISTS episode_email_preferences (
    user_id          TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enabled          INTEGER NOT NULL DEFAULT 0,
    include_content  INTEGER NOT NULL DEFAULT 0,
    consented_at     TEXT,
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
-- ADR-0012 removes Gmail delivery and its stored OAuth credentials.
DROP TABLE IF EXISTS user_gmail_configs;
"#;

struct BlobMeta {
    generation: i64,
    wrapped_dek_b64: String,
}

struct Handle {
    conn: Connection,
    meta: BlobMeta,
    temp_path: PathBuf,
}

fn remove_sqlite_temp_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(sidecar));
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Confidential-space deployments are Unix, where unlinking an open
        // SQLite file is safe; the inode disappears when `conn` then drops.
        remove_sqlite_temp_files(&self.temp_path);
    }
}

struct PendingTempFile {
    path: PathBuf,
    armed: bool,
}

impl PendingTempFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingTempFile {
    fn drop(&mut self) {
        if self.armed {
            remove_sqlite_temp_files(&self.path);
        }
    }
}

pub struct ControlStore {
    inner: Mutex<Option<Handle>>,
    kms: Arc<dyn KmsClient>,
    gcs: Arc<dyn GcsClient>,
}

/// A user identity row (the fields callers actually need).
pub struct User {
    pub id: String,
    #[allow(dead_code)] // surfaced for callers that log/display the account
    pub email: String,
}

/// Content-free, durable status for an account-deletion operation.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct AccountDeletionOperation {
    pub operation_id: String,
    pub status: String,
    pub reason: String,
    pub retry_after_seconds: Option<u64>,
    pub hard_delete_time: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebhookSubscription {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub endpoint_url: String,
    pub signing_secret: String,
    pub include_content: bool,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EpisodeEmailPreference {
    pub enabled: bool,
    pub include_content: bool,
    pub recipient_email: String,
    pub consented_at: Option<String>,
    pub updated_at: String,
}

fn is_active_user_conn(conn: &Connection, user_id: &str) -> Result<bool> {
    let active: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND status = 'active')",
        [user_id],
        |r| r.get(0),
    )?;
    Ok(active != 0)
}

fn is_deleted_identity_conn(conn: &Connection, provider: &str, subject: &str) -> Result<bool> {
    let deleted: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM deleted_identities WHERE provider = ?1 AND subject = ?2)",
        rusqlite::params![provider, subject],
        |row| row.get(0),
    )?;
    Ok(deleted != 0)
}

fn is_deleted_user_conn(conn: &Connection, stable_user_id: &str) -> Result<bool> {
    let deleted: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM deleted_users WHERE user_id = ?1)",
        [stable_user_id],
        |r| r.get(0),
    )?;
    Ok(deleted != 0)
}

fn user_status_conn(conn: &Connection, user_id: &str) -> Result<Option<String>> {
    let status = conn
        .query_row("SELECT status FROM users WHERE id = ?1", [user_id], |r| {
            r.get::<_, String>(0)
        })
        .optional()?;
    if status.is_some() {
        return Ok(status);
    }
    if is_deleted_user_conn(conn, user_id)? {
        return Ok(Some("deleted".to_string()));
    }
    Ok(None)
}

fn account_deletion_operation_conn(
    conn: &Connection,
    user_id: &str,
) -> Result<Option<AccountDeletionOperation>> {
    let row = conn
        .query_row(
            "SELECT operation_id, status, reason, retry_after_seconds, hard_delete_time
             FROM account_deletion_operations WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(operation_id, status, reason, retry_after_seconds, hard_delete_time)| {
            let retry_after_seconds =
                retry_after_seconds
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| {
                        EnclaveError::Store("invalid persisted account-deletion retry delay".into())
                    })?;
            Ok(AccountDeletionOperation {
                operation_id,
                status,
                reason,
                retry_after_seconds,
                hard_delete_time,
            })
        },
    )
    .transpose()
}

/// Remove identity/accounting state and leave only a stable, non-content
/// tombstone. Returning Google credentials can then be denied instead of
/// recreating the just-deleted account.
fn delete_user_identity_conn(conn: &Connection, user_id: &str) -> Result<AccountDeletionOperation> {
    let tx = conn.unchecked_transaction()?;
    let identity: Option<(String, String)> = tx
        .query_row(
            "SELECT google_sub, status FROM users WHERE id = ?1",
            [user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((google_sub, status)) = identity else {
        // A prior finalization may have committed locally and then failed while
        // uploading the encrypted control DB. A retry also handles tombstones
        // created by releases predating durable operation status.
        let tombstoned: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM deleted_users WHERE user_id = ?1)",
            [user_id],
            |r| r.get(0),
        )?;
        if tombstoned == 0 {
            tx.rollback()?;
            return Err(EnclaveError::Conflict("account is unavailable".into()));
        }
        let updated = tx.execute(
            "UPDATE account_deletion_operations
             SET status = 'physical_complete', reason = 'content_deleted',
                 retry_after_seconds = NULL, hard_delete_time = NULL,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE user_id = ?1",
            [user_id],
        )?;
        if updated != 1 {
            tx.rollback()?;
            return Err(EnclaveError::Conflict(
                "account deletion operation was not initialized".into(),
            ));
        }
        let operation = account_deletion_operation_conn(&tx, user_id)?
            .ok_or_else(|| EnclaveError::Store("account deletion operation disappeared".into()))?;
        tx.commit()?;
        return Ok(operation);
    };
    if status != "deleting" {
        tx.rollback()?;
        return Err(EnclaveError::Conflict(
            "account deletion was not initialized".into(),
        ));
    }

    let stable_user_id = super::tokens::derive_stable_uuid(&google_sub);
    tx.execute(
        "INSERT OR IGNORE INTO deleted_users (user_id) VALUES (?1)",
        [&stable_user_id],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO deleted_users (user_id) VALUES (?1)",
        [user_id],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO deleted_identities (provider, subject) \\
         SELECT provider, subject FROM auth_identities WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute(
        "DELETE FROM oauth_authorization_codes WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute("DELETE FROM oauth_consents WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM refresh_tokens WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM usage_daily WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM query_log WHERE user_id = ?1", [user_id])?;
    tx.execute(
        "DELETE FROM webhook_subscriptions WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute(
        "DELETE FROM episode_email_preferences WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute(
        "DELETE FROM apple_credentials WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute("DELETE FROM auth_identities WHERE user_id = ?1", [user_id])?;
    let deleted = tx.execute("DELETE FROM users WHERE id = ?1", [user_id])?;
    if deleted != 1 {
        tx.rollback()?;
        return Err(EnclaveError::Store(
            "account identity deletion affected an unexpected row count".into(),
        ));
    }
    let operation_updated = tx.execute(
        "UPDATE account_deletion_operations
         SET status = 'physical_complete', reason = 'content_deleted',
             retry_after_seconds = NULL, hard_delete_time = NULL,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE user_id = ?1",
        [user_id],
    )?;
    if operation_updated != 1 {
        tx.rollback()?;
        return Err(EnclaveError::Conflict(
            "account deletion operation was not initialized".into(),
        ));
    }
    let operation = account_deletion_operation_conn(&tx, user_id)?
        .ok_or_else(|| EnclaveError::Store("account deletion operation disappeared".into()))?;
    tx.commit()?;
    Ok(operation)
}

fn begin_user_deletion_conn(
    conn: &Connection,
    user_id: &str,
    proposed_operation_id: &str,
) -> Result<Option<AccountDeletionOperation>> {
    let tx = conn.unchecked_transaction()?;
    let status: Option<String> = tx
        .query_row("SELECT status FROM users WHERE id = ?1", [user_id], |r| {
            r.get(0)
        })
        .optional()?;
    let tombstoned = status.is_none() && is_deleted_user_conn(&tx, user_id)?;
    if !tombstoned && !matches!(status.as_deref(), Some("active" | "deleting")) {
        tx.rollback()?;
        return Ok(None);
    }

    if !tombstoned {
        tx.execute(
            "UPDATE users SET status = 'deleting' WHERE id = ?1",
            [user_id],
        )?;
        tx.execute(
            "DELETE FROM oauth_authorization_codes WHERE user_id = ?1",
            [user_id],
        )?;
        tx.execute("DELETE FROM oauth_consents WHERE user_id = ?1", [user_id])?;
        tx.execute("DELETE FROM refresh_tokens WHERE user_id = ?1", [user_id])?;
        tx.execute(
            "UPDATE webhook_subscriptions SET enabled = 0, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ?1",
            [user_id],
        )?;
        tx.execute(
            "UPDATE episode_email_preferences SET enabled = 0, include_content = 0, \
             consented_at = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ?1",
            [user_id],
        )?;
    }
    tx.execute(
        "INSERT OR IGNORE INTO account_deletion_operations
         (user_id, operation_id, status, reason, retry_after_seconds)
         VALUES (?1, ?2, 'pending', 'content_deletion_in_progress', 30)",
        rusqlite::params![user_id, proposed_operation_id],
    )?;
    let operation = account_deletion_operation_conn(&tx, user_id)?.ok_or_else(|| {
        EnclaveError::Store("failed to initialize account deletion operation".into())
    })?;
    if !tombstoned && operation.status == "physical_complete" {
        tx.rollback()?;
        return Err(EnclaveError::Conflict(
            "physically complete deletion operation still has an identity row".into(),
        ));
    }
    tx.commit()?;
    Ok(Some(operation))
}

fn deletion_operation_status_for_reason(reason: &str) -> &'static str {
    match reason {
        "legacy_generation_unavailable" | "legacy_snapshot_too_large" => "failed_retryable",
        _ => "pending",
    }
}

fn update_user_deletion_status_conn(
    conn: &Connection,
    user_id: &str,
    reason: &str,
    retry_after_seconds: Option<u64>,
    hard_delete_time: Option<&str>,
) -> Result<AccountDeletionOperation> {
    let retry_after_seconds = retry_after_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| EnclaveError::Store("account-deletion retry delay is too large".into()))?;
    let tx = conn.unchecked_transaction()?;
    let status = deletion_operation_status_for_reason(reason);
    let updated = tx.execute(
        "UPDATE account_deletion_operations
         SET status = ?2, reason = ?3, retry_after_seconds = ?4,
             hard_delete_time = ?5,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE user_id = ?1",
        rusqlite::params![
            user_id,
            status,
            reason,
            retry_after_seconds,
            hard_delete_time
        ],
    )?;
    if updated != 1 {
        tx.rollback()?;
        return Err(EnclaveError::Conflict(
            "account deletion operation was not initialized".into(),
        ));
    }
    let operation = account_deletion_operation_conn(&tx, user_id)?
        .ok_or_else(|| EnclaveError::Store("account deletion operation disappeared".into()))?;
    tx.commit()?;
    Ok(operation)
}

impl ControlStore {
    pub fn new(kms: Arc<dyn KmsClient>, gcs: Arc<dyn GcsClient>) -> Self {
        Self {
            inner: Mutex::new(None),
            kms,
            gcs,
        }
    }

    /// Run a read-only closure against the control DB (loads on first use).
    pub async fn read<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let mut guard = self.inner.lock().await;
        if guard.is_none() {
            *guard = Some(self.load().await?);
        }
        f(&guard.as_ref().unwrap().conn)
    }

    /// Run a mutating closure, then persist the whole control DB back to GCS.
    pub async fn write<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let mut guard = self.inner.lock().await;
        if guard.is_none() {
            *guard = Some(self.load().await?);
        }
        let out = match f(&guard.as_ref().unwrap().conn) {
            Ok(out) => out,
            Err(error) => {
                *guard = None;
                return Err(error);
            }
        };
        if let Err(error) = self.flush(guard.as_mut().unwrap()).await {
            // The SQLite transaction has already committed locally. Discard it
            // after a failed object write so replay/credential state is loaded
            // again from the last durable GCS generation on the next request.
            *guard = None;
            return Err(error);
        }
        Ok(out)
    }

    /// Run a mutating closure and persist only when it reports a change.
    ///
    /// OAuth invalid/replay paths use this so an unauthenticated request cannot
    /// force a full encrypted control-DB rewrite when no state was changed.
    pub(crate) async fn write_if_changed<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<(T, bool)>,
    {
        let mut guard = self.inner.lock().await;
        if guard.is_none() {
            *guard = Some(self.load().await?);
        }
        let (out, changed) = match f(&guard.as_ref().unwrap().conn) {
            Ok(outcome) => outcome,
            Err(error) => {
                *guard = None;
                return Err(error);
            }
        };
        if changed {
            if let Err(error) = self.flush(guard.as_mut().unwrap()).await {
                *guard = None;
                return Err(error);
            }
        }
        Ok(out)
    }

    async fn load(&self) -> Result<Handle> {
        let (plaintext, meta) = match self.gcs.get_object(CONTROL_OBJECT).await {
            Ok(resp) => {
                let dek = load_dek(self.kms.as_ref(), &resp.wrapped_dek_b64).await?;
                let opened = decrypt_bound_blob(&dek, &resp.ciphertext, CONTROL_CONTEXT)?;
                (
                    opened.plaintext,
                    BlobMeta {
                        generation: resp.generation,
                        wrapped_dek_b64: resp.wrapped_dek_b64,
                    },
                )
            }
            Err(EnclaveError::NotFound) => {
                info!("creating new control DB");
                let (_, wrapped) = generate_and_wrap_dek(self.kms.as_ref()).await?;
                (
                    Vec::new(),
                    BlobMeta {
                        generation: 0,
                        wrapped_dek_b64: wrapped,
                    },
                )
            }
            Err(e) => return Err(e),
        };

        let temp_path = std::env::temp_dir().join(format!(
            "kioku-control-{}.db",
            super::tokens::random_token_hex()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let std_temp_file = options.open(&temp_path)?;
        let mut pending_temp = PendingTempFile::new(temp_path.clone());
        let mut temp_file = tokio::fs::File::from_std(std_temp_file);
        if !plaintext.is_empty() {
            temp_file.write_all(&plaintext).await?;
            temp_file.flush().await?;
        }
        drop(temp_file);
        let conn = Connection::open(&temp_path)?;
        conn.execute_batch(SCHEMA)?;
        let mut schema_migrations = 0;
        for column in [
            "ALTER TABLE usage_daily ADD COLUMN vertex_requests INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE usage_daily ADD COLUMN vertex_output_tokens INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE usage_daily ADD COLUMN vertex_audio_output_tokens INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE usage_daily ADD COLUMN vertex_screen_output_tokens INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE usage_daily ADD COLUMN vertex_derived_output_tokens INTEGER NOT NULL DEFAULT 0",
        ] {
            match conn.execute(column, []) {
                Ok(_) => schema_migrations += 1,
                Err(error) if error.to_string().contains("duplicate column name") => {}
                Err(error) => return Err(error.into()),
            }
        }
        // Historical builds retained raw search text in the central accounting
        // DB. Remove it during load so the migration is automatic and durable.
        let redacted_queries = conn.execute(
            "UPDATE query_log SET query_text = NULL WHERE query_text IS NOT NULL",
            [],
        )?;
        let mut handle = Handle {
            conn,
            meta,
            temp_path,
        };
        if redacted_queries > 0 || schema_migrations > 0 {
            self.flush(&mut handle).await?;
            info!(
                rows = redacted_queries,
                schema_migrations, "control DB migrated"
            );
        }
        pending_temp.disarm();
        Ok(handle)
    }

    async fn flush(&self, handle: &mut Handle) -> Result<()> {
        handle
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let db_bytes = tokio::fs::read(&handle.temp_path).await?;
        let dek = load_dek(self.kms.as_ref(), &handle.meta.wrapped_dek_b64).await?;
        let ciphertext = encrypt_bound_blob(&dek, &db_bytes, CONTROL_CONTEXT)?;
        let new_gen = self
            .gcs
            .put_object(
                CONTROL_OBJECT,
                &ciphertext,
                &handle.meta.wrapped_dek_b64,
                handle.meta.generation,
            )
            .await?;
        handle.meta.generation = new_gen;
        Ok(())
    }

    /// Move a pre-stable-id user database without breaking its object-bound
    /// AEAD context. A raw GCS copy would retain the old context and become
    /// undecryptable under the stable object's name.
    async fn rebind_user_blob(&self, old_user_id: &str, new_user_id: &str) -> Result<()> {
        let old_object = format!("indexes/{old_user_id}.db.enc");
        let new_object = format!("indexes/{new_user_id}.db.enc");
        let old = self.gcs.get_object(&old_object).await?;
        let dek = load_dek(self.kms.as_ref(), &old.wrapped_dek_b64).await?;
        let old_context = crate::store::user_blob_context(old_user_id);
        let opened = decrypt_bound_blob(&dek, &old.ciphertext, &old_context)?;

        match self.gcs.get_object(&new_object).await {
            Ok(existing) => {
                let existing_dek = load_dek(self.kms.as_ref(), &existing.wrapped_dek_b64).await?;
                let new_context = crate::store::user_blob_context(new_user_id);
                let existing_opened =
                    decrypt_bound_blob(&existing_dek, &existing.ciphertext, &new_context)?;

                if existing_opened.plaintext != opened.plaintext {
                    return Err(EnclaveError::Conflict(
                        "stable user object already exists with different content".into(),
                    ));
                }
            }
            Err(EnclaveError::NotFound) => {
                let new_context = crate::store::user_blob_context(new_user_id);
                let rebound = encrypt_bound_blob(&dek, &opened.plaintext, &new_context)?;
                self.gcs
                    .put_object(&new_object, &rebound, &old.wrapped_dek_b64, 0)
                    .await?;
            }
            Err(e) => return Err(e),
        }

        self.gcs.delete_object(&old_object).await?;
        Ok(())
    }

    // ── Configuration / JWT secrets ─────────────────────────────────────────────

    /// Load or generate the JWT signing secrets. Generates a random one on first boot
    /// and persists it in the control DB's `config` table.
    pub async fn get_or_generate_jwt_secrets(&self) -> Result<Vec<String>> {
        self.write(|conn| {
            let current: Option<String> = conn
                .query_row(
                    "SELECT value FROM config WHERE key = 'jwt_secret_current'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;

            let secrets = match current {
                Some(curr) => {
                    let mut list = vec![curr];
                    let prev: Option<String> = conn
                        .query_row(
                            "SELECT value FROM config WHERE key = 'jwt_secret_previous'",
                            [],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if let Some(p) = prev {
                        list.push(p);
                    }
                    list
                }
                None => {
                    let new_secret = super::tokens::random_token_hex();
                    conn.execute(
                        "INSERT INTO config (key, value) VALUES ('jwt_secret_current', ?1)",
                        [&new_secret],
                    )?;
                    vec![new_secret]
                }
            };
            Ok(secrets)
        })
        .await
    }

    /// Rotate the JWT signing secret: current moves to previous, and a new one is generated.
    #[allow(dead_code)]
    pub async fn rotate_jwt_secret(&self) -> Result<Vec<String>> {
        self.write(|conn| {
            let current: Option<String> = conn
                .query_row(
                    "SELECT value FROM config WHERE key = 'jwt_secret_current'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;

            let new_secret = super::tokens::random_token_hex();
            if let Some(curr) = current {
                conn.execute(
                    "INSERT OR REPLACE INTO config (key, value) VALUES ('jwt_secret_previous', ?1)",
                    [&curr],
                )?;
            }
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('jwt_secret_current', ?1)",
                [&new_secret],
            )?;

            let mut list = vec![new_secret];
            if let Some(curr) = conn
                .query_row(
                    "SELECT value FROM config WHERE key = 'jwt_secret_previous'",
                    [],
                    |r| r.get(0),
                )
                .optional()?
            {
                list.push(curr);
            }
            Ok(list)
        })
        .await
    }

    // ── Identity ────────────────────────────────────────────────────────────────

    /// Upsert a user by `google_sub`; returns id + email.
    pub async fn upsert_user(&self, google_sub: &str, email: &str) -> Result<User> {
        let google_sub = google_sub.to_string();
        let email = email.to_string();
        let stable_id = super::tokens::derive_stable_uuid(&google_sub);

        // 1. Check if the user already exists. A stable deletion tombstone is
        // authoritative: Google credentials must not recreate a deleted user.
        let existing = self
            .read({
                let google_sub = google_sub.clone();
                let stable_id = stable_id.clone();
                move |conn| {
                    if is_deleted_user_conn(conn, &stable_id)? {
                        return Err(EnclaveError::Auth("account deleted".into()));
                    }
                    let row = conn
                        .query_row(
                            "SELECT id, email, status FROM users WHERE google_sub = ?1",
                            [&google_sub],
                            |r| {
                                Ok((
                                    r.get::<_, String>(0)?,
                                    r.get::<_, String>(1)?,
                                    r.get::<_, String>(2)?,
                                ))
                            },
                        )
                        .optional()?;
                    match row {
                        Some((_, _, ref status)) if status != "active" => {
                            Err(EnclaveError::Auth("account inactive".into()))
                        }
                        Some((id, current_email, _)) => Ok(Some((id, current_email))),
                        None => Ok(None),
                    }
                }
            })
            .await?;

        // Google ID tokens authenticate every web/API request. Avoid rewriting
        // the encrypted control DB for the overwhelmingly common no-op case;
        // screenshot upload bursts otherwise exceed GCS's per-object write
        // rate and turn valid image requests into intermittent 500 responses.
        if let Some((existing_id, existing_email)) = existing.as_ref() {
            if existing_id == &stable_id && existing_email == &email {
                return Ok(User {
                    id: stable_id,
                    email,
                });
            }
        }

        // 2. If it has an old ID, authenticate and re-encrypt the GCS blob under
        // the stable object's context before updating the identity row.
        if let Some((old_id, _)) = existing.as_ref() {
            if old_id != &stable_id {
                info!(
                    old_id = %old_id,
                    stable_id = %stable_id,
                    "rebinding GCS index blob to stable ID"
                );
                match self.rebind_user_blob(old_id, &stable_id).await {
                    Ok(_) => {}
                    Err(EnclaveError::NotFound) => {
                        info!("no existing GCS index blob found, skipping GCS rename");
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // 3. Perform database transaction to insert or update user ID
        let existing_cloned = existing.clone();
        self.write(move |conn| {
            conn.execute("BEGIN TRANSACTION", [])?;
            let res = (|| -> Result<()> {
                if is_deleted_user_conn(conn, &stable_id)? {
                    return Err(EnclaveError::Auth("account deleted".into()));
                }
                if let Some((ref old_id, _)) = existing_cloned {
                    let status: Option<String> = conn
                        .query_row(
                            "SELECT status FROM users WHERE google_sub = ?1",
                            [&google_sub],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if status.as_deref() != Some("active") {
                        return Err(EnclaveError::Auth("account inactive".into()));
                    }
                    if old_id != &stable_id {
                        conn.execute(
                            "UPDATE users SET id = ?1, email = ?2 WHERE google_sub = ?3",
                            rusqlite::params![stable_id, email, google_sub],
                        )?;
                        conn.execute(
                            "UPDATE usage_daily SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE refresh_tokens SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE oauth_authorization_codes SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE oauth_consents SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE query_log SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE webhook_subscriptions SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE episode_email_preferences SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE auth_identities SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE apple_credentials SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                    } else {
                        conn.execute(
                            "UPDATE users SET email = ?1 WHERE google_sub = ?2",
                            rusqlite::params![email, google_sub],
                        )?;
                    }
                } else {
                    conn.execute(
                        "INSERT INTO users (id, google_sub, email) VALUES (?1, ?2, ?3)",
                        rusqlite::params![stable_id, google_sub, email],
                    )?;
                }
                conn.execute(
                    "INSERT INTO auth_identities (provider, subject, user_id, email) \\
                     VALUES ('google', ?1, ?2, ?3) \\
                     ON CONFLICT(provider, subject) DO UPDATE SET email = excluded.email, \\
                     last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                    rusqlite::params![google_sub, stable_id, email],
                )?;
                Ok(())
            })();

            if res.is_ok() {
                conn.execute("COMMIT", [])?;
            } else {
                let _ = conn.execute("ROLLBACK", []);
            }
            res?;

            Ok(User {
                id: stable_id,
                email,
            })
        })
        .await
    }

    /// Resolve a linked provider identity without creating or merging an
    /// account. Email equality is intentionally never an account-link signal.
    pub async fn identity_user(&self, provider: &str, subject: &str) -> Result<Option<User>> {
        let provider = provider.to_string();
        let subject = subject.to_string();
        self.read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT u.id, u.email FROM auth_identities i \\
                     JOIN users u ON u.id = i.user_id \\
                     WHERE i.provider = ?1 AND i.subject = ?2 AND u.status = 'active'",
                    rusqlite::params![provider, subject],
                    |row| {
                        Ok(User {
                            id: row.get(0)?,
                            email: row.get(1)?,
                        })
                    },
                )
                .optional()?)
        })
        .await
    }

    /// Create or resume an Apple-primary account and retain the refresh token
    /// that must be revoked before deletion.
    pub async fn upsert_apple_user(
        &self,
        subject: &str,
        email: &str,
        refresh_token: &str,
    ) -> Result<User> {
        let provider = "apple".to_string();
        let subject = subject.to_string();
        let email = email.to_lowercase();
        let refresh_token = refresh_token.to_string();
        let compatibility_anchor = format!("apple:{subject}");
        let stable_id = super::tokens::derive_provider_uuid(&provider, &subject);
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;
            if is_deleted_identity_conn(&tx, &provider, &subject)? || is_deleted_user_conn(&tx, &stable_id)? {
                tx.rollback()?;
                return Err(EnclaveError::Auth("account deleted".into()));
            }
            let existing: Option<(String, String, String)> = tx.query_row(
                "SELECT u.id, u.email, u.status FROM auth_identities i \\
                 JOIN users u ON u.id = i.user_id WHERE i.provider = ?1 AND i.subject = ?2",
                rusqlite::params![provider, subject],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;
            let (user_id, primary_email) = match existing {
                Some((user_id, primary_email, status)) if status == "active" => {
                    tx.execute(
                        "UPDATE auth_identities SET email = ?1, last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \\
                         WHERE provider = ?2 AND subject = ?3",
                        rusqlite::params![email, provider, subject],
                    )?;
                    let anchor: String = tx.query_row("SELECT google_sub FROM users WHERE id = ?1", [&user_id], |row| row.get(0))?;
                    if anchor == compatibility_anchor {
                        tx.execute("UPDATE users SET email = ?1 WHERE id = ?2", rusqlite::params![email, user_id])?;
                        (user_id, email.clone())
                    } else { (user_id, primary_email) }
                }
                Some(_) => {
                    tx.rollback()?;
                    return Err(EnclaveError::Auth("account inactive".into()));
                }
                None => {
                    let collision: Option<(String, String)> = tx.query_row(
                        "SELECT google_sub, status FROM users WHERE id = ?1", [&stable_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    ).optional()?;
                    match collision {
                        None => tx.execute(
                            "INSERT INTO users (id, google_sub, email) VALUES (?1, ?2, ?3)",
                            rusqlite::params![stable_id, compatibility_anchor, email],
                        )?,
                        Some((anchor, status)) if anchor == compatibility_anchor && status == "active" => 0,
                        Some(_) => {
                            tx.rollback()?;
                            return Err(EnclaveError::Conflict("provider identity collision".into()));
                        }
                    };
                    tx.execute(
                        "INSERT INTO auth_identities (provider, subject, user_id, email) VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![provider, subject, stable_id, email],
                    )?;
                    (stable_id, email.clone())
                }
            };
            tx.execute(
                "INSERT INTO apple_credentials (user_id, refresh_token, revoked_at) VALUES (?1, ?2, NULL) \\
                 ON CONFLICT(user_id) DO UPDATE SET refresh_token = excluded.refresh_token, \\
                 last_validated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), revoked_at = NULL",
                rusqlite::params![user_id, refresh_token],
            )?;
            tx.commit()?;
            Ok(User { id: user_id, email: primary_email })
        }).await
    }

    /// Explicitly link an Apple identity to an authenticated account; it is
    /// never moved from a different account.
    pub async fn link_apple_identity(
        &self,
        user_id: &str,
        subject: &str,
        email: &str,
        refresh_token: &str,
    ) -> Result<()> {
        let user_id = user_id.to_string();
        let subject = subject.to_string();
        let email = email.to_lowercase();
        let refresh_token = refresh_token.to_string();
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;
            if !is_active_user_conn(&tx, &user_id)? {
                tx.rollback()?;
                return Err(EnclaveError::Auth("account inactive".into()));
            }
            if is_deleted_identity_conn(&tx, "apple", &subject)? {
                tx.rollback()?;
                return Err(EnclaveError::Auth("identity deleted".into()));
            }
            let owner: Option<String> = tx.query_row(
                "SELECT user_id FROM auth_identities WHERE provider = 'apple' AND subject = ?1", [&subject], |row| row.get(0),
            ).optional()?;
            if owner.as_deref().is_some_and(|owner| owner != user_id) {
                tx.rollback()?;
                return Err(EnclaveError::Conflict("Apple identity is linked to another account".into()));
            }
            let other: Option<String> = tx.query_row(
                "SELECT subject FROM auth_identities WHERE provider = 'apple' AND user_id = ?1", [&user_id], |row| row.get(0),
            ).optional()?;
            if other.as_deref().is_some_and(|linked| linked != subject) {
                tx.rollback()?;
                return Err(EnclaveError::Conflict("account already has a different Apple identity".into()));
            }
            tx.execute(
                "INSERT INTO auth_identities (provider, subject, user_id, email) VALUES ('apple', ?1, ?2, ?3) \\
                 ON CONFLICT(provider, subject) DO UPDATE SET email = excluded.email, \\
                 last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                rusqlite::params![subject, user_id, email],
            )?;
            tx.execute(
                "INSERT INTO apple_credentials (user_id, refresh_token, revoked_at) VALUES (?1, ?2, NULL) \\
                 ON CONFLICT(user_id) DO UPDATE SET refresh_token = excluded.refresh_token, \\
                 last_validated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), revoked_at = NULL",
                rusqlite::params![user_id, refresh_token],
            )?;
            tx.commit()?;
            Ok(())
        }).await
    }

    pub async fn linked_providers(&self, user_id: &str) -> Result<Vec<String>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT provider FROM auth_identities WHERE user_id = ?1 ORDER BY provider",
            )?;
            let rows = statement.query_map([user_id], |row| row.get::<_, String>(0))?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        })
        .await
    }

    pub async fn apple_refresh_token(&self, user_id: &str) -> Result<Option<String>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            Ok(conn.query_row(
            "SELECT refresh_token FROM apple_credentials WHERE user_id = ?1 AND revoked_at IS NULL",
            [user_id], |row| row.get(0),
        ).optional()?)
        })
        .await
    }

    pub async fn mark_apple_credential_revoked(&self, user_id: &str) -> Result<()> {
        let user_id = user_id.to_string();
        self.write_if_changed(move |conn| {
            let changed = conn.execute(
                "UPDATE apple_credentials SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \\
                 WHERE user_id = ?1 AND revoked_at IS NULL",
                [user_id],
            )? > 0;
            Ok(((), changed))
        })
        .await
    }

    pub async fn user_email(&self, user_id: &str) -> Result<Option<String>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT email FROM users WHERE id = ?1 AND status = 'active'",
                    [&user_id],
                    |r| r.get(0),
                )
                .optional()?)
        })
        .await
    }

    pub async fn user_status(&self, user_id: &str) -> Result<Option<String>> {
        let user_id = user_id.to_string();
        self.read(move |conn| user_status_conn(conn, &user_id))
            .await
    }

    pub async fn account_deletion_operation(
        &self,
        user_id: &str,
    ) -> Result<Option<AccountDeletionOperation>> {
        let user_id = user_id.to_string();
        self.read(move |conn| account_deletion_operation_conn(conn, &user_id))
            .await
    }

    /// All user ids (for the summarizer sweep).
    pub async fn all_user_ids(&self) -> Result<Vec<String>> {
        self.read(|conn| {
            let mut stmt = conn.prepare("SELECT id FROM users WHERE status = 'active'")?;
            let ids = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .filter_map(|x| x.ok())
                .collect();
            Ok(ids)
        })
        .await
    }

    /// A bounded, oldest-attempt-first sweep of pending deletion operations for
    /// the serial reconciler. Returning ids is internal only; callers must not
    /// log them. Failed-retryable rows require explicit remediation first.
    pub async fn deleting_user_ids(&self, limit: usize) -> Result<Vec<String>> {
        let limit = i64::try_from(limit)
            .map_err(|_| EnclaveError::Store("account-deletion sweep limit is too large".into()))?;
        self.read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT users.id
                 FROM users
                 LEFT JOIN account_deletion_operations
                   ON account_deletion_operations.user_id = users.id
                 WHERE users.status = 'deleting'
                   AND COALESCE(account_deletion_operations.status, 'pending') = 'pending'
                 ORDER BY COALESCE(account_deletion_operations.updated_at, users.created_at), users.id
                 LIMIT ?1",
            )?;
            let ids = stmt
                .query_map([limit], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(ids)
        })
        .await
    }

    pub async fn summarized_until(&self, user_id: &str) -> Result<Option<String>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT summarized_until FROM users WHERE id = ?1",
                    [&user_id],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten())
        })
        .await
    }

    pub async fn set_summarized_until(&self, user_id: &str, iso: &str) -> Result<()> {
        let (user_id, iso) = (user_id.to_string(), iso.to_string());
        self.write(move |conn| {
            conn.execute(
                "UPDATE users SET summarized_until = ?1 WHERE id = ?2",
                rusqlite::params![iso, user_id],
            )?;
            Ok(())
        })
        .await
    }

    /// Fail closed before content deletion: mark the account as deleting and
    /// revoke every renewable/pending OAuth credential while creating one
    /// stable, opaque operation id in the same transaction.
    pub async fn begin_user_deletion(
        &self,
        user_id: &str,
    ) -> Result<Option<AccountDeletionOperation>> {
        let user_id = user_id.to_string();
        let proposed_operation_id = format!("del_{}", super::tokens::random_token_hex());
        self.write(move |conn| begin_user_deletion_conn(conn, &user_id, &proposed_operation_id))
            .await
    }

    /// Persist content-free pending/failed-retryable state before returning
    /// HTTP 202. Provider deadline metadata is cleared when the new reason has
    /// no current deadline, so polling never exposes stale retention data.
    pub async fn update_user_deletion_status(
        &self,
        user_id: &str,
        reason: &str,
        retry_after_seconds: Option<u64>,
        hard_delete_time: Option<&str>,
    ) -> Result<AccountDeletionOperation> {
        let user_id = user_id.to_string();
        let reason = reason.to_string();
        let hard_delete_time = hard_delete_time.map(str::to_string);
        self.write(move |conn| {
            update_user_deletion_status_conn(
                conn,
                &user_id,
                &reason,
                retry_after_seconds,
                hard_delete_time.as_deref(),
            )
        })
        .await
    }

    /// Finalize identity deletion only after the content store has completed.
    pub async fn finalize_user_deletion(&self, user_id: &str) -> Result<AccountDeletionOperation> {
        let user_id = user_id.to_string();
        self.write(move |conn| delete_user_identity_conn(conn, &user_id))
            .await
    }

    pub async fn list_webhook_subscriptions(
        &self,
        user_id: &str,
    ) -> Result<Vec<WebhookSubscription>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, name, endpoint_url, signing_secret, include_content, enabled, created_at
                 FROM webhook_subscriptions WHERE user_id = ?1 ORDER BY created_at, id",
            )?;
            let rows = stmt.query_map([&user_id], |r| {
                Ok(WebhookSubscription {
                    id: r.get(0)?,
                    user_id: user_id.clone(),
                    name: r.get(1)?,
                    endpoint_url: r.get(2)?,
                    signing_secret: r.get(3)?,
                    include_content: r.get::<_, i32>(4)? != 0,
                    enabled: r.get::<_, i32>(5)? != 0,
                    created_at: r.get(6)?,
                })
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into)
        })
        .await
    }

    pub async fn get_webhook_subscription(
        &self,
        user_id: &str,
        subscription_id: &str,
    ) -> Result<Option<WebhookSubscription>> {
        let user_id = user_id.to_string();
        let subscription_id = subscription_id.to_string();
        self.read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT name, endpoint_url, signing_secret, include_content, enabled, created_at
                     FROM webhook_subscriptions WHERE id = ?1 AND user_id = ?2",
                    rusqlite::params![subscription_id, user_id],
                    |r| {
                        Ok(WebhookSubscription {
                            id: subscription_id.clone(),
                            user_id: user_id.clone(),
                            name: r.get(0)?,
                            endpoint_url: r.get(1)?,
                            signing_secret: r.get(2)?,
                            include_content: r.get::<_, i32>(3)? != 0,
                            enabled: r.get::<_, i32>(4)? != 0,
                            created_at: r.get(5)?,
                        })
                    },
                )
                .optional()?)
        })
        .await
    }

    pub async fn create_webhook_subscription(
        &self,
        subscription: WebhookSubscription,
    ) -> Result<()> {
        self.write(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT count(*) FROM webhook_subscriptions WHERE user_id = ?1",
                [&subscription.user_id],
                |r| r.get(0),
            )?;
            if count >= 5 {
                return Err(EnclaveError::Conflict(
                    "at most five webhook destinations are allowed".into(),
                ));
            }
            conn.execute(
                "INSERT INTO webhook_subscriptions
                    (id, user_id, name, endpoint_url, signing_secret, include_content, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    subscription.id,
                    subscription.user_id,
                    subscription.name,
                    subscription.endpoint_url,
                    subscription.signing_secret,
                    if subscription.include_content { 1 } else { 0 },
                    if subscription.enabled { 1 } else { 0 },
                ],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn delete_webhook_subscription(
        &self,
        user_id: &str,
        subscription_id: &str,
    ) -> Result<bool> {
        let user_id = user_id.to_string();
        let subscription_id = subscription_id.to_string();
        self.write(move |conn| {
            Ok(conn.execute(
                "DELETE FROM webhook_subscriptions WHERE id = ?1 AND user_id = ?2",
                rusqlite::params![subscription_id, user_id],
            )? == 1)
        })
        .await
    }

    pub async fn disable_webhook_subscription(
        &self,
        user_id: &str,
        subscription_id: &str,
    ) -> Result<()> {
        let user_id = user_id.to_string();
        let subscription_id = subscription_id.to_string();
        self.write(move |conn| {
            conn.execute(
                "UPDATE webhook_subscriptions SET enabled = 0,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE id = ?1 AND user_id = ?2",
                rusqlite::params![subscription_id, user_id],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn get_email_preference(&self, user_id: &str) -> Result<EpisodeEmailPreference> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            let (email, status): (String, String) = conn
                .query_row(
                    "SELECT email, status FROM users WHERE id = ?1",
                    [&user_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or_else(|| EnclaveError::Auth("unknown user".into()))?;

            if status != "active" {
                return Err(EnclaveError::Auth("account inactive or deleting".into()));
            }

            let pref = conn
                .query_row(
                    "SELECT enabled, include_content, consented_at, updated_at \
                     FROM episode_email_preferences WHERE user_id = ?1",
                    [&user_id],
                    |r| {
                        let enabled_num: i64 = r.get(0)?;
                        let include_num: i64 = r.get(1)?;
                        Ok(EpisodeEmailPreference {
                            enabled: enabled_num != 0,
                            include_content: include_num != 0,
                            recipient_email: email.clone(),
                            consented_at: r.get(2)?,
                            updated_at: r.get(3)?,
                        })
                    },
                )
                .optional()?;

            Ok(pref.unwrap_or_else(|| EpisodeEmailPreference {
                enabled: false,
                include_content: false,
                recipient_email: email,
                consented_at: None,
                updated_at: isotime::format_epoch_millis(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64,
                ),
            }))
        })
        .await
    }

    pub async fn set_email_preference(
        &self,
        user_id: &str,
        enabled: bool,
        mut include_content: bool,
    ) -> Result<EpisodeEmailPreference> {
        let user_id = user_id.to_string();
        self.write(move |conn| {
            let (email, status): (String, String) = conn
                .query_row("SELECT email, status FROM users WHERE id = ?1", [&user_id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?
                .ok_or_else(|| EnclaveError::Auth("unknown user".into()))?;

            if status != "active" {
                return Err(EnclaveError::InvalidRequest(
                    "cannot update email preferences for inactive or deleting user".into(),
                ));
            }

            if !enabled {
                include_content = false;
            }

            let now = isotime::format_epoch_millis(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
            );

            let existing_consent: Option<Option<String>> = conn
                .query_row(
                    "SELECT consented_at FROM episode_email_preferences WHERE user_id = ?1",
                    [&user_id],
                    |r| r.get(0),
                )
                .optional()?;

            let consented_at = match (enabled, include_content) {
                (false, _) => None,
                (true, true) => {
                    if let Some(Some(prev)) = existing_consent {
                        Some(prev)
                    } else {
                        Some(now.clone())
                    }
                }
                (true, false) => existing_consent.flatten(),
            };

            conn.execute(
                "INSERT INTO episode_email_preferences (user_id, enabled, include_content, consented_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(user_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    include_content = excluded.include_content,
                    consented_at = excluded.consented_at,
                    updated_at = excluded.updated_at",
                rusqlite::params![
                    user_id,
                    if enabled { 1 } else { 0 },
                    if include_content { 1 } else { 0 },
                    consented_at,
                    now,
                ],
            )?;

            Ok(EpisodeEmailPreference {
                enabled,
                include_content,
                recipient_email: email,
                consented_at,
                updated_at: now,
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_ID: &str = "11111111-1111-4111-8111-111111111111";
    const GOOGLE_SUB: &str = "google-subject-123";
    const OPERATION_ID: &str =
        "del_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn account_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO users (id, google_sub, email) VALUES (?1, ?2, 'owner@example.com')",
            rusqlite::params![USER_ID, GOOGLE_SUB],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO usage_daily (user_id, day) VALUES (?1, '2026-07-21')",
            [USER_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_clients (client_id, redirect_uris) VALUES ('client', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at) \
             VALUES ('refresh', ?1, 'client', '2099-01-01T00:00:00.000Z')",
            [USER_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_authorization_codes (code_hash, user_id, client_id, expires_at) \
             VALUES ('code', ?1, 'client', '2099-01-01T00:00:00.000Z')",
            [USER_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_consents (consent_hash, user_id, client_id, redirect_uri, expires_at) \
             VALUES ('consent', ?1, 'client', 'https://client.example/cb', '2099-01-01T00:00:00.000Z')",
            [USER_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO query_log (user_id, source, query_text) VALUES (?1, 'mcp', 'private query')",
            [USER_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO webhook_subscriptions
             (id, user_id, name, endpoint_url, signing_secret, include_content)
             VALUES ('hook-1', ?1, 'Automation', 'https://example.com/hook', 'whsec_test', 1)",
            [USER_ID],
        )
        .unwrap();
        conn
    }

    #[test]
    fn unknown_users_are_not_active() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        assert!(!is_active_user_conn(&conn, "missing").unwrap());
    }

    #[test]
    fn control_schema_removes_legacy_gmail_credentials() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE user_gmail_configs (
                user_id TEXT PRIMARY KEY,
                refresh_token TEXT
             );
             INSERT INTO user_gmail_configs VALUES ('owner', 'secret');",
        )
        .unwrap();

        conn.execute_batch(SCHEMA).unwrap();

        let gmail_table: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'user_gmail_configs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let webhook_table: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'webhook_subscriptions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(gmail_table, 0);
        assert_eq!(webhook_table, 1);
    }

    #[test]
    fn deletion_is_fail_closed_then_finalized_with_tombstone() {
        let conn = account_conn();
        let first = begin_user_deletion_conn(&conn, USER_ID, OPERATION_ID)
            .unwrap()
            .unwrap();
        // Initialization is idempotent so a failed content deletion can retry.
        let retry = begin_user_deletion_conn(&conn, USER_ID, "del_different")
            .unwrap()
            .unwrap();
        assert_eq!(first.operation_id, OPERATION_ID);
        assert_eq!(retry.operation_id, OPERATION_ID);
        assert_eq!(
            conn.query_row("SELECT status FROM users WHERE id = ?1", [USER_ID], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
            "deleting"
        );
        for table in [
            "refresh_tokens",
            "oauth_authorization_codes",
            "oauth_consents",
        ] {
            let count: i64 = conn
                .query_row(
                    &format!("SELECT count(*) FROM {table} WHERE user_id = ?1"),
                    [USER_ID],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} was not revoked");
        }
        let webhook_enabled: i64 = conn
            .query_row(
                "SELECT enabled FROM webhook_subscriptions WHERE user_id = ?1",
                [USER_ID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(webhook_enabled, 0);

        let completed = delete_user_identity_conn(&conn, USER_ID).unwrap();
        assert_eq!(completed.status, "physical_complete");
        assert_eq!(completed.reason, "content_deleted");
        assert_eq!(completed.operation_id, OPERATION_ID);
        assert!(!is_active_user_conn(&conn, USER_ID).unwrap());
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM query_log WHERE user_id = ?1",
                [USER_ID],
                |r| { r.get::<_, i64>(0) }
            )
            .unwrap(),
            0
        );
        let stable_id = super::super::tokens::derive_stable_uuid(GOOGLE_SUB);
        assert!(is_deleted_user_conn(&conn, &stable_id).unwrap());
    }

    #[test]
    fn finalization_requires_the_deleting_state() {
        let conn = account_conn();
        assert!(matches!(
            delete_user_identity_conn(&conn, USER_ID),
            Err(EnclaveError::Conflict(_))
        ));
        assert!(is_active_user_conn(&conn, USER_ID).unwrap());
    }

    #[test]
    fn finalized_tombstone_keeps_deletion_retry_repairable() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let stable_id = super::super::tokens::derive_stable_uuid(GOOGLE_SUB);
        conn.execute(
            "INSERT INTO users (id, google_sub, email) VALUES (?1, ?2, 'owner@example.com')",
            rusqlite::params![stable_id, GOOGLE_SUB],
        )
        .unwrap();
        assert!(begin_user_deletion_conn(&conn, &stable_id, OPERATION_ID)
            .unwrap()
            .is_some());
        assert_eq!(
            delete_user_identity_conn(&conn, &stable_id).unwrap().status,
            "physical_complete"
        );

        // This is the in-memory state left behind if the final control-DB GCS
        // upload fails. Authentication, begin, and finalize must all allow the
        // next DELETE /api/account request to durably re-flush the tombstone.
        assert_eq!(
            user_status_conn(&conn, &stable_id).unwrap().as_deref(),
            Some("deleted")
        );
        let retry = begin_user_deletion_conn(&conn, &stable_id, "del_different")
            .unwrap()
            .unwrap();
        assert_eq!(retry.operation_id, OPERATION_ID);
        assert_eq!(retry.status, "physical_complete");
        assert_eq!(
            delete_user_identity_conn(&conn, &stable_id).unwrap().status,
            "physical_complete"
        );
    }

    #[test]
    fn deletion_status_metadata_is_current_and_queryable() {
        let conn = account_conn();
        begin_user_deletion_conn(&conn, USER_ID, OPERATION_ID)
            .unwrap()
            .unwrap();
        let pending = update_user_deletion_status_conn(
            &conn,
            USER_ID,
            "soft_delete_retention",
            Some(86_400),
            Some("2026-08-14T00:00:00.000Z"),
        )
        .unwrap();
        assert_eq!(pending.status, "pending");
        assert_eq!(pending.reason, "soft_delete_retention");
        assert_eq!(pending.retry_after_seconds, Some(86_400));
        assert_eq!(
            pending.hard_delete_time.as_deref(),
            Some("2026-08-14T00:00:00.000Z")
        );

        let later_transient = update_user_deletion_status_conn(
            &conn,
            USER_ID,
            "content_store_unavailable",
            Some(30),
            None,
        )
        .unwrap();
        assert_eq!(later_transient.reason, "content_store_unavailable");
        assert!(later_transient.hard_delete_time.is_none());
        assert_eq!(
            account_deletion_operation_conn(&conn, USER_ID).unwrap(),
            Some(later_transient)
        );

        for reason in ["legacy_generation_unavailable", "legacy_snapshot_too_large"] {
            let failed =
                update_user_deletion_status_conn(&conn, USER_ID, reason, None, None).unwrap();
            assert_eq!(failed.status, "failed_retryable");
            assert_eq!(failed.reason, reason);
            assert!(failed.retry_after_seconds.is_none());
            assert!(failed.hard_delete_time.is_none());
        }
    }

    #[tokio::test]
    async fn unchanged_user_upsert_does_not_rewrite_control_object() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = ControlStore::new(kms, gcs.clone());

        let first = store
            .upsert_user(GOOGLE_SUB, "owner@example.com")
            .await
            .unwrap();
        let first_generation = gcs.get_object(CONTROL_OBJECT).await.unwrap().generation;

        let second = store
            .upsert_user(GOOGLE_SUB, "owner@example.com")
            .await
            .unwrap();
        let second_generation = gcs.get_object(CONTROL_OBJECT).await.unwrap().generation;

        assert_eq!(first.id, second.id);
        assert_eq!(first_generation, second_generation);
    }

    #[test]
    fn sqlite_temp_cleanup_removes_main_wal_and_shm() {
        let path = std::env::temp_dir().join(format!(
            "kioku-control-cleanup-test-{}.db",
            super::super::tokens::random_token_hex()
        ));
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));
        for file in [&path, &wal, &shm] {
            std::fs::write(file, b"test").unwrap();
        }

        remove_sqlite_temp_files(&path);
        assert!(!path.exists());
        assert!(!wal.exists());
        assert!(!shm.exists());
    }

    #[tokio::test]
    async fn email_preference_lifecycle_and_deletion() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = ControlStore::new(kms, gcs);

        let user = store
            .upsert_user("google-sub-email-test", "user@example.com")
            .await
            .unwrap();

        // 1. Missing row is disabled by default
        let default_pref = store.get_email_preference(&user.id).await.unwrap();
        assert!(!default_pref.enabled);
        assert!(!default_pref.include_content);
        assert_eq!(default_pref.recipient_email, "user@example.com");
        assert!(default_pref.consented_at.is_none());

        // 2. Enable notification-only
        let notif_pref = store
            .set_email_preference(&user.id, true, false)
            .await
            .unwrap();
        assert!(notif_pref.enabled);
        assert!(!notif_pref.include_content);
        assert!(notif_pref.consented_at.is_none());

        // 3. Enable full content sets consent timestamp
        let full_pref = store
            .set_email_preference(&user.id, true, true)
            .await
            .unwrap();
        assert!(full_pref.enabled);
        assert!(full_pref.include_content);
        assert!(full_pref.consented_at.is_some());

        // 4. Disable clears include_content and consent
        let disabled_pref = store
            .set_email_preference(&user.id, false, true)
            .await
            .unwrap();
        assert!(!disabled_pref.enabled);
        assert!(!disabled_pref.include_content);
        assert!(disabled_pref.consented_at.is_none());

        // 5. Inactive / deleting user cannot be enabled
        store.begin_user_deletion(&user.id).await.unwrap();
        assert!(store
            .set_email_preference(&user.id, true, false)
            .await
            .is_err());

        let pref_during_deletion = store.get_email_preference(&user.id).await;
        assert!(pref_during_deletion.is_err());
    }
}
