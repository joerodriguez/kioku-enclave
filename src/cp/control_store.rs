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
const MAX_PENDING_RECORDING_LEASE_REQUESTS_PER_USER: i64 = 1;
const MAX_RECORDING_LEASE_DENIALS_PER_USER: i64 = 100;
const RECORDING_LEASE_DURATION_MS: i64 = 60_000;

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
    user_id           TEXT NOT NULL REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
    client_id         TEXT NOT NULL,
    refresh_token     TEXT NOT NULL,
    last_validated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    revoked_at        TEXT,
    PRIMARY KEY (user_id, client_id)
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
-- The external billing plane sees only this random pseudonym. Its mapping to
-- Google-derived identity remains inside the encrypted control database.
CREATE TABLE IF NOT EXISTS billing_accounts (
    user_id    TEXT PRIMARY KEY,
    account_id TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS billing_detach_outbox (
    account_id      TEXT PRIMARY KEY,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
-- Independent monotonic authority for the per-user Vertex producer-coverage
-- sequence. It lives outside the user index so a missing or restored old index
-- cannot silently reset coverage to a fresh, complete sequence 1.
CREATE TABLE IF NOT EXISTS vertex_coverage_anchors (
    user_id         TEXT NOT NULL,
    period          TEXT NOT NULL,
    sequence        INTEGER NOT NULL CHECK (sequence > 0),
    pending_events  INTEGER NOT NULL CHECK (pending_events >= 0),
    lost_events     INTEGER NOT NULL CHECK (lost_events >= 0),
    observed_at     TEXT NOT NULL,
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (user_id, period)
);
CREATE TABLE IF NOT EXISTS recording_leases (
    user_id    TEXT PRIMARY KEY,
    lease_id   TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS recording_lease_requests (
    user_id      TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    requested_lease_id TEXT,
    issued_lease_id TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('pending','granted','conflict')),
    summary_json  TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (user_id, request_id)
);
CREATE TABLE IF NOT EXISTS recording_lease_denials (
    user_id      TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    requested_lease_id TEXT,
    issued_lease_id TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    denial_code  TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (user_id, request_id)
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

fn migrate_apple_credentials_schema(conn: &Connection) -> Result<usize> {
    let mut migrations = 0;
    match conn.execute(
        "ALTER TABLE apple_credentials ADD COLUMN client_id TEXT NOT NULL DEFAULT 'com.kioku.ios'",
        [],
    ) {
        Ok(_) => migrations += 1,
        Err(error) if error.to_string().contains("duplicate column name") => {}
        Err(error) => return Err(error.into()),
    }
    let primary_key: Vec<String> = {
        let mut statement = conn.prepare("PRAGMA table_info(apple_credentials)")?;
        let columns = statement.query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
        })?;
        let mut primary = columns
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|(_, position)| *position > 0)
            .collect::<Vec<_>>();
        primary.sort_by_key(|(_, position)| *position);
        primary.into_iter().map(|(name, _)| name).collect()
    };
    if primary_key == ["user_id"] {
        conn.execute_batch(
            "ALTER TABLE apple_credentials RENAME TO apple_credentials_legacy;
             CREATE TABLE apple_credentials (
                user_id TEXT NOT NULL REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
                client_id TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                last_validated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                revoked_at TEXT,
                PRIMARY KEY (user_id, client_id)
             );
             INSERT INTO apple_credentials
                (user_id, client_id, refresh_token, last_validated_at, revoked_at)
             SELECT user_id, client_id, refresh_token, last_validated_at, revoked_at
             FROM apple_credentials_legacy;
             DROP TABLE apple_credentials_legacy;",
        )?;
        migrations += 1;
    }
    Ok(migrations)
}

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

#[derive(Debug, Clone, PartialEq)]
pub struct RecordingLeaseRequestRow {
    pub requested_lease_id: Option<String>,
    pub issued_lease_id: String,
    pub expires_at: String,
    pub state: String,
    pub summary: Option<serde_json::Value>,
    pub denial_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VertexCoverageAnchor {
    pub period: String,
    pub sequence: u64,
    pub pending_events: u64,
    pub lost_events: u64,
    pub observed_at: String,
}

fn valid_utc_month(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 7
        || bytes[4] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let month = (bytes[5] - b'0') * 10 + (bytes[6] - b'0');
    (1..=12).contains(&month)
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
        "INSERT OR IGNORE INTO deleted_identities (provider, subject) SELECT provider, subject FROM auth_identities WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute(
        "DELETE FROM oauth_authorization_codes WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute("DELETE FROM oauth_consents WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM refresh_tokens WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM usage_daily WHERE user_id = ?1", [user_id])?;
    tx.execute(
        "INSERT OR IGNORE INTO billing_detach_outbox (account_id)
         SELECT account_id FROM billing_accounts WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute("DELETE FROM billing_accounts WHERE user_id = ?1", [user_id])?;
    tx.execute(
        "DELETE FROM vertex_coverage_anchors WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute("DELETE FROM recording_leases WHERE user_id = ?1", [user_id])?;
    tx.execute(
        "DELETE FROM recording_lease_requests WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute(
        "DELETE FROM recording_lease_denials WHERE user_id = ?1",
        [user_id],
    )?;
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
        let mut schema_migrations = migrate_apple_credentials_schema(&conn)?;
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

        // The content buckets are versioned. An unqualified delete only hides
        // the live generation and leaves every prior encrypted index version
        // recoverable. Migration is a privacy boundary, so purge and verify
        // every exact generation of the pre-stable-id object.
        crate::store::delete_all_object_generations(self.gcs.as_ref(), &old_object).await?;
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
                            "UPDATE billing_accounts SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE recording_leases SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE recording_lease_requests SET user_id = ?1 WHERE user_id = ?2",
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
                            "UPDATE vertex_coverage_anchors SET user_id = ?1 WHERE user_id = ?2",
                            rusqlite::params![stable_id, old_id],
                        )?;
                        conn.execute(
                            "UPDATE recording_lease_denials SET user_id = ?1 WHERE user_id = ?2",
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
                    "INSERT INTO auth_identities (provider, subject, user_id, email) VALUES ('google', ?1, ?2, ?3) ON CONFLICT(provider, subject) DO UPDATE SET email = excluded.email, last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
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
                    "SELECT u.id, u.email FROM auth_identities i JOIN users u ON u.id = i.user_id WHERE i.provider = ?1 AND i.subject = ?2 AND u.status = 'active'",
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
        client_id: &str,
        refresh_token: &str,
    ) -> Result<User> {
        let provider = "apple".to_string();
        let subject = subject.to_string();
        let email = email.to_lowercase();
        let client_id = client_id.to_string();
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
                "SELECT u.id, u.email, u.status FROM auth_identities i JOIN users u ON u.id = i.user_id WHERE i.provider = ?1 AND i.subject = ?2",
                rusqlite::params![provider, subject],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;
            let (user_id, primary_email) = match existing {
                Some((user_id, primary_email, status)) if status == "active" => {
                    tx.execute(
                        "UPDATE auth_identities SET email = ?1, last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE provider = ?2 AND subject = ?3",
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
                "INSERT INTO apple_credentials (user_id, client_id, refresh_token, revoked_at) VALUES (?1, ?2, ?3, NULL) ON CONFLICT(user_id, client_id) DO UPDATE SET refresh_token = excluded.refresh_token, last_validated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), revoked_at = NULL",
                rusqlite::params![user_id, client_id, refresh_token],
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
        client_id: &str,
        refresh_token: &str,
    ) -> Result<()> {
        let user_id = user_id.to_string();
        let subject = subject.to_string();
        let email = email.to_lowercase();
        let client_id = client_id.to_string();
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
                "INSERT INTO auth_identities (provider, subject, user_id, email) VALUES ('apple', ?1, ?2, ?3) ON CONFLICT(provider, subject) DO UPDATE SET email = excluded.email, last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                rusqlite::params![subject, user_id, email],
            )?;
            tx.execute(
                "INSERT INTO apple_credentials (user_id, client_id, refresh_token, revoked_at) VALUES (?1, ?2, ?3, NULL) ON CONFLICT(user_id, client_id) DO UPDATE SET refresh_token = excluded.refresh_token, last_validated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), revoked_at = NULL",
                rusqlite::params![user_id, client_id, refresh_token],
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

    pub async fn apple_refresh_credentials(&self, user_id: &str) -> Result<Vec<(String, String)>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT client_id, refresh_token FROM apple_credentials
                 WHERE user_id = ?1 AND revoked_at IS NULL ORDER BY client_id",
            )?;
            let rows = statement.query_map([user_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        })
        .await
    }

    pub async fn mark_apple_credential_revoked(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<()> {
        let user_id = user_id.to_string();
        let client_id = client_id.to_string();
        self.write_if_changed(move |conn| {
            let changed = conn.execute(
                "UPDATE apple_credentials SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE user_id = ?1 AND client_id = ?2 AND revoked_at IS NULL",
                rusqlite::params![user_id, client_id],
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

    /// Resolve only the pseudonymous accounts present on one validated admin
    /// billing page. Missing, duplicate, or inactive mappings fail closed.
    pub async fn active_identities_for_billing_accounts(
        &self,
        account_ids: Vec<String>,
    ) -> Result<Vec<(String, String, String)>> {
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT u.id,u.email
                 FROM billing_accounts b JOIN users u ON u.id=b.user_id
                 WHERE b.account_id=?1 AND u.status='active'",
            )?;
            let mut identities = Vec::with_capacity(account_ids.len());
            for account_id in account_ids {
                let identity = statement
                    .query_row([&account_id], |row| Ok((row.get(0)?, row.get(1)?)))
                    .optional()?
                    .ok_or_else(|| {
                        EnclaveError::Config(
                            "billing margin row has no active enclave identity".into(),
                        )
                    })?;
                identities.push((identity.0, identity.1, account_id));
            }
            Ok(identities)
        })
        .await
    }

    /// Global coverage completeness comes from the control-plane high-water
    /// anchors, so an admin page never has to open every active user index.
    pub async fn active_vertex_coverage_complete(&self, period: &str) -> Result<bool> {
        let period = period.to_string();
        self.read(move |conn| {
            let incomplete: i64 = conn.query_row(
                "SELECT count(*)
                 FROM users u
                 LEFT JOIN vertex_coverage_anchors a
                   ON a.user_id=u.id AND a.period=?1
                 WHERE u.status='active'
                   AND (a.user_id IS NULL OR a.pending_events!=0 OR a.lost_events!=0)",
                [&period],
                |row| row.get(0),
            )?;
            Ok(incomplete == 0)
        })
        .await
    }

    pub async fn billing_account_id(&self, user_id: &str) -> Result<String> {
        let user_id = user_id.to_string();
        let new_account_id = format!("acct_{}", super::tokens::random_token_hex());
        self.write_if_changed(move |conn| {
            if user_status_conn(conn, &user_id)?.as_deref() != Some("active") {
                return Err(EnclaveError::Auth("account inactive".into()));
            }
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO billing_accounts (user_id,account_id) VALUES (?1,?2)",
                rusqlite::params![&user_id, &new_account_id],
            )?;
            let account_id = conn.query_row(
                "SELECT account_id FROM billing_accounts WHERE user_id=?1",
                [&user_id],
                |row| row.get(0),
            )?;
            Ok((account_id, inserted != 0))
        })
        .await
    }

    /// Return the durable billing pseudonym needed to settle usage before
    /// account content is destroyed. Active accounts may create the mapping;
    /// deletion retries may reuse an existing mapping while `deleting` but can
    /// never recreate one after deletion has started.
    pub async fn billing_account_id_for_deletion(&self, user_id: &str) -> Result<String> {
        let user_id = user_id.to_string();
        let new_account_id = format!("acct_{}", super::tokens::random_token_hex());
        self.write_if_changed(move |conn| {
            let status = user_status_conn(conn, &user_id)?;
            if status.as_deref() == Some("active") {
                let inserted = conn.execute(
                    "INSERT OR IGNORE INTO billing_accounts (user_id,account_id) VALUES (?1,?2)",
                    rusqlite::params![&user_id, &new_account_id],
                )?;
                let account_id = conn.query_row(
                    "SELECT account_id FROM billing_accounts WHERE user_id=?1",
                    [&user_id],
                    |row| row.get(0),
                )?;
                return Ok((account_id, inserted != 0));
            }
            if status.as_deref() == Some("deleting") {
                let account_id = conn
                    .query_row(
                        "SELECT account_id FROM billing_accounts WHERE user_id=?1",
                        [&user_id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or_else(|| {
                        EnclaveError::Conflict(
                            "deleting account has no durable billing mapping".into(),
                        )
                    })?;
                return Ok((account_id, false));
            }
            Err(EnclaveError::Auth("account inactive".into()))
        })
        .await
    }

    /// Reconcile a user-index coverage snapshot against the independent
    /// control-plane high-water mark. A rolled-back or replaced index can only
    /// move forward by emitting a new, explicitly incomplete snapshot.
    pub async fn reconcile_vertex_coverage(
        &self,
        user_id: &str,
        period: &str,
        sequence: u64,
        pending_events: u64,
        lost_events: u64,
        observed_at: &str,
    ) -> Result<VertexCoverageAnchor> {
        if !valid_utc_month(period) {
            return Err(EnclaveError::InvalidRequest(
                "Vertex coverage period must be YYYY-MM".into(),
            ));
        }
        let user_id = user_id.to_string();
        let period = period.to_string();
        let observed_at = observed_at.to_string();
        let sequence = i64::try_from(sequence)
            .map_err(|_| EnclaveError::Config("coverage sequence overflow".into()))?;
        let pending_events = i64::try_from(pending_events)
            .map_err(|_| EnclaveError::Config("coverage pending count overflow".into()))?;
        let lost_events = i64::try_from(lost_events)
            .map_err(|_| EnclaveError::Config("coverage lost count overflow".into()))?;
        self.write_if_changed(move |conn| {
            if !matches!(
                user_status_conn(conn, &user_id)?.as_deref(),
                Some("active" | "deleting")
            ) {
                return Err(EnclaveError::Auth("account inactive".into()));
            }
            let existing: Option<(i64, i64, i64, String)> = conn
                .query_row(
                    "SELECT sequence,pending_events,lost_events,observed_at
                     FROM vertex_coverage_anchors WHERE user_id=?1 AND period=?2",
                    rusqlite::params![user_id, period],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;

            let (chosen_sequence, chosen_pending, chosen_lost, chosen_observed, changed) =
                match existing {
                    None => (
                        sequence,
                        pending_events,
                        lost_events,
                        observed_at.clone(),
                        true,
                    ),
                    Some((current_sequence, _, current_lost, _)) if sequence > current_sequence => {
                        (
                            sequence,
                            pending_events,
                            current_lost.max(lost_events),
                            observed_at.clone(),
                            true,
                        )
                    }
                    Some((current_sequence, current_pending, current_lost, current_observed))
                        if sequence == current_sequence
                            && pending_events == current_pending
                            && lost_events == current_lost
                            && observed_at == current_observed =>
                    {
                        (
                            sequence,
                            pending_events,
                            lost_events,
                            observed_at.clone(),
                            false,
                        )
                    }
                    Some((current_sequence, _, current_lost, _)) => {
                        let next = current_sequence.checked_add(1).ok_or_else(|| {
                            EnclaveError::Config("coverage sequence overflow".into())
                        })?;
                        let now: String = conn.query_row(
                            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                            [],
                            |row| row.get(0),
                        )?;
                        (
                            next,
                            pending_events,
                            current_lost.max(lost_events).max(1),
                            now,
                            true,
                        )
                    }
                };

            if changed {
                conn.execute(
                    "INSERT INTO vertex_coverage_anchors
                     (user_id,period,sequence,pending_events,lost_events,observed_at)
                     VALUES (?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(user_id,period) DO UPDATE SET
                       sequence=excluded.sequence,
                       pending_events=excluded.pending_events,
                       lost_events=excluded.lost_events,
                       observed_at=excluded.observed_at,
                       updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                    rusqlite::params![
                        user_id,
                        period,
                        chosen_sequence,
                        chosen_pending,
                        chosen_lost,
                        chosen_observed
                    ],
                )?;
            }
            Ok((
                VertexCoverageAnchor {
                    period,
                    sequence: u64::try_from(chosen_sequence)
                        .map_err(|_| EnclaveError::Config("coverage sequence overflow".into()))?,
                    pending_events: u64::try_from(chosen_pending).map_err(|_| {
                        EnclaveError::Config("coverage pending count overflow".into())
                    })?,
                    lost_events: u64::try_from(chosen_lost)
                        .map_err(|_| EnclaveError::Config("coverage lost count overflow".into()))?,
                    observed_at: chosen_observed,
                },
                changed,
            ))
        })
        .await
    }

    pub async fn vertex_coverage_anchor(
        &self,
        user_id: &str,
        period: &str,
    ) -> Result<Option<VertexCoverageAnchor>> {
        if !valid_utc_month(period) {
            return Err(EnclaveError::InvalidRequest(
                "Vertex coverage period must be YYYY-MM".into(),
            ));
        }
        let user_id = user_id.to_string();
        let period = period.to_string();
        self.read(move |conn| {
            let row: Option<(i64, i64, i64, String)> = conn
                .query_row(
                    "SELECT sequence,pending_events,lost_events,observed_at
                     FROM vertex_coverage_anchors WHERE user_id=?1 AND period=?2",
                    rusqlite::params![user_id, period],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            row.map(|(sequence, pending_events, lost_events, observed_at)| {
                Ok(VertexCoverageAnchor {
                    period,
                    sequence: u64::try_from(sequence)
                        .map_err(|_| EnclaveError::Config("coverage sequence overflow".into()))?,
                    pending_events: u64::try_from(pending_events).map_err(|_| {
                        EnclaveError::Config("coverage pending count overflow".into())
                    })?,
                    lost_events: u64::try_from(lost_events)
                        .map_err(|_| EnclaveError::Config("coverage lost count overflow".into()))?,
                    observed_at,
                })
            })
            .transpose()
        })
        .await
    }

    pub async fn pending_billing_detach_ids(&self, limit: i64) -> Result<Vec<String>> {
        let limit = limit.clamp(1, 100);
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT account_id FROM billing_detach_outbox ORDER BY created_at LIMIT ?1",
            )?;
            let rows = statement.query_map([limit], |row| row.get(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into)
        })
        .await
    }

    pub async fn complete_billing_detach(&self, account_id: &str) -> Result<()> {
        let account_id = account_id.to_string();
        self.write_if_changed(move |conn| {
            let changed = conn.execute(
                "DELETE FROM billing_detach_outbox WHERE account_id=?1",
                [&account_id],
            )?;
            Ok(((), changed != 0))
        })
        .await
    }

    pub async fn record_billing_detach_failure(&self, account_id: &str) -> Result<()> {
        let account_id = account_id.to_string();
        self.write_if_changed(move |conn| {
            let changed = conn.execute(
                "UPDATE billing_detach_outbox SET attempts=attempts+1,
                 last_attempt_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE account_id=?1",
                [&account_id],
            )?;
            Ok(((), changed != 0))
        })
        .await
    }

    pub async fn recording_lease_receipt(
        &self,
        user_id: &str,
        request_id: &str,
    ) -> Result<Option<RecordingLeaseRequestRow>> {
        let user_id = user_id.to_string();
        let request_id = request_id.to_string();
        self.read(move |conn| {
            type StoredLeaseReceipt = (
                Option<String>,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
            );
            let mut row: Option<StoredLeaseReceipt> = conn
                .query_row(
                    "SELECT requested_lease_id,issued_lease_id,expires_at,state,summary_json
                     FROM recording_lease_requests WHERE user_id=?1 AND request_id=?2",
                    rusqlite::params![user_id, request_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            None,
                        ))
                    },
                )
                .optional()?;
            if row.is_none() {
                row = conn
                    .query_row(
                        "SELECT requested_lease_id,issued_lease_id,expires_at,
                                'denied',summary_json,denial_code
                         FROM recording_lease_denials WHERE user_id=?1 AND request_id=?2",
                        rusqlite::params![user_id, request_id],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                                row.get(5)?,
                            ))
                        },
                    )
                    .optional()?;
            }
            row.map(
                |(requested_lease_id, issued_lease_id, expires_at, state, summary, denial_code)| {
                    let summary = summary
                        .map(|summary| {
                            serde_json::from_str(&summary).map_err(|error| {
                                EnclaveError::Config(format!(
                                    "invalid stored billing summary: {error}"
                                ))
                            })
                        })
                        .transpose()?;
                    Ok(RecordingLeaseRequestRow {
                        requested_lease_id,
                        issued_lease_id,
                        expires_at,
                        state,
                        summary,
                        denial_code,
                    })
                },
            )
            .transpose()
        })
        .await
    }

    pub async fn active_recording_lease(&self, user_id: &str) -> Result<Option<(String, String)>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT lease_id,expires_at FROM recording_leases WHERE user_id=?1",
                    [user_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?)
        })
        .await
    }

    pub async fn begin_recording_lease_request(
        &self,
        user_id: &str,
        request_id: &str,
        requested_lease_id: Option<&str>,
        issued_lease_id: &str,
        expires_at: &str,
    ) -> Result<()> {
        let user_id = user_id.to_string();
        let request_id = request_id.to_string();
        let requested_lease_id = requested_lease_id.map(str::to_string);
        let issued_lease_id = issued_lease_id.to_string();
        let expires_at = expires_at.to_string();
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;
            // An unavailable upstream can leave an uncertain intent. Never
            // expire it locally: only retrying the same deterministic request
            // ID can prove whether billing charged it. A different request is
            // fail-closed until that reconciliation completes.
            let pending: i64 = tx.query_row(
                "SELECT count(*) FROM recording_lease_requests
                 WHERE user_id=?1 AND state='pending'",
                [&user_id],
                |row| row.get(0),
            )?;
            if pending >= MAX_PENDING_RECORDING_LEASE_REQUESTS_PER_USER {
                tx.rollback()?;
                return Err(EnclaveError::Conflict(
                    "too many pending recording lease requests".into(),
                ));
            }
            tx.execute(
                "INSERT INTO recording_lease_requests
                 (user_id,request_id,requested_lease_id,issued_lease_id,expires_at,state)
                 VALUES (?1,?2,?3,?4,?5,'pending')",
                rusqlite::params![
                    user_id,
                    request_id,
                    requested_lease_id,
                    issued_lease_id,
                    expires_at
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn deny_recording_lease_request(
        &self,
        user_id: &str,
        request_id: &str,
        denial_code: &str,
        summary: &serde_json::Value,
    ) -> Result<()> {
        let user_id = user_id.to_string();
        let request_id = request_id.to_string();
        let denial_code = denial_code.to_string();
        let summary = serde_json::to_string(summary)?;
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let pending: (Option<String>, String, String) = tx.query_row(
                "SELECT requested_lease_id,issued_lease_id,expires_at
                 FROM recording_lease_requests
                 WHERE user_id=?1 AND request_id=?2 AND state='pending'",
                rusqlite::params![user_id, request_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            tx.execute(
                "DELETE FROM recording_lease_requests
                 WHERE user_id=?1 AND request_id=?2 AND state='pending'",
                rusqlite::params![user_id, request_id],
            )?;
            tx.execute(
                "INSERT INTO recording_lease_denials
                 (user_id,request_id,requested_lease_id,issued_lease_id,expires_at,
                  denial_code,summary_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![
                    user_id,
                    request_id,
                    pending.0,
                    pending.1,
                    pending.2,
                    denial_code,
                    summary
                ],
            )?;
            tx.execute(
                "DELETE FROM recording_lease_denials
                 WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-7 days')",
                [],
            )?;
            tx.execute(
                "DELETE FROM recording_lease_denials
                 WHERE user_id=?1 AND request_id IN (
                   SELECT request_id FROM recording_lease_denials
                   WHERE user_id=?1 ORDER BY created_at DESC,rowid DESC
                   LIMIT -1 OFFSET ?2
                 )",
                rusqlite::params![user_id, MAX_RECORDING_LEASE_DENIALS_PER_USER],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn complete_recording_lease(
        &self,
        user_id: &str,
        request_id: &str,
        retry_now_ms: Option<i64>,
        summary: &serde_json::Value,
    ) -> Result<(String, String)> {
        let user_id = user_id.to_string();
        let request_id = request_id.to_string();
        let summary = serde_json::to_string(summary)?;
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let (lease_id, pending_expires_at): (String, String) = tx.query_row(
                "SELECT issued_lease_id,expires_at FROM recording_lease_requests
                 WHERE user_id=?1 AND request_id=?2 AND state='pending'",
                rusqlite::params![user_id, request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let pending_expires_ms = super::isotime::parse_epoch_millis(&pending_expires_at)
                .ok_or_else(|| {
                    EnclaveError::Config("invalid pending recording lease expiry".into())
                })?;
            let active: Option<(String, String)> = tx
                .query_row(
                    "SELECT lease_id,expires_at FROM recording_leases WHERE user_id=?1",
                    [&user_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let active_expires_ms = match active {
                Some((active_lease_id, _)) if active_lease_id != lease_id => {
                    return Err(EnclaveError::Conflict(
                        "a different recording lease became active".into(),
                    ));
                }
                Some((_, active_expires_at)) => Some(
                    super::isotime::parse_epoch_millis(&active_expires_at).ok_or_else(|| {
                        EnclaveError::Config("invalid active recording lease expiry".into())
                    })?,
                ),
                None => None,
            };
            let expires_ms = match retry_now_ms {
                Some(retry_now_ms) => retry_now_ms
                    .max(active_expires_ms.unwrap_or(i64::MIN))
                    .saturating_add(RECORDING_LEASE_DURATION_MS)
                    .max(pending_expires_ms),
                None => pending_expires_ms.max(active_expires_ms.unwrap_or(i64::MIN)),
            };
            let expires_at = super::isotime::format_epoch_millis(expires_ms);
            tx.execute(
                "UPDATE recording_lease_requests SET expires_at=?3
                 WHERE user_id=?1 AND request_id=?2 AND state='pending'",
                rusqlite::params![user_id, request_id, expires_at],
            )?;
            tx.execute(
                "INSERT INTO recording_leases (user_id,lease_id,expires_at)
                 VALUES (?1,?2,?3)
                 ON CONFLICT(user_id) DO UPDATE SET lease_id=excluded.lease_id,
                    expires_at=excluded.expires_at,
                    updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                rusqlite::params![user_id, lease_id, expires_at],
            )?;
            tx.execute(
                "UPDATE recording_lease_requests SET state='granted',summary_json=?3
                 WHERE user_id=?1 AND request_id=?2 AND state='pending'",
                rusqlite::params![user_id, request_id, summary],
            )?;
            tx.execute(
                "DELETE FROM recording_lease_requests
                 WHERE state!='pending'
                   AND created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','-7 days')",
                [],
            )?;
            tx.commit()?;
            Ok((lease_id, expires_at))
        })
        .await
    }

    pub async fn conflict_recording_lease_request(
        &self,
        user_id: &str,
        request_id: &str,
    ) -> Result<()> {
        let user_id = user_id.to_string();
        let request_id = request_id.to_string();
        self.write_if_changed(move |conn| {
            let changed = conn.execute(
                "UPDATE recording_lease_requests SET state='conflict'
                 WHERE user_id=?1 AND request_id=?2 AND state='pending'",
                rusqlite::params![user_id, request_id],
            )?;
            Ok(((), changed != 0))
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
        let mut guard = self.inner.lock().await;
        if guard.is_none() {
            *guard = Some(self.load().await?);
        }
        let operation = match delete_user_identity_conn(&guard.as_ref().unwrap().conn, user_id) {
            Ok(operation) => operation,
            Err(error) => {
                *guard = None;
                return Err(error);
            }
        };
        if let Err(error) = self.flush(guard.as_mut().unwrap()).await {
            *guard = None;
            return Err(error);
        }

        // The shared object is versioned. Keep the control-store mutex until
        // every older generation containing identity or billing mappings has
        // been deleted and the sanitized generation has been re-observed.
        let current_generation = guard
            .as_ref()
            .map(|handle| handle.meta.generation)
            .ok_or(EnclaveError::NotFound)?;
        crate::store::delete_object_generations_except(
            self.gcs.as_ref(),
            CONTROL_OBJECT,
            current_generation,
        )
        .await?;
        Ok(operation)
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
    use crate::store::{GcsGetResponse, GcsListVersionsResponse};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Notify;

    const USER_ID: &str = "11111111-1111-4111-8111-111111111111";
    const GOOGLE_SUB: &str = "google-subject-123";
    const OPERATION_ID: &str =
        "del_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct PausingGcs {
        inner: Arc<crate::store::tests::FakeGcs>,
        pause_next_control_list: AtomicBool,
        list_started: Notify,
        resume_list: Notify,
    }

    impl PausingGcs {
        fn new(inner: Arc<crate::store::tests::FakeGcs>) -> Self {
            Self {
                inner,
                pause_next_control_list: AtomicBool::new(false),
                list_started: Notify::new(),
                resume_list: Notify::new(),
            }
        }

        fn pause_next_control_list(&self) {
            self.pause_next_control_list.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl GcsClient for PausingGcs {
        async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse> {
            self.inner.get_object(object_name).await
        }

        async fn get_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> Result<GcsGetResponse> {
            self.inner
                .get_object_generation(object_name, generation)
                .await
        }

        async fn put_object(
            &self,
            object_name: &str,
            ciphertext: &[u8],
            wrapped_dek_b64: &str,
            if_generation_match: i64,
        ) -> Result<i64> {
            self.inner
                .put_object(
                    object_name,
                    ciphertext,
                    wrapped_dek_b64,
                    if_generation_match,
                )
                .await
        }

        async fn delete_object(&self, object_name: &str) -> Result<()> {
            self.inner.delete_object(object_name).await
        }

        async fn copy_generation_if_absent(
            &self,
            source_name: &str,
            source_generation: i64,
            destination_name: &str,
        ) -> Result<crate::store::GcsGenerationCopy> {
            self.inner
                .copy_generation_if_absent(source_name, source_generation, destination_name)
                .await
        }

        async fn list_object_versions(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> Result<GcsListVersionsResponse> {
            if prefix == CONTROL_OBJECT
                && self.pause_next_control_list.swap(false, Ordering::SeqCst)
            {
                self.list_started.notify_one();
                self.resume_list.notified().await;
            }
            self.inner.list_object_versions(prefix, page_token).await
        }

        async fn list_live_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> Result<GcsListVersionsResponse> {
            self.inner.list_live_objects(prefix, page_token).await
        }

        async fn delete_object_generation(&self, object_name: &str, generation: i64) -> Result<()> {
            self.inner
                .delete_object_generation(object_name, generation)
                .await
        }

        async fn list_soft_deleted_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> Result<GcsListVersionsResponse> {
            self.inner
                .list_soft_deleted_objects(prefix, page_token)
                .await
        }
    }

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
    fn apple_credentials_migrate_from_one_user_row_to_one_row_per_client() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE users (id TEXT PRIMARY KEY);
             INSERT INTO users VALUES ('user-1');
             CREATE TABLE apple_credentials (
                user_id TEXT PRIMARY KEY REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
                refresh_token TEXT NOT NULL,
                last_validated_at TEXT NOT NULL,
                revoked_at TEXT
             );
             INSERT INTO apple_credentials VALUES
                ('user-1', 'ios-refresh', '2026-08-10T00:00:00Z', NULL);",
        )
        .unwrap();

        assert_eq!(migrate_apple_credentials_schema(&conn).unwrap(), 2);
        conn.execute(
            "INSERT INTO apple_credentials
             (user_id, client_id, refresh_token, last_validated_at)
             VALUES ('user-1', 'com.kiokuu.app', 'mac-refresh', '2026-08-10T00:00:01Z')",
            [],
        )
        .unwrap();
        let rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM apple_credentials WHERE user_id = 'user-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let ios: String = conn
            .query_row(
                "SELECT refresh_token FROM apple_credentials
                 WHERE user_id = 'user-1' AND client_id = 'com.kioku.ios'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2);
        assert_eq!(ios, "ios-refresh");
        assert_eq!(migrate_apple_credentials_schema(&conn).unwrap(), 0);
    }

    #[test]
    fn deletion_is_fail_closed_then_finalized_with_tombstone() {
        let conn = account_conn();
        conn.execute(
            "INSERT INTO billing_accounts (user_id, account_id) VALUES (?1, 'acct_random')",
            [USER_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO recording_leases (user_id,lease_id,expires_at)
             VALUES (?1,'lease_random','2099-01-01T00:00:00.000Z')",
            [USER_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO recording_lease_requests
             (user_id,request_id,requested_lease_id,issued_lease_id,expires_at,state,summary_json)
             VALUES (?1,'request',NULL,'lease_random','2099-01-01T00:00:00.000Z','granted','{}')",
            [USER_ID],
        )
        .unwrap();
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
        for table in ["recording_leases", "recording_lease_requests"] {
            let count: i64 = conn
                .query_row(
                    &format!("SELECT count(*) FROM {table} WHERE user_id=?1"),
                    [USER_ID],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} survived deletion");
        }
        let stable_id = super::super::tokens::derive_stable_uuid(GOOGLE_SUB);
        assert!(is_deleted_user_conn(&conn, &stable_id).unwrap());
        assert_eq!(
            conn.query_row("SELECT account_id FROM billing_detach_outbox", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "acct_random"
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM billing_accounts WHERE user_id=?1",
                [USER_ID],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
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

    #[tokio::test]
    async fn stable_id_rebind_purges_every_legacy_index_generation() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let content = crate::store::Store::new(kms.clone(), gcs.clone());
        let legacy_user_id = "legacy-user-id";
        let stable_user_id = "11111111-1111-4111-8111-111111111111";

        content.with_user(legacy_user_id, |_| Ok(())).await.unwrap();
        content.save_user(legacy_user_id).await.unwrap();
        content
            .with_user(legacy_user_id, |conn| {
                conn.execute(
                    "INSERT INTO app_metadata (key,value) VALUES ('legacy','second')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        content.save_user(legacy_user_id).await.unwrap();
        let legacy_object = format!("indexes/{legacy_user_id}.db.enc");
        // Modern saves prune superseded generations. Inject one retained
        // historical generation to exercise the migration privacy boundary.
        let live = gcs.get_object(&legacy_object).await.unwrap();
        gcs.put_object(
            &legacy_object,
            &live.ciphertext,
            &live.wrapped_dek_b64,
            live.generation,
        )
        .await
        .unwrap();
        assert_eq!(gcs.exact_generation_count(&legacy_object), 2);

        let control = ControlStore::new(kms, gcs.clone());
        control
            .rebind_user_blob(legacy_user_id, stable_user_id)
            .await
            .unwrap();

        assert_eq!(gcs.exact_generation_count(&legacy_object), 0);
        assert_eq!(
            gcs.exact_generation_count(&format!("indexes/{stable_user_id}.db.enc")),
            1
        );
    }

    #[tokio::test]
    async fn account_finalization_purges_identity_from_older_control_generations() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let control = ControlStore::new(kms.clone(), gcs.clone());
        let user = control
            .upsert_user("privacy-purge-subject", "private@example.com")
            .await
            .unwrap();
        control.billing_account_id(&user.id).await.unwrap();
        control.begin_user_deletion(&user.id).await.unwrap();
        assert!(gcs.exact_generation_count(CONTROL_OBJECT) >= 3);

        assert_eq!(
            control
                .finalize_user_deletion(&user.id)
                .await
                .unwrap()
                .status,
            "physical_complete"
        );
        assert_eq!(gcs.exact_generation_count(CONTROL_OBJECT), 1);

        // A clean restart sees only the sanitized current generation.
        drop(control);
        let reloaded = ControlStore::new(kms, gcs);
        assert_eq!(
            reloaded.user_status(&user.id).await.unwrap().as_deref(),
            Some("deleted")
        );
    }

    #[tokio::test]
    async fn account_finalization_bounded_parallel_purge_handles_long_control_history() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let control = ControlStore::new(kms.clone(), gcs.clone());
        let user = control
            .upsert_user("long-control-history", "history@example.com")
            .await
            .unwrap();
        for index in 0..128 {
            control
                .set_summarized_until(
                    &user.id,
                    &format!("2026-08-09T12:{:02}:00.000Z", index % 60),
                )
                .await
                .unwrap();
        }
        control.begin_user_deletion(&user.id).await.unwrap();
        assert!(gcs.exact_generation_count(CONTROL_OBJECT) > 100);

        assert_eq!(
            control
                .finalize_user_deletion(&user.id)
                .await
                .unwrap()
                .status,
            "physical_complete"
        );
        assert_eq!(gcs.exact_generation_count(CONTROL_OBJECT), 1);
        assert_eq!(
            ControlStore::new(kms, gcs)
                .user_status(&user.id)
                .await
                .unwrap()
                .as_deref(),
            Some("deleted")
        );
    }

    #[tokio::test]
    async fn account_finalization_holds_control_writes_until_privacy_purge_finishes() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let backing = Arc::new(FakeGcs::new());
        let gcs = Arc::new(PausingGcs::new(backing.clone()));
        let control = Arc::new(ControlStore::new(kms.clone(), gcs.clone()));
        let user = control
            .upsert_user("privacy-race-subject", "private@example.com")
            .await
            .unwrap();
        control.billing_account_id(&user.id).await.unwrap();
        control.begin_user_deletion(&user.id).await.unwrap();

        gcs.pause_next_control_list();
        let deleting_control = Arc::clone(&control);
        let deleting_user = user.id.clone();
        let deletion = tokio::spawn(async move {
            deleting_control
                .finalize_user_deletion(&deleting_user)
                .await
        });
        gcs.list_started.notified().await;

        let writing_control = Arc::clone(&control);
        let concurrent_write = tokio::spawn(async move {
            writing_control
                .upsert_user("concurrent-subject", "other@example.com")
                .await
        });
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !concurrent_write.is_finished(),
            "a control write escaped while the privacy purge was paused"
        );

        gcs.resume_list.notify_one();
        assert_eq!(deletion.await.unwrap().unwrap().status, "physical_complete");
        let other = concurrent_write.await.unwrap().unwrap();

        // The purge leaves its sanitized generation, then the previously
        // blocked write adds one more. If the writer had escaped between the
        // flush and purge, its successful generation would have been deleted.
        assert_eq!(backing.exact_generation_count(CONTROL_OBJECT), 2);
        drop(control);
        let reloaded = ControlStore::new(kms, gcs);
        assert_eq!(
            reloaded.user_email(&other.id).await.unwrap().as_deref(),
            Some("other@example.com")
        );
        assert_eq!(
            reloaded.user_status(&user.id).await.unwrap().as_deref(),
            Some("deleted")
        );
    }

    #[tokio::test]
    async fn coverage_high_water_marks_a_rolled_back_user_index_incomplete() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let control = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let user = control
            .upsert_user("coverage-rollback-subject", "coverage@example.com")
            .await
            .unwrap();
        let established = control
            .reconcile_vertex_coverage(&user.id, "2026-08", 7, 0, 0, "2026-08-09T12:00:00.000Z")
            .await
            .unwrap();
        assert_eq!(established.sequence, 7);
        assert_eq!(established.lost_events, 0);

        let repaired = control
            .reconcile_vertex_coverage(&user.id, "2026-08", 1, 0, 0, "2026-08-09T11:00:00.000Z")
            .await
            .unwrap();
        assert_eq!(repaired.sequence, 8);
        assert_eq!(repaired.lost_events, 1);
        assert_eq!(
            control
                .vertex_coverage_anchor(&user.id, "2026-08")
                .await
                .unwrap(),
            Some(repaired)
        );

        let later = control
            .reconcile_vertex_coverage(&user.id, "2026-08", 9, 0, 0, "2026-08-09T13:00:00.000Z")
            .await
            .unwrap();
        assert_eq!(later.sequence, 9);
        assert_eq!(later.lost_events, 1);
    }

    #[tokio::test]
    async fn lease_intents_and_denial_receipts_are_bounded_per_user() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let control = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let first = control
            .upsert_user("lease-bound-first", "first@example.com")
            .await
            .unwrap();
        let second = control
            .upsert_user("lease-bound-second", "second@example.com")
            .await
            .unwrap();

        for index in 0..MAX_PENDING_RECORDING_LEASE_REQUESTS_PER_USER {
            control
                .begin_recording_lease_request(
                    &first.id,
                    &format!("pending-{index}"),
                    None,
                    &format!("lease_pending_{index}"),
                    "2099-01-01T00:01:00.000Z",
                )
                .await
                .unwrap();
        }
        assert!(matches!(
            control
                .begin_recording_lease_request(
                    &first.id,
                    "pending-over-cap",
                    None,
                    "lease_pending_over_cap",
                    "2099-01-01T00:01:00.000Z",
                )
                .await,
            Err(EnclaveError::Conflict(_))
        ));
        // One account at its cap cannot block an unrelated account.
        control
            .begin_recording_lease_request(
                &second.id,
                "other-user-pending",
                None,
                "lease_other_user",
                "2099-01-01T00:01:00.000Z",
            )
            .await
            .unwrap();
        control
            .deny_recording_lease_request(
                &second.id,
                "other-user-pending",
                "monthly_allowance_exhausted",
                &serde_json::json!({"recording":{"allowed":false}}),
            )
            .await
            .unwrap();

        for index in 0..(MAX_RECORDING_LEASE_DENIALS_PER_USER + 5) {
            let request_id = format!("denied-{index}");
            control
                .begin_recording_lease_request(
                    &second.id,
                    &request_id,
                    None,
                    &format!("lease_denied_{index}"),
                    "2099-01-01T00:01:00.000Z",
                )
                .await
                .unwrap();
            control
                .deny_recording_lease_request(
                    &second.id,
                    &request_id,
                    "monthly_allowance_exhausted",
                    &serde_json::json!({"recording":{"allowed":false}}),
                )
                .await
                .unwrap();
        }
        let second_id = second.id.clone();
        let denial_count: i64 = control
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT count(*) FROM recording_lease_denials WHERE user_id=?1",
                    [&second_id],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(denial_count, MAX_RECORDING_LEASE_DENIALS_PER_USER);
    }

    #[tokio::test]
    async fn pending_recording_lease_can_be_rebased_atomically_before_grant() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let control = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let user = control
            .upsert_user("lease-rebase-subject", "lease-rebase@example.com")
            .await
            .unwrap();
        let retry_now_ms =
            super::super::isotime::parse_epoch_millis("2026-08-09T00:00:00.000Z").unwrap();
        let user_id = user.id.clone();
        control
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO recording_leases (user_id,lease_id,expires_at)
                     VALUES (?1,'lease_rebase','2026-08-09T00:00:10.000Z')",
                    [&user_id],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        control
            .begin_recording_lease_request(
                &user.id,
                "request-rebase",
                Some("lease_rebase"),
                "lease_rebase",
                "2026-08-09T00:01:00.000Z",
            )
            .await
            .unwrap();

        let granted = control
            .complete_recording_lease(
                &user.id,
                "request-rebase",
                Some(retry_now_ms),
                &serde_json::json!({"recording":{"allowed":true}}),
            )
            .await
            .unwrap();
        assert_eq!(
            granted,
            ("lease_rebase".into(), "2026-08-09T00:01:10.000Z".into())
        );
        assert_eq!(
            control.active_recording_lease(&user.id).await.unwrap(),
            Some(granted)
        );
        let receipt = control
            .recording_lease_receipt(&user.id, "request-rebase")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, "granted");
        assert_eq!(receipt.expires_at, "2026-08-09T00:01:10.000Z");

        // Even a later duplicate receipt carrying an older proposed expiry
        // cannot move the active lease backwards.
        control
            .begin_recording_lease_request(
                &user.id,
                "request-monotonic",
                Some("lease_rebase"),
                "lease_rebase",
                "2026-08-09T00:00:20.000Z",
            )
            .await
            .unwrap();
        let monotonic = control
            .complete_recording_lease(
                &user.id,
                "request-monotonic",
                None,
                &serde_json::json!({"recording":{"allowed":true}}),
            )
            .await
            .unwrap();
        assert_eq!(monotonic.1, "2026-08-09T00:01:10.000Z");
    }

    #[tokio::test]
    async fn competing_pending_lease_ids_cannot_reach_or_overwrite_a_grant() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let control = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let user = control
            .upsert_user("lease-competing-subject", "lease-competing@example.com")
            .await
            .unwrap();
        control
            .begin_recording_lease_request(
                &user.id,
                "request-first",
                None,
                "lease_first",
                "2026-08-09T00:01:00.000Z",
            )
            .await
            .unwrap();
        let stale_user_id = user.id.clone();
        control
            .write(move |conn| {
                conn.execute(
                    "UPDATE recording_lease_requests
                     SET created_at='2000-01-01T00:00:00.000Z'
                     WHERE user_id=?1 AND request_id='request-first'",
                    [&stale_user_id],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            control
                .begin_recording_lease_request(
                    &user.id,
                    "request-second",
                    None,
                    "lease_second",
                    "2026-08-09T00:01:01.000Z",
                )
                .await,
            Err(EnclaveError::Conflict(_))
        ));

        // Defense in depth for pre-fix state: if another lease somehow became
        // active, completing the old pending intent must not overwrite it.
        let user_id = user.id.clone();
        control
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO recording_leases (user_id,lease_id,expires_at)
                     VALUES (?1,'lease_other','2026-08-09T00:02:00.000Z')",
                    [&user_id],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            control
                .complete_recording_lease(
                    &user.id,
                    "request-first",
                    None,
                    &serde_json::json!({"recording":{"allowed":true}}),
                )
                .await,
            Err(EnclaveError::Conflict(_))
        ));
        assert_eq!(
            control.active_recording_lease(&user.id).await.unwrap(),
            Some(("lease_other".into(), "2026-08-09T00:02:00.000Z".into()))
        );
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
