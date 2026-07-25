//! Control-plane state store: identity and accounting in an encrypted SQLite
//! blob in GCS, replacing the legacy managed SQL store.
//!
//! Tables: `users`, `usage_daily`, `oauth_clients`,
//! `refresh_tokens`, `query_log`. No user *content* — that stays in the per-user
//! index blobs ([`crate::store`]). One small control blob,
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
CREATE TABLE IF NOT EXISTS usage_daily (
    user_id     TEXT NOT NULL,
    day         TEXT NOT NULL,
    utterances  INTEGER NOT NULL DEFAULT 0,
    screenshots INTEGER NOT NULL DEFAULT 0,
    mcp_calls   INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS user_gmail_configs (
    user_id            TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enabled            INTEGER NOT NULL DEFAULT 0,
    enabled_at         TEXT,
    gmail_email        TEXT,
    google_sub         TEXT,
    refresh_token      TEXT,
    reconnect_required INTEGER NOT NULL DEFAULT 0,
    updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GmailConfig {
    pub user_id: String,
    pub enabled: bool,
    pub enabled_at: Option<String>,
    pub gmail_email: Option<String>,
    pub google_sub: Option<String>,
    pub refresh_token: Option<String>,
    pub reconnect_required: bool,
}

#[cfg(test)]
fn is_active_user_conn(conn: &Connection, user_id: &str) -> Result<bool> {
    let active: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND status = 'active')",
        [user_id],
        |r| r.get(0),
    )?;
    Ok(active != 0)
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

/// Remove identity/accounting state and leave only a stable, non-content
/// tombstone. Returning Google credentials can then be denied instead of
/// recreating the just-deleted account.
fn delete_user_identity_conn(conn: &Connection, user_id: &str) -> Result<bool> {
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
        // uploading the encrypted control DB. Report the existing tombstone as
        // a successful finalization so write_if_changed re-flushes that state.
        let tombstoned: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM deleted_users WHERE user_id = ?1)",
            [user_id],
            |r| r.get(0),
        )?;
        tx.rollback()?;
        return Ok(tombstoned != 0);
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
        "DELETE FROM oauth_authorization_codes WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute("DELETE FROM oauth_consents WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM refresh_tokens WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM usage_daily WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM query_log WHERE user_id = ?1", [user_id])?;
    tx.execute(
        "DELETE FROM user_gmail_configs WHERE user_id = ?1",
        [user_id],
    )?;
    let deleted = tx.execute("DELETE FROM users WHERE id = ?1", [user_id])?;
    tx.commit()?;
    Ok(deleted == 1)
}

fn begin_user_deletion_conn(conn: &Connection, user_id: &str) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let status: Option<String> = tx
        .query_row("SELECT status FROM users WHERE id = ?1", [user_id], |r| {
            r.get(0)
        })
        .optional()?;
    if status.is_none() && is_deleted_user_conn(&tx, user_id)? {
        // Permit an idempotent retry after local finalization succeeded but its
        // encrypted GCS flush failed. The public wrapper flushes this state.
        tx.rollback()?;
        return Ok(true);
    }
    if !matches!(status.as_deref(), Some("active" | "deleting")) {
        tx.rollback()?;
        return Ok(false);
    }

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
        "UPDATE user_gmail_configs SET enabled = 0, refresh_token = NULL, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ?1",
        [user_id],
    )?;
    tx.commit()?;
    Ok(true)
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
        if redacted_queries > 0 {
            self.flush(&mut handle).await?;
            info!(
                rows = redacted_queries,
                "redacted legacy control-plane query text"
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
    /// revoke every renewable/pending OAuth credential in one transaction.
    pub async fn begin_user_deletion(&self, user_id: &str) -> Result<bool> {
        let user_id = user_id.to_string();
        self.write(move |conn| begin_user_deletion_conn(conn, &user_id))
            .await
    }

    /// Finalize identity deletion only after the content store has completed.
    pub async fn finalize_user_deletion(&self, user_id: &str) -> Result<bool> {
        let user_id = user_id.to_string();
        self.write_if_changed(move |conn| {
            let deleted = delete_user_identity_conn(conn, &user_id)?;
            Ok((deleted, deleted))
        })
        .await
    }

    pub async fn get_gmail_config(&self, user_id: &str) -> Result<Option<GmailConfig>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            let row = conn
                .query_row(
                    "SELECT enabled, enabled_at, gmail_email, google_sub, refresh_token, reconnect_required
                     FROM user_gmail_configs WHERE user_id = ?1",
                    [&user_id],
                    |r| {
                        Ok(GmailConfig {
                            user_id: user_id.clone(),
                            enabled: r.get::<_, i32>(0)? != 0,
                            enabled_at: r.get(1)?,
                            gmail_email: r.get(2)?,
                            google_sub: r.get(3)?,
                            refresh_token: r.get(4)?,
                            reconnect_required: r.get::<_, i32>(5)? != 0,
                        })
                    },
                )
                .optional()?;
            Ok(row)
        })
        .await
    }

    pub async fn upsert_gmail_config(&self, config: GmailConfig) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO user_gmail_configs (user_id, enabled, enabled_at, gmail_email, google_sub, refresh_token, reconnect_required)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(user_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    enabled_at = excluded.enabled_at,
                    gmail_email = excluded.gmail_email,
                    google_sub = excluded.google_sub,
                    refresh_token = excluded.refresh_token,
                    reconnect_required = excluded.reconnect_required,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                rusqlite::params![
                    config.user_id,
                    if config.enabled { 1 } else { 0 },
                    config.enabled_at,
                    config.gmail_email,
                    config.google_sub,
                    config.refresh_token,
                    if config.reconnect_required { 1 } else { 0 }
                ],
            )?;
            Ok(())
        })
        .await
    }

    #[allow(dead_code)]
    pub async fn disable_gmail_config(&self, user_id: &str) -> Result<()> {
        let user_id = user_id.to_string();
        self.write(move |conn| {
            conn.execute(
                "UPDATE user_gmail_configs SET
                    enabled = 0,
                    refresh_token = NULL,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE user_id = ?1",
                [&user_id],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_ID: &str = "11111111-1111-4111-8111-111111111111";
    const GOOGLE_SUB: &str = "google-subject-123";

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
            "INSERT INTO user_gmail_configs (user_id, enabled, refresh_token) VALUES (?1, 1, 'gmail-secret')",
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
    fn deletion_is_fail_closed_then_finalized_with_tombstone() {
        let conn = account_conn();
        assert!(begin_user_deletion_conn(&conn, USER_ID).unwrap());
        // Initialization is idempotent so a failed content deletion can retry.
        assert!(begin_user_deletion_conn(&conn, USER_ID).unwrap());
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
        let gmail: (i64, Option<String>) = conn
            .query_row(
                "SELECT enabled, refresh_token FROM user_gmail_configs WHERE user_id = ?1",
                [USER_ID],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(gmail, (0, None));

        assert!(delete_user_identity_conn(&conn, USER_ID).unwrap());
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
        assert!(begin_user_deletion_conn(&conn, &stable_id).unwrap());
        assert!(delete_user_identity_conn(&conn, &stable_id).unwrap());

        // This is the in-memory state left behind if the final control-DB GCS
        // upload fails. Authentication, begin, and finalize must all allow the
        // next DELETE /api/account request to durably re-flush the tombstone.
        assert_eq!(
            user_status_conn(&conn, &stable_id).unwrap().as_deref(),
            Some("deleted")
        );
        assert!(begin_user_deletion_conn(&conn, &stable_id).unwrap());
        assert!(delete_user_identity_conn(&conn, &stable_id).unwrap());
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
}
