//! Control-plane state store (ADR-0001): identity + accounting in an encrypted
//! SQLite blob in GCS, replacing the old Cloud SQL Postgres (`cloud/src/db.js`).
//!
//! Tables (ported from db.js): `users`, `usage_daily`, `oauth_clients`,
//! `refresh_tokens`, `query_log`. No user *content* — that stays in the per-user
//! index blobs ([`crate::store`]). One small control blob,
//! `control/control.db.enc`, encrypted under its own KMS-wrapped DEK exactly like
//! a user index, so identity state survives VM rolls without a managed database.
//!
//! Write volume here is tiny (sign-ins, token rotation, daily counters), so
//! whole-blob persist-on-write is fine — unlike user indexes (see ADR-0002).

use std::{
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension};
use tokio::sync::Mutex;
use tracing::info;

use crate::{
    crypto::{decrypt_blob, encrypt_blob, generate_and_wrap_dek, load_dek, KmsClient},
    error::{EnclaveError, Result},
    store::GcsClient,
};

const CONTROL_OBJECT: &str = "control/control.db.enc";

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
        let out = f(&guard.as_ref().unwrap().conn)?;
        self.flush(guard.as_mut().unwrap()).await?;
        Ok(out)
    }

    async fn load(&self) -> Result<Handle> {
        let (plaintext, meta) = match self.gcs.get_object(CONTROL_OBJECT).await {
            Ok(resp) => {
                let dek = load_dek(self.kms.as_ref(), &resp.wrapped_dek_b64).await?;
                let plaintext = decrypt_blob(&dek, &resp.ciphertext)?;
                (
                    plaintext,
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
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        if !plaintext.is_empty() {
            tokio::fs::write(&temp_path, &plaintext).await?;
        }
        let conn = Connection::open(&temp_path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Handle {
            conn,
            meta,
            temp_path,
        })
    }

    async fn flush(&self, handle: &mut Handle) -> Result<()> {
        handle
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let db_bytes = tokio::fs::read(&handle.temp_path).await?;
        let dek = load_dek(self.kms.as_ref(), &handle.meta.wrapped_dek_b64).await?;
        let ciphertext = encrypt_blob(&dek, &db_bytes)?;
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

        // 1. Check if user already exists
        let existing = self
            .read({
                let google_sub = google_sub.clone();
                move |conn| {
                    Ok(conn
                        .query_row(
                            "SELECT id FROM users WHERE google_sub = ?1",
                            [&google_sub],
                            |r| r.get::<_, String>(0),
                        )
                        .optional()?)
                }
            })
            .await?;

        // 2. If exists and has old ID, perform GCS rename before updating database
        if let Some(ref old_id) = existing {
            if old_id != &stable_id {
                let old_gcs = format!("indexes/{old_id}.db.enc");
                let new_gcs = format!("indexes/{stable_id}.db.enc");
                info!(
                    old_id = %old_id,
                    stable_id = %stable_id,
                    "renaming GCS index blob to stable ID"
                );
                match self.gcs.rename_object(&old_gcs, &new_gcs).await {
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
                if let Some(ref old_id) = existing_cloned {
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
                .query_row("SELECT email FROM users WHERE id = ?1", [&user_id], |r| {
                    r.get(0)
                })
                .optional()?)
        })
        .await
    }

    pub async fn user_status(&self, user_id: &str) -> Result<String> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            Ok(conn
                .query_row("SELECT status FROM users WHERE id = ?1", [&user_id], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?
                .unwrap_or_else(|| "active".to_string()))
        })
        .await
    }

    /// All user ids (for the summarizer sweep).
    pub async fn all_user_ids(&self) -> Result<Vec<String>> {
        self.read(|conn| {
            let mut stmt = conn.prepare("SELECT id FROM users")?;
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

    /// Delete a user's identity rows (content deletion is handled separately).
    pub async fn delete_user(&self, user_id: &str) -> Result<bool> {
        let user_id = user_id.to_string();
        self.write(move |conn| {
            conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?1", [&user_id])?;
            conn.execute("DELETE FROM usage_daily WHERE user_id = ?1", [&user_id])?;
            conn.execute(
                "DELETE FROM user_gmail_configs WHERE user_id = ?1",
                [&user_id],
            )?;
            let n = conn.execute("DELETE FROM users WHERE id = ?1", [&user_id])?;
            Ok(n > 0)
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
