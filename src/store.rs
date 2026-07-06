//! Per-user encrypted SQLite index store.
//!
//! # Lifecycle
//!
//! 1. **load(user_id)** — fetch the user's encrypted blob from GCS (or create
//!    an empty one on first use), decrypt it to a temporary file, open rusqlite,
//!    run schema migrations, cache the handle.
//!
//! 2. Callers write rows via the open [`rusqlite::Connection`].
//!
//! 3. **save(user_id)** — WAL checkpoint → read temp file → AES-GCM encrypt →
//!    PUT back to GCS with `ifGenerationMatch` for optimistic concurrency.
//!
//! # Optimistic concurrency / conflict story
//!
//! GCS object versioning provides `generation` numbers.  On every PUT we pass
//! `ifGenerationMatch=<generation-we-read>`.  If another enclave instance wrote
//! between our read and write GCS returns 412 Precondition Failed, which we
//! surface as [`crate::error::EnclaveError::Conflict`].  The caller (handler)
//! should reload, re-apply changes, and retry.  In the current single-node MIG
//! topology conflicts are rare; this is future-proofing for horizontal scale-out.
//!
//! # LRU cache
//!
//! A simple `HashMap<UserId, UserHandle>` with last-used timestamps and a
//! configurable cap (`STORE_MAX_OPEN`, default 16).  On eviction the handle is
//! saved and closed.  All access is behind a `tokio::sync::Mutex` (coarse but
//! correct for the current single-node topology — revisit with per-user locks
//! if contention shows up).
//!
//! # user_id validation
//!
//! `user_id` is caller-supplied and is interpolated into both the temp-file
//! path and the GCS object name. [`validate_user_id`] restricts it to
//! `[A-Za-z0-9_-]{1,128}` so a hostile caller cannot use path metacharacters
//! (`../`, `/`, NUL, …) to steer the decrypted plaintext database to an
//! attacker-chosen filesystem path or GCS object. Handlers enforce this at
//! the API boundary (returning 400) and the store re-checks it before any
//! path is derived (defense in depth).

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Once},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{ffi::sqlite3_auto_extension, Connection};
use serde::Deserialize;
use sqlite_vec::sqlite3_vec_init;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::{
    crypto::{decrypt_blob, encrypt_blob, generate_and_wrap_dek, load_dek, Dek, KmsClient},
    error::{EnclaveError, Result},
};

// ── Types ─────────────────────────────────────────────────────────────────────

pub type UserId = String;

/// Maximum accepted `user_id` length. Real ids are UUIDs (36 chars); 128
/// leaves generous headroom without allowing pathological inputs.
pub const MAX_USER_ID_LEN: usize = 128;

/// Validate a caller-supplied `user_id` before it is used to derive any
/// filesystem path or GCS object name.
///
/// Accepts only `[A-Za-z0-9_-]{1,128}` (real ids are UUIDs, which pass).
/// Everything else — path separators, dots, whitespace, control characters,
/// non-ASCII — is rejected so the decrypted plaintext database can never be
/// written to a path the caller chose.
pub fn validate_user_id(user_id: &str) -> Result<()> {
    let ok = !user_id.is_empty()
        && user_id.len() <= MAX_USER_ID_LEN
        && user_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(EnclaveError::InvalidRequest(
            "invalid user_id: must match [A-Za-z0-9_-]{1,128}".into(),
        ))
    }
}

/// GCS blob metadata we need to track between load and save.
struct BlobMeta {
    /// GCS object `generation` at load time.  Used for `ifGenerationMatch`.
    /// `0` means "object must not exist yet" (first write for a new user).
    generation: i64,
    /// Base64-encoded wrapped DEK stored alongside the blob (in GCS metadata).
    wrapped_dek_b64: String,
}

struct UserHandle {
    /// The (validated) user id this handle belongs to. Stored directly so the
    /// GCS object name never has to be reconstructed from the temp-file path.
    user_id: UserId,
    conn: Connection,
    blob_meta: BlobMeta,
    temp_path: PathBuf,
    last_used: Instant,
}

/// The shared store, wrapped in Arc so handlers can clone it cheaply.
pub struct Store {
    inner: Mutex<StoreInner>,
    kms: Arc<dyn KmsClient>,
    gcs: Arc<dyn GcsClient>,
    max_open: usize,
}

struct StoreInner {
    handles: HashMap<UserId, UserHandle>,
}

impl Store {
    pub fn new(kms: Arc<dyn KmsClient>, gcs: Arc<dyn GcsClient>) -> Self {
        let max_open = std::env::var("STORE_MAX_OPEN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(16usize);
        Store {
            inner: Mutex::new(StoreInner {
                handles: HashMap::new(),
            }),
            kms,
            gcs,
            max_open,
        }
    }

    /// Run an operation with a user's open SQLite connection.
    /// Loads the user on first access; evicts LRU handle if over cap.
    pub async fn with_user<F, T>(&self, user_id: &str, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let mut inner = self.inner.lock().await;
        // Evict LRU if needed before potentially adding a new entry
        if !inner.handles.contains_key(user_id) && inner.handles.len() >= self.max_open {
            self.evict_lru_locked(&mut inner).await?;
        }
        if !inner.handles.contains_key(user_id) {
            let handle = self.load_user(user_id).await?;
            inner.handles.insert(user_id.to_string(), handle);
        }
        let handle = inner.handles.get_mut(user_id).unwrap();
        handle.last_used = Instant::now();
        f(&handle.conn)
    }

    /// Persist a user's index back to GCS.
    pub async fn save_user(&self, user_id: &str) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let handle = inner
            .handles
            .get_mut(user_id)
            .ok_or(EnclaveError::NotFound)?;
        self.flush_handle(handle).await
    }

    /// Hard-delete all user data: evict from cache and delete the GCS object.
    ///
    /// Idempotent: if the user was never seen (no cache entry, no GCS object)
    /// this returns `Ok(())`.
    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        validate_user_id(user_id)?;
        // 1. Evict the cached handle (and temp file) without flushing —
        //    we are deleting the data, not saving it.
        {
            let mut inner = self.inner.lock().await;
            if let Some(handle) = inner.handles.remove(user_id) {
                info!(user_id, "evicting user handle for deletion");
                // Best-effort cleanup of the temp file; ignore errors.
                let _ = std::fs::remove_file(&handle.temp_path);
                // Drop the Connection so the file is fully released.
                drop(handle);
            }
        }

        // 2. Delete the GCS object. 404 is treated as success by the GCS
        //    implementations, so this call is idempotent.
        let object_name = gcs_object_name(user_id);
        info!(user_id, object = %object_name, "deleting GCS object");
        self.gcs.delete_object(&object_name).await?;

        Ok(())
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    async fn load_user(&self, user_id: &str) -> Result<UserHandle> {
        // Defense in depth: handlers validate at the API boundary, but no
        // path or object name may ever be derived from an unvalidated id.
        validate_user_id(user_id)?;
        let object_name = gcs_object_name(user_id);

        // Try to fetch existing blob from GCS
        let fetch_result = self.gcs.get_object(&object_name).await;
        let (plaintext_db, blob_meta) = match fetch_result {
            Ok(resp) => {
                // Unwrap the DEK from KMS
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
                // New user — generate a fresh DEK and an empty database
                info!(user_id, "creating new user index");
                let (dek, wrapped) = generate_and_wrap_dek(self.kms.as_ref()).await?;
                let empty_db = create_empty_db(&dek)?;
                (
                    empty_db,
                    BlobMeta {
                        generation: 0,
                        wrapped_dek_b64: wrapped,
                    },
                )
            }
            Err(e) => return Err(e),
        };

        // Write plaintext to a temp file and open it with rusqlite
        let temp_path = temp_db_path(user_id);
        tokio::fs::write(&temp_path, &plaintext_db).await?;
        let conn = open_db(&temp_path)?;

        Ok(UserHandle {
            user_id: user_id.to_string(),
            conn,
            blob_meta,
            temp_path,
            last_used: Instant::now(),
        })
    }

    async fn flush_handle(&self, handle: &mut UserHandle) -> Result<()> {
        // WAL checkpoint: make sure all WAL pages are in the main DB file
        handle
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

        // Read the SQLite file from disk
        let db_bytes = tokio::fs::read(&handle.temp_path).await?;

        // Unwrap DEK from KMS then re-encrypt the DB file
        let dek = load_dek(
            // We call KMS here, but the lock is held — acceptable for now.
            // TODO: drop lock before KMS call in a future pass.
            self.kms.as_ref(),
            &handle.blob_meta.wrapped_dek_b64,
        )
        .await?;
        let ciphertext = encrypt_blob(&dek, &db_bytes)?;

        let object_name = gcs_object_name(&handle.user_id);
        let new_generation = self
            .gcs
            .put_object(
                &object_name,
                &ciphertext,
                &handle.blob_meta.wrapped_dek_b64,
                handle.blob_meta.generation,
            )
            .await?;
        // Invariant: record the post-write generation, or the NEXT save's
        // `ifGenerationMatch` conflicts against our own previous write.
        handle.blob_meta.generation = new_generation;

        debug!("flushed user index to GCS");
        Ok(())
    }

    async fn evict_lru_locked(&self, inner: &mut StoreInner) -> Result<()> {
        let oldest_id = inner
            .handles
            .iter()
            .min_by_key(|(_, h)| h.last_used)
            .map(|(id, _)| id.clone());

        if let Some(id) = oldest_id {
            if let Some(mut handle) = inner.handles.remove(&id) {
                warn!(evicted_user = %id, "LRU eviction");
                // Best-effort flush; log but don't propagate
                if let Err(e) = self.flush_handle(&mut handle).await {
                    tracing::error!(user_id = %id, error = %e, "eviction flush failed");
                }
                // Clean up temp file
                let _ = std::fs::remove_file(&handle.temp_path);
            }
        }
        Ok(())
    }
}

// ── sqlite-vec auto-extension registration ─────────────────────────────────────
//
// sqlite3_auto_extension registers the vec0 virtual-table module into every
// SQLite database connection opened after this call.  The Once guard ensures
// we only call it once per process — repeated calls are safe per sqlite3 docs
// but the Once makes the intent clear.
//
// SAFETY: sqlite3_vec_init matches the sqlite3_auto_extension function-pointer
// signature (sqlite3*, char**, sqlite3_api_routines*) → int.  The transmute is
// the standard pattern endorsed by the sqlite-vec crate itself (see its own
// test in src/lib.rs).  We call this exactly once before any Connection opens.

static VEC_EXT_ONCE: Once = Once::new();

pub(crate) fn init_vec_extension() {
    VEC_EXT_ONCE.call_once(|| {
        // SAFETY: sqlite3_vec_init matches the sqlite3_auto_extension callback
        // signature: (sqlite3*, char**, sqlite3_api_routines*) → int.
        // We use the same transmute pattern that the sqlite-vec crate uses in
        // its own test suite (src/lib.rs).  The allow-attribute suppresses the
        // clippy lint that requires explicit type annotations — the annotation
        // would require importing libsqlite3-sys types which are not exported by
        // rusqlite's public API.
        unsafe {
            #[allow(clippy::missing_transmute_annotations)]
            sqlite3_auto_extension(Some(std::mem::transmute(sqlite3_vec_init as *const ())));
        }
    });
}

// ── Schema ────────────────────────────────────────────────────────────────────

/// SQLite schema for the per-user encrypted index.
const SCHEMA_SQL: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Audio segments (carrier of utterances)
CREATE TABLE IF NOT EXISTS audio_segments (
    id                  INTEGER PRIMARY KEY,
    started_at          TEXT NOT NULL,
    ended_at            TEXT NOT NULL,
    duration_seconds    REAL NOT NULL,
    source_type         TEXT NOT NULL CHECK (source_type IN ('mic','system')),
    audio_format        TEXT NOT NULL DEFAULT 'm4a',
    file_size_bytes     INTEGER,
    speech_percentage   REAL,
    detected_language   TEXT,
    transcription_status TEXT NOT NULL DEFAULT 'pending',
    processing_error    TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Utterances / transcript segments
CREATE TABLE IF NOT EXISTS utterances (
    id                      INTEGER PRIMARY KEY,
    audio_segment_id        INTEGER NOT NULL REFERENCES audio_segments(id) ON DELETE CASCADE,
    start_offset_seconds    REAL NOT NULL,
    end_offset_seconds      REAL NOT NULL,
    text                    TEXT NOT NULL,
    language                TEXT,
    confidence              REAL,
    speaker_label           TEXT NOT NULL,
    source_key              TEXT,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- FTS5 index over utterance text
CREATE VIRTUAL TABLE IF NOT EXISTS utterances_fts
    USING fts5(text, content='utterances', content_rowid='id');

-- Screenshots + OCR text
CREATE TABLE IF NOT EXISTS screenshots (
    id           INTEGER PRIMARY KEY,
    captured_at  TEXT NOT NULL,
    active_app   TEXT,
    window_title TEXT,
    ocr_text     TEXT,
    url          TEXT,
    ocr_status   TEXT NOT NULL DEFAULT 'done',
    image_hash   TEXT,
    is_duplicate INTEGER NOT NULL DEFAULT 0,
    source_key   TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- FTS5 index over screenshot OCR text
CREATE VIRTUAL TABLE IF NOT EXISTS screenshots_fts
    USING fts5(ocr_text, content='screenshots', content_rowid='id');

-- Summarised episodes (v2). Identity is the autoincrement `id` (stable across
-- summariser runs, round-tripped by the control plane as episode_ref);
-- started_at / ended_at are DERIVED metadata (min/max of member timestamps) and
-- are NOT unique. Membership lives in episode_members. `id` stays INTEGER
-- because episodes_fts is an external-content FTS5 table keyed on its rowid.
CREATE TABLE IF NOT EXISTS episodes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    ended_at      TEXT NOT NULL,
    type          TEXT,
    title         TEXT,
    summary       TEXT,
    participants  TEXT,  -- JSON array of strings
    languages     TEXT,  -- JSON array of strings
    action_items  TEXT,  -- JSON array of strings
    model         TEXT,
    topics        TEXT,  -- JSON array (legacy)
    people        TEXT,  -- JSON array (legacy)
    -- Minute-timeline gists (ADR-0004): JSON array of {start, gist} buckets.
    -- MERGED on episode extension (union by bucket start), never replaced —
    -- see episodes.rs merge_minute_summaries.
    minute_summaries TEXT,
    -- Plain-text concatenation of the minute gists. episodes_fts is an
    -- external-content table, so the indexed text must be a real column of
    -- this table (rebuild reads it back); indexing the raw JSON would put
    -- "start"/"gist"/timestamps into the index.
    minutes_text  TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_episodes_started_at ON episodes(started_at);

-- Explicit episode membership (FK join). record_type ∈ {utterance, screenshot};
-- record_id references utterances(id) / screenshots(id). Enables both
-- "records of an episode" and the reverse "episode of a record" lookup, and
-- expresses nesting (the innermost episode claims a record).
CREATE TABLE IF NOT EXISTS episode_members (
    episode_id   INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
    record_type  TEXT NOT NULL CHECK (record_type IN ('utterance','screenshot')),
    record_id    INTEGER NOT NULL,
    PRIMARY KEY (episode_id, record_type, record_id)
);
CREATE INDEX IF NOT EXISTS idx_episode_members_record
    ON episode_members(record_type, record_id);

-- FTS5 over episode title + summary + minute-timeline gists
CREATE VIRTUAL TABLE IF NOT EXISTS episodes_fts
    USING fts5(title, summary, minutes_text, content='episodes', content_rowid='id');

-- Vector index for utterance embeddings (all-MiniLM-L6-v2, 384-dim, cosine).
-- Keyed by utterance rowid. Populated only when the ingest payload carries
-- an embedding_b64 field; rows without embeddings simply have no vec_utterances
-- entry — they are still found by FTS but not by vector KNN.
CREATE VIRTUAL TABLE IF NOT EXISTS vec_utterances USING vec0(
    utterance_id INTEGER PRIMARY KEY,
    embedding float[384] distance_metric=cosine
);

-- Vector index for screenshot OCR embeddings (same model/space as
-- vec_utterances — see src/embedding.rs MODEL_ID). Keyed by screenshot rowid.
-- The Mac embeds ocr_text capped at 10k chars (chunked + mean-pooled);
-- screenshots without OCR or embeddings simply have no row here.
CREATE VIRTUAL TABLE IF NOT EXISTS vec_screenshots USING vec0(
    screenshot_id INTEGER PRIMARY KEY,
    embedding float[384] distance_metric=cosine
);

-- Vector index for episode embeddings (ADR-0004 §G.2). Episodes are born in
-- the enclave (the Mac never sees them), so these vectors are computed
-- IN-enclave by the candle encoder at summarizer-upsert time — same pinned
-- MODEL_ID space as vec_utterances/vec_screenshots. Text = title + exec
-- summary + minute gists.
CREATE VIRTUAL TABLE IF NOT EXISTS vec_episodes USING vec0(
    episode_id INTEGER PRIMARY KEY,
    embedding float[384] distance_metric=cosine
);

-- FTS sync triggers: utterances. Like episodes_fts below, these are
-- EXTERNAL-CONTENT tables: delete/update must use the 'delete' command with
-- the OLD column values — by AFTER DELETE time the content row is gone and a
-- plain DELETE/UPDATE on the shadow can't recover the terms (index
-- corruption). Harmless historically (rows were never deleted); load-bearing
-- since episode purge (ADR-0004 follow-up) started deleting member rows.
CREATE TRIGGER IF NOT EXISTS utterances_insert_fts AFTER INSERT ON utterances BEGIN
    INSERT INTO utterances_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS utterances_delete_fts AFTER DELETE ON utterances BEGIN
    INSERT INTO utterances_fts(utterances_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TRIGGER IF NOT EXISTS utterances_update_fts AFTER UPDATE ON utterances BEGIN
    INSERT INTO utterances_fts(utterances_fts, rowid, text) VALUES ('delete', old.id, old.text);
    INSERT INTO utterances_fts(rowid, text) VALUES (new.id, new.text);
END;

-- FTS sync triggers: screenshots (same 'delete'-command requirement as above)
CREATE TRIGGER IF NOT EXISTS screenshots_insert_fts AFTER INSERT ON screenshots BEGIN
    INSERT INTO screenshots_fts(rowid, ocr_text) VALUES (new.id, new.ocr_text);
END;
CREATE TRIGGER IF NOT EXISTS screenshots_delete_fts AFTER DELETE ON screenshots BEGIN
    INSERT INTO screenshots_fts(screenshots_fts, rowid, ocr_text) VALUES ('delete', old.id, old.ocr_text);
END;
CREATE TRIGGER IF NOT EXISTS screenshots_update_fts AFTER UPDATE ON screenshots BEGIN
    INSERT INTO screenshots_fts(screenshots_fts, rowid, ocr_text) VALUES ('delete', old.id, old.ocr_text);
    INSERT INTO screenshots_fts(rowid, ocr_text) VALUES (new.id, new.ocr_text);
END;

-- FTS sync triggers: episodes. external-content FTS5 must be maintained with
-- the special 'delete' command (passing the OLD column values so the right
-- terms are removed) — a plain DELETE/UPDATE on the FTS shadow corrupts the
-- index ("database disk image is malformed") because FTS can't recover the old
-- terms once the content row has changed. The v2 id-keyed upsert UPDATEs rows
-- in place, so the update trigger MUST use this form.
CREATE TRIGGER IF NOT EXISTS episodes_insert_fts AFTER INSERT ON episodes BEGIN
    INSERT INTO episodes_fts(rowid, title, summary, minutes_text)
        VALUES (new.id, new.title, new.summary, new.minutes_text);
END;
CREATE TRIGGER IF NOT EXISTS episodes_delete_fts AFTER DELETE ON episodes BEGIN
    INSERT INTO episodes_fts(episodes_fts, rowid, title, summary, minutes_text)
        VALUES ('delete', old.id, old.title, old.summary, old.minutes_text);
END;
CREATE TRIGGER IF NOT EXISTS episodes_update_fts AFTER UPDATE ON episodes BEGIN
    INSERT INTO episodes_fts(episodes_fts, rowid, title, summary, minutes_text)
        VALUES ('delete', old.id, old.title, old.summary, old.minutes_text);
    INSERT INTO episodes_fts(rowid, title, summary, minutes_text)
        VALUES (new.id, new.title, new.summary, new.minutes_text);
END;
"#;

/// Schema-upgrade statements that are safe to replay on every open.
///
/// `ALTER TABLE … ADD COLUMN` returns `SQLITE_ERROR` ("duplicate column name")
/// if the column already exists; we swallow that specific error so existing
/// blobs created with the old schema self-upgrade transparently.
///
/// `CREATE UNIQUE INDEX IF NOT EXISTS` is truly idempotent.
fn run_migrations(conn: &Connection) -> Result<()> {
    // utterances.source_key (sync idempotency key)
    if let Err(e) = conn.execute_batch("ALTER TABLE utterances ADD COLUMN source_key TEXT;") {
        // SQLite returns "duplicate column name: source_key" — ignore it.
        let msg = e.to_string();
        if !msg.contains("duplicate column name") {
            return Err(e.into());
        }
    }
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_utterances_source_key
             ON utterances(source_key) WHERE source_key IS NOT NULL;",
    )?;

    // screenshots.source_key
    if let Err(e) = conn.execute_batch("ALTER TABLE screenshots ADD COLUMN source_key TEXT;") {
        let msg = e.to_string();
        if !msg.contains("duplicate column name") {
            return Err(e.into());
        }
    }
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_screenshots_source_key
             ON screenshots(source_key) WHERE source_key IS NOT NULL;",
    )?;

    // ── v2 episodes migration: id-keyed episodes + explicit membership ──────────
    //
    // v1 keyed episodes by `started_at` (UNIQUE) and had no membership. v2 makes
    // identity the autoincrement `id` and adds the `episode_members` join table.
    // We detect the v1 schema by the ABSENCE of the `updated_at` column (added in
    // v2): new blobs already have the v2 schema from SCHEMA_SQL and skip this
    // block; old blobs drop the v1 `episodes` (+ its FTS) and recreate. The v1
    // episode rows are intentionally discarded — the summariser backfills them
    // under v2 (utterances/screenshots are untouched).
    let episodes_is_v1: bool = {
        let has_updated_at: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('episodes') WHERE name = 'updated_at'",
            [],
            |r| r.get(0),
        )?;
        has_updated_at == 0
    };
    if episodes_is_v1 {
        conn.execute_batch(
            r#"
            DROP TRIGGER IF EXISTS episodes_insert_fts;
            DROP TRIGGER IF EXISTS episodes_delete_fts;
            DROP TRIGGER IF EXISTS episodes_update_fts;
            DROP TABLE IF EXISTS episodes_fts;
            DROP TABLE IF EXISTS episode_members;
            DROP TABLE IF EXISTS episodes;

            CREATE TABLE episodes (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at    TEXT NOT NULL,
                ended_at      TEXT NOT NULL,
                type          TEXT,
                title         TEXT,
                summary       TEXT,
                participants  TEXT,
                languages     TEXT,
                action_items  TEXT,
                model         TEXT,
                topics        TEXT,
                people        TEXT,
                created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                updated_at    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_episodes_started_at ON episodes(started_at);
            CREATE VIRTUAL TABLE episodes_fts
                USING fts5(title, summary, content='episodes', content_rowid='id');
            CREATE TRIGGER episodes_insert_fts AFTER INSERT ON episodes BEGIN
                INSERT INTO episodes_fts(rowid, title, summary) VALUES (new.id, new.title, new.summary);
            END;
            CREATE TRIGGER episodes_delete_fts AFTER DELETE ON episodes BEGIN
                INSERT INTO episodes_fts(episodes_fts, rowid, title, summary)
                    VALUES ('delete', old.id, old.title, old.summary);
            END;
            CREATE TRIGGER episodes_update_fts AFTER UPDATE ON episodes BEGIN
                INSERT INTO episodes_fts(episodes_fts, rowid, title, summary)
                    VALUES ('delete', old.id, old.title, old.summary);
                INSERT INTO episodes_fts(rowid, title, summary) VALUES (new.id, new.title, new.summary);
            END;

            CREATE TABLE episode_members (
                episode_id   INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
                record_type  TEXT NOT NULL CHECK (record_type IN ('utterance','screenshot')),
                record_id    INTEGER NOT NULL,
                PRIMARY KEY (episode_id, record_type, record_id)
            );
            CREATE INDEX IF NOT EXISTS idx_episode_members_record
                ON episode_members(record_type, record_id);
            "#,
        )?;
    }

    // New episodes columns added in this pass (type / participants / languages /
    // action_items / model).  Ignore "duplicate column name" as above.
    for col_def in &[
        "ALTER TABLE episodes ADD COLUMN type TEXT;",
        "ALTER TABLE episodes ADD COLUMN participants TEXT;",
        "ALTER TABLE episodes ADD COLUMN languages TEXT;",
        "ALTER TABLE episodes ADD COLUMN action_items TEXT;",
        "ALTER TABLE episodes ADD COLUMN model TEXT;",
        // ADR-0004: minute-timeline gists (JSON) + their plain-text projection
        // for FTS. Old rows keep NULL — the debugger derives gists client-side
        // for them and search simply doesn't index minutes on old rows.
        "ALTER TABLE episodes ADD COLUMN minute_summaries TEXT;",
        "ALTER TABLE episodes ADD COLUMN minutes_text TEXT;",
    ] {
        if let Err(e) = conn.execute_batch(col_def) {
            let msg = e.to_string();
            if !msg.contains("duplicate column name") {
                return Err(e.into());
            }
        }
    }

    // ── ADR-0004 §G.3: episodes_fts rebuild to index minutes_text ──────────────
    //
    // episodes_fts is an EXTERNAL-CONTENT FTS5 table: a new indexed column is a
    // rebuild migration, not a column add. Detected by the absence of the
    // minutes_text column in the FTS shadow schema. Steps: drop the old
    // triggers + table, recreate with the third column, re-point the triggers
    // (updates MUST use the 'delete' command — the repo's known footgun; a
    // plain DELETE/UPDATE on the shadow corrupts the index), then a full
    // 'rebuild' re-indexes existing rows from the content table.
    let fts_has_minutes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('episodes_fts') WHERE name = 'minutes_text'",
        [],
        |r| r.get(0),
    )?;
    if fts_has_minutes == 0 {
        conn.execute_batch(
            r#"
            DROP TRIGGER IF EXISTS episodes_insert_fts;
            DROP TRIGGER IF EXISTS episodes_delete_fts;
            DROP TRIGGER IF EXISTS episodes_update_fts;
            DROP TABLE IF EXISTS episodes_fts;
            CREATE VIRTUAL TABLE episodes_fts
                USING fts5(title, summary, minutes_text, content='episodes', content_rowid='id');
            CREATE TRIGGER episodes_insert_fts AFTER INSERT ON episodes BEGIN
                INSERT INTO episodes_fts(rowid, title, summary, minutes_text)
                    VALUES (new.id, new.title, new.summary, new.minutes_text);
            END;
            CREATE TRIGGER episodes_delete_fts AFTER DELETE ON episodes BEGIN
                INSERT INTO episodes_fts(episodes_fts, rowid, title, summary, minutes_text)
                    VALUES ('delete', old.id, old.title, old.summary, old.minutes_text);
            END;
            CREATE TRIGGER episodes_update_fts AFTER UPDATE ON episodes BEGIN
                INSERT INTO episodes_fts(episodes_fts, rowid, title, summary, minutes_text)
                    VALUES ('delete', old.id, old.title, old.summary, old.minutes_text);
                INSERT INTO episodes_fts(rowid, title, summary, minutes_text)
                    VALUES (new.id, new.title, new.summary, new.minutes_text);
            END;
            INSERT INTO episodes_fts(episodes_fts) VALUES ('rebuild');
            "#,
        )?;
    }

    // vec0 virtual table for utterance embeddings — added in this pass.
    // CREATE VIRTUAL TABLE IF NOT EXISTS is idempotent for blobs that already
    // have the table (from SCHEMA_SQL), and creates it for old blobs that were
    // written before this migration ran.
    //
    // Note: vec0 tables cannot be created inside a transaction on some sqlite-vec
    // versions; execute_batch uses implicit per-statement transactions so this is
    // safe. We swallow the "already exists" error (sqlite-vec may not honour IF
    // NOT EXISTS in all versions) while re-raising other errors.
    if let Err(e) = conn.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS vec_utterances USING vec0(
             utterance_id INTEGER PRIMARY KEY,
             embedding float[384] distance_metric=cosine
         );",
    ) {
        let msg = e.to_string();
        // sqlite-vec returns "table vec_utterances already exists" when the table
        // is already present, even with IF NOT EXISTS on some builds.
        if !msg.contains("already exists") {
            return Err(e.into());
        }
    }

    // vec0 table for screenshot OCR embeddings — added with hybrid screenshot
    // search. Same replay-safety notes as vec_utterances above.
    if let Err(e) = conn.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS vec_screenshots USING vec0(
             screenshot_id INTEGER PRIMARY KEY,
             embedding float[384] distance_metric=cosine
         );",
    ) {
        let msg = e.to_string();
        if !msg.contains("already exists") {
            return Err(e.into());
        }
    }

    // vec0 table for in-enclave episode embeddings (ADR-0004 §G.2). Same
    // replay-safety notes as vec_utterances above.
    if let Err(e) = conn.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS vec_episodes USING vec0(
             episode_id INTEGER PRIMARY KEY,
             embedding float[384] distance_metric=cosine
         );",
    ) {
        let msg = e.to_string();
        if !msg.contains("already exists") {
            return Err(e.into());
        }
    }

    // ── utterances/screenshots FTS trigger re-point (episode purge prereq) ────
    //
    // Old blobs carry delete/update triggers in the plain DELETE/UPDATE form,
    // which corrupts an external-content FTS5 index the first time a row is
    // actually deleted (the episodes footgun, present-but-dormant here since
    // day one). Detect the old form by the absence of the 'delete' command in
    // the trigger SQL and recreate. Trigger-only swap — the indexed content is
    // unchanged, so no rebuild is needed.
    let old_form: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' \
         AND name IN ('utterances_delete_fts','screenshots_delete_fts') \
         AND sql NOT LIKE '%''delete''%'",
        [],
        |r| r.get(0),
    )?;
    if old_form > 0 {
        conn.execute_batch(
            r#"
            DROP TRIGGER IF EXISTS utterances_delete_fts;
            DROP TRIGGER IF EXISTS utterances_update_fts;
            DROP TRIGGER IF EXISTS screenshots_delete_fts;
            DROP TRIGGER IF EXISTS screenshots_update_fts;
            CREATE TRIGGER utterances_delete_fts AFTER DELETE ON utterances BEGIN
                INSERT INTO utterances_fts(utterances_fts, rowid, text) VALUES ('delete', old.id, old.text);
            END;
            CREATE TRIGGER utterances_update_fts AFTER UPDATE ON utterances BEGIN
                INSERT INTO utterances_fts(utterances_fts, rowid, text) VALUES ('delete', old.id, old.text);
                INSERT INTO utterances_fts(rowid, text) VALUES (new.id, new.text);
            END;
            CREATE TRIGGER screenshots_delete_fts AFTER DELETE ON screenshots BEGIN
                INSERT INTO screenshots_fts(screenshots_fts, rowid, ocr_text) VALUES ('delete', old.id, old.ocr_text);
            END;
            CREATE TRIGGER screenshots_update_fts AFTER UPDATE ON screenshots BEGIN
                INSERT INTO screenshots_fts(screenshots_fts, rowid, ocr_text) VALUES ('delete', old.id, old.ocr_text);
                INSERT INTO screenshots_fts(rowid, ocr_text) VALUES (new.id, new.ocr_text);
            END;
            "#,
        )?;
    }

    Ok(())
}

fn open_db(path: &PathBuf) -> Result<Connection> {
    // Register the sqlite-vec extension globally before any connection opens.
    // This is idempotent (Once guard) and thread-safe.
    init_vec_extension();
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA_SQL)?;
    run_migrations(&conn)?;
    Ok(conn)
}

/// Build a fresh empty SQLite database in memory, serialize it, encrypt it,
/// and return the plaintext bytes (the caller will write them to disk).
fn create_empty_db(dek: &Dek) -> Result<Vec<u8>> {
    // Use a named temp path so rusqlite can flush WAL
    let tmp = tempfile::NamedTempFile::new().map_err(EnclaveError::Io)?;
    let path = tmp.path().to_path_buf();
    init_vec_extension();
    let conn = Connection::open(&path)?;
    conn.execute_batch(SCHEMA_SQL)?;
    run_migrations(&conn)?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(conn); // close before reading
    let bytes = std::fs::read(&path)?;
    // Encrypt the empty DB to prove the DEK works, then return plaintext
    // (the caller will re-encrypt when saving — here we just want the raw bytes)
    let _ = encrypt_blob(dek, &bytes)?; // smoke-test the key
    Ok(bytes)
}

// ── GCS trait (seam for testing) ──────────────────────────────────────────────

#[derive(Debug)]
pub struct GcsGetResponse {
    pub ciphertext: Vec<u8>,
    pub wrapped_dek_b64: String,
    pub generation: i64,
}

/// Abstraction over GCS so unit tests can inject an in-memory fake.
#[async_trait::async_trait]
pub trait GcsClient: Send + Sync {
    async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse>;
    /// Returns the object's NEW generation on success. Callers must record it
    /// for the next `if_generation_match` — forgetting to do so makes every
    /// save after the first 409 against the caller's own previous write.
    async fn put_object(
        &self,
        object_name: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
        if_generation_match: i64,
    ) -> Result<i64>;
    async fn delete_object(&self, object_name: &str) -> Result<()>;
    async fn rename_object(&self, source_object: &str, dest_object: &str) -> Result<()>;
}

// ── Production GCS client ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GcsObjectMetadata {
    generation: String,
    metadata: Option<GcsCustomMetadata>,
}

#[derive(Deserialize)]
struct GcsCustomMetadata {
    #[serde(rename = "x-kioku-wrapped-dek")]
    wrapped_dek: Option<String>,
}

pub struct GcpGcsClient {
    http: reqwest::Client,
    bucket: String,
}

impl GcpGcsClient {
    pub fn from_env() -> Result<Self> {
        let bucket = std::env::var("GCS_BUCKET")
            .map_err(|_| EnclaveError::Gcs("GCS_BUCKET not set".into()))?;
        Ok(Self {
            http: reqwest::Client::new(),
            bucket,
        })
    }

    async fn access_token(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct Tok {
            access_token: String,
        }
        let tok: Tok = self
            .http
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(tok.access_token)
    }
}

#[async_trait::async_trait]
impl GcsClient for GcpGcsClient {
    async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse> {
        let token = self.access_token().await?;
        let encoded = urlencoding::encode(object_name);

        // Fetch metadata to get generation and wrapped DEK
        let meta_url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}",
            self.bucket, encoded
        );
        let meta_resp = self.http.get(&meta_url).bearer_auth(&token).send().await?;

        if meta_resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(EnclaveError::NotFound);
        }
        let meta: GcsObjectMetadata = meta_resp.error_for_status()?.json().await?;
        let generation: i64 = meta
            .generation
            .parse()
            .map_err(|_| EnclaveError::Gcs("invalid generation".into()))?;
        let wrapped_dek_b64 = meta
            .metadata
            .and_then(|m| m.wrapped_dek)
            .ok_or_else(|| EnclaveError::Gcs("missing wrapped DEK in object metadata".into()))?;

        // Fetch body (media download)
        let data_url = format!(
            "https://storage.googleapis.com/download/storage/v1/b/{}/o/{}?alt=media",
            self.bucket, encoded
        );
        let bytes = self
            .http
            .get(&data_url)
            .bearer_auth(&token)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;

        Ok(GcsGetResponse {
            ciphertext: bytes.to_vec(),
            wrapped_dek_b64,
            generation,
        })
    }

    async fn put_object(
        &self,
        object_name: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
        if_generation_match: i64,
    ) -> Result<i64> {
        let token = self.access_token().await?;
        let encoded = urlencoding::encode(object_name);

        // Multipart upload with metadata
        let upload_url = format!(
            "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=multipart&name={}&ifGenerationMatch={}",
            self.bucket, encoded, if_generation_match
        );

        // Build multipart body (metadata JSON + binary data)
        let metadata_json = serde_json::json!({
            "metadata": {
                "x-kioku-wrapped-dek": wrapped_dek_b64
            }
        })
        .to_string();

        let boundary = format!(
            "kioku-boundary-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let mut body = Vec::new();
        // Metadata part
        body.extend_from_slice(
            format!(
                "--{}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{}\r\n",
                boundary, metadata_json
            )
            .as_bytes(),
        );
        // Data part
        body.extend_from_slice(
            format!(
                "--{}\r\nContent-Type: application/octet-stream\r\n\r\n",
                boundary
            )
            .as_bytes(),
        );
        body.extend_from_slice(ciphertext);
        body.extend_from_slice(format!("\r\n--{}--", boundary).as_bytes());

        let resp = self
            .http
            .post(&upload_url)
            .bearer_auth(&token)
            .header(
                "Content-Type",
                format!("multipart/related; boundary={}", boundary),
            )
            .body(body)
            .send()
            .await?;

        if resp.status() == reqwest::StatusCode::PRECONDITION_FAILED {
            return Err(EnclaveError::Conflict(
                "GCS generation mismatch — concurrent write detected; reload and retry".into(),
            ));
        }
        let resp = resp.error_for_status()?;
        // The upload response carries the object's new generation (as a JSON
        // string) — return it so the caller can match against it next save.
        let meta: GcsObjectMetadata = resp.json().await?;
        let new_gen = meta
            .generation
            .parse::<i64>()
            .map_err(|e| EnclaveError::Gcs(format!("bad generation in PUT response: {e}")))?;
        Ok(new_gen)
    }

    async fn delete_object(&self, object_name: &str) -> Result<()> {
        let token = self.access_token().await?;
        let encoded = urlencoding::encode(object_name);
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}",
            self.bucket, encoded
        );
        let resp = self.http.delete(&url).bearer_auth(&token).send().await?;
        // 404 means already gone — treat as success for idempotency.
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        resp.error_for_status()?;
        Ok(())
    }

    async fn rename_object(&self, source_object: &str, dest_object: &str) -> Result<()> {
        let token = self.access_token().await?;
        let src_encoded = urlencoding::encode(source_object);
        let dest_encoded = urlencoding::encode(dest_object);

        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}/copyTo/b/{}/o/{}",
            self.bucket, src_encoded, self.bucket, dest_encoded
        );

        // copyTo is a bodiless POST: without an explicit empty body, GCS
        // rejects the request with 411 Length Required (observed live 2026-07-05
        // — it broke every sign-in via the stable-id migration path).
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&token)
            .header(reqwest::header::CONTENT_LENGTH, 0)
            .body(Vec::new())
            .send()
            .await?;

        // Callers treat a missing source as "nothing to rename" (idempotent
        // migration), so surface 404 as NotFound rather than a generic error.
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(EnclaveError::NotFound);
        }
        resp.error_for_status()?;

        // Copy succeeded; now delete source
        self.delete_object(source_object).await?;
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn gcs_object_name(user_id: &str) -> String {
    format!("indexes/{user_id}.db.enc")
}

/// Build the temp-file path for a user's decrypted database.
/// Callers must have validated `user_id` first (see [`validate_user_id`]).
fn temp_db_path(user_id: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("kioku-{user_id}-{nanos}.db"))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::sync::Mutex as StdMutex;

    // ── v1 → v2 episodes migration ────────────────────────────────────────────

    /// A blob created under the v1 schema (started_at UNIQUE, no updated_at, no
    /// episode_members) must self-upgrade to v2 on first open, discarding the v1
    /// episode rows (the summariser backfills them) and gaining membership.
    #[test]
    fn v1_episodes_blob_migrates_to_v2() {
        init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        // Minimal v1 schema covering only what run_migrations touches.
        conn.execute_batch(
            r#"
            CREATE TABLE audio_segments (id INTEGER PRIMARY KEY, started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL, duration_seconds REAL NOT NULL DEFAULT 0,
                source_type TEXT NOT NULL DEFAULT 'mic');
            CREATE TABLE utterances (id INTEGER PRIMARY KEY, audio_segment_id INTEGER NOT NULL,
                start_offset_seconds REAL NOT NULL DEFAULT 0, end_offset_seconds REAL NOT NULL DEFAULT 0,
                text TEXT NOT NULL, speaker_label TEXT NOT NULL DEFAULT 'Me');
            CREATE TABLE screenshots (id INTEGER PRIMARY KEY, captured_at TEXT NOT NULL, ocr_text TEXT);
            CREATE TABLE episodes (
                id INTEGER PRIMARY KEY,
                started_at TEXT NOT NULL UNIQUE,
                ended_at TEXT NOT NULL,
                type TEXT, title TEXT, summary TEXT,
                participants TEXT, languages TEXT, action_items TEXT,
                model TEXT, topics TEXT, people TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            );
            CREATE VIRTUAL TABLE episodes_fts USING fts5(title, summary, content='episodes', content_rowid='id');
            CREATE TRIGGER episodes_insert_fts AFTER INSERT ON episodes BEGIN
                INSERT INTO episodes_fts(rowid, title, summary) VALUES (new.id, new.title, new.summary);
            END;
            INSERT INTO episodes (started_at, ended_at, title, summary)
                VALUES ('2026-01-01T09:00:00Z','2026-01-01T10:00:00Z','v1 episode','old');
            "#,
        )
        .unwrap();

        let pre: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('episodes') WHERE name='updated_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pre, 0, "precondition: v1 has no updated_at");

        run_migrations(&conn).unwrap();

        let has_updated: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('episodes') WHERE name='updated_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(has_updated, 1, "updated_at column added");
        let ep_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM episodes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ep_count, 0, "v1 episode rows discarded on migrate");
        let mem_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='episode_members'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(mem_exists, 1, "episode_members created");

        // started_at is no longer UNIQUE in v2.
        conn.execute(
            "INSERT INTO episodes (started_at, ended_at, title) VALUES ('2026-02-01T09:00:00Z','2026-02-01T09:30:00Z','a')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO episodes (started_at, ended_at, title) VALUES ('2026-02-01T09:00:00Z','2026-02-01T09:10:00Z','b')",
            [],
        )
        .unwrap();

        // Second run is a no-op (idempotent) — must NOT wipe v2 data.
        run_migrations(&conn).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM episodes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2, "re-running migrations must not re-drop v2 episodes");
    }

    /// ADR-0004 §G.3: a blob whose episodes_fts predates minutes_text must be
    /// rebuilt (drop + recreate + 'rebuild' + re-pointed triggers), keeping
    /// existing rows searchable and indexing minutes for updated rows.
    #[test]
    fn episodes_fts_rebuild_indexes_minutes() {
        init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        // v2-era schema WITHOUT the minutes columns / 3-column FTS.
        conn.execute_batch(
            r#"
            CREATE TABLE episodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL, ended_at TEXT NOT NULL,
                type TEXT, title TEXT, summary TEXT,
                participants TEXT, languages TEXT, action_items TEXT,
                model TEXT, topics TEXT, people TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                updated_at TEXT
            );
            CREATE TABLE utterances (id INTEGER PRIMARY KEY, audio_segment_id INTEGER NOT NULL,
                start_offset_seconds REAL NOT NULL DEFAULT 0, end_offset_seconds REAL NOT NULL DEFAULT 0,
                text TEXT NOT NULL, speaker_label TEXT NOT NULL DEFAULT 'Me');
            CREATE TABLE screenshots (id INTEGER PRIMARY KEY, captured_at TEXT NOT NULL, ocr_text TEXT);
            CREATE VIRTUAL TABLE episodes_fts USING fts5(title, summary, content='episodes', content_rowid='id');
            CREATE TRIGGER episodes_insert_fts AFTER INSERT ON episodes BEGIN
                INSERT INTO episodes_fts(rowid, title, summary) VALUES (new.id, new.title, new.summary);
            END;
            CREATE TRIGGER episodes_update_fts AFTER UPDATE ON episodes BEGIN
                INSERT INTO episodes_fts(episodes_fts, rowid, title, summary)
                    VALUES ('delete', old.id, old.title, old.summary);
                INSERT INTO episodes_fts(rowid, title, summary) VALUES (new.id, new.title, new.summary);
            END;
            INSERT INTO episodes (started_at, ended_at, title, summary)
                VALUES ('2026-07-01T09:00:00Z','2026-07-01T10:00:00Z','Quarterly planning','budget review');
            "#,
        )
        .unwrap();

        run_migrations(&conn).unwrap();

        // Pre-existing row still searchable through the rebuilt index.
        let hits: i64 = conn
            .query_row(
                "SELECT count(*) FROM episodes_fts WHERE episodes_fts MATCH 'Quarterly'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hits, 1, "rebuild must re-index existing rows");

        // The re-pointed UPDATE trigger indexes minutes_text via the 'delete'
        // command form (a plain UPDATE on the shadow would corrupt the index).
        conn.execute(
            "UPDATE episodes SET minutes_text = 'xylophone practice with Ana' WHERE id = 1",
            [],
        )
        .unwrap();
        let hits: i64 = conn
            .query_row(
                "SELECT count(*) FROM episodes_fts WHERE episodes_fts MATCH 'xylophone'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hits, 1, "minutes_text must be searchable after update");
        // Integrity: an external-content mismatch surfaces here.
        conn.execute_batch("INSERT INTO episodes_fts(episodes_fts) VALUES('integrity-check');")
            .unwrap();

        // Idempotent on the next open.
        run_migrations(&conn).unwrap();
        let hits: i64 = conn
            .query_row(
                "SELECT count(*) FROM episodes_fts WHERE episodes_fts MATCH 'xylophone'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hits, 1, "second migration run must not lose the index");
    }

    /// A blob with the old plain-DELETE FTS triggers on utterances/screenshots
    /// (the dormant external-content footgun) must get them re-pointed to the
    /// 'delete'-command form so row deletion keeps the index consistent.
    #[test]
    fn utterance_fts_delete_trigger_repointed() {
        init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE audio_segments (id INTEGER PRIMARY KEY, started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL, duration_seconds REAL NOT NULL DEFAULT 0,
                source_type TEXT NOT NULL DEFAULT 'mic');
            CREATE TABLE utterances (id INTEGER PRIMARY KEY, audio_segment_id INTEGER NOT NULL,
                start_offset_seconds REAL NOT NULL DEFAULT 0, end_offset_seconds REAL NOT NULL DEFAULT 0,
                text TEXT NOT NULL, speaker_label TEXT NOT NULL DEFAULT 'Me');
            CREATE TABLE screenshots (id INTEGER PRIMARY KEY, captured_at TEXT NOT NULL, ocr_text TEXT);
            CREATE TABLE episodes (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL, type TEXT, title TEXT, summary TEXT, participants TEXT,
                languages TEXT, action_items TEXT, model TEXT, topics TEXT, people TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT);
            CREATE VIRTUAL TABLE utterances_fts USING fts5(text, content='utterances', content_rowid='id');
            CREATE VIRTUAL TABLE screenshots_fts USING fts5(ocr_text, content='screenshots', content_rowid='id');
            CREATE TRIGGER utterances_insert_fts AFTER INSERT ON utterances BEGIN
                INSERT INTO utterances_fts(rowid, text) VALUES (new.id, new.text);
            END;
            CREATE TRIGGER utterances_delete_fts AFTER DELETE ON utterances BEGIN
                DELETE FROM utterances_fts WHERE rowid = old.id;
            END;
            CREATE TRIGGER screenshots_insert_fts AFTER INSERT ON screenshots BEGIN
                INSERT INTO screenshots_fts(rowid, ocr_text) VALUES (new.id, new.ocr_text);
            END;
            CREATE TRIGGER screenshots_delete_fts AFTER DELETE ON screenshots BEGIN
                DELETE FROM screenshots_fts WHERE rowid = old.id;
            END;
            INSERT INTO audio_segments (started_at, ended_at) VALUES ('2026-07-06T09:00:00Z','2026-07-06T09:01:00Z');
            INSERT INTO utterances (audio_segment_id, text) VALUES (1, 'ephemeral walrus');
            INSERT INTO screenshots (captured_at, ocr_text) VALUES ('2026-07-06T09:00:30Z', 'ephemeral aurora');
            "#,
        )
        .unwrap();

        run_migrations(&conn).unwrap();

        // Deleting through the re-pointed triggers keeps the index consistent…
        conn.execute("DELETE FROM utterances WHERE id = 1", [])
            .unwrap();
        conn.execute("DELETE FROM screenshots WHERE id = 1", [])
            .unwrap();
        conn.execute_batch(
            "INSERT INTO utterances_fts(utterances_fts) VALUES('integrity-check');
             INSERT INTO screenshots_fts(screenshots_fts) VALUES('integrity-check');",
        )
        .unwrap();
        // …and the terms are actually gone.
        let hits: i64 = conn
            .query_row(
                "SELECT count(*) FROM utterances_fts WHERE utterances_fts MATCH 'walrus'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hits, 0);

        // Idempotent: second run leaves the fixed triggers alone.
        run_migrations(&conn).unwrap();
        let fixed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' \
                 AND name IN ('utterances_delete_fts','screenshots_delete_fts') \
                 AND sql LIKE '%''delete''%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(fixed, 2);
    }

    // ── Fake KMS ──────────────────────────────────────────────────────────────

    pub struct FakeKms;

    #[async_trait::async_trait]
    impl KmsClient for FakeKms {
        async fn wrap_dek(&self, plaintext_dek: &[u8]) -> crate::error::Result<String> {
            Ok(B64.encode(plaintext_dek))
        }
        async fn unwrap_dek(&self, wrapped_b64: &str) -> crate::error::Result<Vec<u8>> {
            B64.decode(wrapped_b64)
                .map_err(|e| crate::error::EnclaveError::Kms(e.to_string()))
        }
    }

    // ── Fake GCS ──────────────────────────────────────────────────────────────

    /// (ciphertext, wrapped_dek, generation)
    type FakeObject = (Vec<u8>, String, i64);

    pub struct FakeGcs {
        objects: StdMutex<HashMap<String, FakeObject>>,
    }

    impl FakeGcs {
        pub fn new() -> Self {
            Self {
                objects: StdMutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl GcsClient for FakeGcs {
        async fn get_object(&self, object_name: &str) -> crate::error::Result<GcsGetResponse> {
            let store = self.objects.lock().unwrap();
            store
                .get(object_name)
                .map(|(ct, dek, gen)| GcsGetResponse {
                    ciphertext: ct.clone(),
                    wrapped_dek_b64: dek.clone(),
                    generation: *gen,
                })
                .ok_or(crate::error::EnclaveError::NotFound)
        }

        async fn put_object(
            &self,
            object_name: &str,
            ciphertext: &[u8],
            wrapped_dek_b64: &str,
            if_generation_match: i64,
        ) -> crate::error::Result<i64> {
            let mut store = self.objects.lock().unwrap();
            let current_gen = store.get(object_name).map(|(_, _, g)| *g).unwrap_or(0);
            if current_gen != if_generation_match {
                return Err(crate::error::EnclaveError::Conflict(
                    "generation mismatch".into(),
                ));
            }
            let new_gen = current_gen + 1;
            store.insert(
                object_name.to_string(),
                (ciphertext.to_vec(), wrapped_dek_b64.to_string(), new_gen),
            );
            Ok(new_gen)
        }

        async fn delete_object(&self, object_name: &str) -> crate::error::Result<()> {
            self.objects.lock().unwrap().remove(object_name);
            Ok(())
        }

        async fn rename_object(
            &self,
            source_object: &str,
            dest_object: &str,
        ) -> crate::error::Result<()> {
            let mut store = self.objects.lock().unwrap();
            if let Some(obj) = store.remove(source_object) {
                store.insert(dest_object.to_string(), obj);
                Ok(())
            } else {
                Err(crate::error::EnclaveError::NotFound)
            }
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    fn make_store() -> Store {
        Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()))
    }

    #[tokio::test]
    async fn new_user_creates_index() {
        let store = make_store();
        let result = store
            .with_user("alice", |conn| {
                // Table must exist
                let count: i64 = conn
                    .query_row("SELECT count(*) FROM utterances", [], |r| r.get(0))
                    .unwrap();
                Ok(count)
            })
            .await;
        assert!(result.is_ok(), "new user load failed: {result:?}");
        assert_eq!(result.unwrap(), 0);
    }

    /// Regression: the SECOND save on a cached handle must succeed. If flush
    /// does not record the post-PUT generation, every save after the first
    /// conflicts against the process's own previous write.
    #[tokio::test]
    async fn repeated_saves_on_same_handle_succeed() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let store = Store::new(kms.clone(), gcs.clone());

        for i in 0..3 {
            store
                .with_user("greg", move |conn| {
                    conn.execute(
                        "INSERT INTO screenshots (captured_at, ocr_text) VALUES (?1, ?2)",
                        rusqlite::params![format!("2026-01-01T00:0{i}:00Z"), format!("batch {i}")],
                    )?;
                    Ok(())
                })
                .await
                .expect("write");
            store
                .save_user("greg")
                .await
                .unwrap_or_else(|e| panic!("save #{i} failed: {e}"));
        }

        // All three batches survive a reload through fresh decrypt
        let store2 = Store::new(kms, gcs);
        let count: i64 = store2
            .with_user("greg", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |r| r.get(0))?)
            })
            .await
            .expect("reload");
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn write_then_save_then_reload() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let store = Store::new(kms.clone(), gcs.clone());

        // Write a row
        store
            .with_user("bob", |conn| {
                conn.execute(
                    "INSERT INTO audio_segments (started_at, ended_at, duration_seconds, source_type)
                     VALUES ('2026-01-01T00:00:00Z','2026-01-01T00:01:00Z',60.0,'mic')",
                    [],
                )?;
                let seg_id = conn.last_insert_rowid();
                conn.execute(
                    "INSERT INTO utterances (audio_segment_id, start_offset_seconds, end_offset_seconds, text, speaker_label)
                     VALUES (?1, 0.0, 5.0, 'hello world confidential', 'speaker_0')",
                    [&seg_id],
                )?;
                Ok(())
            })
            .await
            .expect("write");

        // Save to fake GCS
        store.save_user("bob").await.expect("save");

        // Create a fresh store over the same fake GCS — simulates restart
        let store2 = Store::new(kms, gcs);
        let found = store2
            .with_user("bob", |conn| {
                // FTS5 content-table pattern: query the virtual table, join back to base
                let text: String = conn.query_row(
                    "SELECT u.text FROM utterances u
                     WHERE u.id IN (
                         SELECT rowid FROM utterances_fts WHERE utterances_fts MATCH 'confidential'
                     )",
                    [],
                    |r| r.get(0),
                )?;
                Ok(text)
            })
            .await
            .expect("reload query");
        assert_eq!(found, "hello world confidential");
    }

    #[tokio::test]
    async fn screenshots_fts_works() {
        let store = make_store();
        store
            .with_user("carol", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, active_app, ocr_text)
                     VALUES ('2026-01-01T00:00:00Z','Safari','quarterly budget review')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("insert screenshot");

        let result = store
            .with_user("carol", |conn| {
                let text: String = conn.query_row(
                    "SELECT ocr_text FROM screenshots WHERE rowid IN (
                         SELECT rowid FROM screenshots_fts WHERE screenshots_fts MATCH 'budget'
                     )",
                    [],
                    |r| r.get(0),
                )?;
                Ok(text)
            })
            .await
            .expect("fts query");
        assert!(result.contains("budget"));
    }

    /// Write data for a user, delete the user, then load the user again.
    /// The reloaded index must be a fresh empty database (the old data is gone).
    #[tokio::test]
    async fn delete_user_clears_data_and_fresh_load_is_empty() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let store = Store::new(kms.clone(), gcs.clone());

        // Write some data for dave.
        store
            .with_user("dave", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, active_app, ocr_text)
                     VALUES ('2026-01-01T00:00:00Z','Chrome','top secret document')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("write dave data");
        store.save_user("dave").await.expect("save dave");

        // Confirm the data is there before deletion.
        let count_before: i64 = store
            .with_user("dave", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |r| r.get(0))?)
            })
            .await
            .expect("count before delete");
        assert_eq!(count_before, 1, "expected 1 screenshot before deletion");

        // Delete dave.
        store.delete_user("dave").await.expect("delete_user");

        // Load dave again on the same store; the GCS object is gone so it
        // creates a fresh empty database.
        let count_after: i64 = store
            .with_user("dave", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |r| r.get(0))?)
            })
            .await
            .expect("load dave after delete");
        assert_eq!(count_after, 0, "expected empty index after deletion");

        // FTS search should find nothing.
        let fts_hits: i64 = store
            .with_user("dave", |conn| {
                Ok(conn.query_row(
                    "SELECT count(*) FROM screenshots WHERE rowid IN (
                         SELECT rowid FROM screenshots_fts WHERE screenshots_fts MATCH 'secret'
                     )",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .expect("fts after delete");
        assert_eq!(fts_hits, 0, "FTS should return nothing after deletion");
    }

    /// Deleting a user that was never seen must succeed without error (idempotent).
    #[tokio::test]
    async fn delete_user_never_seen_is_ok() {
        let store = make_store();
        let result = store.delete_user("ghost-user-xyz").await;
        assert!(
            result.is_ok(),
            "delete_user on never-seen user should be Ok, got: {result:?}"
        );
    }

    // ── user_id validation ─────────────────────────────────────────────────────

    #[test]
    fn user_id_uuid_accepted() {
        assert!(validate_user_id("3f2c1d2e-9a4b-4c8d-b1e0-5a6f7c8d9e0f").is_ok());
        assert!(validate_user_id("simple_user-01").is_ok());
        assert!(validate_user_id(&"a".repeat(MAX_USER_ID_LEN)).is_ok());
    }

    #[test]
    fn user_id_path_traversal_rejected() {
        for bad in [
            "../../../etc/cron.d/evil",
            "..",
            "a/../b",
            "a/b",
            "a\\b",
            "user id",
            "user.id",
            "user\0id",
            "ユーザー",
            "",
        ] {
            assert!(
                validate_user_id(bad).is_err(),
                "user_id {bad:?} should be rejected"
            );
        }
        assert!(validate_user_id(&"a".repeat(MAX_USER_ID_LEN + 1)).is_err());
    }

    /// A traversal-style user_id must be rejected by the store itself before
    /// any temp file or GCS object name is derived (defense in depth).
    #[tokio::test]
    async fn store_rejects_traversal_user_id() {
        let store = make_store();
        let result = store.with_user("../../tmp/evil", |_conn| Ok(())).await;
        assert!(matches!(
            result,
            Err(crate::error::EnclaveError::InvalidRequest(_))
        ));

        let del = store.delete_user("../../tmp/evil").await;
        assert!(matches!(
            del,
            Err(crate::error::EnclaveError::InvalidRequest(_))
        ));
    }

    /// The UserHandle must carry the user_id itself: a save must write to the
    /// GCS object derived from the original user_id, not from any reparsed
    /// temp-file path.
    #[tokio::test]
    async fn handle_round_trips_user_id_to_gcs_object() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());

        // A user_id containing '-' (like a UUID) historically broke the
        // path-stem reconstruction; assert the object lands in the right place.
        let user_id = "3f2c1d2e-9a4b-4c8d-b1e0-5a6f7c8d9e0f";
        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES ('2026-01-01T00:00:00Z', 'x')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("write");
        store.save_user(user_id).await.expect("save");

        let objects = gcs.objects.lock().unwrap();
        let expected = format!("indexes/{user_id}.db.enc");
        assert!(
            objects.contains_key(&expected),
            "expected GCS object {expected:?}, found keys: {:?}",
            objects.keys().collect::<Vec<_>>()
        );
        assert_eq!(objects.len(), 1, "no stray objects should be written");
    }
}
