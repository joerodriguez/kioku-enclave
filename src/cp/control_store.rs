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
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::info;

use crate::{
    archive_v3::{
        ArchiveId, KeyKind, KeyRegistryContext, LogicalLocation, ObjectContext, ObjectId,
        ObjectRole,
    },
    archive_v3_lifecycle::{
        ActiveCreateAdmission, ArtifactCreateState, BootstrapPlan, DeletionInventorySeal,
        DurableBootstrapReservation, DurableInventoryPage, DurablePhysicalCompletion,
        ErasedInventoryPages, InventoryPageReference, LifecycleCreateOutcome, LifecycleError,
        PhysicalDeletionReceipt, PlannedArtifact, PreparedBootstrap, RecoveredBootstrap,
        RecoveredDeletionLifecycle, LIFECYCLE_FORMAT_VERSION, MAX_BOOTSTRAP_WITNESS_BYTES,
        MAX_LIFECYCLE_PAGES,
    },
    cp::isotime,
    crypto::{decrypt_bound_blob, encrypt_bound_blob, generate_and_wrap_dek, load_dek, KmsClient},
    error::{EnclaveError, Result},
    store::{validate_user_id, GcsClient, IdentityRebindSource, Store},
};

const CONTROL_OBJECT: &str = "control/control.db.enc";
const CONTROL_CONTEXT: &[u8] = b"control-db\0control/control.db.enc";
const MAX_PENDING_RECORDING_LEASE_REQUESTS_PER_USER: i64 = 1;
const MAX_RECORDING_LEASE_DENIALS_PER_USER: i64 = 100;
const RECORDING_LEASE_DURATION_MS: i64 = 60_000;
const RECORDING_DELIVERY_EVENTS_PER_MINUTE: i64 = 120;
const RECORDING_DELIVERY_BYTES_PER_MINUTE: i64 = 256 * 1024 * 1024;
const MAX_ARCHIVE_DELETION_CURSOR_BYTES: usize = 4 * 1024;
const MAX_ARCHIVE_ID_CANDIDATES: usize = 8;
const LIFECYCLE_REGISTRY_ORDINAL: u32 = 0;
const LIFECYCLE_ROOT_ORDINAL: u32 = 1;
const LIFECYCLE_WITNESS_ORDINAL: u32 = 2;

fn grant_recording_delivery_minute(tx: &rusqlite::Transaction<'_>, user_id: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO recording_delivery_balances (user_id,event_credits,byte_credits)
         VALUES (?1,?2,?3)
         ON CONFLICT(user_id) DO UPDATE SET
           event_credits=event_credits+excluded.event_credits,
           byte_credits=byte_credits+excluded.byte_credits,
           updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        rusqlite::params![
            user_id,
            RECORDING_DELIVERY_EVENTS_PER_MINUTE,
            RECORDING_DELIVERY_BYTES_PER_MINUTE
        ],
    )?;
    Ok(())
}

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
-- A paid live lease or reconciled offline minute grants a bounded amount of
-- delayed Mac-outbox delivery. This separates capture metering from network
-- transfer time without allowing an unbounded inactive-lease upload path.
CREATE TABLE IF NOT EXISTS recording_delivery_balances (
    user_id       TEXT PRIMARY KEY,
    event_credits INTEGER NOT NULL CHECK (event_credits >= 0),
    byte_credits  INTEGER NOT NULL CHECK (byte_credits >= 0),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS recording_delivery_reservations (
    user_id        TEXT NOT NULL,
    event_id       TEXT NOT NULL,
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0),
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (user_id, event_id)
);
CREATE TABLE IF NOT EXISTS offline_recording_usage_receipts (
    user_id      TEXT NOT NULL,
    request_id   TEXT NOT NULL,
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
-- The archive-v3 namespace is deliberately opaque to identities.  This
-- encrypted control-store mapping is its only account-to-archive association;
-- the future provider witness must receive only archive_id.
CREATE TABLE IF NOT EXISTS archive_bindings (
    user_id    TEXT PRIMARY KEY,
    archive_id BLOB NOT NULL UNIQUE CHECK (length(archive_id) = 16 AND archive_id != zeroblob(16)),
    state      TEXT NOT NULL CHECK (state IN ('active_legacy', 'tombstoned')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    tombstoned_at TEXT
);
-- This is a durable, encrypted control-plane ledger for a later exact v3
-- deletion worker.  It intentionally has no completed states: this release
-- has no v3 provider authority and must not claim key/object/retention
-- completion.  Each cursor is opaque provider continuation state, never an
-- identity, object name, or user-content field.
CREATE TABLE IF NOT EXISTS archive_deletion_ledgers (
    archive_id                  BLOB PRIMARY KEY CHECK (length(archive_id) = 16 AND archive_id != zeroblob(16)),
    state                       TEXT NOT NULL CHECK (state IN ('active_legacy', 'tombstoned')),
    deletion_fence_id           BLOB CHECK (deletion_fence_id IS NULL OR length(deletion_fence_id) = 16),
    inventory_format_version    INTEGER NOT NULL DEFAULT 1 CHECK (inventory_format_version = 1),
    archive_object_cursor       BLOB,
    key_registry_cursor         BLOB,
    legacy_generation_cursor    BLOB,
    media_inventory_cursor      BLOB,
    legacy_rebind_fence_object_name TEXT CHECK (
        legacy_rebind_fence_object_name IS NULL
        OR length(legacy_rebind_fence_object_name) > 0
    ),
    tombstoned_at               TEXT,
    updated_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (
        (state = 'active_legacy' AND deletion_fence_id IS NULL AND tombstoned_at IS NULL)
        OR
        (state = 'tombstoned' AND deletion_fence_id IS NOT NULL
         AND length(deletion_fence_id) = 16 AND deletion_fence_id != zeroblob(16)
         AND tombstoned_at IS NOT NULL)
    )
);
-- Inactive archive-v3 create-ahead authority. This extends the existing
-- archive binding/deletion ledger rather than inventing a second identity or
-- tombstone source. Exact bootstrap payloads remain control-DEK encrypted and
-- bounded until physical deletion makes erasure safe.
CREATE TABLE IF NOT EXISTS archive_lifecycle_anchors (
    archive_id BLOB PRIMARY KEY REFERENCES archive_deletion_ledgers(archive_id),
    format_version INTEGER NOT NULL CHECK (format_version = 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (state IN (
        'reserved', 'objects_prepared', 'witness_prepared', 'witnessed',
        'deletion_frozen', 'inventory_sealed', 'physical_complete'
    )),
    bootstrap_attempt_id BLOB NOT NULL CHECK (length(bootstrap_attempt_id) = 16 AND bootstrap_attempt_id != zeroblob(16)),
    database_epoch BLOB NOT NULL CHECK (length(database_epoch) = 16 AND database_epoch != zeroblob(16)),
    key_epoch BLOB NOT NULL CHECK (length(key_epoch) = 16 AND key_epoch != zeroblob(16)),
    registry_object_id BLOB NOT NULL CHECK (length(registry_object_id) = 16 AND registry_object_id != zeroblob(16)),
    root_object_id BLOB NOT NULL CHECK (length(root_object_id) = 16 AND root_object_id != zeroblob(16)),
    wrapped_registry_hash BLOB CHECK (wrapped_registry_hash IS NULL OR length(wrapped_registry_hash) = 32),
    wrapped_registry_len INTEGER CHECK (wrapped_registry_len IS NULL OR wrapped_registry_len > 0),
    wrapped_registry_bytes BLOB,
    root_envelope_hash BLOB CHECK (root_envelope_hash IS NULL OR length(root_envelope_hash) = 32),
    root_envelope_len INTEGER CHECK (root_envelope_len IS NULL OR root_envelope_len > 0),
    root_envelope_bytes BLOB,
    witness_record_hash BLOB CHECK (witness_record_hash IS NULL OR length(witness_record_hash) = 32),
    witness_record_len INTEGER CHECK (witness_record_len IS NULL OR witness_record_len > 0),
    witness_record_bytes BLOB,
    witness_create_state TEXT CHECK (witness_create_state IS NULL OR witness_create_state IN ('planned','outcome_unknown','created','confirmed_absent')),
    witness_admission_revision INTEGER,
    deletion_fence BLOB CHECK (deletion_fence IS NULL OR (length(deletion_fence) = 16 AND deletion_fence != zeroblob(16))),
    inventory_page_count INTEGER CHECK (inventory_page_count IS NULL OR inventory_page_count > 0),
    inventory_artifact_count INTEGER CHECK (inventory_artifact_count IS NULL OR inventory_artifact_count > 0),
    inventory_terminal_hash BLOB CHECK (inventory_terminal_hash IS NULL OR length(inventory_terminal_hash) = 32),
    inventory_commitment BLOB CHECK (inventory_commitment IS NULL OR length(inventory_commitment) = 32),
    inventory_seal_revision INTEGER CHECK (inventory_seal_revision IS NULL OR inventory_seal_revision > 0),
    physical_provider_drain_commitment BLOB CHECK (physical_provider_drain_commitment IS NULL OR length(physical_provider_drain_commitment) = 32),
    payload_erased INTEGER NOT NULL DEFAULT 0 CHECK (payload_erased IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (
        (state = 'reserved' AND wrapped_registry_bytes IS NULL AND root_envelope_bytes IS NULL)
        OR
        (state IN ('objects_prepared','witness_prepared','witnessed')
         AND length(wrapped_registry_bytes) = wrapped_registry_len
         AND length(root_envelope_bytes) = root_envelope_len)
        OR
        (state IN ('deletion_frozen','inventory_sealed','physical_complete')
         AND ((wrapped_registry_bytes IS NULL AND root_envelope_bytes IS NULL)
              OR (length(wrapped_registry_bytes) = wrapped_registry_len
                  AND length(root_envelope_bytes) = root_envelope_len)))
    ),
    CHECK (
        (state IN ('reserved','objects_prepared') AND witness_record_bytes IS NULL)
        OR
        (state IN ('witness_prepared','witnessed')
         AND length(witness_record_bytes) = witness_record_len
         AND witness_create_state IS NOT NULL)
        OR
        (state IN ('deletion_frozen','inventory_sealed','physical_complete')
         AND ((witness_record_bytes IS NULL AND witness_create_state IS NULL)
              OR (length(witness_record_bytes) = witness_record_len
                  AND witness_create_state IS NOT NULL)))
    )
);
CREATE TABLE IF NOT EXISTS archive_lifecycle_bootstrap_creates (
    archive_id BLOB NOT NULL REFERENCES archive_lifecycle_anchors(archive_id),
    bootstrap_attempt_id BLOB NOT NULL CHECK (length(bootstrap_attempt_id) = 16),
    artifact_ordinal INTEGER NOT NULL CHECK (artifact_ordinal IN (0, 1)),
    canonical_key TEXT NOT NULL CHECK (length(canonical_key) > 0 AND length(canonical_key) <= 1024),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16 AND object_id != zeroblob(16)),
    object_role INTEGER NOT NULL CHECK (object_role BETWEEN 1 AND 9),
    ciphertext_hash BLOB NOT NULL CHECK (length(ciphertext_hash) = 32),
    encoded_len INTEGER NOT NULL CHECK (encoded_len > 0),
    create_state TEXT NOT NULL CHECK (create_state IN ('planned','outcome_unknown','created','confirmed_absent')),
    admission_revision INTEGER,
    PRIMARY KEY (archive_id, bootstrap_attempt_id, artifact_ordinal),
    UNIQUE (archive_id, object_id)
);
CREATE TABLE IF NOT EXISTS archive_lifecycle_inventory_pages (
    archive_id BLOB NOT NULL REFERENCES archive_lifecycle_anchors(archive_id),
    page_ordinal INTEGER NOT NULL CHECK (page_ordinal >= 0),
    page_id BLOB NOT NULL CHECK (length(page_id) = 16 AND page_id != zeroblob(16)),
    previous_hash BLOB NOT NULL CHECK (length(previous_hash) = 32),
    page_hash BLOB NOT NULL CHECK (length(page_hash) = 32),
    encoded_len INTEGER NOT NULL CHECK (encoded_len > 0 AND encoded_len <= 65536),
    PRIMARY KEY (archive_id, page_ordinal),
    UNIQUE (archive_id, page_id),
    UNIQUE (archive_id, page_hash)
);
-- Durable authority for the legacy identity -> stable-ID transition. This row
-- is encrypted inside the control blob and precedes every provider mutation.
-- It retains both exact namespaces through account deletion so a deletion
-- started before reauthentication cannot strand either side of a partial move.
CREATE TABLE IF NOT EXISTS identity_rebind_operations (
    operation_id          TEXT PRIMARY KEY,
    google_sub            TEXT NOT NULL UNIQUE,
    old_user_id           TEXT NOT NULL,
    stable_user_id        TEXT NOT NULL UNIQUE,
    archive_id            BLOB NOT NULL CHECK (length(archive_id) = 16 AND archive_id != zeroblob(16)),
    old_object_name       TEXT NOT NULL,
    stable_object_name    TEXT NOT NULL,
    source_base_generation INTEGER NOT NULL CHECK (source_base_generation >= 0),
    source_generation     INTEGER,
    source_commitment     BLOB NOT NULL CHECK (length(source_commitment) = 32),
    stage                 TEXT NOT NULL CHECK (stage IN (
        'prepared', 'source_freezing', 'source_frozen', 'stable_writing',
        'stable_written', 'old_purging', 'old_purged', 'committed',
        'deletion_pending', 'deletion_reconciled'
    )),
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (
        (stage IN ('prepared', 'source_freezing', 'deletion_pending', 'deletion_reconciled')
         AND source_generation IS NULL)
        OR
        (stage NOT IN ('prepared', 'source_freezing', 'deletion_pending', 'deletion_reconciled')
         AND source_generation IS NOT NULL AND source_generation > 0)
        OR
        (stage IN ('deletion_pending', 'deletion_reconciled') AND source_generation > 0)
    ),
    CHECK (old_user_id != stable_user_id)
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
CREATE TABLE IF NOT EXISTS push_installations (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
    platform         TEXT NOT NULL CHECK (platform IN ('ios','macos')),
    topic            TEXT NOT NULL,
    environment      TEXT NOT NULL CHECK (environment IN ('sandbox','production')),
    device_token     TEXT NOT NULL,
    token_generation INTEGER NOT NULL DEFAULT 1,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (topic, environment, device_token)
);
CREATE INDEX IF NOT EXISTS push_installations_user_idx
    ON push_installations(user_id, enabled, last_seen_at);
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

#[derive(Clone)]
pub struct ControlStore {
    inner: Arc<Mutex<Option<Handle>>>,
    kms: Arc<dyn KmsClient>,
    gcs: Arc<dyn GcsClient>,
    /// Production authority for serializing legacy identity rebinding with
    /// account deletion. Tests which do not exercise rebinding may omit it;
    /// the rebind path itself always fails closed when it is absent.
    lifecycle_store: Option<Arc<Store>>,
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

/// Internal-only opaque archive binding.  It is deliberately absent from API
/// and export models; archive IDs may leave this encrypted control store only
/// when a later separately-authorized v3 authority path is added.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArchiveBinding {
    archive_id: ArchiveId,
}

impl std::fmt::Debug for ArchiveBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ArchiveBinding(<opaque>)")
    }
}

impl ArchiveBinding {
    #[allow(
        dead_code,
        reason = "reserved for separately-authorized v3 authority wiring"
    )]
    pub(crate) const fn archive_id(self) -> ArchiveId {
        self.archive_id
    }
}

/// The only transitions enabled in this prerequisite are
/// `ActiveLegacy -> Tombstoned`.  Future provider-backed work may add exact
/// inventory/erasure transitions, but this type intentionally has no state
/// that could be mistaken for cryptographic, logical, or physical completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArchiveDeletionState {
    ActiveLegacy,
    Tombstoned,
}

impl ArchiveDeletionState {
    const fn as_db(self) -> &'static str {
        match self {
            Self::ActiveLegacy => "active_legacy",
            Self::Tombstoned => "tombstoned",
        }
    }

    fn from_db(value: &str) -> Result<Self> {
        match value {
            "active_legacy" => Ok(Self::ActiveLegacy),
            "tombstoned" => Ok(Self::Tombstoned),
            _ => Err(EnclaveError::Store("invalid archive deletion state".into())),
        }
    }
}

/// Typed shape of the encrypted, resumable v3-deletion inventory. Cursor fields
/// are raw opaque continuation tokens; the retained legacy marker name is a
/// domain-separated HMAC under the KMS-protected control DEK, never an
/// identity-derived plaintext or publicly enumerable namespace. No code treats
/// absent cursor state as inventory completion.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ArchiveDeletionLedger {
    pub(crate) binding: ArchiveBinding,
    pub(crate) state: ArchiveDeletionState,
    pub(crate) deletion_fence_id: Option<ArchiveId>,
    pub(crate) archive_object_cursor: Option<Vec<u8>>,
    pub(crate) key_registry_cursor: Option<Vec<u8>>,
    pub(crate) legacy_generation_cursor: Option<Vec<u8>>,
    pub(crate) media_inventory_cursor: Option<Vec<u8>>,
    pub(crate) legacy_rebind_fence_object_name: Option<String>,
}

impl std::fmt::Debug for ArchiveDeletionLedger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ArchiveDeletionLedger(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum IdentityRebindStage {
    Prepared,
    SourceFreezing,
    SourceFrozen,
    StableWriting,
    StableWritten,
    OldPurging,
    OldPurged,
    Committed,
    DeletionPending,
    DeletionReconciled,
}

impl IdentityRebindStage {
    const fn as_db(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::SourceFreezing => "source_freezing",
            Self::SourceFrozen => "source_frozen",
            Self::StableWriting => "stable_writing",
            Self::StableWritten => "stable_written",
            Self::OldPurging => "old_purging",
            Self::OldPurged => "old_purged",
            Self::Committed => "committed",
            Self::DeletionPending => "deletion_pending",
            Self::DeletionReconciled => "deletion_reconciled",
        }
    }

    fn from_db(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "source_freezing" => Ok(Self::SourceFreezing),
            "source_frozen" => Ok(Self::SourceFrozen),
            "stable_writing" => Ok(Self::StableWriting),
            "stable_written" => Ok(Self::StableWritten),
            "old_purging" => Ok(Self::OldPurging),
            "old_purged" => Ok(Self::OldPurged),
            "committed" => Ok(Self::Committed),
            "deletion_pending" => Ok(Self::DeletionPending),
            "deletion_reconciled" => Ok(Self::DeletionReconciled),
            _ => Err(EnclaveError::Store("invalid identity rebind stage".into())),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct IdentityRebindOperation {
    operation_id: String,
    google_sub: String,
    pub(crate) old_user_id: String,
    pub(crate) stable_user_id: String,
    binding: ArchiveBinding,
    old_object_name: String,
    stable_object_name: String,
    source_base_generation: i64,
    source_generation: Option<i64>,
    source_commitment: [u8; 32],
    stage: IdentityRebindStage,
}

impl std::fmt::Debug for IdentityRebindOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("IdentityRebindOperation(<opaque>)")
    }
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

#[derive(Clone, PartialEq, Eq)]
pub struct PushInstallation {
    pub id: String,
    pub user_id: String,
    pub platform: String,
    pub topic: String,
    pub environment: String,
    pub device_token: String,
    pub token_generation: i64,
    pub enabled: bool,
}

impl std::fmt::Debug for PushInstallation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PushInstallation")
            .field("id", &"<opaque>")
            .field("platform", &self.platform)
            .field("topic", &self.topic)
            .field("environment", &self.environment)
            .field("token_generation", &self.token_generation)
            .field("enabled", &self.enabled)
            .finish()
    }
}

fn push_installation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PushInstallation> {
    Ok(PushInstallation {
        id: row.get(0)?,
        user_id: row.get(1)?,
        platform: row.get(2)?,
        topic: row.get(3)?,
        environment: row.get(4)?,
        device_token: row.get(5)?,
        token_generation: row.get(6)?,
        enabled: row.get::<_, i64>(7)? != 0,
    })
}

fn load_push_installation_conn(
    conn: &Connection,
    user_id: &str,
    installation_id: &str,
) -> Result<Option<PushInstallation>> {
    Ok(conn
        .query_row(
            "SELECT id,user_id,platform,topic,environment,device_token,token_generation,enabled \
             FROM push_installations WHERE user_id=?1 AND id=?2",
            rusqlite::params![user_id, installation_id],
            push_installation_from_row,
        )
        .optional()?)
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

/// Aggregate owner-reporting counts derived inside the encrypted control
/// store. The shape deliberately cannot carry account identifiers or signup
/// timestamps across the owner API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedAccountMetrics {
    pub retained_active_accounts: u64,
    pub new_retained_active_accounts_mtd: u64,
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

fn retained_active_account_metrics_conn(
    conn: &Connection,
    period: &str,
) -> Result<RetainedAccountMetrics> {
    let (retained, new_mtd): (i64, i64) = conn.query_row(
        "SELECT count(*),
                COALESCE(SUM(CASE WHEN substr(created_at,1,7)=?1 THEN 1 ELSE 0 END),0)
         FROM users
         WHERE status='active'",
        [period],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(RetainedAccountMetrics {
        retained_active_accounts: u64::try_from(retained)
            .map_err(|_| EnclaveError::Config("active account count overflow".into()))?,
        new_retained_active_accounts_mtd: u64::try_from(new_mtd)
            .map_err(|_| EnclaveError::Config("new active account count overflow".into()))?,
    })
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

fn archive_id_from_blob(value: Vec<u8>) -> Result<ArchiveId> {
    let bytes: [u8; 16] = value
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Store("invalid persisted opaque archive binding".into()))?;
    if bytes == [0; 16] {
        return Err(EnclaveError::Store(
            "invalid persisted zero archive identifier".into(),
        ));
    }
    Ok(ArchiveId::from_bytes(bytes))
}

fn random_nonzero_archive_id() -> Result<ArchiveId> {
    for _ in 0..MAX_ARCHIVE_ID_CANDIDATES {
        let value = *ArchiveId::random().as_bytes();
        if value != [0; 16] {
            return Ok(ArchiveId::from_bytes(value));
        }
    }
    Err(EnclaveError::Store(
        "opaque archive identifier generation exhausted".into(),
    ))
}

fn checked_archive_deletion_cursor(value: Option<Vec<u8>>) -> Result<Option<Vec<u8>>> {
    if value
        .as_ref()
        .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_ARCHIVE_DELETION_CURSOR_BYTES)
    {
        return Err(EnclaveError::Store(
            "invalid persisted archive deletion cursor".into(),
        ));
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArchiveLifecycleState {
    Reserved,
    ObjectsPrepared,
    WitnessPrepared,
    Witnessed,
    DeletionFrozen,
    InventorySealed,
    PhysicalComplete,
}

/// Unforgeable outside this producer module. Archive lifecycle receipt
/// factories require this witness that state was just validated in the
/// encrypted control-store transaction/read snapshot.
pub(crate) struct LifecyclePersistenceContext(());

impl LifecyclePersistenceContext {
    fn validated() -> Self {
        Self(())
    }
}

impl ArchiveLifecycleState {
    fn from_db(value: &str) -> Result<Self> {
        match value {
            "reserved" => Ok(Self::Reserved),
            "objects_prepared" => Ok(Self::ObjectsPrepared),
            "witness_prepared" => Ok(Self::WitnessPrepared),
            "witnessed" => Ok(Self::Witnessed),
            "deletion_frozen" => Ok(Self::DeletionFrozen),
            "inventory_sealed" => Ok(Self::InventorySealed),
            "physical_complete" => Ok(Self::PhysicalComplete),
            _ => Err(EnclaveError::Store(
                "invalid archive lifecycle state".into(),
            )),
        }
    }

    const fn admits_creates(self) -> bool {
        matches!(
            self,
            Self::ObjectsPrepared | Self::WitnessPrepared | Self::Witnessed
        )
    }
}

#[derive(Clone, Copy)]
struct ArchiveLifecycleAnchor {
    plan: BootstrapPlan,
    revision: u64,
    state: ArchiveLifecycleState,
}

impl std::fmt::Debug for ArchiveLifecycleAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ArchiveLifecycleAnchor(<opaque>)")
    }
}

fn lifecycle_store_error(_error: LifecycleError) -> EnclaveError {
    EnclaveError::Store("archive lifecycle ledger rejected durable state".into())
}

fn fixed_16(value: Vec<u8>) -> Result<[u8; 16]> {
    let bytes: [u8; 16] = value
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Store("invalid archive lifecycle identifier".into()))?;
    if bytes == [0; 16] {
        return Err(EnclaveError::Store(
            "invalid zero archive lifecycle identifier".into(),
        ));
    }
    Ok(bytes)
}

fn fixed_32(value: Vec<u8>) -> Result<[u8; 32]> {
    let bytes = fixed_32_allow_zero(value)?;
    if bytes == [0; 32] {
        return Err(EnclaveError::Store(
            "invalid zero archive lifecycle commitment".into(),
        ));
    }
    Ok(bytes)
}

fn fixed_32_allow_zero(value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Store("invalid archive lifecycle commitment".into()))
}

fn lifecycle_anchor_conn(
    conn: &Connection,
    archive_id: ArchiveId,
) -> Result<Option<ArchiveLifecycleAnchor>> {
    let row = conn
        .query_row(
            "SELECT format_version, revision, state, bootstrap_attempt_id,
                    database_epoch, key_epoch, registry_object_id, root_object_id
             FROM archive_lifecycle_anchors WHERE archive_id = ?1",
            [archive_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            format_version,
            revision,
            state,
            attempt,
            database_epoch,
            key_epoch,
            registry_object_id,
            root_object_id,
        )| {
            if format_version != i64::from(LIFECYCLE_FORMAT_VERSION) {
                return Err(EnclaveError::Store(
                    "unsupported archive lifecycle format".into(),
                ));
            }
            let revision = u64::try_from(revision)
                .map_err(|_| EnclaveError::Store("invalid archive lifecycle revision".into()))?;
            let plan = BootstrapPlan::new(
                archive_id,
                crate::archive_v3_lifecycle::BootstrapAttemptId::from_bytes(fixed_16(attempt)?)
                    .map_err(lifecycle_store_error)?,
                crate::archive_v3::DatabaseEpoch::from_bytes(fixed_16(database_epoch)?),
                crate::archive_v3::KeyEpoch::from_bytes(fixed_16(key_epoch)?),
                ObjectId::from_bytes(fixed_16(registry_object_id)?),
                ObjectId::from_bytes(fixed_16(root_object_id)?),
            )
            .map_err(lifecycle_store_error)?;
            Ok(ArchiveLifecycleAnchor {
                plan,
                revision,
                state: ArchiveLifecycleState::from_db(&state)?,
            })
        },
    )
    .transpose()
}

fn lifecycle_binding_for_plan_conn(conn: &Connection, plan: BootstrapPlan) -> Result<()> {
    let row = conn
        .query_row(
            "SELECT b.state, l.state
             FROM archive_bindings b
             JOIN archive_deletion_ledgers l ON l.archive_id = b.archive_id
             WHERE b.archive_id = ?1",
            [plan.archive_id().as_bytes().as_slice()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    match row {
        Some((binding, ledger)) if binding == "active_legacy" && ledger == "active_legacy" => {
            Ok(())
        }
        _ => Err(EnclaveError::Conflict(
            "archive lifecycle plan is not bound to an active archive".into(),
        )),
    }
}

fn lifecycle_archive_active_conn(conn: &Connection, archive_id: ArchiveId) -> Result<()> {
    let active: i64 = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM archive_lifecycle_anchors a
             JOIN archive_deletion_ledgers d ON d.archive_id = a.archive_id
             JOIN archive_bindings b ON b.archive_id = a.archive_id
             WHERE a.archive_id = ?1 AND b.state = 'active_legacy'
               AND d.state = 'active_legacy' AND d.deletion_fence_id IS NULL
         )",
        [archive_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if active == 1 {
        Ok(())
    } else {
        Err(EnclaveError::Conflict(
            "archive lifecycle deletion has begun".into(),
        ))
    }
}

fn active_lifecycle_revision_conn(
    conn: &Connection,
    archive_id: ArchiveId,
) -> Result<(u64, ArchiveLifecycleState)> {
    let (revision, state) = conn
        .query_row(
            "SELECT a.revision, a.state
             FROM archive_lifecycle_anchors a
             JOIN archive_deletion_ledgers d ON d.archive_id = a.archive_id
             JOIN archive_bindings b ON b.archive_id = a.archive_id
             WHERE a.archive_id = ?1 AND b.state = 'active_legacy'
               AND d.state = 'active_legacy' AND d.deletion_fence_id IS NULL",
            [archive_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| EnclaveError::Conflict("archive lifecycle deletion has begun".into()))?;
    Ok((
        u64::try_from(revision)
            .map_err(|_| EnclaveError::Store("archive lifecycle revision is invalid".into()))?,
        ArchiveLifecycleState::from_db(&state)?,
    ))
}

fn reserve_archive_bootstrap_conn(
    conn: &Connection,
    plan: BootstrapPlan,
) -> Result<DurableBootstrapReservation> {
    lifecycle_binding_for_plan_conn(conn, plan)?;
    if let Some(existing) = lifecycle_anchor_conn(conn, plan.archive_id())? {
        if existing.plan != plan {
            return Err(EnclaveError::Conflict(
                "archive lifecycle bootstrap reservation conflicts".into(),
            ));
        }
        // The reservation CAS is always revision 1. Later revisions describe
        // prepared/admitted work and must not turn a recovered reservation
        // into a different authority receipt.
        return DurableBootstrapReservation::from_persisted(
            &LifecyclePersistenceContext::validated(),
            existing.plan,
            1,
        )
        .map_err(lifecycle_store_error);
    }
    conn.execute(
        "INSERT INTO archive_lifecycle_anchors
         (archive_id, format_version, revision, state, bootstrap_attempt_id,
          database_epoch, key_epoch, registry_object_id, root_object_id)
         VALUES (?1, ?2, 1, 'reserved', ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            plan.archive_id().as_bytes().as_slice(),
            i64::from(LIFECYCLE_FORMAT_VERSION),
            plan.attempt_id().as_bytes().as_slice(),
            plan.database_epoch().as_bytes().as_slice(),
            plan.key_epoch().as_bytes().as_slice(),
            plan.registry_object_id().as_bytes().as_slice(),
            plan.root_object_id().as_bytes().as_slice(),
        ],
    )?;
    DurableBootstrapReservation::from_persisted(&LifecyclePersistenceContext::validated(), plan, 1)
        .map_err(lifecycle_store_error)
}

fn artifact_state_db(state: ArtifactCreateState) -> &'static str {
    match state {
        ArtifactCreateState::Planned => "planned",
        ArtifactCreateState::OutcomeUnknown => "outcome_unknown",
        ArtifactCreateState::Created => "created",
        ArtifactCreateState::ConfirmedAbsent => "confirmed_absent",
    }
}

fn prepare_archive_bootstrap_conn(
    conn: &Connection,
    reservation: DurableBootstrapReservation,
    wrapped_registry: &[u8],
    root_envelope: &[u8],
) -> Result<PreparedBootstrap> {
    let plan = reservation.plan();
    let current = lifecycle_anchor_conn(conn, plan.archive_id())?
        .ok_or_else(|| EnclaveError::Store("archive lifecycle reservation disappeared".into()))?;
    if current.plan != plan || reservation.revision() != 1 {
        return Err(EnclaveError::Conflict(
            "archive lifecycle reservation is stale".into(),
        ));
    }
    if current.state != ArchiveLifecycleState::Reserved {
        if !matches!(
            current.state,
            ArchiveLifecycleState::ObjectsPrepared
                | ArchiveLifecycleState::WitnessPrepared
                | ArchiveLifecycleState::Witnessed
        ) {
            return Err(EnclaveError::Conflict(
                "archive lifecycle bootstrap is frozen".into(),
            ));
        }
        let (stored_registry, stored_root, registry_hash, root_hash) = conn.query_row(
            "SELECT wrapped_registry_bytes, root_envelope_bytes,
                    wrapped_registry_hash, root_envelope_hash
             FROM archive_lifecycle_anchors WHERE archive_id = ?1",
            [plan.archive_id().as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;
        return PreparedBootstrap::from_persisted(
            &LifecyclePersistenceContext::validated(),
            reservation,
            current.revision,
            stored_registry,
            stored_root,
            fixed_32(registry_hash)?,
            fixed_32(root_hash)?,
        )
        .map_err(lifecycle_store_error);
    }
    if current.revision != reservation.revision() {
        return Err(EnclaveError::Conflict(
            "archive lifecycle reservation revision changed".into(),
        ));
    }
    let registry_hash: [u8; 32] = Sha256::digest(wrapped_registry).into();
    let root_hash: [u8; 32] = Sha256::digest(root_envelope).into();
    let prepared = PreparedBootstrap::from_persisted(
        &LifecyclePersistenceContext::validated(),
        reservation,
        reservation
            .revision()
            .checked_add(1)
            .ok_or_else(|| EnclaveError::Store("archive lifecycle revision exhausted".into()))?,
        wrapped_registry.to_vec(),
        root_envelope.to_vec(),
        registry_hash,
        root_hash,
    )
    .map_err(lifecycle_store_error)?;
    let registry_context =
        KeyRegistryContext::new(plan.archive_id(), KeyKind::Archive, plan.key_epoch());
    let registry_key = registry_context.object_key(plan.registry_object_id());
    let root_key = ObjectContext::new(
        plan.archive_id(),
        plan.database_epoch(),
        plan.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root { root_seq: 0 },
        plan.root_object_id(),
        None,
    )
    .map_err(|_| EnclaveError::Store("archive lifecycle root context is invalid".into()))?
    .object_key();
    let tx = conn.unchecked_transaction()?;
    let updated = tx.execute(
        "UPDATE archive_lifecycle_anchors
         SET revision = revision + 1, state = 'objects_prepared',
             wrapped_registry_hash = ?3, wrapped_registry_len = ?4,
             wrapped_registry_bytes = ?5, root_envelope_hash = ?6,
             root_envelope_len = ?7, root_envelope_bytes = ?8,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE archive_id = ?1 AND revision = ?2 AND state = 'reserved'",
        rusqlite::params![
            plan.archive_id().as_bytes().as_slice(),
            i64::try_from(reservation.revision())
                .map_err(|_| EnclaveError::Store("archive lifecycle revision overflow".into()))?,
            registry_hash.as_slice(),
            i64::try_from(wrapped_registry.len())
                .map_err(|_| EnclaveError::Store("archive lifecycle payload too large".into()))?,
            wrapped_registry,
            root_hash.as_slice(),
            i64::try_from(root_envelope.len())
                .map_err(|_| EnclaveError::Store("archive lifecycle payload too large".into()))?,
            root_envelope,
        ],
    )?;
    if updated != 1 {
        return Err(EnclaveError::Conflict(
            "archive lifecycle prepare lost its compare-and-swap".into(),
        ));
    }
    for (ordinal, key, role, hash, len) in [
        (
            LIFECYCLE_REGISTRY_ORDINAL,
            registry_key,
            ObjectRole::KeyRegistryV3,
            registry_hash,
            wrapped_registry.len(),
        ),
        (
            LIFECYCLE_ROOT_ORDINAL,
            root_key,
            ObjectRole::RootV3,
            root_hash,
            root_envelope.len(),
        ),
    ] {
        tx.execute(
            "INSERT INTO archive_lifecycle_bootstrap_creates
             (archive_id, bootstrap_attempt_id, artifact_ordinal, canonical_key,
              object_id, object_role, ciphertext_hash, encoded_len, create_state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'planned')",
            rusqlite::params![
                plan.archive_id().as_bytes().as_slice(),
                plan.attempt_id().as_bytes().as_slice(),
                i64::from(ordinal),
                key.as_str(),
                key.object_id().as_bytes().as_slice(),
                i64::from(role as u8),
                hash.as_slice(),
                i64::try_from(len).map_err(|_| EnclaveError::Store(
                    "archive lifecycle payload too large".into()
                ))?,
            ],
        )?;
    }
    tx.commit()?;
    Ok(prepared)
}

fn recover_archive_bootstrap_conn(
    conn: &Connection,
    archive_id: ArchiveId,
) -> Result<RecoveredBootstrap> {
    lifecycle_archive_active_conn(conn, archive_id)?;
    let anchor = lifecycle_anchor_conn(conn, archive_id)?
        .ok_or_else(|| EnclaveError::Store("archive lifecycle anchor disappeared".into()))?;
    let reservation = DurableBootstrapReservation::from_persisted(
        &LifecyclePersistenceContext::validated(),
        anchor.plan,
        1,
    )
    .map_err(lifecycle_store_error)?;
    if anchor.state == ArchiveLifecycleState::Reserved {
        if anchor.revision != 1 {
            return Err(EnclaveError::Store(
                "reserved archive lifecycle revision changed".into(),
            ));
        }
        return Ok(RecoveredBootstrap::Reserved(reservation));
    }
    if !matches!(
        anchor.state,
        ArchiveLifecycleState::ObjectsPrepared
            | ArchiveLifecycleState::WitnessPrepared
            | ArchiveLifecycleState::Witnessed
    ) {
        return Err(EnclaveError::Conflict(
            "archive bootstrap recovery is frozen for deletion".into(),
        ));
    }
    let (wrapped, root, wrapped_hash, root_hash, wrapped_len, root_len) = conn.query_row(
        "SELECT wrapped_registry_bytes, root_envelope_bytes,
                wrapped_registry_hash, root_envelope_hash,
                wrapped_registry_len, root_envelope_len
         FROM archive_lifecycle_anchors WHERE archive_id = ?1",
        [archive_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    if usize::try_from(wrapped_len).ok() != Some(wrapped.len())
        || usize::try_from(root_len).ok() != Some(root.len())
    {
        return Err(EnclaveError::Store(
            "archive lifecycle prepared byte lengths changed".into(),
        ));
    }
    PreparedBootstrap::from_persisted(
        &LifecyclePersistenceContext::validated(),
        reservation,
        anchor.revision,
        wrapped,
        root,
        fixed_32(wrapped_hash)?,
        fixed_32(root_hash)?,
    )
    .map(RecoveredBootstrap::Prepared)
    .map_err(lifecycle_store_error)
}

fn prepare_archive_witness_conn(
    conn: &Connection,
    archive_id: ArchiveId,
    expected_revision: u64,
    encoded_witness: &[u8],
) -> Result<u64> {
    if encoded_witness.is_empty() || encoded_witness.len() > MAX_BOOTSTRAP_WITNESS_BYTES {
        return Err(EnclaveError::Store(
            "archive lifecycle witness candidate is invalid".into(),
        ));
    }
    let hash: [u8; 32] = Sha256::digest(encoded_witness).into();
    let anchor = lifecycle_anchor_conn(conn, archive_id)?
        .ok_or_else(|| EnclaveError::Store("archive lifecycle anchor disappeared".into()))?;
    if matches!(
        anchor.state,
        ArchiveLifecycleState::WitnessPrepared | ArchiveLifecycleState::Witnessed
    ) {
        let (stored, stored_hash): (Vec<u8>, Vec<u8>) = conn.query_row(
            "SELECT witness_record_bytes, witness_record_hash
             FROM archive_lifecycle_anchors WHERE archive_id = ?1",
            [archive_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if anchor.revision != expected_revision
            || stored != encoded_witness
            || fixed_32(stored_hash)? != hash
        {
            return Err(EnclaveError::Conflict(
                "archive lifecycle witness preparation changed".into(),
            ));
        }
        return Ok(anchor.revision);
    }
    let unresolved: i64 = conn.query_row(
        "SELECT count(*) FROM archive_lifecycle_bootstrap_creates
         WHERE archive_id = ?1 AND create_state != 'created'",
        [archive_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if unresolved != 0 {
        return Err(EnclaveError::Conflict(
            "archive lifecycle witness cannot precede exact object reconciliation".into(),
        ));
    }
    let updated = conn.execute(
        "UPDATE archive_lifecycle_anchors
         SET revision = revision + 1, state = 'witness_prepared',
             witness_record_hash = ?3, witness_record_len = ?4,
             witness_record_bytes = ?5, witness_create_state = 'planned',
             witness_admission_revision = NULL,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE archive_id = ?1 AND revision = ?2 AND state = 'objects_prepared'",
        rusqlite::params![
            archive_id.as_bytes().as_slice(),
            i64::try_from(expected_revision)
                .map_err(|_| EnclaveError::Store("archive lifecycle revision overflow".into()))?,
            hash.as_slice(),
            i64::try_from(encoded_witness.len())
                .map_err(|_| EnclaveError::Store("archive lifecycle witness too large".into()))?,
            encoded_witness,
        ],
    )?;
    if updated != 1 {
        return Err(EnclaveError::Conflict(
            "archive lifecycle witness prepare lost its compare-and-swap".into(),
        ));
    }
    expected_revision
        .checked_add(1)
        .ok_or_else(|| EnclaveError::Store("archive lifecycle revision exhausted".into()))
}

fn admit_archive_create_conn(
    conn: &Connection,
    archive_id: ArchiveId,
    expected_revision: u64,
    artifact_ordinal: u32,
) -> Result<ActiveCreateAdmission> {
    let tx = conn.unchecked_transaction()?;
    lifecycle_archive_active_conn(&tx, archive_id)?;
    let anchor = lifecycle_anchor_conn(&tx, archive_id)?
        .ok_or_else(|| EnclaveError::Store("archive lifecycle anchor disappeared".into()))?;
    if anchor.revision != expected_revision || !anchor.state.admits_creates() {
        return Err(EnclaveError::Conflict(
            "archive lifecycle create admission is stale or frozen".into(),
        ));
    }
    let in_flight: i64 = tx.query_row(
        "SELECT
            (SELECT count(*) FROM archive_lifecycle_bootstrap_creates
             WHERE archive_id = ?1 AND admission_revision IS NOT NULL)
            +
            (SELECT count(*) FROM archive_lifecycle_anchors
             WHERE archive_id = ?1 AND witness_admission_revision IS NOT NULL)",
        [archive_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let (artifact_hash, existing_admission) = if artifact_ordinal == LIFECYCLE_WITNESS_ORDINAL {
        tx.query_row(
            "SELECT witness_record_hash, witness_admission_revision
             FROM archive_lifecycle_anchors
             WHERE archive_id = ?1 AND state IN ('witness_prepared','witnessed')",
            [archive_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?
        .ok_or_else(|| EnclaveError::Conflict("archive witness is not prepared".into()))?
    } else {
        tx.query_row(
            "SELECT ciphertext_hash, admission_revision
             FROM archive_lifecycle_bootstrap_creates
             WHERE archive_id = ?1 AND artifact_ordinal = ?2",
            rusqlite::params![
                archive_id.as_bytes().as_slice(),
                i64::from(artifact_ordinal)
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?
        .ok_or_else(|| EnclaveError::Conflict("archive artifact is not planned".into()))?
    };
    if let Some(existing_admission) = existing_admission {
        if in_flight != 1 || u64::try_from(existing_admission).ok() != Some(expected_revision) {
            return Err(EnclaveError::Conflict(
                "archive lifecycle has a different unreconciled create".into(),
            ));
        }
        let receipt = ActiveCreateAdmission::from_fresh_cas(
            &LifecyclePersistenceContext::validated(),
            archive_id,
            anchor.plan.attempt_id(),
            expected_revision,
            artifact_ordinal,
            fixed_32(artifact_hash)?,
        )
        .map_err(lifecycle_store_error)?;
        tx.commit()?;
        return Ok(receipt);
    }
    if in_flight != 0 {
        return Err(EnclaveError::Conflict(
            "archive lifecycle has a different unreconciled create".into(),
        ));
    }
    let admission_revision = expected_revision
        .checked_add(1)
        .ok_or_else(|| EnclaveError::Store("archive lifecycle revision exhausted".into()))?;
    let updated = tx.execute(
        "UPDATE archive_lifecycle_anchors
         SET revision = revision + 1,
             witness_admission_revision = CASE WHEN ?3 = 2 THEN revision + 1 ELSE witness_admission_revision END,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE archive_id = ?1 AND revision = ?2
           AND state IN ('objects_prepared','witness_prepared','witnessed')",
        rusqlite::params![
            archive_id.as_bytes().as_slice(),
            i64::try_from(expected_revision).map_err(|_| EnclaveError::Store("archive lifecycle revision overflow".into()))?,
            i64::from(artifact_ordinal),
        ],
    )?;
    if updated != 1 {
        return Err(EnclaveError::Conflict(
            "archive lifecycle create admission lost its compare-and-swap".into(),
        ));
    }
    if artifact_ordinal != LIFECYCLE_WITNESS_ORDINAL {
        let changed = tx.execute(
            "UPDATE archive_lifecycle_bootstrap_creates SET admission_revision = ?3
             WHERE archive_id = ?1 AND artifact_ordinal = ?2 AND admission_revision IS NULL",
            rusqlite::params![
                archive_id.as_bytes().as_slice(),
                i64::from(artifact_ordinal),
                i64::try_from(admission_revision).map_err(|_| EnclaveError::Store(
                    "archive lifecycle revision overflow".into()
                ))?,
            ],
        )?;
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "archive lifecycle create admission conflicts".into(),
            ));
        }
    }
    tx.commit()?;
    ActiveCreateAdmission::from_fresh_cas(
        &LifecyclePersistenceContext::validated(),
        archive_id,
        anchor.plan.attempt_id(),
        admission_revision,
        artifact_ordinal,
        fixed_32(artifact_hash)?,
    )
    .map_err(lifecycle_store_error)
}

fn reconcile_archive_create_conn(
    conn: &Connection,
    admission: &ActiveCreateAdmission,
    outcome: LifecycleCreateOutcome,
) -> Result<u64> {
    let state = match outcome {
        LifecycleCreateOutcome::Created | LifecycleCreateOutcome::AlreadyPresentExact => {
            ArtifactCreateState::Created
        }
        LifecycleCreateOutcome::OutcomeUnknown => ArtifactCreateState::OutcomeUnknown,
        LifecycleCreateOutcome::ConfirmedAbsent => ArtifactCreateState::ConfirmedAbsent,
    };
    let tx = conn.unchecked_transaction()?;
    let anchor = lifecycle_anchor_conn(&tx, admission.archive_id())?
        .ok_or_else(|| EnclaveError::Store("archive lifecycle anchor disappeared".into()))?;
    let frozen_offset = u64::from(anchor.state == ArchiveLifecycleState::DeletionFrozen);
    if anchor.plan.attempt_id() != admission.attempt_id()
        || anchor.revision != admission.revision().saturating_add(frozen_offset)
        || !matches!(
            anchor.state,
            ArchiveLifecycleState::ObjectsPrepared
                | ArchiveLifecycleState::WitnessPrepared
                | ArchiveLifecycleState::Witnessed
                | ArchiveLifecycleState::DeletionFrozen
        )
    {
        return Err(EnclaveError::Conflict(
            "archive lifecycle reconciliation is stale".into(),
        ));
    }
    if outcome == LifecycleCreateOutcome::OutcomeUnknown {
        let changed = if admission.artifact_ordinal() == LIFECYCLE_WITNESS_ORDINAL {
            tx.execute(
                "UPDATE archive_lifecycle_anchors SET witness_create_state = 'outcome_unknown'
                 WHERE archive_id = ?1 AND witness_admission_revision = ?2
                   AND witness_record_hash = ?3",
                rusqlite::params![
                    admission.archive_id().as_bytes().as_slice(),
                    i64::try_from(admission.revision()).map_err(|_| EnclaveError::Store(
                        "archive lifecycle revision overflow".into()
                    ))?,
                    admission.artifact_hash().as_slice(),
                ],
            )?
        } else {
            tx.execute(
                "UPDATE archive_lifecycle_bootstrap_creates SET create_state = 'outcome_unknown'
                 WHERE archive_id = ?1 AND bootstrap_attempt_id = ?2
                   AND artifact_ordinal = ?3 AND admission_revision = ?4
                   AND ciphertext_hash = ?5",
                rusqlite::params![
                    admission.archive_id().as_bytes().as_slice(),
                    admission.attempt_id().as_bytes().as_slice(),
                    i64::from(admission.artifact_ordinal()),
                    i64::try_from(admission.revision()).map_err(|_| EnclaveError::Store(
                        "archive lifecycle revision overflow".into()
                    ))?,
                    admission.artifact_hash().as_slice(),
                ],
            )?
        };
        if changed != 1 {
            return Err(EnclaveError::Conflict(
                "archive lifecycle ambiguous outcome conflicts".into(),
            ));
        }
        tx.commit()?;
        return Ok(anchor.revision);
    }
    let next_revision = anchor
        .revision
        .checked_add(1)
        .ok_or_else(|| EnclaveError::Store("archive lifecycle revision exhausted".into()))?;
    let changed = if admission.artifact_ordinal() == LIFECYCLE_WITNESS_ORDINAL {
        tx.execute(
            "UPDATE archive_lifecycle_anchors
             SET revision = revision + 1,
                 state = CASE
                     WHEN state = 'deletion_frozen' THEN state
                     WHEN ?3 = 'created' THEN 'witnessed'
                     ELSE state
                 END,
                 witness_create_state = ?3, witness_admission_revision = NULL,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE archive_id = ?1 AND revision = ?5
               AND witness_admission_revision = ?2 AND witness_record_hash = ?4
               AND state IN ('witness_prepared','witnessed','deletion_frozen')",
            rusqlite::params![
                admission.archive_id().as_bytes().as_slice(),
                i64::try_from(admission.revision()).map_err(|_| EnclaveError::Store(
                    "archive lifecycle revision overflow".into()
                ))?,
                artifact_state_db(state),
                admission.artifact_hash().as_slice(),
                i64::try_from(anchor.revision).map_err(|_| EnclaveError::Store(
                    "archive lifecycle revision overflow".into()
                ))?,
            ],
        )?
    } else {
        let create_changed = tx.execute(
            "UPDATE archive_lifecycle_bootstrap_creates
             SET create_state = ?4, admission_revision = NULL
             WHERE archive_id = ?1 AND bootstrap_attempt_id = ?2
               AND artifact_ordinal = ?3 AND admission_revision = ?5
               AND ciphertext_hash = ?6",
            rusqlite::params![
                admission.archive_id().as_bytes().as_slice(),
                admission.attempt_id().as_bytes().as_slice(),
                i64::from(admission.artifact_ordinal()),
                artifact_state_db(state),
                i64::try_from(admission.revision()).map_err(|_| EnclaveError::Store(
                    "archive lifecycle revision overflow".into()
                ))?,
                admission.artifact_hash().as_slice(),
            ],
        )?;
        if create_changed != 1 {
            return Err(EnclaveError::Conflict(
                "archive lifecycle artifact reconciliation conflicts".into(),
            ));
        }
        tx.execute(
            "UPDATE archive_lifecycle_anchors
             SET revision = revision + 1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE archive_id = ?1 AND revision = ?2",
            rusqlite::params![
                admission.archive_id().as_bytes().as_slice(),
                i64::try_from(anchor.revision).map_err(|_| EnclaveError::Store(
                    "archive lifecycle revision overflow".into()
                ))?,
            ],
        )?
    };
    if changed != 1 {
        return Err(EnclaveError::Conflict(
            "archive lifecycle reconciliation lost its compare-and-swap".into(),
        ));
    }
    tx.commit()?;
    Ok(next_revision)
}

fn freeze_archive_lifecycle_conn(
    conn: &Connection,
    archive_id: ArchiveId,
    expected_revision: u64,
    deletion_fence: ObjectId,
) -> Result<u64> {
    if deletion_fence.as_bytes() == &[0; 16] {
        return Err(EnclaveError::Store(
            "archive lifecycle deletion fence is invalid".into(),
        ));
    }
    let tx = conn.unchecked_transaction()?;
    let durable_fence = tx
        .query_row(
            "SELECT deletion_fence_id FROM archive_deletion_ledgers
             WHERE archive_id = ?1 AND state = 'tombstoned'",
            [archive_id.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| {
            EnclaveError::Conflict("archive lifecycle deletion is not tombstoned".into())
        })?;
    if fixed_16(durable_fence)? != *deletion_fence.as_bytes() {
        return Err(EnclaveError::Conflict(
            "archive lifecycle deletion fence changed".into(),
        ));
    }
    let updated = tx.execute(
        "UPDATE archive_lifecycle_anchors
         SET revision = revision + 1, state = 'deletion_frozen', deletion_fence = ?3,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE archive_id = ?1 AND revision = ?2
           AND state IN ('reserved','objects_prepared','witness_prepared','witnessed')",
        rusqlite::params![
            archive_id.as_bytes().as_slice(),
            i64::try_from(expected_revision)
                .map_err(|_| EnclaveError::Store("archive lifecycle revision overflow".into()))?,
            deletion_fence.as_bytes().as_slice(),
        ],
    )?;
    if updated != 1 {
        let existing = tx
            .query_row(
                "SELECT revision, deletion_fence FROM archive_lifecycle_anchors
                 WHERE archive_id = ?1 AND state = 'deletion_frozen'",
                [archive_id.as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        if let Some((revision, existing_fence)) = existing {
            if fixed_16(existing_fence)? == *deletion_fence.as_bytes() {
                let revision = u64::try_from(revision).map_err(|_| {
                    EnclaveError::Store("archive lifecycle revision is invalid".into())
                })?;
                tx.commit()?;
                return Ok(revision);
            }
        }
        return Err(EnclaveError::Conflict(
            "archive lifecycle freeze lost its compare-and-swap".into(),
        ));
    }
    let revision = expected_revision
        .checked_add(1)
        .ok_or_else(|| EnclaveError::Store("archive lifecycle revision exhausted".into()))?;
    tx.commit()?;
    Ok(revision)
}

fn lifecycle_role(value: i64) -> Result<ObjectRole> {
    match value {
        1 => Ok(ObjectRole::CheckpointChunkV3),
        2 => Ok(ObjectRole::WalSegmentV3),
        3 => Ok(ObjectRole::ExtentV3),
        4 => Ok(ObjectRole::MerkleNodeV3),
        5 => Ok(ObjectRole::RootV3),
        6 => Ok(ObjectRole::KeyRegistryV3),
        7 => Ok(ObjectRole::StagingV3),
        8 => Ok(ObjectRole::CheckpointManifestV3),
        9 => Ok(ObjectRole::WalCommitDescriptorV3),
        _ => Err(EnclaveError::Store(
            "archive lifecycle object role is invalid".into(),
        )),
    }
}

fn lifecycle_artifact_state(value: &str) -> Result<ArtifactCreateState> {
    match value {
        "planned" => Ok(ArtifactCreateState::Planned),
        "outcome_unknown" => Ok(ArtifactCreateState::OutcomeUnknown),
        "created" => Ok(ArtifactCreateState::Created),
        "confirmed_absent" => Ok(ArtifactCreateState::ConfirmedAbsent),
        _ => Err(EnclaveError::Store(
            "archive lifecycle create state is invalid".into(),
        )),
    }
}

fn lifecycle_create_ahead_conn(
    conn: &Connection,
    plan: BootstrapPlan,
) -> Result<Vec<PlannedArtifact>> {
    let mut statement = conn.prepare(
        "SELECT bootstrap_attempt_id, artifact_ordinal, canonical_key, object_id,
                object_role, ciphertext_hash, encoded_len, create_state,
                admission_revision
         FROM archive_lifecycle_bootstrap_creates
         WHERE archive_id = ?1
         ORDER BY bootstrap_attempt_id, artifact_ordinal, canonical_key",
    )?;
    let rows = statement.query_map([plan.archive_id().as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, Option<i64>>(8)?,
        ))
    })?;
    rows.map(|row| {
        let (
            attempt,
            ordinal,
            canonical_key,
            object_id,
            role,
            hash,
            encoded_len,
            state,
            admission_revision,
        ) = row?;
        if admission_revision.is_some() || state == "outcome_unknown" {
            return Err(EnclaveError::Conflict(
                "archive lifecycle has unresolved create work".into(),
            ));
        }
        let attempt =
            crate::archive_v3_lifecycle::BootstrapAttemptId::from_bytes(fixed_16(attempt)?)
                .map_err(lifecycle_store_error)?;
        let object_id = ObjectId::from_bytes(fixed_16(object_id)?);
        PlannedArtifact::new(
            plan.archive_id(),
            attempt,
            u32::try_from(ordinal)
                .map_err(|_| EnclaveError::Store("archive lifecycle ordinal is invalid".into()))?,
            crate::archive_v3::ObjectKey::from_validated_canonical(canonical_key, object_id),
            lifecycle_role(role)?,
            fixed_32(hash)?,
            usize::try_from(encoded_len).map_err(|_| {
                EnclaveError::Store("archive lifecycle encoded length is invalid".into())
            })?,
            lifecycle_artifact_state(&state)?,
        )
        .map_err(lifecycle_store_error)
    })
    .collect()
}

fn seal_archive_inventory_conn(
    conn: &Connection,
    archive_id: ArchiveId,
    expected_revision: u64,
    deletion_fence: ObjectId,
    durable_pages: &[DurableInventoryPage],
) -> Result<DeletionInventorySeal> {
    let pages = durable_pages
        .iter()
        .map(DurableInventoryPage::page)
        .collect::<Vec<_>>();
    let anchor = lifecycle_anchor_conn(conn, archive_id)?
        .ok_or_else(|| EnclaveError::Store("archive lifecycle anchor disappeared".into()))?;
    if anchor.state != ArchiveLifecycleState::DeletionFrozen || anchor.revision != expected_revision
    {
        return Err(EnclaveError::Conflict(
            "archive lifecycle inventory seal is stale".into(),
        ));
    }
    let persisted_fence = conn.query_row(
        "SELECT deletion_fence FROM archive_lifecycle_anchors WHERE archive_id = ?1",
        [archive_id.as_bytes().as_slice()],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    if fixed_16(persisted_fence)? != *deletion_fence.as_bytes() {
        return Err(EnclaveError::Conflict(
            "archive lifecycle inventory fence changed".into(),
        ));
    }
    if pages.is_empty() || pages.len() > MAX_LIFECYCLE_PAGES {
        return Err(EnclaveError::Store(
            "archive lifecycle inventory page count is invalid".into(),
        ));
    }
    let witness_unresolved: i64 = conn.query_row(
        "SELECT CASE
             WHEN witness_admission_revision IS NOT NULL THEN 1
             WHEN witness_create_state = 'outcome_unknown' THEN 1
             ELSE 0
         END
         FROM archive_lifecycle_anchors WHERE archive_id = ?1",
        [archive_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if witness_unresolved != 0 {
        return Err(EnclaveError::Conflict(
            "archive lifecycle witness create is unresolved".into(),
        ));
    }
    let create_ahead = lifecycle_create_ahead_conn(conn, anchor.plan)?;
    for planned in &create_ahead {
        let included = pages.iter().flat_map(|page| page.entries()).any(|entry| {
            entry.attempt_id() == planned.attempt_id()
                && entry.ordinal() == planned.ordinal()
                && entry.key() == planned.key()
                && entry.role() == planned.role()
                && entry.ciphertext_hash() == planned.ciphertext_hash()
                && entry.encoded_len() == planned.encoded_len()
                && entry.create_state() == planned.create_state()
        });
        if !included {
            return Err(EnclaveError::Store(
                "archive lifecycle inventory omitted create-ahead work".into(),
            ));
        }
    }
    let next_revision = expected_revision
        .checked_add(1)
        .ok_or_else(|| EnclaveError::Store("archive lifecycle revision exhausted".into()))?;
    let seal = DeletionInventorySeal::from_durable_pages(
        &LifecyclePersistenceContext::validated(),
        archive_id,
        deletion_fence,
        next_revision,
        durable_pages,
    )
    .map_err(lifecycle_store_error)?;
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "DELETE FROM archive_lifecycle_inventory_pages WHERE archive_id = ?1",
        [archive_id.as_bytes().as_slice()],
    )?;
    for page in pages {
        tx.execute(
            "INSERT INTO archive_lifecycle_inventory_pages
             (archive_id, page_ordinal, page_id, previous_hash, page_hash, encoded_len)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                archive_id.as_bytes().as_slice(),
                i64::from(page.page_ordinal()),
                page.page_id().as_bytes().as_slice(),
                page.previous_hash().as_slice(),
                page.page_hash().as_slice(),
                i64::try_from(page.encoded().len()).map_err(|_| EnclaveError::Store(
                    "archive lifecycle page length overflow".into()
                ))?,
            ],
        )?;
    }
    let updated = tx.execute(
        "UPDATE archive_lifecycle_anchors
         SET revision = revision + 1, state = 'inventory_sealed',
             inventory_page_count = ?3, inventory_artifact_count = ?4,
             inventory_terminal_hash = ?5, inventory_commitment = ?6,
             inventory_seal_revision = revision + 1,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE archive_id = ?1 AND revision = ?2 AND state = 'deletion_frozen'",
        rusqlite::params![
            archive_id.as_bytes().as_slice(),
            i64::try_from(expected_revision)
                .map_err(|_| EnclaveError::Store("archive lifecycle revision overflow".into()))?,
            i64::from(seal.page_count()),
            i64::from(seal.artifact_count()),
            seal.terminal_page_hash().as_slice(),
            seal.inventory_commitment().as_slice(),
        ],
    )?;
    if updated != 1 {
        return Err(EnclaveError::Conflict(
            "archive lifecycle inventory seal lost its compare-and-swap".into(),
        ));
    }
    tx.commit()?;
    Ok(seal)
}

fn load_sealed_archive_inventory_references_conn(
    conn: &Connection,
    expected: &DeletionInventorySeal,
) -> Result<Vec<InventoryPageReference>> {
    let row = conn
        .query_row(
            "SELECT inventory_seal_revision, state, deletion_fence, inventory_page_count,
                    inventory_artifact_count, inventory_terminal_hash,
                    inventory_commitment
             FROM archive_lifecycle_anchors WHERE archive_id = ?1",
            [expected.archive_id().as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            EnclaveError::Store("sealed archive lifecycle inventory disappeared".into())
        })?;
    let (revision, state, fence, page_count, artifact_count, terminal, commitment) = row;
    if !matches!(
        ArchiveLifecycleState::from_db(&state)?,
        ArchiveLifecycleState::InventorySealed | ArchiveLifecycleState::PhysicalComplete
    ) || u64::try_from(revision).ok() != Some(expected.revision())
        || fixed_16(fence)? != *expected.deletion_fence().as_bytes()
        || u32::try_from(page_count).ok() != Some(expected.page_count())
        || u32::try_from(artifact_count).ok() != Some(expected.artifact_count())
        || fixed_32(terminal)? != expected.terminal_page_hash()
        || fixed_32(commitment)? != expected.inventory_commitment()
    {
        return Err(EnclaveError::Conflict(
            "sealed archive lifecycle inventory commitment changed".into(),
        ));
    }
    let mut statement = conn.prepare(
        "SELECT page_ordinal, page_id, previous_hash, page_hash, encoded_len
         FROM archive_lifecycle_inventory_pages
         WHERE archive_id = ?1 ORDER BY page_ordinal",
    )?;
    let rows = statement.query_map([expected.archive_id().as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut references = Vec::new();
    let mut expected_previous = [0; 32];
    for row in rows {
        let (ordinal, page_id, previous_hash, page_hash, encoded_len) = row?;
        let reference = InventoryPageReference::from_persisted(
            &LifecyclePersistenceContext::validated(),
            expected.archive_id(),
            u32::try_from(ordinal).map_err(|_| {
                EnclaveError::Store("archive lifecycle page ordinal is invalid".into())
            })?,
            ObjectId::from_bytes(fixed_16(page_id)?),
            fixed_32_allow_zero(previous_hash)?,
            fixed_32(page_hash)?,
            u32::try_from(encoded_len).map_err(|_| {
                EnclaveError::Store("archive lifecycle page length is invalid".into())
            })?,
        )
        .map_err(lifecycle_store_error)?;
        if usize::try_from(reference.page_ordinal()).ok() != Some(references.len())
            || reference.previous_hash() != expected_previous
        {
            return Err(EnclaveError::Store(
                "sealed archive lifecycle page reference was tampered".into(),
            ));
        }
        expected_previous = reference.page_hash();
        references.push(reference);
    }
    if u32::try_from(references.len()).ok() != Some(expected.page_count())
        || expected_previous != expected.terminal_page_hash()
    {
        return Err(EnclaveError::Conflict(
            "sealed archive lifecycle inventory does not match its anchor".into(),
        ));
    }
    Ok(references)
}

fn recover_archive_deletion_lifecycle_conn(
    conn: &Connection,
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
) -> Result<RecoveredDeletionLifecycle> {
    let tx = conn.unchecked_transaction()?;
    let row = tx
        .query_row(
            "SELECT state, revision, inventory_seal_revision, deletion_fence,
                    inventory_page_count, inventory_artifact_count,
                    inventory_terminal_hash, inventory_commitment,
                    physical_provider_drain_commitment
             FROM archive_lifecycle_anchors WHERE archive_id = ?1",
            [archive_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| EnclaveError::Store("archive lifecycle anchor disappeared".into()))?;
    let (
        state,
        anchor_revision,
        seal_revision,
        persisted_fence,
        page_count,
        artifact_count,
        terminal_hash,
        inventory_hash,
        drain_hash,
    ) = row;
    let state = ArchiveLifecycleState::from_db(&state)?;
    if !matches!(
        state,
        ArchiveLifecycleState::InventorySealed | ArchiveLifecycleState::PhysicalComplete
    ) || fixed_16(persisted_fence)? != *deletion_fence.as_bytes()
    {
        return Err(EnclaveError::Conflict(
            "archive lifecycle sealed recovery authority changed".into(),
        ));
    }
    let seal_revision = u64::try_from(seal_revision)
        .map_err(|_| EnclaveError::Store("archive lifecycle seal revision is invalid".into()))?;
    let anchor_revision = u64::try_from(anchor_revision)
        .map_err(|_| EnclaveError::Store("archive lifecycle revision is invalid".into()))?;
    let seal = DeletionInventorySeal::from_persisted_anchor(
        &LifecyclePersistenceContext::validated(),
        archive_id,
        deletion_fence,
        seal_revision,
        u32::try_from(page_count)
            .map_err(|_| EnclaveError::Store("archive lifecycle page count is invalid".into()))?,
        u32::try_from(artifact_count).map_err(|_| {
            EnclaveError::Store("archive lifecycle artifact count is invalid".into())
        })?,
        fixed_32(terminal_hash)?,
        fixed_32(inventory_hash)?,
    )
    .map_err(lifecycle_store_error)?;
    // Validate the retained exact-name reference chain in the same SQLite
    // snapshot that minted the recovered seal.
    load_sealed_archive_inventory_references_conn(&tx, &seal)?;
    let physical_completion = match state {
        ArchiveLifecycleState::InventorySealed => {
            if anchor_revision != seal_revision || drain_hash.is_some() {
                return Err(EnclaveError::Store(
                    "sealed archive lifecycle revision changed".into(),
                ));
            }
            None
        }
        ArchiveLifecycleState::PhysicalComplete => {
            if Some(anchor_revision) != seal_revision.checked_add(1) {
                return Err(EnclaveError::Store(
                    "physical archive lifecycle revision changed".into(),
                ));
            }
            let drain = fixed_32(drain_hash.ok_or_else(|| {
                EnclaveError::Store("physical provider drain commitment disappeared".into())
            })?)?;
            let physical = PhysicalDeletionReceipt::from_persisted_control(
                &LifecyclePersistenceContext::validated(),
                seal,
                drain,
            )
            .map_err(lifecycle_store_error)?;
            Some(
                DurablePhysicalCompletion::from_persisted(
                    &LifecyclePersistenceContext::validated(),
                    physical,
                    anchor_revision,
                )
                .map_err(lifecycle_store_error)?,
            )
        }
        _ => unreachable!("state was checked above"),
    };
    let recovered = RecoveredDeletionLifecycle::from_persisted(
        &LifecyclePersistenceContext::validated(),
        seal,
        physical_completion,
    )
    .map_err(lifecycle_store_error)?;
    tx.commit()?;
    Ok(recovered)
}

fn mark_archive_physical_complete_conn(
    conn: &Connection,
    completion: &PhysicalDeletionReceipt,
) -> Result<DurablePhysicalCompletion> {
    let seal = completion.seal();
    let updated = conn.execute(
        "UPDATE archive_lifecycle_anchors
         SET revision = revision + 1, state = 'physical_complete',
             physical_provider_drain_commitment = ?3,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE archive_id = ?1 AND state = 'inventory_sealed'
           AND inventory_seal_revision = ?2 AND deletion_fence = ?4
           AND inventory_commitment = ?5 AND inventory_page_count = ?6
           AND inventory_terminal_hash = ?7",
        rusqlite::params![
            seal.archive_id().as_bytes().as_slice(),
            i64::try_from(seal.revision()).map_err(|_| {
                EnclaveError::Store("archive lifecycle revision overflow".into())
            })?,
            completion.provider_drain_commitment().as_slice(),
            seal.deletion_fence().as_bytes().as_slice(),
            seal.inventory_commitment().as_slice(),
            i64::from(seal.page_count()),
            seal.terminal_page_hash().as_slice(),
        ],
    )?;
    if updated > 1 {
        return Err(EnclaveError::Store(
            "archive lifecycle physical completion affected multiple rows".into(),
        ));
    }
    let exact_revision: Option<i64> = conn
        .query_row(
            "SELECT revision FROM archive_lifecycle_anchors
         WHERE archive_id = ?1 AND state = 'physical_complete'
           AND inventory_seal_revision = ?2
           AND physical_provider_drain_commitment = ?3
           AND deletion_fence = ?4 AND inventory_commitment = ?5
           AND inventory_page_count = ?6 AND inventory_terminal_hash = ?7",
            rusqlite::params![
                seal.archive_id().as_bytes().as_slice(),
                i64::try_from(seal.revision()).map_err(|_| {
                    EnclaveError::Store("archive lifecycle revision overflow".into())
                })?,
                completion.provider_drain_commitment().as_slice(),
                seal.deletion_fence().as_bytes().as_slice(),
                seal.inventory_commitment().as_slice(),
                i64::from(seal.page_count()),
                seal.terminal_page_hash().as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    let control_revision = exact_revision.ok_or_else(|| {
        EnclaveError::Conflict("archive lifecycle physical completion changed".into())
    })?;
    DurablePhysicalCompletion::from_persisted(
        &LifecyclePersistenceContext::validated(),
        *completion,
        u64::try_from(control_revision)
            .map_err(|_| EnclaveError::Store("archive lifecycle revision is invalid".into()))?,
    )
    .map_err(lifecycle_store_error)
}

/// Erase only retry payloads after both the witness/provider physical receipt
/// and the page-store's exact absence receipt match the retained seal. The
/// content-free anchor, seal, page IDs/hashes, and deletion fence remain as a
/// permanent no-resurrection tombstone.
fn erase_archive_lifecycle_payload_conn(
    conn: &Connection,
    completion: &DurablePhysicalCompletion,
    erased_pages: ErasedInventoryPages,
) -> Result<()> {
    if !erased_pages.matches(*completion) {
        return Err(EnclaveError::Conflict(
            "archive lifecycle erased-page receipt changed".into(),
        ));
    }
    let physical = completion.physical_receipt();
    let seal = physical.seal();
    let updated = conn.execute(
        "UPDATE archive_lifecycle_anchors
         SET wrapped_registry_bytes = NULL, root_envelope_bytes = NULL,
             witness_record_bytes = NULL, witness_create_state = NULL,
             witness_admission_revision = NULL, payload_erased = 1,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE archive_id = ?1 AND state = 'physical_complete'
           AND inventory_seal_revision = ?2
           AND physical_provider_drain_commitment = ?3
           AND deletion_fence = ?4 AND inventory_commitment = ?5
           AND payload_erased = 0",
        rusqlite::params![
            seal.archive_id().as_bytes().as_slice(),
            i64::try_from(seal.revision()).map_err(|_| {
                EnclaveError::Store("archive lifecycle revision overflow".into())
            })?,
            physical.provider_drain_commitment().as_slice(),
            seal.deletion_fence().as_bytes().as_slice(),
            seal.inventory_commitment().as_slice(),
        ],
    )?;
    if updated == 1 {
        return Ok(());
    }
    let exact: i64 = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM archive_lifecycle_anchors
             WHERE archive_id = ?1 AND state = 'physical_complete'
               AND inventory_seal_revision = ?2
               AND physical_provider_drain_commitment = ?3
               AND deletion_fence = ?4 AND inventory_commitment = ?5
               AND payload_erased = 1
               AND wrapped_registry_bytes IS NULL
               AND root_envelope_bytes IS NULL AND witness_record_bytes IS NULL
         )",
        rusqlite::params![
            seal.archive_id().as_bytes().as_slice(),
            i64::try_from(seal.revision()).map_err(|_| {
                EnclaveError::Store("archive lifecycle revision overflow".into())
            })?,
            physical.provider_drain_commitment().as_slice(),
            seal.deletion_fence().as_bytes().as_slice(),
            seal.inventory_commitment().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if exact == 1 {
        Ok(())
    } else {
        Err(EnclaveError::Conflict(
            "archive lifecycle payload erasure changed".into(),
        ))
    }
}

fn archive_binding_conn(conn: &Connection, user_id: &str) -> Result<Option<ArchiveBinding>> {
    conn.query_row(
        "SELECT archive_id FROM archive_bindings WHERE user_id = ?1",
        [user_id],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()?
    .map(archive_id_from_blob)
    .transpose()
    .map(|binding| binding.map(|archive_id| ArchiveBinding { archive_id }))
}

fn archive_deletion_ledger_conn(
    conn: &Connection,
    user_id: &str,
) -> Result<Option<ArchiveDeletionLedger>> {
    let row = conn
        .query_row(
            "SELECT b.archive_id, b.state, b.tombstoned_at,
                    l.state, l.deletion_fence_id, l.inventory_format_version,
                    l.tombstoned_at,
                    l.archive_object_cursor, l.key_registry_cursor,
                    l.legacy_generation_cursor, l.media_inventory_cursor,
                    l.legacy_rebind_fence_object_name
             FROM archive_bindings b
             JOIN archive_deletion_ledgers l ON l.archive_id = b.archive_id
             WHERE b.user_id = ?1",
            [user_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            archive_id,
            binding_state,
            binding_tombstoned_at,
            state,
            deletion_fence_id,
            inventory_format_version,
            ledger_tombstoned_at,
            archive_object_cursor,
            key_registry_cursor,
            legacy_generation_cursor,
            media_inventory_cursor,
            legacy_rebind_fence_object_name,
        )| {
            let binding_state = ArchiveDeletionState::from_db(&binding_state)?;
            let state = ArchiveDeletionState::from_db(&state)?;
            if binding_state != state {
                return Err(EnclaveError::Store(
                    "archive binding and deletion ledger states disagree".into(),
                ));
            }
            if inventory_format_version != 1 {
                return Err(EnclaveError::Store(
                    "unsupported archive deletion inventory format".into(),
                ));
            }
            let deletion_fence_id = deletion_fence_id.map(archive_id_from_blob).transpose()?;
            match (state, deletion_fence_id) {
                (ArchiveDeletionState::ActiveLegacy, None)
                | (ArchiveDeletionState::Tombstoned, Some(_)) => {}
                (ArchiveDeletionState::ActiveLegacy, Some(_)) => {
                    return Err(EnclaveError::Store(
                        "active archive ledger has a deletion fence".into(),
                    ));
                }
                (ArchiveDeletionState::Tombstoned, None) => {
                    return Err(EnclaveError::Store(
                        "tombstoned archive ledger is missing its deletion fence".into(),
                    ));
                }
            }
            let timestamps_match_state = match state {
                ArchiveDeletionState::ActiveLegacy => {
                    binding_tombstoned_at.is_none() && ledger_tombstoned_at.is_none()
                }
                ArchiveDeletionState::Tombstoned => {
                    binding_tombstoned_at
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
                        && ledger_tombstoned_at
                            .as_deref()
                            .is_some_and(|value| !value.is_empty())
                }
            };
            if !timestamps_match_state {
                return Err(EnclaveError::Store(
                    "archive tombstone timestamps disagree with state".into(),
                ));
            }
            if let Some(fence_name) = legacy_rebind_fence_object_name.as_deref() {
                if !crate::store::is_canonical_identity_rebind_fence_object_name(fence_name) {
                    return Err(EnclaveError::Store(
                        "invalid archived rebind fence name".into(),
                    ));
                }
            }
            Ok(ArchiveDeletionLedger {
                binding: ArchiveBinding {
                    archive_id: archive_id_from_blob(archive_id)?,
                },
                state,
                deletion_fence_id,
                archive_object_cursor: checked_archive_deletion_cursor(archive_object_cursor)?,
                key_registry_cursor: checked_archive_deletion_cursor(key_registry_cursor)?,
                legacy_generation_cursor: checked_archive_deletion_cursor(
                    legacy_generation_cursor,
                )?,
                media_inventory_cursor: checked_archive_deletion_cursor(media_inventory_cursor)?,
                legacy_rebind_fence_object_name,
            })
        },
    )
    .transpose()
}

fn validate_active_archive_binding_conn(
    conn: &Connection,
    user_id: &str,
) -> Result<ArchiveBinding> {
    let ledger = archive_deletion_ledger_conn(conn, user_id)?.ok_or_else(|| {
        EnclaveError::Store("active account is missing its archive ledger".into())
    })?;
    if ledger.state != ArchiveDeletionState::ActiveLegacy || ledger.deletion_fence_id.is_some() {
        return Err(EnclaveError::Auth("account archive is inactive".into()));
    }
    Ok(ledger.binding)
}

/// Revalidate every local precondition for a legacy-ID migration. Callers do
/// this only after holding both Store lifecycle gates, and repeat it in the
/// final transaction after provider work. The expected random binding makes a
/// stale preliminary read fail closed instead of moving a different archive.
fn validate_archive_rebind_conn(
    conn: &Connection,
    google_sub: &str,
    old_user_id: &str,
    stable_user_id: &str,
    expected_binding: ArchiveBinding,
) -> Result<()> {
    if is_deleted_user_conn(conn, stable_user_id)? {
        return Err(EnclaveError::Auth("account deleted".into()));
    }
    let source = conn
        .query_row(
            "SELECT id, status FROM users WHERE google_sub = ?1",
            [google_sub],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    match source {
        Some((id, status)) if id == old_user_id && status == "active" => {}
        Some((id, _)) if id != old_user_id => {
            return Err(EnclaveError::Conflict(
                "canonical identity migration source changed".into(),
            ));
        }
        _ => return Err(EnclaveError::Auth("account inactive".into())),
    }
    if validate_active_archive_binding_conn(conn, old_user_id)? != expected_binding {
        return Err(EnclaveError::Conflict(
            "canonical identity migration archive changed".into(),
        ));
    }
    if archive_binding_conn(conn, stable_user_id)?.is_some() {
        return Err(EnclaveError::Conflict(
            "canonical identity migration has a conflicting archive binding".into(),
        ));
    }
    let target_user_exists: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)",
        [stable_user_id],
        |row| row.get(0),
    )?;
    if target_user_exists != 0 {
        return Err(EnclaveError::Conflict(
            "canonical identity migration target account already exists".into(),
        ));
    }
    Ok(())
}

type IdentityRebindRow = (
    String,
    String,
    String,
    String,
    Vec<u8>,
    String,
    String,
    i64,
    Option<i64>,
    Vec<u8>,
    String,
);

fn identity_rebind_operation_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<IdentityRebindRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn decode_identity_rebind_operation(row: IdentityRebindRow) -> Result<IdentityRebindOperation> {
    let (
        operation_id,
        google_sub,
        old_user_id,
        stable_user_id,
        archive_id,
        old_object_name,
        stable_object_name,
        source_base_generation,
        source_generation,
        source_commitment,
        stage,
    ) = row;
    if !operation_id.starts_with("rebind_") || operation_id.len() != 71 || google_sub.is_empty() {
        return Err(EnclaveError::Store(
            "invalid persisted identity rebind operation".into(),
        ));
    }
    validate_user_id(&old_user_id)?;
    validate_user_id(&stable_user_id)?;
    if old_user_id == stable_user_id
        || old_object_name != format!("indexes/{old_user_id}.db.enc")
        || stable_object_name != format!("indexes/{stable_user_id}.db.enc")
        || source_base_generation < 0
    {
        return Err(EnclaveError::Store(
            "invalid persisted identity rebind namespace".into(),
        ));
    }
    let source_commitment: [u8; 32] = source_commitment
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Store("invalid rebind source commitment".into()))?;
    let stage = IdentityRebindStage::from_db(&stage)?;
    if (matches!(
        stage,
        IdentityRebindStage::Prepared | IdentityRebindStage::SourceFreezing
    ) && source_generation.is_some())
        || (stage > IdentityRebindStage::Prepared
            && !matches!(
                stage,
                IdentityRebindStage::SourceFreezing
                    | IdentityRebindStage::DeletionPending
                    | IdentityRebindStage::DeletionReconciled
            )
            && source_generation.is_none_or(|generation| generation <= 0))
    {
        return Err(EnclaveError::Store(
            "identity rebind generation disagrees with stage".into(),
        ));
    }
    Ok(IdentityRebindOperation {
        operation_id,
        google_sub,
        old_user_id,
        stable_user_id,
        binding: ArchiveBinding {
            archive_id: archive_id_from_blob(archive_id)?,
        },
        old_object_name,
        stable_object_name,
        source_base_generation,
        source_generation,
        source_commitment,
        stage,
    })
}

const IDENTITY_REBIND_SELECT: &str =
    "SELECT operation_id, google_sub, old_user_id, stable_user_id, archive_id,
            old_object_name, stable_object_name, source_base_generation,
            source_generation, source_commitment, stage
     FROM identity_rebind_operations";

fn identity_rebind_operation_for_subject_conn(
    conn: &Connection,
    google_sub: &str,
) -> Result<Option<IdentityRebindOperation>> {
    conn.query_row(
        &format!("{IDENTITY_REBIND_SELECT} WHERE google_sub = ?1"),
        [google_sub],
        identity_rebind_operation_from_row,
    )
    .optional()?
    .map(decode_identity_rebind_operation)
    .transpose()
}

fn identity_rebind_operation_for_user_conn(
    conn: &Connection,
    user_id: &str,
) -> Result<Option<IdentityRebindOperation>> {
    conn.query_row(
        &format!("{IDENTITY_REBIND_SELECT} WHERE old_user_id = ?1 OR stable_user_id = ?1"),
        [user_id],
        identity_rebind_operation_from_row,
    )
    .optional()?
    .map(decode_identity_rebind_operation)
    .transpose()
}

fn pending_identity_rebind_operations_conn(
    conn: &Connection,
    limit: i64,
) -> Result<Vec<IdentityRebindOperation>> {
    let mut statement = conn.prepare(&format!(
        "{IDENTITY_REBIND_SELECT}
         WHERE stage NOT IN ('committed', 'deletion_pending', 'deletion_reconciled')
           AND (
             stage IN ('source_freezing', 'stable_writing')
             OR EXISTS (
               SELECT 1 FROM users
               WHERE users.google_sub = identity_rebind_operations.google_sub
                 AND users.id = identity_rebind_operations.old_user_id
                 AND users.status = 'active'
             )
           )
         ORDER BY updated_at, operation_id
         LIMIT ?1"
    ))?;
    let rows = statement
        .query_map([limit], identity_rebind_operation_from_row)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(decode_identity_rebind_operation)
        .collect()
}

#[allow(
    clippy::too_many_arguments,
    reason = "exact durable rebind authority is intentionally passed field-by-field"
)]
fn prepare_identity_rebind_conn(
    conn: &Connection,
    operation_id: &str,
    google_sub: &str,
    old_user_id: &str,
    stable_user_id: &str,
    fence_object_name: &str,
    binding: ArchiveBinding,
    source: &IdentityRebindSource,
) -> Result<IdentityRebindOperation> {
    if !crate::store::is_canonical_identity_rebind_fence_object_name(fence_object_name) {
        return Err(EnclaveError::Store(
            "identity rebind fence name is not canonical".into(),
        ));
    }
    validate_archive_rebind_conn(conn, google_sub, old_user_id, stable_user_id, binding)?;
    let old_object_name = format!("indexes/{old_user_id}.db.enc");
    let stable_object_name = format!("indexes/{stable_user_id}.db.enc");
    conn.execute(
        "INSERT OR IGNORE INTO identity_rebind_operations
         (operation_id, google_sub, old_user_id, stable_user_id, archive_id,
          old_object_name, stable_object_name, source_base_generation,
          source_commitment, stage)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'prepared')",
        rusqlite::params![
            operation_id,
            google_sub,
            old_user_id,
            stable_user_id,
            binding.archive_id.as_bytes().as_slice(),
            old_object_name,
            stable_object_name,
            source.base_generation,
            source.commitment.as_slice(),
        ],
    )?;
    let ledger_updated = conn.execute(
        "UPDATE archive_deletion_ledgers
         SET legacy_rebind_fence_object_name = ?2,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE archive_id = ?1
           AND (legacy_rebind_fence_object_name IS NULL
                OR legacy_rebind_fence_object_name = ?2)",
        rusqlite::params![binding.archive_id.as_bytes().as_slice(), fence_object_name],
    )?;
    if ledger_updated != 1 {
        return Err(EnclaveError::Conflict(
            "identity rebind archive fence inventory conflicts".into(),
        ));
    }
    let operation = identity_rebind_operation_for_subject_conn(conn, google_sub)?
        .ok_or_else(|| EnclaveError::Store("identity rebind prepare disappeared".into()))?;
    if operation.old_user_id != old_user_id
        || operation.stable_user_id != stable_user_id
        || operation.binding != binding
        || operation.source_base_generation != source.base_generation
        || operation.source_commitment != source.commitment
        || operation.old_object_name != old_object_name
        || operation.stable_object_name != stable_object_name
    {
        return Err(EnclaveError::Conflict(
            "conflicting durable identity rebind operation".into(),
        ));
    }
    Ok(operation)
}

fn advance_identity_rebind_conn(
    conn: &Connection,
    operation: &IdentityRebindOperation,
    next_stage: IdentityRebindStage,
    source_generation: Option<i64>,
) -> Result<IdentityRebindOperation> {
    let current = identity_rebind_operation_for_subject_conn(conn, &operation.google_sub)?
        .ok_or_else(|| EnclaveError::Store("identity rebind operation disappeared".into()))?;
    if current.operation_id != operation.operation_id
        || current.old_user_id != operation.old_user_id
        || current.stable_user_id != operation.stable_user_id
        || current.binding != operation.binding
        || current.source_commitment != operation.source_commitment
    {
        return Err(EnclaveError::Conflict(
            "identity rebind authority changed".into(),
        ));
    }
    if current.stage >= next_stage {
        return Ok(current);
    }
    if next_stage <= current.stage {
        return Err(EnclaveError::Conflict(
            "identity rebind stage cannot move backward".into(),
        ));
    }
    let generation = source_generation.or(current.source_generation);
    if next_stage > IdentityRebindStage::Prepared
        && !matches!(
            next_stage,
            IdentityRebindStage::SourceFreezing
                | IdentityRebindStage::DeletionPending
                | IdentityRebindStage::DeletionReconciled
        )
        && generation.is_none_or(|generation| generation <= 0)
    {
        return Err(EnclaveError::Store(
            "identity rebind stage requires a source generation".into(),
        ));
    }
    conn.execute(
        "UPDATE identity_rebind_operations
         SET stage = ?2, source_generation = ?3,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE operation_id = ?1",
        rusqlite::params![operation.operation_id, next_stage.as_db(), generation],
    )?;
    identity_rebind_operation_for_subject_conn(conn, &operation.google_sub)?
        .ok_or_else(|| EnclaveError::Store("identity rebind operation disappeared".into()))
}

fn rebase_identity_rebind_source_conn(
    conn: &Connection,
    operation: &IdentityRebindOperation,
    source: &IdentityRebindSource,
) -> Result<IdentityRebindOperation> {
    let current = identity_rebind_operation_for_subject_conn(conn, &operation.google_sub)?
        .ok_or_else(|| EnclaveError::Store("identity rebind operation disappeared".into()))?;
    if current.operation_id != operation.operation_id
        || current.old_user_id != operation.old_user_id
        || current.stable_user_id != operation.stable_user_id
        || current.binding != operation.binding
        || current.stage != IdentityRebindStage::SourceFreezing
        || source.source_generation <= current.source_base_generation
    {
        return Err(EnclaveError::Conflict(
            "identity rebind source cannot be rebased".into(),
        ));
    }
    conn.execute(
        "UPDATE identity_rebind_operations
         SET source_base_generation = ?2, source_commitment = ?3,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE operation_id = ?1 AND stage = 'source_freezing'",
        rusqlite::params![
            operation.operation_id,
            source.source_generation,
            source.commitment.as_slice(),
        ],
    )?;
    identity_rebind_operation_for_subject_conn(conn, &operation.google_sub)?
        .ok_or_else(|| EnclaveError::Store("identity rebind operation disappeared".into()))
}

fn claim_identity_rebind_deletion_conn(conn: &Connection, user_id: &str) -> Result<bool> {
    let Some(operation) = identity_rebind_operation_for_user_conn(conn, user_id)? else {
        return Ok(true);
    };
    if matches!(
        operation.stage,
        IdentityRebindStage::SourceFreezing | IdentityRebindStage::StableWriting
    ) {
        return Ok(false);
    }
    let claimed = advance_identity_rebind_conn(
        conn,
        &operation,
        IdentityRebindStage::DeletionPending,
        operation.source_generation,
    )?;
    Ok(claimed.stage >= IdentityRebindStage::DeletionPending)
}

/// Insert one random binding plus its inactive deletion-ledger row in the
/// caller's transaction. Existing same-user state is idempotently validated;
/// a random ID owned by another user consumes one bounded retry.
fn create_active_archive_binding_with_candidates<F>(
    conn: &Connection,
    user_id: &str,
    mut next_candidate: F,
) -> Result<ArchiveBinding>
where
    F: FnMut() -> [u8; 16],
{
    if archive_binding_conn(conn, user_id)?.is_some() {
        return validate_active_archive_binding_conn(conn, user_id);
    }
    for _ in 0..MAX_ARCHIVE_ID_CANDIDATES {
        let candidate = next_candidate();
        if candidate == [0; 16] {
            continue;
        }
        let proposed = ArchiveId::from_bytes(candidate);
        let retained_or_live_ledger: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM archive_deletion_ledgers WHERE archive_id = ?1)",
            [proposed.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if retained_or_live_ledger != 0 {
            continue;
        }
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO archive_bindings (user_id, archive_id, state)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                user_id,
                proposed.as_bytes().as_slice(),
                ArchiveDeletionState::ActiveLegacy.as_db()
            ],
        )?;
        if inserted == 0 {
            if archive_binding_conn(conn, user_id)?.is_some() {
                return validate_active_archive_binding_conn(conn, user_id);
            }
            let owned_elsewhere: i64 = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM archive_bindings WHERE archive_id = ?1)",
                [proposed.as_bytes().as_slice()],
                |row| row.get(0),
            )?;
            if owned_elsewhere != 0 {
                continue;
            }
            return Err(EnclaveError::Store(
                "archive binding insertion was ignored without an owner".into(),
            ));
        }
        conn.execute(
            "INSERT INTO archive_deletion_ledgers (archive_id, state)
             VALUES (?1, ?2)",
            rusqlite::params![
                proposed.as_bytes().as_slice(),
                ArchiveDeletionState::ActiveLegacy.as_db()
            ],
        )?;
        return validate_active_archive_binding_conn(conn, user_id);
    }
    Err(EnclaveError::Conflict(
        "opaque archive identifier allocation exhausted".into(),
    ))
}

fn create_active_archive_binding_conn(conn: &Connection, user_id: &str) -> Result<ArchiveBinding> {
    create_active_archive_binding_with_candidates(conn, user_id, || *ArchiveId::random().as_bytes())
}

/// Establish the only enabled archive-v3 deletion transition.  The random
/// fence and any future opaque cursors remain in the encrypted ledger even
/// after the ordinary identity rows are removed.
fn tombstone_archive_deletion_ledger_conn(
    conn: &Connection,
    user_id: &str,
    fence_object_name: &str,
) -> Result<ArchiveDeletionLedger> {
    if !crate::store::is_canonical_identity_rebind_fence_object_name(fence_object_name) {
        return Err(EnclaveError::Store(
            "archive deletion fence name is not canonical".into(),
        ));
    }
    let binding = archive_binding_conn(conn, user_id)?.ok_or_else(|| {
        EnclaveError::Store("refusing identity deletion without an archive binding".into())
    })?;
    let state: String = conn.query_row(
        "SELECT state FROM archive_bindings WHERE user_id = ?1",
        [user_id],
        |row| row.get(0),
    )?;
    match ArchiveDeletionState::from_db(&state)? {
        ArchiveDeletionState::ActiveLegacy => {
            let fence = random_nonzero_archive_id()?;
            let updated = conn.execute(
                "UPDATE archive_bindings
                 SET state = 'tombstoned', tombstoned_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE user_id = ?1 AND state = 'active_legacy'",
                [user_id],
            )?;
            if updated != 1 {
                return Err(EnclaveError::Conflict(
                    "archive deletion fence changed concurrently".into(),
                ));
            }
            let updated = conn.execute(
                "UPDATE archive_deletion_ledgers
                 SET state = 'tombstoned', deletion_fence_id = ?2,
                     legacy_rebind_fence_object_name = COALESCE(
                         legacy_rebind_fence_object_name, ?3
                     ),
                     tombstoned_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE archive_id = ?1 AND state = 'active_legacy'
                   AND (legacy_rebind_fence_object_name IS NULL
                        OR legacy_rebind_fence_object_name = ?3)",
                rusqlite::params![
                    binding.archive_id.as_bytes().as_slice(),
                    fence.as_bytes().as_slice(),
                    fence_object_name,
                ],
            )?;
            if updated != 1 {
                return Err(EnclaveError::Store(
                    "archive deletion ledger is missing or inconsistent".into(),
                ));
            }
        }
        ArchiveDeletionState::Tombstoned => {}
    }
    let ledger = archive_deletion_ledger_conn(conn, user_id)?
        .ok_or_else(|| EnclaveError::Store("archive deletion ledger disappeared".into()))?;
    if ledger.binding != binding || ledger.state != ArchiveDeletionState::Tombstoned {
        return Err(EnclaveError::Store(
            "archive deletion tombstone is inconsistent".into(),
        ));
    }
    let fence = ledger
        .deletion_fence_id
        .ok_or_else(|| EnclaveError::Store("archive deletion fence disappeared".into()))?;
    // If this archive has opted into the inactive lifecycle ledger, close its
    // create-admission state in this same control-store transaction as the
    // account/binding tombstone. In-flight admissions remain reconcilable, but
    // no concurrent or restarted caller can obtain a new provider admission.
    conn.execute(
        "UPDATE archive_lifecycle_anchors
         SET revision = revision + 1, state = 'deletion_frozen', deletion_fence = ?2,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE archive_id = ?1
           AND state IN ('reserved','objects_prepared','witness_prepared','witnessed')",
        rusqlite::params![
            binding.archive_id.as_bytes().as_slice(),
            fence.as_bytes().as_slice(),
        ],
    )?;
    let lifecycle: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT state, deletion_fence FROM archive_lifecycle_anchors
             WHERE archive_id = ?1",
            [binding.archive_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((state, lifecycle_fence)) = lifecycle {
        if !matches!(
            ArchiveLifecycleState::from_db(&state)?,
            ArchiveLifecycleState::DeletionFrozen
                | ArchiveLifecycleState::InventorySealed
                | ArchiveLifecycleState::PhysicalComplete
        ) || fixed_16(lifecycle_fence)? != *fence.as_bytes()
        {
            return Err(EnclaveError::Conflict(
                "archive lifecycle freeze conflicts with deletion tombstone".into(),
            ));
        }
    }
    Ok(ledger)
}

/// Backfill legacy identities once while the encrypted control database is
/// loaded. Archive IDs are generated independently for every canonical user;
/// they are never derived from, logged with, or exposed alongside an identity.
fn backfill_archive_bindings_conn(conn: &Connection) -> Result<usize> {
    let tx = conn.unchecked_transaction()?;
    let user_ids = {
        let mut statement = tx.prepare(
            "SELECT id FROM users
             WHERE NOT EXISTS (SELECT 1 FROM archive_bindings b WHERE b.user_id = users.id)
             ORDER BY id",
        )?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows
    };
    for user_id in &user_ids {
        create_active_archive_binding_conn(&tx, user_id)?;
    }
    tx.commit()?;
    Ok(user_ids.len())
}

/// Remove identity/accounting state and leave only a stable, non-content
/// tombstone. Returning Google credentials can then be denied instead of
/// recreating the just-deleted account.
fn delete_user_identity_conn(
    conn: &Connection,
    user_id: &str,
    fence_object_name: &str,
) -> Result<AccountDeletionOperation> {
    let tx = conn.unchecked_transaction()?;
    let rebind_operation = identity_rebind_operation_for_user_conn(&tx, user_id)?;
    if rebind_operation
        .as_ref()
        .is_some_and(|operation| operation.stage != IdentityRebindStage::DeletionReconciled)
    {
        tx.rollback()?;
        return Err(EnclaveError::Conflict(
            "identity rebind namespaces are not deletion-reconciled".into(),
        ));
    }
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
        if let Some(rebind_operation) = rebind_operation.as_ref() {
            tx.execute(
                "DELETE FROM identity_rebind_operations WHERE operation_id = ?1",
                [&rebind_operation.operation_id],
            )?;
        }
        tx.commit()?;
        return Ok(operation);
    };
    if status != "deleting" {
        tx.rollback()?;
        return Err(EnclaveError::Conflict(
            "account deletion was not initialized".into(),
        ));
    }
    // Recheck the durable pre-v3 fence in the same transaction that removes
    // ordinary identity data. A retry preserves the ledger state; it cannot
    // reopen an archive after a partial finalization.
    tombstone_archive_deletion_ledger_conn(&tx, user_id, fence_object_name)?;

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
    tx.execute(
        "DELETE FROM recording_delivery_balances WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute(
        "DELETE FROM recording_delivery_reservations WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute(
        "DELETE FROM offline_recording_usage_receipts WHERE user_id = ?1",
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
        "DELETE FROM push_installations WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute(
        "DELETE FROM apple_credentials WHERE user_id = ?1",
        [user_id],
    )?;
    tx.execute("DELETE FROM auth_identities WHERE user_id = ?1", [user_id])?;
    // Keep the archive-keyed ledger but erase the identity -> archive mapping.
    // `deleted_users`/`deleted_identities` are the no-resurrection fence after
    // finalization; nothing can reconnect this former account to its archive.
    let erased_binding =
        tx.execute("DELETE FROM archive_bindings WHERE user_id = ?1", [user_id])?;
    if erased_binding != 1 {
        tx.rollback()?;
        return Err(EnclaveError::Store(
            "archive binding disappeared during identity deletion".into(),
        ));
    }
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
    if let Some(rebind_operation) = rebind_operation.as_ref() {
        let erased = tx.execute(
            "DELETE FROM identity_rebind_operations WHERE operation_id = ?1",
            [&rebind_operation.operation_id],
        )?;
        if erased != 1 {
            tx.rollback()?;
            return Err(EnclaveError::Conflict(
                "identity rebind deletion authority disappeared".into(),
            ));
        }
    }
    tx.commit()?;
    Ok(operation)
}

fn begin_user_deletion_conn(
    conn: &Connection,
    user_id: &str,
    proposed_operation_id: &str,
    fence_object_name: &str,
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
        tx.execute(
            "UPDATE push_installations SET enabled = 0, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ?1",
            [user_id],
        )?;
    }
    // This precedes every legacy content attempt and, therefore, every later
    // ordinary identity removal. The tombstone is durable even when legacy
    // deletion needs a retry, so future v3 work cannot acquire/recreate the
    // old archive after an account enters deletion.
    if !tombstoned || archive_binding_conn(&tx, user_id)?.is_some() {
        tombstone_archive_deletion_ledger_conn(&tx, user_id, fence_object_name)?;
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
    /// Test-only constructor for control-plane behavior that never performs a
    /// legacy user-ID rebind. Production has no ungated constructor.
    #[cfg(test)]
    pub fn new(kms: Arc<dyn KmsClient>, gcs: Arc<dyn GcsClient>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            kms,
            gcs,
            lifecycle_store: None,
        }
    }

    pub fn new_with_store(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        lifecycle_store: Arc<Store>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            kms,
            gcs,
            lifecycle_store: Some(lifecycle_store),
        }
    }

    pub(crate) async fn initialize_legacy_fence_key(&self) -> Result<()> {
        match self.lifecycle_store.as_ref() {
            Some(store) => {
                // Loading the exact durable control generation installs its
                // KMS-protected DEK as the Store's HMAC key. A new database is
                // made durable by a no-op transaction before this returns.
                if !store.legacy_fence_key_initialized()? {
                    self.read(|_| Ok(())).await?;
                }
                if !store.legacy_fence_key_initialized()? {
                    self.write(|_| Ok(())).await?;
                }
                if !store.legacy_fence_key_initialized()? {
                    return Err(EnclaveError::Store(
                        "durable legacy fence key initialization failed".into(),
                    ));
                }
                Ok(())
            }
            None => {
                #[cfg(test)]
                {
                    Ok(())
                }
                #[cfg(not(test))]
                {
                    Err(EnclaveError::Store(
                        "legacy fence key lacks lifecycle authority".into(),
                    ))
                }
            }
        }
    }

    async fn identity_rebind_fence_object_name(&self, user_id: &str) -> Result<String> {
        self.initialize_legacy_fence_key().await?;
        match self.lifecycle_store.as_ref() {
            Some(store) => {
                let retained = self
                    .read({
                        let user_id = user_id.to_string();
                        move |conn| {
                            Ok(archive_deletion_ledger_conn(conn, &user_id)?
                                .and_then(|ledger| ledger.legacy_rebind_fence_object_name))
                        }
                    })
                    .await?;
                match retained {
                    Some(name) => Ok(name),
                    None => store.identity_rebind_fence_object_name(user_id),
                }
            }
            None => {
                #[cfg(test)]
                {
                    Ok(crate::store::test_identity_rebind_fence_object_name(
                        user_id,
                    ))
                }
                #[cfg(not(test))]
                {
                    let _ = user_id;
                    Err(EnclaveError::Store(
                        "legacy fence name lacks lifecycle authority".into(),
                    ))
                }
            }
        }
    }

    async fn prepare_identity_rebind(
        &self,
        google_sub: &str,
        old_user_id: &str,
        stable_user_id: &str,
        binding: ArchiveBinding,
        source: &IdentityRebindSource,
    ) -> Result<IdentityRebindOperation> {
        let proposed_operation_id = format!("rebind_{}", super::tokens::random_token_hex());
        let fence_object_name = self.identity_rebind_fence_object_name(old_user_id).await?;
        let attempt = self
            .write({
                let proposed_operation_id = proposed_operation_id.clone();
                let google_sub = google_sub.to_string();
                let old_user_id = old_user_id.to_string();
                let stable_user_id = stable_user_id.to_string();
                let fence_object_name = fence_object_name.clone();
                let source_base_generation = source.base_generation;
                let source_commitment = source.commitment;
                move |conn| {
                    let source = IdentityRebindSource {
                        base_generation: source_base_generation,
                        source_generation: source_base_generation,
                        commitment: source_commitment,
                        plaintext: Vec::new(),
                        wrapped_dek_b64: String::new(),
                    };
                    prepare_identity_rebind_conn(
                        conn,
                        &proposed_operation_id,
                        &google_sub,
                        &old_user_id,
                        &stable_user_id,
                        &fence_object_name,
                        binding,
                        &source,
                    )
                }
            })
            .await;
        match attempt {
            Ok(operation) => Ok(operation),
            Err(error) => {
                // A competing control generation or a lost successful PUT is
                // resolved only by reloading the encrypted authority and
                // comparing every exact prepared field.
                let observed = self
                    .read({
                        let google_sub = google_sub.to_string();
                        move |conn| identity_rebind_operation_for_subject_conn(conn, &google_sub)
                    })
                    .await?;
                match observed {
                    Some(operation)
                        if operation.old_user_id == old_user_id
                            && operation.stable_user_id == stable_user_id
                            && operation.binding == binding
                            && operation.source_base_generation == source.base_generation
                            && operation.source_commitment == source.commitment =>
                    {
                        Ok(operation)
                    }
                    _ => Err(error),
                }
            }
        }
    }

    async fn advance_identity_rebind(
        &self,
        operation: &IdentityRebindOperation,
        next_stage: IdentityRebindStage,
        source_generation: Option<i64>,
    ) -> Result<IdentityRebindOperation> {
        let attempt = self
            .write({
                let operation = operation.clone();
                move |conn| {
                    advance_identity_rebind_conn(conn, &operation, next_stage, source_generation)
                }
            })
            .await;
        match attempt {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let observed = self
                    .read({
                        let google_sub = operation.google_sub.clone();
                        move |conn| identity_rebind_operation_for_subject_conn(conn, &google_sub)
                    })
                    .await?;
                match observed {
                    Some(current)
                        if current.operation_id == operation.operation_id
                            && current.binding == operation.binding
                            && current.source_commitment == operation.source_commitment
                            && current.stage >= next_stage =>
                    {
                        Ok(current)
                    }
                    _ => Err(error),
                }
            }
        }
    }

    async fn rebase_identity_rebind_source(
        &self,
        operation: &IdentityRebindOperation,
        source: &IdentityRebindSource,
    ) -> Result<IdentityRebindOperation> {
        let attempt = self
            .write({
                let operation = operation.clone();
                let source_base_generation = source.source_generation;
                let source_commitment = source.commitment;
                move |conn| {
                    let source = IdentityRebindSource {
                        base_generation: source_base_generation,
                        source_generation: source_base_generation,
                        commitment: source_commitment,
                        plaintext: Vec::new(),
                        wrapped_dek_b64: String::new(),
                    };
                    rebase_identity_rebind_source_conn(conn, &operation, &source)
                }
            })
            .await;
        match attempt {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let observed = self
                    .read({
                        let google_sub = operation.google_sub.clone();
                        move |conn| identity_rebind_operation_for_subject_conn(conn, &google_sub)
                    })
                    .await?;
                match observed {
                    Some(current)
                        if current.operation_id == operation.operation_id
                            && current.stage == IdentityRebindStage::SourceFreezing
                            && current.source_base_generation == source.source_generation
                            && current.source_commitment == source.commitment =>
                    {
                        Ok(current)
                    }
                    _ => Err(error),
                }
            }
        }
    }

    /// Recover a bounded set of durable identity transitions before request
    /// admission starts. Ordinary pending stages run to `committed`; if an
    /// account entered deletion while a provider create was explicitly in
    /// flight, recovery records that create's exact completed stage and leaves
    /// the deletion reconciler to claim and purge both namespaces.
    pub(crate) async fn reconcile_pending_identity_rebinds(&self) -> Result<usize> {
        const STARTUP_REBIND_PAGE_SIZE: i64 = 64;
        const STARTUP_REBIND_HARD_LIMIT: usize = 4096;
        let store = self.lifecycle_store.as_ref().cloned().ok_or_else(|| {
            EnclaveError::Store("identity rebind recovery lacks lifecycle authority".into())
        })?;
        let mut recovered = 0usize;
        let mut inspected = 0usize;
        loop {
            let operations = self
                .read(|conn| {
                    pending_identity_rebind_operations_conn(conn, STARTUP_REBIND_PAGE_SIZE)
                })
                .await?;
            if operations.is_empty() {
                break;
            }
            if inspected.saturating_add(operations.len()) > STARTUP_REBIND_HARD_LIMIT {
                return Err(EnclaveError::Store(
                    "identity rebind startup backlog exceeds the hard safety limit".into(),
                ));
            }
            inspected = inspected.saturating_add(operations.len());
            for operation in operations {
                let email = self
                    .read({
                        let google_sub = operation.google_sub.clone();
                        move |conn| {
                            conn.query_row(
                                "SELECT email FROM users WHERE google_sub = ?1",
                                [&google_sub],
                                |row| row.get::<_, String>(0),
                            )
                            .optional()?
                            .ok_or_else(|| {
                                EnclaveError::Store(
                                    "pending identity rebind lost its account".into(),
                                )
                            })
                        }
                    })
                    .await?;
                let transition = store
                    .begin_identity_rebind(&operation.old_user_id, &operation.stable_user_id)
                    .await?;
                match self
                    .resume_identity_rebind(operation, transition, email)
                    .await
                {
                    Ok(_) => recovered = recovered.saturating_add(1),
                    // Deletion is the durable winner. A writing stage was
                    // reconciled before this result; safe stages are left for
                    // the deletion worker without provider mutation.
                    Err(EnclaveError::Auth(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(recovered)
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
        let (plaintext, meta, durable_fence_key) = match self.gcs.get_object(CONTROL_OBJECT).await {
            Ok(resp) => {
                let dek = load_dek(self.kms.as_ref(), &resp.wrapped_dek_b64).await?;
                let opened = decrypt_bound_blob(&dek, &resp.ciphertext, CONTROL_CONTEXT)?;
                (
                    opened.plaintext,
                    BlobMeta {
                        generation: resp.generation,
                        wrapped_dek_b64: resp.wrapped_dek_b64,
                    },
                    Some(dek.0),
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
                    None,
                )
            }
            Err(e) => return Err(e),
        };

        if let (Some(store), Some(key)) = (self.lifecycle_store.as_ref(), durable_fence_key) {
            store.install_legacy_fence_key(key)?;
        }

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
        schema_migrations += conn.execute(
            "INSERT OR IGNORE INTO config (key, value)
             VALUES ('archive_lifecycle_schema', '1')",
            [],
        )?;
        schema_migrations += backfill_archive_bindings_conn(&conn)?;
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
        let put_result = self
            .gcs
            .put_object(
                CONTROL_OBJECT,
                &ciphertext,
                &handle.meta.wrapped_dek_b64,
                handle.meta.generation,
            )
            .await;
        let new_gen = match put_result {
            Ok(generation) => generation,
            Err(error) => match self.gcs.get_object(CONTROL_OBJECT).await {
                Ok(current)
                    if current.generation > handle.meta.generation
                        && current.wrapped_dek_b64 == handle.meta.wrapped_dek_b64
                        && current.ciphertext == ciphertext =>
                {
                    // Exact reread is the only authority for a control PUT
                    // whose response was lost. A different ciphertext is a
                    // genuine competing control generation and remains an
                    // error even when its decoded rows happen to look similar.
                    current.generation
                }
                _ => return Err(error),
            },
        };
        handle.meta.generation = new_gen;
        if let Some(store) = self.lifecycle_store.as_ref() {
            let dek = load_dek(self.kms.as_ref(), &handle.meta.wrapped_dek_b64).await?;
            store.install_legacy_fence_key(dek.0)?;
        }
        Ok(())
    }

    /// Move a pre-stable-id user database without breaking its object-bound
    /// AEAD context. A raw GCS copy would retain the old context and become
    /// undecryptable under the stable object's name.
    #[cfg(test)]
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

    async fn decode_rebind_source_response(
        &self,
        operation: &IdentityRebindOperation,
        response: crate::store::GcsGetResponse,
        user_id_context: &str,
        require_source_generation: bool,
    ) -> Result<IdentityRebindSource> {
        let expected_generation = operation.source_generation.ok_or_else(|| {
            EnclaveError::Store("identity rebind source generation is missing".into())
        })?;
        if require_source_generation && response.generation != expected_generation {
            return Err(EnclaveError::Conflict(
                "identity rebind source generation changed".into(),
            ));
        }
        let dek = load_dek(self.kms.as_ref(), &response.wrapped_dek_b64).await?;
        let opened = decrypt_bound_blob(
            &dek,
            &response.ciphertext,
            &crate::store::user_blob_context(user_id_context),
        )?;
        let commitment: [u8; 32] = Sha256::digest(&opened.plaintext).into();
        if commitment != operation.source_commitment {
            return Err(EnclaveError::Conflict(
                "identity rebind source commitment changed".into(),
            ));
        }
        Ok(IdentityRebindSource {
            base_generation: operation.source_base_generation,
            source_generation: expected_generation,
            commitment,
            plaintext: opened.plaintext,
            wrapped_dek_b64: response.wrapped_dek_b64,
        })
    }

    async fn load_identity_rebind_source(
        &self,
        operation: &IdentityRebindOperation,
    ) -> Result<IdentityRebindSource> {
        let generation = operation.source_generation.ok_or_else(|| {
            EnclaveError::Store("identity rebind source generation is missing".into())
        })?;
        match self
            .gcs
            .get_object_generation(&operation.old_object_name, generation)
            .await
        {
            Ok(response) => {
                self.decode_rebind_source_response(
                    operation,
                    response,
                    &operation.old_user_id,
                    true,
                )
                .await
            }
            Err(EnclaveError::NotFound)
                if operation.stage >= IdentityRebindStage::StableWritten =>
            {
                let response = self.gcs.get_object(&operation.stable_object_name).await?;
                self.decode_rebind_source_response(
                    operation,
                    response,
                    &operation.stable_user_id,
                    false,
                )
                .await
            }
            Err(error) => Err(error),
        }
    }

    async fn validate_stable_rebind_target(
        &self,
        operation: &IdentityRebindOperation,
        source: &IdentityRebindSource,
    ) -> Result<()> {
        let existing = self.gcs.get_object(&operation.stable_object_name).await?;
        if existing.wrapped_dek_b64 != source.wrapped_dek_b64 {
            return Err(EnclaveError::Conflict(
                "stable rebind target uses a different wrapped key".into(),
            ));
        }
        let dek = load_dek(self.kms.as_ref(), &existing.wrapped_dek_b64).await?;
        let opened = decrypt_bound_blob(
            &dek,
            &existing.ciphertext,
            &crate::store::user_blob_context(&operation.stable_user_id),
        )?;
        let commitment: [u8; 32] = Sha256::digest(&opened.plaintext).into();
        if commitment != operation.source_commitment || opened.plaintext != source.plaintext {
            return Err(EnclaveError::Conflict(
                "stable rebind target differs from its exact source".into(),
            ));
        }
        Ok(())
    }

    async fn identity_rebind_account_is_active(
        &self,
        operation: &IdentityRebindOperation,
    ) -> Result<bool> {
        let google_sub = operation.google_sub.clone();
        let old_user_id = operation.old_user_id.clone();
        self.read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT status = 'active' FROM users
                     WHERE google_sub = ?1 AND id = ?2",
                    rusqlite::params![google_sub, old_user_id],
                    |row| row.get::<_, bool>(0),
                )
                .optional()?
                .unwrap_or(false))
        })
        .await
    }

    async fn ensure_identity_rebind_provider_fence(
        &self,
        operation: &IdentityRebindOperation,
    ) -> Result<String> {
        let store = self.lifecycle_store.as_ref().ok_or_else(|| {
            EnclaveError::Store("identity rebind fence lacks lifecycle authority".into())
        })?;
        let authority = store
            .fence_and_drain_legacy_writes(&operation.old_user_id, &operation.operation_id)
            .await?;
        if authority != operation.operation_id {
            return Err(EnclaveError::Auth(
                "account deletion superseded identity rebind provider authority".into(),
            ));
        }
        Ok(authority)
    }

    async fn resume_identity_rebind(
        &self,
        mut operation: IdentityRebindOperation,
        mut transition: crate::store::IdentityRebindTransition,
        email: String,
    ) -> Result<User> {
        if operation.stage >= IdentityRebindStage::DeletionPending {
            return Err(EnclaveError::Auth(
                "account deletion superseded identity rebind".into(),
            ));
        }
        if operation.stage >= IdentityRebindStage::Committed {
            transition.complete().await;
            return self
                .identity_user("google", &operation.google_sub)
                .await?
                .ok_or_else(|| {
                    EnclaveError::Store("committed identity rebind lost its user".into())
                });
        }
        let mut account_active = self.identity_rebind_account_is_active(&operation).await?;
        if !account_active
            && !matches!(
                operation.stage,
                IdentityRebindStage::SourceFreezing | IdentityRebindStage::StableWriting
            )
        {
            return Err(EnclaveError::Auth(
                "account deletion superseded identity rebind".into(),
            ));
        }

        if operation.stage == IdentityRebindStage::Prepared {
            operation = self
                .advance_identity_rebind(&operation, IdentityRebindStage::SourceFreezing, None)
                .await?;
            if operation.stage >= IdentityRebindStage::DeletionPending {
                return Err(EnclaveError::Auth(
                    "account deletion superseded identity rebind".into(),
                ));
            }
        }

        let source = if operation.stage == IdentityRebindStage::SourceFreezing {
            let marker_authority = self
                .ensure_identity_rebind_provider_fence(&operation)
                .await?;
            let first_freeze = transition
                .freeze_source(
                    operation.source_base_generation,
                    &operation.source_commitment,
                    &marker_authority,
                )
                .await;
            let frozen = match first_freeze {
                Ok(frozen) => frozen,
                Err(error @ EnclaveError::Conflict(_)) => {
                    let refreshed = transition.source_snapshot().await?;
                    operation = self
                        .rebase_identity_rebind_source(&operation, &refreshed)
                        .await?;
                    transition
                        .freeze_source(
                            operation.source_base_generation,
                            &operation.source_commitment,
                            &marker_authority,
                        )
                        .await
                        .map_err(|retry_error| match retry_error {
                            EnclaveError::Conflict(_) => error,
                            other => other,
                        })?
                }
                Err(error) => return Err(error),
            };
            operation = self
                .advance_identity_rebind(
                    &operation,
                    IdentityRebindStage::SourceFrozen,
                    Some(frozen.source_generation),
                )
                .await?;
            account_active = self.identity_rebind_account_is_active(&operation).await?;
            if operation.stage >= IdentityRebindStage::DeletionPending {
                return Err(EnclaveError::Auth(
                    "account deletion superseded identity rebind".into(),
                ));
            }
            if !account_active {
                return Err(EnclaveError::Auth(
                    "account deletion superseded identity rebind".into(),
                ));
            }
            frozen
        } else {
            self.load_identity_rebind_source(&operation).await?
        };

        if operation.stage == IdentityRebindStage::SourceFrozen {
            match self.gcs.get_object(&operation.stable_object_name).await {
                Err(EnclaveError::NotFound) => {}
                Ok(_) => {
                    return Err(EnclaveError::Conflict(
                        "stable rebind target appeared before write intent".into(),
                    ))
                }
                Err(error) => return Err(error),
            }
            operation = self
                .advance_identity_rebind(
                    &operation,
                    IdentityRebindStage::StableWriting,
                    operation.source_generation,
                )
                .await?;
            account_active = self.identity_rebind_account_is_active(&operation).await?;
            if operation.stage >= IdentityRebindStage::DeletionPending {
                return Err(EnclaveError::Auth(
                    "account deletion superseded identity rebind".into(),
                ));
            }
            if !account_active {
                return Err(EnclaveError::Auth(
                    "account deletion superseded identity rebind".into(),
                ));
            }
        }

        if operation.stage == IdentityRebindStage::StableWriting {
            let store = self.lifecycle_store.as_ref().ok_or_else(|| {
                EnclaveError::Store("stable rebind write lacks lifecycle authority".into())
            })?;
            store
                .reconcile_stable_rebind_intents(&operation.stable_user_id)
                .await?;
            match self
                .validate_stable_rebind_target(&operation, &source)
                .await
            {
                Ok(()) => {}
                Err(EnclaveError::NotFound) => {
                    let dek = load_dek(self.kms.as_ref(), &source.wrapped_dek_b64).await?;
                    let rebound = encrypt_bound_blob(
                        &dek,
                        &source.plaintext,
                        &crate::store::user_blob_context(&operation.stable_user_id),
                    )?;
                    match store
                        .put_stable_rebind_index(
                            &operation.stable_user_id,
                            &operation.stable_object_name,
                            &rebound,
                            &source.wrapped_dek_b64,
                        )
                        .await
                    {
                        Ok(_) => {}
                        Err(EnclaveError::Conflict(_)) => {
                            self.validate_stable_rebind_target(&operation, &source)
                                .await?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
            self.validate_stable_rebind_target(&operation, &source)
                .await?;
            operation = self
                .advance_identity_rebind(
                    &operation,
                    IdentityRebindStage::StableWritten,
                    operation.source_generation,
                )
                .await?;
            account_active = self.identity_rebind_account_is_active(&operation).await?;
            if !account_active {
                return Err(EnclaveError::Auth(
                    "account deletion superseded identity rebind".into(),
                ));
            }
        } else if operation.stage >= IdentityRebindStage::StableWritten {
            self.validate_stable_rebind_target(&operation, &source)
                .await?;
        }

        if operation.stage == IdentityRebindStage::StableWritten {
            operation = self
                .advance_identity_rebind(
                    &operation,
                    IdentityRebindStage::OldPurging,
                    operation.source_generation,
                )
                .await?;
            if operation.stage >= IdentityRebindStage::DeletionPending {
                return Err(EnclaveError::Auth(
                    "account deletion superseded identity rebind".into(),
                ));
            }
        }
        if operation.stage == IdentityRebindStage::OldPurging {
            crate::store::delete_all_object_generations(
                self.gcs.as_ref(),
                &operation.old_object_name,
            )
            .await?;
            operation = self
                .advance_identity_rebind(
                    &operation,
                    IdentityRebindStage::OldPurged,
                    operation.source_generation,
                )
                .await?;
            if operation.stage >= IdentityRebindStage::DeletionPending {
                return Err(EnclaveError::Auth(
                    "account deletion superseded identity rebind".into(),
                ));
            }
        }
        if operation.stage == IdentityRebindStage::OldPurged {
            let user = match self.commit_identity_rebind(email, operation.clone()).await {
                Ok(user) => user,
                Err(error) => {
                    let observed = self
                        .read({
                            let google_sub = operation.google_sub.clone();
                            move |conn| {
                                identity_rebind_operation_for_subject_conn(conn, &google_sub)
                            }
                        })
                        .await?;
                    match observed {
                        Some(current)
                            if current.operation_id == operation.operation_id
                                && current.stage >= IdentityRebindStage::Committed
                                && current.stage < IdentityRebindStage::DeletionPending =>
                        {
                            self.identity_user("google", &operation.google_sub)
                                .await?
                                .ok_or_else(|| {
                                    EnclaveError::Store(
                                        "committed identity rebind lost its user".into(),
                                    )
                                })?
                        }
                        _ => return Err(error),
                    }
                }
            };
            transition.complete().await;
            return Ok(user);
        }
        if operation.stage >= IdentityRebindStage::Committed
            && operation.stage < IdentityRebindStage::DeletionPending
        {
            transition.complete().await;
            return self
                .identity_user("google", &operation.google_sub)
                .await?
                .ok_or_else(|| {
                    EnclaveError::Store("committed identity rebind lost its user".into())
                });
        }
        Err(EnclaveError::Store(
            "identity rebind stopped in an invalid stage".into(),
        ))
    }

    async fn commit_identity_rebind(
        &self,
        email: String,
        operation: IdentityRebindOperation,
    ) -> Result<User> {
        let google_sub = operation.google_sub.clone();
        let stable_id = operation.stable_user_id.clone();
        let existing = Some((
            operation.old_user_id.clone(),
            String::new(),
            operation.binding,
        ));
        self.write(move |conn| {
            conn.execute("BEGIN TRANSACTION", [])?;
            let res = (|| -> Result<()> {
                if is_deleted_user_conn(conn, &stable_id)? {
                    return Err(EnclaveError::Auth("account deleted".into()));
                }
                if let Some((ref old_id, _, source_binding)) = existing {
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
                        validate_archive_rebind_conn(
                            conn,
                            &google_sub,
                            old_id,
                            &stable_id,
                            source_binding,
                        )?;
                        conn.execute(
                            "UPDATE users SET id = ?1, email = ?2 WHERE google_sub = ?3",
                            rusqlite::params![stable_id, email, google_sub],
                        )?;
                        for table in [
                            "usage_daily",
                            "billing_accounts",
                            "recording_leases",
                            "recording_lease_requests",
                            "refresh_tokens",
                            "oauth_authorization_codes",
                            "oauth_consents",
                            "query_log",
                            "vertex_coverage_anchors",
                            "recording_lease_denials",
                            "recording_delivery_balances",
                            "recording_delivery_reservations",
                            "offline_recording_usage_receipts",
                            "webhook_subscriptions",
                            "episode_email_preferences",
                            "push_installations",
                            "auth_identities",
                            "apple_credentials",
                            "archive_bindings",
                        ] {
                            conn.execute(
                                &format!("UPDATE {table} SET user_id = ?1 WHERE user_id = ?2"),
                                rusqlite::params![stable_id, old_id],
                            )?;
                        }
                    } else {
                        conn.execute(
                            "UPDATE users SET email = ?1 WHERE google_sub = ?2",
                            rusqlite::params![email, google_sub],
                        )?;
                    }
                } else {
                    conn.execute(
                        "INSERT INTO users (id, google_sub, email) VALUES (?1, ?2, ?3)
                         ON CONFLICT(google_sub) DO UPDATE SET email = excluded.email
                         WHERE users.id = excluded.id AND users.status = 'active'",
                        rusqlite::params![stable_id, google_sub, email],
                    )?;
                    let created_status: Option<(String, String)> = conn
                        .query_row(
                            "SELECT id, status FROM users WHERE google_sub = ?1",
                            [&google_sub],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    if !matches!(created_status, Some((ref id, ref status)) if id == &stable_id && status == "active") {
                        return Err(EnclaveError::Auth("account inactive".into()));
                    }
                }
                conn.execute(
                    "INSERT INTO auth_identities (provider, subject, user_id, email) VALUES ('google', ?1, ?2, ?3) ON CONFLICT(provider, subject) DO UPDATE SET email = excluded.email, last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                    rusqlite::params![google_sub, stable_id, email],
                )?;
                if archive_binding_conn(conn, &stable_id)?.is_some() {
                    validate_active_archive_binding_conn(conn, &stable_id)?;
                } else if existing.is_none() {
                    create_active_archive_binding_conn(conn, &stable_id)?;
                } else {
                    return Err(EnclaveError::Store(
                        "existing account lost its archive binding".into(),
                    ));
                }
                let committed = advance_identity_rebind_conn(
                    conn,
                    &operation,
                    IdentityRebindStage::Committed,
                    operation.source_generation,
                )?;
                if committed.stage != IdentityRebindStage::Committed {
                    return Err(EnclaveError::Store(
                        "identity rebind control commit did not become durable".into(),
                    ));
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
                        Some((id, current_email, _)) => {
                            let binding = validate_active_archive_binding_conn(conn, &id)?;
                            Ok(Some((id, current_email, binding)))
                        }
                        None => Ok(None),
                    }
                }
            })
            .await?;

        // Google ID tokens authenticate every web/API request. Avoid rewriting
        // the encrypted control DB for the overwhelmingly common no-op case;
        // screenshot upload bursts otherwise exceed GCS's per-object write
        // rate and turn valid image requests into intermittent 500 responses.
        if let Some((existing_id, existing_email, _)) = existing.as_ref() {
            if existing_id == &stable_id && existing_email == &email {
                return Ok(User {
                    id: stable_id,
                    email,
                });
            }
        }

        // 2. Legacy IDs enter an owned, durable state machine. The Store-owned
        // transition fences both namespaces and snapshots the latest actor;
        // the encrypted prepare record is committed before its first provider
        // write, then remains the authority across retries and restarts.
        if let Some((old_id, _, source_binding)) = existing.as_ref() {
            if old_id != &stable_id {
                let owned = ControlStore::clone(self);
                let old_id = old_id.clone();
                let stable_id = stable_id.clone();
                let google_sub = google_sub.clone();
                let email = email.clone();
                let source_binding = *source_binding;
                let task = tokio::spawn(async move {
                    let store = owned.lifecycle_store.as_ref().cloned().ok_or_else(|| {
                        EnclaveError::Store(
                            "legacy identity rebind lacks lifecycle authority".into(),
                        )
                    })?;
                    let mut transition = store.begin_identity_rebind(&old_id, &stable_id).await?;
                    let pending = owned
                        .read({
                            let google_sub = google_sub.clone();
                            move |conn| {
                                identity_rebind_operation_for_subject_conn(conn, &google_sub)
                            }
                        })
                        .await?;
                    let operation = match pending {
                        Some(operation) => {
                            if operation.old_user_id != old_id
                                || operation.stable_user_id != stable_id
                                || operation.binding != source_binding
                            {
                                return Err(EnclaveError::Conflict(
                                    "durable identity rebind authority conflicts with login".into(),
                                ));
                            }
                            operation
                        }
                        None => {
                            let source = transition.source_snapshot().await?;
                            owned
                                .prepare_identity_rebind(
                                    &google_sub,
                                    &old_id,
                                    &stable_id,
                                    source_binding,
                                    &source,
                                )
                                .await?
                        }
                    };
                    owned
                        .resume_identity_rebind(operation, transition, email)
                        .await
                });
                return task.await.map_err(|_| {
                    EnclaveError::Store("legacy identity rebind task failed".into())
                })?;
            }
        }

        // 3. Perform database transaction to insert or update user ID. The
        // legacy-ID case returned through the durable state machine above.
        let existing_cloned = existing.clone();
        self.write(move |conn| {
            conn.execute("BEGIN TRANSACTION", [])?;
            let res = (|| -> Result<()> {
                if is_deleted_user_conn(conn, &stable_id)? {
                    return Err(EnclaveError::Auth("account deleted".into()));
                }
                if let Some((ref old_id, _, source_binding)) = existing_cloned {
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
                        validate_archive_rebind_conn(
                            conn,
                            &google_sub,
                            old_id,
                            &stable_id,
                            source_binding,
                        )?;
                        return Err(EnclaveError::Store(
                            "legacy identity rebind bypassed its durable state machine".into(),
                        ));
                    } else {
                        conn.execute(
                            "UPDATE users SET email = ?1 WHERE google_sub = ?2",
                            rusqlite::params![email, google_sub],
                        )?;
                    }
                } else {
                    conn.execute(
                        "INSERT INTO users (id, google_sub, email) VALUES (?1, ?2, ?3)
                         ON CONFLICT(google_sub) DO UPDATE SET email = excluded.email
                         WHERE users.id = excluded.id AND users.status = 'active'",
                        rusqlite::params![stable_id, google_sub, email],
                    )?;
                    let created_status: Option<(String, String)> = conn
                        .query_row(
                            "SELECT id, status FROM users WHERE google_sub = ?1",
                            [&google_sub],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    if !matches!(created_status, Some((ref id, ref status)) if id == &stable_id && status == "active") {
                        return Err(EnclaveError::Auth("account inactive".into()));
                    }
                }
                conn.execute(
                    "INSERT INTO auth_identities (provider, subject, user_id, email) VALUES ('google', ?1, ?2, ?3) ON CONFLICT(provider, subject) DO UPDATE SET email = excluded.email, last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                    rusqlite::params![google_sub, stable_id, email],
                )?;
                if archive_binding_conn(conn, &stable_id)?.is_some() {
                    validate_active_archive_binding_conn(conn, &stable_id)?;
                } else if existing_cloned.is_none() {
                    create_active_archive_binding_conn(conn, &stable_id)?;
                } else {
                    return Err(EnclaveError::Store(
                        "existing account lost its archive binding".into(),
                    ));
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

    /// Resolve a linked provider identity without creating or merging an
    /// account. Email equality is intentionally never an account-link signal.
    pub async fn identity_user(&self, provider: &str, subject: &str) -> Result<Option<User>> {
        let provider = provider.to_string();
        let subject = subject.to_string();
        self.read(move |conn| {
            let user = conn
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
                .optional()?;
            if let Some(user) = &user {
                validate_active_archive_binding_conn(conn, &user.id)?;
            }
            Ok(user)
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
                    validate_active_archive_binding_conn(&tx, &user_id)?;
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
                        None => {
                            tx.execute(
                                "INSERT INTO users (id, google_sub, email) VALUES (?1, ?2, ?3)",
                                rusqlite::params![stable_id, compatibility_anchor, email],
                            )?;
                            create_active_archive_binding_conn(&tx, &stable_id)?;
                        }
                        Some((anchor, status)) if anchor == compatibility_anchor && status == "active" => {
                            validate_active_archive_binding_conn(&tx, &stable_id)?;
                        }
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
            validate_active_archive_binding_conn(&tx, &user_id)?;
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
            validate_active_archive_binding_conn(&tx, &user_id)?;
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

    /// Count retained active accounts and the subset created in one UTC
    /// calendar month. This owner-reporting read returns aggregates only.
    pub async fn retained_active_account_metrics(
        &self,
        period: &str,
    ) -> Result<RetainedAccountMetrics> {
        if !valid_utc_month(period) {
            return Err(EnclaveError::InvalidRequest(
                "account metrics period must be YYYY-MM".into(),
            ));
        }
        let period = period.to_string();
        self.read(move |conn| retained_active_account_metrics_conn(conn, &period))
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

    pub async fn offline_recording_usage_receipt(
        &self,
        user_id: &str,
        request_id: &str,
    ) -> Result<bool> {
        let user_id = user_id.to_string();
        let request_id = request_id.to_string();
        self.read(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT 1 FROM offline_recording_usage_receipts
                     WHERE user_id=?1 AND request_id=?2",
                    rusqlite::params![user_id, request_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
        .await
    }

    /// Records one billing-acknowledged offline minute and grants its bounded
    /// delivery budget exactly once. A deterministic upstream duplicate after
    /// response loss can safely call this method again.
    pub async fn complete_offline_recording_usage(
        &self,
        user_id: &str,
        request_id: &str,
    ) -> Result<bool> {
        let user_id = user_id.to_string();
        let request_id = request_id.to_string();
        self.write_if_changed(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO offline_recording_usage_receipts
                 (user_id,request_id) VALUES (?1,?2)",
                rusqlite::params![user_id, request_id],
            )? != 0;
            if inserted {
                grant_recording_delivery_minute(&tx, &user_id)?;
            }
            tx.commit()?;
            Ok((inserted, inserted))
        })
        .await
    }

    /// Reserves one bounded delayed-delivery slot for an encrypted Mac outbox
    /// event. Repeating the same event is idempotent; a reference-to-canonical
    /// rebase spends only the newly required byte delta.
    pub async fn reserve_recording_delivery(
        &self,
        user_id: &str,
        event_id: &str,
        media_bytes: i64,
    ) -> Result<bool> {
        let user_id = user_id.to_string();
        let event_id = event_id.to_string();
        let media_bytes = media_bytes.max(0);
        self.write_if_changed(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT reserved_bytes FROM recording_delivery_reservations
                     WHERE user_id=?1 AND event_id=?2",
                    rusqlite::params![user_id, event_id],
                    |row| row.get(0),
                )
                .optional()?;
            let (event_cost, byte_cost) = match existing {
                Some(reserved) => (0, media_bytes.saturating_sub(reserved)),
                None => (1, media_bytes),
            };
            let available: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT event_credits,byte_credits FROM recording_delivery_balances
                     WHERE user_id=?1",
                    [&user_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((events, bytes)) = available else {
                tx.rollback()?;
                return Ok((false, false));
            };
            if events < event_cost || bytes < byte_cost {
                tx.rollback()?;
                return Ok((false, false));
            }
            if event_cost != 0 || byte_cost != 0 {
                tx.execute(
                    "UPDATE recording_delivery_balances
                     SET event_credits=event_credits-?2,byte_credits=byte_credits-?3,
                         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     WHERE user_id=?1",
                    rusqlite::params![user_id, event_cost, byte_cost],
                )?;
                tx.execute(
                    "INSERT INTO recording_delivery_reservations
                     (user_id,event_id,reserved_bytes) VALUES (?1,?2,?3)
                     ON CONFLICT(user_id,event_id) DO UPDATE
                     SET reserved_bytes=MAX(reserved_bytes,excluded.reserved_bytes)",
                    rusqlite::params![user_id, event_id, media_bytes],
                )?;
            }
            tx.commit()?;
            Ok((true, event_cost != 0 || byte_cost != 0))
        })
        .await
    }

    pub async fn complete_recording_delivery(&self, user_id: &str, event_id: &str) -> Result<()> {
        let user_id = user_id.to_string();
        let event_id = event_id.to_string();
        self.write_if_changed(move |conn| {
            let changed = conn.execute(
                "DELETE FROM recording_delivery_reservations WHERE user_id=?1 AND event_id=?2",
                rusqlite::params![user_id, event_id],
            )? != 0;
            Ok(((), changed))
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

    pub async fn pending_recording_lease_request(
        &self,
        user_id: &str,
    ) -> Result<Option<(String, RecordingLeaseRequestRow)>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            type StoredPendingLease = (String, Option<String>, String, String);
            let row: Option<StoredPendingLease> = conn
                .query_row(
                    "SELECT request_id,requested_lease_id,issued_lease_id,expires_at
                     FROM recording_lease_requests
                     WHERE user_id=?1 AND state='pending'
                     ORDER BY created_at,rowid LIMIT 1",
                    [user_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            Ok(row.map(
                |(request_id, requested_lease_id, issued_lease_id, expires_at)| {
                    (
                        request_id,
                        RecordingLeaseRequestRow {
                            requested_lease_id,
                            issued_lease_id,
                            expires_at,
                            state: "pending".into(),
                            summary: None,
                            denial_code: None,
                        },
                    )
                },
            ))
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
                Some((active_lease_id, active_expires_at)) => {
                    let active_expires_ms = super::isotime::parse_epoch_millis(&active_expires_at)
                        .ok_or_else(|| {
                            EnclaveError::Config("invalid active recording lease expiry".into())
                        })?;
                    if active_lease_id != lease_id
                        && retry_now_ms.is_none_or(|now_ms| active_expires_ms > now_ms)
                    {
                        return Err(EnclaveError::Conflict(
                            "a different recording lease became active".into(),
                        ));
                    }
                    Some(active_expires_ms)
                }
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
            grant_recording_delivery_minute(&tx, &user_id)?;
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

    /// Internal inspection seam for future v3 deletion work. It is not a
    /// route, export field, telemetry dimension, or provider integration.
    #[allow(
        dead_code,
        reason = "reserved for the separately-authorized v3 deletion worker"
    )]
    pub(crate) async fn archive_deletion_ledger(
        &self,
        user_id: &str,
    ) -> Result<Option<ArchiveDeletionLedger>> {
        let user_id = user_id.to_string();
        self.read(move |conn| archive_deletion_ledger_conn(conn, &user_id))
            .await
    }

    /// Inactive archive-v3 lifecycle methods. They mutate only the encrypted
    /// control ledger and are intentionally not called by startup, Store,
    /// routes, or any provider adapter. Account deletion only atomically
    /// freezes an already-existing inactive anchor; it constructs no runtime.
    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn reserve_archive_bootstrap(
        &self,
        plan: BootstrapPlan,
    ) -> Result<DurableBootstrapReservation> {
        self.write_if_changed(move |conn| {
            reserve_archive_bootstrap_conn(conn, plan).map(|receipt| (receipt, true))
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn prepare_archive_bootstrap(
        &self,
        reservation: DurableBootstrapReservation,
        wrapped_registry: Vec<u8>,
        root_envelope: Vec<u8>,
    ) -> Result<PreparedBootstrap> {
        self.write_if_changed(move |conn| {
            prepare_archive_bootstrap_conn(conn, reservation, &wrapped_registry, &root_envelope)
                .map(|receipt| (receipt, true))
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn recover_archive_bootstrap(
        &self,
        archive_id: ArchiveId,
    ) -> Result<RecoveredBootstrap> {
        self.read(move |conn| recover_archive_bootstrap_conn(conn, archive_id))
            .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn prepare_archive_witness(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        encoded_witness: Vec<u8>,
    ) -> Result<u64> {
        self.write_if_changed(move |conn| {
            prepare_archive_witness_conn(conn, archive_id, expected_revision, &encoded_witness)
                .map(|revision| (revision, true))
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn admit_archive_create(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        artifact_ordinal: u32,
    ) -> Result<ActiveCreateAdmission> {
        self.write_if_changed(move |conn| {
            admit_archive_create_conn(conn, archive_id, expected_revision, artifact_ordinal)
                .map(|admission| (admission, true))
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn reconcile_archive_create(
        &self,
        admission: ActiveCreateAdmission,
        outcome: LifecycleCreateOutcome,
    ) -> Result<u64> {
        self.write_if_changed(move |conn| {
            reconcile_archive_create_conn(conn, &admission, outcome)
                .map(|revision| (revision, true))
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn freeze_archive_lifecycle(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        deletion_fence: ObjectId,
    ) -> Result<u64> {
        self.write_if_changed(move |conn| {
            freeze_archive_lifecycle_conn(conn, archive_id, expected_revision, deletion_fence)
                .map(|revision| (revision, true))
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn seal_archive_inventory(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        deletion_fence: ObjectId,
        pages: Vec<DurableInventoryPage>,
    ) -> Result<DeletionInventorySeal> {
        self.write_if_changed(move |conn| {
            seal_archive_inventory_conn(conn, archive_id, expected_revision, deletion_fence, &pages)
                .map(|seal| (seal, true))
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn load_sealed_archive_inventory_references(
        &self,
        seal: DeletionInventorySeal,
    ) -> Result<Vec<InventoryPageReference>> {
        self.read(move |conn| load_sealed_archive_inventory_references_conn(conn, &seal))
            .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn recover_archive_deletion_lifecycle(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<RecoveredDeletionLifecycle> {
        self.read(move |conn| {
            recover_archive_deletion_lifecycle_conn(conn, archive_id, deletion_fence)
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn mark_archive_physical_complete(
        &self,
        completion: PhysicalDeletionReceipt,
    ) -> Result<DurablePhysicalCompletion> {
        self.write_if_changed(move |conn| {
            mark_archive_physical_complete_conn(conn, &completion).map(|receipt| (receipt, true))
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn erase_archive_lifecycle_payload(
        &self,
        completion: DurablePhysicalCompletion,
        erased_pages: ErasedInventoryPages,
    ) -> Result<()> {
        self.write_if_changed(move |conn| {
            erase_archive_lifecycle_payload_conn(conn, &completion, erased_pages)
                .map(|()| ((), true))
        })
        .await
    }

    #[allow(
        dead_code,
        reason = "reserved for reviewed archive-v3 authority wiring"
    )]
    pub(crate) async fn revalidate_active_archive_lifecycle(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
    ) -> Result<u64> {
        self.read(move |conn| {
            let (revision, state) = active_lifecycle_revision_conn(conn, archive_id)?;
            if revision < expected_revision || !state.admits_creates() {
                return Err(EnclaveError::Conflict(
                    "archive lifecycle is stale or frozen".into(),
                ));
            }
            Ok(revision)
        })
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

    /// Return the encrypted durable two-namespace authority associated with
    /// either side of an identity rebind. The operation is internal-only and
    /// its debug representation is deliberately opaque.
    pub(crate) async fn identity_rebind_operation_for_user(
        &self,
        user_id: &str,
    ) -> Result<Option<IdentityRebindOperation>> {
        let user_id = user_id.to_string();
        self.read(move |conn| identity_rebind_operation_for_user_conn(conn, &user_id))
            .await
    }

    /// Claim a pending identity rebind for account deletion. If the durable
    /// operation is at a provider-write stage, this live retry owns both Store
    /// lifecycle gates and resumes that exact intent until it reaches a stage
    /// deletion can monotonically claim. Provider intent leases/CAS serialize
    /// cross-instance takeover; progress never depends on a future restart.
    pub(crate) async fn claim_identity_rebind_deletion(&self, user_id: &str) -> Result<bool> {
        let user_id = user_id.to_string();
        for _ in 0..4 {
            let claimed = self
                .write({
                    let user_id = user_id.clone();
                    move |conn| claim_identity_rebind_deletion_conn(conn, &user_id)
                })
                .await?;
            let operation = self
                .read({
                    let user_id = user_id.clone();
                    move |conn| identity_rebind_operation_for_user_conn(conn, &user_id)
                })
                .await?;
            if claimed {
                if let Some(operation) = operation {
                    self.ensure_identity_rebind_provider_fence(&operation)
                        .await?;
                }
                return Ok(true);
            }

            let operation = operation.ok_or_else(|| {
                EnclaveError::Store("identity rebind deletion claim disappeared".into())
            })?;
            if !matches!(
                operation.stage,
                IdentityRebindStage::SourceFreezing | IdentityRebindStage::StableWriting
            ) {
                continue;
            }
            let store = self.lifecycle_store.as_ref().cloned().ok_or_else(|| {
                EnclaveError::Store("identity rebind deletion lacks lifecycle authority".into())
            })?;
            let email = self
                .read({
                    let google_sub = operation.google_sub.clone();
                    move |conn| {
                        conn.query_row(
                            "SELECT email FROM users WHERE google_sub = ?1",
                            [&google_sub],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?
                        .ok_or_else(|| {
                            EnclaveError::Store("identity rebind deletion lost its account".into())
                        })
                    }
                })
                .await?;
            let transition = store
                .begin_identity_rebind(&operation.old_user_id, &operation.stable_user_id)
                .await?;
            match self
                .resume_identity_rebind(operation, transition, email)
                .await
            {
                Ok(_) | Err(EnclaveError::Auth(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Err(EnclaveError::Conflict(
            "identity rebind deletion claim did not reach a safe stage".into(),
        ))
    }

    /// Record that both exact namespaces have completed physical deletion.
    /// Final identity cleanup refuses to erase the operation before this
    /// durable reconciliation point.
    pub(crate) async fn mark_identity_rebind_deletion_reconciled(
        &self,
        user_id: &str,
    ) -> Result<()> {
        let user_id = user_id.to_string();
        self.write(move |conn| {
            let Some(operation) = identity_rebind_operation_for_user_conn(conn, &user_id)? else {
                return Ok(());
            };
            if operation.stage < IdentityRebindStage::DeletionPending {
                return Err(EnclaveError::Conflict(
                    "identity rebind deletion was not durably claimed".into(),
                ));
            }
            let reconciled = advance_identity_rebind_conn(
                conn,
                &operation,
                IdentityRebindStage::DeletionReconciled,
                operation.source_generation,
            )?;
            if reconciled.stage != IdentityRebindStage::DeletionReconciled {
                return Err(EnclaveError::Conflict(
                    "identity rebind deletion did not reconcile".into(),
                ));
            }
            Ok(())
        })
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
        let fence_object_name = self.identity_rebind_fence_object_name(&user_id).await?;
        self.write(move |conn| {
            begin_user_deletion_conn(conn, &user_id, &proposed_operation_id, &fence_object_name)
        })
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
        let fence_object_name = self.identity_rebind_fence_object_name(user_id).await?;
        let mut guard = self.inner.lock().await;
        if guard.is_none() {
            *guard = Some(self.load().await?);
        }
        let operation = match delete_user_identity_conn(
            &guard.as_ref().unwrap().conn,
            user_id,
            &fence_object_name,
        ) {
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

    pub async fn upsert_push_installation(
        &self,
        installation: PushInstallation,
    ) -> Result<PushInstallation> {
        self.write(move |conn| {
            if !is_active_user_conn(conn, &installation.user_id)? {
                return Err(EnclaveError::Auth("account inactive or deleting".into()));
            }
            let tx = conn.unchecked_transaction()?;
            tx.execute(
                "DELETE FROM push_installations WHERE topic=?1 AND environment=?2 \
                 AND device_token=?3 AND id<>?4",
                rusqlite::params![
                    installation.topic,
                    installation.environment,
                    installation.device_token,
                    installation.id
                ],
            )?;
            tx.execute(
                "INSERT INTO push_installations \
                   (id,user_id,platform,topic,environment,device_token,token_generation,enabled) \
                 VALUES (?1,?2,?3,?4,?5,?6,1,1) \
                 ON CONFLICT(id) DO UPDATE SET \
                   user_id=excluded.user_id,platform=excluded.platform,topic=excluded.topic, \
                   environment=excluded.environment, \
                   token_generation=CASE WHEN device_token=excluded.device_token \
                     AND topic=excluded.topic AND environment=excluded.environment \
                     THEN token_generation ELSE token_generation+1 END, \
                   device_token=excluded.device_token,enabled=1, \
                   updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), \
                   last_seen_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                rusqlite::params![
                    installation.id,
                    installation.user_id,
                    installation.platform,
                    installation.topic,
                    installation.environment,
                    installation.device_token,
                ],
            )?;
            let excess: i64 = tx.query_row(
                "SELECT MAX(0,COUNT(*)-10) FROM push_installations \
                 WHERE user_id=?1 AND enabled=1",
                [&installation.user_id],
                |row| row.get(0),
            )?;
            if excess > 0 {
                tx.execute(
                    "DELETE FROM push_installations WHERE id IN ( \
                       SELECT id FROM push_installations WHERE user_id=?1 AND enabled=1 AND id<>?2 \
                       ORDER BY last_seen_at ASC,id ASC LIMIT ?3)",
                    rusqlite::params![installation.user_id, installation.id, excess],
                )?;
            }
            let installed =
                load_push_installation_conn(&tx, &installation.user_id, &installation.id)?
                    .ok_or_else(|| {
                        EnclaveError::Store("push installation upsert disappeared".into())
                    })?;
            tx.commit()?;
            Ok(installed)
        })
        .await
    }

    pub async fn list_push_installations(&self, user_id: &str) -> Result<Vec<PushInstallation>> {
        let user_id = user_id.to_string();
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT id,user_id,platform,topic,environment,device_token,token_generation,enabled \
                 FROM push_installations WHERE user_id=?1 AND enabled=1 ORDER BY id",
            )?;
            let rows = statement.query_map([user_id], push_installation_from_row)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into)
        })
        .await
    }

    pub async fn get_push_installation(
        &self,
        user_id: &str,
        installation_id: &str,
    ) -> Result<Option<PushInstallation>> {
        let user_id = user_id.to_string();
        let installation_id = installation_id.to_string();
        self.read(move |conn| load_push_installation_conn(conn, &user_id, &installation_id))
            .await
    }

    pub async fn delete_push_installation(
        &self,
        user_id: &str,
        installation_id: &str,
    ) -> Result<bool> {
        let user_id = user_id.to_string();
        let installation_id = installation_id.to_string();
        self.write(move |conn| {
            Ok(conn.execute(
                "DELETE FROM push_installations WHERE user_id=?1 AND id=?2",
                rusqlite::params![user_id, installation_id],
            )? == 1)
        })
        .await
    }

    pub async fn disable_push_installation_generation(
        &self,
        user_id: &str,
        installation_id: &str,
        token_generation: i64,
    ) -> Result<bool> {
        let user_id = user_id.to_string();
        let installation_id = installation_id.to_string();
        self.write(move |conn| {
            Ok(conn.execute(
                "UPDATE push_installations SET enabled=0, \
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') \
                 WHERE user_id=?1 AND id=?2 AND token_generation=?3",
                rusqlite::params![user_id, installation_id, token_generation],
            )? == 1)
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
    use crate::archive_v3_lifecycle::InventoryPage;
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
        pause_after_put_target: std::sync::Mutex<Option<String>>,
        put_committed: Notify,
        resume_put: Notify,
        pause_after_get_target: std::sync::Mutex<Option<String>>,
        get_completed: Notify,
        resume_get: Notify,
    }

    impl PausingGcs {
        fn new(inner: Arc<crate::store::tests::FakeGcs>) -> Self {
            Self {
                inner,
                pause_next_control_list: AtomicBool::new(false),
                list_started: Notify::new(),
                resume_list: Notify::new(),
                pause_after_put_target: std::sync::Mutex::new(None),
                put_committed: Notify::new(),
                resume_put: Notify::new(),
                pause_after_get_target: std::sync::Mutex::new(None),
                get_completed: Notify::new(),
                resume_get: Notify::new(),
            }
        }

        fn pause_next_control_list(&self) {
            self.pause_next_control_list.store(true, Ordering::SeqCst);
        }

        fn pause_after_next_put(&self, object_name: &str) {
            *self.pause_after_put_target.lock().unwrap() = Some(object_name.to_string());
        }

        fn pause_after_next_get(&self, object_name: &str) {
            *self.pause_after_get_target.lock().unwrap() = Some(object_name.to_string());
        }
    }

    #[async_trait::async_trait]
    impl GcsClient for PausingGcs {
        async fn trusted_time_millis(
            &self,
            authority_object_name: &str,
            authority_generation: i64,
        ) -> Result<i64> {
            self.inner
                .trusted_time_millis(authority_object_name, authority_generation)
                .await
        }

        async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse> {
            let result = self.inner.get_object(object_name).await;
            let should_pause = {
                let mut target = self.pause_after_get_target.lock().unwrap();
                if target.as_deref() == Some(object_name) {
                    *target = None;
                    true
                } else {
                    false
                }
            };
            if should_pause {
                self.get_completed.notify_one();
                self.resume_get.notified().await;
            }
            result
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
            let generation = self
                .inner
                .put_object(
                    object_name,
                    ciphertext,
                    wrapped_dek_b64,
                    if_generation_match,
                )
                .await?;
            let should_pause = {
                let mut target = self.pause_after_put_target.lock().unwrap();
                if target.as_deref() == Some(object_name) {
                    *target = None;
                    true
                } else {
                    false
                }
            };
            if should_pause {
                self.put_committed.notify_one();
                self.resume_put.notified().await;
            }
            Ok(generation)
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

    async fn seed_legacy_rebind_account(
        control: &ControlStore,
        content: &Store,
        subject: &str,
        old_user_id: &str,
    ) {
        content
            .with_user(old_user_id, |conn| {
                conn.execute(
                    "INSERT INTO app_metadata (key, value) VALUES ('legacy-rebind', 'seeded')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        content.save_user(old_user_id).await.unwrap();
        let subject = subject.to_string();
        let old_user_id = old_user_id.to_string();
        control
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO users (id, google_sub, email)
                     VALUES (?1, ?2, 'legacy@example.com')",
                    rusqlite::params![old_user_id, subject],
                )?;
                create_active_archive_binding_conn(conn, &old_user_id)?;
                Ok(())
            })
            .await
            .unwrap();
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
        conn.execute(
            "INSERT INTO push_installations
             (id,user_id,platform,topic,environment,device_token)
             VALUES ('22222222-2222-4222-8222-222222222222',?1,'ios','com.kioku.ios',
                     'production','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
            [USER_ID],
        )
        .unwrap();
        create_active_archive_binding_conn(&conn, USER_ID).unwrap();
        conn
    }

    fn lifecycle_file_conn(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let exists: i64 = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)",
                [USER_ID],
                |row| row.get(0),
            )
            .unwrap();
        if exists == 0 {
            conn.execute(
                "INSERT INTO users (id, google_sub, email)
                 VALUES (?1, ?2, 'owner@example.com')",
                rusqlite::params![USER_ID, GOOGLE_SUB],
            )
            .unwrap();
            create_active_archive_binding_conn(&conn, USER_ID).unwrap();
        }
        conn
    }

    fn lifecycle_plan(conn: &Connection) -> BootstrapPlan {
        let binding = create_active_archive_binding_conn(conn, USER_ID).unwrap();
        BootstrapPlan::new(
            binding.archive_id(),
            crate::archive_v3_lifecycle::BootstrapAttemptId::from_bytes([41; 16]).unwrap(),
            crate::archive_v3::DatabaseEpoch::from_bytes([42; 16]),
            crate::archive_v3::KeyEpoch::from_bytes([43; 16]),
            ObjectId::from_bytes([44; 16]),
            ObjectId::from_bytes([45; 16]),
        )
        .unwrap()
    }

    fn durable_inventory_page(page: InventoryPage) -> DurableInventoryPage {
        let encoded = page.encoded().to_vec();
        DurableInventoryPage::from_exact_readback(page, &encoded).unwrap()
    }

    #[test]
    fn bootstrap_recovery_needs_only_archive_authority_after_close_and_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sqlite");
        let conn = lifecycle_file_conn(&path);
        let plan = lifecycle_plan(&conn);
        let archive_id = plan.archive_id();
        reserve_archive_bootstrap_conn(&conn, plan).unwrap();
        drop(conn);

        let conn = lifecycle_file_conn(&path);
        let recovered = recover_archive_bootstrap_conn(&conn, archive_id).unwrap();
        assert_eq!(recovered.reservation().plan(), plan);
        assert!(recovered.prepared().is_none());
        let reservation = recovered.reservation();
        prepare_archive_bootstrap_conn(&conn, reservation, b"wrapped-restart", b"root-restart")
            .unwrap();
        drop(conn);

        let conn = lifecycle_file_conn(&path);
        let recovered = recover_archive_bootstrap_conn(&conn, archive_id).unwrap();
        let prepared = recovered.prepared().unwrap();
        assert_eq!(prepared.reservation().plan(), plan);
        assert_eq!(prepared.wrapped_registry(), b"wrapped-restart");
        assert_eq!(prepared.root_envelope(), b"root-restart");
    }

    #[test]
    fn lifecycle_bootstrap_is_create_ahead_restart_stable_and_freezes_admission() {
        let conn = account_conn();
        let plan = lifecycle_plan(&conn);
        let reserved = reserve_archive_bootstrap_conn(&conn, plan).unwrap();
        assert_eq!(reserved.revision(), 1);
        let recovered = reserve_archive_bootstrap_conn(&conn, plan).unwrap();
        assert_eq!(recovered, reserved);
        let conflicting = BootstrapPlan::new(
            plan.archive_id(),
            crate::archive_v3_lifecycle::BootstrapAttemptId::from_bytes([99; 16]).unwrap(),
            plan.database_epoch(),
            plan.key_epoch(),
            plan.registry_object_id(),
            plan.root_object_id(),
        )
        .unwrap();
        assert!(reserve_archive_bootstrap_conn(&conn, conflicting).is_err());

        let prepared =
            prepare_archive_bootstrap_conn(&conn, reserved, b"wrapped", b"root").unwrap();
        let recovered_reservation = reserve_archive_bootstrap_conn(&conn, plan).unwrap();
        assert_eq!(recovered_reservation, reserved);
        let recovered_prepared =
            prepare_archive_bootstrap_conn(&conn, recovered_reservation, b"replacement", b"bytes")
                .unwrap();
        assert_eq!(recovered_prepared.wrapped_registry(), b"wrapped");
        assert_eq!(recovered_prepared.root_envelope(), b"root");
        assert_eq!(recovered_prepared.revision(), prepared.revision());
        let exact_bytes: (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT wrapped_registry_bytes, root_envelope_bytes
                 FROM archive_lifecycle_anchors WHERE archive_id = ?1",
                [plan.archive_id().as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(exact_bytes, (b"wrapped".to_vec(), b"root".to_vec()));
        assert!(prepare_archive_witness_conn(
            &conn,
            plan.archive_id(),
            prepared.revision(),
            b"witness"
        )
        .is_err());

        let registry = admit_archive_create_conn(
            &conn,
            plan.archive_id(),
            prepared.revision(),
            LIFECYCLE_REGISTRY_ORDINAL,
        )
        .unwrap();
        assert!(admit_archive_create_conn(
            &conn,
            plan.archive_id(),
            registry.revision(),
            LIFECYCLE_ROOT_ORDINAL,
        )
        .is_err());
        assert_eq!(
            reconcile_archive_create_conn(&conn, &registry, LifecycleCreateOutcome::OutcomeUnknown)
                .unwrap(),
            registry.revision()
        );
        let revision = reconcile_archive_create_conn(
            &conn,
            &registry,
            LifecycleCreateOutcome::AlreadyPresentExact,
        )
        .unwrap();
        let root =
            admit_archive_create_conn(&conn, plan.archive_id(), revision, LIFECYCLE_ROOT_ORDINAL)
                .unwrap();
        let revision =
            reconcile_archive_create_conn(&conn, &root, LifecycleCreateOutcome::Created).unwrap();
        let revision = prepare_archive_witness_conn(
            &conn,
            plan.archive_id(),
            revision,
            b"exact-witness-record",
        )
        .unwrap();
        assert_eq!(
            prepare_archive_witness_conn(
                &conn,
                plan.archive_id(),
                revision,
                b"exact-witness-record",
            )
            .unwrap(),
            revision
        );
        assert!(prepare_archive_witness_conn(
            &conn,
            plan.archive_id(),
            revision,
            b"different-witness-record",
        )
        .is_err());
        let witness = admit_archive_create_conn(
            &conn,
            plan.archive_id(),
            revision,
            LIFECYCLE_WITNESS_ORDINAL,
        )
        .unwrap();
        reconcile_archive_create_conn(&conn, &witness, LifecycleCreateOutcome::OutcomeUnknown)
            .unwrap();

        let fence_name = crate::store::test_identity_rebind_fence_object_name(USER_ID);
        let ledger = tombstone_archive_deletion_ledger_conn(&conn, USER_ID, &fence_name).unwrap();
        let fence = ObjectId::from_bytes(*ledger.deletion_fence_id.unwrap().as_bytes());
        assert!(admit_archive_create_conn(
            &conn,
            plan.archive_id(),
            witness.revision(),
            LIFECYCLE_ROOT_ORDINAL,
        )
        .is_err());
        assert!(active_lifecycle_revision_conn(&conn, plan.archive_id()).is_err());
        assert_eq!(
            lifecycle_anchor_conn(&conn, plan.archive_id())
                .unwrap()
                .unwrap()
                .revision,
            witness.revision() + 1
        );
        let frozen_revision =
            freeze_archive_lifecycle_conn(&conn, plan.archive_id(), witness.revision(), fence)
                .unwrap();
        assert_eq!(frozen_revision, witness.revision() + 1);
        assert_eq!(
            freeze_archive_lifecycle_conn(&conn, plan.archive_id(), witness.revision(), fence)
                .unwrap(),
            frozen_revision
        );
        assert!(admit_archive_create_conn(
            &conn,
            plan.archive_id(),
            frozen_revision,
            LIFECYCLE_ROOT_ORDINAL,
        )
        .is_err());
        let reconciled =
            reconcile_archive_create_conn(&conn, &witness, LifecycleCreateOutcome::ConfirmedAbsent)
                .unwrap();
        assert_eq!(reconciled, frozen_revision + 1);
    }

    #[test]
    fn lifecycle_inventory_seal_detects_omission_tamper_and_rollback() {
        let conn = account_conn();
        let plan = lifecycle_plan(&conn);
        let reserved = reserve_archive_bootstrap_conn(&conn, plan).unwrap();
        let prepared =
            prepare_archive_bootstrap_conn(&conn, reserved, b"wrapped", b"root").unwrap();
        let registry = admit_archive_create_conn(
            &conn,
            plan.archive_id(),
            prepared.revision(),
            LIFECYCLE_REGISTRY_ORDINAL,
        )
        .unwrap();
        let revision = reconcile_archive_create_conn(
            &conn,
            &registry,
            LifecycleCreateOutcome::ConfirmedAbsent,
        )
        .unwrap();
        let root =
            admit_archive_create_conn(&conn, plan.archive_id(), revision, LIFECYCLE_ROOT_ORDINAL)
                .unwrap();
        let revision =
            reconcile_archive_create_conn(&conn, &root, LifecycleCreateOutcome::Created).unwrap();
        let fence_name = crate::store::test_identity_rebind_fence_object_name(USER_ID);
        let ledger = tombstone_archive_deletion_ledger_conn(&conn, USER_ID, &fence_name).unwrap();
        let fence = ObjectId::from_bytes(*ledger.deletion_fence_id.unwrap().as_bytes());
        let revision =
            freeze_archive_lifecycle_conn(&conn, plan.archive_id(), revision, fence).unwrap();
        let entries = lifecycle_create_ahead_conn(&conn, plan).unwrap();
        assert!(seal_archive_inventory_conn(
            &conn,
            plan.archive_id(),
            revision,
            fence,
            &[durable_inventory_page(
                InventoryPage::build(plan.archive_id(), 0, [0; 32], vec![entries[0].clone()])
                    .unwrap(),
            )],
        )
        .is_err());
        let page = InventoryPage::build(plan.archive_id(), 0, [0; 32], entries).unwrap();
        let pages = vec![durable_inventory_page(page)];
        let seal =
            seal_archive_inventory_conn(&conn, plan.archive_id(), revision, fence, &pages).unwrap();
        let references = load_sealed_archive_inventory_references_conn(&conn, &seal).unwrap();
        assert_eq!(references.len(), 1);
        let stale = DeletionInventorySeal::for_test(
            plan.archive_id(),
            ObjectId::from_bytes([77; 16]),
            seal.revision(),
            &pages,
        )
        .unwrap();
        assert!(load_sealed_archive_inventory_references_conn(&conn, &stale).is_err());
        let completion = PhysicalDeletionReceipt::for_test(seal, [88; 32]).unwrap();
        // A witness/provider receipt remains insufficient after a crash until
        // the control anchor durably records the same commitment. The CAS is
        // exactly recoverable and idempotent after restart.
        let durable_completion = mark_archive_physical_complete_conn(&conn, &completion).unwrap();
        assert_eq!(
            mark_archive_physical_complete_conn(&conn, &completion).unwrap(),
            durable_completion
        );
        let erased_pages =
            ErasedInventoryPages::from_exact_absence(&durable_completion, &references).unwrap();
        assert_eq!(
            load_sealed_archive_inventory_references_conn(&conn, &seal).unwrap(),
            references
        );
        erase_archive_lifecycle_payload_conn(&conn, &durable_completion, erased_pages).unwrap();
        let erased: (Option<Vec<u8>>, Option<Vec<u8>>, i64, i64) = conn
            .query_row(
                "SELECT wrapped_registry_bytes, root_envelope_bytes, payload_erased,
                        (SELECT count(*) FROM archive_lifecycle_inventory_pages
                         WHERE archive_id = ?1)
                 FROM archive_lifecycle_anchors WHERE archive_id = ?1",
                [plan.archive_id().as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(erased, (None, None, 1, 1));
        conn.execute(
            "UPDATE archive_lifecycle_inventory_pages
             SET page_hash = zeroblob(32)
             WHERE archive_id = ?1 AND page_ordinal = 0",
            [plan.archive_id().as_bytes().as_slice()],
        )
        .unwrap();
        assert!(load_sealed_archive_inventory_references_conn(&conn, &seal).is_err());
    }

    #[test]
    fn deletion_recovery_survives_close_after_seal_control_mark_and_page_erasure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sqlite");
        let conn = lifecycle_file_conn(&path);
        let plan = lifecycle_plan(&conn);
        let archive_id = plan.archive_id();
        let reserved = reserve_archive_bootstrap_conn(&conn, plan).unwrap();
        let prepared =
            prepare_archive_bootstrap_conn(&conn, reserved, b"wrapped", b"root").unwrap();
        let registry = admit_archive_create_conn(
            &conn,
            archive_id,
            prepared.revision(),
            LIFECYCLE_REGISTRY_ORDINAL,
        )
        .unwrap();
        let revision =
            reconcile_archive_create_conn(&conn, &registry, LifecycleCreateOutcome::Created)
                .unwrap();
        let root =
            admit_archive_create_conn(&conn, archive_id, revision, LIFECYCLE_ROOT_ORDINAL).unwrap();
        let revision =
            reconcile_archive_create_conn(&conn, &root, LifecycleCreateOutcome::Created).unwrap();
        let fence_name = crate::store::test_identity_rebind_fence_object_name(USER_ID);
        let ledger = tombstone_archive_deletion_ledger_conn(&conn, USER_ID, &fence_name).unwrap();
        let fence = ObjectId::from_bytes(*ledger.deletion_fence_id.unwrap().as_bytes());
        let frozen_revision =
            freeze_archive_lifecycle_conn(&conn, archive_id, revision, fence).unwrap();
        let entries = lifecycle_create_ahead_conn(&conn, plan).unwrap();
        let page = InventoryPage::build(archive_id, 0, [0; 32], entries).unwrap();
        let pages = vec![durable_inventory_page(page)];
        seal_archive_inventory_conn(&conn, archive_id, frozen_revision, fence, &pages).unwrap();
        drop(pages);
        drop(conn);

        // No caller-retained seal survives this restart. The encrypted anchor
        // and exact page-reference chain reconstruct it in one snapshot.
        let conn = lifecycle_file_conn(&path);
        let recovered = recover_archive_deletion_lifecycle_conn(&conn, archive_id, fence).unwrap();
        assert!(recovered.physical_completion().is_none());
        let seal = recovered.seal();
        let physical = PhysicalDeletionReceipt::for_test(seal, [88; 32]).unwrap();
        mark_archive_physical_complete_conn(&conn, &physical).unwrap();
        let references = load_sealed_archive_inventory_references_conn(&conn, &seal).unwrap();
        let durable = recover_archive_deletion_lifecycle_conn(&conn, archive_id, fence)
            .unwrap()
            .physical_completion()
            .unwrap();
        // Model exact page-store erasure, then lose both the absence receipt
        // and every old seal/completion value in a process crash.
        ErasedInventoryPages::from_exact_absence(&durable, &references).unwrap();
        drop(conn);

        let conn = lifecycle_file_conn(&path);
        let recovered = recover_archive_deletion_lifecycle_conn(&conn, archive_id, fence).unwrap();
        let durable = recovered.physical_completion().unwrap();
        let references =
            load_sealed_archive_inventory_references_conn(&conn, &recovered.seal()).unwrap();
        let erased = ErasedInventoryPages::from_exact_absence(&durable, &references).unwrap();
        erase_archive_lifecycle_payload_conn(&conn, &durable, erased).unwrap();
        let payload_erased: i64 = conn
            .query_row(
                "SELECT payload_erased FROM archive_lifecycle_anchors WHERE archive_id = ?1",
                [archive_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(payload_erased, 1);
    }

    #[test]
    fn lifecycle_control_codec_round_trips_wal_v3_roles_and_rejects_relabeling() {
        let conn = account_conn();
        let plan = lifecycle_plan(&conn);
        let reserved = reserve_archive_bootstrap_conn(&conn, plan).unwrap();
        prepare_archive_bootstrap_conn(&conn, reserved, b"wrapped", b"root").unwrap();
        let wal = ObjectContext::new(
            plan.archive_id(),
            plan.database_epoch(),
            plan.key_epoch(),
            ObjectRole::WalSegmentV3,
            LogicalLocation::Wal {
                root_seq: 1,
                wal_generation: 1,
                segment_index: 0,
            },
            ObjectId::from_bytes([81; 16]),
            None,
        )
        .unwrap()
        .object_key();
        let commit = ObjectContext::new(
            plan.archive_id(),
            plan.database_epoch(),
            plan.key_epoch(),
            ObjectRole::WalCommitDescriptorV3,
            LogicalLocation::WalCommitDescriptor { root_seq: 1 },
            ObjectId::from_bytes([82; 16]),
            None,
        )
        .unwrap()
        .object_key();
        for (ordinal, key, role) in [
            (LIFECYCLE_REGISTRY_ORDINAL, &wal, ObjectRole::WalSegmentV3),
            (
                LIFECYCLE_ROOT_ORDINAL,
                &commit,
                ObjectRole::WalCommitDescriptorV3,
            ),
        ] {
            conn.execute(
                "UPDATE archive_lifecycle_bootstrap_creates
                 SET canonical_key = ?4, object_id = ?5, object_role = ?6
                 WHERE archive_id = ?1 AND bootstrap_attempt_id = ?2
                   AND artifact_ordinal = ?3",
                rusqlite::params![
                    plan.archive_id().as_bytes().as_slice(),
                    plan.attempt_id().as_bytes().as_slice(),
                    i64::from(ordinal),
                    key.as_str(),
                    key.object_id().as_bytes().as_slice(),
                    i64::from(role as u8),
                ],
            )
            .unwrap();
        }
        let decoded = lifecycle_create_ahead_conn(&conn, plan).unwrap();
        assert_eq!(decoded[0].role(), ObjectRole::WalSegmentV3);
        assert_eq!(decoded[1].role(), ObjectRole::WalCommitDescriptorV3);
        conn.execute(
            "UPDATE archive_lifecycle_bootstrap_creates SET object_role = 6
             WHERE archive_id = ?1 AND artifact_ordinal = ?2",
            rusqlite::params![
                plan.archive_id().as_bytes().as_slice(),
                i64::from(LIFECYCLE_ROOT_ORDINAL),
            ],
        )
        .unwrap();
        assert!(lifecycle_create_ahead_conn(&conn, plan).is_err());
    }

    #[test]
    fn retained_account_metrics_count_only_active_rows_in_the_requested_utc_month() {
        let conn = account_conn();
        conn.execute(
            "UPDATE users SET created_at='2026-08-01T00:00:00.000Z' WHERE id=?1",
            [USER_ID],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO users (id,google_sub,email,status,created_at) VALUES
               ('11111111-1111-4111-8111-111111111112','prior','prior@example.com','active','2026-07-31T23:59:59.999Z'),
               ('11111111-1111-4111-8111-111111111113','future','future@example.com','active','2026-09-01T00:00:00.000Z'),
               ('11111111-1111-4111-8111-111111111114','deleting','deleting@example.com','deleting','2026-08-02T00:00:00.000Z');",
        )
        .unwrap();

        assert_eq!(
            retained_active_account_metrics_conn(&conn, "2026-08").unwrap(),
            RetainedAccountMetrics {
                retained_active_accounts: 3,
                new_retained_active_accounts_mtd: 1,
            }
        );
    }

    #[test]
    fn unknown_users_are_not_active() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        assert!(!is_active_user_conn(&conn, "missing").unwrap());
    }

    #[test]
    fn archive_id_allocation_retries_zero_and_cross_user_collision_but_is_bounded() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        let first =
            create_active_archive_binding_with_candidates(&conn, "first", || [2; 16]).unwrap();
        assert_eq!(first.archive_id().as_bytes(), &[2; 16]);

        let mut candidates = [[0; 16], [2; 16], [3; 16]].into_iter();
        let second = create_active_archive_binding_with_candidates(&conn, "second", || {
            candidates.next().unwrap()
        })
        .unwrap();
        assert_eq!(second.archive_id().as_bytes(), &[3; 16]);

        // Finalization erases the identity mapping but retains its archive-keyed
        // tombstone. That ID remains permanently unavailable to new accounts.
        conn.execute(
            "INSERT INTO archive_deletion_ledgers
             (archive_id, state, deletion_fence_id, tombstoned_at)
             VALUES (?1, 'tombstoned', ?2, '2026-08-11T00:00:00.000Z')",
            rusqlite::params![[4_u8; 16].as_slice(), [5_u8; 16].as_slice()],
        )
        .unwrap();
        let mut retained_collision = [[4; 16], [6; 16]].into_iter();
        let after_retained =
            create_active_archive_binding_with_candidates(&conn, "after-retained", || {
                retained_collision.next().unwrap()
            })
            .unwrap();
        assert_eq!(after_retained.archive_id().as_bytes(), &[6; 16]);

        // Same-user creation is idempotent and never asks for another random
        // candidate after the exact binding and ledger already exist.
        let replay =
            create_active_archive_binding_with_candidates(&conn, "second", || -> [u8; 16] {
                panic!("idempotent binding replay consumed randomness")
            })
            .unwrap();
        assert_eq!(replay, second);

        let mut attempts = 0;
        let exhausted = create_active_archive_binding_with_candidates(&conn, "third", || {
            attempts += 1;
            if attempts % 2 == 0 {
                [2; 16]
            } else {
                [0; 16]
            }
        });
        assert!(matches!(exhausted, Err(EnclaveError::Conflict(_))));
        assert_eq!(attempts, MAX_ARCHIVE_ID_CANDIDATES);
        assert_eq!(archive_binding_conn(&conn, "third").unwrap(), None);
    }

    #[test]
    fn archive_schema_and_decoder_reject_zero_ids_and_invalid_fences() {
        let schema_conn = Connection::open_in_memory().unwrap();
        schema_conn.execute_batch(SCHEMA).unwrap();
        assert!(schema_conn
            .execute(
                "INSERT INTO archive_bindings (user_id, archive_id, state)
                 VALUES ('zero', zeroblob(16), 'active_legacy')",
                [],
            )
            .is_err());
        create_active_archive_binding_with_candidates(&schema_conn, "active", || [4; 16]).unwrap();
        assert!(schema_conn
            .execute(
                "UPDATE archive_deletion_ledgers
                 SET state = 'tombstoned', tombstoned_at = '2026-08-11T00:00:00.000Z'
                 WHERE archive_id = ?1",
                [ArchiveId::from_bytes([4; 16]).as_bytes().as_slice()],
            )
            .is_err());

        let zero_binding = account_conn();
        zero_binding
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        zero_binding
            .execute(
                "UPDATE archive_bindings SET archive_id = zeroblob(16) WHERE user_id = ?1",
                [USER_ID],
            )
            .unwrap();
        assert!(archive_binding_conn(&zero_binding, USER_ID).is_err());

        let active_fence = account_conn();
        active_fence
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        active_fence
            .execute(
                "UPDATE archive_deletion_ledgers SET deletion_fence_id = ?2
                 WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                rusqlite::params![USER_ID, [5_u8; 16].as_slice()],
            )
            .unwrap();
        assert!(archive_deletion_ledger_conn(&active_fence, USER_ID).is_err());

        let unsupported_inventory = account_conn();
        unsupported_inventory
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        unsupported_inventory
            .execute(
                "UPDATE archive_deletion_ledgers SET inventory_format_version = 2
                 WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                [USER_ID],
            )
            .unwrap();
        assert!(archive_deletion_ledger_conn(&unsupported_inventory, USER_ID).is_err());

        let active_with_tombstone_time = account_conn();
        active_with_tombstone_time
            .execute(
                "UPDATE archive_bindings
                 SET tombstoned_at = '2026-08-11T00:00:00.000Z'
                 WHERE user_id = ?1",
                [USER_ID],
            )
            .unwrap();
        assert!(archive_deletion_ledger_conn(&active_with_tombstone_time, USER_ID).is_err());

        let tombstone_without_ledger_time = account_conn();
        tombstone_without_ledger_time
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        tombstone_without_ledger_time
            .execute(
                "UPDATE archive_bindings
                 SET state = 'tombstoned', tombstoned_at = '2026-08-11T00:00:00.000Z'
                 WHERE user_id = ?1",
                [USER_ID],
            )
            .unwrap();
        tombstone_without_ledger_time
            .execute(
                "UPDATE archive_deletion_ledgers
                 SET state = 'tombstoned', deletion_fence_id = ?2, tombstoned_at = NULL
                 WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                rusqlite::params![USER_ID, [6_u8; 16].as_slice()],
            )
            .unwrap();
        assert!(archive_deletion_ledger_conn(&tombstone_without_ledger_time, USER_ID).is_err());

        for fence in [None, Some([0_u8; 16])] {
            let tombstoned = account_conn();
            tombstoned
                .execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            tombstoned
                .execute(
                    "UPDATE archive_bindings
                     SET state = 'tombstoned', tombstoned_at = '2026-08-11T00:00:00.000Z'
                     WHERE user_id = ?1",
                    [USER_ID],
                )
                .unwrap();
            tombstoned
                .execute(
                    "UPDATE archive_deletion_ledgers
                     SET state = 'tombstoned', deletion_fence_id = ?2,
                         tombstoned_at = '2026-08-11T00:00:00.000Z'
                     WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                    rusqlite::params![USER_ID, fence.map(|value| value.to_vec())],
                )
                .unwrap();
            assert!(archive_deletion_ledger_conn(&tombstoned, USER_ID).is_err());
        }
    }

    #[test]
    fn archive_deletion_ledger_debug_redacts_nonempty_cursors() {
        let ledger = ArchiveDeletionLedger {
            binding: ArchiveBinding {
                archive_id: ArchiveId::from_bytes([7; 16]),
            },
            state: ArchiveDeletionState::Tombstoned,
            deletion_fence_id: Some(ArchiveId::from_bytes([8; 16])),
            archive_object_cursor: Some(b"provider-object-cursor".to_vec()),
            key_registry_cursor: Some(b"provider-key-cursor".to_vec()),
            legacy_generation_cursor: Some(b"provider-legacy-cursor".to_vec()),
            media_inventory_cursor: Some(b"provider-media-cursor".to_vec()),
            legacy_rebind_fence_object_name: Some("opaque-fence-name".into()),
        };
        let rendered = format!("{ledger:?}");
        assert_eq!(rendered, "ArchiveDeletionLedger(<opaque>)");
        assert!(!rendered.contains("cursor"));
        assert!(!rendered.contains('7'));
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
        let fence = crate::store::test_identity_rebind_fence_object_name(USER_ID);
        let first = begin_user_deletion_conn(&conn, USER_ID, OPERATION_ID, &fence)
            .unwrap()
            .unwrap();
        // Initialization is idempotent so a failed content deletion can retry.
        let retry = begin_user_deletion_conn(&conn, USER_ID, "del_different", &fence)
            .unwrap()
            .unwrap();
        assert_eq!(first.operation_id, OPERATION_ID);
        assert_eq!(retry.operation_id, OPERATION_ID);
        let fenced_ledger = archive_deletion_ledger_conn(&conn, USER_ID)
            .unwrap()
            .unwrap();
        assert_eq!(fenced_ledger.state, ArchiveDeletionState::Tombstoned);
        assert!(fenced_ledger.archive_object_cursor.is_none());
        assert!(fenced_ledger.key_registry_cursor.is_none());
        assert!(fenced_ledger.legacy_generation_cursor.is_none());
        assert!(fenced_ledger.media_inventory_cursor.is_none());
        assert_eq!(
            format!("{:?}", fenced_ledger.binding),
            "ArchiveBinding(<opaque>)"
        );
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
        let push_enabled: i64 = conn
            .query_row(
                "SELECT enabled FROM push_installations WHERE user_id = ?1",
                [USER_ID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(push_enabled, 0);

        let completed = delete_user_identity_conn(&conn, USER_ID, &fence).unwrap();
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
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM push_installations WHERE user_id = ?1",
                [USER_ID],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        // The v3 ledger deliberately remains fenced after ordinary identity
        // removal. It has no completion marker because no v3 provider was
        // called by this legacy deletion path.
        assert_eq!(archive_binding_conn(&conn, USER_ID).unwrap(), None);
        let retained_state: String = conn
            .query_row(
                "SELECT state FROM archive_deletion_ledgers WHERE archive_id = ?1",
                [fenced_ledger.binding.archive_id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            ArchiveDeletionState::from_db(&retained_state).unwrap(),
            ArchiveDeletionState::Tombstoned
        );
        for table in [
            "recording_leases",
            "recording_lease_requests",
            "recording_lease_denials",
            "recording_delivery_balances",
            "recording_delivery_reservations",
            "offline_recording_usage_receipts",
        ] {
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
    fn deletion_consumes_every_identity_rebind_stage_and_waits_only_for_provider_creates() {
        let stages = [
            IdentityRebindStage::Prepared,
            IdentityRebindStage::SourceFreezing,
            IdentityRebindStage::SourceFrozen,
            IdentityRebindStage::StableWriting,
            IdentityRebindStage::StableWritten,
            IdentityRebindStage::OldPurging,
            IdentityRebindStage::OldPurged,
            IdentityRebindStage::Committed,
        ];
        for (index, stage) in stages.into_iter().enumerate() {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(SCHEMA).unwrap();
            let old_id = format!("legacy-delete-stage-{index}");
            let subject = format!("delete-stage-subject-{index}");
            let stable_id = super::super::tokens::derive_stable_uuid(&subject);
            conn.execute(
                "INSERT INTO users (id, google_sub, email) VALUES (?1, ?2, 'stage@example.com')",
                rusqlite::params![old_id, subject],
            )
            .unwrap();
            let binding = create_active_archive_binding_conn(&conn, &old_id).unwrap();
            let source = IdentityRebindSource {
                base_generation: 1,
                source_generation: 1,
                commitment: [index as u8 + 1; 32],
                plaintext: Vec::new(),
                wrapped_dek_b64: String::new(),
            };
            let operation_id = format!("rebind_{:064x}", index + 1);
            let mut operation = prepare_identity_rebind_conn(
                &conn,
                &operation_id,
                &subject,
                &old_id,
                &stable_id,
                &crate::store::test_identity_rebind_fence_object_name(&old_id),
                binding,
                &source,
            )
            .unwrap();
            if stage != IdentityRebindStage::Prepared {
                let generation = if stage == IdentityRebindStage::SourceFreezing {
                    None
                } else {
                    Some(2)
                };
                conn.execute(
                    "UPDATE identity_rebind_operations SET stage = ?2, source_generation = ?3
                     WHERE operation_id = ?1",
                    rusqlite::params![operation_id, stage.as_db(), generation],
                )
                .unwrap();
                operation = identity_rebind_operation_for_subject_conn(&conn, &subject)
                    .unwrap()
                    .unwrap();
            }
            let fence = crate::store::test_identity_rebind_fence_object_name(&old_id);
            begin_user_deletion_conn(&conn, &old_id, &format!("del_{:064x}", index + 1), &fence)
                .unwrap()
                .unwrap();

            let writing = matches!(
                stage,
                IdentityRebindStage::SourceFreezing | IdentityRebindStage::StableWriting
            );
            assert_eq!(
                claim_identity_rebind_deletion_conn(&conn, &old_id).unwrap(),
                !writing,
                "unexpected claim result at {stage:?}"
            );
            if writing {
                let _completed = advance_identity_rebind_conn(
                    &conn,
                    &operation,
                    match stage {
                        IdentityRebindStage::SourceFreezing => IdentityRebindStage::SourceFrozen,
                        IdentityRebindStage::StableWriting => IdentityRebindStage::StableWritten,
                        _ => unreachable!(),
                    },
                    Some(2),
                )
                .unwrap();
                assert!(claim_identity_rebind_deletion_conn(&conn, &old_id).unwrap());
            }
            let claimed = identity_rebind_operation_for_user_conn(&conn, &old_id)
                .unwrap()
                .unwrap();
            assert_eq!(claimed.stage, IdentityRebindStage::DeletionPending);
            assert!(matches!(
                delete_user_identity_conn(&conn, &old_id, &fence),
                Err(EnclaveError::Conflict(_))
            ));
            let reconciled = advance_identity_rebind_conn(
                &conn,
                &claimed,
                IdentityRebindStage::DeletionReconciled,
                claimed.source_generation,
            )
            .unwrap();
            assert_eq!(reconciled.stage, IdentityRebindStage::DeletionReconciled);
            assert_eq!(
                delete_user_identity_conn(&conn, &old_id, &fence)
                    .unwrap()
                    .status,
                "physical_complete"
            );
            assert!(identity_rebind_operation_for_user_conn(&conn, &old_id)
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn live_deletion_retry_resumes_source_freezing_without_restart() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let content = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let control = ControlStore::new_with_store(kms, gcs, content.clone());
        let old_user_id = "live-delete-source-freezing";
        let subject = "live-delete-source-freezing-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        seed_legacy_rebind_account(&control, &content, subject, old_user_id).await;

        let mut transition = content
            .begin_identity_rebind(old_user_id, &stable_user_id)
            .await
            .unwrap();
        let source = transition.source_snapshot().await.unwrap();
        let binding = control
            .archive_deletion_ledger(old_user_id)
            .await
            .unwrap()
            .unwrap()
            .binding;
        let operation = control
            .prepare_identity_rebind(subject, old_user_id, &stable_user_id, binding, &source)
            .await
            .unwrap();
        let operation = control
            .advance_identity_rebind(&operation, IdentityRebindStage::SourceFreezing, None)
            .await
            .unwrap();
        assert_eq!(operation.stage, IdentityRebindStage::SourceFreezing);
        drop(transition);

        control
            .begin_user_deletion(old_user_id)
            .await
            .unwrap()
            .unwrap();
        assert!(control
            .claim_identity_rebind_deletion(old_user_id)
            .await
            .unwrap());
        let claimed = control
            .identity_rebind_operation_for_user(old_user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.stage, IdentityRebindStage::DeletionPending);
        assert!(claimed
            .source_generation
            .is_some_and(|generation| generation > 0));
    }

    #[tokio::test]
    async fn live_deletion_retry_resumes_stable_writing_without_restart() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let content = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let control = ControlStore::new_with_store(kms, gcs.clone(), content.clone());
        let old_user_id = "live-delete-stable-writing";
        let subject = "live-delete-stable-writing-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        seed_legacy_rebind_account(&control, &content, subject, old_user_id).await;

        let mut transition = content
            .begin_identity_rebind(old_user_id, &stable_user_id)
            .await
            .unwrap();
        let source = transition.source_snapshot().await.unwrap();
        let binding = control
            .archive_deletion_ledger(old_user_id)
            .await
            .unwrap()
            .unwrap()
            .binding;
        let mut operation = control
            .prepare_identity_rebind(subject, old_user_id, &stable_user_id, binding, &source)
            .await
            .unwrap();
        operation = control
            .advance_identity_rebind(&operation, IdentityRebindStage::SourceFreezing, None)
            .await
            .unwrap();
        let authority = control
            .ensure_identity_rebind_provider_fence(&operation)
            .await
            .unwrap();
        let frozen = transition
            .freeze_source(
                operation.source_base_generation,
                &operation.source_commitment,
                &authority,
            )
            .await
            .unwrap();
        operation = control
            .advance_identity_rebind(
                &operation,
                IdentityRebindStage::SourceFrozen,
                Some(frozen.source_generation),
            )
            .await
            .unwrap();
        control
            .advance_identity_rebind(
                &operation,
                IdentityRebindStage::StableWriting,
                operation.source_generation,
            )
            .await
            .unwrap();
        drop(transition);

        control
            .begin_user_deletion(old_user_id)
            .await
            .unwrap()
            .unwrap();
        assert!(control
            .claim_identity_rebind_deletion(old_user_id)
            .await
            .unwrap());
        let claimed = control
            .identity_rebind_operation_for_user(old_user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.stage, IdentityRebindStage::DeletionPending);
        assert_eq!(
            gcs.exact_generation_count(&format!("indexes/{stable_user_id}.db.enc")),
            1
        );
    }

    #[test]
    fn finalization_requires_the_deleting_state() {
        let conn = account_conn();
        let fence = crate::store::test_identity_rebind_fence_object_name(USER_ID);
        assert!(matches!(
            delete_user_identity_conn(&conn, USER_ID, &fence),
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
        create_active_archive_binding_conn(&conn, &stable_id).unwrap();
        let fence = crate::store::test_identity_rebind_fence_object_name(&stable_id);
        assert!(
            begin_user_deletion_conn(&conn, &stable_id, OPERATION_ID, &fence)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            delete_user_identity_conn(&conn, &stable_id, &fence)
                .unwrap()
                .status,
            "physical_complete"
        );

        // This is the in-memory state left behind if the final control-DB GCS
        // upload fails. Authentication, begin, and finalize must all allow the
        // next DELETE /api/account request to durably re-flush the tombstone.
        assert_eq!(
            user_status_conn(&conn, &stable_id).unwrap().as_deref(),
            Some("deleted")
        );
        let retry = begin_user_deletion_conn(&conn, &stable_id, "del_different", &fence)
            .unwrap()
            .unwrap();
        assert_eq!(retry.operation_id, OPERATION_ID);
        assert_eq!(retry.status, "physical_complete");
        assert_eq!(
            delete_user_identity_conn(&conn, &stable_id, &fence)
                .unwrap()
                .status,
            "physical_complete"
        );
    }

    #[test]
    fn deletion_status_metadata_is_current_and_queryable() {
        let conn = account_conn();
        let fence = crate::store::test_identity_rebind_fence_object_name(USER_ID);
        begin_user_deletion_conn(&conn, USER_ID, OPERATION_ID, &fence)
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
    async fn lost_successful_control_put_is_accepted_only_by_exact_ciphertext_reread() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let gcs = Arc::new(FakeGcs::new());
        let control = ControlStore::new(Arc::new(FakeKms), gcs.clone());
        gcs.fail_next_put_after_commit(EnclaveError::Gcs(
            "simulated lost successful response".into(),
        ));
        let user = control
            .upsert_user("lost-control-put-subject", "lost@example.com")
            .await
            .unwrap();
        assert_eq!(
            control.user_status(&user.id).await.unwrap().as_deref(),
            Some("active")
        );
        assert!(gcs.get_object(CONTROL_OBJECT).await.unwrap().generation > 0);
    }

    #[tokio::test]
    async fn unchanged_google_reauthentication_fails_closed_on_archive_state() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let missing = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let missing_user = missing
            .upsert_user("missing-ledger-subject", "missing@example.com")
            .await
            .unwrap();
        let missing_id = missing_user.id.clone();
        missing
            .write(move |conn| {
                conn.execute(
                    "DELETE FROM archive_deletion_ledgers
                     WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                    [&missing_id],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            missing
                .upsert_user("missing-ledger-subject", "missing@example.com")
                .await,
            Err(EnclaveError::Store(_))
        ));

        let tombstoned = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let tombstoned_user = tombstoned
            .upsert_user("tombstoned-ledger-subject", "tombstoned@example.com")
            .await
            .unwrap();
        let tombstoned_id = tombstoned_user.id.clone();
        tombstoned
            .write(move |conn| {
                conn.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
                conn.execute(
                    "UPDATE archive_bindings
                     SET state = 'tombstoned', tombstoned_at = '2026-08-11T00:00:00.000Z'
                     WHERE user_id = ?1",
                    [&tombstoned_id],
                )?;
                conn.execute(
                    "UPDATE archive_deletion_ledgers
                     SET state = 'tombstoned', deletion_fence_id = ?2,
                         tombstoned_at = '2026-08-11T00:00:00.000Z'
                     WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                    rusqlite::params![tombstoned_id, [6_u8; 16].as_slice()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            tombstoned
                .upsert_user("tombstoned-ledger-subject", "tombstoned@example.com")
                .await,
            Err(EnclaveError::Auth(_))
        ));
    }

    #[tokio::test]
    async fn apple_existing_and_link_paths_require_an_exact_active_archive_ledger() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let existing = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let apple_user = existing
            .upsert_apple_user(
                "apple-existing-subject",
                "apple@example.com",
                "com.kioku.ios",
                "refresh-one",
            )
            .await
            .unwrap();
        let apple_id = apple_user.id.clone();
        existing
            .write(move |conn| {
                conn.execute(
                    "DELETE FROM archive_deletion_ledgers
                     WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                    [&apple_id],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            existing
                .upsert_apple_user(
                    "apple-existing-subject",
                    "apple@example.com",
                    "com.kioku.ios",
                    "refresh-two",
                )
                .await,
            Err(EnclaveError::Store(_))
        ));
        assert!(matches!(
            existing
                .identity_user("apple", "apple-existing-subject")
                .await,
            Err(EnclaveError::Store(_))
        ));

        let malformed = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let malformed_user = malformed
            .upsert_apple_user(
                "apple-malformed-subject",
                "malformed@example.com",
                "com.kioku.ios",
                "refresh-one",
            )
            .await
            .unwrap();
        let malformed_id = malformed_user.id.clone();
        malformed
            .write(move |conn| {
                conn.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
                conn.execute(
                    "UPDATE archive_deletion_ledgers SET deletion_fence_id = ?2
                     WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                    rusqlite::params![malformed_id, [8_u8; 16].as_slice()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            malformed
                .upsert_apple_user(
                    "apple-malformed-subject",
                    "malformed@example.com",
                    "com.kioku.ios",
                    "refresh-two",
                )
                .await,
            Err(EnclaveError::Store(_))
        ));

        let tombstoned = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let tombstoned_user = tombstoned
            .upsert_apple_user(
                "apple-tombstoned-subject",
                "tombstoned@example.com",
                "com.kioku.ios",
                "refresh-one",
            )
            .await
            .unwrap();
        let tombstoned_id = tombstoned_user.id.clone();
        tombstoned
            .write(move |conn| {
                conn.execute(
                    "UPDATE archive_bindings
                     SET state = 'tombstoned', tombstoned_at = '2026-08-11T00:00:00.000Z'
                     WHERE user_id = ?1",
                    [&tombstoned_id],
                )?;
                conn.execute(
                    "UPDATE archive_deletion_ledgers
                     SET state = 'tombstoned', deletion_fence_id = ?2,
                         tombstoned_at = '2026-08-11T00:00:00.000Z'
                     WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                    rusqlite::params![tombstoned_id, [9_u8; 16].as_slice()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            tombstoned
                .upsert_apple_user(
                    "apple-tombstoned-subject",
                    "tombstoned@example.com",
                    "com.kioku.ios",
                    "refresh-two",
                )
                .await,
            Err(EnclaveError::Auth(_))
        ));

        let linking = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let google = linking
            .upsert_user("apple-link-owner", "owner@example.com")
            .await
            .unwrap();
        let google_id = google.id.clone();
        linking
            .write(move |conn| {
                conn.execute(
                    "DELETE FROM archive_deletion_ledgers
                     WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                    [&google_id],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            linking
                .link_apple_identity(
                    &google.id,
                    "new-apple-link",
                    "owner@example.com",
                    "com.kioku.ios",
                    "refresh-link",
                )
                .await,
            Err(EnclaveError::Store(_))
        ));

        let malformed_link = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let malformed_owner = malformed_link
            .upsert_user("malformed-link-owner", "malformed-link@example.com")
            .await
            .unwrap();
        let malformed_owner_id = malformed_owner.id.clone();
        malformed_link
            .write(move |conn| {
                conn.execute(
                    "UPDATE archive_deletion_ledgers
                     SET state = 'tombstoned', deletion_fence_id = ?2,
                         tombstoned_at = '2026-08-11T00:00:00.000Z'
                     WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                    rusqlite::params![malformed_owner_id, [10_u8; 16].as_slice()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            malformed_link
                .link_apple_identity(
                    &malformed_owner.id,
                    "malformed-apple-link",
                    "malformed-link@example.com",
                    "com.kioku.ios",
                    "refresh-link",
                )
                .await,
            Err(EnclaveError::Store(_))
        ));

        let tombstoned_link = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let tombstoned_owner = tombstoned_link
            .upsert_user("tombstoned-link-owner", "tombstoned-link@example.com")
            .await
            .unwrap();
        let tombstoned_owner_id = tombstoned_owner.id.clone();
        tombstoned_link
            .write(move |conn| {
                conn.execute(
                    "UPDATE archive_bindings
                     SET state = 'tombstoned', tombstoned_at = '2026-08-11T00:00:00.000Z'
                     WHERE user_id = ?1",
                    [&tombstoned_owner_id],
                )?;
                conn.execute(
                    "UPDATE archive_deletion_ledgers
                     SET state = 'tombstoned', deletion_fence_id = ?2,
                         tombstoned_at = '2026-08-11T00:00:00.000Z'
                     WHERE archive_id = (SELECT archive_id FROM archive_bindings WHERE user_id = ?1)",
                    rusqlite::params![tombstoned_owner_id, [11_u8; 16].as_slice()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            tombstoned_link
                .link_apple_identity(
                    &tombstoned_owner.id,
                    "tombstoned-apple-link",
                    "tombstoned-link@example.com",
                    "com.kioku.ios",
                    "refresh-link",
                )
                .await,
            Err(EnclaveError::Auth(_))
        ));
    }

    #[tokio::test]
    async fn archive_binding_is_random_restart_stable_and_never_in_public_models() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let control = ControlStore::new(kms.clone(), gcs.clone());
        let user = control
            .upsert_user("archive-binding-subject", "archive@example.com")
            .await
            .unwrap();
        let first = control
            .archive_deletion_ledger(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.state, ArchiveDeletionState::ActiveLegacy);
        assert_eq!(format!("{:?}", first.binding), "ArchiveBinding(<opaque>)");
        let first_id = *first.binding.archive_id().as_bytes();

        drop(control);
        let restarted = ControlStore::new(kms, gcs);
        let same = restarted
            .upsert_user("archive-binding-subject", "archive@example.com")
            .await
            .unwrap();
        let reloaded = restarted
            .archive_deletion_ledger(&same.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*reloaded.binding.archive_id().as_bytes(), first_id);
        assert_eq!(format!("{:?}", reloaded), format!("{:?}", first));

        // The same canonical subject in an independently initialized control
        // store receives a different random archive ID, proving the binding is
        // persisted state rather than a stable/user-derived hash.
        let independent = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let independent_user = independent
            .upsert_user("archive-binding-subject", "archive@example.com")
            .await
            .unwrap();
        let independent_id = *independent
            .archive_deletion_ledger(&independent_user.id)
            .await
            .unwrap()
            .unwrap()
            .binding
            .archive_id()
            .as_bytes();
        assert_ne!(independent_id, first_id);

        // The public deletion response has no archive identifier or ledger
        // fields, and no route/export model received one in this change.
        let public = serde_json::to_string(&AccountDeletionOperation {
            operation_id: "del_public".into(),
            status: "pending".into(),
            reason: "content_deletion_in_progress".into(),
            retry_after_seconds: Some(30),
            hard_delete_time: None,
        })
        .unwrap();
        assert!(!public.contains("archive"));
        assert!(!public.contains("cursor"));
    }

    #[tokio::test]
    async fn concurrent_creation_keeps_one_binding_and_deletion_prevents_resurrection() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let barrier = Arc::new(tokio::sync::Barrier::new(12));
        let mut tasks = Vec::new();
        for _ in 0..12 {
            let control = Arc::clone(&control);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                control
                    .upsert_user("concurrent-archive-subject", "concurrent@example.com")
                    .await
            }));
        }
        let mut users = Vec::new();
        for task in tasks {
            users.push(task.await.unwrap().unwrap());
        }
        assert!(users.iter().all(|user| user.id == users[0].id));
        let user_id = users[0].id.clone();
        let bindings: i64 = control
            .read({
                let user_id = user_id.clone();
                move |conn| {
                    Ok(conn.query_row(
                        "SELECT count(*) FROM archive_bindings WHERE user_id = ?1",
                        [&user_id],
                        |row| row.get(0),
                    )?)
                }
            })
            .await
            .unwrap();
        assert_eq!(bindings, 1);

        let before = control
            .archive_deletion_ledger(&user_id)
            .await
            .unwrap()
            .unwrap();
        control
            .begin_user_deletion(&user_id)
            .await
            .unwrap()
            .unwrap();
        let retry = control
            .begin_user_deletion(&user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retry.status, "pending");
        let tombstoned = control
            .archive_deletion_ledger(&user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.binding, tombstoned.binding);
        assert_eq!(tombstoned.state, ArchiveDeletionState::Tombstoned);

        // Simulate legacy deletion's completed identity transaction. The
        // remaining encrypted archive tombstone blocks a later login from
        // creating or reconnecting any archive.
        control.finalize_user_deletion(&user_id).await.unwrap();
        assert!(matches!(
            control
                .upsert_user("concurrent-archive-subject", "concurrent@example.com")
                .await,
            Err(EnclaveError::Auth(_))
        ));
    }

    #[tokio::test]
    async fn deletion_wins_legacy_rebind_without_moving_stable_content() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let inner = Arc::new(FakeGcs::new());
        let gcs = Arc::new(PausingGcs::new(inner.clone()));
        let gcs_client: Arc<dyn GcsClient> = gcs;
        let content = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let control = Arc::new(ControlStore::new_with_store(
            kms,
            gcs_client,
            content.clone(),
        ));
        let old_user_id = "legacy-delete-wins";
        let subject = "legacy-delete-wins-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        seed_legacy_rebind_account(&control, &content, subject, old_user_id).await;

        let deletion_guard = content.lock_user_lifecycle(old_user_id).await.unwrap();
        control
            .begin_user_deletion(old_user_id)
            .await
            .unwrap()
            .unwrap();
        let rebind_control = control.clone();
        let rebind = tokio::spawn(async move {
            rebind_control
                .upsert_user(subject, "legacy@example.com")
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(
            inner.exact_generation_count(&format!("indexes/{stable_user_id}.db.enc")),
            0
        );
        drop(deletion_guard);

        assert!(matches!(rebind.await.unwrap(), Err(EnclaveError::Auth(_))));
        content.delete_user(old_user_id).await.unwrap();
        control.finalize_user_deletion(old_user_id).await.unwrap();
        assert_eq!(
            inner.exact_generation_count(&format!("indexes/{stable_user_id}.db.enc")),
            0
        );
        assert_eq!(
            control
                .user_status(&stable_user_id)
                .await
                .unwrap()
                .as_deref(),
            Some("deleted")
        );
    }

    #[tokio::test]
    async fn rebind_wins_and_queued_deletion_cannot_orphan_stable_content() {
        use crate::store::tests::{FakeGcs, FakeKms};
        use tokio::sync::oneshot;

        let kms = Arc::new(FakeKms);
        let inner = Arc::new(FakeGcs::new());
        let gcs = Arc::new(PausingGcs::new(inner.clone()));
        let gcs_client: Arc<dyn GcsClient> = gcs.clone();
        let content = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let control = Arc::new(ControlStore::new_with_store(
            kms,
            gcs_client,
            content.clone(),
        ));
        let old_user_id = "legacy-rebind-wins";
        let subject = "legacy-rebind-wins-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        let old_object = format!("indexes/{old_user_id}.db.enc");
        let stable_object = format!("indexes/{stable_user_id}.db.enc");
        seed_legacy_rebind_account(&control, &content, subject, old_user_id).await;

        gcs.pause_after_next_put(&stable_object);
        let rebind_control = control.clone();
        let mut rebind = tokio::spawn(async move {
            rebind_control
                .upsert_user(subject, "legacy@example.com")
                .await
        });
        tokio::select! {
            () = gcs.put_committed.notified() => {}
            outcome = &mut rebind => match outcome {
                Ok(Err(error)) => panic!("rebind failed before stable PUT: {error}"),
                Ok(Ok(_)) => panic!("rebind completed without pausing after stable PUT"),
                Err(error) => panic!("rebind task failed before stable PUT: {error}"),
            },
        }
        assert_eq!(inner.exact_generation_count(&stable_object), 1);

        let (attempted_tx, attempted_rx) = oneshot::channel();
        let deletion_content = content.clone();
        let deletion_control = control.clone();
        let deletion = tokio::spawn(async move {
            attempted_tx.send(()).unwrap();
            let _guard = deletion_content
                .lock_user_lifecycle(old_user_id)
                .await
                .unwrap();
            deletion_control.begin_user_deletion(old_user_id).await
        });
        attempted_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!deletion.is_finished());

        gcs.resume_put.notify_one();
        let rebound = rebind.await.unwrap().unwrap();
        assert_eq!(rebound.id, stable_user_id);
        assert_eq!(deletion.await.unwrap().unwrap(), None);
        assert_eq!(inner.exact_generation_count(&old_object), 0);
        assert_eq!(inner.exact_generation_count(&stable_object), 1);
        assert_eq!(
            control
                .user_status(&stable_user_id)
                .await
                .unwrap()
                .as_deref(),
            Some("active")
        );
        let ledger = control
            .archive_deletion_ledger(&stable_user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ledger.state, ArchiveDeletionState::ActiveLegacy);
    }

    #[tokio::test]
    async fn two_store_writer_wins_prefence_cas_then_rebind_rebases_exact_source() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let inner = Arc::new(FakeGcs::new());
        let gcs = Arc::new(PausingGcs::new(inner.clone()));
        let gcs_client: Arc<dyn GcsClient> = gcs.clone();
        let rebind_store = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let writer_store = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let control = Arc::new(ControlStore::new_with_store(
            kms,
            gcs_client,
            rebind_store.clone(),
        ));
        let old_user_id = "legacy-two-store-writer-wins";
        let subject = "legacy-two-store-writer-wins-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        seed_legacy_rebind_account(&control, &rebind_store, subject, old_user_id).await;
        let fence = crate::store::test_identity_rebind_fence_object_name(old_user_id);

        writer_store
            .with_user(old_user_id, |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO app_metadata (key, value)
                     VALUES ('remote-writer', 'durable')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let old_object = format!("indexes/{old_user_id}.db.enc");
        gcs.pause_after_next_put(&old_object);
        let writer = {
            let writer_store = writer_store.clone();
            tokio::spawn(async move { writer_store.save_user(old_user_id).await })
        };
        gcs.put_committed.notified().await;

        // The writer owns a durable Requesting intent and its generation CAS
        // has committed, but the response/terminal tombstone is paused. The
        // first rebind attempt creates the marker and must remain retryable
        // instead of fencing or overtaking that active request.
        assert!(matches!(
            control.upsert_user(subject, "legacy@example.com").await,
            Err(EnclaveError::DeletionPending(
                crate::error::DeletionPending {
                    reason: crate::error::DeletionPendingReason::LegacyWriteIntentUnsettled,
                    ..
                }
            ))
        ));
        gcs.resume_put.notify_one();
        writer.await.unwrap().unwrap();

        // A live retry drains the now-terminal intent, durably rebases the
        // exact source generation/commitment, and forces a second CAS bump
        // before copying the stable object.
        let user = control
            .upsert_user(subject, "legacy@example.com")
            .await
            .unwrap();
        assert_eq!(user.id, stable_user_id);

        let stable_store = Store::new(Arc::new(FakeKms), inner.clone());
        let copied: String = stable_store
            .read_user(&stable_user_id, |conn| {
                Ok(conn.query_row(
                    "SELECT value FROM app_metadata WHERE key = 'remote-writer'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(copied, "durable");
        let operation = control
            .identity_rebind_operation_for_user(&stable_user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(operation.stage, IdentityRebindStage::Committed);
        assert!(operation.source_base_generation >= 2);
        assert_eq!(
            control
                .archive_deletion_ledger(&stable_user_id)
                .await
                .unwrap()
                .unwrap()
                .legacy_rebind_fence_object_name
                .as_deref(),
            Some(fence.as_str())
        );
    }

    #[tokio::test]
    async fn two_store_rebind_wins_cas_and_stale_writer_cannot_resurrect_old_namespace() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let inner = Arc::new(FakeGcs::new());
        let gcs = Arc::new(PausingGcs::new(inner.clone()));
        let gcs_client: Arc<dyn GcsClient> = gcs.clone();
        let rebind_store = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let writer_store = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let control = Arc::new(ControlStore::new_with_store(
            kms,
            gcs_client,
            rebind_store.clone(),
        ));
        let old_user_id = "legacy-two-store-rebind-wins";
        let subject = "legacy-two-store-rebind-wins-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        let old_object = format!("indexes/{old_user_id}.db.enc");
        seed_legacy_rebind_account(&control, &rebind_store, subject, old_user_id).await;
        writer_store
            .with_user(old_user_id, |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO app_metadata (key, value)
                     VALUES ('stale-writer', 'must-not-commit')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let fence = crate::store::test_identity_rebind_fence_object_name(old_user_id);
        gcs.pause_after_next_get(&fence);
        let writer = {
            let writer_store = writer_store.clone();
            tokio::spawn(async move { writer_store.save_user(old_user_id).await })
        };
        gcs.get_completed.notified().await;
        let rebound = control
            .upsert_user(subject, "legacy@example.com")
            .await
            .unwrap();
        assert_eq!(rebound.id, stable_user_id);
        gcs.resume_get.notify_one();
        assert!(writer.await.unwrap().is_err());
        assert_eq!(inner.exact_generation_count(&old_object), 0);

        // Even after account finalization, the content-free provider marker is
        // retained as the ledger-known no-resurrection tombstone. A stale
        // Store image cannot create an old raw object or flush its old actor.
        control
            .begin_user_deletion(&stable_user_id)
            .await
            .unwrap()
            .unwrap();
        assert!(control
            .claim_identity_rebind_deletion(&stable_user_id)
            .await
            .unwrap());
        rebind_store
            .delete_identity_rebind_users(old_user_id, &stable_user_id)
            .await
            .unwrap();
        control
            .mark_identity_rebind_deletion_reconciled(&stable_user_id)
            .await
            .unwrap();
        control
            .finalize_user_deletion(&stable_user_id)
            .await
            .unwrap();
        assert!(inner.get_object(&fence).await.is_ok());
        assert!(writer_store
            .put_user_media(
                old_user_id,
                &format!("raw/{old_user_id}/late.enc"),
                b"late",
                "wrapped",
            )
            .await
            .is_err());
        assert_eq!(
            inner.exact_generation_count(&format!("raw/{old_user_id}/late.enc")),
            0
        );
    }

    #[tokio::test]
    async fn prefence_raw_intent_is_fenced_before_data_io_and_old_inventory_is_retained() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let inner = Arc::new(FakeGcs::new());
        let gcs = Arc::new(PausingGcs::new(inner.clone()));
        let gcs_client: Arc<dyn GcsClient> = gcs.clone();
        let rebind_store = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let raw_store = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let control = Arc::new(ControlStore::new_with_store(
            kms,
            gcs_client,
            rebind_store.clone(),
        ));
        let old_user_id = "legacy-late-raw-put";
        let subject = "legacy-late-raw-put-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        let raw_name = format!("raw/{old_user_id}/late.enc");
        seed_legacy_rebind_account(&control, &rebind_store, subject, old_user_id).await;

        let fence = crate::store::test_identity_rebind_fence_object_name(old_user_id);
        gcs.pause_after_next_get(&fence);
        let raw_put = {
            let raw_store = raw_store.clone();
            let raw_name = raw_name.clone();
            tokio::spawn(async move {
                raw_store
                    .put_user_media(old_user_id, &raw_name, b"late", "wrapped")
                    .await
            })
        };
        gcs.get_completed.notified().await;
        control
            .upsert_user(subject, "legacy@example.com")
            .await
            .unwrap();
        gcs.resume_get.notify_one();
        assert!(raw_put.await.unwrap().is_err());
        assert_eq!(inner.exact_generation_count(&raw_name), 0);

        // The durable pre-marker intent was visible to rebind and terminalized
        // before any raw data I/O. The committed operation and retained archive
        // ledger still preserve the exact old prefix and marker through final
        // deletion.
        raw_store
            .with_user(old_user_id, |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO app_metadata (key, value)
                     VALUES ('late-raw-link', 'pending')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(raw_store.save_user(old_user_id).await.is_err());
        let operation = control
            .identity_rebind_operation_for_user(&stable_user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(operation.old_user_id, old_user_id);
        assert_eq!(operation.stage, IdentityRebindStage::Committed);
        assert_eq!(
            control
                .archive_deletion_ledger(&stable_user_id)
                .await
                .unwrap()
                .unwrap()
                .legacy_rebind_fence_object_name
                .as_deref(),
            Some(fence.as_str())
        );

        control
            .begin_user_deletion(&stable_user_id)
            .await
            .unwrap()
            .unwrap();
        assert!(control
            .claim_identity_rebind_deletion(&stable_user_id)
            .await
            .unwrap());
        rebind_store
            .delete_identity_rebind_users(old_user_id, &stable_user_id)
            .await
            .unwrap();
        assert_eq!(inner.exact_generation_count(&raw_name), 0);
    }

    #[tokio::test]
    async fn cancelled_rebind_caller_keeps_lifecycle_gates_until_owned_commit() {
        use crate::store::tests::{FakeGcs, FakeKms};
        use tokio::sync::oneshot;

        let kms = Arc::new(FakeKms);
        let inner = Arc::new(FakeGcs::new());
        let gcs = Arc::new(PausingGcs::new(inner.clone()));
        let gcs_client: Arc<dyn GcsClient> = gcs.clone();
        let content = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let control = Arc::new(ControlStore::new_with_store(
            kms,
            gcs_client,
            content.clone(),
        ));
        let old_user_id = "legacy-cancelled-rebind";
        let subject = "legacy-cancelled-rebind-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        let old_object = format!("indexes/{old_user_id}.db.enc");
        let stable_object = format!("indexes/{stable_user_id}.db.enc");
        seed_legacy_rebind_account(&control, &content, subject, old_user_id).await;

        gcs.pause_after_next_put(&stable_object);
        let cancelled_control = control.clone();
        let mut cancelled = tokio::spawn(async move {
            cancelled_control
                .upsert_user(subject, "legacy@example.com")
                .await
        });
        tokio::select! {
            () = gcs.put_committed.notified() => {}
            outcome = &mut cancelled => match outcome {
                Ok(Err(error)) => panic!("rebind failed before stable PUT: {error}"),
                Ok(Ok(_)) => panic!("rebind completed without pausing after stable PUT"),
                Err(error) => panic!("rebind task failed before stable PUT: {error}"),
            },
        }
        cancelled.abort();
        assert!(matches!(cancelled.await, Err(error) if error.is_cancelled()));
        assert_eq!(inner.exact_generation_count(&old_object), 2);
        assert_eq!(inner.exact_generation_count(&stable_object), 1);
        assert_eq!(
            control.user_status(old_user_id).await.unwrap().as_deref(),
            Some("active")
        );

        let (attempted_tx, attempted_rx) = oneshot::channel();
        let deletion_content = content.clone();
        let deletion_control = control.clone();
        let deletion = tokio::spawn(async move {
            attempted_tx.send(()).unwrap();
            let _guard = deletion_content
                .lock_user_lifecycle(old_user_id)
                .await
                .unwrap();
            deletion_control.begin_user_deletion(old_user_id).await
        });
        attempted_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!deletion.is_finished());

        gcs.resume_put.notify_one();
        assert_eq!(deletion.await.unwrap().unwrap(), None);
        assert_eq!(inner.exact_generation_count(&old_object), 0);
        assert_eq!(inner.exact_generation_count(&stable_object), 1);
        assert_eq!(
            control
                .user_status(&stable_user_id)
                .await
                .unwrap()
                .as_deref(),
            Some("active")
        );
    }

    #[tokio::test]
    async fn restart_repairs_a_stable_put_committed_before_control_rebind() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let inner = Arc::new(FakeGcs::new());
        let gcs = Arc::new(PausingGcs::new(inner.clone()));
        let gcs_client: Arc<dyn GcsClient> = gcs.clone();
        let content = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let control = Arc::new(ControlStore::new_with_store(
            kms.clone(),
            gcs_client.clone(),
            content.clone(),
        ));
        let old_user_id = "legacy-restart-rebind";
        let subject = "legacy-restart-rebind-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        let old_object = format!("indexes/{old_user_id}.db.enc");
        let stable_object = format!("indexes/{stable_user_id}.db.enc");
        seed_legacy_rebind_account(&control, &content, subject, old_user_id).await;

        // Model process interruption after the durable provider-write intent
        // and create-only stable PUT commit, but before its completed stage.
        let mut transition = content
            .begin_identity_rebind(old_user_id, &stable_user_id)
            .await
            .unwrap();
        let initial = transition.source_snapshot().await.unwrap();
        let binding = control
            .archive_deletion_ledger(old_user_id)
            .await
            .unwrap()
            .unwrap()
            .binding;
        let mut operation = control
            .prepare_identity_rebind(subject, old_user_id, &stable_user_id, binding, &initial)
            .await
            .unwrap();
        operation = control
            .advance_identity_rebind(&operation, IdentityRebindStage::SourceFreezing, None)
            .await
            .unwrap();
        let marker_authority = control
            .ensure_identity_rebind_provider_fence(&operation)
            .await
            .unwrap();
        let frozen = transition
            .freeze_source(
                operation.source_base_generation,
                &operation.source_commitment,
                &marker_authority,
            )
            .await
            .unwrap();
        operation = control
            .advance_identity_rebind(
                &operation,
                IdentityRebindStage::SourceFrozen,
                Some(frozen.source_generation),
            )
            .await
            .unwrap();
        operation = control
            .advance_identity_rebind(
                &operation,
                IdentityRebindStage::StableWriting,
                operation.source_generation,
            )
            .await
            .unwrap();
        assert_eq!(operation.stage, IdentityRebindStage::StableWriting);
        let dek = load_dek(control.kms.as_ref(), &frozen.wrapped_dek_b64)
            .await
            .unwrap();
        let stable_ciphertext = encrypt_bound_blob(
            &dek,
            &frozen.plaintext,
            &crate::store::user_blob_context(&stable_user_id),
        )
        .unwrap();
        gcs.pause_after_next_put(&stable_object);
        let interrupted_write = {
            let content = content.clone();
            let stable_user_id = stable_user_id.clone();
            let stable_object = stable_object.clone();
            let wrapped_dek_b64 = frozen.wrapped_dek_b64.clone();
            tokio::spawn(async move {
                content
                    .put_stable_rebind_index(
                        &stable_user_id,
                        &stable_object,
                        &stable_ciphertext,
                        &wrapped_dek_b64,
                    )
                    .await
            })
        };
        gcs.put_committed.notified().await;
        interrupted_write.abort();
        assert!(matches!(
            interrupted_write.await,
            Err(error) if error.is_cancelled()
        ));
        // The durable intent remains Requesting. A restarted instance may
        // take it over only after provider time has passed its ownership
        // lease, then exact-reread the already-created stable destination.
        inner.set_provider_clock_millis(1_900_000_000_000);
        drop(transition);
        assert_eq!(inner.exact_generation_count(&old_object), 2);
        assert_eq!(inner.exact_generation_count(&stable_object), 1);
        assert_eq!(
            control.user_status(old_user_id).await.unwrap().as_deref(),
            Some("active")
        );

        drop(control);
        drop(content);
        let restarted_content = Arc::new(Store::new(kms.clone(), gcs_client.clone()));
        let restarted = ControlStore::new_with_store(kms, gcs_client, restarted_content);
        assert_eq!(
            restarted
                .reconcile_pending_identity_rebinds()
                .await
                .unwrap(),
            1
        );
        let repaired = restarted.identity_user("google", subject).await.unwrap();
        assert_eq!(repaired.unwrap().id, stable_user_id);
        assert_eq!(inner.exact_generation_count(&old_object), 0);
        assert_eq!(inner.exact_generation_count(&stable_object), 1);
        assert_eq!(
            restarted
                .user_status(&stable_user_id)
                .await
                .unwrap()
                .as_deref(),
            Some("active")
        );
    }

    #[tokio::test]
    async fn startup_rebind_recovery_drains_more_than_one_bounded_page() {
        use crate::store::tests::{FakeGcs, FakeKms};

        const OPERATION_COUNT: usize = 65;
        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let template_store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let mut template_transition = template_store
            .begin_identity_rebind("template-old", "template-stable")
            .await
            .unwrap();
        let template = template_transition.source_snapshot().await.unwrap();
        drop(template_transition);
        let dek = load_dek(kms.as_ref(), &template.wrapped_dek_b64)
            .await
            .unwrap();

        for index in 0..OPERATION_COUNT {
            let old_id = format!("startup-page-old-{index}");
            let ciphertext = encrypt_bound_blob(
                &dek,
                &template.plaintext,
                &crate::store::user_blob_context(&old_id),
            )
            .unwrap();
            gcs.put_object(
                &format!("indexes/{old_id}.db.enc"),
                &ciphertext,
                &template.wrapped_dek_b64,
                0,
            )
            .await
            .unwrap();
        }

        let recovery_store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let control = ControlStore::new_with_store(kms, gcs, recovery_store);
        let commitment = template.commitment;
        control
            .write(move |conn| {
                for index in 0..OPERATION_COUNT {
                    let old_id = format!("startup-page-old-{index}");
                    let subject = format!("startup-page-subject-{index}");
                    let stable_id = super::super::tokens::derive_stable_uuid(&subject);
                    conn.execute(
                        "INSERT INTO users (id, google_sub, email)
                         VALUES (?1, ?2, 'startup@example.com')",
                        rusqlite::params![old_id, subject],
                    )?;
                    let binding = create_active_archive_binding_conn(conn, &old_id)?;
                    let source = IdentityRebindSource {
                        base_generation: 1,
                        source_generation: 1,
                        commitment,
                        plaintext: Vec::new(),
                        wrapped_dek_b64: String::new(),
                    };
                    prepare_identity_rebind_conn(
                        conn,
                        &format!("rebind_{:064x}", index + 1),
                        &subject,
                        &old_id,
                        &stable_id,
                        &crate::store::test_identity_rebind_fence_object_name(&old_id),
                        binding,
                        &source,
                    )?;
                }
                Ok(())
            })
            .await
            .unwrap();

        assert_eq!(
            control.reconcile_pending_identity_rebinds().await.unwrap(),
            OPERATION_COUNT
        );
        assert!(control
            .read(|conn| pending_identity_rebind_operations_conn(conn, 1))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn restart_resumes_partial_old_generation_purge_without_reauthentication() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let content = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let control = ControlStore::new_with_store(kms.clone(), gcs.clone(), content.clone());
        let old_user_id = "legacy-partial-old-purge";
        let subject = "legacy-partial-old-purge-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        let old_object = format!("indexes/{old_user_id}.db.enc");
        let stable_object = format!("indexes/{stable_user_id}.db.enc");
        seed_legacy_rebind_account(&control, &content, subject, old_user_id).await;
        content
            .with_user(old_user_id, |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO app_metadata (key, value)
                     VALUES ('second-generation', 'present')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        content.save_user(old_user_id).await.unwrap();
        assert_eq!(gcs.exact_generation_count(&old_object), 2);
        gcs.fail_next_generation_delete(&old_object, 1);

        assert!(control
            .upsert_user(subject, "legacy@example.com")
            .await
            .is_err());
        let pending = control
            .identity_rebind_operation_for_user(old_user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.stage, IdentityRebindStage::OldPurging);
        assert_eq!(gcs.exact_generation_count(&stable_object), 1);

        drop(control);
        drop(content);
        let restarted_store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let restarted = ControlStore::new_with_store(kms, gcs.clone(), restarted_store);
        assert_eq!(
            restarted
                .reconcile_pending_identity_rebinds()
                .await
                .unwrap(),
            1
        );
        assert_eq!(gcs.exact_generation_count(&old_object), 0);
        assert_eq!(gcs.exact_generation_count(&stable_object), 1);
        assert_eq!(
            restarted
                .user_status(&stable_user_id)
                .await
                .unwrap()
                .as_deref(),
            Some("active")
        );
    }

    #[tokio::test]
    async fn ungated_test_control_store_refuses_legacy_rebind_before_provider_io() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let content = Store::new(kms.clone(), gcs.clone());
        let control = ControlStore::new(kms, gcs.clone());
        let old_user_id = "legacy-ungated-rebind";
        let subject = "legacy-ungated-rebind-subject";
        let stable_user_id = super::super::tokens::derive_stable_uuid(subject);
        seed_legacy_rebind_account(&control, &content, subject, old_user_id).await;

        assert!(matches!(
            control.upsert_user(subject, "legacy@example.com").await,
            Err(EnclaveError::Store(_))
        ));
        assert_eq!(
            gcs.exact_generation_count(&format!("indexes/{stable_user_id}.db.enc")),
            0
        );
    }

    #[tokio::test]
    async fn legacy_id_rebind_refuses_a_conflicting_target_binding_before_blob_migration() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let kms = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let lifecycle_store = Arc::new(Store::new(kms.clone(), gcs.clone()));
        let control = ControlStore::new_with_store(kms, gcs, lifecycle_store);
        let old_id = "legacy-identity-id".to_string();
        let subject = "legacy-archive-binding-subject".to_string();
        let stable_id = super::super::tokens::derive_stable_uuid(&subject);
        control
            .write({
                let old_id = old_id.clone();
                let subject = subject.clone();
                let stable_id = stable_id.clone();
                move |conn| {
                    conn.execute(
                        "INSERT INTO users (id, google_sub, email) VALUES (?1, ?2, 'legacy@example.com')",
                        rusqlite::params![old_id, subject],
                    )?;
                    create_active_archive_binding_conn(conn, &old_id)?;
                    // This can only be a prior incomplete/corrupt migration;
                    // reject it deterministically rather than silently choosing
                    // one random archive ID or tripping a late UNIQUE error.
                    create_active_archive_binding_conn(conn, &stable_id)?;
                    Ok(())
                }
            })
            .await
            .unwrap();

        assert!(matches!(
            control.upsert_user(&subject, "legacy@example.com").await,
            Err(EnclaveError::Conflict(_))
        ));
        let retained_id: String = control
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT id FROM users WHERE google_sub = ?1",
                    [&subject],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(retained_id, old_id);
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
        let pending = control
            .pending_recording_lease_request(&first.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.0, "pending-0");
        assert_eq!(pending.1.state, "pending");
        assert_eq!(pending.1.issued_lease_id, "lease_pending_0");
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
    async fn offline_minute_grants_one_idempotent_bounded_delivery_budget() {
        use crate::store::tests::{FakeGcs, FakeKms};

        let control = ControlStore::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let user = control
            .upsert_user("offline-delivery-subject", "offline@example.com")
            .await
            .unwrap();
        assert!(!control
            .reserve_recording_delivery(&user.id, "event-before-credit", 1)
            .await
            .unwrap());

        assert!(control
            .complete_offline_recording_usage(&user.id, "offline-request")
            .await
            .unwrap());
        assert!(!control
            .complete_offline_recording_usage(&user.id, "offline-request")
            .await
            .unwrap());
        assert!(control
            .offline_recording_usage_receipt(&user.id, "offline-request")
            .await
            .unwrap());

        assert!(control
            .reserve_recording_delivery(&user.id, "event-one", 100)
            .await
            .unwrap());
        // A canonical rebase for the same event spends only its byte delta and
        // never a second event credit.
        assert!(control
            .reserve_recording_delivery(&user.id, "event-one", 250)
            .await
            .unwrap());
        let user_id = user.id.clone();
        let balance: (i64, i64) = control
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT event_credits,byte_credits FROM recording_delivery_balances
                     WHERE user_id=?1",
                    [&user_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(balance.0, RECORDING_DELIVERY_EVENTS_PER_MINUTE - 1);
        assert_eq!(balance.1, RECORDING_DELIVERY_BYTES_PER_MINUTE - 250);
        control
            .complete_recording_delivery(&user.id, "event-one")
            .await
            .unwrap();
        let user_id = user.id.clone();
        assert_eq!(
            control
                .read(move |conn| {
                    Ok(conn.query_row(
                        "SELECT count(*) FROM recording_delivery_reservations
                         WHERE user_id=?1",
                        [&user_id],
                        |row| row.get::<_, i64>(0),
                    )?)
                })
                .await
                .unwrap(),
            0
        );
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
        let before_active_expiry =
            super::super::isotime::parse_epoch_millis("2026-08-09T00:01:00.000Z").unwrap();
        assert!(matches!(
            control
                .complete_recording_lease(
                    &user.id,
                    "request-first",
                    Some(before_active_expiry),
                    &serde_json::json!({"recording":{"allowed":true}}),
                )
                .await,
            Err(EnclaveError::Conflict(_))
        ));
        assert_eq!(
            control.active_recording_lease(&user.id).await.unwrap(),
            Some(("lease_other".into(), "2026-08-09T00:02:00.000Z".into()))
        );

        // Once that unrelated lease is expired, the still-pending, billed
        // intent can take over and receive its full minute from recovery time.
        let after_active_expiry =
            super::super::isotime::parse_epoch_millis("2026-08-09T00:03:00.000Z").unwrap();
        let recovered = control
            .complete_recording_lease(
                &user.id,
                "request-first",
                Some(after_active_expiry),
                &serde_json::json!({"recording":{"allowed":true}}),
            )
            .await
            .unwrap();
        assert_eq!(
            recovered,
            ("lease_first".into(), "2026-08-09T00:04:00.000Z".into())
        );
        assert_eq!(
            control.active_recording_lease(&user.id).await.unwrap(),
            Some(recovered)
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
