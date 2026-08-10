//! Per-user encrypted SQLite index store.
//!
//! # Lifecycle
//!
//! 1. **load(user_id)** — fetch the user's encrypted blob from GCS (or create
//!    an empty one on first use), decrypt it to a temporary file, open rusqlite,
//!    run schema migrations, cache the handle.
//!
//! 2. Callers query or write through a tracked [`rusqlite::Connection`]
//!    closure. SQLite row changes (including triggers), schema changes, and
//!    persistent header versions advance a process-local mutation generation.
//!
//! 3. **save(user_id)** — if dirty: WAL checkpoint → read temp file → AES-GCM
//!    encrypt → PUT back to GCS with `ifGenerationMatch`. A proven-clean save
//!    returns without KMS, encryption, file read, or GCS work.
//!
//! # Optimistic concurrency / conflict story
//!
//! GCS object versioning provides `generation` numbers.  On every PUT we pass
//! `ifGenerationMatch=<generation-we-read>`.  If another enclave instance wrote
//! between our read and write GCS returns 412 Precondition Failed. A retry after
//! a lost successful PUT reconciles only when the current object has the exact
//! wrapped DEK and authenticated plaintext we intended to persist; every other
//! 412 surfaces as [`crate::error::EnclaveError::Conflict`]. The caller (handler)
//! should then reload, re-apply changes, and retry. In the current single-node
//! topology conflicts are rare; this is future-proofing for horizontal scale-out.
//!
//! # LRU cache
//!
//! A brief registry lock tracks actor identity, deletion fences, LRU order, and
//! the configurable open-handle cap (`STORE_MAX_OPEN`, default 16). Each user
//! actor owns its SQLite connection behind a separate async mutex. On eviction
//! the victim is saved and closed under only that user's lock; another user's
//! GCS, KMS, SQLite, or filesystem work never holds the registry lock.
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
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Once, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{ffi::sqlite3_auto_extension, Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use sqlite_vec::sqlite3_vec_init;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify};
use tracing::{debug, info, warn};

use crate::{
    crypto::{
        decrypt_bound_blob, encrypt_bound_blob, generate_and_wrap_dek, load_dek, Dek, KmsClient,
    },
    error::{EnclaveError, Result},
    storage_observability::{
        StorageMetrics, StorageMetricsSnapshot, AMPLIFICATION_PPM_BUCKET_UPPER_BOUNDS,
        BYTE_BUCKET_UPPER_BOUNDS, LATENCY_US_BUCKET_UPPER_BOUNDS,
    },
};

// ── Types ─────────────────────────────────────────────────────────────────────

pub type UserId = String;

/// Maximum accepted `user_id` length. Real ids are UUIDs (36 chars); 128
/// leaves generous headroom without allowing pathological inputs.
pub const MAX_USER_ID_LEN: usize = 128;

/// Selected screenshot evidence is always written below this owner-scoped raw
/// media namespace.  Keep construction here rather than at individual writers:
/// the object key is part of the AEAD context as well as the storage boundary.
pub const SELECTED_EVIDENCE_MEDIA_SEGMENT: &str = "evidence";

/// Canonical brief schema/prompt version. Keeping it beside the persistence
/// migration prevents a worker bump from forgetting to queue stored briefs.
pub(crate) const EPISODE_FINALIZATION_VERSION: i32 = 5;

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

/// Build the only object key used for newly selected screenshot evidence.
///
/// Existing database rows may still name legacy `media/{opaque_key}` objects;
/// readers and deletion deliberately use those stored keys for compatibility.
/// New writes must use this helper so no writer can accidentally create an
/// unscoped media object. The opaque identifier is the 128-bit lowercase hex
/// value generated by the evidence upload path.
pub(crate) fn selected_evidence_media_object_key(
    user_id: &str,
    opaque_key: &str,
) -> Result<String> {
    validate_user_id(user_id)?;
    let valid_opaque_key = opaque_key.len() == 32
        && opaque_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if !valid_opaque_key {
        return Err(EnclaveError::InvalidRequest(
            "invalid selected evidence media identifier".into(),
        ));
    }
    Ok(format!(
        "raw/{user_id}/{SELECTED_EVIDENCE_MEDIA_SEGMENT}/{opaque_key}.enc"
    ))
}

/// GCS blob metadata we need to track between load and save.
struct BlobMeta {
    /// GCS object `generation` at load time.  Used for `ifGenerationMatch`.
    /// `0` means "object must not exist yet" (first write for a new user).
    generation: i64,
    /// Base64-encoded wrapped DEK stored alongside the blob (in GCS metadata).
    wrapped_dek_b64: String,
    /// UTC epoch day whose named checkpoint this process has fully verified.
    /// This is deliberately process-local; restart re-verifies once.
    verified_legacy_recovery_day: Option<i64>,
    /// A flush failed after local mutation but before authoritative remote
    /// persistence. The next access must retry that pending save before a
    /// caller can observe a duplicate and acknowledge without persisting it.
    retry_save_before_access: bool,
}

struct UserHandle {
    /// The (validated) user id this handle belongs to. Stored directly so the
    /// GCS object name never has to be reconstructed from the temp-file path.
    user_id: UserId,
    conn: Connection,
    blob_meta: BlobMeta,
    /// Monotonic process-local generation advanced whenever SQLite reports a
    /// possible persistent logical mutation. `dirty` remains the fail-closed
    /// authority if this diagnostic counter ever saturates.
    mutation_generation: u64,
    persisted_mutation_generation: u64,
    dirty: bool,
    temp_path: PathBuf,
}

/// The shared store, wrapped in Arc so handlers can clone it cheaply.
pub struct Store {
    registry: Mutex<StoreRegistry>,
    registry_changed: Arc<Notify>,
    pub kms: Arc<dyn KmsClient>,
    pub gcs: Arc<dyn GcsClient>,
    pub media_gcs: Arc<dyn GcsClient>,
    max_open: usize,
    checkpoint_clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    storage_metrics: StorageMetrics,
}

struct UserActor {
    state: Mutex<UserActorState>,
}

#[derive(Default)]
struct UserActorState {
    handle: Option<UserHandle>,
    /// An eviction that raced a queued `save_user` already persisted the exact
    /// handle that save intended to flush. The actor is weakly retained only
    /// while such queued requests still exist.
    cleanly_evicted: bool,
}

struct StoreRegistry {
    /// Weak entries preserve one actor identity across concurrent cache misses
    /// without retaining an unbounded number of idle actors forever.
    actors: HashMap<UserId, Weak<UserActor>>,
    /// Strong references for handles that are loading, open, or being evicted.
    /// Its length is the strictly enforced `STORE_MAX_OPEN` reservation count.
    open_users: HashMap<UserId, OpenUser>,
    /// Process-local deletion fence. Once set, in-flight requests that passed
    /// authentication cannot recreate or save this user's content.
    blocked_users: HashSet<UserId>,
    /// Exact media inventory captured before deletion I/O. Keeping it outside
    /// the open-handle cache lets a failed deletion release scarce SQLite
    /// capacity without forgetting locally committed-but-unsaved media keys.
    pending_deletion_media: HashMap<UserId, Arc<[String]>>,
    /// Bounded completion markers make `with_user(...); save_user(...)`
    /// idempotent when an unrelated cache miss evicts and flushes that handle
    /// in between the two calls.
    recent_clean_evictions: HashMap<UserId, u64>,
    access_clock: u64,
}

struct OpenUser {
    actor: Arc<UserActor>,
    last_used: u64,
    status: OpenStatus,
    /// Weak liveness token for a cancellable Loading/Evicting transition. If
    /// the owning future is dropped, the token expires and the next capacity
    /// waiter can repair the process-local registry state.
    transition: Option<Weak<RegistryTransition>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenStatus {
    Loading,
    Open,
    Evicting,
    /// An eviction future was cancelled. The handle may still be present, or
    /// the flush may already have completed and removed it. Either case is
    /// recoverable under the same actor lock.
    RecoveredEviction,
}

struct EvictionCandidate {
    user_id: UserId,
    actor: Arc<UserActor>,
    transition: Arc<RegistryTransition>,
}

enum CapacityAction {
    Reserved(Arc<RegistryTransition>),
    Evict(EvictionCandidate),
    Wait,
}

/// A cancellable registry transition owns one strong token while the registry
/// retains only a weak reference. Dropping the future expires the token and
/// wakes a capacity waiter, which repairs the abandoned state without doing
/// async work from `Drop`.
struct RegistryTransition {
    registry_changed: Arc<Notify>,
}

impl RegistryTransition {
    fn new(registry_changed: &Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            registry_changed: Arc::clone(registry_changed),
        })
    }
}

impl Drop for RegistryTransition {
    fn drop(&mut self) {
        self.registry_changed.notify_one();
    }
}

/// Own a freshly loaded handle until its registry reservation is committed.
/// Cancellation while waiting for that final registry lock must close SQLite
/// before removing its plaintext temp files.
struct PendingUserHandle(Option<UserHandle>);

impl PendingUserHandle {
    fn new(handle: UserHandle) -> Self {
        Self(Some(handle))
    }

    fn take(mut self) -> UserHandle {
        self.0.take().expect("pending user handle already consumed")
    }
}

impl Drop for PendingUserHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let temp_path = handle.temp_path.clone();
            drop(handle);
            remove_temp_db_files(&temp_path);
        }
    }
}

enum SaveTarget {
    Actor(Arc<UserActor>),
    AlreadyFlushed,
}

impl StoreRegistry {
    fn next_access(&mut self) -> u64 {
        self.access_clock = self.access_clock.saturating_add(1);
        self.access_clock
    }

    fn actor_for(&mut self, user_id: &str, max_open: usize) -> Arc<UserActor> {
        if let Some(actor) = self.actors.get(user_id).and_then(Weak::upgrade) {
            return actor;
        }

        // Failed loads leave only expired weak entries. Bound that bookkeeping
        // without scanning the registry on every ordinary request.
        let cleanup_threshold = max_open.saturating_mul(4).max(64);
        if self.actors.len() >= cleanup_threshold {
            self.actors.retain(|_, actor| actor.strong_count() != 0);
        }

        let actor = Arc::new(UserActor {
            state: Mutex::new(UserActorState::default()),
        });
        self.actors
            .insert(user_id.to_string(), Arc::downgrade(&actor));
        actor
    }

    fn touch(&mut self, user_id: &str) {
        let access = self.next_access();
        if let Some(open) = self.open_users.get_mut(user_id) {
            // Once eviction is selected, that ordering decision wins. A racing
            // access keeps this same actor Arc, waits for eviction, then reloads;
            // a racing save observes `cleanly_evicted` and succeeds because the
            // eviction itself performed the requested flush.
            if open.status != OpenStatus::Evicting {
                open.last_used = access;
            }
        }
    }

    fn record_clean_eviction(&mut self, user_id: &str, max_open: usize) {
        let access = self.next_access();
        let limit = max_open.saturating_mul(4).max(64);
        if self.recent_clean_evictions.len() >= limit
            && !self.recent_clean_evictions.contains_key(user_id)
        {
            if let Some(oldest) = self
                .recent_clean_evictions
                .iter()
                .min_by_key(|(_, access)| **access)
                .map(|(user_id, _)| user_id.clone())
            {
                self.recent_clean_evictions.remove(&oldest);
            }
        }
        self.recent_clean_evictions
            .insert(user_id.to_string(), access);
    }

    /// Repair transitions whose owning request future was cancelled. Loading
    /// handles are not installed until their reservation is committed, so an
    /// abandoned Loading entry can be removed. An abandoned eviction may have
    /// stopped before or after its flush; preserve the actor and let its next
    /// holder resolve the handle state under the per-user lock.
    fn recover_abandoned_transitions(&mut self) {
        let abandoned_loads = self
            .open_users
            .iter()
            .filter(|(_, open)| open.status == OpenStatus::Loading && transition_expired(open))
            .map(|(user_id, _)| user_id.clone())
            .collect::<Vec<_>>();
        for user_id in abandoned_loads {
            self.open_users.remove(&user_id);
        }

        for open in self.open_users.values_mut() {
            if open.status == OpenStatus::Evicting && transition_expired(open) {
                open.status = OpenStatus::RecoveredEviction;
                open.transition = None;
            }
        }
    }
}

fn transition_expired(open: &OpenUser) -> bool {
    open.transition.as_ref().and_then(Weak::upgrade).is_none()
}

fn transition_matches(open: &OpenUser, transition: &Arc<RegistryTransition>) -> bool {
    open.transition
        .as_ref()
        .and_then(Weak::upgrade)
        .is_some_and(|current| Arc::ptr_eq(&current, transition))
}

#[derive(Debug, Clone)]
pub struct EmailDeliveryRow {
    pub episode_id: i64,
    pub delivery_version: i32,
    pub delivery_id: String,
    pub include_content: bool,
    pub state: String,
    pub attempt_count: i32,
    pub next_attempt_at: String,
    pub provider_message_id: Option<String>,
    pub response_status: Option<u16>,
    pub error_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Store {
    pub fn new(kms: Arc<dyn KmsClient>, gcs: Arc<dyn GcsClient>) -> Self {
        let media_gcs = Arc::clone(&gcs);
        Self::new_internal(kms, gcs, media_gcs)
    }

    pub fn new_with_media(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
    ) -> Self {
        Self::new_internal(kms, gcs, media_gcs)
    }

    fn new_internal(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
    ) -> Self {
        let max_open = std::env::var("STORE_MAX_OPEN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(16usize)
            .max(1);
        Self::new_internal_with_max_open(kms, gcs, media_gcs, max_open)
    }

    fn new_internal_with_max_open(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
        max_open: usize,
    ) -> Self {
        Store {
            registry: Mutex::new(StoreRegistry {
                actors: HashMap::new(),
                open_users: HashMap::new(),
                blocked_users: HashSet::new(),
                pending_deletion_media: HashMap::new(),
                recent_clean_evictions: HashMap::new(),
                access_clock: 0,
            }),
            registry_changed: Arc::new(Notify::new()),
            kms,
            gcs,
            media_gcs,
            max_open: max_open.max(1),
            checkpoint_clock: Arc::new(SystemTime::now),
            storage_metrics: StorageMetrics::default(),
        }
    }

    /// Periodically emit one process-wide, unlabeled snapshot through the
    /// existing structured tracing pipeline. No network metrics service is
    /// introduced, and idle intervals are suppressed.
    pub fn spawn_metrics_reporter(store: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            let mut last_snapshot = store.storage_metrics_snapshot();
            loop {
                interval.tick().await;
                let snapshot = store.storage_metrics_snapshot();
                if snapshot == last_snapshot {
                    continue;
                }
                log_storage_metrics(&snapshot);
                last_snapshot = snapshot;
            }
        });
    }

    pub(crate) fn storage_metrics_snapshot(&self) -> StorageMetricsSnapshot {
        self.storage_metrics.snapshot()
    }

    pub async fn put_media(&self, name: &str, data: &[u8], wrapped_dek_b64: &str) -> Result<i64> {
        self.put_media_at_generation(name, data, wrapped_dek_b64, 0)
            .await
    }

    pub async fn put_media_at_generation(
        &self,
        name: &str,
        data: &[u8],
        wrapped_dek_b64: &str,
        generation: i64,
    ) -> Result<i64> {
        self.media_gcs
            .put_object(name, data, wrapped_dek_b64, generation)
            .await
    }

    pub async fn get_media(&self, name: &str) -> Result<crate::store::GcsGetResponse> {
        self.media_gcs.get_object(name).await
    }

    pub async fn delete_media(&self, name: &str) -> Result<()> {
        self.media_gcs.delete_object(name).await
    }

    pub async fn delete_media_generation(&self, name: &str, generation: i64) -> Result<()> {
        self.media_gcs
            .delete_object_generation(name, generation)
            .await
    }

    /// Run an operation with a user's open SQLite connection.
    /// Loads the user on first access; evicts LRU handle if over cap.
    pub async fn with_user<F, T>(&self, user_id: &str, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let actor = self.actor_for_access(user_id).await?;
        let mut state = actor.state.lock().await;

        // Deletion may have installed its fence after this request found the
        // actor but before it won the per-user lock.
        self.reject_if_blocked(user_id).await?;
        if state.handle.is_none() {
            self.ensure_loaded(user_id, &actor, &mut state).await?;
            // A load can block on GCS/KMS. Never expose a freshly loaded
            // connection if deletion fenced the user during that await.
            self.reject_if_blocked(user_id).await?;
        }
        let handle = state.handle.as_mut().ok_or_else(|| {
            EnclaveError::Store("open-user registry lost its SQLite handle".into())
        })?;
        if handle.blob_meta.retry_save_before_access {
            self.flush_handle(handle).await?;
        }
        let before = database_mutation_fingerprint(&handle.conn)?;
        let result = f(&handle.conn);
        match database_mutation_fingerprint(&handle.conn) {
            Ok(after) if after != before => handle.mark_dirty(),
            Ok(_) => {}
            Err(error) => {
                // The closure may already have committed. If we cannot prove
                // the post-state, retain the handle as dirty and fail closed.
                handle.mark_dirty();
                return Err(error);
            }
        }
        result
    }

    /// Run a closure under SQLite's connection-level query-only guard.
    ///
    /// This is the explicit API for operations claimed to be read-only. Any
    /// attempted SQL mutation fails in SQLite, and the guard is restored even
    /// when the caller returns an error.
    pub async fn with_user_read<F, T>(&self, user_id: &str, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        self.with_user(user_id, move |conn| {
            conn.pragma_update(None, "query_only", true)?;
            let result = f(conn);
            let restore = conn.pragma_update(None, "query_only", false);
            if let Err(error) = restore {
                return Err(error.into());
            }
            result
        })
        .await
    }

    /// Conservatively declare an operation mutating before invoking it.
    ///
    /// Use this for extension or FFI work whose effects cannot be represented
    /// by SQLite's row/schema/header mutation fingerprint. Ordinary SQL can use
    /// [`Store::with_user`], which detects direct, trigger, and schema changes.
    pub async fn with_user_mut<F, T>(&self, user_id: &str, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let actor = self.actor_for_access(user_id).await?;
        let mut state = actor.state.lock().await;

        self.reject_if_blocked(user_id).await?;
        if state.handle.is_none() {
            self.ensure_loaded(user_id, &actor, &mut state).await?;
            self.reject_if_blocked(user_id).await?;
        }

        let handle = state.handle.as_mut().ok_or_else(|| {
            EnclaveError::Store("open-user registry lost its SQLite handle".into())
        })?;
        if handle.blob_meta.retry_save_before_access {
            self.flush_handle(handle).await?;
        }
        handle.mark_dirty();
        f(&handle.conn)
    }

    /// Persist a user's index back to GCS.
    pub async fn save_user(&self, user_id: &str) -> Result<()> {
        let actor = match self.actor_for_existing(user_id).await? {
            SaveTarget::Actor(actor) => actor,
            SaveTarget::AlreadyFlushed => return Ok(()),
        };
        let mut state = actor.state.lock().await;
        self.reject_if_blocked(user_id).await?;
        if let Some(handle) = state.handle.as_mut() {
            self.flush_handle(handle).await
        } else if state.cleanly_evicted {
            // Eviction serialized ahead of this save and flushed the same
            // connection successfully. Treat it as an idempotent save success.
            Ok(())
        } else if self.was_recently_cleanly_evicted(user_id).await {
            Ok(())
        } else {
            Err(EnclaveError::NotFound)
        }
    }

    /// Hard-delete all user data: evict from cache and delete the GCS object.
    ///
    /// Idempotent: if the user was never seen (no cache entry, no GCS object)
    /// this returns `Ok(())`.
    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        validate_user_id(user_id)?;

        // Install the fence before waiting for any in-flight same-user work.
        // Existing work may finish; later work re-checks after winning the
        // actor lock and fails without recreating or saving the account.
        let actor = self.actor_for_deletion(user_id).await;
        let mut state = actor.state.lock().await;

        // 1. Query for GCS media keys to clean up. Persist the exact inventory
        // in the process-local deletion state before issuing any delete. A
        // retry after partial failure can therefore release the SQLite handle
        // (and its max-open slot) without losing locally-only media references.
        let saved_inventory = self
            .registry
            .lock()
            .await
            .pending_deletion_media
            .get(user_id)
            .cloned();
        let keys_to_delete = if let Some(keys) = saved_inventory {
            keys
        } else {
            if state.handle.is_none() {
                self.ensure_loaded(user_id, &actor, &mut state).await?;
            }
            let keys: Arc<[String]> = media_keys(
                &state
                    .handle
                    .as_ref()
                    .ok_or_else(|| EnclaveError::Store("delete load lost its handle".into()))?
                    .conn,
            )?
            .into();
            self.registry
                .lock()
                .await
                .pending_deletion_media
                .insert(user_id.to_string(), Arc::clone(&keys));
            keys
        };

        // The exact inventory is now independent of the live Connection, so
        // release its max-open slot before any slow remote deletion. The GCS
        // database remains authoritative until every referenced object is gone.
        self.discard_handle_for_deletion(user_id, &actor, &mut state)
            .await;

        // `versions=true` excludes soft-deleted objects. Record pre-existing
        // residue, but continue removing anything still live/noncurrent. Final
        // verification below remains fail-closed.
        let _preexisting_soft_deleted = self
            .has_soft_deleted_account_objects(user_id, &keys_to_delete)
            .await?;

        // Delete every historical raw-media generation, including objects no
        // longer represented by the current SQLite blob. The prefix includes
        // its trailing slash, so another user's similarly named prefix cannot
        // be selected.
        self.delete_all_versions_under(&self.media_gcs, &media_prefix(user_id))
            .await?;
        for key in keys_to_delete.iter() {
            self.delete_all_versions_for_name(&self.media_gcs, key)
                .await?;
        }

        // Every retained legacy DB/checkpoint generation can name unscoped
        // evidence that the live DB no longer references. Inventory one exact
        // generation at a time, delete its media, and only then erase that DB
        // generation. Any unreadable generation leaves deletion incomplete.
        self.inventory_and_delete_legacy_databases(user_id, &gcs_object_name(user_id), true)
            .await?;
        self.inventory_and_delete_legacy_databases(
            user_id,
            &legacy_recovery_prefix(user_id),
            false,
        )
        .await?;

        if self
            .has_soft_deleted_account_objects(user_id, &keys_to_delete)
            .await?
        {
            return Err(soft_deleted_account_objects_error());
        }

        self.registry
            .lock()
            .await
            .pending_deletion_media
            .remove(user_id);
        Ok(())
    }

    async fn has_soft_deleted_account_objects(
        &self,
        user_id: &str,
        referenced_media_keys: &[String],
    ) -> Result<bool> {
        let namespaces = [
            (&self.gcs, gcs_object_name(user_id), true),
            (&self.gcs, legacy_recovery_prefix(user_id), false),
            (&self.media_gcs, media_prefix(user_id), false),
        ];
        for (gcs, selector, exact_name) in namespaces {
            if has_matching_soft_deleted_object(gcs.as_ref(), &selector, exact_name).await? {
                return Ok(true);
            }
        }
        for name in referenced_media_keys {
            if has_matching_soft_deleted_object(self.media_gcs.as_ref(), name, true).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn delete_all_versions_for_name(
        &self,
        gcs: &Arc<dyn GcsClient>,
        name: &str,
    ) -> Result<()> {
        delete_matching_object_versions(gcs.as_ref(), name, true).await
    }

    async fn delete_all_versions_under(
        &self,
        gcs: &Arc<dyn GcsClient>,
        prefix: &str,
    ) -> Result<()> {
        delete_matching_object_versions(gcs.as_ref(), prefix, false).await
    }

    async fn inventory_and_delete_legacy_databases(
        &self,
        user_id: &str,
        selector: &str,
        exact_name: bool,
    ) -> Result<()> {
        let mut page_token = None;
        for _ in 0..MAX_GCS_LIST_PAGES {
            let page = self
                .gcs
                .list_object_versions(selector, page_token.as_deref())
                .await?;
            let matching = page
                .versions
                .into_iter()
                .filter(|version| {
                    if exact_name {
                        version.name == selector
                    } else {
                        version.name.starts_with(selector)
                    }
                })
                .collect::<Vec<_>>();
            if !matching.is_empty() {
                for version in matching {
                    let keys = match self
                        .media_keys_from_legacy_generation(user_id, &version)
                        .await
                    {
                        Ok(keys) => keys,
                        // A concurrent/idempotent retry may have already
                        // removed the exact generation after it was listed.
                        Err(EnclaveError::NotFound) => Vec::new(),
                        Err(_) => return Err(legacy_inventory_incomplete_error()),
                    };
                    for key in keys {
                        self.delete_all_versions_for_name(&self.media_gcs, &key)
                            .await?;
                        if has_matching_soft_deleted_object(self.media_gcs.as_ref(), &key, true)
                            .await?
                        {
                            return Err(soft_deleted_account_objects_error());
                        }
                    }
                    self.gcs
                        .delete_object_generation(&version.name, version.generation)
                        .await?;
                }
                page_token = None;
                continue;
            }
            match page.next_page_token {
                Some(next) if page_token.as_deref() != Some(next.as_str()) => {
                    page_token = Some(next)
                }
                Some(_) => {
                    return Err(EnclaveError::Gcs(
                        "GCS legacy database listing repeated a page cursor".into(),
                    ))
                }
                None => return Ok(()),
            }
        }
        Err(EnclaveError::Gcs(
            "GCS legacy database listing exceeded the bounded page limit".into(),
        ))
    }

    async fn media_keys_from_legacy_generation(
        &self,
        user_id: &str,
        version: &GcsObjectVersion,
    ) -> Result<Vec<String>> {
        if version.size > MAX_LEGACY_DELETION_SNAPSHOT_BYTES {
            return Err(legacy_inventory_incomplete_error());
        }
        let response = self
            .gcs
            .get_object_generation(&version.name, version.generation)
            .await?;
        let dek = load_dek(self.kms.as_ref(), &response.wrapped_dek_b64).await?;
        let opened = decrypt_bound_blob(&dek, &response.ciphertext, &user_blob_context(user_id))?;
        let temp_path = write_private_temp_db(user_id, &opened.plaintext).await?;
        let result = (|| {
            init_vec_extension();
            let conn = Connection::open_with_flags(&temp_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            conn.execute_batch("PRAGMA query_only=ON;")?;
            media_keys(&conn)
        })();
        remove_temp_db_files(&temp_path);
        result
    }

    // ── Email Outbox ───────────────────────────────────────────────────────────

    pub async fn enqueue_email_delivery(
        &self,
        user_id: &str,
        episode_id: i64,
        delivery_version: i32,
        include_content: bool,
    ) -> Result<String> {
        let user = user_id.to_string();
        let delivery_id = format!("deliv_{}", crate::cp::tokens::random_token_hex());
        let now = crate::cp::isotime::format_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );

        let id = delivery_id.clone();
        self.with_user(&user, move |conn| {
            conn.execute(
                "INSERT INTO email_deliveries
                 (episode_id, delivery_version, delivery_id, include_content, state, attempt_count, next_attempt_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5, ?5, ?5)",
                rusqlite::params![
                    episode_id,
                    delivery_version,
                    id,
                    if include_content { 1 } else { 0 },
                    now,
                ],
            )?;
            Ok(())
        })
        .await?;
        self.save_user(user_id).await?;
        Ok(delivery_id)
    }

    pub async fn next_email_delivery(&self, user_id: &str) -> Result<Option<EmailDeliveryRow>> {
        let user = user_id.to_string();
        let now = crate::cp::isotime::format_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );

        self.with_user(&user, move |conn| {
            Ok(conn
                .query_row(
                    "SELECT episode_id, delivery_version, delivery_id, include_content, state,
                            attempt_count, next_attempt_at, provider_message_id, response_status,
                            error_code, created_at, updated_at
                     FROM email_deliveries
                     WHERE state IN ('pending', 'retry') AND next_attempt_at <= ?1
                     ORDER BY created_at, episode_id
                     LIMIT 1",
                    [&now],
                    |r| {
                        let include_num: i64 = r.get(3)?;
                        let resp_status: Option<i64> = r.get(8)?;
                        Ok(EmailDeliveryRow {
                            episode_id: r.get(0)?,
                            delivery_version: r.get(1)?,
                            delivery_id: r.get(2)?,
                            include_content: include_num != 0,
                            state: r.get(4)?,
                            attempt_count: r.get(5)?,
                            next_attempt_at: r.get(6)?,
                            provider_message_id: r.get(7)?,
                            response_status: resp_status.map(|s| s as u16),
                            error_code: r.get(9)?,
                            created_at: r.get(10)?,
                            updated_at: r.get(11)?,
                        })
                    },
                )
                .optional()?)
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_email_delivery_state(
        &self,
        user_id: &str,
        episode_id: i64,
        delivery_version: i32,
        state: &str,
        attempt_count: i32,
        provider_message_id: Option<&str>,
        response_status: Option<u16>,
        error_code: Option<&str>,
    ) -> Result<()> {
        let user = user_id.to_string();
        let state = state.to_string();
        let provider_message_id = provider_message_id.map(str::to_string);
        let error_code = error_code.map(str::to_string);
        let now = crate::cp::isotime::format_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );

        self.with_user(&user, move |conn| {
            conn.execute(
                "UPDATE email_deliveries
                 SET state = ?1, attempt_count = ?2, provider_message_id = ?3,
                     response_status = ?4, error_code = ?5, updated_at = ?6
                 WHERE episode_id = ?7 AND delivery_version = ?8",
                rusqlite::params![
                    state,
                    attempt_count,
                    provider_message_id,
                    response_status.map(i64::from),
                    error_code,
                    now,
                    episode_id,
                    delivery_version,
                ],
            )?;
            Ok(())
        })
        .await?;
        self.save_user(user_id).await
    }

    pub async fn set_email_delivery_next_attempt(
        &self,
        user_id: &str,
        episode_id: i64,
        delivery_version: i32,
        next_attempt_at: &str,
    ) -> Result<()> {
        let user = user_id.to_string();
        let next_attempt_at = next_attempt_at.to_string();
        let now = crate::cp::isotime::format_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );

        self.with_user(&user, move |conn| {
            conn.execute(
                "UPDATE email_deliveries
                 SET next_attempt_at = ?1, updated_at = ?2
                 WHERE episode_id = ?3 AND delivery_version = ?4",
                rusqlite::params![next_attempt_at, now, episode_id, delivery_version],
            )?;
            Ok(())
        })
        .await?;
        self.save_user(user_id).await
    }

    pub async fn cancel_pending_email_deliveries(&self, user_id: &str, reason: &str) -> Result<()> {
        let user = user_id.to_string();
        let reason = reason.to_string();
        let now = crate::cp::isotime::format_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );

        self.with_user(&user, move |conn| {
            conn.execute(
                "UPDATE email_deliveries
                 SET state = 'cancelled', error_code = ?1, updated_at = ?2
                 WHERE state IN ('pending', 'retry')",
                rusqlite::params![reason, now],
            )?;
            Ok(())
        })
        .await?;
        self.save_user(user_id).await
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    async fn actor_for_access(&self, user_id: &str) -> Result<Arc<UserActor>> {
        validate_user_id(user_id)?;
        let mut registry = self.registry.lock().await;
        if registry.blocked_users.contains(user_id) {
            return Err(deleted_user_error());
        }
        let actor = registry.actor_for(user_id, self.max_open);
        registry.touch(user_id);
        Ok(actor)
    }

    async fn actor_for_existing(&self, user_id: &str) -> Result<SaveTarget> {
        validate_user_id(user_id)?;
        let mut registry = self.registry.lock().await;
        if registry.blocked_users.contains(user_id) {
            return Err(deleted_user_error());
        }
        if let Some(actor) = registry.actors.get(user_id).and_then(Weak::upgrade) {
            registry.touch(user_id);
            Ok(SaveTarget::Actor(actor))
        } else if registry.recent_clean_evictions.contains_key(user_id) {
            Ok(SaveTarget::AlreadyFlushed)
        } else {
            Err(EnclaveError::NotFound)
        }
    }

    async fn actor_for_deletion(&self, user_id: &str) -> Arc<UserActor> {
        let mut registry = self.registry.lock().await;
        registry.blocked_users.insert(user_id.to_string());
        registry.recent_clean_evictions.remove(user_id);
        let actor = registry.actor_for(user_id, self.max_open);
        registry.touch(user_id);
        actor
    }

    async fn reject_if_blocked(&self, user_id: &str) -> Result<()> {
        if self.registry.lock().await.blocked_users.contains(user_id) {
            Err(deleted_user_error())
        } else {
            Ok(())
        }
    }

    async fn was_recently_cleanly_evicted(&self, user_id: &str) -> bool {
        self.registry
            .lock()
            .await
            .recent_clean_evictions
            .contains_key(user_id)
    }

    /// Reserve one of the bounded open-handle slots. Full-cache eviction is
    /// performed without the registry lock; loading/evicting reservations keep
    /// concurrent cache misses from exceeding `max_open`.
    async fn reserve_open_slot(
        &self,
        user_id: &str,
        actor: &Arc<UserActor>,
    ) -> Result<Arc<RegistryTransition>> {
        loop {
            // `notify_one` retains a permit if a state transition lands between
            // the registry check and this await, avoiding a lost wakeup.
            let changed = self.registry_changed.notified();
            let action = {
                let mut registry = self.registry.lock().await;
                registry.recover_abandoned_transitions();

                let recovered_same_actor = registry.open_users.get(user_id).is_some_and(|open| {
                    open.status == OpenStatus::RecoveredEviction && Arc::ptr_eq(&open.actor, actor)
                });
                if recovered_same_actor {
                    // This method is called only while the actor state has no
                    // handle. A cancelled eviction already removed it, so its
                    // stale capacity registration can be released and reloaded.
                    registry.open_users.remove(user_id);
                } else if registry.open_users.contains_key(user_id) {
                    return Err(EnclaveError::Store(
                        "duplicate open-handle reservation for one user".into(),
                    ));
                }

                if registry.open_users.len() < self.max_open {
                    let transition = RegistryTransition::new(&self.registry_changed);
                    let access = registry.next_access();
                    registry.open_users.insert(
                        user_id.to_string(),
                        OpenUser {
                            actor: Arc::clone(actor),
                            last_used: access,
                            status: OpenStatus::Loading,
                            transition: Some(Arc::downgrade(&transition)),
                        },
                    );
                    CapacityAction::Reserved(transition)
                } else {
                    let candidate_id = registry
                        .open_users
                        .iter()
                        .filter(|(candidate_id, open)| {
                            candidate_id.as_str() != user_id
                                && matches!(
                                    open.status,
                                    OpenStatus::Open | OpenStatus::RecoveredEviction
                                )
                                && !registry.blocked_users.contains(candidate_id.as_str())
                        })
                        .min_by_key(|(_, open)| open.last_used)
                        .map(|(candidate_id, _)| candidate_id.clone());

                    if let Some(candidate_id) = candidate_id {
                        let transition = RegistryTransition::new(&self.registry_changed);
                        let Some(open) = registry.open_users.get_mut(&candidate_id) else {
                            return Err(EnclaveError::Store(
                                "LRU candidate disappeared under registry lock".into(),
                            ));
                        };
                        open.status = OpenStatus::Evicting;
                        open.transition = Some(Arc::downgrade(&transition));
                        CapacityAction::Evict(EvictionCandidate {
                            user_id: candidate_id,
                            actor: Arc::clone(&open.actor),
                            transition,
                        })
                    } else {
                        CapacityAction::Wait
                    }
                }
            };

            match action {
                CapacityAction::Reserved(transition) => return Ok(transition),
                CapacityAction::Evict(candidate) => self.evict_candidate(candidate).await?,
                CapacityAction::Wait => changed.await,
            }
        }
    }

    async fn finish_load_registration(
        &self,
        user_id: &str,
        actor: &Arc<UserActor>,
        transition: &Arc<RegistryTransition>,
        loaded: bool,
    ) -> Result<()> {
        let mut registry = self.registry.lock().await;
        let valid = registry.open_users.get(user_id).is_some_and(|open| {
            open.status == OpenStatus::Loading
                && Arc::ptr_eq(&open.actor, actor)
                && transition_matches(open, transition)
        });
        if !valid {
            return Err(EnclaveError::Store(
                "open-handle reservation changed during load".into(),
            ));
        }

        if loaded {
            let access = registry.next_access();
            let open = registry.open_users.get_mut(user_id).ok_or_else(|| {
                EnclaveError::Store("validated load reservation disappeared".into())
            })?;
            open.status = OpenStatus::Open;
            open.last_used = access;
            open.transition = None;
            registry.recent_clean_evictions.remove(user_id);
        } else {
            registry.open_users.remove(user_id);
        }
        drop(registry);
        self.registry_changed.notify_one();
        Ok(())
    }

    async fn ensure_loaded(
        &self,
        user_id: &str,
        actor: &Arc<UserActor>,
        state: &mut UserActorState,
    ) -> Result<()> {
        if state.handle.is_some() {
            return Ok(());
        }

        let transition = self.reserve_open_slot(user_id, actor).await?;
        match self.load_user(user_id).await {
            Ok(handle) => {
                let pending = PendingUserHandle::new(handle);
                if let Err(error) = self
                    .finish_load_registration(user_id, actor, &transition, true)
                    .await
                {
                    return Err(error);
                }
                state.handle = Some(pending.take());
                state.cleanly_evicted = false;
                Ok(())
            }
            Err(load_error) => {
                self.finish_load_registration(user_id, actor, &transition, false)
                    .await?;
                Err(load_error)
            }
        }
    }

    async fn release_open_registration(&self, user_id: &str, actor: &Arc<UserActor>) {
        let mut registry = self.registry.lock().await;
        let matches = registry
            .open_users
            .get(user_id)
            .is_some_and(|open| Arc::ptr_eq(&open.actor, actor));
        if matches {
            registry.open_users.remove(user_id);
        }
        drop(registry);
        self.registry_changed.notify_one();
    }

    async fn complete_clean_eviction_registration(
        &self,
        user_id: &str,
        actor: &Arc<UserActor>,
        transition: &Arc<RegistryTransition>,
    ) {
        let mut registry = self.registry.lock().await;
        let matches = registry.open_users.get(user_id).is_some_and(|open| {
            open.status == OpenStatus::Evicting
                && Arc::ptr_eq(&open.actor, actor)
                && transition_matches(open, transition)
        });
        if matches {
            registry.open_users.remove(user_id);
        }
        if !registry.blocked_users.contains(user_id) {
            registry.record_clean_eviction(user_id, self.max_open);
        }
        drop(registry);
        self.registry_changed.notify_one();
    }

    async fn discard_handle_for_deletion(
        &self,
        user_id: &str,
        actor: &Arc<UserActor>,
        state: &mut UserActorState,
    ) {
        if let Some(handle) = state.handle.take() {
            info!("evicting deleted user handle");
            let temp_path = handle.temp_path.clone();
            drop(handle);
            remove_temp_db_files(&temp_path);
        }
        state.cleanly_evicted = false;
        self.release_open_registration(user_id, actor).await;
    }

    async fn evict_candidate(&self, candidate: EvictionCandidate) -> Result<()> {
        let mut state = candidate.actor.state.lock().await;
        warn!("LRU user-handle eviction");
        let had_handle = state.handle.is_some();

        if let Some(handle) = state.handle.as_mut() {
            // A failed flush leaves the connection, generation, and plaintext
            // temp files attached to the same actor. The waiting cache miss
            // fails rather than discarding unpersisted mutations.
            if let Err(error) = self.flush_handle(handle).await {
                tracing::error!("user-handle eviction flush failed");
                let mut registry = self.registry.lock().await;
                if let Some(open) = registry.open_users.get_mut(&candidate.user_id) {
                    if open.status == OpenStatus::Evicting
                        && Arc::ptr_eq(&open.actor, &candidate.actor)
                        && transition_matches(open, &candidate.transition)
                    {
                        open.status = OpenStatus::Open;
                        open.transition = None;
                    }
                }
                drop(registry);
                self.registry_changed.notify_one();
                return Err(error);
            }
        }

        if let Some(handle) = state.handle.take() {
            let temp_path = handle.temp_path.clone();
            drop(handle);
            remove_temp_db_files(&temp_path);
        }
        state.cleanly_evicted = had_handle;
        if had_handle {
            self.complete_clean_eviction_registration(
                &candidate.user_id,
                &candidate.actor,
                &candidate.transition,
            )
            .await;
        } else {
            self.release_open_registration(&candidate.user_id, &candidate.actor)
                .await;
        }
        Ok(())
    }

    async fn load_user(&self, user_id: &str) -> Result<UserHandle> {
        // Defense in depth: handlers validate at the API boundary, but no
        // path or object name may ever be derived from an unvalidated id.
        validate_user_id(user_id)?;
        let object_name = gcs_object_name(user_id);

        // Try to fetch existing blob from GCS
        let fetch_result = self.gcs.get_object(&object_name).await;
        let (plaintext_db, blob_meta, envelope_rewrite_dirty) = match fetch_result {
            Ok(resp) => {
                self.storage_metrics
                    .record_encrypted_download(resp.ciphertext.len() as u64);
                // Unwrap the DEK from KMS
                let dek = load_dek(self.kms.as_ref(), &resp.wrapped_dek_b64).await?;
                let context = user_blob_context(user_id);
                let opened = decrypt_bound_blob(&dek, &resp.ciphertext, &context)?;
                (
                    opened.plaintext,
                    BlobMeta {
                        generation: resp.generation,
                        wrapped_dek_b64: resp.wrapped_dek_b64,
                        verified_legacy_recovery_day: None,
                        retry_save_before_access: false,
                    },
                    opened.requires_rewrite,
                )
            }
            Err(EnclaveError::NotFound) => {
                // New user — generate a fresh DEK and an empty database
                info!("creating new user index");
                let (dek, wrapped) = generate_and_wrap_dek(self.kms.as_ref()).await?;
                let empty_db = create_empty_db(&dek)?;
                (
                    empty_db,
                    BlobMeta {
                        generation: 0,
                        wrapped_dek_b64: wrapped,
                        verified_legacy_recovery_day: None,
                        retry_save_before_access: false,
                    },
                    false,
                )
            }
            Err(e) => return Err(e),
        };
        self.storage_metrics
            .record_logical_db_bytes(plaintext_db.len() as u64);

        // Write plaintext to a temp file and open it with rusqlite
        let temp_path = write_private_temp_db(user_id, &plaintext_db).await?;
        let (conn, migration_dirty) = match open_db(&temp_path) {
            Ok(opened) => opened,
            Err(e) => {
                remove_temp_db_files(&temp_path);
                return Err(e);
            }
        };

        Ok(UserHandle {
            user_id: user_id.to_string(),
            conn,
            blob_meta,
            mutation_generation: u64::from(migration_dirty || envelope_rewrite_dirty),
            persisted_mutation_generation: 0,
            dirty: migration_dirty || envelope_rewrite_dirty,
            temp_path,
        })
    }

    async fn flush_handle(&self, handle: &mut UserHandle) -> Result<()> {
        let started = Instant::now();
        self.storage_metrics.record_save_attempt();
        if !handle.dirty {
            debug!(
                mutation_generation = handle.mutation_generation,
                persisted_mutation_generation = handle.persisted_mutation_generation,
                "skipped clean user index save"
            );
            let latency_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
            self.storage_metrics.record_save_completed(None, latency_us);
            return Ok(());
        }

        // From this point until the generation-checked PUT succeeds, the local
        // handle may contain state a request intends to acknowledge. Any
        // failure must make the next access retry persistence before its
        // closure can observe an idempotency duplicate and return success.
        handle.blob_meta.retry_save_before_access = true;

        let result = self.flush_handle_inner(handle).await;
        let latency_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        match &result {
            Ok((logical_db_bytes, changed_wal_bytes_proxy, encrypted_bytes)) => {
                self.storage_metrics.record_save_completed(
                    Some((
                        *logical_db_bytes,
                        *changed_wal_bytes_proxy,
                        *encrypted_bytes,
                    )),
                    latency_us,
                )
            }
            Err(_) => self.storage_metrics.record_save_failed(latency_us),
        }
        result.map(|_| ())
    }

    async fn flush_handle_inner(&self, handle: &mut UserHandle) -> Result<(u64, u64, u64)> {
        // The WAL length before checkpoint is the best available Phase-0 proxy
        // for bytes changed since the previous flush. It is not exact dirty
        // page bytes: it includes WAL headers/frame metadata and SQLite may
        // auto-checkpoint frames before this observation.
        let wal_path = sqlite_sidecar_path(&handle.temp_path, "-wal");
        let changed_wal_bytes_proxy = match tokio::fs::metadata(&wal_path).await {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        self.storage_metrics
            .record_changed_wal_bytes_proxy(changed_wal_bytes_proxy);

        // WAL checkpoint: make sure all WAL pages are in the main DB file
        handle
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

        // Read the SQLite file from disk
        let db_bytes = tokio::fs::read(&handle.temp_path).await?;

        // Unwrap DEK from KMS then re-encrypt the DB file
        let dek = load_dek(self.kms.as_ref(), &handle.blob_meta.wrapped_dek_b64).await?;
        let object_name = gcs_object_name(&handle.user_id);
        let context = user_blob_context(&handle.user_id);
        let ciphertext = encrypt_bound_blob(&dek, &db_bytes, &context)?;

        // Before the first overwrite of each UTC day, preserve the exact
        // currently authoritative generation. A generation-zero object has no
        // prior remote state at risk, so its initial create needs no copy; its
        // next overwrite will establish the checkpoint. Cache only a fully
        // verified day, and re-verify once after process restart.
        let checkpoint_now = (self.checkpoint_clock)();
        let checkpoint_day = utc_epoch_day(checkpoint_now);
        if handle.blob_meta.generation > 0
            && handle.blob_meta.verified_legacy_recovery_day != Some(checkpoint_day)
        {
            self.ensure_legacy_recovery_checkpoint(
                &handle.user_id,
                handle.blob_meta.generation,
                checkpoint_now,
            )
            .await?;
            handle.blob_meta.verified_legacy_recovery_day = Some(checkpoint_day);
        }

        let logical_db_bytes = db_bytes.len() as u64;
        let encrypted_bytes = ciphertext.len() as u64;
        self.storage_metrics
            .record_encrypted_upload_attempt(encrypted_bytes);
        let put_result = self
            .gcs
            .put_object(
                &object_name,
                &ciphertext,
                &handle.blob_meta.wrapped_dek_b64,
                handle.blob_meta.generation,
            )
            .await;
        let new_generation = match put_result {
            Ok(generation) => generation,
            Err(conflict @ EnclaveError::Conflict(_)) => {
                // A generation mismatch can be the retry of a PUT that GCS
                // committed before its response was lost or the caller was
                // cancelled. Reconcile only against the current immutable
                // snapshot: the wrapped DEK metadata must be byte-for-byte the
                // same, that DEK must authenticate the current envelope, and
                // the plaintext SQLite image must exactly equal this pending
                // save. Any genuine concurrent write remains a conflict.
                match self
                    .reconcile_committed_snapshot(
                        &object_name,
                        &handle.blob_meta.wrapped_dek_b64,
                        &dek,
                        &context,
                        &db_bytes,
                    )
                    .await
                {
                    Some(generation) => generation,
                    None => return Err(conflict),
                }
            }
            Err(error) => return Err(error),
        };
        // Invariant: record the post-write generation, or the NEXT save's
        // `ifGenerationMatch` conflicts against our own previous write.
        handle.blob_meta.generation = new_generation;
        handle.blob_meta.retry_save_before_access = false;
        handle.persisted_mutation_generation = handle.mutation_generation;
        handle.dirty = false;

        debug!("flushed user index to GCS");
        Ok((logical_db_bytes, changed_wal_bytes_proxy, encrypted_bytes))
    }

    async fn reconcile_committed_snapshot(
        &self,
        object_name: &str,
        expected_wrapped_dek_b64: &str,
        expected_dek: &Dek,
        context: &[u8],
        expected_plaintext: &[u8],
    ) -> Option<i64> {
        let current = self.gcs.get_object(object_name).await.ok()?;
        self.storage_metrics
            .record_encrypted_download(current.ciphertext.len() as u64);
        if current.generation <= 0 || current.wrapped_dek_b64 != expected_wrapped_dek_b64 {
            return None;
        }
        let opened = decrypt_bound_blob(expected_dek, &current.ciphertext, context).ok()?;
        if opened.requires_rewrite || opened.plaintext != expected_plaintext {
            return None;
        }
        Some(current.generation)
    }

    async fn ensure_legacy_recovery_checkpoint(
        &self,
        user_id: &str,
        source_generation: i64,
        now: SystemTime,
    ) -> Result<()> {
        let destination = legacy_recovery_checkpoint_name(user_id, now);
        let source = gcs_object_name(user_id);
        let copied = self
            .gcs
            .copy_generation_if_absent(&source, source_generation, &destination)
            .await?;
        if copied.source.generation != source_generation {
            return Err(EnclaveError::Gcs(
                "legacy recovery source generation did not match requested generation".into(),
            ));
        }
        verify_legacy_recovery_copy(
            &source,
            source_generation,
            &copied.source,
            &copied.destination,
            copied.created,
        )
    }
}

fn deleted_user_error() -> EnclaveError {
    EnclaveError::Auth("user account is deleted".into())
}

impl UserHandle {
    fn mark_dirty(&mut self) {
        self.mutation_generation = self.mutation_generation.saturating_add(1);
        self.dirty = true;
    }
}

fn log_storage_metrics(snapshot: &StorageMetricsSnapshot) {
    info!(
        target: "kioku::storage_metrics",
        metric_schema = "archive_snapshot_v1",
        logical_db_bytes_count = snapshot.logical_db_bytes.count,
        logical_db_bytes_sum = snapshot.logical_db_bytes.sum,
        logical_db_bytes_max = snapshot.logical_db_bytes.max,
        byte_bucket_upper_bounds = ?BYTE_BUCKET_UPPER_BOUNDS,
        logical_db_bytes_cumulative_buckets = ?snapshot.logical_db_bytes.cumulative_buckets,
        changed_wal_bytes_proxy_count = snapshot.changed_wal_bytes_proxy.count,
        changed_wal_bytes_proxy_sum = snapshot.changed_wal_bytes_proxy.sum,
        changed_wal_bytes_proxy_max = snapshot.changed_wal_bytes_proxy.max,
        changed_wal_bytes_proxy_cumulative_buckets = ?snapshot.changed_wal_bytes_proxy.cumulative_buckets,
        encrypted_upload_bytes_count = snapshot.encrypted_upload_bytes.count,
        encrypted_upload_bytes_total = snapshot.encrypted_upload_bytes.sum,
        encrypted_upload_bytes_max = snapshot.encrypted_upload_bytes.max,
        encrypted_upload_bytes_cumulative_buckets = ?snapshot.encrypted_upload_bytes.cumulative_buckets,
        encrypted_upload_attempted_bytes_total = snapshot.encrypted_upload_attempted_bytes_total,
        encrypted_download_bytes_count = snapshot.encrypted_download_bytes.count,
        encrypted_download_bytes_total = snapshot.encrypted_download_bytes.sum,
        encrypted_download_bytes_max = snapshot.encrypted_download_bytes.max,
        encrypted_download_bytes_cumulative_buckets = ?snapshot.encrypted_download_bytes.cumulative_buckets,
        save_attempts_total = snapshot.save_attempts_total,
        save_completed_total = snapshot.save_completed_total,
        save_failed_total = snapshot.save_failed_total,
        save_skipped_total = snapshot.save_skipped_total,
        save_latency_us_count = snapshot.save_latency_us.count,
        save_latency_us_sum = snapshot.save_latency_us.sum,
        save_latency_us_max = snapshot.save_latency_us.max,
        save_latency_us_bucket_upper_bounds = ?LATENCY_US_BUCKET_UPPER_BOUNDS,
        save_latency_us_cumulative_buckets = ?snapshot.save_latency_us.cumulative_buckets,
        write_amplification_ppm_count = snapshot.write_amplification_ppm.count,
        write_amplification_ppm_sum = snapshot.write_amplification_ppm.sum,
        write_amplification_ppm_max = snapshot.write_amplification_ppm.max,
        write_amplification_ppm_bucket_upper_bounds = ?AMPLIFICATION_PPM_BUCKET_UPPER_BOUNDS,
        write_amplification_ppm_cumulative_buckets = ?snapshot.write_amplification_ppm.cumulative_buckets,
        "aggregate archive storage metrics"
    );
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
    salient_ocr_text TEXT, -- bounded chrome-reduced projection; ocr_text remains lossless
    url          TEXT,
    ocr_status   TEXT NOT NULL DEFAULT 'done',
    image_hash   TEXT,
    is_duplicate INTEGER NOT NULL DEFAULT 0,
    source_key   TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    display_id INTEGER,
    capture_context_version INTEGER,
    capture_status TEXT,
    primary_bundle_id TEXT,
    primary_window_id INTEGER,
    capture_group_id TEXT,
    visible_windows_json TEXT,
    visible_windows_truncated INTEGER NOT NULL DEFAULT 0,
    visual_signals_json TEXT,
    semantic_context_hash TEXT,
    browser_snapshot_source_key TEXT,
    duplicate_of_id INTEGER REFERENCES screenshots(id) ON DELETE SET NULL,
    visible_until TEXT,
    dedupe_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS browser_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key TEXT NOT NULL UNIQUE,
    captured_at TEXT NOT NULL,
    browser_bundle_id TEXT NOT NULL,
    browser_name TEXT NOT NULL,
    permission_status TEXT NOT NULL,
    active_window_index INTEGER,
    active_tab_index INTEGER,
    reported_tab_count INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS browser_tabs (
    browser_snapshot_id INTEGER NOT NULL REFERENCES browser_snapshots(id) ON DELETE CASCADE,
    window_index INTEGER NOT NULL,
    tab_index INTEGER NOT NULL,
    title TEXT,
    url TEXT,
    url_scheme TEXT,
    is_active INTEGER NOT NULL,
    is_loading INTEGER,
    PRIMARY KEY (browser_snapshot_id, window_index, tab_index)
);
CREATE TABLE IF NOT EXISTS screen_observation_jobs (
    screenshot_id INTEGER PRIMARY KEY REFERENCES screenshots(id) ON DELETE CASCADE,
    input_revision TEXT NOT NULL,
    observation_version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','processing','retry_wait','ready','fallback')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS screen_observations (
    screenshot_id INTEGER PRIMARY KEY REFERENCES screenshots(id) ON DELETE CASCADE,
    input_revision TEXT NOT NULL,
    observation_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ready','fallback')),
    generation_method TEXT NOT NULL,
    literal_description TEXT NOT NULL,
    screen_state TEXT NOT NULL,
    content_type TEXT NOT NULL,
    visible_text_summary TEXT,
    notable_items_json TEXT NOT NULL DEFAULT '[]',
    model_name TEXT,
    prompt_version INTEGER NOT NULL,
    completed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS episode_screen_interpretations (
    episode_id INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
    screenshot_id INTEGER NOT NULL REFERENCES screenshots(id) ON DELETE CASCADE,
    episode_revision TEXT NOT NULL,
    interpretation_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ready','fallback')),
    activity_summary TEXT,
    relevance_level INTEGER NOT NULL CHECK (relevance_level BETWEEN 0 AND 3),
    relevance_reason TEXT,
    milestone_type TEXT NOT NULL DEFAULT 'none',
    base_score INTEGER NOT NULL DEFAULT 0,
    key_rank INTEGER,
    is_key_screen INTEGER NOT NULL DEFAULT 0,
    semantic_group TEXT,
    model_name TEXT,
    prompt_version INTEGER NOT NULL,
    completed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (episode_id, screenshot_id)
);
CREATE TABLE IF NOT EXISTS episode_screen_interpretation_jobs (
    episode_id INTEGER PRIMARY KEY REFERENCES episodes(id) ON DELETE CASCADE,
    episode_revision TEXT NOT NULL,
    interpretation_version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','processing','retry_wait','ready','fallback')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
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
    -- ADR-0009: summarizer-assigned visibility tier. `none` is hidden from
    -- normal episode browse/search; `low` and `normal` remain visible.
    substance     TEXT NOT NULL DEFAULT 'normal'
                  CHECK (substance IN ('none','low','normal')),
    visual_evidence TEXT NOT NULL DEFAULT 'none'
                  CHECK (visual_evidence IN ('none','useful')),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at    TEXT,
    finalized_at  TEXT,
    finalization_version INTEGER,
    finalization_status TEXT NOT NULL DEFAULT 'pending_horizon',
    finalization_error TEXT,
    finalization_attempted_at TEXT,
    finalization_attempt_count INTEGER NOT NULL DEFAULT 0,
    finalization_next_attempt_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_episodes_started_at ON episodes(started_at);

-- Per-user, content-side task markers. Kept in the encrypted user DB so
-- one-off data passes follow the data through cache eviction and redeploys.
CREATE TABLE IF NOT EXISTS app_metadata (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

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

-- Opaque random object mapping for screenshot evidence (ADR-0010).
CREATE TABLE IF NOT EXISTS screenshot_images (
    id            TEXT PRIMARY KEY,
    screenshot_id INTEGER NOT NULL REFERENCES screenshots(id) ON DELETE CASCADE,
    episode_id    INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
    source_key    TEXT NOT NULL UNIQUE,
    captured_at   TEXT NOT NULL,
    object_key    TEXT NOT NULL UNIQUE,
    mime_type     TEXT NOT NULL CHECK (mime_type = 'image/jpeg'),
    width         INTEGER NOT NULL,
    height        INTEGER NOT NULL,
    byte_length   INTEGER NOT NULL CHECK (byte_length <= 153600),
    sha256        TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_screenshot_images_episode_id ON screenshot_images(episode_id);

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
-- Scoped to the indexed column (ADR-0006 §F.7): bulk speaker relabels
-- must not delete-and-reinsert unchanged text for every touched row.
CREATE TRIGGER IF NOT EXISTS utterances_update_fts AFTER UPDATE OF text ON utterances BEGIN
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
CREATE TRIGGER IF NOT EXISTS screenshots_update_fts AFTER UPDATE OF ocr_text ON screenshots BEGIN
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
-- Scoped (ADR-0006 §F.7): participants-only patches (§E.2) must not
-- re-index title/summary/minutes.
CREATE TRIGGER IF NOT EXISTS episodes_update_fts AFTER UPDATE OF title, summary, minutes_text ON episodes BEGIN
    INSERT INTO episodes_fts(episodes_fts, rowid, title, summary, minutes_text)
        VALUES ('delete', old.id, old.title, old.summary, old.minutes_text);
    INSERT INTO episodes_fts(rowid, title, summary, minutes_text)
        VALUES (new.id, new.title, new.summary, new.minutes_text);
END;

-- Canonical structured brief storage
CREATE TABLE IF NOT EXISTS episode_final_briefs (
    episode_id        INTEGER PRIMARY KEY REFERENCES episodes(id) ON DELETE CASCADE,
    overview          TEXT NOT NULL,
    decisions         TEXT NOT NULL, -- JSON array
    action_items      TEXT NOT NULL, -- JSON array
    important_links   TEXT NOT NULL, -- JSON array
    open_questions    TEXT NOT NULL, -- JSON array
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Per-destination signed-webhook outbox. Endpoint URLs and signing secrets
-- remain in the encrypted control DB; content blobs keep only opaque ids.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    episode_id       INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
    subscription_id  TEXT NOT NULL,
    delivery_version INTEGER NOT NULL,
    event_id          TEXT NOT NULL UNIQUE,
    state             TEXT NOT NULL CHECK (state IN ('pending', 'sent', 'retry', 'cancelled', 'failed')),
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   TEXT, -- ISO 8601
    response_status   INTEGER,
    error_code        TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (episode_id, subscription_id, delivery_version)
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx
    ON webhook_deliveries(state, next_attempt_at);

CREATE TABLE IF NOT EXISTS email_deliveries (
    episode_id          INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
    delivery_version    INTEGER NOT NULL,
    delivery_id         TEXT NOT NULL UNIQUE,
    include_content     INTEGER NOT NULL,
    state               TEXT NOT NULL CHECK ( state IN ('pending', 'retry', 'accepted', 'cancelled', 'failed') ),
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    next_attempt_at     TEXT NOT NULL,
    provider_message_id TEXT,
    response_status     INTEGER,
    error_code          TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (episode_id, delivery_version)
);
CREATE INDEX IF NOT EXISTS email_deliveries_due_idx
    ON email_deliveries(state, next_attempt_at);

-- Device sync watermarks per modality
CREATE TABLE IF NOT EXISTS device_watermarks (
    device_id    TEXT NOT NULL,
    modality     TEXT NOT NULL CHECK (modality IN ('audio','screen')),
    watermark_at TEXT NOT NULL, -- ISO 8601
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (device_id, modality)
);
"#;

/// Schema-upgrade statements that are safe to replay on every open.
///
/// `ALTER TABLE … ADD COLUMN` returns `SQLITE_ERROR` ("duplicate column name")
/// if the column already exists; we swallow that specific error so existing
/// blobs created with the old schema self-upgrade transparently.
///
/// `CREATE UNIQUE INDEX IF NOT EXISTS` is truly idempotent.
fn run_migrations(conn: &Connection) -> Result<()> {
    crate::cp::mcp_projection::init_projection_schema(conn)?;
    crate::cp::media::init_schema(conn)?;
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

    // Lossy projection for summaries/UI; ocr_text remains lossless and is the
    // only screenshot text indexed by FTS.
    if let Err(e) = conn.execute_batch("ALTER TABLE screenshots ADD COLUMN salient_ocr_text TEXT;")
    {
        let msg = e.to_string();
        if !msg.contains("duplicate column name") {
            return Err(e.into());
        }
    }

    for definition in [
        "display_id INTEGER",
        "capture_context_version INTEGER",
        "capture_status TEXT",
        "primary_bundle_id TEXT",
        "primary_window_id INTEGER",
        "capture_group_id TEXT",
        "visible_windows_json TEXT",
        "visible_windows_truncated INTEGER NOT NULL DEFAULT 0",
        "visual_signals_json TEXT",
        "semantic_context_hash TEXT",
        "browser_snapshot_source_key TEXT",
        "duplicate_of_id INTEGER REFERENCES screenshots(id) ON DELETE SET NULL",
        "visible_until TEXT",
        "dedupe_version INTEGER NOT NULL DEFAULT 1",
    ] {
        if let Err(error) =
            conn.execute_batch(&format!("ALTER TABLE screenshots ADD COLUMN {definition};"))
        {
            if !error.to_string().contains("duplicate column name") {
                return Err(error.into());
            }
        }
    }
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS browser_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_key TEXT NOT NULL UNIQUE,
            captured_at TEXT NOT NULL,
            browser_bundle_id TEXT NOT NULL,
            browser_name TEXT NOT NULL,
            permission_status TEXT NOT NULL,
            active_window_index INTEGER,
            active_tab_index INTEGER,
            reported_tab_count INTEGER NOT NULL DEFAULT 0,
            truncated INTEGER NOT NULL DEFAULT 0,
            content_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS browser_tabs (
            browser_snapshot_id INTEGER NOT NULL REFERENCES browser_snapshots(id) ON DELETE CASCADE,
            window_index INTEGER NOT NULL,
            tab_index INTEGER NOT NULL,
            title TEXT,
            url TEXT,
            url_scheme TEXT,
            is_active INTEGER NOT NULL,
            is_loading INTEGER,
            PRIMARY KEY (browser_snapshot_id, window_index, tab_index)
        );
        CREATE TABLE IF NOT EXISTS screen_observation_jobs (
            screenshot_id INTEGER PRIMARY KEY REFERENCES screenshots(id) ON DELETE CASCADE,
            input_revision TEXT NOT NULL,
            observation_version INTEGER NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('pending','processing','retry_wait','ready','fallback')),
            attempt_count INTEGER NOT NULL DEFAULT 0,
            error_code TEXT,
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS screen_observations (
            screenshot_id INTEGER PRIMARY KEY REFERENCES screenshots(id) ON DELETE CASCADE,
            input_revision TEXT NOT NULL,
            observation_version INTEGER NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('ready','fallback')),
            generation_method TEXT NOT NULL,
            literal_description TEXT NOT NULL,
            screen_state TEXT NOT NULL,
            content_type TEXT NOT NULL,
            visible_text_summary TEXT,
            notable_items_json TEXT NOT NULL DEFAULT '[]',
            model_name TEXT,
            prompt_version INTEGER NOT NULL,
            completed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_observation_jobs_state ON screen_observation_jobs(state, screenshot_id);
        "#,
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
                substance     TEXT NOT NULL DEFAULT 'normal'
                              CHECK (substance IN ('none','low','normal')),
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
        // ADR-0009: legacy rows conservatively remain visible until the
        // one-time summarizer backfill classifies them.
        "ALTER TABLE episodes ADD COLUMN substance TEXT NOT NULL DEFAULT 'normal' CHECK (substance IN ('none','low','normal'));",
        // ADR-0010: visual evidence eligibility
        "ALTER TABLE episodes ADD COLUMN visual_evidence TEXT NOT NULL DEFAULT 'none' CHECK (visual_evidence IN ('none','useful'));",
    ] {
        if let Err(e) = conn.execute_batch(col_def) {
            let msg = e.to_string();
            if !msg.contains("duplicate column name") {
                return Err(e.into());
            }
        }
    }

    // ADR-0009 one-off backfill marker. This table is deliberately separate
    // from the control DB: it belongs to the encrypted per-user content blob.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS app_metadata (
             key         TEXT PRIMARY KEY,
             value       TEXT NOT NULL,
             updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
         );",
    )?;

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
            CREATE TRIGGER episodes_update_fts AFTER UPDATE OF title, summary, minutes_text ON episodes BEGIN
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

    // ── FTS update-trigger scoping (ADR-0006 §F.7) ─────────────────────────────
    //
    // Blobs migrated before this pass carry UPDATE triggers that fire on ANY
    // column update. A bulk speaker relabel (thousands of rows, only
    // speaker_label changes) would then delete-and-reinsert the unchanged
    // indexed text for every row — pure FTS write churn. Same for
    // participants-only episode patches (§E.2). Re-point the update triggers
    // to `AFTER UPDATE OF <indexed column(s)>`; detection is the absence of
    // "UPDATE OF" in the trigger SQL. Trigger-only swap; content unchanged,
    // no rebuild. Runs AFTER the blocks below so their (scoped) recreations
    // aren't double-handled on fresh migrations.
    let scope_update_triggers = |conn: &Connection| -> Result<()> {
        let unscoped: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' \
             AND name IN ('utterances_update_fts','screenshots_update_fts','episodes_update_fts') \
             AND sql NOT LIKE '%UPDATE OF%'",
            [],
            |r| r.get(0),
        )?;
        if unscoped > 0 {
            conn.execute_batch(
                r#"
                DROP TRIGGER IF EXISTS utterances_update_fts;
                DROP TRIGGER IF EXISTS screenshots_update_fts;
                DROP TRIGGER IF EXISTS episodes_update_fts;
                CREATE TRIGGER utterances_update_fts AFTER UPDATE OF text ON utterances BEGIN
                    INSERT INTO utterances_fts(utterances_fts, rowid, text) VALUES ('delete', old.id, old.text);
                    INSERT INTO utterances_fts(rowid, text) VALUES (new.id, new.text);
                END;
                CREATE TRIGGER screenshots_update_fts AFTER UPDATE OF ocr_text ON screenshots BEGIN
                    INSERT INTO screenshots_fts(screenshots_fts, rowid, ocr_text) VALUES ('delete', old.id, old.ocr_text);
                    INSERT INTO screenshots_fts(rowid, ocr_text) VALUES (new.id, new.ocr_text);
                END;
                CREATE TRIGGER episodes_update_fts AFTER UPDATE OF title, summary, minutes_text ON episodes BEGIN
                    INSERT INTO episodes_fts(episodes_fts, rowid, title, summary, minutes_text)
                        VALUES ('delete', old.id, old.title, old.summary, old.minutes_text);
                    INSERT INTO episodes_fts(rowid, title, summary, minutes_text)
                        VALUES (new.id, new.title, new.summary, new.minutes_text);
                END;
                "#,
            )?;
        }
        Ok(())
    };

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
            CREATE TRIGGER utterances_update_fts AFTER UPDATE OF text ON utterances BEGIN
                INSERT INTO utterances_fts(utterances_fts, rowid, text) VALUES ('delete', old.id, old.text);
                INSERT INTO utterances_fts(rowid, text) VALUES (new.id, new.text);
            END;
            CREATE TRIGGER screenshots_delete_fts AFTER DELETE ON screenshots BEGIN
                INSERT INTO screenshots_fts(screenshots_fts, rowid, ocr_text) VALUES ('delete', old.id, old.ocr_text);
            END;
            CREATE TRIGGER screenshots_update_fts AFTER UPDATE OF ocr_text ON screenshots BEGIN
                INSERT INTO screenshots_fts(screenshots_fts, rowid, ocr_text) VALUES ('delete', old.id, old.ocr_text);
                INSERT INTO screenshots_fts(rowid, ocr_text) VALUES (new.id, new.ocr_text);
            END;
            "#,
        )?;
    }

    // Last: scope any remaining unscoped update triggers (§F.7). Runs after
    // every block that may have (re)created triggers, so one pass suffices
    // for blobs at any prior migration level.
    scope_update_triggers(conn)?;

    // ADR-0011: Add finalized_at and finalization_version columns to episodes table
    if let Err(e) = conn.execute_batch("ALTER TABLE episodes ADD COLUMN finalized_at TEXT;") {
        let msg = e.to_string();
        if !msg.contains("duplicate column name") {
            return Err(e.into());
        }
    }
    if let Err(e) = conn
        .execute_batch("ALTER TABLE episodes ADD COLUMN finalization_version INTEGER DEFAULT 1;")
    {
        let msg = e.to_string();
        if !msg.contains("duplicate column name") {
            return Err(e.into());
        }
    }
    for col_def in &[
        "ALTER TABLE episodes ADD COLUMN finalization_status TEXT NOT NULL DEFAULT 'pending_horizon';",
        "ALTER TABLE episodes ADD COLUMN finalization_error TEXT;",
        "ALTER TABLE episodes ADD COLUMN finalization_attempted_at TEXT;",
        "ALTER TABLE episodes ADD COLUMN finalization_attempt_count INTEGER NOT NULL DEFAULT 0;",
        "ALTER TABLE episodes ADD COLUMN finalization_next_attempt_at TEXT;",
    ] {
        if let Err(e) = conn.execute_batch(col_def) {
            let msg = e.to_string();
            if !msg.contains("duplicate column name") {
                return Err(e.into());
            }
        }
    }
    // Historical briefs remain readable but are never automatically sent back
    // to a paid model merely because the analysis schema changed. A scoped
    // user/operator action can still request regeneration explicitly.
    conn.execute(
        "UPDATE episodes
         SET finalization_status = 'complete',
             finalization_error = NULL,
             finalization_attempt_count = 0,
             finalization_next_attempt_at = NULL
         WHERE finalized_at IS NOT NULL
           AND (finalization_status IS NOT 'complete'
                OR finalization_error IS NOT NULL
                OR finalization_attempt_count <> 0
                OR finalization_next_attempt_at IS NOT NULL)",
        [],
    )?;
    // Quarantine the pre-guard retry loop. Its attempt count was not persisted,
    // so treating it as fresh would immediately repeat the production incident.
    conn.execute(
        "UPDATE episodes
         SET finalization_status = 'failed_terminal',
             finalization_error = 'legacy unbounded retry quarantined; retry explicitly',
             finalization_attempt_count = 3,
             finalization_next_attempt_at = NULL
         WHERE finalized_at IS NULL
           AND finalization_status IN ('retry_model', 'processing')",
        [],
    )?;

    // ADR-0011/0012: canonical briefs, generic webhook outbox, and watermarks.
    // The Gmail-specific table is deliberately dropped so old message ids and
    // error details do not linger after the feature and its credentials are removed.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS episode_final_briefs (
            episode_id        INTEGER PRIMARY KEY REFERENCES episodes(id) ON DELETE CASCADE,
            overview          TEXT NOT NULL,
            decisions         TEXT NOT NULL,
            action_items      TEXT NOT NULL,
            important_links   TEXT NOT NULL,
            open_questions    TEXT NOT NULL,
            created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        DROP TABLE IF EXISTS episode_deliveries;
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            episode_id       INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
            subscription_id  TEXT NOT NULL,
            delivery_version INTEGER NOT NULL,
            event_id          TEXT NOT NULL UNIQUE,
            state             TEXT NOT NULL CHECK (state IN ('pending', 'sent', 'retry', 'cancelled', 'failed')),
            attempt_count     INTEGER NOT NULL DEFAULT 0,
            next_attempt_at   TEXT,
            response_status   INTEGER,
            error_code        TEXT,
            created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            PRIMARY KEY (episode_id, subscription_id, delivery_version)
        );
        CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx
            ON webhook_deliveries(state, next_attempt_at);
        CREATE TABLE IF NOT EXISTS email_deliveries (
            episode_id          INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
            delivery_version    INTEGER NOT NULL,
            delivery_id         TEXT NOT NULL UNIQUE,
            include_content     INTEGER NOT NULL,
            state               TEXT NOT NULL CHECK ( state IN ('pending', 'retry', 'accepted', 'cancelled', 'failed') ),
            attempt_count       INTEGER NOT NULL DEFAULT 0,
            next_attempt_at     TEXT NOT NULL,
            provider_message_id TEXT,
            response_status     INTEGER,
            error_code          TEXT,
            created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            PRIMARY KEY (episode_id, delivery_version)
        );
        CREATE INDEX IF NOT EXISTS email_deliveries_due_idx
            ON email_deliveries(state, next_attempt_at);
        CREATE TABLE IF NOT EXISTS device_watermarks (
            device_id    TEXT NOT NULL,
            modality     TEXT NOT NULL CHECK (modality IN ('audio','screen')),
            watermark_at TEXT NOT NULL,
            updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            PRIMARY KEY (device_id, modality)
        );
        CREATE TABLE IF NOT EXISTS episode_screen_interpretations (
            episode_id INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
            screenshot_id INTEGER NOT NULL REFERENCES screenshots(id) ON DELETE CASCADE,
            episode_revision TEXT NOT NULL DEFAULT '',
            interpretation_version INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'fallback' CHECK (status IN ('ready','fallback')),
            activity_summary TEXT,
            relevance_level INTEGER NOT NULL CHECK (relevance_level BETWEEN 0 AND 3),
            relevance_reason TEXT,
            milestone_type TEXT NOT NULL DEFAULT 'none',
            base_score INTEGER NOT NULL DEFAULT 0,
            key_rank INTEGER,
            is_key_screen INTEGER NOT NULL DEFAULT 0,
            semantic_group TEXT,
            model_name TEXT,
            prompt_version INTEGER NOT NULL DEFAULT 1,
            completed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            PRIMARY KEY (episode_id, screenshot_id)
        );
        CREATE TABLE IF NOT EXISTS episode_screen_interpretation_jobs (
            episode_id INTEGER PRIMARY KEY REFERENCES episodes(id) ON DELETE CASCADE,
            episode_revision TEXT NOT NULL,
            interpretation_version INTEGER NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('pending','processing','retry_wait','ready','fallback')),
            attempt_count INTEGER NOT NULL DEFAULT 0,
            error_code TEXT,
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_episode_screen_rank
            ON episode_screen_interpretations(episode_id, is_key_screen, key_rank);
        "#,
    )?;

    for definition in [
        "episode_revision TEXT NOT NULL DEFAULT ''",
        "interpretation_version INTEGER NOT NULL DEFAULT 1",
        "status TEXT NOT NULL DEFAULT 'fallback' CHECK (status IN ('ready','fallback'))",
        "milestone_type TEXT NOT NULL DEFAULT 'none'",
        "base_score INTEGER NOT NULL DEFAULT 0",
        "model_name TEXT",
        "prompt_version INTEGER NOT NULL DEFAULT 1",
        "completed_at TEXT",
    ] {
        if let Err(error) = conn.execute_batch(&format!(
            "ALTER TABLE episode_screen_interpretations ADD COLUMN {definition};"
        )) {
            if !error.to_string().contains("duplicate column name") {
                return Err(error.into());
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DatabaseMutationFingerprint {
    total_changes: u64,
    schema_version: i64,
    user_version: i64,
    application_id: i64,
}

fn database_mutation_fingerprint(conn: &Connection) -> Result<DatabaseMutationFingerprint> {
    Ok(DatabaseMutationFingerprint {
        // SQLite total_changes includes row changes performed by triggers.
        total_changes: conn.total_changes(),
        schema_version: conn.query_row("PRAGMA schema_version", [], |row| row.get(0))?,
        user_version: conn.query_row("PRAGMA user_version", [], |row| row.get(0))?,
        application_id: conn.query_row("PRAGMA application_id", [], |row| row.get(0))?,
    })
}

fn open_db(path: &PathBuf) -> Result<(Connection, bool)> {
    // Register the sqlite-vec extension globally before any connection opens.
    // This is idempotent (Once guard) and thread-safe.
    init_vec_extension();
    let conn = Connection::open(path)?;
    let before = database_mutation_fingerprint(&conn)?;
    conn.execute_batch(SCHEMA_SQL)?;
    run_migrations(&conn)?;
    let migrated = database_mutation_fingerprint(&conn)? != before;
    Ok((conn, migrated))
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
    let _ = encrypt_bound_blob(dek, &bytes, b"empty-db-self-test")?; // smoke-test the key
    Ok(bytes)
}

// ── GCS trait (seam for testing) ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsObjectMetadata {
    pub generation: i64,
    pub size: u64,
    /// Provider-calculated CRC32C in GCS's base64 representation.
    pub crc32c: String,
    pub md5_hash: Option<String>,
    pub wrapped_dek_b64: String,
    pub legacy_recovery: Option<LegacyRecoveryBinding>,
}

/// Provider-stored protocol marker written atomically with a daily recovery
/// rewrite. Its source identity and integrity fields describe the immutable
/// generation from which the destination bytes were copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyRecoveryBinding {
    pub format_version: u8,
    pub source_object: String,
    pub source_generation: i64,
    pub source_size: u64,
    pub source_crc32c: String,
}

#[derive(Debug)]
pub struct GcsGetResponse {
    pub ciphertext: Vec<u8>,
    pub wrapped_dek_b64: String,
    pub generation: i64,
}

/// One concrete GCS object generation.  Names and generations are routing
/// metadata only; callers must never log them because names can carry user data.
#[derive(Clone, PartialEq, Eq)]
pub struct GcsObjectVersion {
    pub name: String,
    pub generation: i64,
    pub size: u64,
}

#[derive(Clone, Default)]
pub struct GcsListVersionsResponse {
    pub versions: Vec<GcsObjectVersion>,
    pub next_page_token: Option<String>,
}

/// Result of a generation-pinned, create-only recovery copy.  The metadata is
/// intentionally content-free and is sufficient for export/deletion inventory
/// code to identify an exact checkpoint generation without reading ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsGenerationCopy {
    pub source: GcsObjectMetadata,
    pub destination: GcsObjectMetadata,
    /// False means this UTC day's immutable destination already existed.
    pub created: bool,
}

/// Abstraction over GCS so unit tests can inject an in-memory fake.
#[async_trait::async_trait]
pub trait GcsClient: Send + Sync {
    async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse>;
    /// Fetches one exact live/noncurrent generation, including its historical
    /// wrapped-DEK metadata.
    async fn get_object_generation(
        &self,
        object_name: &str,
        generation: i64,
    ) -> Result<GcsGetResponse>;
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
    /// Copy exactly `source_generation` to a destination that must not already
    /// exist. If a prior attempt may have succeeded, implementations must read
    /// and return that destination instead of copying a newer source version.
    async fn copy_generation_if_absent(
        &self,
        source_name: &str,
        source_generation: i64,
        destination_name: &str,
    ) -> Result<GcsGenerationCopy>;
    async fn delete_object(&self, object_name: &str) -> Result<()>;
    /// Lists live and noncurrent generations under an exact caller-owned
    /// prefix/name. `page_token` is an opaque GCS cursor.
    async fn list_object_versions(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse>;
    /// Deletes exactly one generation. Not-found is success so deletion
    /// inventories can be retried after partial completion.
    async fn delete_object_generation(&self, object_name: &str, generation: i64) -> Result<()>;
    /// Lists soft-deleted objects separately from live/noncurrent versions.
    /// Callers must not try to delete these: GCS retains them until its
    /// immutable `hardDeleteTime`.
    async fn list_soft_deleted_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse>;
}

const GCS_LIST_PAGE_SIZE: usize = 1_000;
const MAX_GCS_LIST_PAGES: usize = 1_000_000;
/// Historical Phase-0 inventory still decrypts one whole legacy SQLite
/// snapshot. Reject larger generations before download until the streaming
/// archive converter replaces this compatibility path.
const MAX_LEGACY_DELETION_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

fn soft_deleted_account_objects_error() -> EnclaveError {
    EnclaveError::Conflict(
        "GCS soft-deleted account objects remain until their provider hard-delete deadline".into(),
    )
}

fn legacy_inventory_incomplete_error() -> EnclaveError {
    EnclaveError::Conflict(
        "a retained legacy database generation could not be inventoried; deletion is incomplete"
            .into(),
    )
}

/// Deletes at most one provider page at a time, then restarts at the first
/// page. Restarting avoids skipped generations when deleting changes the
/// meaning of a continuation token, while keeping memory bounded by one page.
async fn delete_matching_object_versions(
    gcs: &dyn GcsClient,
    selector: &str,
    exact_name: bool,
) -> Result<()> {
    let mut page_token = None;
    for _ in 0..MAX_GCS_LIST_PAGES {
        let page = gcs
            .list_object_versions(selector, page_token.as_deref())
            .await?;
        let matching = page
            .versions
            .into_iter()
            .filter(|version| {
                if exact_name {
                    version.name == selector
                } else {
                    version.name.starts_with(selector)
                }
            })
            .collect::<Vec<_>>();
        if !matching.is_empty() {
            for version in matching {
                gcs.delete_object_generation(&version.name, version.generation)
                    .await?;
            }
            page_token = None;
            continue;
        }
        match page.next_page_token {
            Some(next) if page_token.as_deref() != Some(next.as_str()) => page_token = Some(next),
            Some(_) => {
                return Err(EnclaveError::Gcs(
                    "GCS version listing repeated a page cursor".into(),
                ))
            }
            None => return Ok(()),
        }
    }
    Err(EnclaveError::Gcs(
        "GCS version listing exceeded the bounded page limit".into(),
    ))
}

/// Streams soft-deleted inventory and returns as soon as one account-owned
/// object is found. No content inventory is accumulated in enclave memory.
async fn has_matching_soft_deleted_object(
    gcs: &dyn GcsClient,
    selector: &str,
    exact_name: bool,
) -> Result<bool> {
    let mut page_token = None;
    for _ in 0..MAX_GCS_LIST_PAGES {
        let page = gcs
            .list_soft_deleted_objects(selector, page_token.as_deref())
            .await?;
        if page.versions.into_iter().any(|version| {
            if exact_name {
                version.name == selector
            } else {
                version.name.starts_with(selector)
            }
        }) {
            return Ok(true);
        }
        match page.next_page_token {
            Some(next) if page_token.as_deref() != Some(next.as_str()) => page_token = Some(next),
            Some(_) => {
                return Err(EnclaveError::Gcs(
                    "GCS soft-delete listing repeated a page cursor".into(),
                ))
            }
            None => return Ok(false),
        }
    }
    Err(EnclaveError::Gcs(
        "GCS soft-delete listing exceeded the bounded page limit".into(),
    ))
}

// ── Production GCS client ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GcsApiObjectMetadata {
    generation: String,
    size: String,
    #[serde(rename = "crc32c")]
    crc32c: Option<String>,
    #[serde(rename = "md5Hash")]
    md5_hash: Option<String>,
    metadata: Option<GcsCustomMetadata>,
}

#[derive(Deserialize)]
struct GcsListVersionsPage {
    #[serde(default)]
    items: Vec<GcsVersionMetadata>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct GcsErrorEnvelope {
    error: GcsErrorBody,
}

#[derive(Deserialize)]
struct GcsErrorBody {
    code: u16,
    #[serde(default)]
    errors: Vec<GcsErrorDetail>,
}

#[derive(Deserialize)]
struct GcsErrorDetail {
    reason: String,
}

#[derive(Deserialize)]
struct GcsVersionMetadata {
    name: String,
    generation: String,
    size: String,
}

fn decode_gcs_versions_page(
    body: &[u8],
    generation_label: &str,
) -> Result<GcsListVersionsResponse> {
    let page: GcsListVersionsPage = serde_json::from_slice(body)?;
    let versions = page
        .items
        .into_iter()
        .map(|item| {
            Ok(GcsObjectVersion {
                name: item.name,
                generation: item.generation.parse().map_err(|_| {
                    EnclaveError::Gcs(format!("invalid {generation_label} generation"))
                })?,
                size: item
                    .size
                    .parse()
                    .map_err(|_| EnclaveError::Gcs("invalid listed object size".into()))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(GcsListVersionsResponse {
        versions,
        next_page_token: page.next_page_token,
    })
}

fn decode_soft_deleted_list_response(
    status: reqwest::StatusCode,
    body: &[u8],
    first_page: bool,
) -> Result<GcsListVersionsResponse> {
    if status.is_success() {
        return decode_gcs_versions_page(body, "soft-deleted");
    }
    // With this fixed request shape, the JSON API documents first-page
    // invalidArgument as the response when the bucket has no soft-delete
    // policy. Never apply the exception to continuation requests or any other
    // status/reason, since those may indicate a bad cursor or request bug.
    let policy_disabled = status == reqwest::StatusCode::BAD_REQUEST
        && first_page
        && serde_json::from_slice::<GcsErrorEnvelope>(body).is_ok_and(|envelope| {
            envelope.error.code == 400
                && !envelope.error.errors.is_empty()
                && envelope
                    .error
                    .errors
                    .iter()
                    .all(|detail| detail.reason == "invalidArgument")
        });
    if policy_disabled {
        return Ok(GcsListVersionsResponse::default());
    }
    Err(EnclaveError::Gcs(format!(
        "GCS soft-delete listing failed with HTTP {}",
        status.as_u16()
    )))
}

impl GcsApiObjectMetadata {
    fn into_public(self) -> Result<GcsObjectMetadata> {
        let custom = self
            .metadata
            .ok_or_else(|| EnclaveError::Gcs("missing GCS custom metadata".into()))?;
        let wrapped_dek_b64 = custom
            .wrapped_dek
            .clone()
            .ok_or_else(|| EnclaveError::Gcs("missing wrapped DEK in object metadata".into()))?;
        let legacy_recovery = custom.legacy_recovery_binding()?;
        Ok(GcsObjectMetadata {
            generation: self
                .generation
                .parse()
                .map_err(|_| EnclaveError::Gcs("invalid generation".into()))?,
            size: self
                .size
                .parse()
                .map_err(|_| EnclaveError::Gcs("invalid GCS object size".into()))?,
            crc32c: self
                .crc32c
                .ok_or_else(|| EnclaveError::Gcs("missing GCS CRC32C".into()))?,
            md5_hash: self.md5_hash,
            wrapped_dek_b64,
            legacy_recovery,
        })
    }
}

#[derive(Debug, Deserialize)]
struct GcsCustomMetadata {
    #[serde(rename = "x-kioku-wrapped-dek")]
    wrapped_dek: Option<String>,
    #[serde(rename = "x-kioku-legacy-recovery-format")]
    legacy_recovery_format: Option<String>,
    #[serde(rename = "x-kioku-legacy-source-object")]
    legacy_source_object: Option<String>,
    #[serde(rename = "x-kioku-legacy-source-generation")]
    legacy_source_generation: Option<String>,
    #[serde(rename = "x-kioku-legacy-source-size")]
    legacy_source_size: Option<String>,
    #[serde(rename = "x-kioku-legacy-source-crc32c")]
    legacy_source_crc32c: Option<String>,
}

impl GcsCustomMetadata {
    fn legacy_recovery_binding(&self) -> Result<Option<LegacyRecoveryBinding>> {
        let fields_present = [
            self.legacy_recovery_format.is_some(),
            self.legacy_source_object.is_some(),
            self.legacy_source_generation.is_some(),
            self.legacy_source_size.is_some(),
            self.legacy_source_crc32c.is_some(),
        ];
        if fields_present.iter().all(|present| !present) {
            return Ok(None);
        }
        if !fields_present.iter().all(|present| *present) {
            return Err(EnclaveError::Gcs(
                "incomplete legacy recovery checkpoint metadata".into(),
            ));
        }
        Ok(Some(LegacyRecoveryBinding {
            format_version: self
                .legacy_recovery_format
                .as_deref()
                .unwrap_or_default()
                .parse()
                .map_err(|_| EnclaveError::Gcs("invalid legacy recovery format".into()))?,
            source_object: self.legacy_source_object.clone().unwrap_or_default(),
            source_generation: self
                .legacy_source_generation
                .as_deref()
                .unwrap_or_default()
                .parse()
                .map_err(|_| {
                    EnclaveError::Gcs("invalid legacy recovery source generation".into())
                })?,
            source_size: self
                .legacy_source_size
                .as_deref()
                .unwrap_or_default()
                .parse()
                .map_err(|_| EnclaveError::Gcs("invalid legacy recovery source size".into()))?,
            source_crc32c: self.legacy_source_crc32c.clone().unwrap_or_default(),
        }))
    }
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
            http: gcs_http_client(),
            bucket,
        })
    }

    pub fn from_bucket(bucket: String) -> Self {
        Self {
            http: gcs_http_client(),
            bucket,
        }
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
            .timeout(Duration::from_secs(3))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(tok.access_token)
    }
    async fn object_metadata(
        &self,
        object_name: &str,
        generation: Option<i64>,
    ) -> Result<GcsObjectMetadata> {
        let token = self.access_token().await?;
        let encoded = urlencoding::encode(object_name);
        let generation_query = generation
            .map(|g| format!("?generation={g}"))
            .unwrap_or_default();
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}{}",
            self.bucket, encoded, generation_query
        );
        let response = self.http.get(url).bearer_auth(token).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(EnclaveError::NotFound);
        }
        response
            .error_for_status()?
            .json::<GcsApiObjectMetadata>()
            .await?
            .into_public()
    }

    async fn get_object_at_generation(
        &self,
        object_name: &str,
        requested_generation: Option<i64>,
    ) -> Result<GcsGetResponse> {
        let metadata = self
            .object_metadata(object_name, requested_generation)
            .await?;
        let generation = metadata.generation;
        let token = self.access_token().await?;
        let encoded = urlencoding::encode(object_name);

        let data_url = format!(
            "https://storage.googleapis.com/download/storage/v1/b/{}/o/{}?alt=media&generation={}",
            self.bucket, encoded, generation
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
            wrapped_dek_b64: metadata.wrapped_dek_b64,
            generation,
        })
    }
}

fn gcs_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(300))
        .build()
        .expect("static GCS HTTP client configuration is valid")
}

#[async_trait::async_trait]
impl GcsClient for GcpGcsClient {
    async fn get_object(&self, object_name: &str) -> Result<GcsGetResponse> {
        self.get_object_at_generation(object_name, None).await
    }

    async fn get_object_generation(
        &self,
        object_name: &str,
        generation: i64,
    ) -> Result<GcsGetResponse> {
        self.get_object_at_generation(object_name, Some(generation))
            .await
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
        let meta: GcsApiObjectMetadata = resp.json().await?;
        let new_gen = meta
            .generation
            .parse::<i64>()
            .map_err(|e| EnclaveError::Gcs(format!("bad generation in PUT response: {e}")))?;
        Ok(new_gen)
    }

    async fn copy_generation_if_absent(
        &self,
        source_name: &str,
        source_generation: i64,
        destination_name: &str,
    ) -> Result<GcsGenerationCopy> {
        let source = self
            .object_metadata(source_name, Some(source_generation))
            .await?;
        if source.generation != source_generation {
            return Err(EnclaveError::Gcs(
                "GCS returned an unexpected source generation".into(),
            ));
        }
        let token = self.access_token().await?;
        let source_encoded = urlencoding::encode(source_name);
        let destination_encoded = urlencoding::encode(destination_name);
        // Supplying the complete custom metadata in the Rewrite request makes
        // the protocol marker and wrapped DEK part of the same create-only
        // destination operation as the copied bytes.
        let destination_resource = serde_json::json!({
            "metadata": {
                "x-kioku-wrapped-dek": source.wrapped_dek_b64.clone(),
                "x-kioku-legacy-recovery-format": "1",
                "x-kioku-legacy-source-object": source_name,
                "x-kioku-legacy-source-generation": source_generation.to_string(),
                "x-kioku-legacy-source-size": source.size.to_string(),
                "x-kioku-legacy-source-crc32c": source.crc32c.clone(),
            }
        });
        let mut url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}/rewriteTo/b/{}/o/{}?sourceGeneration={}&ifSourceGenerationMatch={}&ifGenerationMatch=0",
            self.bucket,
            source_encoded,
            self.bucket,
            destination_encoded,
            source_generation,
            source_generation
        );
        loop {
            let response = self
                .http
                .post(&url)
                .bearer_auth(&token)
                .json(&destination_resource)
                .send()
                .await?;
            if response.status() == reqwest::StatusCode::PRECONDITION_FAILED {
                // A lost success or another writer can only converge by checking
                // the named destination; never retry against a latest source.
                let destination = self.object_metadata(destination_name, None).await?;
                return Ok(GcsGenerationCopy {
                    source,
                    destination,
                    created: false,
                });
            }
            #[derive(Deserialize)]
            struct RewriteResponse {
                done: Option<bool>,
                #[serde(rename = "rewriteToken")]
                rewrite_token: Option<String>,
                resource: Option<GcsApiObjectMetadata>,
            }
            let rewritten: RewriteResponse = response.error_for_status()?.json().await?;
            if rewritten.done == Some(true) {
                let destination = rewritten
                    .resource
                    .ok_or_else(|| {
                        EnclaveError::Gcs("GCS rewrite completed without metadata".into())
                    })?
                    .into_public()?;
                return Ok(GcsGenerationCopy {
                    source,
                    destination,
                    created: true,
                });
            }
            let token = rewritten
                .rewrite_token
                .ok_or_else(|| EnclaveError::Gcs("GCS rewrite incomplete without token".into()))?;
            url = format!(
                "https://storage.googleapis.com/storage/v1/b/{}/o/{}/rewriteTo/b/{}/o/{}?sourceGeneration={}&ifSourceGenerationMatch={}&ifGenerationMatch=0&rewriteToken={}",
                self.bucket, source_encoded, self.bucket, destination_encoded,
                source_generation, source_generation,
                urlencoding::encode(&token)
            );
        }
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

    async fn list_object_versions(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        let token = self.access_token().await?;
        let mut url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o?versions=true&maxResults={}&prefix={}",
            self.bucket,
            GCS_LIST_PAGE_SIZE,
            urlencoding::encode(prefix)
        );
        if let Some(page_token) = page_token {
            url.push_str("&pageToken=");
            url.push_str(&urlencoding::encode(page_token));
        }
        let response = self.http.get(&url).bearer_auth(&token).send().await?;
        let response = response.error_for_status()?;
        decode_gcs_versions_page(&response.bytes().await?, "listed")
    }

    async fn list_soft_deleted_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        let token = self.access_token().await?;
        let mut url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o?softDeleted=true&maxResults={}&prefix={}",
            self.bucket,
            GCS_LIST_PAGE_SIZE,
            urlencoding::encode(prefix)
        );
        if let Some(page_token) = page_token {
            url.push_str("&pageToken=");
            url.push_str(&urlencoding::encode(page_token));
        }
        let response = self.http.get(&url).bearer_auth(&token).send().await?;
        let status = response.status();
        let body = response.bytes().await?;
        decode_soft_deleted_list_response(status, &body, page_token.is_none())
    }

    async fn delete_object_generation(&self, object_name: &str, generation: i64) -> Result<()> {
        let token = self.access_token().await?;
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}?generation={}",
            self.bucket,
            urlencoding::encode(object_name),
            generation
        );
        let response = self.http.delete(&url).bearer_auth(&token).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        response.error_for_status()?;
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn gcs_object_name(user_id: &str) -> String {
    format!("indexes/{user_id}.db.enc")
}

fn media_prefix(user_id: &str) -> String {
    format!("raw/{user_id}/")
}

fn legacy_recovery_prefix(user_id: &str) -> String {
    format!("legacy-recovery/{user_id}/")
}

/// Stable named checkpoint for the UTC day containing `now`. This name is an
/// inventory boundary: export/delete can list `legacy-recovery/{user_id}/`
/// without interpreting ciphertext or user content.
pub fn legacy_recovery_checkpoint_name(user_id: &str, now: SystemTime) -> String {
    let (year, month, day) = civil_from_unix_days(utc_epoch_day(now));
    format!("legacy-recovery/{user_id}/{year:04}-{month:02}-{day:02}.db.enc")
}

fn utc_epoch_day(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64 / 86_400
}

// Gregorian civil date from Unix epoch day, adapted from the public-domain
// Hinnant calendar algorithm. It avoids a runtime timezone dependency; UTC is
// the sole permitted checkpoint boundary.
fn civil_from_unix_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    (
        year + if month <= 2 { 1 } else { 0 },
        month as u32,
        day as u32,
    )
}

fn verify_legacy_recovery_copy(
    expected_source_object: &str,
    requested_source_generation: i64,
    source: &GcsObjectMetadata,
    destination: &GcsObjectMetadata,
    created: bool,
) -> Result<()> {
    let binding = destination.legacy_recovery.as_ref().ok_or_else(|| {
        EnclaveError::Gcs("missing legacy recovery checkpoint protocol metadata".into())
    })?;
    let common_valid = source.generation == requested_source_generation
        && requested_source_generation > 0
        && destination.generation > 0
        && !destination.wrapped_dek_b64.is_empty()
        && !destination.crc32c.is_empty()
        && source.wrapped_dek_b64 == destination.wrapped_dek_b64
        && binding.format_version == 1
        && binding.source_object == expected_source_object
        && binding.source_generation > 0
        && binding.source_generation <= requested_source_generation
        && binding.source_size == destination.size
        && !binding.source_crc32c.is_empty()
        && binding.source_crc32c == destination.crc32c;
    let created_valid = !created
        || (binding.source_generation == requested_source_generation
            && source.size == destination.size
            && source.crc32c == destination.crc32c
            && source.md5_hash == destination.md5_hash);
    if !common_valid || !created_valid {
        return Err(EnclaveError::Gcs(
            "legacy recovery checkpoint metadata verification failed".into(),
        ));
    }
    Ok(())
}

fn media_keys(conn: &Connection) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for table in ["screenshot_images", "media_objects"] {
        let table_exists: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        if table_exists == 0 {
            continue;
        }
        let mut stmt = conn.prepare(&format!("SELECT object_key FROM {table}"))?;
        keys.extend(
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?,
        );
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

pub(crate) fn user_blob_context(user_id: &str) -> Vec<u8> {
    format!("user-db\0{}", gcs_object_name(user_id)).into_bytes()
}

pub(crate) fn media_blob_context(user_id: &str, object_key: &str) -> Vec<u8> {
    format!("media\0{user_id}\0{object_key}").into_bytes()
}

/// Persist a decrypted database in an atomically-created, owner-only temp file.
///
/// `NamedTempFile` uses an unpredictable suffix and exclusive creation, avoiding
/// the symlink/race vulnerability of deriving a pathname and writing it later.
/// The `TempPath` guard removes a partial file if an async write fails; after a
/// successful write we deliberately persist the pathname for SQLite to manage.
async fn write_private_temp_db(user_id: &str, plaintext: &[u8]) -> Result<PathBuf> {
    let named = tempfile::Builder::new()
        .prefix(&format!("kioku-{user_id}-"))
        .suffix(".db")
        .tempfile_in(std::env::temp_dir())?;
    let (std_file, temp_path) = named.into_parts();
    let mut file = tokio::fs::File::from_std(std_file);
    file.write_all(plaintext).await?;
    file.flush().await?;
    drop(file);
    temp_path.keep().map_err(|e| EnclaveError::Io(e.error))
}

/// Best-effort removal of the plaintext database and SQLite sidecar files.
fn remove_temp_db_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(sqlite_sidecar_path(path, suffix));
    }
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Mutex as StdMutex,
    };
    use tokio::sync::Semaphore;

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
        let has_substance: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('episodes') WHERE name='substance'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(has_substance, 1, "substance column added");
        let metadata_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_metadata'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(metadata_exists, 1, "per-user task markers created");

        // started_at is no longer UNIQUE in v2.
        conn.execute(
            "INSERT INTO episodes (started_at, ended_at, title) VALUES ('2026-02-01T09:00:00Z','2026-02-01T09:30:00Z','a')",
            [],
        )
        .unwrap();
        let default_substance: String = conn
            .query_row("SELECT substance FROM episodes LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            default_substance, "normal",
            "legacy-compatible default is visible"
        );
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

    #[test]
    fn finalization_migration_never_auto_queues_historical_briefs() {
        init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_SQL).unwrap();
        conn.execute(
            "INSERT INTO episodes
             (id, started_at, ended_at, title, finalized_at, finalization_version,
              finalization_status, finalization_error)
             VALUES
             (1, '2026-07-01T09:00:00Z', '2026-07-01T10:00:00Z', 'stale',
              '2026-07-01T14:00:00Z', 4, 'complete', 'old error'),
             (2, '2026-07-02T09:00:00Z', '2026-07-02T10:00:00Z', 'current',
              '2026-07-02T14:00:00Z', 5, 'processing', 'old error')",
            [],
        )
        .unwrap();

        run_migrations(&conn).unwrap();

        let stale: (String, Option<String>) = conn
            .query_row(
                "SELECT finalization_status, finalization_error FROM episodes WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let current: (String, Option<String>) = conn
            .query_row(
                "SELECT finalization_status, finalization_error FROM episodes WHERE id = 2",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stale, ("complete".into(), None));
        assert_eq!(current, ("complete".into(), None));

        let retry_columns: (i64, Option<String>) = conn
            .query_row(
                "SELECT finalization_attempt_count, finalization_next_attempt_at \
                 FROM episodes WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(retry_columns, (0, None));
    }

    #[test]
    fn webhook_migration_removes_the_gmail_outbox() {
        init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_SQL).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE episode_deliveries (
                episode_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                delivery_version INTEGER NOT NULL,
                state TEXT NOT NULL,
                gmail_message_id TEXT,
                error_message TEXT
            );
            "#,
        )
        .unwrap();

        run_migrations(&conn).unwrap();

        let gmail_table: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'episode_deliveries'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let webhook_table: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'webhook_deliveries'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(gmail_table, 0);
        assert_eq!(webhook_table, 1);
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

    #[derive(Clone)]
    struct FakeObject {
        ciphertext: Vec<u8>,
        wrapped_dek_b64: String,
        generation: i64,
        live: bool,
        soft_deleted: bool,
        crc32c: String,
        md5_hash: Option<String>,
        legacy_recovery: Option<LegacyRecoveryBinding>,
    }

    pub struct FakeGcs {
        objects: StdMutex<HashMap<String, Vec<FakeObject>>>,
        fail_copy: StdMutex<Option<EnclaveError>>,
        fail_copy_after_create: StdMutex<Option<EnclaveError>>,
        fail_put: StdMutex<Option<EnclaveError>>,
        fail_put_after_commit: StdMutex<Option<EnclaveError>>,
        fail_generation_delete: StdMutex<Option<(String, i64)>>,
        soft_delete_enabled: StdMutex<bool>,
        repeat_version_cursor: StdMutex<bool>,
        listed_size_overrides: StdMutex<HashMap<String, u64>>,
        exact_generation_gets: StdMutex<usize>,
        copy_calls: StdMutex<Vec<(String, i64, String)>>,
        put_calls: StdMutex<Vec<(String, i64)>>,
    }

    impl FakeGcs {
        pub fn new() -> Self {
            Self {
                objects: StdMutex::new(HashMap::new()),
                fail_copy: StdMutex::new(None),
                fail_copy_after_create: StdMutex::new(None),
                fail_put: StdMutex::new(None),
                fail_put_after_commit: StdMutex::new(None),
                fail_generation_delete: StdMutex::new(None),
                soft_delete_enabled: StdMutex::new(false),
                repeat_version_cursor: StdMutex::new(false),
                listed_size_overrides: StdMutex::new(HashMap::new()),
                exact_generation_gets: StdMutex::new(0),
                copy_calls: StdMutex::new(Vec::new()),
                put_calls: StdMutex::new(Vec::new()),
            }
        }

        fn metadata(object: &FakeObject) -> GcsObjectMetadata {
            GcsObjectMetadata {
                generation: object.generation,
                size: object.ciphertext.len() as u64,
                crc32c: object.crc32c.clone(),
                md5_hash: object.md5_hash.clone(),
                wrapped_dek_b64: object.wrapped_dek_b64.clone(),
                legacy_recovery: object.legacy_recovery.clone(),
            }
        }

        fn set_soft_delete_enabled(&self, enabled: bool) {
            *self.soft_delete_enabled.lock().unwrap() = enabled;
        }

        fn set_repeat_version_cursor(&self, enabled: bool) {
            *self.repeat_version_cursor.lock().unwrap() = enabled;
        }

        fn set_listed_size(&self, object_name: &str, size: u64) {
            self.listed_size_overrides
                .lock()
                .unwrap()
                .insert(object_name.into(), size);
        }

        fn exact_generation_get_count(&self) -> usize {
            *self.exact_generation_gets.lock().unwrap()
        }

        fn version_count(&self, prefix: &str) -> usize {
            self.objects
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .map(|(_, versions)| {
                    versions
                        .iter()
                        .filter(|version| !version.soft_deleted)
                        .count()
                })
                .sum()
        }

        fn soft_deleted_count(&self, prefix: &str) -> usize {
            self.objects
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .map(|(_, versions)| {
                    versions
                        .iter()
                        .filter(|version| version.soft_deleted)
                        .count()
                })
                .sum()
        }

        fn soft_delete_generation(&self, object_name: &str, generation: i64) {
            if let Some(versions) = self.objects.lock().unwrap().get_mut(object_name) {
                if let Some(version) = versions
                    .iter_mut()
                    .find(|version| version.generation == generation)
                {
                    version.live = false;
                    version.soft_deleted = true;
                }
            }
        }

        fn fail_next_generation_delete(&self, object_name: &str, generation: i64) {
            *self.fail_generation_delete.lock().unwrap() = Some((object_name.into(), generation));
        }

        fn generation(&self, object_name: &str) -> Option<i64> {
            self.objects
                .lock()
                .unwrap()
                .get(object_name)
                .and_then(|versions| versions.iter().rev().find(|v| v.live))
                .map(|v| v.generation)
        }

        fn put_attempts(&self) -> usize {
            self.put_calls.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl GcsClient for FakeGcs {
        async fn get_object(&self, object_name: &str) -> crate::error::Result<GcsGetResponse> {
            let store = self.objects.lock().unwrap();
            store
                .get(object_name)
                .and_then(|versions| versions.iter().rev().find(|version| version.live))
                .map(|version| GcsGetResponse {
                    ciphertext: version.ciphertext.clone(),
                    wrapped_dek_b64: version.wrapped_dek_b64.clone(),
                    generation: version.generation,
                })
                .ok_or(crate::error::EnclaveError::NotFound)
        }

        async fn get_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<GcsGetResponse> {
            *self.exact_generation_gets.lock().unwrap() += 1;
            let store = self.objects.lock().unwrap();
            store
                .get(object_name)
                .and_then(|versions| {
                    versions
                        .iter()
                        .find(|version| version.generation == generation && !version.soft_deleted)
                })
                .map(|version| GcsGetResponse {
                    ciphertext: version.ciphertext.clone(),
                    wrapped_dek_b64: version.wrapped_dek_b64.clone(),
                    generation: version.generation,
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
            self.put_calls
                .lock()
                .unwrap()
                .push((object_name.to_string(), if_generation_match));
            if let Some(error) = self.fail_put.lock().unwrap().take() {
                return Err(error);
            }
            let mut store = self.objects.lock().unwrap();
            let current_gen = store
                .get(object_name)
                .and_then(|versions| versions.iter().rev().find(|version| version.live))
                .map(|version| version.generation)
                .unwrap_or(0);
            if current_gen != if_generation_match {
                return Err(crate::error::EnclaveError::Conflict(
                    "generation mismatch".into(),
                ));
            }
            let new_gen = current_gen + 1;
            let new_obj = FakeObject {
                ciphertext: ciphertext.to_vec(),
                wrapped_dek_b64: wrapped_dek_b64.to_string(),
                generation: new_gen,
                live: true,
                soft_deleted: false,
                crc32c: format!("fake-crc32c-{}", ciphertext.len()),
                md5_hash: Some(format!("fake-md5-{}", ciphertext.len())),
                legacy_recovery: None,
            };
            if let Some(versions) = store.get_mut(object_name) {
                for version in versions.iter_mut() {
                    version.live = false;
                }
                versions.push(new_obj);
            } else {
                store.insert(object_name.to_string(), vec![new_obj]);
            }
            if let Some(error) = self.fail_put_after_commit.lock().unwrap().take() {
                return Err(error);
            }
            Ok(new_gen)
        }

        async fn copy_generation_if_absent(
            &self,
            source_name: &str,
            source_generation: i64,
            destination_name: &str,
        ) -> crate::error::Result<GcsGenerationCopy> {
            self.copy_calls.lock().unwrap().push((
                source_name.to_string(),
                source_generation,
                destination_name.to_string(),
            ));
            if let Some(error) = self.fail_copy.lock().unwrap().take() {
                return Err(error);
            }
            let mut store = self.objects.lock().unwrap();
            let source = store
                .get(source_name)
                .and_then(|versions| {
                    versions
                        .iter()
                        .find(|v| v.generation == source_generation && !v.soft_deleted)
                })
                .cloned()
                .ok_or(EnclaveError::NotFound)?;
            if let Some(destination) = store
                .get(destination_name)
                .and_then(|versions| versions.iter().rev().find(|v| v.live))
            {
                return Ok(GcsGenerationCopy {
                    source: Self::metadata(&source),
                    destination: Self::metadata(destination),
                    created: false,
                });
            }
            let mut destination = source.clone();
            destination.generation = 1;
            destination.live = true;
            destination.soft_deleted = false;
            destination.legacy_recovery = Some(LegacyRecoveryBinding {
                format_version: 1,
                source_object: source_name.to_string(),
                source_generation,
                source_size: source.ciphertext.len() as u64,
                source_crc32c: source.crc32c.clone(),
            });
            if let Some(versions) = store.get_mut(destination_name) {
                for version in versions.iter_mut() {
                    version.live = false;
                }
                versions.push(destination.clone());
            } else {
                store.insert(destination_name.to_string(), vec![destination.clone()]);
            }
            if let Some(error) = self.fail_copy_after_create.lock().unwrap().take() {
                return Err(error);
            }
            Ok(GcsGenerationCopy {
                source: Self::metadata(&source),
                destination: Self::metadata(&destination),
                created: true,
            })
        }

        async fn delete_object(&self, object_name: &str) -> crate::error::Result<()> {
            if let Some(versions) = self.objects.lock().unwrap().get_mut(object_name) {
                for version in versions.iter_mut() {
                    version.live = false;
                }
            }
            Ok(())
        }

        async fn list_object_versions(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            const PAGE_SIZE: usize = 2;
            let start = page_token
                .map(|value| value.parse::<usize>())
                .transpose()
                .map_err(|_| EnclaveError::Gcs("invalid fake GCS page cursor".into()))?
                .unwrap_or(0);
            let store = self.objects.lock().unwrap();
            let size_overrides = self.listed_size_overrides.lock().unwrap().clone();
            let mut versions = store
                .iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .flat_map(|(name, objects)| {
                    let size_override = size_overrides.get(name).copied();
                    objects
                        .iter()
                        .filter(|object| !object.soft_deleted)
                        .map(move |object| GcsObjectVersion {
                            name: name.clone(),
                            generation: object.generation,
                            size: size_override.unwrap_or(object.ciphertext.len() as u64),
                        })
                })
                .collect::<Vec<_>>();
            versions.sort_by(|left, right| {
                left.name
                    .cmp(&right.name)
                    .then(left.generation.cmp(&right.generation))
            });
            let end = (start + PAGE_SIZE).min(versions.len());
            let next_page_token =
                if *self.repeat_version_cursor.lock().unwrap() && page_token.is_some() {
                    page_token.map(str::to_string)
                } else {
                    (end < versions.len()).then(|| end.to_string())
                };
            Ok(GcsListVersionsResponse {
                versions: versions[start..end].to_vec(),
                next_page_token,
            })
        }

        async fn delete_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<()> {
            if self
                .fail_generation_delete
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|failure| failure.0 == object_name && failure.1 == generation)
            {
                *self.fail_generation_delete.lock().unwrap() = None;
                return Err(EnclaveError::Gcs(
                    "injected generation-delete failure".into(),
                ));
            }
            let soft_delete_enabled = *self.soft_delete_enabled.lock().unwrap();
            let mut store = self.objects.lock().unwrap();
            if let Some(versions) = store.get_mut(object_name) {
                if soft_delete_enabled {
                    if let Some(version) = versions
                        .iter_mut()
                        .find(|version| version.generation == generation)
                    {
                        version.live = false;
                        version.soft_deleted = true;
                    }
                } else {
                    versions.retain(|version| version.generation != generation);
                }
                if versions.is_empty() {
                    store.remove(object_name);
                }
            }
            Ok(())
        }

        async fn list_soft_deleted_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            const PAGE_SIZE: usize = 2;
            if !*self.soft_delete_enabled.lock().unwrap() {
                return Ok(GcsListVersionsResponse::default());
            }
            let start = page_token
                .map(str::parse::<usize>)
                .transpose()
                .map_err(|_| EnclaveError::Gcs("invalid fake GCS page cursor".into()))?
                .unwrap_or(0);
            let store = self.objects.lock().unwrap();
            let size_overrides = self.listed_size_overrides.lock().unwrap().clone();
            let mut versions = store
                .iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .flat_map(|(name, objects)| {
                    let size_override = size_overrides.get(name).copied();
                    objects
                        .iter()
                        .filter(|object| object.soft_deleted)
                        .map(move |object| GcsObjectVersion {
                            name: name.clone(),
                            generation: object.generation,
                            size: size_override.unwrap_or(object.ciphertext.len() as u64),
                        })
                })
                .collect::<Vec<_>>();
            versions.sort_by(|left, right| {
                left.name
                    .cmp(&right.name)
                    .then(left.generation.cmp(&right.generation))
            });
            let end = (start + PAGE_SIZE).min(versions.len());
            let next_page_token =
                if *self.repeat_version_cursor.lock().unwrap() && page_token.is_some() {
                    page_token.map(str::to_string)
                } else {
                    (end < versions.len()).then(|| end.to_string())
                };
            Ok(GcsListVersionsResponse {
                versions: versions[start..end].to_vec(),
                next_page_token,
            })
        }
    }

    struct BlockingPutGcs {
        inner: Arc<FakeGcs>,
        target: String,
        block_once: AtomicBool,
        started: Notify,
        release: Semaphore,
    }

    impl BlockingPutGcs {
        fn new(inner: Arc<FakeGcs>, target: String) -> Self {
            Self {
                inner,
                target,
                block_once: AtomicBool::new(true),
                started: Notify::new(),
                release: Semaphore::new(0),
            }
        }

        async fn wait_until_blocked(&self) {
            self.started.notified().await;
        }

        fn release(&self) {
            self.release.add_permits(1);
        }
    }

    #[async_trait::async_trait]
    impl GcsClient for BlockingPutGcs {
        async fn get_object(&self, object_name: &str) -> crate::error::Result<GcsGetResponse> {
            self.inner.get_object(object_name).await
        }

        async fn put_object(
            &self,
            object_name: &str,
            ciphertext: &[u8],
            wrapped_dek_b64: &str,
            if_generation_match: i64,
        ) -> crate::error::Result<i64> {
            if object_name == self.target && self.block_once.swap(false, Ordering::SeqCst) {
                self.started.notify_one();
                self.release
                    .acquire()
                    .await
                    .map_err(|_| EnclaveError::Store("test GCS gate closed".into()))?
                    .forget();
            }
            self.inner
                .put_object(
                    object_name,
                    ciphertext,
                    wrapped_dek_b64,
                    if_generation_match,
                )
                .await
        }

        async fn delete_object(&self, object_name: &str) -> crate::error::Result<()> {
            self.inner.delete_object(object_name).await
        }

        async fn get_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<GcsGetResponse> {
            self.inner
                .get_object_generation(object_name, generation)
                .await
        }

        async fn copy_generation_if_absent(
            &self,
            source_object_name: &str,
            source_generation: i64,
            destination_object_name: &str,
        ) -> crate::error::Result<GcsGenerationCopy> {
            self.inner
                .copy_generation_if_absent(
                    source_object_name,
                    source_generation,
                    destination_object_name,
                )
                .await
        }

        async fn list_object_versions(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_object_versions(prefix, page_token).await
        }

        async fn delete_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<()> {
            self.inner
                .delete_object_generation(object_name, generation)
                .await
        }

        async fn list_soft_deleted_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner
                .list_soft_deleted_objects(prefix, page_token)
                .await
        }
    }

    struct BlockingGetGcs {
        inner: Arc<FakeGcs>,
        target: String,
        block_once: AtomicBool,
        started: Notify,
        release: Semaphore,
    }

    impl BlockingGetGcs {
        fn new(inner: Arc<FakeGcs>, target: String) -> Self {
            Self {
                inner,
                target,
                block_once: AtomicBool::new(true),
                started: Notify::new(),
                release: Semaphore::new(0),
            }
        }

        async fn wait_until_blocked(&self) {
            self.started.notified().await;
        }

        fn release(&self) {
            self.release.add_permits(1);
        }
    }

    #[async_trait::async_trait]
    impl GcsClient for BlockingGetGcs {
        async fn get_object(&self, object_name: &str) -> crate::error::Result<GcsGetResponse> {
            if object_name == self.target && self.block_once.swap(false, Ordering::SeqCst) {
                self.started.notify_one();
                self.release
                    .acquire()
                    .await
                    .map_err(|_| EnclaveError::Store("test GCS gate closed".into()))?
                    .forget();
            }
            self.inner.get_object(object_name).await
        }

        async fn put_object(
            &self,
            object_name: &str,
            ciphertext: &[u8],
            wrapped_dek_b64: &str,
            if_generation_match: i64,
        ) -> crate::error::Result<i64> {
            self.inner
                .put_object(
                    object_name,
                    ciphertext,
                    wrapped_dek_b64,
                    if_generation_match,
                )
                .await
        }

        async fn delete_object(&self, object_name: &str) -> crate::error::Result<()> {
            self.inner.delete_object(object_name).await
        }

        async fn get_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<GcsGetResponse> {
            self.inner
                .get_object_generation(object_name, generation)
                .await
        }

        async fn copy_generation_if_absent(
            &self,
            source_object_name: &str,
            source_generation: i64,
            destination_object_name: &str,
        ) -> crate::error::Result<GcsGenerationCopy> {
            self.inner
                .copy_generation_if_absent(
                    source_object_name,
                    source_generation,
                    destination_object_name,
                )
                .await
        }

        async fn list_object_versions(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_object_versions(prefix, page_token).await
        }

        async fn delete_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<()> {
            self.inner
                .delete_object_generation(object_name, generation)
                .await
        }

        async fn list_soft_deleted_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner
                .list_soft_deleted_objects(prefix, page_token)
                .await
        }
    }

    struct FailPutOnceGcs {
        inner: Arc<FakeGcs>,
        target: String,
        fail_once: AtomicBool,
    }

    #[async_trait::async_trait]
    impl GcsClient for FailPutOnceGcs {
        async fn get_object(&self, object_name: &str) -> crate::error::Result<GcsGetResponse> {
            self.inner.get_object(object_name).await
        }

        async fn put_object(
            &self,
            object_name: &str,
            ciphertext: &[u8],
            wrapped_dek_b64: &str,
            if_generation_match: i64,
        ) -> crate::error::Result<i64> {
            if object_name == self.target && self.fail_once.swap(false, Ordering::SeqCst) {
                return Err(EnclaveError::Gcs("injected PUT failure".into()));
            }
            self.inner
                .put_object(
                    object_name,
                    ciphertext,
                    wrapped_dek_b64,
                    if_generation_match,
                )
                .await
        }

        async fn delete_object(&self, object_name: &str) -> crate::error::Result<()> {
            self.inner.delete_object(object_name).await
        }

        async fn get_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<GcsGetResponse> {
            self.inner
                .get_object_generation(object_name, generation)
                .await
        }

        async fn copy_generation_if_absent(
            &self,
            source_object_name: &str,
            source_generation: i64,
            destination_object_name: &str,
        ) -> crate::error::Result<GcsGenerationCopy> {
            self.inner
                .copy_generation_if_absent(
                    source_object_name,
                    source_generation,
                    destination_object_name,
                )
                .await
        }

        async fn list_object_versions(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_object_versions(prefix, page_token).await
        }

        async fn delete_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<()> {
            self.inner
                .delete_object_generation(object_name, generation)
                .await
        }

        async fn list_soft_deleted_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner
                .list_soft_deleted_objects(prefix, page_token)
                .await
        }
    }

    struct FailDeleteOnceGcs {
        inner: Arc<FakeGcs>,
        target: String,
        fail_once: AtomicBool,
        delete_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl GcsClient for FailDeleteOnceGcs {
        async fn get_object(&self, object_name: &str) -> crate::error::Result<GcsGetResponse> {
            self.inner.get_object(object_name).await
        }

        async fn put_object(
            &self,
            object_name: &str,
            ciphertext: &[u8],
            wrapped_dek_b64: &str,
            if_generation_match: i64,
        ) -> crate::error::Result<i64> {
            self.inner
                .put_object(
                    object_name,
                    ciphertext,
                    wrapped_dek_b64,
                    if_generation_match,
                )
                .await
        }

        async fn delete_object(&self, object_name: &str) -> crate::error::Result<()> {
            if object_name == self.target {
                self.delete_calls.fetch_add(1, Ordering::SeqCst);
                if self.fail_once.swap(false, Ordering::SeqCst) {
                    return Err(EnclaveError::Gcs("injected DELETE failure".into()));
                }
            }
            self.inner.delete_object(object_name).await
        }

        async fn get_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<GcsGetResponse> {
            self.inner
                .get_object_generation(object_name, generation)
                .await
        }

        async fn copy_generation_if_absent(
            &self,
            source_object_name: &str,
            source_generation: i64,
            destination_object_name: &str,
        ) -> crate::error::Result<GcsGenerationCopy> {
            self.inner
                .copy_generation_if_absent(
                    source_object_name,
                    source_generation,
                    destination_object_name,
                )
                .await
        }

        async fn list_object_versions(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_object_versions(prefix, page_token).await
        }

        async fn delete_object_generation(
            &self,
            object_name: &str,
            generation: i64,
        ) -> crate::error::Result<()> {
            if object_name == self.target {
                self.delete_calls.fetch_add(1, Ordering::SeqCst);
                if self.fail_once.swap(false, Ordering::SeqCst) {
                    return Err(EnclaveError::Gcs("injected DELETE failure".into()));
                }
            }
            self.inner
                .delete_object_generation(object_name, generation)
                .await
        }

        async fn list_soft_deleted_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner
                .list_soft_deleted_objects(prefix, page_token)
                .await
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    fn make_store() -> Store {
        Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()))
    }

    fn insert_screenshot_evidence(conn: &Connection, object_key: &str) -> Result<()> {
        conn.execute(
            "INSERT INTO screenshots(id,captured_at) VALUES (1,'2026-01-01T00:00:00Z')",
            [],
        )?;
        conn.execute(
            "INSERT INTO episodes(id,started_at,ended_at) \
             VALUES (1,'2026-01-01T00:00:00Z','2026-01-01T00:01:00Z')",
            [],
        )?;
        conn.execute(
            "INSERT INTO screenshot_images \
             (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,width,height,byte_length,sha256) \
             VALUES ('image-1',1,1,'source-1','2026-01-01T00:00:00Z',?1,'image/jpeg',1,1,1,?2)",
            rusqlite::params![object_key, "a".repeat(64)],
        )?;
        Ok(())
    }

    fn store_with_checkpoint_time(gcs: Arc<FakeGcs>, unix_seconds: u64) -> Store {
        let mut store = Store::new(Arc::new(FakeKms), gcs);
        store.checkpoint_clock = Arc::new(move || UNIX_EPOCH + Duration::from_secs(unix_seconds));
        store
    }

    fn store_with_mutable_checkpoint_time(
        gcs: Arc<FakeGcs>,
        unix_seconds: u64,
    ) -> (Store, Arc<AtomicU64>) {
        let clock = Arc::new(AtomicU64::new(unix_seconds));
        let clock_for_store = Arc::clone(&clock);
        let mut store = Store::new(Arc::new(FakeKms), gcs);
        store.checkpoint_clock = Arc::new(move || {
            UNIX_EPOCH + Duration::from_secs(clock_for_store.load(Ordering::SeqCst))
        });
        (store, clock)
    }

    async fn write_and_save(store: &Store, user_id: &str, marker: &str) -> Result<()> {
        let marker = marker.to_string();
        store
            .with_user(user_id, move |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES ('2026-01-01T00:00:00Z', ?1)",
                    [&marker],
                )?;
                Ok(())
            })
            .await?;
        store.save_user(user_id).await
    }

    #[tokio::test]
    async fn legacy_recovery_checkpoint_is_once_per_utc_day_and_pins_first_save() {
        let gcs = Arc::new(FakeGcs::new());
        // 2026-01-01T12:00:00Z
        let store = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        write_and_save(&store, "checkpoint-user", "first")
            .await
            .unwrap();
        write_and_save(&store, "checkpoint-user", "second")
            .await
            .unwrap();
        write_and_save(&store, "checkpoint-user", "third")
            .await
            .unwrap();

        let checkpoint = legacy_recovery_checkpoint_name(
            "checkpoint-user",
            UNIX_EPOCH + Duration::from_secs(1_767_268_800),
        );
        let objects = gcs.objects.lock().unwrap();
        assert_eq!(
            objects
                .keys()
                .filter(|name| name.starts_with("legacy-recovery/checkpoint-user/"))
                .count(),
            1
        );
        let checkpoint = objects.get(&checkpoint).unwrap().last().unwrap();
        assert_eq!(checkpoint.generation, 1);
        assert_eq!(
            checkpoint
                .legacy_recovery
                .as_ref()
                .unwrap()
                .source_generation,
            1,
            "checkpoint must bind the pre-overwrite authoritative generation"
        );
        drop(objects);
        let calls = gcs.copy_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "same-day saves must hit the process cache");
        assert_eq!(calls[0].1, 1);
    }

    #[test]
    fn legacy_recovery_checkpoint_uses_utc_not_local_day() {
        assert_eq!(
            legacy_recovery_checkpoint_name(
                "alice",
                UNIX_EPOCH + Duration::from_secs(1_767_225_599)
            ),
            "legacy-recovery/alice/2025-12-31.db.enc"
        );
        assert_eq!(
            legacy_recovery_checkpoint_name(
                "alice",
                UNIX_EPOCH + Duration::from_secs(1_767_225_600)
            ),
            "legacy-recovery/alice/2026-01-01.db.enc"
        );
    }

    #[tokio::test]
    async fn legacy_recovery_checkpoint_survives_process_restart() {
        let gcs = Arc::new(FakeGcs::new());
        let time = 1_767_268_800;
        let first = store_with_checkpoint_time(gcs.clone(), time);
        write_and_save(&first, "restart-user", "first")
            .await
            .unwrap();
        write_and_save(&first, "restart-user", "second")
            .await
            .unwrap();
        let second = store_with_checkpoint_time(gcs.clone(), time);
        write_and_save(&second, "restart-user", "third")
            .await
            .unwrap();
        assert_eq!(
            gcs.objects
                .lock()
                .unwrap()
                .keys()
                .filter(|name| name.starts_with("legacy-recovery/restart-user/"))
                .count(),
            1
        );
        assert_eq!(
            gcs.copy_calls.lock().unwrap().len(),
            2,
            "restart re-verifies the existing destination exactly once"
        );
    }

    #[tokio::test]
    async fn legacy_recovery_checkpoint_lost_success_converges_on_retry() {
        let gcs = Arc::new(FakeGcs::new());
        let store = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        write_and_save(&store, "retry-user", "first").await.unwrap();
        *gcs.fail_copy_after_create.lock().unwrap() =
            Some(EnclaveError::Gcs("lost response".into()));
        assert!(write_and_save(&store, "retry-user", "second")
            .await
            .is_err());
        assert_eq!(
            gcs.put_calls.lock().unwrap().len(),
            1,
            "lost checkpoint response must happen before the overwrite"
        );
        // A handler-style retry re-enters through with_user. The store must
        // persist the pending local mutation before the closure can observe it
        // as a duplicate and return success without another save_user call.
        let count: i64 = store
            .with_user("retry-user", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            gcs.objects
                .lock()
                .unwrap()
                .keys()
                .filter(|name| name.starts_with("legacy-recovery/retry-user/"))
                .count(),
            1
        );
        assert_eq!(gcs.put_calls.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn failed_put_is_persisted_before_handler_style_retry_observes_duplicate() {
        let gcs = Arc::new(FakeGcs::new());
        let store = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        write_and_save(&store, "put-retry-user", "first")
            .await
            .unwrap();
        *gcs.fail_put.lock().unwrap() = Some(EnclaveError::Gcs("transient PUT failure".into()));

        assert!(matches!(
            write_and_save(&store, "put-retry-user", "second").await,
            Err(EnclaveError::Gcs(_))
        ));
        assert_eq!(gcs.copy_calls.lock().unwrap().len(), 1);
        assert_eq!(gcs.put_calls.lock().unwrap().len(), 2);
        assert_eq!(
            gcs.objects
                .lock()
                .unwrap()
                .get(&gcs_object_name("put-retry-user"))
                .unwrap()
                .last()
                .unwrap()
                .generation,
            1,
            "failed PUT must leave remote authority unchanged"
        );

        // This models an idempotency retry: before the handler closure can see
        // the locally inserted row and call it a duplicate, with_user retries
        // the pending authoritative PUT.
        let local_count: i64 = store
            .with_user("put-retry-user", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(local_count, 2);
        assert_eq!(gcs.copy_calls.lock().unwrap().len(), 1);
        assert_eq!(gcs.put_calls.lock().unwrap().len(), 3);

        let restarted = Store::new(Arc::new(FakeKms), gcs);
        let durable_count: i64 = restarted
            .with_user("put-retry-user", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(durable_count, 2);
    }

    #[tokio::test]
    async fn legacy_recovery_checkpoint_failure_withholds_save_success() {
        let gcs = Arc::new(FakeGcs::new());
        let store = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        write_and_save(&store, "failure-user", "first")
            .await
            .unwrap();
        *gcs.fail_copy.lock().unwrap() = Some(EnclaveError::Gcs("copy unavailable".into()));
        assert!(matches!(
            write_and_save(&store, "failure-user", "second").await,
            Err(EnclaveError::Gcs(_))
        ));
        assert_eq!(
            gcs.put_calls.lock().unwrap().len(),
            1,
            "checkpoint failure must prevent the authoritative overwrite"
        );
        store.save_user("failure-user").await.unwrap();
        assert_eq!(
            gcs.copy_calls.lock().unwrap().len(),
            2,
            "failure must not poison the verified-day cache"
        );
    }

    #[tokio::test]
    async fn legacy_recovery_checkpoint_rejects_existing_integrity_mismatch() {
        let gcs = Arc::new(FakeGcs::new());
        let store = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        write_and_save(&store, "mismatch-user", "first")
            .await
            .unwrap();
        write_and_save(&store, "mismatch-user", "second")
            .await
            .unwrap();
        let checkpoint = legacy_recovery_checkpoint_name(
            "mismatch-user",
            UNIX_EPOCH + Duration::from_secs(1_767_268_800),
        );
        gcs.objects
            .lock()
            .unwrap()
            .get_mut(&checkpoint)
            .unwrap()
            .last_mut()
            .unwrap()
            .crc32c
            .clear();
        let restarted = store_with_checkpoint_time(gcs, 1_767_268_800);
        assert!(matches!(
            write_and_save(&restarted, "mismatch-user", "third").await,
            Err(EnclaveError::Gcs(_))
        ));
    }

    #[tokio::test]
    async fn legacy_recovery_checkpoint_rejects_unmarked_preexisting_destination() {
        let gcs = Arc::new(FakeGcs::new());
        let time = 1_767_268_800;
        let store = store_with_checkpoint_time(gcs.clone(), time);
        write_and_save(&store, "unmarked-user", "first")
            .await
            .unwrap();
        let source_name = gcs_object_name("unmarked-user");
        let destination_name = legacy_recovery_checkpoint_name(
            "unmarked-user",
            UNIX_EPOCH + Duration::from_secs(time),
        );
        {
            let mut objects = gcs.objects.lock().unwrap();
            let mut malicious = objects.get(&source_name).unwrap().last().unwrap().clone();
            malicious.generation = 7;
            malicious.legacy_recovery = None;
            objects.insert(destination_name, vec![malicious]);
        }

        assert!(matches!(
            write_and_save(&store, "unmarked-user", "second").await,
            Err(EnclaveError::Gcs(_))
        ));
        assert_eq!(gcs.put_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn legacy_recovery_checkpoint_rejects_mismatched_protocol_marker() {
        let gcs = Arc::new(FakeGcs::new());
        let time = 1_767_268_800;
        let store = store_with_checkpoint_time(gcs.clone(), time);
        write_and_save(&store, "marker-user", "first")
            .await
            .unwrap();
        let source_name = gcs_object_name("marker-user");
        let destination_name =
            legacy_recovery_checkpoint_name("marker-user", UNIX_EPOCH + Duration::from_secs(time));
        {
            let mut objects = gcs.objects.lock().unwrap();
            let mut malicious = objects.get(&source_name).unwrap().last().unwrap().clone();
            malicious.generation = 9;
            malicious.legacy_recovery = Some(LegacyRecoveryBinding {
                format_version: 1,
                source_object: "indexes/a-different-user.db.enc".into(),
                source_generation: 1,
                source_size: malicious.ciphertext.len() as u64,
                source_crc32c: malicious.crc32c.clone(),
            });
            objects.insert(destination_name, vec![malicious]);
        }

        assert!(matches!(
            write_and_save(&store, "marker-user", "second").await,
            Err(EnclaveError::Gcs(_))
        ));
        assert_eq!(gcs.put_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn utc_rollover_requires_a_new_checkpoint_and_failure_does_not_cache() {
        let gcs = Arc::new(FakeGcs::new());
        let day_one = 1_767_268_800;
        let (store, clock) = store_with_mutable_checkpoint_time(gcs.clone(), day_one);
        write_and_save(&store, "rollover-user", "first")
            .await
            .unwrap();
        write_and_save(&store, "rollover-user", "second")
            .await
            .unwrap();
        assert_eq!(gcs.copy_calls.lock().unwrap().len(), 1);

        clock.store(day_one + 86_400, Ordering::SeqCst);
        *gcs.fail_copy.lock().unwrap() = Some(EnclaveError::Gcs("rollover failure".into()));
        assert!(write_and_save(&store, "rollover-user", "third")
            .await
            .is_err());
        assert_eq!(gcs.put_calls.lock().unwrap().len(), 2);

        store.save_user("rollover-user").await.unwrap();
        write_and_save(&store, "rollover-user", "fourth")
            .await
            .unwrap();
        assert_eq!(gcs.copy_calls.lock().unwrap().len(), 3);
        assert_eq!(
            gcs.objects
                .lock()
                .unwrap()
                .keys()
                .filter(|name| name.starts_with("legacy-recovery/rollover-user/"))
                .count(),
            2
        );
    }

    fn seed_user_object_with_missing_schema(gcs: &FakeGcs, user_id: &str) {
        let dek = Dek([7_u8; 32]);
        let current = create_empty_db(&dek).unwrap();
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), current).unwrap();
        let conn = Connection::open(temp.path()).unwrap();
        conn.execute_batch(
            "DROP TABLE email_deliveries;
             PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .unwrap();
        drop(conn);
        let old_bytes = std::fs::read(temp.path()).unwrap();
        let ciphertext = encrypt_bound_blob(&dek, &old_bytes, &user_blob_context(user_id)).unwrap();
        gcs.objects.lock().unwrap().insert(
            gcs_object_name(user_id),
            vec![FakeObject {
                ciphertext,
                wrapped_dek_b64: B64.encode(dek.0),
                generation: 1,
                live: true,
                soft_deleted: false,
                crc32c: "fake-crc32c".into(),
                md5_hash: None,
                legacy_recovery: None,
            }],
        );
    }

    fn seed_user_object_with_legacy_envelope(gcs: &FakeGcs, user_id: &str) {
        let dek = Dek([9_u8; 32]);
        let plaintext = create_empty_db(&dek).unwrap();
        let legacy =
            crate::crypto::encrypt_blob_with_aad(&dek, &plaintext, &user_blob_context(user_id))
                .unwrap();
        gcs.objects.lock().unwrap().insert(
            gcs_object_name(user_id),
            vec![FakeObject {
                ciphertext: legacy,
                wrapped_dek_b64: B64.encode(dek.0),
                generation: 1,
                live: true,
                soft_deleted: false,
                crc32c: "fake-crc32c".into(),
                md5_hash: None,
                legacy_recovery: None,
            }],
        );
    }

    #[tokio::test]
    async fn read_only_access_and_save_do_not_create_or_rewrite_an_object() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let store = Store::new(kms.clone(), gcs.clone());

        let count: i64 = store
            .with_user_read("read-only-new", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(count, 0);
        let metrics_before_clean_save = store.storage_metrics_snapshot();
        store.save_user("read-only-new").await.unwrap();
        let metrics_after_clean_save = store.storage_metrics_snapshot();
        assert_eq!(gcs.put_attempts(), 0);
        assert_eq!(gcs.generation(&gcs_object_name("read-only-new")), None);
        assert_eq!(
            metrics_after_clean_save.save_attempts_total,
            metrics_before_clean_save.save_attempts_total + 1
        );
        assert_eq!(
            metrics_after_clean_save.save_skipped_total,
            metrics_before_clean_save.save_skipped_total + 1
        );
        assert_eq!(
            metrics_after_clean_save.save_completed_total,
            metrics_before_clean_save.save_completed_total
        );
        assert_eq!(
            metrics_after_clean_save.save_failed_total,
            metrics_before_clean_save.save_failed_total
        );
        assert_eq!(
            metrics_after_clean_save.save_latency_us.count,
            metrics_before_clean_save.save_latency_us.count + 1
        );

        store
            .with_user("read-only-existing", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES ('2026-01-01T00:00:00Z', 'durable')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user("read-only-existing").await.unwrap();
        let attempts_after_write = gcs.put_attempts();
        let generation_after_write = gcs
            .generation(&gcs_object_name("read-only-existing"))
            .unwrap();

        store
            .with_user_read("read-only-existing", |conn| {
                let _: i64 =
                    conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user("read-only-existing").await.unwrap();
        assert_eq!(gcs.put_attempts(), attempts_after_write);
        assert_eq!(
            gcs.generation(&gcs_object_name("read-only-existing")),
            Some(generation_after_write)
        );

        // Process restart must not make idempotent schema setup look dirty.
        let reopened = Store::new(kms, gcs.clone());
        reopened
            .with_user_read("read-only-existing", |conn| {
                Ok(
                    conn.query_row("SELECT count(*) FROM screenshots", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                )
            })
            .await
            .unwrap();
        reopened.save_user("read-only-existing").await.unwrap();
        assert_eq!(gcs.put_attempts(), attempts_after_write);
        assert_eq!(
            gcs.generation(&gcs_object_name("read-only-existing")),
            Some(generation_after_write)
        );
    }

    #[tokio::test]
    async fn query_only_api_rejects_sql_mutation_and_restores_guard_after_error() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        let result = store
            .with_user_read("guarded-reader", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at) VALUES ('2026-01-01T00:00:00Z')",
                    [],
                )?;
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(EnclaveError::Db(_))));
        store
            .with_user("guarded-reader", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at) VALUES ('2026-01-01T00:00:00Z')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("query_only must be restored after the read closure error");
        store.save_user("guarded-reader").await.unwrap();
        assert_eq!(gcs.put_attempts(), 1);
    }

    #[tokio::test]
    async fn direct_schema_and_trigger_mutations_advance_dirty_generation_and_persist() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let store = Store::new(kms.clone(), gcs.clone());

        store
            .with_user("tracked-mutations", |conn| {
                conn.execute_batch(
                    "CREATE TABLE dirty_save_probe(value TEXT NOT NULL);
                     CREATE TRIGGER dirty_save_probe_mirror AFTER INSERT ON dirty_save_probe BEGIN
                         INSERT INTO dirty_save_probe(value) VALUES ('triggered');
                     END;",
                )?;
                conn.execute("INSERT INTO dirty_save_probe(value) VALUES ('direct')", [])?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user("tracked-mutations").await.unwrap();
        assert_eq!(
            gcs.generation(&gcs_object_name("tracked-mutations")),
            Some(1)
        );

        let restarted = Store::new(kms, gcs);
        let values: Vec<String> = restarted
            .with_user_read("tracked-mutations", |conn| {
                let mut statement =
                    conn.prepare("SELECT value FROM dirty_save_probe ORDER BY rowid")?;
                let values = statement
                    .query_map([], |row| row.get(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(values)
            })
            .await
            .unwrap();
        assert_eq!(values, vec!["direct", "triggered"]);
    }

    #[tokio::test]
    async fn clean_eviction_skips_put_but_dirty_eviction_and_migration_flush() {
        let gcs = Arc::new(FakeGcs::new());
        let mut store = Store::new(Arc::new(FakeKms), gcs.clone());
        store.max_open = 1;

        store
            .with_user("clean-eviction", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at) VALUES ('2026-01-01T00:00:00Z')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user("clean-eviction").await.unwrap();
        let after_initial_save = gcs.put_attempts();
        store
            .with_user_read("other-reader", |conn| {
                Ok(
                    conn.query_row("SELECT count(*) FROM screenshots", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                )
            })
            .await
            .unwrap();
        assert_eq!(gcs.put_attempts(), after_initial_save);

        store
            .with_user("dirty-eviction", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at) VALUES ('2026-01-02T00:00:00Z')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let before_dirty_evict = gcs.put_attempts();
        store
            .with_user_read("dirty-eviction-next", |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(gcs.put_attempts(), before_dirty_evict + 1);
        assert_eq!(gcs.generation(&gcs_object_name("dirty-eviction")), Some(1));

        seed_user_object_with_missing_schema(&gcs, "migration-eviction");
        store
            .with_user_read("migration-eviction", |conn| {
                let present: i64 = conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='email_deliveries'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(present, 1);
                Ok(())
            })
            .await
            .unwrap();
        let before_migration_evict = gcs.put_attempts();
        store
            .with_user_read("post-migration-reader", |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(gcs.put_attempts(), before_migration_evict + 1);
        assert_eq!(
            gcs.generation(&gcs_object_name("migration-eviction")),
            Some(2)
        );
    }

    #[tokio::test]
    async fn failed_put_retains_dirty_generation_for_retry() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        store
            .with_user("dirty-retry", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at) VALUES ('2026-01-01T00:00:00Z')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        *gcs.fail_put.lock().unwrap() = Some(EnclaveError::Gcs("injected PUT failure".into()));
        assert!(matches!(
            store.save_user("dirty-retry").await,
            Err(EnclaveError::Gcs(_))
        ));
        assert_eq!(gcs.generation(&gcs_object_name("dirty-retry")), None);
        store.save_user("dirty-retry").await.unwrap();
        assert_eq!(gcs.generation(&gcs_object_name("dirty-retry")), Some(1));
    }

    #[tokio::test]
    async fn lost_put_success_reconciles_exact_snapshot_before_access() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let store = Store::new(kms.clone(), gcs.clone());
        store
            .with_user("lost-put-success", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-01-01T00:00:00Z', 'durable despite lost response')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        *gcs.fail_put_after_commit.lock().unwrap() =
            Some(EnclaveError::Gcs("lost PUT response".into()));

        assert!(matches!(
            store.save_user("lost-put-success").await,
            Err(EnclaveError::Gcs(_))
        ));
        let object_name = gcs_object_name("lost-put-success");
        assert_eq!(gcs.generation(&object_name), Some(1));

        // Access retries with the old generation, receives a conflict, and
        // accepts the current generation only after exact authenticated
        // plaintext/DEK reconciliation.
        let count: i64 = store
            .with_user_read("lost-put-success", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(gcs.version_count(&object_name), 1);
        assert_eq!(
            gcs.put_calls.lock().unwrap().as_slice(),
            &[(object_name.clone(), 0), (object_name.clone(), 0)]
        );

        let restarted = Store::new(kms, gcs);
        let durable_count: i64 = restarted
            .with_user_read("lost-put-success", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(durable_count, 1);
    }

    #[tokio::test]
    async fn generation_conflict_with_different_snapshot_remains_conflict() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let local = Store::new(kms.clone(), gcs.clone());
        write_and_save(&local, "real-conflict", "baseline")
            .await
            .unwrap();
        local
            .with_user("real-conflict", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-01-02T00:00:00Z', 'local pending state')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let concurrent = Store::new(kms, gcs.clone());
        write_and_save(&concurrent, "real-conflict", "different remote state")
            .await
            .unwrap();

        assert!(matches!(
            local.save_user("real-conflict").await,
            Err(EnclaveError::Conflict(_))
        ));
        assert_eq!(gcs.generation(&gcs_object_name("real-conflict")), Some(2));
    }

    #[tokio::test]
    async fn lost_put_success_with_changed_wrapped_dek_remains_conflict() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        store
            .with_user("lost-put-dek-mismatch", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at) VALUES ('2026-01-01T00:00:00Z')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        *gcs.fail_put_after_commit.lock().unwrap() =
            Some(EnclaveError::Gcs("lost PUT response".into()));
        assert!(store.save_user("lost-put-dek-mismatch").await.is_err());

        let object_name = gcs_object_name("lost-put-dek-mismatch");
        gcs.objects
            .lock()
            .unwrap()
            .get_mut(&object_name)
            .unwrap()
            .last_mut()
            .unwrap()
            .wrapped_dek_b64 = B64.encode([9_u8; 32]);

        assert!(matches!(
            store.save_user("lost-put-dek-mismatch").await,
            Err(EnclaveError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn legacy_envelope_read_remains_dirty_until_v2_rewrite_succeeds() {
        let gcs = Arc::new(FakeGcs::new());
        seed_user_object_with_legacy_envelope(&gcs, "legacy-envelope");
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        store
            .with_user_read("legacy-envelope", |conn| {
                Ok(
                    conn.query_row("SELECT count(*) FROM screenshots", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                )
            })
            .await
            .unwrap();
        store.save_user("legacy-envelope").await.unwrap();
        assert_eq!(gcs.generation(&gcs_object_name("legacy-envelope")), Some(2));
    }

    fn make_store_with_limit(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
        max_open: usize,
    ) -> Store {
        Store::new_internal_with_max_open(kms, gcs, media_gcs, max_open)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_user_gcs_save_does_not_block_another_users_read_write_or_save() {
        let inner = Arc::new(FakeGcs::new());
        let blocked = Arc::new(BlockingPutGcs::new(
            Arc::clone(&inner),
            gcs_object_name("slow-user"),
        ));
        let store = Arc::new(make_store_with_limit(
            Arc::new(FakeKms),
            blocked.clone(),
            blocked.clone(),
            2,
        ));

        for user_id in ["slow-user", "fast-user"] {
            store
                .with_user(user_id, |_| Ok(()))
                .await
                .expect("preload user");
        }
        store
            .with_user("slow-user", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-08-01T00:00:00Z', 'slow')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("mutate slow user");

        let slow_store = Arc::clone(&store);
        let slow_save = tokio::spawn(async move { slow_store.save_user("slow-user").await });
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            blocked.wait_until_blocked(),
        )
        .await
        .expect("slow user's GCS PUT never reached the gate");

        let fast_result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let counts = store
                .with_user("fast-user", |conn| {
                    let before: i64 =
                        conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?;
                    conn.execute(
                        "INSERT INTO screenshots (captured_at, ocr_text) \
                         VALUES ('2026-08-01T00:00:01Z', 'fast')",
                        [],
                    )?;
                    let after: i64 =
                        conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?;
                    Ok((before, after))
                })
                .await?;
            store.save_user("fast-user").await?;
            Result::<_>::Ok(counts)
        })
        .await
        .expect("unrelated user was blocked by slow user's GCS PUT")
        .expect("unrelated user operation failed");
        assert_eq!(fast_result, (0, 1));

        blocked.release();
        slow_save
            .await
            .expect("slow save task panicked")
            .expect("slow save failed after release");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_user_connection_operations_remain_strictly_serialized() {
        let store = Arc::new(make_store());
        store
            .with_user("ordered-user", |_| Ok(()))
            .await
            .expect("preload user");

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_store = Arc::clone(&store);
        let first = tokio::spawn(async move {
            first_store
                .with_user("ordered-user", move |conn| {
                    let _ = entered_tx.send(());
                    release_rx.recv().map_err(|_| {
                        EnclaveError::Store("same-user test release dropped".into())
                    })?;
                    conn.execute(
                        "INSERT INTO screenshots (captured_at, ocr_text) \
                         VALUES ('2026-08-01T00:00:00Z', 'first')",
                        [],
                    )?;
                    Ok(())
                })
                .await
        });
        entered_rx.await.expect("first operation did not enter");

        let second_entered = Arc::new(Notify::new());
        let second_signal = Arc::clone(&second_entered);
        let second_store = Arc::clone(&store);
        let second = tokio::spawn(async move {
            second_store
                .with_user("ordered-user", move |conn| {
                    second_signal.notify_one();
                    Ok(
                        conn.query_row("SELECT count(*) FROM screenshots", [], |row| {
                            row.get::<_, i64>(0)
                        })?,
                    )
                })
                .await
        });

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                second_entered.notified(),
            )
            .await
            .is_err(),
            "second same-user operation entered while the first still held the actor"
        );

        release_tx.send(()).expect("release first operation");
        first
            .await
            .expect("first operation task panicked")
            .expect("first operation failed");
        let observed = second
            .await
            .expect("second operation task panicked")
            .expect("second operation failed");
        assert_eq!(observed, 1, "second operation must observe the first");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_first_load_releases_its_capacity_reservation() {
        let inner = Arc::new(FakeGcs::new());
        let blocked = Arc::new(BlockingGetGcs::new(
            Arc::clone(&inner),
            gcs_object_name("cancelled-load-user"),
        ));
        let store = Arc::new(make_store_with_limit(
            Arc::new(FakeKms),
            blocked.clone(),
            blocked.clone(),
            1,
        ));

        let load_store = Arc::clone(&store);
        let load = tokio::spawn(async move {
            load_store
                .with_user("cancelled-load-user", |_| Ok(()))
                .await
        });
        blocked.wait_until_blocked().await;
        load.abort();
        assert!(load
            .await
            .expect_err("load task was not cancelled")
            .is_cancelled());

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            store.with_user("post-cancel-user", |_| Ok(())).await
        })
        .await
        .expect("cancelled Loading reservation permanently consumed STORE_MAX_OPEN")
        .expect("cold load after cancelled reservation failed");

        let registry = store.registry.lock().await;
        assert!(!registry.open_users.contains_key("cancelled-load-user"));
        assert!(registry.open_users.contains_key("post-cancel-user"));
        assert_eq!(registry.open_users.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_eviction_restores_the_victim_and_capacity() {
        let inner = Arc::new(FakeGcs::new());
        let blocked = Arc::new(BlockingPutGcs::new(
            Arc::clone(&inner),
            gcs_object_name("cancelled-eviction-user"),
        ));
        let kms = Arc::new(FakeKms);
        let store = Arc::new(make_store_with_limit(
            kms.clone(),
            blocked.clone(),
            blocked.clone(),
            1,
        ));
        store
            .with_user("cancelled-eviction-user", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-08-01T00:00:00Z', 'survives cancellation')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("mutate eviction victim");

        let newcomer_store = Arc::clone(&store);
        let newcomer = tokio::spawn(async move {
            newcomer_store
                .with_user("cancelled-new-user", |_| Ok(()))
                .await
        });
        blocked.wait_until_blocked().await;
        newcomer.abort();
        assert!(newcomer
            .await
            .expect_err("eviction task was not cancelled")
            .is_cancelled());

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            store.with_user("post-eviction-cancel", |_| Ok(())).await
        })
        .await
        .expect("cancelled Evicting transition permanently consumed STORE_MAX_OPEN")
        .expect("cold load after cancelled eviction failed");

        let fresh = Store::new(kms, inner);
        let persisted: i64 = fresh
            .with_user("cancelled-eviction-user", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .expect("reload cancelled eviction victim");
        assert_eq!(persisted, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deletion_fence_wins_against_an_inflight_first_load() {
        let inner = Arc::new(FakeGcs::new());
        let blocked = Arc::new(BlockingGetGcs::new(
            Arc::clone(&inner),
            gcs_object_name("load-race-user"),
        ));
        let store = Arc::new(make_store_with_limit(
            Arc::new(FakeKms),
            blocked.clone(),
            blocked.clone(),
            1,
        ));

        let load_store = Arc::clone(&store);
        let load =
            tokio::spawn(async move { load_store.with_user("load-race-user", |_| Ok(())).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            blocked.wait_until_blocked(),
        )
        .await
        .expect("first load never reached GCS");

        let delete_store = Arc::clone(&store);
        let deletion =
            tokio::spawn(async move { delete_store.delete_user("load-race-user").await });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if store
                    .registry
                    .lock()
                    .await
                    .blocked_users
                    .contains("load-race-user")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("deletion fence was not installed");

        blocked.release();
        assert!(matches!(
            load.await.expect("load task panicked"),
            Err(EnclaveError::Auth(_))
        ));
        deletion
            .await
            .expect("deletion task panicked")
            .expect("deletion failed");
        let registry = store.registry.lock().await;
        assert!(registry.blocked_users.contains("load-race-user"));
        assert!(registry.open_users.is_empty());
    }

    #[tokio::test]
    async fn failed_eviction_preserves_the_live_handle_and_unsaved_changes() {
        let inner = Arc::new(FakeGcs::new());
        let failing = Arc::new(FailPutOnceGcs {
            inner: Arc::clone(&inner),
            target: gcs_object_name("eviction-user"),
            fail_once: AtomicBool::new(true),
        });
        let kms = Arc::new(FakeKms);
        let store = make_store_with_limit(kms.clone(), failing.clone(), failing, 1);

        store
            .with_user("eviction-user", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-08-01T00:00:00Z', 'must survive')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("mutate eviction victim");

        assert!(matches!(
            store.with_user("new-user", |_| Ok(())).await,
            Err(EnclaveError::Gcs(_))
        ));
        let count: i64 = store
            .with_user("eviction-user", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .expect("victim handle was discarded after failed eviction");
        assert_eq!(count, 1);

        store
            .save_user("eviction-user")
            .await
            .expect("retry save should succeed");
        let fresh = Store::new(kms, inner);
        let persisted: i64 = fresh
            .with_user("eviction-user", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .expect("reload saved eviction victim");
        assert_eq!(persisted, 1);
    }

    #[tokio::test]
    async fn save_after_completed_intervening_eviction_is_idempotent_success() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let store = make_store_with_limit(kms.clone(), gcs.clone(), gcs.clone(), 1);

        store
            .with_user("evicted-before-save", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-08-01T00:00:00Z', 'already flushed')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("mutate first user");

        // With one slot, this cannot complete without flushing and dropping
        // the first user's last strong actor reference.
        store
            .with_user("evicting-user", |_| Ok(()))
            .await
            .expect("evict first user");
        assert!(store
            .registry
            .lock()
            .await
            .actors
            .get("evicted-before-save")
            .is_some_and(|actor| actor.upgrade().is_none()));

        store
            .save_user("evicted-before-save")
            .await
            .expect("intervening eviction already performed this save");
        assert!(matches!(
            store.save_user("never-opened-user").await,
            Err(EnclaveError::NotFound)
        ));

        let fresh = Store::new(kms, gcs);
        let persisted: i64 = fresh
            .with_user("evicted-before-save", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .expect("reload eviction-flushed data");
        assert_eq!(persisted, 1);
    }

    #[tokio::test]
    async fn save_queued_behind_an_inflight_eviction_observes_its_flush() {
        let inner = Arc::new(FakeGcs::new());
        let blocked = Arc::new(BlockingPutGcs::new(
            Arc::clone(&inner),
            gcs_object_name("queued-save-user"),
        ));
        let store = Arc::new(make_store_with_limit(
            Arc::new(FakeKms),
            blocked.clone(),
            blocked.clone(),
            1,
        ));
        store
            .with_user("queued-save-user", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-08-01T00:00:00Z', 'queued save')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("mutate eviction victim");

        let newcomer_store = Arc::clone(&store);
        let newcomer = tokio::spawn(async move {
            newcomer_store
                .with_user("queued-new-user", |_| Ok(()))
                .await
        });
        blocked.wait_until_blocked().await;

        let save_store = Arc::clone(&store);
        let queued_save =
            tokio::spawn(async move { save_store.save_user("queued-save-user").await });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let save_has_actor = store
                    .registry
                    .lock()
                    .await
                    .actors
                    .get("queued-save-user")
                    .is_some_and(|actor| actor.strong_count() >= 3);
                if save_has_actor {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("save never queued behind the evicting actor");

        blocked.release();
        newcomer
            .await
            .expect("newcomer task panicked")
            .expect("newcomer load failed");
        queued_save
            .await
            .expect("queued save task panicked")
            .expect("eviction flush should satisfy queued save");
    }

    #[test]
    fn clean_eviction_completion_registry_is_bounded() {
        let mut registry = StoreRegistry {
            actors: HashMap::new(),
            open_users: HashMap::new(),
            blocked_users: HashSet::new(),
            pending_deletion_media: HashMap::new(),
            recent_clean_evictions: HashMap::new(),
            access_clock: 0,
        };
        for index in 0..100 {
            registry.record_clean_eviction(&format!("user-{index}"), 1);
        }
        assert_eq!(registry.recent_clean_evictions.len(), 64);
    }

    #[tokio::test]
    async fn failed_deletion_releases_capacity_without_losing_retry_inventory() {
        let database_gcs = Arc::new(FakeGcs::new());
        let media_inner = Arc::new(FakeGcs::new());
        let media_key = "media/local-only";
        let failing_media = Arc::new(FailDeleteOnceGcs {
            inner: Arc::clone(&media_inner),
            target: media_key.to_string(),
            fail_once: AtomicBool::new(true),
            delete_calls: AtomicUsize::new(0),
        });
        failing_media
            .put_object(media_key, b"ciphertext", "wrapped", 0)
            .await
            .expect("seed media object");

        let store = make_store_with_limit(
            Arc::new(FakeKms),
            database_gcs.clone(),
            failing_media.clone(),
            1,
        );
        store
            .with_user("delete-user", |conn| {
                conn.execute_batch("PRAGMA foreign_keys=OFF;")?;
                conn.execute(
                    "INSERT INTO media_objects \
                     (asset_id,event_id,object_key,mime_type,codec,byte_length,sha256) \
                     VALUES ('local-asset','local-event','media/local-only', \
                             'image/jpeg','jpeg',1,'local-sha')",
                    [],
                )?;
                conn.execute_batch("PRAGMA foreign_keys=ON;")?;
                Ok(())
            })
            .await
            .expect("record locally-only media key");

        assert!(matches!(
            store.delete_user("delete-user").await,
            Err(EnclaveError::Gcs(_))
        ));
        {
            let registry = store.registry.lock().await;
            assert!(
                registry.open_users.is_empty(),
                "failed delete pinned capacity"
            );
            assert_eq!(
                registry
                    .pending_deletion_media
                    .get("delete-user")
                    .map(AsRef::as_ref),
                Some([media_key.to_string()].as_slice())
            );
        }

        // Phase 0d deliberately has no durable deletion ledger: a restarted
        // Store does not inherit this locally-only inventory. The remote DB is
        // retained on failure, but unsaved media keys require the later
        // encrypted ADR-0022 deletion ledger for crash-safe recovery.
        let restarted =
            make_store_with_limit(Arc::new(FakeKms), database_gcs, failing_media.clone(), 1);
        assert!(restarted
            .registry
            .lock()
            .await
            .pending_deletion_media
            .is_empty());

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            store.with_user("unrelated-user", |_| Ok(())).await?;
            store.save_user("unrelated-user").await
        })
        .await
        .expect("blocked failed deletion starved the only open slot")
        .expect("unrelated user failed after deletion error");

        store
            .delete_user("delete-user")
            .await
            .expect("deletion retry should use retained media inventory");
        assert_eq!(failing_media.delete_calls.load(Ordering::SeqCst), 2);
        assert!(!media_inner.objects.lock().unwrap().contains_key(media_key));
        let registry = store.registry.lock().await;
        assert!(!registry.pending_deletion_media.contains_key("delete-user"));
        assert_eq!(registry.open_users.len(), 1);
        assert!(registry.open_users.contains_key("unrelated-user"));
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
    async fn snapshot_metrics_use_pre_checkpoint_wal_as_changed_byte_proxy() {
        let store = make_store();

        // Establish a checkpointed baseline so schema creation/migration WAL
        // frames do not become part of the changed-write assertion.
        store
            .with_user("metric-user", |_| Ok(()))
            .await
            .expect("load");
        store.save_user("metric-user").await.expect("baseline save");

        store
            .with_user("metric-user", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-01-01T00:00:00Z', 'synthetic')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("write");

        let wal_bytes_before_save = {
            let actor = store.actor_for_access("metric-user").await.unwrap();
            let state = actor.state.lock().await;
            let handle = state.handle.as_ref().expect("open handle");
            std::fs::metadata(sqlite_sidecar_path(&handle.temp_path, "-wal"))
                .expect("WAL metadata")
                .len()
        };
        assert!(wal_bytes_before_save > 0, "mutation must create WAL frames");

        let before_changed = store.storage_metrics_snapshot();
        store.save_user("metric-user").await.expect("changed save");
        let after_changed = store.storage_metrics_snapshot();
        assert_eq!(
            after_changed.changed_wal_bytes_proxy.count,
            before_changed.changed_wal_bytes_proxy.count + 1
        );
        assert_eq!(
            after_changed
                .changed_wal_bytes_proxy
                .sum
                .saturating_sub(before_changed.changed_wal_bytes_proxy.sum),
            wal_bytes_before_save
        );
        assert_eq!(
            after_changed.write_amplification_ppm.count,
            before_changed.write_amplification_ppm.count + 1
        );

        // A second save with forced dirty marking (e.g. with_user_mut without
        // SQL changes) still rewrites the complete encrypted database. Its
        // observed WAL denominator is zero, so the amplification sample must
        // be +Inf (the final bucket only).
        store
            .with_user_mut("metric-user", |_| Ok(()))
            .await
            .expect("mut access without sql");

        let wal_bytes_before_noop = {
            let actor = store.actor_for_access("metric-user").await.unwrap();
            let state = actor.state.lock().await;
            let handle = state.handle.as_ref().expect("open handle");
            std::fs::metadata(sqlite_sidecar_path(&handle.temp_path, "-wal"))
                .map(|metadata| metadata.len())
                .unwrap_or(0)
        };
        assert_eq!(wal_bytes_before_noop, 0);

        let before_noop = store.storage_metrics_snapshot();
        store.save_user("metric-user").await.expect("no-op save");
        let after_noop = store.storage_metrics_snapshot();
        assert_eq!(
            after_noop.changed_wal_bytes_proxy.count,
            before_noop.changed_wal_bytes_proxy.count + 1
        );
        assert_eq!(
            after_noop.changed_wal_bytes_proxy.sum,
            before_noop.changed_wal_bytes_proxy.sum
        );
        assert_eq!(after_noop.write_amplification_ppm.max, u64::MAX);
        for index in 0..AMPLIFICATION_PPM_BUCKET_UPPER_BOUNDS.len() - 1 {
            assert_eq!(
                after_noop.write_amplification_ppm.cumulative_buckets[index],
                before_noop.write_amplification_ppm.cumulative_buckets[index]
            );
        }
        assert_eq!(
            after_noop.write_amplification_ppm.cumulative_buckets[9],
            before_noop.write_amplification_ppm.cumulative_buckets[9] + 1
        );
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

    /// Write data for a user and delete it. The process-local deletion fence
    /// must prevent an in-flight stale request from recreating the index.
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

        assert!(matches!(
            store.with_user("dave", |_| Ok(())).await,
            Err(EnclaveError::Auth(_))
        ));
        assert!(matches!(
            store.save_user("dave").await,
            Err(EnclaveError::Auth(_))
        ));
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

    #[tokio::test]
    async fn account_deletion_paginates_and_removes_all_user_generations_only() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        write_and_save(&store, "alice", "init").await.unwrap();
        let index = gcs_object_name("alice");
        let live = gcs.get_object(&index).await.unwrap();
        gcs.put_object(
            &index,
            &live.ciphertext,
            &live.wrapped_dek_b64,
            live.generation,
        )
        .await
        .unwrap();
        for name in ["raw/alice/a.enc", "raw/alice/b.enc"] {
            let first = gcs
                .put_object(name, b"ciphertext", "wrapped", 0)
                .await
                .unwrap();
            gcs.put_object(name, b"ciphertext-2", "wrapped", first)
                .await
                .unwrap();
        }
        let checkpoint_source = gcs.get_object(&index).await.unwrap();
        let checkpoint = "legacy-recovery/alice/day-1.db.enc";
        gcs.put_object(
            checkpoint,
            &checkpoint_source.ciphertext,
            &checkpoint_source.wrapped_dek_b64,
            0,
        )
        .await
        .unwrap();
        gcs.put_object("raw/alice-other/keep.enc", b"other", "wrapped", 0)
            .await
            .unwrap();
        gcs.put_object("raw/bob/keep.enc", b"other", "wrapped", 0)
            .await
            .unwrap();

        store.delete_user("alice").await.unwrap();

        assert_eq!(gcs.version_count(&index), 0);
        assert_eq!(gcs.version_count("raw/alice/"), 0);
        assert_eq!(gcs.version_count("legacy-recovery/alice/"), 0);
        assert_eq!(gcs.version_count("raw/bob/"), 1);
        assert_eq!(gcs.version_count("raw/alice-other/"), 1);
    }

    #[tokio::test]
    async fn account_deletion_retries_after_exact_generation_failure_and_not_found() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        write_and_save(&store, "alice", "init").await.unwrap();
        let media = "raw/alice/retry.enc";
        let first = gcs.put_object(media, b"one", "wrapped", 0).await.unwrap();
        let second = gcs
            .put_object(media, b"two", "wrapped", first)
            .await
            .unwrap();
        gcs.fail_next_generation_delete(media, second);

        assert!(store.delete_user("alice").await.is_err());
        // The first generation may already be gone; retry must tolerate it.
        store.delete_user("alice").await.unwrap();
        assert_eq!(gcs.version_count(media), 0);
    }

    #[tokio::test]
    async fn preexisting_soft_residue_does_not_block_live_version_cleanup() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        write_and_save(&store, "alice", "v1").await.unwrap();
        let index = gcs_object_name("alice");
        let old_generation = gcs.get_object(&index).await.unwrap().generation;
        write_and_save(&store, "alice", "v2").await.unwrap();
        gcs.soft_delete_generation(&index, old_generation);
        gcs.set_soft_delete_enabled(true);

        assert!(matches!(
            store.delete_user("alice").await,
            Err(EnclaveError::Conflict(_))
        ));
        assert_eq!(gcs.version_count(&index), 0);
        assert_eq!(gcs.soft_deleted_count(&index), 2);
    }

    #[tokio::test]
    async fn post_delete_soft_inventory_prevents_success_when_policy_is_enabled() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        write_and_save(&store, "alice", "init").await.unwrap();
        gcs.put_object("raw/alice/capture.enc", b"media", "wrapped", 0)
            .await
            .unwrap();
        gcs.set_soft_delete_enabled(true);

        assert!(matches!(
            store.delete_user("alice").await,
            Err(EnclaveError::Conflict(_))
        ));
        assert!(gcs.soft_deleted_count(&gcs_object_name("alice")) > 0);
        assert_eq!(gcs.soft_deleted_count("raw/alice/"), 1);
    }

    #[tokio::test]
    async fn blocked_retry_keeps_live_db_inventory_for_unscoped_media() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        let media = "media/opaque-evidence-key";
        store
            .with_user("alice", |conn| insert_screenshot_evidence(conn, media))
            .await
            .unwrap();
        store.save_user("alice").await.unwrap();
        let first = gcs.put_object(media, b"one", "wrapped", 0).await.unwrap();
        let second = gcs
            .put_object(media, b"two", "wrapped", first)
            .await
            .unwrap();
        gcs.fail_next_generation_delete(media, second);

        assert!(store.delete_user("alice").await.is_err());
        assert_eq!(gcs.version_count(media), 1);
        store.delete_user("alice").await.unwrap();
        assert_eq!(gcs.version_count(media), 0);
    }

    #[tokio::test]
    async fn historical_database_generation_inventories_removed_unscoped_evidence() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        let media = "media/historical-only-evidence";
        store
            .with_user("alice", |conn| insert_screenshot_evidence(conn, media))
            .await
            .unwrap();
        store.save_user("alice").await.unwrap();
        store
            .with_user("alice", |conn| {
                conn.execute("DELETE FROM screenshot_images", [])?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user("alice").await.unwrap();
        gcs.put_object(media, b"historical", "wrapped", 0)
            .await
            .unwrap();

        store.delete_user("alice").await.unwrap();
        assert_eq!(gcs.version_count(media), 0);
        assert_eq!(gcs.version_count(&gcs_object_name("alice")), 0);
    }

    #[tokio::test]
    async fn unreadable_recovery_generation_keeps_deletion_incomplete() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        write_and_save(&store, "alice", "init").await.unwrap();
        let recovery = "legacy-recovery/alice/unreadable.db.enc";
        gcs.put_object(
            recovery,
            b"not-an-encrypted-database",
            "not-a-wrapped-key",
            0,
        )
        .await
        .unwrap();

        let deletion = store.delete_user("alice").await;
        assert!(
            matches!(
                deletion,
                Err(EnclaveError::Conflict(ref message)) if message.contains("inventor")
            ),
            "unexpected deletion result: {deletion:?}"
        );
        assert_eq!(gcs.version_count(recovery), 1);
    }

    #[tokio::test]
    async fn oversized_legacy_generation_fails_before_snapshot_download() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        write_and_save(&store, "alice", "init").await.unwrap();
        let index = gcs_object_name("alice");
        gcs.set_listed_size(&index, MAX_LEGACY_DELETION_SNAPSHOT_BYTES + 1);

        assert!(matches!(
            store.delete_user("alice").await,
            Err(EnclaveError::Conflict(_))
        ));
        assert_eq!(gcs.exact_generation_get_count(), 0);
        assert_eq!(gcs.version_count(&index), 1);
    }

    #[tokio::test]
    async fn repeated_version_cursor_fails_closed() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        for suffix in ["-a", "-b", "-c"] {
            gcs.put_object(
                &format!("indexes/alice.db.enc{suffix}"),
                b"other",
                "wrapped",
                0,
            )
            .await
            .unwrap();
        }
        gcs.set_repeat_version_cursor(true);
        assert!(matches!(
            store
                .delete_all_versions_for_name(&store.gcs, "indexes/alice.db.enc")
                .await,
            Err(EnclaveError::Gcs(message)) if message.contains("repeated")
        ));
    }

    #[tokio::test]
    async fn repeated_soft_delete_cursor_fails_closed() {
        let gcs = Arc::new(FakeGcs::new());
        for suffix in ["-a", "-b", "-c"] {
            let name = format!("indexes/alice.db.enc{suffix}");
            let generation = gcs.put_object(&name, b"other", "wrapped", 0).await.unwrap();
            gcs.soft_delete_generation(&name, generation);
        }
        gcs.set_soft_delete_enabled(true);
        gcs.set_repeat_version_cursor(true);
        assert!(matches!(
            has_matching_soft_deleted_object(gcs.as_ref(), "indexes/alice.db.enc", true).await,
            Err(EnclaveError::Gcs(message)) if message.contains("repeated")
        ));
    }

    #[test]
    fn soft_delete_policy_disabled_400_is_empty_only_on_first_page() {
        let body = br#"{"error":{"code":400,"errors":[{"reason":"invalidArgument"}]}}"#;
        let first = decode_soft_deleted_list_response(reqwest::StatusCode::BAD_REQUEST, body, true)
            .unwrap();
        assert!(first.versions.is_empty());
        assert!(
            decode_soft_deleted_list_response(reqwest::StatusCode::BAD_REQUEST, body, false,)
                .is_err()
        );
    }

    #[test]
    fn soft_delete_listing_does_not_mask_other_bad_requests() {
        for body in [
            br#"{"error":{"code":400,"errors":[{"reason":"badRequest"}]}}"#.as_slice(),
            br#"{"error":{"code":400,"errors":[]}}"#.as_slice(),
            br#"not-json"#.as_slice(),
        ] {
            assert!(decode_soft_deleted_list_response(
                reqwest::StatusCode::BAD_REQUEST,
                body,
                true,
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn copied_user_blob_cannot_be_opened_as_another_user() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        store
            .with_user("alice", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES ('2026-01-01T00:00:00Z', 'alice secret')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user("alice").await.unwrap();

        let alice_object = gcs_object_name("alice");
        let bob_object = gcs_object_name("bob");
        {
            let mut objects = gcs.objects.lock().unwrap();
            let copied = objects.get(&alice_object).unwrap().clone();
            objects.insert(bob_object, copied);
        }

        let fresh = Store::new(Arc::new(FakeKms), gcs);
        assert!(matches!(
            fresh.with_user("bob", |_| Ok(())).await,
            Err(EnclaveError::Crypto(_))
        ));
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

    #[test]
    fn selected_evidence_media_key_is_validated_and_owner_scoped() {
        let opaque_key = "0123456789abcdef0123456789abcdef";
        let alice = selected_evidence_media_object_key("alice-1", opaque_key).unwrap();
        let bob = selected_evidence_media_object_key("bob-2", opaque_key).unwrap();
        assert_eq!(
            alice,
            "raw/alice-1/evidence/0123456789abcdef0123456789abcdef.enc"
        );
        assert_eq!(
            bob,
            "raw/bob-2/evidence/0123456789abcdef0123456789abcdef.enc"
        );
        assert_ne!(alice, bob, "owners must never share an evidence prefix");

        for invalid in [
            "",
            "0123456789abcdef0123456789abcde",   // short
            "0123456789abcdef0123456789abcdef0", // long
            "0123456789ABCDEF0123456789ABCDEF",  // uppercase
            "0123456789abcdef0123456789abcde/",  // path separator
        ] {
            assert!(
                selected_evidence_media_object_key("alice-1", invalid).is_err(),
                "opaque key {invalid:?} should be rejected"
            );
        }
        assert!(selected_evidence_media_object_key("alice/../bob", opaque_key).is_err());
    }

    #[tokio::test]
    async fn selected_evidence_media_key_writes_reads_and_deletes_with_bound_context() {
        let user_id = "selected-evidence-owner";
        let object_key =
            selected_evidence_media_object_key(user_id, "0123456789abcdef0123456789abcdef")
                .unwrap();
        let store = make_store();
        let (dek, wrapped_dek) = generate_and_wrap_dek(store.kms.as_ref()).await.unwrap();
        let ciphertext = encrypt_bound_blob(
            &dek,
            b"selected screenshot evidence",
            &media_blob_context(user_id, &object_key),
        )
        .unwrap();

        store
            .put_media(&object_key, &ciphertext, &wrapped_dek)
            .await
            .unwrap();
        let stored = store.get_media(&object_key).await.unwrap();
        let opened = decrypt_bound_blob(
            &dek,
            &stored.ciphertext,
            &media_blob_context(user_id, &object_key),
        )
        .unwrap();
        assert_eq!(opened.plaintext, b"selected screenshot evidence");
        assert!(decrypt_bound_blob(
            &dek,
            &stored.ciphertext,
            &media_blob_context("other-owner", &object_key),
        )
        .is_err());

        store.delete_media(&object_key).await.unwrap();
        assert!(matches!(
            store.get_media(&object_key).await,
            Err(EnclaveError::NotFound)
        ));
    }

    #[test]
    fn migrations_install_cloud_capture_schema_and_media_cleanup_finds_every_object() {
        init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_SQL).unwrap();
        run_migrations(&conn).unwrap();

        let media_table: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='media_objects'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(media_table, 1);

        conn.execute(
            "INSERT INTO capture_sessions \
             (id,device_id,install_id,started_at,last_event_at,schema_version) \
             VALUES ('session','device','install','2026-01-01T00:00:00Z','2026-01-01T00:00:01Z',2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO capture_streams (id,capture_session_id,device_id,stream_kind) \
             VALUES ('stream','session','device','mic')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO capture_events \
             (event_id,device_id,install_id,capture_session_id,stream_id,stream_kind,sequence, \
              source_wall_at,source_monotonic_ns,started_at,ended_at,timezone_id,utc_offset_minutes, \
              clock_uncertainty_ms,asset_id,manifest_digest) \
             VALUES ('event','device','install','session','stream','mic',0, \
                     '2026-01-01T00:00:00Z','1','2026-01-01T00:00:00Z', \
                     '2026-01-01T00:00:01Z','UTC',0,1,'asset', \
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO media_objects \
             (asset_id,event_id,object_key,mime_type,codec,byte_length,sha256) \
             VALUES ('asset','event','raw/cloud','audio/m4a','aac',1, \
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
            [],
        )
        .unwrap();

        assert_eq!(media_keys(&conn).unwrap(), vec!["raw/cloud".to_string()]);
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
        // The initial create has no previous generation to protect. Its first
        // overwrite establishes the daily recovery copy.
        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES ('2026-01-01T00:00:01Z', 'y')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("second write");
        store.save_user(user_id).await.expect("second save");

        let objects = gcs.objects.lock().unwrap();
        let expected = format!("indexes/{user_id}.db.enc");
        assert!(
            objects.contains_key(&expected),
            "expected GCS object {expected:?}, found keys: {:?}",
            objects.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            objects.len(),
            2,
            "only the index and its named daily recovery checkpoint should be written"
        );
        assert!(
            objects
                .keys()
                .any(|name| name.starts_with(&format!("legacy-recovery/{user_id}/"))),
            "expected named daily recovery checkpoint"
        );
    }

    #[tokio::test]
    async fn email_deliveries_outbox_operations() {
        let store = make_store();
        let user_id = "test-email-outbox-user";

        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO episodes (id, started_at, ended_at, title, summary, substance)
                     VALUES (100, '2026-07-30T10:00:00Z', '2026-07-30T10:30:00Z', 'Test Title', 'Test Summary', 'normal')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        // Enqueue delivery
        let id1 = store
            .enqueue_email_delivery(user_id, 100, 1, false)
            .await
            .unwrap();
        assert!(id1.starts_with("deliv_"));

        // Duplicate episode_id & delivery_version cannot enqueue twice
        assert!(store
            .enqueue_email_delivery(user_id, 100, 1, true)
            .await
            .is_err());

        // Query due row
        let due = store
            .next_email_delivery(user_id)
            .await
            .unwrap()
            .expect("due row");
        assert_eq!(due.episode_id, 100);
        assert_eq!(due.delivery_version, 1);
        assert_eq!(due.delivery_id, id1);
        assert!(!due.include_content);
        assert_eq!(due.state, "pending");

        // Update state to accepted
        store
            .update_email_delivery_state(
                user_id,
                100,
                1,
                "accepted",
                1,
                Some("msg_resend_1"),
                Some(200),
                None,
            )
            .await
            .unwrap();

        // No more due rows
        assert!(store.next_email_delivery(user_id).await.unwrap().is_none());
    }
}
