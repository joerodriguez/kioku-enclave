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
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    ffi::{CStr, CString},
    hash::{Hash, Hasher},
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicI64, Ordering as AtomicOrdering},
        Arc, Once, RwLock as StdRwLock, Weak,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
use std::collections::VecDeque;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use rusqlite::{ffi::sqlite3_auto_extension, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlite_vec::sqlite3_vec_init;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::{
    archive_v3_maintenance_import::{
        AuthenticatedMaintenanceImportPlan, MaintenanceImportOperationId, MaintenanceSourceBinding,
        MaintenanceStorePlanView,
    },
    archive_v3_shadow_parity::AuthenticatedWalOwnerStaging,
    archive_v3_sqlite_vfs::{
        CaptureRegistration, CaptureRegistry, OwnedCapturedDrain, RegisteredCaptureVfs,
    },
    archive_v3_wal_idempotency::{
        ErasedPreparedLogicalMutation, ErasedPreparedLookup, ErasedValidatedWalLogicalResult,
        LogicalMutationDisposition, WalIdempotencyError,
    },
    archive_v3_wal_owner::{
        WalOperationIdentity, WalOwnerAttempt, WalOwnerContext, WalOwnerError, WalOwnerInstanceId,
        WalOwnerStoreBinding, WalOwnerStoreContext,
    },
    crypto::{
        decrypt_bound_blob, encrypt_bound_blob, generate_and_wrap_dek, load_dek, Dek, KmsClient,
    },
    error::{DeletionPending, DeletionPendingReason, EnclaveError, Result},
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

const LEGACY_WRITE_INTENT_FORMAT_VERSION: u8 = 1;
const LEGACY_WRITE_INTENT_METADATA: &str = "kioku-legacy-write-intent-v1";
const LEGACY_WRITE_INTENT_PREFIX: &str = "control/legacy-write-intents";
const LEGACY_WRITE_PROVIDER_TIMEOUT: Duration = Duration::from_secs(300);
const LEGACY_WRITE_PROVIDER_SAFETY_MILLIS: i64 = 60_000;
// Production GCS requests are bounded at five minutes. Takeover waits an
// additional minute so an expired owner cannot still have a provider request
// capable of committing after the replacement owner settles the intent.
const LEGACY_WRITE_INTENT_LEASE_MILLIS: i64 = 360_000;
const IDENTITY_REBIND_FENCE_METADATA: &str = "kioku-identity-rebind-fence-v1";

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

/// Build the sole object key accepted for a canonical Cloud Capture asset.
///
/// This mirrors the capture manifest's opaque-ID grammar so a persisted
/// `media_objects.object_key` can be re-derived from authenticated account and
/// asset identity instead of being trusted as a provider routing capability.
pub(crate) fn canonical_capture_media_object_key(user_id: &str, asset_id: &str) -> Result<String> {
    validate_user_id(user_id)?;
    let valid_asset_id = !asset_id.is_empty()
        && asset_id.len() <= 128
        && asset_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid_asset_id {
        return Err(EnclaveError::InvalidRequest(
            "invalid canonical capture asset identifier".into(),
        ));
    }
    Ok(format!("raw/{user_id}/{asset_id}.enc"))
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
    /// Rust drops fields in declaration order: ordinary teardown closes SQLite
    /// before retiring this registration. The reviewed advisory terminal may
    /// take and retire it in place while the legacy connection stays open.
    conn: Connection,
    _shadow_capture_registration: Option<CaptureRegistration>,
    blob_meta: BlobMeta,
    /// Monotonic process-local generation advanced whenever SQLite reports a
    /// possible persistent logical mutation. `dirty` remains the fail-closed
    /// authority if this diagnostic counter ever saturates.
    mutation_generation: u64,
    persisted_mutation_generation: u64,
    dirty: bool,
    temp_path: PathBuf,
}

/// Persistence authority selected only at construction. Production remains
/// on the legacy whole-snapshot path. The inactive WAL-only policy is a
/// fail-closed test seam: it permits guarded reads but cannot acknowledge or
/// persist an unauthenticated logical mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StorePersistencePolicy {
    LegacySnapshot,
    WalLogicalOnly,
    /// The read-write connection a WAL owner serves from.
    ///
    /// Unlike [`Self::LegacySnapshot`] this open runs **no** DDL. An
    /// archive-v3 owner pins its schema into checkpoint commitments, so any
    /// page the open path wrote outside the publication protocol would
    /// diverge the live database from the bytes the owner authenticated. The
    /// schema is therefore established once, at genesis, and afterwards only
    /// ever advanced by a sealed plan under the owner's own lease.
    ///
    /// "No DDL" is a prohibition on mutation, not on inspection: the open path
    /// is *required* to read the archive's epoch marker and refuse an archive
    /// this binary cannot describe, and it asserts the mutation fingerprint on
    /// both sides of doing so.
    WalOwnerAuthoritative,
}

/// The shared store, wrapped in Arc so handlers can clone it cheaply.
pub struct Store {
    registry: Mutex<StoreRegistry>,
    registry_changed: Arc<Notify>,
    lifecycle_gates: Mutex<HashMap<UserId, Arc<Mutex<()>>>>,
    /// Admission barrier for operations which can create a raw object outside
    /// the SQLite actor.  It is deliberately separate from the async actor
    /// mutex so a GCS PUT can remain in an owned task without holding a SQLite
    /// connection, while deletion can still atomically close admission and
    /// wait for every admitted writer to settle.
    content_write_barrier: Arc<ContentWriteBarrier>,
    /// Inactive exact-user local-only selection. Every production constructor
    /// stores `None`; only the consuming advisory release transition may
    /// install one selection while both local admission gates are still
    /// closed. No startup/config/provider path can select a user.
    shadow_capture: StdRwLock<Option<StoreShadowCaptureSelection>>,
    persistence_policy: StorePersistencePolicy,
    /// Inactive per-user WAL-authority persistence selections. Every
    /// production constructor starts empty; the only installer consumes the
    /// sealed Control-minted selection selected off the durable
    /// `wal_authoritative` maintenance-import terminal, and there is no
    /// removal: a selected user can never fall back to snapshot persistence.
    wal_authority_persistence: StdRwLock<HashMap<UserId, [u8; 16]>>,
    /// Inactive per-user WAL serving slots. Registered only by the
    /// config-gated startup relaunch after reconstruction; empty in every
    /// production constructor today. A selected user with no registered
    /// slot refuses reads rather than ever serving the stale legacy
    /// snapshot. Registration is install-once and there is no removal; the
    /// authority *inside* a slot is replaceable under the slot's own guard.
    wal_serving_authorities: StdRwLock<HashMap<UserId, Arc<WalServingLane>>>,
    /// The in-process relaunch driver, installed once at startup. Absent in
    /// every production constructor and in every test that does not install
    /// one, in which case a terminal slot simply stays terminal — exactly
    /// today's behaviour.
    wal_serving_relaunch: StdRwLock<Option<Arc<dyn WalServingRelaunch>>>,
    pub kms: Arc<dyn KmsClient>,
    pub gcs: Arc<dyn GcsClient>,
    /// Current media write/read bucket. New capture objects are written here.
    pub media_gcs: Arc<dyn GcsClient>,
    /// Migration-only source for media that predates the current media bucket.
    /// Reads fall back here only after the current bucket returns NotFound;
    /// cleanup scans both providers because bucket identity is not inferable
    /// from a historical database key.
    pub legacy_media_gcs: Arc<dyn GcsClient>,
    max_open: usize,
    checkpoint_clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    storage_metrics: StorageMetrics,
    legacy_checkpoint_reconciliation: Mutex<LegacyCheckpointReconciliation>,
    /// HMAC key for identity-unlinkable retained fence object names. In
    /// production this is the KMS-unwrapped control-store DEK, installed only
    /// after that exact encrypted control generation is durable.
    legacy_fence_key: StdRwLock<Option<Zeroizing<[u8; 32]>>>,
    /// The archive-v3 deletion lane, installed once at startup when the image
    /// carries an archive-v3 runtime. Absent in every production constructor
    /// today, which is exactly why `delete_account_content` still fails closed
    /// as `archive_v3_deletion_unwired` for a WAL-authoritative account rather
    /// than letting the legacy sweep vacuously succeed.
    ///
    /// It is not per-user: deletion tombstones the archive binding first, so a
    /// mid-deletion restart has no selection to key off and the lane must be
    /// constructible for an archive that no longer appears in any startup
    /// scan.
    wal_deletion_lane: StdRwLock<Option<Arc<crate::archive_v3_deletion_lane::WalDeletionLane>>>,
}

// ── WAL serving slot: replaceable, never removable ───────────────────────────

/// How long the driver will wait for proof that the previous owner is dead.
pub(crate) const WAL_RELAUNCH_JOIN_DEADLINE: Duration = Duration::from_secs(30);
const WAL_RELAUNCH_BACKOFF_MIN: Duration = Duration::from_secs(1);
const WAL_RELAUNCH_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Wall-clock budget for healing one lane, measured from its first relaunch
/// attempt.
///
/// It MUST outlast the WAL owner lease with margin. A lane with no pending
/// durable owner work is fenced out of its own successor by three predicates
/// in `archive_v3_witness` — `exact_wal_owner_renewal_from` requires a strictly
/// advanced record, `exact_wal_owner_reacquire_from` requires
/// `last_server_tick >= previous.lease_expires_at_tick`, and the provider
/// fallback refuses with `Fenced` while `now < previous.lease_expires_at_tick`
/// — until its own lease lapses, at most `OWNER_LEASE_TICKS` (300) after the
/// last renewal. That wait is the cross-process fence and is not introduced
/// here: a process restart hits the identical three clauses. The budget is
/// deadline-based, and generous relative to the lease, precisely so such a lane
/// heals when the lease lapses instead of exhausting a short budget into a new
/// permanent terminal.
const WAL_RELAUNCH_WALL_DEADLINE: Duration = Duration::from_secs(900);
/// The `OWNER_LEASE_TICKS` value the wall deadline is sized against.
/// `wal_relaunch_wall_deadline_outlasts_the_owner_lease` pins that the
/// publisher still declares exactly this.
const WAL_OWNER_LEASE_TICKS_MIRROR: u64 = 300;
const _: () = assert!(
    WAL_RELAUNCH_WALL_DEADLINE.as_secs() >= WAL_OWNER_LEASE_TICKS_MIRROR * 3,
    "the relaunch budget must outlast the WAL owner lease with margin"
);

/// Why a serving lane stopped trying to heal itself. Every variant is terminal
/// for this process: the lane keeps refusing exactly as it does today, and only
/// a restart (or an operator) moves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalQuarantineReason {
    /// The previous owner could not be proven dead inside the join deadline.
    /// Never construct a successor over this: refusing is always safe.
    Stuck,
    /// The per-lane generation budget is spent.
    GenerationsExhausted,
    /// The wall-clock heal budget elapsed.
    DeadlineExceeded,
    /// The rebuilt authority bound an archive other than the one this slot was
    /// installed for.
    ArchiveMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalLaneState {
    Serving,
    Quarantined(WalQuarantineReason),
}

/// Outcome of one `recover_wal_serving_authority` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalRecoveryOutcome {
    /// The slot's authority is not terminal — either it never was, or another
    /// caller already replaced it. No launch was issued.
    AlreadyLive,
    /// A successor was built and atomically swapped into the slot.
    Replaced,
    /// A launch is not due yet, or the last one failed and is backing off.
    Backoff,
    Quarantined(WalQuarantineReason),
}

/// Per-lane relaunch budget and backoff ledger. Guarded by the lane's async
/// mutex; the guard is the single-flight token for the whole 12-step sequence.
struct WalRelaunchLedger {
    /// Successful swaps. Capped by `MAX_WAL_SERVING_GENERATIONS`, which is
    /// itself strictly below the durable per-operation attempt cap.
    installed_generations: u32,
    /// Failed builds. These deliberately do NOT consume the generation budget:
    /// a build that never produced a lane never minted a new owner instance id
    /// and so never burned a durable attempt. Charging them here would let a
    /// provider outage exhaust the generation budget before the wall deadline
    /// — and before the owner lease it is sized against — could ever be
    /// reached.
    launch_failures: u32,
    // `tokio::time::Instant` rather than `std::time::Instant`: identical in
    // production, and it lets the wall-deadline and backoff paths be driven
    // deterministically under a paused test clock instead of by real sleeping.
    first_attempt_at: Option<tokio::time::Instant>,
    next_attempt_at: Option<tokio::time::Instant>,
    backoff: Duration,
    state: WalLaneState,
}

impl WalRelaunchLedger {
    const fn fresh() -> Self {
        Self {
            installed_generations: 0,
            launch_failures: 0,
            first_attempt_at: None,
            next_attempt_at: None,
            backoff: WAL_RELAUNCH_BACKOFF_MIN,
            state: WalLaneState::Serving,
        }
    }

    fn defer(&mut self, now: tokio::time::Instant) {
        self.next_attempt_at = Some(now + self.backoff);
        self.backoff = (self.backoff * 2).min(WAL_RELAUNCH_BACKOFF_MAX);
    }
}

/// One user's WAL serving slot.
///
/// The slot is atomically REPLACEABLE and never removable. That is strictly
/// stronger than a remove-then-install pair: the slot holds exactly one
/// authority for its entire life, so there is never an instant with no
/// authority for a registered user, and no code path can leave a selected user
/// silently unregistered and then be raced by a fresh install. It is also why
/// `install_wal_serving_authority` keeps its install-once contract and why
/// there is deliberately no removal API.
pub(crate) struct WalServingLane {
    /// The only mutator is `Store::recover_wal_serving_authority`, and only
    /// while holding `relaunch`.
    current: StdRwLock<Arc<crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority>>,
    relaunch: Mutex<WalRelaunchLedger>,
    /// Pinned at install from the durable-terminal selection. A rebuilt
    /// authority that binds a different archive is refused, not swapped in.
    archive_id: [u8; 16],
    generation: std::sync::atomic::AtomicU64,
    /// EVENT counters, not state counters: a genuine-corruption -> heal loop
    /// that stays under budget must not be able to heal silently.
    relaunches_total: std::sync::atomic::AtomicU64,
    launch_failures_total: std::sync::atomic::AtomicU64,
    quarantines_total: std::sync::atomic::AtomicU64,
}

impl WalServingLane {
    fn install(
        archive_id: [u8; 16],
        authority: Arc<crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority>,
    ) -> Self {
        Self {
            current: StdRwLock::new(authority),
            relaunch: Mutex::new(WalRelaunchLedger::fresh()),
            archive_id,
            generation: std::sync::atomic::AtomicU64::new(0),
            relaunches_total: std::sync::atomic::AtomicU64::new(0),
            launch_failures_total: std::sync::atomic::AtomicU64::new(0),
            quarantines_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The authority currently holding this archive. A poisoned slot lock
    /// cannot be recovered into a safe answer, so callers treat the error as
    /// unavailable rather than launching over an unknown owner.
    fn current(
        &self,
    ) -> Result<Arc<crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority>> {
        self.current
            .read()
            .map(|current| Arc::clone(&current))
            .map_err(|_| EnclaveError::Store("wal serving slot poisoned".into()))
    }

    #[cfg(test)]
    pub(crate) fn generation_for_test(&self) -> u64 {
        self.generation.load(AtomicOrdering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn is_terminal_for_test(&self) -> bool {
        self.current().is_ok_and(|current| current.is_terminal())
    }

    #[cfg(test)]
    pub(crate) fn authority_for_test(
        &self,
    ) -> Arc<crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority> {
        self.current().expect("test slot is readable")
    }

    #[cfg(test)]
    pub(crate) async fn ledger_for_test(&self) -> (u32, u32, WalLaneState) {
        let guard = self.relaunch.lock().await;
        (
            guard.installed_generations,
            guard.launch_failures,
            guard.state,
        )
    }
}

/// Content-free aggregate serving health. Counts only — never a user id, an
/// archive id, or any other content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalServingHealth {
    pub serving: usize,
    pub terminal: usize,
    pub quarantined: usize,
    pub relaunches_total: u64,
    pub launch_failures_total: u64,
    pub quarantines_total: u64,
}

/// Rebuilds one user's serving authority through the byte-identical startup
/// ladder. There is exactly one ladder and one set of predicates: the driver
/// adds no launch branch, no witness call, no lease call, and no Control write
/// of its own.
#[async_trait::async_trait]
pub(crate) trait WalServingRelaunch: Send + Sync {
    /// Returns the archive id the rebuilt authority actually bound, so the
    /// slot can refuse a successor for a different archive.
    async fn rebuild(
        &self,
        user_id: &str,
    ) -> Result<(
        [u8; 16],
        Arc<crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority>,
    )>;
}

/// One explicitly named, non-default VFS installation and its bounded path
/// registry. Construction is crate-private and performs no cloud, witness,
/// archive-binding, route, health, or admission work.
pub(crate) struct StoreShadowCapture {
    registry: CaptureRegistry,
    vfs_name: CString,
}

/// Exact one-user capture selection. Store construction can inject it only in
/// tests; the sole production mutation is the consuming advisory-owner resume
/// transition while both exact-user gates are closed. The Store applies it
/// only when the validated user identity matches byte-for-byte.
pub(crate) struct StoreShadowCaptureSelection {
    user_id: UserId,
    capture: Arc<StoreShadowCapture>,
}

impl StoreShadowCaptureSelection {
    fn capture_for_user(&self, user_id: &str) -> Option<Arc<StoreShadowCapture>> {
        (self.user_id == user_id).then(|| Arc::clone(&self.capture))
    }

    #[cfg(test)]
    fn for_test(user_id: &str, capture: Arc<StoreShadowCapture>) -> Self {
        validate_user_id(user_id).expect("test capture user identity");
        Self {
            user_id: user_id.to_owned(),
            capture,
        }
    }
}

impl std::fmt::Debug for StoreShadowCaptureSelection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoreShadowCaptureSelection(<exact-user-inactive>)")
    }
}

impl StoreShadowCapture {
    #[allow(
        dead_code,
        reason = "reserved for separately reviewed default-off shadow runtime composition"
    )]
    pub(crate) fn install(vfs_name: &str) -> Result<Self> {
        let registry = CaptureRegistry::new();
        let vfs = RegisteredCaptureVfs::install(vfs_name, registry.clone())
            .map_err(|_| EnclaveError::Store("shadow capture VFS installation failed".into()))?;
        let vfs_name = vfs.name().to_owned();
        // Dropping the installation handle deliberately leaks its bounded
        // SQLite callback allocation; retain only the safe copied name in the
        // cross-thread Store adapter.
        drop(vfs);
        Ok(Self { registry, vfs_name })
    }

    fn register(&self, path: &Path) -> Result<CaptureRegistration> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| EnclaveError::Store("shadow capture path contains NUL".into()))?;
        self.registry
            .register(&path)
            .map_err(|_| EnclaveError::Store("shadow capture registration failed".into()))
    }

    fn register_after_generation(
        &self,
        path: &Path,
        previous_generation: u64,
    ) -> Result<CaptureRegistration> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| EnclaveError::Store("shadow capture path contains NUL".into()))?;
        self.registry
            .register_after_generation(&path, previous_generation)
            .map_err(|_| EnclaveError::Store("shadow capture registration failed".into()))
    }

    fn vfs_name(&self) -> &CStr {
        &self.vfs_name
    }

    /// Process-wide singleton capture VFS for every WAL-owner lane, mirroring
    /// the shared test capture below.
    ///
    /// MANDATORY, not an optimization. `MAX_CAPTURE_VFS_INSTALLATIONS` is a
    /// process-lifetime global enforced by a `fetch_update` in
    /// `archive_v3_sqlite_vfs`, and every install deliberately `Box::leak`s its
    /// bounded SQLite callback allocation. Installing per launch was harmless
    /// while the only launch was startup; once a serving slot can be
    /// relaunched in-process, a per-generation install hard-fails with
    /// `CaptureVfsError::TooManyInstallations` after the ceiling and makes
    /// `sqlite3_vfs_find` name resolution order-dependent before then.
    ///
    /// Sound because the VFS is a stateless wrapper over per-path
    /// registrations: each lane registers its own 128-bit-random recovery path,
    /// the registry is separately capped, and `CaptureRegistration::drop`
    /// retires and scrubs a dead lane's slot — which the relaunch driver's
    /// proof of death guarantees has already run before a successor registers.
    pub(crate) fn shared_for_wal_owner() -> Result<Arc<Self>> {
        // A `Mutex` rather than a `OnceLock`: installation is fallible, and a
        // lost `get_or_init` race would burn one of the eight process-lifetime
        // installations on an allocation nobody keeps.
        static CAPTURE: std::sync::Mutex<Option<Arc<StoreShadowCapture>>> =
            std::sync::Mutex::new(None);
        let mut capture = CAPTURE
            .lock()
            .map_err(|_| EnclaveError::Store("shadow capture singleton poisoned".into()))?;
        if let Some(capture) = capture.as_ref() {
            return Ok(Arc::clone(capture));
        }
        let installed = Arc::new(StoreShadowCapture::install(
            "kioku-archive-v3-wal-owner-v1",
        )?);
        *capture = Some(Arc::clone(&installed));
        Ok(installed)
    }

    #[cfg(test)]
    pub(crate) fn shared_for_test() -> Arc<Self> {
        static CAPTURE: std::sync::OnceLock<Arc<StoreShadowCapture>> = std::sync::OnceLock::new();
        Arc::clone(CAPTURE.get_or_init(|| {
            Arc::new(
                StoreShadowCapture::install("kioku-shared-capture-test")
                    .expect("shared test capture VFS installs once"),
            )
        }))
    }

    #[cfg(test)]
    pub(crate) fn register_path_for_test(&self, path: &Path) -> Result<CaptureRegistration> {
        self.register(path)
    }

    #[cfg(test)]
    pub(crate) fn register_path_after_generation_for_test(
        &self,
        path: &Path,
        previous_generation: u64,
    ) -> Result<CaptureRegistration> {
        self.register_after_generation(path, previous_generation)
    }

    #[cfg(test)]
    pub(crate) fn vfs_name_for_test(&self) -> &CStr {
        self.vfs_name()
    }
}

impl std::fmt::Debug for StoreShadowCapture {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoreShadowCapture(<inactive>)")
    }
}

/// Content-free startup reconciliation state. It deliberately has no archive,
/// object, or account identifiers so it is safe to expose through aggregate
/// logs and diagnostics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacyCheckpointReconciliation {
    pub ready: bool,
    pub completed_scans: u64,
    pub listed_live_objects: u64,
    pub live_archives_checked: u64,
    pub checkpoints_verified: u64,
    pub failures: u64,
}

struct UserActor {
    state: Arc<Mutex<UserActorState>>,
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
    /// Bounded completion markers make `with_user(...); save_user(...)`
    /// idempotent when an unrelated cache miss evicts and flushes that handle
    /// in between the two calls.
    recent_clean_evictions: HashMap<UserId, u64>,
    access_clock: u64,
}

#[derive(Default)]
struct ContentWriteBarrierState {
    blocked_users: HashSet<UserId>,
    active_writes: HashMap<UserId, usize>,
}

struct ContentWriteBarrier {
    state: std::sync::Mutex<ContentWriteBarrierState>,
    changed: Notify,
}

impl Default for ContentWriteBarrier {
    fn default() -> Self {
        Self {
            state: std::sync::Mutex::new(ContentWriteBarrierState::default()),
            changed: Notify::new(),
        }
    }
}

/// Keeps an admitted raw-content operation visible to account deletion.  It
/// can be moved into an owned GCS task, so request cancellation never lets
/// deletion outrun a PUT whose provider outcome is still unknown.
pub struct ContentWriteLease {
    barrier: Arc<ContentWriteBarrier>,
    user_id: UserId,
}

/// Content-free commitment to the exact latest acknowledged legacy actor
/// snapshot. The plaintext never enters the control store; only this digest,
/// its conditional source generation, and the opaque wrapped key metadata are
/// carried through the rebind transition.
pub(crate) struct IdentityRebindSource {
    pub(crate) base_generation: i64,
    pub(crate) source_generation: i64,
    pub(crate) commitment: [u8; 32],
    pub(crate) plaintext: Vec<u8>,
    pub(crate) wrapped_dek_b64: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LegacyWriteBackend {
    Index,
    Media,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LegacyWriteKind {
    IndexPut,
    MediaPut,
    RecoveryCopy,
    StableCreate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LegacyWriteIntentState {
    Prepared,
    Requesting,
    Committed,
    Conflict,
    Fenced,
}

impl LegacyWriteIntentState {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Conflict | Self::Fenced)
    }
}

/// Durable provider-side authority for one exact legacy content mutation.
/// Request bytes are already encrypted and are retained only while a crashed
/// owner may need takeover; terminal tombstones erase them but preserve the
/// precondition and digests through the archive-deletion lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyWriteIntent {
    format_version: u8,
    request_id: String,
    user_id: String,
    backend: LegacyWriteBackend,
    kind: LegacyWriteKind,
    object_name: String,
    if_generation_match: Option<i64>,
    source_object_name: Option<String>,
    source_generation: Option<i64>,
    ciphertext_sha256: String,
    wrapped_dek_sha256: String,
    ciphertext_b64: Option<String>,
    wrapped_dek_b64: Option<String>,
    state: LegacyWriteIntentState,
    owner_token: Option<String>,
    lease_expires_at_millis: Option<i64>,
    outcome_generation: Option<i64>,
}

#[derive(Clone)]
enum LegacyWriteRequest {
    Put {
        backend: LegacyWriteBackend,
        kind: LegacyWriteKind,
        object_name: String,
        ciphertext: Vec<u8>,
        wrapped_dek_b64: String,
        if_generation_match: i64,
    },
    RecoveryCopy {
        source_object_name: String,
        source_generation: i64,
        destination_object_name: String,
    },
}

#[derive(Clone)]
struct PersistedLegacyWriteIntent {
    object_name: String,
    generation: i64,
    intent: LegacyWriteIntent,
}

fn valid_legacy_fence_authority(authority: &str) -> bool {
    let suffix = if authority.starts_with("rebind_") || authority.starts_with("delete_") {
        authority.get(7..)
    } else if authority.starts_with("archive_") {
        authority.get(8..)
    } else {
        None
    };
    suffix.is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

/// Store-owned two-namespace transition. Both lifecycle gates, raw-content
/// admissions, and actor states remain fenced until `complete` makes only the
/// stable namespace available. Dropping a pending transition deliberately
/// leaves both process-local fences installed; the durable control operation
/// is the restart authority.
pub(crate) struct IdentityRebindTransition {
    store: Arc<Store>,
    old_user_id: UserId,
    stable_user_id: UserId,
    _lifecycle_guards: Vec<OwnedMutexGuard<()>>,
    old_actor: Arc<UserActor>,
    stable_actor: Arc<UserActor>,
    old_state: OwnedMutexGuard<UserActorState>,
    _stable_state: OwnedMutexGuard<UserActorState>,
}

/// Unforgeable Store-side token for consuming the identity-bearing portion of
/// an authenticated maintenance plan. No caller can extract that identity.
pub(crate) struct StoreMaintenanceContext(());

/// Store-owned one-user maintenance transition. Dropping it deliberately
/// leaves durable/provider fences closed; restart must reauthenticate the
/// encrypted control operation before obtaining another transition.
pub(crate) struct ArchiveMaintenanceTransition {
    store: Arc<Store>,
    plan: MaintenanceStorePlanView,
    _lifecycle_guard: OwnedMutexGuard<()>,
    actor: Arc<UserActor>,
    state: OwnedMutexGuard<UserActorState>,
}

/// Store-owned pre-transition admission. It holds the exact user's lifecycle
/// gate without changing either local admission fence, so Control can perform
/// its final terminal-release check before maintenance blocks the process.
pub(crate) struct ArchiveMaintenanceAdmission {
    store: Arc<Store>,
    plan: MaintenanceStorePlanView,
    lifecycle_guard: OwnedMutexGuard<()>,
}

/// Content-free tentative source facts observed while all local admissions
/// are already closed but before the permanent provider marker is created.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaintenanceTentativeSource {
    pub(crate) base_generation: i64,
    pub(crate) plaintext_hash: [u8; 32],
    pub(crate) plaintext_len: u64,
    pub(crate) sqlite_schema_version: u32,
    pub(crate) wrapped_dek_commitment: [u8; 32],
}

/// Owned, immutable plaintext snapshot. Its path and identity fields have no
/// general getters; checkpoint/parity adapters borrow it through reviewed
/// producer seams. Drop scrubs the database and both SQLite sidecars.
pub(crate) struct PinnedLegacySnapshot {
    path: PathBuf,
    _archive_id: crate::archive_v3::ArchiveId,
    _operation_id: MaintenanceImportOperationId,
    source: MaintenanceSourceBinding,
    _store: Arc<Store>,
    _plan: MaintenanceStorePlanView,
    _lifecycle_guard: OwnedMutexGuard<()>,
    _actor: Arc<UserActor>,
    _state: OwnedMutexGuard<UserActorState>,
}

/// Long-lived process-local admission fence transferred by the completed
/// maintenance import. The pinned plaintext family is scrubbed before this
/// value is minted, while the lifecycle and actor guards remain owned until a
/// future WAL owner consumes or drops the handoff.
pub(crate) struct StoreWalAuthorityFence {
    _pinned: PinnedLegacySnapshot,
}

/// Read-only admission for stopping one exact pre-owner maintenance operation.
/// It verifies GCS provider marker absence/deletion and retains the exact-user
/// lifecycle lock across Control's durable abort write.
#[allow(dead_code)]
pub(crate) struct StorePreOwnerAbortAdmission {
    archive_id: crate::archive_v3::ArchiveId,
    operation_id: MaintenanceImportOperationId,
    user_id: UserId,
    fence_authority_commitment: [u8; 32],
    user_commitment: [u8; 32],
    commitment: [u8; 32],
    _lifecycle_guard: OwnedMutexGuard<()>,
}

/// Opaque proof that one exact pre-owner abort reopened both local legacy
/// gates without installing capture. The lifecycle lock remains owned through
/// completion.
#[allow(dead_code)]
pub(crate) struct StorePreOwnerAbortRestored {
    archive_id: crate::archive_v3::ArchiveId,
    operation_id: MaintenanceImportOperationId,
    user_id: UserId,
    user_commitment: [u8; 32],
    commitment: [u8; 32],
    _lifecycle_guard: OwnedMutexGuard<()>,
}

#[allow(dead_code)]
impl StorePreOwnerAbortRestored {
    pub(crate) fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub(crate) fn user_id(&self) -> &str {
        &self.user_id
    }

    pub(crate) const fn archive_id(&self) -> crate::archive_v3::ArchiveId {
        self.archive_id
    }

    pub(crate) const fn operation_id(&self) -> MaintenanceImportOperationId {
        self.operation_id
    }

    pub(crate) fn authenticate(
        &self,
        _token: crate::archive_v3_maintenance_import::MaintenanceCoordinatorContext,
        archive_id: crate::archive_v3::ArchiveId,
        operation_id: MaintenanceImportOperationId,
    ) -> Result<[u8; 32]> {
        if self.archive_id != archive_id || self.operation_id != operation_id {
            return Err(EnclaveError::Conflict(
                "pre-owner abort restored target changed".into(),
            ));
        }
        let expected = pre_owner_abort_restored_commitment(
            self.archive_id,
            self.operation_id,
            self.user_commitment,
        );
        if self.commitment != expected {
            return Err(EnclaveError::Conflict(
                "pre-owner abort restoration changed".into(),
            ));
        }
        Ok(self.commitment)
    }
}

fn pre_owner_abort_restored_commitment(
    archive_id: crate::archive_v3::ArchiveId,
    operation_id: MaintenanceImportOperationId,
    user_commitment: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"kioku/archive-v3/pre-owner-abort-restored/v1\0");
    hasher.update(archive_id.as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(user_commitment);
    hasher.finalize().into()
}

#[cfg(test)]
impl StoreWalAuthorityFence {
    pub(crate) fn scratch_family_absent_for_test(&self) -> bool {
        !self._pinned.path.exists()
            && !sqlite_sidecar_path(&self._pinned.path, "-wal").exists()
            && !sqlite_sidecar_path(&self._pinned.path, "-shm").exists()
    }
}

#[cfg(test)]
pub(crate) struct WalCheckpointStall {
    entered: tokio::sync::Semaphore,
    released: std::sync::Mutex<bool>,
    release: std::sync::Condvar,
}

#[cfg(test)]
impl WalCheckpointStall {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Semaphore::new(0),
            released: std::sync::Mutex::new(false),
            release: std::sync::Condvar::new(),
        })
    }

    fn block(&self) {
        self.entered.add_permits(1);
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.release.wait(released).unwrap();
        }
    }

    pub(crate) async fn wait_entered(&self) {
        self.entered.acquire().await.unwrap().forget();
    }

    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }
}

/// Dedicated writable owner for one authenticated recovered archive-v3
/// SQLite copy. It is disjoint from the ordinary Store registry and legacy
/// persistence policy: the only mutation input is a sealed logical-domain
/// plan, and the only output is an opaque captured publication lease.
/// Erased query-only read for the WAL store lane. Implemented only by the
/// closure adapter below; the executor (`read_query_only`) owns every guard.
pub(crate) trait ErasedWalStoreRead: Send {
    fn run(
        self: Box<Self>,
        connection: &Connection,
    ) -> std::result::Result<Box<dyn std::any::Any + Send>, EnclaveError>;
}

/// Closure adapter carrying a typed query-only read across the lane thread.
pub(crate) struct WalStoreReadClosure<F>(F);

impl<F> WalStoreReadClosure<F> {
    pub(crate) fn from_closure<T>(read: F) -> Self
    where
        F: FnOnce(&Connection) -> std::result::Result<T, EnclaveError> + Send,
        T: Send + 'static,
    {
        Self(read)
    }
}

impl<F, T> ErasedWalStoreRead for WalStoreReadClosure<F>
where
    F: FnOnce(&Connection) -> std::result::Result<T, EnclaveError> + Send,
    T: Send + 'static,
{
    fn run(
        self: Box<Self>,
        connection: &Connection,
    ) -> std::result::Result<Box<dyn std::any::Any + Send>, EnclaveError> {
        (self.0)(connection).map(|value| Box::new(value) as Box<dyn std::any::Any + Send>)
    }
}

pub(crate) struct SingleArchiveWalStoreOwner {
    staged: Option<AuthenticatedWalOwnerStaging>,
    #[allow(
        dead_code,
        reason = "reserved for the inactive offline WAL owner; startup and serving remain intentionally unwired"
    )]
    path: PathBuf,
    connection: Option<Connection>,
    registration: Option<CaptureRegistration>,
    _capture: Arc<StoreShadowCapture>,
    token: WalOwnerStoreContext,
    binding: WalOwnerStoreBinding,
    instance_id: WalOwnerInstanceId,
    poisoned: bool,
    #[cfg(test)]
    checkpoint_stall: Option<Arc<WalCheckpointStall>>,
}

/// Cleanup-owning stable checkpoint source. It can only be produced by
/// consuming the dedicated WAL Store owner after checkpoint/TRUNCATE, capture
/// retirement, connection close, and exact sidecar absence checks.
pub(crate) struct WalOwnerCheckpointSource {
    _staged: AuthenticatedWalOwnerStaging,
    file: std::fs::File,
    logical_file_length: u64,
    plaintext_hash: [u8; 32],
    sqlite_schema_version: u32,
    binding: WalOwnerStoreBinding,
}

/// Store-private producer token for source-worker validation. Its field is
/// not visible to sibling modules.
pub(crate) struct StoreWalCheckpointContext(());

impl WalOwnerCheckpointSource {
    pub(crate) fn rebind_after_lease_maintenance(
        &mut self,
        _token: crate::archive_v3_wal_owner::WalCheckpointSourceContext,
        next: WalOwnerStoreBinding,
    ) -> std::result::Result<(), WalOwnerError> {
        self.rebind_after_lease_maintenance_inner(next)
    }

    fn rebind_after_lease_maintenance_inner(
        &mut self,
        next: WalOwnerStoreBinding,
    ) -> std::result::Result<(), WalOwnerError> {
        let previous =
            crate::archive_v3_witness::WitnessRecord::decode(self.binding.witness_bytes())
                .map_err(|_| WalOwnerError::Corrupt)?;
        let observed = crate::archive_v3_witness::WitnessRecord::decode(next.witness_bytes())
            .map_err(|_| WalOwnerError::Corrupt)?;
        observed
            .exact_wal_owner_checkpoint_lease_successor_from(
                &previous,
                crate::archive_v3_wal_owner::WalCheckpointSourceContext::for_store(
                    StoreWalCheckpointContext(()),
                ),
            )
            .map_err(|_| WalOwnerError::Conflict)?;
        if next.archive_id() != self.binding.archive_id()
            || next.database_epoch() != self.binding.database_epoch()
            || next.key_epoch() != self.binding.key_epoch()
            || next.root() != self.binding.root()
        {
            return Err(WalOwnerError::Conflict);
        }
        self.binding = next;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn authenticated_facts(
        &self,
        _token: crate::archive_v3_wal_owner::WalCheckpointSourceContext,
        binding: &WalOwnerStoreBinding,
    ) -> std::result::Result<(u64, [u8; 32], u32), WalOwnerError> {
        if binding != &self.binding
            || self.logical_file_length == 0
            || self.plaintext_hash == [0; 32]
        {
            return Err(WalOwnerError::Conflict);
        }
        Ok((
            self.logical_file_length,
            self.plaintext_hash,
            self.sqlite_schema_version,
        ))
    }

    #[cfg(test)]
    pub(crate) fn read_checkpoint_exact(
        &mut self,
        _token: crate::archive_v3_wal_owner::WalCheckpointSourceContext,
        offset: u64,
        destination: &mut [u8],
    ) -> std::result::Result<(), WalOwnerError> {
        self.read_checkpoint_exact_inner(offset, destination)
    }

    fn read_checkpoint_exact_inner(
        &mut self,
        offset: u64,
        destination: &mut [u8],
    ) -> std::result::Result<(), WalOwnerError> {
        use std::io::{Read as _, Seek as _, SeekFrom};

        let end = offset
            .checked_add(destination.len() as u64)
            .ok_or(WalOwnerError::Corrupt)?;
        if destination.is_empty() || end > self.logical_file_length {
            return Err(WalOwnerError::Corrupt);
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.read_exact(destination))
            .map_err(|_| WalOwnerError::Corrupt)
    }
}

impl std::fmt::Debug for WalOwnerCheckpointSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WalOwnerCheckpointSource(<opaque>)")
    }
}

impl crate::archive_v3_shadow_checkpoint::CheckpointSource for WalOwnerCheckpointSource {
    fn logical_file_length(&self) -> crate::archive_v3_shadow_checkpoint::Result<u64> {
        Ok(self.logical_file_length)
    }

    fn read_exact(
        &mut self,
        logical_offset: u64,
        destination: &mut [u8],
    ) -> crate::archive_v3_shadow_checkpoint::Result<()> {
        use std::io::{Read as _, Seek as _, SeekFrom};

        let end = logical_offset
            .checked_add(destination.len() as u64)
            .ok_or(crate::archive_v3_shadow_checkpoint::ShadowCheckpointError::Source)?;
        if destination.is_empty() || end > self.logical_file_length {
            return Err(crate::archive_v3_shadow_checkpoint::ShadowCheckpointError::Source);
        }
        self.file
            .seek(SeekFrom::Start(logical_offset))
            .and_then(|_| self.file.read_exact(destination))
            .map_err(|_| crate::archive_v3_shadow_checkpoint::ShadowCheckpointError::Source)
    }
}

enum WalOwnerCheckpointReaderCommand {
    Read {
        offset: u64,
        length: usize,
        response:
            tokio::sync::oneshot::Sender<std::result::Result<Zeroizing<Vec<u8>>, WalOwnerError>>,
    },
    Rebind {
        next: Box<WalOwnerStoreBinding>,
        response: tokio::sync::oneshot::Sender<std::result::Result<(), WalOwnerError>>,
    },
    Close {
        response: tokio::sync::oneshot::Sender<()>,
    },
}

/// Async-facing handle for the cleanup-owning checkpoint reader thread. No
/// file or path crosses this boundary; every blocking seek/read remains on the
/// dedicated thread, and dropping the handle closes the command channel so
/// the worker drops and scrubs its authenticated staging owner.
pub(crate) struct WalOwnerCheckpointReader {
    sender: std::sync::mpsc::Sender<WalOwnerCheckpointReaderCommand>,
    thread: Option<std::thread::JoinHandle<()>>,
    logical_file_length: u64,
    plaintext_hash: [u8; 32],
    sqlite_schema_version: u32,
    binding: WalOwnerStoreBinding,
}

impl WalOwnerCheckpointReader {
    pub(crate) fn spawn(
        source: WalOwnerCheckpointSource,
    ) -> std::result::Result<Self, WalOwnerError> {
        let logical_file_length = source.logical_file_length;
        let plaintext_hash = source.plaintext_hash;
        let sqlite_schema_version = source.sqlite_schema_version;
        let binding = source.binding.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("kioku-wal-checkpoint-source".to_owned())
            .spawn(move || {
                let mut source = source;
                while let Ok(command) = receiver.recv() {
                    match command {
                        WalOwnerCheckpointReaderCommand::Read {
                            offset,
                            length,
                            response,
                        } => {
                            let mut bytes = Zeroizing::new(vec![0; length]);
                            let result = source
                                .read_checkpoint_exact_inner(offset, bytes.as_mut_slice())
                                .map(|()| bytes);
                            let _ = response.send(result);
                        }
                        WalOwnerCheckpointReaderCommand::Rebind { next, response } => {
                            let result = source.rebind_after_lease_maintenance_inner(*next);
                            let _ = response.send(result);
                        }
                        WalOwnerCheckpointReaderCommand::Close { response } => {
                            drop(source);
                            let _ = response.send(());
                            return;
                        }
                    }
                }
            })
            .map_err(|_| WalOwnerError::Persistence)?;
        Ok(Self {
            sender,
            thread: Some(thread),
            logical_file_length,
            plaintext_hash,
            sqlite_schema_version,
            binding,
        })
    }

    pub(crate) fn authenticated_facts(
        &self,
        _token: crate::archive_v3_wal_owner::WalCheckpointSourceContext,
        binding: &WalOwnerStoreBinding,
    ) -> std::result::Result<(u64, [u8; 32], u32), WalOwnerError> {
        if binding != &self.binding {
            return Err(WalOwnerError::Conflict);
        }
        Ok((
            self.logical_file_length,
            self.plaintext_hash,
            self.sqlite_schema_version,
        ))
    }

    pub(crate) async fn read_exact_owned(
        &self,
        offset: u64,
        length: usize,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, WalOwnerError> {
        let (response, result) = tokio::sync::oneshot::channel();
        self.sender
            .send(WalOwnerCheckpointReaderCommand::Read {
                offset,
                length,
                response,
            })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)?
    }

    pub(crate) async fn rebind(
        &mut self,
        next: WalOwnerStoreBinding,
    ) -> std::result::Result<(), WalOwnerError> {
        let retained = next.clone();
        let (response, result) = tokio::sync::oneshot::channel();
        self.sender
            .send(WalOwnerCheckpointReaderCommand::Rebind {
                next: Box::new(next),
                response,
            })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)??;
        self.binding = retained;
        Ok(())
    }

    pub(crate) async fn close(mut self) -> std::result::Result<(), WalOwnerError> {
        let (response, result) = tokio::sync::oneshot::channel();
        self.sender
            .send(WalOwnerCheckpointReaderCommand::Close { response })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)?;
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| WalOwnerError::Poisoned)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for WalOwnerCheckpointReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WalOwnerCheckpointReader(<opaque>)")
    }
}

#[async_trait::async_trait]
impl crate::archive_v3_shadow_checkpoint::OwnedCheckpointSource for WalOwnerCheckpointReader {
    fn authenticated_facts(
        &self,
    ) -> crate::archive_v3_shadow_checkpoint::Result<(u64, [u8; 32], u32)> {
        if self.logical_file_length == 0 || self.plaintext_hash == [0; 32] {
            return Err(crate::archive_v3_shadow_checkpoint::ShadowCheckpointError::Source);
        }
        Ok((
            self.logical_file_length,
            self.plaintext_hash,
            self.sqlite_schema_version,
        ))
    }

    async fn read_exact_owned(
        &self,
        logical_offset: u64,
        length: usize,
    ) -> crate::archive_v3_shadow_checkpoint::Result<Zeroizing<Vec<u8>>> {
        WalOwnerCheckpointReader::read_exact_owned(self, logical_offset, length)
            .await
            .map_err(|_| crate::archive_v3_shadow_checkpoint::ShadowCheckpointError::Source)
    }
}

pub(crate) enum WalStoreApply {
    Applied {
        context: Box<WalOwnerContext>,
        drain: OwnedCapturedDrain,
        result: ErasedValidatedWalLogicalResult,
    },
    Replayed(ErasedValidatedWalLogicalResult),
}

pub(crate) enum WalStoreReplay {
    Absent(Box<dyn ErasedPreparedLogicalMutation>),
    Present(ErasedValidatedWalLogicalResult),
}

impl SingleArchiveWalStoreOwner {
    #[allow(
        dead_code,
        reason = "reserved for the inactive offline WAL owner; startup and serving remain intentionally unwired"
    )]
    pub(crate) fn from_authenticated_staging(
        token: WalOwnerStoreContext,
        staged: AuthenticatedWalOwnerStaging,
        binding: WalOwnerStoreBinding,
        capture: Arc<StoreShadowCapture>,
    ) -> std::result::Result<Self, WalOwnerError> {
        let path = staged
            .path_for_store(token, &binding)
            .map_err(|_| WalOwnerError::Corrupt)?;
        let recovered_wal_generation = staged
            .recovered_wal_generation_for_store(token, &binding)
            .map_err(|_| WalOwnerError::Corrupt)?;
        let owned_path = path.to_path_buf();
        let (connection, registration, migration_dirty) = open_db_after_wal_generation(
            &owned_path,
            capture.as_ref(),
            StorePersistencePolicy::WalOwnerAuthoritative,
            recovered_wal_generation,
        )
        .map_err(|_| WalOwnerError::Corrupt)?;
        let registration = registration.ok_or(WalOwnerError::Capture)?;
        // Kept as a tripwire. Under `WalOwnerAuthoritative` the open runs no
        // DDL and asserts the database was untouched, so this is now
        // unreachable by construction rather than by inspection — and it
        // should stay here to catch a future open path that reintroduces a
        // write.
        if migration_dirty {
            drop(connection);
            drop(registration);
            return Err(WalOwnerError::Corrupt);
        }
        staged
            .validate_opened(token, &binding, &connection)
            .map_err(|_| WalOwnerError::Corrupt)?;
        let instance_id = WalOwnerInstanceId::random_for_store(token)?;
        Ok(Self {
            staged: Some(staged),
            path: owned_path,
            connection: Some(connection),
            registration: Some(registration),
            _capture: capture,
            token,
            binding,
            instance_id,
            poisoned: false,
            #[cfg(test)]
            checkpoint_stall: None,
        })
    }

    pub(crate) const fn binding(&self) -> &WalOwnerStoreBinding {
        &self.binding
    }

    pub(crate) const fn instance_id(&self) -> WalOwnerInstanceId {
        self.instance_id
    }

    /// Query-only read over the lane's authoritative connection, dispatched
    /// exclusively by the WAL owner actor AFTER any in-flight apply has fully
    /// witness-settled and advanced — a reader can never observe locally
    /// committed but unsettled state. The connection is guarded exactly like
    /// `lookup_settled_replay`: SQLite `query_only` around the closure plus a
    /// before/after mutation fingerprint, and any observed mutation, restore
    /// failure, or capture activity poisons this owner, because a write that
    /// bypassed the WAL ladder can never be settled. The outer result is the
    /// guard/lane integrity; the inner result is the closure's own outcome.
    pub(crate) fn read_query_only(
        &mut self,
        read: Box<dyn ErasedWalStoreRead>,
    ) -> std::result::Result<
        std::result::Result<Box<dyn std::any::Any + Send>, EnclaveError>,
        WalOwnerError,
    > {
        if self.poisoned {
            return Err(WalOwnerError::Poisoned);
        }
        let registration = self.registration.as_ref().ok_or(WalOwnerError::Poisoned)?;
        if registration.completed_len() != 0 {
            self.poison();
            return Err(WalOwnerError::Corrupt);
        }
        let connection = self.connection.as_ref().ok_or(WalOwnerError::Poisoned)?;
        let before = match database_mutation_fingerprint(connection) {
            Ok(before) => before,
            Err(_) => {
                self.poison();
                return Err(WalOwnerError::Corrupt);
            }
        };
        if connection.pragma_update(None, "query_only", true).is_err() {
            self.poison();
            return Err(WalOwnerError::Corrupt);
        }
        let result = read.run(connection);
        let after = database_mutation_fingerprint(connection);
        let restore = connection.pragma_update(None, "query_only", false);
        let registration = self.registration.as_ref().ok_or(WalOwnerError::Poisoned)?;
        let capture_empty = registration.completed_len() == 0;
        match (after, restore, capture_empty) {
            (Ok(after), Ok(()), true) if after == before => Ok(result),
            _ => {
                self.poison();
                Err(WalOwnerError::Corrupt)
            }
        }
    }

    /// Exact local lookup performed only after the actor has reconciled
    /// encrypted Control and freshly authenticated the provider head. A
    /// locally committed but unsettled operation retains exactly one captured
    /// commit, so it cannot take this path.
    pub(crate) fn lookup_settled_replay(
        &mut self,
        prepared: Box<dyn ErasedPreparedLogicalMutation>,
    ) -> std::result::Result<WalStoreReplay, WalOwnerError> {
        if self.poisoned {
            return Err(WalOwnerError::Poisoned);
        }
        let registration = self.registration.as_ref().ok_or(WalOwnerError::Poisoned)?;
        if registration.completed_len() != 0 {
            return Ok(WalStoreReplay::Absent(prepared));
        }
        let connection = self.connection.as_ref().ok_or(WalOwnerError::Poisoned)?;
        let before =
            database_mutation_fingerprint(connection).map_err(|_| WalOwnerError::Corrupt)?;
        connection
            .pragma_update(None, "query_only", true)
            .map_err(|_| WalOwnerError::Corrupt)?;
        let result = prepared.lookup_for_owner(connection);
        let after = database_mutation_fingerprint(connection);
        let restore = connection.pragma_update(None, "query_only", false);
        let capture_empty = registration.completed_len() == 0;
        match (result, after, restore, capture_empty) {
            (Ok(ErasedPreparedLookup::Present(result)), Ok(after), Ok(()), true)
                if after == before =>
            {
                Ok(WalStoreReplay::Present(result))
            }
            (Ok(ErasedPreparedLookup::Absent(prepared)), Ok(after), Ok(()), true)
                if after == before =>
            {
                Ok(WalStoreReplay::Absent(prepared))
            }
            (Err(WalIdempotencyError::FingerprintConflict), Ok(after), Ok(()), true)
                if after == before =>
            {
                Err(WalOwnerError::Conflict)
            }
            _ => {
                self.poison();
                Err(WalOwnerError::Corrupt)
            }
        }
    }

    pub(crate) fn apply_prepared(
        &mut self,
        prepared: Box<dyn ErasedPreparedLogicalMutation>,
        attempt: WalOwnerAttempt,
    ) -> std::result::Result<WalStoreApply, WalOwnerError> {
        if self.poisoned {
            return Err(WalOwnerError::Poisoned);
        }
        if !matches!(
            attempt.stage(),
            crate::archive_v3_wal_owner::WalPublicationStage::Prepared
                | crate::archive_v3_wal_owner::WalPublicationStage::Captured
        ) {
            self.poison();
            return Err(WalOwnerError::Conflict);
        }
        let identity = WalOperationIdentity::from_erased_prepared(prepared.as_ref());
        let execution = prepared
            .execute_for_owner(self.connection.as_mut().ok_or(WalOwnerError::Poisoned)?)
            .map_err(|_| WalOwnerError::Conflict)?;
        if execution.kind() != identity.kind()
            || execution.operation_id() != identity.operation_id()
            || execution.request_fingerprint() != identity.request_fingerprint()
        {
            self.poison();
            return Err(WalOwnerError::Corrupt);
        }
        let registration = self.registration.as_ref().ok_or(WalOwnerError::Poisoned)?;
        let disposition = execution.disposition();
        let result = execution.into_validated_result();
        match disposition {
            LogicalMutationDisposition::Replayed => {
                if attempt.stage() == crate::archive_v3_wal_owner::WalPublicationStage::Witnessed {
                    if registration.completed_len() != 0 {
                        self.poison();
                        return Err(WalOwnerError::Capture);
                    }
                    return Ok(WalStoreApply::Replayed(result));
                }
                if !matches!(
                    attempt.stage(),
                    crate::archive_v3_wal_owner::WalPublicationStage::Prepared
                        | crate::archive_v3_wal_owner::WalPublicationStage::Captured
                ) || registration.completed_len() != 1
                {
                    self.poison();
                    return Err(WalOwnerError::Capture);
                }
                self.take_exact_captured(identity, attempt, result)
            }
            LogicalMutationDisposition::Applied => {
                self.take_exact_captured(identity, attempt, result)
            }
        }
    }

    fn take_exact_captured(
        &mut self,
        identity: WalOperationIdentity,
        attempt: WalOwnerAttempt,
        result: ErasedValidatedWalLogicalResult,
    ) -> std::result::Result<WalStoreApply, WalOwnerError> {
        let registration = self.registration.as_ref().ok_or(WalOwnerError::Poisoned)?;
        let lease =
            match registration.begin_exact_one_drain(attempt.session_id(), attempt.attempt_id()) {
                Ok(value) => value,
                Err(_) => {
                    self.poison();
                    return Err(WalOwnerError::Capture);
                }
            };
        let drain = match lease.take_for_publication() {
            Ok(value) => value,
            Err(_) => {
                self.poison();
                return Err(WalOwnerError::Capture);
            }
        };
        let observed_wal_generation = drain
            .observed_wal_generation(self.token)
            .map_err(|_| WalOwnerError::Capture)?;
        let context = WalOwnerContext::from_store(
            self.token,
            self.binding.clone(),
            identity,
            attempt.owner_id(),
            self.instance_id,
            drain.stream_id(),
            attempt,
            observed_wal_generation,
        )?;
        drain
            .exact_commit(&context)
            .map_err(|_| WalOwnerError::Capture)?;
        Ok(WalStoreApply::Applied {
            context: Box::new(context),
            drain,
            result,
        })
    }

    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
        self.connection.take();
        self.registration.take();
        self.staged.take();
    }

    pub(crate) fn advance_binding(
        &mut self,
        context: &WalOwnerContext,
        next: WalOwnerStoreBinding,
    ) -> std::result::Result<(), WalOwnerError> {
        if self.poisoned
            || context.binding() != &self.binding
            || next.archive_id() != self.binding.archive_id()
            || next.database_epoch() != self.binding.database_epoch()
            || next.key_epoch() != self.binding.key_epoch()
            || next.root().sequence()
                != self
                    .binding
                    .root()
                    .sequence()
                    .checked_add(1)
                    .ok_or(WalOwnerError::Corrupt)?
        {
            self.poison();
            return Err(WalOwnerError::Conflict);
        }
        self.binding = next;
        Ok(())
    }

    pub(crate) fn refresh_lease_binding(
        &mut self,
        next: WalOwnerStoreBinding,
    ) -> std::result::Result<(), WalOwnerError> {
        if self.poisoned
            || next.archive_id() != self.binding.archive_id()
            || next.database_epoch() != self.binding.database_epoch()
            || next.key_epoch() != self.binding.key_epoch()
            || next.root() != self.binding.root()
            || self
                .registration
                .as_ref()
                .ok_or(WalOwnerError::Poisoned)?
                .completed_len()
                != 0
        {
            self.poison();
            return Err(WalOwnerError::Conflict);
        }
        self.binding = next;
        Ok(())
    }

    pub(crate) fn take_checkpoint_source(
        &mut self,
    ) -> std::result::Result<WalOwnerCheckpointSource, WalOwnerError> {
        #[cfg(test)]
        if let Some(stall) = self.checkpoint_stall.as_ref() {
            stall.block();
        }
        if self.poisoned
            || self
                .registration
                .as_ref()
                .ok_or(WalOwnerError::Poisoned)?
                .completed_len()
                != 0
        {
            self.poison();
            return Err(WalOwnerError::Conflict);
        }
        let connection = self.connection.as_ref().ok_or(WalOwnerError::Poisoned)?;
        let (busy, remaining, checkpointed): (i64, i64, i64) = connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|_| WalOwnerError::Corrupt)?;
        if (busy, remaining, checkpointed) != (0, 0, 0) {
            self.poison();
            return Err(WalOwnerError::Capture);
        }
        let sqlite_schema_version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| WalOwnerError::Corrupt)?;
        if self
            .registration
            .as_ref()
            .ok_or(WalOwnerError::Poisoned)?
            .completed_len()
            != 0
        {
            self.poison();
            return Err(WalOwnerError::Capture);
        }
        self.connection.take();
        self.registration.take();
        let wal = sqlite_sidecar_path(&self.path, "-wal");
        let shm = sqlite_sidecar_path(&self.path, "-shm");
        if wal.exists() || shm.exists() {
            self.poison();
            return Err(WalOwnerError::Corrupt);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(&self.path)
            .map_err(|_| WalOwnerError::Corrupt)?;
        let logical_file_length = file.metadata().map_err(|_| WalOwnerError::Corrupt)?.len();
        let mut hash_source = file.try_clone().map_err(|_| WalOwnerError::Corrupt)?;
        let mut hasher = Sha256::new();
        let mut hashed_length = 0_u64;
        let mut buffer = zeroize::Zeroizing::new(vec![0_u8; 1024 * 1024]);
        loop {
            use std::io::Read as _;
            let count = hash_source
                .read(buffer.as_mut_slice())
                .map_err(|_| WalOwnerError::Corrupt)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            hashed_length = hashed_length
                .checked_add(u64::try_from(count).map_err(|_| WalOwnerError::Corrupt)?)
                .ok_or(WalOwnerError::Corrupt)?;
        }
        let plaintext_hash: [u8; 32] = hasher.finalize().into();
        if logical_file_length == 0
            || hashed_length != logical_file_length
            || plaintext_hash == [0; 32]
        {
            return Err(WalOwnerError::Corrupt);
        }
        let staged = self.staged.take().ok_or(WalOwnerError::Poisoned)?;
        self.poisoned = true;
        Ok(WalOwnerCheckpointSource {
            _staged: staged,
            file,
            logical_file_length,
            plaintext_hash,
            sqlite_schema_version,
            binding: self.binding.clone(),
        })
    }

    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    #[cfg(test)]
    pub(crate) fn stall_checkpoint_for_wal_owner_test(&mut self, stall: Arc<WalCheckpointStall>) {
        self.checkpoint_stall = Some(stall);
    }

    #[cfg(test)]
    pub(crate) fn for_wal_owner_test(
        binding: WalOwnerStoreBinding,
    ) -> std::result::Result<Self, WalOwnerError> {
        let plaintext = create_empty_db(&Dek([0x71; 32])).map_err(|_| WalOwnerError::Corrupt)?;
        Self::from_wal_owner_test_plaintext(binding, plaintext)
    }

    #[cfg(test)]
    pub(crate) fn scratch_path_for_wal_owner_test(&self) -> PathBuf {
        self.path.clone()
    }

    #[cfg(test)]
    pub(crate) fn from_wal_owner_test_plaintext(
        binding: WalOwnerStoreBinding,
        plaintext: Vec<u8>,
    ) -> std::result::Result<Self, WalOwnerError> {
        use std::os::unix::fs::PermissionsExt;

        static NEXT_CAPTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let suffix = NEXT_CAPTURE.fetch_add(1, AtomicOrdering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kioku-wal-owner-{}-{suffix}.db",
            std::process::id()
        ));
        std::fs::write(&path, plaintext).map_err(|_| WalOwnerError::Corrupt)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| WalOwnerError::Corrupt)?;
        let setup = Connection::open(&path).map_err(|_| WalOwnerError::Corrupt)?;
        setup
            .execute_batch(SCHEMA_SQL)
            .map_err(|_| WalOwnerError::Corrupt)?;
        run_migrations(&setup).map_err(|_| WalOwnerError::Corrupt)?;
        setup
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS wal_owner_test_values(value BLOB NOT NULL);
                 CREATE TABLE IF NOT EXISTS wal_owner_test_operations(
                    operation_kind INTEGER NOT NULL,
                    operation_id BLOB NOT NULL,
                    request_fingerprint BLOB NOT NULL,
                    result BLOB NOT NULL,
                    PRIMARY KEY(operation_kind,operation_id),
                    CHECK(operation_kind BETWEEN 1 AND 12),
                    CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                    CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                    CHECK(length(result)>0 AND length(result)<=4096)
                 ) WITHOUT ROWID;
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .map_err(|_| WalOwnerError::Corrupt)?;
        drop(setup);
        let staged = AuthenticatedWalOwnerStaging::for_test(path, &binding, 0)
            .map_err(|_| WalOwnerError::Corrupt)?;
        let capture = StoreShadowCapture::shared_for_test();
        Self::from_authenticated_staging(WalOwnerStoreContext::for_test(), staged, binding, capture)
    }

    #[cfg(test)]
    pub(crate) fn checkpointed_plaintext_for_wal_owner_test(
        &mut self,
    ) -> std::result::Result<Vec<u8>, WalOwnerError> {
        if self.poisoned
            || self
                .registration
                .as_ref()
                .ok_or(WalOwnerError::Poisoned)?
                .completed_len()
                != 0
        {
            return Err(WalOwnerError::Conflict);
        }
        let connection = self.connection.as_ref().ok_or(WalOwnerError::Poisoned)?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|_| WalOwnerError::Corrupt)?;
        if self
            .registration
            .as_ref()
            .ok_or(WalOwnerError::Poisoned)?
            .completed_len()
            != 0
        {
            self.poison();
            return Err(WalOwnerError::Capture);
        }
        std::fs::read(&self.path).map_err(|_| WalOwnerError::Corrupt)
    }
}

impl Drop for SingleArchiveWalStoreOwner {
    fn drop(&mut self) {
        self.connection.take();
        self.registration.take();
        self.staged.take();
    }
}

impl std::fmt::Debug for SingleArchiveWalStoreOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SingleArchiveWalStoreOwner(<opaque>)")
    }
}

/// Owned, one-shot exact-generation revalidation capability. Only a pinned
/// maintenance snapshot can mint it; it carries no path or identity getters
/// and owns only the provider handle plus the immutable source binding needed
/// across asynchronous provider reads.
pub(crate) struct MaintenanceGenerationRevalidation {
    store: Arc<Store>,
    user_id: UserId,
    source: MaintenanceSourceBinding,
}

/// The permanent marker can serialize behind one already-admitted legacy
/// writer. In that sole case Store retains every local gate and returns the
/// newly authoritative, still-unmodified source so encrypted control can
/// durably rebase before the mandatory generation bump is retried.
pub(crate) enum MaintenanceFenceAndPin {
    Pinned(PinnedLegacySnapshot),
    Rebase {
        transition: ArchiveMaintenanceTransition,
        source: MaintenanceTentativeSource,
    },
}

impl PinnedLegacySnapshot {
    pub(crate) const fn source_binding(&self) -> MaintenanceSourceBinding {
        self.source
    }

    pub(crate) fn path_for_checkpoint_source(
        &self,
        _token: crate::archive_v3_shadow_checkpoint::MaintenanceCheckpointSourceContext,
    ) -> &Path {
        &self.path
    }

    pub(crate) fn path_for_parity(
        &self,
        _token: crate::archive_v3_shadow_parity::MaintenanceParitySourceContext,
    ) -> &Path {
        &self.path
    }

    #[cfg(test)]
    fn path_for_maintenance_test(&self) -> &Path {
        &self.path
    }

    /// Mint the owned fresh-read capability immediately before parity becomes
    /// durable. The pinned snapshot remains owned by the coordinator so its
    /// lifecycle gates and scratch cleanup stay in force during revalidation.
    pub(crate) fn exact_generation_revalidation(&self) -> MaintenanceGenerationRevalidation {
        MaintenanceGenerationRevalidation {
            store: Arc::clone(&self._store),
            user_id: self._plan.user_id.clone(),
            source: self.source,
        }
    }

    pub(crate) fn into_wal_authority_fence(
        self,
        _token: crate::archive_v3_maintenance_import::MaintenanceCoordinatorContext,
        expected_source: MaintenanceSourceBinding,
    ) -> Result<StoreWalAuthorityFence> {
        if self.source != expected_source {
            return Err(EnclaveError::Conflict(
                "maintenance WAL handoff source changed".into(),
            ));
        }
        remove_temp_db_files(&self.path);
        if self.path.exists()
            || sqlite_sidecar_path(&self.path, "-wal").exists()
            || sqlite_sidecar_path(&self.path, "-shm").exists()
        {
            return Err(EnclaveError::Store(
                "maintenance WAL handoff scratch cleanup failed".into(),
            ));
        }
        Ok(StoreWalAuthorityFence { _pinned: self })
    }
}

impl MaintenanceGenerationRevalidation {
    /// Fresh exact-generation revalidation. This performs no write and rejects
    /// any envelope, metadata, plaintext, or schema substitution.
    pub(crate) async fn verify(self) -> Result<()> {
        let Self {
            store,
            user_id,
            source,
        } = self;
        let source = source.store_view(StoreMaintenanceContext(()));
        let object = store
            .gcs
            .get_object_generation(&gcs_object_name(&user_id), source.generation)
            .await?;
        if object.generation != source.generation
            || <[u8; 32]>::from(Sha256::digest(object.wrapped_dek_b64.as_bytes()))
                != source.wrapped_dek_commitment
        {
            return Err(EnclaveError::Conflict(
                "maintenance pinned generation metadata changed".into(),
            ));
        }
        let dek = load_dek(store.kms.as_ref(), &object.wrapped_dek_b64).await?;
        let opened = decrypt_bound_blob(&dek, &object.ciphertext, &user_blob_context(&user_id))?;
        if u64::try_from(opened.plaintext.len()).ok() != Some(source.plaintext_len)
            || <[u8; 32]>::from(Sha256::digest(&opened.plaintext)) != source.plaintext_hash
        {
            return Err(EnclaveError::Conflict(
                "maintenance pinned generation plaintext changed".into(),
            ));
        }
        let path = write_private_temp_db(&user_id, &opened.plaintext).await?;
        let schema = (|| -> Result<u32> {
            let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let value: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            u32::try_from(value)
                .map_err(|_| EnclaveError::Store("maintenance source schema is invalid".into()))
        })();
        remove_temp_db_files(&path);
        if schema? != source.sqlite_schema_version {
            return Err(EnclaveError::Conflict(
                "maintenance pinned generation schema changed".into(),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for PinnedLegacySnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PinnedLegacySnapshot(<redacted>)")
    }
}

impl std::fmt::Debug for StoreWalAuthorityFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoreWalAuthorityFence(<opaque>)")
    }
}

impl Drop for PinnedLegacySnapshot {
    fn drop(&mut self) {
        remove_temp_db_files(&self.path);
    }
}

impl ContentWriteLease {
    /// A child lease is intentionally allowed after the user is fenced: its
    /// parent was admitted before the fence and deletion must wait for both.
    pub fn child(&self) -> Self {
        let mut state = self.barrier.state.lock().expect("content barrier poisoned");
        let count = state.active_writes.entry(self.user_id.clone()).or_default();
        *count = count.saturating_add(1);
        Self {
            barrier: Arc::clone(&self.barrier),
            user_id: self.user_id.clone(),
        }
    }
}

impl Drop for ContentWriteLease {
    fn drop(&mut self) {
        let mut state = self.barrier.state.lock().expect("content barrier poisoned");
        let remove = match state.active_writes.get_mut(&self.user_id) {
            Some(count) => {
                debug_assert!(*count > 0, "content-write lease underflow");
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => false,
        };
        if remove {
            state.active_writes.remove(&self.user_id);
            // Retain a permit if the deletion waiter has created its future
            // but has not yet polled it. This closes the check-then-wait gap
            // without making the barrier dependent on executor timing.
            self.barrier.changed.notify_one();
        }
    }
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

fn legacy_write_intent_prefix(user_id: &str) -> String {
    format!("{LEGACY_WRITE_INTENT_PREFIX}/{user_id}/")
}

fn legacy_write_intent_object_name(user_id: &str, request_id: &str) -> String {
    format!("{}{request_id}", legacy_write_intent_prefix(user_id))
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl LegacyWriteIntent {
    fn prepared(user_id: &str, request: &LegacyWriteRequest) -> Self {
        let request_id = format!("intent_{}", crate::cp::tokens::random_token_hex());
        match request {
            LegacyWriteRequest::Put {
                backend,
                kind,
                object_name,
                ciphertext,
                wrapped_dek_b64,
                if_generation_match,
            } => Self {
                format_version: LEGACY_WRITE_INTENT_FORMAT_VERSION,
                request_id,
                user_id: user_id.to_string(),
                backend: *backend,
                kind: *kind,
                object_name: object_name.clone(),
                if_generation_match: Some(*if_generation_match),
                source_object_name: None,
                source_generation: None,
                ciphertext_sha256: sha256_hex_bytes(ciphertext),
                wrapped_dek_sha256: sha256_hex_bytes(wrapped_dek_b64.as_bytes()),
                ciphertext_b64: Some(B64.encode(ciphertext)),
                wrapped_dek_b64: Some(wrapped_dek_b64.clone()),
                state: LegacyWriteIntentState::Prepared,
                owner_token: None,
                lease_expires_at_millis: None,
                outcome_generation: None,
            },
            LegacyWriteRequest::RecoveryCopy {
                source_object_name,
                source_generation,
                destination_object_name,
            } => Self {
                format_version: LEGACY_WRITE_INTENT_FORMAT_VERSION,
                request_id,
                user_id: user_id.to_string(),
                backend: LegacyWriteBackend::Index,
                kind: LegacyWriteKind::RecoveryCopy,
                object_name: destination_object_name.clone(),
                if_generation_match: Some(0),
                source_object_name: Some(source_object_name.clone()),
                source_generation: Some(*source_generation),
                ciphertext_sha256: sha256_hex_bytes(&[]),
                wrapped_dek_sha256: sha256_hex_bytes(&[]),
                ciphertext_b64: None,
                wrapped_dek_b64: None,
                state: LegacyWriteIntentState::Prepared,
                owner_token: None,
                lease_expires_at_millis: None,
                outcome_generation: None,
            },
        }
    }

    fn validate(&self, object_name: &str) -> Result<()> {
        validate_user_id(&self.user_id)?;
        if self.format_version != LEGACY_WRITE_INTENT_FORMAT_VERSION
            || !self.request_id.starts_with("intent_")
            || self.request_id.len() != 71
            || legacy_write_intent_object_name(&self.user_id, &self.request_id) != object_name
            || self.object_name.is_empty()
            || self
                .if_generation_match
                .is_none_or(|generation| generation < 0)
        {
            return Err(EnclaveError::Store(
                "invalid persisted legacy write intent authority".into(),
            ));
        }
        if self.ciphertext_sha256.len() != 64
            || self.wrapped_dek_sha256.len() != 64
            || !self
                .ciphertext_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !self
                .wrapped_dek_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(EnclaveError::Store(
                "invalid legacy write intent commitment".into(),
            ));
        }
        let valid_namespace = match self.kind {
            LegacyWriteKind::IndexPut | LegacyWriteKind::StableCreate => {
                self.backend == LegacyWriteBackend::Index
                    && self.object_name == gcs_object_name(&self.user_id)
            }
            LegacyWriteKind::MediaPut => {
                self.backend == LegacyWriteBackend::Media
                    && self.object_name.starts_with(&media_prefix(&self.user_id))
            }
            LegacyWriteKind::RecoveryCopy => {
                let expected_source = gcs_object_name(&self.user_id);
                self.backend == LegacyWriteBackend::Index
                    && self.source_object_name.as_deref() == Some(expected_source.as_str())
                    && self
                        .object_name
                        .starts_with(&legacy_recovery_prefix(&self.user_id))
            }
        };
        if !valid_namespace {
            return Err(EnclaveError::Store(
                "legacy write intent escaped its bound namespace".into(),
            ));
        }
        let put_shape = !matches!(self.kind, LegacyWriteKind::RecoveryCopy)
            && self.source_object_name.is_none()
            && self.source_generation.is_none()
            && (!self.state.is_terminal()
                || (self.ciphertext_b64.is_none() && self.wrapped_dek_b64.is_none()));
        let copy_shape = matches!(self.kind, LegacyWriteKind::RecoveryCopy)
            && self.backend == LegacyWriteBackend::Index
            && self.if_generation_match == Some(0)
            && self
                .source_object_name
                .as_deref()
                .is_some_and(|name| !name.is_empty())
            && self
                .source_generation
                .is_some_and(|generation| generation > 0)
            && self.ciphertext_b64.is_none()
            && self.wrapped_dek_b64.is_none();
        if !put_shape && !copy_shape {
            return Err(EnclaveError::Store(
                "invalid persisted legacy write intent request".into(),
            ));
        }
        match self.state {
            LegacyWriteIntentState::Prepared => {
                if self.owner_token.is_some()
                    || self.lease_expires_at_millis.is_some()
                    || self.outcome_generation.is_some()
                    || (!matches!(self.kind, LegacyWriteKind::RecoveryCopy)
                        && (self.ciphertext_b64.is_none() || self.wrapped_dek_b64.is_none()))
                {
                    return Err(EnclaveError::Store(
                        "invalid prepared legacy write intent".into(),
                    ));
                }
            }
            LegacyWriteIntentState::Requesting => {
                if self
                    .owner_token
                    .as_deref()
                    .is_none_or(|owner| !owner.starts_with("owner_") || owner.len() != 70)
                    || self
                        .lease_expires_at_millis
                        .is_none_or(|expiry| expiry <= 0)
                    || self.outcome_generation.is_some()
                    || (!matches!(self.kind, LegacyWriteKind::RecoveryCopy)
                        && (self.ciphertext_b64.is_none() || self.wrapped_dek_b64.is_none()))
                {
                    return Err(EnclaveError::Store(
                        "invalid requesting legacy write intent".into(),
                    ));
                }
            }
            LegacyWriteIntentState::Committed => {
                if self.owner_token.is_some()
                    || self.lease_expires_at_millis.is_some()
                    || self
                        .outcome_generation
                        .is_none_or(|generation| generation <= 0)
                    || self.ciphertext_b64.is_some()
                    || self.wrapped_dek_b64.is_some()
                {
                    return Err(EnclaveError::Store(
                        "invalid committed legacy write intent".into(),
                    ));
                }
            }
            LegacyWriteIntentState::Conflict | LegacyWriteIntentState::Fenced => {
                if self.owner_token.is_some()
                    || self.lease_expires_at_millis.is_some()
                    || self.outcome_generation.is_some()
                    || self.ciphertext_b64.is_some()
                    || self.wrapped_dek_b64.is_some()
                {
                    return Err(EnclaveError::Store(
                        "invalid terminal legacy write intent".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn request(&self) -> Result<LegacyWriteRequest> {
        if self.state.is_terminal() {
            return Err(EnclaveError::Store(
                "terminal legacy write intent has no request payload".into(),
            ));
        }
        if self.kind == LegacyWriteKind::RecoveryCopy {
            return Ok(LegacyWriteRequest::RecoveryCopy {
                source_object_name: self.source_object_name.clone().ok_or_else(|| {
                    EnclaveError::Store("legacy recovery intent lost its source".into())
                })?,
                source_generation: self.source_generation.ok_or_else(|| {
                    EnclaveError::Store("legacy recovery intent lost its generation".into())
                })?,
                destination_object_name: self.object_name.clone(),
            });
        }
        let ciphertext = B64
            .decode(self.ciphertext_b64.as_deref().ok_or_else(|| {
                EnclaveError::Store("legacy write intent lost its ciphertext".into())
            })?)
            .map_err(|_| EnclaveError::Store("invalid legacy write intent ciphertext".into()))?;
        let wrapped_dek_b64 = self.wrapped_dek_b64.clone().ok_or_else(|| {
            EnclaveError::Store("legacy write intent lost its wrapped key".into())
        })?;
        if sha256_hex_bytes(&ciphertext) != self.ciphertext_sha256
            || sha256_hex_bytes(wrapped_dek_b64.as_bytes()) != self.wrapped_dek_sha256
        {
            return Err(EnclaveError::Store(
                "legacy write intent request commitment mismatch".into(),
            ));
        }
        Ok(LegacyWriteRequest::Put {
            backend: self.backend,
            kind: self.kind,
            object_name: self.object_name.clone(),
            ciphertext,
            wrapped_dek_b64,
            if_generation_match: self.if_generation_match.ok_or_else(|| {
                EnclaveError::Store("legacy write intent lost its precondition".into())
            })?,
        })
    }

    fn terminal(&self, state: LegacyWriteIntentState, outcome_generation: Option<i64>) -> Self {
        debug_assert!(state.is_terminal());
        let mut terminal = self.clone();
        terminal.state = state;
        terminal.owner_token = None;
        terminal.lease_expires_at_millis = None;
        terminal.outcome_generation = outcome_generation;
        terminal.ciphertext_b64 = None;
        terminal.wrapped_dek_b64 = None;
        terminal
    }
}

async fn load_persisted_legacy_write_intent(
    gcs: &dyn GcsClient,
    object_name: &str,
) -> Result<PersistedLegacyWriteIntent> {
    let current = gcs.get_object(object_name).await?;
    if current.generation <= 0 || current.wrapped_dek_b64 != LEGACY_WRITE_INTENT_METADATA {
        return Err(EnclaveError::Store(
            "legacy write intent provider metadata is invalid".into(),
        ));
    }
    let intent: LegacyWriteIntent = serde_json::from_slice(&current.ciphertext)?;
    intent.validate(object_name)?;
    Ok(PersistedLegacyWriteIntent {
        object_name: object_name.to_string(),
        generation: current.generation,
        intent,
    })
}

async fn verify_persisted_legacy_write_intent_owner(
    gcs: &dyn GcsClient,
    claimed: &PersistedLegacyWriteIntent,
) -> Result<tokio::time::Instant> {
    let current = load_persisted_legacy_write_intent(gcs, &claimed.object_name).await?;
    // Anchor the request deadline before the provider-time read. Network
    // latency and scheduler delay therefore consume, rather than extend, the
    // lease budget returned by that authenticated response.
    let monotonic_before_provider_read = tokio::time::Instant::now();
    let trusted_now = gcs
        .trusted_time_millis(&claimed.object_name, current.generation)
        .await?;
    let lease_expiry = current.intent.lease_expires_at_millis.ok_or_else(|| {
        EnclaveError::Conflict("legacy write intent ownership lease disappeared".into())
    })?;
    if current.generation != claimed.generation
        || current.intent.state != LegacyWriteIntentState::Requesting
        || current.intent.owner_token != claimed.intent.owner_token
        || current.intent.lease_expires_at_millis != claimed.intent.lease_expires_at_millis
    {
        return Err(EnclaveError::Conflict(
            "legacy write intent ownership changed before provider request".into(),
        ));
    }
    let remaining = lease_expiry.saturating_sub(trusted_now);
    if remaining <= LEGACY_WRITE_PROVIDER_SAFETY_MILLIS {
        return Err(EnclaveError::Conflict(
            "legacy write intent lease is too near expiry for provider request".into(),
        ));
    }
    let maximum_request_millis = i64::try_from(LEGACY_WRITE_PROVIDER_TIMEOUT.as_millis())
        .map_err(|_| EnclaveError::Store("legacy write timeout exceeded i64".into()))?;
    let request_millis =
        maximum_request_millis.min(remaining.saturating_sub(LEGACY_WRITE_PROVIDER_SAFETY_MILLIS));
    let request_millis = u64::try_from(request_millis).map_err(|_| {
        EnclaveError::Conflict("legacy write intent request budget was not positive".into())
    })?;
    let deadline = monotonic_before_provider_read
        .checked_add(Duration::from_millis(request_millis))
        .ok_or_else(|| EnclaveError::Store("legacy write deadline overflowed".into()))?;
    if deadline <= tokio::time::Instant::now() {
        return Err(EnclaveError::Conflict(
            "legacy write intent request deadline elapsed during ownership verification".into(),
        ));
    }
    Ok(deadline)
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
            state: Arc::new(Mutex::new(UserActorState::default())),
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
    pub rowid: i64,
    pub episode_id: i64,
    pub delivery_version: i64,
    pub delivery_id: String,
    pub include_content: bool,
    pub state: String,
    pub attempt_count: i64,
    pub next_attempt_at: String,
    pub provider_message_id: Option<String>,
    pub response_status: Option<i64>,
    pub error_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct PushDeliveryRow {
    pub rowid: i64,
    pub episode_id: i64,
    pub installation_binding: String,
    pub delivery_version: i64,
    pub delivery_id: String,
    pub handoff_handle: String,
    pub collapse_id: String,
    pub state: String,
    pub attempt_count: i64,
    pub next_attempt_at: String,
    pub response_status: Option<i64>,
    pub error_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl std::fmt::Debug for PushDeliveryRow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PushDeliveryRow")
            .field("rowid", &self.rowid)
            .field("episode_id", &self.episode_id)
            .field("delivery_version", &self.delivery_version)
            .field("attempt_count", &self.attempt_count)
            .finish_non_exhaustive()
    }
}

impl Store {
    pub fn new(kms: Arc<dyn KmsClient>, gcs: Arc<dyn GcsClient>) -> Self {
        let media_gcs = Arc::clone(&gcs);
        Self::new_internal(kms, gcs, Arc::clone(&media_gcs), media_gcs)
    }

    pub fn new_with_media(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
    ) -> Self {
        Self::new_internal(kms, gcs, Arc::clone(&media_gcs), media_gcs)
    }

    /// Construct the Phase-0 split-media topology. The legacy client is
    /// deliberately explicit: production startup must not silently point it
    /// at another bucket when the baked migration evidence is absent.
    pub fn new_with_media_and_legacy(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
        legacy_media_gcs: Arc<dyn GcsClient>,
    ) -> Self {
        Self::new_internal(kms, gcs, media_gcs, legacy_media_gcs)
    }

    fn new_internal(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
        legacy_media_gcs: Arc<dyn GcsClient>,
    ) -> Self {
        let max_open = std::env::var("STORE_MAX_OPEN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(16usize)
            .max(1);
        Self::new_internal_with_max_open(kms, gcs, media_gcs, legacy_media_gcs, max_open)
    }

    fn new_internal_with_max_open(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
        legacy_media_gcs: Arc<dyn GcsClient>,
        max_open: usize,
    ) -> Self {
        Self::new_internal_with_max_open_and_shadow_capture(
            kms,
            gcs,
            media_gcs,
            legacy_media_gcs,
            max_open,
            None,
        )
    }

    #[allow(
        dead_code,
        reason = "reserved for separately reviewed default-off shadow runtime composition"
    )]
    pub(crate) fn new_internal_with_max_open_and_shadow_capture(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
        legacy_media_gcs: Arc<dyn GcsClient>,
        max_open: usize,
        shadow_capture: Option<StoreShadowCaptureSelection>,
    ) -> Self {
        Self::new_internal_with_max_open_shadow_capture_and_policy(
            kms,
            gcs,
            media_gcs,
            legacy_media_gcs,
            max_open,
            shadow_capture,
            StorePersistencePolicy::LegacySnapshot,
        )
    }

    fn new_internal_with_max_open_shadow_capture_and_policy(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        media_gcs: Arc<dyn GcsClient>,
        legacy_media_gcs: Arc<dyn GcsClient>,
        max_open: usize,
        shadow_capture: Option<StoreShadowCaptureSelection>,
        persistence_policy: StorePersistencePolicy,
    ) -> Self {
        Store {
            registry: Mutex::new(StoreRegistry {
                actors: HashMap::new(),
                open_users: HashMap::new(),
                blocked_users: HashSet::new(),
                recent_clean_evictions: HashMap::new(),
                access_clock: 0,
            }),
            registry_changed: Arc::new(Notify::new()),
            lifecycle_gates: Mutex::new(HashMap::new()),
            content_write_barrier: Arc::new(ContentWriteBarrier::default()),
            shadow_capture: StdRwLock::new(shadow_capture),
            persistence_policy,
            wal_authority_persistence: StdRwLock::new(HashMap::new()),
            wal_serving_authorities: StdRwLock::new(HashMap::new()),
            wal_serving_relaunch: StdRwLock::new(None),
            kms,
            gcs,
            media_gcs,
            legacy_media_gcs,
            max_open: max_open.max(1),
            checkpoint_clock: Arc::new(SystemTime::now),
            storage_metrics: StorageMetrics::default(),
            legacy_checkpoint_reconciliation: Mutex::new(LegacyCheckpointReconciliation::default()),
            legacy_fence_key: StdRwLock::new(initial_legacy_fence_key()),
            wal_deletion_lane: StdRwLock::new(None),
        }
    }

    /// Inactive test-only constructor for the fail-closed WAL logical-write
    /// gate. There is deliberately no environment, startup, config, route, or
    /// production constructor that can select this policy.
    #[cfg(test)]
    pub(crate) fn new_wal_logical_only_for_test(
        kms: Arc<dyn KmsClient>,
        gcs: Arc<dyn GcsClient>,
        max_open: usize,
    ) -> Self {
        let media = Arc::clone(&gcs);
        Self::new_internal_with_max_open_shadow_capture_and_policy(
            kms,
            gcs,
            Arc::clone(&media),
            media,
            max_open,
            None,
            StorePersistencePolicy::WalLogicalOnly,
        )
    }

    /// Install the KMS-protected key that separates provider fence names from
    /// identities retained in the decrypted control rows. A live process
    /// never changes keys: disagreement means its control authority changed
    /// underneath it and all marker operations fail closed until restart.
    pub(crate) fn install_legacy_fence_key(&self, key: [u8; 32]) -> Result<()> {
        #[cfg(test)]
        {
            let _ = key;
            Ok(())
        }
        #[cfg(not(test))]
        {
            let mut current = self
                .legacy_fence_key
                .write()
                .map_err(|_| EnclaveError::Store("legacy fence key lock poisoned".into()))?;
            match current.as_deref() {
                Some(existing) if existing == key.as_slice() => Ok(()),
                Some(_) => Err(EnclaveError::Conflict(
                    "durable control key changed while legacy fences were active".into(),
                )),
                None => {
                    *current = Some(Zeroizing::new(key));
                    Ok(())
                }
            }
        }
    }

    /// Install the per-user WAL-authority persistence selection by consuming
    /// the sealed Control-minted facts. Install-once per user: an identical
    /// re-install is idempotent, a different archive is a Conflict, and no
    /// removal exists. The sole production caller is serving startup, which
    /// installs every durable-terminal selection before request admission and
    /// fails startup closed on any refusal.
    pub(crate) fn install_wal_authority_persistence(
        &self,
        selection: crate::cp::control_store::WalAuthoritativePersistenceSelection,
    ) -> Result<()> {
        let user_id = selection.user_id().to_owned();
        validate_user_id(&user_id)?;
        let archive_id = *selection.archive_id().as_bytes();
        let mut selections = self.wal_authority_persistence.write().map_err(|_| {
            EnclaveError::Store("wal-authority persistence selections poisoned".into())
        })?;
        match selections.get(&user_id) {
            Some(existing) if *existing == archive_id => Ok(()),
            Some(_) => Err(EnclaveError::Conflict(
                "wal-authority persistence already selected for a different archive".into(),
            )),
            None => {
                selections.insert(user_id, archive_id);
                Ok(())
            }
        }
    }

    /// Register the launched WAL serving authority for one selected user.
    /// Requires the durable-terminal selection to already be installed (the
    /// authority's basis), and is install-once: a second registration for the
    /// same user is a Conflict. No removal exists.
    ///
    /// What the slot registers is supervised, not abandoned. The authority
    /// inside it is atomically replaceable by
    /// `recover_wal_serving_authority`, which is the ONLY mutator of the slot
    /// and runs only after the previous owner has been proven dead. A slot
    /// whose authority is terminal and whose relaunch is refused — no driver
    /// installed, budget spent, backoff pending, or quarantined — keeps
    /// refusing every call exactly as it does today, and the process restart
    /// remains the outer recovery. Nothing in startup, config, routes, or
    /// providers calls this yet; the sole intended caller is the config-gated
    /// startup relaunch.
    pub(crate) fn install_wal_serving_authority(
        &self,
        user_id: &str,
        archive_id: [u8; 16],
        authority: Arc<crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority>,
    ) -> Result<()> {
        validate_user_id(user_id)?;
        let selections = self.wal_authority_persistence.read().map_err(|_| {
            EnclaveError::Store("wal-authority persistence selections poisoned".into())
        })?;
        let selected = selections.get(user_id).copied();
        drop(selections);
        let Some(selected) = selected else {
            return Err(EnclaveError::Conflict(
                "wal serving authority requires the durable-terminal selection".into(),
            ));
        };
        if selected != archive_id {
            return Err(EnclaveError::Conflict(
                "wal serving authority bound a different archive than the selection".into(),
            ));
        }
        let mut authorities = self
            .wal_serving_authorities
            .write()
            .map_err(|_| EnclaveError::Store("wal serving authorities poisoned".into()))?;
        if authorities.contains_key(user_id) {
            return Err(EnclaveError::Conflict(
                "wal serving authority already registered".into(),
            ));
        }
        authorities.insert(
            user_id.to_owned(),
            Arc::new(WalServingLane::install(archive_id, authority)),
        );
        Ok(())
    }

    /// Install the in-process relaunch driver. Install-once, and the driver is
    /// the only construction path a slot replacement may use.
    pub(crate) fn install_wal_serving_relaunch(
        &self,
        driver: Arc<dyn WalServingRelaunch>,
    ) -> Result<()> {
        let mut installed = self
            .wal_serving_relaunch
            .write()
            .map_err(|_| EnclaveError::Store("wal serving relaunch driver poisoned".into()))?;
        if installed.is_some() {
            return Err(EnclaveError::Conflict(
                "wal serving relaunch driver already installed".into(),
            ));
        }
        *installed = Some(driver);
        Ok(())
    }

    /// True exactly when the user has a durable-terminal WAL-authority
    /// selection installed (never the whole-Store test seam): the users whose
    /// legacy blob must never load again.
    fn wal_selected(&self, user_id: &str) -> bool {
        match self.wal_authority_persistence.read() {
            Ok(selections) => selections.contains_key(user_id),
            // Poisoned lock fails closed to "selected": refusal, not legacy.
            Err(_) => true,
        }
    }

    /// True exactly when this process has already registered a launched WAL
    /// serving authority for the user. `install_wal_serving_authority` is
    /// install-once, so a launcher must ask this before launching: a second
    /// launch would acquire a competing WAL-owner lease and fence the
    /// authority that is already serving. A poisoned registry answers "yes",
    /// which refuses a new launch rather than racing one.
    pub(crate) fn has_wal_serving_authority(&self, user_id: &str) -> bool {
        match self.wal_serving_authorities.read() {
            Ok(authorities) => authorities.contains_key(user_id),
            Err(_) => true,
        }
    }

    /// Resolve the user's serving slot. The map's `std` guard is released
    /// before the caller can await anything: holding it across an await is
    /// both a deadlock risk and a `Send`-bound compile error.
    pub(crate) fn wal_serving_lane(&self, user_id: &str) -> Option<Arc<WalServingLane>> {
        self.wal_serving_authorities
            .read()
            .ok()
            .and_then(|authorities| authorities.get(user_id).cloned())
    }

    /// Replace a terminal serving authority in place, after proving the
    /// previous one is dead.
    ///
    /// This is the ONLY mutator of a slot's authority, and it is a replace,
    /// never a remove: the slot holds exactly one authority for its whole
    /// life. It never re-submits a client operation and never decides the fate
    /// of a retained commit — the durable stage decides, and the existing
    /// ladder resolves it on the client's own idempotent retry.
    ///
    /// Fencing rests on five facts, in order of the steps below:
    ///
    /// 1. Single-flight. `relaunch` serializes callers; the loser re-reads the
    ///    slot, finds it non-terminal, and issues no launch.
    /// 2. Terminal precondition AND proof of death. The trigger is the actor
    ///    task's own termination — never the lane's poison flag, which the
    ///    ordinary checkpoint path raises mid-root-advance. Then
    ///    `join_terminated` must SUCCEED: a timeout quarantines and never
    ///    constructs.
    /// 3. Monotonicity. `is_terminal()` reads an `AtomicBool` set by a drop
    ///    guard inside the actor future, so it is set when the future
    ///    completes or unwinds, never goes true -> false, and cannot be
    ///    invalidated between the check and the swap.
    /// 4. No third mutator. Registration is install-once and there is no
    ///    removal, so the guarded replace below is the only writer.
    /// 5. No witness relaxation. The successor re-enters the byte-identical
    ///    startup ladder; the durable stage picks the predicate, not the
    ///    driver, and no lease, witness, or evidence is fabricated.
    pub(crate) async fn recover_wal_serving_authority(
        &self,
        user_id: &str,
    ) -> Result<WalRecoveryOutcome> {
        let Some(lane) = self.wal_serving_lane(user_id) else {
            return Err(EnclaveError::Store(
                "wal-authoritative user has no serving authority".into(),
            ));
        };
        // Cheap pre-check under no lock at all.
        if !lane.current()?.is_terminal() {
            return Ok(WalRecoveryOutcome::AlreadyLive);
        }
        let driver = self
            .wal_serving_relaunch
            .read()
            .map_err(|_| EnclaveError::Store("wal serving relaunch driver poisoned".into()))?
            .as_ref()
            .map(Arc::clone);
        let Some(driver) = driver else {
            // No driver installed: a terminal slot stays terminal and the
            // process restart remains the recovery, exactly as today.
            return Ok(WalRecoveryOutcome::Backoff);
        };
        let mut guard = lane.relaunch.lock().await;
        // Re-read under the guard: another caller may have already replaced
        // the authority while this one waited.
        let current = lane.current()?;
        if !current.is_terminal() {
            return Ok(WalRecoveryOutcome::AlreadyLive);
        }
        if let WalLaneState::Quarantined(reason) = guard.state {
            return Ok(WalRecoveryOutcome::Quarantined(reason));
        }
        let now = tokio::time::Instant::now();
        if guard.next_attempt_at.is_some_and(|due| now < due) {
            return Ok(WalRecoveryOutcome::Backoff);
        }
        let first = *guard.first_attempt_at.get_or_insert(now);
        if now.duration_since(first) > WAL_RELAUNCH_WALL_DEADLINE {
            return Ok(Self::quarantine(
                &lane,
                &mut guard,
                WalQuarantineReason::DeadlineExceeded,
            ));
        }
        if guard.installed_generations >= crate::archive_v3_wal_owner::MAX_WAL_SERVING_GENERATIONS {
            return Ok(Self::quarantine(
                &lane,
                &mut guard,
                WalQuarantineReason::GenerationsExhausted,
            ));
        }
        // PROOF OF DEATH. Nothing is constructed before this resolves, and a
        // deadline expiry is never treated as death.
        if current
            .join_terminated(WAL_RELAUNCH_JOIN_DEADLINE)
            .await
            .is_err()
        {
            return Ok(Self::quarantine(
                &lane,
                &mut guard,
                WalQuarantineReason::Stuck,
            ));
        }
        let rebuilt = driver.rebuild(user_id).await;
        let (archive_id, replacement) = match rebuilt {
            Ok(rebuilt) => rebuilt,
            Err(_) => {
                // A failed build minted no lane and therefore no new owner
                // instance id, so it burned no durable attempt. It must not
                // consume the generation budget.
                guard.launch_failures = guard.launch_failures.saturating_add(1);
                lane.launch_failures_total
                    .fetch_add(1, AtomicOrdering::AcqRel);
                guard.defer(tokio::time::Instant::now());
                return Ok(WalRecoveryOutcome::Backoff);
            }
        };
        if archive_id != lane.archive_id {
            // Drop the orphan rather than serve a different archive under this
            // user's slot. It renewed a lease it will never use; the next
            // launch renews again through the same predicate.
            drop(replacement);
            return Ok(Self::quarantine(
                &lane,
                &mut guard,
                WalQuarantineReason::ArchiveMismatch,
            ));
        }
        {
            let mut slot = lane
                .current
                .write()
                .map_err(|_| EnclaveError::Store("wal serving slot poisoned".into()))?;
            *slot = replacement;
        }
        guard.installed_generations = guard.installed_generations.saturating_add(1);
        guard.backoff = WAL_RELAUNCH_BACKOFF_MIN;
        guard.next_attempt_at = None;
        // The wall deadline bounds ONE healing incident, so a successful heal
        // ends the incident and the next fault starts its own clock. Without
        // this the deadline ran from the process's first-ever relaunch, and a
        // second independent fault more than WAL_RELAUNCH_WALL_DEADLINE later
        // was quarantined with ZERO rebuild attempts — degrading the lane to
        // exactly the permanent outage this driver exists to end.
        //
        // `installed_generations` is deliberately NOT reset here, and must not
        // be. It is cumulative for the life of the lane because Control bumps
        // an operation's durable attempt each time it observes a new
        // owner_instance_id, so a long-pending operation accrues one attempt
        // per successful generation. Only a cumulative count keeps
        // MAX_WAL_SERVING_GENERATIONS strictly under MAX_WAL_OWNER_ATTEMPTS.
        // Resetting it would let repeated heals cross the durable cap and turn
        // a transient fault into restart-proof write-death.
        guard.first_attempt_at = None;
        lane.generation.fetch_add(1, AtomicOrdering::AcqRel);
        lane.relaunches_total.fetch_add(1, AtomicOrdering::AcqRel);
        Ok(WalRecoveryOutcome::Replaced)
    }

    fn quarantine(
        lane: &WalServingLane,
        guard: &mut WalRelaunchLedger,
        reason: WalQuarantineReason,
    ) -> WalRecoveryOutcome {
        if guard.state == WalLaneState::Serving {
            lane.quarantines_total.fetch_add(1, AtomicOrdering::AcqRel);
        }
        guard.state = WalLaneState::Quarantined(reason);
        WalRecoveryOutcome::Quarantined(reason)
    }

    /// Content-free aggregate serving health for the liveness probe. The event
    /// counters are the point: a genuine-corruption -> heal loop that stays
    /// under budget increments `relaunches_total` on every generation, so it
    /// cannot heal silently. State counts alone would show a steady
    /// `serving: 1` and hide it.
    pub(crate) fn wal_serving_health(&self) -> WalServingHealth {
        let mut health = WalServingHealth::default();
        let Ok(lanes) = self.wal_serving_authorities.read() else {
            return health;
        };
        for lane in lanes.values() {
            let quarantined = lane
                .relaunch
                .try_lock()
                .is_ok_and(|guard| matches!(guard.state, WalLaneState::Quarantined(_)));
            let terminal = lane.current().is_ok_and(|current| current.is_terminal());
            if quarantined {
                health.quarantined += 1;
            } else if terminal {
                health.terminal += 1;
            } else {
                health.serving += 1;
            }
            health.relaunches_total += lane.relaunches_total.load(AtomicOrdering::Acquire);
            health.launch_failures_total +=
                lane.launch_failures_total.load(AtomicOrdering::Acquire);
            health.quarantines_total += lane.quarantines_total.load(AtomicOrdering::Acquire);
        }
        health
    }

    /// Dual-path read: the single API domain code migrates onto. An
    /// unselected user reads through the ordinary guarded legacy path; a
    /// selected user's read routes to the registered serving authority's
    /// settled-only lane, and refuses as unavailable when no authority is
    /// registered — a WAL-authoritative user is never served the stale
    /// legacy snapshot, and closure errors surface unchanged.
    #[allow(
        dead_code,
        reason = "reserved for the per-domain routing migrations; serving remains intentionally unwired"
    )]
    pub(crate) async fn wal_authoritative_read<F, T>(&self, user_id: &str, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if !self.wal_selected(user_id) {
            return self.with_user_read(user_id, f).await;
        }
        let lane = self.wal_serving_lane(user_id).ok_or_else(|| {
            EnclaveError::Store("wal-authoritative user has no serving authority".into())
        })?;
        // Heal before the call, never retry after a failure: the closure is
        // not moved into a call that is going to fail, and a refused or
        // backing-off relaunch simply leaves the request to refuse as it does
        // today.
        if lane.current()?.is_terminal() {
            let _ = self.recover_wal_serving_authority(user_id).await;
        }
        let authority = lane.current()?;
        match authority.read(f).await {
            Ok(inner) => inner,
            Err(_) => Err(EnclaveError::Store(
                "wal serving authority is unavailable".into(),
            )),
        }
    }

    /// Route branch for the per-domain migrations: true exactly when the
    /// user has a durable-terminal WAL-authority selection, so the route
    /// takes the plan-and-submit path instead of the legacy mutation path.
    pub(crate) fn is_wal_authoritative(&self, user_id: &str) -> bool {
        self.wal_selected(user_id)
    }

    /// Submit one sealed, already-prepared logical plan through the selected
    /// user's serving authority. Acknowledgement is the typed decoded output,
    /// released only after immutable WAL publication and witness settlement.
    /// Routes must branch on `is_wal_authoritative` first: an unselected user
    /// refuses (their mutations stay on the legacy path), and a selected user
    /// with no registered authority refuses as unavailable. Owner-side
    /// refusals surface content-free: conflicts as Conflict (the client
    /// retries its durable outbox marker), everything else as unavailable.
    pub(crate) async fn wal_authoritative_submit<P>(
        &self,
        user_id: &str,
        prepared: crate::archive_v3_wal_idempotency::PreparedLogicalMutation<P>,
    ) -> Result<P::Output>
    where
        P: crate::archive_v3_wal_idempotency::WalLogicalDomainPlan,
    {
        if !self.wal_selected(user_id) {
            return Err(EnclaveError::Conflict(
                "wal-authoritative submit requires a selected user".into(),
            ));
        }
        let lane = self.wal_serving_lane(user_id).ok_or_else(|| {
            EnclaveError::Store("wal-authoritative user has no serving authority".into())
        })?;
        // Heal before the call. This is deliberately NOT a retry-after-failure
        // hook: a submit that died after `mark_send_started` has an unknown
        // outcome, and its retry must remain the client's own idempotent
        // outbox retry. The driver never re-submits an operation.
        if lane.current()?.is_terminal() {
            let _ = self.recover_wal_serving_authority(user_id).await;
        }
        let authority = lane.current()?;
        authority
            .submit(prepared)
            .await
            .map_err(|error| match error {
                crate::archive_v3_wal_owner::WalOwnerError::Conflict => {
                    EnclaveError::Conflict("wal submit conflicted; retry".into())
                }
                _ => EnclaveError::Store("wal serving authority is unavailable".into()),
            })
    }

    /// Resolve the persistence policy for one user: the WAL-logical policy
    /// applies when the whole Store was constructed with it (test seam) or
    /// when the user has a durable-terminal-backed WAL-authority selection.
    /// A poisoned selection lock fails closed to the non-persisting policy
    /// rather than ever letting a selected user reach snapshot persistence.
    fn persistence_policy_for(&self, user_id: &str) -> StorePersistencePolicy {
        if self.persistence_policy == StorePersistencePolicy::WalLogicalOnly {
            return StorePersistencePolicy::WalLogicalOnly;
        }
        match self.wal_authority_persistence.read() {
            Ok(selections) if selections.contains_key(user_id) => {
                StorePersistencePolicy::WalLogicalOnly
            }
            Ok(_) => StorePersistencePolicy::LegacySnapshot,
            Err(_) => StorePersistencePolicy::WalLogicalOnly,
        }
    }

    pub(crate) fn identity_rebind_fence_object_name(&self, user_id: &str) -> Result<String> {
        validate_user_id(user_id)?;
        let key = self
            .legacy_fence_key
            .read()
            .map_err(|_| EnclaveError::Store("legacy fence key lock poisoned".into()))?;
        let key = key.as_deref().ok_or_else(|| {
            EnclaveError::Store("durable legacy fence key is not initialized".into())
        })?;
        Ok(identity_rebind_fence_object_name_with_key(key, user_id))
    }

    pub(crate) fn legacy_fence_key_initialized(&self) -> Result<bool> {
        self.legacy_fence_key
            .read()
            .map(|key| key.is_some())
            .map_err(|_| EnclaveError::Store("legacy fence key lock poisoned".into()))
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

    /// Returns aggregate-only reconciliation progress. `ready` is false until
    /// one complete, error-free pass has verified today's checkpoint for every
    /// currently live legacy archive discovered through GCS listing.
    pub async fn legacy_checkpoint_reconciliation(&self) -> LegacyCheckpointReconciliation {
        self.legacy_checkpoint_reconciliation.lock().await.clone()
    }

    /// Reconcile legacy archives already present before the first new save.
    /// This runs serially (one GCS operation chain at a time), retains only one
    /// listing page, and retries later after failures. It never changes bucket
    /// lifecycle policy or archive authority.
    pub fn spawn_legacy_checkpoint_reconciler(store: Arc<Self>) {
        tokio::spawn(async move {
            let mut retry_delay = Duration::from_secs(5);
            loop {
                match store.reconcile_legacy_recovery_checkpoints_once().await {
                    Ok(progress) => {
                        info!(
                            target: "kioku::legacy_checkpoint_reconciliation",
                            ready = progress.ready,
                            completed_scans = progress.completed_scans,
                            listed_live_objects = progress.listed_live_objects,
                            live_archives_checked = progress.live_archives_checked,
                            checkpoints_verified = progress.checkpoints_verified,
                            failures = progress.failures,
                            "legacy recovery checkpoint reconciliation completed"
                        );
                        retry_delay = Duration::from_secs(3600);
                    }
                    Err(()) => {
                        let progress = store.legacy_checkpoint_reconciliation().await;
                        warn!(
                            target: "kioku::legacy_checkpoint_reconciliation",
                            ready = false,
                            listed_live_objects = progress.listed_live_objects,
                            live_archives_checked = progress.live_archives_checked,
                            checkpoints_verified = progress.checkpoints_verified,
                            failures = progress.failures,
                            retry_delay_seconds = retry_delay.as_secs(),
                            "legacy recovery checkpoint reconciliation incomplete; retrying"
                        );
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(300));
                    }
                }
                tokio::time::sleep(retry_delay).await;
            }
        });
    }

    /// One bounded-memory pass. Listing excludes noncurrent versions, and each
    /// listed name is explicitly read without a generation to bind the
    /// checkpoint to GCS's current live generation. Any listing/read mismatch
    /// fails the pass closed so readiness cannot be asserted on an incomplete
    /// view.
    pub async fn reconcile_legacy_recovery_checkpoints_once(
        &self,
    ) -> std::result::Result<LegacyCheckpointReconciliation, ()> {
        *self.legacy_checkpoint_reconciliation.lock().await =
            LegacyCheckpointReconciliation::default();
        let mut progress = LegacyCheckpointReconciliation::default();
        let now = (self.checkpoint_clock)();
        let mut page_token = None;
        // Keep fixed-size fingerprints rather than retaining every opaque
        // provider cursor. A repeated cursor always maps to the same bit and
        // fails closed; a collision can only stop a pass early, never let an
        // incomplete listing assert readiness.
        let mut seen_cursor_fingerprints = [0_u64; GCS_CURSOR_FINGERPRINT_WORDS];
        for _ in 0..MAX_GCS_LIST_PAGES {
            let page = match self
                .gcs
                .list_live_objects("indexes/", page_token.as_deref())
                .await
            {
                Ok(page) => page,
                Err(_) => {
                    return self
                        .finish_legacy_checkpoint_reconciliation(progress, false)
                        .await
                }
            };
            for listed in page.versions {
                progress.listed_live_objects = progress.listed_live_objects.saturating_add(1);
                let Some(user_id) = legacy_index_user_id(&listed.name) else {
                    return self
                        .finish_legacy_checkpoint_reconciliation(progress, false)
                        .await;
                };
                // This uses the same admission barrier as raw media writes.
                // A concurrent account deletion either waits for this exact
                // copy/verification or prevents it from starting before its
                // recovery-prefix inventory becomes authoritative.
                let lease = match self.acquire_content_write(&user_id).await {
                    Ok(lease) => lease,
                    Err(_) => {
                        return self
                            .finish_legacy_checkpoint_reconciliation(progress, false)
                            .await
                    }
                };
                let live = match self.gcs.get_object(&listed.name).await {
                    Ok(live) => live,
                    Err(EnclaveError::NotFound) => {
                        return self
                            .finish_legacy_checkpoint_reconciliation(progress, false)
                            .await
                    }
                    Err(_) => {
                        return self
                            .finish_legacy_checkpoint_reconciliation(progress, false)
                            .await
                    }
                };
                if live.generation <= 0 {
                    return self
                        .finish_legacy_checkpoint_reconciliation(progress, false)
                        .await;
                }
                progress.live_archives_checked = progress.live_archives_checked.saturating_add(1);
                if self
                    .ensure_legacy_recovery_checkpoint(
                        &user_id,
                        live.generation,
                        now,
                        lease.child(),
                        None,
                    )
                    .await
                    .is_err()
                {
                    return self
                        .finish_legacy_checkpoint_reconciliation(progress, false)
                        .await;
                }
                progress.checkpoints_verified = progress.checkpoints_verified.saturating_add(1);
            }
            match page.next_page_token {
                Some(next) => {
                    let mut hasher = DefaultHasher::new();
                    next.hash(&mut hasher);
                    let fingerprint = (hasher.finish() as usize) % GCS_CURSOR_FINGERPRINT_BITS;
                    let word = fingerprint / u64::BITS as usize;
                    let mask = 1_u64 << (fingerprint % u64::BITS as usize);
                    if seen_cursor_fingerprints[word] & mask != 0 {
                        return self
                            .finish_legacy_checkpoint_reconciliation(progress, false)
                            .await;
                    }
                    seen_cursor_fingerprints[word] |= mask;
                    page_token = Some(next);
                }
                None => {
                    progress.completed_scans = 1;
                    return self
                        .finish_legacy_checkpoint_reconciliation(progress, true)
                        .await;
                }
            }
        }
        self.finish_legacy_checkpoint_reconciliation(progress, false)
            .await
    }

    async fn finish_legacy_checkpoint_reconciliation(
        &self,
        mut progress: LegacyCheckpointReconciliation,
        ready: bool,
    ) -> std::result::Result<LegacyCheckpointReconciliation, ()> {
        progress.ready = ready;
        if !ready {
            progress.failures = 1;
        }
        *self.legacy_checkpoint_reconciliation.lock().await = progress.clone();
        if ready {
            Ok(progress)
        } else {
            Err(())
        }
    }

    #[cfg(test)]
    pub async fn put_media(&self, name: &str, data: &[u8], wrapped_dek_b64: &str) -> Result<i64> {
        self.put_media_at_generation(name, data, wrapped_dek_b64, 0)
            .await
    }

    /// Put media owned by one authenticated account. The explicit owner is
    /// required because historical object keys can be unscoped; deriving
    /// authority from a provider name would silently exempt those objects from
    /// the cross-instance identity-rebind fence.
    pub async fn put_user_media(
        &self,
        user_id: &str,
        name: &str,
        data: &[u8],
        wrapped_dek_b64: &str,
    ) -> Result<i64> {
        validate_user_id(user_id)?;
        let provider_lease = self.acquire_content_write(user_id).await?;
        self.execute_legacy_write_with_intent(
            user_id,
            LegacyWriteRequest::Put {
                backend: LegacyWriteBackend::Media,
                kind: LegacyWriteKind::MediaPut,
                object_name: name.to_string(),
                ciphertext: data.to_vec(),
                wrapped_dek_b64: wrapped_dek_b64.to_string(),
                if_generation_match: 0,
            },
            None,
            Some(provider_lease),
        )
        .await
    }

    /// Persist a stable rebind create through the same cross-instance intent
    /// protocol as ordinary legacy writes. The stable namespace has its own
    /// retained marker, installed by deletion before it drains this intent.
    pub(crate) async fn put_stable_rebind_index(
        &self,
        stable_user_id: &str,
        object_name: &str,
        ciphertext: &[u8],
        wrapped_dek_b64: &str,
    ) -> Result<i64> {
        validate_user_id(stable_user_id)?;
        self.reconcile_unfenced_legacy_write_intents(stable_user_id)
            .await?;
        self.execute_legacy_write_with_intent(
            stable_user_id,
            LegacyWriteRequest::Put {
                backend: LegacyWriteBackend::Index,
                kind: LegacyWriteKind::StableCreate,
                object_name: object_name.to_string(),
                ciphertext: ciphertext.to_vec(),
                wrapped_dek_b64: wrapped_dek_b64.to_string(),
                if_generation_match: 0,
            },
            None,
            None,
        )
        .await
    }

    /// Settle a crash-left stable-create intent before the control state
    /// decides whether a new create is required. This prevents a restart from
    /// issuing a second randomized ciphertext after the first exact intent
    /// already committed at the provider.
    pub(crate) async fn reconcile_stable_rebind_intents(&self, stable_user_id: &str) -> Result<()> {
        validate_user_id(stable_user_id)?;
        self.reconcile_unfenced_legacy_write_intents(stable_user_id)
            .await
    }

    async fn persist_legacy_write_intent(
        &self,
        object_name: &str,
        intent: &LegacyWriteIntent,
        if_generation_match: i64,
    ) -> Result<i64> {
        intent.validate(object_name)?;
        let encoded = serde_json::to_vec(intent)?;
        let put = self
            .gcs
            .put_object(
                object_name,
                &encoded,
                LEGACY_WRITE_INTENT_METADATA,
                if_generation_match,
            )
            .await;
        match put {
            Ok(generation) => Ok(generation),
            Err(error) => match self.gcs.get_object(object_name).await {
                Ok(current)
                    if current.generation > if_generation_match
                        && current.wrapped_dek_b64 == LEGACY_WRITE_INTENT_METADATA
                        && current.ciphertext == encoded =>
                {
                    Ok(current.generation)
                }
                _ => Err(error),
            },
        }
    }

    async fn load_legacy_write_intent(
        &self,
        object_name: &str,
    ) -> Result<PersistedLegacyWriteIntent> {
        load_persisted_legacy_write_intent(self.gcs.as_ref(), object_name).await
    }

    async fn create_legacy_write_intent(
        &self,
        user_id: &str,
        request: &LegacyWriteRequest,
    ) -> Result<PersistedLegacyWriteIntent> {
        let intent = LegacyWriteIntent::prepared(user_id, request);
        let object_name = legacy_write_intent_object_name(user_id, &intent.request_id);
        let generation = self
            .persist_legacy_write_intent(&object_name, &intent, 0)
            .await?;
        Ok(PersistedLegacyWriteIntent {
            object_name,
            generation,
            intent,
        })
    }

    async fn identity_write_fence_authority(&self, user_id: &str) -> Result<Option<String>> {
        let marker_name = self.identity_rebind_fence_object_name(user_id)?;
        match self.gcs.get_object(&marker_name).await {
            Err(EnclaveError::NotFound) => Ok(None),
            Err(error) => Err(error),
            Ok(marker) => {
                let authority = String::from_utf8(marker.ciphertext).map_err(|_| {
                    EnclaveError::Store("legacy content fence authority is invalid".into())
                })?;
                let valid_authority = valid_legacy_fence_authority(&authority);
                if marker.generation <= 0
                    || marker.wrapped_dek_b64 != IDENTITY_REBIND_FENCE_METADATA
                    || !valid_authority
                {
                    return Err(EnclaveError::Store(
                        "legacy content fence provider state is invalid".into(),
                    ));
                }
                Ok(Some(authority))
            }
        }
    }

    async fn terminalize_legacy_write_intent(
        &self,
        persisted: &PersistedLegacyWriteIntent,
        state: LegacyWriteIntentState,
        outcome_generation: Option<i64>,
    ) -> Result<PersistedLegacyWriteIntent> {
        let terminal = persisted.intent.terminal(state, outcome_generation);
        let terminalized = match self
            .persist_legacy_write_intent(&persisted.object_name, &terminal, persisted.generation)
            .await
        {
            Ok(generation) => Ok(PersistedLegacyWriteIntent {
                object_name: persisted.object_name.clone(),
                generation,
                intent: terminal,
            }),
            Err(error) => {
                let current = self
                    .load_legacy_write_intent(&persisted.object_name)
                    .await?;
                if current.intent.state == state
                    && current.intent.outcome_generation == outcome_generation
                {
                    Ok(current)
                } else {
                    Err(EnclaveError::Store(format!(
                        "legacy write intent terminalization failed: {error}"
                    )))
                }
            }
        }?;
        self.purge_legacy_write_intent_payload_generations(
            &terminalized.object_name,
            terminalized.generation,
        )
        .await?;
        Ok(terminalized)
    }

    async fn purge_legacy_write_intent_payload_generations(
        &self,
        object_name: &str,
        retained_terminal_generation: i64,
    ) -> Result<()> {
        for _ in 0..MAX_GCS_LIST_PAGES {
            let page = self.gcs.list_object_versions(object_name, None).await?;
            let stale = page.versions.into_iter().find(|version| {
                version.name == object_name && version.generation != retained_terminal_generation
            });
            match stale {
                Some(version) => {
                    self.gcs
                        .delete_object_generation(object_name, version.generation)
                        .await?;
                }
                None if page.next_page_token.is_none() => return Ok(()),
                None => {
                    return Err(EnclaveError::Gcs(
                        "legacy write intent retained generation was not in the first bounded page"
                            .into(),
                    ))
                }
            }
        }
        Err(EnclaveError::Gcs(
            "legacy write intent version listing exceeded its page bound".into(),
        ))
    }

    async fn claim_legacy_write_intent(
        &self,
        persisted: &PersistedLegacyWriteIntent,
    ) -> Result<PersistedLegacyWriteIntent> {
        if !matches!(
            persisted.intent.state,
            LegacyWriteIntentState::Prepared | LegacyWriteIntentState::Requesting
        ) {
            return Err(EnclaveError::Conflict(
                "legacy write intent is already terminal".into(),
            ));
        }
        let mut claimed = persisted.intent.clone();
        claimed.state = LegacyWriteIntentState::Requesting;
        claimed.owner_token = Some(format!("owner_{}", crate::cp::tokens::random_token_hex()));
        claimed.lease_expires_at_millis = Some(
            self.gcs
                .trusted_time_millis(&persisted.object_name, persisted.generation)
                .await?
                .saturating_add(LEGACY_WRITE_INTENT_LEASE_MILLIS),
        );
        let generation = self
            .persist_legacy_write_intent(&persisted.object_name, &claimed, persisted.generation)
            .await?;
        Ok(PersistedLegacyWriteIntent {
            object_name: persisted.object_name.clone(),
            generation,
            intent: claimed,
        })
    }

    async fn execute_claimed_legacy_write_intent(
        &self,
        claimed: PersistedLegacyWriteIntent,
        provider_lease: Option<ContentWriteLease>,
    ) -> Result<i64> {
        // Keep both the write barrier lease and the provider request in this
        // future. A caller cancellation therefore drops the provider future;
        // there is no detached task that can outlive intent ownership.
        let _provider_lease = provider_lease;
        let request = claimed.intent.request()?;
        match request {
            LegacyWriteRequest::Put {
                backend,
                object_name,
                ciphertext,
                wrapped_dek_b64,
                if_generation_match,
                ..
            } => {
                let provider = match backend {
                    LegacyWriteBackend::Index => Arc::clone(&self.gcs),
                    LegacyWriteBackend::Media => Arc::clone(&self.media_gcs),
                };
                let request_object_name = object_name.clone();
                let request_ciphertext = ciphertext.clone();
                let request_wrapped_dek = wrapped_dek_b64.clone();
                let intent_gcs = Arc::clone(&self.gcs);
                let claim_authority = claimed.clone();
                let request_deadline = verify_persisted_legacy_write_intent_owner(
                    intent_gcs.as_ref(),
                    &claim_authority,
                )
                .await?;
                let outcome = tokio::time::timeout_at(request_deadline, async {
                    let response = provider
                        .put_object(
                            &request_object_name,
                            &request_ciphertext,
                            &request_wrapped_dek,
                            if_generation_match,
                        )
                        .await;
                    match response {
                        Ok(generation) => Ok(generation),
                        Err(error) => match provider.get_object(&request_object_name).await {
                            Ok(current)
                                if current.generation > if_generation_match
                                    && current.wrapped_dek_b64 == request_wrapped_dek
                                    && current.ciphertext == request_ciphertext =>
                            {
                                Ok(current.generation)
                            }
                            _ if matches!(&error, EnclaveError::Conflict(_)) => Err(error),
                            _ => Err(error),
                        },
                    }
                })
                .await
                .map_err(|_| EnclaveError::Gcs("legacy write provider timeout".into()))?;
                match outcome {
                    Ok(generation) => {
                        self.terminalize_legacy_write_intent(
                            &claimed,
                            LegacyWriteIntentState::Committed,
                            Some(generation),
                        )
                        .await?;
                        Ok(generation)
                    }
                    Err(error) => {
                        self.terminalize_legacy_write_intent(
                            &claimed,
                            LegacyWriteIntentState::Conflict,
                            None,
                        )
                        .await?;
                        Err(error)
                    }
                }
            }
            LegacyWriteRequest::RecoveryCopy {
                source_object_name,
                source_generation,
                destination_object_name,
            } => {
                let copy_gcs = Arc::clone(&self.gcs);
                let copy_source = source_object_name.clone();
                let copy_destination = destination_object_name.clone();
                let intent_gcs = Arc::clone(&self.gcs);
                let claim_authority = claimed.clone();
                let request_deadline = verify_persisted_legacy_write_intent_owner(
                    intent_gcs.as_ref(),
                    &claim_authority,
                )
                .await?;
                let generation = tokio::time::timeout_at(request_deadline, async {
                    let copied = match copy_gcs
                        .copy_generation_if_absent(
                            &copy_source,
                            source_generation,
                            &copy_destination,
                        )
                        .await
                    {
                        Ok(copied) => copied,
                        Err(first_error) => {
                            // The create-only copy is idempotent: a second
                            // exact attempt either adopts the already-created
                            // bound destination or repeats the same source
                            // generation. Both attempts share this one owned
                            // timeout, so ambiguity handling cannot outlive
                            // the intent lease.
                            match copy_gcs
                                .copy_generation_if_absent(
                                    &copy_source,
                                    source_generation,
                                    &copy_destination,
                                )
                                .await
                            {
                                Ok(copied) => copied,
                                Err(_) => return Err(first_error),
                            }
                        }
                    };
                    if copied.source.generation != source_generation {
                        return Err(EnclaveError::Gcs(
                            "legacy recovery source generation did not match requested generation"
                                .into(),
                        ));
                    }
                    verify_legacy_recovery_copy(
                        &copy_source,
                        source_generation,
                        &copied.source,
                        &copied.destination,
                        copied.created,
                    )?;
                    Ok(copied.destination.generation)
                })
                .await
                .map_err(|_| EnclaveError::Gcs("legacy recovery provider timeout".into()))??;
                self.terminalize_legacy_write_intent(
                    &claimed,
                    LegacyWriteIntentState::Committed,
                    Some(generation),
                )
                .await?;
                Ok(generation)
            }
        }
    }

    async fn execute_legacy_write_with_intent(
        &self,
        user_id: &str,
        request: LegacyWriteRequest,
        allowed_marker_authority: Option<&str>,
        provider_lease: Option<ContentWriteLease>,
    ) -> Result<i64> {
        validate_user_id(user_id)?;
        let prepared = self.create_legacy_write_intent(user_id, &request).await?;
        let marker = self.identity_write_fence_authority(user_id).await?;
        if marker.as_deref() != allowed_marker_authority {
            self.terminalize_legacy_write_intent(&prepared, LegacyWriteIntentState::Fenced, None)
                .await?;
            return Err(EnclaveError::Auth(
                "retained provider marker fenced the legacy write".into(),
            ));
        }
        let claimed = self.claim_legacy_write_intent(&prepared).await?;
        self.execute_claimed_legacy_write_intent(claimed, provider_lease)
            .await
    }

    async fn drain_one_legacy_write_intent(
        &self,
        mut persisted: PersistedLegacyWriteIntent,
        fence_prepared: bool,
    ) -> Result<bool> {
        loop {
            match persisted.intent.state {
                state if state.is_terminal() => {
                    self.purge_legacy_write_intent_payload_generations(
                        &persisted.object_name,
                        persisted.generation,
                    )
                    .await?;
                    return Ok(true);
                }
                LegacyWriteIntentState::Prepared => {
                    if !fence_prepared {
                        let claimed = match self.claim_legacy_write_intent(&persisted).await {
                            Ok(claimed) => claimed,
                            Err(EnclaveError::Conflict(_)) => {
                                persisted = self
                                    .load_legacy_write_intent(&persisted.object_name)
                                    .await?;
                                continue;
                            }
                            Err(error) => return Err(error),
                        };
                        self.execute_claimed_legacy_write_intent(claimed, None)
                            .await?;
                        return Ok(true);
                    }
                    match self
                        .terminalize_legacy_write_intent(
                            &persisted,
                            LegacyWriteIntentState::Fenced,
                            None,
                        )
                        .await
                    {
                        Ok(_) => return Ok(true),
                        Err(EnclaveError::Conflict(_)) => {
                            persisted = self
                                .load_legacy_write_intent(&persisted.object_name)
                                .await?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                LegacyWriteIntentState::Requesting => {
                    let now = self
                        .gcs
                        .trusted_time_millis(&persisted.object_name, persisted.generation)
                        .await?;
                    if persisted
                        .intent
                        .lease_expires_at_millis
                        .is_some_and(|expiry| expiry > now)
                    {
                        return Ok(false);
                    }
                    let claimed = match self.claim_legacy_write_intent(&persisted).await {
                        Ok(claimed) => claimed,
                        Err(EnclaveError::Conflict(_)) => {
                            persisted = self
                                .load_legacy_write_intent(&persisted.object_name)
                                .await?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    self.execute_claimed_legacy_write_intent(claimed, None)
                        .await?;
                    return Ok(true);
                }
                _ => unreachable!("terminal legacy write intent handled above"),
            }
        }
    }

    /// Strongly consistently inventory every durable pre-marker request. The
    /// marker is already live before this scan: intents created later must see
    /// it and terminalize without destination I/O. Prepared intents are
    /// fenced here; requesting intents are either awaited or taken over after
    /// a lease longer than the bounded provider request timeout.
    async fn drain_legacy_write_intents(&self, user_id: &str) -> Result<()> {
        let prefix = legacy_write_intent_prefix(user_id);
        let mut page_token = None;
        let mut unsettled = false;
        for _ in 0..MAX_GCS_LIST_PAGES {
            let page = self
                .gcs
                .list_live_objects(&prefix, page_token.as_deref())
                .await?;
            for listed in page.versions {
                if !listed.name.starts_with(&prefix) {
                    return Err(EnclaveError::Store(
                        "legacy write intent listing escaped its exact prefix".into(),
                    ));
                }
                let persisted = self.load_legacy_write_intent(&listed.name).await?;
                unsettled |= !self.drain_one_legacy_write_intent(persisted, true).await?;
            }
            match page.next_page_token {
                None => {
                    let soft_deleted =
                        matching_soft_deleted_inventory(self.gcs.as_ref(), &prefix, false).await?;
                    if soft_deleted.found {
                        return Err(soft_deleted_account_objects_error(soft_deleted));
                    }
                    if unsettled {
                        return Err(legacy_write_intent_unsettled_error());
                    }
                    return Ok(());
                }
                Some(next) if page_token.as_deref() != Some(next.as_str()) => {
                    page_token = Some(next)
                }
                Some(_) => {
                    return Err(EnclaveError::Gcs(
                        "legacy write intent listing repeated a page cursor".into(),
                    ))
                }
            }
        }
        Err(EnclaveError::Gcs(
            "legacy write intent listing exceeded its page bound".into(),
        ))
    }

    /// Resume crash-left intents while no retained marker exists. Prepared
    /// requests are claimed and sent from their encrypted exact payload;
    /// expired Requesting leases are taken over by the shared drain helper.
    /// If a marker appeared first, switch to the fencing drain instead.
    async fn reconcile_unfenced_legacy_write_intents(&self, user_id: &str) -> Result<()> {
        if self
            .identity_write_fence_authority(user_id)
            .await?
            .is_some()
        {
            return self.drain_legacy_write_intents(user_id).await;
        }
        let prefix = legacy_write_intent_prefix(user_id);
        let mut page_token = None;
        let mut unsettled = false;
        for _ in 0..MAX_GCS_LIST_PAGES {
            let page = self
                .gcs
                .list_live_objects(&prefix, page_token.as_deref())
                .await?;
            for listed in page.versions {
                if !listed.name.starts_with(&prefix) {
                    return Err(EnclaveError::Store(
                        "legacy write intent listing escaped its exact prefix".into(),
                    ));
                }
                let persisted = self.load_legacy_write_intent(&listed.name).await?;
                unsettled |= !self.drain_one_legacy_write_intent(persisted, false).await?;
            }
            match page.next_page_token {
                None => {
                    if unsettled {
                        return Err(legacy_write_intent_unsettled_error());
                    }
                    return Ok(());
                }
                Some(next) if page_token.as_deref() != Some(next.as_str()) => {
                    page_token = Some(next)
                }
                Some(_) => {
                    return Err(EnclaveError::Gcs(
                        "legacy write intent listing repeated a page cursor".into(),
                    ))
                }
            }
        }
        Err(EnclaveError::Gcs(
            "legacy write intent listing exceeded its page bound".into(),
        ))
    }

    /// Create or adopt the retained provider marker, then drain the bounded,
    /// strongly consistent intent inventory. The returned exact authority is
    /// required only by rebind/deletion-owned writes that intentionally settle
    /// state after the marker; ordinary writers accept only marker absence.
    pub(crate) async fn fence_and_drain_legacy_writes(
        &self,
        user_id: &str,
        proposed_authority: &str,
    ) -> Result<String> {
        validate_user_id(user_id)?;
        if !valid_legacy_fence_authority(proposed_authority) {
            return Err(EnclaveError::Store(
                "invalid proposed legacy write fence authority".into(),
            ));
        }
        let marker_name = self.identity_rebind_fence_object_name(user_id)?;
        let put = self
            .gcs
            .put_object(
                &marker_name,
                proposed_authority.as_bytes(),
                IDENTITY_REBIND_FENCE_METADATA,
                0,
            )
            .await;
        if let Err(error) = put {
            let observed = self.identity_write_fence_authority(user_id).await?;
            if observed.is_none() {
                return Err(error);
            }
        }
        let authority = self
            .identity_write_fence_authority(user_id)
            .await?
            .ok_or_else(|| EnclaveError::Store("legacy write fence disappeared".into()))?;
        self.drain_legacy_write_intents(user_id).await?;
        Ok(authority)
    }

    #[cfg(test)]
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

    /// Admit a raw-content write before it performs its first preflight, KMS,
    /// or GCS operation. The returned lease must remain alive through the
    /// durable database save; move a child into an owned provider task when a
    /// request cancellation must not abandon an in-flight PUT.
    pub async fn acquire_content_write(&self, user_id: &str) -> Result<ContentWriteLease> {
        self.acquire_content_write_inner(user_id, false)
    }

    /// The deletion path has already closed admission before it reaches its
    /// forced local flush.  It still needs a lease for any cancellation-safe
    /// provider work it starts, but must be allowed to obtain that lease after
    /// installing its own fence.
    fn acquire_content_write_for_deletion(&self, user_id: &str) -> Result<ContentWriteLease> {
        self.acquire_content_write_inner(user_id, true)
    }

    fn acquire_content_write_inner(
        &self,
        user_id: &str,
        allow_already_blocked: bool,
    ) -> Result<ContentWriteLease> {
        validate_user_id(user_id)?;
        let mut state = self
            .content_write_barrier
            .state
            .lock()
            .expect("content barrier poisoned");
        if state.blocked_users.contains(user_id) && !allow_already_blocked {
            return Err(deleted_user_error());
        }
        let count = state.active_writes.entry(user_id.to_string()).or_default();
        *count = count.saturating_add(1);
        Ok(ContentWriteLease {
            barrier: Arc::clone(&self.content_write_barrier),
            user_id: user_id.to_string(),
        })
    }

    /// Atomically prohibit future content writes and wait for every writer
    /// admitted before the fence to settle. This is intentionally invoked
    /// before the actor deletion fence so a request cannot pass a preflight,
    /// start a raw PUT, and then recreate content after deletion inventory.
    async fn block_content_writes_for_deletion(&self, user_id: &str) {
        loop {
            let notified = self.content_write_barrier.changed.notified();
            let pending = {
                let mut state = self
                    .content_write_barrier
                    .state
                    .lock()
                    .expect("content barrier poisoned");
                state.blocked_users.insert(user_id.to_string());
                state.active_writes.get(user_id).copied().unwrap_or(0)
            };
            if pending == 0 {
                return;
            }
            notified.await;
        }
    }

    pub async fn get_media(&self, name: &str) -> Result<crate::store::GcsGetResponse> {
        match self.media_gcs.get_object(name).await {
            Ok(object) => Ok(object),
            Err(EnclaveError::NotFound) => self.legacy_media_gcs.get_object(name).await,
            Err(error) => Err(error),
        }
    }

    /// Read only the current raw-media provider. Canonical capture receipts
    /// bind this backend and must never fall back to the legacy bucket.
    pub(crate) async fn get_current_media(&self, name: &str) -> Result<GcsGetResponse> {
        self.media_gcs.get_object(name).await
    }

    /// Read the exact current-provider generation sealed into a canonical
    /// capture receipt. This is distinct from compatibility media reads, which
    /// may intentionally fall back to the legacy bucket.
    pub(crate) async fn get_current_media_generation(
        &self,
        name: &str,
        generation: i64,
    ) -> Result<GcsGetResponse> {
        if generation <= 0 {
            return Err(EnclaveError::Store(
                "canonical capture generation must be positive".into(),
            ));
        }
        self.media_gcs.get_object_generation(name, generation).await
    }

    fn unique_media_providers(&self) -> impl Iterator<Item = &Arc<dyn GcsClient>> {
        std::iter::once(&self.media_gcs).chain(
            (!Arc::ptr_eq(&self.media_gcs, &self.legacy_media_gcs))
                .then_some(&self.legacy_media_gcs),
        )
    }

    pub async fn delete_media(&self, name: &str) -> Result<()> {
        self.delete_media_on_both(name, None).await
    }

    /// Delete one retained logical media object without assuming provider
    /// generations are comparable. New rows name the current backend and use
    /// their exact recorded generation there. Legacy migration shadows (and
    /// pre-provenance rows) are deleted only after their independently returned
    /// generation decrypts under the exact owner/key context and matches the
    /// row's persisted plaintext SHA-256.
    pub async fn delete_retained_media(
        &self,
        user_id: &str,
        name: &str,
        generation: Option<i64>,
        object_backend: Option<&str>,
        expected_sha256: &str,
    ) -> Result<()> {
        validate_user_id(user_id)?;
        if generation.is_some_and(|value| value <= 0)
            || expected_sha256.len() != 64
            || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || (object_backend == Some("current") && generation.is_none())
        {
            return Err(EnclaveError::Store(
                "invalid retained media deletion identity".into(),
            ));
        }
        if !matches!(object_backend, None | Some("current")) {
            return Err(EnclaveError::Store(
                "invalid retained media backend provenance".into(),
            ));
        }

        let current_exact = if let Some(generation) = generation {
            match self.media_gcs.get_object_generation(name, generation).await {
                Ok(object) => Some(object),
                Err(EnclaveError::NotFound) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let legacy_exact = if let (None, Some(generation)) = (object_backend, generation) {
            match self
                .legacy_media_gcs
                .get_object_generation(name, generation)
                .await
            {
                Ok(object) => Some(object),
                Err(EnclaveError::NotFound) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let current_live = if object_backend.is_none() {
            match self.media_gcs.get_object(name).await {
                Ok(object) => Some(object),
                Err(EnclaveError::NotFound) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let legacy_live = match self.legacy_media_gcs.get_object(name).await {
            Ok(object) => Some(object),
            Err(EnclaveError::NotFound) => None,
            Err(error) => return Err(error),
        };

        let mut current_generations = HashSet::new();
        let mut legacy_generations = HashSet::new();
        if let Some(object) = current_exact {
            if self
                .retained_media_identity_matches(user_id, name, &object, expected_sha256)
                .await?
            {
                current_generations.insert(object.generation);
            } else {
                return Err(EnclaveError::Store(
                    "current media candidate does not match its retained identity".into(),
                ));
            }
        }
        if let Some(object) = current_live {
            if self
                .retained_media_identity_matches(user_id, name, &object, expected_sha256)
                .await?
            {
                current_generations.insert(object.generation);
            } else {
                return Err(EnclaveError::Store(
                    "current media key has an unverified live generation".into(),
                ));
            }
        }
        if let Some(object) = legacy_exact {
            if self
                .retained_media_identity_matches(user_id, name, &object, expected_sha256)
                .await?
            {
                legacy_generations.insert(object.generation);
            } else {
                return Err(EnclaveError::Store(
                    "legacy media candidate does not match its retained identity".into(),
                ));
            }
        }
        if let Some(object) = legacy_live {
            if self
                .retained_media_identity_matches(user_id, name, &object, expected_sha256)
                .await?
            {
                legacy_generations.insert(object.generation);
            } else {
                return Err(EnclaveError::Store(
                    "legacy media key has an unverified live generation".into(),
                ));
            }
        }

        // Delete migration shadows first. If that provider fails, the exact
        // current generation remains available as authenticated retry evidence.
        for candidate_generation in legacy_generations {
            match self
                .legacy_media_gcs
                .delete_object_generation(name, candidate_generation)
                .await
            {
                Ok(()) | Err(EnclaveError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        for candidate_generation in current_generations {
            match self
                .media_gcs
                .delete_object_generation(name, candidate_generation)
                .await
            {
                Ok(()) | Err(EnclaveError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn retained_media_identity_matches(
        &self,
        user_id: &str,
        name: &str,
        object: &GcsGetResponse,
        expected_sha256: &str,
    ) -> Result<bool> {
        let dek = load_dek(self.kms.as_ref(), &object.wrapped_dek_b64).await?;
        let opened =
            decrypt_bound_blob(&dek, &object.ciphertext, &media_blob_context(user_id, name))?;
        let actual_sha256 = format!("{:x}", Sha256::digest(&opened.plaintext));
        Ok(actual_sha256.eq_ignore_ascii_case(expected_sha256))
    }

    /// Remove a media object from both migration providers. A missing object
    /// on one provider is expected when the key belongs to the other bucket;
    /// any other error is retained so callers cannot mark physical cleanup
    /// complete after a partial provider failure.
    async fn delete_media_on_both(&self, name: &str, generation: Option<i64>) -> Result<()> {
        let current = match generation {
            Some(generation) => {
                self.media_gcs
                    .delete_object_generation(name, generation)
                    .await
            }
            None => self.media_gcs.delete_object(name).await,
        };
        let legacy = match generation {
            Some(generation) => {
                self.legacy_media_gcs
                    .delete_object_generation(name, generation)
                    .await
            }
            None => self.legacy_media_gcs.delete_object(name).await,
        };
        match (current, legacy) {
            (Ok(()), Ok(()))
            | (Ok(()), Err(EnclaveError::NotFound))
            | (Err(EnclaveError::NotFound), Ok(())) => Ok(()),
            (Err(EnclaveError::NotFound), Err(EnclaveError::NotFound)) => {
                Err(EnclaveError::NotFound)
            }
            (Err(error), Ok(())) | (Err(error), Err(EnclaveError::NotFound)) => Err(error),
            (Ok(()), Err(error)) | (Err(EnclaveError::NotFound), Err(error)) => Err(error),
            (Err(error), Err(_)) => Err(error),
        }
    }

    /// Serialize one account's cloud-write lifecycle with deletion. The gate
    /// is process-local and contains no customer data.
    pub async fn lock_user_lifecycle(&self, user_id: &str) -> Result<OwnedMutexGuard<()>> {
        validate_user_id(user_id)?;
        let gate = {
            let mut gates = self.lifecycle_gates.lock().await;
            Arc::clone(
                gates
                    .entry(user_id.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        Ok(gate.lock_owned().await)
    }

    async fn lock_user_lifecycles(
        &self,
        first_user_id: &str,
        second_user_id: &str,
    ) -> Result<Vec<OwnedMutexGuard<()>>> {
        let (first, second) = if first_user_id <= second_user_id {
            (first_user_id, second_user_id)
        } else {
            (second_user_id, first_user_id)
        };
        let mut guards = vec![self.lock_user_lifecycle(first).await?];
        if first != second {
            guards.push(self.lock_user_lifecycle(second).await?);
        }
        Ok(guards)
    }

    async fn block_content_writes_for_users(&self, user_ids: [&str; 2]) {
        loop {
            let notified = self.content_write_barrier.changed.notified();
            let pending = {
                let mut state = self
                    .content_write_barrier
                    .state
                    .lock()
                    .expect("content barrier poisoned");
                for user_id in user_ids {
                    state.blocked_users.insert(user_id.to_string());
                }
                user_ids
                    .iter()
                    .map(|user_id| state.active_writes.get(*user_id).copied().unwrap_or(0))
                    .sum::<usize>()
            };
            if pending == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Acquire the exact user's lifecycle gate without changing local
    /// admission. The caller must recheck terminal Control state while this
    /// value is alive, then consume it through `begin`. The input is a
    /// non-cloneable encrypted-control capability, never a raw user/archive
    /// pair. This method is intentionally not wired to production startup.
    pub(crate) async fn acquire_archive_maintenance_admission(
        self: &Arc<Self>,
        _token: crate::archive_v3_maintenance_import::MaintenanceCoordinatorContext,
        plan: AuthenticatedMaintenanceImportPlan,
    ) -> Result<ArchiveMaintenanceAdmission> {
        let plan = plan.into_store_view(StoreMaintenanceContext(()));
        validate_user_id(&plan.user_id)?;
        let lifecycle_guard = self.lock_user_lifecycle(&plan.user_id).await?;
        Ok(ArchiveMaintenanceAdmission {
            store: Arc::clone(self),
            plan,
            lifecycle_guard,
        })
    }

    /// Begin a two-namespace identity transition. This performs no provider
    /// writes: it serializes both lifecycle names, atomically closes and drains
    /// raw-content admission, blocks actor recreation, and owns both actor
    /// states. The caller must durably prepare the control operation before
    /// asking the returned transition to flush the old actor.
    pub(crate) async fn begin_identity_rebind(
        self: &Arc<Self>,
        old_user_id: &str,
        stable_user_id: &str,
    ) -> Result<IdentityRebindTransition> {
        validate_user_id(old_user_id)?;
        validate_user_id(stable_user_id)?;
        if old_user_id == stable_user_id {
            return Err(EnclaveError::Conflict(
                "identity rebind requires two distinct user ids".into(),
            ));
        }
        let lifecycle_guards = self
            .lock_user_lifecycles(old_user_id, stable_user_id)
            .await?;
        self.block_content_writes_for_users([old_user_id, stable_user_id])
            .await;
        let (old_actor, stable_actor) = {
            let mut registry = self.registry.lock().await;
            registry.blocked_users.insert(old_user_id.to_string());
            registry.blocked_users.insert(stable_user_id.to_string());
            registry.recent_clean_evictions.remove(old_user_id);
            registry.recent_clean_evictions.remove(stable_user_id);
            let old_actor = registry.actor_for(old_user_id, self.max_open);
            let stable_actor = registry.actor_for(stable_user_id, self.max_open);
            (old_actor, stable_actor)
        };
        let (old_state, stable_state) = if old_user_id <= stable_user_id {
            let old_state = Arc::clone(&old_actor.state).lock_owned().await;
            let stable_state = Arc::clone(&stable_actor.state).lock_owned().await;
            (old_state, stable_state)
        } else {
            let stable_state = Arc::clone(&stable_actor.state).lock_owned().await;
            let old_state = Arc::clone(&old_actor.state).lock_owned().await;
            (old_state, stable_state)
        };
        if stable_state.handle.is_some() {
            return Err(EnclaveError::Conflict(
                "stable identity target already has a local actor".into(),
            ));
        }
        Ok(IdentityRebindTransition {
            store: Arc::clone(self),
            old_user_id: old_user_id.to_string(),
            stable_user_id: stable_user_id.to_string(),
            _lifecycle_guards: lifecycle_guards,
            old_actor,
            stable_actor,
            old_state,
            _stable_state: stable_state,
        })
    }

    /// Run an operation with a user's open SQLite connection.
    /// Loads the user on first access; evicts LRU handle if over cap.
    pub async fn with_user<F, T>(&self, user_id: &str, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        // A WAL-authoritative user's legacy blob must never load again: after
        // the cutover it is a stale snapshot, so every legacy-path read for a
        // selected user refuses outright and availability arrives only
        // through the routed settled-only lane (`wal_authoritative_read`).
        // `with_user_read` and `read_user` delegate here, making this the
        // single legacy-load choke point; the mutation family already
        // refuses through the per-user policy.
        if self.wal_selected(user_id) {
            return Err(EnclaveError::Store(
                "wal-authoritative user reads are routed".into(),
            ));
        }
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
        let policy = self.persistence_policy_for(user_id);
        if policy == StorePersistencePolicy::WalLogicalOnly
            && (handle.dirty || handle.blob_meta.retry_save_before_access)
        {
            return Err(wal_logical_only_error());
        }
        if handle.blob_meta.retry_save_before_access {
            self.flush_handle(handle).await?;
        }
        let wal_query_only = policy == StorePersistencePolicy::WalLogicalOnly;
        if wal_query_only {
            handle.conn.pragma_update(None, "query_only", true)?;
        }
        let before = database_mutation_fingerprint(&handle.conn)?;
        let result = f(&handle.conn);
        let after = database_mutation_fingerprint(&handle.conn);
        let restore = wal_query_only
            .then(|| handle.conn.pragma_update(None, "query_only", false))
            .transpose();
        if let Err(error) = restore {
            handle.mark_dirty();
            return Err(error.into());
        }
        match after {
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
        if self.persistence_policy_for(user_id) == StorePersistencePolicy::WalLogicalOnly {
            return Err(wal_logical_only_error());
        }
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

    /// Run a proven read-only operation without making a clean cache entry
    /// eligible for a write on eviction.
    pub async fn read_user<F, T>(&self, user_id: &str, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        self.with_user_read(user_id, f).await
    }

    /// Run an operation whose closure reports whether it actually changed the
    /// database. This keeps periodic no-op reconciliation scans read-only.
    pub async fn with_user_if_changed<F, T>(&self, user_id: &str, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<(T, bool)>,
    {
        if self.persistence_policy_for(user_id) == StorePersistencePolicy::WalLogicalOnly {
            return Err(wal_logical_only_error());
        }
        self.with_user(user_id, move |conn| f(conn).map(|(value, _changed)| value))
            .await
    }

    /// Persist a user's index back to GCS.
    pub async fn save_user(&self, user_id: &str) -> Result<()> {
        // A selected user has no legacy state to persist — their handle can
        // never load — so saving is a provider-silent no-op success, keeping
        // migration-era callers that save after mutations working unchanged.
        if self.wal_selected(user_id) {
            return Ok(());
        }
        let actor = match self.actor_for_existing(user_id).await? {
            SaveTarget::Actor(actor) => actor,
            SaveTarget::AlreadyFlushed => return Ok(()),
        };
        let mut state = actor.state.lock().await;
        self.reject_if_blocked(user_id).await?;
        if let Some(handle) = state.handle.as_mut() {
            if self.persistence_policy_for(user_id) == StorePersistencePolicy::WalLogicalOnly {
                return if handle.dirty || handle.blob_meta.retry_save_before_access {
                    Err(wal_logical_only_error())
                } else {
                    Ok(())
                };
            }
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
        let _lifecycle_guard = self.lock_user_lifecycle(user_id).await?;

        let proposed_authority = format!("delete_{}", crate::cp::tokens::random_token_hex());
        let marker_authority = self
            .fence_and_drain_legacy_writes(user_id, &proposed_authority)
            .await?;

        // Raw media PUTs do not hold the SQLite actor while they await GCS.
        // Close that independent admission path first, then wait for every
        // already-admitted request (including an owned, cancellation-safe PUT)
        // to settle before inventory can become authoritative.
        self.block_content_writes_for_deletion(user_id).await;

        self.delete_user_fenced(user_id, &marker_authority).await
    }

    /// Delete both exact namespaces retained by a durable identity-rebind
    /// operation. Both lifecycle gates and both raw-content admission fences
    /// are acquired together before either inventory is observed, so neither
    /// side can be recreated between the two physical purges.
    pub(crate) async fn delete_identity_rebind_users(
        &self,
        old_user_id: &str,
        stable_user_id: &str,
    ) -> Result<()> {
        validate_user_id(old_user_id)?;
        validate_user_id(stable_user_id)?;
        if old_user_id == stable_user_id {
            return Err(EnclaveError::Conflict(
                "identity rebind deletion requires distinct user ids".into(),
            ));
        }
        let _lifecycle_guards = self
            .lock_user_lifecycles(old_user_id, stable_user_id)
            .await?;
        let old_proposed = format!("delete_{}", crate::cp::tokens::random_token_hex());
        let stable_proposed = format!("delete_{}", crate::cp::tokens::random_token_hex());
        let old_authority = self
            .fence_and_drain_legacy_writes(old_user_id, &old_proposed)
            .await?;
        let stable_authority = self
            .fence_and_drain_legacy_writes(stable_user_id, &stable_proposed)
            .await?;
        self.block_content_writes_for_users([old_user_id, stable_user_id])
            .await;
        self.delete_user_fenced(old_user_id, &old_authority).await?;
        self.delete_user_fenced(stable_user_id, &stable_authority)
            .await
    }

    /// Delete one namespace whose lifecycle and raw-content gates are already
    /// owned by the caller.
    async fn delete_user_fenced(&self, user_id: &str, marker_authority: &str) -> Result<()> {
        // Install the fence before waiting for any in-flight same-user work.
        // Existing work may finish; later work re-checks after winning the
        // actor lock and fails without recreating or saving the account.
        let actor = self.actor_for_deletion(user_id).await;
        let mut state = actor.state.lock().await;

        // 1. Make the exact deletion inventory durable before any remote
        // delete. A failed delete can then evict this handle without losing a
        // locally committed media reference across restart: the still-present
        // authoritative user DB is sufficient to rebuild the inventory.
        if state.handle.is_none() {
            self.ensure_loaded(user_id, &actor, &mut state).await?;
        }
        let handle = state
            .handle
            .as_mut()
            .ok_or_else(|| EnclaveError::Store("delete load lost its handle".into()))?;
        if handle.dirty || handle.blob_meta.retry_save_before_access {
            self.flush_handle_for_deletion(handle, marker_authority)
                .await?;
        }
        let keys_to_delete: Arc<[String]> = media_keys(&handle.conn)?.into();

        // The exact inventory is now independent of the live Connection, so
        // release its max-open slot before any slow remote deletion. The GCS
        // database remains authoritative until every referenced object is gone.
        self.discard_handle_for_deletion(user_id, &actor, &mut state)
            .await;

        // `versions=true` excludes soft-deleted objects. Record pre-existing
        // residue, but continue removing anything still live/noncurrent. Final
        // verification below remains fail-closed.
        let mut soft_deleted = self
            .soft_deleted_account_inventory(user_id, &keys_to_delete)
            .await?;

        // Delete every historical raw-media generation, including objects no
        // longer represented by the current SQLite blob. The prefix includes
        // its trailing slash, so another user's similarly named prefix cannot
        // be selected.
        for media_gcs in self.unique_media_providers() {
            self.delete_all_versions_under(media_gcs, &media_prefix(user_id))
                .await?;
            self.delete_all_versions_under(media_gcs, &legacy_media_prefix(user_id))
                .await?;
        }
        for key in keys_to_delete.iter() {
            for media_gcs in self.unique_media_providers() {
                self.delete_all_versions_for_name(media_gcs, key).await?;
            }
        }

        // Every retained legacy DB/checkpoint generation can name unscoped
        // evidence that the live DB no longer references. Inventory one exact
        // generation at a time, delete its media, and only then erase that DB
        // generation. Any unreadable generation leaves deletion incomplete.
        self.inventory_and_delete_legacy_databases(
            user_id,
            &gcs_object_name(user_id),
            true,
            &mut soft_deleted,
        )
        .await?;
        self.inventory_and_delete_legacy_databases(
            user_id,
            &legacy_recovery_prefix(user_id),
            false,
            &mut soft_deleted,
        )
        .await?;

        soft_deleted.merge(
            self.soft_deleted_account_inventory(user_id, &keys_to_delete)
                .await?,
        );
        if soft_deleted.found {
            return Err(soft_deleted_account_objects_error(soft_deleted));
        }

        // A second strongly consistent drain closes the interval between the
        // pre-inventory marker scan and physical deletion. An intent created
        // after the marker is fenced without data I/O; an accepted request
        // remains nonterminal and prevents finalization until reconciled.
        self.drain_legacy_write_intents(user_id).await?;

        Ok(())
    }

    /// Install the archive-v3 deletion lane. Install-once, like the serving
    /// authority: a second install refuses rather than replacing a lane that a
    /// deletion may already be driving.
    pub(crate) fn install_wal_deletion_lane(
        &self,
        lane: Arc<crate::archive_v3_deletion_lane::WalDeletionLane>,
    ) -> Result<()> {
        let mut installed = self
            .wal_deletion_lane
            .write()
            .map_err(|_| EnclaveError::Store("deletion lane registry is poisoned".into()))?;
        if installed.is_some() {
            return Err(EnclaveError::Conflict(
                "an archive-v3 deletion lane is already installed".into(),
            ));
        }
        *installed = Some(lane);
        Ok(())
    }

    /// The installed archive-v3 deletion lane, if this image has one. A
    /// poisoned registry answers `None`, which routes to the honest pending
    /// refusal rather than to the legacy sweep.
    pub(crate) fn wal_deletion_lane(
        &self,
    ) -> Option<Arc<crate::archive_v3_deletion_lane::WalDeletionLane>> {
        self.wal_deletion_lane
            .read()
            .ok()
            .and_then(|lane| lane.clone())
    }

    /// Freeze the exact media inventory of a WAL-authoritative account
    /// *before* deletion tombstones its archive binding.
    ///
    /// This runs in the pre-`begin_user_deletion` window on purpose. After the
    /// tombstone the binding is filtered out of the startup selection scan, no
    /// serving authority is ever re-registered, and this read could never
    /// succeed again — freezing it afterwards would wedge media enumeration
    /// forever on the first crash. Here the selection is still installed, so a
    /// crash simply re-reads the same rows.
    ///
    /// Unlike the legacy inventory this deliberately keeps pruned and
    /// soft-deleted rows: `media_keys` filters `deleted_at`/`processing_state`
    /// because it is answering "what is live", while deletion is answering
    /// "what was ever named" — a pruner that crashed between the provider
    /// delete and the row update leaves an object the filtered query hides.
    pub(crate) async fn freeze_wal_authoritative_media_keys(
        &self,
        user_id: &str,
    ) -> Result<Vec<String>> {
        validate_user_id(user_id)?;
        self.wal_authoritative_read(user_id, deletion_media_keys)
            .await
    }

    /// Erase a WAL-authoritative account's media from a frozen exact-name
    /// inventory, then prove the result.
    ///
    /// Exact names are the completeness proof: every frozen key is deleted
    /// across every media provider's live and noncurrent generations and then
    /// re-checked for soft-delete residue. The two user-scoped prefix sweeps
    /// are additive erasure only — byte-identical to the legacy path's — and
    /// are never treated as evidence that an unnamed object is gone.
    ///
    /// Every key is validated against this account's own `raw/{user}/` and
    /// `media/{user}/` namespaces before it can reach a destructive call. That
    /// is the blast-radius bound for this lane, standing in for the archive
    /// prefix check the driver applies to its own entries: a corrupted frozen
    /// inventory can name nothing outside the account being deleted.
    pub(crate) async fn delete_wal_authoritative_media(
        &self,
        user_id: &str,
        frozen_keys: &[String],
    ) -> Result<()> {
        validate_user_id(user_id)?;
        let owned = [media_prefix(user_id), legacy_media_prefix(user_id)];
        for key in frozen_keys {
            if !owned.iter().any(|prefix| key.starts_with(prefix.as_str())) {
                return Err(EnclaveError::Store(
                    "frozen media inventory named an object outside the account".into(),
                ));
            }
        }
        // The archive database cannot enumerate a provider PUT whose durable
        // media row never landed. Every media PUT is nevertheless preceded by
        // the retained legacy-write intent, so install the account's durable
        // provider fence and drain that exact create-ahead family before the
        // prefix sweep. The marker survives process restart and prevents an
        // old intent reconciler or another enclave instance from recreating a
        // media object after this pass proves it absent.
        let proposed_authority = format!("delete_{}", crate::cp::tokens::random_token_hex());
        self.fence_and_drain_legacy_writes(user_id, &proposed_authority)
            .await?;
        self.block_content_writes_for_deletion(user_id).await;

        let mut soft_deleted = self
            .soft_deleted_account_inventory(user_id, frozen_keys)
            .await?;
        for media_gcs in self.unique_media_providers() {
            for prefix in &owned {
                self.delete_all_versions_under(media_gcs, prefix).await?;
            }
        }
        for key in frozen_keys {
            for media_gcs in self.unique_media_providers() {
                self.delete_all_versions_for_name(media_gcs, key).await?;
            }
        }
        soft_deleted.merge(
            self.soft_deleted_account_inventory(user_id, frozen_keys)
                .await?,
        );
        if soft_deleted.found {
            return Err(soft_deleted_account_objects_error(soft_deleted));
        }
        // Fail closed on the exact names: absence must be proven, never
        // inferred from the delete having returned Ok.
        for key in frozen_keys {
            for media_gcs in self.unique_media_providers() {
                if !list_all_object_versions(media_gcs.as_ref(), key)
                    .await?
                    .into_iter()
                    .all(|version| version.name != *key)
                {
                    return Err(EnclaveError::Store(
                        "a frozen media object is still present after deletion".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn soft_deleted_account_inventory(
        &self,
        user_id: &str,
        referenced_media_keys: &[String],
    ) -> Result<SoftDeletedInventory> {
        let mut inventory = SoftDeletedInventory::default();
        for (gcs, selector, exact_name) in [
            (&self.gcs, gcs_object_name(user_id), true),
            (&self.gcs, legacy_recovery_prefix(user_id), false),
        ] {
            inventory
                .merge(matching_soft_deleted_inventory(gcs.as_ref(), &selector, exact_name).await?);
        }
        for media_gcs in self.unique_media_providers() {
            for selector in [media_prefix(user_id), legacy_media_prefix(user_id)] {
                inventory.merge(
                    matching_soft_deleted_inventory(media_gcs.as_ref(), &selector, false).await?,
                );
            }
        }
        for name in referenced_media_keys {
            for media_gcs in self.unique_media_providers() {
                inventory
                    .merge(matching_soft_deleted_inventory(media_gcs.as_ref(), name, true).await?);
            }
        }
        Ok(inventory)
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
        soft_deleted: &mut SoftDeletedInventory,
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
                        Err(EnclaveError::NotFound) => {
                            return Err(legacy_generation_unavailable_error())
                        }
                        Err(error @ EnclaveError::DeletionPending(_)) => return Err(error),
                        Err(_) => return Err(legacy_inventory_incomplete_error()),
                    };
                    let mut blocked_media = SoftDeletedInventory::default();
                    for key in keys {
                        for media_gcs in self.unique_media_providers() {
                            self.delete_all_versions_for_name(media_gcs, &key).await?;
                            blocked_media.merge(
                                matching_soft_deleted_inventory(media_gcs.as_ref(), &key, true)
                                    .await?,
                            );
                        }
                    }
                    if blocked_media.found {
                        soft_deleted.merge(blocked_media);
                        // Retain this exact legacy generation as the durable
                        // inventory for unscoped media until provider retention
                        // expires. The process-local inventory alone is not
                        // sufficient across a restart.
                        return Err(soft_deleted_account_objects_error(soft_deleted.clone()));
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
            return Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::LegacySnapshotTooLarge,
                retry_after_seconds: None,
                hard_delete_time: None,
            }));
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
        delivery_version: i64,
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
        let now = crate::cp::isotime::format_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );

        self.wal_authoritative_read(user_id, move |conn| {
            Ok(conn
                .query_row(
                    "SELECT rowid, episode_id, delivery_version, delivery_id, include_content, state,
                            attempt_count, next_attempt_at, provider_message_id, response_status,
                            error_code, created_at, updated_at
                     FROM email_deliveries
                     WHERE state IN ('pending', 'retry')
                       AND (
                         next_attempt_at <= ?1
                         OR length(next_attempt_at) != 24
                         OR next_attempt_at NOT GLOB
                           '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
                         OR julianday(next_attempt_at) IS NULL
                       )
                     ORDER BY created_at, episode_id, delivery_id
                     LIMIT 1",
                    [&now],
                    |r| {
                        let include_num: i64 = r.get(4)?;
                        Ok(EmailDeliveryRow {
                            rowid: r.get(0)?,
                            episode_id: r.get(1)?,
                            delivery_version: r.get(2)?,
                            delivery_id: r.get(3)?,
                            include_content: include_num != 0,
                            state: r.get(5)?,
                            attempt_count: r.get(6)?,
                            next_attempt_at: r.get(7)?,
                            provider_message_id: r.get(8)?,
                            response_status: r.get(9)?,
                            error_code: r.get(10)?,
                            created_at: r.get(11)?,
                            updated_at: r.get(12)?,
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
        delivery_version: i64,
        state: &str,
        attempt_count: i64,
        provider_message_id: Option<&str>,
        response_status: Option<u16>,
        error_code: Option<&str>,
        next_attempt_at: Option<&str>,
    ) -> Result<()> {
        let user = user_id.to_string();
        let state = state.to_string();
        let provider_message_id = provider_message_id.map(str::to_string);
        let error_code = error_code.map(str::to_string);
        let next_attempt_at = next_attempt_at.map(str::to_string);
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
                     response_status = ?4, error_code = ?5,
                     next_attempt_at = COALESCE(?6,next_attempt_at), updated_at = ?7
                 WHERE episode_id = ?8 AND delivery_version = ?9",
                rusqlite::params![
                    state,
                    attempt_count,
                    provider_message_id,
                    response_status.map(i64::from),
                    error_code,
                    next_attempt_at,
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

    // ── Push Outbox ────────────────────────────────────────────────────────────

    pub async fn next_push_delivery(&self, user_id: &str) -> Result<Option<PushDeliveryRow>> {
        let now = crate::cp::isotime::format_epoch_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );
        self.wal_authoritative_read(user_id, move |conn| {
            Ok(conn
                .query_row(
                    "SELECT rowid,episode_id,installation_id,delivery_version,delivery_id, \
                            handoff_handle,collapse_id,state,attempt_count,next_attempt_at, \
                            response_status,error_code,created_at,updated_at \
                     FROM push_deliveries WHERE state IN ('pending','retry') \
                       AND next_attempt_at<=?1 ORDER BY created_at,episode_id LIMIT 1",
                    [&now],
                    |row| {
                        Ok(PushDeliveryRow {
                            rowid: row.get(0)?,
                            episode_id: row.get(1)?,
                            installation_binding: row.get(2)?,
                            delivery_version: row.get(3)?,
                            delivery_id: row.get(4)?,
                            handoff_handle: row.get(5)?,
                            collapse_id: row.get(6)?,
                            state: row.get(7)?,
                            attempt_count: row.get(8)?,
                            next_attempt_at: row.get(9)?,
                            response_status: row.get(10)?,
                            error_code: row.get(11)?,
                            created_at: row.get(12)?,
                            updated_at: row.get(13)?,
                        })
                    },
                )
                .optional()?)
        })
        .await
    }

    pub async fn resolve_push_handoff(
        &self,
        user_id: &str,
        handoff_handle: &str,
    ) -> Result<Option<i64>> {
        let handoff = handoff_handle.to_string();
        self.wal_authoritative_read(user_id, move |conn| {
            let claims_present: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' \
                 AND name='archive_v3_wal_push_send_claims')",
                [],
                |row| row.get(0),
            )?;
            let query = if claims_present {
                "SELECT d.episode_id FROM push_deliveries d JOIN episodes e ON e.id=d.episode_id \
                 WHERE d.handoff_handle=?1 \
                   AND (d.state IN ('pending','retry','accepted') OR EXISTS ( \
                     SELECT 1 FROM archive_v3_wal_push_send_claims c \
                     WHERE c.delivery_id=d.delivery_id AND c.outcome IN ('started','ambiguous'))) \
                   AND e.finalization_status='complete'"
            } else {
                "SELECT d.episode_id FROM push_deliveries d JOIN episodes e ON e.id=d.episode_id \
                 WHERE d.handoff_handle=?1 AND d.state IN ('pending','retry','accepted') \
                   AND e.finalization_status='complete'"
            };
            Ok(conn
                .query_row(query, [handoff], |row| row.get(0))
                .optional()?)
        })
        .await
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
                self.finish_load_registration(user_id, actor, &transition, true)
                    .await?;
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
            if self.persistence_policy_for(&candidate.user_id)
                == StorePersistencePolicy::WalLogicalOnly
                && (handle.dirty || handle.blob_meta.retry_save_before_access)
            {
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
                return Err(wal_logical_only_error());
            }
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
                // WAL-only has no reviewed bootstrap/genesis mutation. A
                // missing user must fail before KMS wrap, empty-database
                // creation, temp-file creation, or any provider write.
                if self.persistence_policy_for(user_id) == StorePersistencePolicy::WalLogicalOnly {
                    return Err(wal_logical_only_error());
                }
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

        // A legacy envelope would require an authoritative rewrite even when
        // its SQLite schema is otherwise current. WAL-only mode has no owner
        // for that mutation, so reject before creating or opening a local
        // database file.
        if self.persistence_policy_for(user_id) == StorePersistencePolicy::WalLogicalOnly
            && envelope_rewrite_dirty
        {
            return Err(wal_logical_only_error());
        }

        // Write plaintext to a temp file and open it with rusqlite
        let temp_path = write_private_temp_db(user_id, &plaintext_db).await?;
        let selected_capture = self.shadow_capture.read().ok().and_then(|selection| {
            selection
                .as_ref()
                .and_then(|selection| selection.capture_for_user(user_id))
        });
        let (conn, shadow_capture_registration, migration_dirty) = match open_db(
            &temp_path,
            selected_capture.as_deref(),
            self.persistence_policy_for(user_id),
        ) {
            Ok(opened) => opened,
            Err(e) => {
                remove_temp_db_files(&temp_path);
                return Err(e);
            }
        };

        Ok(UserHandle {
            user_id: user_id.to_string(),
            conn,
            _shadow_capture_registration: shadow_capture_registration,
            blob_meta,
            mutation_generation: u64::from(migration_dirty || envelope_rewrite_dirty),
            persisted_mutation_generation: 0,
            dirty: migration_dirty || envelope_rewrite_dirty,
            temp_path,
        })
    }

    async fn flush_handle(&self, handle: &mut UserHandle) -> Result<()> {
        if self.persistence_policy_for(&handle.user_id) == StorePersistencePolicy::WalLogicalOnly
            && handle.dirty
        {
            return Err(wal_logical_only_error());
        }
        self.flush_handle_with_admission(handle, false, None, true)
            .await
    }

    /// Deletion closes normal admission before making its final local state
    /// durable. Its own provider work remains visible to the barrier, while
    /// ordinary writers remain rejected.
    async fn flush_handle_for_deletion(
        &self,
        handle: &mut UserHandle,
        marker_authority: &str,
    ) -> Result<()> {
        self.flush_handle_with_admission(handle, true, Some(marker_authority), true)
            .await
    }

    async fn flush_handle_for_rebind(
        &self,
        handle: &mut UserHandle,
        marker_authority: &str,
    ) -> Result<()> {
        self.flush_handle_with_admission(handle, true, Some(marker_authority), true)
            .await
    }

    async fn flush_handle_for_maintenance(
        &self,
        handle: &mut UserHandle,
        marker_authority: &str,
    ) -> Result<()> {
        // Maintenance itself pins the exact bumped generation. Creating an
        // additional legacy recovery-copy object is outside this protocol's
        // reviewed effect set and is unnecessary while the permanent marker
        // has already closed all ordinary legacy writers.
        self.flush_handle_with_admission(handle, true, Some(marker_authority), false)
            .await
    }

    async fn flush_handle_with_admission(
        &self,
        handle: &mut UserHandle,
        deletion_owned: bool,
        allowed_marker_authority: Option<&str>,
        preserve_recovery_checkpoint: bool,
    ) -> Result<()> {
        if self.persistence_policy_for(&handle.user_id) == StorePersistencePolicy::WalLogicalOnly
            && handle.dirty
        {
            return Err(wal_logical_only_error());
        }
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

        // A flush can issue the authoritative index PUT and, on the first
        // overwrite of a UTC day, a recovery-copy rewrite. Keep this parent
        // lease for the whole transition; each provider operation receives an
        // owned child below, so cancellation cannot make deletion outrun a
        // request whose provider outcome remains unknown.
        let content_write = if deletion_owned {
            self.acquire_content_write_for_deletion(&handle.user_id)?
        } else {
            self.acquire_content_write_inner(&handle.user_id, false)?
        };
        let result = self
            .flush_handle_inner(
                handle,
                &content_write,
                allowed_marker_authority,
                preserve_recovery_checkpoint,
            )
            .await;
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

    async fn flush_handle_inner(
        &self,
        handle: &mut UserHandle,
        content_write: &ContentWriteLease,
        allowed_marker_authority: Option<&str>,
        preserve_recovery_checkpoint: bool,
    ) -> Result<(u64, u64, u64)> {
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
        if preserve_recovery_checkpoint
            && handle.blob_meta.generation > 0
            && handle.blob_meta.verified_legacy_recovery_day != Some(checkpoint_day)
        {
            self.ensure_legacy_recovery_checkpoint(
                &handle.user_id,
                handle.blob_meta.generation,
                checkpoint_now,
                content_write.child(),
                allowed_marker_authority,
            )
            .await?;
            handle.blob_meta.verified_legacy_recovery_day = Some(checkpoint_day);
        }

        let logical_db_bytes = db_bytes.len() as u64;
        let encrypted_bytes = ciphertext.len() as u64;
        self.storage_metrics
            .record_encrypted_upload_attempt(encrypted_bytes);
        let put_generation = handle.blob_meta.generation;
        let put_lease = content_write.child();
        let put_result = self
            .execute_legacy_write_with_intent(
                &handle.user_id,
                LegacyWriteRequest::Put {
                    backend: LegacyWriteBackend::Index,
                    kind: LegacyWriteKind::IndexPut,
                    object_name: object_name.clone(),
                    ciphertext,
                    wrapped_dek_b64: handle.blob_meta.wrapped_dek_b64.clone(),
                    if_generation_match: put_generation,
                },
                allowed_marker_authority,
                Some(put_lease),
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
        content_write: ContentWriteLease,
        allowed_marker_authority: Option<&str>,
    ) -> Result<()> {
        self.reconcile_unfenced_legacy_write_intents(user_id)
            .await?;
        let destination = legacy_recovery_checkpoint_name(user_id, now);
        let source = gcs_object_name(user_id);
        self.execute_legacy_write_with_intent(
            user_id,
            LegacyWriteRequest::RecoveryCopy {
                source_object_name: source,
                source_generation,
                destination_object_name: destination,
            },
            allowed_marker_authority,
            Some(content_write),
        )
        .await
        .map(|_| ())
    }
}

impl IdentityRebindTransition {
    async fn snapshot_handle(handle: &mut UserHandle) -> Result<IdentityRebindSource> {
        handle
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let plaintext = tokio::fs::read(&handle.temp_path).await?;
        let commitment: [u8; 32] = Sha256::digest(&plaintext).into();
        Ok(IdentityRebindSource {
            base_generation: handle.blob_meta.generation,
            source_generation: handle.blob_meta.generation,
            commitment,
            plaintext,
            wrapped_dek_b64: handle.blob_meta.wrapped_dek_b64.clone(),
        })
    }

    /// Read the exact latest actor image while both actor states and all raw
    /// admissions are fenced. This performs provider reads when the actor was
    /// cold, but no provider writes.
    pub(crate) async fn source_snapshot(&mut self) -> Result<IdentityRebindSource> {
        self.store
            .ensure_loaded(&self.old_user_id, &self.old_actor, &mut self.old_state)
            .await?;
        let handle = self
            .old_state
            .handle
            .as_mut()
            .ok_or_else(|| EnclaveError::Store("rebind source actor disappeared".into()))?;
        Self::snapshot_handle(handle).await
    }

    /// After the encrypted control operation is durable, conditionally flush
    /// the exact snapshotted actor and return its authoritative generation.
    pub(crate) async fn freeze_source(
        &mut self,
        expected_base_generation: i64,
        expected_commitment: &[u8; 32],
        marker_authority: &str,
    ) -> Result<IdentityRebindSource> {
        let before = self.source_snapshot().await?;
        if before.base_generation < expected_base_generation
            || &before.commitment != expected_commitment
        {
            return Err(EnclaveError::Conflict(
                "legacy rebind source changed after durable prepare".into(),
            ));
        }
        let handle = self
            .old_state
            .handle
            .as_mut()
            .ok_or_else(|| EnclaveError::Store("rebind source actor disappeared".into()))?;
        let had_local_changes = handle.dirty || handle.blob_meta.retry_save_before_access;
        // A WAL-authoritative user's legacy snapshot is frozen and
        // non-authoritative: every legacy writer is refused, so there is no
        // in-flight remote writer for the generation-CAS bump to race. Forcing
        // the bump anyway makes the flush refuse with a `Store` error — not the
        // `Conflict` the recovery branch below expects — so the transition is
        // dropped without `complete()`, leaving BOTH identities fenced and the
        // live user told their account is deleted for the process lifetime.
        if self.store.wal_selected(&self.old_user_id) {
            if had_local_changes {
                // Unflushed legacy mutations cannot exist for a selected user.
                // If one somehow does, fail closed rather than silently
                // discarding state we cannot account for.
                return Err(EnclaveError::Store(
                    "wal-authoritative rebind source carries unflushed legacy changes".into(),
                ));
            }
            let frozen = Self::snapshot_handle(handle).await?;
            if frozen.source_generation <= 0 || &frozen.commitment != expected_commitment {
                return Err(EnclaveError::Conflict(
                    "legacy rebind source changed after durable prepare".into(),
                ));
            }
            return Ok(frozen);
        }
        if !had_local_changes {
            // Always perform a same-plaintext generation-CAS bump after the
            // durable provider fence appears. A remote writer that checked
            // before the marker and is already in flight must race this exact
            // bump: one succeeds and the other receives a generation conflict.
            handle.mark_dirty();
        }
        if let Err(error) = self
            .store
            .flush_handle_for_rebind(handle, marker_authority)
            .await
        {
            if !had_local_changes && matches!(&error, EnclaveError::Conflict(_)) {
                // The remote writer won the one permissible pre-fence CAS.
                // This actor was clean, so no local mutation is discarded:
                // reload the new authoritative source and let the control
                // state machine durably rebase its commitment before retrying
                // the forced bump.
                let stale =
                    self.old_state.handle.take().ok_or_else(|| {
                        EnclaveError::Store("rebind source actor disappeared".into())
                    })?;
                let stale_path = stale.temp_path.clone();
                drop(stale);
                remove_temp_db_files(&stale_path);
                let fresh = self.store.load_user(&self.old_user_id).await?;
                self.old_state.handle = Some(fresh);
            }
            return Err(error);
        }
        let frozen = Self::snapshot_handle(handle).await?;
        if frozen.source_generation <= 0 || &frozen.commitment != expected_commitment {
            return Err(EnclaveError::Conflict(
                "legacy rebind flush did not preserve its source commitment".into(),
            ));
        }
        Ok(frozen)
    }

    /// Complete the process-local transition after the durable control record
    /// reaches `committed`: discard the old actor permanently while reopening
    /// only the stable namespace. The old namespace remains fenced.
    pub(crate) async fn complete(mut self) {
        self.store
            .discard_handle_for_deletion(&self.old_user_id, &self.old_actor, &mut self.old_state)
            .await;
        self.store
            .release_open_registration(&self.stable_user_id, &self.stable_actor)
            .await;
        {
            let mut registry = self.store.registry.lock().await;
            registry.blocked_users.remove(&self.stable_user_id);
        }
        {
            let mut barrier = self
                .store
                .content_write_barrier
                .state
                .lock()
                .expect("content barrier poisoned");
            barrier.blocked_users.remove(&self.stable_user_id);
        }
        self.store.content_write_barrier.changed.notify_waiters();
    }
}

impl ArchiveMaintenanceAdmission {
    /// Close and drain both local admission paths only after the caller has
    /// performed its final Control check under this same lifecycle guard.
    pub(crate) async fn begin(self) -> ArchiveMaintenanceTransition {
        let Self {
            store,
            plan,
            lifecycle_guard,
        } = self;
        store.block_content_writes_for_deletion(&plan.user_id).await;
        let actor = store.actor_for_deletion(&plan.user_id).await;
        let state = Arc::clone(&actor.state).lock_owned().await;
        ArchiveMaintenanceTransition {
            store,
            plan,
            _lifecycle_guard: lifecycle_guard,
            actor,
            state,
        }
    }
}

impl ArchiveMaintenanceTransition {
    async fn source_facts(handle: &mut UserHandle) -> Result<MaintenanceTentativeSource> {
        if handle.blob_meta.generation <= 0 {
            return Err(EnclaveError::NotFound);
        }
        handle
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let plaintext = tokio::fs::read(&handle.temp_path).await?;
        let plaintext_len = u64::try_from(plaintext.len())
            .map_err(|_| EnclaveError::Store("maintenance source is too large".into()))?;
        if plaintext_len == 0
            || !plaintext_len.is_multiple_of(u64::from(crate::archive_v3::SQLITE_PAGE_SIZE))
            || plaintext_len > crate::archive_v3::MAX_DATABASE_BYTES
        {
            return Err(EnclaveError::Store(
                "maintenance source geometry is invalid".into(),
            ));
        }
        let sqlite_schema_version: i64 =
            handle
                .conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let sqlite_schema_version = u32::try_from(sqlite_schema_version)
            .map_err(|_| EnclaveError::Store("maintenance source schema is invalid".into()))?;
        Ok(MaintenanceTentativeSource {
            base_generation: handle.blob_meta.generation,
            plaintext_hash: Sha256::digest(&plaintext).into(),
            plaintext_len,
            sqlite_schema_version,
            wrapped_dek_commitment: Sha256::digest(handle.blob_meta.wrapped_dek_b64.as_bytes())
                .into(),
        })
    }

    /// Observe the tentative exact source without provider mutation. The
    /// lifecycle/actor/content gates have already been acquired by `begin`.
    pub(crate) async fn tentative_source(&mut self) -> Result<MaintenanceTentativeSource> {
        self.store
            .ensure_loaded(&self.plan.user_id, &self.actor, &mut self.state)
            .await?;
        let handle =
            self.state.handle.as_mut().ok_or_else(|| {
                EnclaveError::Store("maintenance source actor disappeared".into())
            })?;
        Self::source_facts(handle).await
    }

    /// Create/adopt the permanent provider marker, drain every pre-marker
    /// intent, perform the mandatory same-plaintext generation-CAS bump, and
    /// consume the actor into an owned private snapshot.
    pub(crate) async fn fence_and_pin(
        mut self,
        expected: MaintenanceTentativeSource,
    ) -> Result<MaintenanceFenceAndPin> {
        let authority = self
            .store
            .fence_and_drain_legacy_writes(&self.plan.user_id, &self.plan.fence_authority)
            .await?;
        if authority != self.plan.fence_authority {
            return Err(EnclaveError::Conflict(
                "legacy archive fence belongs to another operation".into(),
            ));
        }
        let observed = self.tentative_source().await?;
        if observed.base_generation < expected.base_generation
            || observed.plaintext_hash != expected.plaintext_hash
            || observed.plaintext_len != expected.plaintext_len
            || observed.sqlite_schema_version != expected.sqlite_schema_version
            || observed.wrapped_dek_commitment != expected.wrapped_dek_commitment
        {
            return Ok(MaintenanceFenceAndPin::Rebase {
                transition: self,
                source: observed,
            });
        }
        let handle =
            self.state.handle.as_mut().ok_or_else(|| {
                EnclaveError::Store("maintenance source actor disappeared".into())
            })?;
        let had_local_changes = handle.dirty || handle.blob_meta.retry_save_before_access;
        handle.mark_dirty();
        if let Err(error) = self
            .store
            .flush_handle_for_maintenance(handle, &authority)
            .await
        {
            if !had_local_changes && matches!(&error, EnclaveError::Conflict(_)) {
                let stale = self.state.handle.take().ok_or_else(|| {
                    EnclaveError::Store("maintenance source actor disappeared".into())
                })?;
                let stale_path = stale.temp_path.clone();
                drop(stale);
                remove_temp_db_files(&stale_path);
                let fresh = self.store.load_user(&self.plan.user_id).await?;
                self.state.handle = Some(fresh);
                let source = self.tentative_source().await?;
                return Ok(MaintenanceFenceAndPin::Rebase {
                    transition: self,
                    source,
                });
            }
            return Err(error);
        }
        let pinned = Self::source_facts(handle).await?;
        if pinned.base_generation <= expected.base_generation
            || pinned.plaintext_hash != expected.plaintext_hash
            || pinned.plaintext_len != expected.plaintext_len
            || pinned.sqlite_schema_version != expected.sqlite_schema_version
            || pinned.wrapped_dek_commitment != expected.wrapped_dek_commitment
        {
            return Err(EnclaveError::Conflict(
                "maintenance generation bump changed plaintext".into(),
            ));
        }
        let source = MaintenanceSourceBinding::from_pinned(
            self.plan.archive_id,
            self.plan.operation_id,
            pinned.base_generation,
            pinned.plaintext_hash,
            pinned.plaintext_len,
            pinned.sqlite_schema_version,
            pinned.wrapped_dek_commitment,
        )
        .map_err(|_| EnclaveError::Store("maintenance pinned source is invalid".into()))?;
        let handle =
            self.state.handle.take().ok_or_else(|| {
                EnclaveError::Store("maintenance source actor disappeared".into())
            })?;
        let path = handle.temp_path.clone();
        drop(handle);
        remove_temp_db_sidecars(&path);
        if let Err(error) = ensure_temp_db_sidecars_absent(&path) {
            remove_temp_db_files(&path);
            return Err(error);
        }
        self.state.cleanly_evicted = false;
        self.store
            .release_open_registration(&self.plan.user_id, &self.actor)
            .await;
        Ok(MaintenanceFenceAndPin::Pinned(PinnedLegacySnapshot {
            path,
            _archive_id: self.plan.archive_id,
            _operation_id: self.plan.operation_id,
            source,
            _store: self.store,
            _plan: self.plan,
            _lifecycle_guard: self._lifecycle_guard,
            _actor: self.actor,
            _state: self.state,
        }))
    }

    /// Restart recovery reads only the exact positive generation committed by
    /// encrypted control and reauthenticates envelope context, wrapped-DEK
    /// metadata, plaintext digest/length, and SQLite schema before reminting a
    /// private staging owner.
    pub(crate) async fn recover_pinned(
        mut self,
        expected: MaintenanceSourceBinding,
    ) -> Result<PinnedLegacySnapshot> {
        let expected_view = expected.store_view(StoreMaintenanceContext(()));
        let authority = self
            .store
            .fence_and_drain_legacy_writes(&self.plan.user_id, &self.plan.fence_authority)
            .await?;
        if authority != self.plan.fence_authority {
            return Err(EnclaveError::Conflict(
                "legacy archive fence belongs to another operation".into(),
            ));
        }
        if let Some(handle) = self.state.handle.take() {
            let stale_path = handle.temp_path.clone();
            drop(handle);
            remove_temp_db_files(&stale_path);
        }
        self.store
            .release_open_registration(&self.plan.user_id, &self.actor)
            .await;
        let object = self
            .store
            .gcs
            .get_object_generation(
                &gcs_object_name(&self.plan.user_id),
                expected_view.generation,
            )
            .await?;
        if object.generation != expected_view.generation
            || Sha256::digest(object.wrapped_dek_b64.as_bytes()).as_slice()
                != expected_view.wrapped_dek_commitment
        {
            return Err(EnclaveError::Conflict(
                "maintenance pinned generation metadata changed".into(),
            ));
        }
        let dek = load_dek(self.store.kms.as_ref(), &object.wrapped_dek_b64).await?;
        let opened = decrypt_bound_blob(
            &dek,
            &object.ciphertext,
            &user_blob_context(&self.plan.user_id),
        )?;
        if u64::try_from(opened.plaintext.len()).ok() != Some(expected_view.plaintext_len)
            || <[u8; 32]>::from(Sha256::digest(&opened.plaintext)) != expected_view.plaintext_hash
        {
            return Err(EnclaveError::Conflict(
                "maintenance pinned generation plaintext changed".into(),
            ));
        }
        let path = write_private_temp_db(&self.plan.user_id, &opened.plaintext).await?;
        let schema_result = (|| -> Result<u32> {
            let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let value: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            u32::try_from(value)
                .map_err(|_| EnclaveError::Store("maintenance source schema is invalid".into()))
        })();
        let schema = match schema_result {
            Ok(schema) => schema,
            Err(error) => {
                remove_temp_db_files(&path);
                return Err(error);
            }
        };
        if schema != expected_view.sqlite_schema_version {
            remove_temp_db_files(&path);
            return Err(EnclaveError::Conflict(
                "maintenance pinned generation schema changed".into(),
            ));
        }
        remove_temp_db_sidecars(&path);
        if let Err(error) = ensure_temp_db_sidecars_absent(&path) {
            remove_temp_db_files(&path);
            return Err(error);
        }
        Ok(PinnedLegacySnapshot {
            path,
            _archive_id: self.plan.archive_id,
            _operation_id: self.plan.operation_id,
            source: expected,
            _store: self.store,
            _plan: self.plan,
            _lifecycle_guard: self._lifecycle_guard,
            _actor: self.actor,
            _state: self.state,
        })
    }
}

fn deleted_user_error() -> EnclaveError {
    EnclaveError::Auth("user account is deleted".into())
}

fn wal_owner_open_error() -> EnclaveError {
    EnclaveError::Store("wal owner database failed its open-time preconditions".into())
}

fn wal_logical_only_error() -> EnclaveError {
    EnclaveError::Store(
        "legacy snapshot mutation is disabled until a WAL logical operation is prepared".into(),
    )
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
pub(crate) const SCHEMA_SQL: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Audio segments (carrier of utterances)
CREATE TABLE IF NOT EXISTS audio_segments (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
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
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    audio_segment_id        INTEGER NOT NULL REFERENCES audio_segments(id) ON DELETE CASCADE,
    start_offset_seconds    REAL NOT NULL,
    end_offset_seconds      REAL NOT NULL,
    text                    TEXT NOT NULL,
    language                TEXT,
    confidence              REAL,
    speaker_label           TEXT NOT NULL,
    source_key              TEXT,
    speaker_observation_id  INTEGER,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- FTS5 index over utterance text
CREATE VIRTUAL TABLE IF NOT EXISTS utterances_fts
    USING fts5(text, content='utterances', content_rowid='id');

-- Screenshots + OCR text
CREATE TABLE IF NOT EXISTS screenshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
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
    finalization_next_attempt_at TEXT,
    identity_revision INTEGER NOT NULL DEFAULT 0,
    finalized_identity_revision INTEGER NOT NULL DEFAULT 0,
    identity_refresh_status TEXT DEFAULT NULL CHECK (identity_refresh_status IN ('queued', 'processing', 'ready', 'failed')),
    speaker_processing_status TEXT NOT NULL DEFAULT 'ready' CHECK (speaker_processing_status IN ('ready', 'pending', 'degraded'))
);
CREATE INDEX IF NOT EXISTS idx_episodes_started_at ON episodes(started_at);

-- Per-user, content-side task markers. Kept in the encrypted user DB so
-- one-off data passes follow the data through cache eviction and redeploys.
CREATE TABLE IF NOT EXISTS app_metadata (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Privacy-minimized Vertex cost attribution. One row is created before an
-- outbound invocation and completed in place. It contains no prompt, output,
-- response id, episode id, Google identity, or provider account identifier.
CREATE TABLE IF NOT EXISTS vertex_usage_events (
    event_id                TEXT PRIMARY KEY,
    operation               TEXT NOT NULL CHECK (operation IN (
        'audio_understanding','screen_understanding','episode_summarization',
        'episode_finalization')),
    requested_model         TEXT NOT NULL,
    returned_model          TEXT,
    location                TEXT NOT NULL,
    traffic_type            TEXT NOT NULL DEFAULT 'on_demand' CHECK (traffic_type IN (
        'on_demand','batch','provisioned_throughput')),
    http_status             INTEGER,
    prompt_tokens           INTEGER,
    input_text_tokens       INTEGER,
    input_audio_tokens      INTEGER,
    input_image_tokens      INTEGER,
    cached_input_tokens     INTEGER,
    cached_input_text_tokens INTEGER,
    cached_input_audio_tokens INTEGER,
    cached_input_image_tokens INTEGER,
    output_text_tokens      INTEGER,
    thought_tokens          INTEGER,
    total_tokens            INTEGER,
    outcome                 TEXT NOT NULL CHECK (outcome IN ('started','metered','usage_missing','ambiguous','not_billed')),
    delivery_state          TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','delivered')),
    delivery_attempt_count  INTEGER NOT NULL DEFAULT 0,
    observed_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS vertex_usage_events_outbox_idx
    ON vertex_usage_events(delivery_state, observed_at);
CREATE TABLE IF NOT EXISTS vertex_usage_coverage (
    period          TEXT PRIMARY KEY,
    sequence        INTEGER NOT NULL CHECK (sequence > 0),
    pending_events  INTEGER NOT NULL CHECK (pending_events >= 0),
    lost_events     INTEGER NOT NULL DEFAULT 0 CHECK (lost_events >= 0),
    delivery_state  TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','delivered')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
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

-- Per-installation finalized-memory notification outbox. The raw handoff is
-- opaque, random, and encrypted with the rest of the user's content DB.
CREATE TABLE IF NOT EXISTS push_deliveries (
    episode_id        INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
    installation_id   TEXT NOT NULL,
    delivery_version  INTEGER NOT NULL,
    delivery_id       TEXT NOT NULL UNIQUE,
    handoff_handle    TEXT NOT NULL UNIQUE,
    collapse_id       TEXT NOT NULL,
    state             TEXT NOT NULL CHECK (state IN ('pending','retry','accepted','cancelled','failed')),
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   TEXT NOT NULL,
    response_status   INTEGER,
    error_code        TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (episode_id, installation_id, delivery_version)
);
CREATE INDEX IF NOT EXISTS push_deliveries_due_idx
    ON push_deliveries(state, next_attempt_at);

-- Device sync watermarks per modality
CREATE TABLE IF NOT EXISTS device_watermarks (
    device_id    TEXT NOT NULL,
    modality     TEXT NOT NULL CHECK (modality IN ('audio','screen')),
    watermark_at TEXT NOT NULL, -- ISO 8601
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (device_id, modality)
);

-- ADR-0022 schema ladder: this archive's own record of the numbered epoch it
-- has reached and the ladder chain it reached it by.
--
-- The row is a BIRTH WITNESS. Every path that materializes an archive seeds it
-- unconditionally, epoch 0 included, so a served archive always carries one
-- row. An ABSENT row is therefore a REFUSAL, never "epoch 0" -- absence means
-- the file was created by a binary older than this table, or by a path that is
-- not allowed to produce a servable archive, and neither may be coerced into a
-- servable epoch. `build_canonical` leaves it empty on purpose: the canonical
-- is a schema reference, not an archive.
--
-- After birth only the owner-side SchemaEpochAdvance plan ever writes it --
-- product code never does.
CREATE TABLE IF NOT EXISTS schema_epoch (
    singleton    INTEGER PRIMARY KEY CHECK (singleton = 1),
    epoch        INTEGER NOT NULL CHECK (epoch >= 0),
    chain_digest BLOB NOT NULL CHECK (length(chain_digest) = 32 AND chain_digest != zeroblob(32))
);
"#;

/// Schema-upgrade statements that are safe to replay on every open.
///
/// `ALTER TABLE … ADD COLUMN` returns `SQLITE_ERROR` ("duplicate column name")
/// if the column already exists; we swallow that specific error so existing
/// blobs created with the old schema self-upgrade transparently.
///
/// `CREATE UNIQUE INDEX IF NOT EXISTS` is truly idempotent.
pub(crate) fn run_migrations(conn: &Connection) -> Result<()> {
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
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vertex_usage_events (
             event_id TEXT PRIMARY KEY,
             operation TEXT NOT NULL CHECK (operation IN (
                'audio_understanding','screen_understanding','episode_summarization',
                'episode_finalization')),
             requested_model TEXT NOT NULL,
             returned_model TEXT,
             location TEXT NOT NULL,
             traffic_type TEXT NOT NULL DEFAULT 'on_demand' CHECK (traffic_type IN (
                'on_demand','batch','provisioned_throughput')),
             http_status INTEGER,
             prompt_tokens INTEGER,
             input_text_tokens INTEGER,
             input_audio_tokens INTEGER,
             input_image_tokens INTEGER,
             cached_input_tokens INTEGER,
             cached_input_text_tokens INTEGER,
             cached_input_audio_tokens INTEGER,
             cached_input_image_tokens INTEGER,
             output_text_tokens INTEGER,
             thought_tokens INTEGER,
             total_tokens INTEGER,
             outcome TEXT NOT NULL CHECK (outcome IN ('started','metered','usage_missing','ambiguous','not_billed')),
             delivery_state TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','delivered')),
             delivery_attempt_count INTEGER NOT NULL DEFAULT 0,
             observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
             updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
         );
         CREATE INDEX IF NOT EXISTS vertex_usage_events_outbox_idx
             ON vertex_usage_events(delivery_state, observed_at);
         CREATE TABLE IF NOT EXISTS vertex_usage_coverage (
             period TEXT PRIMARY KEY,
             sequence INTEGER NOT NULL CHECK (sequence > 0),
             pending_events INTEGER NOT NULL CHECK (pending_events >= 0),
             lost_events INTEGER NOT NULL DEFAULT 0 CHECK (lost_events >= 0),
             delivery_state TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','delivered')),
             updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
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
        "ALTER TABLE episodes ADD COLUMN identity_revision INTEGER NOT NULL DEFAULT 0;",
        "ALTER TABLE episodes ADD COLUMN finalized_identity_revision INTEGER NOT NULL DEFAULT 0;",
        "ALTER TABLE episodes ADD COLUMN identity_refresh_status TEXT DEFAULT NULL CHECK (identity_refresh_status IN ('queued', 'processing', 'ready', 'failed'));",
        "ALTER TABLE episodes ADD COLUMN speaker_processing_status TEXT NOT NULL DEFAULT 'ready' CHECK (speaker_processing_status IN ('ready', 'pending', 'degraded'));",
        "ALTER TABLE utterances ADD COLUMN speaker_observation_id INTEGER;",
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
    let needs_complete_backfill: bool = conn
        .query_row(
            "SELECT 1 FROM episodes WHERE finalized_at IS NOT NULL \
             AND (finalization_status IS NOT 'complete' \
                  OR finalization_error IS NOT NULL \
                  OR finalization_attempt_count <> 0 \
                  OR finalization_next_attempt_at IS NOT NULL) LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if needs_complete_backfill {
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
    }
    // Quarantine the pre-guard retry loop. Its attempt count was not persisted,
    // so treating it as fresh would immediately repeat the production incident.
    let needs_quarantine: bool = conn
        .query_row(
            "SELECT 1 FROM episodes WHERE finalized_at IS NULL \
             AND finalization_status IN ('retry_model', 'processing') LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if needs_quarantine {
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
    }

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
        CREATE TABLE IF NOT EXISTS push_deliveries (
            episode_id INTEGER NOT NULL REFERENCES episodes(id) ON DELETE CASCADE,
            installation_id TEXT NOT NULL,
            delivery_version INTEGER NOT NULL,
            delivery_id TEXT NOT NULL UNIQUE,
            handoff_handle TEXT NOT NULL UNIQUE,
            collapse_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('pending','retry','accepted','cancelled','failed')),
            attempt_count INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT NOT NULL,
            response_status INTEGER,
            error_code TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            PRIMARY KEY (episode_id, installation_id, delivery_version)
        );
        CREATE INDEX IF NOT EXISTS push_deliveries_due_idx
            ON push_deliveries(state, next_attempt_at);
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

fn open_db(
    path: &PathBuf,
    shadow_capture: Option<&StoreShadowCapture>,
    persistence_policy: StorePersistencePolicy,
) -> Result<(Connection, Option<CaptureRegistration>, bool)> {
    open_db_inner(path, shadow_capture, persistence_policy, None)
}

fn open_db_after_wal_generation(
    path: &PathBuf,
    shadow_capture: &StoreShadowCapture,
    persistence_policy: StorePersistencePolicy,
    previous_generation: u64,
) -> Result<(Connection, Option<CaptureRegistration>, bool)> {
    open_db_inner(
        path,
        Some(shadow_capture),
        persistence_policy,
        Some(previous_generation),
    )
}

fn open_db_inner(
    path: &PathBuf,
    shadow_capture: Option<&StoreShadowCapture>,
    persistence_policy: StorePersistencePolicy,
    previous_generation: Option<u64>,
) -> Result<(Connection, Option<CaptureRegistration>, bool)> {
    // Register the sqlite-vec extension globally before any connection opens.
    // This is idempotent (Once guard) and thread-safe.
    init_vec_extension();
    if persistence_policy == StorePersistencePolicy::WalLogicalOnly {
        // WAL-only is intentionally unavailable with capture: capture would
        // observe local writes while this gate has no publication owner.
        if shadow_capture.is_some() {
            return Err(wal_logical_only_error());
        }
        validate_checkpointed_sqlite_file(path)?;
        ensure_no_sqlite_sidecars(path)?;
        // SQLite's ordinary read-only WAL mode may still create `-shm` or open
        // a sidecar. `immutable=1` promises this private copy cannot change and
        // makes reads use only the checkpointed main file.
        let uri = sqlite_immutable_uri(path)?;
        let conn = Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        let schema_result = validate_wal_logical_schema(&conn);
        let sidecar_result = ensure_no_sqlite_sidecars(path);
        schema_result?;
        sidecar_result?;
        return Ok((conn, None, false));
    }
    // Register before opening so both the main database and its first WAL
    // attachment resolve the same connection-scoped capture state. Failure to
    // open drops/retire the registration before the caller removes the file.
    let captured = shadow_capture.and_then(|shadow_capture| {
        let registration = match previous_generation {
            Some(previous_generation) => shadow_capture
                .register_after_generation(path, previous_generation)
                .ok()?,
            None => shadow_capture.register(path).ok()?,
        };
        Connection::open_with_flags_and_vfs(path, OpenFlags::default(), shadow_capture.vfs_name())
            .ok()
            .map(|connection| (connection, registration))
    });
    // Capture is non-authoritative even when injected. Registry exhaustion,
    // VFS incompatibility, or named-open failure silently falls back to the
    // exact legacy open and can never deny user access or persistence.
    let (conn, registration) = match captured {
        Some((connection, registration)) => (connection, Some(registration)),
        None => (Connection::open(path)?, None),
    };
    let before = database_mutation_fingerprint(&conn)?;
    if persistence_policy == StorePersistencePolicy::WalOwnerAuthoritative {
        // **No DDL; read-only assertions are required.** The prohibition here
        // is on *mutating* the database at open — never on inspecting it. The
        // fingerprint assertion below is what enforces the first, and the
        // epoch-marker check further down is required by the second: without
        // it this branch performs no schema comparison at all, and an archive
        // built by a binary older than the re-baseline would be served rather
        // than refused. Do not delete that check as a "DDL in the owner path"
        // violation — it runs no DDL and moves nothing.
        //
        // The two pragmas at the head of `SCHEMA_SQL` still have to be
        // accounted for, because skipping the batch skips them too.
        //
        // `journal_mode` is persisted in the database header, so it is
        // asserted rather than set — an owner database that is not in WAL mode
        // did not come from the genesis materializer and must not be served.
        let journal: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(wal_owner_open_error());
        }
        // `foreign_keys` is connection-scoped and defaults OFF, so it must be
        // set on every connection. This is the only production site that
        // enables foreign keys for a user database; without it roughly two
        // dozen `ON DELETE CASCADE` clauses silently stop cascading and
        // nothing downstream — not the fingerprint, not the schema descriptor
        // — would ever notice.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
        if foreign_keys != 1 {
            return Err(wal_owner_open_error());
        }
        // Neither pragma may perturb the database. Asserting it here is what
        // makes the `migration_dirty` tripwire in the owner vacuously true
        // instead of merely relaxed.
        if database_mutation_fingerprint(&conn)? != before {
            return Err(wal_owner_open_error());
        }
        // The birth-witness latch. Marker-only: one row, no descriptor build.
        //
        // This is the owner-path half of the closure. `validate_wal_logical_schema`
        // guards only the `WalLogicalOnly` branch above, which a genesis-born
        // WAL-authoritative archive never takes, so before this check the owner
        // path compared no schema of any kind. An archive with no marker (an
        // older binary built it, or a rolled-back image did) and an archive
        // whose recorded chain is not this binary's baseline are both refused
        // here rather than served.
        //
        // Deliberately NOT `assert_canonical_at`: the chain conjunct already
        // binds the archive to this binary's `BASELINE_DIGEST`, and building a
        // canonical database on every owner open would be a per-open cost for
        // a strictly weaker reason.
        let marker =
            crate::schema_ladder::read_archive_epoch(&conn).map_err(|_| wal_owner_open_error())?;
        crate::schema_ladder::validate_servable_epoch(marker)
            .map_err(|_| wal_owner_open_error())?;
        // Reading the marker must not perturb the database either.
        if database_mutation_fingerprint(&conn)? != before {
            return Err(wal_owner_open_error());
        }
        return Ok((conn, registration, false));
    }
    conn.execute_batch(SCHEMA_SQL)?;
    run_migrations(&conn)?;
    let migrated = database_mutation_fingerprint(&conn)? != before;
    Ok((conn, registration, migrated))
}

/// The three measurements a fresh archive-v3 genesis must publish alongside
/// its first checkpoint, plus the private proof that the measured connection
/// passed the exact birth check.
///
/// The WAL owner authenticates the database it later opens by exact file
/// length, `user_version`, and plaintext SHA-256, so genesis cannot simply
/// hand over bytes — it must commit to these measurements at creation time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GenesisStoreFacts {
    pub(crate) logical_file_length: u64,
    pub(crate) plaintext_sha256: [u8; 32],
    pub(crate) user_version: u32,
    /// Unforgeable outside this module: possession proves the same connection
    /// passed the exact birth check before its bytes were checkpointed.
    pub(crate) birth_witness: GenesisBirthWitness,
}

/// Capability minted only by the exact schema validator above the genesis
/// checkpoint boundary. Keeping its field private prevents a sibling producer
/// from turning an ordinary boolean into operational proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GenesisBirthWitness {
    _private: (),
}

#[cfg(test)]
impl GenesisStoreFacts {
    pub(crate) fn for_test(
        logical_file_length: u64,
        plaintext_sha256: [u8; 32],
        user_version: u32,
    ) -> Self {
        Self {
            logical_file_length,
            plaintext_sha256,
            user_version,
            birth_witness: GenesisBirthWitness { _private: () },
        }
    }
}

/// Materialize the empty, schema-current SQLite database that a freshly
/// created archive publishes as its first checkpoint.
///
/// Migration got its base database from the user's legacy snapshot; a
/// genesis archive has no such source, and an archive root with a zero-length
/// database can never be recovered (`validate_snapshot_length` rejects it).
/// So the empty database is built here, fully checkpointed, and measured.
///
/// The checkpoint and sidecar checks are load-bearing rather than tidiness: a
/// residual `-wal`/`-shm` pair would leave committed pages outside the file
/// that gets measured, so the length and hash published here would disagree
/// with the bytes the owner authenticates on open, and the archive would be
/// unopenable from birth.
pub(crate) fn initialize_genesis_store(path: &Path) -> Result<GenesisStoreFacts> {
    init_vec_extension();
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA_SQL)?;
    run_migrations(&conn)?;
    // The ladder steps and the birth witness are one atomic unit: an archive
    // whose DDL and whose recorded epoch disagree is exactly the state the
    // marker exists to make impossible. Both must land before the checkpoint
    // and the `fs::read` below, or the published `GenesisStoreFacts` describe a
    // file the owner will never authenticate.
    let tx = conn.unchecked_transaction()?;
    crate::schema_ladder::apply_steps(&tx, 0, crate::schema_ladder::SCHEMA_EPOCH_TARGET)?;
    crate::schema_ladder::seed_epoch_marker(&tx, crate::schema_ladder::SCHEMA_EPOCH_TARGET)?;
    tx.commit()?;
    validate_genesis_birth_witness(&conn)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")?;
    let user_version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    // Fold every committed page back into the main file before it is measured.
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(conn);
    ensure_no_sqlite_sidecars(path)?;
    validate_checkpointed_sqlite_file(path)?;
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() {
        return Err(EnclaveError::Store("genesis database is empty".into()));
    }
    let logical_file_length = u64::try_from(bytes.len())
        .map_err(|_| EnclaveError::Store("genesis database is too large".into()))?;
    let plaintext_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    Ok(GenesisStoreFacts {
        logical_file_length,
        plaintext_sha256,
        user_version,
        birth_witness: GenesisBirthWitness { _private: () },
    })
}

#[cfg(test)]
pub(crate) fn initialize_wal_owner_store_for_test(path: &Path) -> Result<u32> {
    init_vec_extension();
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA_SQL)?;
    run_migrations(&conn)?;
    let tx = conn.unchecked_transaction()?;
    crate::schema_ladder::apply_steps(&tx, 0, crate::schema_ladder::SCHEMA_EPOCH_TARGET)?;
    crate::schema_ladder::seed_epoch_marker(&tx, crate::schema_ladder::SCHEMA_EPOCH_TARGET)?;
    tx.commit()?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")?;
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(Into::into)
}

fn ensure_no_sqlite_sidecars(path: &Path) -> Result<()> {
    if ["-wal", "-shm"]
        .iter()
        .any(|suffix| sqlite_sidecar_path(path, suffix).exists())
    {
        return Err(wal_logical_only_error());
    }
    Ok(())
}

fn validate_checkpointed_sqlite_file(path: &Path) -> Result<()> {
    let mut file = std::fs::File::open(path)?;
    let metadata_len = file.metadata()?.len();
    let mut header = [0_u8; 100];
    file.read_exact(&mut header)?;
    if &header[..16] != b"SQLite format 3\0"
        || !matches!(header[18], 1 | 2)
        || header[19] != header[18]
    {
        return Err(wal_logical_only_error());
    }
    let change_counter = u32::from_be_bytes(
        header[24..28]
            .try_into()
            .map_err(|_| wal_logical_only_error())?,
    );
    let database_pages = u32::from_be_bytes(
        header[28..32]
            .try_into()
            .map_err(|_| wal_logical_only_error())?,
    );
    let valid_for = u32::from_be_bytes(
        header[92..96]
            .try_into()
            .map_err(|_| wal_logical_only_error())?,
    );
    let encoded_page_size = u16::from_be_bytes([header[16], header[17]]);
    let page_size = if encoded_page_size == 1 {
        65_536_u64
    } else {
        u64::from(encoded_page_size)
    };
    let valid_page_size = page_size.is_power_of_two() && (512..=65_536).contains(&page_size);
    let expected_len = page_size.checked_mul(u64::from(database_pages));
    if !valid_page_size
        || database_pages == 0
        || change_counter != valid_for
        || expected_len != Some(metadata_len)
    {
        return Err(wal_logical_only_error());
    }
    Ok(())
}

fn sqlite_immutable_uri(path: &Path) -> Result<String> {
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            uri.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut uri, "%{byte:02X}").map_err(|_| wal_logical_only_error())?;
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Ok(uri)
}

pub(crate) type SchemaDescriptorRow = (String, String, String, String);

/// Every `sqlite_schema` row except the names SQLite reserves for itself.
///
/// # Why the `ESCAPE`
///
/// The exclusion was written `name NOT LIKE 'sqlite_%'`, in which `_` is
/// LIKE's **single-character wildcard**. SQLite reserves only the literal
/// seven-character prefix `sqlite_` (`sqlite3CheckObjectName`, case
/// insensitive), so `sqlitew`, `sqlitex` and `SQLITEQ_x` are legal user DDL —
/// verified directly: `CREATE TRIGGER sqlitew AFTER INSERT ON episodes …` is
/// accepted, and the unescaped predicate discarded it before any caller saw
/// it. All three callers of this function compare a live database against a
/// canonical build, so a discarded row is a discarded *difference*: an
/// undeclared trigger on a product table produced a byte-identical descriptor
/// to a clean archive.
///
/// `LIKE 'sqlite\_%' ESCAPE '\'` matches exactly the reserved prefix and keeps
/// LIKE's default ASCII case-insensitivity, so it is identical to the intended
/// semantics on every name SQLite can actually create (`sqlite_sequence`,
/// `sqlite_autoindex_*`, `sqlite_stat1`) and strictly stronger on everything
/// else. `GLOB 'sqlite_*'` was rejected as the fix: GLOB is case-sensitive,
/// which would have been a second, unrelated behaviour change.
pub(crate) fn schema_descriptor(conn: &Connection) -> Result<Vec<SchemaDescriptorRow>> {
    let mut statement = conn.prepare(
        r"SELECT type,name,tbl_name,coalesce(sql,'')
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite\_%' ESCAPE '\'
         ORDER BY type,name,tbl_name,coalesce(sql,'')",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Prove that a just-materialized archive was born at this binary's exact
/// schema target before any of its bytes can cross a provider boundary.
///
/// The epoch row is authenticated separately because table descriptors do not
/// contain data. Descriptor equality is deliberately stronger than searching
/// three DDL strings for `AUTOINCREMENT`: it binds every table, index, trigger,
/// and virtual-table declaration to the frozen baseline plus reviewed ladder,
/// and therefore includes the allocator declarations without a token/comment
/// parsing ambiguity.
fn validate_genesis_birth_witness(conn: &Connection) -> Result<()> {
    let marker = crate::schema_ladder::read_archive_epoch(conn)
        .map_err(|_| EnclaveError::Store("genesis birth witness is unavailable".into()))?;
    if marker.epoch != crate::schema_ladder::SCHEMA_EPOCH_TARGET
        || marker.chain
            != crate::schema_ladder::chain_digest(crate::schema_ladder::SCHEMA_EPOCH_TARGET)
    {
        return Err(EnclaveError::Store(
            "genesis birth witness does not match the binary".into(),
        ));
    }
    let canonical = crate::schema_ladder::LadderView::PRODUCTION
        .build_canonical(crate::schema_ladder::SCHEMA_EPOCH_TARGET)?;
    if schema_descriptor(conn)? != schema_descriptor(&canonical)? {
        return Err(EnclaveError::Store(
            "genesis schema does not match the binary".into(),
        ));
    }
    Ok(())
}

/// Prove the decrypted database already has the exact schema a fresh current
/// database would receive, without mutating the target. Older or extra schema
/// fails closed until a separately authorized migration runs under legacy
/// persistence.
///
/// # Epoch awareness
///
/// The comparand is `build_canonical(marker.epoch)`, not a bare baseline. This
/// is a change of pinned VALUE (*which* canonical) under an unchanged RULE
/// (verbatim descriptor equality, refuse on mismatch), and it strictly *adds*
/// two refusals ahead of the comparison it already performed:
///
/// * an archive with no epoch marker is refused rather than compared — before
///   this, a database built by a binary older than the sealed re-baseline was
///   only caught if its descriptor happened to differ;
/// * an archive whose recorded epoch this binary cannot serve, or whose
///   recorded chain is not this binary's `BASELINE_DIGEST` + `SCHEMA_LADDER`,
///   is refused. The chain conjunct is what stops the marker being
///   self-certifying: the archive supplies the epoch, but the comparand is
///   recomputed here.
///
/// While the ladder is empty every archive is at epoch 0 and
/// `build_canonical(0)` is exactly the bare baseline, so nothing else moves.
/// The `user_version` / `application_id` comparison below is deliberately left
/// alone and stays absolute: `build_canonical` never sets `user_version`, so
/// making it epoch-relative is what would turn it into the tautology where the
/// archive supplies the value that selects its own comparand.
fn validate_wal_logical_schema(conn: &Connection) -> Result<()> {
    let marker =
        crate::schema_ladder::read_archive_epoch(conn).map_err(|_| wal_logical_only_error())?;
    crate::schema_ladder::validate_servable_epoch(marker).map_err(|_| wal_logical_only_error())?;
    let canonical = crate::schema_ladder::build_canonical(marker.epoch)
        .map_err(|_| wal_logical_only_error())?;
    let current_versions = (
        conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
        conn.query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))?,
    );
    let canonical_versions = (
        canonical.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
        canonical.query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))?,
    );
    if current_versions != canonical_versions
        || schema_descriptor(conn)? != schema_descriptor(&canonical)?
    {
        return Err(wal_logical_only_error());
    }
    Ok(())
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
    // Seeded here too, even though this is the legacy-snapshot new-user path.
    // If it were skipped, an absent marker would be ambiguous between "an old
    // binary built this" and "the legacy path built this" — and the whole value
    // of the birth witness is that absence has exactly one meaning.
    let tx = conn.unchecked_transaction()?;
    crate::schema_ladder::apply_steps(&tx, 0, crate::schema_ladder::SCHEMA_EPOCH_TARGET)?;
    crate::schema_ladder::seed_epoch_marker(&tx, crate::schema_ladder::SCHEMA_EPOCH_TARGET)?;
    tx.commit()?;
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
    /// Present only for provider soft-deleted inventory. GCS owns this
    /// immutable deadline; callers preserve it for deletion-status reporting.
    pub hard_delete_time: Option<String>,
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
    /// Return provider time from a read-only authenticated metadata response
    /// for this exact existing authority generation. Implementations must not
    /// use the caller's process wall clock or create clock objects. Provider
    /// request futures must be cancellation-owned: dropping a timed-out future
    /// cannot leave a detached request that may commit after lease expiry.
    async fn trusted_time_millis(
        &self,
        authority_object_name: &str,
        authority_generation: i64,
    ) -> Result<i64>;
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
    /// Lists only the currently live objects under `prefix` (`versions=false`).
    /// Reconciliation uses this instead of deriving liveness from a historical
    /// version listing.
    async fn list_live_objects(
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

async fn list_all_object_versions(
    gcs: &dyn GcsClient,
    prefix: &str,
) -> Result<Vec<GcsObjectVersion>> {
    let mut versions = Vec::new();
    let mut page_token: Option<String> = None;
    for _ in 0..MAX_GCS_LIST_PAGES {
        let page = gcs
            .list_object_versions(prefix, page_token.as_deref())
            .await?;
        versions.extend(page.versions);
        match page.next_page_token {
            None => return Ok(versions),
            Some(next) if page_token.as_deref() != Some(next.as_str()) => page_token = Some(next),
            Some(_) => {
                return Err(EnclaveError::Gcs(
                    "GCS version listing repeated a page cursor".into(),
                ))
            }
        }
    }
    Err(EnclaveError::Gcs(
        "GCS version listing exceeded its page bound".into(),
    ))
}

pub(crate) async fn delete_all_object_generations(
    gcs: &dyn GcsClient,
    object_name: &str,
) -> Result<()> {
    for version in list_all_object_versions(gcs, object_name)
        .await?
        .into_iter()
        .filter(|version| version.name == object_name)
    {
        gcs.delete_object_generation(&version.name, version.generation)
            .await?;
    }
    if list_all_object_versions(gcs, object_name)
        .await?
        .iter()
        .any(|version| version.name == object_name)
    {
        return Err(EnclaveError::Gcs(
            "GCS object generations remain after deletion".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn delete_object_generations_except(
    gcs: &dyn GcsClient,
    object_name: &str,
    keep_generation: i64,
) -> Result<()> {
    let versions = list_all_object_versions(gcs, object_name).await?;
    if !versions
        .iter()
        .any(|version| version.name == object_name && version.generation == keep_generation)
    {
        return Err(EnclaveError::Gcs(
            "required current GCS generation is missing during privacy purge".into(),
        ));
    }
    for version in versions
        .into_iter()
        .filter(|version| version.name == object_name && version.generation != keep_generation)
    {
        gcs.delete_object_generation(&version.name, version.generation)
            .await?;
    }
    if list_all_object_versions(gcs, object_name)
        .await?
        .iter()
        .any(|version| version.name == object_name && version.generation != keep_generation)
    {
        return Err(EnclaveError::Gcs(
            "superseded GCS generations remain after privacy purge".into(),
        ));
    }
    Ok(())
}

const GCS_LIST_PAGE_SIZE: usize = 1_000;
const MAX_GCS_LIST_PAGES: usize = 1_000_000;
const GCS_CURSOR_FINGERPRINT_BITS: usize = 1 << 18;
const GCS_CURSOR_FINGERPRINT_WORDS: usize = GCS_CURSOR_FINGERPRINT_BITS / u64::BITS as usize;
/// Historical Phase-0 inventory still decrypts one whole legacy SQLite
/// snapshot. Reject larger generations before download until the streaming
/// archive converter replaces this compatibility path.
const MAX_LEGACY_DELETION_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SoftDeletedInventory {
    found: bool,
    latest_hard_delete_time: Option<String>,
}

impl SoftDeletedInventory {
    fn include(&mut self, version: GcsObjectVersion) {
        self.found = true;
        self.include_deadline(version.hard_delete_time);
    }

    fn include_deadline(&mut self, hard_delete_time: Option<String>) {
        let Some(candidate) = hard_delete_time else {
            return;
        };
        let replace = match self.latest_hard_delete_time.as_deref() {
            None => true,
            Some(current) => match (
                crate::cp::isotime::parse_epoch_millis(current),
                crate::cp::isotime::parse_epoch_millis(&candidate),
            ) {
                (Some(current), Some(candidate)) => candidate > current,
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (None, None) => candidate.as_str() > current,
            },
        };
        if replace {
            self.latest_hard_delete_time = Some(candidate);
        }
    }

    fn merge(&mut self, other: Self) {
        if !other.found {
            return;
        }
        self.found = true;
        self.include_deadline(other.latest_hard_delete_time);
    }
}

fn soft_deleted_account_objects_error(inventory: SoftDeletedInventory) -> EnclaveError {
    let retry_after_seconds = inventory
        .latest_hard_delete_time
        .as_deref()
        .and_then(crate::cp::isotime::parse_epoch_millis)
        .and_then(|deadline_ms| {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_millis()
                .try_into()
                .ok()?;
            let remaining_ms = deadline_ms.saturating_sub(now_ms).max(1);
            u64::try_from(remaining_ms.saturating_add(999) / 1_000).ok()
        });
    EnclaveError::DeletionPending(DeletionPending {
        reason: DeletionPendingReason::SoftDeleteRetention,
        retry_after_seconds,
        hard_delete_time: inventory.latest_hard_delete_time,
    })
}

fn legacy_inventory_incomplete_error() -> EnclaveError {
    EnclaveError::DeletionPending(DeletionPending {
        reason: DeletionPendingReason::LegacyInventoryIncomplete,
        retry_after_seconds: None,
        hard_delete_time: None,
    })
}

fn legacy_write_intent_unsettled_error() -> EnclaveError {
    EnclaveError::DeletionPending(DeletionPending {
        reason: DeletionPendingReason::LegacyWriteIntentUnsettled,
        retry_after_seconds: Some(5),
        hard_delete_time: None,
    })
}

fn legacy_generation_unavailable_error() -> EnclaveError {
    EnclaveError::DeletionPending(DeletionPending {
        reason: DeletionPendingReason::LegacyGenerationUnavailable,
        retry_after_seconds: None,
        hard_delete_time: None,
    })
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

/// Streams one selector's soft-deleted inventory and preserves only the latest
/// provider hard-delete deadline. No content inventory is accumulated.
async fn matching_soft_deleted_inventory(
    gcs: &dyn GcsClient,
    selector: &str,
    exact_name: bool,
) -> Result<SoftDeletedInventory> {
    let mut page_token = None;
    let mut inventory = SoftDeletedInventory::default();
    for _ in 0..MAX_GCS_LIST_PAGES {
        let page = gcs
            .list_soft_deleted_objects(selector, page_token.as_deref())
            .await?;
        for version in page.versions.into_iter().filter(|version| {
            if exact_name {
                version.name == selector
            } else {
                version.name.starts_with(selector)
            }
        }) {
            inventory.include(version);
        }
        match page.next_page_token {
            Some(next) if page_token.as_deref() != Some(next.as_str()) => page_token = Some(next),
            Some(_) => {
                return Err(EnclaveError::Gcs(
                    "GCS soft-delete listing repeated a page cursor".into(),
                ))
            }
            None => return Ok(inventory),
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
    #[serde(rename = "hardDeleteTime")]
    hard_delete_time: Option<String>,
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
                hard_delete_time: item.hard_delete_time,
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
    /// Kept as explicit client configuration so the exact-generation HTTP
    /// sequence can be exercised against a local server. Production always
    /// uses Google's canonical API origin.
    api_base: String,
    metadata_token_url: String,
    trusted_time_floor_millis: AtomicI64,
}

impl GcpGcsClient {
    pub fn from_env() -> Result<Self> {
        let bucket = std::env::var("GCS_BUCKET")
            .map_err(|_| EnclaveError::Gcs("GCS_BUCKET not set".into()))?;
        Ok(Self::from_parts(bucket, "https://storage.googleapis.com".into(), "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".into()))
    }

    pub fn from_bucket(bucket: String) -> Self {
        Self::from_parts(
            bucket,
            "https://storage.googleapis.com".into(),
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".into(),
        )
    }

    fn from_parts(bucket: String, api_base: String, metadata_token_url: String) -> Self {
        Self {
            http: gcs_http_client(),
            bucket,
            api_base,
            metadata_token_url,
            trusted_time_floor_millis: AtomicI64::new(0),
        }
    }

    #[cfg(test)]
    fn for_test_endpoint(bucket: String, endpoint: String) -> Self {
        Self::from_parts(
            bucket,
            endpoint.clone(),
            format!("{endpoint}/computeMetadata/v1/instance/service-accounts/default/token"),
        )
    }

    async fn access_token(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct Tok {
            access_token: String,
        }
        let tok: Tok = self
            .http
            .get(&self.metadata_token_url)
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
            "{}/storage/v1/b/{}/o/{}{}",
            self.api_base, self.bucket, encoded, generation_query
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
            "{}/download/storage/v1/b/{}/o/{}?alt=media&generation={}",
            self.api_base, self.bucket, encoded, generation
        );
        let response = self.http.get(&data_url).bearer_auth(&token).send().await?;
        exact_generation_download_status(response.status())?;
        let bytes = response.error_for_status()?.bytes().await?;
        Ok(GcsGetResponse {
            ciphertext: bytes.to_vec(),
            wrapped_dek_b64: metadata.wrapped_dek_b64,
            generation,
        })
    }
}

fn exact_generation_download_status(status: reqwest::StatusCode) -> Result<()> {
    if status == reqwest::StatusCode::NOT_FOUND {
        Err(EnclaveError::NotFound)
    } else {
        Ok(())
    }
}

fn gcs_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(300))
        .build()
        .expect("static GCS HTTP client configuration is valid")
}

fn provider_date_millis(headers: &reqwest::header::HeaderMap) -> Result<i64> {
    let mut values = headers.get_all(reqwest::header::DATE).iter();
    let raw = values
        .next()
        .ok_or_else(|| EnclaveError::Gcs("GCS response omitted provider Date".into()))?;
    if values.next().is_some() {
        return Err(EnclaveError::Gcs(
            "GCS response contained multiple provider Date values".into(),
        ));
    }
    let raw = raw
        .to_str()
        .map_err(|_| EnclaveError::Gcs("GCS provider Date was not ASCII".into()))?;
    let provider_time = httpdate::parse_http_date(raw)
        .map_err(|_| EnclaveError::Gcs("GCS provider Date was malformed".into()))?;
    let millis = provider_time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EnclaveError::Gcs("GCS provider Date preceded the Unix epoch".into()))?
        .as_millis();
    i64::try_from(millis)
        .map_err(|_| EnclaveError::Gcs("GCS provider Date exceeded the supported range".into()))
}

#[async_trait::async_trait]
impl GcsClient for GcpGcsClient {
    async fn trusted_time_millis(
        &self,
        authority_object_name: &str,
        authority_generation: i64,
    ) -> Result<i64> {
        if !self.api_base.starts_with("https://") && !cfg!(test) {
            return Err(EnclaveError::Gcs(
                "GCS trusted-time endpoint was not authenticated TLS".into(),
            ));
        }
        let token = self.access_token().await?;
        let encoded = urlencoding::encode(authority_object_name);
        let url = format!(
            "{}/storage/v1/b/{}/o/{}?fields=name,generation",
            self.api_base, self.bucket, encoded
        );
        let response = self.http.get(url).bearer_auth(token).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(EnclaveError::NotFound);
        }
        let response = response.error_for_status()?;
        let observed = provider_date_millis(response.headers())?;
        #[derive(Deserialize)]
        struct AuthorityMetadata {
            generation: String,
        }
        let observed_generation = response
            .json::<AuthorityMetadata>()
            .await?
            .generation
            .parse::<i64>()
            .map_err(|_| EnclaveError::Gcs("invalid trusted-time authority generation".into()))?;
        if observed_generation != authority_generation {
            return Err(EnclaveError::Conflict(
                "trusted-time authority generation changed".into(),
            ));
        }
        loop {
            let floor = self.trusted_time_floor_millis.load(AtomicOrdering::Acquire);
            if observed < floor {
                return Err(EnclaveError::Gcs(
                    "GCS provider Date regressed during legacy-write protocol".into(),
                ));
            }
            if self
                .trusted_time_floor_millis
                .compare_exchange(
                    floor,
                    observed,
                    AtomicOrdering::AcqRel,
                    AtomicOrdering::Acquire,
                )
                .is_ok()
            {
                return Ok(observed);
            }
        }
    }

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
            "{}/upload/storage/v1/b/{}/o?uploadType=multipart&name={}&ifGenerationMatch={}",
            self.api_base, self.bucket, encoded, if_generation_match
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
            "{}/storage/v1/b/{}/o/{}/rewriteTo/b/{}/o/{}?sourceGeneration={}&ifSourceGenerationMatch={}&ifGenerationMatch=0",
            self.api_base, self.bucket,
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
                "{}/storage/v1/b/{}/o/{}/rewriteTo/b/{}/o/{}?sourceGeneration={}&ifSourceGenerationMatch={}&ifGenerationMatch=0&rewriteToken={}",
                self.api_base, self.bucket, source_encoded, self.bucket, destination_encoded,
                source_generation, source_generation,
                urlencoding::encode(&token)
            );
        }
    }

    async fn delete_object(&self, object_name: &str) -> Result<()> {
        let token = self.access_token().await?;
        let encoded = urlencoding::encode(object_name);
        let url = format!(
            "{}/storage/v1/b/{}/o/{}",
            self.api_base, self.bucket, encoded
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
            "{}/storage/v1/b/{}/o?versions=true&maxResults={}&prefix={}",
            self.api_base,
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

    async fn list_live_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        let token = self.access_token().await?;
        let mut url = format!(
            "{}/storage/v1/b/{}/o?maxResults={}&prefix={}",
            self.api_base,
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
        decode_gcs_versions_page(&response.bytes().await?, "live")
    }

    async fn list_soft_deleted_objects(
        &self,
        prefix: &str,
        page_token: Option<&str>,
    ) -> Result<GcsListVersionsResponse> {
        let token = self.access_token().await?;
        let mut url = format!(
            "{}/storage/v1/b/{}/o?softDeleted=true&maxResults={}&prefix={}",
            self.api_base,
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
            "{}/storage/v1/b/{}/o/{}?generation={}",
            self.api_base,
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

fn identity_rebind_fence_object_name_with_key(key: &[u8], user_id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts every fixed-size control key");
    mac.update(b"kioku.legacy-rebind-fence.v3\0");
    mac.update(user_id.as_bytes());
    let digest = mac.finalize().into_bytes();
    let digest_hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("control/identity-rebind-fences/fence_{}", digest_hex)
}

#[cfg(test)]
const TEST_LEGACY_FENCE_KEY: [u8; 32] = [0x5a; 32];

#[cfg(test)]
fn initial_legacy_fence_key() -> Option<Zeroizing<[u8; 32]>> {
    Some(Zeroizing::new(TEST_LEGACY_FENCE_KEY))
}

#[cfg(not(test))]
fn initial_legacy_fence_key() -> Option<Zeroizing<[u8; 32]>> {
    None
}

#[cfg(test)]
pub(crate) fn test_identity_rebind_fence_object_name(user_id: &str) -> String {
    identity_rebind_fence_object_name_with_key(&TEST_LEGACY_FENCE_KEY, user_id)
}

pub(crate) fn is_canonical_identity_rebind_fence_object_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("control/identity-rebind-fences/fence_") else {
        return false;
    };
    suffix.len() == 64
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn media_prefix(user_id: &str) -> String {
    format!("raw/{user_id}/")
}

fn legacy_media_prefix(user_id: &str) -> String {
    format!("media/{user_id}/")
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

/// Accept only an exact legacy archive object name. Listing is not trusted to
/// supply a source generation: callers must subsequently use `get_object` to
/// resolve GCS's live generation explicitly.
fn legacy_index_user_id(object_name: &str) -> Option<String> {
    let user_id = object_name
        .strip_prefix("indexes/")?
        .strip_suffix(".db.enc")?;
    if user_id.is_empty() || user_id.contains('/') || validate_user_id(user_id).is_err() {
        return None;
    }
    Some(user_id.to_owned())
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
    for (table, state_filter) in [
        ("screenshot_images", ""),
        (
            "media_objects",
            " WHERE deleted_at IS NULL AND processing_state != 'pruned'",
        ),
    ] {
        let table_exists: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        if table_exists == 0 {
            continue;
        }
        let mut stmt = conn.prepare(&format!("SELECT object_key FROM {table}{state_filter}"))?;
        keys.extend(
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?,
        );
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

/// The deletion variant of [`media_keys`]: no `deleted_at` /
/// `processing_state` filter.
///
/// `media_keys` answers "which objects does the live database still
/// reference"; deletion must answer "which objects were ever named". A pruner
/// that crashed after deleting the provider object but before updating the row
/// — or after marking the row pruned but before deleting the object — leaves
/// exactly the rows the filtered query hides. Reporting an account physically
/// complete on the filtered set would be a false completion.
fn deletion_media_keys(conn: &Connection) -> Result<Vec<String>> {
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
        let mut statement = conn.prepare(&format!("SELECT object_key FROM {table}"))?;
        keys.extend(
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?,
        );
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

#[cfg(test)]
fn historical_media_keys(conn: &Connection, user_id: &str) -> Result<Vec<String>> {
    let raw_prefix = format!("raw/{user_id}/");
    let media_prefix = format!("media/{user_id}/");
    Ok(media_keys(conn)?
        .into_iter()
        .filter(|key| !key.starts_with(&raw_prefix) && !key.starts_with(&media_prefix))
        .collect())
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
    remove_temp_db_sidecars(path);
}

fn remove_temp_db_sidecars(path: &Path) {
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(sqlite_sidecar_path(path, suffix));
    }
}

fn ensure_temp_db_sidecars_absent(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm"] {
        match std::fs::metadata(sqlite_sidecar_path(path, suffix)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(EnclaveError::Store(
                    "maintenance snapshot retained a SQLite sidecar".into(),
                ))
            }
        }
    }
    Ok(())
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
    fn speaker_identity_backfill_runs_on_databases_missing_the_status_column() {
        // Production incident 2026-08-18 (v0.8.26): databases created before
        // the zero-touch speaker-identity release have app_metadata (so the
        // v2 backfill runs inside media::init_schema) but get the
        // episodes.speaker_processing_status column only from the ALTER loop
        // that runs AFTER init_schema returns — every existing user database
        // failed to open with "no such column". Reproduce that exact shape:
        // current schema, minus the column, minus the backfill marker.
        init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_SQL).unwrap();
        run_migrations(&conn).unwrap();
        conn.execute_batch("ALTER TABLE episodes DROP COLUMN speaker_processing_status;")
            .unwrap();
        conn.execute(
            "DELETE FROM app_metadata WHERE key='speaker-identity-backfill-v2'",
            [],
        )
        .unwrap();

        run_migrations(&conn).unwrap();

        let restored: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('episodes') \
                 WHERE name='speaker_processing_status'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            restored, 1,
            "migration must restore the column before the backfill"
        );
        let complete: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM app_metadata WHERE key='speaker-identity-backfill-v2')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            complete,
            "backfill must complete instead of failing the open"
        );
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

    #[derive(Default)]
    struct CountingKms {
        wraps: AtomicUsize,
        unwraps: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl KmsClient for CountingKms {
        async fn wrap_dek(&self, plaintext_dek: &[u8]) -> crate::error::Result<String> {
            self.wraps.fetch_add(1, Ordering::SeqCst);
            Ok(B64.encode(plaintext_dek))
        }

        async fn unwrap_dek(&self, wrapped_b64: &str) -> crate::error::Result<Vec<u8>> {
            self.unwraps.fetch_add(1, Ordering::SeqCst);
            B64.decode(wrapped_b64)
                .map_err(|error| crate::error::EnclaveError::Kms(error.to_string()))
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
        hard_delete_time: Option<String>,
        crc32c: String,
        md5_hash: Option<String>,
        legacy_recovery: Option<LegacyRecoveryBinding>,
    }

    pub struct FakeGcs {
        objects: StdMutex<HashMap<String, Vec<FakeObject>>>,
        fail_copy: StdMutex<VecDeque<EnclaveError>>,
        fail_copy_after_create: StdMutex<Option<EnclaveError>>,
        fail_get: StdMutex<Option<EnclaveError>>,
        fail_exact_get: StdMutex<Option<EnclaveError>>,
        fail_put: StdMutex<Option<EnclaveError>>,
        fail_put_for_object: StdMutex<Option<(String, EnclaveError)>>,
        fail_put_after_commit: StdMutex<Option<EnclaveError>>,
        fail_put_for_object_after_commit: StdMutex<Option<(String, EnclaveError)>>,
        corrupt_wrapped_dek_after_commit_failure: StdMutex<Option<String>>,
        fail_generation_delete: StdMutex<Option<(String, i64)>>,
        fail_generation_delete_after_commit: StdMutex<Option<(String, i64)>>,
        vanish_generation_on_get: StdMutex<Option<(String, i64)>>,
        soft_delete_enabled: StdMutex<bool>,
        soft_delete_hard_delete_time: StdMutex<Option<String>>,
        repeat_version_cursor: StdMutex<bool>,
        listed_size_overrides: StdMutex<HashMap<String, u64>>,
        exact_generation_gets: StdMutex<usize>,
        live_gets: StdMutex<Vec<String>>,
        copy_calls: StdMutex<Vec<(String, i64, String)>>,
        put_calls: StdMutex<Vec<(String, i64)>>,
        provider_clock_millis: AtomicU64,
        list_calls: AtomicUsize,
        delete_generation_calls: AtomicUsize,
    }

    impl FakeGcs {
        pub fn new() -> Self {
            Self {
                objects: StdMutex::new(HashMap::new()),
                fail_copy: StdMutex::new(VecDeque::new()),
                fail_copy_after_create: StdMutex::new(None),
                fail_get: StdMutex::new(None),
                fail_exact_get: StdMutex::new(None),
                fail_put: StdMutex::new(None),
                fail_put_for_object: StdMutex::new(None),
                fail_put_after_commit: StdMutex::new(None),
                fail_put_for_object_after_commit: StdMutex::new(None),
                corrupt_wrapped_dek_after_commit_failure: StdMutex::new(None),
                fail_generation_delete: StdMutex::new(None),
                fail_generation_delete_after_commit: StdMutex::new(None),
                vanish_generation_on_get: StdMutex::new(None),
                soft_delete_enabled: StdMutex::new(false),
                soft_delete_hard_delete_time: StdMutex::new(Some(
                    "2099-01-01T00:00:00.000Z".into(),
                )),
                repeat_version_cursor: StdMutex::new(false),
                listed_size_overrides: StdMutex::new(HashMap::new()),
                exact_generation_gets: StdMutex::new(0),
                live_gets: StdMutex::new(Vec::new()),
                copy_calls: StdMutex::new(Vec::new()),
                put_calls: StdMutex::new(Vec::new()),
                provider_clock_millis: AtomicU64::new(1_800_000_000_000),
                list_calls: AtomicUsize::new(0),
                delete_generation_calls: AtomicUsize::new(0),
            }
        }

        pub fn exact_generation_count(&self, object_name: &str) -> usize {
            self.objects
                .lock()
                .unwrap()
                .get(object_name)
                .map_or(0, Vec::len)
        }

        pub fn reset_operation_counts(&self) {
            self.list_calls.store(0, Ordering::SeqCst);
            self.delete_generation_calls.store(0, Ordering::SeqCst);
        }

        pub fn operation_counts(&self) -> (usize, usize) {
            (
                self.list_calls.load(Ordering::SeqCst),
                self.delete_generation_calls.load(Ordering::SeqCst),
            )
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

        pub(crate) fn set_soft_delete_enabled(&self, enabled: bool) {
            *self.soft_delete_enabled.lock().unwrap() = enabled;
        }

        fn set_soft_delete_hard_delete_time(&self, hard_delete_time: Option<&str>) {
            *self.soft_delete_hard_delete_time.lock().unwrap() =
                hard_delete_time.map(str::to_string);
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

        pub(crate) fn live_get_count(&self) -> usize {
            self.live_gets.lock().unwrap().len()
        }

        pub(crate) fn version_count(&self, prefix: &str) -> usize {
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

        pub(crate) fn expire_soft_deleted(&self, prefix: &str) {
            let mut objects = self.objects.lock().unwrap();
            objects.retain(|name, versions| {
                if name.starts_with(prefix) {
                    versions.retain(|version| !version.soft_deleted);
                }
                !versions.is_empty()
            });
        }

        pub(crate) fn purge_versions(&self, prefix: &str) {
            self.objects
                .lock()
                .unwrap()
                .retain(|name, _| !name.starts_with(prefix));
        }

        fn soft_delete_generation(&self, object_name: &str, generation: i64) {
            let hard_delete_time = self.soft_delete_hard_delete_time.lock().unwrap().clone();
            if let Some(versions) = self.objects.lock().unwrap().get_mut(object_name) {
                if let Some(version) = versions
                    .iter_mut()
                    .find(|version| version.generation == generation)
                {
                    version.live = false;
                    version.soft_deleted = true;
                    version.hard_delete_time = hard_delete_time;
                }
            }
        }

        pub(crate) fn vanish_next_exact_generation_get(&self, object_name: &str, generation: i64) {
            *self.vanish_generation_on_get.lock().unwrap() = Some((object_name.into(), generation));
        }

        pub(crate) fn fail_next_put_after_commit(&self, error: EnclaveError) {
            *self.fail_put_after_commit.lock().unwrap() = Some(error);
        }

        pub(crate) fn fail_next_put(&self, error: EnclaveError) {
            *self.fail_put.lock().unwrap() = Some(error);
        }

        pub(crate) fn fail_next_put_for_object(&self, object_name: &str, error: EnclaveError) {
            *self.fail_put_for_object.lock().unwrap() = Some((object_name.into(), error));
        }

        pub(crate) fn fail_next_put_for_object_after_commit(
            &self,
            object_name: &str,
            error: EnclaveError,
        ) {
            *self.fail_put_for_object_after_commit.lock().unwrap() =
                Some((object_name.into(), error));
        }

        pub(crate) fn fail_next_get(&self, error: EnclaveError) {
            *self.fail_get.lock().unwrap() = Some(error);
        }

        pub(crate) fn fail_next_exact_get(&self, error: EnclaveError) {
            *self.fail_exact_get.lock().unwrap() = Some(error);
        }

        pub(crate) fn fail_next_generation_delete(&self, object_name: &str, generation: i64) {
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

        pub(crate) fn set_provider_clock_millis(&self, millis: i64) {
            self.provider_clock_millis.store(
                u64::try_from(millis).expect("test provider time must be nonnegative"),
                Ordering::SeqCst,
            );
        }
    }

    #[async_trait::async_trait]
    impl GcsClient for FakeGcs {
        async fn trusted_time_millis(
            &self,
            authority_object_name: &str,
            authority_generation: i64,
        ) -> crate::error::Result<i64> {
            match self.generation(authority_object_name) {
                Some(generation) if generation == authority_generation => {}
                Some(_) => {
                    return Err(crate::error::EnclaveError::Conflict(
                        "trusted-time authority generation changed".into(),
                    ))
                }
                None => return Err(crate::error::EnclaveError::NotFound),
            }
            Ok(self
                .provider_clock_millis
                .fetch_add(1_000, Ordering::SeqCst) as i64)
        }

        async fn get_object(&self, object_name: &str) -> crate::error::Result<GcsGetResponse> {
            self.live_gets.lock().unwrap().push(object_name.into());
            if let Some(error) = self.fail_get.lock().unwrap().take() {
                return Err(error);
            }
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
            if let Some(error) = self.fail_exact_get.lock().unwrap().take() {
                return Err(error);
            }
            let mut vanish = self.vanish_generation_on_get.lock().unwrap();
            let should_vanish = vanish
                .as_ref()
                .is_some_and(|target| target.0 == object_name && target.1 == generation);
            if should_vanish {
                *vanish = None;
            }
            drop(vanish);
            let mut store = self.objects.lock().unwrap();
            if should_vanish {
                if let Some(versions) = store.get_mut(object_name) {
                    versions.retain(|version| version.generation != generation);
                    if versions.is_empty() {
                        store.remove(object_name);
                    }
                }
                return Err(crate::error::EnclaveError::NotFound);
            }
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
            let is_write_intent = object_name.starts_with(LEGACY_WRITE_INTENT_PREFIX);
            if !is_write_intent {
                self.put_calls
                    .lock()
                    .unwrap()
                    .push((object_name.to_string(), if_generation_match));
            }
            if !is_write_intent {
                let matching_failure = {
                    let mut failure = self.fail_put_for_object.lock().unwrap();
                    if failure
                        .as_ref()
                        .is_some_and(|(expected, _)| expected == object_name)
                    {
                        failure.take().map(|(_, error)| error)
                    } else {
                        None
                    }
                };
                if let Some(error) = matching_failure {
                    return Err(error);
                }
                if let Some(error) = self.fail_put.lock().unwrap().take() {
                    return Err(error);
                }
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
                hard_delete_time: None,
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
            if !is_write_intent {
                let matching_failure = {
                    let mut failure = self.fail_put_for_object_after_commit.lock().unwrap();
                    if failure
                        .as_ref()
                        .is_some_and(|(expected, _)| expected == object_name)
                    {
                        failure.take().map(|(_, error)| error)
                    } else {
                        None
                    }
                };
                if let Some(error) = matching_failure {
                    return Err(error);
                }
                if let Some(error) = self.fail_put_after_commit.lock().unwrap().take() {
                    if let Some(replacement) = self
                        .corrupt_wrapped_dek_after_commit_failure
                        .lock()
                        .unwrap()
                        .take()
                    {
                        if let Some(current) = store
                            .get_mut(object_name)
                            .and_then(|versions| versions.iter_mut().rev().find(|item| item.live))
                        {
                            current.wrapped_dek_b64 = replacement;
                        }
                    }
                    return Err(error);
                }
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
            if let Some(error) = self.fail_copy.lock().unwrap().pop_front() {
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
            destination.hard_delete_time = None;
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
            self.list_calls.fetch_add(1, Ordering::SeqCst);
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
                            hard_delete_time: None,
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

        async fn list_live_objects(
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
            let mut versions = store
                .iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .filter_map(|(name, objects)| {
                    objects
                        .iter()
                        .rev()
                        .find(|object| object.live)
                        .map(|object| GcsObjectVersion {
                            name: name.clone(),
                            generation: object.generation,
                            size: object.ciphertext.len() as u64,
                            hard_delete_time: None,
                        })
                })
                .collect::<Vec<_>>();
            versions.sort_by(|left, right| left.name.cmp(&right.name));
            let end = (start + PAGE_SIZE).min(versions.len());
            let next_page_token =
                if *self.repeat_version_cursor.lock().unwrap() && page_token.is_some() {
                    page_token.map(str::to_owned)
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
            self.delete_generation_calls.fetch_add(1, Ordering::SeqCst);
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
            let hard_delete_time = self.soft_delete_hard_delete_time.lock().unwrap().clone();
            let mut store = self.objects.lock().unwrap();
            if let Some(versions) = store.get_mut(object_name) {
                if soft_delete_enabled {
                    if let Some(version) = versions
                        .iter_mut()
                        .find(|version| version.generation == generation)
                    {
                        version.live = false;
                        version.soft_deleted = true;
                        version.hard_delete_time = hard_delete_time;
                    }
                } else {
                    versions.retain(|version| version.generation != generation);
                }
                if versions.is_empty() {
                    store.remove(object_name);
                }
            }
            drop(store);
            if self
                .fail_generation_delete_after_commit
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|failure| failure.0 == object_name && failure.1 == generation)
            {
                *self.fail_generation_delete_after_commit.lock().unwrap() = None;
                return Err(EnclaveError::Gcs(
                    "injected lost generation-delete response".into(),
                ));
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
                            hard_delete_time: object.hard_delete_time.clone(),
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
        operation: BlockingGcsOperation,
        block_once: AtomicBool,
        started: Notify,
        release: Semaphore,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum BlockingGcsOperation {
        Put,
        Copy,
    }

    impl BlockingPutGcs {
        fn new(inner: Arc<FakeGcs>, target: String) -> Self {
            Self {
                inner,
                target,
                operation: BlockingGcsOperation::Put,
                block_once: AtomicBool::new(true),
                started: Notify::new(),
                release: Semaphore::new(0),
            }
        }

        fn copy_to(inner: Arc<FakeGcs>, target: String) -> Self {
            Self {
                inner,
                target,
                operation: BlockingGcsOperation::Copy,
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
        async fn trusted_time_millis(
            &self,
            authority_object_name: &str,
            authority_generation: i64,
        ) -> crate::error::Result<i64> {
            self.inner
                .trusted_time_millis(authority_object_name, authority_generation)
                .await
        }

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
            if self.operation == BlockingGcsOperation::Put
                && object_name == self.target
                && self.block_once.swap(false, Ordering::SeqCst)
            {
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
            if self.operation == BlockingGcsOperation::Copy
                && destination_object_name == self.target
                && self.block_once.swap(false, Ordering::SeqCst)
            {
                self.started.notify_one();
                self.release
                    .acquire()
                    .await
                    .map_err(|_| EnclaveError::Store("test GCS gate closed".into()))?
                    .forget();
            }
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

        async fn list_live_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_live_objects(prefix, page_token).await
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

    fn test_rebind_authority(byte: u8) -> String {
        format!("rebind_{byte:064x}")
    }

    fn sole_requesting_intent_expiry(gcs: &FakeGcs, user_id: &str) -> i64 {
        let prefix = legacy_write_intent_prefix(user_id);
        let expiries = gcs
            .objects
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name.starts_with(&prefix))
            .filter_map(|(_, versions)| versions.iter().rev().find(|item| item.live))
            .filter_map(|object| {
                serde_json::from_slice::<LegacyWriteIntent>(&object.ciphertext).ok()
            })
            .filter(|intent| intent.state == LegacyWriteIntentState::Requesting)
            .filter_map(|intent| intent.lease_expires_at_millis)
            .collect::<Vec<_>>();
        assert_eq!(expiries.len(), 1, "expected one active requesting intent");
        expiries[0]
    }

    #[tokio::test]
    async fn two_store_absent_index_generation_zero_intent_blocks_purge_until_outcome() {
        let user_id = "intent-index-generation-zero";
        let object_name = gcs_object_name(user_id);
        let inner = Arc::new(FakeGcs::new());
        let blocking = Arc::new(BlockingPutGcs::new(inner.clone(), object_name.clone()));
        let provider: Arc<dyn GcsClient> = blocking.clone();
        let writer = Arc::new(Store::new(Arc::new(FakeKms), provider.clone()));
        let deleter = Store::new(Arc::new(FakeKms), provider);

        writer
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO app_metadata (key, value) VALUES ('intent', 'generation-zero')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let write = {
            let writer = writer.clone();
            tokio::spawn(async move { writer.save_user(user_id).await })
        };
        blocking.wait_until_blocked().await;

        let authority = test_rebind_authority(1);
        assert!(matches!(
            deleter
                .fence_and_drain_legacy_writes(user_id, &authority)
                .await,
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::LegacyWriteIntentUnsettled,
                ..
            }))
        ));
        assert_eq!(inner.exact_generation_count(&object_name), 0);

        blocking.release();
        write.await.unwrap().unwrap();
        deleter
            .fence_and_drain_legacy_writes(user_id, &authority)
            .await
            .unwrap();
        deleter.delete_user(user_id).await.unwrap();
        assert_eq!(inner.exact_generation_count(&object_name), 0);
    }

    #[tokio::test]
    async fn two_store_raw_intent_survives_first_deletion_inventory_and_cannot_resurrect() {
        let user_id = "intent-raw-final-inventory";
        let object_name = format!("raw/{user_id}/capture.enc");
        let inner = Arc::new(FakeGcs::new());
        let blocking = Arc::new(BlockingPutGcs::new(inner.clone(), object_name.clone()));
        let provider: Arc<dyn GcsClient> = blocking.clone();
        let writer = Arc::new(Store::new(Arc::new(FakeKms), provider.clone()));
        let deleter = Store::new(Arc::new(FakeKms), provider);

        let write = {
            let writer = writer.clone();
            let object_name = object_name.clone();
            tokio::spawn(async move {
                writer
                    .put_user_media(user_id, &object_name, b"ciphertext", "wrapped")
                    .await
            })
        };
        blocking.wait_until_blocked().await;
        let authority = test_rebind_authority(2);
        assert!(matches!(
            deleter
                .fence_and_drain_legacy_writes(user_id, &authority)
                .await,
            Err(EnclaveError::DeletionPending(_))
        ));
        assert_eq!(inner.exact_generation_count(&object_name), 0);

        blocking.release();
        write.await.unwrap().unwrap();
        deleter.delete_user(user_id).await.unwrap();
        assert_eq!(inner.exact_generation_count(&object_name), 0);
        deleter.drain_legacy_write_intents(user_id).await.unwrap();
    }

    #[tokio::test]
    async fn wal_media_deletion_fences_intents_and_closes_unrecorded_put_residue() {
        let user_id = "wal-media-intent-fence";
        let object_name = format!("raw/{user_id}/capture.enc");
        let inner = Arc::new(FakeGcs::new());
        let blocking = Arc::new(BlockingPutGcs::new(inner.clone(), object_name.clone()));
        let provider: Arc<dyn GcsClient> = blocking.clone();
        let writer = Arc::new(Store::new(Arc::new(FakeKms), provider.clone()));
        let deleter = Store::new(Arc::new(FakeKms), provider);

        let write = {
            let writer = Arc::clone(&writer);
            let object_name = object_name.clone();
            tokio::spawn(async move {
                writer
                    .put_user_media(user_id, &object_name, b"ciphertext", "wrapped")
                    .await
            })
        };
        blocking.wait_until_blocked().await;
        assert!(matches!(
            deleter.delete_wal_authoritative_media(user_id, &[]).await,
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::LegacyWriteIntentUnsettled,
                ..
            }))
        ));
        assert_eq!(inner.exact_generation_count(&object_name), 0);

        blocking.release();
        write.await.unwrap().unwrap();
        deleter
            .delete_wal_authoritative_media(user_id, &[])
            .await
            .unwrap();
        assert_eq!(inner.exact_generation_count(&object_name), 0);
        assert!(matches!(
            writer
                .put_user_media(user_id, &object_name, b"later", "wrapped")
                .await,
            Err(EnclaveError::Auth(_))
        ));
        assert_eq!(inner.exact_generation_count(&object_name), 0);
    }

    #[tokio::test]
    async fn two_store_checkpoint_intent_blocks_final_inventory_until_copy_reconciles() {
        let user_id = "intent-checkpoint-final-inventory";
        let day = UNIX_EPOCH + Duration::from_secs(1_767_268_800);
        let destination = legacy_recovery_checkpoint_name(user_id, day);
        let inner = Arc::new(FakeGcs::new());
        let seed = Store::new(Arc::new(FakeKms), inner.clone());
        write_and_save(&seed, user_id, "seed").await.unwrap();
        let source_generation = inner.generation(&gcs_object_name(user_id)).unwrap();

        let blocking = Arc::new(BlockingPutGcs::copy_to(inner.clone(), destination.clone()));
        let provider: Arc<dyn GcsClient> = blocking.clone();
        let writer = Arc::new(Store::new(Arc::new(FakeKms), provider.clone()));
        let deleter = Store::new(Arc::new(FakeKms), provider);
        let lease = writer.acquire_content_write(user_id).await.unwrap();
        let copy = {
            let writer = writer.clone();
            tokio::spawn(async move {
                writer
                    .ensure_legacy_recovery_checkpoint(user_id, source_generation, day, lease, None)
                    .await
            })
        };
        blocking.wait_until_blocked().await;
        let authority = test_rebind_authority(3);
        assert!(matches!(
            deleter
                .fence_and_drain_legacy_writes(user_id, &authority)
                .await,
            Err(EnclaveError::DeletionPending(_))
        ));
        assert_eq!(inner.exact_generation_count(&destination), 0);

        blocking.release();
        copy.await.unwrap().unwrap();
        deleter.delete_user(user_id).await.unwrap();
        assert_eq!(inner.exact_generation_count(&destination), 0);
    }

    #[tokio::test]
    async fn two_store_delayed_stable_create_remains_visible_until_terminal_tombstone() {
        let user_id = "intent-stable-create";
        let object_name = gcs_object_name(user_id);
        let inner = Arc::new(FakeGcs::new());
        let blocking = Arc::new(BlockingPutGcs::new(inner.clone(), object_name.clone()));
        let provider: Arc<dyn GcsClient> = blocking.clone();
        let kms: Arc<dyn KmsClient> = Arc::new(FakeKms);
        let writer = Arc::new(Store::new(kms.clone(), provider.clone()));
        let deleter = Store::new(kms.clone(), provider);
        let (dek, wrapped) = generate_and_wrap_dek(kms.as_ref()).await.unwrap();
        let plaintext = create_empty_db(&dek).unwrap();
        let ciphertext = encrypt_bound_blob(&dek, &plaintext, &user_blob_context(user_id)).unwrap();

        let create = {
            let writer = writer.clone();
            let object_name = object_name.clone();
            tokio::spawn(async move {
                writer
                    .put_stable_rebind_index(user_id, &object_name, &ciphertext, &wrapped)
                    .await
            })
        };
        blocking.wait_until_blocked().await;
        let authority = test_rebind_authority(4);
        assert!(matches!(
            deleter
                .fence_and_drain_legacy_writes(user_id, &authority)
                .await,
            Err(EnclaveError::DeletionPending(_))
        ));

        blocking.release();
        create.await.unwrap().unwrap();
        deleter.delete_user(user_id).await.unwrap();
        assert_eq!(inner.exact_generation_count(&object_name), 0);
        let intents = inner
            .list_live_objects(&legacy_write_intent_prefix(user_id), None)
            .await
            .unwrap();
        assert!(intents.versions.iter().all(|listed| {
            let object = inner.objects.lock().unwrap()[&listed.name]
                .iter()
                .rev()
                .find(|object| object.live)
                .unwrap()
                .clone();
            let intent: LegacyWriteIntent = serde_json::from_slice(&object.ciphertext).unwrap();
            intent.state.is_terminal()
                && intent.ciphertext_b64.is_none()
                && intent.wrapped_dek_b64.is_none()
        }));
    }

    #[tokio::test]
    async fn expired_requesting_intent_is_taken_over_after_owner_crash() {
        let user_id = "intent-requesting-takeover";
        let object_name = format!("raw/{user_id}/takeover.enc");
        let inner = Arc::new(FakeGcs::new());
        let first = Store::new(Arc::new(FakeKms), inner.clone());
        let restarted = Store::new(Arc::new(FakeKms), inner.clone());
        let request = LegacyWriteRequest::Put {
            backend: LegacyWriteBackend::Media,
            kind: LegacyWriteKind::MediaPut,
            object_name: object_name.clone(),
            ciphertext: b"encrypted-takeover".to_vec(),
            wrapped_dek_b64: "wrapped-takeover".into(),
            if_generation_match: 0,
        };
        let prepared = first
            .create_legacy_write_intent(user_id, &request)
            .await
            .unwrap();
        let mut requesting = first.claim_legacy_write_intent(&prepared).await.unwrap();
        requesting.intent.lease_expires_at_millis = Some(1);
        requesting.generation = first
            .persist_legacy_write_intent(
                &requesting.object_name,
                &requesting.intent,
                requesting.generation,
            )
            .await
            .unwrap();

        let authority = test_rebind_authority(5);
        restarted
            .fence_and_drain_legacy_writes(user_id, &authority)
            .await
            .unwrap();
        assert_eq!(inner.exact_generation_count(&object_name), 1);
        let terminal = restarted
            .load_legacy_write_intent(&requesting.object_name)
            .await
            .unwrap();
        assert_eq!(terminal.intent.state, LegacyWriteIntentState::Committed);
        assert!(terminal.intent.ciphertext_b64.is_none());
        assert_eq!(inner.exact_generation_count(&requesting.object_name), 1);
    }

    struct BlockingTrustedTimeGcs {
        inner: Arc<FakeGcs>,
        armed: AtomicBool,
        response_ready: Notify,
        release_response: Semaphore,
    }

    impl BlockingTrustedTimeGcs {
        fn new(inner: Arc<FakeGcs>) -> Self {
            Self {
                inner,
                armed: AtomicBool::new(false),
                response_ready: Notify::new(),
                release_response: Semaphore::new(0),
            }
        }

        fn arm(&self) {
            self.armed.store(true, Ordering::SeqCst);
        }

        async fn wait_until_response_ready(&self) {
            self.response_ready.notified().await;
        }

        fn release(&self) {
            self.release_response.add_permits(1);
        }
    }

    #[async_trait::async_trait]
    impl GcsClient for BlockingTrustedTimeGcs {
        async fn trusted_time_millis(
            &self,
            authority_object_name: &str,
            authority_generation: i64,
        ) -> crate::error::Result<i64> {
            let time = self
                .inner
                .trusted_time_millis(authority_object_name, authority_generation)
                .await?;
            if self.armed.swap(false, Ordering::SeqCst) {
                self.response_ready.notify_one();
                self.release_response
                    .acquire()
                    .await
                    .map_err(|_| EnclaveError::Store("test trusted-time gate closed".into()))?
                    .forget();
            }
            Ok(time)
        }

        async fn get_object(&self, object_name: &str) -> crate::error::Result<GcsGetResponse> {
            self.inner.get_object(object_name).await
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

        async fn copy_generation_if_absent(
            &self,
            source_name: &str,
            source_generation: i64,
            destination_name: &str,
        ) -> crate::error::Result<GcsGenerationCopy> {
            self.inner
                .copy_generation_if_absent(source_name, source_generation, destination_name)
                .await
        }

        async fn delete_object(&self, object_name: &str) -> crate::error::Result<()> {
            self.inner.delete_object(object_name).await
        }

        async fn list_object_versions(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_object_versions(prefix, page_token).await
        }

        async fn list_live_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_live_objects(prefix, page_token).await
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

    #[tokio::test(start_paused = true)]
    async fn absolute_deadline_fences_delayed_verified_owner_after_takeover_and_deletion() {
        let user_id = "intent-absolute-deadline";
        let object_name = format!("raw/{user_id}/must-not-resurrect.enc");
        let inner = Arc::new(FakeGcs::new());
        let delayed_provider = Arc::new(BlockingTrustedTimeGcs::new(inner.clone()));
        let original = Arc::new(Store::new(Arc::new(FakeKms), delayed_provider.clone()));
        let takeover = Store::new(Arc::new(FakeKms), inner.clone());
        let request = LegacyWriteRequest::Put {
            backend: LegacyWriteBackend::Media,
            kind: LegacyWriteKind::MediaPut,
            object_name: object_name.clone(),
            ciphertext: b"encrypted-absolute-deadline".to_vec(),
            wrapped_dek_b64: "wrapped-absolute-deadline".into(),
            if_generation_match: 0,
        };
        let prepared = original
            .create_legacy_write_intent(user_id, &request)
            .await
            .unwrap();
        let claimed = original.claim_legacy_write_intent(&prepared).await.unwrap();
        let lease_expiry = claimed.intent.lease_expires_at_millis.unwrap();

        delayed_provider.arm();
        let late_claim = claimed.clone();
        let late_store = Arc::clone(&original);
        let delayed = tokio::spawn(async move {
            late_store
                .execute_claimed_legacy_write_intent(late_claim, None)
                .await
        });
        delayed_provider.wait_until_response_ready().await;

        // The authenticated Date response exists, but delivery of it to the
        // executor is scheduler-delayed. A different instance observes the
        // expired provider lease, takes over, commits once, and deletion then
        // removes that exact destination generation.
        inner.set_provider_clock_millis(lease_expiry + 1_000);
        assert!(takeover
            .drain_one_legacy_write_intent(claimed, false)
            .await
            .unwrap());
        let committed_generation = inner.generation(&object_name).unwrap();
        inner
            .delete_object_generation(&object_name, committed_generation)
            .await
            .unwrap();

        tokio::time::advance(LEGACY_WRITE_PROVIDER_TIMEOUT + Duration::from_secs(1)).await;
        delayed_provider.release();
        assert!(matches!(
            delayed.await.unwrap(),
            Err(EnclaveError::Conflict(_))
        ));
        assert_eq!(inner.put_attempts(), 1);
        assert_eq!(inner.exact_generation_count(&object_name), 0);
    }

    #[tokio::test]
    async fn stale_intent_owner_cannot_issue_or_resurrect_after_lease_margin_and_takeover() {
        let user_id = "intent-stale-owner";
        let object_name = format!("raw/{user_id}/must-not-resurrect.enc");
        let inner = Arc::new(FakeGcs::new());
        let original = Store::new(Arc::new(FakeKms), inner.clone());
        let takeover = Store::new(Arc::new(FakeKms), inner.clone());
        let request = LegacyWriteRequest::Put {
            backend: LegacyWriteBackend::Media,
            kind: LegacyWriteKind::MediaPut,
            object_name: object_name.clone(),
            ciphertext: b"encrypted-stale-owner".to_vec(),
            wrapped_dek_b64: "wrapped-stale-owner".into(),
            if_generation_match: 0,
        };
        let prepared = original
            .create_legacy_write_intent(user_id, &request)
            .await
            .unwrap();
        let claimed = original.claim_legacy_write_intent(&prepared).await.unwrap();
        let lease_expiry = claimed.intent.lease_expires_at_millis.unwrap();

        // A fresh trusted-time read caps the provider timeout to the lease's
        // remaining budget less the safety margin.
        inner
            .set_provider_clock_millis(lease_expiry - LEGACY_WRITE_PROVIDER_SAFETY_MILLIS - 12_345);
        let deadline = verify_persisted_legacy_write_intent_owner(inner.as_ref(), &claimed)
            .await
            .unwrap();
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(remaining <= Duration::from_millis(12_345));
        assert!(!remaining.is_zero());

        // Once the safety window begins, the original owner performs no
        // destination I/O even though its durable claim has not yet expired.
        inner.set_provider_clock_millis(lease_expiry - 30_000);
        assert!(matches!(
            original
                .execute_claimed_legacy_write_intent(claimed.clone(), None)
                .await,
            Err(EnclaveError::Conflict(_))
        ));
        assert_eq!(inner.put_attempts(), 0);
        assert_eq!(inner.exact_generation_count(&object_name), 0);

        // After expiry another instance takes over the encrypted exact
        // request, commits it once, and replaces the ownership generation.
        inner.set_provider_clock_millis(lease_expiry + 1_000);
        assert!(takeover
            .drain_one_legacy_write_intent(claimed.clone(), false)
            .await
            .unwrap());
        assert_eq!(inner.put_attempts(), 1);
        let committed_generation = inner.generation(&object_name).unwrap();

        // Simulate deletion after takeover. A late future holding the stale
        // claim cannot issue the provider request or recreate the object.
        inner
            .delete_object_generation(&object_name, committed_generation)
            .await
            .unwrap();
        assert!(matches!(
            original
                .execute_claimed_legacy_write_intent(claimed, None)
                .await,
            Err(EnclaveError::Conflict(_))
        ));
        assert_eq!(inner.put_attempts(), 1);
        assert_eq!(inner.exact_generation_count(&object_name), 0);
    }

    #[tokio::test]
    async fn two_store_intent_created_after_retained_marker_performs_no_data_io() {
        let user_id = "intent-after-marker";
        let object_name = format!("raw/{user_id}/must-not-exist.enc");
        let inner = Arc::new(FakeGcs::new());
        let marker_store = Store::new(Arc::new(FakeKms), inner.clone());
        let writer_store = Store::new(Arc::new(FakeKms), inner.clone());
        marker_store
            .fence_and_drain_legacy_writes(user_id, &test_rebind_authority(6))
            .await
            .unwrap();

        assert!(matches!(
            writer_store
                .put_user_media(user_id, &object_name, b"ciphertext", "wrapped")
                .await,
            Err(EnclaveError::Auth(_))
        ));
        assert_eq!(inner.exact_generation_count(&object_name), 0);
        marker_store
            .drain_legacy_write_intents(user_id)
            .await
            .unwrap();
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
        async fn trusted_time_millis(
            &self,
            authority_object_name: &str,
            authority_generation: i64,
        ) -> crate::error::Result<i64> {
            self.inner
                .trusted_time_millis(authority_object_name, authority_generation)
                .await
        }

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

        async fn list_live_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_live_objects(prefix, page_token).await
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
        async fn trusted_time_millis(
            &self,
            authority_object_name: &str,
            authority_generation: i64,
        ) -> crate::error::Result<i64> {
            self.inner
                .trusted_time_millis(authority_object_name, authority_generation)
                .await
        }

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

        async fn list_live_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_live_objects(prefix, page_token).await
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
        async fn trusted_time_millis(
            &self,
            authority_object_name: &str,
            authority_generation: i64,
        ) -> crate::error::Result<i64> {
            self.inner
                .trusted_time_millis(authority_object_name, authority_generation)
                .await
        }

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

        async fn list_live_objects(
            &self,
            prefix: &str,
            page_token: Option<&str>,
        ) -> crate::error::Result<GcsListVersionsResponse> {
            self.inner.list_live_objects(prefix, page_token).await
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

    pub(crate) fn insert_screenshot_evidence(conn: &Connection, object_key: &str) -> Result<()> {
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

    #[tokio::test]
    async fn startup_reconciliation_checkpoints_only_the_current_live_generation_and_is_idempotent()
    {
        let gcs = Arc::new(FakeGcs::new());
        let store = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        let archive = gcs_object_name("backfill-user");
        gcs.put_object(&archive, b"old", "wrapped", 0)
            .await
            .unwrap();
        gcs.put_object(&archive, b"current", "wrapped", 1)
            .await
            .unwrap();
        let gone = gcs_object_name("deleted-user");
        gcs.put_object(&gone, b"gone", "wrapped", 0).await.unwrap();
        gcs.delete_object(&gone).await.unwrap();
        let gets_before = gcs.live_get_count();

        let first = store
            .reconcile_legacy_recovery_checkpoints_once()
            .await
            .unwrap();
        assert!(first.ready);
        assert_eq!(first.live_archives_checked, 1);
        assert_eq!(
            gcs.live_gets.lock().unwrap()[gets_before..]
                .iter()
                .filter(|name| *name == &archive)
                .count(),
            1,
            "intent and fence reads must not duplicate the archive read"
        );
        let checkpoint = legacy_recovery_checkpoint_name(
            "backfill-user",
            UNIX_EPOCH + Duration::from_secs(1_767_268_800),
        );
        assert_eq!(gcs.version_count(&checkpoint), 1);
        let binding = gcs.objects.lock().unwrap()[&checkpoint]
            .last()
            .unwrap()
            .legacy_recovery
            .as_ref()
            .unwrap()
            .clone();
        assert_eq!(binding.source_generation, 2);
        assert_eq!(gcs.copy_calls.lock().unwrap().len(), 1);

        let second = store
            .reconcile_legacy_recovery_checkpoints_once()
            .await
            .unwrap();
        assert!(second.ready);
        assert_eq!(
            gcs.version_count(&checkpoint),
            1,
            "retry must not overwrite the immutable checkpoint"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deletion_waits_for_reconciliation_copy_before_recovery_inventory() {
        let inner = Arc::new(FakeGcs::new());
        // Seed a valid encrypted database and a day-one checkpoint. Reconcile
        // on day two so it must create a new immutable recovery copy.
        let seed = store_with_checkpoint_time(Arc::clone(&inner), 1_767_268_800);
        write_and_save(&seed, "checkpoint-delete-race", "seed")
            .await
            .expect("seed encrypted user database");
        drop(seed);

        let checkpoint_time = 1_767_355_200;
        let checkpoint = legacy_recovery_checkpoint_name(
            "checkpoint-delete-race",
            UNIX_EPOCH + Duration::from_secs(checkpoint_time),
        );
        let blocked = Arc::new(BlockingPutGcs::copy_to(
            Arc::clone(&inner),
            checkpoint.clone(),
        ));
        let mut raw_store =
            make_store_with_limit(Arc::new(FakeKms), blocked.clone(), inner.clone(), 1);
        raw_store.checkpoint_clock =
            Arc::new(move || UNIX_EPOCH + Duration::from_secs(checkpoint_time));
        let store = Arc::new(raw_store);

        let reconcile_store = Arc::clone(&store);
        let reconcile = tokio::spawn(async move {
            reconcile_store
                .reconcile_legacy_recovery_checkpoints_once()
                .await
        });
        blocked.wait_until_blocked().await;

        let delete_store = Arc::clone(&store);
        let deletion =
            tokio::spawn(async move { delete_store.delete_user("checkpoint-delete-race").await });
        let pending = tokio::time::timeout(Duration::from_millis(100), deletion)
            .await
            .expect("deletion must promptly expose its durable pending state")
            .expect("deletion task panicked");
        assert!(matches!(
            pending,
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::LegacyWriteIntentUnsettled,
                ..
            }))
        ));
        assert_eq!(inner.version_count(&checkpoint), 0);
        assert_eq!(
            inner.version_count(&gcs_object_name("checkpoint-delete-race")),
            1
        );

        blocked.release();
        reconcile
            .await
            .expect("reconciler task panicked")
            .expect("reconciler failed after copy release");
        store
            .delete_user("checkpoint-delete-race")
            .await
            .expect("deletion retry failed after reconciliation settled");
        assert_eq!(inner.version_count(&checkpoint), 0);
        assert!(inner
            .objects
            .lock()
            .unwrap()
            .keys()
            .all(|name| !name.starts_with("legacy-recovery/checkpoint-delete-race/")));
    }

    #[tokio::test]
    async fn startup_reconciliation_fails_closed_for_malformed_governed_index_name() {
        let gcs = Arc::new(FakeGcs::new());
        gcs.put_object("indexes/not/a.db.enc", b"bad", "wrapped", 0)
            .await
            .unwrap();
        let store = store_with_checkpoint_time(gcs, 1_767_268_800);
        assert!(store
            .reconcile_legacy_recovery_checkpoints_once()
            .await
            .is_err());
        assert!(!store.legacy_checkpoint_reconciliation().await.ready);
    }

    #[tokio::test]
    async fn startup_reconciliation_rejects_repeated_live_listing_cursor() {
        let gcs = Arc::new(FakeGcs::new());
        for user in ["cursor-a", "cursor-b", "cursor-c"] {
            gcs.put_object(&gcs_object_name(user), b"current", "wrapped", 0)
                .await
                .unwrap();
        }
        gcs.set_repeat_version_cursor(true);
        let store = store_with_checkpoint_time(gcs, 1_767_268_800);
        assert!(store
            .reconcile_legacy_recovery_checkpoints_once()
            .await
            .is_err());
        assert!(!store.legacy_checkpoint_reconciliation().await.ready);
    }

    #[tokio::test]
    async fn startup_reconciliation_is_not_ready_after_partial_failure_and_recovers_after_restart()
    {
        let gcs = Arc::new(FakeGcs::new());
        let archive = gcs_object_name("retry-backfill");
        gcs.put_object(&archive, b"current", "wrapped", 0)
            .await
            .unwrap();
        *gcs.fail_copy.lock().unwrap() = VecDeque::from([
            EnclaveError::Gcs("temporary copy failure 1".into()),
            EnclaveError::Gcs("temporary copy failure 2".into()),
        ]);
        let first = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        assert!(first
            .reconcile_legacy_recovery_checkpoints_once()
            .await
            .is_err());
        let failed = first.legacy_checkpoint_reconciliation().await;
        assert!(!failed.ready);
        assert_eq!(failed.failures, 1);

        let expiry = sole_requesting_intent_expiry(&gcs, "retry-backfill");
        gcs.set_provider_clock_millis(expiry + 1_000);
        let restarted = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        let recovered = restarted
            .reconcile_legacy_recovery_checkpoints_once()
            .await
            .unwrap();
        assert!(recovered.ready);
        assert_eq!(recovered.completed_scans, 1);
    }

    #[tokio::test]
    async fn startup_reconciliation_converges_after_copy_precondition_race() {
        let gcs = Arc::new(FakeGcs::new());
        let archive = gcs_object_name("race-backfill");
        gcs.put_object(&archive, b"current", "wrapped", 0)
            .await
            .unwrap();
        *gcs.fail_copy_after_create.lock().unwrap() =
            Some(EnclaveError::Gcs("lost copy response".into()));
        let first = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        assert!(
            first
                .reconcile_legacy_recovery_checkpoints_once()
                .await
                .unwrap()
                .ready,
            "the owned retry must exact-adopt a copy whose response was lost"
        );

        let restarted = store_with_checkpoint_time(gcs.clone(), 1_767_268_800);
        assert!(
            restarted
                .reconcile_legacy_recovery_checkpoints_once()
                .await
                .unwrap()
                .ready
        );
        let checkpoint = legacy_recovery_checkpoint_name(
            "race-backfill",
            UNIX_EPOCH + Duration::from_secs(1_767_268_800),
        );
        assert_eq!(gcs.version_count(&checkpoint), 1);
        assert_eq!(gcs.copy_calls.lock().unwrap().len(), 3);
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
        write_and_save(&store, "retry-user", "second")
            .await
            .unwrap();
        assert_eq!(
            gcs.put_calls.lock().unwrap().len(),
            2,
            "an exact retry resolves the lost checkpoint response before overwrite"
        );
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
        assert_eq!(gcs.copy_calls.lock().unwrap().len(), 2);
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
        *gcs.fail_copy.lock().unwrap() = VecDeque::from([
            EnclaveError::Gcs("copy unavailable 1".into()),
            EnclaveError::Gcs("copy unavailable 2".into()),
        ]);
        assert!(matches!(
            write_and_save(&store, "failure-user", "second").await,
            Err(EnclaveError::Gcs(_))
        ));
        assert_eq!(
            gcs.put_calls.lock().unwrap().len(),
            1,
            "checkpoint failure must prevent the authoritative overwrite"
        );
        assert!(matches!(
            store.save_user("failure-user").await,
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::LegacyWriteIntentUnsettled,
                ..
            }))
        ));
        let expiry = sole_requesting_intent_expiry(&gcs, "failure-user");
        gcs.set_provider_clock_millis(expiry + 1_000);
        store.save_user("failure-user").await.unwrap();
        assert_eq!(
            gcs.copy_calls.lock().unwrap().len(),
            4,
            "takeover plus the caller's exact destination verification are bounded"
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
        *gcs.fail_copy.lock().unwrap() = VecDeque::from([
            EnclaveError::Gcs("rollover failure 1".into()),
            EnclaveError::Gcs("rollover failure 2".into()),
        ]);
        assert!(write_and_save(&store, "rollover-user", "third")
            .await
            .is_err());
        assert_eq!(gcs.put_calls.lock().unwrap().len(), 2);

        let expiry = sole_requesting_intent_expiry(&gcs, "rollover-user");
        gcs.set_provider_clock_millis(expiry + 1_000);
        store.save_user("rollover-user").await.unwrap();
        write_and_save(&store, "rollover-user", "fourth")
            .await
            .unwrap();
        assert_eq!(
            gcs.copy_calls.lock().unwrap().len(),
            5,
            "failed day-two copy is retried twice, then taken over and exact-verified"
        );
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
             DROP TABLE push_deliveries;
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
                hard_delete_time: None,
                crc32c: "fake-crc32c".into(),
                md5_hash: None,
                legacy_recovery: None,
            }],
        );
    }

    fn seed_current_user_object(gcs: &FakeGcs, user_id: &str) {
        let dek = Dek([6_u8; 32]);
        let plaintext = create_empty_db(&dek).unwrap();
        let ciphertext = encrypt_bound_blob(&dek, &plaintext, &user_blob_context(user_id)).unwrap();
        gcs.objects.lock().unwrap().insert(
            gcs_object_name(user_id),
            vec![FakeObject {
                ciphertext,
                wrapped_dek_b64: B64.encode(dek.0),
                generation: 1,
                live: true,
                soft_deleted: false,
                hard_delete_time: None,
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
                hard_delete_time: None,
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
    async fn wal_logical_only_reads_are_query_only_and_mutation_closures_never_run() {
        let gcs = Arc::new(FakeGcs::new());
        seed_current_user_object(&gcs, "wal-guard");
        let store = Store::new_wal_logical_only_for_test(Arc::new(FakeKms), gcs.clone(), 2);
        let puts_before = gcs.put_attempts();
        let raw = store
            .with_user("wal-guard", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at) VALUES (?1)",
                    ["2026-08-13T12:00:00Z"],
                )?;
                Ok(())
            })
            .await;
        assert!(raw.is_err());
        assert_eq!(gcs.put_attempts(), puts_before);

        let mut_ran = Arc::new(AtomicBool::new(false));
        let mut_ran_in_closure = Arc::clone(&mut_ran);
        assert!(store
            .with_user_mut("wal-guard", move |_| {
                mut_ran_in_closure.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .is_err());
        assert!(!mut_ran.load(Ordering::SeqCst));

        let changed_ran = Arc::new(AtomicBool::new(false));
        let changed_ran_in_closure = Arc::clone(&changed_ran);
        assert!(store
            .with_user_if_changed("wal-guard", move |_| {
                changed_ran_in_closure.store(true, Ordering::SeqCst);
                Ok(((), true))
            })
            .await
            .is_err());
        assert!(!changed_ran.load(Ordering::SeqCst));
        assert_eq!(gcs.put_attempts(), puts_before);
    }

    #[tokio::test]
    async fn wal_logical_only_dirty_save_and_eviction_stay_resident_without_put() {
        let gcs = Arc::new(FakeGcs::new());
        seed_current_user_object(&gcs, "wal-dirty");
        seed_current_user_object(&gcs, "wal-next");
        let store = Store::new_wal_logical_only_for_test(Arc::new(FakeKms), gcs.clone(), 1);
        store.with_user_read("wal-dirty", |_| Ok(())).await.unwrap();
        let actor = match store.actor_for_existing("wal-dirty").await.unwrap() {
            SaveTarget::Actor(actor) => actor,
            SaveTarget::AlreadyFlushed => panic!("fresh WAL-only actor was unexpectedly evicted"),
        };
        {
            let mut state = actor.state.lock().await;
            state.handle.as_mut().unwrap().mark_dirty();
        }
        let puts_before = gcs.put_attempts();
        assert!(store.save_user("wal-dirty").await.is_err());
        assert_eq!(gcs.put_attempts(), puts_before);
        assert!(store.with_user_read("wal-next", |_| Ok(())).await.is_err());
        assert_eq!(gcs.put_attempts(), puts_before);
        let state = actor.state.lock().await;
        assert!(state.handle.is_some());
        assert!(state.handle.as_ref().unwrap().dirty);
    }

    #[tokio::test]
    async fn wal_logical_only_rejects_migration_or_envelope_rewrite_without_put() {
        let gcs = Arc::new(FakeGcs::new());
        seed_user_object_with_missing_schema(&gcs, "wal-migration");
        seed_user_object_with_legacy_envelope(&gcs, "wal-envelope");
        let store = Store::new_wal_logical_only_for_test(Arc::new(FakeKms), gcs.clone(), 1);
        let puts_before = gcs.put_attempts();
        assert!(store
            .with_user_read("wal-migration", |_| Ok(()))
            .await
            .is_err());
        assert_eq!(gcs.put_attempts(), puts_before);
        assert!(matches!(
            store.actor_for_existing("wal-migration").await,
            Err(EnclaveError::NotFound)
        ));
        assert!(store
            .with_user_read("wal-envelope", |_| Ok(()))
            .await
            .is_err());
        assert_eq!(gcs.put_attempts(), puts_before);
        assert!(matches!(
            store.actor_for_existing("wal-envelope").await,
            Err(EnclaveError::NotFound)
        ));
    }

    #[tokio::test]
    async fn wal_logical_only_missing_user_has_no_kms_temp_or_put_authority() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(CountingKms::default());
        let prefix = "kioku-wal-missing-";
        let temp_count = || {
            std::fs::read_dir(std::env::temp_dir())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
                .count()
        };
        let before_temp = temp_count();
        let store = Store::new_wal_logical_only_for_test(kms.clone(), gcs.clone(), 1);
        assert!(store
            .with_user_read("wal-missing", |_| Ok(()))
            .await
            .is_err());
        assert_eq!(kms.wraps.load(Ordering::SeqCst), 0);
        assert_eq!(kms.unwraps.load(Ordering::SeqCst), 0);
        assert_eq!(gcs.put_attempts(), 0);
        assert_eq!(temp_count(), before_temp);
    }

    /// A database that has drifted from `SCHEMA_SQL`, so that reconciliation
    /// is observable: the legacy open path recreates the dropped table, the
    /// owner path must leave it missing.
    #[cfg(test)]
    fn drifted_owner_database(directory: &std::path::Path, name: &str) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, create_empty_db(&Dek([9_u8; 32])).unwrap()).unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DROP TABLE email_deliveries;").unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(conn);
        path
    }

    #[cfg(test)]
    fn email_deliveries_exists(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'email_deliveries'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            == 1
    }

    #[test]
    fn wal_owner_open_runs_no_ddl_and_enables_foreign_keys() {
        let directory = tempfile::tempdir().unwrap();
        let owner_path = drifted_owner_database(directory.path(), "owner.db");
        let (connection, _registration, migrated) = open_db(
            &owner_path,
            None,
            StorePersistencePolicy::WalOwnerAuthoritative,
        )
        .unwrap();

        // An archive-v3 owner pins its schema into checkpoint commitments, so
        // a page written by the open path would diverge the live database from
        // the bytes the owner authenticated.
        assert!(!migrated);
        assert!(
            !email_deliveries_exists(&connection),
            "the owner open reconciled the schema; it must run no DDL"
        );
        // Connection-scoped and OFF by default. `SCHEMA_SQL` is the only other
        // place a user database turns this on, and the owner open skips it.
        assert_eq!(
            connection
                .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(connection);

        // The contrast that gives the assertion above its meaning: the same
        // drift, opened the legacy way, is reconciled.
        let legacy_path = drifted_owner_database(directory.path(), "legacy.db");
        let (connection, _registration, migrated) =
            open_db(&legacy_path, None, StorePersistencePolicy::LegacySnapshot).unwrap();
        assert!(migrated);
        assert!(email_deliveries_exists(&connection));
    }

    #[test]
    fn wal_owner_open_refuses_a_database_that_is_not_in_wal_mode() {
        // Journal mode lives in the database header, so a non-WAL file did not
        // come from the genesis materializer. Serving it would put the owner's
        // commits somewhere the publication protocol never reads.
        let directory = tempfile::tempdir().unwrap();
        let path = drifted_owner_database(directory.path(), "rollback.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode = DELETE;").unwrap();
        drop(conn);
        assert!(open_db(&path, None, StorePersistencePolicy::WalOwnerAuthoritative).is_err());
    }

    /// Every table whose `id` is a row *allocator* — implicitly assigned by
    /// SQLite on insert — **and** which some path deletes from. A plain
    /// `INTEGER PRIMARY KEY` reuses ids after a delete; every one of these has
    /// at least one satellite keyed by that id which is cleaned by an explicit
    /// statement rather than by a cascade, so a reused id aliases a deleted
    /// row's satellites onto a new row.
    ///
    /// Derived by sweeping all four frozen DDL sources; see the PR body. The
    /// remaining plain `INTEGER PRIMARY KEY` declarations in the baseline are
    /// borrowed keys (`screenshot_id`, `episode_id`) or projection mirrors,
    /// never allocators, and adding `AUTOINCREMENT` to them would be wrong.
    #[cfg(test)]
    const ALLOCATOR_TABLES: &[&str] = &["audio_segments", "utterances", "screenshots"];

    #[test]
    fn baseline_declares_autoincrement_for_every_deleting_allocator_table() {
        // Registration is a sqlite3_auto_extension hook, so it must precede
        // the open or SCHEMA_SQL's vec0 virtual tables fail with "no such
        // module". Inverted, these passed only when an alphabetically earlier
        // test happened to fire the Once first.
        init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_SQL).unwrap();
        run_migrations(&conn).unwrap();
        for table in ALLOCATOR_TABLES {
            let sql: String = conn
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                sql.contains("AUTOINCREMENT"),
                "{table} allocates ids and is deleted from, so its id must \
                 never be reissued:\n{sql}"
            );
        }
    }

    #[test]
    fn deleted_allocator_ids_are_never_reissued() {
        // The single most important assertion in the re-baseline. On the
        // pre-edit baseline every one of these reissues id 1, which is the
        // killed MAX(id)+1 allocator with its guardrail removed.
        // Registration is a sqlite3_auto_extension hook, so it must precede
        // the open or SCHEMA_SQL's vec0 virtual tables fail with "no such
        // module". Inverted, these passed only when an alphabetically earlier
        // test happened to fire the Once first.
        init_vec_extension();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_SQL).unwrap();
        run_migrations(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO audio_segments (started_at, ended_at, duration_seconds, source_type)
                 VALUES ('a','b',1.0,'mic');
             INSERT INTO utterances (audio_segment_id, start_offset_seconds, end_offset_seconds,
                                     text, speaker_label)
                 VALUES (1, 0.0, 1.0, 'hello', 'S1');
             INSERT INTO screenshots (captured_at) VALUES ('a');",
        )
        .unwrap();
        for table in ALLOCATOR_TABLES {
            let first: i64 = conn
                .query_row(&format!("SELECT max(id) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(first, 1, "{table}: first insert must allocate 1");
        }

        // `utterances` cascades from `audio_segments`, so delete it first and
        // let the cascade take the rest.
        conn.execute_batch("DELETE FROM audio_segments; DELETE FROM screenshots;")
            .unwrap();
        for table in ALLOCATOR_TABLES {
            let remaining: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(remaining, 0, "{table} should be empty (cascade included)");
            // The high-water survives the delete. This is the durable fact
            // that makes reuse impossible; `read_audio_sequence_pins` reads it.
            let seq: i64 = conn
                .query_row(
                    "SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name=?1),0)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(seq, 1, "{table}: DELETE must not rewind the high-water");
        }

        conn.execute_batch(
            "INSERT INTO audio_segments (started_at, ended_at, duration_seconds, source_type)
                 VALUES ('a','b',1.0,'mic');
             INSERT INTO utterances (audio_segment_id, start_offset_seconds, end_offset_seconds,
                                     text, speaker_label)
                 VALUES (2, 0.0, 1.0, 'hello', 'S1');
             INSERT INTO screenshots (captured_at) VALUES ('a');",
        )
        .unwrap();
        for table in ALLOCATOR_TABLES {
            let reissued: i64 = conn
                .query_row(&format!("SELECT max(id) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(
                reissued, 2,
                "{table} reissued a deleted id; a stale satellite row \
                 (vec_*, episode_members, mcp_safe_*) would now alias onto it"
            );
        }
    }

    #[test]
    fn bundled_sqlite_reproduces_the_measured_autoincrement_semantics() {
        // T-14. The design was measured on the sqlite CLI; these are the same
        // behaviours re-asserted against the bundled rusqlite build, because
        // the baseline is being changed on the strength of them.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE auto (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);
             CREATE TABLE plain (id INTEGER PRIMARY KEY, v TEXT);",
        )
        .unwrap();
        let seq = |name: &str| -> i64 {
            conn.query_row(
                "SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name=?1),0)",
                [name],
                |row| row.get(0),
            )
            .unwrap()
        };
        // A virgin AUTOINCREMENT table has NO sqlite_sequence row, so the
        // COALESCE pin genuinely reads 0. Never "fall back to MAX(id)" here —
        // that is the killed allocator.
        assert_eq!(seq("auto"), 0);
        conn.execute("INSERT INTO auto (v) VALUES ('a')", [])
            .unwrap();
        assert_eq!(conn.last_insert_rowid(), 1);
        assert_eq!(seq("auto"), 1);
        conn.execute("INSERT INTO auto (v) VALUES ('b')", [])
            .unwrap();
        assert_eq!(seq("auto"), 2);
        conn.execute("DELETE FROM auto", []).unwrap();
        assert_eq!(seq("auto"), 2, "delete-all leaves the high-water");
        conn.execute("INSERT INTO auto (v) VALUES ('c')", [])
            .unwrap();
        assert_eq!(conn.last_insert_rowid(), 3, "no reuse");

        // The contrast that gives the change its meaning.
        conn.execute("INSERT INTO plain (v) VALUES ('a')", [])
            .unwrap();
        conn.execute("INSERT INTO plain (v) VALUES ('b')", [])
            .unwrap();
        assert_eq!(seq("plain"), 0, "a plain PK never gets a sequence row");
        conn.execute("DELETE FROM plain WHERE id = 2", []).unwrap();
        conn.execute("INSERT INTO plain (v) VALUES ('c')", [])
            .unwrap();
        assert_eq!(conn.last_insert_rowid(), 2, "a plain PK REUSES id 2");

        // DDL is transactional, which crash point 9 depends on.
        let tx = conn.unchecked_transaction().unwrap();
        tx.execute_batch("CREATE TABLE rolled_back (x INTEGER);")
            .unwrap();
        drop(tx);
        assert!(
            conn.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='rolled_back'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap()
                == 0
        );
    }

    #[test]
    fn genesis_store_is_born_with_the_epoch_marker_and_publishes_matching_facts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("genesis.db");
        let facts = initialize_genesis_store(&path).unwrap();

        // Re-measuring the file must reproduce the published facts exactly:
        // the marker and the ladder steps land BEFORE the checkpoint and the
        // read, or the owner would authenticate bytes genesis never described.
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(facts.logical_file_length, bytes.len() as u64);
        assert_eq!(
            facts.plaintext_sha256,
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );

        let conn = Connection::open(&path).unwrap();
        let marker = crate::schema_ladder::read_archive_epoch(&conn).unwrap();
        assert_eq!(marker.epoch, crate::schema_ladder::SCHEMA_EPOCH_TARGET);
        assert_eq!(
            marker.chain,
            crate::schema_ladder::chain_digest(crate::schema_ladder::SCHEMA_EPOCH_TARGET)
        );
        crate::schema_ladder::validate_servable_epoch(marker).unwrap();
        for table in ALLOCATOR_TABLES {
            let sql: String = conn
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(sql.contains("AUTOINCREMENT"), "{table} born without it");
        }
        validate_genesis_birth_witness(&conn).unwrap();
        let _validated_capability = facts.birth_witness;
    }

    #[test]
    fn genesis_birth_witness_refuses_marker_and_schema_drift() {
        let directory = tempfile::tempdir().unwrap();

        let missing_marker = directory.path().join("missing-marker.db");
        initialize_genesis_store(&missing_marker).unwrap();
        let conn = Connection::open(&missing_marker).unwrap();
        conn.execute("DELETE FROM schema_epoch", []).unwrap();
        assert!(validate_genesis_birth_witness(&conn).is_err());
        drop(conn);

        let plain_allocator = directory.path().join("plain-allocator.db");
        initialize_genesis_store(&plain_allocator).unwrap();
        let conn = Connection::open(&plain_allocator).unwrap();
        // Change only the stored canonical declaration. A token/comment
        // search could still be fooled by unrelated text; descriptor equality
        // must refuse the actual allocator declaration drift.
        conn.execute_batch(
            "PRAGMA writable_schema=ON;
             UPDATE sqlite_schema
                SET sql=replace(sql, ' PRIMARY KEY AUTOINCREMENT', ' PRIMARY KEY')
              WHERE type='table' AND name='screenshots';
             PRAGMA writable_schema=OFF;",
        )
        .unwrap();
        assert!(validate_genesis_birth_witness(&conn).is_err());
    }

    #[test]
    fn every_archive_materializing_path_seeds_the_birth_witness() {
        // Absence must have exactly ONE meaning. If any path that can produce
        // a servable archive skipped the seed, "no row" would be ambiguous
        // between "an old binary built this" and "that other path built this",
        // and the owner-open refusal would have to be softened to admit it.
        let directory = tempfile::tempdir().unwrap();

        let empty = directory.path().join("empty.db");
        std::fs::write(&empty, create_empty_db(&Dek([3_u8; 32])).unwrap()).unwrap();
        let conn = Connection::open(&empty).unwrap();
        assert_eq!(
            crate::schema_ladder::read_archive_epoch(&conn)
                .unwrap()
                .epoch,
            crate::schema_ladder::SCHEMA_EPOCH_TARGET
        );
        drop(conn);

        let owner = directory.path().join("owner.db");
        initialize_wal_owner_store_for_test(&owner).unwrap();
        let conn = Connection::open(&owner).unwrap();
        assert_eq!(
            crate::schema_ladder::read_archive_epoch(&conn)
                .unwrap()
                .epoch,
            crate::schema_ladder::SCHEMA_EPOCH_TARGET
        );
    }

    #[test]
    fn wal_owner_open_refuses_an_archive_with_no_epoch_marker() {
        // T-12b. This is the archive a rolled-back or mid-deploy binary older
        // than the re-baseline produces: plain-primary-key ids, no marker.
        // Before the latch was wired, the `WalOwnerAuthoritative` branch
        // performed NO schema comparison of any kind and served it.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("no-marker.db");
        initialize_wal_owner_store_for_test(&path).unwrap();
        assert!(open_db(&path, None, StorePersistencePolicy::WalOwnerAuthoritative).is_ok());

        // (a) The row is gone.
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM schema_epoch", []).unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(conn);
        assert!(
            open_db(&path, None, StorePersistencePolicy::WalOwnerAuthoritative).is_err(),
            "an archive with no birth witness must be refused at owner open"
        );

        // (b) The whole TABLE is gone — the literal shape a binary older than
        // this baseline produces, since it never declared `schema_epoch` at
        // all. The refusal must not depend on the table happening to exist.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DROP TABLE schema_epoch; PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(conn);
        assert!(
            open_db(&path, None, StorePersistencePolicy::WalOwnerAuthoritative).is_err(),
            "an archive with no schema_epoch table must be refused at owner open"
        );
    }

    #[test]
    fn wal_owner_open_refuses_a_marker_whose_chain_is_not_this_binarys_baseline() {
        // T-17b. `chain_digest(0) = SHA256(DOMAIN || BASELINE_DIGEST)`, so the
        // marker carries the re-baselined digest at birth and an archive born
        // under any other baseline is refused. The archive cannot certify its
        // own epoch: the comparand is recomputed from this binary.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("foreign-chain.db");
        initialize_wal_owner_store_for_test(&path).unwrap();

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE schema_epoch SET chain_digest = ?1 WHERE singleton = 1",
            [&[0xab_u8; 32][..]],
        )
        .unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(conn);

        assert!(
            open_db(&path, None, StorePersistencePolicy::WalOwnerAuthoritative).is_err(),
            "a marker whose chain is not this binary's baseline must be refused"
        );
    }

    #[test]
    fn wal_logical_only_immutable_open_never_creates_sqlite_sidecars() {
        let dek = Dek([8_u8; 32]);
        let current = create_empty_db(&dek).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let current_path = directory.path().join("current.db");
        std::fs::write(&current_path, &current).unwrap();
        assert!(!sqlite_sidecar_path(&current_path, "-wal").exists());
        assert!(!sqlite_sidecar_path(&current_path, "-shm").exists());
        let (connection, registration, migrated) =
            open_db(&current_path, None, StorePersistencePolicy::WalLogicalOnly).unwrap();
        assert!(registration.is_none());
        assert!(!migrated);
        assert!(current_path.exists());
        assert!(!sqlite_sidecar_path(&current_path, "-wal").exists());
        assert!(!sqlite_sidecar_path(&current_path, "-shm").exists());
        drop(connection);

        let stale_path = directory.path().join("stale.db");
        std::fs::write(&stale_path, current).unwrap();
        let stale = Connection::open(&stale_path).unwrap();
        stale.execute_batch("DROP TABLE email_deliveries;").unwrap();
        stale
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(stale);
        let _ = std::fs::remove_file(sqlite_sidecar_path(&stale_path, "-wal"));
        let _ = std::fs::remove_file(sqlite_sidecar_path(&stale_path, "-shm"));
        assert!(!sqlite_sidecar_path(&stale_path, "-wal").exists());
        assert!(!sqlite_sidecar_path(&stale_path, "-shm").exists());
        assert!(open_db(&stale_path, None, StorePersistencePolicy::WalLogicalOnly,).is_err());
        assert!(stale_path.exists());
        assert!(!sqlite_sidecar_path(&stale_path, "-wal").exists());
        assert!(!sqlite_sidecar_path(&stale_path, "-shm").exists());
    }

    #[test]
    fn genesis_store_is_checkpointed_sidecar_free_and_self_describing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("genesis.db");
        let facts = initialize_genesis_store(&path).unwrap();

        // The published facts must describe the bytes on disk exactly: the WAL
        // owner authenticates a database by length, user_version and plaintext
        // SHA-256, so a genesis archive whose facts disagree is unopenable
        // from birth.
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(facts.logical_file_length, bytes.len() as u64);
        assert_eq!(
            facts.plaintext_sha256,
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        assert!(facts.logical_file_length > 0);

        // No residual -wal/-shm: committed pages left outside the measured
        // file are exactly how the length and hash would drift.
        assert!(ensure_no_sqlite_sidecars(&path).is_ok());
        assert!(validate_checkpointed_sqlite_file(&path).is_ok());

        // Schema-current: the same version the legacy path produces, so a
        // genesis archive is not born already needing a migration.
        let legacy = dir.path().join("legacy.db");
        let expected_version = initialize_wal_owner_store_for_test(&legacy).unwrap();
        assert_eq!(facts.user_version, expected_version);

        // The product schema really is present, not an empty file.
        let conn = Connection::open(&path).unwrap();
        let episodes: i64 = conn
            .query_row("SELECT count(*) FROM episodes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(episodes, 0);

        // Deterministic: two genesis databases agree on length and version.
        // (The byte hash may legitimately differ if SQLite embeds any
        // nondeterminism; assert the contract we actually depend on.)
        let second = dir.path().join("genesis2.db");
        let again = initialize_genesis_store(&second).unwrap();
        assert_eq!(again.user_version, facts.user_version);
        assert_eq!(again.logical_file_length, facts.logical_file_length);
    }

    #[tokio::test]
    async fn wal_authoritative_rebind_freezes_the_frozen_snapshot_without_flushing() {
        let gcs = Arc::new(FakeGcs::new());
        seed_current_user_object(&gcs, "rebind-selected-old");
        let store = Arc::new(Store::new(Arc::new(FakeKms), gcs.clone()));
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    "rebind-selected-old",
                    crate::archive_v3::ArchiveId::from_bytes([0x71; 16]),
                ),
            )
            .unwrap();

        let mut transition = store
            .begin_identity_rebind("rebind-selected-old", "rebind-selected-new")
            .await
            .unwrap();
        let snapshot = transition.source_snapshot().await.unwrap();
        let puts_before = gcs.put_attempts();

        // The legacy snapshot of a selected user is frozen and
        // non-authoritative: every legacy writer is refused, so there is no
        // in-flight writer for the generation-CAS bump to race. Before this
        // branch existed the forced bump made the flush refuse with a `Store`
        // error — not the `Conflict` the recovery path expects — so the
        // transition was dropped without `complete()` and BOTH identities
        // stayed fenced, telling a live user their account was deleted.
        let frozen = transition
            .freeze_source(
                snapshot.base_generation,
                &snapshot.commitment,
                &test_rebind_authority(9),
            )
            .await
            .expect("a selected user's rebind must freeze without flushing");
        assert_eq!(frozen.commitment, snapshot.commitment);
        assert!(frozen.source_generation > 0);
        // No provider write happened: the frozen snapshot was not re-uploaded.
        assert_eq!(gcs.put_attempts(), puts_before);
    }

    #[tokio::test]
    async fn wal_authority_selection_applies_per_user_and_leaves_legacy_users_untouched() {
        let gcs = Arc::new(FakeGcs::new());
        seed_current_user_object(&gcs, "wal-selected");
        seed_current_user_object(&gcs, "legacy-neighbor");
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    "wal-selected",
                    crate::archive_v3::ArchiveId::from_bytes([0x5e; 16]),
                ),
            )
            .unwrap();

        // The selected user's legacy blob never loads again: every
        // legacy-path read refuses outright (never the stale snapshot),
        // mutation closures never run, saves are provider-silent no-ops, and
        // the routed read reports the authority as missing rather than
        // falling back.
        let puts_before = gcs.put_attempts();
        let read_ran = Arc::new(AtomicBool::new(false));
        let read_ran_in_closure = Arc::clone(&read_ran);
        assert!(store
            .with_user("wal-selected", move |_| {
                read_ran_in_closure.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .is_err());
        assert!(!read_ran.load(Ordering::SeqCst));
        assert!(store
            .with_user_read("wal-selected", |_| Ok(()))
            .await
            .is_err());
        let mut_ran = Arc::new(AtomicBool::new(false));
        let mut_ran_in_closure = Arc::clone(&mut_ran);
        assert!(store
            .with_user_mut("wal-selected", move |_| {
                mut_ran_in_closure.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .is_err());
        assert!(!mut_ran.load(Ordering::SeqCst));
        assert!(store
            .with_user_if_changed("wal-selected", |_| Ok(((), true)))
            .await
            .is_err());
        assert!(store
            .wal_authoritative_read("wal-selected", |_| Ok(()))
            .await
            .is_err());
        store.save_user("wal-selected").await.unwrap();
        assert_eq!(gcs.put_attempts(), puts_before);

        // The unselected neighbor keeps every legacy snapshot capability
        // through the very same Store instance.
        store
            .with_user("legacy-neighbor", |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at) VALUES (?1)",
                    ["2026-08-19T12:00:01Z"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        // The dual-path routed read serves unselected users through the
        // ordinary guarded legacy path.
        let counted: i64 = store
            .wal_authoritative_read("legacy-neighbor", |conn| {
                Ok(conn.query_row("SELECT count(*) FROM screenshots", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(counted, 1);
        store.save_user("legacy-neighbor").await.unwrap();
        assert_eq!(gcs.put_attempts(), puts_before + 1);
    }

    #[tokio::test]
    async fn wal_authority_selection_refuses_every_legacy_load_before_provider_access() {
        let gcs = Arc::new(FakeGcs::new());
        seed_current_user_object(&gcs, "wal-seeded-selected");
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    "wal-seeded-selected",
                    crate::archive_v3::ArchiveId::from_bytes([0x5f; 16]),
                ),
            )
            .unwrap();
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    "wal-missing-selected",
                    crate::archive_v3::ArchiveId::from_bytes([0x60; 16]),
                ),
            )
            .unwrap();

        // Selected users refuse before any KMS wrap, temp file, or provider
        // access — whether their legacy object exists (stale snapshot) or
        // not (no reviewed WAL genesis): the legacy path never opens.
        let puts_before = gcs.put_attempts();
        assert!(store
            .with_user_read("wal-seeded-selected", |_| Ok(()))
            .await
            .is_err());
        assert!(store
            .with_user_read("wal-missing-selected", |_| Ok(()))
            .await
            .is_err());
        assert!(store
            .wal_authoritative_read("wal-missing-selected", |_| Ok(()))
            .await
            .is_err());
        assert_eq!(gcs.put_attempts(), puts_before);
        // Saving a selected user is a provider-silent no-op: nothing legacy
        // ever loaded, and nothing may ever persist.
        store.save_user("wal-seeded-selected").await.unwrap();
        assert_eq!(gcs.put_attempts(), puts_before);
    }

    /// The exact-name requirement must actually bite: a frozen media
    /// inventory that names an object outside the account's own namespaces is
    /// refused *before* any destructive provider call.
    ///
    /// This is the blast-radius bound for the media lane, standing in for the
    /// archive-prefix check the deletion driver applies to its own entries. A
    /// prefix-only design cannot supply it, which is precisely why media —
    /// whose keys live outside the archive prefix — gets its own exact-name
    /// lane rather than being smuggled into the driver's inventory.
    #[tokio::test]
    async fn a_foreign_media_key_is_refused_before_any_provider_deletion() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        for (name, body) in [
            ("raw/victim/keep.enc", &b"victim"[..]),
            ("raw/other-account/keep.enc", &b"other"[..]),
            ("indexes/other-account.db.enc", &b"index"[..]),
        ] {
            gcs.put_object(name, body, "wrapped", 0).await.unwrap();
        }

        for foreign in [
            "raw/other-account/keep.enc".to_string(),
            "indexes/other-account.db.enc".to_string(),
            "media/other-account/keep.enc".to_string(),
            // A prefix-shaped near-miss: `raw/victim-other/` shares the
            // account's name as a string prefix but is a different account.
            "raw/victim-other/keep.enc".to_string(),
            String::new(),
        ] {
            let error = store
                .delete_wal_authoritative_media(
                    "victim",
                    &["raw/victim/keep.enc".to_string(), foreign.clone()],
                )
                .await
                .expect_err("a key outside the account must be refused");
            assert!(
                matches!(error, EnclaveError::Store(ref message)
                    if message.contains("outside the account")),
                "unexpected error for {foreign:?}: {error:?}"
            );
        }

        // Nothing was deleted: the refusal precedes every provider call, so
        // even the account's own legitimate key survives the refused batch.
        assert_eq!(gcs.version_count("raw/victim/"), 1);
        assert_eq!(gcs.version_count("raw/other-account/"), 1);
        assert_eq!(gcs.version_count("indexes/other-account.db.enc"), 1);
    }

    /// The account's own frozen names are erased across every generation, and
    /// completion is only reported once each one is proven absent.
    #[tokio::test]
    async fn frozen_media_names_are_erased_and_proven_absent() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        for name in [
            "raw/subject/live.enc",
            "raw/subject/pruned.enc",
            "media/subject/legacy.enc",
        ] {
            let created = gcs.put_object(name, b"first", "wrapped", 0).await.unwrap();
            gcs.put_object(name, b"second", "wrapped", created)
                .await
                .unwrap();
        }
        gcs.put_object("raw/bystander/keep.enc", b"keep", "wrapped", 0)
            .await
            .unwrap();

        store
            .delete_wal_authoritative_media(
                "subject",
                &[
                    "raw/subject/live.enc".to_string(),
                    "raw/subject/pruned.enc".to_string(),
                    "media/subject/legacy.enc".to_string(),
                ],
            )
            .await
            .expect("every frozen name is erasable");

        assert_eq!(gcs.version_count("raw/subject/"), 0);
        assert_eq!(gcs.version_count("media/subject/"), 0);
        assert_eq!(gcs.version_count("raw/bystander/"), 1);
    }

    /// The deletion inventory must keep rows the live-media query hides. A
    /// pruner that crashed between the provider delete and the row update
    /// leaves exactly these, and reporting completion on the filtered set
    /// would be a false completion.
    #[test]
    fn the_deletion_media_inventory_keeps_pruned_and_soft_deleted_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE screenshot_images (object_key TEXT);
             CREATE TABLE media_objects (object_key TEXT, deleted_at TEXT, processing_state TEXT);
             INSERT INTO screenshot_images VALUES ('raw/u/shot.enc');
             INSERT INTO media_objects VALUES ('raw/u/live.enc', NULL, 'ready');
             INSERT INTO media_objects VALUES ('raw/u/pruned.enc', NULL, 'pruned');
             INSERT INTO media_objects VALUES ('raw/u/deleted.enc', '2026-01-01', 'ready');",
        )
        .unwrap();
        assert_eq!(
            media_keys(&conn).unwrap(),
            vec!["raw/u/live.enc".to_string(), "raw/u/shot.enc".to_string()],
            "the live query hides pruned and soft-deleted rows"
        );
        assert_eq!(
            deletion_media_keys(&conn).unwrap(),
            vec![
                "raw/u/deleted.enc".to_string(),
                "raw/u/live.enc".to_string(),
                "raw/u/pruned.enc".to_string(),
                "raw/u/shot.enc".to_string(),
            ],
            "the deletion query must name everything that was ever recorded"
        );
    }

    // ── Group C: in-process WAL serving relaunch ────────────────────────────

    const RELAUNCH_ARCHIVE: [u8; 16] = [0x7c; 16];
    const RELAUNCH_USER: &str = "relaunch-subject";

    /// What the driver answers with. The driver is the ONLY construction path
    /// a slot replacement may use, so a test double here is a test double for
    /// the entire launch ladder.
    #[derive(Clone, Copy)]
    enum FakeRebuild {
        Terminal,
        Live,
        Fail,
        OtherArchive,
    }

    struct CountingRelaunch {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        answer: FakeRebuild,
    }

    impl CountingRelaunch {
        fn new(answer: FakeRebuild) -> Arc<Self> {
            Arc::new(Self {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                answer,
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::Acquire)
        }
    }

    #[async_trait::async_trait]
    impl WalServingRelaunch for CountingRelaunch {
        async fn rebuild(
            &self,
            _user_id: &str,
        ) -> Result<(
            [u8; 16],
            Arc<crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority>,
        )> {
            self.calls.fetch_add(1, AtomicOrdering::AcqRel);
            match self.answer {
                FakeRebuild::Fail => Err(EnclaveError::Store("rebuild refused".into())),
                FakeRebuild::Live => Ok((
                    RELAUNCH_ARCHIVE,
                    Arc::new(
                        crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::live_for_relaunch_test(),
                    ),
                )),
                FakeRebuild::Terminal => Ok((
                    RELAUNCH_ARCHIVE,
                    Arc::new(
                        crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::terminal_for_relaunch_test()
                            .await,
                    ),
                )),
                FakeRebuild::OtherArchive => Ok((
                    [0x0d; 16],
                    Arc::new(
                        crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::live_for_relaunch_test(),
                    ),
                )),
            }
        }
    }

    fn relaunch_store() -> Arc<Store> {
        let store = Arc::new(Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new())));
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    RELAUNCH_USER,
                    crate::archive_v3::ArchiveId::from_bytes(RELAUNCH_ARCHIVE),
                ),
            )
            .unwrap();
        store
    }

    /// Wait for the slot's authority to publish its termination flag. The
    /// actor future is spawned, so "terminal" is observable only after it has
    /// been polled to completion at least once.
    async fn await_terminal_slot(lane: &WalServingLane) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !lane.is_terminal_for_test() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the slot's authority never became terminal");
    }

    async fn install_terminal_slot(store: &Store) {
        store
            .install_wal_serving_authority(
                RELAUNCH_USER,
                RELAUNCH_ARCHIVE,
                Arc::new(
                    crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::terminal_for_relaunch_test()
                        .await,
                ),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn construction_never_begins_before_proof_of_death() {
        // A wedged blocking lane still holds the writable SQLite connection
        // and the capture registration. `is_terminal()` alone would let a
        // successor be constructed over it — two live owners believing they
        // hold the same archive. The driver must refuse instead.
        let store = relaunch_store();
        let (stuck, release) =
            crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::stuck_for_relaunch_test(
            );
        store
            .install_wal_serving_authority(RELAUNCH_USER, RELAUNCH_ARCHIVE, Arc::new(stuck))
            .unwrap();
        let driver = CountingRelaunch::new(FakeRebuild::Live);
        store
            .install_wal_serving_relaunch(Arc::clone(&driver) as Arc<dyn WalServingRelaunch>)
            .unwrap();
        let lane = store.wal_serving_lane(RELAUNCH_USER).unwrap();
        await_terminal_slot(&lane).await;
        assert!(lane.is_terminal_for_test(), "the actor future is over");

        let outcome = store
            .recover_wal_serving_authority(RELAUNCH_USER)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            WalRecoveryOutcome::Quarantined(WalQuarantineReason::Stuck)
        );
        assert_eq!(
            driver.calls(),
            0,
            "nothing may be constructed without proof of death"
        );
        assert_eq!(lane.generation_for_test(), 0);
        // Quarantine is terminal for this process: it does not retry itself
        // back into a race once the lane finally leaves.
        release.release();
        assert_eq!(
            store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap(),
            WalRecoveryOutcome::Quarantined(WalQuarantineReason::Stuck)
        );
        assert_eq!(driver.calls(), 0);
        let health = store.wal_serving_health();
        assert_eq!(health.quarantined, 1);
        assert_eq!(health.quarantines_total, 1, "quarantine is an event");
        assert_eq!(health.relaunches_total, 0);
    }

    #[tokio::test]
    async fn a_proven_dead_authority_is_replaced_in_place_and_never_removed() {
        let store = relaunch_store();
        install_terminal_slot(&store).await;
        let driver = CountingRelaunch::new(FakeRebuild::Live);
        store
            .install_wal_serving_relaunch(Arc::clone(&driver) as Arc<dyn WalServingRelaunch>)
            .unwrap();
        let lane = store.wal_serving_lane(RELAUNCH_USER).unwrap();
        let stale = lane.authority_for_test();

        assert_eq!(
            store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap(),
            WalRecoveryOutcome::Replaced
        );
        assert_eq!(driver.calls(), 1);
        assert_eq!(lane.generation_for_test(), 1);
        assert!(!lane.is_terminal_for_test());

        // The slot is the same slot: replaced, never removed. There is no
        // instant at which a registered user has no authority.
        assert!(store.has_wal_serving_authority(RELAUNCH_USER));
        assert!(Arc::ptr_eq(
            &lane,
            &store.wal_serving_lane(RELAUNCH_USER).unwrap()
        ));

        // A stale clone of the previous authority can never write again: its
        // actor future is over, so the only thing a surviving clone can do is
        // enqueue onto a channel whose receiver died with the future.
        assert!(!Arc::ptr_eq(&stale, &lane.authority_for_test()));
        assert!(stale.read(|_| Ok(())).await.is_err());

        // A second call finds the slot live and issues no launch.
        assert_eq!(
            store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap(),
            WalRecoveryOutcome::AlreadyLive
        );
        assert_eq!(driver.calls(), 1);

        let health = store.wal_serving_health();
        assert_eq!(health.serving, 1);
        assert_eq!(health.terminal, 0);
        assert_eq!(health.relaunches_total, 1, "a heal is an event");
    }

    #[tokio::test]
    async fn a_successor_for_a_different_archive_is_refused_not_swapped_in() {
        let store = relaunch_store();
        install_terminal_slot(&store).await;
        let driver = CountingRelaunch::new(FakeRebuild::OtherArchive);
        store
            .install_wal_serving_relaunch(Arc::clone(&driver) as Arc<dyn WalServingRelaunch>)
            .unwrap();
        let lane = store.wal_serving_lane(RELAUNCH_USER).unwrap();
        assert_eq!(
            store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap(),
            WalRecoveryOutcome::Quarantined(WalQuarantineReason::ArchiveMismatch)
        );
        assert_eq!(lane.generation_for_test(), 0);
        assert!(lane.is_terminal_for_test(), "the slot kept its own archive");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn thirty_two_concurrent_callers_launch_exactly_once() {
        let store = relaunch_store();
        install_terminal_slot(&store).await;
        let driver = CountingRelaunch::new(FakeRebuild::Live);
        store
            .install_wal_serving_relaunch(Arc::clone(&driver) as Arc<dyn WalServingRelaunch>)
            .unwrap();
        let mut callers = Vec::new();
        for _ in 0..32 {
            let store = Arc::clone(&store);
            callers.push(tokio::spawn(async move {
                store.recover_wal_serving_authority(RELAUNCH_USER).await
            }));
        }
        let mut replaced = 0;
        let mut already_live = 0;
        for caller in callers {
            match caller.await.unwrap().unwrap() {
                WalRecoveryOutcome::Replaced => replaced += 1,
                WalRecoveryOutcome::AlreadyLive => already_live += 1,
                other => panic!("unexpected concurrent outcome {other:?}"),
            }
        }
        assert_eq!(replaced, 1, "single-flight: exactly one launch");
        assert_eq!(already_live, 31);
        assert_eq!(driver.calls(), 1, "no thundering herd");
        assert_eq!(
            store
                .wal_serving_lane(RELAUNCH_USER)
                .unwrap()
                .generation_for_test(),
            1
        );
    }

    /// A successful heal ENDS the incident, so a later fault gets the full
    /// wall budget again — but the generation count stays cumulative.
    ///
    /// The wall deadline bounds ONE healing incident. Measuring it from the
    /// process's first-ever relaunch instead made the driver disarm itself:
    /// a second, independent fault more than `WAL_RELAUNCH_WALL_DEADLINE`
    /// later was quarantined `DeadlineExceeded` with ZERO rebuild attempts,
    /// degrading the lane to exactly the permanent outage this driver exists
    /// to end. In a long-lived enclave that made self-heal a
    /// fifteen-minutes-after-the-first-fault feature.
    ///
    /// The other half is just as load-bearing in the opposite direction:
    /// `installed_generations` must NOT reset. Control bumps an operation's
    /// durable attempt each time it observes a new `owner_instance_id`, so a
    /// long-pending operation accrues one attempt per successful generation.
    /// Only a cumulative count keeps `MAX_WAL_SERVING_GENERATIONS` strictly
    /// under `MAX_WAL_OWNER_ATTEMPTS`; resetting it would let repeated heals
    /// cross the durable cap and turn a transient fault into restart-proof
    /// write-death. So this test pins BOTH: the clock resets, the budget does
    /// not.
    #[tokio::test(start_paused = true)]
    async fn a_later_incident_gets_a_fresh_wall_budget_but_not_a_fresh_generation_budget() {
        let store = relaunch_store();
        install_terminal_slot(&store).await;
        // Terminal rebuilds hand back a successor that is itself terminal, so
        // a second incident is reachable without any extra machinery.
        let driver = CountingRelaunch::new(FakeRebuild::Terminal);
        store
            .install_wal_serving_relaunch(Arc::clone(&driver) as Arc<dyn WalServingRelaunch>)
            .unwrap();
        let lane = store.wal_serving_lane(RELAUNCH_USER).unwrap();

        // Incident 1 heals.
        assert_eq!(
            store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap(),
            WalRecoveryOutcome::Replaced
        );
        assert_eq!(lane.relaunches_total.load(AtomicOrdering::Acquire), 1);

        // ...and the enclave serves for longer than one healing budget.
        tokio::time::advance(WAL_RELAUNCH_WALL_DEADLINE + Duration::from_secs(60)).await;

        // Incident 2 must still get its own budget.
        let outcome = store
            .recover_wal_serving_authority(RELAUNCH_USER)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            WalRecoveryOutcome::Replaced,
            "a later independent fault must heal, not inherit the first \
             incident's expired wall deadline"
        );
        assert_eq!(
            store.wal_serving_health().quarantined,
            0,
            "the lane must not be quarantined by a deadline it never spent"
        );
        assert_eq!(driver.calls(), 2);

        // The generation budget, by contrast, is cumulative across incidents.
        assert_eq!(
            lane.relaunches_total.load(AtomicOrdering::Acquire),
            2,
            "generations must accumulate across incidents; resetting them \
             would let repeated heals cross the durable attempt cap"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_driver_backs_off_without_consuming_the_generation_budget() {
        // A failed build minted no lane and therefore no new owner instance
        // id, so it burned no durable attempt. Charging it to the generation
        // budget would let a provider outage exhaust the budget long before
        // the wall deadline — which is sized to outlast the owner lease — can
        // be reached, converting a transient outage into a new permanent
        // terminal.
        let store = relaunch_store();
        install_terminal_slot(&store).await;
        let driver = CountingRelaunch::new(FakeRebuild::Fail);
        store
            .install_wal_serving_relaunch(Arc::clone(&driver) as Arc<dyn WalServingRelaunch>)
            .unwrap();
        let lane = store.wal_serving_lane(RELAUNCH_USER).unwrap();

        assert_eq!(
            store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap(),
            WalRecoveryOutcome::Backoff
        );
        assert_eq!(driver.calls(), 1);
        // Immediately again: the backoff refuses without touching the driver.
        assert_eq!(
            store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap(),
            WalRecoveryOutcome::Backoff
        );
        assert_eq!(driver.calls(), 1, "backoff must not re-enter the driver");

        // Keep failing across the wall deadline. Generations stay at zero and
        // the lane finally quarantines on the deadline, not on the budget.
        let mut attempts = 1;
        for _ in 0..64 {
            tokio::time::advance(Duration::from_secs(120)).await;
            match store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap()
            {
                WalRecoveryOutcome::Backoff => attempts += 1,
                WalRecoveryOutcome::Quarantined(reason) => {
                    assert_eq!(reason, WalQuarantineReason::DeadlineExceeded);
                    break;
                }
                other => panic!("unexpected outcome {other:?}"),
            }
        }
        let (generations, failures, state) = lane.ledger_for_test().await;
        assert_eq!(generations, 0, "failed launches never consume generations");
        assert!(failures >= 2, "launch failures accumulate: {failures}");
        assert_eq!(
            state,
            WalLaneState::Quarantined(WalQuarantineReason::DeadlineExceeded)
        );
        assert!(attempts > 1);
        let health = store.wal_serving_health();
        assert_eq!(health.quarantined, 1);
        assert_eq!(health.relaunches_total, 0);
        assert_eq!(health.launch_failures_total, u64::from(failures));
    }

    #[tokio::test(start_paused = true)]
    async fn the_generation_budget_bounds_a_corruption_heal_loop_and_stays_visible() {
        // A genuinely corrupt archive that dies every generation must NOT heal
        // forever in silence. It is bounded by the generation budget, and
        // every generation is an observable event.
        let store = relaunch_store();
        install_terminal_slot(&store).await;
        let driver = CountingRelaunch::new(FakeRebuild::Terminal);
        store
            .install_wal_serving_relaunch(Arc::clone(&driver) as Arc<dyn WalServingRelaunch>)
            .unwrap();
        let lane = store.wal_serving_lane(RELAUNCH_USER).unwrap();
        let budget = crate::archive_v3_wal_owner::MAX_WAL_SERVING_GENERATIONS;
        for generation in 1..=budget {
            assert_eq!(
                store
                    .recover_wal_serving_authority(RELAUNCH_USER)
                    .await
                    .unwrap(),
                WalRecoveryOutcome::Replaced,
                "generation {generation}"
            );
            assert_eq!(lane.generation_for_test(), u64::from(generation));
        }
        assert_eq!(
            store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap(),
            WalRecoveryOutcome::Quarantined(WalQuarantineReason::GenerationsExhausted)
        );
        assert_eq!(driver.calls() as u32, budget);
        let health = store.wal_serving_health();
        assert_eq!(
            health.relaunches_total,
            u64::from(budget),
            "a heal loop under budget must be visible as events, not as a \
             steady `serving` count"
        );
        assert_eq!(health.quarantines_total, 1);
    }

    #[tokio::test]
    async fn a_terminal_slot_without_a_driver_keeps_refusing_exactly_as_today() {
        // Poison must remain a real, reachable, fail-closed state. Without a
        // driver installed — every test and every image that does not install
        // one — a terminal slot stays terminal and the routed read refuses.
        let store = relaunch_store();
        install_terminal_slot(&store).await;
        assert_eq!(
            store
                .recover_wal_serving_authority(RELAUNCH_USER)
                .await
                .unwrap(),
            WalRecoveryOutcome::Backoff
        );
        let refused = store
            .wal_authoritative_read(RELAUNCH_USER, |_| Ok(()))
            .await;
        assert!(
            matches!(refused, Err(EnclaveError::Store(_))),
            "a terminal slot must fail closed: {refused:?}"
        );
        assert!(store
            .wal_serving_lane(RELAUNCH_USER)
            .unwrap()
            .is_terminal_for_test());
    }

    #[tokio::test]
    async fn a_routed_read_heals_before_the_call_and_a_submit_is_never_auto_retried() {
        let store = relaunch_store();
        install_terminal_slot(&store).await;
        let driver = CountingRelaunch::new(FakeRebuild::Live);
        store
            .install_wal_serving_relaunch(Arc::clone(&driver) as Arc<dyn WalServingRelaunch>)
            .unwrap();
        // The routed read heals the slot before issuing its closure. The fake
        // successor refuses every call, so the read still errors — the point
        // is that the slot was replaced, in-process, without a restart.
        let _ = store
            .wal_authoritative_read(RELAUNCH_USER, |_| Ok(()))
            .await;
        assert_eq!(driver.calls(), 1, "heal-before-call ran");
        assert_eq!(
            store
                .wal_serving_lane(RELAUNCH_USER)
                .unwrap()
                .generation_for_test(),
            1
        );
        // A second read finds the slot live and does not relaunch again.
        let _ = store
            .wal_authoritative_read(RELAUNCH_USER, |_| Ok(()))
            .await;
        assert_eq!(driver.calls(), 1);
    }

    #[test]
    fn the_wal_owner_capture_vfs_installs_once_per_process() {
        // `MAX_CAPTURE_VFS_INSTALLATIONS` is a process-lifetime global and
        // every install deliberately leaks its bounded callback allocation.
        // Installing per launch was harmless while startup was the only
        // launcher; with an in-process relaunch it hard-fails after the
        // ceiling and makes VFS name resolution order-dependent before then.
        let publisher = include_str!("archive_v3_wal_owner/publisher.rs");
        let production = &publisher[..publisher
            .find(concat!("mod ", "tests"))
            .unwrap_or(publisher.len())];
        assert!(
            production.contains("StoreShadowCapture::shared_for_wal_owner()"),
            "the WAL owner must use the shared capture singleton"
        );
        assert!(
            !production.contains(concat!("StoreShadowCapture::install", "(")),
            "the WAL owner must not install a VFS per launch"
        );
        // Non-vacuous: with a per-call install this loop hard-fails on the
        // ninth iteration with TooManyInstallations.
        let first = StoreShadowCapture::shared_for_wal_owner().unwrap();
        for _ in 0..32 {
            let again = StoreShadowCapture::shared_for_wal_owner().unwrap();
            assert!(
                Arc::ptr_eq(&first, &again),
                "every WAL-owner launch must share one installation"
            );
        }
    }

    #[test]
    fn the_serving_slot_is_replaceable_and_never_removable() {
        // Every clause below is a predicate, gate, or failure handler this
        // change is forbidden to relax. Pinned by source string so softening
        // one is a test failure, not a review miss.
        let source = include_str!("store.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        for required in [
            // The SERVING read poisons on unsettled state. The fix stops that
            // state from being reached; it never makes this guard quieter.
            "        if registration.completed_len() != 0 {\n\
             \x20           self.poison();\n\
             \x20           return Err(WalOwnerError::Corrupt);\n\
             \x20       }",
            // The pre-admission LOOKUP degrades instead. The asymmetry is
            // deliberate: a lookup that declines to consult unsettled state is
            // conservative; a serving read that skipped a retained commit
            // would be serving a lie.
            "        if registration.completed_len() != 0 {\n\
             \x20           return Ok(WalStoreReplay::Absent(prepared));\n\
             \x20       }",
            // `refresh_lease_binding` and `take_checkpoint_source` poison on
            // unsettled state, and `take_checkpoint_source` only succeeds when
            // the capture is empty — which is why a checkpoint-arm relaunch is
            // provably lossless.
            "                .completed_len()\n\
             \x20               != 0\n\
             \x20       {\n\
             \x20           self.poison();\n\
             \x20           return Err(WalOwnerError::Conflict);",
            // `advance_binding`'s exact-successor conjunction.
            "            || next.root().sequence()\n\
             \x20               != self\n\
             \x20                   .binding\n\
             \x20                   .root()\n\
             \x20                   .sequence()\n\
             \x20                   .checked_add(1)",
            // Install-once, no removal.
            "\"wal serving authority already registered\"",
            "\"wal serving authority requires the durable-terminal selection\"",
            // Proof of death precedes construction, and a timeout quarantines.
            "join_terminated(WAL_RELAUNCH_JOIN_DEADLINE)",
            "WalQuarantineReason::Stuck",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
        for forbidden in [
            concat!("fn remove_wal_serving_", "authority"),
            concat!("fn take_wal_serving_", "authority"),
            // The live-lease same-owner heartbeat must never be pulled into a
            // launch ladder; using it there would delete the cross-process
            // fence entirely.
            concat!("maintain_owner_", "lease"),
            concat!("maintain_exact_wal_owner_", "lease"),
        ] {
            assert!(
                !production.contains(forbidden),
                "found forbidden {forbidden}"
            );
        }
        // No removal may ever be reached through the serving registry.
        for (offset, _) in production.match_indices(".remove(") {
            let back = production[..offset]
                .char_indices()
                .rev()
                .nth(200)
                .map_or(0, |(index, _)| index);
            assert!(
                !production[back..offset].contains("wal_serving_authorities"),
                "the serving registry gained a removal: {}",
                &production[back..offset + 32]
            );
        }
        // Exactly one writer of the slot, and it is inside the driver.
        let writes: Vec<usize> = production
            .match_indices(".current\n                .write()")
            .map(|(offset, _)| offset)
            .collect();
        assert_eq!(writes.len(), 1, "the slot has more than one writer");
        let driver = production
            .find("pub(crate) async fn recover_wal_serving_authority(")
            .expect("the driver moved");
        let driver_end = production[driver..]
            .find("\n    fn quarantine(")
            .expect("the driver's end moved")
            + driver;
        assert!(
            (driver..driver_end).contains(&writes[0]),
            "the only slot write must live inside recover_wal_serving_authority"
        );
    }

    #[test]
    fn wal_relaunch_wall_deadline_outlasts_the_owner_lease() {
        // The Class-1 relaunch is refused by the witness lease predicates
        // until the lane's own lease lapses. The heal budget is sized against
        // that constant, so a change to it must be a deliberate, visible one.
        let publisher = include_str!("archive_v3_wal_owner/publisher.rs");
        assert!(
            publisher.contains(&format!(
                "const OWNER_LEASE_TICKS: u64 = {WAL_OWNER_LEASE_TICKS_MIRROR};"
            )),
            "the owner lease the relaunch budget is sized against changed"
        );
        assert!(WAL_RELAUNCH_WALL_DEADLINE.as_secs() >= WAL_OWNER_LEASE_TICKS_MIRROR * 3);
    }

    #[tokio::test]
    async fn wal_authority_selection_installs_once_per_user_and_refuses_archive_changes() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        let first = crate::archive_v3::ArchiveId::from_bytes([0x61; 16]);
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    "selected-once",
                    first,
                ),
            )
            .unwrap();
        // Identical re-install is idempotent; a different archive conflicts.
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    "selected-once",
                    first,
                ),
            )
            .unwrap();
        assert!(matches!(
            store.install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    "selected-once",
                    crate::archive_v3::ArchiveId::from_bytes([0x62; 16]),
                ),
            ),
            Err(EnclaveError::Conflict(_))
        ));
        // A second user selects independently of the first.
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    "selected-second",
                    crate::archive_v3::ArchiveId::from_bytes([0x63; 16]),
                ),
            )
            .unwrap();
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
                let push_present: i64 = conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='push_deliveries'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(push_present, 1);
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

        store.save_user("lost-put-success").await.unwrap();
        let object_name = gcs_object_name("lost-put-success");
        assert_eq!(gcs.generation(&object_name), Some(1));

        // The same owned attempt accepts the committed generation only after
        // exact ciphertext and wrapped-key reconciliation.
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
            &[(object_name.clone(), 0)]
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
        *gcs.corrupt_wrapped_dek_after_commit_failure.lock().unwrap() =
            Some(B64.encode([9_u8; 32]));
        assert!(store.save_user("lost-put-dek-mismatch").await.is_err());

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
        Store::new_internal_with_max_open(kms, gcs, Arc::clone(&media_gcs), media_gcs, max_open)
    }

    #[tokio::test]
    async fn exact_user_shadow_capture_excludes_others_and_retires_on_eviction_and_deletion() {
        let ordinary = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        assert!(ordinary.shadow_capture.read().unwrap().is_none());

        let capture = StoreShadowCapture::shared_for_test();
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new_internal_with_max_open_and_shadow_capture(
            Arc::new(FakeKms),
            gcs.clone(),
            gcs.clone(),
            gcs,
            1,
            Some(StoreShadowCaptureSelection::for_test(
                "capture-lifetime",
                Arc::clone(&capture),
            )),
        );
        store
            .with_user("capture-lifetime", |connection| {
                connection.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES (?1, ?2)",
                    ["2026-08-13T12:00:00Z", "first"],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let actor = match store.actor_for_existing("capture-lifetime").await.unwrap() {
            SaveTarget::Actor(actor) => actor,
            SaveTarget::AlreadyFlushed => panic!("capture handle unexpectedly evicted"),
        };
        let first_stream = {
            let state = actor.state.lock().await;
            let registration = state
                .handle
                .as_ref()
                .unwrap()
                ._shadow_capture_registration
                .as_ref()
                .unwrap();
            let stream = registration.stream_id();
            let first = registration
                .begin_drain(
                    crate::archive_v3_shadow_session::ShadowSessionId::from_bytes([31; 16]),
                    crate::archive_v3_shadow_session::ShadowAttemptId::from_bytes([32; 16]),
                )
                .unwrap()
                .commit()
                .unwrap();
            assert_eq!(first.stream_id(), stream);
            assert!(!first.commits().is_empty());
            stream
        };

        store
            .with_user("capture-lifetime", |connection| {
                connection.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES (?1, ?2)",
                    ["2026-08-13T12:01:00Z", "second"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        {
            let state = actor.state.lock().await;
            let registration = state
                .handle
                .as_ref()
                .unwrap()
                ._shadow_capture_registration
                .as_ref()
                .unwrap();
            assert_eq!(registration.stream_id(), first_stream);
            let second = registration
                .begin_drain(
                    crate::archive_v3_shadow_session::ShadowSessionId::from_bytes([31; 16]),
                    crate::archive_v3_shadow_session::ShadowAttemptId::from_bytes([33; 16]),
                )
                .unwrap()
                .commit()
                .unwrap();
            assert!(!second.commits().is_empty());
        }

        store
            .with_user("capture-lifetime", |connection| {
                connection.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES (?1, ?2)",
                    ["2026-08-13T12:02:00Z", "pending eviction"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let eviction_lease = {
            let state = actor.state.lock().await;
            state
                .handle
                .as_ref()
                .unwrap()
                ._shadow_capture_registration
                .as_ref()
                .unwrap()
                .begin_drain(
                    crate::archive_v3_shadow_session::ShadowSessionId::from_bytes([31; 16]),
                    crate::archive_v3_shadow_session::ShadowAttemptId::from_bytes([34; 16]),
                )
                .unwrap()
        };
        drop(actor);
        // With a one-handle bound this access flushes, closes, and retires the
        // first connection while its capture lease remains outstanding.
        store
            .with_user("capture-evictor", |connection| {
                connection.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES (?1, ?2)",
                    ["2026-08-13T12:03:00Z", "pending deletion"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            eviction_lease.commit(),
            Err(crate::archive_v3_sqlite_vfs::CaptureRegistryError::Retired)
        ));
        assert!(!capture.registry.contains_stream_for_test(first_stream));

        let unselected_actor = match store.actor_for_existing("capture-evictor").await.unwrap() {
            SaveTarget::Actor(actor) => actor,
            SaveTarget::AlreadyFlushed => panic!("unselected handle unexpectedly evicted"),
        };
        {
            let state = unselected_actor.state.lock().await;
            assert!(
                state
                    .handle
                    .as_ref()
                    .unwrap()
                    ._shadow_capture_registration
                    .is_none(),
                "an unrelated user must never enter the selected capture VFS"
            );
        }
        drop(unselected_actor);

        store
            .with_user("capture-lifetime", |connection| {
                connection.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES (?1, ?2)",
                    ["2026-08-13T12:04:00Z", "pending deletion"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let deletion_actor = match store.actor_for_existing("capture-lifetime").await.unwrap() {
            SaveTarget::Actor(actor) => actor,
            SaveTarget::AlreadyFlushed => panic!("deletion capture handle unexpectedly evicted"),
        };
        let (deletion_lease, deletion_stream) = {
            let state = deletion_actor.state.lock().await;
            let registration = state
                .handle
                .as_ref()
                .unwrap()
                ._shadow_capture_registration
                .as_ref()
                .unwrap();
            let stream = registration.stream_id();
            let lease = registration
                .begin_drain(
                    crate::archive_v3_shadow_session::ShadowSessionId::from_bytes([41; 16]),
                    crate::archive_v3_shadow_session::ShadowAttemptId::from_bytes([42; 16]),
                )
                .unwrap();
            (lease, stream)
        };
        drop(deletion_actor);
        store.delete_user("capture-lifetime").await.unwrap();
        assert!(matches!(
            deletion_lease.commit(),
            Err(crate::archive_v3_sqlite_vfs::CaptureRegistryError::Retired)
        ));
        assert!(!capture.registry.contains_stream_for_test(deletion_stream));

        let directory = tempfile::TempDir::new().unwrap();
        let directory_path = directory.path().to_path_buf();
        assert!(open_db(
            &directory_path,
            Some(capture.as_ref()),
            StorePersistencePolicy::LegacySnapshot,
        )
        .is_err());
        assert!(!capture.registry.contains_path_for_test(&directory_path));

        let unavailable_capture = StoreShadowCapture {
            registry: CaptureRegistry::new(),
            vfs_name: CString::new("kioku-unregistered-capture-vfs").unwrap(),
        };
        let database = tempfile::NamedTempFile::new().unwrap();
        let database_path = database.path().to_path_buf();
        let (connection, registration, _) = open_db(
            &database_path,
            Some(&unavailable_capture),
            StorePersistencePolicy::LegacySnapshot,
        )
        .unwrap();
        assert!(registration.is_none());
        assert!(unavailable_capture.registry.is_empty_for_test());
        drop(connection);
        drop(store);
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

        // LIVENESS bound, not a latency assertion: a leaked STORE_MAX_OPEN slot
        // blocks this call forever, so any bound well above real scheduling
        // noise catches the regression identically. It was 2s, which a machine
        // running concurrent cargo builds legitimately exceeds -- the test then
        // failed a full suite while passing in ~0.7s in isolation.
        //
        // Do NOT bulk-raise the other 2s timeouts in this file. Several of them
        // are ISOLATION assertions where the bound IS the claim (e.g. "unrelated
        // user was blocked by slow user's GCS PUT"): widening those would weaken
        // a real predicate rather than de-flake a proxy.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
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
        blocked.release();
        assert!(newcomer
            .await
            .expect_err("eviction task was not cancelled")
            .is_cancelled());

        // LIVENESS bound -- see the note on the cancelled-Loading timeout above.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
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
    async fn split_media_cancelled_put_keeps_both_deletion_scans_behind_provider_settlement() {
        let database_gcs = Arc::new(FakeGcs::new());
        let current_inner = Arc::new(FakeGcs::new());
        let legacy_media = Arc::new(FakeGcs::new());
        let media_name = "raw/content-lease-user/late.enc";
        let blocked_media = Arc::new(BlockingPutGcs::new(
            Arc::clone(&current_inner),
            media_name.to_string(),
        ));
        let store = Arc::new(Store::new_with_media_and_legacy(
            Arc::new(FakeKms),
            database_gcs,
            blocked_media.clone(),
            legacy_media.clone(),
        ));
        let legacy_name = "raw/content-lease-user/legacy.enc";
        legacy_media
            .put_object(legacy_name, b"legacy", "wrapped", 0)
            .await
            .unwrap();
        current_inner.reset_operation_counts();
        legacy_media.reset_operation_counts();

        let request_lease = store
            .acquire_content_write("content-lease-user")
            .await
            .expect("admit content write");
        let put_lease = request_lease.child();
        let put_store = Arc::clone(&store);
        let put = tokio::spawn(async move {
            let _put_lease = put_lease;
            put_store
                .put_media(media_name, b"ciphertext", "wrapped")
                .await
        });
        blocked_media.wait_until_blocked().await;

        // Model an aborted HTTP request: its owned provider task continues.
        drop(request_lease);
        let delete_store = Arc::clone(&store);
        let mut deletion =
            tokio::spawn(async move { delete_store.delete_user("content-lease-user").await });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut deletion)
                .await
                .is_err(),
            "deletion must wait for an admitted provider PUT"
        );
        assert_eq!(current_inner.operation_counts().0, 0);
        assert_eq!(legacy_media.operation_counts().0, 0);
        assert!(legacy_media.get_object(legacy_name).await.is_ok());

        blocked_media.release();
        put.await
            .expect("owned provider PUT panicked")
            .expect("owned provider PUT failed");
        deletion
            .await
            .expect("deletion task panicked")
            .expect("deletion failed after provider settlement");
        assert!(matches!(
            current_inner.get_object(media_name).await,
            Err(EnclaveError::NotFound)
        ));
        assert!(matches!(
            legacy_media.get_object(legacy_name).await,
            Err(EnclaveError::NotFound)
        ));
        assert!(current_inner.operation_counts().0 > 0);
        assert!(legacy_media.operation_counts().0 > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_authoritative_index_put_keeps_deletion_behind_provider_settlement() {
        let database_inner = Arc::new(FakeGcs::new());
        let user_id = "cancelled-index-save-user";
        let blocked_database = Arc::new(BlockingPutGcs::new(
            Arc::clone(&database_inner),
            gcs_object_name(user_id),
        ));
        let store = Arc::new(make_store_with_limit(
            Arc::new(FakeKms),
            blocked_database.clone(),
            database_inner.clone(),
            1,
        ));
        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-08-01T00:00:00Z', 'must not survive deletion')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("dirty first-write user");

        let save_store = Arc::clone(&store);
        let save = tokio::spawn(async move { save_store.save_user(user_id).await });
        blocked_database.wait_until_blocked().await;

        // The outer save future models a cancelled HTTP request or worker.
        // Cancellation drops the directly-owned provider future; only the
        // durable Requesting intent remains for bounded takeover.
        save.abort();
        assert!(save
            .await
            .expect_err("save was not cancelled")
            .is_cancelled());

        blocked_database.release();
        tokio::task::yield_now().await;
        assert!(matches!(
            database_inner.get_object(&gcs_object_name(user_id)).await,
            Err(EnclaveError::NotFound)
        ));
        assert!(matches!(
            store.delete_user(user_id).await,
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::LegacyWriteIntentUnsettled,
                ..
            }))
        ));
        let expiry = sole_requesting_intent_expiry(&database_inner, user_id);
        database_inner.set_provider_clock_millis(expiry + 1_000);
        store
            .delete_user(user_id)
            .await
            .expect("deletion failed after expired-intent takeover");
        assert!(matches!(
            database_inner.get_object(&gcs_object_name(user_id)).await,
            Err(EnclaveError::NotFound)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_checkpoint_copy_keeps_deletion_behind_provider_settlement() {
        let inner = Arc::new(FakeGcs::new());
        let user_id = "cancelled-checkpoint-save-user";
        let day_one = 1_767_268_800;
        let day_two = 1_767_355_200;
        let seed = store_with_checkpoint_time(Arc::clone(&inner), day_one);
        write_and_save(&seed, user_id, "day one")
            .await
            .expect("seed user");
        drop(seed);

        let checkpoint =
            legacy_recovery_checkpoint_name(user_id, UNIX_EPOCH + Duration::from_secs(day_two));
        let blocked_database = Arc::new(BlockingPutGcs::copy_to(
            Arc::clone(&inner),
            checkpoint.clone(),
        ));
        let mut raw_store = make_store_with_limit(
            Arc::new(FakeKms),
            blocked_database.clone(),
            inner.clone(),
            1,
        );
        raw_store.checkpoint_clock = Arc::new(move || UNIX_EPOCH + Duration::from_secs(day_two));
        let store = Arc::new(raw_store);
        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) \
                     VALUES ('2026-08-02T00:00:00Z', 'checkpoint race')",
                    [],
                )?;
                Ok(())
            })
            .await
            .expect("dirty checkpoint user");

        let save_store = Arc::clone(&store);
        let save = tokio::spawn(async move { save_store.save_user(user_id).await });
        blocked_database.wait_until_blocked().await;
        save.abort();
        assert!(save
            .await
            .expect_err("save was not cancelled")
            .is_cancelled());

        blocked_database.release();
        tokio::task::yield_now().await;
        assert!(matches!(
            inner.get_object(&checkpoint).await,
            Err(EnclaveError::NotFound)
        ));
        assert!(matches!(
            store.delete_user(user_id).await,
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::LegacyWriteIntentUnsettled,
                ..
            }))
        ));
        let expiry = sole_requesting_intent_expiry(&inner, user_id);
        inner.set_provider_clock_millis(expiry + 1_000);
        store
            .delete_user(user_id)
            .await
            .expect("deletion failed after expired checkpoint-intent takeover");
        assert!(matches!(
            inner.get_object(&checkpoint).await,
            Err(EnclaveError::NotFound)
        ));
        assert!(matches!(
            inner.get_object(&gcs_object_name(user_id)).await,
            Err(EnclaveError::NotFound)
        ));
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
            recent_clean_evictions: HashMap::new(),
            access_clock: 0,
        };
        for index in 0..100 {
            registry.record_clean_eviction(&format!("user-{index}"), 1);
        }
        assert_eq!(registry.recent_clean_evictions.len(), 64);
    }

    #[tokio::test]
    async fn failed_deletion_durably_flushes_local_media_inventory_for_restart_retry() {
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
        }

        // The forced pre-delete snapshot is the durable inventory. A new Store
        // must rederive and delete the locally-created key without relying on
        // any process-local deletion state.
        assert!(database_gcs
            .get_object(&gcs_object_name("delete-user"))
            .await
            .is_ok());
        drop(store);
        let restarted =
            make_store_with_limit(Arc::new(FakeKms), database_gcs, failing_media.clone(), 1);

        // LIVENESS bound -- see the note on the cancelled-Loading timeout above.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            restarted.delete_user("delete-user").await
        })
        .await
        .expect("restart retry stalled")
        .expect("restart retry lost local media inventory");
        assert_eq!(failing_media.delete_calls.load(Ordering::SeqCst), 2);
        assert!(!media_inner.objects.lock().unwrap().contains_key(media_key));
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

    #[tokio::test]
    async fn delete_user_removes_every_exact_index_generation() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        store.with_user("alice", |_| Ok(())).await.unwrap();
        store.save_user("alice").await.unwrap();
        store
            .with_user("alice", |conn| {
                conn.execute(
                    "INSERT INTO app_metadata (key,value) VALUES ('second','generation')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user("alice").await.unwrap();

        let exact = gcs_object_name("alice");
        // Current save policy prunes older versions. Retain one explicit
        // noncurrent generation so this test covers exact-version deletion.
        let live = gcs.get_object(&exact).await.unwrap();
        gcs.put_object(
            &exact,
            &live.ciphertext,
            &live.wrapped_dek_b64,
            live.generation,
        )
        .await
        .unwrap();
        let similarly_prefixed = format!("{exact}-other");
        gcs.put_object(&similarly_prefixed, b"keep", "wrapped", 0)
            .await
            .unwrap();
        assert_eq!(
            list_all_object_versions(gcs.as_ref(), &exact)
                .await
                .unwrap()
                .iter()
                .filter(|version| version.name == exact)
                .count(),
            2
        );

        store.delete_user("alice").await.unwrap();

        assert!(list_all_object_versions(gcs.as_ref(), &exact)
            .await
            .unwrap()
            .iter()
            .all(|version| version.name != exact));
        assert!(gcs.get_object(&similarly_prefixed).await.is_ok());
    }

    #[tokio::test]
    async fn read_only_lru_churn_never_writes_clean_user_indexes() {
        let gcs = Arc::new(FakeGcs::new());
        let kms = Arc::new(FakeKms);
        let mut writer = Store::new(kms.clone(), gcs.clone());
        writer.max_open = 2;
        let users = (0..20)
            .map(|index| format!("idle-{index}"))
            .collect::<Vec<_>>();

        for user_id in &users {
            writer
                .with_user(user_id, |conn| {
                    conn.execute(
                        "INSERT INTO app_metadata (key,value) VALUES ('created','yes')",
                        [],
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
            writer.save_user(user_id).await.unwrap();
        }
        for user_id in &users {
            assert_eq!(gcs.exact_generation_count(&gcs_object_name(user_id)), 1);
        }

        let mut scanner = Store::new(kms, gcs.clone());
        scanner.max_open = 2;
        for _ in 0..3 {
            for user_id in &users {
                let value: String = scanner
                    .read_user(user_id, |conn| {
                        Ok(conn.query_row(
                            "SELECT value FROM app_metadata WHERE key='created'",
                            [],
                            |row| row.get(0),
                        )?)
                    })
                    .await
                    .unwrap();
                assert_eq!(value, "yes");
            }
        }
        for user_id in &users {
            assert_eq!(gcs.exact_generation_count(&gcs_object_name(user_id)), 1);
        }

        scanner
            .with_user(&users[0], |conn| {
                conn.execute(
                    "UPDATE app_metadata SET value='changed' WHERE key='created'",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        scanner.save_user(&users[0]).await.unwrap();
        assert_eq!(gcs.exact_generation_count(&gcs_object_name(&users[0])), 2);
        for user_id in &users[1..] {
            assert_eq!(gcs.exact_generation_count(&gcs_object_name(user_id)), 1);
        }
    }

    #[tokio::test]
    async fn deletion_waits_for_inflight_upload_and_sweeps_unreferenced_media_prefix() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(Arc::new(FakeKms), gcs.clone()));
        let user_id = "capture-delete-race-user";
        store.with_user(user_id, |_| Ok(())).await.unwrap();
        store.save_user(user_id).await.unwrap();

        // Model an upload that passed preflight and placed the encrypted object
        // but has not yet recorded its database row. Deletion must wait at the
        // same lifecycle fence, then remove the whole namespaced prefix even
        // though this object is absent from the DB snapshot.
        let upload_guard = store.lock_user_lifecycle(user_id).await.unwrap();
        let object_key = format!("raw/{user_id}/asset.enc");
        store
            .put_media(&object_key, b"encrypted-media", "wrapped")
            .await
            .unwrap();
        let deleting_store = Arc::clone(&store);
        let deletion = tokio::spawn(async move { deleting_store.delete_user(user_id).await });
        tokio::task::yield_now().await;
        assert!(!deletion.is_finished());

        drop(upload_guard);
        deletion.await.unwrap().unwrap();

        assert!(
            list_all_object_versions(gcs.as_ref(), &format!("raw/{user_id}/"))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn account_deletion_scans_both_media_buckets_without_cross_user_deletion() {
        let indexes = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let store = Store::new_with_media_and_legacy(
            Arc::new(FakeKms),
            indexes,
            current.clone(),
            legacy.clone(),
        );
        write_and_save(&store, "alice", "init").await.unwrap();
        for (gcs, name) in [
            (&current, "raw/alice/current.enc"),
            (&current, "media/alice/current-legacy-name.enc"),
            (&legacy, "raw/alice/legacy-name.enc"),
            (&legacy, "media/alice/legacy.enc"),
        ] {
            gcs.put_object(name, b"ciphertext", "wrapped", 0)
                .await
                .unwrap();
        }
        legacy
            .put_object("raw/bob/keep.enc", b"other-user", "wrapped", 0)
            .await
            .unwrap();
        current
            .put_object("raw/bob/current-keep.enc", b"other-user", "wrapped", 0)
            .await
            .unwrap();

        store.delete_user("alice").await.unwrap();
        for (gcs, prefix) in [
            (&current, "raw/alice/"),
            (&current, "media/alice/"),
            (&legacy, "raw/alice/"),
            (&legacy, "media/alice/"),
        ] {
            assert!(list_all_object_versions(gcs.as_ref(), prefix)
                .await
                .unwrap()
                .is_empty());
        }
        assert!(legacy.get_object("raw/bob/keep.enc").await.is_ok());
        assert!(current.get_object("raw/bob/current-keep.enc").await.is_ok());
    }

    #[tokio::test]
    async fn legacy_media_soft_delete_blocks_physical_account_completion() {
        let indexes = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let store =
            Store::new_with_media_and_legacy(Arc::new(FakeKms), indexes, current, legacy.clone());
        write_and_save(&store, "alice", "init").await.unwrap();
        legacy
            .put_object("raw/alice/retained.enc", b"ciphertext", "wrapped", 0)
            .await
            .unwrap();
        legacy.set_soft_delete_enabled(true);

        assert!(matches!(
            store.delete_user("alice").await,
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::SoftDeleteRetention,
                ..
            }))
        ));
        assert!(legacy.soft_deleted_count("raw/alice/") > 0);
    }

    #[tokio::test]
    async fn deletion_cost_tracks_live_generations_not_pruned_media_ledger_rows() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        let user_id = "large-pruned-ledger-user";
        store
            .with_user(user_id, |conn| {
                conn.execute_batch("PRAGMA foreign_keys=OFF;")?;
                let tx = conn.unchecked_transaction()?;
                for index in 0..2_000 {
                    tx.execute(
                        "INSERT INTO media_objects
                         (asset_id,event_id,object_key,mime_type,codec,byte_length,sha256,
                          processing_state,deleted_at)
                         VALUES (?1,?2,?3,'audio/m4a','aac',1,?4,'pruned',
                                 '2026-08-09T12:00:00.000Z')",
                        rusqlite::params![
                            format!("pruned-asset-{index}"),
                            format!("pruned-event-{index}"),
                            format!("raw/{user_id}/pruned-{index}.enc"),
                            format!("{index:064x}"),
                        ],
                    )?;
                }
                tx.execute(
                    "INSERT INTO media_objects
                     (asset_id,event_id,object_key,mime_type,codec,byte_length,sha256,
                      processing_state)
                     VALUES ('legacy-asset','legacy-event','legacy/object.enc',
                             'audio/m4a','aac',1,?1,'ready')",
                    ["f".repeat(64)],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(user_id).await.unwrap();

        for (name, generations) in [
            (format!("raw/{user_id}/live.enc"), 2),
            (format!("media/{user_id}/screen.enc"), 1),
            ("legacy/object.enc".to_string(), 2),
        ] {
            for generation in 0..generations {
                store
                    .put_media_at_generation(&name, b"ciphertext", "wrapped", generation)
                    .await
                    .unwrap();
            }
        }

        gcs.reset_operation_counts();
        store.delete_user(user_id).await.unwrap();
        let (list_calls, delete_calls) = gcs.operation_counts();
        assert!(
            list_calls <= 12,
            "pruned ledger rows caused {list_calls} GCS listings"
        );
        assert_eq!(delete_calls, 6);
        for prefix in [
            format!("raw/{user_id}/"),
            format!("media/{user_id}/"),
            "legacy/object.enc".to_string(),
            gcs_object_name(user_id),
        ] {
            assert!(
                list_all_object_versions(gcs.as_ref(), &prefix)
                    .await
                    .unwrap()
                    .is_empty(),
                "deletion left generations under {prefix}"
            );
        }

        gcs.reset_operation_counts();
        store.delete_user(user_id).await.unwrap();
        let (retry_lists, retry_deletes) = gcs.operation_counts();
        assert!(retry_lists <= 6);
        assert_eq!(retry_deletes, 0);
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
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::SoftDeleteRetention,
                hard_delete_time: Some(ref deadline),
                ..
            })) if deadline == "2099-01-01T00:00:00.000Z"
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
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::SoftDeleteRetention,
                hard_delete_time: Some(ref deadline),
                ..
            })) if deadline == "2099-01-01T00:00:00.000Z"
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
    async fn historical_unscoped_inventory_tracks_soft_delete_retention_in_both_media_buckets() {
        let indexes = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let store = Store::new_with_media_and_legacy(
            Arc::new(FakeKms),
            indexes.clone(),
            current.clone(),
            legacy.clone(),
        );
        let current_key = "unscoped/current-evidence.enc";
        let legacy_key = "unscoped/legacy-evidence.enc";
        store
            .with_user("alice", |conn| {
                insert_screenshot_evidence(conn, current_key)?;
                conn.execute(
                    "INSERT INTO screenshots(id,captured_at) VALUES (2,'2026-01-01T00:00:01Z')",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO screenshot_images \
                     (id,screenshot_id,episode_id,source_key,captured_at,object_key,mime_type,width,height,byte_length,sha256) \
                     VALUES ('image-2',2,1,'source-2','2026-01-01T00:00:01Z',?1,'image/jpeg',1,1,1,?2)",
                    rusqlite::params![legacy_key, "b".repeat(64)],
                )?;
                Ok(())
            })
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
        current
            .put_object(current_key, b"current", "wrapped", 0)
            .await
            .unwrap();
        legacy
            .put_object(legacy_key, b"legacy", "wrapped", 0)
            .await
            .unwrap();
        current.set_soft_delete_enabled(true);
        legacy.set_soft_delete_enabled(true);

        assert!(matches!(
            store.delete_user("alice").await,
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::SoftDeleteRetention,
                ..
            }))
        ));
        assert_eq!(current.soft_deleted_count(current_key), 1);
        assert_eq!(legacy.soft_deleted_count(legacy_key), 1);
        assert!(indexes.version_count(&legacy_recovery_prefix("alice")) > 0);

        current.expire_soft_deleted(current_key);
        legacy.expire_soft_deleted(legacy_key);
        store.delete_user("alice").await.unwrap();
        assert_eq!(indexes.version_count(&gcs_object_name("alice")), 0);
    }

    #[tokio::test]
    async fn exact_generation_disappearing_after_inventory_fails_closed() {
        let gcs = Arc::new(FakeGcs::new());
        let store = Store::new(Arc::new(FakeKms), gcs.clone());
        let media = "media/historical-race-evidence";
        store
            .with_user("alice", |conn| insert_screenshot_evidence(conn, media))
            .await
            .unwrap();
        store.save_user("alice").await.unwrap();
        let index = gcs_object_name("alice");
        let historical_generation = gcs.get_object(&index).await.unwrap().generation;
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
        gcs.vanish_next_exact_generation_get(&index, historical_generation);

        let deletion = store.delete_user("alice").await;
        assert!(matches!(
            deletion,
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::LegacyGenerationUnavailable,
                ..
            }))
        ));
        assert_eq!(gcs.version_count(media), 1);
        assert_eq!(gcs.version_count(&index), 1);
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
                Err(EnclaveError::DeletionPending(DeletionPending {
                    reason: DeletionPendingReason::LegacyInventoryIncomplete,
                    ..
                }))
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
            Err(EnclaveError::DeletionPending(DeletionPending {
                reason: DeletionPendingReason::LegacySnapshotTooLarge,
                ..
            }))
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
            matching_soft_deleted_inventory(gcs.as_ref(), "indexes/alice.db.enc", true).await,
            Err(EnclaveError::Gcs(message)) if message.contains("repeated")
        ));
    }

    #[tokio::test]
    async fn soft_deleted_inventory_preserves_latest_provider_deadline_across_pages() {
        let gcs = Arc::new(FakeGcs::new());
        gcs.set_soft_delete_enabled(true);
        for (suffix, deadline) in [
            ("a", "2026-08-12T00:00:00.000Z"),
            ("b", "2026-08-14T00:00:00Z"),
            ("c", "2026-08-13T00:00:00.000Z"),
        ] {
            let name = format!("raw/alice/{suffix}.enc");
            let generation = gcs.put_object(&name, b"data", "wrapped", 0).await.unwrap();
            gcs.set_soft_delete_hard_delete_time(Some(deadline));
            gcs.soft_delete_generation(&name, generation);
        }

        let inventory = matching_soft_deleted_inventory(gcs.as_ref(), "raw/alice/", false)
            .await
            .unwrap();
        assert!(inventory.found);
        assert_eq!(
            inventory.latest_hard_delete_time.as_deref(),
            Some("2026-08-14T00:00:00Z")
        );
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
    fn soft_delete_listing_decodes_provider_hard_delete_time() {
        let body = br#"{"items":[{"name":"raw/alice/a.enc","generation":"7","size":"12","hardDeleteTime":"2026-08-14T00:00:00.000Z"}]}"#;
        let page = decode_soft_deleted_list_response(reqwest::StatusCode::OK, body, true).unwrap();
        assert_eq!(
            page.versions[0].hard_delete_time.as_deref(),
            Some("2026-08-14T00:00:00.000Z")
        );
    }

    #[test]
    fn production_exact_generation_download_maps_second_window_404_to_not_found() {
        assert!(matches!(
            exact_generation_download_status(reqwest::StatusCode::NOT_FOUND),
            Err(EnclaveError::NotFound)
        ));
        assert!(exact_generation_download_status(reqwest::StatusCode::OK).is_ok());
        assert!(exact_generation_download_status(reqwest::StatusCode::BAD_GATEWAY).is_ok());
    }

    #[test]
    fn provider_date_parser_fails_closed_on_missing_malformed_or_duplicate_values() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(provider_date_millis(&headers).is_err());
        headers.insert(
            reqwest::header::DATE,
            reqwest::header::HeaderValue::from_static("not-a-date"),
        );
        assert!(provider_date_millis(&headers).is_err());
        headers.insert(
            reqwest::header::DATE,
            reqwest::header::HeaderValue::from_static("Sun, 06 Nov 1994 08:49:37 GMT"),
        );
        headers.append(
            reqwest::header::DATE,
            reqwest::header::HeaderValue::from_static("Sun, 06 Nov 1994 08:49:38 GMT"),
        );
        assert!(provider_date_millis(&headers).is_err());
    }

    #[test]
    fn identity_rebind_fence_name_is_canonical_deterministic_and_opaque() {
        let user_id = "legacy-visible-user-id";
        let name = test_identity_rebind_fence_object_name(user_id);
        assert_eq!(name, test_identity_rebind_fence_object_name(user_id));
        assert_ne!(
            name,
            test_identity_rebind_fence_object_name("different-user-id")
        );
        assert_ne!(
            name,
            identity_rebind_fence_object_name_with_key(&[0xa5; 32], user_id)
        );
        assert!(is_canonical_identity_rebind_fence_object_name(&name));
        assert!(!name.contains(user_id));
        assert!(!is_canonical_identity_rebind_fence_object_name(
            "control/identity-rebind-fences/legacy-visible-user-id"
        ));
        assert!(!is_canonical_identity_rebind_fence_object_name(
            "control/identity-rebind-fences/fence_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
    }

    #[tokio::test]
    async fn production_live_listing_uses_configured_endpoint_and_exact_shape() {
        use axum::{
            extract::Request,
            http::{header, Method, StatusCode},
            response::IntoResponse,
            routing::any,
            Json, Router,
        };
        use serde_json::json;
        use tokio::net::TcpListener;

        let listing_hits = Arc::new(AtomicUsize::new(0));
        let unexpected_hits = Arc::new(AtomicUsize::new(0));
        let listing_hits_for_app = Arc::clone(&listing_hits);
        let unexpected_hits_for_app = Arc::clone(&unexpected_hits);
        let app = Router::new().fallback(any(move |request: Request| {
            let listing_hits = Arc::clone(&listing_hits_for_app);
            let unexpected_hits = Arc::clone(&unexpected_hits_for_app);
            async move {
                match request.uri().path() {
                    "/computeMetadata/v1/instance/service-accounts/default/token" => {
                        Json(json!({"access_token": "test-token"})).into_response()
                    }
                    "/storage/v1/b/test-bucket/o" => {
                        assert_eq!(request.method(), Method::GET);
                        assert_eq!(
                            request.headers().get(header::AUTHORIZATION).unwrap(),
                            "Bearer test-token"
                        );
                        let query = request.uri().query().unwrap();
                        assert!(query.contains("maxResults=1000"));
                        assert!(query.contains("prefix=control%2Flegacy%20write%2F"));
                        assert!(query.contains("pageToken=cursor%2F2"));
                        assert!(!query.contains("versions="));
                        listing_hits.fetch_add(1, Ordering::SeqCst);
                        Json(json!({
                            "items": [{
                                "name": "control/legacy write/intent_1",
                                "generation": "7",
                                "size": "12"
                            }]
                        }))
                        .into_response()
                    }
                    _ => {
                        unexpected_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                }
            }
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GcpGcsClient::for_test_endpoint("test-bucket".into(), endpoint);
        let page = client
            .list_live_objects("control/legacy write/", Some("cursor/2"))
            .await
            .unwrap();
        assert_eq!(page.versions.len(), 1);
        assert_eq!(page.versions[0].generation, 7);
        assert_eq!(listing_hits.load(Ordering::SeqCst), 1);
        assert_eq!(unexpected_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn production_trusted_time_is_read_only_and_rejects_provider_regression() {
        use axum::{
            extract::Request,
            http::{header, HeaderValue, Method, StatusCode},
            response::IntoResponse,
            routing::any,
            Json, Router,
        };
        use serde_json::json;
        use tokio::net::TcpListener;

        let metadata_hits = Arc::new(AtomicUsize::new(0));
        let mutation_hits = Arc::new(AtomicUsize::new(0));
        let metadata_hits_for_app = Arc::clone(&metadata_hits);
        let mutation_hits_for_app = Arc::clone(&mutation_hits);
        let app = Router::new().fallback(any(move |request: Request| {
            let metadata_hits = Arc::clone(&metadata_hits_for_app);
            let mutation_hits = Arc::clone(&mutation_hits_for_app);
            async move {
                match request.uri().path() {
                    "/computeMetadata/v1/instance/service-accounts/default/token" => {
                        Json(json!({"access_token": "test-token"})).into_response()
                    }
                    path if path.starts_with("/storage/v1/b/test-bucket/o/") => {
                        assert_eq!(request.method(), Method::GET);
                        assert_eq!(
                            request.headers().get(header::AUTHORIZATION).unwrap(),
                            "Bearer test-token"
                        );
                        let hit = metadata_hits.fetch_add(1, Ordering::SeqCst);
                        let date = if hit == 0 {
                            "Sun, 06 Nov 1994 08:49:37 GMT"
                        } else {
                            "Sun, 06 Nov 1994 08:49:36 GMT"
                        };
                        let mut response = Json(json!({"generation": "7"})).into_response();
                        response
                            .headers_mut()
                            .insert(header::DATE, HeaderValue::from_static(date));
                        response
                    }
                    _ => {
                        mutation_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                }
            }
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GcpGcsClient::for_test_endpoint("test-bucket".into(), endpoint);
        let authority = "control/legacy-write-intents/alice/intent_authority";
        assert_eq!(
            client.trusted_time_millis(authority, 7).await.unwrap(),
            784_111_777_000
        );
        assert!(matches!(
            client.trusted_time_millis(authority, 7).await,
            Err(EnclaveError::Gcs(message)) if message.contains("regressed")
        ));
        assert_eq!(metadata_hits.load(Ordering::SeqCst), 2);
        assert_eq!(mutation_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn production_exact_generation_media_404_after_metadata_is_not_found() {
        use axum::{
            extract::Request, http::StatusCode, response::IntoResponse, routing::any, Json, Router,
        };
        use serde_json::json;
        use tokio::net::TcpListener;

        let metadata_hits = Arc::new(AtomicUsize::new(0));
        let media_hits = Arc::new(AtomicUsize::new(0));
        let metadata_hits_for_app = Arc::clone(&metadata_hits);
        let media_hits_for_app = Arc::clone(&media_hits);
        let app = Router::new().fallback(any(move |request: Request| {
            let metadata_hits = Arc::clone(&metadata_hits_for_app);
            let media_hits = Arc::clone(&media_hits_for_app);
            async move {
                match request.uri().path() {
                    "/computeMetadata/v1/instance/service-accounts/default/token" => {
                        Json(json!({"access_token": "test-token"})).into_response()
                    }
                    path if path.starts_with("/storage/v1/b/test-bucket/o/") => {
                        metadata_hits.fetch_add(1, Ordering::SeqCst);
                        Json(json!({
                            "generation": "7",
                            "size": "12",
                            "updated": "2026-08-11T00:00:00.000Z",
                            "crc32c": "test-crc32c",
                            "metadata": {"x-kioku-wrapped-dek": "test-wrapped-dek"}
                        }))
                        .into_response()
                    }
                    path if path.starts_with("/download/storage/v1/b/test-bucket/o/") => {
                        media_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NOT_FOUND.into_response()
                    }
                    _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GcpGcsClient::for_test_endpoint("test-bucket".into(), endpoint);
        let result = client
            .get_object_generation("indexes/opaque.db.enc", 7)
            .await;

        assert!(matches!(result, Err(EnclaveError::NotFound)));
        assert_eq!(metadata_hits.load(Ordering::SeqCst), 1);
        assert_eq!(media_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn production_exact_generation_metadata_404_is_not_found_without_download() {
        use axum::{
            extract::Request, http::StatusCode, response::IntoResponse, routing::any, Json, Router,
        };
        use serde_json::json;
        use tokio::net::TcpListener;

        let media_hits = Arc::new(AtomicUsize::new(0));
        let media_hits_for_app = Arc::clone(&media_hits);
        let app = Router::new().fallback(any(move |request: Request| {
            let media_hits = Arc::clone(&media_hits_for_app);
            async move {
                match request.uri().path() {
                    "/computeMetadata/v1/instance/service-accounts/default/token" => {
                        Json(json!({"access_token": "test-token"})).into_response()
                    }
                    path if path.starts_with("/storage/v1/b/test-bucket/o/") => {
                        StatusCode::NOT_FOUND.into_response()
                    }
                    path if path.starts_with("/download/storage/v1/b/test-bucket/o/") => {
                        media_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                    _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GcpGcsClient::for_test_endpoint("test-bucket".into(), endpoint);
        let result = client
            .get_object_generation("indexes/opaque.db.enc", 7)
            .await;

        assert!(matches!(result, Err(EnclaveError::NotFound)));
        assert_eq!(media_hits.load(Ordering::SeqCst), 0);
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

    #[tokio::test]
    async fn split_media_uses_current_writes_then_exact_legacy_read_and_dual_delete() {
        let index = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let store = Store::new_with_media_and_legacy(
            Arc::new(FakeKms),
            index,
            current.clone(),
            legacy.clone(),
        );
        let key = "raw/split-media-owner/asset.enc";

        legacy
            .put_object(key, b"legacy", "legacy-wrapped", 0)
            .await
            .unwrap();
        let fallback = store.get_media(key).await.unwrap();
        assert_eq!(fallback.ciphertext, b"legacy");

        store
            .put_media(key, b"current", "current-wrapped")
            .await
            .unwrap();
        let preferred = store.get_media(key).await.unwrap();
        assert_eq!(preferred.ciphertext, b"current");
        assert_eq!(
            current.get_object(key).await.unwrap().ciphertext,
            b"current"
        );
        assert_eq!(legacy.get_object(key).await.unwrap().ciphertext, b"legacy");

        store.delete_media(key).await.unwrap();
        assert!(matches!(
            current.get_object(key).await,
            Err(EnclaveError::NotFound)
        ));
        assert!(matches!(
            legacy.get_object(key).await,
            Err(EnclaveError::NotFound)
        ));
    }

    #[tokio::test]
    async fn split_media_does_not_fallback_after_current_provider_error() {
        let index = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let store = Store::new_with_media_and_legacy(
            Arc::new(FakeKms),
            index,
            current.clone(),
            legacy.clone(),
        );
        let key = "raw/split-media-owner/provider-error.enc";
        legacy
            .put_object(key, b"legacy", "legacy-wrapped", 0)
            .await
            .unwrap();
        current.fail_next_get(EnclaveError::Gcs("current media unavailable".into()));

        assert!(matches!(
            store.get_media(key).await,
            Err(EnclaveError::Gcs(message)) if message == "current media unavailable"
        ));
        assert_eq!(
            legacy.live_get_count(),
            0,
            "legacy must not mask current errors"
        );
    }

    async fn retained_media_ciphertext(
        store: &Store,
        user_id: &str,
        object_key: &str,
        plaintext: &[u8],
    ) -> (Vec<u8>, String, String) {
        let (dek, wrapped_dek) = generate_and_wrap_dek(store.kms.as_ref()).await.unwrap();
        let ciphertext =
            encrypt_bound_blob(&dek, plaintext, &media_blob_context(user_id, object_key)).unwrap();
        let sha256 = format!("{:x}", Sha256::digest(plaintext));
        (ciphertext, wrapped_dek, sha256)
    }

    #[tokio::test]
    async fn retained_media_deletes_each_providers_own_unequal_generation() {
        let index = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let store = Store::new_with_media_and_legacy(
            Arc::new(FakeKms),
            index,
            current.clone(),
            legacy.clone(),
        );
        let user_id = "retention-legacy-higher";
        let key = format!("raw/{user_id}/asset.enc");
        let (ciphertext, wrapped_dek, sha256) =
            retained_media_ciphertext(&store, user_id, &key, b"same logical media").await;
        let current_generation = current
            .put_object(&key, &ciphertext, &wrapped_dek, 0)
            .await
            .unwrap();
        let legacy_seed = legacy
            .put_object(&key, b"older unrelated", "wrapped", 0)
            .await
            .unwrap();
        let legacy_generation = legacy
            .put_object(&key, &ciphertext, &wrapped_dek, legacy_seed)
            .await
            .unwrap();
        assert!(legacy_generation > current_generation);

        store
            .delete_retained_media(
                user_id,
                &key,
                Some(current_generation),
                Some("current"),
                &sha256,
            )
            .await
            .unwrap();

        assert_eq!(current.version_count(&key), 0);
        assert_eq!(
            legacy.version_count(&key),
            1,
            "unrelated legacy history remains"
        );
    }

    #[tokio::test]
    async fn migrated_retention_row_without_provenance_authenticates_each_live_generation() {
        let index = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let store = Store::new_with_media_and_legacy(
            Arc::new(FakeKms),
            index,
            current.clone(),
            legacy.clone(),
        );
        let user_id = "retention-migrated-row";
        let key = format!("raw/{user_id}/asset.enc");
        let (ciphertext, wrapped_dek, sha256) =
            retained_media_ciphertext(&store, user_id, &key, b"migrated logical media").await;
        let seed_generation = current
            .put_object(&key, b"older unrelated", "wrapped", 0)
            .await
            .unwrap();
        let current_generation = current
            .put_object(&key, &ciphertext, &wrapped_dek, seed_generation)
            .await
            .unwrap();
        let legacy_generation = legacy
            .put_object(&key, &ciphertext, &wrapped_dek, 0)
            .await
            .unwrap();
        assert_ne!(current_generation, legacy_generation);

        store
            .delete_retained_media(user_id, &key, None, None, &sha256)
            .await
            .unwrap();

        assert_eq!(current.version_count(&key), 1);
        assert_eq!(legacy.version_count(&key), 0);
    }

    #[tokio::test]
    async fn retained_media_never_deletes_newer_unverified_legacy_generation() {
        let index = Arc::new(FakeGcs::new());
        let current = Arc::new(FakeGcs::new());
        let legacy = Arc::new(FakeGcs::new());
        let store = Store::new_with_media_and_legacy(
            Arc::new(FakeKms),
            index,
            current.clone(),
            legacy.clone(),
        );
        let user_id = "retention-newer-legacy";
        let key = format!("raw/{user_id}/asset.enc");
        let (ciphertext, wrapped_dek, sha256) =
            retained_media_ciphertext(&store, user_id, &key, b"retained logical media").await;
        let current_generation = current
            .put_object(&key, &ciphertext, &wrapped_dek, 0)
            .await
            .unwrap();
        let legacy_generation = legacy
            .put_object(&key, &ciphertext, &wrapped_dek, 0)
            .await
            .unwrap();
        let (newer_ciphertext, newer_wrapped_dek, _) =
            retained_media_ciphertext(&store, user_id, &key, b"newer independent media").await;
        let newer_generation = legacy
            .put_object(
                &key,
                &newer_ciphertext,
                &newer_wrapped_dek,
                legacy_generation,
            )
            .await
            .unwrap();

        assert!(store
            .delete_retained_media(
                user_id,
                &key,
                Some(current_generation),
                Some("current"),
                &sha256,
            )
            .await
            .is_err());
        assert_eq!(current.version_count(&key), 1);
        assert_eq!(legacy.version_count(&key), 2);
        assert_eq!(legacy.generation(&key), Some(newer_generation));
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

        assert_eq!(
            historical_media_keys(&conn, "owner").unwrap(),
            vec!["raw/cloud".to_string()]
        );
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
            5,
            "index, checkpoint, and three retained terminal intents should be written"
        );
        assert_eq!(
            objects
                .keys()
                .filter(|name| name.starts_with(&legacy_write_intent_prefix(user_id)))
                .count(),
            3
        );
        assert!(
            objects
                .keys()
                .any(|name| name.starts_with(&format!("legacy-recovery/{user_id}/"))),
            "expected named daily recovery checkpoint"
        );
    }

    fn maintenance_test_plan(user_id: &str) -> AuthenticatedMaintenanceImportPlan {
        AuthenticatedMaintenanceImportPlan::for_test(
            user_id,
            crate::archive_v3::ArchiveId::from_bytes([0x61; 16]),
            [0x62; 16],
            crate::archive_v3::ObjectId::from_bytes([0x63; 16]),
        )
    }

    #[tokio::test]
    async fn archive_maintenance_fences_bumps_and_scrubs_one_exact_snapshot() {
        let user_id = "11111111-1111-4111-8111-111111111199";
        let kms: Arc<dyn KmsClient> = Arc::new(FakeKms);
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(kms, gcs.clone()));
        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO app_metadata(key,value) VALUES('maintenance','source')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(user_id).await.unwrap();
        let object_name = gcs_object_name(user_id);
        assert_eq!(gcs.exact_generation_count(&object_name), 1);

        let plan = maintenance_test_plan(user_id);
        let admission = store
            .acquire_archive_maintenance_admission(
                crate::archive_v3_maintenance_import::MaintenanceCoordinatorContext::for_test(),
                plan,
            )
            .await
            .unwrap();
        // Lifecycle acquisition alone must not close either local admission
        // path. Control performs its final terminal-release check here.
        store.with_user(user_id, |_| Ok(())).await.unwrap();
        let content_lease = store.acquire_content_write(user_id).await.unwrap();
        drop(content_lease);
        let mut transition = admission.begin().await;
        assert!(matches!(
            store.with_user(user_id, |_| Ok(())).await,
            Err(EnclaveError::Auth(_))
        ));
        assert!(matches!(
            store.acquire_content_write(user_id).await,
            Err(EnclaveError::Auth(_))
        ));
        let tentative = transition.tentative_source().await.unwrap();
        assert!(tentative.base_generation > 0);
        assert_eq!(tentative.sqlite_schema_version, 0);
        let pinned = match transition.fence_and_pin(tentative).await.unwrap() {
            MaintenanceFenceAndPin::Pinned(pinned) => pinned,
            MaintenanceFenceAndPin::Rebase { .. } => panic!("unexpected maintenance rebase"),
        };
        let source = pinned.source_binding();
        let source_view = source.store_view(StoreMaintenanceContext(()));
        assert!(source_view.generation > tentative.base_generation);
        assert_eq!(source_view.plaintext_hash, tentative.plaintext_hash);
        assert_eq!(source_view.plaintext_len, tentative.plaintext_len);
        assert_eq!(gcs.exact_generation_count(&object_name), 2);

        let path = pinned.path_for_maintenance_test().to_path_buf();
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));
        std::fs::write(&wal, b"plaintext-sidecar").unwrap();
        std::fs::write(&shm, b"plaintext-sidecar").unwrap();
        // The surviving production conversion (the advisory capture target
        // went with the Phase-2 deletion). Consuming the pinned snapshot must
        // scrub every plaintext scratch byte -- main file and both sidecars.
        let fence = pinned
            .into_wal_authority_fence(
                crate::archive_v3_maintenance_import::MaintenanceCoordinatorContext::for_test(),
                source,
            )
            .unwrap();
        assert!(!path.exists());
        assert!(!wal.exists());
        assert!(!shm.exists());
        // A fence is not release authority: the Store and content barrier
        // remain fail-closed for this identity while it exists.
        assert!(matches!(
            store.with_user(user_id, |_| Ok(())).await,
            Err(EnclaveError::Auth(_))
        ));
        drop(fence);
        assert_eq!(gcs.exact_generation_count(&object_name), 2);
    }

    #[tokio::test]
    async fn archive_maintenance_restart_recovers_only_exact_pinned_generation() {
        let user_id = "11111111-1111-4111-8111-111111111198";
        let gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(Arc::new(FakeKms), gcs.clone()));
        store
            .with_user(user_id, |conn| {
                conn.execute(
                    "INSERT INTO app_metadata(key,value) VALUES('maintenance','restart')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(user_id).await.unwrap();
        let mut transition = store
            .acquire_archive_maintenance_admission(
                crate::archive_v3_maintenance_import::MaintenanceCoordinatorContext::for_test(),
                maintenance_test_plan(user_id),
            )
            .await
            .unwrap()
            .begin()
            .await;
        let tentative = transition.tentative_source().await.unwrap();
        let pinned = match transition.fence_and_pin(tentative).await.unwrap() {
            MaintenanceFenceAndPin::Pinned(pinned) => pinned,
            MaintenanceFenceAndPin::Rebase { .. } => panic!("unexpected maintenance rebase"),
        };
        let source = pinned.source_binding();
        let source_view = source.store_view(StoreMaintenanceContext(()));
        drop(pinned);
        drop(store);

        let restarted = Arc::new(Store::new(Arc::new(FakeKms), gcs.clone()));
        let transition = restarted
            .acquire_archive_maintenance_admission(
                crate::archive_v3_maintenance_import::MaintenanceCoordinatorContext::for_test(),
                maintenance_test_plan(user_id),
            )
            .await
            .unwrap()
            .begin()
            .await;
        let recovered = transition.recover_pinned(source).await.unwrap();
        recovered
            .exact_generation_revalidation()
            .verify()
            .await
            .unwrap();
        assert!(recovered.path_for_maintenance_test().exists());
        drop(recovered);

        gcs.vanish_next_exact_generation_get(&gcs_object_name(user_id), source_view.generation);
        let second_restart = Arc::new(Store::new(Arc::new(FakeKms), gcs));
        let transition = second_restart
            .acquire_archive_maintenance_admission(
                crate::archive_v3_maintenance_import::MaintenanceCoordinatorContext::for_test(),
                maintenance_test_plan(user_id),
            )
            .await
            .unwrap()
            .begin()
            .await;
        assert!(transition.recover_pinned(source).await.is_err());
    }

    #[test]
    fn archive_maintenance_store_surface_has_no_delete_or_live_constructor() {
        let source = include_str!("store.rs");
        let main = include_str!("main.rs");
        let begin = source.find("impl ArchiveMaintenanceTransition").unwrap();
        let end = source[begin..]
            .find("fn deleted_user_error")
            .map(|offset| begin + offset)
            .unwrap();
        let implementation = &source[begin..end];
        for forbidden in [
            concat!("delete_", "object"),
            concat!("list_", "object"),
            concat!("purge_", "versions"),
            concat!("WalLogical", "Only"),
        ] {
            assert!(
                !implementation.contains(forbidden),
                "forbidden operation: {forbidden}"
            );
        }
        assert!(!main.contains("begin_archive_maintenance"));
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
                None,
            )
            .await
            .unwrap();

        // No more due rows
        assert!(store.next_email_delivery(user_id).await.unwrap().is_none());

        // A malformed future-looking timestamp must be returned to the owner
        // for provider-free terminal settlement. It must not become an
        // immortal row merely because lexical ordering puts it after `now`.
        store
            .with_user(user_id, |conn| {
                conn.execute_batch(
                    "INSERT INTO episodes
                       (id,started_at,ended_at,title,summary,substance)
                     VALUES
                       (101,'2026-07-30T11:00:00Z','2026-07-30T11:30:00Z',
                        'Malformed retry','Test Summary','normal');
                     INSERT INTO email_deliveries
                       (episode_id,delivery_version,delivery_id,include_content,state,
                        attempt_count,next_attempt_at,created_at,updated_at)
                     VALUES
                       (101,1,'deliv_malformed_retry',0,'retry',0,'zzzz-not-a-time',
                        '2026-07-30T11:30:00.000Z','2026-07-30T11:30:00.000Z');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let malformed = store
            .next_email_delivery(user_id)
            .await
            .unwrap()
            .expect("malformed retry is surfaced");
        assert_eq!(malformed.delivery_id, "deliv_malformed_retry");
    }
}
