#![allow(
    dead_code,
    reason = "this deliberately private, inactive witness contract is compiled and unit-tested before ADR-0022 shadow-gate wiring"
)]

//! Inactive, content-free witness contract for ADR-0022 archive-v3 shadow recovery.
//!
//! The witness is the future authority for one exact immutable root, its
//! archive key-registry commitment, and writer fencing.  Recovery receives
//! only that exact nominated object/hash pair; it must never search a prefix
//! or choose a plausible immutable object.  This module has no network,
//! storage-provider, `Store`, VFS, route, or production-authority wiring.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::Mutex,
};

use thiserror::Error;

use crate::archive_v3::{ArchiveId, DatabaseEpoch, KeyEpoch, KeyKind, ObjectId};

const WITNESS_MAGIC: &[u8; 8] = b"KAWITv1\0";
const WITNESS_VERSION: u8 = 1;
/// The one fixed-size encoded witness record.  Decoders reject every other
/// length rather than allocating from provider-supplied length fields.
pub const WITNESS_RECORD_BYTES: usize = 164;
const MAX_LEASE_TICKS: u64 = 86_400;
const MAX_RESOLVED_OPERATIONS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum WitnessError {
    #[error("witness is unavailable")]
    Unavailable,
    #[error("witness archive record is absent")]
    MissingArchive,
    #[error("witness archive record already exists")]
    AlreadyExists,
    #[error("witness request is malformed")]
    Malformed,
    #[error("witness record is corrupted")]
    Corrupt,
    #[error("witness lease is absent, expired, or fenced")]
    Fenced,
    #[error("witness compare-and-advance precondition did not match")]
    CompareFailed,
    #[error("witness transition is invalid for the current state")]
    InvalidTransition,
    #[error("witness operation identifier was reused with different contents")]
    OperationMismatch,
    #[error("witness synchronization failed")]
    Synchronization,
}

type Result<T> = std::result::Result<T, WitnessError>;

/// Opaque idempotency key for a root transition.  It is intentionally not a
/// user/account identifier and its Debug form never reveals its bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WitnessOperationId([u8; 16]);

impl WitnessOperationId {
    pub const fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for WitnessOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WitnessOperationId(<opaque>)")
    }
}

/// Exact immutable-root reference nominated by the witness.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RootReference {
    sequence: u64,
    object_id: ObjectId,
    ciphertext_hash: [u8; 32],
}

impl RootReference {
    pub(crate) const fn new(sequence: u64, object_id: ObjectId, ciphertext_hash: [u8; 32]) -> Self {
        Self {
            sequence,
            object_id,
            ciphertext_hash,
        }
    }

    fn valid(&self) -> bool {
        nonzero_id(self.object_id.as_bytes()) && nonzero_hash(&self.ciphertext_hash)
    }
}

impl fmt::Debug for RootReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootReference(<opaque>)")
    }
}

/// Exact archive-key registry object nominated by the witness.  Media keys
/// are deliberately excluded: a root can never substitute a media registry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyRegistryReference {
    key_kind: KeyKind,
    key_epoch: KeyEpoch,
    object_id: ObjectId,
    ciphertext_hash: [u8; 32],
}

impl KeyRegistryReference {
    pub(crate) const fn new(
        key_epoch: KeyEpoch,
        object_id: ObjectId,
        ciphertext_hash: [u8; 32],
    ) -> Self {
        Self {
            key_kind: KeyKind::Archive,
            key_epoch,
            object_id,
            ciphertext_hash,
        }
    }

    fn valid_archive_registry(&self) -> bool {
        self.key_kind == KeyKind::Archive
            && nonzero_id(self.key_epoch.as_bytes())
            && nonzero_id(self.object_id.as_bytes())
            && nonzero_hash(&self.ciphertext_hash)
    }
}

impl fmt::Debug for KeyRegistryReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyRegistryReference(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MigrationState {
    Legacy = 0,
    Shadow = 1,
    WalAuthoritative = 2,
    ExtentShadow = 3,
    ExtentAuthoritative = 4,
}

impl MigrationState {
    fn decode(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::Shadow),
            2 => Ok(Self::WalAuthoritative),
            3 => Ok(Self::ExtentShadow),
            4 => Ok(Self::ExtentAuthoritative),
            _ => Err(WitnessError::Corrupt),
        }
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::Legacy => Some(Self::Shadow),
            Self::Shadow => Some(Self::WalAuthoritative),
            Self::WalAuthoritative => Some(Self::ExtentShadow),
            Self::ExtentShadow => Some(Self::ExtentAuthoritative),
            Self::ExtentAuthoritative => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeletionState {
    Active = 0,
    Tombstoned = 1,
    CryptographicallyErased = 2,
    LogicalObjectsAbsent = 3,
    PhysicalComplete = 4,
}

impl DeletionState {
    fn decode(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Active),
            1 => Ok(Self::Tombstoned),
            2 => Ok(Self::CryptographicallyErased),
            3 => Ok(Self::LogicalObjectsAbsent),
            4 => Ok(Self::PhysicalComplete),
            _ => Err(WitnessError::Corrupt),
        }
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::Active => Some(Self::Tombstoned),
            Self::Tombstoned => Some(Self::CryptographicallyErased),
            Self::CryptographicallyErased => Some(Self::LogicalObjectsAbsent),
            Self::LogicalObjectsAbsent => Some(Self::PhysicalComplete),
            Self::PhysicalComplete => None,
        }
    }
}

/// Bounded current witness state.  This is exactly the recovery authority,
/// not a directory of storage-provider prefixes or object listings.
#[derive(Clone, PartialEq, Eq)]
pub struct WitnessRecord {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    root: RootReference,
    registry: KeyRegistryReference,
    migration: MigrationState,
    deletion: DeletionState,
}

impl WitnessRecord {
    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub fn database_epoch(&self) -> DatabaseEpoch {
        self.database_epoch
    }

    pub fn root(&self) -> RootReference {
        self.root
    }

    pub fn registry(&self) -> KeyRegistryReference {
        self.registry
    }

    pub fn migration(&self) -> MigrationState {
        self.migration
    }

    pub fn deletion(&self) -> DeletionState {
        self.deletion
    }

    fn valid(&self) -> bool {
        nonzero_id(self.archive_id.as_bytes())
            && nonzero_id(self.database_epoch.as_bytes())
            && self.root.valid()
            && self.registry.valid_archive_registry()
    }

    /// Fixed-size, content-free provider-record encoding.
    pub fn encode(&self) -> [u8; WITNESS_RECORD_BYTES] {
        let mut out = [0u8; WITNESS_RECORD_BYTES];
        let mut offset = 0;
        put(&mut out, &mut offset, WITNESS_MAGIC);
        put(&mut out, &mut offset, &[WITNESS_VERSION]);
        put(&mut out, &mut offset, self.archive_id.as_bytes());
        put(&mut out, &mut offset, self.database_epoch.as_bytes());
        put(&mut out, &mut offset, &self.root.sequence.to_be_bytes());
        put(&mut out, &mut offset, self.root.object_id.as_bytes());
        put(&mut out, &mut offset, &self.root.ciphertext_hash);
        put(&mut out, &mut offset, &[self.registry.key_kind as u8]);
        put(&mut out, &mut offset, self.registry.key_epoch.as_bytes());
        put(&mut out, &mut offset, self.registry.object_id.as_bytes());
        put(&mut out, &mut offset, &self.registry.ciphertext_hash);
        put(
            &mut out,
            &mut offset,
            &[self.migration as u8, self.deletion as u8],
        );
        debug_assert_eq!(offset, WITNESS_RECORD_BYTES);
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != WITNESS_RECORD_BYTES {
            return Err(WitnessError::Corrupt);
        }
        let mut offset = 0;
        if take(input, &mut offset, WITNESS_MAGIC.len())? != WITNESS_MAGIC
            || take(input, &mut offset, 1)?[0] != WITNESS_VERSION
        {
            return Err(WitnessError::Corrupt);
        }
        let archive_id = ArchiveId::from_bytes(take_array(take(input, &mut offset, 16)?)?);
        let database_epoch = DatabaseEpoch::from_bytes(take_array(take(input, &mut offset, 16)?)?);
        let sequence = u64::from_be_bytes(take_array(take(input, &mut offset, 8)?)?);
        let root_object = ObjectId::from_bytes(take_array(take(input, &mut offset, 16)?)?);
        let root_hash = take_array(take(input, &mut offset, 32)?)?;
        let key_kind = match take(input, &mut offset, 1)?[0] {
            1 => KeyKind::Archive,
            2 => KeyKind::Media,
            _ => return Err(WitnessError::Corrupt),
        };
        let key_epoch = KeyEpoch::from_bytes(take_array(take(input, &mut offset, 16)?)?);
        let registry_object = ObjectId::from_bytes(take_array(take(input, &mut offset, 16)?)?);
        let registry_hash = take_array(take(input, &mut offset, 32)?)?;
        let migration = MigrationState::decode(take(input, &mut offset, 1)?[0])?;
        let deletion = DeletionState::decode(take(input, &mut offset, 1)?[0])?;
        if offset != input.len() {
            return Err(WitnessError::Corrupt);
        }
        let record = Self {
            archive_id,
            database_epoch,
            root: RootReference {
                sequence,
                object_id: root_object,
                ciphertext_hash: root_hash,
            },
            registry: KeyRegistryReference {
                key_kind,
                key_epoch,
                object_id: registry_object,
                ciphertext_hash: registry_hash,
            },
            migration,
            deletion,
        };
        record
            .valid()
            .then_some(record)
            .ok_or(WitnessError::Corrupt)
    }
}

impl fmt::Debug for WitnessRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WitnessRecord(<content-free opaque commitments>)")
    }
}

/// Bootstrap is intentionally explicit: it nominates one genesis root and one
/// archive key registry, without consulting a storage-provider listing.
#[derive(Clone, PartialEq, Eq)]
pub struct WitnessBootstrap {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    genesis_root: RootReference,
    registry: KeyRegistryReference,
}

impl WitnessBootstrap {
    pub(crate) const fn new(
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        genesis_root: RootReference,
        registry: KeyRegistryReference,
    ) -> Self {
        Self {
            archive_id,
            database_epoch,
            genesis_root,
            registry,
        }
    }
}

impl fmt::Debug for WitnessBootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WitnessBootstrap(<opaque>)")
    }
}

/// Lease token returned only by a successful fenced acquire/renew operation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WitnessLease {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: KeyEpoch,
    owner: ObjectId,
    fencing_epoch: u64,
    expires_at_tick: u64,
}

impl fmt::Debug for WitnessLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WitnessLease(<opaque>)")
    }
}

/// Complete compare-and-advance precondition and candidate.  A caller must
/// supply the parent sequence/hash and the exact candidate object/hash in the
/// same fenced operation.
#[derive(Clone, PartialEq, Eq)]
pub struct RootAdvance {
    operation_id: WitnessOperationId,
    lease: WitnessLease,
    now_tick: u64,
    expected_parent: RootReference,
    expected_registry: KeyRegistryReference,
    candidate_database_epoch: DatabaseEpoch,
    candidate_key_epoch: KeyEpoch,
    candidate: RootReference,
}

impl RootAdvance {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        operation_id: WitnessOperationId,
        lease: WitnessLease,
        now_tick: u64,
        expected_parent: RootReference,
        expected_registry: KeyRegistryReference,
        candidate_database_epoch: DatabaseEpoch,
        candidate_key_epoch: KeyEpoch,
        candidate: RootReference,
    ) -> Self {
        Self {
            operation_id,
            lease,
            now_tick,
            expected_parent,
            expected_registry,
            candidate_database_epoch,
            candidate_key_epoch,
            candidate,
        }
    }
}

impl fmt::Debug for RootAdvance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootAdvance(<opaque>)")
    }
}

/// Exact witness result retained for idempotent lost-success resolution.
#[derive(Clone, PartialEq, Eq)]
pub struct WitnessReceipt {
    record: WitnessRecord,
}

impl WitnessReceipt {
    pub fn record(&self) -> &WitnessRecord {
        &self.record
    }
}

impl fmt::Debug for WitnessReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WitnessReceipt(<opaque>)")
    }
}

/// Content-free witness operations.  Provider implementations must make each
/// mutation linearizable; no caller may compose a read, a listing, and a later
/// write in lieu of the compare-and-advance operation.
pub trait Witness: Send + Sync {
    fn read_current(&self, archive_id: ArchiveId) -> Result<Option<WitnessRecord>>;
    fn recovery_root(&self, archive_id: ArchiveId) -> Result<RecoveryRoot>;
    fn acquire_lease(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        owner: ObjectId,
        now_tick: u64,
        duration_ticks: u64,
    ) -> Result<WitnessLease>;
    fn renew_lease(
        &self,
        lease: WitnessLease,
        now_tick: u64,
        duration_ticks: u64,
    ) -> Result<WitnessLease>;
    fn revoke_lease(&self, lease: WitnessLease, now_tick: u64) -> Result<()>;
    fn compare_and_advance_root(&self, advance: RootAdvance) -> Result<WitnessReceipt>;
    fn advance_migration(
        &self,
        advance: RootAdvance,
        next: MigrationState,
    ) -> Result<WitnessReceipt>;
    fn advance_deletion(&self, advance: RootAdvance, next: DeletionState)
        -> Result<WitnessReceipt>;
    fn rotate_key_registry(
        &self,
        advance: RootAdvance,
        next: KeyRegistryReference,
    ) -> Result<WitnessReceipt>;
    fn resolve_operation(
        &self,
        archive_id: ArchiveId,
        operation_id: WitnessOperationId,
    ) -> Result<Option<WitnessReceipt>>;
}

/// Exact root and archive key registry accepted for cold recovery.  The caller
/// may fetch only these immutable object ids and verify these hashes.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryRoot {
    root: RootReference,
    registry: KeyRegistryReference,
    migration: MigrationState,
    deletion: DeletionState,
}

impl fmt::Debug for RecoveryRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryRoot(<opaque witness nomination>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Transition {
    Root,
    Migration(MigrationState),
    Deletion(DeletionState),
    Rotation(KeyRegistryReference),
}

#[derive(Clone)]
struct ResolvedOperation {
    operation_id: WitnessOperationId,
    advance: RootAdvance,
    transition: Transition,
    receipt: WitnessReceipt,
}

struct LeaseState {
    lease: WitnessLease,
}

struct ArchiveState {
    record: WitnessRecord,
    lease: Option<LeaseState>,
    next_fencing_epoch: u64,
    resolved: VecDeque<ResolvedOperation>,
}

struct InMemoryState {
    available: bool,
    archives: BTreeMap<ArchiveId, ArchiveState>,
}

/// Mutex-backed model used only by contract tests.  One critical section per
/// operation is the linearization point; it intentionally provides no durable
/// storage or production failure semantics.
pub struct InMemoryWitness {
    state: Mutex<InMemoryState>,
}

impl InMemoryWitness {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(InMemoryState {
                available: true,
                archives: BTreeMap::new(),
            }),
        }
    }

    pub fn bootstrap(&self, bootstrap: WitnessBootstrap) -> Result<WitnessRecord> {
        if !valid_bootstrap(&bootstrap) {
            return Err(WitnessError::Malformed);
        }
        let mut state = self.lock()?;
        ensure_available(&state)?;
        if state.archives.contains_key(&bootstrap.archive_id) {
            return Err(WitnessError::AlreadyExists);
        }
        let record = WitnessRecord {
            archive_id: bootstrap.archive_id,
            database_epoch: bootstrap.database_epoch,
            root: bootstrap.genesis_root,
            registry: bootstrap.registry,
            migration: MigrationState::Legacy,
            deletion: DeletionState::Active,
        };
        state.archives.insert(
            bootstrap.archive_id,
            ArchiveState {
                record: record.clone(),
                lease: None,
                next_fencing_epoch: 1,
                resolved: VecDeque::new(),
            },
        );
        Ok(record)
    }

    #[cfg(test)]
    fn set_available_for_test(&self, available: bool) {
        self.state.lock().expect("test witness lock").available = available;
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, InMemoryState>> {
        self.state.lock().map_err(|_| WitnessError::Synchronization)
    }

    fn apply(&self, advance: RootAdvance, transition: Transition) -> Result<WitnessReceipt> {
        let mut state = self.lock()?;
        ensure_available(&state)?;
        let archive = state
            .archives
            .get_mut(&advance.lease.archive_id)
            .ok_or(WitnessError::MissingArchive)?;

        if let Some(existing) = archive
            .resolved
            .iter()
            .find(|item| item.operation_id == advance.operation_id)
        {
            return if existing.advance == advance && existing.transition == transition {
                Ok(existing.receipt.clone())
            } else {
                Err(WitnessError::OperationMismatch)
            };
        }

        validate_advance(archive, &advance, &transition)?;
        apply_transition(&mut archive.record, &transition);
        archive.record.root = advance.candidate;
        let receipt = WitnessReceipt {
            record: archive.record.clone(),
        };
        archive.resolved.push_back(ResolvedOperation {
            operation_id: advance.operation_id,
            advance,
            transition,
            receipt: receipt.clone(),
        });
        if archive.resolved.len() > MAX_RESOLVED_OPERATIONS {
            let _ = archive.resolved.pop_front();
        }
        Ok(receipt)
    }
}

impl Default for InMemoryWitness {
    fn default() -> Self {
        Self::new()
    }
}

impl Witness for InMemoryWitness {
    fn read_current(&self, archive_id: ArchiveId) -> Result<Option<WitnessRecord>> {
        let state = self.lock()?;
        ensure_available(&state)?;
        Ok(state
            .archives
            .get(&archive_id)
            .map(|entry| entry.record.clone()))
    }

    fn recovery_root(&self, archive_id: ArchiveId) -> Result<RecoveryRoot> {
        let state = self.lock()?;
        ensure_available(&state)?;
        let record = &state
            .archives
            .get(&archive_id)
            .ok_or(WitnessError::MissingArchive)?
            .record;
        Ok(RecoveryRoot {
            root: record.root,
            registry: record.registry,
            migration: record.migration,
            deletion: record.deletion,
        })
    }

    fn acquire_lease(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        owner: ObjectId,
        now_tick: u64,
        duration_ticks: u64,
    ) -> Result<WitnessLease> {
        let expires_at_tick = checked_expiry(now_tick, duration_ticks)?;
        if !nonzero_id(owner.as_bytes()) {
            return Err(WitnessError::Malformed);
        }
        let mut state = self.lock()?;
        ensure_available(&state)?;
        let archive = state
            .archives
            .get_mut(&archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        if archive.record.database_epoch != database_epoch
            || archive.record.registry.key_epoch != key_epoch
        {
            return Err(WitnessError::CompareFailed);
        }
        if archive
            .lease
            .as_ref()
            .is_some_and(|current| now_tick < current.lease.expires_at_tick)
        {
            return Err(WitnessError::Fenced);
        }
        let fencing_epoch = archive.next_fencing_epoch;
        archive.next_fencing_epoch = fencing_epoch
            .checked_add(1)
            .ok_or(WitnessError::Malformed)?;
        let lease = WitnessLease {
            archive_id,
            database_epoch,
            key_epoch,
            owner,
            fencing_epoch,
            expires_at_tick,
        };
        archive.lease = Some(LeaseState { lease });
        Ok(lease)
    }

    fn renew_lease(
        &self,
        lease: WitnessLease,
        now_tick: u64,
        duration_ticks: u64,
    ) -> Result<WitnessLease> {
        let expires_at_tick = checked_expiry(now_tick, duration_ticks)?;
        let mut state = self.lock()?;
        ensure_available(&state)?;
        let archive = state
            .archives
            .get_mut(&lease.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        validate_live_lease(archive, lease, now_tick)?;
        let renewed = WitnessLease {
            expires_at_tick,
            ..lease
        };
        archive.lease = Some(LeaseState { lease: renewed });
        Ok(renewed)
    }

    fn revoke_lease(&self, lease: WitnessLease, now_tick: u64) -> Result<()> {
        let mut state = self.lock()?;
        ensure_available(&state)?;
        let archive = state
            .archives
            .get_mut(&lease.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        validate_live_lease(archive, lease, now_tick)?;
        archive.lease = None;
        Ok(())
    }

    fn compare_and_advance_root(&self, advance: RootAdvance) -> Result<WitnessReceipt> {
        self.apply(advance, Transition::Root)
    }

    fn advance_migration(
        &self,
        advance: RootAdvance,
        next: MigrationState,
    ) -> Result<WitnessReceipt> {
        self.apply(advance, Transition::Migration(next))
    }

    fn advance_deletion(
        &self,
        advance: RootAdvance,
        next: DeletionState,
    ) -> Result<WitnessReceipt> {
        self.apply(advance, Transition::Deletion(next))
    }

    fn rotate_key_registry(
        &self,
        advance: RootAdvance,
        next: KeyRegistryReference,
    ) -> Result<WitnessReceipt> {
        self.apply(advance, Transition::Rotation(next))
    }

    fn resolve_operation(
        &self,
        archive_id: ArchiveId,
        operation_id: WitnessOperationId,
    ) -> Result<Option<WitnessReceipt>> {
        let state = self.lock()?;
        ensure_available(&state)?;
        Ok(state.archives.get(&archive_id).and_then(|archive| {
            archive
                .resolved
                .iter()
                .find(|item| item.operation_id == operation_id)
                .map(|item| item.receipt.clone())
        }))
    }
}

fn valid_bootstrap(bootstrap: &WitnessBootstrap) -> bool {
    nonzero_id(bootstrap.archive_id.as_bytes())
        && nonzero_id(bootstrap.database_epoch.as_bytes())
        && bootstrap.genesis_root.sequence == 0
        && bootstrap.genesis_root.valid()
        && bootstrap.registry.valid_archive_registry()
        && bootstrap.registry.key_epoch != KeyEpoch::from_bytes([0; 16])
}

fn validate_advance(
    archive: &ArchiveState,
    advance: &RootAdvance,
    transition: &Transition,
) -> Result<()> {
    let record = &archive.record;
    if !advance.expected_parent.valid()
        || !advance.expected_registry.valid_archive_registry()
        || !advance.candidate.valid()
        || advance.lease.archive_id != record.archive_id
        || advance.lease.database_epoch != record.database_epoch
        || advance.candidate_database_epoch != record.database_epoch
        || advance.expected_parent != record.root
        || advance.expected_registry != record.registry
        || advance.candidate.sequence
            != record
                .root
                .sequence
                .checked_add(1)
                .ok_or(WitnessError::Malformed)?
        || advance.candidate.object_id == record.root.object_id
    {
        return Err(WitnessError::CompareFailed);
    }
    validate_live_lease(archive, advance.lease, advance.now_tick)?;
    match transition {
        Transition::Root => {
            if record.deletion != DeletionState::Active
                || advance.lease.key_epoch != record.registry.key_epoch
                || advance.candidate_key_epoch != record.registry.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
        Transition::Migration(next) => {
            if record.deletion != DeletionState::Active
                || record.migration.next() != Some(*next)
                || advance.lease.key_epoch != record.registry.key_epoch
                || advance.candidate_key_epoch != record.registry.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
        Transition::Deletion(next) => {
            if record.deletion.next() != Some(*next)
                || advance.lease.key_epoch != record.registry.key_epoch
                || advance.candidate_key_epoch != record.registry.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
        Transition::Rotation(next) => {
            if record.deletion != DeletionState::Active
                || !next.valid_archive_registry()
                || next == &record.registry
                || next.key_epoch == record.registry.key_epoch
                || advance.lease.key_epoch != record.registry.key_epoch
                || advance.candidate_key_epoch != next.key_epoch
                || advance.candidate.sequence
                    != record
                        .root
                        .sequence
                        .checked_add(1)
                        .ok_or(WitnessError::Malformed)?
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
    }
    Ok(())
}

fn apply_transition(record: &mut WitnessRecord, transition: &Transition) {
    match transition {
        Transition::Root => {}
        Transition::Migration(next) => record.migration = *next,
        Transition::Deletion(next) => record.deletion = *next,
        Transition::Rotation(next) => record.registry = *next,
    }
}

fn validate_live_lease(archive: &ArchiveState, lease: WitnessLease, now_tick: u64) -> Result<()> {
    let current = archive.lease.as_ref().ok_or(WitnessError::Fenced)?.lease;
    if current != lease
        || now_tick >= current.expires_at_tick
        || lease.database_epoch != archive.record.database_epoch
        || lease.key_epoch != archive.record.registry.key_epoch
    {
        return Err(WitnessError::Fenced);
    }
    Ok(())
}

fn checked_expiry(now_tick: u64, duration_ticks: u64) -> Result<u64> {
    if !(1..=MAX_LEASE_TICKS).contains(&duration_ticks) {
        return Err(WitnessError::Malformed);
    }
    now_tick
        .checked_add(duration_ticks)
        .ok_or(WitnessError::Malformed)
}

fn ensure_available(state: &InMemoryState) -> Result<()> {
    state
        .available
        .then_some(())
        .ok_or(WitnessError::Unavailable)
}

fn nonzero_id(value: &[u8; 16]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn nonzero_hash(value: &[u8; 32]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn put<const N: usize>(out: &mut [u8; N], offset: &mut usize, value: &[u8]) {
    let end = *offset + value.len();
    out[*offset..end].copy_from_slice(value);
    *offset = end;
}

fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(length).ok_or(WitnessError::Corrupt)?;
    let value = input.get(*offset..end).ok_or(WitnessError::Corrupt)?;
    *offset = end;
    Ok(value)
}

fn take_array<const N: usize>(input: &[u8]) -> Result<[u8; N]> {
    input.try_into().map_err(|_| WitnessError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn bootstrap() -> WitnessBootstrap {
        WitnessBootstrap {
            archive_id: ArchiveId::from_bytes(id(1)),
            database_epoch: DatabaseEpoch::from_bytes(id(2)),
            genesis_root: RootReference {
                sequence: 0,
                object_id: ObjectId::from_bytes(id(3)),
                ciphertext_hash: hash(4),
            },
            registry: KeyRegistryReference {
                key_kind: KeyKind::Archive,
                key_epoch: KeyEpoch::from_bytes(id(5)),
                object_id: ObjectId::from_bytes(id(6)),
                ciphertext_hash: hash(7),
            },
        }
    }

    fn setup() -> (InMemoryWitness, WitnessRecord, WitnessLease) {
        let witness = InMemoryWitness::new();
        let record = witness.bootstrap(bootstrap()).unwrap();
        let lease = witness
            .acquire_lease(
                record.archive_id,
                record.database_epoch,
                record.registry.key_epoch,
                ObjectId::from_bytes(id(8)),
                10,
                20,
            )
            .unwrap();
        (witness, record, lease)
    }

    fn advance(record: &WitnessRecord, lease: WitnessLease, operation: u8) -> RootAdvance {
        RootAdvance {
            operation_id: WitnessOperationId::from_bytes(id(operation)),
            lease,
            now_tick: 11,
            expected_parent: record.root,
            expected_registry: record.registry,
            candidate_database_epoch: record.database_epoch,
            candidate_key_epoch: record.registry.key_epoch,
            candidate: RootReference {
                sequence: record.root.sequence + 1,
                object_id: ObjectId::from_bytes(id(operation.wrapping_add(20))),
                ciphertext_hash: hash(operation.wrapping_add(30)),
            },
        }
    }

    #[test]
    fn recovery_returns_only_the_exact_witness_nominated_root() {
        let (witness, record, lease) = setup();
        let committed = witness
            .compare_and_advance_root(advance(&record, lease, 9))
            .unwrap();
        let recovery = witness.recovery_root(record.archive_id).unwrap();
        assert_eq!(recovery.root, committed.record.root);
        assert_eq!(recovery.registry, committed.record.registry);
    }

    #[test]
    fn stale_fence_and_expired_lease_cannot_advance() {
        let (witness, record, stale) = setup();
        let fresh = witness
            .acquire_lease(
                record.archive_id,
                record.database_epoch,
                record.registry.key_epoch,
                ObjectId::from_bytes(id(10)),
                31,
                20,
            )
            .unwrap();
        assert_eq!(
            witness.compare_and_advance_root(advance(&record, stale, 11)),
            Err(WitnessError::Fenced)
        );
        assert!(witness
            .compare_and_advance_root(advance(&record, fresh, 12))
            .is_ok());
    }

    #[test]
    fn renewal_requires_the_exact_fence_and_revoke_blocks_the_old_lease() {
        let (witness, record, lease) = setup();
        let renewed = witness.renew_lease(lease, 11, 20).unwrap();
        assert_eq!(
            witness.renew_lease(lease, 12, 20),
            Err(WitnessError::Fenced)
        );
        witness.revoke_lease(renewed, 12).unwrap();
        assert_eq!(
            witness.compare_and_advance_root(advance(&record, renewed, 13)),
            Err(WitnessError::Fenced)
        );
    }

    #[test]
    fn compare_and_advance_rejects_cas_races_and_wrong_candidates() {
        let (witness, record, lease) = setup();
        let first = advance(&record, lease, 9);
        let second = advance(&record, lease, 10);
        witness.compare_and_advance_root(first).unwrap();
        assert_eq!(
            witness.compare_and_advance_root(second),
            Err(WitnessError::CompareFailed)
        );

        let (witness, record, lease) = setup();
        let mut wrong = advance(&record, lease, 11);
        wrong.candidate.sequence += 1;
        assert_eq!(
            witness.compare_and_advance_root(wrong),
            Err(WitnessError::CompareFailed)
        );
        let mut wrong_epoch = advance(&record, lease, 12);
        wrong_epoch.candidate_database_epoch = DatabaseEpoch::from_bytes(id(99));
        assert_eq!(
            witness.compare_and_advance_root(wrong_epoch),
            Err(WitnessError::CompareFailed)
        );
    }

    #[test]
    fn lost_success_is_resolved_only_for_the_same_operation_contents() {
        let (witness, record, lease) = setup();
        let request = advance(&record, lease, 9);
        let first = witness.compare_and_advance_root(request.clone()).unwrap();
        let retried = witness.compare_and_advance_root(request.clone()).unwrap();
        assert_eq!(first, retried);
        assert_eq!(
            witness
                .resolve_operation(record.archive_id, request.operation_id)
                .unwrap(),
            Some(first.clone())
        );
        let mut changed = request;
        changed.candidate.ciphertext_hash = hash(99);
        assert_eq!(
            witness.compare_and_advance_root(changed),
            Err(WitnessError::OperationMismatch)
        );
    }

    #[test]
    fn key_registry_rotation_requires_the_exact_old_registry_and_new_epoch() {
        let (witness, record, lease) = setup();
        let mut request = advance(&record, lease, 9);
        let next = KeyRegistryReference {
            key_kind: KeyKind::Archive,
            key_epoch: KeyEpoch::from_bytes(id(11)),
            object_id: ObjectId::from_bytes(id(12)),
            ciphertext_hash: hash(13),
        };
        request.candidate_key_epoch = next.key_epoch;
        assert!(witness.rotate_key_registry(request.clone(), next).is_ok());

        let (witness, record, lease) = setup();
        request.expected_registry.object_id = ObjectId::from_bytes(id(99));
        assert_eq!(
            witness.rotate_key_registry(request, next),
            Err(WitnessError::CompareFailed)
        );
        let same_epoch = KeyRegistryReference {
            key_epoch: record.registry.key_epoch,
            ..next
        };
        let mut same_epoch_request = advance(&record, lease, 10);
        same_epoch_request.candidate_key_epoch = same_epoch.key_epoch;
        assert_eq!(
            witness.rotate_key_registry(same_epoch_request, same_epoch),
            Err(WitnessError::InvalidTransition)
        );
    }

    #[test]
    fn migration_and_deletion_are_forward_only_and_tombstone_blocks_writes() {
        let (witness, record, lease) = setup();
        let shadow = witness
            .advance_migration(advance(&record, lease, 9), MigrationState::Shadow)
            .unwrap();
        let tombstoned = witness
            .advance_deletion(
                advance(shadow.record(), lease, 10),
                DeletionState::Tombstoned,
            )
            .unwrap();
        assert_eq!(tombstoned.record.deletion, DeletionState::Tombstoned);
        assert_eq!(
            witness.compare_and_advance_root(advance(tombstoned.record(), lease, 11)),
            Err(WitnessError::InvalidTransition)
        );
        assert_eq!(
            witness.advance_migration(
                advance(tombstoned.record(), lease, 12),
                MigrationState::WalAuthoritative,
            ),
            Err(WitnessError::InvalidTransition)
        );
    }

    #[test]
    fn fixed_record_decoder_rejects_tamper_truncation_and_invalid_registry_kind() {
        let (_, record, _) = setup();
        let encoded = record.encode();
        assert_eq!(WitnessRecord::decode(&encoded).unwrap(), record);
        assert_eq!(
            WitnessRecord::decode(&encoded[..WITNESS_RECORD_BYTES - 1]),
            Err(WitnessError::Corrupt)
        );
        let mut tampered = encoded;
        tampered[0] ^= 1;
        assert_eq!(WitnessRecord::decode(&tampered), Err(WitnessError::Corrupt));
        let mut media_registry = encoded;
        media_registry[97] = KeyKind::Media as u8;
        assert_eq!(
            WitnessRecord::decode(&media_registry),
            Err(WitnessError::Corrupt)
        );
    }

    #[test]
    fn unavailable_witness_fails_closed_and_debug_is_content_free() {
        let (witness, record, lease) = setup();
        witness.set_available_for_test(false);
        assert_eq!(
            witness.read_current(record.archive_id),
            Err(WitnessError::Unavailable)
        );
        assert_eq!(
            witness.compare_and_advance_root(advance(&record, lease, 9)),
            Err(WitnessError::Unavailable)
        );
        let debug = format!(
            "{record:?} {lease:?} {:?}",
            WitnessOperationId::from_bytes([0xaa; 16])
        );
        assert!(!debug.contains("aa"));
        assert!(!debug.contains("01"));
    }
}
