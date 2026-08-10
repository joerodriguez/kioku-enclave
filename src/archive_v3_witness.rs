#![allow(dead_code, reason = "inactive ADR-0022 witness contract")]
//! Content-free, inactive ADR-0022 witness contract. Provider persistence is
//! fixed-size and contains every lease/fence/root commitment needed after restart.

use crate::archive_v3::{ArchiveId, DatabaseEpoch, KeyEpoch, KeyKind, ObjectId};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"KAWITv2\0";
const VERSION: u8 = 2;
pub const WITNESS_RECORD_BYTES: usize = 423;
const MAX_LEASE_TICKS: u64 = 86_400;

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
    #[error("trusted witness clock regressed or is unavailable")]
    Clock,
    #[error("witness lease is absent, expired, or fenced")]
    Fenced,
    #[error("witness compare-and-advance precondition did not match")]
    CompareFailed,
    #[error("witness transition is invalid for the current state")]
    InvalidTransition,
    #[error("witness synchronization failed")]
    Synchronization,
}
type Result<T> = std::result::Result<T, WitnessError>;

/// Production providers derive this inside their transaction. Callers never supply time.
trait TrustedClock: Send + Sync {
    fn now_tick(&self) -> Result<u64>;
}
struct SystemClock;
impl TrustedClock for SystemClock {
    fn now_tick(&self) -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WitnessError::Clock)
            .map(|v| v.as_secs())
    }
}

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
    fn valid(self) -> bool {
        nonzero_id(self.object_id.as_bytes()) && nonzero_hash(&self.ciphertext_hash)
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn object_id(&self) -> ObjectId {
        self.object_id
    }

    pub fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }
}
impl fmt::Debug for RootReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootReference(<opaque>)")
    }
}

/// Header fields independently verified from the encrypted root before witness CAS.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RootCommitment {
    root: RootReference,
    parent: Option<RootReference>,
    database_epoch: DatabaseEpoch,
    key_epoch: KeyEpoch,
    owner_fencing_epoch: u64,
}
impl RootCommitment {
    pub(crate) const fn genesis(
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        root: RootReference,
    ) -> Self {
        Self {
            root,
            parent: None,
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 0,
        }
    }
    pub(crate) const fn candidate(
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        owner_fencing_epoch: u64,
        parent: RootReference,
        root: RootReference,
    ) -> Self {
        Self {
            root,
            parent: Some(parent),
            database_epoch,
            key_epoch,
            owner_fencing_epoch,
        }
    }
    fn valid(self) -> bool {
        nonzero_id(self.database_epoch.as_bytes())
            && nonzero_id(self.key_epoch.as_bytes())
            && self.root.valid()
            && match self.parent {
                None => self.root.sequence == 0 && self.owner_fencing_epoch == 0,
                Some(parent) => {
                    parent.valid()
                        && parent.sequence.checked_add(1) == Some(self.root.sequence)
                        && self.owner_fencing_epoch != 0
                }
            }
    }

    pub fn root(&self) -> RootReference {
        self.root
    }

    pub fn parent(&self) -> Option<RootReference> {
        self.parent
    }

    pub fn database_epoch(&self) -> DatabaseEpoch {
        self.database_epoch
    }

    pub fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    pub fn owner_fencing_epoch(&self) -> u64 {
        self.owner_fencing_epoch
    }
}
impl fmt::Debug for RootCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootCommitment(<opaque>)")
    }
}

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
    fn valid(self) -> bool {
        self.key_kind == KeyKind::Archive
            && nonzero_id(self.key_epoch.as_bytes())
            && nonzero_id(self.object_id.as_bytes())
            && nonzero_hash(&self.ciphertext_hash)
    }

    pub fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    pub fn object_id(&self) -> ObjectId {
        self.object_id
    }

    pub fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
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
    ShadowWal = 1,
    WalAuthoritative = 2,
    ShadowExtents = 3,
    ExtentAuthoritative = 4,
    LegacyRetired = 5,
    Deleting = 6,
    Deleted = 7,
}
impl MigrationState {
    fn decode(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::ShadowWal),
            2 => Ok(Self::WalAuthoritative),
            3 => Ok(Self::ShadowExtents),
            4 => Ok(Self::ExtentAuthoritative),
            5 => Ok(Self::LegacyRetired),
            6 => Ok(Self::Deleting),
            7 => Ok(Self::Deleted),
            _ => Err(WitnessError::Corrupt),
        }
    }
    fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Legacy, Self::ShadowWal)
                | (Self::Legacy, Self::ShadowExtents)
                | (Self::ShadowWal, Self::WalAuthoritative)
                | (Self::WalAuthoritative, Self::ShadowExtents)
                | (Self::ShadowExtents, Self::ExtentAuthoritative)
                | (Self::ExtentAuthoritative, Self::LegacyRetired)
        )
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
    fn decode(v: u8) -> Result<Self> {
        match v {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeletionEvidenceKind {
    Tombstone = 1,
    KeyErasure = 2,
    Inventory = 3,
    Retention = 4,
}
impl DeletionEvidenceKind {
    fn decode(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Tombstone),
            2 => Ok(Self::KeyErasure),
            3 => Ok(Self::Inventory),
            4 => Ok(Self::Retention),
            _ => Err(WitnessError::Corrupt),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeletionEvidence {
    kind: DeletionEvidenceKind,
    commitment: [u8; 32],
}
impl DeletionEvidence {
    pub(crate) const fn new(kind: DeletionEvidenceKind, commitment: [u8; 32]) -> Self {
        Self { kind, commitment }
    }
    fn valid_for(self, state: DeletionState) -> bool {
        nonzero_hash(&self.commitment)
            && matches!(
                (state, self.kind),
                (DeletionState::Tombstoned, DeletionEvidenceKind::Tombstone)
                    | (
                        DeletionState::CryptographicallyErased,
                        DeletionEvidenceKind::KeyErasure
                    )
                    | (
                        DeletionState::LogicalObjectsAbsent,
                        DeletionEvidenceKind::Inventory
                    )
                    | (
                        DeletionState::PhysicalComplete,
                        DeletionEvidenceKind::Retention
                    )
            )
    }
}
impl fmt::Debug for DeletionEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeletionEvidence(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Predecessor {
    database_epoch: DatabaseEpoch,
    root: RootReference,
}

/// The entire durable provider state; no fencing state is local-only.
#[derive(Clone, PartialEq, Eq)]
pub struct WitnessRecord {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    predecessor: Option<Predecessor>,
    root: RootCommitment,
    registry: KeyRegistryReference,
    owner_id: Option<ObjectId>,
    current_fencing_epoch: u64,
    next_fencing_epoch: u64,
    lease_expires_at_tick: u64,
    deletion_fencing_epoch: Option<u64>,
    last_server_tick: u64,
    migration: MigrationState,
    deletion: DeletionState,
    deletion_evidence: Option<DeletionEvidence>,
}
impl WitnessRecord {
    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }
    pub fn database_epoch(&self) -> DatabaseEpoch {
        self.database_epoch
    }
    pub fn root(&self) -> RootCommitment {
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
            && self.root.database_epoch == self.database_epoch
            && self.root.key_epoch == self.registry.key_epoch
            && self.registry.valid()
            && self.next_fencing_epoch > self.current_fencing_epoch
            && match self.owner_id {
                Some(v) => nonzero_id(v.as_bytes()) && self.lease_expires_at_tick != 0,
                None => self.lease_expires_at_tick == 0,
            }
            && match self.deletion {
                DeletionState::Active => {
                    self.deletion_fencing_epoch.is_none() && self.deletion_evidence.is_none()
                }
                _ => {
                    self.deletion_fencing_epoch
                        .is_some_and(|v| v > self.current_fencing_epoch)
                        && self.deletion_evidence.is_some()
                }
            }
    }
    pub fn encode(&self) -> [u8; WITNESS_RECORD_BYTES] {
        let mut out = [0; WITNESS_RECORD_BYTES];
        let mut p = 0;
        put(&mut out, &mut p, MAGIC);
        put(&mut out, &mut p, &[VERSION]);
        put(&mut out, &mut p, self.archive_id.as_bytes());
        put(&mut out, &mut p, self.database_epoch.as_bytes());
        put(&mut out, &mut p, &[self.predecessor.is_some() as u8]);
        if let Some(x) = self.predecessor {
            put(&mut out, &mut p, x.database_epoch.as_bytes());
            root_put(&mut out, &mut p, x.root);
        } else {
            put(&mut out, &mut p, &[0; 16]);
            root_put(&mut out, &mut p, zero_root());
        }
        root_put(&mut out, &mut p, self.root.root);
        put(&mut out, &mut p, self.root.database_epoch.as_bytes());
        put(&mut out, &mut p, self.root.key_epoch.as_bytes());
        put(
            &mut out,
            &mut p,
            &self.root.owner_fencing_epoch.to_be_bytes(),
        );
        put(&mut out, &mut p, &[self.root.parent.is_some() as u8]);
        root_put(&mut out, &mut p, self.root.parent.unwrap_or_else(zero_root));
        put(&mut out, &mut p, self.registry.key_epoch.as_bytes());
        put(&mut out, &mut p, &[self.registry.key_kind as u8]);
        put(&mut out, &mut p, self.registry.object_id.as_bytes());
        put(&mut out, &mut p, &self.registry.ciphertext_hash);
        put(
            &mut out,
            &mut p,
            self.owner_id
                .unwrap_or_else(|| ObjectId::from_bytes([0; 16]))
                .as_bytes(),
        );
        put(&mut out, &mut p, &self.current_fencing_epoch.to_be_bytes());
        put(&mut out, &mut p, &self.next_fencing_epoch.to_be_bytes());
        put(&mut out, &mut p, &self.lease_expires_at_tick.to_be_bytes());
        put(
            &mut out,
            &mut p,
            &self.deletion_fencing_epoch.unwrap_or(0).to_be_bytes(),
        );
        put(&mut out, &mut p, &self.last_server_tick.to_be_bytes());
        put(
            &mut out,
            &mut p,
            &[self.migration as u8, self.deletion as u8],
        );
        if let Some(x) = self.deletion_evidence {
            put(&mut out, &mut p, &[x.kind as u8]);
            put(&mut out, &mut p, &x.commitment);
        } else {
            put(&mut out, &mut p, &[0]);
            put(&mut out, &mut p, &[0; 32]);
        }
        debug_assert_eq!(p, WITNESS_RECORD_BYTES);
        out
    }
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != WITNESS_RECORD_BYTES {
            return Err(WitnessError::Corrupt);
        }
        let mut p = 0;
        if take(input, &mut p, 8)? != MAGIC || take(input, &mut p, 1)?[0] != VERSION {
            return Err(WitnessError::Corrupt);
        }
        let archive_id = ArchiveId::from_bytes(array(take(input, &mut p, 16)?)?);
        let database_epoch = DatabaseEpoch::from_bytes(array(take(input, &mut p, 16)?)?);
        let predecessor_present = boolean(take(input, &mut p, 1)?[0])?;
        let pred_epoch = DatabaseEpoch::from_bytes(array(take(input, &mut p, 16)?)?);
        let pred_root = root_take(input, &mut p)?;
        let root_ref = root_take(input, &mut p)?;
        let root_db = DatabaseEpoch::from_bytes(array(take(input, &mut p, 16)?)?);
        let root_key = KeyEpoch::from_bytes(array(take(input, &mut p, 16)?)?);
        let root_fence = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let parent_present = boolean(take(input, &mut p, 1)?[0])?;
        let parent = root_take(input, &mut p)?;
        let registry_key = KeyEpoch::from_bytes(array(take(input, &mut p, 16)?)?);
        let registry_kind = key_kind(take(input, &mut p, 1)?[0])?;
        let registry_object = ObjectId::from_bytes(array(take(input, &mut p, 16)?)?);
        let registry_hash = array(take(input, &mut p, 32)?)?;
        let owner = ObjectId::from_bytes(array(take(input, &mut p, 16)?)?);
        let current = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let next = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let expiry = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let deletion_fence = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let last_tick = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let migration = MigrationState::decode(take(input, &mut p, 1)?[0])?;
        let deletion = DeletionState::decode(take(input, &mut p, 1)?[0])?;
        let evidence_kind = take(input, &mut p, 1)?[0];
        let evidence_hash = array(take(input, &mut p, 32)?)?;
        if p != input.len() {
            return Err(WitnessError::Corrupt);
        }
        let deletion_evidence = if evidence_kind == 0 {
            None
        } else {
            Some(DeletionEvidence {
                kind: DeletionEvidenceKind::decode(evidence_kind)?,
                commitment: evidence_hash,
            })
        };
        let record = Self {
            archive_id,
            database_epoch,
            predecessor: predecessor_present.then_some(Predecessor {
                database_epoch: pred_epoch,
                root: pred_root,
            }),
            root: RootCommitment {
                root: root_ref,
                parent: parent_present.then_some(parent),
                database_epoch: root_db,
                key_epoch: root_key,
                owner_fencing_epoch: root_fence,
            },
            registry: KeyRegistryReference {
                key_kind: registry_kind,
                key_epoch: registry_key,
                object_id: registry_object,
                ciphertext_hash: registry_hash,
            },
            owner_id: nonzero_id(owner.as_bytes()).then_some(owner),
            current_fencing_epoch: current,
            next_fencing_epoch: next,
            lease_expires_at_tick: expiry,
            deletion_fencing_epoch: (deletion_fence != 0).then_some(deletion_fence),
            last_server_tick: last_tick,
            migration,
            deletion,
            deletion_evidence,
        };
        record
            .valid()
            .then_some(record)
            .ok_or(WitnessError::Corrupt)
    }
}
impl fmt::Debug for WitnessRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WitnessRecord(<opaque>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WitnessBootstrap {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    genesis_root: RootCommitment,
    registry: KeyRegistryReference,
}
impl WitnessBootstrap {
    pub(crate) const fn new(
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        genesis_root: RootCommitment,
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeletionAuthorization {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    fencing_epoch: u64,
}
impl fmt::Debug for DeletionAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeletionAuthorization(<opaque>)")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct RootAdvance {
    lease: WitnessLease,
    expected_root: RootCommitment,
    expected_registry: KeyRegistryReference,
    candidate: RootCommitment,
}
impl RootAdvance {
    pub(crate) const fn new(
        lease: WitnessLease,
        expected_root: RootCommitment,
        expected_registry: KeyRegistryReference,
        candidate: RootCommitment,
    ) -> Self {
        Self {
            lease,
            expected_root,
            expected_registry,
            candidate,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeletionAdvance {
    authorization: DeletionAuthorization,
    expected_root: RootCommitment,
    expected_registry: KeyRegistryReference,
    candidate: RootCommitment,
    evidence: DeletionEvidence,
}
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
#[derive(Clone, PartialEq, Eq)]
pub struct TombstoneReceipt {
    receipt: WitnessReceipt,
    authorization: DeletionAuthorization,
}
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryRoot {
    root: RootCommitment,
    registry: KeyRegistryReference,
    predecessor: Option<Predecessor>,
    migration: MigrationState,
    deletion: DeletionState,
}
impl RecoveryRoot {
    pub fn root(&self) -> RootCommitment {
        self.root
    }
    pub fn registry(&self) -> KeyRegistryReference {
        self.registry
    }
    pub fn predecessor_database_epoch(&self) -> Option<DatabaseEpoch> {
        self.predecessor.map(|x| x.database_epoch)
    }
    pub fn migration(&self) -> MigrationState {
        self.migration
    }
    pub fn deletion(&self) -> DeletionState {
        self.deletion
    }
}
impl fmt::Debug for RecoveryRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryRoot(<opaque>)")
    }
}

/// Lost success is resolved by reading and comparing the exact current candidate. The
/// operation-result ledger remains inside the encrypted witnessed root, not a bounded cache.
pub trait Witness: Send + Sync {
    fn read_current(&self, archive_id: ArchiveId) -> Result<Option<WitnessRecord>>;
    fn recovery_root(&self, archive_id: ArchiveId) -> Result<RecoveryRoot>;
    fn acquire_lease(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> Result<WitnessLease>;
    fn renew_lease(&self, lease: WitnessLease, duration_ticks: u64) -> Result<WitnessLease>;
    fn revoke_lease(&self, lease: WitnessLease) -> Result<()>;
    fn compare_and_advance_root(&self, advance: RootAdvance) -> Result<WitnessReceipt>;
    fn advance_migration(
        &self,
        advance: RootAdvance,
        next: MigrationState,
    ) -> Result<WitnessReceipt>;
    fn rotate_key_registry(
        &self,
        advance: RootAdvance,
        next: KeyRegistryReference,
    ) -> Result<WitnessReceipt>;
    fn cut_over_database_epoch(
        &self,
        advance: RootAdvance,
        next: DatabaseEpoch,
    ) -> Result<WitnessReceipt>;
    fn tombstone(
        &self,
        advance: RootAdvance,
        evidence: DeletionEvidence,
    ) -> Result<TombstoneReceipt>;
    fn advance_deletion(
        &self,
        advance: DeletionAdvance,
        next: DeletionState,
    ) -> Result<WitnessReceipt>;
}

struct State {
    available: bool,
    records: BTreeMap<ArchiveId, WitnessRecord>,
}
pub struct InMemoryWitness {
    clock: Arc<dyn TrustedClock>,
    state: Mutex<State>,
}
impl InMemoryWitness {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
    fn with_clock(clock: Arc<dyn TrustedClock>) -> Self {
        Self {
            clock,
            state: Mutex::new(State {
                available: true,
                records: BTreeMap::new(),
            }),
        }
    }
    fn from_records(
        clock: Arc<dyn TrustedClock>,
        records: Vec<[u8; WITNESS_RECORD_BYTES]>,
    ) -> Result<Self> {
        let mut result = BTreeMap::new();
        for bytes in records {
            let r = WitnessRecord::decode(&bytes)?;
            if result.insert(r.archive_id, r).is_some() {
                return Err(WitnessError::Corrupt);
            }
        }
        Ok(Self {
            clock,
            state: Mutex::new(State {
                available: true,
                records: result,
            }),
        })
    }
    pub fn bootstrap(&self, b: WitnessBootstrap) -> Result<WitnessRecord> {
        if !nonzero_id(b.archive_id.as_bytes())
            || !b.genesis_root.valid()
            || b.genesis_root.database_epoch != b.database_epoch
            || b.genesis_root.key_epoch != b.registry.key_epoch
            || !b.registry.valid()
        {
            return Err(WitnessError::Malformed);
        }
        let mut state = self.lock()?;
        available(&state)?;
        if state.records.contains_key(&b.archive_id) {
            return Err(WitnessError::AlreadyExists);
        }
        let r = WitnessRecord {
            archive_id: b.archive_id,
            database_epoch: b.database_epoch,
            predecessor: None,
            root: b.genesis_root,
            registry: b.registry,
            owner_id: None,
            current_fencing_epoch: 0,
            next_fencing_epoch: 1,
            lease_expires_at_tick: 0,
            deletion_fencing_epoch: None,
            last_server_tick: 0,
            migration: MigrationState::Legacy,
            deletion: DeletionState::Active,
            deletion_evidence: None,
        };
        state.records.insert(r.archive_id, r.clone());
        Ok(r)
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| WitnessError::Synchronization)
    }
    fn now(&self, r: &mut WitnessRecord) -> Result<u64> {
        let now = self.clock.now_tick()?;
        if now < r.last_server_tick {
            return Err(WitnessError::Clock);
        }
        r.last_server_tick = now;
        Ok(now)
    }
    #[cfg(test)]
    fn snapshots(&self) -> Vec<[u8; WITNESS_RECORD_BYTES]> {
        self.state
            .lock()
            .expect("test lock")
            .records
            .values()
            .map(WitnessRecord::encode)
            .collect()
    }
    #[cfg(test)]
    fn unavailable(&self) {
        self.state.lock().expect("test lock").available = false;
    }
    fn normal(&self, a: RootAdvance, kind: Normal) -> Result<WitnessReceipt> {
        let mut s = self.lock()?;
        available(&s)?;
        let r = s
            .records
            .get_mut(&a.lease.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let now = self.now(r)?;
        normal_ok(r, &a, now, kind)?;
        match kind {
            Normal::Root => {}
            Normal::Migration(x) => r.migration = x,
            Normal::Rotation(x) => r.registry = x,
            Normal::Epoch(x) => {
                r.predecessor = Some(Predecessor {
                    database_epoch: r.database_epoch,
                    root: r.root.root,
                });
                r.database_epoch = x;
                // A database-epoch cutover invalidates the old writer token. The
                // owner must acquire a new higher fence against the new epoch.
                r.owner_id = None;
                r.lease_expires_at_tick = 0;
            }
        }
        r.root = a.candidate;
        Ok(WitnessReceipt { record: r.clone() })
    }
}
impl Default for InMemoryWitness {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
enum Normal {
    Root,
    Migration(MigrationState),
    Rotation(KeyRegistryReference),
    Epoch(DatabaseEpoch),
}
impl Witness for InMemoryWitness {
    fn read_current(&self, id: ArchiveId) -> Result<Option<WitnessRecord>> {
        let s = self.lock()?;
        available(&s)?;
        Ok(s.records.get(&id).cloned())
    }
    fn recovery_root(&self, id: ArchiveId) -> Result<RecoveryRoot> {
        let s = self.lock()?;
        available(&s)?;
        let r = s.records.get(&id).ok_or(WitnessError::MissingArchive)?;
        Ok(RecoveryRoot {
            root: r.root,
            registry: r.registry,
            predecessor: r.predecessor,
            migration: r.migration,
            deletion: r.deletion,
        })
    }
    fn acquire_lease(
        &self,
        id: ArchiveId,
        db: DatabaseEpoch,
        key: KeyEpoch,
        owner: ObjectId,
        duration: u64,
    ) -> Result<WitnessLease> {
        if !nonzero_id(owner.as_bytes()) {
            return Err(WitnessError::Malformed);
        }
        let mut s = self.lock()?;
        available(&s)?;
        let r = s.records.get_mut(&id).ok_or(WitnessError::MissingArchive)?;
        let now = self.now(r)?;
        let expiry = expiry(now, duration)?;
        if r.deletion != DeletionState::Active {
            return Err(WitnessError::InvalidTransition);
        }
        if r.database_epoch != db || r.registry.key_epoch != key {
            return Err(WitnessError::CompareFailed);
        }
        if r.owner_id.is_some() && now < r.lease_expires_at_tick {
            return Err(WitnessError::Fenced);
        }
        let fence = r.next_fencing_epoch;
        r.next_fencing_epoch = fence.checked_add(1).ok_or(WitnessError::Malformed)?;
        r.current_fencing_epoch = fence;
        r.owner_id = Some(owner);
        r.lease_expires_at_tick = expiry;
        Ok(WitnessLease {
            archive_id: id,
            database_epoch: db,
            key_epoch: key,
            owner,
            fencing_epoch: fence,
            expires_at_tick: expiry,
        })
    }
    fn renew_lease(&self, l: WitnessLease, duration: u64) -> Result<WitnessLease> {
        let mut s = self.lock()?;
        available(&s)?;
        let r = s
            .records
            .get_mut(&l.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let now = self.now(r)?;
        lease_ok(r, l, now)?;
        let e = expiry(now, duration)?;
        if e <= r.lease_expires_at_tick {
            return Err(WitnessError::InvalidTransition);
        }
        r.lease_expires_at_tick = e;
        Ok(WitnessLease {
            expires_at_tick: e,
            ..l
        })
    }
    fn revoke_lease(&self, l: WitnessLease) -> Result<()> {
        let mut s = self.lock()?;
        available(&s)?;
        let r = s
            .records
            .get_mut(&l.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let now = self.now(r)?;
        lease_ok(r, l, now)?;
        r.owner_id = None;
        r.lease_expires_at_tick = 0;
        Ok(())
    }
    fn compare_and_advance_root(&self, a: RootAdvance) -> Result<WitnessReceipt> {
        self.normal(a, Normal::Root)
    }
    fn advance_migration(&self, a: RootAdvance, x: MigrationState) -> Result<WitnessReceipt> {
        self.normal(a, Normal::Migration(x))
    }
    fn rotate_key_registry(
        &self,
        a: RootAdvance,
        x: KeyRegistryReference,
    ) -> Result<WitnessReceipt> {
        self.normal(a, Normal::Rotation(x))
    }
    fn cut_over_database_epoch(&self, a: RootAdvance, x: DatabaseEpoch) -> Result<WitnessReceipt> {
        self.normal(a, Normal::Epoch(x))
    }
    fn tombstone(&self, a: RootAdvance, evidence: DeletionEvidence) -> Result<TombstoneReceipt> {
        if !evidence.valid_for(DeletionState::Tombstoned) {
            return Err(WitnessError::Malformed);
        }
        let mut s = self.lock()?;
        available(&s)?;
        let r = s
            .records
            .get_mut(&a.lease.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let now = self.now(r)?;
        normal_ok(r, &a, now, Normal::Root)?;
        let df = r.next_fencing_epoch;
        r.next_fencing_epoch = df.checked_add(1).ok_or(WitnessError::Malformed)?;
        r.root = a.candidate;
        r.deletion = DeletionState::Tombstoned;
        r.migration = MigrationState::Deleting;
        r.deletion_evidence = Some(evidence);
        r.owner_id = None;
        r.lease_expires_at_tick = 0;
        r.deletion_fencing_epoch = Some(df);
        Ok(TombstoneReceipt {
            receipt: WitnessReceipt { record: r.clone() },
            authorization: DeletionAuthorization {
                archive_id: r.archive_id,
                database_epoch: r.database_epoch,
                fencing_epoch: df,
            },
        })
    }
    fn advance_deletion(&self, a: DeletionAdvance, next: DeletionState) -> Result<WitnessReceipt> {
        let mut s = self.lock()?;
        available(&s)?;
        let r = s
            .records
            .get_mut(&a.authorization.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let _ = self.now(r)?;
        deletion_ok(r, &a, next)?;
        r.root = a.candidate;
        r.deletion = next;
        r.deletion_evidence = Some(a.evidence);
        if next == DeletionState::PhysicalComplete {
            r.migration = MigrationState::Deleted;
        }
        Ok(WitnessReceipt { record: r.clone() })
    }
}
fn normal_ok(r: &WitnessRecord, a: &RootAdvance, now: u64, kind: Normal) -> Result<()> {
    if r.deletion != DeletionState::Active {
        return Err(WitnessError::InvalidTransition);
    }
    lease_ok(r, a.lease, now)?;
    if a.expected_root != r.root
        || a.expected_registry != r.registry
        || !a.candidate.valid()
        || a.candidate.parent != Some(r.root.root)
        || a.candidate.root.sequence
            != r.root
                .root
                .sequence
                .checked_add(1)
                .ok_or(WitnessError::Malformed)?
        || a.candidate.root.object_id == r.root.root.object_id
        || a.candidate.owner_fencing_epoch != a.lease.fencing_epoch
    {
        return Err(WitnessError::CompareFailed);
    }
    match kind {
        Normal::Root => {
            if a.candidate.database_epoch != r.database_epoch
                || a.candidate.key_epoch != r.registry.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
        Normal::Migration(x) => {
            if !r.migration.permits(x)
                || a.candidate.database_epoch != r.database_epoch
                || a.candidate.key_epoch != r.registry.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
        Normal::Rotation(x) => {
            if !x.valid()
                || x == r.registry
                || x.key_epoch == r.registry.key_epoch
                || a.candidate.database_epoch != r.database_epoch
                || a.candidate.key_epoch != x.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
        Normal::Epoch(x) => {
            if !nonzero_id(x.as_bytes())
                || x == r.database_epoch
                || a.candidate.database_epoch != x
                || a.candidate.key_epoch != r.registry.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
    };
    Ok(())
}
fn deletion_ok(r: &WitnessRecord, a: &DeletionAdvance, next: DeletionState) -> Result<()> {
    if r.deletion.next() != Some(next)
        || !a.evidence.valid_for(next)
        || a.authorization.archive_id != r.archive_id
        || a.authorization.database_epoch != r.database_epoch
        || Some(a.authorization.fencing_epoch) != r.deletion_fencing_epoch
        || a.expected_root != r.root
        || a.expected_registry != r.registry
        || !a.candidate.valid()
        || a.candidate.parent != Some(r.root.root)
        || a.candidate.root.sequence
            != r.root
                .root
                .sequence
                .checked_add(1)
                .ok_or(WitnessError::Malformed)?
        || a.candidate.database_epoch != r.database_epoch
        || a.candidate.key_epoch != r.registry.key_epoch
        || a.candidate.owner_fencing_epoch != a.authorization.fencing_epoch
    {
        return Err(WitnessError::CompareFailed);
    }
    Ok(())
}
fn lease_ok(r: &WitnessRecord, l: WitnessLease, now: u64) -> Result<()> {
    if r.deletion != DeletionState::Active
        || r.owner_id != Some(l.owner)
        || r.current_fencing_epoch != l.fencing_epoch
        || r.lease_expires_at_tick != l.expires_at_tick
        || now >= l.expires_at_tick
        || l.database_epoch != r.database_epoch
        || l.key_epoch != r.registry.key_epoch
    {
        Err(WitnessError::Fenced)
    } else {
        Ok(())
    }
}
fn expiry(now: u64, duration: u64) -> Result<u64> {
    if !(1..=MAX_LEASE_TICKS).contains(&duration) {
        return Err(WitnessError::Malformed);
    }
    now.checked_add(duration).ok_or(WitnessError::Malformed)
}
fn available(s: &State) -> Result<()> {
    s.available.then_some(()).ok_or(WitnessError::Unavailable)
}
fn nonzero_id(v: &[u8; 16]) -> bool {
    v.iter().any(|x| *x != 0)
}
fn nonzero_hash(v: &[u8; 32]) -> bool {
    v.iter().any(|x| *x != 0)
}
fn boolean(v: u8) -> Result<bool> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WitnessError::Corrupt),
    }
}
fn key_kind(v: u8) -> Result<KeyKind> {
    match v {
        1 => Ok(KeyKind::Archive),
        2 => Ok(KeyKind::Media),
        _ => Err(WitnessError::Corrupt),
    }
}
fn zero_root() -> RootReference {
    RootReference::new(0, ObjectId::from_bytes([0; 16]), [0; 32])
}
fn root_put<const N: usize>(out: &mut [u8; N], p: &mut usize, r: RootReference) {
    put(out, p, &r.sequence.to_be_bytes());
    put(out, p, r.object_id.as_bytes());
    put(out, p, &r.ciphertext_hash);
}
fn root_take(input: &[u8], p: &mut usize) -> Result<RootReference> {
    Ok(RootReference::new(
        u64::from_be_bytes(array(take(input, p, 8)?)?),
        ObjectId::from_bytes(array(take(input, p, 16)?)?),
        array(take(input, p, 32)?)?,
    ))
}
fn put<const N: usize>(out: &mut [u8; N], p: &mut usize, v: &[u8]) {
    let end = *p + v.len();
    out[*p..end].copy_from_slice(v);
    *p = end;
}
fn take<'a>(v: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = p.checked_add(n).ok_or(WitnessError::Corrupt)?;
    let r = v.get(*p..end).ok_or(WitnessError::Corrupt)?;
    *p = end;
    Ok(r)
}
fn array<const N: usize>(v: &[u8]) -> Result<[u8; N]> {
    v.try_into().map_err(|_| WitnessError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FakeClock(Mutex<u64>);
    impl FakeClock {
        fn new(v: u64) -> Self {
            Self(Mutex::new(v))
        }
        fn set(&self, v: u64) {
            *self.0.lock().expect("test clock") = v;
        }
    }
    impl TrustedClock for FakeClock {
        fn now_tick(&self) -> Result<u64> {
            Ok(*self.0.lock().map_err(|_| WitnessError::Synchronization)?)
        }
    }
    fn id(v: u8) -> [u8; 16] {
        [v; 16]
    }
    fn hash(v: u8) -> [u8; 32] {
        [v; 32]
    }
    fn boot() -> WitnessBootstrap {
        let db = DatabaseEpoch::from_bytes(id(2));
        let key = KeyEpoch::from_bytes(id(5));
        WitnessBootstrap::new(
            ArchiveId::from_bytes(id(1)),
            db,
            RootCommitment::genesis(
                db,
                key,
                RootReference::new(0, ObjectId::from_bytes(id(3)), hash(4)),
            ),
            KeyRegistryReference::new(key, ObjectId::from_bytes(id(6)), hash(7)),
        )
    }
    fn setup() -> (InMemoryWitness, Arc<FakeClock>, WitnessRecord, WitnessLease) {
        let c = Arc::new(FakeClock::new(10));
        let w = InMemoryWitness::with_clock(c.clone());
        let r = w.bootstrap(boot()).unwrap();
        let l = w
            .acquire_lease(
                r.archive_id,
                r.database_epoch,
                r.registry.key_epoch,
                ObjectId::from_bytes(id(8)),
                20,
            )
            .unwrap();
        (w, c, r, l)
    }
    fn cand(r: &WitnessRecord, fence: u64, v: u8) -> RootCommitment {
        RootCommitment::candidate(
            r.database_epoch,
            r.registry.key_epoch,
            fence,
            r.root.root,
            RootReference::new(
                r.root.root.sequence + 1,
                ObjectId::from_bytes(id(v)),
                hash(v.wrapping_add(40)),
            ),
        )
    }
    fn adv(r: &WitnessRecord, l: WitnessLease, v: u8) -> RootAdvance {
        RootAdvance::new(l, r.root, r.registry, cand(r, l.fencing_epoch, v))
    }
    fn del(
        r: &WitnessRecord,
        a: DeletionAuthorization,
        v: u8,
        k: DeletionEvidenceKind,
    ) -> DeletionAdvance {
        DeletionAdvance {
            authorization: a,
            expected_root: r.root,
            expected_registry: r.registry,
            candidate: cand(r, a.fencing_epoch, v),
            evidence: DeletionEvidence::new(k, hash(v)),
        }
    }
    #[test]
    fn durable_codec_round_trip_and_restart_never_reuses_fence() {
        let (w, c, r, first) = setup();
        let bytes = w.snapshots();
        let decoded = WitnessRecord::decode(&bytes[0]).unwrap();
        assert_eq!(decoded.encode(), bytes[0]);
        c.set(31);
        let restarted = InMemoryWitness::from_records(c.clone(), bytes).unwrap();
        let next = restarted
            .acquire_lease(
                r.archive_id,
                r.database_epoch,
                r.registry.key_epoch,
                ObjectId::from_bytes(id(9)),
                20,
            )
            .unwrap();
        assert!(next.fencing_epoch > first.fencing_epoch);
    }
    #[test]
    fn trusted_clock_rejects_regression_and_expiry() {
        let (w, c, r, l) = setup();
        c.set(9);
        assert_eq!(w.renew_lease(l, 20), Err(WitnessError::Clock));
        c.set(30);
        assert_eq!(
            w.compare_and_advance_root(adv(&r, l, 9)),
            Err(WitnessError::Fenced)
        );
    }
    #[test]
    fn candidate_binds_parent_epochs_and_fence() {
        let (w, _, r, l) = setup();
        let mut a = adv(&r, l, 9);
        a.candidate.owner_fencing_epoch += 1;
        assert_eq!(
            w.compare_and_advance_root(a),
            Err(WitnessError::CompareFailed)
        );
        let mut a = adv(&r, l, 10);
        a.candidate.key_epoch = KeyEpoch::from_bytes(id(99));
        assert_eq!(
            w.compare_and_advance_root(a),
            Err(WitnessError::InvalidTransition)
        );
    }
    #[test]
    fn lost_success_reads_exact_current_candidate() {
        let (w, _, r, l) = setup();
        let a = adv(&r, l, 9);
        let receipt = w.compare_and_advance_root(a.clone()).unwrap();
        assert_eq!(
            w.read_current(r.archive_id).unwrap().unwrap().root,
            a.candidate
        );
        assert_eq!(receipt.record.root, a.candidate);
    }
    #[test]
    fn tombstone_fences_owner_and_requires_evidence() {
        let (w, _, r, l) = setup();
        let t = w
            .tombstone(
                adv(&r, l, 9),
                DeletionEvidence::new(DeletionEvidenceKind::Tombstone, hash(10)),
            )
            .unwrap();
        let x = t.receipt.record;
        assert_eq!(
            w.acquire_lease(
                x.archive_id,
                x.database_epoch,
                x.registry.key_epoch,
                ObjectId::from_bytes(id(9)),
                1
            ),
            Err(WitnessError::InvalidTransition)
        );
        assert_eq!(w.renew_lease(l, 1), Err(WitnessError::Fenced));
        assert_eq!(
            w.advance_deletion(
                del(&x, t.authorization, 10, DeletionEvidenceKind::Inventory),
                DeletionState::CryptographicallyErased
            ),
            Err(WitnessError::CompareFailed)
        );
    }
    #[test]
    fn deletion_evidence_direct_extent_and_epoch_cutover() {
        let (w, _, r, l) = setup();
        let s = w
            .advance_migration(adv(&r, l, 9), MigrationState::ShadowExtents)
            .unwrap();
        let e = w
            .advance_migration(adv(s.record(), l, 10), MigrationState::ExtentAuthoritative)
            .unwrap();
        let retired = w
            .advance_migration(adv(e.record(), l, 11), MigrationState::LegacyRetired)
            .unwrap();
        let mut a = adv(retired.record(), l, 12);
        let db = DatabaseEpoch::from_bytes(id(44));
        a.candidate.database_epoch = db;
        let cut = w.cut_over_database_epoch(a, db).unwrap();
        assert_eq!(
            cut.record.predecessor.unwrap().database_epoch,
            r.database_epoch
        );
        let cutover_lease = w
            .acquire_lease(
                cut.record.archive_id,
                cut.record.database_epoch,
                cut.record.registry.key_epoch,
                ObjectId::from_bytes(id(8)),
                20,
            )
            .unwrap();
        let t = w
            .tombstone(
                adv(cut.record(), cutover_lease, 13),
                DeletionEvidence::new(DeletionEvidenceKind::Tombstone, hash(1)),
            )
            .unwrap();
        let er = w
            .advance_deletion(
                del(
                    t.receipt.record(),
                    t.authorization,
                    14,
                    DeletionEvidenceKind::KeyErasure,
                ),
                DeletionState::CryptographicallyErased,
            )
            .unwrap();
        let absent = w
            .advance_deletion(
                del(
                    er.record(),
                    t.authorization,
                    15,
                    DeletionEvidenceKind::Inventory,
                ),
                DeletionState::LogicalObjectsAbsent,
            )
            .unwrap();
        let complete = w
            .advance_deletion(
                del(
                    absent.record(),
                    t.authorization,
                    16,
                    DeletionEvidenceKind::Retention,
                ),
                DeletionState::PhysicalComplete,
            )
            .unwrap();
        assert_eq!(complete.record.migration, MigrationState::Deleted);
    }
    #[test]
    fn unavailable_and_debug_are_content_free() {
        let (w, _, r, l) = setup();
        w.unavailable();
        assert_eq!(w.read_current(r.archive_id), Err(WitnessError::Unavailable));
        assert_eq!(
            w.compare_and_advance_root(adv(&r, l, 9)),
            Err(WitnessError::Unavailable)
        );
        assert!(!format!("{r:?} {l:?}").contains("01"));
    }
}
