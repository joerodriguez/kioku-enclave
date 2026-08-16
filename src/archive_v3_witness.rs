#![allow(dead_code, reason = "inactive ADR-0022 witness contract")]
//! Content-free, inactive ADR-0022 witness contract. Provider persistence is
//! fixed-size and contains every lease/fence/root commitment needed after restart.

use crate::archive_v3::{
    ArchiveId, ArchiveRoot, CiphertextEnvelope, DatabaseEpoch, KeyEpoch, KeyKind, ObjectContext,
    ObjectId, VerifiedArchiveCipher,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"KAWITv3\0";
const VERSION: u8 = 3;
pub const WITNESS_RECORD_BYTES: usize = 724;
const DELETION_EVIDENCE_STAGES: usize = 4;
const MAX_LEASE_TICKS: u64 = 86_400;
const ROOT_COMMITMENT_BYTES: usize = 153;
const KEY_REGISTRY_REFERENCE_BYTES: usize = 73;
const DELETION_EVIDENCE_DOMAIN: &[u8] = b"kioku:archive:v3:deletion-evidence:v2\0";
const DATABASE_EPOCH_DOMAIN: &[u8] = b"kioku:archive:v3:database-epoch\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum WitnessError {
    #[error("witness is unavailable")]
    Unavailable,
    #[error("witness archive record is absent")]
    MissingArchive,
    #[error("the exact immutable root object is absent")]
    MissingRootObject,
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
    #[error("deletion worker is not authorized")]
    Unauthorized,
    #[error("witness synchronization failed")]
    Synchronization,
}
type Result<T> = std::result::Result<T, WitnessError>;

pub struct DeletionWorkerCredential {
    provider_assertion: Zeroizing<Vec<u8>>,
}
impl DeletionWorkerCredential {
    #[cfg(test)]
    fn new(provider_assertion: &[u8]) -> Result<Self> {
        if provider_assertion.is_empty() {
            return Err(WitnessError::Malformed);
        }
        Ok(Self {
            provider_assertion: Zeroizing::new(provider_assertion.to_vec()),
        })
    }

    fn provider_assertion(&self) -> &[u8] {
        &self.provider_assertion
    }
}
impl fmt::Debug for DeletionWorkerCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeletionWorkerCredential(<opaque>)")
    }
}

pub struct DeletionStageProof {
    provider_assertion: Zeroizing<Vec<u8>>,
    inventory_commitment: Option<[u8; 32]>,
    provider_drain_commitment: Option<[u8; 32]>,
}
impl DeletionStageProof {
    #[cfg(test)]
    fn new(provider_assertion: &[u8]) -> Result<Self> {
        if provider_assertion.is_empty() {
            return Err(WitnessError::Malformed);
        }
        Ok(Self {
            provider_assertion: Zeroizing::new(provider_assertion.to_vec()),
            inventory_commitment: None,
            provider_drain_commitment: None,
        })
    }

    fn provider_assertion(&self) -> &[u8] {
        &self.provider_assertion
    }

    pub(crate) fn bind_inventory_drain(
        &self,
        inventory_commitment: [u8; 32],
        provider_drain_commitment: [u8; 32],
    ) -> Result<Self> {
        if self.provider_assertion.is_empty()
            || !nonzero_hash(&inventory_commitment)
            || !nonzero_hash(&provider_drain_commitment)
        {
            return Err(WitnessError::Malformed);
        }
        Ok(Self {
            provider_assertion: Zeroizing::new(self.provider_assertion.to_vec()),
            inventory_commitment: Some(inventory_commitment),
            provider_drain_commitment: Some(provider_drain_commitment),
        })
    }

    pub(crate) fn bind_inventory_only(&self, inventory_commitment: [u8; 32]) -> Result<Self> {
        if self.provider_assertion.is_empty() || !nonzero_hash(&inventory_commitment) {
            return Err(WitnessError::Malformed);
        }
        Ok(Self {
            provider_assertion: Zeroizing::new(self.provider_assertion.to_vec()),
            inventory_commitment: Some(inventory_commitment),
            provider_drain_commitment: None,
        })
    }

    pub(crate) const fn inventory_binding(&self) -> Option<[u8; 32]> {
        self.inventory_commitment
    }

    pub(crate) fn drain_binding(&self) -> Option<([u8; 32], [u8; 32])> {
        self.inventory_commitment
            .zip(self.provider_drain_commitment)
    }
}
impl fmt::Debug for DeletionStageProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeletionStageProof(<opaque>)")
    }
}

/// Production providers authenticate the attested deletion worker/operation
/// principal on every destructive transition. Persistence alone never mints a
/// deletion capability.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DeletionWorkerIdentity {
    worker_id: ObjectId,
    operation_id: ObjectId,
}
impl DeletionWorkerIdentity {
    fn new(worker_id: ObjectId, operation_id: ObjectId) -> Result<Self> {
        if !nonzero_id(worker_id.as_bytes()) || !nonzero_id(operation_id.as_bytes()) {
            return Err(WitnessError::Unauthorized);
        }
        Ok(Self {
            worker_id,
            operation_id,
        })
    }
}

#[derive(Clone, Copy)]
struct DeletionStageContext {
    archive_id: ArchiveId,
    identity: DeletionWorkerIdentity,
    deletion_fencing_epoch: u64,
    target: DeletionState,
    root: RootCommitment,
    registry: KeyRegistryReference,
    inventory_commitment: Option<[u8; 32]>,
    provider_drain_commitment: Option<[u8; 32]>,
}

trait DeletionWorkerAuthenticator: Send + Sync {
    fn authenticate(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> Result<DeletionWorkerIdentity>;

    fn verify_stage(
        &self,
        credential: &DeletionWorkerCredential,
        context: DeletionStageContext,
        proof: &DeletionStageProof,
    ) -> Result<[u8; 32]>;
}
struct DenyDeletionWorkers;
impl DeletionWorkerAuthenticator for DenyDeletionWorkers {
    fn authenticate(
        &self,
        _archive_id: ArchiveId,
        _credential: &DeletionWorkerCredential,
    ) -> Result<DeletionWorkerIdentity> {
        Err(WitnessError::Unauthorized)
    }

    fn verify_stage(
        &self,
        _credential: &DeletionWorkerCredential,
        _context: DeletionStageContext,
        _proof: &DeletionStageProof,
    ) -> Result<[u8; 32]> {
        Err(WitnessError::Unauthorized)
    }
}

#[cfg(test)]
struct DeletionDriverTestAuthenticator {
    archive_id: ArchiveId,
}

#[cfg(test)]
impl DeletionWorkerAuthenticator for DeletionDriverTestAuthenticator {
    fn authenticate(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> Result<DeletionWorkerIdentity> {
        if archive_id != self.archive_id || credential.provider_assertion() != b"driver-worker" {
            return Err(WitnessError::Unauthorized);
        }
        DeletionWorkerIdentity::new(
            ObjectId::from_bytes([70; 16]),
            ObjectId::from_bytes([71; 16]),
        )
    }

    fn verify_stage(
        &self,
        credential: &DeletionWorkerCredential,
        context: DeletionStageContext,
        proof: &DeletionStageProof,
    ) -> Result<[u8; 32]> {
        if self.authenticate(context.archive_id, credential)? != context.identity {
            return Err(WitnessError::Unauthorized);
        }
        let expected = match context.target {
            DeletionState::Active => return Err(WitnessError::InvalidTransition),
            DeletionState::Tombstoned => b"driver-tombstone".as_slice(),
            DeletionState::CryptographicallyErased => b"driver-erasure".as_slice(),
            DeletionState::LogicalObjectsAbsent => b"driver-inventory".as_slice(),
            DeletionState::PhysicalComplete => b"driver-retention".as_slice(),
        };
        if proof.provider_assertion() != expected {
            return Err(WitnessError::Unauthorized);
        }
        match context.target {
            DeletionState::CryptographicallyErased
                if context
                    .inventory_commitment
                    .is_some_and(|value| nonzero_hash(&value))
                    && context.provider_drain_commitment.is_none() => {}
            DeletionState::CryptographicallyErased => return Err(WitnessError::Unauthorized),
            DeletionState::PhysicalComplete
                if context
                    .inventory_commitment
                    .is_some_and(|value| nonzero_hash(&value))
                    && context
                        .provider_drain_commitment
                        .is_some_and(|value| nonzero_hash(&value)) => {}
            DeletionState::PhysicalComplete => return Err(WitnessError::Unauthorized),
            _ if context.inventory_commitment.is_none()
                && context.provider_drain_commitment.is_none() => {}
            _ => return Err(WitnessError::Unauthorized),
        }
        Ok(Sha256::digest(expected).into())
    }
}

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

/// Read-after-create boundary for root publication. The witness derives a
/// commitment only from the exact immutable object returned for the nominated
/// context; sealing bytes in memory is insufficient to advance authority.
#[async_trait::async_trait]
pub(crate) trait ExactRootProvider: Send + Sync {
    async fn read_exact(&self, context: &ObjectContext) -> Result<CiphertextEnvelope>;
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
    pub(crate) fn from_persisted_wal_candidate(
        _token: crate::archive_v3_wal_owner::WalWitnessAdvanceContext,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        owner_fencing_epoch: u64,
        parent: RootReference,
        root: RootReference,
    ) -> Result<Self> {
        let value = Self::candidate(database_epoch, key_epoch, owner_fencing_epoch, parent, root);
        value.valid().then_some(value).ok_or(WitnessError::Corrupt)
    }

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
    const fn candidate(
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

    #[cfg(test)]
    pub(crate) const fn candidate_for_test(
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        owner_fencing_epoch: u64,
        parent: RootReference,
        root: RootReference,
    ) -> Self {
        Self::candidate(database_epoch, key_epoch, owner_fencing_epoch, parent, root)
    }

    /// Authenticate, decode, and context-check the exact immutable root envelope
    /// before producing the only commitment accepted by non-test advance builders.
    pub(crate) async fn from_authenticated_provider_object(
        expected_archive_id: ArchiveId,
        expected_registry: KeyRegistryReference,
        context: &ObjectContext,
        provider: &dyn ExactRootProvider,
        cipher: &VerifiedArchiveCipher,
    ) -> Result<Self> {
        if context.archive_id() != expected_archive_id
            || cipher.archive_id() != expected_archive_id
            || cipher.key_epoch() != expected_registry.key_epoch
            || cipher.registry_rotation_generation() != expected_registry.rotation_generation
            || cipher.registry_object_id() != expected_registry.object_id
            || cipher.registry_ciphertext_hash() != expected_registry.ciphertext_hash
        {
            return Err(WitnessError::Malformed);
        }
        let envelope = provider.read_exact(context).await?;
        let plaintext = cipher
            .open(context, &envelope)
            .map_err(|_| WitnessError::Malformed)?;
        let root = ArchiveRoot::decode(&plaintext).map_err(|_| WitnessError::Malformed)?;
        root.validate_for_context(context)
            .map_err(|_| WitnessError::Malformed)?;
        let reference = RootReference::new(root.root_seq, context.object_id(), envelope.hash());
        let commitment = match root.parent {
            None => Self::genesis(root.database_epoch, root.key_epoch, reference),
            Some(parent) => Self::candidate(
                root.database_epoch,
                root.key_epoch,
                root.owner_fencing_epoch,
                RootReference::new(
                    root.root_seq
                        .checked_sub(1)
                        .ok_or(WitnessError::Malformed)?,
                    parent.object_id,
                    parent.envelope_hash,
                ),
                reference,
            ),
        };
        commitment
            .valid()
            .then_some(commitment)
            .ok_or(WitnessError::Malformed)
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
    rotation_generation: u64,
    object_id: ObjectId,
    ciphertext_hash: [u8; 32],
}
impl KeyRegistryReference {
    pub(crate) const fn new(
        key_epoch: KeyEpoch,
        rotation_generation: u64,
        object_id: ObjectId,
        ciphertext_hash: [u8; 32],
    ) -> Self {
        Self {
            key_kind: KeyKind::Archive,
            key_epoch,
            rotation_generation,
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

    pub fn rotation_generation(&self) -> u64 {
        self.rotation_generation
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
    EpochCutover = 5,
    LegacyRetired = 6,
    Deleting = 7,
    Deleted = 8,
}
impl MigrationState {
    fn decode(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::ShadowWal),
            2 => Ok(Self::WalAuthoritative),
            3 => Ok(Self::ShadowExtents),
            4 => Ok(Self::ExtentAuthoritative),
            5 => Ok(Self::EpochCutover),
            6 => Ok(Self::LegacyRetired),
            7 => Ok(Self::Deleting),
            8 => Ok(Self::Deleted),
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
                | (Self::EpochCutover, Self::LegacyRetired)
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

    const fn evidence_count(self) -> usize {
        self as usize
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

    const fn for_state(state: DeletionState) -> Option<Self> {
        match state {
            DeletionState::Active => None,
            DeletionState::Tombstoned => Some(Self::Tombstone),
            DeletionState::CryptographicallyErased => Some(Self::KeyErasure),
            DeletionState::LogicalObjectsAbsent => Some(Self::Inventory),
            DeletionState::PhysicalComplete => Some(Self::Retention),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeletionEvidence {
    kind: DeletionEvidenceKind,
    commitment: [u8; 32],
}
impl DeletionEvidence {
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
    root: RootCommitment,
    registry: KeyRegistryReference,
}

/// The entire durable provider state; no fencing state is local-only.
#[derive(Clone, PartialEq, Eq)]
pub struct WitnessRecord {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    database_epoch_generation: u64,
    predecessor: Option<Predecessor>,
    root: RootCommitment,
    registry: KeyRegistryReference,
    owner_id: Option<ObjectId>,
    current_fencing_epoch: u64,
    next_fencing_epoch: u64,
    lease_expires_at_tick: u64,
    deletion_fencing_epoch: Option<u64>,
    deletion_worker_id: Option<ObjectId>,
    deletion_operation_id: Option<ObjectId>,
    last_server_tick: u64,
    migration: MigrationState,
    deletion: DeletionState,
    deletion_evidence: [Option<DeletionEvidence>; DELETION_EVIDENCE_STAGES],
}
impl WitnessRecord {
    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }
    pub fn database_epoch(&self) -> DatabaseEpoch {
        self.database_epoch
    }
    pub fn database_epoch_generation(&self) -> u64 {
        self.database_epoch_generation
    }
    pub fn root(&self) -> RootCommitment {
        self.root
    }
    pub fn registry(&self) -> KeyRegistryReference {
        self.registry
    }
    pub(crate) fn authorizes_lease(&self, lease: WitnessLease) -> bool {
        self.archive_id == lease.archive_id
            && self.database_epoch == lease.database_epoch
            && self.registry.key_epoch == lease.key_epoch
            && self.owner_id == Some(lease.owner)
            && self.current_fencing_epoch == lease.fencing_epoch
            && self.lease_expires_at_tick == lease.expires_at_tick
            && self.deletion == DeletionState::Active
    }

    /// Recover the exact still-current maintenance lease without accepting a
    /// caller-supplied fence or expiry. A missing, expired, deleting, or
    /// differently-owned lease never becomes retry authority.
    pub(crate) fn exact_active_lease_for_owner(&self, owner: ObjectId) -> Result<WitnessLease> {
        if self.deletion != DeletionState::Active
            || self.owner_id != Some(owner)
            || self.current_fencing_epoch == 0
            || self.lease_expires_at_tick == 0
            || self.last_server_tick >= self.lease_expires_at_tick
        {
            return Err(WitnessError::Fenced);
        }
        let lease = WitnessLease {
            archive_id: self.archive_id,
            database_epoch: self.database_epoch,
            key_epoch: self.registry.key_epoch,
            owner,
            fencing_epoch: self.current_fencing_epoch,
            expires_at_tick: self.lease_expires_at_tick,
        };
        self.authorizes_lease(lease)
            .then_some(lease)
            .ok_or(WitnessError::Fenced)
    }

    pub(crate) fn has_exact_active_wal_owner_lease(&self) -> bool {
        self.migration == MigrationState::WalAuthoritative
            && self
                .owner_id
                .and_then(|owner| self.exact_active_lease_for_owner(owner).ok())
                .is_some()
    }

    /// Phase-1-only unleased terminal predicate. It intentionally exposes no
    /// owner identity or lease capability and cannot accept WalAuthoritative.
    pub(crate) fn is_exact_unleased_advisory_terminal(&self) -> bool {
        self.valid()
            && self.deletion == DeletionState::Active
            && self.migration == MigrationState::ShadowWal
            && self.owner_id.is_none()
            && self.lease_expires_at_tick == 0
    }

    pub(crate) fn exact_active_lease_for_wal_owner_bytes(
        &self,
        owner: &[u8; 16],
    ) -> Result<WitnessLease> {
        self.exact_active_lease_for_owner(ObjectId::from_bytes(*owner))
    }

    /// Validate the sole exact witness-owned transition from an unleased
    /// WalAuthoritative maintenance handoff to the first durable WAL owner.
    /// No graph, epoch, registry, migration, deletion, predecessor, or
    /// evidence field may change; only trusted time and the canonical next
    /// owner/fence/expiry tuple may advance.
    pub(crate) fn exact_wal_owner_acquire_from(
        &self,
        expected: &Self,
        owner: &[u8; 16],
    ) -> Result<WitnessLease> {
        let owner = ObjectId::from_bytes(*owner);
        let lease = self.exact_active_lease_for_owner(owner)?;
        if !expected.valid()
            || !self.valid()
            || expected.deletion != DeletionState::Active
            || expected.migration != MigrationState::WalAuthoritative
            || expected.owner_id.is_some()
            || expected.lease_expires_at_tick != 0
            || self.archive_id != expected.archive_id
            || self.database_epoch != expected.database_epoch
            || self.database_epoch_generation != expected.database_epoch_generation
            || self.predecessor != expected.predecessor
            || self.root != expected.root
            || self.registry != expected.registry
            || self.owner_id != Some(owner)
            || self.current_fencing_epoch != expected.next_fencing_epoch
            || self.next_fencing_epoch
                != self
                    .current_fencing_epoch
                    .checked_add(1)
                    .ok_or(WitnessError::Fenced)?
            || self.last_server_tick < expected.last_server_tick
            || self.lease_expires_at_tick <= self.last_server_tick
            || self.migration != expected.migration
            || self.deletion != expected.deletion
            || self.deletion_fencing_epoch != expected.deletion_fencing_epoch
            || self.deletion_worker_id != expected.deletion_worker_id
            || self.deletion_operation_id != expected.deletion_operation_id
            || self.deletion_evidence != expected.deletion_evidence
        {
            return Err(WitnessError::Fenced);
        }
        Ok(lease)
    }

    /// Validate the sole witness-owned transition from the released Phase-1
    /// `ShadowWal` terminal to its first advisory owner. This predicate is
    /// domain-separated by type and migration state from WalAuthoritative;
    /// it grants neither root-advance nor acknowledgement authority.
    pub(crate) fn exact_advisory_owner_acquire_from(
        &self,
        expected: &Self,
        owner: &[u8; 16],
    ) -> Result<WitnessLease> {
        let owner = ObjectId::from_bytes(*owner);
        let lease = self.exact_active_lease_for_owner(owner)?;
        if !expected.is_exact_unleased_advisory_terminal()
            || !self.valid()
            || self.archive_id != expected.archive_id
            || self.database_epoch != expected.database_epoch
            || self.database_epoch_generation != expected.database_epoch_generation
            || self.predecessor != expected.predecessor
            || self.root != expected.root
            || self.registry != expected.registry
            || self.owner_id != Some(owner)
            || self.current_fencing_epoch != expected.next_fencing_epoch
            || self.next_fencing_epoch
                != self
                    .current_fencing_epoch
                    .checked_add(1)
                    .ok_or(WitnessError::Fenced)?
            || self.last_server_tick < expected.last_server_tick
            || self.lease_expires_at_tick <= self.last_server_tick
            || self.migration != MigrationState::ShadowWal
            || self.deletion != expected.deletion
            || self.deletion_fencing_epoch != expected.deletion_fencing_epoch
            || self.deletion_worker_id != expected.deletion_worker_id
            || self.deletion_operation_id != expected.deletion_operation_id
            || self.deletion_evidence != expected.deletion_evidence
        {
            return Err(WitnessError::Fenced);
        }
        Ok(lease)
    }

    /// Authenticate one live Phase-1 advisory-owner heartbeat. Trusted time
    /// and lease expiry may move forward at the same fence; every archive,
    /// graph, registry, migration, deletion, and owner field remains exact.
    pub(crate) fn exact_advisory_owner_heartbeat_from(
        &self,
        previous: &Self,
        owner: &[u8; 16],
    ) -> Result<WitnessLease> {
        let owner = ObjectId::from_bytes(*owner);
        let previous_lease = previous.exact_active_lease_for_owner(owner)?;
        let lease = self.exact_active_lease_for_owner(owner)?;
        if !self.valid()
            || !previous.valid()
            || self.archive_id != previous.archive_id
            || self.database_epoch != previous.database_epoch
            || self.database_epoch_generation != previous.database_epoch_generation
            || self.predecessor != previous.predecessor
            || self.root != previous.root
            || self.registry != previous.registry
            || self.current_fencing_epoch != previous.current_fencing_epoch
            || self.next_fencing_epoch != previous.next_fencing_epoch
            || self.last_server_tick < previous.last_server_tick
            || self.lease_expires_at_tick < previous.lease_expires_at_tick
            || lease.fencing_epoch != previous_lease.fencing_epoch
            || self.migration != MigrationState::ShadowWal
            || previous.migration != MigrationState::ShadowWal
            || self.deletion != DeletionState::Active
            || previous.deletion != DeletionState::Active
            || self.deletion_fencing_epoch != previous.deletion_fencing_epoch
            || self.deletion_worker_id != previous.deletion_worker_id
            || self.deletion_operation_id != previous.deletion_operation_id
            || self.deletion_evidence != previous.deletion_evidence
        {
            return Err(WitnessError::Fenced);
        }
        Ok(lease)
    }

    /// Authenticate the sole Phase-1 advisory-owner takeover after the exact
    /// retained lease expired. Only trusted time, expiry, and the canonical
    /// next fence pair may advance; root publication remains impossible.
    pub(crate) fn exact_advisory_owner_reacquire_from(
        &self,
        previous: &Self,
        owner: &[u8; 16],
    ) -> Result<WitnessLease> {
        let owner = ObjectId::from_bytes(*owner);
        let previous_lease = previous.exact_active_lease_for_owner(owner)?;
        let lease = self.exact_active_lease_for_owner(owner)?;
        if !self.valid()
            || !previous.valid()
            || self.archive_id != previous.archive_id
            || self.database_epoch != previous.database_epoch
            || self.database_epoch_generation != previous.database_epoch_generation
            || self.predecessor != previous.predecessor
            || self.root != previous.root
            || self.registry != previous.registry
            || self.current_fencing_epoch != previous.next_fencing_epoch
            || self.next_fencing_epoch
                != self
                    .current_fencing_epoch
                    .checked_add(1)
                    .ok_or(WitnessError::Fenced)?
            || self.last_server_tick < previous.lease_expires_at_tick
            || self.last_server_tick <= previous.last_server_tick
            || self.lease_expires_at_tick <= previous.lease_expires_at_tick
            || lease.fencing_epoch <= previous_lease.fencing_epoch
            || self.migration != MigrationState::ShadowWal
            || previous.migration != MigrationState::ShadowWal
            || self.deletion != DeletionState::Active
            || previous.deletion != DeletionState::Active
            || self.deletion_fencing_epoch != previous.deletion_fencing_epoch
            || self.deletion_worker_id != previous.deletion_worker_id
            || self.deletion_operation_id != previous.deletion_operation_id
            || self.deletion_evidence != previous.deletion_evidence
        {
            return Err(WitnessError::Fenced);
        }
        Ok(lease)
    }

    /// Validate a fresh current ordinary-root descendant against the durable
    /// owner acquisition. Root and trusted tick may advance; the complete
    /// owner lease, archive/database/key lineage, predecessor, registry,
    /// migration, deletion, and evidence tuple remains exact.
    pub(crate) fn retains_exact_wal_owner_lease_from(
        &self,
        acquired: &Self,
        owner: &[u8; 16],
    ) -> Result<WitnessLease> {
        let owner = ObjectId::from_bytes(*owner);
        let acquired_lease = acquired.exact_active_lease_for_owner(owner)?;
        let current_lease = self.exact_active_lease_for_owner(owner)?;
        if !self.valid()
            || !acquired.valid()
            || current_lease != acquired_lease
            || self.archive_id != acquired.archive_id
            || self.database_epoch != acquired.database_epoch
            || self.database_epoch_generation != acquired.database_epoch_generation
            || self.predecessor != acquired.predecessor
            || self.registry != acquired.registry
            || self.current_fencing_epoch != acquired.current_fencing_epoch
            || self.next_fencing_epoch != acquired.next_fencing_epoch
            || self.last_server_tick < acquired.last_server_tick
            || self.migration != MigrationState::WalAuthoritative
            || acquired.migration != MigrationState::WalAuthoritative
            || self.deletion != DeletionState::Active
            || acquired.deletion != DeletionState::Active
            || self.deletion_fencing_epoch != acquired.deletion_fencing_epoch
            || self.deletion_worker_id != acquired.deletion_worker_id
            || self.deletion_operation_id != acquired.deletion_operation_id
            || self.deletion_evidence != acquired.deletion_evidence
            || self.root.root().sequence() < acquired.root.root().sequence()
        {
            return Err(WitnessError::Fenced);
        }
        Ok(current_lease)
    }

    /// Validate the sole fresh-process reacquire after the retained durable
    /// owner's prior lease has expired. The exact provider record and root are
    /// unchanged; trusted time, expiry, and the canonical fence pair advance.
    pub(crate) fn exact_wal_owner_reacquire_from(
        &self,
        previous: &Self,
        owner: &[u8; 16],
    ) -> Result<WitnessLease> {
        let owner = ObjectId::from_bytes(*owner);
        let previous_lease = previous.exact_active_lease_for_owner(owner)?;
        let lease = self.exact_active_lease_for_owner(owner)?;
        if !self.valid()
            || !previous.valid()
            || self.archive_id != previous.archive_id
            || self.database_epoch != previous.database_epoch
            || self.database_epoch_generation != previous.database_epoch_generation
            || self.predecessor != previous.predecessor
            || self.root != previous.root
            || self.registry != previous.registry
            || self.current_fencing_epoch != previous.next_fencing_epoch
            || self.next_fencing_epoch
                != self
                    .current_fencing_epoch
                    .checked_add(1)
                    .ok_or(WitnessError::Fenced)?
            || self.last_server_tick < previous.lease_expires_at_tick
            || self.last_server_tick <= previous.last_server_tick
            || self.lease_expires_at_tick <= previous.lease_expires_at_tick
            || lease.fencing_epoch <= previous_lease.fencing_epoch
            || self.migration != MigrationState::WalAuthoritative
            || previous.migration != MigrationState::WalAuthoritative
            || self.deletion != DeletionState::Active
            || previous.deletion != DeletionState::Active
            || self.deletion_fencing_epoch != previous.deletion_fencing_epoch
            || self.deletion_worker_id != previous.deletion_worker_id
            || self.deletion_operation_id != previous.deletion_operation_id
            || self.deletion_evidence != previous.deletion_evidence
        {
            return Err(WitnessError::Fenced);
        }
        Ok(lease)
    }

    pub(crate) fn exact_wal_owner_renewal_from(
        &self,
        previous: &Self,
        owner: &[u8; 16],
    ) -> Result<WitnessLease> {
        let owner = ObjectId::from_bytes(*owner);
        let previous_lease = previous.exact_active_lease_for_owner(owner)?;
        let lease = self.exact_active_lease_for_owner(owner)?;
        if !self.valid()
            || !previous.valid()
            || self.archive_id != previous.archive_id
            || self.database_epoch != previous.database_epoch
            || self.database_epoch_generation != previous.database_epoch_generation
            || self.predecessor != previous.predecessor
            || self.root != previous.root
            || self.registry != previous.registry
            || self.current_fencing_epoch != previous.current_fencing_epoch
            || self.next_fencing_epoch != previous.next_fencing_epoch
            || self.last_server_tick <= previous.last_server_tick
            || self.lease_expires_at_tick <= previous.lease_expires_at_tick
            || lease.fencing_epoch != previous_lease.fencing_epoch
            || self.migration != MigrationState::WalAuthoritative
            || previous.migration != MigrationState::WalAuthoritative
            || self.deletion != DeletionState::Active
            || previous.deletion != DeletionState::Active
            || self.deletion_fencing_epoch != previous.deletion_fencing_epoch
            || self.deletion_worker_id != previous.deletion_worker_id
            || self.deletion_operation_id != previous.deletion_operation_id
            || self.deletion_evidence != previous.deletion_evidence
        {
            return Err(WitnessError::Fenced);
        }
        Ok(lease)
    }

    /// Authenticate a live-owner heartbeat. A provider may retain the exact
    /// lease when ample lifetime remains, advance only trusted time, or extend
    /// expiry at the same fence. It may not change any graph, registry,
    /// deletion, owner, or fencing field.
    pub(crate) fn exact_wal_owner_heartbeat_from(
        &self,
        previous: &Self,
        owner: &[u8; 16],
    ) -> Result<WitnessLease> {
        let owner = ObjectId::from_bytes(*owner);
        let previous_lease = previous.exact_active_lease_for_owner(owner)?;
        let lease = self.exact_active_lease_for_owner(owner)?;
        if !self.valid()
            || !previous.valid()
            || self.archive_id != previous.archive_id
            || self.database_epoch != previous.database_epoch
            || self.database_epoch_generation != previous.database_epoch_generation
            || self.predecessor != previous.predecessor
            || self.root != previous.root
            || self.registry != previous.registry
            || self.current_fencing_epoch != previous.current_fencing_epoch
            || self.next_fencing_epoch != previous.next_fencing_epoch
            || self.last_server_tick < previous.last_server_tick
            || self.lease_expires_at_tick < previous.lease_expires_at_tick
            || lease.fencing_epoch != previous_lease.fencing_epoch
            || self.migration != MigrationState::WalAuthoritative
            || previous.migration != MigrationState::WalAuthoritative
            || self.deletion != DeletionState::Active
            || previous.deletion != DeletionState::Active
            || self.deletion_fencing_epoch != previous.deletion_fencing_epoch
            || self.deletion_worker_id != previous.deletion_worker_id
            || self.deletion_operation_id != previous.deletion_operation_id
            || self.deletion_evidence != previous.deletion_evidence
        {
            return Err(WitnessError::Fenced);
        }
        Ok(lease)
    }

    /// Checkpoint staging may reconstruct only the exact active owner lease
    /// already embedded in its authenticated expected witness. The private
    /// token prevents this comparison fact from becoming general lease
    /// authority outside the WAL publisher/control path.
    pub(crate) fn wal_owner_checkpoint_lease(
        &self,
        _token: crate::archive_v3_wal_owner::WalCheckpointSourceContext,
        owner: ObjectId,
    ) -> Result<WitnessLease> {
        if self.deletion != DeletionState::Active
            || self.migration != MigrationState::WalAuthoritative
        {
            return Err(WitnessError::InvalidTransition);
        }
        self.exact_active_lease_for_owner(owner)
    }

    /// Stable checkpoint-source subject. Provider-derived lease clock,
    /// expiry, owner and fencing fields are deliberately removed, while the
    /// complete archive/database-generation/predecessor/root/registry/
    /// migration/deletion/evidence tuple remains encoded exactly. This lets a
    /// same-subject heartbeat or reacquire retain one Store-owned source
    /// without weakening any immutable witness binding.
    pub(crate) fn wal_owner_checkpoint_source_subject(
        &self,
        _token: crate::archive_v3_wal_owner::WalCheckpointSourceContext,
    ) -> Result<[u8; 32]> {
        if !self.valid()
            || self.deletion != DeletionState::Active
            || self.migration != MigrationState::WalAuthoritative
        {
            return Err(WitnessError::Corrupt);
        }
        let mut stable = self.clone();
        stable.owner_id = None;
        stable.current_fencing_epoch = 0;
        stable.next_fencing_epoch = 0;
        stable.lease_expires_at_tick = 0;
        stable.last_server_tick = 0;
        let mut hasher = Sha256::new();
        hasher.update(b"kioku/archive-v3/wal-owner-checkpoint-source-subject/v1\0");
        hasher.update(stable.encode());
        let commitment: [u8; 32] = hasher.finalize().into();
        (commitment != [0; 32])
            .then_some(commitment)
            .ok_or(WitnessError::Corrupt)
    }

    pub(crate) fn exact_wal_owner_checkpoint_lease_successor_from(
        &self,
        previous: &Self,
        _token: crate::archive_v3_wal_owner::WalCheckpointSourceContext,
    ) -> Result<()> {
        let owner = previous.owner_id.ok_or(WitnessError::Fenced)?;
        if self
            .exact_wal_owner_heartbeat_from(previous, owner.as_bytes())
            .is_ok()
            || self
                .exact_wal_owner_reacquire_from(previous, owner.as_bytes())
                .is_ok()
        {
            Ok(())
        } else {
            Err(WitnessError::Fenced)
        }
    }

    /// Authenticate either the byte-exact retained terminal record or the
    /// sole witness-owned successor produced by releasing that record's
    /// maintenance lease. The release clears owner/expiry and monotonically
    /// advances the trusted provider tick. Every graph, database-generation,
    /// predecessor, registry, fencing, migration, and deletion/evidence field
    /// remains exact. A higher-fence released record cannot prove who held the
    /// intervening lease and is therefore rejected.
    pub(crate) fn exact_maintenance_terminal_or_release_from(
        &self,
        retained: &Self,
        owner: ObjectId,
    ) -> Result<bool> {
        self.exact_maintenance_release_from(retained, owner, MigrationState::WalAuthoritative)
    }

    /// Authenticate either the byte-exact retained Phase-1 advisory record or
    /// the sole witness-owned successor produced by releasing that record's
    /// maintenance lease. This is deliberately distinct from the
    /// WalAuthoritative terminal predicate: a ShadowWal release never grants
    /// serving or acknowledgement authority.
    pub(crate) fn exact_maintenance_advisory_or_release_from(
        &self,
        retained: &Self,
        owner: ObjectId,
    ) -> Result<bool> {
        self.exact_maintenance_release_from(retained, owner, MigrationState::ShadowWal)
    }

    fn exact_maintenance_release_from(
        &self,
        retained: &Self,
        owner: ObjectId,
        expected_migration: MigrationState,
    ) -> Result<bool> {
        retained.exact_active_lease_for_owner(owner)?;
        if !retained.valid()
            || retained.migration != expected_migration
            || retained.deletion != DeletionState::Active
        {
            return Err(WitnessError::Fenced);
        }
        if self == retained
            || self.exact_maintenance_release_active_at_provider_tick(
                retained,
                owner,
                expected_migration,
            )
        {
            return Ok(true);
        }
        if !self.valid()
            || self.archive_id != retained.archive_id
            || self.database_epoch != retained.database_epoch
            || self.database_epoch_generation != retained.database_epoch_generation
            || self.predecessor != retained.predecessor
            || self.root != retained.root
            || self.registry != retained.registry
            || retained.owner_id != Some(owner)
            || self.owner_id.is_some()
            || self.current_fencing_epoch != retained.current_fencing_epoch
            || self.next_fencing_epoch != retained.next_fencing_epoch
            || self.lease_expires_at_tick != 0
            || self.last_server_tick < retained.last_server_tick
            || self.migration != expected_migration
            || self.deletion != DeletionState::Active
            || self.deletion_fencing_epoch != retained.deletion_fencing_epoch
            || self.deletion_worker_id != retained.deletion_worker_id
            || self.deletion_operation_id != retained.deletion_operation_id
            || self.deletion_evidence != retained.deletion_evidence
        {
            return Err(WitnessError::Fenced);
        }
        Ok(false)
    }

    fn exact_maintenance_terminal_active_at_provider_tick(
        &self,
        retained: &Self,
        owner: ObjectId,
    ) -> bool {
        self.exact_maintenance_release_active_at_provider_tick(
            retained,
            owner,
            MigrationState::WalAuthoritative,
        )
    }

    fn exact_maintenance_advisory_active_at_provider_tick(
        &self,
        retained: &Self,
        owner: ObjectId,
    ) -> bool {
        self.exact_maintenance_release_active_at_provider_tick(
            retained,
            owner,
            MigrationState::ShadowWal,
        )
    }

    fn exact_maintenance_release_active_at_provider_tick(
        &self,
        retained: &Self,
        owner: ObjectId,
        expected_migration: MigrationState,
    ) -> bool {
        let same_fence_owner = self.current_fencing_epoch == retained.current_fencing_epoch
            && self.next_fencing_epoch == retained.next_fencing_epoch
            && self.lease_expires_at_tick == retained.lease_expires_at_tick;
        self.valid()
            && retained.valid()
            && self.archive_id == retained.archive_id
            && self.database_epoch == retained.database_epoch
            && self.database_epoch_generation == retained.database_epoch_generation
            && self.predecessor == retained.predecessor
            && self.root == retained.root
            && self.registry == retained.registry
            && self.owner_id == Some(owner)
            && retained.owner_id == Some(owner)
            && same_fence_owner
            && self.last_server_tick >= retained.last_server_tick
            && self.migration == expected_migration
            && retained.migration == expected_migration
            && self.deletion == DeletionState::Active
            && retained.deletion == DeletionState::Active
            && self.deletion_fencing_epoch == retained.deletion_fencing_epoch
            && self.deletion_worker_id == retained.deletion_worker_id
            && self.deletion_operation_id == retained.deletion_operation_id
            && self.deletion_evidence == retained.deletion_evidence
    }

    fn same_maintenance_lease_subject(&self, previous: &Self, owner: ObjectId) -> bool {
        self.valid()
            && previous.valid()
            && self.archive_id == previous.archive_id
            && self.database_epoch == previous.database_epoch
            && self.database_epoch_generation == previous.database_epoch_generation
            && self.predecessor == previous.predecessor
            && self.root == previous.root
            && self.registry == previous.registry
            && self.owner_id == Some(owner)
            && previous.owner_id == Some(owner)
            && self.migration == previous.migration
            && self.deletion == DeletionState::Active
            && previous.deletion == DeletionState::Active
            && self.deletion_fencing_epoch == previous.deletion_fencing_epoch
            && self.deletion_worker_id == previous.deletion_worker_id
            && self.deletion_operation_id == previous.deletion_operation_id
            && self.deletion_evidence == previous.deletion_evidence
    }

    /// Accept only the witness-owned transition produced by renewing the
    /// retained maintenance lease. Comparing the full records here prevents a
    /// same-owner record with a changed graph, next fence, or deletion tuple
    /// from being adopted as renewal authority after restart.
    pub(crate) fn exact_maintenance_renewal_from(
        &self,
        previous: &Self,
        owner: ObjectId,
    ) -> Result<WitnessLease> {
        let previous_lease = previous.exact_active_lease_for_owner(owner)?;
        let renewed_lease = self.exact_active_lease_for_owner(owner)?;
        if !self.same_maintenance_lease_subject(previous, owner)
            || self.current_fencing_epoch != previous.current_fencing_epoch
            || self.next_fencing_epoch != previous.next_fencing_epoch
            || self.last_server_tick <= previous.last_server_tick
            || self.lease_expires_at_tick <= previous.lease_expires_at_tick
            || renewed_lease.fencing_epoch != previous_lease.fencing_epoch
        {
            return Err(WitnessError::Fenced);
        }
        Ok(renewed_lease)
    }

    /// Accept only the witness-owned transition produced by acquiring the
    /// retained owner after its prior lease expired. A reacquire consumes the
    /// exact previously advertised next fence, advances the next fence once,
    /// and monotonically advances trusted time and expiry while every graph,
    /// migration, and deletion fact remains identical.
    pub(crate) fn exact_maintenance_reacquire_from(
        &self,
        previous: &Self,
        owner: ObjectId,
    ) -> Result<WitnessLease> {
        let previous_lease = previous.exact_active_lease_for_owner(owner)?;
        let reacquired_lease = self.exact_active_lease_for_owner(owner)?;
        if !self.same_maintenance_lease_subject(previous, owner)
            || self.current_fencing_epoch != previous.next_fencing_epoch
            || self.next_fencing_epoch
                != self
                    .current_fencing_epoch
                    .checked_add(1)
                    .ok_or(WitnessError::Fenced)?
            || self.last_server_tick <= previous.last_server_tick
            || self.last_server_tick < previous.lease_expires_at_tick
            || self.lease_expires_at_tick <= previous.lease_expires_at_tick
            || reacquired_lease.fencing_epoch <= previous_lease.fencing_epoch
        {
            return Err(WitnessError::Fenced);
        }
        Ok(reacquired_lease)
    }

    /// Deterministically apply one already-authenticated migration advance to
    /// a private in-memory copy. Maintenance control persists these exact
    /// bytes before the provider request, so restart compares full witness
    /// state rather than reconstructing or accepting a caller root.
    pub(crate) fn exact_migration_candidate(
        &self,
        advance: &RootAdvance,
        next: MigrationState,
    ) -> Result<WitnessRecord> {
        if !self.valid() || advance.archive_id() != self.archive_id {
            return Err(WitnessError::InvalidTransition);
        }
        let local = InMemoryWitness::from_provider_record_at_tick(
            Some(self.encode()),
            self.last_server_tick,
        )?;
        local
            .advance_migration(advance.clone(), next)
            .map(|receipt| receipt.record().clone())
    }

    /// Encrypted-control restart validation for retained maintenance sends.
    /// The persisted candidate is comparison data only: applying its root and
    /// registry to this exact current record must reproduce every candidate
    /// byte before control may remint a durable stage.
    pub(crate) fn retained_maintenance_candidate_is_exact(
        &self,
        _token: crate::cp::control_store::MaintenancePersistenceContext,
        candidate: &WitnessRecord,
        owner: ObjectId,
        next: MigrationState,
    ) -> bool {
        let Ok(lease) = self.exact_active_lease_for_owner(owner) else {
            return false;
        };
        let advance = RootAdvance {
            lease,
            expected_root: self.root,
            expected_registry: self.registry,
            candidate_registry: candidate.registry,
            candidate: candidate.root,
        };
        self.exact_migration_candidate(&advance, next)
            .is_ok_and(|expected| expected == *candidate)
    }

    /// Validate a retained migration candidate after the provider has moved
    /// to that candidate and may subsequently have renewed the same lease.
    /// The only mutable fields admitted are the monotonically newer provider
    /// tick and lease expiry; all graph, registry, ownership, fencing, and
    /// deletion facts remain byte-for-byte identical.
    pub(crate) fn retained_maintenance_candidate_matches_current(
        &self,
        _token: crate::cp::control_store::MaintenancePersistenceContext,
        candidate: &WitnessRecord,
        owner: ObjectId,
        next: MigrationState,
    ) -> bool {
        self.valid()
            && candidate.valid()
            && self.migration == next
            && candidate.migration == next
            && self.deletion == DeletionState::Active
            && candidate.deletion == DeletionState::Active
            && self.archive_id == candidate.archive_id
            && self.database_epoch == candidate.database_epoch
            && self.database_epoch_generation == candidate.database_epoch_generation
            && self.predecessor == candidate.predecessor
            && self.root == candidate.root
            && self.registry == candidate.registry
            && self.owner_id == Some(owner)
            && candidate.owner_id == Some(owner)
            && self.current_fencing_epoch == candidate.current_fencing_epoch
            && self.next_fencing_epoch == candidate.next_fencing_epoch
            && candidate.lease_expires_at_tick <= self.lease_expires_at_tick
            && candidate.last_server_tick <= self.last_server_tick
            && self.deletion_fencing_epoch == candidate.deletion_fencing_epoch
            && self.deletion_worker_id == candidate.deletion_worker_id
            && self.deletion_operation_id == candidate.deletion_operation_id
            && self.deletion_evidence == candidate.deletion_evidence
    }

    /// Validate the current provider record as a monotone lease descendant of
    /// an already-settled migration candidate. This deliberately differs from
    /// the strict one-step renewal and reacquire validators: encrypted control
    /// may restart after more than one provider-authenticated lease transition,
    /// while the byte-exact migration candidate must remain immutable.
    pub(crate) fn retained_maintenance_candidate_has_lease_descendant(
        &self,
        _token: crate::cp::control_store::MaintenancePersistenceContext,
        candidate: &WitnessRecord,
        owner: ObjectId,
        next: MigrationState,
    ) -> bool {
        let immutable_subject_is_exact = self.valid()
            && candidate.valid()
            && self.migration == next
            && candidate.migration == next
            && self.deletion == DeletionState::Active
            && candidate.deletion == DeletionState::Active
            && self.archive_id == candidate.archive_id
            && self.database_epoch == candidate.database_epoch
            && self.database_epoch_generation == candidate.database_epoch_generation
            && self.predecessor == candidate.predecessor
            && self.root == candidate.root
            && self.registry == candidate.registry
            && self.owner_id == Some(owner)
            && candidate.owner_id == Some(owner)
            && self.deletion_fencing_epoch == candidate.deletion_fencing_epoch
            && self.deletion_worker_id == candidate.deletion_worker_id
            && self.deletion_operation_id == candidate.deletion_operation_id
            && self.deletion_evidence == candidate.deletion_evidence;
        let canonical_fence_pairs = candidate
            .current_fencing_epoch
            .checked_add(1)
            .is_some_and(|next_fence| next_fence == candidate.next_fencing_epoch)
            && self
                .current_fencing_epoch
                .checked_add(1)
                .is_some_and(|next_fence| next_fence == self.next_fencing_epoch);
        let same_fence_renewal_lineage = self.current_fencing_epoch
            == candidate.current_fencing_epoch
            && self.next_fencing_epoch == candidate.next_fencing_epoch
            && self.last_server_tick >= candidate.last_server_tick
            && self.lease_expires_at_tick >= candidate.lease_expires_at_tick;
        let reacquired_lineage = self.current_fencing_epoch >= candidate.next_fencing_epoch
            && self.last_server_tick >= candidate.lease_expires_at_tick
            && self.lease_expires_at_tick > candidate.lease_expires_at_tick;
        immutable_subject_is_exact
            && canonical_fence_pairs
            && (same_fence_renewal_lineage || reacquired_lineage)
    }

    /// Validate the retained predecessor of a terminal maintenance candidate.
    /// The predecessor may carry an older exact lease expiry/provider tick;
    /// applying the terminal root to it must still produce a candidate whose
    /// only differences from the current record are those admitted monotonic
    /// lease fields.
    pub(crate) fn retained_maintenance_predecessor_matches_current(
        &self,
        token: crate::cp::control_store::MaintenancePersistenceContext,
        current: &WitnessRecord,
        retained_current_candidate: &WitnessRecord,
        owner: ObjectId,
        next: MigrationState,
    ) -> bool {
        if !current.retained_maintenance_candidate_has_lease_descendant(
            token,
            retained_current_candidate,
            owner,
            next,
        ) {
            return false;
        }
        let mut predecessor_at_send = self.clone();
        predecessor_at_send.current_fencing_epoch =
            retained_current_candidate.current_fencing_epoch;
        predecessor_at_send.next_fencing_epoch = retained_current_candidate.next_fencing_epoch;
        predecessor_at_send.lease_expires_at_tick =
            retained_current_candidate.lease_expires_at_tick;
        predecessor_at_send.last_server_tick = retained_current_candidate.last_server_tick;
        if !predecessor_at_send.retained_maintenance_candidate_has_lease_descendant(
            token,
            self,
            owner,
            self.migration,
        ) {
            return false;
        }
        let Ok(lease) = predecessor_at_send.exact_active_lease_for_owner(owner) else {
            return false;
        };
        let advance = RootAdvance {
            lease,
            expected_root: predecessor_at_send.root,
            expected_registry: predecessor_at_send.registry,
            candidate_registry: retained_current_candidate.registry,
            candidate: retained_current_candidate.root,
        };
        predecessor_at_send
            .exact_migration_candidate(&advance, next)
            .is_ok_and(|candidate| candidate == *retained_current_candidate)
    }

    /// Firestore's transaction read advances only the trusted local tick while
    /// validating a retained maintenance send. All durable candidate fields
    /// except that refreshed tick must remain identical before the adapter may
    /// commit the byte-exact control-retained candidate.
    pub(crate) fn matches_retained_maintenance_candidate(&self, candidate: &WitnessRecord) -> bool {
        self.valid()
            && candidate.valid()
            && self.archive_id == candidate.archive_id
            && self.database_epoch == candidate.database_epoch
            && self.database_epoch_generation == candidate.database_epoch_generation
            && self.predecessor == candidate.predecessor
            && self.root == candidate.root
            && self.registry == candidate.registry
            && self.owner_id == candidate.owner_id
            && self.current_fencing_epoch == candidate.current_fencing_epoch
            && self.next_fencing_epoch == candidate.next_fencing_epoch
            && self.lease_expires_at_tick == candidate.lease_expires_at_tick
            && self.last_server_tick >= candidate.last_server_tick
            && self.migration == candidate.migration
            && self.deletion == candidate.deletion
            && self.deletion_fencing_epoch == candidate.deletion_fencing_epoch
            && self.deletion_worker_id == candidate.deletion_worker_id
            && self.deletion_operation_id == candidate.deletion_operation_id
            && self.deletion_evidence == candidate.deletion_evidence
    }
    pub(crate) fn predecessor_root(&self) -> Option<RootCommitment> {
        self.predecessor.map(|value| value.root)
    }
    pub(crate) fn predecessor_registry(&self) -> Option<KeyRegistryReference> {
        self.predecessor.map(|value| value.registry)
    }
    #[cfg(test)]
    pub(crate) fn with_registry_for_test(&self, registry: KeyRegistryReference) -> Self {
        let mut forged = self.clone();
        forged.registry = registry;
        forged
    }
    #[cfg(test)]
    pub(crate) fn with_archive_id_for_test(&self, archive_id: ArchiveId) -> Self {
        let mut forged = self.clone();
        forged.archive_id = archive_id;
        forged
    }
    #[cfg(test)]
    pub(crate) fn tombstoned_for_test(&self) -> Self {
        let mut forged = self.clone();
        forged.deletion = DeletionState::Tombstoned;
        forged
    }
    #[cfg(test)]
    pub(crate) fn with_root_for_test(&self, root: RootCommitment) -> Self {
        let mut forged = self.clone();
        forged.root = root;
        forged
    }
    #[cfg(test)]
    pub(crate) fn with_candidate_root_for_test(
        &self,
        candidate: RootReference,
        owner_fencing_epoch: u64,
    ) -> Self {
        let mut forged = self.clone();
        forged.root = RootCommitment::candidate(
            self.database_epoch,
            self.registry.key_epoch,
            owner_fencing_epoch,
            self.root.root(),
            candidate,
        );
        forged
    }
    #[cfg(test)]
    pub(crate) fn renewed_maintenance_lease_for_test(&self) -> Self {
        let mut renewed = self.clone();
        renewed.last_server_tick = self
            .last_server_tick
            .checked_add(1)
            .expect("test maintenance tick overflow");
        renewed.lease_expires_at_tick = self
            .lease_expires_at_tick
            .checked_add(10)
            .expect("test maintenance expiry overflow");
        renewed
    }
    #[cfg(test)]
    pub(crate) fn reacquired_maintenance_lease_for_test(&self) -> Self {
        let mut reacquired = self.clone();
        reacquired.current_fencing_epoch = self.next_fencing_epoch;
        reacquired.next_fencing_epoch = self
            .next_fencing_epoch
            .checked_add(1)
            .expect("test maintenance fence overflow");
        reacquired.last_server_tick = self.lease_expires_at_tick;
        reacquired.lease_expires_at_tick = self
            .lease_expires_at_tick
            .checked_add(10)
            .expect("test maintenance expiry overflow");
        reacquired
    }
    #[cfg(test)]
    pub(crate) fn with_next_fencing_epoch_for_test(&self, next: u64) -> Self {
        let mut forged = self.clone();
        forged.next_fencing_epoch = next;
        forged
    }
    #[cfg(test)]
    pub(crate) fn with_lease_expiry_for_test(&self, expiry: u64) -> Self {
        let mut forged = self.clone();
        forged.lease_expires_at_tick = expiry;
        forged
    }
    #[cfg(test)]
    pub(crate) fn with_deletion_for_test(&self, deletion: DeletionState) -> Self {
        let mut forged = self.clone();
        forged.deletion = deletion;
        forged
    }
    #[cfg(test)]
    pub(crate) fn with_migration_for_test(&self, migration: MigrationState) -> Self {
        let mut forged = self.clone();
        forged.migration = migration;
        forged
    }
    #[cfg(test)]
    pub(crate) fn released_wal_owner_for_test(&self) -> Self {
        let mut released = self.clone();
        released.migration = MigrationState::WalAuthoritative;
        released.owner_id = None;
        released.lease_expires_at_tick = 0;
        released
    }
    pub fn migration(&self) -> MigrationState {
        self.migration
    }
    pub fn deletion(&self) -> DeletionState {
        self.deletion
    }
    pub(crate) fn last_server_tick(&self) -> u64 {
        self.last_server_tick
    }
    fn valid(&self) -> bool {
        nonzero_id(self.archive_id.as_bytes())
            && nonzero_id(self.database_epoch.as_bytes())
            && self.root.valid()
            && self.root.database_epoch == self.database_epoch
            && self.root.key_epoch == self.registry.key_epoch
            && self.registry.valid()
            && self.predecessor.is_none_or(|predecessor| {
                predecessor.root.valid()
                    && predecessor.registry.valid()
                    && predecessor.root.database_epoch != self.database_epoch
                    && predecessor.root.key_epoch == predecessor.registry.key_epoch
                    && predecessor.root.root.sequence < self.root.root.sequence
                    && predecessor.registry.rotation_generation <= self.registry.rotation_generation
                    && (predecessor.registry.rotation_generation
                        < self.registry.rotation_generation
                        || predecessor.registry == self.registry)
            })
            && (self.database_epoch_generation == 0) == self.predecessor.is_none()
            && self.database_epoch_generation <= 1
            && epoch_lifecycle_valid(self)
            && self.next_fencing_epoch > self.current_fencing_epoch
            && match self.owner_id {
                Some(v) => nonzero_id(v.as_bytes()) && self.lease_expires_at_tick != 0,
                None => self.lease_expires_at_tick == 0,
            }
            && match self.deletion {
                DeletionState::Active => {
                    self.deletion_fencing_epoch.is_none()
                        && self.deletion_worker_id.is_none()
                        && self.deletion_operation_id.is_none()
                        && self.root.owner_fencing_epoch <= self.current_fencing_epoch
                        && !matches!(
                            self.migration,
                            MigrationState::Deleting | MigrationState::Deleted
                        )
                        && deletion_evidence_valid(self.deletion, &self.deletion_evidence)
                }
                _ => {
                    self.deletion_fencing_epoch.is_some_and(|v| {
                        v > self.current_fencing_epoch
                            && self.next_fencing_epoch > v
                            && self.root.owner_fencing_epoch <= self.current_fencing_epoch
                    }) && self
                        .deletion_worker_id
                        .is_some_and(|worker_id| nonzero_id(worker_id.as_bytes()))
                        && self
                            .deletion_operation_id
                            .is_some_and(|operation_id| nonzero_id(operation_id.as_bytes()))
                        && self.owner_id.is_none()
                        && self.lease_expires_at_tick == 0
                        && matches!(
                            (self.deletion, self.migration),
                            (
                                DeletionState::Tombstoned
                                    | DeletionState::CryptographicallyErased
                                    | DeletionState::LogicalObjectsAbsent,
                                MigrationState::Deleting
                            ) | (DeletionState::PhysicalComplete, MigrationState::Deleted)
                        )
                        && deletion_evidence_valid(self.deletion, &self.deletion_evidence)
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
        put(
            &mut out,
            &mut p,
            &self.database_epoch_generation.to_be_bytes(),
        );
        put(&mut out, &mut p, &[self.predecessor.is_some() as u8]);
        if let Some(x) = self.predecessor {
            root_commitment_put(&mut out, &mut p, x.root);
            registry_put(&mut out, &mut p, x.registry);
        } else {
            put(&mut out, &mut p, &[0; 226]);
        }
        root_commitment_put(&mut out, &mut p, self.root);
        registry_put(&mut out, &mut p, self.registry);
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
        put(
            &mut out,
            &mut p,
            self.deletion_worker_id
                .unwrap_or_else(|| ObjectId::from_bytes([0; 16]))
                .as_bytes(),
        );
        put(
            &mut out,
            &mut p,
            self.deletion_operation_id
                .unwrap_or_else(|| ObjectId::from_bytes([0; 16]))
                .as_bytes(),
        );
        put(&mut out, &mut p, &self.last_server_tick.to_be_bytes());
        put(
            &mut out,
            &mut p,
            &[self.migration as u8, self.deletion as u8],
        );
        for evidence in self.deletion_evidence {
            if let Some(x) = evidence {
                put(&mut out, &mut p, &[x.kind as u8]);
                put(&mut out, &mut p, &x.commitment);
            } else {
                put(&mut out, &mut p, &[0; 33]);
            }
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
        let database_epoch_generation = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let predecessor_present = boolean(take(input, &mut p, 1)?[0])?;
        let predecessor = if predecessor_present {
            Some(Predecessor {
                root: root_commitment_take(input, &mut p)?,
                registry: registry_take(input, &mut p)?,
            })
        } else {
            if take(input, &mut p, 226)?.iter().any(|byte| *byte != 0) {
                return Err(WitnessError::Corrupt);
            }
            None
        };
        let root = root_commitment_take(input, &mut p)?;
        let registry = registry_take(input, &mut p)?;
        let owner = ObjectId::from_bytes(array(take(input, &mut p, 16)?)?);
        let current = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let next = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let expiry = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let deletion_fence = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let deletion_worker = ObjectId::from_bytes(array(take(input, &mut p, 16)?)?);
        let deletion_operation = ObjectId::from_bytes(array(take(input, &mut p, 16)?)?);
        let last_tick = u64::from_be_bytes(array(take(input, &mut p, 8)?)?);
        let migration = MigrationState::decode(take(input, &mut p, 1)?[0])?;
        let deletion = DeletionState::decode(take(input, &mut p, 1)?[0])?;
        let mut deletion_evidence = [None; DELETION_EVIDENCE_STAGES];
        for evidence in &mut deletion_evidence {
            let kind = take(input, &mut p, 1)?[0];
            let commitment = array(take(input, &mut p, 32)?)?;
            *evidence = if kind == 0 {
                if nonzero_hash(&commitment) {
                    return Err(WitnessError::Corrupt);
                }
                None
            } else {
                Some(DeletionEvidence {
                    kind: DeletionEvidenceKind::decode(kind)?,
                    commitment,
                })
            };
        }
        if p != input.len() {
            return Err(WitnessError::Corrupt);
        }
        let record = Self {
            archive_id,
            database_epoch,
            database_epoch_generation,
            predecessor,
            root,
            registry,
            owner_id: nonzero_id(owner.as_bytes()).then_some(owner),
            current_fencing_epoch: current,
            next_fencing_epoch: next,
            lease_expires_at_tick: expiry,
            deletion_fencing_epoch: (deletion_fence != 0).then_some(deletion_fence),
            deletion_worker_id: nonzero_id(deletion_worker.as_bytes()).then_some(deletion_worker),
            deletion_operation_id: nonzero_id(deletion_operation.as_bytes())
                .then_some(deletion_operation),
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
    pub(crate) fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }
    #[cfg(test)]
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

    pub(crate) async fn from_authenticated_genesis(
        archive_id: ArchiveId,
        registry: KeyRegistryReference,
        context: &ObjectContext,
        provider: &dyn ExactRootProvider,
        cipher: &VerifiedArchiveCipher,
    ) -> Result<Self> {
        let genesis_root = RootCommitment::from_authenticated_provider_object(
            archive_id, registry, context, provider, cipher,
        )
        .await?;
        if genesis_root.parent.is_some()
            || genesis_root.root.sequence != 0
            || genesis_root.key_epoch != registry.key_epoch
            || !registry.valid()
        {
            return Err(WitnessError::Malformed);
        }
        Ok(Self {
            archive_id,
            database_epoch: genesis_root.database_epoch,
            genesis_root,
            registry,
        })
    }

    pub(crate) fn expected_initial_record_bytes(&self) -> Result<[u8; WITNESS_RECORD_BYTES]> {
        let witness = InMemoryWitness::with_clock(Arc::new(SystemClock));
        witness
            .bootstrap(self.clone())
            .map(|record| record.encode())
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
impl WitnessLease {
    pub(crate) fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }
    pub(crate) fn database_epoch(&self) -> DatabaseEpoch {
        self.database_epoch
    }
    pub(crate) fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }
    pub(crate) fn owner(&self) -> ObjectId {
        self.owner
    }
    pub(crate) fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }
    pub(crate) fn expires_at_tick(&self) -> u64 {
        self.expires_at_tick
    }
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
#[cfg(test)]
impl DeletionAuthorization {
    pub(crate) fn with_fencing_epoch_for_test(self, fencing_epoch: u64) -> Self {
        Self {
            fencing_epoch,
            ..self
        }
    }
}

/// Opaque, provider-authenticated destructive-operation binding.  It is
/// derived only from a fresh deletion-only witness recovery and carries the
/// archive/database/fence/worker/operation tuple without exposing its
/// persisted identity fields to deletion providers or logs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeletionExecutionBinding {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    deletion_fencing_epoch: u64,
    worker_id: ObjectId,
    operation_id: ObjectId,
}

impl DeletionExecutionBinding {
    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"kioku/archive-v3/deletion-execution-binding/v1\0");
        hasher.update(self.archive_id.as_bytes());
        hasher.update(self.database_epoch.as_bytes());
        hasher.update(self.deletion_fencing_epoch.to_be_bytes());
        hasher.update(self.worker_id.as_bytes());
        hasher.update(self.operation_id.as_bytes());
        hasher.finalize().into()
    }

    #[cfg(test)]
    pub(crate) const fn with_archive_id_for_test(self, archive_id: ArchiveId) -> Self {
        Self { archive_id, ..self }
    }

    #[cfg(test)]
    pub(crate) const fn with_database_epoch_for_test(self, database_epoch: DatabaseEpoch) -> Self {
        Self {
            database_epoch,
            ..self
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_fencing_epoch_for_test(self, deletion_fencing_epoch: u64) -> Self {
        Self {
            deletion_fencing_epoch,
            ..self
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_worker_for_test(self, worker_id: ObjectId) -> Self {
        Self { worker_id, ..self }
    }

    #[cfg(test)]
    pub(crate) const fn with_operation_for_test(self, operation_id: ObjectId) -> Self {
        Self {
            operation_id,
            ..self
        }
    }
}

impl fmt::Debug for DeletionExecutionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeletionExecutionBinding(<opaque>)")
    }
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
    candidate_registry: KeyRegistryReference,
    candidate: RootCommitment,
}

/// Exact ordinary-root transition input retained by the inactive WAL owner.
/// The provider may advance only its trusted transaction tick; every owner,
/// lease, fence, predecessor, registry, epoch, deletion, and candidate-root
/// fact is rederived from the byte-exact expected witness on every reopen.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedWalRootAdvance {
    expected: [u8; WITNESS_RECORD_BYTES],
    advance: RootAdvance,
}

impl AuthenticatedWalRootAdvance {
    pub(crate) fn from_expected_witness(
        _token: crate::archive_v3_wal_owner::WalWitnessAdvanceContext,
        expected: &WitnessRecord,
        candidate: RootCommitment,
    ) -> Result<Self> {
        if !expected.valid()
            || expected.deletion != DeletionState::Active
            || expected.migration != MigrationState::WalAuthoritative
        {
            return Err(WitnessError::InvalidTransition);
        }
        let owner = expected.owner_id.ok_or(WitnessError::Fenced)?;
        let advance = RootAdvance {
            lease: expected.exact_active_lease_for_owner(owner)?,
            expected_root: expected.root,
            expected_registry: expected.registry,
            candidate_registry: expected.registry,
            candidate,
        };
        normal_ok(expected, &advance, expected.last_server_tick, Normal::Root)?;
        Ok(Self {
            expected: expected.encode(),
            advance,
        })
    }

    pub(crate) fn from_persisted(
        token: crate::archive_v3_wal_owner::WalWitnessAdvanceContext,
        expected: &[u8; WITNESS_RECORD_BYTES],
        candidate: RootCommitment,
    ) -> Result<Self> {
        let expected_record = WitnessRecord::decode(expected)?;
        let value = Self::from_expected_witness(token, &expected_record, candidate)?;
        if &value.expected != expected {
            return Err(WitnessError::Corrupt);
        }
        Ok(value)
    }

    pub(crate) const fn expected_witness(&self) -> &[u8; WITNESS_RECORD_BYTES] {
        &self.expected
    }

    pub(crate) const fn candidate(&self) -> RootCommitment {
        self.advance.candidate
    }

    pub(crate) const fn candidate_registry(&self) -> KeyRegistryReference {
        self.advance.candidate_registry
    }

    pub(crate) fn provider_advance(
        &self,
        _token: crate::archive_v3_wal_owner::WalWitnessAdvanceContext,
    ) -> RootAdvance {
        self.advance.clone()
    }

    pub(crate) fn validate_observed(&self, observed: &WitnessRecord) -> Result<()> {
        let expected = WitnessRecord::decode(&self.expected)?;
        if observed.last_server_tick < expected.last_server_tick
            || observed.last_server_tick >= self.advance.lease.expires_at_tick
        {
            return Err(WitnessError::Fenced);
        }
        let local = InMemoryWitness::from_provider_record_at_tick(
            Some(self.expected),
            observed.last_server_tick,
        )?;
        let reproduced = local.compare_and_advance_root(self.advance.clone())?;
        (reproduced.record() == observed)
            .then_some(())
            .ok_or(WitnessError::InvalidTransition)
    }
}

impl fmt::Debug for AuthenticatedWalRootAdvance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedWalRootAdvance(<opaque>)")
    }
}

impl RootAdvance {
    pub(crate) fn archive_id(&self) -> ArchiveId {
        self.lease.archive_id
    }

    /// Rehydrate one exact durable send after process restart. The candidate
    /// contributes no authority: rebuilding and applying this advance to the
    /// freshly read exact current witness must reproduce every candidate byte.
    pub(crate) fn from_retained_migration_candidate(
        _token: crate::archive_v3_maintenance_import::MaintenanceWitnessRecoveryContext,
        current: &WitnessRecord,
        candidate: &WitnessRecord,
        owner: ObjectId,
        next: MigrationState,
    ) -> Result<Self> {
        let lease = current.exact_active_lease_for_owner(owner)?;
        let advance = Self {
            lease,
            expected_root: current.root,
            expected_registry: current.registry,
            candidate_registry: candidate.registry,
            candidate: candidate.root,
        };
        if current.exact_migration_candidate(&advance, next)? != *candidate {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(advance)
    }
    #[cfg(test)]
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
            candidate_registry: expected_registry,
            candidate,
        }
    }

    pub(crate) async fn from_authenticated_candidate(
        lease: WitnessLease,
        expected_root: RootCommitment,
        expected_registry: KeyRegistryReference,
        candidate_registry: KeyRegistryReference,
        context: &ObjectContext,
        provider: &dyn ExactRootProvider,
        cipher: &VerifiedArchiveCipher,
    ) -> Result<Self> {
        Ok(Self {
            lease,
            expected_root,
            expected_registry,
            candidate_registry,
            candidate: RootCommitment::from_authenticated_provider_object(
                lease.archive_id,
                candidate_registry,
                context,
                provider,
                cipher,
            )
            .await?,
        })
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeletionAdvance {
    authorization: DeletionAuthorization,
    expected_root: RootCommitment,
    expected_registry: KeyRegistryReference,
}

/// Exact-current deletion transition. Unlike the legacy tombstone seam this
/// does not require a writer lease and cannot publish a new root as a side
/// effect of deletion. The complete mutable witness snapshot is captured from
/// one authenticated read and compared transactionally before the owner is
/// revoked and the deletion fence is installed.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TombstoneAdvance {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    expected_root: RootCommitment,
    expected_registry: KeyRegistryReference,
    expected_current_fencing_epoch: u64,
    expected_next_fencing_epoch: u64,
}

impl TombstoneAdvance {
    pub(crate) fn from_current(record: &WitnessRecord) -> Result<Self> {
        if record.deletion != DeletionState::Active
            || record.next_fencing_epoch == 0
            || record.next_fencing_epoch <= record.current_fencing_epoch
        {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(Self {
            archive_id: record.archive_id,
            database_epoch: record.database_epoch,
            expected_root: record.root,
            expected_registry: record.registry,
            expected_current_fencing_epoch: record.current_fencing_epoch,
            expected_next_fencing_epoch: record.next_fencing_epoch,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    #[cfg(test)]
    pub(crate) const fn with_root_for_test(self, expected_root: RootCommitment) -> Self {
        Self {
            expected_root,
            ..self
        }
    }
}

impl fmt::Debug for TombstoneAdvance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TombstoneAdvance(<opaque>)")
    }
}
impl DeletionAdvance {
    pub(crate) fn archive_id(&self) -> ArchiveId {
        self.authorization.archive_id
    }
    pub(crate) const fn new(
        authorization: DeletionAuthorization,
        expected_root: RootCommitment,
        expected_registry: KeyRegistryReference,
    ) -> Self {
        Self {
            authorization,
            expected_root,
            expected_registry,
        }
    }
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
impl TombstoneReceipt {
    pub fn receipt(&self) -> &WitnessReceipt {
        &self.receipt
    }

    pub fn authorization(&self) -> DeletionAuthorization {
        self.authorization
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeletionRecovery {
    receipt: WitnessReceipt,
    authorization: DeletionAuthorization,
}
impl DeletionRecovery {
    pub fn receipt(&self) -> &WitnessReceipt {
        &self.receipt
    }

    pub fn authorization(&self) -> DeletionAuthorization {
        self.authorization
    }

    pub(crate) fn execution_binding(&self) -> Result<DeletionExecutionBinding> {
        let record = self.receipt.record();
        let deletion_fencing_epoch = record.deletion_fencing_epoch.ok_or(WitnessError::Corrupt)?;
        let worker_id = record.deletion_worker_id.ok_or(WitnessError::Corrupt)?;
        let operation_id = record.deletion_operation_id.ok_or(WitnessError::Corrupt)?;
        if record.deletion == DeletionState::Active
            || self.authorization.archive_id != record.archive_id
            || self.authorization.database_epoch != record.database_epoch
            || self.authorization.fencing_epoch != deletion_fencing_epoch
        {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(DeletionExecutionBinding {
            archive_id: record.archive_id,
            database_epoch: record.database_epoch,
            deletion_fencing_epoch,
            worker_id,
            operation_id,
        })
    }

    /// Convert deletion-only authorization into the exact immutable graph
    /// snapshot accepted by the reachability visitor. Only the Tombstoned
    /// state is usable: after key erasure, archive metadata must never be
    /// opened again, and Active is not deletion authority.
    pub(crate) fn tombstoned_recovery_root(&self) -> Result<RecoveryRoot> {
        let record = self.receipt.record();
        let _binding = self.execution_binding()?;
        if record.deletion != DeletionState::Tombstoned {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(RecoveryRoot {
            archive_id: record.archive_id,
            root: record.root,
            registry: record.registry,
            predecessor: record.predecessor,
            migration: record.migration,
            deletion: record.deletion,
        })
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryRoot {
    archive_id: ArchiveId,
    root: RootCommitment,
    registry: KeyRegistryReference,
    predecessor: Option<Predecessor>,
    migration: MigrationState,
    deletion: DeletionState,
}
impl RecoveryRoot {
    /// WAL-owner recovery authority is minted only from one exact active
    /// WalAuthoritative provider record. It is deliberately distinct from the
    /// maintenance migration recovery constructor.
    pub(crate) fn from_exact_wal_authoritative_record(record: &WitnessRecord) -> Result<Self> {
        if !record.valid()
            || record.deletion != DeletionState::Active
            || record.migration != MigrationState::WalAuthoritative
        {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(Self {
            archive_id: record.archive_id,
            root: record.root,
            registry: record.registry,
            predecessor: record.predecessor,
            migration: record.migration,
            deletion: record.deletion,
        })
    }

    /// Convert one freshly authenticated exact provider record into recovery
    /// authority only while it is the active, non-deleting archive. This is
    /// the maintenance-import counterpart to the deletion-only conversion;
    /// callers cannot nominate a root independently of the witness bytes.
    pub(crate) fn from_exact_active_record(record: &WitnessRecord) -> Result<Self> {
        if !record.valid()
            || record.deletion != DeletionState::Active
            || !matches!(
                record.migration,
                MigrationState::Legacy | MigrationState::ShadowWal
            )
        {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(Self {
            archive_id: record.archive_id,
            root: record.root,
            registry: record.registry,
            predecessor: record.predecessor,
            migration: record.migration,
            deletion: record.deletion,
        })
    }

    /// WAL-owner-only recovery conversion. The exact provider record must be
    /// Active, WalAuthoritative, and hold a live witness-owned lease; a caller
    /// still cannot nominate any root or registry field independently.
    pub(crate) fn from_exact_wal_owner_record(record: &WitnessRecord) -> Result<Self> {
        let owner = record.owner_id.ok_or(WitnessError::Fenced)?;
        record.exact_active_lease_for_owner(owner)?;
        if !record.valid()
            || record.deletion != DeletionState::Active
            || record.migration != MigrationState::WalAuthoritative
        {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(Self {
            archive_id: record.archive_id,
            root: record.root,
            registry: record.registry,
            predecessor: record.predecessor,
            migration: record.migration,
            deletion: record.deletion,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_migration_for_test(mut self, migration: MigrationState) -> Self {
        self.migration = migration;
        self
    }

    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub fn root(&self) -> RootCommitment {
        self.root
    }
    pub fn registry(&self) -> KeyRegistryReference {
        self.registry
    }
    pub fn predecessor_database_epoch(&self) -> Option<DatabaseEpoch> {
        self.predecessor.map(|x| x.root.database_epoch)
    }
    pub fn predecessor_root(&self) -> Option<RootCommitment> {
        self.predecessor.map(|x| x.root)
    }
    pub fn predecessor_registry(&self) -> Option<KeyRegistryReference> {
        self.predecessor.map(|x| x.registry)
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

/// Narrow exact-current admission seam for inactive recovery consumers.  A
/// retained `RecoveryRoot` is only a snapshot; callers must re-admit it at
/// the witness immediately before issuing any recovery capability.
#[async_trait::async_trait]
pub(crate) trait ExactCurrentRecoveryAdmission: Send + Sync {
    async fn admit_exact_current(
        &self,
        expected: &RecoveryRoot,
    ) -> std::result::Result<(), WitnessError>;
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
    #[cfg(test)]
    fn tombstone(
        &self,
        advance: RootAdvance,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> Result<TombstoneReceipt>;
    fn tombstone_current(
        &self,
        advance: TombstoneAdvance,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> Result<TombstoneReceipt>;
    /// Reconstruct deletion-only authorization from the durable provider record
    /// after a worker/provider restart. The provider reauthenticates and matches
    /// the exact persisted worker/operation identity; this never re-enables
    /// ordinary recovery.
    fn resume_deletion(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> Result<DeletionRecovery>;
    /// Re-authenticate an already-complete deletion and verify that the raw
    /// inventory/drain tuple still hashes to the retained final evidence. This
    /// closes the crash window between witness completion and lifecycle-ledger
    /// payload cleanup without changing the witness encoding.
    fn verify_physical_completion(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> Result<DeletionRecovery>;
    fn advance_deletion(
        &self,
        advance: DeletionAdvance,
        next: DeletionState,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> Result<WitnessReceipt>;
}

struct State {
    available: bool,
    records: BTreeMap<ArchiveId, WitnessRecord>,
}
pub struct InMemoryWitness {
    clock: Arc<dyn TrustedClock>,
    deletion_authenticator: Arc<dyn DeletionWorkerAuthenticator>,
    state: Mutex<State>,
}
impl InMemoryWitness {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
    #[cfg(test)]
    pub(crate) fn with_incrementing_clock_for_test(start_tick: u64) -> Self {
        struct IncrementingClock(std::sync::atomic::AtomicU64);
        impl TrustedClock for IncrementingClock {
            fn now_tick(&self) -> Result<u64> {
                self.0
                    .fetch_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |tick| tick.checked_add(1),
                    )
                    .map_err(|_| WitnessError::Clock)
            }
        }
        Self::with_clock(Arc::new(IncrementingClock(
            std::sync::atomic::AtomicU64::new(start_tick),
        )))
    }
    fn with_clock(clock: Arc<dyn TrustedClock>) -> Self {
        Self::with_clock_and_authenticator(clock, Arc::new(DenyDeletionWorkers))
    }
    /// Replays one provider record against a provider-supplied, transaction
    /// read-time-derived tick.  This is deliberately crate-private: concrete
    /// witness adapters use it to reuse the audited transition rules without
    /// treating a local wall clock as authority.
    pub(crate) fn from_provider_record_at_tick(
        record: Option<[u8; WITNESS_RECORD_BYTES]>,
        tick: u64,
    ) -> Result<Self> {
        struct FixedClock(u64);
        impl TrustedClock for FixedClock {
            fn now_tick(&self) -> Result<u64> {
                Ok(self.0)
            }
        }
        Self::from_records(Arc::new(FixedClock(tick)), record.into_iter().collect())
    }

    /// WAL-publisher-only exact acquisition. The byte-exact unleased terminal
    /// record is checked before the trusted transaction tick is applied, so a
    /// fresh process cannot adopt or renew another owner's live lease.
    pub(crate) fn acquire_exact_wal_owner_lease(
        &self,
        expected: &WitnessRecord,
        owner: ObjectId,
        duration: u64,
    ) -> Result<(WitnessRecord, WitnessLease)> {
        if !nonzero_id(owner.as_bytes())
            || expected.deletion != DeletionState::Active
            || expected.migration != MigrationState::WalAuthoritative
            || expected.owner_id.is_some()
            || expected.lease_expires_at_tick != 0
        {
            return Err(WitnessError::InvalidTransition);
        }
        let mut state = self.lock()?;
        available(&state)?;
        let current = state
            .records
            .get_mut(&expected.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        if current != expected {
            return Err(WitnessError::CompareFailed);
        }
        let now = self.now(current)?;
        let expires_at_tick = expiry(now, duration)?;
        if current.owner_id.is_some() || now < current.lease_expires_at_tick {
            return Err(WitnessError::Fenced);
        }
        let fencing_epoch = current.next_fencing_epoch;
        current.next_fencing_epoch = fencing_epoch
            .checked_add(1)
            .ok_or(WitnessError::Malformed)?;
        current.current_fencing_epoch = fencing_epoch;
        current.owner_id = Some(owner);
        current.lease_expires_at_tick = expires_at_tick;
        let lease = WitnessLease {
            archive_id: current.archive_id,
            database_epoch: current.database_epoch,
            key_epoch: current.registry.key_epoch,
            owner,
            fencing_epoch,
            expires_at_tick,
        };
        Ok((current.clone(), lease))
    }

    /// Phase-1-only exact advisory-owner acquisition. The provider mutation
    /// accepts only the byte-exact unleased `ShadowWal` predecessor and then
    /// validates the complete successor tuple before returning it.
    pub(crate) fn acquire_exact_advisory_owner_lease(
        &self,
        expected: &WitnessRecord,
        owner: ObjectId,
        duration: u64,
    ) -> Result<(WitnessRecord, WitnessLease)> {
        if !nonzero_id(owner.as_bytes()) || !expected.is_exact_unleased_advisory_terminal() {
            return Err(WitnessError::InvalidTransition);
        }
        let mut state = self.lock()?;
        available(&state)?;
        let current = state
            .records
            .get_mut(&expected.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        if current != expected {
            return Err(WitnessError::CompareFailed);
        }
        let now = self.now(current)?;
        let expires_at_tick = expiry(now, duration)?;
        if current.owner_id.is_some() || now < current.lease_expires_at_tick {
            return Err(WitnessError::Fenced);
        }
        let fencing_epoch = current.next_fencing_epoch;
        current.next_fencing_epoch = fencing_epoch
            .checked_add(1)
            .ok_or(WitnessError::Malformed)?;
        current.current_fencing_epoch = fencing_epoch;
        current.owner_id = Some(owner);
        current.lease_expires_at_tick = expires_at_tick;
        let lease = current.exact_active_lease_for_owner(owner)?;
        current.exact_advisory_owner_acquire_from(expected, owner.as_bytes())?;
        Ok((current.clone(), lease))
    }

    /// Phase-1 advisory heartbeat/reacquire transaction. The provider's
    /// trusted transaction tick decides whether the current fence is retained
    /// or the expired owner is reacquired at the canonical next fence.
    pub(crate) fn maintain_exact_advisory_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: ObjectId,
        duration: u64,
    ) -> Result<(WitnessRecord, WitnessLease)> {
        if !nonzero_id(owner.as_bytes())
            || duration == 0
            || previous.deletion != DeletionState::Active
            || previous.migration != MigrationState::ShadowWal
            || previous.owner_id != Some(owner)
        {
            return Err(WitnessError::InvalidTransition);
        }
        let mut state = self.lock()?;
        available(&state)?;
        let current = state
            .records
            .get_mut(&previous.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        if current != previous {
            return Err(WitnessError::CompareFailed);
        }
        let now = self.now(current)?;
        if now >= previous.lease_expires_at_tick {
            let expires_at_tick = expiry(now, duration)?;
            let fencing_epoch = current.next_fencing_epoch;
            current.current_fencing_epoch = fencing_epoch;
            current.next_fencing_epoch = fencing_epoch
                .checked_add(1)
                .ok_or(WitnessError::Malformed)?;
            current.owner_id = Some(owner);
            current.lease_expires_at_tick = expires_at_tick;
        } else {
            let remaining = previous
                .lease_expires_at_tick
                .checked_sub(now)
                .ok_or(WitnessError::Malformed)?;
            if remaining <= duration / 2 {
                let next_expiry = expiry(now, duration)?;
                if next_expiry > current.lease_expires_at_tick {
                    current.lease_expires_at_tick = next_expiry;
                }
            }
        }
        let lease = current.exact_active_lease_for_owner(owner)?;
        if current.current_fencing_epoch == previous.current_fencing_epoch {
            current.exact_advisory_owner_heartbeat_from(previous, owner.as_bytes())?;
        } else {
            current.exact_advisory_owner_reacquire_from(previous, owner.as_bytes())?;
        }
        Ok((current.clone(), lease))
    }

    /// Fresh-process advisory takeover. It never retains or heartbeats the
    /// old fence: the exact prior lease must be expired at the provider's
    /// trusted transaction tick before the canonical next fence is issued.
    pub(crate) fn reacquire_exact_advisory_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: ObjectId,
        duration: u64,
    ) -> Result<(WitnessRecord, WitnessLease)> {
        if !nonzero_id(owner.as_bytes())
            || duration == 0
            || previous.deletion != DeletionState::Active
            || previous.migration != MigrationState::ShadowWal
            || previous.owner_id != Some(owner)
        {
            return Err(WitnessError::InvalidTransition);
        }
        let mut state = self.lock()?;
        available(&state)?;
        let current = state
            .records
            .get_mut(&previous.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        if current != previous {
            return Err(WitnessError::CompareFailed);
        }
        let now = self.now(current)?;
        if now < previous.lease_expires_at_tick {
            return Err(WitnessError::Fenced);
        }
        let expires_at_tick = expiry(now, duration)?;
        let fencing_epoch = current.next_fencing_epoch;
        current.current_fencing_epoch = fencing_epoch;
        current.next_fencing_epoch = fencing_epoch
            .checked_add(1)
            .ok_or(WitnessError::Malformed)?;
        current.owner_id = Some(owner);
        current.lease_expires_at_tick = expires_at_tick;
        let lease = current.exact_active_lease_for_owner(owner)?;
        current.exact_advisory_owner_reacquire_from(previous, owner.as_bytes())?;
        Ok((current.clone(), lease))
    }

    pub(crate) fn reacquire_exact_wal_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: ObjectId,
        duration: u64,
    ) -> Result<(WitnessRecord, WitnessLease)> {
        if !nonzero_id(owner.as_bytes())
            || previous.deletion != DeletionState::Active
            || previous.migration != MigrationState::WalAuthoritative
            || previous.owner_id != Some(owner)
        {
            return Err(WitnessError::InvalidTransition);
        }
        let mut state = self.lock()?;
        available(&state)?;
        let current = state
            .records
            .get_mut(&previous.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        if current != previous {
            return Err(WitnessError::CompareFailed);
        }
        let now = self.now(current)?;
        if now < previous.lease_expires_at_tick {
            return Err(WitnessError::Fenced);
        }
        let expires_at_tick = expiry(now, duration)?;
        let fencing_epoch = current.next_fencing_epoch;
        current.current_fencing_epoch = fencing_epoch;
        current.next_fencing_epoch = fencing_epoch
            .checked_add(1)
            .ok_or(WitnessError::Malformed)?;
        current.owner_id = Some(owner);
        current.lease_expires_at_tick = expires_at_tick;
        let lease = current.exact_active_lease_for_owner(owner)?;
        current.exact_wal_owner_reacquire_from(previous, owner.as_bytes())?;
        Ok((current.clone(), lease))
    }

    /// Live-owner maintenance transaction. Same-second calls retain the
    /// authenticated lease, later calls renew only when half its requested
    /// lifetime has elapsed, and an expired same-owner lease reacquires at the
    /// next fence. The caller classifies the exact returned transition before
    /// persisting Control state.
    pub(crate) fn maintain_exact_wal_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: ObjectId,
        duration: u64,
    ) -> Result<(WitnessRecord, WitnessLease)> {
        if !nonzero_id(owner.as_bytes())
            || duration == 0
            || previous.deletion != DeletionState::Active
            || previous.migration != MigrationState::WalAuthoritative
            || previous.owner_id != Some(owner)
        {
            return Err(WitnessError::InvalidTransition);
        }
        let mut state = self.lock()?;
        available(&state)?;
        let current = state
            .records
            .get_mut(&previous.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        if current != previous {
            return Err(WitnessError::CompareFailed);
        }
        let now = self.now(current)?;
        if now >= previous.lease_expires_at_tick {
            let expires_at_tick = expiry(now, duration)?;
            let fencing_epoch = current.next_fencing_epoch;
            current.current_fencing_epoch = fencing_epoch;
            current.next_fencing_epoch = fencing_epoch
                .checked_add(1)
                .ok_or(WitnessError::Malformed)?;
            current.owner_id = Some(owner);
            current.lease_expires_at_tick = expires_at_tick;
        } else {
            let remaining = previous
                .lease_expires_at_tick
                .checked_sub(now)
                .ok_or(WitnessError::Malformed)?;
            if remaining <= duration / 2 {
                let next_expiry = expiry(now, duration)?;
                if next_expiry > current.lease_expires_at_tick {
                    current.lease_expires_at_tick = next_expiry;
                }
            }
        }
        let lease = current.exact_active_lease_for_owner(owner)?;
        if current.current_fencing_epoch == previous.current_fencing_epoch {
            current.exact_wal_owner_heartbeat_from(previous, owner.as_bytes())?;
        } else {
            current.exact_wal_owner_reacquire_from(previous, owner.as_bytes())?;
        }
        Ok((current.clone(), lease))
    }

    /// Terminal-only maintenance release. Unlike generic lease revocation,
    /// this exact retained-R2 transition may clear the importer owner after
    /// the lease has just expired without advancing its fence. It cannot
    /// adopt any reacquired owner or change any nonlease witness field.
    pub(crate) fn release_exact_maintenance_terminal(
        &self,
        retained: &WitnessRecord,
        owner: ObjectId,
    ) -> Result<WitnessRecord> {
        let mut state = self.lock()?;
        available(&state)?;
        let current = state
            .records
            .get_mut(&retained.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let _now = self.now(current)?;
        if current
            .exact_maintenance_terminal_or_release_from(retained, owner)
            .is_ok()
            && current.owner_id.is_none()
        {
            return Ok(current.clone());
        }
        if !current.exact_maintenance_terminal_active_at_provider_tick(retained, owner) {
            return Err(WitnessError::Fenced);
        }
        current.owner_id = None;
        current.lease_expires_at_tick = 0;
        if !current.valid() {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(current.clone())
    }

    /// Phase-1-only maintenance release. It clears only the exact importer
    /// lease from an authenticated ShadowWal record and preserves every root,
    /// registry, fence, migration, and deletion fact. It cannot create or
    /// imply WalAuthoritative state.
    pub(crate) fn release_exact_maintenance_advisory(
        &self,
        retained: &WitnessRecord,
        owner: ObjectId,
    ) -> Result<WitnessRecord> {
        let mut state = self.lock()?;
        available(&state)?;
        let current = state
            .records
            .get_mut(&retained.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let _now = self.now(current)?;
        if current
            .exact_maintenance_advisory_or_release_from(retained, owner)
            .is_ok()
            && current.owner_id.is_none()
        {
            return Ok(current.clone());
        }
        if !current.exact_maintenance_advisory_active_at_provider_tick(retained, owner) {
            return Err(WitnessError::Fenced);
        }
        current.owner_id = None;
        current.lease_expires_at_tick = 0;
        if !current.valid() {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(current.clone())
    }

    fn with_clock_and_authenticator(
        clock: Arc<dyn TrustedClock>,
        deletion_authenticator: Arc<dyn DeletionWorkerAuthenticator>,
    ) -> Self {
        Self {
            clock,
            deletion_authenticator,
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
        Self::from_records_with_authenticator(clock, Arc::new(DenyDeletionWorkers), records)
    }
    fn from_records_with_authenticator(
        clock: Arc<dyn TrustedClock>,
        deletion_authenticator: Arc<dyn DeletionWorkerAuthenticator>,
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
            deletion_authenticator,
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
            database_epoch_generation: 0,
            predecessor: None,
            root: b.genesis_root,
            registry: b.registry,
            owner_id: None,
            current_fencing_epoch: 0,
            next_fencing_epoch: 1,
            lease_expires_at_tick: 0,
            deletion_fencing_epoch: None,
            deletion_worker_id: None,
            deletion_operation_id: None,
            last_server_tick: 0,
            migration: MigrationState::Legacy,
            deletion: DeletionState::Active,
            deletion_evidence: [None; DELETION_EVIDENCE_STAGES],
        };
        state.records.insert(r.archive_id, r.clone());
        Ok(r)
    }
    /// Bootstrap while persisting the transaction's trusted provider clock.
    pub(crate) fn bootstrap_at_tick(
        &self,
        b: WitnessBootstrap,
        tick: u64,
    ) -> Result<WitnessRecord> {
        let record = self.bootstrap(b)?;
        let mut state = self.lock()?;
        let record = state
            .records
            .get_mut(&record.archive_id)
            .ok_or(WitnessError::Synchronization)?;
        record.last_server_tick = tick;
        Ok(record.clone())
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
    fn authenticate_deletion_worker(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> Result<DeletionWorkerIdentity> {
        self.deletion_authenticator
            .authenticate(archive_id, credential)
    }
    fn verified_deletion_evidence(
        &self,
        record: &WitnessRecord,
        context: DeletionStageContext,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> Result<DeletionEvidence> {
        let provider_commitment = self
            .deletion_authenticator
            .verify_stage(credential, context, proof)?;
        deletion_evidence_from_verified_stage(record, context, provider_commitment)
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
    #[cfg(test)]
    pub(crate) fn replace_current_for_test(&self, record: WitnessRecord) -> Result<()> {
        let mut state = self.lock()?;
        if !state.records.contains_key(&record.archive_id) {
            return Err(WitnessError::MissingArchive);
        }
        state.records.insert(record.archive_id, record);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn advance_exact_retained_migration_for_test(
        &self,
        advance: RootAdvance,
        next: MigrationState,
        candidate: &WitnessRecord,
    ) -> Result<WitnessReceipt> {
        let mut state = self.lock()?;
        available(&state)?;
        let record = state
            .records
            .get_mut(&advance.lease.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let mut produced = record.clone();
        let now = self.now(&mut produced)?;
        normal_ok(&produced, &advance, now, Normal::Migration(next))?;
        produced.migration = next;
        produced.root = advance.candidate;
        if !produced.matches_retained_maintenance_candidate(candidate) {
            return Err(WitnessError::InvalidTransition);
        }
        *record = candidate.clone();
        Ok(WitnessReceipt {
            record: candidate.clone(),
        })
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
            Normal::Rotation(x) => {
                r.registry = x;
                // A key epoch transition invalidates the token that was bound
                // to the prior key epoch; the owner must acquire a higher fence.
                r.owner_id = None;
                r.lease_expires_at_tick = 0;
            }
            Normal::Epoch(x) => {
                r.predecessor = Some(Predecessor {
                    root: r.root,
                    registry: r.registry,
                });
                r.database_epoch = x;
                r.database_epoch_generation = r
                    .database_epoch_generation
                    .checked_add(1)
                    .ok_or(WitnessError::InvalidTransition)?;
                r.migration = MigrationState::EpochCutover;
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

#[cfg(test)]
pub(crate) struct DeletionDriverTestFixture {
    pub(crate) witness: InMemoryWitness,
    pub(crate) tombstone: TombstoneReceipt,
    pub(crate) credential: DeletionWorkerCredential,
    pub(crate) wrong_credential: DeletionWorkerCredential,
    pub(crate) key_erasure: DeletionStageProof,
    pub(crate) inventory: DeletionStageProof,
    pub(crate) retention: DeletionStageProof,
}

#[cfg(test)]
pub(crate) fn deletion_driver_test_fixture() -> DeletionDriverTestFixture {
    let archive_id = ArchiveId::from_bytes([1; 16]);
    let database_epoch = DatabaseEpoch::from_bytes([2; 16]);
    let key_epoch = KeyEpoch::from_bytes([3; 16]);
    let registry = KeyRegistryReference::new(key_epoch, 0, ObjectId::from_bytes([6; 16]), [7; 32]);
    let genesis = RootCommitment::genesis(
        database_epoch,
        key_epoch,
        RootReference::new(0, ObjectId::from_bytes([4; 16]), [5; 32]),
    );
    let witness = InMemoryWitness::with_clock_and_authenticator(
        Arc::new(SystemClock),
        Arc::new(DeletionDriverTestAuthenticator { archive_id }),
    );
    witness
        .bootstrap(WitnessBootstrap::new(
            archive_id,
            database_epoch,
            genesis,
            registry,
        ))
        .expect("driver fixture bootstrap");
    let lease = witness
        .acquire_lease(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectId::from_bytes([9; 16]),
            300,
        )
        .expect("driver fixture lease");
    let candidate = RootCommitment::candidate(
        database_epoch,
        key_epoch,
        lease.fencing_epoch,
        genesis.root,
        RootReference::new(1, ObjectId::from_bytes([10; 16]), [11; 32]),
    );
    let credential = DeletionWorkerCredential::new(b"driver-worker").expect("driver credential");
    let tombstone_proof =
        DeletionStageProof::new(b"driver-tombstone").expect("driver tombstone proof");
    let tombstone = witness
        .tombstone(
            RootAdvance::new(lease, genesis, registry, candidate),
            &credential,
            &tombstone_proof,
        )
        .expect("driver fixture tombstone");
    DeletionDriverTestFixture {
        witness,
        tombstone,
        credential,
        wrong_credential: DeletionWorkerCredential::new(b"wrong-worker")
            .expect("wrong driver credential"),
        key_erasure: DeletionStageProof::new(b"driver-erasure").expect("driver erasure proof"),
        inventory: DeletionStageProof::new(b"driver-inventory").expect("driver inventory proof"),
        retention: DeletionStageProof::new(b"driver-retention").expect("driver retention proof"),
    }
}

#[cfg(test)]
pub(crate) fn active_deletion_test_fixture(
) -> (InMemoryWitness, ArchiveId, DeletionWorkerCredential) {
    let archive_id = ArchiveId::from_bytes([81; 16]);
    let database_epoch = DatabaseEpoch::from_bytes([82; 16]);
    let key_epoch = KeyEpoch::from_bytes([83; 16]);
    let registry =
        KeyRegistryReference::new(key_epoch, 0, ObjectId::from_bytes([84; 16]), [85; 32]);
    let root = RootCommitment::genesis(
        database_epoch,
        key_epoch,
        RootReference::new(0, ObjectId::from_bytes([86; 16]), [87; 32]),
    );
    let witness = InMemoryWitness::with_clock_and_authenticator(
        Arc::new(SystemClock),
        Arc::new(DeletionDriverTestAuthenticator { archive_id }),
    );
    witness
        .bootstrap(WitnessBootstrap::new(
            archive_id,
            database_epoch,
            root,
            registry,
        ))
        .expect("active deletion fixture bootstrap");
    (
        witness,
        archive_id,
        DeletionWorkerCredential::new(b"driver-worker").expect("active deletion credential"),
    )
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
        if r.deletion != DeletionState::Active {
            return Err(WitnessError::InvalidTransition);
        }
        Ok(RecoveryRoot {
            archive_id: r.archive_id,
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
    #[cfg(test)]
    fn tombstone(
        &self,
        a: RootAdvance,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> Result<TombstoneReceipt> {
        let identity = self.authenticate_deletion_worker(a.lease.archive_id, credential)?;
        let mut s = self.lock()?;
        available(&s)?;
        let r = s
            .records
            .get_mut(&a.lease.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let now = self.now(r)?;
        normal_ok(r, &a, now, Normal::Root)?;
        let df = r.next_fencing_epoch;
        let next_fencing_epoch = df.checked_add(1).ok_or(WitnessError::Malformed)?;
        let evidence = self.verified_deletion_evidence(
            r,
            DeletionStageContext {
                archive_id: r.archive_id,
                identity,
                deletion_fencing_epoch: df,
                target: DeletionState::Tombstoned,
                root: a.candidate,
                registry: r.registry,
                inventory_commitment: None,
                provider_drain_commitment: None,
            },
            credential,
            proof,
        )?;
        r.next_fencing_epoch = next_fencing_epoch;
        r.root = a.candidate;
        r.deletion = DeletionState::Tombstoned;
        r.migration = MigrationState::Deleting;
        r.deletion_evidence[0] = Some(evidence);
        r.owner_id = None;
        r.lease_expires_at_tick = 0;
        r.deletion_fencing_epoch = Some(df);
        r.deletion_worker_id = Some(identity.worker_id);
        r.deletion_operation_id = Some(identity.operation_id);
        Ok(TombstoneReceipt {
            receipt: WitnessReceipt { record: r.clone() },
            authorization: DeletionAuthorization {
                archive_id: r.archive_id,
                database_epoch: r.database_epoch,
                fencing_epoch: df,
            },
        })
    }
    fn tombstone_current(
        &self,
        advance: TombstoneAdvance,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> Result<TombstoneReceipt> {
        let identity = self.authenticate_deletion_worker(advance.archive_id, credential)?;
        let mut state = self.lock()?;
        available(&state)?;
        let record = state
            .records
            .get_mut(&advance.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let _trusted_tick = self.now(record)?;
        if record.deletion != DeletionState::Active
            || record.archive_id != advance.archive_id
            || record.database_epoch != advance.database_epoch
            || record.root != advance.expected_root
            || record.registry != advance.expected_registry
            || record.current_fencing_epoch != advance.expected_current_fencing_epoch
            || record.next_fencing_epoch != advance.expected_next_fencing_epoch
        {
            return Err(WitnessError::CompareFailed);
        }
        let deletion_fencing_epoch = advance.expected_next_fencing_epoch;
        let next_fencing_epoch = deletion_fencing_epoch
            .checked_add(1)
            .ok_or(WitnessError::Malformed)?;
        let evidence = self.verified_deletion_evidence(
            record,
            DeletionStageContext {
                archive_id: record.archive_id,
                identity,
                deletion_fencing_epoch,
                target: DeletionState::Tombstoned,
                root: record.root,
                registry: record.registry,
                inventory_commitment: None,
                provider_drain_commitment: None,
            },
            credential,
            proof,
        )?;
        record.next_fencing_epoch = next_fencing_epoch;
        record.deletion = DeletionState::Tombstoned;
        record.migration = MigrationState::Deleting;
        record.deletion_evidence[0] = Some(evidence);
        record.owner_id = None;
        record.lease_expires_at_tick = 0;
        record.deletion_fencing_epoch = Some(deletion_fencing_epoch);
        record.deletion_worker_id = Some(identity.worker_id);
        record.deletion_operation_id = Some(identity.operation_id);
        Ok(TombstoneReceipt {
            receipt: WitnessReceipt {
                record: record.clone(),
            },
            authorization: DeletionAuthorization {
                archive_id: record.archive_id,
                database_epoch: record.database_epoch,
                fencing_epoch: deletion_fencing_epoch,
            },
        })
    }
    fn resume_deletion(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> Result<DeletionRecovery> {
        let identity = self.authenticate_deletion_worker(archive_id, credential)?;
        let s = self.lock()?;
        available(&s)?;
        let r = s
            .records
            .get(&archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        if r.deletion == DeletionState::Active {
            return Err(WitnessError::InvalidTransition);
        }
        if r.deletion_worker_id != Some(identity.worker_id)
            || r.deletion_operation_id != Some(identity.operation_id)
        {
            return Err(WitnessError::Unauthorized);
        }
        let fencing_epoch = r.deletion_fencing_epoch.ok_or(WitnessError::Corrupt)?;
        Ok(DeletionRecovery {
            receipt: WitnessReceipt { record: r.clone() },
            authorization: DeletionAuthorization {
                archive_id: r.archive_id,
                database_epoch: r.database_epoch,
                fencing_epoch,
            },
        })
    }
    fn verify_physical_completion(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> Result<DeletionRecovery> {
        let identity = self.authenticate_deletion_worker(archive_id, credential)?;
        let s = self.lock()?;
        available(&s)?;
        let r = s
            .records
            .get(&archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        if r.deletion != DeletionState::PhysicalComplete
            || r.deletion_worker_id != Some(identity.worker_id)
            || r.deletion_operation_id != Some(identity.operation_id)
        {
            return Err(WitnessError::InvalidTransition);
        }
        let deletion_fencing_epoch = r.deletion_fencing_epoch.ok_or(WitnessError::Corrupt)?;
        let (inventory_commitment, provider_drain_commitment) =
            proof.drain_binding().ok_or(WitnessError::Malformed)?;
        // Reconstruct the exact pre-final evidence chain that was hashed by
        // `advance_deletion`. The retained PhysicalComplete slot contains the
        // hash being verified and must not recursively become its own input.
        // Every identity/fence/root/registry/prior-stage field remains exact.
        let mut pre_final = r.clone();
        pre_final.deletion_evidence[DeletionState::PhysicalComplete.evidence_count() - 1] = None;
        let expected = self.verified_deletion_evidence(
            &pre_final,
            DeletionStageContext {
                archive_id,
                identity,
                deletion_fencing_epoch,
                target: DeletionState::PhysicalComplete,
                root: r.root,
                registry: r.registry,
                inventory_commitment: Some(inventory_commitment),
                provider_drain_commitment: Some(provider_drain_commitment),
            },
            credential,
            proof,
        )?;
        if r.deletion_evidence[DeletionState::PhysicalComplete.evidence_count() - 1]
            != Some(expected)
        {
            return Err(WitnessError::CompareFailed);
        }
        Ok(DeletionRecovery {
            receipt: WitnessReceipt { record: r.clone() },
            authorization: DeletionAuthorization {
                archive_id,
                database_epoch: r.database_epoch,
                fencing_epoch: deletion_fencing_epoch,
            },
        })
    }
    fn advance_deletion(
        &self,
        a: DeletionAdvance,
        next: DeletionState,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> Result<WitnessReceipt> {
        let identity = self.authenticate_deletion_worker(a.authorization.archive_id, credential)?;
        let mut s = self.lock()?;
        available(&s)?;
        let r = s
            .records
            .get_mut(&a.authorization.archive_id)
            .ok_or(WitnessError::MissingArchive)?;
        let _ = self.now(r)?;
        deletion_ok(r, &a, next, identity)?;
        let deletion_fencing_epoch = r.deletion_fencing_epoch.ok_or(WitnessError::Corrupt)?;
        let (inventory_commitment, provider_drain_commitment) =
            match (next, proof.inventory_binding(), proof.drain_binding()) {
                (DeletionState::CryptographicallyErased, Some(inventory), None) => {
                    (Some(inventory), None)
                }
                (DeletionState::CryptographicallyErased, _, _) => {
                    return Err(WitnessError::Malformed)
                }
                (DeletionState::PhysicalComplete, _, Some((inventory, drain))) => {
                    (Some(inventory), Some(drain))
                }
                (DeletionState::PhysicalComplete, _, None) => return Err(WitnessError::Malformed),
                (_, None, None) => (None, None),
                (_, _, _) => return Err(WitnessError::Malformed),
            };
        let evidence = self.verified_deletion_evidence(
            r,
            DeletionStageContext {
                archive_id: r.archive_id,
                identity,
                deletion_fencing_epoch,
                target: next,
                root: r.root,
                registry: r.registry,
                inventory_commitment,
                provider_drain_commitment,
            },
            credential,
            proof,
        )?;
        r.deletion = next;
        r.deletion_evidence[next.evidence_count() - 1] = Some(evidence);
        if next == DeletionState::PhysicalComplete {
            r.migration = MigrationState::Deleted;
        }
        Ok(WitnessReceipt { record: r.clone() })
    }
}

#[async_trait::async_trait]
impl ExactCurrentRecoveryAdmission for InMemoryWitness {
    async fn admit_exact_current(
        &self,
        expected: &RecoveryRoot,
    ) -> std::result::Result<(), WitnessError> {
        let current = self.recovery_root(expected.archive_id())?;
        if current != *expected {
            return Err(WitnessError::CompareFailed);
        }
        Ok(())
    }
}
fn normal_ok(r: &WitnessRecord, a: &RootAdvance, now: u64, kind: Normal) -> Result<()> {
    if r.deletion != DeletionState::Active {
        return Err(WitnessError::InvalidTransition);
    }
    lease_ok(r, a.lease, now)?;
    if a.expected_root != r.root
        || a.expected_registry != r.registry
        || !a.candidate_registry.valid()
        || !a.candidate.valid()
        || a.candidate.key_epoch != a.candidate_registry.key_epoch
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
            if a.candidate_registry != r.registry
                || a.candidate.database_epoch != r.database_epoch
                || a.candidate.key_epoch != r.registry.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
        Normal::Migration(x) => {
            if !r.migration.permits(x)
                || a.candidate_registry != r.registry
                || a.candidate.database_epoch != r.database_epoch
                || a.candidate.key_epoch != r.registry.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
        Normal::Rotation(x) => {
            let next_rotation_generation = r
                .registry
                .rotation_generation
                .checked_add(1)
                .ok_or(WitnessError::InvalidTransition)?;
            if !x.valid()
                || x == r.registry
                || a.candidate_registry != x
                || x.rotation_generation != next_rotation_generation
                || x.key_epoch == r.registry.key_epoch
                || a.candidate.database_epoch != r.database_epoch
                || a.candidate.key_epoch != x.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
        Normal::Epoch(x) => {
            let (_, expected_database_epoch) = next_database_epoch(r)?;
            if !nonzero_id(x.as_bytes())
                || x == r.database_epoch
                || r.migration != MigrationState::ExtentAuthoritative
                || x != expected_database_epoch
                || a.candidate_registry != r.registry
                || a.candidate.database_epoch != x
                || a.candidate.key_epoch != r.registry.key_epoch
            {
                return Err(WitnessError::InvalidTransition);
            }
        }
    };
    Ok(())
}
fn deletion_ok(
    r: &WitnessRecord,
    a: &DeletionAdvance,
    next: DeletionState,
    identity: DeletionWorkerIdentity,
) -> Result<()> {
    if r.deletion.next() != Some(next)
        || a.authorization.archive_id != r.archive_id
        || a.authorization.database_epoch != r.database_epoch
        || Some(a.authorization.fencing_epoch) != r.deletion_fencing_epoch
        || Some(identity.worker_id) != r.deletion_worker_id
        || Some(identity.operation_id) != r.deletion_operation_id
        || a.expected_root != r.root
        || a.expected_registry != r.registry
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
fn next_database_epoch(record: &WitnessRecord) -> Result<(u64, DatabaseEpoch)> {
    let generation = record
        .database_epoch_generation
        .checked_add(1)
        .ok_or(WitnessError::InvalidTransition)?;
    let mut root_bytes = [0u8; ROOT_COMMITMENT_BYTES];
    let mut offset = 0;
    root_commitment_put(&mut root_bytes, &mut offset, record.root);
    if offset != root_bytes.len() {
        return Err(WitnessError::Malformed);
    }
    let mut hasher = Sha256::new();
    hasher.update(DATABASE_EPOCH_DOMAIN);
    hasher.update(record.archive_id.as_bytes());
    hasher.update(record.database_epoch.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(root_bytes);
    let digest = hasher.finalize();
    let mut epoch = [0u8; 16];
    epoch.copy_from_slice(&digest[..16]);
    if !nonzero_id(&epoch) {
        return Err(WitnessError::Malformed);
    }
    Ok((generation, DatabaseEpoch::from_bytes(epoch)))
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
fn epoch_lifecycle_valid(record: &WitnessRecord) -> bool {
    match record.deletion {
        DeletionState::Active => matches!(
            (record.database_epoch_generation, record.migration),
            (
                0,
                MigrationState::Legacy
                    | MigrationState::ShadowWal
                    | MigrationState::WalAuthoritative
                    | MigrationState::ShadowExtents
                    | MigrationState::ExtentAuthoritative
            ) | (
                1,
                MigrationState::EpochCutover | MigrationState::LegacyRetired
            )
        ),
        _ => matches!(record.database_epoch_generation, 0 | 1),
    }
}
fn deletion_evidence_valid(
    state: DeletionState,
    evidence: &[Option<DeletionEvidence>; DELETION_EVIDENCE_STAGES],
) -> bool {
    let expected_states = [
        DeletionState::Tombstoned,
        DeletionState::CryptographicallyErased,
        DeletionState::LogicalObjectsAbsent,
        DeletionState::PhysicalComplete,
    ];
    evidence.iter().enumerate().all(|(index, item)| {
        if index < state.evidence_count() {
            item.is_some_and(|value| value.valid_for(expected_states[index]))
        } else {
            item.is_none()
        }
    })
}
fn deletion_evidence_from_verified_stage(
    record: &WitnessRecord,
    context: DeletionStageContext,
    provider_commitment: [u8; 32],
) -> Result<DeletionEvidence> {
    let kind =
        DeletionEvidenceKind::for_state(context.target).ok_or(WitnessError::InvalidTransition)?;
    if context.archive_id != record.archive_id
        || context.registry != record.registry
        || context.deletion_fencing_epoch == 0
        || !nonzero_hash(&provider_commitment)
    {
        return Err(WitnessError::Malformed);
    }
    match (
        context.target,
        context.inventory_commitment,
        context.provider_drain_commitment,
    ) {
        (DeletionState::CryptographicallyErased, Some(inventory), None)
            if nonzero_hash(&inventory) => {}
        (DeletionState::CryptographicallyErased, _, _) => return Err(WitnessError::Malformed),
        (DeletionState::PhysicalComplete, Some(inventory), Some(drain))
            if nonzero_hash(&inventory) && nonzero_hash(&drain) => {}
        (DeletionState::PhysicalComplete, _, _) => return Err(WitnessError::Malformed),
        (_, None, None) => {}
        (_, _, _) => return Err(WitnessError::Malformed),
    }
    let mut root_bytes = [0u8; ROOT_COMMITMENT_BYTES];
    let mut root_offset = 0;
    root_commitment_put(&mut root_bytes, &mut root_offset, context.root);
    if root_offset != root_bytes.len() {
        return Err(WitnessError::Malformed);
    }
    let mut registry_bytes = [0u8; KEY_REGISTRY_REFERENCE_BYTES];
    let mut registry_offset = 0;
    registry_put(&mut registry_bytes, &mut registry_offset, record.registry);
    if registry_offset != registry_bytes.len() {
        return Err(WitnessError::Malformed);
    }
    let mut hasher = Sha256::new();
    hasher.update(DELETION_EVIDENCE_DOMAIN);
    hasher.update(context.archive_id.as_bytes());
    hasher.update(context.identity.worker_id.as_bytes());
    hasher.update(context.identity.operation_id.as_bytes());
    hasher.update(context.deletion_fencing_epoch.to_be_bytes());
    hasher.update([context.target as u8]);
    hasher.update(root_bytes);
    hasher.update(registry_bytes);
    match context.inventory_commitment {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value);
        }
        None => hasher.update([0u8; 33]),
    }
    match context.provider_drain_commitment {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value);
        }
        None => hasher.update([0u8; 33]),
    }
    for evidence in record.deletion_evidence {
        match evidence {
            Some(value) => {
                hasher.update([value.kind as u8]);
                hasher.update(value.commitment);
            }
            None => hasher.update([0u8; 33]),
        }
    }
    hasher.update(provider_commitment);
    let commitment = hasher.finalize().into();
    Ok(DeletionEvidence { kind, commitment })
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
fn root_commitment_put<const N: usize>(out: &mut [u8; N], p: &mut usize, r: RootCommitment) {
    root_put(out, p, r.root);
    put(out, p, r.database_epoch.as_bytes());
    put(out, p, r.key_epoch.as_bytes());
    put(out, p, &r.owner_fencing_epoch.to_be_bytes());
    put(out, p, &[r.parent.is_some() as u8]);
    root_put(out, p, r.parent.unwrap_or_else(zero_root));
}
fn root_commitment_take(input: &[u8], p: &mut usize) -> Result<RootCommitment> {
    let root = root_take(input, p)?;
    let database_epoch = DatabaseEpoch::from_bytes(array(take(input, p, 16)?)?);
    let key_epoch = KeyEpoch::from_bytes(array(take(input, p, 16)?)?);
    let owner_fencing_epoch = u64::from_be_bytes(array(take(input, p, 8)?)?);
    let parent_present = boolean(take(input, p, 1)?[0])?;
    let encoded_parent = root_take(input, p)?;
    if !parent_present && encoded_parent != zero_root() {
        return Err(WitnessError::Corrupt);
    }
    Ok(RootCommitment {
        root,
        parent: parent_present.then_some(encoded_parent),
        database_epoch,
        key_epoch,
        owner_fencing_epoch,
    })
}
fn registry_put<const N: usize>(out: &mut [u8; N], p: &mut usize, registry: KeyRegistryReference) {
    put(out, p, registry.key_epoch.as_bytes());
    put(out, p, &[registry.key_kind as u8]);
    put(out, p, &registry.rotation_generation.to_be_bytes());
    put(out, p, registry.object_id.as_bytes());
    put(out, p, &registry.ciphertext_hash);
}
fn registry_take(input: &[u8], p: &mut usize) -> Result<KeyRegistryReference> {
    Ok(KeyRegistryReference {
        key_epoch: KeyEpoch::from_bytes(array(take(input, p, 16)?)?),
        key_kind: key_kind(take(input, p, 1)?[0])?,
        rotation_generation: u64::from_be_bytes(array(take(input, p, 8)?)?),
        object_id: ObjectId::from_bytes(array(take(input, p, 16)?)?),
        ciphertext_hash: array(take(input, p, 32)?)?,
    })
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
    use crate::archive_v3::{
        resolve_archive_cipher, ArchiveDek, ArchiveV3Error, ExactKeyRegistryProvider,
        KeyRegistryContext, KeyRegistryPlaintext, LogicalLocation, ObjectRole, ParentReference,
        ARCHIVE_FORMAT_VERSION, SQLITE_PAGE_SIZE,
    };
    use sha2::{Digest, Sha256};
    const WRAPPED_REGISTRY: &[u8] = b"test-kms-wrapped-archive-registry";
    struct FakeRootProvider {
        object_id: ObjectId,
        stored: Option<CiphertextEnvelope>,
    }
    #[async_trait::async_trait]
    impl ExactRootProvider for FakeRootProvider {
        async fn read_exact(&self, context: &ObjectContext) -> Result<CiphertextEnvelope> {
            if context.object_id() != self.object_id {
                return Err(WitnessError::MissingRootObject);
            }
            self.stored.clone().ok_or(WitnessError::MissingRootObject)
        }
    }
    fn stored_root_provider(
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
    ) -> FakeRootProvider {
        FakeRootProvider {
            object_id: context.object_id(),
            stored: Some(envelope.clone()),
        }
    }
    struct FakeKeyRegistryProvider {
        registry_object_id: ObjectId,
        plaintext: Vec<u8>,
    }
    #[async_trait::async_trait]
    impl ExactKeyRegistryProvider for FakeKeyRegistryProvider {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            if object_id != self.registry_object_id {
                return Err(ArchiveV3Error::InvalidContext);
            }
            destination[..WRAPPED_REGISTRY.len()].copy_from_slice(WRAPPED_REGISTRY);
            Ok(WRAPPED_REGISTRY.len())
        }

        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            wrapped_registry_ciphertext: &[u8],
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            if wrapped_registry_ciphertext != WRAPPED_REGISTRY {
                return Err(ArchiveV3Error::InvalidContext);
            }
            destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            Ok(self.plaintext.len())
        }
    }
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
    struct FakeDeletionAuthenticator;
    impl DeletionWorkerAuthenticator for FakeDeletionAuthenticator {
        fn authenticate(
            &self,
            archive_id: ArchiveId,
            credential: &DeletionWorkerCredential,
        ) -> Result<DeletionWorkerIdentity> {
            if archive_id != ArchiveId::from_bytes(id(1)) {
                return Err(WitnessError::Unauthorized);
            }
            match credential.provider_assertion() {
                b"provider-attestation-1" => DeletionWorkerIdentity::new(
                    ObjectId::from_bytes(id(70)),
                    ObjectId::from_bytes(id(71)),
                ),
                b"provider-attestation-2" => DeletionWorkerIdentity::new(
                    ObjectId::from_bytes(id(70)),
                    ObjectId::from_bytes(id(72)),
                ),
                _ => Err(WitnessError::Unauthorized),
            }
        }

        fn verify_stage(
            &self,
            credential: &DeletionWorkerCredential,
            context: DeletionStageContext,
            proof: &DeletionStageProof,
        ) -> Result<[u8; 32]> {
            if self.authenticate(context.archive_id, credential)? != context.identity
                || context.deletion_fencing_epoch == 0
                || !context.root.valid()
                || !context.registry.valid()
            {
                return Err(WitnessError::Unauthorized);
            }
            let expected = match context.target {
                DeletionState::Active => return Err(WitnessError::InvalidTransition),
                DeletionState::Tombstoned => b"provider-proof-tombstone".as_slice(),
                DeletionState::CryptographicallyErased => b"provider-proof-erasure".as_slice(),
                DeletionState::LogicalObjectsAbsent => b"provider-proof-inventory".as_slice(),
                DeletionState::PhysicalComplete => b"provider-proof-retention".as_slice(),
            };
            if proof.provider_assertion() != expected {
                return Err(WitnessError::Unauthorized);
            }
            match context.target {
                DeletionState::CryptographicallyErased
                    if context
                        .inventory_commitment
                        .is_some_and(|value| nonzero_hash(&value))
                        && context.provider_drain_commitment.is_none() => {}
                DeletionState::CryptographicallyErased => return Err(WitnessError::Unauthorized),
                DeletionState::PhysicalComplete
                    if context
                        .inventory_commitment
                        .is_some_and(|value| nonzero_hash(&value))
                        && context
                            .provider_drain_commitment
                            .is_some_and(|value| nonzero_hash(&value)) => {}
                DeletionState::PhysicalComplete => return Err(WitnessError::Unauthorized),
                _ if context.inventory_commitment.is_none()
                    && context.provider_drain_commitment.is_none() => {}
                _ => return Err(WitnessError::Unauthorized),
            }
            Ok(Sha256::digest(proof.provider_assertion()).into())
        }
    }
    fn id(v: u8) -> [u8; 16] {
        [v; 16]
    }
    fn hash(v: u8) -> [u8; 32] {
        [v; 32]
    }
    fn deletion_credential() -> DeletionWorkerCredential {
        DeletionWorkerCredential::new(b"provider-attestation-1").unwrap()
    }
    fn wrong_deletion_credential() -> DeletionWorkerCredential {
        DeletionWorkerCredential::new(b"provider-attestation-2").unwrap()
    }
    fn deletion_proof(state: DeletionState) -> DeletionStageProof {
        let assertion = match state {
            DeletionState::Active => b"invalid".as_slice(),
            DeletionState::Tombstoned => b"provider-proof-tombstone".as_slice(),
            DeletionState::CryptographicallyErased => b"provider-proof-erasure".as_slice(),
            DeletionState::LogicalObjectsAbsent => b"provider-proof-inventory".as_slice(),
            DeletionState::PhysicalComplete => b"provider-proof-retention".as_slice(),
        };
        let proof = DeletionStageProof::new(assertion).unwrap();
        match state {
            DeletionState::CryptographicallyErased => proof.bind_inventory_only(hash(81)).unwrap(),
            DeletionState::PhysicalComplete => {
                proof.bind_inventory_drain(hash(81), hash(82)).unwrap()
            }
            _ => proof,
        }
    }
    fn wrapped_registry_hash() -> [u8; 32] {
        Sha256::digest(WRAPPED_REGISTRY).into()
    }
    async fn verified_cipher(
        archive_id: ArchiveId,
        key_epoch: KeyEpoch,
        rotation_generation: u64,
        registry_object_id: ObjectId,
        dek: [u8; 32],
    ) -> VerifiedArchiveCipher {
        let context = KeyRegistryContext::with_rotation_generation(
            archive_id,
            KeyKind::Archive,
            key_epoch,
            rotation_generation,
        );
        let provider = FakeKeyRegistryProvider {
            registry_object_id,
            plaintext: KeyRegistryPlaintext::encode_archive(&context, &ArchiveDek::from_bytes(dek))
                .unwrap()
                .to_vec(),
        };
        resolve_archive_cipher(
            &context,
            registry_object_id,
            wrapped_registry_hash(),
            &provider,
        )
        .await
        .unwrap()
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
            KeyRegistryReference::new(key, 0, ObjectId::from_bytes(id(6)), wrapped_registry_hash()),
        )
    }
    fn setup() -> (InMemoryWitness, Arc<FakeClock>, WitnessRecord, WitnessLease) {
        let c = Arc::new(FakeClock::new(10));
        let w = InMemoryWitness::with_clock_and_authenticator(
            c.clone(),
            Arc::new(FakeDeletionAuthenticator),
        );
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
    fn restart(witness: &InMemoryWitness, clock: Arc<FakeClock>) -> InMemoryWitness {
        InMemoryWitness::from_records_with_authenticator(
            clock,
            Arc::new(FakeDeletionAuthenticator),
            witness.snapshots(),
        )
        .unwrap()
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
    fn del(r: &WitnessRecord, a: DeletionAuthorization) -> DeletionAdvance {
        DeletionAdvance::new(a, r.root, r.registry)
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
    fn durable_decoder_rejects_impossible_cross_field_lifecycle_states() {
        let (w, _, r, lease) = setup();
        let mut active_deleted = r.clone();
        active_deleted.migration = MigrationState::Deleted;
        assert_eq!(
            WitnessRecord::decode(&active_deleted.encode()),
            Err(WitnessError::Corrupt)
        );
        let mut active_with_worker = r.clone();
        active_with_worker.deletion_worker_id = Some(ObjectId::from_bytes(id(70)));
        active_with_worker.deletion_operation_id = Some(ObjectId::from_bytes(id(71)));
        assert_eq!(
            WitnessRecord::decode(&active_with_worker.encode()),
            Err(WitnessError::Corrupt)
        );

        let tombstone = w
            .tombstone(
                adv(&r, lease, 9),
                &deletion_credential(),
                &deletion_proof(DeletionState::Tombstoned),
            )
            .unwrap();
        let mut bad_fence = tombstone.receipt.record.clone();
        bad_fence.next_fencing_epoch = bad_fence.deletion_fencing_epoch.unwrap();
        assert_eq!(
            WitnessRecord::decode(&bad_fence.encode()),
            Err(WitnessError::Corrupt)
        );
        let mut missing_worker = tombstone.receipt.record.clone();
        missing_worker.deletion_worker_id = None;
        assert_eq!(
            WitnessRecord::decode(&missing_worker.encode()),
            Err(WitnessError::Corrupt)
        );
        let mut wrong_evidence = tombstone.receipt.record;
        wrong_evidence.deletion_evidence[0] = Some(DeletionEvidence {
            kind: DeletionEvidenceKind::Inventory,
            commitment: hash(10),
        });
        assert_eq!(
            WitnessRecord::decode(&wrong_evidence.encode()),
            Err(WitnessError::Corrupt)
        );
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
            Err(WitnessError::CompareFailed)
        );
    }

    #[test]
    fn wal_owner_advance_accepts_only_provider_tick_and_rejects_tuple_substitution() {
        let (witness, clock, legacy, lease) = setup();
        clock.set(11);
        let shadow = witness
            .advance_migration(adv(&legacy, lease, 81), MigrationState::ShadowWal)
            .unwrap();
        clock.set(12);
        let authoritative = witness
            .advance_migration(
                adv(shadow.record(), lease, 82),
                MigrationState::WalAuthoritative,
            )
            .unwrap();
        let candidate = cand(authoritative.record(), lease.fencing_epoch, 83);
        let retained = AuthenticatedWalRootAdvance::from_expected_witness(
            crate::archive_v3_wal_owner::WalWitnessAdvanceContext::for_test(),
            authoritative.record(),
            candidate,
        )
        .unwrap();
        let provider = InMemoryWitness::from_provider_record_at_tick(
            Some(authoritative.record().encode()),
            15,
        )
        .unwrap();
        let observed = provider
            .compare_and_advance_root(retained.provider_advance(
                crate::archive_v3_wal_owner::WalWitnessAdvanceContext::for_test(),
            ))
            .unwrap();
        assert_eq!(observed.record().last_server_tick, 15);
        assert!(retained.validate_observed(observed.record()).is_ok());

        for mut substituted in [
            observed.record().clone(),
            observed.record().clone(),
            observed.record().clone(),
            observed.record().clone(),
        ]
        .into_iter()
        .enumerate()
        {
            match substituted.0 {
                0 => substituted.1.owner_id = Some(ObjectId::from_bytes(id(90))),
                1 => substituted.1.current_fencing_epoch += 1,
                2 => substituted.1.next_fencing_epoch += 1,
                _ => {
                    substituted.1.root.parent = Some(RootReference::new(
                        1,
                        ObjectId::from_bytes(id(91)),
                        hash(92),
                    ))
                }
            }
            assert!(retained.validate_observed(&substituted.1).is_err());
        }
    }
    #[test]
    fn database_epoch_cutover_requires_extent_authority_and_preserves_rollback() {
        fn rejected(
            witness: &InMemoryWitness,
            record: &WitnessRecord,
            lease: WitnessLease,
            value: u8,
        ) {
            let next_database = DatabaseEpoch::from_bytes(id(value.wrapping_add(80)));
            let mut advance = adv(record, lease, value);
            advance.candidate.database_epoch = next_database;
            assert_eq!(
                witness.cut_over_database_epoch(advance, next_database),
                Err(WitnessError::InvalidTransition)
            );
        }

        let (w, _, r, lease) = setup();
        rejected(&w, &r, lease, 9);
        let shadow_wal = w
            .advance_migration(adv(&r, lease, 10), MigrationState::ShadowWal)
            .unwrap();
        rejected(&w, shadow_wal.record(), lease, 11);
        let wal = w
            .advance_migration(
                adv(shadow_wal.record(), lease, 12),
                MigrationState::WalAuthoritative,
            )
            .unwrap();
        rejected(&w, wal.record(), lease, 13);
        let shadow_extents = w
            .advance_migration(adv(wal.record(), lease, 14), MigrationState::ShadowExtents)
            .unwrap();
        rejected(&w, shadow_extents.record(), lease, 15);
        let extents = w
            .advance_migration(
                adv(shadow_extents.record(), lease, 16),
                MigrationState::ExtentAuthoritative,
            )
            .unwrap();
        assert_eq!(
            w.advance_migration(
                adv(extents.record(), lease, 17),
                MigrationState::LegacyRetired,
            ),
            Err(WitnessError::InvalidTransition)
        );
        let (_, next_database) = next_database_epoch(extents.record()).unwrap();
        let mut cutover = adv(extents.record(), lease, 17);
        cutover.candidate.database_epoch = next_database;
        let cutover = w.cut_over_database_epoch(cutover, next_database).unwrap();
        assert_eq!(cutover.record.migration, MigrationState::EpochCutover);
        assert_eq!(cutover.record.database_epoch_generation, 1);
        assert_eq!(
            cutover.record.predecessor.unwrap().root,
            extents.record.root
        );
        let mut corrupt_registry_lineage = cutover.record.clone();
        let impossible_generation = corrupt_registry_lineage.registry.rotation_generation + 1;
        corrupt_registry_lineage
            .predecessor
            .as_mut()
            .unwrap()
            .registry
            .rotation_generation = impossible_generation;
        assert_eq!(
            WitnessRecord::decode(&corrupt_registry_lineage.encode()),
            Err(WitnessError::Corrupt)
        );
        let mut substituted_equal_generation_registry = cutover.record.clone();
        let predecessor = substituted_equal_generation_registry
            .predecessor
            .as_mut()
            .unwrap();
        predecessor.registry.object_id = ObjectId::from_bytes(id(98));
        predecessor.registry.ciphertext_hash = hash(99);
        assert_eq!(
            WitnessRecord::decode(&substituted_equal_generation_registry.encode()),
            Err(WitnessError::Corrupt)
        );
        let mut reopened_cutover_gate = cutover.record.clone();
        reopened_cutover_gate.migration = MigrationState::ExtentAuthoritative;
        assert_eq!(
            WitnessRecord::decode(&reopened_cutover_gate.encode()),
            Err(WitnessError::Corrupt)
        );
        let cutover_lease = w
            .acquire_lease(
                cutover.record.archive_id,
                cutover.record.database_epoch,
                cutover.record.registry.key_epoch,
                ObjectId::from_bytes(id(8)),
                20,
            )
            .unwrap();
        let mut epoch_reuse = adv(cutover.record(), cutover_lease, 18);
        epoch_reuse.candidate.database_epoch = r.database_epoch;
        assert_eq!(
            w.cut_over_database_epoch(epoch_reuse, r.database_epoch),
            Err(WitnessError::InvalidTransition)
        );
        w.advance_migration(
            adv(cutover.record(), cutover_lease, 19),
            MigrationState::LegacyRetired,
        )
        .unwrap();
    }
    #[test]
    fn key_rotation_generation_rejects_skips_and_retired_registry_rollback() {
        let (w, _, r, lease) = setup();
        let next_key = KeyEpoch::from_bytes(id(50));
        let skipped =
            KeyRegistryReference::new(next_key, 2, ObjectId::from_bytes(id(51)), hash(52));
        let mut skipped_advance = adv(&r, lease, 9);
        skipped_advance.candidate.key_epoch = next_key;
        skipped_advance.candidate_registry = skipped;
        assert_eq!(
            w.rotate_key_registry(skipped_advance, skipped),
            Err(WitnessError::InvalidTransition)
        );

        let next = KeyRegistryReference::new(next_key, 1, ObjectId::from_bytes(id(51)), hash(52));
        let mut advance = adv(&r, lease, 10);
        advance.candidate.key_epoch = next_key;
        advance.candidate_registry = next;
        let rotated = w.rotate_key_registry(advance, next).unwrap();
        let new_lease = w
            .acquire_lease(
                r.archive_id,
                r.database_epoch,
                next_key,
                ObjectId::from_bytes(id(8)),
                20,
            )
            .unwrap();
        let mut rollback = adv(rotated.record(), new_lease, 11);
        rollback.candidate.key_epoch = r.registry.key_epoch;
        rollback.candidate_registry = r.registry;
        assert_eq!(
            w.rotate_key_registry(rollback, r.registry),
            Err(WitnessError::InvalidTransition)
        );
    }
    #[tokio::test]
    async fn authenticated_root_envelope_is_the_only_non_test_candidate_builder() {
        let (w, _, r, lease) = setup();
        let cipher = verified_cipher(
            r.archive_id,
            r.registry.key_epoch,
            r.registry.rotation_generation,
            r.registry.object_id,
            [0x55; 32],
        )
        .await;
        let parent = ParentReference {
            object_id: r.root.root.object_id,
            envelope_hash: r.root.root.ciphertext_hash,
        };
        let context = ObjectContext::new(
            r.archive_id,
            r.database_epoch,
            r.registry.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 1 },
            ObjectId::from_bytes(id(9)),
            Some(parent.clone()),
        )
        .unwrap();
        let root = ArchiveRoot {
            root_seq: 1,
            parent: Some(parent),
            database_epoch: r.database_epoch,
            key_epoch: r.registry.key_epoch,
            owner_fencing_epoch: lease.fencing_epoch,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: 0,
            logical_file_length: 0,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        let envelope = cipher.seal(&context, &root.encode().unwrap()).unwrap();
        let missing_provider = FakeRootProvider {
            object_id: context.object_id(),
            stored: None,
        };
        assert!(matches!(
            RootAdvance::from_authenticated_candidate(
                lease,
                r.root,
                r.registry,
                r.registry,
                &context,
                &missing_provider,
                &cipher,
            )
            .await,
            Err(WitnessError::MissingRootObject)
        ));
        let provider = stored_root_provider(&context, &envelope);
        let advance = RootAdvance::from_authenticated_candidate(
            lease, r.root, r.registry, r.registry, &context, &provider, &cipher,
        )
        .await
        .unwrap();
        assert_eq!(advance.candidate.root.object_id, context.object_id());
        assert_eq!(advance.candidate.root.ciphertext_hash, envelope.hash());
        w.compare_and_advance_root(advance).unwrap();

        assert_eq!(
            RootCommitment::from_authenticated_provider_object(
                ArchiveId::from_bytes(id(99)),
                r.registry,
                &context,
                &provider,
                &cipher,
            )
            .await,
            Err(WitnessError::Malformed)
        );
        let same_epoch_wrong_registry = KeyRegistryReference::new(
            r.registry.key_epoch,
            r.registry.rotation_generation,
            ObjectId::from_bytes(id(88)),
            wrapped_registry_hash(),
        );
        assert_eq!(
            RootCommitment::from_authenticated_provider_object(
                r.archive_id,
                same_epoch_wrong_registry,
                &context,
                &provider,
                &cipher,
            )
            .await,
            Err(WitnessError::Malformed)
        );
        let mut tampered_wire = envelope.encode();
        let last = tampered_wire.len() - 1;
        tampered_wire[last] ^= 1;
        let tampered = CiphertextEnvelope::decode(&tampered_wire).unwrap();
        let tampered_provider = stored_root_provider(&context, &tampered);
        assert_eq!(
            RootCommitment::from_authenticated_provider_object(
                r.archive_id,
                r.registry,
                &context,
                &tampered_provider,
                &cipher,
            )
            .await,
            Err(WitnessError::Malformed)
        );
    }
    #[tokio::test]
    async fn authenticated_genesis_envelope_is_required_for_non_test_bootstrap() {
        let archive_id = ArchiveId::from_bytes(id(1));
        let database_epoch = DatabaseEpoch::from_bytes(id(2));
        let key_epoch = KeyEpoch::from_bytes(id(5));
        let context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ObjectId::from_bytes(id(3)),
            None,
        )
        .unwrap();
        let root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: 0,
            logical_file_length: 0,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        let registry = KeyRegistryReference::new(
            key_epoch,
            0,
            ObjectId::from_bytes(id(6)),
            wrapped_registry_hash(),
        );
        let cipher = verified_cipher(
            archive_id,
            key_epoch,
            registry.rotation_generation,
            registry.object_id,
            [0x77; 32],
        )
        .await;
        let envelope = cipher.seal(&context, &root.encode().unwrap()).unwrap();
        let provider = stored_root_provider(&context, &envelope);
        let bootstrap = WitnessBootstrap::from_authenticated_genesis(
            archive_id, registry, &context, &provider, &cipher,
        )
        .await
        .unwrap();
        let witness = InMemoryWitness::with_clock(Arc::new(FakeClock::new(10)));
        let record = witness.bootstrap(bootstrap).unwrap();
        assert_eq!(record.root.root.ciphertext_hash, envelope.hash());

        let wrong_registry = KeyRegistryReference::new(
            KeyEpoch::from_bytes(id(9)),
            0,
            ObjectId::from_bytes(id(10)),
            hash(11),
        );
        assert!(matches!(
            WitnessBootstrap::from_authenticated_genesis(
                archive_id,
                wrong_registry,
                &context,
                &provider,
                &cipher,
            )
            .await,
            Err(WitnessError::Malformed)
        ));
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
                &deletion_credential(),
                &deletion_proof(DeletionState::Tombstoned),
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
        let unauthorized_erasure = deletion_proof(DeletionState::LogicalObjectsAbsent)
            .bind_inventory_only(hash(81))
            .unwrap();
        assert_eq!(
            w.advance_deletion(
                del(&x, t.authorization),
                DeletionState::CryptographicallyErased,
                &deletion_credential(),
                &unauthorized_erasure,
            ),
            Err(WitnessError::Unauthorized)
        );
    }
    #[test]
    fn exact_current_tombstone_never_publishes_a_root_and_rejects_stale_snapshots() {
        let (w, _, initial, lease) = setup();
        let current = w.read_current(initial.archive_id).unwrap().unwrap();
        let exact = TombstoneAdvance::from_current(&current).unwrap();
        let next = adv(&current, lease, 9);
        let advanced = w.compare_and_advance_root(next).unwrap();
        assert!(matches!(
            w.tombstone_current(
                exact,
                &deletion_credential(),
                &deletion_proof(DeletionState::Tombstoned),
            ),
            Err(WitnessError::CompareFailed)
        ));
        let exact = TombstoneAdvance::from_current(advanced.record()).unwrap();
        let root_before = advanced.record().root();
        let tombstone = w
            .tombstone_current(
                exact,
                &deletion_credential(),
                &deletion_proof(DeletionState::Tombstoned),
            )
            .unwrap();
        assert_eq!(tombstone.receipt().record().root(), root_before);
        assert_eq!(
            tombstone.receipt().record().deletion(),
            DeletionState::Tombstoned
        );
    }
    #[test]
    fn deletion_requires_provider_authentication_and_exact_persisted_identity() {
        let denied_clock = Arc::new(FakeClock::new(10));
        let denied = InMemoryWitness::with_clock(denied_clock);
        let denied_record = denied.bootstrap(boot()).unwrap();
        let denied_lease = denied
            .acquire_lease(
                denied_record.archive_id,
                denied_record.database_epoch,
                denied_record.registry.key_epoch,
                ObjectId::from_bytes(id(8)),
                20,
            )
            .unwrap();
        assert!(matches!(
            denied.tombstone(
                adv(&denied_record, denied_lease, 9),
                &deletion_credential(),
                &deletion_proof(DeletionState::Tombstoned),
            ),
            Err(WitnessError::Unauthorized)
        ));

        let (w, clock, r, lease) = setup();
        let tombstone = w
            .tombstone(
                adv(&r, lease, 9),
                &deletion_credential(),
                &deletion_proof(DeletionState::Tombstoned),
            )
            .unwrap();
        let wrong = wrong_deletion_credential();
        assert!(matches!(
            w.resume_deletion(r.archive_id, &wrong),
            Err(WitnessError::Unauthorized)
        ));

        let restarted = InMemoryWitness::from_records_with_authenticator(
            clock,
            Arc::new(FakeDeletionAuthenticator),
            w.snapshots(),
        )
        .unwrap();
        assert!(matches!(
            restarted.resume_deletion(r.archive_id, &wrong),
            Err(WitnessError::Unauthorized)
        ));
        assert_eq!(
            restarted.advance_deletion(
                del(tombstone.receipt.record(), tombstone.authorization()),
                DeletionState::CryptographicallyErased,
                &wrong,
                &deletion_proof(DeletionState::CryptographicallyErased),
            ),
            Err(WitnessError::CompareFailed)
        );
        assert_eq!(
            restarted
                .read_current(r.archive_id)
                .unwrap()
                .unwrap()
                .deletion,
            DeletionState::Tombstoned
        );
    }
    #[test]
    fn deletion_resumes_after_every_restart_and_preserves_all_stage_evidence() {
        let (w, clock, r, lease) = setup();
        let tombstone = w
            .tombstone(
                adv(&r, lease, 9),
                &deletion_credential(),
                &deletion_proof(DeletionState::Tombstoned),
            )
            .unwrap();
        let tombstone_root = tombstone.receipt.record.root;
        assert_eq!(
            w.recovery_root(r.archive_id),
            Err(WitnessError::InvalidTransition)
        );

        let after_tombstone_restart = restart(&w, clock.clone());
        let resumed = after_tombstone_restart
            .resume_deletion(r.archive_id, &deletion_credential())
            .unwrap();
        let erased = after_tombstone_restart
            .advance_deletion(
                del(resumed.receipt().record(), resumed.authorization()),
                DeletionState::CryptographicallyErased,
                &deletion_credential(),
                &deletion_proof(DeletionState::CryptographicallyErased),
            )
            .unwrap();
        assert_eq!(erased.record.root, tombstone_root);

        let after_erasure_restart = restart(&after_tombstone_restart, clock.clone());
        let resumed = after_erasure_restart
            .resume_deletion(r.archive_id, &deletion_credential())
            .unwrap();
        let absent = after_erasure_restart
            .advance_deletion(
                del(resumed.receipt().record(), resumed.authorization()),
                DeletionState::LogicalObjectsAbsent,
                &deletion_credential(),
                &deletion_proof(DeletionState::LogicalObjectsAbsent),
            )
            .unwrap();
        assert_eq!(absent.record.root, tombstone_root);

        let after_inventory_restart = restart(&after_erasure_restart, clock);
        let resumed = after_inventory_restart
            .resume_deletion(r.archive_id, &deletion_credential())
            .unwrap();
        let unbound_retention = DeletionStageProof::new(b"provider-proof-retention").unwrap();
        assert_eq!(
            after_inventory_restart.advance_deletion(
                del(resumed.receipt().record(), resumed.authorization()),
                DeletionState::PhysicalComplete,
                &deletion_credential(),
                &unbound_retention,
            ),
            Err(WitnessError::Malformed)
        );
        let complete = after_inventory_restart
            .advance_deletion(
                del(resumed.receipt().record(), resumed.authorization()),
                DeletionState::PhysicalComplete,
                &deletion_credential(),
                &deletion_proof(DeletionState::PhysicalComplete),
            )
            .unwrap();
        assert_eq!(complete.record.root, tombstone_root);
        assert_eq!(complete.record.migration, MigrationState::Deleted);
        assert_eq!(
            complete
                .record
                .deletion_evidence
                .map(|evidence| evidence.unwrap().kind),
            [
                DeletionEvidenceKind::Tombstone,
                DeletionEvidenceKind::KeyErasure,
                DeletionEvidenceKind::Inventory,
                DeletionEvidenceKind::Retention,
            ]
        );
        let commitments = complete
            .record
            .deletion_evidence
            .map(|evidence| evidence.unwrap().commitment);
        assert!(commitments.iter().all(nonzero_hash));
        assert!(commitments
            .iter()
            .enumerate()
            .all(|(index, commitment)| commitments[..index]
                .iter()
                .all(|prior| prior != commitment)));
        assert_eq!(
            after_inventory_restart
                .resume_deletion(r.archive_id, &deletion_credential())
                .unwrap()
                .receipt()
                .record()
                .deletion(),
            DeletionState::PhysicalComplete
        );
        after_inventory_restart
            .verify_physical_completion(
                r.archive_id,
                &deletion_credential(),
                &deletion_proof(DeletionState::PhysicalComplete),
            )
            .unwrap();
        assert!(after_inventory_restart
            .verify_physical_completion(
                r.archive_id,
                &deletion_credential(),
                &DeletionStageProof::new(b"different-final-proof").unwrap(),
            )
            .is_err());
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
        let (_, db) = next_database_epoch(e.record()).unwrap();
        let mut a = adv(e.record(), l, 11);
        a.candidate.database_epoch = db;
        let cut = w.cut_over_database_epoch(a, db).unwrap();
        let recovery = w.recovery_root(r.archive_id).unwrap();
        assert_eq!(recovery.predecessor_root(), Some(e.record.root));
        assert_eq!(recovery.predecessor_registry(), Some(e.record.registry));
        let cutover_lease = w
            .acquire_lease(
                cut.record.archive_id,
                cut.record.database_epoch,
                cut.record.registry.key_epoch,
                ObjectId::from_bytes(id(8)),
                20,
            )
            .unwrap();
        let retired = w
            .advance_migration(
                adv(cut.record(), cutover_lease, 12),
                MigrationState::LegacyRetired,
            )
            .unwrap();
        let next_key = KeyEpoch::from_bytes(id(55));
        let next_registry =
            KeyRegistryReference::new(next_key, 1, ObjectId::from_bytes(id(56)), hash(57));
        let mut rotate = adv(retired.record(), cutover_lease, 13);
        rotate.candidate.key_epoch = next_key;
        rotate.candidate_registry = next_registry;
        let rotated = w.rotate_key_registry(rotate, next_registry).unwrap();
        let recovery = w.recovery_root(r.archive_id).unwrap();
        assert_eq!(recovery.predecessor_root(), Some(e.record.root));
        assert_eq!(recovery.predecessor_registry(), Some(e.record.registry));
        assert_eq!(recovery.registry(), next_registry);
        let deletion_lease = w
            .acquire_lease(
                rotated.record.archive_id,
                rotated.record.database_epoch,
                rotated.record.registry.key_epoch,
                ObjectId::from_bytes(id(8)),
                20,
            )
            .unwrap();
        let t = w
            .tombstone(
                adv(rotated.record(), deletion_lease, 14),
                &deletion_credential(),
                &deletion_proof(DeletionState::Tombstoned),
            )
            .unwrap();
        let er = w
            .advance_deletion(
                del(t.receipt.record(), t.authorization),
                DeletionState::CryptographicallyErased,
                &deletion_credential(),
                &deletion_proof(DeletionState::CryptographicallyErased),
            )
            .unwrap();
        let absent = w
            .advance_deletion(
                del(er.record(), t.authorization),
                DeletionState::LogicalObjectsAbsent,
                &deletion_credential(),
                &deletion_proof(DeletionState::LogicalObjectsAbsent),
            )
            .unwrap();
        let complete = w
            .advance_deletion(
                del(absent.record(), t.authorization),
                DeletionState::PhysicalComplete,
                &deletion_credential(),
                &deletion_proof(DeletionState::PhysicalComplete),
            )
            .unwrap();
        assert_eq!(complete.record.migration, MigrationState::Deleted);
    }
    #[test]
    fn maintenance_lease_transitions_bind_full_fence_and_time_tuple() {
        let (witness, _, bootstrap, lease) = setup();
        let owner = ObjectId::from_bytes(id(8));
        let current = witness.read_current(bootstrap.archive_id).unwrap().unwrap();
        let token = crate::cp::control_store::MaintenancePersistenceContext::for_test();
        let renewed = current.renewed_maintenance_lease_for_test();
        assert_eq!(
            renewed
                .exact_maintenance_renewal_from(&current, owner)
                .unwrap()
                .fencing_epoch(),
            lease.fencing_epoch()
        );
        assert!(renewed
            .with_next_fencing_epoch_for_test(current.next_fencing_epoch + 1)
            .exact_maintenance_renewal_from(&current, owner)
            .is_err());
        assert!(renewed
            .with_lease_expiry_for_test(lease.expires_at_tick() - 1)
            .exact_maintenance_renewal_from(&current, owner)
            .is_err());

        let reacquired = current.reacquired_maintenance_lease_for_test();
        assert_eq!(
            reacquired
                .exact_maintenance_reacquire_from(&current, owner)
                .unwrap()
                .fencing_epoch(),
            current.next_fencing_epoch
        );
        assert!(reacquired
            .with_next_fencing_epoch_for_test(reacquired.next_fencing_epoch + 1)
            .exact_maintenance_reacquire_from(&current, owner)
            .is_err());

        assert!(renewed.retained_maintenance_candidate_has_lease_descendant(
            token,
            &current,
            owner,
            MigrationState::Legacy,
        ));
        assert!(
            reacquired.retained_maintenance_candidate_has_lease_descendant(
                token,
                &current,
                owner,
                MigrationState::Legacy,
            )
        );
        let reacquired_again = reacquired.reacquired_maintenance_lease_for_test();
        assert!(
            reacquired_again.retained_maintenance_candidate_has_lease_descendant(
                token,
                &current,
                owner,
                MigrationState::Legacy,
            )
        );
        assert!(!reacquired_again
            .with_next_fencing_epoch_for_test(reacquired_again.next_fencing_epoch + 1)
            .retained_maintenance_candidate_has_lease_descendant(
                token,
                &current,
                owner,
                MigrationState::Legacy,
            ));
        assert!(!reacquired_again
            .with_lease_expiry_for_test(current.lease_expires_at_tick)
            .retained_maintenance_candidate_has_lease_descendant(
                token,
                &current,
                owner,
                MigrationState::Legacy,
            ));
        assert!(!reacquired_again
            .with_migration_for_test(MigrationState::ShadowWal)
            .retained_maintenance_candidate_has_lease_descendant(
                token,
                &current,
                owner,
                MigrationState::Legacy,
            ));
        assert!(!reacquired_again
            .with_deletion_for_test(DeletionState::Tombstoned)
            .retained_maintenance_candidate_has_lease_descendant(
                token,
                &current,
                owner,
                MigrationState::Legacy,
            ));
    }
    #[test]
    fn maintenance_terminal_release_binds_every_nonlease_field() {
        let (witness, _, bootstrap, lease) = setup();
        let owner = ObjectId::from_bytes(id(8));
        let mut retained = witness.read_current(bootstrap.archive_id).unwrap().unwrap();
        retained.migration = MigrationState::WalAuthoritative;
        assert!(retained
            .exact_maintenance_terminal_or_release_from(&retained, owner)
            .is_ok());

        let mut released_records = Vec::new();
        for tick in [
            retained.last_server_tick + 1,
            retained.lease_expires_at_tick,
            retained.lease_expires_at_tick + 1,
        ] {
            let local =
                InMemoryWitness::from_provider_record_at_tick(Some(retained.encode()), tick)
                    .unwrap();
            let released = local
                .release_exact_maintenance_terminal(&retained, owner)
                .unwrap();
            assert_eq!(released.last_server_tick, tick);
            assert!(released
                .exact_maintenance_terminal_or_release_from(&retained, owner)
                .is_ok());
            released_records.push(released);
        }
        let released = released_records.remove(0);
        assert!(released
            .exact_maintenance_terminal_or_release_from(&retained, owner)
            .is_ok());
        let reacquired = retained.reacquired_maintenance_lease_for_test();
        let competing = InMemoryWitness::from_provider_record_at_tick(
            Some(reacquired.encode()),
            reacquired.last_server_tick,
        )
        .unwrap();
        assert!(competing
            .release_exact_maintenance_terminal(&retained, owner)
            .is_err());

        let competing_owner = ObjectId::from_bytes(id(49));
        let competing = InMemoryWitness::from_provider_record_at_tick(
            Some(retained.encode()),
            retained.lease_expires_at_tick,
        )
        .unwrap();
        let competing_lease = competing
            .acquire_lease(
                retained.archive_id,
                retained.database_epoch,
                retained.registry.key_epoch,
                competing_owner,
                60,
            )
            .unwrap();
        competing.revoke_lease(competing_lease).unwrap();
        let competing_released = competing
            .read_current(retained.archive_id)
            .unwrap()
            .unwrap();
        assert!(competing_released.owner_id.is_none());
        assert_ne!(
            competing_released.current_fencing_epoch,
            retained.current_fencing_epoch
        );
        assert!(competing_released
            .exact_maintenance_terminal_or_release_from(&retained, owner)
            .is_err());
        let retry = InMemoryWitness::from_provider_record_at_tick(
            Some(competing_released.encode()),
            competing_released.last_server_tick + 1,
        )
        .unwrap();
        assert!(retry
            .release_exact_maintenance_terminal(&retained, owner)
            .is_err());

        let mut altered = Vec::new();
        let mut value = released.clone();
        value.archive_id = ArchiveId::from_bytes(id(40));
        altered.push(value);
        let mut value = released.clone();
        value.database_epoch = DatabaseEpoch::from_bytes(id(41));
        altered.push(value);
        let mut value = released.clone();
        value.database_epoch_generation = 1;
        altered.push(value);
        let mut value = released.clone();
        value.predecessor = Some(Predecessor {
            root: retained.root,
            registry: retained.registry,
        });
        altered.push(value);
        let mut value = released.clone();
        value.root = cand(&retained, lease.fencing_epoch, 42);
        altered.push(value);
        let mut value = released.clone();
        value.registry = KeyRegistryReference::new(
            retained.registry.key_epoch,
            1,
            ObjectId::from_bytes(id(43)),
            hash(44),
        );
        altered.push(value);
        let mut value = released.clone();
        value.owner_id = Some(ObjectId::from_bytes(id(45)));
        value.lease_expires_at_tick = retained.lease_expires_at_tick;
        altered.push(value);
        let mut value = released.clone();
        value.current_fencing_epoch = 0;
        altered.push(value);
        let mut value = released.clone();
        value.next_fencing_epoch += 1;
        altered.push(value);
        let mut value = released.clone();
        value.lease_expires_at_tick = 1;
        altered.push(value);
        let mut value = released.clone();
        value.last_server_tick = retained.last_server_tick.saturating_sub(1);
        altered.push(value);
        let mut value = released.clone();
        value.migration = MigrationState::ShadowWal;
        altered.push(value);
        let mut value = released.clone();
        value.deletion = DeletionState::Tombstoned;
        altered.push(value);
        let mut value = released.clone();
        value.deletion_fencing_epoch = Some(retained.next_fencing_epoch + 1);
        altered.push(value);
        let mut value = released.clone();
        value.deletion_worker_id = Some(ObjectId::from_bytes(id(46)));
        altered.push(value);
        let mut value = released.clone();
        value.deletion_operation_id = Some(ObjectId::from_bytes(id(47)));
        altered.push(value);
        let mut value = released.clone();
        value.deletion_evidence[0] = Some(DeletionEvidence {
            kind: DeletionEvidenceKind::Tombstone,
            commitment: hash(48),
        });
        altered.push(value);
        assert!(altered.iter().all(|record| record
            .exact_maintenance_terminal_or_release_from(&retained, owner)
            .is_err()));
    }

    #[test]
    fn wal_owner_acquire_renew_and_reacquire_are_exact_full_tuple_transitions() {
        let (witness, _, bootstrap, _) = setup();
        let importer = ObjectId::from_bytes(id(8));
        let owner = ObjectId::from_bytes(id(61));
        let mut terminal = witness.read_current(bootstrap.archive_id).unwrap().unwrap();
        terminal.migration = MigrationState::WalAuthoritative;
        let release_provider = InMemoryWitness::from_provider_record_at_tick(
            Some(terminal.encode()),
            terminal.last_server_tick + 1,
        )
        .unwrap();
        let released = release_provider
            .release_exact_maintenance_terminal(&terminal, importer)
            .unwrap();

        let acquire_provider = InMemoryWitness::from_provider_record_at_tick(
            Some(released.encode()),
            released.last_server_tick + 1,
        )
        .unwrap();
        let (acquired, lease) = acquire_provider
            .acquire_exact_wal_owner_lease(&released, owner, 20)
            .unwrap();
        assert_eq!(
            acquired
                .exact_wal_owner_acquire_from(&released, owner.as_bytes())
                .unwrap(),
            lease
        );
        assert!(acquired
            .with_next_fencing_epoch_for_test(acquired.next_fencing_epoch + 1)
            .exact_wal_owner_acquire_from(&released, owner.as_bytes())
            .is_err());

        let renewal_provider = InMemoryWitness::from_provider_record_at_tick(
            Some(acquired.encode()),
            acquired.last_server_tick + 1,
        )
        .unwrap();
        renewal_provider.renew_lease(lease, 40).unwrap();
        let renewed = renewal_provider
            .read_current(acquired.archive_id)
            .unwrap()
            .unwrap();
        assert!(renewed
            .exact_wal_owner_renewal_from(&acquired, owner.as_bytes())
            .is_ok());
        assert!(renewed
            .with_lease_expiry_for_test(acquired.lease_expires_at_tick)
            .exact_wal_owner_renewal_from(&acquired, owner.as_bytes())
            .is_err());

        let reacquire_provider = InMemoryWitness::from_provider_record_at_tick(
            Some(renewed.encode()),
            renewed.lease_expires_at_tick,
        )
        .unwrap();
        let (reacquired, _) = reacquire_provider
            .reacquire_exact_wal_owner_lease(&renewed, owner, 40)
            .unwrap();
        assert!(reacquired
            .exact_wal_owner_reacquire_from(&renewed, owner.as_bytes())
            .is_ok());
        assert!(reacquired
            .with_migration_for_test(MigrationState::ShadowWal)
            .exact_wal_owner_reacquire_from(&renewed, owner.as_bytes())
            .is_err());
    }

    #[test]
    fn advisory_owner_acquire_is_exact_and_shadow_wal_only() {
        let (witness, _, bootstrap, _) = setup();
        let importer = ObjectId::from_bytes(id(8));
        let owner = ObjectId::from_bytes(id(65));
        let current = witness.read_current(bootstrap.archive_id).unwrap().unwrap();
        let retained = current.with_migration_for_test(MigrationState::ShadowWal);
        let release_provider = InMemoryWitness::from_provider_record_at_tick(
            Some(retained.encode()),
            retained.last_server_tick + 1,
        )
        .unwrap();
        let released = release_provider
            .release_exact_maintenance_advisory(&retained, importer)
            .unwrap();
        assert!(released.is_exact_unleased_advisory_terminal());

        let acquire_provider = InMemoryWitness::from_provider_record_at_tick(
            Some(released.encode()),
            released.last_server_tick + 1,
        )
        .unwrap();
        let (acquired, lease) = acquire_provider
            .acquire_exact_advisory_owner_lease(&released, owner, 20)
            .unwrap();
        assert_eq!(
            acquired
                .exact_advisory_owner_acquire_from(&released, owner.as_bytes())
                .unwrap(),
            lease
        );
        let heartbeat_provider = InMemoryWitness::from_provider_record_at_tick(
            Some(acquired.encode()),
            acquired.last_server_tick + 1,
        )
        .unwrap();
        let (heartbeat, heartbeat_lease) = heartbeat_provider
            .maintain_exact_advisory_owner_lease(&acquired, owner, 20)
            .unwrap();
        assert_eq!(
            heartbeat
                .exact_advisory_owner_heartbeat_from(&acquired, owner.as_bytes())
                .unwrap(),
            heartbeat_lease
        );
        assert!(heartbeat
            .with_migration_for_test(MigrationState::WalAuthoritative)
            .exact_advisory_owner_heartbeat_from(&acquired, owner.as_bytes())
            .is_err());

        let premature = InMemoryWitness::from_provider_record_at_tick(
            Some(heartbeat.encode()),
            heartbeat.last_server_tick + 1,
        )
        .unwrap();
        assert!(premature
            .reacquire_exact_advisory_owner_lease(&heartbeat, owner, 20)
            .is_err());

        let reacquire_provider = InMemoryWitness::from_provider_record_at_tick(
            Some(heartbeat.encode()),
            heartbeat.lease_expires_at_tick,
        )
        .unwrap();
        let (reacquired, reacquired_lease) = reacquire_provider
            .reacquire_exact_advisory_owner_lease(&heartbeat, owner, 20)
            .unwrap();
        assert_eq!(
            reacquired
                .exact_advisory_owner_reacquire_from(&heartbeat, owner.as_bytes())
                .unwrap(),
            reacquired_lease
        );
        assert!(reacquired
            .with_next_fencing_epoch_for_test(reacquired.next_fencing_epoch + 1)
            .exact_advisory_owner_reacquire_from(&heartbeat, owner.as_bytes())
            .is_err());
        assert!(acquired
            .with_next_fencing_epoch_for_test(acquired.next_fencing_epoch + 1)
            .exact_advisory_owner_acquire_from(&released, owner.as_bytes())
            .is_err());
        assert!(acquired
            .with_migration_for_test(MigrationState::WalAuthoritative)
            .exact_advisory_owner_acquire_from(&released, owner.as_bytes())
            .is_err());
        assert!(acquire_provider
            .acquire_exact_advisory_owner_lease(&released, owner, 20)
            .is_err());
        assert!(InMemoryWitness::from_provider_record_at_tick(
            Some(
                released
                    .with_migration_for_test(MigrationState::WalAuthoritative)
                    .encode()
            ),
            released.last_server_tick + 1,
        )
        .unwrap()
        .acquire_exact_advisory_owner_lease(
            &released.with_migration_for_test(MigrationState::WalAuthoritative),
            owner,
            20,
        )
        .is_err());
    }

    #[test]
    fn wal_owner_maintenance_reuses_adequate_lease_in_one_provider_second() {
        let (witness, _, bootstrap, _) = setup();
        let importer = ObjectId::from_bytes(id(8));
        let owner = ObjectId::from_bytes(id(62));
        let mut terminal = witness.read_current(bootstrap.archive_id).unwrap().unwrap();
        terminal.migration = MigrationState::WalAuthoritative;
        let release_provider = InMemoryWitness::from_provider_record_at_tick(
            Some(terminal.encode()),
            terminal.last_server_tick + 1,
        )
        .unwrap();
        let released = release_provider
            .release_exact_maintenance_terminal(&terminal, importer)
            .unwrap();
        let provider_tick = released.last_server_tick + 1;
        let provider =
            InMemoryWitness::from_provider_record_at_tick(Some(released.encode()), provider_tick)
                .unwrap();
        let (acquired, lease) = provider
            .acquire_exact_wal_owner_lease(&released, owner, 300)
            .unwrap();

        // An immediate submission and a second serialized submission in the
        // same provider second both reuse the exact adequate lease. Neither
        // attempts an impossible strictly-monotone renewal.
        let (immediate, immediate_lease) = provider
            .maintain_exact_wal_owner_lease(&acquired, owner, 300)
            .unwrap();
        let (second, second_lease) = provider
            .maintain_exact_wal_owner_lease(&immediate, owner, 300)
            .unwrap();
        assert_eq!(immediate, acquired);
        assert_eq!(second, acquired);
        assert_eq!(immediate_lease, lease);
        assert_eq!(second_lease, lease);
        assert_eq!(second.last_server_tick, provider_tick);
        let token = crate::archive_v3_wal_owner::WalCheckpointSourceContext::for_test();
        assert_eq!(
            acquired.wal_owner_checkpoint_source_subject(token).unwrap(),
            second.wal_owner_checkpoint_source_subject(token).unwrap()
        );
        assert_ne!(
            second.wal_owner_checkpoint_source_subject(token).unwrap(),
            second
                .with_candidate_root_for_test(
                    RootReference::new(
                        second.root().root().sequence() + 1,
                        ObjectId::from_bytes(id(63)),
                        hash(64),
                    ),
                    second.current_fencing_epoch,
                )
                .wal_owner_checkpoint_source_subject(token)
                .unwrap()
        );
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
