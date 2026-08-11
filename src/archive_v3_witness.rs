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
    pub(crate) fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
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
impl RootAdvance {
    pub(crate) fn archive_id(&self) -> ArchiveId {
        self.lease.archive_id
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
            || record.deletion == DeletionState::PhysicalComplete
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
        if matches!(
            r.deletion,
            DeletionState::Active | DeletionState::PhysicalComplete
        ) {
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
        let (inventory_commitment, provider_drain_commitment) = match (next, proof.drain_binding())
        {
            (DeletionState::PhysicalComplete, Some((inventory, drain))) => {
                (Some(inventory), Some(drain))
            }
            (DeletionState::PhysicalComplete, None) => return Err(WitnessError::Malformed),
            (_, None) => (None, None),
            (_, Some(_)) => return Err(WitnessError::Malformed),
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
        if state == DeletionState::PhysicalComplete {
            proof.bind_inventory_drain(hash(81), hash(82)).unwrap()
        } else {
            proof
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
            logical_file_length: 0,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_chain_root: None,
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
            logical_file_length: 0,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_chain_root: None,
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
        assert_eq!(
            w.advance_deletion(
                del(&x, t.authorization),
                DeletionState::CryptographicallyErased,
                &deletion_credential(),
                &deletion_proof(DeletionState::LogicalObjectsAbsent),
            ),
            Err(WitnessError::Unauthorized)
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
        assert!(matches!(
            after_inventory_restart.resume_deletion(r.archive_id, &deletion_credential()),
            Err(WitnessError::InvalidTransition)
        ));
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
