#![allow(
    dead_code,
    reason = "inactive ADR-0022 durable shadow-session codec is compiled before ledger, VFS, or runtime wiring"
)]

//! Bounded, content-free durable identity for one inactive shadow publication.
//!
//! This is deliberately only a codec and state machine.  It has no SQLite,
//! Store, VFS, witness-provider, credential, or network authority.

use std::fmt;

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::archive_v3_witness::{
    DeletionState, MigrationState, RootReference, WitnessLease, WitnessRecord,
};

const MAGIC: &[u8; 8] = b"KASSSv1\0";
const VERSION: u8 = 1;
const SESSION_ID_DOMAIN: &[u8] = b"kioku:archive:v3:shadow-session\0";
const MAINTENANCE_ZERO_WAL_BINDING_DOMAIN: &[u8] =
    b"kioku:archive:v3:maintenance-zero-wal-binding/v1\0";
const WAL_OWNER_CHECKPOINT_BINDING_DOMAIN: &[u8] =
    b"kioku:archive:v3:wal-owner-checkpoint-binding/v1\0";
pub const SHADOW_SESSION_RECORD_BYTES: usize = 344;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShadowSessionId([u8; 16]);

impl ShadowSessionId {
    /// Derive the stable session identity from the caller's durable operation
    /// identity. Retrying the same operation therefore cannot silently start a
    /// different publication session after an ambiguous witness response.
    pub fn for_operation(operation_id: [u8; 16]) -> Result<Self> {
        if !nonzero(&operation_id) {
            return Err(ShadowSessionError::Malformed("operation ID"));
        }
        let mut hash = Sha256::new();
        hash.update(SESSION_ID_DOMAIN);
        hash.update(operation_id);
        let digest: [u8; 32] = hash.finalize().into();
        let mut value = [0; 16];
        value.copy_from_slice(&digest[..16]);
        Ok(Self(value))
    }
    pub const fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
impl fmt::Debug for ShadowSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShadowSessionId(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShadowAttemptId([u8; 16]);

impl ShadowAttemptId {
    pub fn random() -> Self {
        let mut value = [0; 16];
        OsRng.fill_bytes(&mut value);
        Self(value)
    }
    pub const fn from_bytes(value: [u8; 16]) -> Self {
        Self(value)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
impl fmt::Debug for ShadowAttemptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShadowAttemptId(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ShadowSessionState {
    Prepared = 1,
    CandidatePersisted = 2,
    ReconcileRequired = 3,
    Witnessed = 4,
    Superseded = 5,
    Aborted = 6,
}

impl ShadowSessionState {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::CandidatePersisted),
            3 => Ok(Self::ReconcileRequired),
            4 => Ok(Self::Witnessed),
            5 => Ok(Self::Superseded),
            6 => Ok(Self::Aborted),
            _ => Err(ShadowSessionError::Corrupt),
        }
    }
    fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Prepared,
                Self::CandidatePersisted | Self::Superseded | Self::Aborted
            ) | (
                Self::CandidatePersisted,
                Self::ReconcileRequired | Self::Witnessed | Self::Superseded | Self::Aborted
            ) | (
                Self::ReconcileRequired,
                Self::Witnessed | Self::Superseded | Self::Aborted
            )
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShadowCandidate {
    root_seq: u64,
    object_id: [u8; 16],
    ciphertext_hash: [u8; 32],
}
impl ShadowCandidate {
    pub fn new(root_seq: u64, object_id: [u8; 16], ciphertext_hash: [u8; 32]) -> Result<Self> {
        let value = Self {
            root_seq,
            object_id,
            ciphertext_hash,
        };
        value
            .valid()
            .then_some(value)
            .ok_or(ShadowSessionError::Malformed("candidate"))
    }
    fn valid(self) -> bool {
        self.root_seq != 0 && nonzero(&self.object_id) && nonzero(&self.ciphertext_hash)
    }
    pub const fn root_seq(self) -> u64 {
        self.root_seq
    }
    pub const fn object_id(self) -> [u8; 16] {
        self.object_id
    }
    pub const fn ciphertext_hash(self) -> [u8; 32] {
        self.ciphertext_hash
    }

    pub fn from_root_reference(reference: RootReference) -> Result<Self> {
        Self::new(
            reference.sequence(),
            *reference.object_id().as_bytes(),
            reference.ciphertext_hash(),
        )
    }

    fn matches_root(self, reference: RootReference) -> bool {
        self.root_seq == reference.sequence()
            && self.object_id == *reference.object_id().as_bytes()
            && self.ciphertext_hash == reference.ciphertext_hash()
    }
}
impl fmt::Debug for ShadowCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShadowCandidate(<opaque>)")
    }
}

/// Exact, content-free facts that must agree before a restarted publication can
/// use its retained candidate.  Opaque IDs are stored as comparison data only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShadowSessionBinding {
    archive_id: [u8; 16],
    database_epoch: [u8; 16],
    database_epoch_generation: u64,
    registry_epoch: [u8; 16],
    registry_rotation_generation: u64,
    registry_object_id: [u8; 16],
    registry_ciphertext_hash: [u8; 32],
    base_root_seq: u64,
    base_root_object_id: [u8; 16],
    base_root_ciphertext_hash: [u8; 32],
    owner_fence: u64,
    operation_id: [u8; 16],
    request_fingerprint: [u8; 32],
    migration_state: u8,
    wal_generation: u64,
    first_frame_no: u64,
    frame_count: u32,
}
impl ShadowSessionBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        archive_id: [u8; 16],
        database_epoch: [u8; 16],
        database_epoch_generation: u64,
        registry_epoch: [u8; 16],
        registry_rotation_generation: u64,
        registry_object_id: [u8; 16],
        registry_ciphertext_hash: [u8; 32],
        base_root_seq: u64,
        base_root_object_id: [u8; 16],
        base_root_ciphertext_hash: [u8; 32],
        owner_fence: u64,
        operation_id: [u8; 16],
        request_fingerprint: [u8; 32],
        migration_state: u8,
        wal_generation: u64,
        first_frame_no: u64,
        frame_count: u32,
    ) -> Result<Self> {
        let value = Self {
            archive_id,
            database_epoch,
            database_epoch_generation,
            registry_epoch,
            registry_rotation_generation,
            registry_object_id,
            registry_ciphertext_hash,
            base_root_seq,
            base_root_object_id,
            base_root_ciphertext_hash,
            owner_fence,
            operation_id,
            request_fingerprint,
            migration_state,
            wal_generation,
            first_frame_no,
            frame_count,
        };
        value
            .valid()
            .then_some(value)
            .ok_or(ShadowSessionError::Malformed("binding"))
    }
    fn valid_identity_core(self) -> bool {
        nonzero(&self.archive_id)
            && nonzero(&self.database_epoch)
            && nonzero(&self.registry_epoch)
            && nonzero(&self.registry_object_id)
            && nonzero(&self.registry_ciphertext_hash)
            && nonzero(&self.base_root_object_id)
            && nonzero(&self.base_root_ciphertext_hash)
            && self.owner_fence != 0
            && nonzero(&self.operation_id)
            && nonzero(&self.request_fingerprint)
    }
    fn valid_identity(self) -> bool {
        self.valid_identity_core() && matches!(self.migration_state, 0 | 1)
    }
    fn valid(self) -> bool {
        self.valid_identity()
            && self.wal_generation != 0
            && self.first_frame_no != 0
            && self.frame_count != 0
    }
    pub const fn archive_id(self) -> [u8; 16] {
        self.archive_id
    }
    pub const fn database_epoch(self) -> [u8; 16] {
        self.database_epoch
    }
    pub(crate) const fn registry_epoch(self) -> [u8; 16] {
        self.registry_epoch
    }
    pub(crate) const fn base_root_seq(self) -> u64 {
        self.base_root_seq
    }
    pub(crate) const fn base_root_object_id(self) -> [u8; 16] {
        self.base_root_object_id
    }
    pub(crate) const fn base_root_ciphertext_hash(self) -> [u8; 32] {
        self.base_root_ciphertext_hash
    }
    pub const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }
    pub const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }
    pub const fn migration_state(self) -> u8 {
        self.migration_state
    }

    pub fn from_witness(
        witness: &WitnessRecord,
        lease: WitnessLease,
        operation_id: [u8; 16],
        request_fingerprint: [u8; 32],
        wal_generation: u64,
        first_frame_no: u64,
        frame_count: u32,
    ) -> Result<Self> {
        if witness.deletion() != DeletionState::Active
            || !matches!(
                witness.migration(),
                MigrationState::Legacy | MigrationState::ShadowWal
            )
            || lease.archive_id() != witness.archive_id()
            || lease.database_epoch() != witness.database_epoch()
            || lease.key_epoch() != witness.registry().key_epoch()
            || !witness.authorizes_lease(lease)
        {
            return Err(ShadowSessionError::BindingConflict);
        }
        let root = witness.root().root();
        let registry = witness.registry();
        Self::new(
            *witness.archive_id().as_bytes(),
            *witness.database_epoch().as_bytes(),
            witness.database_epoch_generation(),
            *registry.key_epoch().as_bytes(),
            registry.rotation_generation(),
            *registry.object_id().as_bytes(),
            registry.ciphertext_hash(),
            root.sequence(),
            *root.object_id().as_bytes(),
            root.ciphertext_hash(),
            lease.fencing_epoch(),
            operation_id,
            request_fingerprint,
            witness.migration() as u8,
            wal_generation,
            first_frame_no,
            frame_count,
        )
    }

    /// Construct the distinct checkpoint-only maintenance binding. Normal
    /// shadow publications continue to require a nonzero WAL tuple; this
    /// producer-gated constructor accepts only the canonical all-zero tuple
    /// and derives a domain-separated fingerprint from the durable operation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_maintenance_witness(
        _token: crate::archive_v3_maintenance_import::MaintenanceZeroWalBindingContext,
        witness: &WitnessRecord,
        lease: WitnessLease,
        operation_id: [u8; 16],
        operation_commitment: [u8; 32],
        wal_generation: u64,
        first_frame_no: u64,
        frame_count: u32,
    ) -> Result<Self> {
        if (wal_generation, first_frame_no, frame_count) != (0, 0, 0)
            || !nonzero(&operation_id)
            || !nonzero(&operation_commitment)
            || witness.deletion() != DeletionState::Active
            || !matches!(
                witness.migration(),
                MigrationState::Legacy | MigrationState::ShadowWal
            )
            || lease.archive_id() != witness.archive_id()
            || lease.database_epoch() != witness.database_epoch()
            || lease.key_epoch() != witness.registry().key_epoch()
            || !witness.authorizes_lease(lease)
        {
            return Err(ShadowSessionError::BindingConflict);
        }
        let mut request_fingerprint = Sha256::new();
        request_fingerprint.update(MAINTENANCE_ZERO_WAL_BINDING_DOMAIN);
        request_fingerprint.update(operation_id);
        request_fingerprint.update(operation_commitment);
        let request_fingerprint: [u8; 32] = request_fingerprint.finalize().into();
        let root = witness.root().root();
        let registry = witness.registry();
        let binding = Self {
            archive_id: *witness.archive_id().as_bytes(),
            database_epoch: *witness.database_epoch().as_bytes(),
            database_epoch_generation: witness.database_epoch_generation(),
            registry_epoch: *registry.key_epoch().as_bytes(),
            registry_rotation_generation: registry.rotation_generation(),
            registry_object_id: *registry.object_id().as_bytes(),
            registry_ciphertext_hash: registry.ciphertext_hash(),
            base_root_seq: root.sequence(),
            base_root_object_id: *root.object_id().as_bytes(),
            base_root_ciphertext_hash: root.ciphertext_hash(),
            owner_fence: lease.fencing_epoch(),
            operation_id,
            request_fingerprint,
            migration_state: witness.migration() as u8,
            wal_generation,
            first_frame_no,
            frame_count,
        };
        (binding.valid_identity()
            && (
                binding.wal_generation,
                binding.first_frame_no,
                binding.frame_count,
            ) == (0, 0, 0))
            .then_some(binding)
            .ok_or(ShadowSessionError::Malformed("maintenance binding"))
    }

    /// Publisher-only canonical zero-WAL binding for one durable checkpoint
    /// attempt. Ordinary capture still requires a nonzero WAL tuple and the
    /// maintenance constructor remains limited to Legacy/ShadowWal.
    pub(crate) fn from_wal_owner_checkpoint(
        _token: crate::archive_v3_wal_owner::WalCheckpointSourceContext,
        witness: &WitnessRecord,
        lease: WitnessLease,
        operation_id: [u8; 16],
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        attempt: u32,
    ) -> Result<Self> {
        if !nonzero(&operation_id)
            || session_id.as_bytes() == &[0; 16]
            || attempt_id.as_bytes() == &[0; 16]
            || attempt == 0
            || witness.deletion() != DeletionState::Active
            || witness.migration() != MigrationState::WalAuthoritative
            || lease.archive_id() != witness.archive_id()
            || lease.database_epoch() != witness.database_epoch()
            || lease.key_epoch() != witness.registry().key_epoch()
            || !witness.authorizes_lease(lease)
        {
            return Err(ShadowSessionError::BindingConflict);
        }
        let mut request_fingerprint = Sha256::new();
        request_fingerprint.update(WAL_OWNER_CHECKPOINT_BINDING_DOMAIN);
        request_fingerprint.update(operation_id);
        request_fingerprint.update(session_id.as_bytes());
        request_fingerprint.update(attempt_id.as_bytes());
        request_fingerprint.update(attempt.to_be_bytes());
        let request_fingerprint: [u8; 32] = request_fingerprint.finalize().into();
        let root = witness.root().root();
        let registry = witness.registry();
        let binding = Self {
            archive_id: *witness.archive_id().as_bytes(),
            database_epoch: *witness.database_epoch().as_bytes(),
            database_epoch_generation: witness.database_epoch_generation(),
            registry_epoch: *registry.key_epoch().as_bytes(),
            registry_rotation_generation: registry.rotation_generation(),
            registry_object_id: *registry.object_id().as_bytes(),
            registry_ciphertext_hash: registry.ciphertext_hash(),
            base_root_seq: root.sequence(),
            base_root_object_id: *root.object_id().as_bytes(),
            base_root_ciphertext_hash: root.ciphertext_hash(),
            owner_fence: lease.fencing_epoch(),
            operation_id,
            request_fingerprint,
            migration_state: witness.migration() as u8,
            wal_generation: 0,
            first_frame_no: 0,
            frame_count: 0,
        };
        (binding.valid_identity_core()
            && binding.migration_state == MigrationState::WalAuthoritative as u8
            && (
                binding.wal_generation,
                binding.first_frame_no,
                binding.frame_count,
            ) == (0, 0, 0))
            .then_some(binding)
            .ok_or(ShadowSessionError::Malformed("WAL checkpoint binding"))
    }

    fn matches_witness_identity(self, witness: &WitnessRecord) -> bool {
        let registry = witness.registry();
        self.archive_id == *witness.archive_id().as_bytes()
            && self.database_epoch == *witness.database_epoch().as_bytes()
            && self.database_epoch_generation == witness.database_epoch_generation()
            && self.registry_epoch == *registry.key_epoch().as_bytes()
            && self.registry_rotation_generation == registry.rotation_generation()
            && self.registry_object_id == *registry.object_id().as_bytes()
            && self.registry_ciphertext_hash == registry.ciphertext_hash()
            && self.migration_state == witness.migration() as u8
            && witness.deletion() == DeletionState::Active
    }

    fn matches_base_root(self, root: RootReference) -> bool {
        self.base_root_seq == root.sequence()
            && self.base_root_object_id == *root.object_id().as_bytes()
            && self.base_root_ciphertext_hash == root.ciphertext_hash()
    }
}
impl fmt::Debug for ShadowSessionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShadowSessionBinding(<opaque>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ShadowSessionRecord {
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    binding: ShadowSessionBinding,
    state: ShadowSessionState,
    candidate: Option<ShadowCandidate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ShadowSessionError {
    #[error("archive-v3 shadow session is malformed: {0}")]
    Malformed(&'static str),
    #[error("archive-v3 shadow session record is corrupt")]
    Corrupt,
    #[error("archive-v3 shadow session state transition is invalid")]
    InvalidTransition,
    #[error("archive-v3 shadow session binding does not match")]
    BindingConflict,
    #[error("archive-v3 shadow session candidate is immutable")]
    CandidateConflict,
}
pub type Result<T> = std::result::Result<T, ShadowSessionError>;

/// Pure restart decision. `RetrySameCandidate` is not write authority: the
/// caller must still obtain and validate a fresh witness lease before issuing
/// the exact retained CAS candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowReconcileDecision {
    Witnessed,
    RetrySameCandidate,
    Superseded,
    Aborted,
}

impl ShadowSessionRecord {
    pub fn prepared(
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
    ) -> Result<Self> {
        let record = Self {
            session_id,
            attempt_id,
            binding,
            state: ShadowSessionState::Prepared,
            candidate: None,
        };
        record
            .valid()
            .then_some(record)
            .ok_or(ShadowSessionError::Malformed("record"))
    }
    pub const fn session_id(&self) -> ShadowSessionId {
        self.session_id
    }
    pub const fn attempt_id(&self) -> ShadowAttemptId {
        self.attempt_id
    }
    pub const fn state(&self) -> ShadowSessionState {
        self.state
    }
    pub const fn binding(&self) -> ShadowSessionBinding {
        self.binding
    }
    pub const fn candidate(&self) -> Option<ShadowCandidate> {
        self.candidate
    }
    pub fn require_binding(&self, binding: ShadowSessionBinding) -> Result<()> {
        (self.binding == binding)
            .then_some(())
            .ok_or(ShadowSessionError::BindingConflict)
    }
    pub fn require_prepared_authority(
        &self,
        witness: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<()> {
        if self.state != ShadowSessionState::Prepared
            || self.candidate.is_some()
            || !self.binding.matches_witness_identity(witness)
            || self.binding.owner_fence != lease.fencing_epoch()
            || !witness.authorizes_lease(lease)
        {
            return Err(ShadowSessionError::BindingConflict);
        }
        Ok(())
    }
    pub fn reconcile_against(&self, witness: &WitnessRecord) -> Result<ShadowReconcileDecision> {
        if !matches!(
            self.state,
            ShadowSessionState::CandidatePersisted | ShadowSessionState::ReconcileRequired
        ) {
            return Err(ShadowSessionError::InvalidTransition);
        }
        let candidate = self
            .candidate
            .ok_or(ShadowSessionError::Malformed("candidate required"))?;
        if !self.binding.matches_witness_identity(witness) {
            return Ok(ShadowReconcileDecision::Superseded);
        }
        let commitment = witness.root();
        if candidate.matches_root(commitment.root()) {
            return Ok(
                if commitment.owner_fencing_epoch() == self.binding.owner_fence
                    && commitment
                        .parent()
                        .is_some_and(|parent| self.binding.matches_base_root(parent))
                {
                    ShadowReconcileDecision::Witnessed
                } else {
                    ShadowReconcileDecision::Superseded
                },
            );
        }
        Ok(if self.binding.matches_base_root(commitment.root()) {
            ShadowReconcileDecision::RetrySameCandidate
        } else {
            ShadowReconcileDecision::Superseded
        })
    }
    pub fn persist_candidate(&mut self, candidate: ShadowCandidate) -> Result<()> {
        if candidate.root_seq
            != self
                .binding
                .base_root_seq
                .checked_add(1)
                .ok_or(ShadowSessionError::Malformed("root sequence"))?
        {
            return Err(ShadowSessionError::BindingConflict);
        }
        match self.candidate {
            Some(existing) if existing != candidate => Err(ShadowSessionError::CandidateConflict),
            Some(_) => Ok(()),
            None if self.state == ShadowSessionState::Prepared => {
                self.candidate = Some(candidate);
                self.state = ShadowSessionState::CandidatePersisted;
                Ok(())
            }
            None => Err(ShadowSessionError::InvalidTransition),
        }
    }
    pub fn transition(&mut self, next: ShadowSessionState) -> Result<()> {
        if !self.state.permits(next) {
            return Err(ShadowSessionError::InvalidTransition);
        }
        if matches!(
            next,
            ShadowSessionState::CandidatePersisted
                | ShadowSessionState::ReconcileRequired
                | ShadowSessionState::Witnessed
        ) && self.candidate.is_none()
        {
            return Err(ShadowSessionError::Malformed("candidate required"));
        }
        self.state = next;
        Ok(())
    }
    pub fn encode(&self) -> Result<[u8; SHADOW_SESSION_RECORD_BYTES]> {
        if !self.valid() {
            return Err(ShadowSessionError::Corrupt);
        }
        let mut out = [0; SHADOW_SESSION_RECORD_BYTES];
        let mut p = 0;
        put(&mut out, &mut p, MAGIC);
        put(&mut out, &mut p, &[VERSION, self.state as u8]);
        put(&mut out, &mut p, self.session_id.as_bytes());
        put(&mut out, &mut p, self.attempt_id.as_bytes());
        let b = self.binding;
        put(&mut out, &mut p, &b.archive_id);
        put(&mut out, &mut p, &b.database_epoch);
        put_u64(&mut out, &mut p, b.database_epoch_generation);
        put(&mut out, &mut p, &b.registry_epoch);
        put_u64(&mut out, &mut p, b.registry_rotation_generation);
        put(&mut out, &mut p, &b.registry_object_id);
        put(&mut out, &mut p, &b.registry_ciphertext_hash);
        put_u64(&mut out, &mut p, b.base_root_seq);
        put(&mut out, &mut p, &b.base_root_object_id);
        put(&mut out, &mut p, &b.base_root_ciphertext_hash);
        put_u64(&mut out, &mut p, b.owner_fence);
        put(&mut out, &mut p, &b.operation_id);
        put(&mut out, &mut p, &b.request_fingerprint);
        put(&mut out, &mut p, &[b.migration_state]);
        put_u64(&mut out, &mut p, b.wal_generation);
        put_u64(&mut out, &mut p, b.first_frame_no);
        put_u32(&mut out, &mut p, b.frame_count);
        if let Some(c) = self.candidate {
            put(&mut out, &mut p, &[1]);
            put_u64(&mut out, &mut p, c.root_seq);
            put(&mut out, &mut p, &c.object_id);
            put(&mut out, &mut p, &c.ciphertext_hash);
        } else {
            put(&mut out, &mut p, &[0]);
            put(&mut out, &mut p, &[0; 56]);
        }
        debug_assert_eq!(p, SHADOW_SESSION_RECORD_BYTES);
        Ok(out)
    }
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != SHADOW_SESSION_RECORD_BYTES {
            return Err(ShadowSessionError::Corrupt);
        }
        let mut p = 0;
        if take(input, &mut p, 8)? != MAGIC || take(input, &mut p, 1)?[0] != VERSION {
            return Err(ShadowSessionError::Corrupt);
        }
        let state = ShadowSessionState::decode(take(input, &mut p, 1)?[0])?;
        let session_id = ShadowSessionId::from_bytes(array(take(input, &mut p, 16)?)?);
        let attempt_id = ShadowAttemptId::from_bytes(array(take(input, &mut p, 16)?)?);
        let binding = ShadowSessionBinding::new(
            array(take(input, &mut p, 16)?)?,
            array(take(input, &mut p, 16)?)?,
            get_u64(input, &mut p)?,
            array(take(input, &mut p, 16)?)?,
            get_u64(input, &mut p)?,
            array(take(input, &mut p, 16)?)?,
            array(take(input, &mut p, 32)?)?,
            get_u64(input, &mut p)?,
            array(take(input, &mut p, 16)?)?,
            array(take(input, &mut p, 32)?)?,
            get_u64(input, &mut p)?,
            array(take(input, &mut p, 16)?)?,
            array(take(input, &mut p, 32)?)?,
            take(input, &mut p, 1)?[0],
            get_u64(input, &mut p)?,
            get_u64(input, &mut p)?,
            get_u32(input, &mut p)?,
        )
        .map_err(|_| ShadowSessionError::Corrupt)?;
        let candidate = match take(input, &mut p, 1)?[0] {
            0 => {
                if take(input, &mut p, 56)?.iter().any(|x| *x != 0) {
                    return Err(ShadowSessionError::Corrupt);
                }
                None
            }
            1 => Some(
                ShadowCandidate::new(
                    get_u64(input, &mut p)?,
                    array(take(input, &mut p, 16)?)?,
                    array(take(input, &mut p, 32)?)?,
                )
                .map_err(|_| ShadowSessionError::Corrupt)?,
            ),
            _ => return Err(ShadowSessionError::Corrupt),
        };
        let record = Self {
            session_id,
            attempt_id,
            binding,
            state,
            candidate,
        };
        record
            .valid()
            .then_some(record)
            .ok_or(ShadowSessionError::Corrupt)
    }
    fn valid(&self) -> bool {
        nonzero(self.session_id.as_bytes())
            && nonzero(self.attempt_id.as_bytes())
            && self.binding.valid()
            && match (self.state, self.candidate) {
                (ShadowSessionState::Prepared, None) => true,
                (
                    ShadowSessionState::CandidatePersisted
                    | ShadowSessionState::ReconcileRequired
                    | ShadowSessionState::Witnessed,
                    Some(c),
                ) => c.valid() && self.binding.base_root_seq.checked_add(1) == Some(c.root_seq),
                (ShadowSessionState::Superseded | ShadowSessionState::Aborted, candidate) => {
                    candidate.is_none_or(ShadowCandidate::valid)
                }
                _ => false,
            }
    }
}
impl fmt::Debug for ShadowSessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShadowSessionRecord(<opaque>)")
    }
}

fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}
fn put(out: &mut [u8], p: &mut usize, value: &[u8]) {
    out[*p..*p + value.len()].copy_from_slice(value);
    *p += value.len();
}
fn put_u64(out: &mut [u8], p: &mut usize, value: u64) {
    put(out, p, &value.to_be_bytes());
}
fn put_u32(out: &mut [u8], p: &mut usize, value: u32) {
    put(out, p, &value.to_be_bytes());
}
fn take<'a>(input: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = p.checked_add(n).ok_or(ShadowSessionError::Corrupt)?;
    let value = input.get(*p..end).ok_or(ShadowSessionError::Corrupt)?;
    *p = end;
    Ok(value)
}
fn array<const N: usize>(value: &[u8]) -> Result<[u8; N]> {
    value.try_into().map_err(|_| ShadowSessionError::Corrupt)
}
fn get_u64(input: &[u8], p: &mut usize) -> Result<u64> {
    Ok(u64::from_be_bytes(array(take(input, p, 8)?)?))
}
fn get_u32(input: &[u8], p: &mut usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(take(input, p, 4)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{ArchiveId, DatabaseEpoch, KeyEpoch, ObjectId},
        archive_v3_witness::{
            InMemoryWitness, KeyRegistryReference, MigrationState, RootAdvance, RootCommitment,
            Witness, WitnessBootstrap,
        },
    };
    fn binding() -> ShadowSessionBinding {
        ShadowSessionBinding::new(
            [1; 16], [2; 16], 7, [3; 16], 9, [4; 16], [5; 32], 11, [6; 16], [7; 32], 13, [8; 16],
            [9; 32], 1, 15, 17, 19,
        )
        .unwrap()
    }
    fn record() -> ShadowSessionRecord {
        ShadowSessionRecord::prepared(
            ShadowSessionId::from_bytes([10; 16]),
            ShadowAttemptId::from_bytes([11; 16]),
            binding(),
        )
        .unwrap()
    }
    fn candidate() -> ShadowCandidate {
        ShadowCandidate::new(12, [12; 16], [13; 32]).unwrap()
    }
    fn witnessed_binding() -> (WitnessRecord, WitnessLease, ShadowSessionBinding) {
        let archive_id = ArchiveId::from_bytes([21; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([22; 16]);
        let key_epoch = KeyEpoch::from_bytes([23; 16]);
        let root = RootReference::new(0, ObjectId::from_bytes([24; 16]), [25; 32]);
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(database_epoch, key_epoch, root),
                KeyRegistryReference::new(key_epoch, 0, ObjectId::from_bytes([26; 16]), [27; 32]),
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(
                archive_id,
                database_epoch,
                key_epoch,
                ObjectId::from_bytes([28; 16]),
                60,
            )
            .unwrap();
        let record = witness.read_current(archive_id).unwrap().unwrap();
        let binding =
            ShadowSessionBinding::from_witness(&record, lease, [29; 16], [30; 32], 1, 1, 3)
                .unwrap();
        (record, lease, binding)
    }
    #[test]
    fn maintenance_zero_wal_binding_is_domain_separated_and_exact() {
        let (legacy, lease, normal) = witnessed_binding();
        let token =
            crate::archive_v3_maintenance_import::MaintenanceZeroWalBindingContext::for_test();
        let maintenance = ShadowSessionBinding::from_maintenance_witness(
            token, &legacy, lease, [29; 16], [30; 32], 0, 0, 0,
        )
        .unwrap();
        assert_ne!(
            maintenance.request_fingerprint(),
            normal.request_fingerprint()
        );
        for tuple in [(0, 0, 1), (0, 1, 0), (1, 0, 0), (1, 1, 1)] {
            assert!(ShadowSessionBinding::from_maintenance_witness(
                crate::archive_v3_maintenance_import::MaintenanceZeroWalBindingContext::for_test(),
                &legacy,
                lease,
                [29; 16],
                [30; 32],
                tuple.0,
                tuple.1,
                tuple.2,
            )
            .is_err());
        }

        let candidate = legacy
            .with_candidate_root_for_test(
                RootReference::new(1, ObjectId::from_bytes([31; 16]), [32; 32]),
                lease.fencing_epoch(),
            )
            .root();
        let shadow = legacy
            .exact_migration_candidate(
                &RootAdvance::new(lease, legacy.root(), legacy.registry(), candidate),
                MigrationState::ShadowWal,
            )
            .unwrap();
        assert!(ShadowSessionBinding::from_maintenance_witness(
            crate::archive_v3_maintenance_import::MaintenanceZeroWalBindingContext::for_test(),
            &shadow,
            lease,
            [29; 16],
            [30; 32],
            0,
            0,
            0,
        )
        .is_ok());
        let authoritative_root = shadow
            .with_candidate_root_for_test(
                RootReference::new(2, ObjectId::from_bytes([33; 16]), [34; 32]),
                lease.fencing_epoch(),
            )
            .root();
        let authoritative = shadow
            .exact_migration_candidate(
                &RootAdvance::new(lease, shadow.root(), shadow.registry(), authoritative_root),
                MigrationState::WalAuthoritative,
            )
            .unwrap();
        assert!(ShadowSessionBinding::from_maintenance_witness(
            crate::archive_v3_maintenance_import::MaintenanceZeroWalBindingContext::for_test(),
            &authoritative,
            lease,
            [29; 16],
            [30; 32],
            0,
            0,
            0,
        )
        .is_err());
    }

    #[test]
    fn wal_owner_checkpoint_binding_accepts_only_authoritative_live_zero_wal_context() {
        let (legacy, lease, _) = witnessed_binding();
        let shadow_root = legacy
            .with_candidate_root_for_test(
                RootReference::new(1, ObjectId::from_bytes([41; 16]), [42; 32]),
                lease.fencing_epoch(),
            )
            .root();
        let shadow = legacy
            .exact_migration_candidate(
                &RootAdvance::new(lease, legacy.root(), legacy.registry(), shadow_root),
                MigrationState::ShadowWal,
            )
            .unwrap();
        let authoritative_root = shadow
            .with_candidate_root_for_test(
                RootReference::new(2, ObjectId::from_bytes([43; 16]), [44; 32]),
                lease.fencing_epoch(),
            )
            .root();
        let authoritative = shadow
            .exact_migration_candidate(
                &RootAdvance::new(lease, shadow.root(), shadow.registry(), authoritative_root),
                MigrationState::WalAuthoritative,
            )
            .unwrap();
        let token = crate::archive_v3_wal_owner::WalCheckpointSourceContext::for_test();
        let first = ShadowSessionBinding::from_wal_owner_checkpoint(
            token,
            &authoritative,
            lease,
            [45; 16],
            ShadowSessionId::from_bytes([46; 16]),
            ShadowAttemptId::from_bytes([47; 16]),
            1,
        )
        .unwrap();
        let second = ShadowSessionBinding::from_wal_owner_checkpoint(
            token,
            &authoritative,
            lease,
            [45; 16],
            ShadowSessionId::from_bytes([46; 16]),
            ShadowAttemptId::from_bytes([48; 16]),
            1,
        )
        .unwrap();
        assert_ne!(first.request_fingerprint(), second.request_fingerprint());
        assert!(ShadowSessionBinding::from_wal_owner_checkpoint(
            token,
            &legacy,
            lease,
            [45; 16],
            ShadowSessionId::from_bytes([46; 16]),
            ShadowAttemptId::from_bytes([47; 16]),
            1,
        )
        .is_err());
        assert!(ShadowSessionBinding::from_wal_owner_checkpoint(
            token,
            &shadow,
            lease,
            [45; 16],
            ShadowSessionId::from_bytes([46; 16]),
            ShadowAttemptId::from_bytes([47; 16]),
            1,
        )
        .is_err());
        assert!(ShadowSessionBinding::from_wal_owner_checkpoint(
            token,
            &authoritative,
            lease,
            [0; 16],
            ShadowSessionId::from_bytes([46; 16]),
            ShadowAttemptId::from_bytes([47; 16]),
            1,
        )
        .is_err());
    }
    #[test]
    fn round_trip_and_redaction() {
        let mut value = record();
        value.persist_candidate(candidate()).unwrap();
        value
            .transition(ShadowSessionState::ReconcileRequired)
            .unwrap();
        let encoded = value.encode().unwrap();
        assert_eq!(ShadowSessionRecord::decode(&encoded).unwrap(), value);
        assert_eq!(format!("{value:?}"), "ShadowSessionRecord(<opaque>)");
    }
    #[test]
    fn transitions_require_candidate_and_are_terminal() {
        let mut value = record();
        assert!(value.transition(ShadowSessionState::Witnessed).is_err());
        value.persist_candidate(candidate()).unwrap();
        value.transition(ShadowSessionState::Witnessed).unwrap();
        assert!(value
            .transition(ShadowSessionState::ReconcileRequired)
            .is_err());
    }
    #[test]
    fn candidate_and_binding_are_immutable() {
        let mut value = record();
        value.persist_candidate(candidate()).unwrap();
        assert!(matches!(
            value.persist_candidate(ShadowCandidate::new(12, [14; 16], [15; 32]).unwrap()),
            Err(ShadowSessionError::CandidateConflict)
        ));
        let mut other = binding();
        other.owner_fence = 99;
        assert_eq!(
            value.require_binding(other),
            Err(ShadowSessionError::BindingConflict)
        );
    }
    #[test]
    fn decoder_rejects_length_version_and_cross_binding() {
        let value = record();
        let bytes = value.encode().unwrap();
        assert!(ShadowSessionRecord::decode(&bytes[..342]).is_err());
        let mut oversized = bytes.to_vec();
        oversized.push(0);
        assert!(ShadowSessionRecord::decode(&oversized).is_err());
        let mut version = bytes;
        version[8] = 2;
        assert!(ShadowSessionRecord::decode(&version).is_err());
        let mut bad = bytes;
        bad[210..218].fill(0);
        assert!(ShadowSessionRecord::decode(&bad).is_err());
    }
    #[test]
    fn prepared_cannot_claim_candidate_and_candidate_root_is_exact_next() {
        let value = record();
        let mut bytes = value.encode().unwrap();
        let candidate_flag = SHADOW_SESSION_RECORD_BYTES - 57;
        bytes[candidate_flag] = 1;
        assert!(ShadowSessionRecord::decode(&bytes).is_err());
        assert!(ShadowCandidate::new(13, [12; 16], [13; 32]).is_ok());
        assert!(value
            .clone()
            .persist_candidate(ShadowCandidate::new(13, [12; 16], [13; 32]).unwrap())
            .is_err());
    }
    #[test]
    fn session_identity_is_stable_operation_derived_and_redacted() {
        let first = ShadowSessionId::for_operation([42; 16]).unwrap();
        let second = ShadowSessionId::for_operation([42; 16]).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, ShadowSessionId::for_operation([43; 16]).unwrap());
        assert!(ShadowSessionId::for_operation([0; 16]).is_err());
        assert_eq!(format!("{first:?}"), "ShadowSessionId(<opaque>)");
    }

    #[test]
    fn typed_witness_binding_and_restart_decision_are_exact_and_non_authorizing() {
        let (base, _lease, binding) = witnessed_binding();
        let mut session = ShadowSessionRecord::prepared(
            ShadowSessionId::for_operation(binding.operation_id()).unwrap(),
            ShadowAttemptId::from_bytes([31; 16]),
            binding,
        )
        .unwrap();
        let root = RootReference::new(1, ObjectId::from_bytes([32; 16]), [33; 32]);
        session
            .persist_candidate(ShadowCandidate::from_root_reference(root).unwrap())
            .unwrap();
        assert_eq!(
            session.reconcile_against(&base).unwrap(),
            ShadowReconcileDecision::RetrySameCandidate
        );
        let witnessed = base.with_candidate_root_for_test(root, 1);
        assert_eq!(
            session.reconcile_against(&witnessed).unwrap(),
            ShadowReconcileDecision::Witnessed
        );
        assert_eq!(
            session
                .reconcile_against(&base.with_candidate_root_for_test(root, 2))
                .unwrap(),
            ShadowReconcileDecision::Superseded
        );
        assert_eq!(
            session
                .reconcile_against(&base.with_migration_for_test(MigrationState::ShadowWal))
                .unwrap(),
            ShadowReconcileDecision::Superseded
        );
        assert_eq!(
            session
                .reconcile_against(&base.tombstoned_for_test())
                .unwrap(),
            ShadowReconcileDecision::Superseded
        );
    }
}
