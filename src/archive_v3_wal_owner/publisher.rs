#![allow(
    dead_code,
    reason = "inactive ADR-0022 single-archive WAL publisher is compiled before any external domain adapter or startup wiring"
)]

//! Private provider/checkpoint half of the single-archive WAL owner.
//!
//! This child module is the only production implementation of the sealed
//! publication authority.  It is constructed by consuming one serving
//! handoff — the parity-certified maintenance handoff or the genesis-ledger
//! handoff — never from archive IDs or provider handles.  Encrypted Control
//! reserves every owner lease, checkpoint attempt, and immutable object before
//! provider mutation.  No type in this module is exported from its parent.

use std::{
    fmt,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::{
    archive_v3::{ArchiveId, ObjectId, VerifiedArchiveCipher},
    archive_v3_maintenance_import::{
        CompletedMaintenanceParityEvidence, CompletedMaintenanceWalHandoffView,
        MaintenanceImportPersistence,
    },
    archive_v3_operation::{RecordOutcome, ShadowObjectFacts, ShadowObjectInventoryPage},
    archive_v3_shadow_checkpoint::{
        reconcile_reserved_shadow_objects, upload_owned_checkpoint, ExactImmutableObjectBackend,
        ShadowObjectInventory, ShadowObjectInventoryError, ShadowObjectStaging, UploadedCheckpoint,
    },
    archive_v3_shadow_session::{ShadowAttemptId, ShadowSessionBinding, ShadowSessionId},
    archive_v3_witness::{
        AuthenticatedWalRootAdvance, DeletionState, MigrationState, RecoveryRoot, RootAdvance,
        WitnessError, WitnessLease, WitnessRecord,
    },
};

use super::{
    AuthenticatedWalOwnerHead, FreshHead, Result, WalOperationIdentity, WalOwnerAttempt,
    WalOwnerControl, WalOwnerError, WalOwnerHandle, WalOwnerId, WalOwnerInstanceId,
    WalOwnerStoreBinding, WalOwnerStoreContext, WalPublicationArtifact, WalPublicationAuthority,
    WalPublicationCandidate, WitnessedWalCandidate,
};

const OWNER_LEASE_FORMAT_V1: u16 = 1;
const CHECKPOINT_FORMAT_V1: u16 = 1;
const OWNER_LEASE_COMMITMENT_DOMAIN: &[u8] = b"kioku/archive-v3/wal-publisher-owner-lease/v1\0";
const CHECKPOINT_SOURCE_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/wal-publisher-checkpoint-source/v1\0";
const CHECKPOINT_ATTEMPT_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/wal-publisher-checkpoint-attempt/v1\0";
const CHECKPOINT_ARTIFACT_SET_DOMAIN: &[u8] =
    b"kioku/archive-v3/wal-publisher-checkpoint-artifacts/v1\0";
const OWNER_LEASE_TICKS: u64 = 300;
const CHECKPOINT_OBJECTS_PER_HEARTBEAT: u32 = 32;

pub(crate) const MAX_CHECKPOINT_ATTEMPTS: u32 = 16;
pub(crate) const MAX_CHECKPOINT_ARTIFACTS: u32 = 32_898;

fn checkpoint_source_binding_commitment(binding: &WalOwnerStoreBinding) -> Result<[u8; 32]> {
    let witness =
        WitnessRecord::decode(binding.witness_bytes()).map_err(|_| WalOwnerError::Corrupt)?;
    let subject = witness
        .wal_owner_checkpoint_source_subject(super::WalCheckpointSourceContext(()))
        .map_err(|_| WalOwnerError::Corrupt)?;
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_SOURCE_COMMITMENT_DOMAIN);
    hasher.update(CHECKPOINT_FORMAT_V1.to_be_bytes());
    hasher.update(subject);
    let commitment: [u8; 32] = hasher.finalize().into();
    (commitment != [0; 32])
        .then_some(commitment)
        .ok_or(WalOwnerError::Corrupt)
}

pub(crate) fn checkpoint_artifact_set_commitment(
    _token: crate::cp::control_store::WalOwnerPersistenceContext,
    attempt: &CheckpointAttempt,
    canonical_rows: &[u8],
) -> Result<[u8; 32]> {
    if canonical_rows.is_empty() {
        return Err(WalOwnerError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_ARTIFACT_SET_DOMAIN);
    hasher.update(CHECKPOINT_FORMAT_V1.to_be_bytes());
    hasher.update(attempt.operation_id.as_bytes());
    hasher.update(attempt.session_id.as_bytes());
    hasher.update(attempt.attempt_id.as_bytes());
    hasher.update(attempt.attempt.to_be_bytes());
    hasher.update(attempt.owner_instance_id.as_bytes());
    hasher.update((canonical_rows.len() as u64).to_be_bytes());
    hasher.update(canonical_rows);
    let value: [u8; 32] = hasher.finalize().into();
    (value != [0; 32])
        .then_some(value)
        .ok_or(WalOwnerError::Corrupt)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum OwnerLeaseStage {
    Reserved = 1,
    SendStarted = 2,
    Bound = 3,
    ManualRequired = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CheckpointStage {
    Prepared = 1,
    SourceReady = 2,
    Uploading = 3,
    CandidateReady = 4,
    SendStarted = 5,
    Witnessed = 6,
    ManualRequired = 7,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckpointOperationId([u8; 16]);

impl CheckpointOperationId {
    fn random() -> Result<Self> {
        for _ in 0..16 {
            let mut value = [0; 16];
            OsRng.fill_bytes(&mut value);
            if value != [0; 16] {
                return Ok(Self(value));
            }
        }
        Err(WalOwnerError::Persistence)
    }

    pub(crate) fn random_for_control(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
    ) -> Result<Self> {
        Self::random()
    }

    pub(crate) fn from_control(value: [u8; 16]) -> Result<Self> {
        (value != [0; 16])
            .then_some(Self(value))
            .ok_or(WalOwnerError::Corrupt)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for CheckpointOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointOperationId(<opaque>)")
    }
}

/// Durable owner reservation. It carries comparison data only and cannot
/// issue or renew a provider lease.
pub(crate) struct ReservedWalOwnerLease {
    owner_id: WalOwnerId,
    expected: WitnessRecord,
    revision: u64,
    commitment: [u8; 32],
    stage: OwnerLeaseStage,
}

impl ReservedWalOwnerLease {
    pub(crate) fn new_for_control(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        owner_id: WalOwnerId,
        expected: WitnessRecord,
    ) -> Result<Self> {
        let commitment = owner_lease_commitment(
            owner_id,
            &expected,
            1,
            OwnerLeaseStage::Reserved,
            None,
            None,
        );
        Self::from_control(
            _token,
            owner_id,
            expected,
            1,
            OwnerLeaseStage::Reserved,
            (None, None),
            commitment,
        )
    }

    pub(crate) fn send_started_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
    ) -> Result<Self> {
        if self.stage != OwnerLeaseStage::Reserved {
            return Err(WalOwnerError::Conflict);
        }
        let revision = self.revision.checked_add(1).ok_or(WalOwnerError::Corrupt)?;
        let commitment = owner_lease_commitment(
            self.owner_id,
            &self.expected,
            revision,
            OwnerLeaseStage::SendStarted,
            None,
            None,
        );
        Self::from_control(
            token,
            self.owner_id,
            self.expected.clone(),
            revision,
            OwnerLeaseStage::SendStarted,
            (None, None),
            commitment,
        )
    }

    pub(crate) fn from_control(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        owner_id: WalOwnerId,
        expected: WitnessRecord,
        revision: u64,
        stage: OwnerLeaseStage,
        lineage: (Option<&WitnessRecord>, Option<&WitnessRecord>),
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        let (predecessor, observed) = lineage;
        if revision == 0
            || expected.deletion() != DeletionState::Active
            || expected.migration() != MigrationState::WalAuthoritative
            || expected.has_exact_active_wal_owner_lease()
            || matches!(stage, OwnerLeaseStage::Bound) != observed.is_some()
            || predecessor.is_some() != observed.is_some()
        {
            return Err(WalOwnerError::Corrupt);
        }
        let commitment =
            owner_lease_commitment(owner_id, &expected, revision, stage, predecessor, observed);
        if commitment == [0; 32] || commitment != persisted_commitment {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            owner_id,
            expected,
            revision,
            commitment,
            stage,
        })
    }

    pub(super) const fn owner_id(&self) -> WalOwnerId {
        self.owner_id
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
    ) -> (WalOwnerId, &WitnessRecord, u64, OwnerLeaseStage, [u8; 32]) {
        (
            self.owner_id,
            &self.expected,
            self.revision,
            self.stage,
            self.commitment,
        )
    }
}

impl fmt::Debug for ReservedWalOwnerLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReservedWalOwnerLease(<opaque>)")
    }
}

/// Non-cloneable live lease. Only the exact provider acquire/adoption path can
/// mint it; fresh processes receive no method that renews a retained lease.
pub(crate) struct LiveWalOwnerLease {
    owner_id: WalOwnerId,
    expected: WitnessRecord,
    predecessor: WitnessRecord,
    observed: WitnessRecord,
    lease: WitnessLease,
    revision: u64,
    commitment: [u8; 32],
}

impl LiveWalOwnerLease {
    pub(crate) fn from_control_persisted(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        owner_id: WalOwnerId,
        expected: WitnessRecord,
        predecessor: WitnessRecord,
        observed: WitnessRecord,
        revision: u64,
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        let lease = if predecessor == expected {
            observed.exact_wal_owner_acquire_from(&expected, owner_id.as_bytes())
        } else {
            observed
                .exact_wal_owner_reacquire_from(&predecessor, owner_id.as_bytes())
                .or_else(|_| {
                    observed.exact_wal_owner_heartbeat_from(&predecessor, owner_id.as_bytes())
                })
        }
        .map_err(|_| WalOwnerError::Conflict)?;
        let commitment = owner_lease_commitment(
            owner_id,
            &expected,
            revision,
            OwnerLeaseStage::Bound,
            Some(&predecessor),
            Some(&observed),
        );
        if revision == 0 || commitment == [0; 32] || commitment != persisted_commitment {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            owner_id,
            expected,
            predecessor,
            observed,
            lease,
            revision,
            commitment,
        })
    }

    pub(crate) fn bind_for_control(
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        reservation: &ReservedWalOwnerLease,
        observed: WitnessRecord,
        lease: WitnessLease,
    ) -> Result<Self> {
        let revision = reservation
            .revision
            .checked_add(1)
            .ok_or(WalOwnerError::Corrupt)?;
        let commitment = owner_lease_commitment(
            reservation.owner_id,
            &reservation.expected,
            revision,
            OwnerLeaseStage::Bound,
            Some(&reservation.expected),
            Some(&observed),
        );
        Self::from_bound(
            token,
            reservation,
            reservation.expected.clone(),
            observed,
            lease,
            revision,
            commitment,
        )
    }

    pub(crate) fn from_bound(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        reservation: &ReservedWalOwnerLease,
        predecessor: WitnessRecord,
        observed: WitnessRecord,
        lease: WitnessLease,
        revision: u64,
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        if reservation.stage != OwnerLeaseStage::SendStarted
            || revision <= reservation.revision
            || predecessor != reservation.expected
            || observed
                .exact_wal_owner_acquire_from(&predecessor, reservation.owner_id.as_bytes())
                .ok()
                != Some(lease)
        {
            return Err(WalOwnerError::Conflict);
        }
        let commitment = owner_lease_commitment(
            reservation.owner_id,
            &reservation.expected,
            revision,
            OwnerLeaseStage::Bound,
            Some(&predecessor),
            Some(&observed),
        );
        if commitment != persisted_commitment || commitment == [0; 32] {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            owner_id: reservation.owner_id,
            expected: reservation.expected.clone(),
            predecessor,
            observed,
            lease,
            revision,
            commitment,
        })
    }

    pub(crate) fn reacquired_for_control(
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        retained: &Self,
        predecessor: WitnessRecord,
        observed: WitnessRecord,
        lease: WitnessLease,
    ) -> Result<Self> {
        predecessor
            .retains_exact_wal_owner_lease_from(&retained.observed, retained.owner_id.as_bytes())
            .map_err(|_| WalOwnerError::Conflict)?;
        if observed
            .exact_wal_owner_reacquire_from(&predecessor, retained.owner_id.as_bytes())
            .ok()
            != Some(lease)
        {
            return Err(WalOwnerError::Conflict);
        }
        let revision = retained
            .revision
            .checked_add(1)
            .ok_or(WalOwnerError::Corrupt)?;
        let commitment = owner_lease_commitment(
            retained.owner_id,
            &retained.expected,
            revision,
            OwnerLeaseStage::Bound,
            Some(&predecessor),
            Some(&observed),
        );
        Self::from_control_persisted(
            token,
            retained.owner_id,
            retained.expected.clone(),
            predecessor,
            observed,
            revision,
            commitment,
        )
    }

    pub(crate) fn renewed_for_control(
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        retained: &Self,
        predecessor: WitnessRecord,
        observed: WitnessRecord,
        lease: WitnessLease,
    ) -> Result<Self> {
        predecessor
            .retains_exact_wal_owner_lease_from(&retained.observed, retained.owner_id.as_bytes())
            .map_err(|_| WalOwnerError::Conflict)?;
        if observed
            .exact_wal_owner_heartbeat_from(&predecessor, retained.owner_id.as_bytes())
            .ok()
            != Some(lease)
        {
            return Err(WalOwnerError::Conflict);
        }
        let revision = retained
            .revision
            .checked_add(1)
            .ok_or(WalOwnerError::Corrupt)?;
        let commitment = owner_lease_commitment(
            retained.owner_id,
            &retained.expected,
            revision,
            OwnerLeaseStage::Bound,
            Some(&predecessor),
            Some(&observed),
        );
        Self::from_control_persisted(
            token,
            retained.owner_id,
            retained.expected.clone(),
            predecessor,
            observed,
            revision,
            commitment,
        )
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
    ) -> (
        WalOwnerId,
        &WitnessRecord,
        &WitnessRecord,
        &WitnessRecord,
        WitnessLease,
        u64,
        [u8; 32],
    ) {
        (
            self.owner_id,
            &self.expected,
            &self.predecessor,
            &self.observed,
            self.lease,
            self.revision,
            self.commitment,
        )
    }
}

impl fmt::Debug for LiveWalOwnerLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveWalOwnerLease(<opaque>)")
    }
}

fn owner_lease_commitment(
    owner_id: WalOwnerId,
    expected: &WitnessRecord,
    revision: u64,
    stage: OwnerLeaseStage,
    predecessor: Option<&WitnessRecord>,
    observed: Option<&WitnessRecord>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_LEASE_COMMITMENT_DOMAIN);
    hasher.update(OWNER_LEASE_FORMAT_V1.to_be_bytes());
    hasher.update(owner_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    hasher.update([stage as u8]);
    hasher.update(expected.encode());
    if let Some(predecessor) = predecessor {
        hasher.update([1]);
        hasher.update(predecessor.encode());
    } else {
        hasher.update([0]);
    }
    if let Some(observed) = observed {
        hasher.update([1]);
        hasher.update(observed.encode());
    } else {
        hasher.update([0]);
    }
    hasher.finalize().into()
}

/// First-pass Store source authentication. The path and bytes remain owned by
/// Store; Control receives only these fixed-size facts.
pub(crate) struct AuthenticatedCheckpointSourcePlan {
    binding_commitment: [u8; 32],
    length: u64,
    plaintext_hash: [u8; 32],
    sqlite_schema_version: u32,
    commitment: [u8; 32],
}

impl AuthenticatedCheckpointSourcePlan {
    pub(super) fn from_store(
        binding: &WalOwnerStoreBinding,
        length: u64,
        plaintext_hash: [u8; 32],
        sqlite_schema_version: u32,
    ) -> Result<Self> {
        if length == 0 || plaintext_hash == [0; 32] {
            return Err(WalOwnerError::Corrupt);
        }
        let binding_commitment = checkpoint_source_binding_commitment(binding)?;
        let mut hasher = Sha256::new();
        hasher.update(CHECKPOINT_SOURCE_COMMITMENT_DOMAIN);
        hasher.update(CHECKPOINT_FORMAT_V1.to_be_bytes());
        hasher.update(binding_commitment);
        hasher.update(length.to_be_bytes());
        hasher.update(plaintext_hash);
        hasher.update(sqlite_schema_version.to_be_bytes());
        let commitment: [u8; 32] = hasher.finalize().into();
        if commitment == [0; 32] {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            binding_commitment,
            length,
            plaintext_hash,
            sqlite_schema_version,
            commitment,
        })
    }

    pub(crate) fn from_control(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        length: u64,
        plaintext_hash: [u8; 32],
        sqlite_schema_version: u32,
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        let value = Self::from_store(binding, length, plaintext_hash, sqlite_schema_version)?;
        (value.commitment == persisted_commitment)
            .then_some(value)
            .ok_or(WalOwnerError::Corrupt)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        binding: &WalOwnerStoreBinding,
        length: u64,
        plaintext_hash: [u8; 32],
        sqlite_schema_version: u32,
    ) -> Result<Self> {
        Self::from_store(binding, length, plaintext_hash, sqlite_schema_version)
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
    ) -> ([u8; 32], u64, [u8; 32], u32, [u8; 32]) {
        (
            self.binding_commitment,
            self.length,
            self.plaintext_hash,
            self.sqlite_schema_version,
            self.commitment,
        )
    }
}

impl fmt::Debug for AuthenticatedCheckpointSourcePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedCheckpointSourcePlan(<opaque>)")
    }
}

pub(crate) struct CheckpointAttempt {
    operation_id: CheckpointOperationId,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    attempt: u32,
    revision: u64,
    stage: CheckpointStage,
    source_commitment: Option<[u8; 32]>,
    candidate: Option<crate::archive_v3_witness::RootCommitment>,
    artifact_commitment: Option<[u8; 32]>,
    owner_instance_id: WalOwnerInstanceId,
    commitment: [u8; 32],
}

pub(crate) type CheckpointAttemptControlView = (
    CheckpointOperationId,
    ShadowSessionId,
    ShadowAttemptId,
    u32,
    u64,
    CheckpointStage,
    Option<[u8; 32]>,
    Option<crate::archive_v3_witness::RootCommitment>,
    Option<[u8; 32]>,
    WalOwnerInstanceId,
    [u8; 32],
);

impl CheckpointAttempt {
    pub(crate) fn new_for_control(
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        operation_id: CheckpointOperationId,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        owner_instance_id: WalOwnerInstanceId,
    ) -> Result<Self> {
        let commitment = checkpoint_attempt_commitment(
            binding,
            operation_id,
            session_id,
            attempt_id,
            1,
            1,
            CheckpointStage::Prepared,
            None,
            None,
            None,
            owner_instance_id,
        );
        Self::from_control(
            token,
            binding,
            operation_id,
            session_id,
            attempt_id,
            1,
            1,
            CheckpointStage::Prepared,
            None,
            None,
            None,
            owner_instance_id,
            commitment,
        )
    }

    pub(crate) fn with_source_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        source: &AuthenticatedCheckpointSourcePlan,
    ) -> Result<Self> {
        if self.stage != CheckpointStage::Prepared
            || source.binding_commitment != checkpoint_source_binding_commitment(binding)?
        {
            return Err(WalOwnerError::Conflict);
        }
        let revision = self.revision.checked_add(1).ok_or(WalOwnerError::Corrupt)?;
        let commitment = checkpoint_attempt_commitment(
            binding,
            self.operation_id,
            self.session_id,
            self.attempt_id,
            self.attempt,
            revision,
            CheckpointStage::SourceReady,
            Some(source.commitment),
            None,
            None,
            self.owner_instance_id,
        );
        Self::from_control(
            token,
            binding,
            self.operation_id,
            self.session_id,
            self.attempt_id,
            self.attempt,
            revision,
            CheckpointStage::SourceReady,
            Some(source.commitment),
            None,
            None,
            self.owner_instance_id,
            commitment,
        )
    }

    pub(crate) fn restart_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        owner_instance_id: WalOwnerInstanceId,
        attempt_id: ShadowAttemptId,
    ) -> Result<Self> {
        if !matches!(
            self.stage,
            CheckpointStage::Prepared | CheckpointStage::SourceReady | CheckpointStage::Uploading
        ) || owner_instance_id == self.owner_instance_id
        {
            return Err(WalOwnerError::Conflict);
        }
        let attempt = self
            .attempt
            .checked_add(1)
            .filter(|attempt| *attempt <= MAX_CHECKPOINT_ATTEMPTS)
            .ok_or(WalOwnerError::Conflict)?;
        let revision = self.revision.checked_add(1).ok_or(WalOwnerError::Corrupt)?;
        let stage = if self.source_commitment.is_some() {
            CheckpointStage::SourceReady
        } else {
            CheckpointStage::Prepared
        };
        let commitment = checkpoint_attempt_commitment(
            binding,
            self.operation_id,
            self.session_id,
            attempt_id,
            attempt,
            revision,
            stage,
            self.source_commitment,
            None,
            None,
            owner_instance_id,
        );
        Self::from_control(
            token,
            binding,
            self.operation_id,
            self.session_id,
            attempt_id,
            attempt,
            revision,
            stage,
            self.source_commitment,
            None,
            None,
            owner_instance_id,
            commitment,
        )
    }

    pub(crate) fn rebind_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        attempt_id: ShadowAttemptId,
    ) -> Result<Self> {
        if !matches!(
            self.stage,
            CheckpointStage::Prepared
                | CheckpointStage::SourceReady
                | CheckpointStage::Uploading
                | CheckpointStage::CandidateReady
        ) {
            return Err(WalOwnerError::Conflict);
        }
        let attempt = self
            .attempt
            .checked_add(1)
            .filter(|attempt| *attempt <= MAX_CHECKPOINT_ATTEMPTS)
            .ok_or(WalOwnerError::Conflict)?;
        let revision = self.revision.checked_add(1).ok_or(WalOwnerError::Corrupt)?;
        // A higher fencing epoch invalidates immutable object AAD, so the
        // prior artifact prefix and candidate are retained only as superseded
        // cleanup evidence. The Store-owned source binds the unchanged exact
        // root and can be reused without re-reading mutable SQLite state.
        let stage = if self.source_commitment.is_some() {
            CheckpointStage::SourceReady
        } else {
            CheckpointStage::Prepared
        };
        let commitment = checkpoint_attempt_commitment(
            binding,
            self.operation_id,
            self.session_id,
            attempt_id,
            attempt,
            revision,
            stage,
            self.source_commitment,
            None,
            None,
            self.owner_instance_id,
        );
        Self::from_control(
            token,
            binding,
            self.operation_id,
            self.session_id,
            attempt_id,
            attempt,
            revision,
            stage,
            self.source_commitment,
            None,
            None,
            self.owner_instance_id,
            commitment,
        )
    }

    pub(crate) fn heartbeat_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
    ) -> Result<Self> {
        if matches!(
            self.stage,
            CheckpointStage::SendStarted
                | CheckpointStage::Witnessed
                | CheckpointStage::ManualRequired
        ) {
            return Err(WalOwnerError::Conflict);
        }
        let revision = self.revision.checked_add(1).ok_or(WalOwnerError::Corrupt)?;
        let commitment = checkpoint_attempt_commitment(
            binding,
            self.operation_id,
            self.session_id,
            self.attempt_id,
            self.attempt,
            revision,
            self.stage,
            self.source_commitment,
            self.candidate.as_ref(),
            self.artifact_commitment,
            self.owner_instance_id,
        );
        Self::from_control(
            token,
            binding,
            self.operation_id,
            self.session_id,
            self.attempt_id,
            self.attempt,
            revision,
            self.stage,
            self.source_commitment,
            self.candidate,
            self.artifact_commitment,
            self.owner_instance_id,
            commitment,
        )
    }

    pub(crate) fn uploading_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
    ) -> Result<Self> {
        if !matches!(
            self.stage,
            CheckpointStage::SourceReady | CheckpointStage::Uploading
        ) {
            return Err(WalOwnerError::Conflict);
        }
        if self.stage == CheckpointStage::Uploading {
            return Self::from_control(
                token,
                binding,
                self.operation_id,
                self.session_id,
                self.attempt_id,
                self.attempt,
                self.revision,
                self.stage,
                self.source_commitment,
                self.candidate,
                self.artifact_commitment,
                self.owner_instance_id,
                self.commitment,
            );
        }
        self.transition_for_control(token, binding, CheckpointStage::Uploading, None, None)
    }

    pub(crate) fn candidate_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        candidate: crate::archive_v3_witness::RootCommitment,
        artifact_commitment: [u8; 32],
    ) -> Result<Self> {
        if self.stage != CheckpointStage::Uploading || artifact_commitment == [0; 32] {
            return Err(WalOwnerError::Conflict);
        }
        self.transition_for_control(
            token,
            binding,
            CheckpointStage::CandidateReady,
            Some(candidate),
            Some(artifact_commitment),
        )
    }

    pub(crate) fn send_started_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
    ) -> Result<Self> {
        if self.stage != CheckpointStage::CandidateReady {
            return Err(WalOwnerError::Conflict);
        }
        self.transition_for_control(
            token,
            binding,
            CheckpointStage::SendStarted,
            self.candidate,
            self.artifact_commitment,
        )
    }

    pub(crate) fn witnessed_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
    ) -> Result<Self> {
        if self.stage != CheckpointStage::SendStarted {
            return Err(WalOwnerError::Conflict);
        }
        self.transition_for_control(
            token,
            binding,
            CheckpointStage::Witnessed,
            self.candidate,
            self.artifact_commitment,
        )
    }

    pub(crate) fn manual_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
    ) -> Result<Self> {
        if matches!(
            self.stage,
            CheckpointStage::Witnessed | CheckpointStage::ManualRequired
        ) {
            return Err(WalOwnerError::Conflict);
        }
        self.transition_for_control(
            token,
            binding,
            CheckpointStage::ManualRequired,
            self.candidate,
            self.artifact_commitment,
        )
    }

    fn transition_for_control(
        &self,
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        stage: CheckpointStage,
        candidate: Option<crate::archive_v3_witness::RootCommitment>,
        artifact_commitment: Option<[u8; 32]>,
    ) -> Result<Self> {
        let revision = self.revision.checked_add(1).ok_or(WalOwnerError::Corrupt)?;
        let commitment = checkpoint_attempt_commitment(
            binding,
            self.operation_id,
            self.session_id,
            self.attempt_id,
            self.attempt,
            revision,
            stage,
            self.source_commitment,
            candidate.as_ref(),
            artifact_commitment,
            self.owner_instance_id,
        );
        Self::from_control(
            token,
            binding,
            self.operation_id,
            self.session_id,
            self.attempt_id,
            self.attempt,
            revision,
            stage,
            self.source_commitment,
            candidate,
            artifact_commitment,
            self.owner_instance_id,
            commitment,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        operation_id: CheckpointOperationId,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        attempt: u32,
        revision: u64,
        stage: CheckpointStage,
        source_commitment: Option<[u8; 32]>,
        candidate: Option<crate::archive_v3_witness::RootCommitment>,
        artifact_commitment: Option<[u8; 32]>,
        owner_instance_id: WalOwnerInstanceId,
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        if session_id.as_bytes() == &[0; 16]
            || attempt_id.as_bytes() == &[0; 16]
            || !(1..=MAX_CHECKPOINT_ATTEMPTS).contains(&attempt)
            || revision == 0
            || owner_instance_id.as_bytes() == &[0; 16]
            || source_commitment.is_some_and(|value| value == [0; 32])
            || artifact_commitment.is_some_and(|value| value == [0; 32])
            || (stage == CheckpointStage::Prepared && source_commitment.is_some())
            || (matches!(
                stage,
                CheckpointStage::SourceReady
                    | CheckpointStage::Uploading
                    | CheckpointStage::CandidateReady
                    | CheckpointStage::SendStarted
                    | CheckpointStage::Witnessed
            ) && source_commitment.is_none())
            || (matches!(
                stage,
                CheckpointStage::CandidateReady
                    | CheckpointStage::SendStarted
                    | CheckpointStage::Witnessed
            ) && candidate.is_none())
            || (matches!(
                stage,
                CheckpointStage::Prepared
                    | CheckpointStage::SourceReady
                    | CheckpointStage::Uploading
            ) && candidate.is_some())
            || (stage == CheckpointStage::ManualRequired
                && candidate.is_some()
                && source_commitment.is_none())
            || candidate.is_some() != artifact_commitment.is_some()
        {
            return Err(WalOwnerError::Corrupt);
        }
        let commitment = checkpoint_attempt_commitment(
            binding,
            operation_id,
            session_id,
            attempt_id,
            attempt,
            revision,
            stage,
            source_commitment,
            candidate.as_ref(),
            artifact_commitment,
            owner_instance_id,
        );
        if commitment == [0; 32] || commitment != persisted_commitment {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            operation_id,
            session_id,
            attempt_id,
            attempt,
            revision,
            stage,
            source_commitment,
            candidate,
            artifact_commitment,
            owner_instance_id,
            commitment,
        })
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
    ) -> CheckpointAttemptControlView {
        (
            self.operation_id,
            self.session_id,
            self.attempt_id,
            self.attempt,
            self.revision,
            self.stage,
            self.source_commitment,
            self.candidate,
            self.artifact_commitment,
            self.owner_instance_id,
            self.commitment,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn checkpoint_attempt_commitment(
    binding: &WalOwnerStoreBinding,
    operation_id: CheckpointOperationId,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    attempt: u32,
    revision: u64,
    stage: CheckpointStage,
    source_commitment: Option<[u8; 32]>,
    candidate: Option<&crate::archive_v3_witness::RootCommitment>,
    artifact_commitment: Option<[u8; 32]>,
    owner_instance_id: WalOwnerInstanceId,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_ATTEMPT_COMMITMENT_DOMAIN);
    hasher.update(CHECKPOINT_FORMAT_V1.to_be_bytes());
    hasher.update(binding.commitment());
    hasher.update(operation_id.as_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(attempt_id.as_bytes());
    hasher.update(attempt.to_be_bytes());
    hasher.update(revision.to_be_bytes());
    hasher.update([stage as u8]);
    hasher.update(source_commitment.unwrap_or([0; 32]));
    if let Some(candidate) = candidate {
        hasher.update(candidate.root().sequence().to_be_bytes());
        hasher.update(candidate.root().object_id().as_bytes());
        hasher.update(candidate.root().ciphertext_hash());
        hasher.update(candidate.owner_fencing_epoch().to_be_bytes());
    } else {
        hasher.update([0; 64]);
    }
    hasher.update(artifact_commitment.unwrap_or([0; 32]));
    hasher.update(owner_instance_id.as_bytes());
    hasher.finalize().into()
}

#[async_trait]
pub(crate) trait WalPublisherControl: WalOwnerControl {
    async fn reserve_owner(
        &self,
        expected_terminal: &WitnessRecord,
    ) -> Result<ReservedWalOwnerLease>;

    async fn mark_owner_send_started(
        &self,
        reserved: &ReservedWalOwnerLease,
    ) -> Result<ReservedWalOwnerLease>;

    async fn bind_owner(
        &self,
        reserved: &ReservedWalOwnerLease,
        observed: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<LiveWalOwnerLease>;

    async fn load_bound_owner(&self, observed: &WitnessRecord) -> Result<LiveWalOwnerLease>;

    async fn load_owner_binding(
        &self,
        expected_terminal: &WitnessRecord,
    ) -> Result<WalOwnerStoreBinding>;

    async fn has_pending_owner_work(&self, binding: &WalOwnerStoreBinding) -> Result<bool>;

    async fn has_pending_checkpoint(&self, binding: &WalOwnerStoreBinding) -> Result<bool>;

    async fn rebind_owner_after_expiry(
        &self,
        previous: &WitnessRecord,
        observed: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<LiveWalOwnerLease>;

    async fn persist_owner_renewal(
        &self,
        previous: &WitnessRecord,
        observed: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<LiveWalOwnerLease>;

    async fn prepare_checkpoint(
        &self,
        binding: &WalOwnerStoreBinding,
        owner_instance_id: WalOwnerInstanceId,
    ) -> Result<CheckpointAttempt>;

    async fn record_checkpoint_source(
        &self,
        binding: &WalOwnerStoreBinding,
        attempt: &CheckpointAttempt,
        source: &AuthenticatedCheckpointSourcePlan,
    ) -> Result<CheckpointAttempt>;

    async fn begin_checkpoint_upload(
        &self,
        binding: &WalOwnerStoreBinding,
        attempt: &CheckpointAttempt,
    ) -> Result<CheckpointAttempt>;

    async fn reserve_checkpoint_artifact(
        &self,
        binding: &WalOwnerStoreBinding,
        attempt: &CheckpointAttempt,
        facts: &ShadowObjectFacts,
    ) -> Result<RecordOutcome>;

    async fn materialize_checkpoint_artifact(
        &self,
        binding: &WalOwnerStoreBinding,
        attempt: &CheckpointAttempt,
        facts: &ShadowObjectFacts,
    ) -> Result<RecordOutcome>;

    async fn load_checkpoint_page(
        &self,
        binding: &WalOwnerStoreBinding,
        attempt: &CheckpointAttempt,
        after: Option<u32>,
    ) -> Result<ShadowObjectInventoryPage>;

    async fn record_checkpoint_candidate(
        &self,
        binding: &WalOwnerStoreBinding,
        attempt: &CheckpointAttempt,
        checkpoint: &UploadedCheckpoint,
        candidate: &crate::archive_v3_witness::RootCommitment,
    ) -> Result<CheckpointAttempt>;

    async fn mark_checkpoint_send_started(
        &self,
        binding: &WalOwnerStoreBinding,
        attempt: &CheckpointAttempt,
    ) -> Result<CheckpointAttempt>;

    async fn settle_checkpoint(
        &self,
        binding: &WalOwnerStoreBinding,
        attempt: &CheckpointAttempt,
        observed: &WitnessRecord,
    ) -> Result<WalOwnerStoreBinding>;

    async fn checkpoint_manual(
        &self,
        binding: &WalOwnerStoreBinding,
        attempt: &CheckpointAttempt,
    ) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PublisherCommitError {
    Rejected,
    DefinitelyFailed,
    OutcomeUnknown,
}

#[async_trait]
pub(super) trait WalOwnerWitnessProvider: Send + Sync {
    async fn read_current_exact(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<WitnessRecord, WitnessError>;

    async fn acquire_owner_lease(
        &self,
        expected: &WitnessRecord,
        owner: WalOwnerId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), PublisherCommitError>;

    async fn renew_owner_lease(
        &self,
        retained: &WitnessRecord,
        lease: WitnessLease,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), PublisherCommitError>;

    async fn reacquire_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: WalOwnerId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), PublisherCommitError>;

    async fn maintain_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: WalOwnerId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), PublisherCommitError>;

    async fn advance_root_unresolved(
        &self,
        expected: &WitnessRecord,
        advance: RootAdvance,
    ) -> std::result::Result<(), PublisherCommitError>;
}

#[async_trait]
impl WalOwnerWitnessProvider for crate::archive_v3_shadow_runtime::WalPublisherRuntimeOwner {
    async fn read_current_exact(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<WitnessRecord, WitnessError> {
        self.read_wal_owner_current_exact(&super::WalPublisherRuntimeContext(()), archive_id)
            .await
    }

    async fn acquire_owner_lease(
        &self,
        expected: &WitnessRecord,
        owner: WalOwnerId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), PublisherCommitError> {
        self.acquire_wal_owner_lease_unresolved(
            &super::WalPublisherRuntimeContext(()),
            expected.clone(),
            ObjectId::from_bytes(*owner.as_bytes()),
            duration_ticks,
        )
        .await
        .map_err(map_firestore_commit_error)
    }

    async fn renew_owner_lease(
        &self,
        retained: &WitnessRecord,
        lease: WitnessLease,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), PublisherCommitError> {
        self.renew_wal_owner_lease_unresolved(
            &super::WalPublisherRuntimeContext(()),
            retained.clone(),
            lease,
            duration_ticks,
        )
        .await
        .map_err(map_firestore_commit_error)
    }

    async fn reacquire_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: WalOwnerId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), PublisherCommitError> {
        self.reacquire_wal_owner_lease_unresolved(
            &super::WalPublisherRuntimeContext(()),
            previous.clone(),
            ObjectId::from_bytes(*owner.as_bytes()),
            duration_ticks,
        )
        .await
        .map_err(map_firestore_commit_error)
    }

    async fn maintain_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: WalOwnerId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), PublisherCommitError> {
        self.maintain_wal_owner_lease_unresolved(
            &super::WalPublisherRuntimeContext(()),
            previous.clone(),
            ObjectId::from_bytes(*owner.as_bytes()),
            duration_ticks,
        )
        .await
        .map_err(map_firestore_commit_error)
    }

    async fn advance_root_unresolved(
        &self,
        expected: &WitnessRecord,
        advance: RootAdvance,
    ) -> std::result::Result<(), PublisherCommitError> {
        self.advance_wal_owner_root_unresolved(
            &super::WalPublisherRuntimeContext(()),
            expected,
            advance,
        )
        .await
        .map_err(map_firestore_commit_error)
    }
}

fn map_firestore_commit_error(
    error: crate::archive_v3_firestore_witness::FirestoreWitnessCommitError,
) -> PublisherCommitError {
    match error {
        crate::archive_v3_firestore_witness::FirestoreWitnessCommitError::Rejected(_) => {
            PublisherCommitError::Rejected
        }
        crate::archive_v3_firestore_witness::FirestoreWitnessCommitError::Failed(_) => {
            PublisherCommitError::DefinitelyFailed
        }
        crate::archive_v3_firestore_witness::FirestoreWitnessCommitError::OutcomeUnknown => {
            PublisherCommitError::OutcomeUnknown
        }
    }
}

/// Runtime/provider owner created only by consuming one serving handoff —
/// the parity-certified maintenance handoff or the genesis-ledger handoff.
/// The long-lived Store fence and whole runtime bundle never leave it. The
/// retained parity evidence is inert after construction and `None` for a
/// genesis-born owner, whose archive has no maintenance history to certify.
pub(super) struct SingleArchiveWalPublisher {
    runtime: crate::archive_v3_shadow_runtime::WalPublisherRuntimeOwner,
    objects: Arc<dyn ExactImmutableObjectBackend>,
    control: Arc<crate::cp::control_store::ControlStore>,
    capture: Arc<crate::store::StoreShadowCapture>,
    _archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    _maintenance_parity: Option<CompletedMaintenanceParityEvidence>,
}

impl SingleArchiveWalPublisher {
    async fn maintain_live_owner_binding(
        &self,
        binding: &WalOwnerStoreBinding,
    ) -> Result<WalOwnerStoreBinding> {
        let previous =
            WitnessRecord::decode(binding.witness_bytes()).map_err(|_| WalOwnerError::Corrupt)?;
        let live = self.control.load_bound_owner(&previous).await?;
        let witness = &self.runtime;
        let mut observed = witness
            .read_current_exact(previous.archive_id())
            .await
            .map_err(|_| WalOwnerError::Publication)?;
        if observed == previous {
            match witness
                .maintain_owner_lease(&previous, live.owner_id, OWNER_LEASE_TICKS)
                .await
            {
                Ok((next, _)) => observed = next,
                Err(PublisherCommitError::OutcomeUnknown) => {
                    observed = witness
                        .read_current_exact(previous.archive_id())
                        .await
                        .map_err(|_| WalOwnerError::Publication)?;
                }
                Err(error) => return Err(map_commit_error(error)),
            }
        }
        if observed == previous {
            return Ok(binding.clone());
        }
        if let Ok(lease) =
            observed.exact_wal_owner_heartbeat_from(&previous, live.owner_id.as_bytes())
        {
            self.control
                .persist_owner_renewal(&previous, &observed, lease)
                .await?;
        } else if let Ok(lease) =
            observed.exact_wal_owner_reacquire_from(&previous, live.owner_id.as_bytes())
        {
            self.control
                .rebind_owner_after_expiry(&previous, &observed, lease)
                .await?;
        } else {
            return Err(WalOwnerError::Conflict);
        }
        WalOwnerStoreBinding::from_authenticated_witness(&observed)
    }

    pub(super) async fn start(
        handoff: crate::archive_v3_shadow_runtime::WalServingHandoff,
    ) -> Result<WalOwnerHandle> {
        let (publisher, staged, binding, store_fence) = match handoff {
            crate::archive_v3_shadow_runtime::WalServingHandoff::Maintenance(handoff) => {
                let CompletedMaintenanceWalHandoffView {
                    runtime,
                    terminal_witness,
                    archive_binding,
                    parity,
                    control,
                    store_fence,
                } = handoff.into_wal_owner(WalOwnerStoreContext(()));
                Self::from_launch_parts(
                    runtime,
                    terminal_witness,
                    archive_binding,
                    control,
                    None,
                    Some(parity),
                    store_fence,
                )
                .await
                .map_err(|error| report_publisher_launch_refusal("compose_maintenance", error))?
            }
            crate::archive_v3_shadow_runtime::WalServingHandoff::Genesis(handoff) => {
                let crate::archive_v3_shadow_runtime::GenesisWalHandoffView {
                    runtime,
                    terminal_witness,
                    archive_binding,
                    reserved,
                    control,
                } = handoff.into_wal_owner(WalOwnerStoreContext(()));
                // A genesis archive has no maintenance history: no parity
                // evidence exists, and `None` for the Store fence is exact —
                // there is no legacy snapshot to pin, precisely like the
                // fenceless maintenance restart reconstruction.
                Self::from_launch_parts(
                    runtime,
                    terminal_witness,
                    archive_binding,
                    control,
                    Some(reserved),
                    None,
                    None,
                )
                .await
                .map_err(|error| report_publisher_launch_refusal("compose_genesis", error))?
            }
        };
        let store = super::WalStoreLane::spawn_authenticated(
            staged,
            binding,
            Arc::clone(&publisher.capture),
            super::LaneLiveness::new(),
        )
        .await
        .map_err(|error| report_publisher_launch_refusal("open_store_lane", error))?;
        let control: Arc<dyn WalOwnerControl> = publisher.control.clone();
        Ok(super::SingleArchiveWalOwner::spawn_lane_with_fence(
            store,
            control,
            Arc::new(publisher),
            store_fence,
        ))
    }

    /// One-shot launch composition from either serving lane's exact parts.
    ///
    /// The maintenance lane carries the parity evidence (and, in-run only,
    /// the Store admission fence): it re-loads and reauthenticates the exact
    /// terminal Control row before any provider work, then reserves the
    /// owner off the maintenance-import ledger. The genesis lane carries
    /// `None` for both and instead re-adopts the durable owner reservation
    /// off the genesis control ledger — that reservation path revalidates
    /// the ledger row's exact terminal bytes inside one transaction — and
    /// the adopted reservation must equal the handoff's carried reservation
    /// exactly. Everything downstream (send marker, provider-CAS acquire
    /// with lost-response adoption, bind, cipher resolution, staging
    /// recovery) is one shared ladder.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated launch tuple; grouping would obscure exact binding"
    )]
    async fn from_launch_parts(
        runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
        terminal_witness: WitnessRecord,
        archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
        control: Arc<crate::cp::control_store::ControlStore>,
        genesis_reservation: Option<ReservedWalOwnerLease>,
        parity: Option<CompletedMaintenanceParityEvidence>,
        store_fence: Option<crate::store::StoreWalAuthorityFence>,
    ) -> Result<(
        Self,
        crate::archive_v3_shadow_parity::AuthenticatedWalOwnerStaging,
        WalOwnerStoreBinding,
        Option<crate::store::StoreWalAuthorityFence>,
    )> {
        // Exactly one launch authority: the maintenance parity evidence or a
        // genesis owner reservation. Both — or neither — is a composition
        // defect, refused before any durable or provider work.
        if genesis_reservation.is_some() == parity.is_some() {
            return Err(report_publisher_launch_refusal(
                "select_launch_authority",
                WalOwnerError::Conflict,
            ));
        }
        if let Some(parity) = parity.as_ref() {
            let terminal_control = MaintenanceImportPersistence::load_exact(
                control.as_ref(),
                parity.operation_id_for_wal_owner(WalOwnerStoreContext(())),
            )
            .await
            .map_err(|_| {
                report_publisher_launch_refusal(
                    "load_maintenance_terminal",
                    WalOwnerError::Conflict,
                )
            })?;
            parity
                .reauthenticate_for_wal_owner(
                    WalOwnerStoreContext(()),
                    &terminal_control,
                    &terminal_witness,
                )
                .map_err(|_| {
                    report_publisher_launch_refusal(
                        "authenticate_maintenance_terminal",
                        WalOwnerError::Conflict,
                    )
                })?;
        }
        let runtime = runtime
            .into_wal_publisher(super::WalPublisherRuntimeContext(()))
            .map_err(|_| {
                report_publisher_launch_refusal(
                    "open_publisher_runtime",
                    WalOwnerError::Publication,
                )
            })?;
        let objects = runtime.objects_owned(&super::WalPublisherRuntimeContext(()));
        let witness = &runtime;
        let reserved = match genesis_reservation {
            None => control
                .reserve_owner(&terminal_witness)
                .await
                .map_err(|error| {
                    report_publisher_launch_refusal("reserve_maintenance_owner", error)
                })?,
            Some(carried) => {
                // Genesis lane: re-adopt the durable reservation off the
                // genesis control ledger. The reservation path revalidates
                // the ledger row's exact terminal bytes and the existing
                // lease's exact-terminal adoption arm; the adopted
                // reservation must be the carried one, field for field, so a
                // handoff can never launch over a reservation it does not
                // durably own.
                let adopted = control
                    .reserve_owner_from_genesis(&terminal_witness)
                    .await
                    .map_err(|error| {
                        report_publisher_launch_refusal("reserve_genesis_owner", error)
                    })?;
                if adopted.owner_id.as_bytes() != carried.owner_id.as_bytes()
                    || adopted.expected != carried.expected
                    || adopted.revision != carried.revision
                    || adopted.stage != carried.stage
                    || adopted.commitment != carried.commitment
                {
                    return Err(report_publisher_launch_refusal(
                        "authenticate_genesis_reservation",
                        WalOwnerError::Conflict,
                    ));
                }
                adopted
            }
        };
        let (observed, _live) = if reserved.stage == OwnerLeaseStage::Bound {
            let durable_binding = control
                .load_owner_binding(&terminal_witness)
                .await
                .map_err(|error| report_publisher_launch_refusal("load_owner_binding", error))?;
            let previous =
                WitnessRecord::decode(durable_binding.witness_bytes()).map_err(|_| {
                    report_publisher_launch_refusal("decode_owner_binding", WalOwnerError::Corrupt)
                })?;
            let retained = control
                .load_bound_owner(&previous)
                .await
                .map_err(|error| report_publisher_launch_refusal("load_bound_owner", error))?;
            if control
                .has_pending_owner_work(&durable_binding)
                .await
                .map_err(|error| report_publisher_launch_refusal("read_pending_work", error))?
            {
                (previous, retained)
            } else {
                let current = witness
                    .read_current_exact(terminal_witness.archive_id())
                    .await
                    .map_err(|_| {
                        report_publisher_launch_refusal(
                            "read_current_witness",
                            WalOwnerError::Publication,
                        )
                    })?;
                if let Ok(lease) =
                    current.exact_wal_owner_heartbeat_from(&previous, retained.owner_id.as_bytes())
                {
                    let live = control
                        .persist_owner_renewal(&previous, &current, lease)
                        .await
                        .map_err(|error| {
                            report_publisher_launch_refusal("persist_owner_renewal", error)
                        })?;
                    (current, live)
                } else if let Ok(lease) =
                    current.exact_wal_owner_reacquire_from(&previous, retained.owner_id.as_bytes())
                {
                    let live = control
                        .rebind_owner_after_expiry(&previous, &current, lease)
                        .await
                        .map_err(|error| {
                            report_publisher_launch_refusal("persist_owner_reacquire", error)
                        })?;
                    (current, live)
                } else {
                    if current != previous {
                        return Err(report_publisher_launch_refusal(
                            "authenticate_owner_predecessor",
                            WalOwnerError::Conflict,
                        ));
                    }
                    let reacquired = witness
                        .reacquire_owner_lease(&previous, retained.owner_id, OWNER_LEASE_TICKS)
                        .await;
                    let (observed, lease) = match reacquired {
                        Ok(value) => value,
                        Err(PublisherCommitError::OutcomeUnknown) => {
                            let observed = witness
                                .read_current_exact(previous.archive_id())
                                .await
                                .map_err(|_| {
                                    report_publisher_launch_refusal(
                                        "adopt_reacquire_readback",
                                        WalOwnerError::Publication,
                                    )
                                })?;
                            let lease = observed
                                .exact_wal_owner_reacquire_from(
                                    &previous,
                                    retained.owner_id.as_bytes(),
                                )
                                .map_err(|_| {
                                    report_publisher_launch_refusal(
                                        "adopt_reacquire_successor",
                                        WalOwnerError::Publication,
                                    )
                                })?;
                            (observed, lease)
                        }
                        Err(error) => {
                            return Err(report_publisher_launch_refusal(
                                "provider_owner_reacquire",
                                map_commit_error(error),
                            ))
                        }
                    };
                    let live = control
                        .rebind_owner_after_expiry(&previous, &observed, lease)
                        .await
                        .map_err(|error| {
                            report_publisher_launch_refusal("bind_reacquired_owner", error)
                        })?;
                    (observed, live)
                }
            }
        } else {
            let reserved = control
                .mark_owner_send_started(&reserved)
                .await
                .map_err(|error| {
                    report_publisher_launch_refusal("mark_owner_send_started", error)
                })?;
            let current = witness
                .read_current_exact(terminal_witness.archive_id())
                .await
                .map_err(|_| {
                    report_publisher_launch_refusal(
                        "read_owner_acquire_witness",
                        WalOwnerError::Publication,
                    )
                })?;
            let (observed, lease) = if let Ok(lease) = current
                .exact_wal_owner_acquire_from(&terminal_witness, reserved.owner_id().as_bytes())
            {
                // A prior process may have lost the provider response after
                // the durable send marker. Adopt only that exact owner and
                // exact ordinary acquire successor before issuing any retry.
                (current, lease)
            } else {
                if current != terminal_witness {
                    return Err(report_publisher_launch_refusal(
                        "authenticate_owner_acquire_predecessor",
                        WalOwnerError::Conflict,
                    ));
                }
                match witness
                    .acquire_owner_lease(&terminal_witness, reserved.owner_id(), OWNER_LEASE_TICKS)
                    .await
                {
                    Ok(value) => value,
                    Err(PublisherCommitError::OutcomeUnknown) => {
                        let observed = witness
                            .read_current_exact(terminal_witness.archive_id())
                            .await
                            .map_err(|_| WalOwnerError::Publication)?;
                        let lease = observed
                            .exact_wal_owner_acquire_from(
                                &terminal_witness,
                                reserved.owner_id().as_bytes(),
                            )
                            .map_err(|_| WalOwnerError::Publication)?;
                        (observed, lease)
                    }
                    Err(error) => {
                        return Err(report_publisher_launch_refusal(
                            "provider_owner_acquire",
                            map_commit_error(error),
                        ))
                    }
                }
            };
            let live = control
                .bind_owner(&reserved, &observed, lease)
                .await
                .map_err(|error| report_publisher_launch_refusal("bind_new_owner", error))?;
            (observed, live)
        };
        let binding =
            WalOwnerStoreBinding::from_authenticated_witness(&observed).map_err(|error| {
                report_publisher_launch_refusal("authenticate_owner_binding", error)
            })?;
        let cipher = Arc::new(
            runtime
                .resolve_wal_owner_cipher(&super::WalPublisherRuntimeContext(()), &observed)
                .await
                .map_err(|_| {
                    report_publisher_launch_refusal(
                        "resolve_archive_cipher",
                        WalOwnerError::Conflict,
                    )
                })?,
        );
        let recovery = RecoveryRoot::from_exact_wal_owner_record(&observed).map_err(|_| {
            report_publisher_launch_refusal("authenticate_recovery_root", WalOwnerError::Conflict)
        })?;
        let staged = crate::archive_v3_shadow_wal::recover_owned_wal_owner_staging(
            recovery,
            Arc::clone(&objects),
            cipher,
            observed.archive_id(),
            &binding,
        )
        .await
        .map_err(|_| {
            report_publisher_launch_refusal("recover_witnessed_staging", WalOwnerError::Publication)
        })?;
        #[cfg(not(test))]
        let capture = crate::store::StoreShadowCapture::shared_for_wal_owner().map_err(|_| {
            report_publisher_launch_refusal("install_wal_capture", WalOwnerError::Capture)
        })?;
        #[cfg(test)]
        let capture = crate::store::StoreShadowCapture::shared_for_test();
        let publisher = Self {
            runtime,
            objects,
            control,
            capture,
            _archive_binding: archive_binding,
            _maintenance_parity: parity,
        };
        Ok((publisher, staged, binding, store_fence))
    }

    async fn exact_cipher(&self, witness: &WitnessRecord) -> Result<Arc<VerifiedArchiveCipher>> {
        self.runtime
            .resolve_wal_owner_cipher(&super::WalPublisherRuntimeContext(()), witness)
            .await
            .map(Arc::new)
            .map_err(|_| WalOwnerError::Conflict)
    }
}

/// Emit only static launch structure. The stage and class are closed enums;
/// no identity, archive coordinate, provider response, or error text crosses
/// this boundary.
fn report_publisher_launch_refusal(stage: &'static str, error: WalOwnerError) -> WalOwnerError {
    let class = match error {
        WalOwnerError::Malformed => "malformed",
        WalOwnerError::Conflict => "conflict",
        WalOwnerError::Corrupt => "corrupt",
        WalOwnerError::Capture => "capture",
        WalOwnerError::Persistence => "persistence",
        WalOwnerError::Publication => "publication",
        WalOwnerError::Poisoned => "poisoned",
        WalOwnerError::Superseded => "superseded",
    };
    warn!(
        metric = "archive_v3_wal_publisher_launch_refusal",
        stage, class, "WAL publisher launch refused"
    );
    error
}

fn map_commit_error(error: PublisherCommitError) -> WalOwnerError {
    match error {
        PublisherCommitError::Rejected => WalOwnerError::Conflict,
        PublisherCommitError::DefinitelyFailed | PublisherCommitError::OutcomeUnknown => {
            WalOwnerError::Publication
        }
    }
}

/// Candidate-sensitive source maintenance is exact-read-only. It deliberately
/// has no witness/provider handle, so neither an expired SendStarted lease nor
/// a lost-success candidate successor can be renewed or reacquired while the
/// blocking Store lane is still producing the checkpoint source.
pub(super) fn authenticate_checkpoint_source_sensitive_observation(
    binding: &WalOwnerStoreBinding,
    attempt: &CheckpointAttempt,
    observed: &WitnessRecord,
) -> Result<()> {
    if !matches!(
        attempt.stage,
        CheckpointStage::CandidateReady | CheckpointStage::SendStarted
    ) {
        return Err(WalOwnerError::Conflict);
    }
    let expected =
        WitnessRecord::decode(binding.witness_bytes()).map_err(|_| WalOwnerError::Corrupt)?;
    let candidate = attempt.candidate.ok_or(WalOwnerError::Corrupt)?;
    let advance = AuthenticatedWalRootAdvance::from_expected_witness(
        super::WalWitnessAdvanceContext::for_publisher(),
        &expected,
        candidate,
    )
    .map_err(|_| WalOwnerError::Conflict)?;
    if observed == &expected || advance.validate_observed(observed).is_ok() {
        Ok(())
    } else {
        Err(WalOwnerError::Conflict)
    }
}

impl super::sealed::PublicationAuthority for SingleArchiveWalPublisher {}

#[async_trait]
impl WalPublicationAuthority for SingleArchiveWalPublisher {
    async fn read_fresh_head(&self, binding: &WalOwnerStoreBinding) -> Result<FreshHead> {
        let observed = self
            .runtime
            .read_current_exact(binding.archive_id())
            .await
            .map_err(|_| WalOwnerError::Publication)?;
        AuthenticatedWalOwnerHead::from_authority(binding, observed)
    }

    async fn checkpoint_pending(&self, binding: &WalOwnerStoreBinding) -> Result<bool> {
        self.control.has_pending_checkpoint(binding).await
    }

    async fn refresh_live_binding(
        &self,
        binding: &WalOwnerStoreBinding,
    ) -> Result<WalOwnerStoreBinding> {
        self.maintain_live_owner_binding(binding).await
    }

    async fn refresh_checkpoint_source_binding(
        &self,
        binding: &WalOwnerStoreBinding,
        owner_instance_id: WalOwnerInstanceId,
    ) -> Result<WalOwnerStoreBinding> {
        // Inspect and authenticate Control before any provider lease
        // mutation. Once a candidate exists, the provider may already be its
        // exact successor after a lost response; renewal/reacquire here would
        // either hide that success or irreversibly advance a SendStarted
        // fence. Source extraction may finish, but only the candidate-aware
        // checkpoint reconciler may decide the next transition.
        let attempt = self
            .control
            .prepare_checkpoint(binding, owner_instance_id)
            .await?;
        match attempt.stage {
            CheckpointStage::CandidateReady | CheckpointStage::SendStarted => {
                let observed = self
                    .runtime
                    .read_current_exact(binding.archive_id())
                    .await
                    .map_err(|_| WalOwnerError::Publication)?;
                authenticate_checkpoint_source_sensitive_observation(binding, &attempt, &observed)?;
                Ok(binding.clone())
            }
            CheckpointStage::Prepared
            | CheckpointStage::SourceReady
            | CheckpointStage::Uploading => self.maintain_live_owner_binding(binding).await,
            CheckpointStage::Witnessed | CheckpointStage::ManualRequired => {
                Err(WalOwnerError::Conflict)
            }
        }
    }

    async fn checkpoint_required(&self, binding: &WalOwnerStoreBinding) -> Result<bool> {
        let expected =
            WitnessRecord::decode(binding.witness_bytes()).map_err(|_| WalOwnerError::Corrupt)?;
        let observed = self
            .runtime
            .read_current_exact(binding.archive_id())
            .await
            .map_err(|_| WalOwnerError::Publication)?;
        if observed != expected {
            return Err(WalOwnerError::Conflict);
        }
        self.control.load_bound_owner(&observed).await?;
        let cipher = self.exact_cipher(&observed).await?;
        let recovery = RecoveryRoot::from_exact_wal_owner_record(&observed)
            .map_err(|_| WalOwnerError::Conflict)?;
        crate::archive_v3_shadow_wal::wal_owner_checkpoint_required(
            &recovery,
            self.objects.as_ref(),
            cipher.as_ref(),
            observed.archive_id(),
        )
        .await
        .map_err(|_| WalOwnerError::Publication)
    }

    async fn checkpoint_and_recover(
        &self,
        binding: &WalOwnerStoreBinding,
        owner_instance_id: WalOwnerInstanceId,
        source: crate::store::WalOwnerCheckpointSource,
    ) -> Result<super::WalCheckpointSettlement> {
        let mut source = crate::store::WalOwnerCheckpointReader::spawn(source)?;
        let mut current_binding = binding.clone();
        let witness = &self.runtime;

        let (next_binding, exact) = loop {
            let expected = WitnessRecord::decode(current_binding.witness_bytes())
                .map_err(|_| WalOwnerError::Corrupt)?;
            let live = self.control.load_bound_owner(&expected).await?;
            let (length, hash, schema) = source
                .authenticated_facts(super::WalCheckpointSourceContext(()), &current_binding)?;
            let source_plan = AuthenticatedCheckpointSourcePlan::from_store(
                &current_binding,
                length,
                hash,
                schema,
            )?;
            let mut attempt = self
                .control
                .prepare_checkpoint(&current_binding, owner_instance_id)
                .await?;
            attempt = self
                .control
                .record_checkpoint_source(&current_binding, &attempt, &source_plan)
                .await?;

            let mut candidate = attempt.candidate;
            if matches!(
                attempt.stage,
                CheckpointStage::SourceReady | CheckpointStage::Uploading
            ) {
                let observed = witness
                    .read_current_exact(expected.archive_id())
                    .await
                    .map_err(|_| WalOwnerError::Publication)?;
                if observed != expected {
                    return Err(WalOwnerError::Conflict);
                }
                attempt = self
                    .control
                    .begin_checkpoint_upload(&current_binding, &attempt)
                    .await?;
                let checkpoint_binding = ShadowSessionBinding::from_wal_owner_checkpoint(
                    super::WalCheckpointSourceContext(()),
                    &expected,
                    live.lease,
                    *attempt.operation_id.as_bytes(),
                    attempt.session_id,
                    attempt.attempt_id,
                    attempt.attempt,
                )
                .map_err(|_| WalOwnerError::Conflict)?;
                let session_id = attempt.session_id;
                let attempt_id = attempt.attempt_id;
                let inventory = CheckpointInventory {
                    publisher: self,
                    state: tokio::sync::Mutex::new(Some(CheckpointUploadState {
                        binding: current_binding.clone(),
                        attempt,
                        materialized_since_heartbeat: 0,
                        superseded: false,
                        failure: None,
                    })),
                    session_binding: checkpoint_binding,
                };
                let staging = ShadowObjectStaging::new(
                    &inventory,
                    session_id,
                    attempt_id,
                    checkpoint_binding,
                );
                let uploaded = {
                    let uploaded = async {
                        reconcile_reserved_shadow_objects(self.objects.as_ref(), &staging)
                            .await
                            .map_err(|_| WalOwnerError::Conflict)?;
                        let cipher = self.exact_cipher(&expected).await?;
                        let checkpoint = upload_owned_checkpoint(
                            self.objects.as_ref(),
                            cipher.as_ref(),
                            expected.archive_id(),
                            expected.database_epoch(),
                            &source,
                            staging.clone(),
                        )
                        .await
                        .map_err(|_| WalOwnerError::Publication)?;
                        let candidate =
                            crate::archive_v3_shadow_wal::create_wal_owner_checkpoint_root(
                                self.objects.as_ref(),
                                cipher.as_ref(),
                                &expected,
                                live.lease,
                                &checkpoint,
                                &staging,
                            )
                            .await
                            .map_err(|_| WalOwnerError::Publication)?;
                        Ok::<_, WalOwnerError>((checkpoint, candidate))
                    };
                    tokio::pin!(uploaded);
                    let mut heartbeat =
                        tokio::time::interval(super::CHECKPOINT_LEASE_HEARTBEAT_INTERVAL);
                    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    heartbeat.tick().await;
                    loop {
                        tokio::select! {
                            result = &mut uploaded => break result,
                            _ = heartbeat.tick() => inventory.maintain_binding().await,
                        }
                    }
                };
                drop(staging);
                let state = inventory.into_state().await?;
                if let Some(error) = state.failure {
                    return Err(error);
                }
                if state.superseded {
                    source.rebind(state.binding.clone()).await?;
                    current_binding = state.binding;
                    continue;
                }
                let (checkpoint, uploaded_candidate) = uploaded?;
                current_binding = state.binding;
                attempt = self
                    .control
                    .record_checkpoint_candidate(
                        &current_binding,
                        &state.attempt,
                        &checkpoint,
                        &uploaded_candidate,
                    )
                    .await?;
                candidate = Some(uploaded_candidate);
            } else if !matches!(
                attempt.stage,
                CheckpointStage::CandidateReady | CheckpointStage::SendStarted
            ) {
                return Err(WalOwnerError::Conflict);
            }

            let candidate = candidate.ok_or(WalOwnerError::Corrupt)?;
            let expected = WitnessRecord::decode(current_binding.witness_bytes())
                .map_err(|_| WalOwnerError::Corrupt)?;
            let advance = AuthenticatedWalRootAdvance::from_expected_witness(
                super::WalWitnessAdvanceContext::for_publisher(),
                &expected,
                candidate,
            )
            .map_err(|_| WalOwnerError::Conflict)?;
            let mut observed = witness
                .read_current_exact(expected.archive_id())
                .await
                .map_err(|_| WalOwnerError::Publication)?;
            if advance.validate_observed(&observed).is_err() {
                if observed != expected {
                    let _ = self
                        .control
                        .checkpoint_manual(&current_binding, &attempt)
                        .await;
                    return Err(WalOwnerError::Conflict);
                }
                if attempt.stage == CheckpointStage::CandidateReady {
                    let refreshed = self.maintain_live_owner_binding(&current_binding).await?;
                    if refreshed != current_binding {
                        source.rebind(refreshed.clone()).await?;
                        current_binding = refreshed;
                        continue;
                    }
                    attempt = self
                        .control
                        .mark_checkpoint_send_started(&current_binding, &attempt)
                        .await?;
                }
                if attempt.stage != CheckpointStage::SendStarted {
                    return Err(WalOwnerError::Conflict);
                }
                match witness
                    .advance_root_unresolved(
                        &expected,
                        advance.provider_advance(super::WalWitnessAdvanceContext::for_publisher()),
                    )
                    .await
                {
                    Ok(()) | Err(PublisherCommitError::OutcomeUnknown) => {}
                    Err(PublisherCommitError::Rejected) => {
                        self.control
                            .checkpoint_manual(&current_binding, &attempt)
                            .await?;
                        return Err(WalOwnerError::Conflict);
                    }
                    Err(PublisherCommitError::DefinitelyFailed) => {
                        return Err(WalOwnerError::Publication);
                    }
                }
                observed = witness
                    .read_current_exact(expected.archive_id())
                    .await
                    .map_err(|_| WalOwnerError::Publication)?;
                if advance.validate_observed(&observed).is_err() {
                    if observed != expected {
                        let _ = self
                            .control
                            .checkpoint_manual(&current_binding, &attempt)
                            .await;
                        return Err(WalOwnerError::Conflict);
                    }
                    return Err(WalOwnerError::Publication);
                }
            }
            if advance.validate_observed(&observed).is_ok()
                && attempt.stage == CheckpointStage::CandidateReady
            {
                // A lost local acknowledgement after an exact provider
                // successor must not cause a second provider send. Persist
                // the missing marker, then settle that already-authenticated
                // successor through the ordinary terminal CAS.
                attempt = self
                    .control
                    .mark_checkpoint_send_started(&current_binding, &attempt)
                    .await?;
            }
            let next_binding = self
                .control
                .settle_checkpoint(&current_binding, &attempt, &observed)
                .await?;
            break (next_binding, observed);
        };
        source.close().await?;
        let fresh = witness
            .read_current_exact(next_binding.archive_id())
            .await
            .map_err(|_| WalOwnerError::Publication)?;
        if fresh != exact || fresh.encode() != *next_binding.witness_bytes() {
            return Err(WalOwnerError::Conflict);
        }
        let cipher = self.exact_cipher(&fresh).await?;
        let recovery = RecoveryRoot::from_exact_wal_owner_record(&fresh)
            .map_err(|_| WalOwnerError::Conflict)?;
        let staged = crate::archive_v3_shadow_wal::recover_owned_wal_owner_staging(
            recovery,
            Arc::clone(&self.objects),
            cipher,
            fresh.archive_id(),
            &next_binding,
        )
        .await
        .map_err(|_| WalOwnerError::Publication)?;
        Ok(super::WalCheckpointSettlement {
            staged,
            binding: next_binding,
            capture: Arc::clone(&self.capture),
        })
    }

    async fn create_candidate(
        &self,
        context: &super::WalOwnerContext,
        captured: &crate::archive_v3_shadow::CapturedWalCommit,
        control: &dyn WalOwnerControl,
    ) -> Result<WalPublicationCandidate> {
        let expected = WitnessRecord::decode(context.binding().witness_bytes())
            .map_err(|_| WalOwnerError::Corrupt)?;
        let live = self.control.load_bound_owner(&expected).await?;
        let cipher = self.exact_cipher(&expected).await?;
        let recovery = RecoveryRoot::from_exact_wal_owner_record(&expected)
            .map_err(|_| WalOwnerError::Conflict)?;
        let staging = ControlledWalStaging {
            context,
            control,
            next_ordinal: AtomicU32::new(0),
        };
        let root = crate::archive_v3_shadow_wal::upload_captured_wal_commit_controlled(
            &recovery,
            self.objects.as_ref(),
            cipher.as_ref(),
            expected.archive_id(),
            live.lease.fencing_epoch(),
            *context.identity().operation_id().as_bytes(),
            *context.identity().request_fingerprint().as_bytes(),
            captured,
            &staging,
        )
        .await
        .map_err(|_| WalOwnerError::Publication)?;
        let artifacts = control
            .authenticate_artifact_set(
                context,
                captured.publication_commitment(),
                captured.first_frame_no(),
                captured.frame_count(),
            )
            .await?;
        WalPublicationCandidate::from_authority(context, captured, root, artifacts)
    }

    async fn send_candidate(
        &self,
        _context: &super::WalOwnerContext,
        candidate: &WalPublicationCandidate,
    ) -> Result<WitnessedWalCandidate> {
        let witness = &self.runtime;
        let expected = WitnessRecord::decode(candidate.expected_witness_bytes())
            .map_err(|_| WalOwnerError::Corrupt)?;
        match witness
            .advance_root_unresolved(&expected, candidate.root_advance_for_authority())
            .await
        {
            Ok(()) | Err(PublisherCommitError::OutcomeUnknown) => {
                let observed = witness
                    .read_current_exact(expected.archive_id())
                    .await
                    .map_err(|_| WalOwnerError::Publication)?;
                WitnessedWalCandidate::from_authority(candidate.clone(), observed)
            }
            Err(error) => Err(map_commit_error(error)),
        }
    }

    async fn resume_candidate(
        &self,
        binding: &WalOwnerStoreBinding,
        _identity: WalOperationIdentity,
        attempt: &WalOwnerAttempt,
        candidate: &WalPublicationCandidate,
    ) -> Result<WitnessedWalCandidate> {
        if attempt.candidate() != Some(candidate) {
            return Err(WalOwnerError::Conflict);
        }
        let observed = self
            .runtime
            .read_current_exact(binding.archive_id())
            .await
            .map_err(|_| WalOwnerError::Publication)?;
        if let Ok(witnessed) =
            WitnessedWalCandidate::from_authority(candidate.clone(), observed.clone())
        {
            return Ok(witnessed);
        }
        if observed.encode() != *candidate.expected_witness_bytes() {
            return Err(WalOwnerError::Conflict);
        }
        self.send_candidate_from_expected(candidate, observed).await
    }
}

struct ControlledWalStaging<'a> {
    context: &'a super::WalOwnerContext,
    control: &'a dyn WalOwnerControl,
    next_ordinal: AtomicU32,
}

#[async_trait]
impl crate::archive_v3_shadow_wal::WalObjectStaging for ControlledWalStaging<'_> {
    async fn create_and_readback(
        &self,
        backend: &dyn ExactImmutableObjectBackend,
        object_context: &crate::archive_v3::ObjectContext,
        envelope: crate::archive_v3::CiphertextEnvelope,
    ) -> crate::archive_v3_shadow_wal::Result<crate::archive_v3::CiphertextEnvelope> {
        let ordinal = self.next_ordinal.fetch_add(1, Ordering::Relaxed);
        let artifact = WalPublicationArtifact::from_authority(
            self.context,
            ordinal,
            object_context,
            envelope.hash(),
        )
        .map_err(|_| crate::archive_v3::ArchiveV3Error::InvalidContext)?;
        self.control
            .reserve_artifact(self.context, &artifact)
            .await
            .map_err(|_| crate::archive_v3::ArchiveV3Error::Authentication)?;
        backend
            .create_if_absent(object_context.object_key(), envelope.clone())
            .await?;
        let readback = backend
            .get(&object_context.object_key())
            .await?
            .ok_or(crate::archive_v3_shadow_wal::ShadowWalError::MissingObject)?;
        if readback != envelope {
            return Err(crate::archive_v3::ArchiveV3Error::Authentication.into());
        }
        self.control
            .mark_artifact_materialized(self.context, &artifact)
            .await
            .map_err(|_| crate::archive_v3::ArchiveV3Error::Authentication)?;
        Ok(readback)
    }
}

impl SingleArchiveWalPublisher {
    async fn send_candidate_from_expected(
        &self,
        candidate: &WalPublicationCandidate,
        expected: WitnessRecord,
    ) -> Result<WitnessedWalCandidate> {
        let witness = &self.runtime;
        match witness
            .advance_root_unresolved(&expected, candidate.root_advance_for_authority())
            .await
        {
            Ok(()) | Err(PublisherCommitError::OutcomeUnknown) => {
                let observed = witness
                    .read_current_exact(expected.archive_id())
                    .await
                    .map_err(|_| WalOwnerError::Publication)?;
                WitnessedWalCandidate::from_authority(candidate.clone(), observed)
            }
            Err(error) => Err(map_commit_error(error)),
        }
    }
}

/// Adapter used by the checkpoint uploader. It is scoped to one exact durable
/// attempt and therefore cannot write into the logical-publication ledger.
struct CheckpointUploadState {
    binding: WalOwnerStoreBinding,
    attempt: CheckpointAttempt,
    materialized_since_heartbeat: u32,
    superseded: bool,
    failure: Option<WalOwnerError>,
}

struct CheckpointInventory<'a> {
    publisher: &'a SingleArchiveWalPublisher,
    state: tokio::sync::Mutex<Option<CheckpointUploadState>>,
    session_binding: ShadowSessionBinding,
}

impl CheckpointInventory<'_> {
    async fn into_state(self) -> Result<CheckpointUploadState> {
        self.state.into_inner().ok_or(WalOwnerError::Corrupt)
    }

    async fn maintain_binding(&self) {
        let mut state = self.state.lock().await;
        let Some(state) = state.as_mut() else {
            return;
        };
        if state.superseded || state.failure.is_some() {
            return;
        }
        let previous = state.binding.clone();
        let next = match self.publisher.maintain_live_owner_binding(&previous).await {
            Ok(next) => next,
            Err(error) => {
                state.failure = Some(error);
                state.superseded = true;
                return;
            }
        };
        state.materialized_since_heartbeat = 0;
        if next == previous {
            return;
        }
        let old = match WitnessRecord::decode(previous.witness_bytes()) {
            Ok(old) => old,
            Err(_) => {
                state.failure = Some(WalOwnerError::Corrupt);
                state.superseded = true;
                return;
            }
        };
        let new = match WitnessRecord::decode(next.witness_bytes()) {
            Ok(new) => new,
            Err(_) => {
                state.failure = Some(WalOwnerError::Corrupt);
                state.superseded = true;
                return;
            }
        };
        let live = match self.publisher.control.load_bound_owner(&new).await {
            Ok(live) => live,
            Err(error) => {
                state.failure = Some(error);
                state.superseded = true;
                return;
            }
        };
        let same_fence = new
            .exact_wal_owner_heartbeat_from(&old, live.owner_id.as_bytes())
            .is_ok();
        let refreshed = match self
            .publisher
            .control
            .prepare_checkpoint(&next, state.attempt.owner_instance_id)
            .await
        {
            Ok(refreshed) => refreshed,
            Err(error) => {
                state.failure = Some(error);
                state.superseded = true;
                return;
            }
        };
        state.binding = next;
        state.attempt = refreshed;
        if !same_fence {
            state.superseded = true;
        }
    }
}

#[async_trait]
impl ShadowObjectInventory for CheckpointInventory<'_> {
    async fn reserve_exact(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        facts: ShadowObjectFacts,
    ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
        let state = self.state.lock().await;
        let state = state.as_ref().ok_or(ShadowObjectInventoryError::Conflict)?;
        if state.superseded
            || session_id != state.attempt.session_id
            || attempt_id != state.attempt.attempt_id
            || binding != self.session_binding
        {
            return Err(ShadowObjectInventoryError::Conflict);
        }
        self.publisher
            .control
            .reserve_checkpoint_artifact(&state.binding, &state.attempt, &facts)
            .await
            .map_err(|_| ShadowObjectInventoryError::Conflict)
    }

    async fn mark_materialized_exact(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        facts: ShadowObjectFacts,
    ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
        let mut guard = self.state.lock().await;
        let state = guard.as_mut().ok_or(ShadowObjectInventoryError::Conflict)?;
        if state.superseded
            || session_id != state.attempt.session_id
            || attempt_id != state.attempt.attempt_id
            || binding != self.session_binding
        {
            return Err(ShadowObjectInventoryError::Conflict);
        }
        let outcome = self
            .publisher
            .control
            .materialize_checkpoint_artifact(&state.binding, &state.attempt, &facts)
            .await
            .map_err(|_| ShadowObjectInventoryError::Conflict)?;
        state.materialized_since_heartbeat = state.materialized_since_heartbeat.saturating_add(1);
        let maintain = state.materialized_since_heartbeat >= CHECKPOINT_OBJECTS_PER_HEARTBEAT;
        drop(guard);
        if maintain {
            self.maintain_binding().await;
            let state = self.state.lock().await;
            let state = state.as_ref().ok_or(ShadowObjectInventoryError::Conflict)?;
            if state.superseded || state.failure.is_some() {
                return Err(ShadowObjectInventoryError::Conflict);
            }
        }
        Ok(outcome)
    }

    async fn load_exact_attempt_page(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        after_ordinal: Option<u32>,
    ) -> std::result::Result<ShadowObjectInventoryPage, ShadowObjectInventoryError> {
        let state = self.state.lock().await;
        let state = state.as_ref().ok_or(ShadowObjectInventoryError::Conflict)?;
        if state.superseded
            || session_id != state.attempt.session_id
            || attempt_id != state.attempt.attempt_id
            || binding != self.session_binding
        {
            return Err(ShadowObjectInventoryError::Conflict);
        }
        self.publisher
            .control
            .load_checkpoint_page(&state.binding, &state.attempt, after_ordinal)
            .await
            .map_err(|_| ShadowObjectInventoryError::Conflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_versions_caps_and_debug_are_fixed() {
        assert_eq!(OWNER_LEASE_FORMAT_V1, 1);
        assert_eq!(CHECKPOINT_FORMAT_V1, 1);
        assert_eq!(MAX_CHECKPOINT_ATTEMPTS, 16);
        assert_eq!(MAX_CHECKPOINT_ARTIFACTS, 32_898);
        assert_eq!(
            format!(
                "{:?}",
                CheckpointOperationId::from_control([1; 16]).unwrap()
            ),
            "CheckpointOperationId(<opaque>)"
        );
        assert!(CheckpointOperationId::from_control([0; 16]).is_err());
    }

    #[test]
    fn checkpoint_stage_order_is_strict_and_manual_is_terminal() {
        let stages = [
            CheckpointStage::Prepared,
            CheckpointStage::SourceReady,
            CheckpointStage::Uploading,
            CheckpointStage::CandidateReady,
            CheckpointStage::SendStarted,
            CheckpointStage::Witnessed,
        ];
        for pair in stages.windows(2) {
            assert_eq!(pair[1] as u8, pair[0] as u8 + 1);
        }
        assert!(CheckpointStage::ManualRequired as u8 > CheckpointStage::Witnessed as u8);
    }

    #[test]
    fn source_commitment_is_binding_and_geometry_sensitive() {
        let source = include_str!("publisher.rs");
        for required in [
            "CHECKPOINT_SOURCE_COMMITMENT_DOMAIN",
            "wal_owner_checkpoint_source_subject",
            "length.to_be_bytes()",
            "plaintext_hash",
            "sqlite_schema_version.to_be_bytes()",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
    }

    #[test]
    fn launch_parts_admit_exactly_one_lane_authority() {
        let source = include_str!("publisher.rs");
        // The two lanes are mutually exclusive by guard, the genesis lane
        // re-adopts its durable reservation off the genesis control ledger,
        // and the maintenance lane still reauthenticates its exact terminal
        // Control row before any provider work.
        assert!(source.contains("genesis_reservation.is_some() == parity.is_some()"));
        assert!(source.contains(concat!("reserve_owner_from_", "genesis(")));
        assert!(source.contains(concat!("reauthenticate_for_wal_", "owner(")));
        assert_eq!(
            source
                .matches(concat!("Self::from_launch_", "parts("))
                .count(),
            2,
            "exactly the two serving lanes may compose a launch"
        );
    }

    #[test]
    fn static_surface_has_no_runtime_wiring_or_destructive_provider_calls() {
        let source = include_str!("publisher.rs");
        for forbidden in [
            concat!("pub(crate) struct SingleArchive", "WalPublisher"),
            concat!("Store::", "new"),
            concat!("Arc<dyn ", "ImmutableObjectBackend>"),
            concat!("delete_", "exact"),
            concat!(".enume", "rate("),
            concat!("list_", "objects"),
            concat!("crate::", "main"),
            concat!("std::env", "::var"),
        ] {
            assert!(!source.contains(forbidden), "found forbidden {forbidden}");
        }
    }
}
