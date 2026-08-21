#![allow(
    dead_code,
    reason = "inactive ADR-0022 single-archive WAL owner is compiled before provider/runtime wiring"
)]

//! Inactive one-owner logical mutation, capture, and durable publication
//! protocol. The owner accepts only a sealed domain plan, runs its exact
//! domain row and mutation in one SQLite `BEGIN IMMEDIATE`, and retains the
//! resulting capture until encrypted control durably authenticates witness
//! settlement. Its private launcher consumes one non-cloneable serving
//! handoff — parity-certified maintenance or ledger-pinned genesis — owns one
//! heterogeneous sealed-plan actor, and composes the private
//! publisher plus mandatory checkpoint recovery. There is no external caller,
//! route, startup, Store-registry, configuration, acknowledgement, deletion,
//! list, or cloud construction path.

mod launcher;
mod publisher;

pub(crate) use publisher::{
    checkpoint_artifact_set_commitment, AuthenticatedCheckpointSourcePlan, CheckpointAttempt,
    CheckpointOperationId, CheckpointStage, LiveWalOwnerLease, OwnerLeaseStage,
    ReservedWalOwnerLease, WalPublisherControl, MAX_CHECKPOINT_ARTIFACTS,
};

use std::{
    any::Any,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::{
    archive_v3::{
        ArchiveId, ArchivePrefix, DatabaseEpoch, KeyEpoch, LogicalLocation, ObjectContext,
        ObjectId, ObjectRole,
    },
    archive_v3_gcs::canonical_object_identity,
    archive_v3_shadow::CapturedWalCommit,
    archive_v3_shadow_session::{ShadowAttemptId, ShadowSessionId},
    archive_v3_shadow_wal::MAX_WAL_SEGMENTS_PER_COMMIT,
    archive_v3_sqlite_vfs::{CaptureStreamId, OwnedCapturedDrain},
    archive_v3_wal_idempotency::{
        ErasedPreparedLogicalMutation, ErasedValidatedWalLogicalResult, PreparedLogicalMutation,
        WalLogicalDomainPlan, WalLogicalOperationId, WalOperationKind, WalRequestFingerprint,
    },
    archive_v3_witness::{
        AuthenticatedWalRootAdvance, DeletionState, MigrationState, RootCommitment, RootReference,
        WitnessRecord,
    },
};

const WAL_OWNER_FORMAT_V1: u16 = 1;
const WAL_OWNER_BINDING_DOMAIN: &[u8] = b"kioku/archive-v3/wal-owner-binding/v1\0";
const WAL_OWNER_CONTEXT_DOMAIN: &[u8] = b"kioku/archive-v3/wal-owner-context/v1\0";
const WAL_OWNER_CANDIDATE_DOMAIN: &[u8] = b"kioku/archive-v3/wal-owner-candidate/v1\0";
const WAL_OWNER_SETTLEMENT_DOMAIN: &[u8] = b"kioku/archive-v3/wal-owner-settlement/v1\0";
const WAL_OWNER_SESSION_DOMAIN: &[u8] = b"kioku/archive-v3/wal-owner-session/v1\0";
const MAX_WAL_OWNER_COMMANDS: usize = 1;
const CHECKPOINT_LEASE_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
pub(crate) const MAX_WAL_OWNER_ATTEMPTS: u32 = 16;
pub(crate) const MAX_WAL_OWNER_ARTIFACTS: u32 = MAX_WAL_SEGMENTS_PER_COMMIT + 2;
/// Bound on how many serving generations one archive's in-process relaunch
/// driver may install before the lane is quarantined.
///
/// Strictly less than `MAX_WAL_OWNER_ATTEMPTS` so driver-driven relaunches can
/// never exhaust the *durable* per-operation attempt cap and turn a transient
/// fault into a restart-proof write-death: Control bumps an operation's
/// attempt only when `prepare_wal_owner_operation_conn` observes a different
/// `owner_instance_id`, and the instance id changes only when a new lane is
/// built -- so attempt burn is bounded by the successful-generation count, not
/// by client retries.
///
/// At least 3 because a send-sensitive retained commit costs two generations
/// to settle: generation N+1 resumes the candidate, advances the witness, and
/// then deliberately poisons; generation N+2 recovers from the advanced root
/// and acknowledges the client's retry by replay.
pub(crate) const MAX_WAL_SERVING_GENERATIONS: u32 = 8;
const _: () = assert!(MAX_WAL_SERVING_GENERATIONS < MAX_WAL_OWNER_ATTEMPTS);
const _: () = assert!(MAX_WAL_SERVING_GENERATIONS >= 3);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum WalOwnerError {
    #[error("WAL owner input is malformed")]
    Malformed,
    #[error("WAL owner authority is stale or conflicting")]
    Conflict,
    #[error("WAL owner state is corrupt or unsupported")]
    Corrupt,
    #[error("WAL owner capture is unavailable")]
    Capture,
    #[error("WAL owner persistence is unavailable")]
    Persistence,
    #[error("WAL owner publication is unavailable")]
    Publication,
    #[error("WAL owner actor is poisoned")]
    Poisoned,
    /// Another process holds the exact owner lease. Distinct from
    /// [`Self::Conflict`] because it is terminal for this owner rather than
    /// retryable: no amount of retrying makes a superseded owner
    /// authoritative again, and telling a caller to retry forever is worse
    /// than telling it the lane is gone.
    #[error("WAL owner has been superseded")]
    Superseded,
}

pub(crate) type Result<T> = std::result::Result<T, WalOwnerError>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalOwnerId([u8; 16]);

impl WalOwnerId {
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

    pub(crate) fn from_control_bytes(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        value: [u8; 16],
    ) -> Result<Self> {
        (value != [0; 16])
            .then_some(Self(value))
            .ok_or(WalOwnerError::Corrupt)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for WalOwnerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalOwnerId(<opaque>)")
    }
}

/// Process-instance identity used only to distinguish a retained same-process
/// drain from a fresh SQLite owner whose WAL salts require a new attempt. This
/// is not the VFS capture stream ID.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalOwnerInstanceId([u8; 16]);

impl WalOwnerInstanceId {
    pub(crate) fn random_for_store(_token: WalOwnerStoreContext) -> Result<Self> {
        for _ in 0..16 {
            let mut value = [0; 16];
            OsRng.fill_bytes(&mut value);
            if value != [0; 16] {
                return Ok(Self(value));
            }
        }
        Err(WalOwnerError::Persistence)
    }

    pub(crate) fn from_control_bytes(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        value: [u8; 16],
    ) -> Result<Self> {
        (value != [0; 16])
            .then_some(Self(value))
            .ok_or(WalOwnerError::Corrupt)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for WalOwnerInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalOwnerInstanceId(<opaque>)")
    }
}

/// Exact active WalAuthoritative witness binding. No caller can nominate a
/// root independently of an authenticated witness record.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WalOwnerStoreBinding {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: KeyEpoch,
    root: RootReference,
    witness_bytes: [u8; crate::archive_v3_witness::WITNESS_RECORD_BYTES],
    witness_hash: [u8; 32],
    commitment: [u8; 32],
}

impl WalOwnerStoreBinding {
    pub(crate) fn from_authenticated_witness(record: &WitnessRecord) -> Result<Self> {
        if record.deletion() != DeletionState::Active
            || record.migration() != MigrationState::WalAuthoritative
            || !record.has_exact_active_wal_owner_lease()
        {
            return Err(WalOwnerError::Conflict);
        }
        let root = record.root().root();
        let witness_bytes = record.encode();
        let witness_hash: [u8; 32] = Sha256::digest(witness_bytes).into();
        let mut hasher = Sha256::new();
        hasher.update(WAL_OWNER_BINDING_DOMAIN);
        hasher.update(WAL_OWNER_FORMAT_V1.to_be_bytes());
        hasher.update(record.archive_id().as_bytes());
        hasher.update(record.database_epoch().as_bytes());
        hasher.update(record.registry().key_epoch().as_bytes());
        hasher.update(root.sequence().to_be_bytes());
        hasher.update(root.object_id().as_bytes());
        hasher.update(root.ciphertext_hash());
        hasher.update(witness_hash);
        let commitment: [u8; 32] = hasher.finalize().into();
        if commitment == [0; 32] {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            archive_id: record.archive_id(),
            database_epoch: record.database_epoch(),
            key_epoch: record.registry().key_epoch(),
            root,
            witness_bytes,
            witness_hash,
            commitment,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn database_epoch(&self) -> DatabaseEpoch {
        self.database_epoch
    }

    pub(crate) const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    pub(crate) const fn root(&self) -> RootReference {
        self.root
    }

    pub(crate) const fn witness_bytes(
        &self,
    ) -> &[u8; crate::archive_v3_witness::WITNESS_RECORD_BYTES] {
        &self.witness_bytes
    }

    pub(crate) const fn witness_hash(&self) -> [u8; 32] {
        self.witness_hash
    }

    pub(crate) const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

impl fmt::Debug for WalOwnerStoreBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalOwnerStoreBinding(<opaque>)")
    }
}

/// Private token allowing Store to construct exact operation contexts.
#[derive(Clone, Copy)]
pub(crate) struct WalOwnerStoreContext(());

/// Producer token for consuming the B0 runtime bundle inside the private
/// publisher child. It has no public or sibling constructor.
#[derive(Clone, Copy)]
pub(crate) struct WalPublisherRuntimeContext(());

#[derive(Clone, Copy)]
pub(crate) struct WalCheckpointSourceContext(());

impl WalCheckpointSourceContext {
    pub(crate) const fn for_store(_token: crate::store::StoreWalCheckpointContext) -> Self {
        Self(())
    }

    pub(crate) const fn for_control(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
    ) -> Self {
        Self(())
    }

    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self(())
    }
}

#[cfg(test)]
impl WalOwnerStoreContext {
    pub(crate) const fn for_test() -> Self {
        Self(())
    }
}

/// Producer token for the witness module's exact ordinary-root transition
/// validator. It carries no authority or caller-selected root.
#[derive(Clone, Copy)]
pub(crate) struct WalWitnessAdvanceContext(());

impl WalWitnessAdvanceContext {
    const fn new() -> Self {
        Self(())
    }

    pub(crate) const fn for_publisher() -> Self {
        Self(())
    }

    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalOperationIdentity {
    kind: WalOperationKind,
    operation_id: WalLogicalOperationId,
    request_fingerprint: WalRequestFingerprint,
}

impl WalOperationIdentity {
    pub(crate) const fn kind(&self) -> WalOperationKind {
        self.kind
    }

    pub(crate) const fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    pub(crate) const fn request_fingerprint(&self) -> WalRequestFingerprint {
        self.request_fingerprint
    }

    pub(crate) fn from_erased_prepared(prepared: &dyn ErasedPreparedLogicalMutation) -> Self {
        Self {
            kind: prepared.kind_for_owner(),
            operation_id: prepared.operation_id_for_owner(),
            request_fingerprint: prepared.request_fingerprint_for_owner(),
        }
    }

    pub(crate) fn from_control_parts(
        token: crate::cp::control_store::WalOwnerPersistenceContext,
        kind: i64,
        operation_id: &[u8],
        request_fingerprint: &[u8],
    ) -> Result<Self> {
        let operation_id: [u8; 16] = operation_id
            .try_into()
            .map_err(|_| WalOwnerError::Corrupt)?;
        let request_fingerprint: [u8; 32] = request_fingerprint
            .try_into()
            .map_err(|_| WalOwnerError::Corrupt)?;
        Ok(Self {
            kind: WalOperationKind::decode(kind).map_err(|_| WalOwnerError::Corrupt)?,
            operation_id: WalLogicalOperationId::from_bytes(operation_id)
                .map_err(|_| WalOwnerError::Corrupt)?,
            request_fingerprint: WalRequestFingerprint::from_control_bytes(
                token,
                request_fingerprint,
            )
            .map_err(|_| WalOwnerError::Corrupt)?,
        })
    }

    pub(crate) fn session_id_for_control(
        &self,
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        archive_id: ArchiveId,
    ) -> Result<ShadowSessionId> {
        let mut hasher = Sha256::new();
        hasher.update(WAL_OWNER_SESSION_DOMAIN);
        hasher.update(WAL_OWNER_FORMAT_V1.to_be_bytes());
        hasher.update(archive_id.as_bytes());
        hasher.update((self.kind as u16).to_be_bytes());
        hasher.update(self.operation_id.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut value = [0; 16];
        value.copy_from_slice(&digest[..16]);
        if value == [0; 16] {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(ShadowSessionId::from_bytes(value))
    }

    #[cfg(test)]
    pub(crate) fn for_test(kind: WalOperationKind, id: u8, fingerprint: u8) -> Self {
        Self {
            kind,
            operation_id: WalLogicalOperationId::from_bytes([id; 16]).unwrap(),
            request_fingerprint: WalRequestFingerprint::for_owner_test([fingerprint; 32]).unwrap(),
        }
    }
}

impl fmt::Debug for WalOperationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalOperationIdentity(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum WalPublicationStage {
    Prepared = 1,
    Captured = 2,
    CandidateReady = 3,
    SendStarted = 4,
    Witnessed = 5,
    ManualRequired = 6,
}

/// Durable attempt selected by encrypted control before local mutation.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WalOwnerAttempt {
    owner_id: WalOwnerId,
    owner_instance_id: WalOwnerInstanceId,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    attempt: u32,
    expected_wal_generation: Option<u64>,
    stage: WalPublicationStage,
    revision: u64,
    capture_commitment: Option<[u8; 32]>,
    first_frame_no: Option<u64>,
    frame_count: Option<u32>,
    candidate: Option<WalPublicationCandidate>,
    observed_binding: Option<WalOwnerStoreBinding>,
}

impl WalOwnerAttempt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        owner_id: WalOwnerId,
        owner_instance_id: WalOwnerInstanceId,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        attempt: u32,
        expected_wal_generation: Option<u64>,
        stage: WalPublicationStage,
        revision: u64,
        capture_commitment: Option<[u8; 32]>,
        first_frame_no: Option<u64>,
        frame_count: Option<u32>,
        candidate: Option<WalPublicationCandidate>,
        observed_binding: Option<WalOwnerStoreBinding>,
    ) -> Result<Self> {
        if attempt == 0
            || attempt > MAX_WAL_OWNER_ATTEMPTS
            || expected_wal_generation.is_some_and(|value| value == 0)
            || revision == 0
            || session_id.as_bytes() == &[0; 16]
            || attempt_id.as_bytes() == &[0; 16]
            || capture_commitment.is_some_and(|value| value == [0; 32])
            || (capture_commitment.is_some() != first_frame_no.is_some())
            || (capture_commitment.is_some() != frame_count.is_some())
            || first_frame_no.is_some_and(|value| value == 0)
            || frame_count.is_some_and(|value| value == 0)
            || matches!(stage, WalPublicationStage::Prepared) != capture_commitment.is_none()
            || matches!(stage, WalPublicationStage::Prepared) != expected_wal_generation.is_none()
            || (matches!(
                stage,
                WalPublicationStage::CandidateReady
                    | WalPublicationStage::SendStarted
                    | WalPublicationStage::Witnessed
            ) && candidate.is_none())
            || (matches!(
                stage,
                WalPublicationStage::Prepared | WalPublicationStage::Captured
            ) && candidate.is_some())
            || (stage == WalPublicationStage::Witnessed) != observed_binding.is_some()
        {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            owner_id,
            owner_instance_id,
            session_id,
            attempt_id,
            attempt,
            expected_wal_generation,
            stage,
            revision,
            capture_commitment,
            first_frame_no,
            frame_count,
            candidate,
            observed_binding,
        })
    }

    pub(crate) const fn owner_id(&self) -> WalOwnerId {
        self.owner_id
    }

    pub(crate) const fn owner_instance_id(&self) -> WalOwnerInstanceId {
        self.owner_instance_id
    }

    pub(crate) const fn session_id(&self) -> ShadowSessionId {
        self.session_id
    }

    pub(crate) const fn attempt_id(&self) -> ShadowAttemptId {
        self.attempt_id
    }

    pub(crate) const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub(crate) const fn expected_wal_generation(&self) -> Option<u64> {
        self.expected_wal_generation
    }

    pub(crate) const fn stage(&self) -> WalPublicationStage {
        self.stage
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn capture_commitment(&self) -> Option<[u8; 32]> {
        self.capture_commitment
    }

    pub(crate) const fn first_frame_no(&self) -> Option<u64> {
        self.first_frame_no
    }

    pub(crate) const fn frame_count(&self) -> Option<u32> {
        self.frame_count
    }

    pub(crate) const fn candidate(&self) -> Option<&WalPublicationCandidate> {
        self.candidate.as_ref()
    }

    pub(crate) const fn observed_binding(&self) -> Option<&WalOwnerStoreBinding> {
        self.observed_binding.as_ref()
    }

    pub(crate) fn expected_binding_for_candidate(&self) -> Option<&WalOwnerStoreBinding> {
        self.candidate
            .as_ref()
            .map(|candidate| candidate.expected_binding())
    }
}

impl fmt::Debug for WalOwnerAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalOwnerAttempt(<opaque>)")
    }
}

/// Full operation/capture binding used by VFS and encrypted control. It has
/// no getters for archive, root, or result data outside reviewed consumers.
pub(crate) struct WalOwnerContext {
    binding: WalOwnerStoreBinding,
    identity: WalOperationIdentity,
    owner_id: WalOwnerId,
    owner_instance_id: WalOwnerInstanceId,
    stream_id: CaptureStreamId,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    attempt: u32,
    wal_generation: u64,
    durable_commitment: [u8; 32],
    commitment: [u8; 32],
}

impl WalOwnerContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_store(
        _token: WalOwnerStoreContext,
        binding: WalOwnerStoreBinding,
        identity: WalOperationIdentity,
        owner_id: WalOwnerId,
        owner_instance_id: WalOwnerInstanceId,
        stream_id: CaptureStreamId,
        attempt: WalOwnerAttempt,
        observed_wal_generation: u64,
    ) -> Result<Self> {
        if attempt.owner_id != owner_id
            || attempt.owner_instance_id != owner_instance_id
            || observed_wal_generation == 0
            || attempt
                .expected_wal_generation
                .is_some_and(|expected| expected != observed_wal_generation)
        {
            return Err(WalOwnerError::Conflict);
        }
        let durable_commitment = durable_context_commitment(
            &binding,
            identity,
            owner_id,
            owner_instance_id,
            attempt.session_id,
            attempt.attempt_id,
            attempt.attempt,
            observed_wal_generation,
        )?;
        let mut hasher = Sha256::new();
        hasher.update(WAL_OWNER_CONTEXT_DOMAIN);
        hasher.update(durable_commitment);
        // The raw stream ID remains process-local; its domain-separated
        // commitment prevents a settlement from one registration consuming a
        // fresh registration's otherwise identical drain.
        hasher.update(stream_id.wal_owner_commitment());
        let commitment: [u8; 32] = hasher.finalize().into();
        if durable_commitment == [0; 32] || commitment == [0; 32] {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            binding,
            identity,
            owner_id,
            owner_instance_id,
            stream_id,
            session_id: attempt.session_id,
            attempt_id: attempt.attempt_id,
            attempt: attempt.attempt,
            wal_generation: observed_wal_generation,
            durable_commitment,
            commitment,
        })
    }

    pub(crate) fn matches_capture(
        &self,
        stream_id: CaptureStreamId,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        wal_generation: u64,
    ) -> bool {
        self.stream_id == stream_id
            && self.session_id == session_id
            && self.attempt_id == attempt_id
            && self.wal_generation == wal_generation
    }

    pub(crate) const fn binding(&self) -> &WalOwnerStoreBinding {
        &self.binding
    }

    pub(crate) const fn identity(&self) -> WalOperationIdentity {
        self.identity
    }

    pub(crate) const fn owner_id(&self) -> WalOwnerId {
        self.owner_id
    }

    pub(crate) const fn owner_instance_id(&self) -> WalOwnerInstanceId {
        self.owner_instance_id
    }

    pub(crate) const fn session_id(&self) -> ShadowSessionId {
        self.session_id
    }

    pub(crate) const fn attempt_id(&self) -> ShadowAttemptId {
        self.attempt_id
    }

    pub(crate) const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub(crate) const fn wal_generation(&self) -> u64 {
        self.wal_generation
    }

    pub(crate) const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub(crate) const fn durable_commitment(&self) -> [u8; 32] {
        self.durable_commitment
    }
}

#[allow(clippy::too_many_arguments)]
fn durable_context_commitment(
    binding: &WalOwnerStoreBinding,
    identity: WalOperationIdentity,
    owner_id: WalOwnerId,
    owner_instance_id: WalOwnerInstanceId,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    attempt: u32,
    wal_generation: u64,
) -> Result<[u8; 32]> {
    if wal_generation == 0 || attempt == 0 || attempt > MAX_WAL_OWNER_ATTEMPTS {
        return Err(WalOwnerError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(WAL_OWNER_CONTEXT_DOMAIN);
    hasher.update(WAL_OWNER_FORMAT_V1.to_be_bytes());
    hasher.update(binding.commitment());
    hasher.update(owner_id.as_bytes());
    hasher.update(owner_instance_id.as_bytes());
    hasher.update(identity.operation_id.as_bytes());
    hasher.update(identity.request_fingerprint.as_bytes());
    hasher.update((identity.kind as u16).to_be_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(attempt_id.as_bytes());
    hasher.update(attempt.to_be_bytes());
    hasher.update(wal_generation.to_be_bytes());
    let value: [u8; 32] = hasher.finalize().into();
    (value != [0; 32])
        .then_some(value)
        .ok_or(WalOwnerError::Corrupt)
}

impl fmt::Debug for WalOwnerContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalOwnerContext(<opaque>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WalPublicationCandidate {
    expected_binding: WalOwnerStoreBinding,
    advance: AuthenticatedWalRootAdvance,
    root: RootReference,
    capture_commitment: [u8; 32],
    first_frame_no: u64,
    frame_count: u32,
    segment_count: u32,
    artifact_commitment: [u8; 32],
    candidate_commitment: [u8; 32],
}

impl WalPublicationCandidate {
    fn from_authority(
        context: &WalOwnerContext,
        captured: &CapturedWalCommit,
        candidate_root: RootCommitment,
        artifact_set: AuthenticatedWalArtifactSet,
    ) -> Result<Self> {
        let current = WitnessRecord::decode(context.binding().witness_bytes())
            .map_err(|_| WalOwnerError::Corrupt)?;
        let root = candidate_root.root();
        let capture_commitment = captured.publication_commitment();
        let expected_segment_count =
            crate::archive_v3_shadow_wal::captured_wal_segment_count(captured)
                .map_err(|_| WalOwnerError::Malformed)?;
        if artifact_set.durable_context_commitment != context.durable_commitment()
            || artifact_set.capture_commitment != capture_commitment
            || artifact_set.first_frame_no != captured.first_frame_no()
            || artifact_set.frame_count != captured.frame_count()
            || artifact_set.segment_count != expected_segment_count
            || root != candidate_root.root()
        {
            return Err(WalOwnerError::Conflict);
        }
        let advance = AuthenticatedWalRootAdvance::from_expected_witness(
            WalWitnessAdvanceContext::new(),
            &current,
            candidate_root,
        )
        .map_err(|_| WalOwnerError::Conflict)?;
        let mut hasher = Sha256::new();
        hasher.update(WAL_OWNER_CANDIDATE_DOMAIN);
        hasher.update(context.durable_commitment());
        hasher.update(context.identity().operation_id().as_bytes());
        hasher.update(context.identity().request_fingerprint().as_bytes());
        hasher.update(context.attempt().to_be_bytes());
        hasher.update(capture_commitment);
        hasher.update(captured.first_frame_no().to_be_bytes());
        hasher.update(captured.frame_count().to_be_bytes());
        hasher.update(artifact_set.segment_count.to_be_bytes());
        hasher.update(artifact_set.artifact_commitment);
        hasher.update(advance.expected_witness());
        hasher.update(root.sequence().to_be_bytes());
        hasher.update(root.object_id().as_bytes());
        hasher.update(root.ciphertext_hash());
        hasher.update(candidate_root.owner_fencing_epoch().to_be_bytes());
        let candidate_commitment: [u8; 32] = hasher.finalize().into();
        if candidate_commitment == [0; 32] {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            expected_binding: context.binding().clone(),
            advance,
            root,
            capture_commitment,
            first_frame_no: captured.first_frame_no(),
            frame_count: captured.frame_count(),
            segment_count: artifact_set.segment_count,
            artifact_commitment: artifact_set.artifact_commitment,
            candidate_commitment,
        })
    }

    pub(crate) const fn root(&self) -> RootReference {
        self.root
    }

    pub(crate) const fn expected_witness_bytes(
        &self,
    ) -> &[u8; crate::archive_v3_witness::WITNESS_RECORD_BYTES] {
        self.advance.expected_witness()
    }

    pub(crate) const fn commitment(&self) -> [u8; 32] {
        self.candidate_commitment
    }

    pub(crate) const fn capture_commitment(&self) -> [u8; 32] {
        self.capture_commitment
    }

    pub(crate) const fn first_frame_no(&self) -> u64 {
        self.first_frame_no
    }

    pub(crate) const fn frame_count(&self) -> u32 {
        self.frame_count
    }

    pub(crate) const fn segment_count(&self) -> u32 {
        self.segment_count
    }

    pub(crate) const fn artifact_commitment(&self) -> [u8; 32] {
        self.artifact_commitment
    }

    pub(crate) fn owner_fencing_epoch(&self) -> u64 {
        self.advance.candidate().owner_fencing_epoch()
    }

    pub(crate) fn expected_binding(&self) -> &WalOwnerStoreBinding {
        &self.expected_binding
    }

    pub(crate) fn root_advance_for_authority(&self) -> crate::archive_v3_witness::RootAdvance {
        self.advance
            .provider_advance(WalWitnessAdvanceContext::new())
    }

    fn authenticated_next_binding(&self, observed: &WitnessRecord) -> Result<WalOwnerStoreBinding> {
        self.advance
            .validate_observed(observed)
            .map_err(|_| WalOwnerError::Conflict)?;
        WalOwnerStoreBinding::from_authenticated_witness(observed)
    }

    pub(crate) fn observed_binding_for_control(
        &self,
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        observed: &[u8; crate::archive_v3_witness::WITNESS_RECORD_BYTES],
    ) -> Result<WalOwnerStoreBinding> {
        let observed = WitnessRecord::decode(observed).map_err(|_| WalOwnerError::Corrupt)?;
        self.authenticated_next_binding(&observed)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control_persisted(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        identity: WalOperationIdentity,
        owner_id: WalOwnerId,
        owner_instance_id: WalOwnerInstanceId,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        attempt: u32,
        wal_generation: u64,
        capture_commitment: [u8; 32],
        first_frame_no: u64,
        frame_count: u32,
        segment_count: u32,
        artifact_commitment: [u8; 32],
        sequence: u64,
        object_id: ObjectId,
        ciphertext_hash: [u8; 32],
        owner_fencing_epoch: u64,
        expected_witness: [u8; crate::archive_v3_witness::WITNESS_RECORD_BYTES],
        candidate_commitment: [u8; 32],
    ) -> Result<Self> {
        if sequence == 0
            || object_id.as_bytes() == &[0; 16]
            || ciphertext_hash == [0; 32]
            || capture_commitment == [0; 32]
            || first_frame_no == 0
            || frame_count == 0
            || segment_count == 0
            || segment_count > MAX_WAL_SEGMENTS_PER_COMMIT
            || artifact_commitment == [0; 32]
            || candidate_commitment == [0; 32]
        {
            return Err(WalOwnerError::Corrupt);
        }
        let root = RootReference::new(sequence, object_id, ciphertext_hash);
        let expected =
            WitnessRecord::decode(&expected_witness).map_err(|_| WalOwnerError::Corrupt)?;
        let root_commitment = RootCommitment::from_persisted_wal_candidate(
            WalWitnessAdvanceContext::new(),
            binding.database_epoch(),
            binding.key_epoch(),
            owner_fencing_epoch,
            binding.root(),
            root,
        )
        .map_err(|_| WalOwnerError::Corrupt)?;
        let advance = AuthenticatedWalRootAdvance::from_persisted(
            WalWitnessAdvanceContext::new(),
            &expected_witness,
            root_commitment,
        )
        .map_err(|_| WalOwnerError::Corrupt)?;
        if expected.encode() != *binding.witness_bytes() {
            return Err(WalOwnerError::Conflict);
        }
        let durable_commitment = durable_context_commitment(
            binding,
            identity,
            owner_id,
            owner_instance_id,
            session_id,
            attempt_id,
            attempt,
            wal_generation,
        )?;
        let mut hasher = Sha256::new();
        hasher.update(WAL_OWNER_CANDIDATE_DOMAIN);
        hasher.update(durable_commitment);
        hasher.update(identity.operation_id().as_bytes());
        hasher.update(identity.request_fingerprint().as_bytes());
        hasher.update(attempt.to_be_bytes());
        hasher.update(capture_commitment);
        hasher.update(first_frame_no.to_be_bytes());
        hasher.update(frame_count.to_be_bytes());
        hasher.update(segment_count.to_be_bytes());
        hasher.update(artifact_commitment);
        hasher.update(expected_witness);
        hasher.update(sequence.to_be_bytes());
        hasher.update(object_id.as_bytes());
        hasher.update(ciphertext_hash);
        hasher.update(owner_fencing_epoch.to_be_bytes());
        if <[u8; 32]>::from(hasher.finalize()) != candidate_commitment {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            expected_binding: binding.clone(),
            advance,
            root,
            capture_commitment,
            first_frame_no,
            frame_count,
            segment_count,
            artifact_commitment,
            candidate_commitment,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_control_test(
        context: &WalOwnerContext,
        captured: &CapturedWalCommit,
        root: RootCommitment,
        artifact_set: AuthenticatedWalArtifactSet,
    ) -> Result<Self> {
        Self::from_authority(context, captured, root, artifact_set)
    }

    #[cfg(test)]
    pub(crate) fn for_persistence_test(
        context: &WalOwnerContext,
        capture_commitment: [u8; 32],
        first_frame_no: u64,
        frame_count: u32,
        candidate_root: RootCommitment,
        artifact_set: AuthenticatedWalArtifactSet,
    ) -> Result<Self> {
        if artifact_set.durable_context_commitment != context.durable_commitment()
            || artifact_set.capture_commitment != capture_commitment
            || artifact_set.first_frame_no != first_frame_no
            || artifact_set.frame_count != frame_count
        {
            return Err(WalOwnerError::Conflict);
        }
        let current = WitnessRecord::decode(context.binding().witness_bytes())
            .map_err(|_| WalOwnerError::Corrupt)?;
        let advance = AuthenticatedWalRootAdvance::from_expected_witness(
            WalWitnessAdvanceContext::new(),
            &current,
            candidate_root,
        )
        .map_err(|_| WalOwnerError::Conflict)?;
        let root = candidate_root.root();
        let mut hasher = Sha256::new();
        hasher.update(WAL_OWNER_CANDIDATE_DOMAIN);
        hasher.update(context.durable_commitment());
        hasher.update(context.identity().operation_id().as_bytes());
        hasher.update(context.identity().request_fingerprint().as_bytes());
        hasher.update(context.attempt().to_be_bytes());
        hasher.update(capture_commitment);
        hasher.update(first_frame_no.to_be_bytes());
        hasher.update(frame_count.to_be_bytes());
        hasher.update(artifact_set.segment_count.to_be_bytes());
        hasher.update(artifact_set.artifact_commitment);
        hasher.update(advance.expected_witness());
        hasher.update(root.sequence().to_be_bytes());
        hasher.update(root.object_id().as_bytes());
        hasher.update(root.ciphertext_hash());
        hasher.update(candidate_root.owner_fencing_epoch().to_be_bytes());
        let candidate_commitment: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            expected_binding: context.binding().clone(),
            advance,
            root,
            capture_commitment,
            first_frame_no,
            frame_count,
            segment_count: artifact_set.segment_count,
            artifact_commitment: artifact_set.artifact_commitment,
            candidate_commitment,
        })
    }
}

impl fmt::Debug for WalPublicationCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalPublicationCandidate(<opaque>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WalPublicationArtifact {
    ordinal: u32,
    context_aad: Zeroizing<Vec<u8>>,
    object_id: ObjectId,
    role: ObjectRole,
    object_key: String,
    ciphertext_hash: [u8; 32],
}

impl WalPublicationArtifact {
    fn from_authority(
        context: &WalOwnerContext,
        ordinal: u32,
        object_context: &ObjectContext,
        ciphertext_hash: [u8; 32],
    ) -> Result<Self> {
        let object_id = object_context.object_id();
        let role = object_context.role();
        let object_key = object_context.object_key().as_str().to_owned();
        let context_aad = object_context.canonical_aad();
        if ordinal >= MAX_WAL_OWNER_ARTIFACTS
            || !matches!(
                role,
                ObjectRole::WalSegmentV3 | ObjectRole::WalCommitDescriptorV3 | ObjectRole::RootV3
            )
            || object_key.is_empty()
            || object_key.len() > 512
            || context_aad.is_empty()
            || context_aad.len() > 512
            || object_id.as_bytes() == &[0; 16]
            || ciphertext_hash == [0; 32]
            || !object_key
                .starts_with(ArchivePrefix::for_archive(context.binding().archive_id()).as_str())
            || canonical_object_identity(&object_key) != Some((object_id, role))
        {
            return Err(WalOwnerError::Malformed);
        }
        Ok(Self {
            ordinal,
            context_aad: Zeroizing::new(context_aad),
            object_id,
            role,
            object_key,
            ciphertext_hash,
        })
    }

    pub(crate) const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub(crate) fn context_aad(&self) -> &[u8] {
        &self.context_aad
    }

    pub(crate) const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    pub(crate) const fn role(&self) -> ObjectRole {
        self.role
    }

    pub(crate) fn object_key(&self) -> &str {
        &self.object_key
    }

    pub(crate) const fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }

    fn decoded_context(&self) -> Result<ObjectContext> {
        let context = ObjectContext::decode_canonical_aad(&self.context_aad)
            .map_err(|_| WalOwnerError::Corrupt)?;
        if context.object_id() != self.object_id
            || context.role() != self.role
            || context.object_key().as_str() != self.object_key
        {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(context)
    }

    pub(crate) fn validate_topology(
        &self,
        context: &WalOwnerContext,
        segment_count: u32,
    ) -> Result<()> {
        self.validate_durable_topology(context.binding(), context.wal_generation(), segment_count)
    }

    pub(crate) fn validate_prefix_topology(
        &self,
        binding: &WalOwnerStoreBinding,
        expected_wal_generation: u64,
    ) -> Result<()> {
        let object = self.decoded_context()?;
        if object.archive_id() != binding.archive_id()
            || object.database_epoch() != binding.database_epoch()
            || object.key_epoch() != binding.key_epoch()
        {
            return Err(WalOwnerError::Conflict);
        }
        let next_root_seq = binding
            .root()
            .sequence()
            .checked_add(1)
            .ok_or(WalOwnerError::Corrupt)?;
        let valid = match (self.ordinal, self.role, object.location()) {
            (
                ordinal,
                ObjectRole::WalSegmentV3,
                LogicalLocation::Wal {
                    root_seq,
                    wal_generation,
                    segment_index,
                },
            ) => {
                ordinal < MAX_WAL_SEGMENTS_PER_COMMIT
                    && *root_seq == next_root_seq
                    && *wal_generation == expected_wal_generation
                    && *segment_index == ordinal
                    && object.parent().is_none()
            }
            (
                ordinal,
                ObjectRole::WalCommitDescriptorV3,
                LogicalLocation::WalCommitDescriptor { root_seq },
            ) => {
                (1..=MAX_WAL_SEGMENTS_PER_COMMIT).contains(&ordinal)
                    && *root_seq == next_root_seq
                    && object.parent().is_none()
            }
            (ordinal, ObjectRole::RootV3, LogicalLocation::Root { root_seq }) => {
                (2..=MAX_WAL_OWNER_ARTIFACTS - 1).contains(&ordinal)
                    && *root_seq == next_root_seq
                    && object.parent().is_some_and(|parent| {
                        parent.object_id == binding.root().object_id()
                            && parent.envelope_hash == binding.root().ciphertext_hash()
                    })
            }
            _ => false,
        };
        valid.then_some(()).ok_or(WalOwnerError::Corrupt)
    }

    pub(crate) fn validate_durable_topology(
        &self,
        binding: &WalOwnerStoreBinding,
        expected_wal_generation: u64,
        segment_count: u32,
    ) -> Result<()> {
        if segment_count == 0 || segment_count > MAX_WAL_SEGMENTS_PER_COMMIT {
            return Err(WalOwnerError::Corrupt);
        }
        let object = self.decoded_context()?;
        if object.archive_id() != binding.archive_id()
            || object.database_epoch() != binding.database_epoch()
            || object.key_epoch() != binding.key_epoch()
        {
            return Err(WalOwnerError::Conflict);
        }
        let next_root_seq = binding
            .root()
            .sequence()
            .checked_add(1)
            .ok_or(WalOwnerError::Corrupt)?;
        let valid = match (self.ordinal, self.role, object.location()) {
            (
                ordinal,
                ObjectRole::WalSegmentV3,
                LogicalLocation::Wal {
                    root_seq,
                    wal_generation,
                    segment_index,
                },
            ) if ordinal < segment_count => {
                *root_seq == next_root_seq
                    && *wal_generation == expected_wal_generation
                    && *segment_index == ordinal
                    && object.parent().is_none()
            }
            (
                ordinal,
                ObjectRole::WalCommitDescriptorV3,
                LogicalLocation::WalCommitDescriptor { root_seq },
            ) if ordinal == segment_count => {
                *root_seq == next_root_seq && object.parent().is_none()
            }
            (ordinal, ObjectRole::RootV3, LogicalLocation::Root { root_seq })
                if ordinal == segment_count + 1 =>
            {
                *root_seq == next_root_seq
                    && object.parent().is_some_and(|parent| {
                        parent.object_id == binding.root().object_id()
                            && parent.envelope_hash == binding.root().ciphertext_hash()
                    })
            }
            _ => false,
        };
        valid.then_some(()).ok_or(WalOwnerError::Corrupt)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control_persisted(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        expected_wal_generation: u64,
        segment_count: u32,
        ordinal: u32,
        context_aad: Vec<u8>,
        object_id: ObjectId,
        role: i64,
        object_key: String,
        ciphertext_hash: [u8; 32],
    ) -> Result<Self> {
        let role = match role {
            2 => ObjectRole::WalSegmentV3,
            5 => ObjectRole::RootV3,
            9 => ObjectRole::WalCommitDescriptorV3,
            _ => return Err(WalOwnerError::Corrupt),
        };
        let value = Self {
            ordinal,
            context_aad: Zeroizing::new(context_aad),
            object_id,
            role,
            object_key,
            ciphertext_hash,
        };
        value.validate_durable_topology(binding, expected_wal_generation, segment_count)?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control_prefix(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        binding: &WalOwnerStoreBinding,
        expected_wal_generation: u64,
        ordinal: u32,
        context_aad: Vec<u8>,
        object_id: ObjectId,
        role: i64,
        object_key: String,
        ciphertext_hash: [u8; 32],
    ) -> Result<Self> {
        let role = match role {
            2 => ObjectRole::WalSegmentV3,
            5 => ObjectRole::RootV3,
            9 => ObjectRole::WalCommitDescriptorV3,
            _ => return Err(WalOwnerError::Corrupt),
        };
        let value = Self {
            ordinal,
            context_aad: Zeroizing::new(context_aad),
            object_id,
            role,
            object_key,
            ciphertext_hash,
        };
        value.validate_prefix_topology(binding, expected_wal_generation)?;
        Ok(value)
    }

    #[cfg(test)]
    pub(crate) fn for_control_test(
        context: &WalOwnerContext,
        ordinal: u32,
        object_context: &ObjectContext,
        ciphertext_hash: [u8; 32],
    ) -> Result<Self> {
        Self::from_authority(context, ordinal, object_context, ciphertext_hash)
    }
}

/// Control-authenticated exact dense one-commit object plan. The provider can
/// consume it to build one candidate, but callers cannot substitute a partial
/// or alternate artifact set.
pub(crate) struct AuthenticatedWalArtifactSet {
    durable_context_commitment: [u8; 32],
    capture_commitment: [u8; 32],
    first_frame_no: u64,
    frame_count: u32,
    segment_count: u32,
    artifact_commitment: [u8; 32],
}

/// Fresh provider-authenticated exact head required before any replay result
/// can leave the actor. It carries no provider handle and exposes no record.
pub(crate) struct AuthenticatedWalOwnerHead {
    binding_commitment: [u8; 32],
}

/// What a successful provider read of the live head actually said.
///
/// Kept separate from `Result` because the two failures are not the same
/// event. A provider that could not be reached says nothing about who owns
/// the lease, and must never cost a rightful owner its lane. A provider that
/// answered, with a valid head belonging to someone else, is a *completed*
/// takeover: this owner can never become authoritative again, and the only
/// honest thing to tell a caller is that the lane is gone.
///
/// Collapsing both into `Err(Conflict)` is what left a fenced-out owner
/// answering "conflict; retry" forever, to a retry that could never succeed.
pub(crate) enum FreshHead {
    /// The live head authenticates this owner's binding and exact lease.
    Authenticated(AuthenticatedWalOwnerHead),
    /// The provider answered, and the lease is no longer this owner's.
    Superseded,
}

impl AuthenticatedWalOwnerHead {
    fn from_authority(
        expected: &WalOwnerStoreBinding,
        observed: WitnessRecord,
    ) -> Result<FreshHead> {
        let actual = WalOwnerStoreBinding::from_authenticated_witness(&observed)?;
        if &actual != expected || !observed.has_exact_active_wal_owner_lease() {
            // The provider answered and the answer is not ours. Note this is
            // reached only on a *successful* read: a transport failure never
            // gets here, which is precisely the distinction being preserved.
            return Ok(FreshHead::Superseded);
        }
        Ok(FreshHead::Authenticated(Self {
            binding_commitment: actual.commitment(),
        }))
    }

    fn authenticates(&self, binding: &WalOwnerStoreBinding) -> bool {
        self.binding_commitment == binding.commitment()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        expected: &WalOwnerStoreBinding,
        observed: WitnessRecord,
    ) -> Result<FreshHead> {
        Self::from_authority(expected, observed)
    }
}

impl fmt::Debug for AuthenticatedWalOwnerHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedWalOwnerHead(<opaque>)")
    }
}

impl AuthenticatedWalArtifactSet {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control_validation(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        context: &WalOwnerContext,
        capture_commitment: [u8; 32],
        first_frame_no: u64,
        frame_count: u32,
        segment_count: u32,
        artifact_commitment: [u8; 32],
    ) -> Result<Self> {
        if capture_commitment == [0; 32]
            || first_frame_no == 0
            || frame_count == 0
            || segment_count == 0
            || segment_count > MAX_WAL_SEGMENTS_PER_COMMIT
            || artifact_commitment == [0; 32]
        {
            return Err(WalOwnerError::Corrupt);
        }
        Ok(Self {
            durable_context_commitment: context.durable_commitment(),
            capture_commitment,
            first_frame_no,
            frame_count,
            segment_count,
            artifact_commitment,
        })
    }

    pub(crate) const fn segment_count(&self) -> u32 {
        self.segment_count
    }

    pub(crate) const fn commitment(&self) -> [u8; 32] {
        self.artifact_commitment
    }
}

/// Provider-derived exact witness observation. Only sealed publication
/// implementations can construct it; PR A provides test implementations only.
pub(crate) struct WitnessedWalCandidate {
    candidate: WalPublicationCandidate,
    observed_witness: [u8; crate::archive_v3_witness::WITNESS_RECORD_BYTES],
}

impl WitnessedWalCandidate {
    fn from_authority(candidate: WalPublicationCandidate, observed: WitnessRecord) -> Result<Self> {
        candidate.authenticated_next_binding(&observed)?;
        Ok(Self {
            candidate,
            observed_witness: observed.encode(),
        })
    }

    pub(crate) const fn candidate(&self) -> &WalPublicationCandidate {
        &self.candidate
    }

    pub(crate) const fn observed_witness(
        &self,
    ) -> &[u8; crate::archive_v3_witness::WITNESS_RECORD_BYTES] {
        &self.observed_witness
    }

    pub(crate) fn next_binding(&self) -> Result<WalOwnerStoreBinding> {
        let observed =
            WitnessRecord::decode(&self.observed_witness).map_err(|_| WalOwnerError::Corrupt)?;
        self.candidate.authenticated_next_binding(&observed)
    }

    #[cfg(test)]
    pub(crate) fn for_control_test(
        candidate: WalPublicationCandidate,
        observed: WitnessRecord,
    ) -> Result<Self> {
        Self::from_authority(candidate, observed)
    }
}

/// Durable settlement capability minted only after encrypted-control CAS.
pub(crate) struct AuthenticatedWalSettlement {
    context_commitment: [u8; 32],
    capture_commitment: [u8; 32],
    candidate_commitment: [u8; 32],
    settlement_commitment: [u8; 32],
    next_binding: WalOwnerStoreBinding,
}

impl AuthenticatedWalSettlement {
    pub(crate) fn from_control_cas(
        _token: crate::cp::control_store::WalOwnerPersistenceContext,
        context: &WalOwnerContext,
        capture_commitment: [u8; 32],
        candidate: &WalPublicationCandidate,
        next_binding: WalOwnerStoreBinding,
    ) -> Result<Self> {
        if capture_commitment == [0; 32] {
            return Err(WalOwnerError::Corrupt);
        }
        let mut hasher = Sha256::new();
        hasher.update(WAL_OWNER_SETTLEMENT_DOMAIN);
        hasher.update(context.commitment());
        hasher.update(capture_commitment);
        hasher.update(candidate.commitment());
        let settlement_commitment: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            context_commitment: context.commitment(),
            capture_commitment,
            candidate_commitment: candidate.commitment(),
            settlement_commitment,
            next_binding,
        })
    }

    pub(crate) fn authenticates(
        &self,
        context: &WalOwnerContext,
        capture_commitment: [u8; 32],
    ) -> bool {
        if self.context_commitment != context.commitment()
            || self.capture_commitment != capture_commitment
            || self.candidate_commitment == [0; 32]
        {
            return false;
        }
        let mut hasher = Sha256::new();
        hasher.update(WAL_OWNER_SETTLEMENT_DOMAIN);
        hasher.update(self.context_commitment);
        hasher.update(self.capture_commitment);
        hasher.update(self.candidate_commitment);
        <[u8; 32]>::from(hasher.finalize()) == self.settlement_commitment
    }

    pub(crate) fn next_binding(&self) -> &WalOwnerStoreBinding {
        &self.next_binding
    }
}

impl fmt::Debug for AuthenticatedWalSettlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedWalSettlement(<opaque>)")
    }
}

/// Read-only encrypted-control preflight. `SettledHead` means there is no
/// unresolved publication that can authorize provider I/O for this request;
/// an exact local domain replay may be released only after the actor also
/// authenticates the fresh current witness head. `Retained` carries the sole
/// unresolved same-operation attempt and never grants a new mutation.
pub(crate) enum WalOwnerAdmission {
    SettledHead,
    SettledExactOperation,
    Retained(Box<WalOwnerAttempt>),
}

impl fmt::Debug for WalOwnerAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalOwnerAdmission(<opaque>)")
    }
}

#[async_trait]
pub(crate) trait WalOwnerControl: Send + Sync {
    async fn inspect_operation(
        &self,
        binding: &WalOwnerStoreBinding,
        identity: WalOperationIdentity,
    ) -> Result<WalOwnerAdmission>;

    async fn prepare_operation(
        &self,
        binding: &WalOwnerStoreBinding,
        owner_instance_id: WalOwnerInstanceId,
        identity: WalOperationIdentity,
    ) -> Result<WalOwnerAttempt>;

    async fn record_captured(
        &self,
        context: &WalOwnerContext,
        capture_commitment: [u8; 32],
        first_frame_no: u64,
        frame_count: u32,
    ) -> Result<WalOwnerAttempt>;

    async fn reserve_artifact(
        &self,
        context: &WalOwnerContext,
        artifact: &WalPublicationArtifact,
    ) -> Result<()>;

    async fn mark_artifact_materialized(
        &self,
        context: &WalOwnerContext,
        artifact: &WalPublicationArtifact,
    ) -> Result<()>;

    async fn authenticate_artifact_set(
        &self,
        context: &WalOwnerContext,
        capture_commitment: [u8; 32],
        first_frame_no: u64,
        frame_count: u32,
    ) -> Result<AuthenticatedWalArtifactSet>;

    async fn record_candidate(
        &self,
        context: &WalOwnerContext,
        capture_commitment: [u8; 32],
        candidate: &WalPublicationCandidate,
    ) -> Result<WalOwnerAttempt>;

    async fn mark_send_started(
        &self,
        context: &WalOwnerContext,
        candidate: &WalPublicationCandidate,
    ) -> Result<WalOwnerAttempt>;

    async fn record_witnessed(
        &self,
        context: &WalOwnerContext,
        capture_commitment: [u8; 32],
        witnessed: WitnessedWalCandidate,
    ) -> Result<AuthenticatedWalSettlement>;

    async fn mark_recovered_send_started(
        &self,
        binding: &WalOwnerStoreBinding,
        identity: WalOperationIdentity,
        attempt: &WalOwnerAttempt,
        candidate: &WalPublicationCandidate,
    ) -> Result<WalOwnerAttempt>;

    async fn record_recovered_witnessed(
        &self,
        binding: &WalOwnerStoreBinding,
        identity: WalOperationIdentity,
        attempt: &WalOwnerAttempt,
        witnessed: WitnessedWalCandidate,
    ) -> Result<WalOwnerStoreBinding>;

    async fn require_manual(&self, context: &WalOwnerContext) -> Result<()>;
}

mod sealed {
    pub(crate) trait PublicationAuthority {}
}

/// Sealed publication boundary. The sole production implementation is the
/// private maintenance-handoff-owned publisher child; deterministic fakes
/// exercise the protocol without exposing provider authority.
#[async_trait]
pub(crate) trait WalPublicationAuthority:
    sealed::PublicationAuthority + Send + Sync + 'static
{
    async fn read_fresh_head(&self, binding: &WalOwnerStoreBinding) -> Result<FreshHead>;

    async fn checkpoint_pending(&self, binding: &WalOwnerStoreBinding) -> Result<bool>;

    async fn refresh_live_binding(
        &self,
        binding: &WalOwnerStoreBinding,
    ) -> Result<WalOwnerStoreBinding>;

    /// Maintains a binding while the blocking Store lane is producing a
    /// checkpoint source. Implementations must authenticate retained
    /// checkpoint state before any provider lease mutation: a candidate or
    /// send marker is reconciled by exact read only, never renewed/reacquired.
    async fn refresh_checkpoint_source_binding(
        &self,
        binding: &WalOwnerStoreBinding,
        owner_instance_id: WalOwnerInstanceId,
    ) -> Result<WalOwnerStoreBinding>;

    async fn checkpoint_required(&self, binding: &WalOwnerStoreBinding) -> Result<bool>;

    async fn checkpoint_and_recover(
        &self,
        binding: &WalOwnerStoreBinding,
        owner_instance_id: WalOwnerInstanceId,
        source: crate::store::WalOwnerCheckpointSource,
    ) -> Result<WalCheckpointSettlement>;

    async fn create_candidate(
        &self,
        context: &WalOwnerContext,
        captured: &CapturedWalCommit,
        control: &dyn WalOwnerControl,
    ) -> Result<WalPublicationCandidate>;

    async fn send_candidate(
        &self,
        context: &WalOwnerContext,
        candidate: &WalPublicationCandidate,
    ) -> Result<WitnessedWalCandidate>;

    async fn resume_candidate(
        &self,
        binding: &WalOwnerStoreBinding,
        identity: WalOperationIdentity,
        attempt: &WalOwnerAttempt,
        candidate: &WalPublicationCandidate,
    ) -> Result<WitnessedWalCandidate>;
}

/// Opaque replacement Store owner minted only after a checkpoint candidate is
/// durably witnessed, Control atomically advances the owner binding, and the
/// exact new root is independently recovered into a fresh private staging
/// copy. It carries no paths, provider handles, or acknowledgement result.
pub(crate) struct WalCheckpointSettlement {
    staged: crate::archive_v3_shadow_parity::AuthenticatedWalOwnerStaging,
    binding: WalOwnerStoreBinding,
    capture: Arc<crate::store::StoreShadowCapture>,
}

impl WalCheckpointSettlement {
    /// The successor lane inherits the predecessor's liveness census: a
    /// replacement must never reset the proof of death for this authority.
    async fn into_lane(self, liveness: LaneLiveness) -> Result<WalStoreLane> {
        WalStoreLane::spawn_authenticated(self.staged, self.binding, self.capture, liveness).await
    }
}

impl fmt::Debug for WalCheckpointSettlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalCheckpointSettlement(<opaque>)")
    }
}

struct WalOwnerCommand {
    prepared: Box<dyn ErasedPreparedLogicalMutation>,
    response: oneshot::Sender<Result<Box<dyn Any + Send>>>,
}

enum WalOwnerMessage {
    Apply(WalOwnerCommand),
    Read {
        read: Box<dyn crate::store::ErasedWalStoreRead>,
        response: oneshot::Sender<
            Result<std::result::Result<Box<dyn Any + Send>, crate::error::EnclaveError>>,
        >,
    },
    #[cfg(test)]
    CheckpointedPlaintext {
        response: oneshot::Sender<Result<Vec<u8>>>,
    },
}

enum WalStoreLaneCommand {
    Lookup {
        prepared: Box<dyn ErasedPreparedLogicalMutation>,
        response: oneshot::Sender<Result<crate::store::WalStoreReplay>>,
    },
    Read {
        read: Box<dyn crate::store::ErasedWalStoreRead>,
        response: oneshot::Sender<
            Result<std::result::Result<Box<dyn Any + Send>, crate::error::EnclaveError>>,
        >,
    },
    Apply {
        prepared: Box<dyn ErasedPreparedLogicalMutation>,
        attempt: Box<WalOwnerAttempt>,
        response: oneshot::Sender<Result<crate::store::WalStoreApply>>,
    },
    Advance {
        context: Box<WalOwnerContext>,
        next: Box<WalOwnerStoreBinding>,
        response: oneshot::Sender<Result<()>>,
    },
    Refresh {
        next: Box<WalOwnerStoreBinding>,
        response: oneshot::Sender<Result<()>>,
    },
    Checkpoint {
        response: oneshot::Sender<Result<crate::store::WalOwnerCheckpointSource>>,
    },
    Poison,
    #[cfg(test)]
    CheckpointedPlaintext {
        response: oneshot::Sender<Result<Vec<u8>>>,
    },
}

/// Live blocking-lane census for one serving authority.
///
/// A serving authority does not own one lane thread for its whole life: a
/// checkpoint consumes the current lane and `WalCheckpointSettlement::into_lane`
/// spawns its successor, so a `JoinHandle` captured at launch names a thread
/// that may already be gone while a different one still holds the writable
/// SQLite connection. The census counts *every* lane thread this authority has
/// ever started and has not yet finished, and the successor inherits it, so
/// "quiet" means no thread of this authority is still running -- not merely
/// that the first one returned.
///
/// The residency guard is dropped by the lane thread's own closure, strictly
/// after `run_wal_store_lane` has returned and therefore strictly after the
/// `SingleArchiveWalStoreOwner` it owned has been dropped: the SQLite
/// `Connection` is closed and `CaptureRegistration::drop` has run
/// `retire_and_scrub()` and freed the registry slot. That ordering holds on a
/// panic unwind exactly as it does on an ordinary return, which is the whole
/// point -- an unwinding lane thread must not be able to look quiet before its
/// plaintext is scrubbed.
#[derive(Clone)]
struct LaneLiveness {
    census: Arc<LaneCensus>,
}

struct LaneCensus {
    live: std::sync::Mutex<usize>,
    quiet: std::sync::Condvar,
}

/// Proof-of-exit guard held by one lane thread. Dropping it -- on return or on
/// unwind -- retires that thread from the census.
struct LaneResidency {
    census: Arc<LaneCensus>,
}

impl LaneLiveness {
    fn new() -> Self {
        Self {
            census: Arc::new(LaneCensus {
                live: std::sync::Mutex::new(0),
                quiet: std::sync::Condvar::new(),
            }),
        }
    }

    /// Enrol a lane thread that is about to be spawned. The returned guard is
    /// moved into the thread closure and is the only way to leave the census.
    fn enter(&self) -> LaneResidency {
        // A poisoned census mutex means some lane thread unwound while holding
        // it. That is exactly the case where the count must still be trusted,
        // so recover the guard rather than losing the census.
        let mut live = self
            .census
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *live += 1;
        drop(live);
        LaneResidency {
            census: Arc::clone(&self.census),
        }
    }

    /// Block until no lane thread of this authority is still running. Returns
    /// false on deadline expiry, which callers MUST treat as "still alive",
    /// never as death.
    fn wait_until_quiet(&self, deadline: std::time::Duration) -> bool {
        let live = self
            .census
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (live, timeout) = self
            .census
            .quiet
            .wait_timeout_while(live, deadline, |live| *live > 0)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !timeout.timed_out() && *live == 0
    }

    #[cfg(test)]
    fn live_for_test(&self) -> usize {
        *self
            .census
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for LaneResidency {
    fn drop(&mut self) {
        let mut live = self
            .census
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *live = live.saturating_sub(1);
        let quiet = *live == 0;
        drop(live);
        if quiet {
            self.census.quiet.notify_all();
        }
    }
}

/// Dedicated blocking lane. The writable SQLite connection and VFS capture
/// registration never enter a Tokio worker; only sealed commands and opaque
/// results cross this boundary.
struct WalStoreLane {
    sender: std::sync::mpsc::Sender<WalStoreLaneCommand>,
    binding: WalOwnerStoreBinding,
    instance_id: WalOwnerInstanceId,
    poisoned: Arc<AtomicBool>,
    /// Inherited by every successor lane this authority mints, so a checkpoint
    /// cannot hide a still-running predecessor from the proof of death.
    liveness: LaneLiveness,
    _thread: std::thread::JoinHandle<()>,
}

impl WalStoreLane {
    fn spawn(
        store: crate::store::SingleArchiveWalStoreOwner,
        liveness: LaneLiveness,
    ) -> Result<Self> {
        let binding = store.binding().clone();
        let instance_id = store.instance_id();
        let poisoned = Arc::new(AtomicBool::new(false));
        let thread_poisoned = Arc::clone(&poisoned);
        let (sender, receiver) = std::sync::mpsc::channel();
        // Enrolled before the spawn so a lane can never be observed quiet in
        // the window between construction and the thread's first instruction.
        let residency = liveness.enter();
        let thread = std::thread::Builder::new()
            .name("kioku-archive-v3-wal-store".into())
            .spawn(move || {
                // Declared first, so it is dropped last: strictly after
                // `run_wal_store_lane` has dropped the store owner.
                let _residency = residency;
                run_wal_store_lane(store, receiver, thread_poisoned);
            })
            .map_err(|_| WalOwnerError::Persistence)?;
        Ok(Self {
            sender,
            binding,
            instance_id,
            poisoned,
            liveness,
            _thread: thread,
        })
    }

    async fn spawn_authenticated(
        staged: crate::archive_v3_shadow_parity::AuthenticatedWalOwnerStaging,
        binding: WalOwnerStoreBinding,
        capture: Arc<crate::store::StoreShadowCapture>,
        liveness: LaneLiveness,
    ) -> Result<Self> {
        Self::spawn_with_builder(
            move || {
                crate::store::SingleArchiveWalStoreOwner::from_authenticated_staging(
                    WalOwnerStoreContext(()),
                    staged,
                    binding,
                    capture,
                )
            },
            liveness,
        )
        .await
    }

    async fn spawn_with_builder<F>(builder: F, liveness: LaneLiveness) -> Result<Self>
    where
        F: FnOnce() -> Result<crate::store::SingleArchiveWalStoreOwner> + Send + 'static,
    {
        let poisoned = Arc::new(AtomicBool::new(false));
        let thread_poisoned = Arc::clone(&poisoned);
        let (sender, receiver) = std::sync::mpsc::channel();
        let (ready, opened) = oneshot::channel();
        let residency = liveness.enter();
        let thread = std::thread::Builder::new()
            .name("kioku-archive-v3-wal-store".into())
            .spawn(move || {
                // Declared first, so it is dropped last: strictly after every
                // early return below and after `run_wal_store_lane` has
                // dropped the store owner.
                let _residency = residency;
                let mut store = match builder() {
                    Ok(store) => store,
                    Err(error) => {
                        thread_poisoned.store(true, Ordering::Release);
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let opened_binding = store.binding().clone();
                let instance_id = store.instance_id();
                if ready.send(Ok((opened_binding, instance_id))).is_err() {
                    // Cancellation of the async constructor cannot detach a
                    // writable SQLite owner. The lane retains cleanup
                    // ownership, poisons it, and exits on this owned thread.
                    store.poison();
                    thread_poisoned.store(true, Ordering::Release);
                    return;
                }
                run_wal_store_lane(store, receiver, thread_poisoned);
            })
            .map_err(|_| WalOwnerError::Persistence)?;
        let (binding, instance_id) = opened.await.map_err(|_| WalOwnerError::Persistence)??;
        Ok(Self {
            sender,
            binding,
            instance_id,
            poisoned,
            liveness,
            _thread: thread,
        })
    }

    /// The census a successor lane must inherit. Never mint a fresh one for a
    /// replacement lane: that would let a checkpoint erase a still-running
    /// predecessor from the proof of death.
    fn liveness(&self) -> LaneLiveness {
        self.liveness.clone()
    }

    const fn binding(&self) -> &WalOwnerStoreBinding {
        &self.binding
    }

    const fn instance_id(&self) -> WalOwnerInstanceId {
        self.instance_id
    }

    fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
        let _ = self.sender.send(WalStoreLaneCommand::Poison);
    }

    async fn lookup(
        &self,
        prepared: Box<dyn ErasedPreparedLogicalMutation>,
    ) -> Result<crate::store::WalStoreReplay> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalStoreLaneCommand::Lookup { prepared, response })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)?
    }

    async fn read(
        &self,
        read: Box<dyn crate::store::ErasedWalStoreRead>,
    ) -> Result<std::result::Result<Box<dyn Any + Send>, crate::error::EnclaveError>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalStoreLaneCommand::Read { read, response })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)?
    }

    async fn apply(
        &self,
        prepared: Box<dyn ErasedPreparedLogicalMutation>,
        attempt: WalOwnerAttempt,
    ) -> Result<crate::store::WalStoreApply> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalStoreLaneCommand::Apply {
                prepared,
                attempt: Box::new(attempt),
                response,
            })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)?
    }

    async fn advance(
        &mut self,
        context: WalOwnerContext,
        next: WalOwnerStoreBinding,
    ) -> Result<()> {
        let retained_next = next.clone();
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalStoreLaneCommand::Advance {
                context: Box::new(context),
                next: Box::new(next),
                response,
            })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)??;
        self.binding = retained_next;
        Ok(())
    }

    async fn checkpoint(&self) -> Result<crate::store::WalOwnerCheckpointSource> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalStoreLaneCommand::Checkpoint { response })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)?
    }

    async fn refresh(&mut self, next: WalOwnerStoreBinding) -> Result<()> {
        let retained = next.clone();
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalStoreLaneCommand::Refresh {
                next: Box::new(next),
                response,
            })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)??;
        self.binding = retained;
        Ok(())
    }

    #[cfg(test)]
    async fn checkpointed_plaintext(&self) -> Result<Vec<u8>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalStoreLaneCommand::CheckpointedPlaintext { response })
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)?
    }
}

/// Raises the lane's poison flag when the lane thread leaves, whether it
/// returns or unwinds.
///
/// Before this guard existed a panic inside any lane command -- a domain plan,
/// rusqlite, the capture VFS -- skipped the trailing `thread_poisoned` store,
/// so `is_poisoned()` stayed false, the actor loop's poison check never broke,
/// and the actor future never completed. Every subsequent `sender.send(...)`
/// failed with `Poisoned` because the receiver had been dropped, but nothing
/// in the process could observe that the lane was gone: the user was 100%
/// offline for reads and writes, in-process, undetected, with no recovery
/// short of a restart. The guard makes an unwinding lane a *detected* dead
/// lane. It strengthens a failure handler and weakens nothing -- every
/// conditional store in the loop below is still in place.
struct LanePoisonOnExit(Arc<AtomicBool>);

impl Drop for LanePoisonOnExit {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn run_wal_store_lane(
    mut store: crate::store::SingleArchiveWalStoreOwner,
    receiver: std::sync::mpsc::Receiver<WalStoreLaneCommand>,
    thread_poisoned: Arc<AtomicBool>,
) {
    let _exit = LanePoisonOnExit(Arc::clone(&thread_poisoned));
    while let Ok(command) = receiver.recv() {
        match command {
            WalStoreLaneCommand::Lookup { prepared, response } => {
                let result = store.lookup_settled_replay(prepared);
                if store.is_poisoned() {
                    thread_poisoned.store(true, Ordering::Release);
                }
                let _ = response.send(result);
            }
            WalStoreLaneCommand::Read { read, response } => {
                let result = store.read_query_only(read);
                if store.is_poisoned() {
                    thread_poisoned.store(true, Ordering::Release);
                }
                let _ = response.send(result);
            }
            WalStoreLaneCommand::Apply {
                prepared,
                attempt,
                response,
            } => {
                let result = store.apply_prepared(prepared, *attempt);
                if store.is_poisoned() {
                    thread_poisoned.store(true, Ordering::Release);
                }
                let _ = response.send(result);
            }
            WalStoreLaneCommand::Advance {
                context,
                next,
                response,
            } => {
                let result = store.advance_binding(context.as_ref(), *next);
                if store.is_poisoned() {
                    thread_poisoned.store(true, Ordering::Release);
                }
                let _ = response.send(result);
            }
            WalStoreLaneCommand::Refresh { next, response } => {
                let result = store.refresh_lease_binding(*next);
                if store.is_poisoned() {
                    thread_poisoned.store(true, Ordering::Release);
                }
                let _ = response.send(result);
            }
            WalStoreLaneCommand::Checkpoint { response } => {
                let result = store.take_checkpoint_source();
                thread_poisoned.store(true, Ordering::Release);
                let _ = response.send(result);
                break;
            }
            WalStoreLaneCommand::Poison => {
                store.poison();
                thread_poisoned.store(true, Ordering::Release);
                break;
            }
            #[cfg(test)]
            WalStoreLaneCommand::CheckpointedPlaintext { response } => {
                let result = store.checkpointed_plaintext_for_wal_owner_test();
                if store.is_poisoned() {
                    thread_poisoned.store(true, Ordering::Release);
                }
                let _ = response.send(result);
            }
        }
    }
    // The trailing store is now `_exit`'s job, so the ordinary and the
    // unwinding exit raise the same flag through the same statement.
}

/// Crate-visible serving authority for one WAL-authoritative archive: the
/// composition the activation change hands to routing. Constructible from
/// either serving handoff — the in-run maintenance handoff, the genesis
/// reservation handoff, or the durable restart reconstruction of either —
/// and every lane goes through the same publisher owner
/// reserve/renew/reacquire path. It exposes exactly the typed settled-only
/// submit and read surfaces and nothing else — no lane, publisher, control,
/// provider, list, or delete access. No production caller exists until the
/// reviewed routing slice.
pub(crate) struct SingleArchiveWalServingAuthority {
    launcher: launcher::SingleArchiveWalLauncherOwner,
}

impl SingleArchiveWalServingAuthority {
    pub(crate) async fn launch(
        handoff: crate::archive_v3_shadow_runtime::WalServingHandoff,
    ) -> Result<Self> {
        Ok(Self {
            launcher: launcher::SingleArchiveWalLauncherOwner::launch(handoff).await?,
        })
    }

    pub(crate) async fn submit<P: WalLogicalDomainPlan>(
        &self,
        prepared: PreparedLogicalMutation<P>,
    ) -> Result<P::Output> {
        self.launcher.submit(prepared).await
    }

    pub(crate) async fn read<F, T>(
        &self,
        read: F,
    ) -> Result<std::result::Result<T, crate::error::EnclaveError>>
    where
        F: FnOnce(&rusqlite::Connection) -> std::result::Result<T, crate::error::EnclaveError>
            + Send
            + 'static,
        T: Send + 'static,
    {
        self.launcher.read(read).await
    }

    /// The sanctioned relaunch trigger for the serving slot: the actor task's
    /// own termination, never the lane's poison flag.
    pub(crate) fn is_terminal(&self) -> bool {
        self.launcher.is_terminal()
    }

    /// Proof of death for the whole authority. See
    /// `WalOwnerHandle::join_terminated`. `Err` means "still alive or
    /// unprovable" and MUST be quarantined, never treated as death.
    pub(crate) async fn join_terminated(&self, deadline: std::time::Duration) -> Result<()> {
        self.launcher.join_terminated(deadline).await
    }

    /// Test-only serving authority over an actor whose lane has already
    /// exited: the shape the relaunch driver must observe as terminal.
    #[cfg(test)]
    pub(crate) async fn terminal_for_relaunch_test() -> Self {
        Self {
            launcher: launcher::SingleArchiveWalLauncherOwner::terminal_for_relaunch_test().await,
        }
    }

    /// Test-only serving authority that is alive and answering. The relaunch
    /// driver must leave it strictly alone.
    #[cfg(test)]
    pub(crate) fn live_for_relaunch_test() -> Self {
        Self {
            launcher: launcher::SingleArchiveWalLauncherOwner::live_for_relaunch_test(),
        }
    }

    /// Test-only serving authority whose blocking lane thread never returns.
    /// The returned release handle unblocks it; the test MUST call it.
    #[cfg(test)]
    pub(crate) fn stuck_for_relaunch_test() -> (Self, StuckLaneRelease) {
        let (launcher, release) =
            launcher::SingleArchiveWalLauncherOwner::stuck_for_relaunch_test();
        (Self { launcher }, release)
    }
}

impl std::fmt::Debug for SingleArchiveWalServingAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SingleArchiveWalServingAuthority(<inactive>)")
    }
}

/// Raises the actor's termination flag when the actor future leaves, whether
/// it completes or unwinds on a task panic.
struct ActorTerminationOnExit(Arc<AtomicBool>);

impl Drop for ActorTerminationOnExit {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Non-cloneable handle owning the actor queue and task. A submitted plan is
/// moved into the queue before awaiting its response; cancellation of that
/// caller therefore cannot cancel post-commit publication work.
pub(crate) struct WalOwnerHandle {
    sender: mpsc::Sender<WalOwnerMessage>,
    /// Monotone false -> true, set by a drop guard inside the actor future so
    /// it is raised on completion *and* on task-panic unwind. This is the ONLY
    /// sanctioned relaunch trigger.
    ///
    /// A trigger must never be derived from the lane's poison flag:
    /// `WalStoreLaneCommand::Checkpoint` raises that flag unconditionally on
    /// the ordinary checkpoint path, and `take_checkpoint_source` raises it on
    /// its success path, while the actor goes on to `checkpoint_and_recover`
    /// and a full witness root advance. A poison-derived trigger would fire
    /// mid-root-advance and spawn a second owner.
    terminated: Arc<AtomicBool>,
    /// Census of this authority's still-running blocking lane threads,
    /// including every checkpoint successor.
    liveness: LaneLiveness,
    /// Held, never detached. `join_terminated` borrows the handle rather than
    /// taking it, so a deadline expiry cannot silently drop the join right and
    /// leave a later call believing the task was reaped.
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl WalOwnerHandle {
    /// Cheap, lock-free peek at the sanctioned relaunch trigger.
    pub(crate) fn is_terminal(&self) -> bool {
        self.terminated.load(Ordering::Acquire)
    }

    /// Prove this owner is dead before anything constructs its successor.
    ///
    /// Completing proves two things. First, the actor `JoinHandle` resolved:
    /// the future returned, so no publication await is suspended and none can
    /// ever be issued again (surviving `Arc` clones of the handle can only
    /// enqueue onto a channel whose receiver died with the future), and the
    /// actor's `SingleArchiveWalOwner` was dropped along with its lane,
    /// Control handle, publication authority and store fence. Second, every
    /// blocking lane thread this authority ever started has left: each one's
    /// `SingleArchiveWalStoreOwner` was dropped on its own thread, closing the
    /// writable SQLite connection and running `CaptureRegistration::drop`,
    /// which scrubs the plaintext and frees the registry slot.
    ///
    /// `Err(Persistence)` on deadline expiry. The caller MUST quarantine on
    /// that error and MUST NOT proceed: a timeout is never treated as death.
    /// Refusing is always safe; forcing never is.
    ///
    /// A task panic is *completion*, not stuckness -- `JoinError::is_panic()`
    /// still means the future is over and its resources are released -- so it
    /// resolves the join rather than quarantining.
    pub(crate) async fn join_terminated(&self, deadline: std::time::Duration) -> Result<()> {
        let started = std::time::Instant::now();
        let remaining = || deadline.saturating_sub(started.elapsed());
        let mut slot = tokio::time::timeout(remaining(), self.task.lock())
            .await
            .map_err(|_| WalOwnerError::Persistence)?;
        if let Some(handle) = slot.as_mut() {
            match tokio::time::timeout(remaining(), handle).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if error.is_panic() => {}
                // A cancelled task is not a task this process can prove
                // finished releasing its resources; refuse.
                Ok(Err(_)) => return Err(WalOwnerError::Persistence),
                // The handle is still in the slot: nothing was detached, so a
                // later call can still join it.
                Err(_) => return Err(WalOwnerError::Persistence),
            }
            // Awaiting a resolved JoinHandle again would panic, and the join
            // right has been fully exercised, so retire the slot.
            *slot = None;
        }
        drop(slot);
        let liveness = self.liveness.clone();
        let lane_deadline = remaining();
        let quiet = tokio::task::spawn_blocking(move || liveness.wait_until_quiet(lane_deadline))
            .await
            .map_err(|_| WalOwnerError::Persistence)?;
        if quiet {
            Ok(())
        } else {
            Err(WalOwnerError::Persistence)
        }
    }
    pub(crate) async fn submit<P: WalLogicalDomainPlan>(
        &self,
        prepared: PreparedLogicalMutation<P>,
    ) -> Result<P::Output> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalOwnerMessage::Apply(WalOwnerCommand {
                prepared: Box::new(prepared),
                response,
            }))
            .await
            .map_err(|_| WalOwnerError::Poisoned)?;
        let output = result.await.map_err(|_| WalOwnerError::Poisoned)??;
        output
            .downcast::<P::Output>()
            .map(|output| *output)
            .map_err(|_| WalOwnerError::Corrupt)
    }

    /// Query-only read serialized behind every in-flight apply's full
    /// settle-advance ladder. The outer error is owner/lane integrity; the
    /// inner result is the closure's own outcome on the settled state.
    pub(crate) async fn read<F, T>(
        &self,
        read: F,
    ) -> Result<std::result::Result<T, crate::error::EnclaveError>>
    where
        F: FnOnce(&rusqlite::Connection) -> std::result::Result<T, crate::error::EnclaveError>
            + Send
            + 'static,
        T: Send + 'static,
    {
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalOwnerMessage::Read {
                read: Box::new(crate::store::WalStoreReadClosure::from_closure(read)),
                response,
            })
            .await
            .map_err(|_| WalOwnerError::Poisoned)?;
        match result.await.map_err(|_| WalOwnerError::Poisoned)?? {
            Ok(output) => output
                .downcast::<T>()
                .map(|output| Ok(*output))
                .map_err(|_| WalOwnerError::Corrupt),
            Err(error) => Ok(Err(error)),
        }
    }

    #[cfg(test)]
    async fn checkpointed_plaintext_for_test(&self) -> Result<Vec<u8>> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(WalOwnerMessage::CheckpointedPlaintext { response })
            .await
            .map_err(|_| WalOwnerError::Poisoned)?;
        result.await.map_err(|_| WalOwnerError::Poisoned)?
    }
}

impl fmt::Debug for WalOwnerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalOwnerHandle(<opaque>)")
    }
}

/// Release handle for a test lane thread that is deliberately wedged. Dropping
/// it unwedges and joins the thread, so a failing assertion cannot leak one.
#[cfg(test)]
pub(crate) struct StuckLaneRelease {
    gate: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl StuckLaneRelease {
    pub(crate) fn release(self) {
        drop(self);
    }
}

#[cfg(test)]
impl Drop for StuckLaneRelease {
    fn drop(&mut self) {
        {
            let (lock, condvar) = &*self.gate;
            let mut released = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *released = true;
            condvar.notify_all();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
impl WalOwnerHandle {
    /// A handle whose actor future has already returned and which never owned
    /// a blocking lane. Terminal, and provably dead.
    pub(crate) async fn terminated_for_relaunch_test() -> Self {
        let (sender, receiver) = mpsc::channel::<WalOwnerMessage>(MAX_WAL_OWNER_COMMANDS);
        let terminated = Arc::new(AtomicBool::new(false));
        let actor_terminated = Arc::clone(&terminated);
        let task = tokio::spawn(async move {
            let _terminated = ActorTerminationOnExit(actor_terminated);
            drop(receiver);
        });
        let handle = Self {
            sender,
            terminated,
            liveness: LaneLiveness::new(),
            task: tokio::sync::Mutex::new(Some(task)),
        };
        while !handle.is_terminal() {
            tokio::task::yield_now().await;
        }
        handle
    }

    /// A handle whose actor future is still running and answering. Never
    /// terminal, so the relaunch driver must leave it strictly alone.
    pub(crate) fn live_for_relaunch_test() -> Self {
        let (sender, mut receiver) = mpsc::channel::<WalOwnerMessage>(MAX_WAL_OWNER_COMMANDS);
        let terminated = Arc::new(AtomicBool::new(false));
        let actor_terminated = Arc::clone(&terminated);
        let task = tokio::spawn(async move {
            let _terminated = ActorTerminationOnExit(actor_terminated);
            while let Some(message) = receiver.recv().await {
                match message {
                    WalOwnerMessage::Apply(command) => {
                        let _ = command.response.send(Err(WalOwnerError::Persistence));
                    }
                    WalOwnerMessage::Read { response, .. } => {
                        let _ = response.send(Err(WalOwnerError::Persistence));
                    }
                    WalOwnerMessage::CheckpointedPlaintext { response } => {
                        let _ = response.send(Err(WalOwnerError::Persistence));
                    }
                }
            }
        });
        Self {
            sender,
            terminated,
            liveness: LaneLiveness::new(),
            task: tokio::sync::Mutex::new(Some(task)),
        }
    }

    /// A handle whose actor future has ended but whose blocking lane thread is
    /// still running. Terminal, but NOT provably dead: `join_terminated` must
    /// refuse it rather than let a successor be constructed over it.
    pub(crate) fn stuck_lane_for_relaunch_test() -> (Self, StuckLaneRelease) {
        let (sender, receiver) = mpsc::channel::<WalOwnerMessage>(MAX_WAL_OWNER_COMMANDS);
        let terminated = Arc::new(AtomicBool::new(false));
        let actor_terminated = Arc::clone(&terminated);
        let task = tokio::spawn(async move {
            let _terminated = ActorTerminationOnExit(actor_terminated);
            drop(receiver);
        });
        let liveness = LaneLiveness::new();
        let residency = liveness.enter();
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let thread_gate = Arc::clone(&gate);
        let thread = std::thread::Builder::new()
            .name("kioku-archive-v3-wal-store-stuck-test".into())
            .spawn(move || {
                let _residency = residency;
                let (lock, condvar) = &*thread_gate;
                let mut released = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*released {
                    released = condvar
                        .wait(released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            })
            .expect("test lane thread spawns");
        (
            Self {
                sender,
                terminated,
                liveness,
                task: tokio::sync::Mutex::new(Some(task)),
            },
            StuckLaneRelease {
                gate,
                thread: Some(thread),
            },
        )
    }
}

/// Sole local actor. It owns the writable staged SQLite connection, capture
/// registration, and one publication authority. It is intentionally private.
struct SingleArchiveWalOwner<A>
where
    A: WalPublicationAuthority,
{
    store: WalStoreLane,
    control: Arc<dyn WalOwnerControl>,
    publication: Arc<A>,
    // The maintenance handoff's SQLite-backed admission fence is Send but
    // deliberately not Sync. The sole actor owns it for its entire lifetime;
    // it never enters the shareable publication authority or crosses an API.
    _store_fence: Option<crate::store::StoreWalAuthorityFence>,
}

impl<A> SingleArchiveWalOwner<A>
where
    A: WalPublicationAuthority,
{
    async fn take_checkpoint_source_with_lease_maintenance(
        &mut self,
    ) -> Result<(WalOwnerStoreBinding, crate::store::WalOwnerCheckpointSource)> {
        let original = self.store.binding().clone();
        let mut current = original.clone();
        let checkpoint = self.store.checkpoint();
        tokio::pin!(checkpoint);
        let mut heartbeat = tokio::time::interval(CHECKPOINT_LEASE_HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let mut source = loop {
            tokio::select! {
                result = &mut checkpoint => break result?,
                _ = heartbeat.tick() => {
                    current = self
                        .publication
                        .refresh_checkpoint_source_binding(&current, self.store.instance_id())
                        .await?;
                }
            }
        };
        if current != original {
            source
                .rebind_after_lease_maintenance(WalCheckpointSourceContext(()), current.clone())?;
        }
        Ok((current, source))
    }

    pub(crate) fn spawn(
        store: crate::store::SingleArchiveWalStoreOwner,
        control: Arc<dyn WalOwnerControl>,
        publication: Arc<A>,
    ) -> WalOwnerHandle {
        match WalStoreLane::spawn(store, LaneLiveness::new()) {
            Ok(store) => Self::spawn_lane(store, control, publication),
            Err(_) => Self::spawn_failed(),
        }
    }

    fn spawn_lane(
        store: WalStoreLane,
        control: Arc<dyn WalOwnerControl>,
        publication: Arc<A>,
    ) -> WalOwnerHandle {
        Self::spawn_lane_with_fence(store, control, publication, None)
    }

    fn spawn_lane_with_fence(
        store: WalStoreLane,
        control: Arc<dyn WalOwnerControl>,
        publication: Arc<A>,
        store_fence: Option<crate::store::StoreWalAuthorityFence>,
    ) -> WalOwnerHandle {
        let (sender, mut receiver) = mpsc::channel::<WalOwnerMessage>(MAX_WAL_OWNER_COMMANDS);
        let terminated = Arc::new(AtomicBool::new(false));
        let liveness = store.liveness();
        let actor_terminated = Arc::clone(&terminated);
        let task = tokio::spawn(async move {
            // Declared first, dropped last: raised when this future completes
            // and when it unwinds on a task panic.
            let _terminated = ActorTerminationOnExit(actor_terminated);
            let mut owner = Self {
                store,
                control,
                publication,
                _store_fence: store_fence,
            };
            while let Some(message) = receiver.recv().await {
                match message {
                    WalOwnerMessage::Apply(command) => {
                        let result = owner.apply_one(command.prepared).await;
                        let _ = command.response.send(result);
                    }
                    // Reads serialize through this actor queue on purpose:
                    // between a lane apply and its witness settlement the
                    // lane's SQLite holds unsettled state, and this loop
                    // finishes the full apply-settle-advance ladder before
                    // taking the next message, so a reader can never observe
                    // an unacknowledged write.
                    //
                    // A read is additionally served only from a head this
                    // owner still authenticates. Applies are fenced at every
                    // step; reads were not, so an owner whose idle lease
                    // expired and was reacquired by another process kept
                    // answering from its frozen SQLite as though it were the
                    // settled authority — unboundedly stale, with no error.
                    // `require_fresh_head` re-reads the live witness and
                    // requires the rebuilt binding to equal this owner's
                    // binding; that commitment covers the whole record, so any
                    // fence takeover or root advance fails it and poisons the
                    // lane, and a superseded owner can never serve again.
                    // Transient provider failures surface as Publication
                    // without poisoning.
                    WalOwnerMessage::Read { read, response } => {
                        let result = match owner.require_fresh_head().await {
                            Ok(()) => owner.store.read(read).await,
                            Err(error) => Err(error),
                        };
                        let _ = response.send(result);
                    }
                    #[cfg(test)]
                    WalOwnerMessage::CheckpointedPlaintext { response } => {
                        let result = owner.store.checkpointed_plaintext().await;
                        let _ = response.send(result);
                    }
                }
                if owner.store.is_poisoned() {
                    break;
                }
            }
        });
        WalOwnerHandle {
            sender,
            terminated,
            liveness,
            task: tokio::sync::Mutex::new(Some(task)),
        }
    }

    fn spawn_failed() -> WalOwnerHandle {
        let (sender, mut receiver) = mpsc::channel::<WalOwnerMessage>(MAX_WAL_OWNER_COMMANDS);
        let terminated = Arc::new(AtomicBool::new(false));
        // No lane was ever built, so this authority's census is empty and
        // `join_terminated` reduces to awaiting the refusal loop.
        let liveness = LaneLiveness::new();
        let actor_terminated = Arc::clone(&terminated);
        let task = tokio::spawn(async move {
            let _terminated = ActorTerminationOnExit(actor_terminated);
            while let Some(command) = receiver.recv().await {
                match command {
                    WalOwnerMessage::Apply(command) => {
                        let _ = command.response.send(Err(WalOwnerError::Persistence));
                    }
                    WalOwnerMessage::Read { response, .. } => {
                        let _ = response.send(Err(WalOwnerError::Persistence));
                    }
                    #[cfg(test)]
                    WalOwnerMessage::CheckpointedPlaintext { response } => {
                        let _ = response.send(Err(WalOwnerError::Persistence));
                    }
                }
            }
        });
        WalOwnerHandle {
            sender,
            terminated,
            liveness,
            task: tokio::sync::Mutex::new(Some(task)),
        }
    }

    async fn apply_one(
        &mut self,
        prepared: Box<dyn ErasedPreparedLogicalMutation>,
    ) -> Result<Box<dyn Any + Send>> {
        if self
            .publication
            .checkpoint_pending(self.store.binding())
            .await?
        {
            let owner_instance_id = self.store.instance_id();
            let (binding, source) = self.take_checkpoint_source_with_lease_maintenance().await?;
            let settlement = self
                .publication
                .checkpoint_and_recover(&binding, owner_instance_id, source)
                .await?;
            self.store = settlement.into_lane(self.store.liveness()).await?;
            self.require_fresh_head().await?;
        }
        let identity = WalOperationIdentity::from_erased_prepared(prepared.as_ref());
        let admission = self
            .control
            .inspect_operation(self.store.binding(), identity)
            .await?;
        let exact_settled = matches!(&admission, WalOwnerAdmission::SettledExactOperation);
        let retained = match admission {
            WalOwnerAdmission::SettledHead => None,
            WalOwnerAdmission::SettledExactOperation => None,
            WalOwnerAdmission::Retained(attempt) => Some(*attempt),
        };
        if let Some(attempt) = retained.as_ref() {
            if matches!(attempt.stage(), WalPublicationStage::ManualRequired) {
                self.store.poison();
                return Err(WalOwnerError::Conflict);
            }
            if matches!(
                attempt.stage(),
                WalPublicationStage::CandidateReady | WalPublicationStage::SendStarted
            ) {
                return self.resume_candidate(identity, attempt.clone()).await;
            }
        }
        self.require_fresh_head().await?;
        let prepared = match self.store.lookup(prepared).await? {
            crate::store::WalStoreReplay::Present(result) => {
                if retained.is_some() {
                    self.store.poison();
                    return Err(WalOwnerError::Conflict);
                }
                return result.release().map_err(|_| WalOwnerError::Corrupt);
            }
            crate::store::WalStoreReplay::Absent(prepared) => {
                if exact_settled {
                    self.store.poison();
                    return Err(WalOwnerError::Corrupt);
                }
                prepared
            }
        };
        // A retained candidate or send marker was reconciled above against
        // its immutable expected witness. Only a settled/replay-absent head
        // may renew the live owner lease. Control atomically rebases any
        // pre-candidate retained attempt to this successor before the actor
        // can enter another SQLite transaction.
        let refreshed = self
            .publication
            .refresh_live_binding(self.store.binding())
            .await?;
        self.store.refresh(refreshed).await?;
        match self
            .control
            .inspect_operation(self.store.binding(), identity)
            .await?
        {
            WalOwnerAdmission::SettledHead | WalOwnerAdmission::SettledExactOperation => {}
            WalOwnerAdmission::Retained(attempt)
                if matches!(
                    attempt.stage(),
                    WalPublicationStage::Prepared | WalPublicationStage::Captured
                ) => {}
            WalOwnerAdmission::Retained(_) => {
                self.store.poison();
                return Err(WalOwnerError::Conflict);
            }
        }
        if self
            .publication
            .checkpoint_required(self.store.binding())
            .await?
        {
            let owner_instance_id = self.store.instance_id();
            let (binding, source) = self.take_checkpoint_source_with_lease_maintenance().await?;
            let settlement = self
                .publication
                .checkpoint_and_recover(&binding, owner_instance_id, source)
                .await?;
            self.store = settlement.into_lane(self.store.liveness()).await?;
            self.require_fresh_head().await?;
        }
        let attempt = self
            .control
            .prepare_operation(self.store.binding(), self.store.instance_id(), identity)
            .await?;
        if !matches!(
            attempt.stage(),
            WalPublicationStage::Prepared | WalPublicationStage::Captured
        ) {
            self.store.poison();
            return Err(WalOwnerError::Conflict);
        }
        // The read-only replay preflight cannot authorize a new mutation.
        // Reauthenticate the exact current head after durable admission and
        // immediately before entering the local transaction.
        self.require_fresh_head().await?;
        let applied = self.store.apply(prepared, attempt.clone()).await?;
        match applied {
            crate::store::WalStoreApply::Replayed(result) => {
                drop(result);
                self.store.poison();
                Err(WalOwnerError::Conflict)
            }
            crate::store::WalStoreApply::Applied {
                context,
                drain,
                result,
            } => self.publish_applied(*context, drain, attempt, result).await,
        }
    }

    async fn require_fresh_head(&mut self) -> Result<()> {
        // A provider error propagates untouched and does NOT poison: a
        // rightful owner must survive a transport blip.
        let fresh = self
            .publication
            .read_fresh_head(self.store.binding())
            .await?;
        let FreshHead::Authenticated(fresh) = fresh else {
            // The provider answered and the lease is someone else's. This is
            // terminal, so stop the lane rather than leaving it to answer
            // "retry" to a retry that can never succeed.
            self.store.poison();
            return Err(WalOwnerError::Superseded);
        };
        if !fresh.authenticates(self.store.binding()) {
            // The actor's own check, not decoration: the outcome above is
            // built by the provider implementation, and this is where the
            // actor refuses to take that on trust.
            self.store.poison();
            return Err(WalOwnerError::Superseded);
        }
        Ok(())
    }

    async fn resume_candidate(
        &mut self,
        identity: WalOperationIdentity,
        mut attempt: WalOwnerAttempt,
    ) -> Result<Box<dyn Any + Send>> {
        let candidate = attempt.candidate().cloned().ok_or(WalOwnerError::Corrupt)?;
        if attempt.stage() == WalPublicationStage::CandidateReady {
            attempt = self
                .control
                .mark_recovered_send_started(self.store.binding(), identity, &attempt, &candidate)
                .await?;
        }
        let witnessed = self
            .publication
            .resume_candidate(self.store.binding(), identity, &attempt, &candidate)
            .await?;
        self.control
            .record_recovered_witnessed(self.store.binding(), identity, &attempt, witnessed)
            .await?;
        // The recovered actor was opened from the pre-candidate witnessed
        // head. It must never acknowledge or accept another mutation after
        // advancing the external witness; a fresh exact recovery remints the
        // authoritative SQLite copy and replays the retained domain result.
        self.store.poison();
        Err(WalOwnerError::Publication)
    }

    async fn publish_applied(
        &mut self,
        context: WalOwnerContext,
        drain: OwnedCapturedDrain,
        attempt: WalOwnerAttempt,
        result: ErasedValidatedWalLogicalResult,
    ) -> Result<Box<dyn Any + Send>> {
        let commit = drain.exact_commit(&context).map_err(|_| {
            self.store.poison();
            WalOwnerError::Capture
        })?;
        let capture_commitment = commit.publication_commitment();
        if let Some(expected) = attempt.capture_commitment() {
            if expected != capture_commitment {
                self.store.poison();
                return Err(WalOwnerError::Conflict);
            }
        }
        self.control
            .record_captured(
                &context,
                capture_commitment,
                commit.first_frame_no(),
                commit.frame_count(),
            )
            .await?;
        let candidate = self
            .publication
            .create_candidate(&context, commit, self.control.as_ref())
            .await?;
        self.control
            .record_candidate(&context, capture_commitment, &candidate)
            .await?;
        self.control.mark_send_started(&context, &candidate).await?;
        let witnessed = match self.publication.send_candidate(&context, &candidate).await {
            Ok(value) => value,
            Err(WalOwnerError::Publication) => return Err(WalOwnerError::Publication),
            Err(error) => {
                let _ = self.control.require_manual(&context).await;
                return Err(error);
            }
        };
        let settlement = match self
            .control
            .record_witnessed(&context, capture_commitment, witnessed)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                self.store.poison();
                return Err(error);
            }
        };
        let next_binding = match drain.settle(&context, settlement) {
            Ok(value) => value,
            Err(_) => {
                self.store.poison();
                return Err(WalOwnerError::Capture);
            }
        };
        self.store.advance(context, next_binding).await?;
        result.release().map_err(|_| WalOwnerError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex,
        },
    };

    use rusqlite::{OptionalExtension, Transaction};
    use zeroize::Zeroizing;

    use crate::{
        archive_v3::{LogicalLocation, ObjectContext, ParentReference},
        archive_v3_wal_idempotency::{
            self, LogicalMutationResult, WalIdempotencyError, WalLogicalDomainLedger,
            WalReplayResult,
        },
        archive_v3_witness::{
            InMemoryWitness, KeyRegistryReference, RootAdvance, RootCommitment, Witness,
            WitnessBootstrap,
        },
    };

    #[derive(Clone)]
    struct TestPlan<const FAMILY: u8 = 0> {
        kind: WalOperationKind,
        operation_id: WalLogicalOperationId,
        value: Vec<u8>,
        fail: bool,
        lookup_attack: LookupAttack,
        stall: Option<Arc<SqlStall>>,
        apply_count: Option<Arc<AtomicUsize>>,
    }

    struct SqlStall {
        entered: tokio::sync::Notify,
        released: Mutex<bool>,
        release: std::sync::Condvar,
    }

    impl SqlStall {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: tokio::sync::Notify::new(),
                released: Mutex::new(false),
                release: std::sync::Condvar::new(),
            })
        }

        fn wait(&self) {
            self.entered.notify_one();
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.release.wait(released).unwrap();
            }
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.release.notify_all();
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum LookupAttack {
        None,
        DirectWrite,
        DisableGuardThenWrite,
        SchemaWrite,
        ReturnSubstitutedResult,
    }

    struct TestLedger<const FAMILY: u8>;

    impl<const FAMILY: u8> archive_v3_wal_idempotency::sealed::DomainPlan for TestPlan<FAMILY> {}
    impl<const FAMILY: u8> archive_v3_wal_idempotency::sealed::DomainLedger for TestLedger<FAMILY> {}

    impl<const FAMILY: u8> WalLogicalDomainPlan for TestPlan<FAMILY> {
        type Ledger = TestLedger<FAMILY>;
        type Output = Vec<u8>;

        fn kind(&self) -> WalOperationKind {
            self.kind
        }

        fn operation_id(&self) -> WalLogicalOperationId {
            self.operation_id
        }

        fn canonical_request(
            &self,
        ) -> std::result::Result<Zeroizing<Vec<u8>>, WalIdempotencyError> {
            Ok(Zeroizing::new(self.value.clone()))
        }

        fn apply(
            &self,
            transaction: &Transaction<'_>,
        ) -> std::result::Result<WalReplayResult, WalIdempotencyError> {
            // Sentinel for the lane-thread panic regression. Raised before any
            // SQL so the unwind crosses no FFI frame, and kept a value sentinel
            // rather than a new field so every other plan constructor stays
            // byte-identical.
            assert!(
                self.value != LANE_PANIC_SENTINEL,
                "deliberate lane-thread panic"
            );
            if let Some(stall) = self.stall.as_ref() {
                stall.wait();
            }
            if let Some(count) = self.apply_count.as_ref() {
                count.fetch_add(1, Ordering::SeqCst);
            }
            transaction
                .execute(
                    "INSERT INTO wal_owner_test_values(value) VALUES (?1)",
                    [&self.value],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if self.fail {
                return Err(WalIdempotencyError::Unavailable);
            }
            WalReplayResult::canonical_response(self.kind(), self.value.clone())
        }

        fn validate_replay(
            &self,
            result: &WalReplayResult,
        ) -> std::result::Result<(), WalIdempotencyError> {
            let expected = WalReplayResult::canonical_response(self.kind(), self.value.clone())?;
            (result == &expected)
                .then_some(())
                .ok_or(WalIdempotencyError::ResultUnsupported)
        }

        fn decode_output(
            &self,
            result: &WalReplayResult,
        ) -> std::result::Result<Self::Output, WalIdempotencyError> {
            self.validate_replay(result)?;
            match result {
                WalReplayResult::CanonicalResponse(value) => Ok(value.to_vec()),
                WalReplayResult::UnitApplied => Err(WalIdempotencyError::ResultUnsupported),
            }
        }
    }

    impl<const FAMILY: u8> WalLogicalDomainLedger<TestPlan<FAMILY>> for TestLedger<FAMILY> {
        fn lookup(
            connection: &rusqlite::Connection,
            prepared: &PreparedLogicalMutation<TestPlan<FAMILY>>,
        ) -> std::result::Result<Option<WalReplayResult>, WalIdempotencyError> {
            match prepared.plan_for_domain_ledger().lookup_attack {
                LookupAttack::None => {}
                LookupAttack::DirectWrite => {
                    let _ = connection.execute(
                        "INSERT INTO wal_owner_test_values(value) VALUES (x'01')",
                        [],
                    );
                    return Err(WalIdempotencyError::Unavailable);
                }
                LookupAttack::DisableGuardThenWrite => {
                    connection
                        .pragma_update(None, "query_only", false)
                        .map_err(|_| WalIdempotencyError::Unavailable)?;
                    connection
                        .execute(
                            "INSERT INTO wal_owner_test_values(value) VALUES (x'02')",
                            [],
                        )
                        .map_err(|_| WalIdempotencyError::Unavailable)?;
                    return Err(WalIdempotencyError::Unavailable);
                }
                LookupAttack::SchemaWrite => {
                    let _ = connection.execute_batch("CREATE TABLE wal_lookup_escape(value BLOB);");
                    return Err(WalIdempotencyError::Unavailable);
                }
                LookupAttack::ReturnSubstitutedResult => {
                    return Ok(Some(WalReplayResult::canonical_response(
                        prepared.plan_for_domain_ledger().kind(),
                        b"substituted-result".to_vec(),
                    )?));
                }
            }
            let existing = connection
                .query_row(
                    "SELECT request_fingerprint,result FROM wal_owner_test_operations
                     WHERE operation_kind=?1 AND operation_id=?2",
                    rusqlite::params![
                        prepared.plan_for_domain_ledger().kind() as i64,
                        prepared.operation_id_for_owner().as_bytes().as_slice(),
                    ],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let Some((fingerprint, result)) = existing else {
                return Ok(None);
            };
            if fingerprint.as_slice() != prepared.request_fingerprint_for_owner().as_bytes() {
                return Err(WalIdempotencyError::FingerprintConflict);
            }
            let result = WalReplayResult::canonical_response(
                prepared.plan_for_domain_ledger().kind(),
                result,
            )?;
            prepared.plan_for_domain_ledger().validate_replay(&result)?;
            Ok(Some(result))
        }

        fn resolve_or_apply(
            transaction: &Transaction<'_>,
            prepared: &PreparedLogicalMutation<TestPlan<FAMILY>>,
        ) -> std::result::Result<LogicalMutationResult, WalIdempotencyError> {
            if let Some(result) = Self::lookup(transaction, prepared)? {
                return Ok(LogicalMutationResult::Replayed(result));
            }
            let result = prepared.plan_for_domain_ledger().apply(transaction)?;
            prepared.plan_for_domain_ledger().validate_replay(&result)?;
            transaction
                .execute(
                    "INSERT INTO wal_owner_test_operations(
                        operation_kind,operation_id,request_fingerprint,result
                     ) VALUES (?1,?2,?3,?4)",
                    rusqlite::params![
                        prepared.plan_for_domain_ledger().kind() as i64,
                        prepared.operation_id_for_owner().as_bytes().as_slice(),
                        prepared
                            .request_fingerprint_for_owner()
                            .as_bytes()
                            .as_slice(),
                        prepared.plan_for_domain_ledger().value.as_slice(),
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            Ok(LogicalMutationResult::Applied(result))
        }
    }

    /// A plan carrying this value panics on the blocking lane thread.
    const LANE_PANIC_SENTINEL: &[u8] = b"kioku-test-panic-the-lane-thread";

    fn plan(id: u8, value: &[u8]) -> PreparedLogicalMutation<TestPlan> {
        plan_kind(WalOperationKind::MediaCaptureEvent, id, value)
    }

    fn plan_kind(
        kind: WalOperationKind,
        id: u8,
        value: &[u8],
    ) -> PreparedLogicalMutation<TestPlan> {
        PreparedLogicalMutation::prepare(TestPlan {
            kind,
            operation_id: WalLogicalOperationId::from_bytes([id; 16]).unwrap(),
            value: value.to_vec(),
            fail: false,
            lookup_attack: LookupAttack::None,
            stall: None,
            apply_count: None,
        })
        .unwrap()
    }

    fn alternate_plan(
        kind: WalOperationKind,
        id: u8,
        value: &[u8],
    ) -> PreparedLogicalMutation<TestPlan<1>> {
        PreparedLogicalMutation::prepare(TestPlan::<1> {
            kind,
            operation_id: WalLogicalOperationId::from_bytes([id; 16]).unwrap(),
            value: value.to_vec(),
            fail: false,
            lookup_attack: LookupAttack::None,
            stall: None,
            apply_count: None,
        })
        .unwrap()
    }

    fn failing_plan(id: u8, value: &[u8]) -> PreparedLogicalMutation<TestPlan> {
        PreparedLogicalMutation::prepare(TestPlan {
            kind: WalOperationKind::MediaCaptureEvent,
            operation_id: WalLogicalOperationId::from_bytes([id; 16]).unwrap(),
            value: value.to_vec(),
            fail: true,
            lookup_attack: LookupAttack::None,
            stall: None,
            apply_count: None,
        })
        .unwrap()
    }

    fn attacking_lookup_plan(
        id: u8,
        value: &[u8],
        lookup_attack: LookupAttack,
    ) -> PreparedLogicalMutation<TestPlan> {
        PreparedLogicalMutation::prepare(TestPlan {
            kind: WalOperationKind::MediaCaptureEvent,
            operation_id: WalLogicalOperationId::from_bytes([id; 16]).unwrap(),
            value: value.to_vec(),
            fail: false,
            lookup_attack,
            stall: None,
            apply_count: None,
        })
        .unwrap()
    }

    fn counted_plan(
        kind: WalOperationKind,
        id: u8,
        value: &[u8],
        apply_count: Arc<AtomicUsize>,
    ) -> PreparedLogicalMutation<TestPlan> {
        PreparedLogicalMutation::prepare(TestPlan {
            kind,
            operation_id: WalLogicalOperationId::from_bytes([id; 16]).unwrap(),
            value: value.to_vec(),
            fail: false,
            lookup_attack: LookupAttack::None,
            stall: None,
            apply_count: Some(apply_count),
        })
        .unwrap()
    }

    fn stalled_plan(
        id: u8,
        value: &[u8],
        stall: Arc<SqlStall>,
    ) -> PreparedLogicalMutation<TestPlan> {
        PreparedLogicalMutation::prepare(TestPlan {
            kind: WalOperationKind::MediaCaptureEvent,
            operation_id: WalLogicalOperationId::from_bytes([id; 16]).unwrap(),
            value: value.to_vec(),
            fail: false,
            lookup_attack: LookupAttack::None,
            stall: Some(stall),
            apply_count: None,
        })
        .unwrap()
    }

    fn authoritative_records() -> (WitnessRecord, WitnessRecord) {
        let archive_id = ArchiveId::from_bytes([1; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([2; 16]);
        let key_epoch = KeyEpoch::from_bytes([3; 16]);
        let registry =
            KeyRegistryReference::new(key_epoch, 0, ObjectId::from_bytes([4; 16]), [5; 32]);
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(
                    database_epoch,
                    key_epoch,
                    RootReference::new(0, ObjectId::from_bytes([6; 16]), [7; 32]),
                ),
                registry,
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(
                archive_id,
                database_epoch,
                key_epoch,
                ObjectId::from_bytes([8; 16]),
                900,
            )
            .unwrap();
        let legacy = witness.read_current(archive_id).unwrap().unwrap();
        let shadow_root = legacy
            .with_candidate_root_for_test(
                RootReference::new(1, ObjectId::from_bytes([9; 16]), [10; 32]),
                lease.fencing_epoch(),
            )
            .root();
        let shadow = legacy
            .exact_migration_candidate(
                &RootAdvance::new(lease, legacy.root(), registry, shadow_root),
                MigrationState::ShadowWal,
            )
            .unwrap();
        let authoritative_root = shadow
            .with_candidate_root_for_test(
                RootReference::new(2, ObjectId::from_bytes([11; 16]), [12; 32]),
                lease.fencing_epoch(),
            )
            .root();
        let authoritative = shadow
            .exact_migration_candidate(
                &RootAdvance::new(lease, shadow.root(), registry, authoritative_root),
                MigrationState::WalAuthoritative,
            )
            .unwrap();
        let next = authoritative.with_candidate_root_for_test(
            RootReference::new(3, ObjectId::from_bytes([13; 16]), [14; 32]),
            lease.fencing_epoch(),
        );
        (authoritative, next)
    }

    fn sensitive_checkpoint_attempt(
        stage: CheckpointStage,
    ) -> (
        WalOwnerStoreBinding,
        WitnessRecord,
        WitnessRecord,
        CheckpointAttempt,
    ) {
        let (expected, successor) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&expected).unwrap();
        let token = crate::cp::control_store::WalOwnerPersistenceContext::for_test();
        let operation = CheckpointOperationId::from_control([0x81; 16]).unwrap();
        let session = ShadowSessionId::for_operation(*operation.as_bytes()).unwrap();
        let attempt = CheckpointAttempt::new_for_control(
            token,
            &binding,
            operation,
            session,
            ShadowAttemptId::from_bytes([0x82; 16]),
            WalOwnerInstanceId::from_control_bytes(token, [0x83; 16]).unwrap(),
        )
        .unwrap();
        let source =
            AuthenticatedCheckpointSourcePlan::for_test(&binding, 4096, [0x84; 32], 7).unwrap();
        let source_ready = attempt
            .with_source_for_control(token, &binding, &source)
            .unwrap();
        if stage == CheckpointStage::SourceReady {
            return (binding, expected, successor, source_ready);
        }
        let uploading = source_ready.uploading_for_control(token, &binding).unwrap();
        let candidate = uploading
            .candidate_for_control(token, &binding, successor.root(), [0x85; 32])
            .unwrap();
        let attempt = if stage == CheckpointStage::CandidateReady {
            candidate
        } else if stage == CheckpointStage::SendStarted {
            candidate.send_started_for_control(token, &binding).unwrap()
        } else {
            panic!("unsupported sensitive checkpoint fixture stage")
        };
        (binding, expected, successor, attempt)
    }

    #[test]
    fn checkpoint_source_sensitive_maintenance_is_exact_read_only() {
        for stage in [
            CheckpointStage::CandidateReady,
            CheckpointStage::SendStarted,
        ] {
            let (binding, expected, successor, retained) = sensitive_checkpoint_attempt(stage);
            // Exact retained head includes the expired-but-unmodified case;
            // exact candidate successor includes a committed/lost response.
            assert!(
                publisher::authenticate_checkpoint_source_sensitive_observation(
                    &binding, &retained, &expected,
                )
                .is_ok()
            );
            assert!(
                publisher::authenticate_checkpoint_source_sensitive_observation(
                    &binding, &retained, &successor,
                )
                .is_ok()
            );
            let alternate = expected.renewed_maintenance_lease_for_test();
            assert!(
                publisher::authenticate_checkpoint_source_sensitive_observation(
                    &binding, &retained, &alternate,
                )
                .is_err()
            );
        }
        let (binding, expected, _, source_ready) =
            sensitive_checkpoint_attempt(CheckpointStage::SourceReady);
        assert!(
            publisher::authenticate_checkpoint_source_sensitive_observation(
                &binding,
                &source_ready,
                &expected,
            )
            .is_err()
        );
    }

    fn attempt(
        owner_instance_id: WalOwnerInstanceId,
        stage: WalPublicationStage,
        revision: u64,
        generation: Option<u64>,
        capture: Option<[u8; 32]>,
        candidate: Option<WalPublicationCandidate>,
        observed_binding: Option<WalOwnerStoreBinding>,
    ) -> WalOwnerAttempt {
        attempt_with_ids(
            owner_instance_id,
            ShadowSessionId::from_bytes([21; 16]),
            ShadowAttemptId::from_bytes([22; 16]),
            stage,
            revision,
            generation,
            capture,
            candidate,
            observed_binding,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn attempt_with_ids(
        owner_instance_id: WalOwnerInstanceId,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        stage: WalPublicationStage,
        revision: u64,
        generation: Option<u64>,
        capture: Option<[u8; 32]>,
        candidate: Option<WalPublicationCandidate>,
        observed_binding: Option<WalOwnerStoreBinding>,
    ) -> WalOwnerAttempt {
        WalOwnerAttempt::from_control(
            crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
            WalOwnerId::from_control_bytes(
                crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
                [20; 16],
            )
            .unwrap(),
            owner_instance_id,
            session_id,
            attempt_id,
            1,
            generation,
            stage,
            revision,
            capture,
            capture.map(|_| 1),
            capture.map(|_| 1),
            candidate,
            observed_binding,
        )
        .unwrap()
    }

    struct FakeControlState {
        identity: Option<WalOperationIdentity>,
        session_id: Option<ShadowSessionId>,
        attempt_id: Option<ShadowAttemptId>,
        stage: WalPublicationStage,
        generation: Option<u64>,
        capture: Option<[u8; 32]>,
        candidate: Option<WalPublicationCandidate>,
        observed_binding: Option<WalOwnerStoreBinding>,
        owner_instance_id: Option<WalOwnerInstanceId>,
        trace: Vec<&'static str>,
    }

    struct FakeControl {
        state: Mutex<FakeControlState>,
        stall_after_capture: bool,
        artifact_segment_count: u32,
        captured: tokio::sync::Notify,
        release_capture: tokio::sync::Semaphore,
        witnessed: tokio::sync::Notify,
        fail_witnessed: AtomicBool,
    }

    impl FakeControl {
        fn new() -> Self {
            Self::with_capture_stall(false)
        }

        fn with_capture_stall(stall_after_capture: bool) -> Self {
            Self {
                state: Mutex::new(FakeControlState {
                    identity: None,
                    session_id: None,
                    attempt_id: None,
                    stage: WalPublicationStage::Prepared,
                    generation: None,
                    capture: None,
                    candidate: None,
                    observed_binding: None,
                    owner_instance_id: None,
                    trace: Vec::new(),
                }),
                stall_after_capture,
                artifact_segment_count: 1,
                captured: tokio::sync::Notify::new(),
                release_capture: tokio::sync::Semaphore::new(0),
                witnessed: tokio::sync::Notify::new(),
                fail_witnessed: AtomicBool::new(false),
            }
        }

        fn with_witnessed_failure(self) -> Self {
            self.fail_witnessed.store(true, Ordering::SeqCst);
            self
        }

        fn snapshot(&self) -> (WalPublicationStage, Vec<&'static str>) {
            let state = self.state.lock().unwrap();
            (state.stage, state.trace.clone())
        }

        fn with_segment_count(mut self, segment_count: u32) -> Self {
            self.artifact_segment_count = segment_count;
            self
        }

        fn identity_ids(
            binding: &WalOwnerStoreBinding,
            identity: WalOperationIdentity,
        ) -> (ShadowSessionId, ShadowAttemptId) {
            let token = crate::cp::control_store::WalOwnerPersistenceContext::for_test();
            let session_id = identity
                .session_id_for_control(token, binding.archive_id())
                .unwrap();
            let mut hasher = Sha256::new();
            hasher.update(b"kioku/archive-v3/wal-owner-test-attempt/v1\0");
            hasher.update(binding.archive_id().as_bytes());
            hasher.update((identity.kind() as u16).to_be_bytes());
            hasher.update(identity.operation_id().as_bytes());
            let digest = hasher.finalize();
            let mut attempt_id = [0_u8; 16];
            attempt_id.copy_from_slice(&digest[..16]);
            if attempt_id == [0; 16] {
                attempt_id[0] = 1;
            }
            (session_id, ShadowAttemptId::from_bytes(attempt_id))
        }

        fn retained_attempt(state: &FakeControlState, revision: u64) -> Result<WalOwnerAttempt> {
            Ok(attempt_with_ids(
                state.owner_instance_id.unwrap_or_else(|| {
                    WalOwnerInstanceId::from_control_bytes(
                        crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
                        [19; 16],
                    )
                    .unwrap()
                }),
                state.session_id.ok_or(WalOwnerError::Corrupt)?,
                state.attempt_id.ok_or(WalOwnerError::Corrupt)?,
                state.stage,
                revision,
                state.generation,
                state.capture,
                state.candidate.clone(),
                state.observed_binding.clone(),
            ))
        }
    }

    #[async_trait]
    impl WalOwnerControl for FakeControl {
        async fn inspect_operation(
            &self,
            _binding: &WalOwnerStoreBinding,
            identity: WalOperationIdentity,
        ) -> Result<WalOwnerAdmission> {
            let state = self.state.lock().unwrap();
            let Some(retained_identity) = state.identity else {
                return Ok(WalOwnerAdmission::SettledHead);
            };
            if state.stage == WalPublicationStage::Witnessed {
                return Ok(if retained_identity == identity {
                    WalOwnerAdmission::SettledExactOperation
                } else {
                    WalOwnerAdmission::SettledHead
                });
            }
            if retained_identity != identity {
                return Err(WalOwnerError::Conflict);
            }
            Self::retained_attempt(&state, 1)
                .map(Box::new)
                .map(WalOwnerAdmission::Retained)
        }

        async fn prepare_operation(
            &self,
            binding: &WalOwnerStoreBinding,
            owner_instance_id: WalOwnerInstanceId,
            identity: WalOperationIdentity,
        ) -> Result<WalOwnerAttempt> {
            let mut state = self.state.lock().unwrap();
            if state.stage == WalPublicationStage::Witnessed && state.identity != Some(identity) {
                state.stage = WalPublicationStage::Prepared;
                state.generation = None;
                state.capture = None;
                state.candidate = None;
                state.observed_binding = None;
                state.owner_instance_id = None;
                state.session_id = None;
                state.attempt_id = None;
            } else if state.identity.is_some() && state.identity != Some(identity) {
                return Err(WalOwnerError::Conflict);
            }
            state.identity = Some(identity);
            if state.session_id.is_none() || state.attempt_id.is_none() {
                let (session_id, attempt_id) = Self::identity_ids(binding, identity);
                state.session_id = Some(session_id);
                state.attempt_id = Some(attempt_id);
            }
            state.trace.push("prepare");
            state.owner_instance_id.get_or_insert(owner_instance_id);
            Self::retained_attempt(&state, 1)
        }

        async fn record_captured(
            &self,
            context: &WalOwnerContext,
            capture: [u8; 32],
            _first_frame_no: u64,
            _frame_count: u32,
        ) -> Result<WalOwnerAttempt> {
            let durable = {
                let mut state = self.state.lock().unwrap();
                state.stage = WalPublicationStage::Captured;
                state.generation = Some(context.wal_generation());
                state.capture = Some(capture);
                state.trace.push("captured");
                Self::retained_attempt(&state, 2)?
            };
            if self.stall_after_capture {
                self.captured.notify_one();
                self.release_capture
                    .acquire()
                    .await
                    .map_err(|_| WalOwnerError::Persistence)?
                    .forget();
            }
            Ok(durable)
        }

        async fn reserve_artifact(
            &self,
            _context: &WalOwnerContext,
            _artifact: &WalPublicationArtifact,
        ) -> Result<()> {
            self.state.lock().unwrap().trace.push("reserve");
            Ok(())
        }

        async fn mark_artifact_materialized(
            &self,
            _context: &WalOwnerContext,
            _artifact: &WalPublicationArtifact,
        ) -> Result<()> {
            self.state.lock().unwrap().trace.push("materialized");
            Ok(())
        }

        async fn authenticate_artifact_set(
            &self,
            context: &WalOwnerContext,
            capture: [u8; 32],
            first_frame_no: u64,
            frame_count: u32,
        ) -> Result<AuthenticatedWalArtifactSet> {
            AuthenticatedWalArtifactSet::from_control_validation(
                crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
                context,
                capture,
                first_frame_no,
                frame_count,
                self.artifact_segment_count,
                [55; 32],
            )
        }

        async fn record_candidate(
            &self,
            _context: &WalOwnerContext,
            _capture: [u8; 32],
            candidate: &WalPublicationCandidate,
        ) -> Result<WalOwnerAttempt> {
            let mut state = self.state.lock().unwrap();
            state.stage = WalPublicationStage::CandidateReady;
            state.candidate = Some(candidate.clone());
            state.trace.push("candidate");
            Self::retained_attempt(&state, 3)
        }

        async fn mark_send_started(
            &self,
            _context: &WalOwnerContext,
            _candidate: &WalPublicationCandidate,
        ) -> Result<WalOwnerAttempt> {
            let mut state = self.state.lock().unwrap();
            state.stage = WalPublicationStage::SendStarted;
            state.trace.push("send-started");
            Self::retained_attempt(&state, 4)
        }

        async fn record_witnessed(
            &self,
            context: &WalOwnerContext,
            capture: [u8; 32],
            witnessed: WitnessedWalCandidate,
        ) -> Result<AuthenticatedWalSettlement> {
            if self.fail_witnessed.load(Ordering::SeqCst) {
                let mut state = self.state.lock().unwrap();
                state.trace.push("witnessed-refused");
                return Err(WalOwnerError::Persistence);
            }
            let settlement = AuthenticatedWalSettlement::from_control_cas(
                crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
                context,
                capture,
                witnessed.candidate(),
                witnessed.next_binding()?,
            )?;
            let mut state = self.state.lock().unwrap();
            state.stage = WalPublicationStage::Witnessed;
            state.observed_binding = Some(witnessed.next_binding()?);
            state.trace.push("witnessed");
            drop(state);
            self.witnessed.notify_waiters();
            Ok(settlement)
        }

        async fn mark_recovered_send_started(
            &self,
            _binding: &WalOwnerStoreBinding,
            _identity: WalOperationIdentity,
            retained: &WalOwnerAttempt,
            candidate: &WalPublicationCandidate,
        ) -> Result<WalOwnerAttempt> {
            if retained.candidate() != Some(candidate) {
                return Err(WalOwnerError::Conflict);
            }
            let mut state = self.state.lock().unwrap();
            state.stage = WalPublicationStage::SendStarted;
            state.candidate = Some(candidate.clone());
            state.trace.push("recovered-send-started");
            Self::retained_attempt(&state, 4)
        }

        async fn record_recovered_witnessed(
            &self,
            _binding: &WalOwnerStoreBinding,
            _identity: WalOperationIdentity,
            retained: &WalOwnerAttempt,
            witnessed: WitnessedWalCandidate,
        ) -> Result<WalOwnerStoreBinding> {
            if retained.candidate() != Some(witnessed.candidate()) {
                return Err(WalOwnerError::Conflict);
            }
            let next = witnessed.next_binding()?;
            let mut state = self.state.lock().unwrap();
            state.stage = WalPublicationStage::Witnessed;
            state.candidate = Some(witnessed.candidate().clone());
            state.observed_binding = Some(next.clone());
            state.trace.push("recovered-witnessed");
            drop(state);
            self.witnessed.notify_waiters();
            Ok(next)
        }

        async fn require_manual(&self, _context: &WalOwnerContext) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            state.stage = WalPublicationStage::ManualRequired;
            state.trace.push("manual");
            Ok(())
        }
    }

    struct FakePublication {
        next: WitnessRecord,
        fail_send_terminal: AtomicBool,
        reject_fresh: AtomicBool,
        supersede_fresh: AtomicBool,
        generic_refreshes: AtomicUsize,
        checkpoint_refreshes: AtomicUsize,
        candidate_sends: AtomicUsize,
        checkpoint_observation: Mutex<Option<(CheckpointAttempt, WitnessRecord)>>,
    }

    impl FakePublication {
        fn new(next: WitnessRecord) -> Self {
            Self {
                next,
                fail_send_terminal: AtomicBool::new(false),
                reject_fresh: AtomicBool::new(false),
                supersede_fresh: AtomicBool::new(false),
                generic_refreshes: AtomicUsize::new(0),
                checkpoint_refreshes: AtomicUsize::new(0),
                candidate_sends: AtomicUsize::new(0),
                checkpoint_observation: Mutex::new(None),
            }
        }

        fn with_checkpoint_observation(
            self,
            attempt: CheckpointAttempt,
            observed: WitnessRecord,
        ) -> Self {
            *self.checkpoint_observation.lock().unwrap() = Some((attempt, observed));
            self
        }

        /// The provider cannot be reached. Says nothing about ownership.
        fn reject_fresh(&self) {
            self.reject_fresh.store(true, Ordering::SeqCst);
        }

        /// The provider answered, and another process holds the exact lease.
        fn supersede_fresh(&self) {
            self.supersede_fresh.store(true, Ordering::SeqCst);
        }

        fn fail_send_terminal(&self) {
            self.fail_send_terminal.store(true, Ordering::SeqCst);
        }
    }

    impl sealed::PublicationAuthority for FakePublication {}

    async fn create_test_candidate(
        next: &WitnessRecord,
        context: &WalOwnerContext,
        captured: &CapturedWalCommit,
        control: &dyn WalOwnerControl,
    ) -> Result<WalPublicationCandidate> {
        for (ordinal, role, location, id, hash) in [
            (
                0,
                ObjectRole::WalSegmentV3,
                LogicalLocation::Wal {
                    root_seq: next.root().root().sequence(),
                    wal_generation: context.wal_generation(),
                    segment_index: 0,
                },
                ObjectId::from_bytes([30; 16]),
                [31; 32],
            ),
            (
                1,
                ObjectRole::WalCommitDescriptorV3,
                LogicalLocation::WalCommitDescriptor {
                    root_seq: next.root().root().sequence(),
                },
                ObjectId::from_bytes([32; 16]),
                [33; 32],
            ),
            (
                2,
                ObjectRole::RootV3,
                LogicalLocation::Root {
                    root_seq: next.root().root().sequence(),
                },
                next.root().root().object_id(),
                next.root().root().ciphertext_hash(),
            ),
        ] {
            let parent = (role == ObjectRole::RootV3).then_some(ParentReference {
                object_id: context.binding().root().object_id(),
                envelope_hash: context.binding().root().ciphertext_hash(),
            });
            let object_context = ObjectContext::new(
                context.binding().archive_id(),
                context.binding().database_epoch(),
                context.binding().key_epoch(),
                role,
                location,
                id,
                parent,
            )
            .unwrap();
            let artifact =
                WalPublicationArtifact::from_authority(context, ordinal, &object_context, hash)?;
            control.reserve_artifact(context, &artifact).await?;
            control
                .mark_artifact_materialized(context, &artifact)
                .await?;
        }
        let artifact_set = control
            .authenticate_artifact_set(
                context,
                captured.publication_commitment(),
                captured.first_frame_no(),
                captured.frame_count(),
            )
            .await?;
        WalPublicationCandidate::from_authority(context, captured, next.root(), artifact_set)
    }

    #[cfg(test)]
    #[async_trait]
    impl WalPublicationAuthority for FakePublication {
        async fn read_fresh_head(&self, binding: &WalOwnerStoreBinding) -> Result<FreshHead> {
            if self.reject_fresh.load(Ordering::SeqCst) {
                return Err(WalOwnerError::Conflict);
            }
            if self.supersede_fresh.load(Ordering::SeqCst) {
                return Ok(FreshHead::Superseded);
            }
            let observed = WitnessRecord::decode(binding.witness_bytes())
                .map_err(|_| WalOwnerError::Corrupt)?;
            AuthenticatedWalOwnerHead::from_authority(binding, observed)
        }

        async fn checkpoint_required(&self, _binding: &WalOwnerStoreBinding) -> Result<bool> {
            Ok(false)
        }

        async fn checkpoint_pending(&self, _binding: &WalOwnerStoreBinding) -> Result<bool> {
            Ok(false)
        }

        async fn refresh_live_binding(
            &self,
            binding: &WalOwnerStoreBinding,
        ) -> Result<WalOwnerStoreBinding> {
            self.generic_refreshes.fetch_add(1, Ordering::SeqCst);
            Ok(binding.clone())
        }

        async fn refresh_checkpoint_source_binding(
            &self,
            binding: &WalOwnerStoreBinding,
            _owner_instance_id: WalOwnerInstanceId,
        ) -> Result<WalOwnerStoreBinding> {
            self.checkpoint_refreshes.fetch_add(1, Ordering::SeqCst);
            if let Some((attempt, observed)) = self.checkpoint_observation.lock().unwrap().as_ref()
            {
                publisher::authenticate_checkpoint_source_sensitive_observation(
                    binding, attempt, observed,
                )?;
            }
            Ok(binding.clone())
        }

        async fn checkpoint_and_recover(
            &self,
            _binding: &WalOwnerStoreBinding,
            _owner_instance_id: WalOwnerInstanceId,
            _source: crate::store::WalOwnerCheckpointSource,
        ) -> Result<WalCheckpointSettlement> {
            Err(WalOwnerError::Conflict)
        }

        async fn create_candidate(
            &self,
            context: &WalOwnerContext,
            captured: &CapturedWalCommit,
            control: &dyn WalOwnerControl,
        ) -> Result<WalPublicationCandidate> {
            create_test_candidate(&self.next, context, captured, control).await
        }

        async fn send_candidate(
            &self,
            _context: &WalOwnerContext,
            candidate: &WalPublicationCandidate,
        ) -> Result<WitnessedWalCandidate> {
            self.candidate_sends.fetch_add(1, Ordering::SeqCst);
            if self.fail_send_terminal.load(Ordering::SeqCst) {
                return Err(WalOwnerError::Corrupt);
            }
            WitnessedWalCandidate::from_authority(candidate.clone(), self.next.clone())
        }

        async fn resume_candidate(
            &self,
            _binding: &WalOwnerStoreBinding,
            _identity: WalOperationIdentity,
            attempt: &WalOwnerAttempt,
            candidate: &WalPublicationCandidate,
        ) -> Result<WitnessedWalCandidate> {
            if attempt.candidate() != Some(candidate)
                || attempt.stage() != WalPublicationStage::SendStarted
            {
                return Err(WalOwnerError::Conflict);
            }
            self.candidate_sends.fetch_add(1, Ordering::SeqCst);
            WitnessedWalCandidate::from_authority(candidate.clone(), self.next.clone())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_checkpoint_source_uses_candidate_sensitive_read_only_maintenance() {
        for case in 0..4 {
            let stage = if case == 0 {
                CheckpointStage::CandidateReady
            } else {
                CheckpointStage::SendStarted
            };
            let (binding, expected, successor, retained) = sensitive_checkpoint_attempt(stage);
            let (observed, should_succeed) = match case {
                // CandidateReady and SendStarted both adopt an exact
                // committed/lost-success successor without another send.
                0 | 1 => (successor.clone(), true),
                // An exact old SendStarted head may be expired, but source
                // extraction still performs no irreversible reacquire.
                2 => (expected.clone(), true),
                // Any other same-root witness transition fails closed.
                _ => (expected.renewed_maintenance_lease_for_test(), false),
            };
            let stall = crate::store::WalCheckpointStall::new();
            let mut store =
                crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding.clone())
                    .unwrap();
            store.stall_checkpoint_for_wal_owner_test(Arc::clone(&stall));
            let lane = WalStoreLane::spawn(store, LaneLiveness::new()).unwrap();
            let publication = Arc::new(
                FakePublication::new(successor).with_checkpoint_observation(retained, observed),
            );
            let mut owner = SingleArchiveWalOwner {
                store: lane,
                control: Arc::new(FakeControl::new()),
                publication: Arc::clone(&publication),
                _store_fence: None,
            };
            let task = tokio::spawn(async move {
                let result = owner.take_checkpoint_source_with_lease_maintenance().await;
                (owner, result)
            });
            stall.wait_entered().await;
            tokio::time::advance(
                CHECKPOINT_LEASE_HEARTBEAT_INTERVAL + std::time::Duration::from_secs(1),
            )
            .await;
            tokio::task::yield_now().await;
            assert_eq!(publication.generic_refreshes.load(Ordering::SeqCst), 0);
            assert!(publication.checkpoint_refreshes.load(Ordering::SeqCst) >= 1);
            stall.release();
            let (_owner, result) = task.await.unwrap();
            if should_succeed {
                let (retained_binding, source) = result.unwrap();
                assert_eq!(retained_binding, binding);
                drop(source);
            } else {
                assert!(matches!(result, Err(WalOwnerError::Conflict)));
            }
            // Neither renewal/reacquire nor candidate send is reachable from
            // the sensitive source-maintenance method.
            assert_eq!(publication.generic_refreshes.load(Ordering::SeqCst), 0);
            assert_eq!(publication.candidate_sends.load(Ordering::SeqCst), 0);
        }
    }

    struct StatefulPublicationState {
        current: WitnessRecord,
        candidates: VecDeque<WitnessRecord>,
        sends: usize,
    }

    struct StatefulPublication {
        state: Mutex<StatefulPublicationState>,
        lose_next_response: AtomicBool,
    }

    impl StatefulPublication {
        fn new(
            current: WitnessRecord,
            candidates: impl IntoIterator<Item = WitnessRecord>,
        ) -> Self {
            Self {
                state: Mutex::new(StatefulPublicationState {
                    current,
                    candidates: candidates.into_iter().collect(),
                    sends: 0,
                }),
                lose_next_response: AtomicBool::new(false),
            }
        }

        fn lose_next_response(&self) {
            self.lose_next_response.store(true, Ordering::SeqCst);
        }

        fn sends(&self) -> usize {
            self.state.lock().unwrap().sends
        }
    }

    impl sealed::PublicationAuthority for StatefulPublication {}

    #[async_trait]
    impl WalPublicationAuthority for StatefulPublication {
        async fn read_fresh_head(&self, binding: &WalOwnerStoreBinding) -> Result<FreshHead> {
            AuthenticatedWalOwnerHead::from_authority(
                binding,
                self.state.lock().unwrap().current.clone(),
            )
        }

        async fn checkpoint_required(&self, _binding: &WalOwnerStoreBinding) -> Result<bool> {
            Ok(false)
        }

        async fn checkpoint_pending(&self, _binding: &WalOwnerStoreBinding) -> Result<bool> {
            Ok(false)
        }

        async fn refresh_live_binding(
            &self,
            binding: &WalOwnerStoreBinding,
        ) -> Result<WalOwnerStoreBinding> {
            Ok(binding.clone())
        }

        async fn refresh_checkpoint_source_binding(
            &self,
            binding: &WalOwnerStoreBinding,
            _owner_instance_id: WalOwnerInstanceId,
        ) -> Result<WalOwnerStoreBinding> {
            Ok(binding.clone())
        }

        async fn checkpoint_and_recover(
            &self,
            _binding: &WalOwnerStoreBinding,
            _owner_instance_id: WalOwnerInstanceId,
            _source: crate::store::WalOwnerCheckpointSource,
        ) -> Result<WalCheckpointSettlement> {
            Err(WalOwnerError::Conflict)
        }

        async fn create_candidate(
            &self,
            context: &WalOwnerContext,
            captured: &CapturedWalCommit,
            control: &dyn WalOwnerControl,
        ) -> Result<WalPublicationCandidate> {
            let next = self
                .state
                .lock()
                .unwrap()
                .candidates
                .front()
                .cloned()
                .ok_or(WalOwnerError::Publication)?;
            create_test_candidate(&next, context, captured, control).await
        }

        async fn send_candidate(
            &self,
            _context: &WalOwnerContext,
            candidate: &WalPublicationCandidate,
        ) -> Result<WitnessedWalCandidate> {
            let witnessed = {
                let mut state = self.state.lock().unwrap();
                let observed = state
                    .candidates
                    .pop_front()
                    .ok_or(WalOwnerError::Publication)?;
                let witnessed =
                    WitnessedWalCandidate::from_authority(candidate.clone(), observed.clone())?;
                state.current = observed.clone();
                state.sends = state.sends.saturating_add(1);
                witnessed
            };
            if self.lose_next_response.swap(false, Ordering::SeqCst) {
                return Err(WalOwnerError::Publication);
            }
            Ok(witnessed)
        }

        async fn resume_candidate(
            &self,
            _binding: &WalOwnerStoreBinding,
            _identity: WalOperationIdentity,
            attempt: &WalOwnerAttempt,
            candidate: &WalPublicationCandidate,
        ) -> Result<WitnessedWalCandidate> {
            if attempt.candidate() != Some(candidate)
                || attempt.stage() != WalPublicationStage::SendStarted
            {
                return Err(WalOwnerError::Conflict);
            }
            let mut state = self.state.lock().unwrap();
            if let Ok(witnessed) =
                WitnessedWalCandidate::from_authority(candidate.clone(), state.current.clone())
            {
                return Ok(witnessed);
            }
            let observed = state
                .candidates
                .pop_front()
                .ok_or(WalOwnerError::Conflict)?;
            let witnessed =
                WitnessedWalCandidate::from_authority(candidate.clone(), observed.clone())?;
            state.current = observed;
            state.sends = state.sends.saturating_add(1);
            Ok(witnessed)
        }
    }

    #[tokio::test]
    async fn actor_applies_once_publishes_in_order_and_replay_does_not_publish() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let control = Arc::new(FakeControl::new());
        let publication = Arc::new(FakePublication::new(next));
        let handle = SingleArchiveWalOwner::spawn(store, control.clone(), publication);

        assert_eq!(
            handle.submit(plan(40, b"portable-request")).await.unwrap(),
            b"portable-request"
        );
        assert_eq!(
            handle.submit(plan(40, b"portable-request")).await.unwrap(),
            b"portable-request"
        );
        let (stage, trace) = control.snapshot();
        assert_eq!(stage, WalPublicationStage::Witnessed);
        assert_eq!(
            trace,
            [
                "prepare",
                "captured",
                "reserve",
                "materialized",
                "reserve",
                "materialized",
                "reserve",
                "materialized",
                "candidate",
                "send-started",
                "witnessed",
            ]
        );
    }

    #[tokio::test]
    async fn blocking_sql_lane_never_stalls_unrelated_tokio_progress() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let control = Arc::new(FakeControl::new());
        let handle = Arc::new(SingleArchiveWalOwner::spawn(
            crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap(),
            control,
            Arc::new(FakePublication::new(next)),
        ));
        let stall = SqlStall::new();
        let entered = stall.entered.notified();
        let submission = tokio::spawn({
            let handle = Arc::clone(&handle);
            let stall = Arc::clone(&stall);
            async move {
                handle
                    .submit(stalled_plan(70, b"blocking-lane", stall))
                    .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered)
            .await
            .unwrap();
        let progressed = Arc::new(AtomicBool::new(false));
        tokio::time::timeout(std::time::Duration::from_secs(5), {
            let progressed = Arc::clone(&progressed);
            async move {
                tokio::task::yield_now().await;
                progressed.store(true, Ordering::SeqCst);
            }
        })
        .await
        .unwrap();
        assert!(progressed.load(Ordering::SeqCst));
        stall.release();
        assert_eq!(submission.await.unwrap().unwrap(), b"blocking-lane");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_stalled_lane_construction_never_blocks_tokio_and_scrubs_owner() {
        let (current, _) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let scratch = store.scratch_path_for_wal_owner_test();
        assert!(scratch.exists());
        let (entered_sender, entered) = oneshot::channel();
        let (release, release_receiver) = std::sync::mpsc::channel();
        let construction = tokio::spawn(async move {
            WalStoreLane::spawn_with_builder(
                move || {
                    let _ = entered_sender.send(());
                    release_receiver
                        .recv()
                        .map_err(|_| WalOwnerError::Persistence)?;
                    Ok(store)
                },
                LaneLiveness::new(),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::task::yield_now().await;
        })
        .await
        .unwrap();
        construction.abort();
        let _ = construction.await;
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while scratch.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled lane retained its staging file");
    }

    #[tokio::test]
    async fn lost_send_success_reopens_at_candidate_head_without_second_apply_or_send() {
        let (current, next) = authoritative_records();
        let publication = Arc::new(StatefulPublication::new(current.clone(), [next.clone()]));
        publication.lose_next_response();
        let control = Arc::new(FakeControl::new());
        let count = Arc::new(AtomicUsize::new(0));
        let first = SingleArchiveWalOwner::spawn(
            crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(
                WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap(),
            )
            .unwrap(),
            control.clone(),
            publication.clone(),
        );
        assert!(matches!(
            first
                .submit(counted_plan(
                    WalOperationKind::MediaCaptureEvent,
                    71,
                    b"lost-send",
                    count.clone(),
                ))
                .await,
            Err(WalOwnerError::Publication)
        ));
        assert_eq!(control.snapshot().0, WalPublicationStage::SendStarted);
        assert_eq!(publication.sends(), 1);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let trace_before_reopen = control.snapshot().1;
        drop(first);

        let reopened = SingleArchiveWalOwner::spawn(
            crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(
                WalOwnerStoreBinding::from_authenticated_witness(&next).unwrap(),
            )
            .unwrap(),
            control.clone(),
            publication.clone(),
        );
        assert!(matches!(
            reopened
                .submit(counted_plan(
                    WalOperationKind::MediaCaptureEvent,
                    71,
                    b"lost-send",
                    count.clone(),
                ))
                .await,
            Err(WalOwnerError::Publication)
        ));
        assert_eq!(control.snapshot().0, WalPublicationStage::Witnessed);
        let trace_after_reopen = control.snapshot().1;
        assert_eq!(
            &trace_after_reopen[..trace_before_reopen.len()],
            trace_before_reopen.as_slice()
        );
        assert_eq!(
            &trace_after_reopen[trace_before_reopen.len()..],
            ["recovered-witnessed"]
        );
        assert_eq!(publication.sends(), 1);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn one_owner_serializes_distinct_plan_types_and_kind_scoped_replay() {
        let (current, next) = authoritative_records();
        let next_next = next.with_candidate_root_for_test(
            RootReference::new(4, ObjectId::from_bytes([15; 16]), [16; 32]),
            next.root().owner_fencing_epoch(),
        );
        let publication = Arc::new(StatefulPublication::new(
            current.clone(),
            [next, next_next.clone()],
        ));
        let control = Arc::new(FakeControl::new());
        let handle = SingleArchiveWalOwner::spawn(
            crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(
                WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap(),
            )
            .unwrap(),
            control.clone(),
            publication.clone(),
        );
        assert_eq!(
            handle
                .submit(plan_kind(
                    WalOperationKind::MediaCaptureEvent,
                    72,
                    b"kind-a",
                ))
                .await
                .unwrap(),
            b"kind-a"
        );
        assert_eq!(
            handle
                .submit(alternate_plan(
                    WalOperationKind::CaptureSessionFinish,
                    72,
                    b"kind-b",
                ))
                .await
                .unwrap(),
            b"kind-b"
        );
        let checkpointed = handle.checkpointed_plaintext_for_test().await.unwrap();
        drop(handle);
        let handle = SingleArchiveWalOwner::spawn(
            crate::store::SingleArchiveWalStoreOwner::from_wal_owner_test_plaintext(
                WalOwnerStoreBinding::from_authenticated_witness(&next_next).unwrap(),
                checkpointed,
            )
            .unwrap(),
            control.clone(),
            publication.clone(),
        );
        let trace_before = control.snapshot().1;
        assert_eq!(
            handle
                .submit(plan_kind(
                    WalOperationKind::MediaCaptureEvent,
                    72,
                    b"kind-a",
                ))
                .await
                .unwrap(),
            b"kind-a"
        );
        assert_eq!(control.snapshot().1, trace_before);
        assert_eq!(publication.sends(), 2);
        assert!(matches!(
            handle
                .submit(plan_kind(
                    WalOperationKind::MediaCaptureEvent,
                    72,
                    b"kind-a-substituted",
                ))
                .await,
            Err(WalOwnerError::Conflict)
        ));
        assert_eq!(control.snapshot().1, trace_before);
        assert_eq!(publication.sends(), 2);
    }

    #[tokio::test]
    async fn alternate_artifact_segment_count_rejects_before_candidate_send() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let control = Arc::new(FakeControl::new().with_segment_count(2));
        let handle = SingleArchiveWalOwner::spawn(
            crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap(),
            control.clone(),
            Arc::new(FakePublication::new(next)),
        );
        assert!(matches!(
            handle.submit(plan(73, b"split-count")).await,
            Err(WalOwnerError::Conflict | WalOwnerError::Malformed)
        ));
        let trace = control.snapshot().1;
        assert!(!trace.contains(&"candidate"));
        assert!(!trace.contains(&"send-started"));
        assert!(!trace.contains(&"witnessed"));
    }

    #[tokio::test]
    async fn rollback_and_fingerprint_conflict_never_publish() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let control = Arc::new(FakeControl::new());
        let publication = Arc::new(FakePublication::new(next));
        let handle = SingleArchiveWalOwner::spawn(store, control.clone(), publication);

        assert!(matches!(
            handle.submit(failing_plan(42, b"rollback")).await,
            Err(WalOwnerError::Conflict)
        ));
        assert_eq!(control.snapshot().1, ["prepare"]);
        assert!(handle.submit(plan(42, b"rollback")).await.is_ok());
        let before_conflict = control.snapshot().1;
        assert!(matches!(
            handle.submit(plan(42, b"different-request")).await,
            Err(WalOwnerError::Conflict)
        ));
        assert_eq!(control.snapshot().1, before_conflict);
    }

    #[tokio::test]
    async fn caller_cancellation_after_local_commit_does_not_cancel_publication() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let control = Arc::new(FakeControl::with_capture_stall(true));
        let publication = Arc::new(FakePublication::new(next));
        let handle = Arc::new(SingleArchiveWalOwner::spawn(
            store,
            control.clone(),
            publication,
        ));
        let caller = tokio::spawn({
            let handle = handle.clone();
            async move { handle.submit(plan(41, b"cancel-after-commit")).await }
        });
        control.captured.notified().await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        control.release_capture.add_permits(1);
        let mut attempts = 0;
        while control.snapshot().0 != WalPublicationStage::Witnessed && attempts < 100 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            attempts += 1;
        }
        assert_eq!(control.snapshot().0, WalPublicationStage::Witnessed);
        let replay = handle.submit(plan(41, b"cancel-after-commit")).await;
        assert_eq!(replay.unwrap(), b"cancel-after-commit");
    }

    #[tokio::test]
    async fn replay_lookup_is_query_only_and_any_escape_or_error_poisons_before_ack() {
        for attack in [
            LookupAttack::DirectWrite,
            LookupAttack::DisableGuardThenWrite,
            LookupAttack::SchemaWrite,
            LookupAttack::ReturnSubstitutedResult,
        ] {
            let (current, next) = authoritative_records();
            let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
            let store =
                crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
            let control = Arc::new(FakeControl::new());
            let publication = Arc::new(FakePublication::new(next));
            let handle = SingleArchiveWalOwner::spawn(store, control.clone(), publication);
            assert_eq!(
                handle.submit(plan(50, b"retained-result")).await.unwrap(),
                b"retained-result"
            );
            assert!(matches!(
                handle
                    .submit(attacking_lookup_plan(50, b"retained-result", attack))
                    .await,
                Err(WalOwnerError::Corrupt | WalOwnerError::Poisoned)
            ));
            let trace = control.snapshot().1;
            assert_eq!(trace.last(), Some(&"witnessed"));
        }
    }

    #[tokio::test]
    async fn reads_observe_only_settled_state_and_mutating_reads_poison_the_lane() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let control = Arc::new(FakeControl::new());
        let publication = Arc::new(FakePublication::new(next));
        let handle = SingleArchiveWalOwner::spawn(store, control, publication);

        // A read after an acknowledged submit observes exactly the settled
        // row: the actor queue finishes the full apply-settle-advance ladder
        // before dispatching the read to the lane.
        handle.submit(plan(42, b"settled-read")).await.unwrap();
        let values = handle
            .read(|connection| {
                let mut statement =
                    connection.prepare("SELECT value FROM wal_owner_test_values ORDER BY rowid")?;
                let rows: Vec<Vec<u8>> = statement
                    .query_map([], |row| row.get(0))?
                    .collect::<std::result::Result<_, _>>()?;
                Ok(rows)
            })
            .await
            .unwrap()
            .unwrap();
        assert!(values.iter().any(|value| value == b"settled-read"));

        // An ordinary mutation attempt inside a read fails under SQLite
        // query_only as the closure's own error, without harming the lane.
        let refused = handle
            .read(|connection| {
                connection.execute(
                    "INSERT INTO wal_owner_test_values(value) VALUES (x'99')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(refused.is_err());
        // The refused mutation left the guard intact: the lane still serves
        // settled reads (publication-independent proof it was not poisoned).
        assert!(handle.read(|_| Ok(())).await.unwrap().is_ok());

        // A read that defeats the pragma guard and actually mutates trips the
        // fingerprint and poisons the lane: a write bypassing the WAL ladder
        // can never be settled, so nothing may be served after it.
        assert!(matches!(
            handle
                .read(|connection| {
                    connection.pragma_update(None, "query_only", false)?;
                    connection.execute(
                        "INSERT INTO wal_owner_test_values(value) VALUES (x'aa')",
                        [],
                    )?;
                    Ok(())
                })
                .await,
            Err(WalOwnerError::Corrupt)
        ));
        assert!(matches!(
            handle.read(|_| Ok(())).await,
            Err(WalOwnerError::Poisoned)
        ));
        assert!(matches!(
            handle.submit(plan(44, b"post-poison")).await,
            Err(WalOwnerError::Poisoned)
        ));
    }

    #[tokio::test]
    async fn a_superseded_owner_stops_instead_of_inviting_an_endless_retry() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let control = Arc::new(FakeControl::new());
        let publication = Arc::new(FakePublication::new(next));
        let handle = SingleArchiveWalOwner::spawn(store, control, Arc::clone(&publication));

        assert!(handle.read(|_| Ok(())).await.unwrap().is_ok());

        // The provider ANSWERS, and the exact lease is someone else's. That
        // is a completed takeover, not a blip: this owner can never become
        // authoritative again.
        publication.supersede_fresh();
        let served = Arc::new(AtomicBool::new(false));
        let served_in_closure = Arc::clone(&served);
        assert!(matches!(
            handle
                .read(move |_| {
                    served_in_closure.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await,
            Err(WalOwnerError::Superseded)
        ));
        assert!(
            !served.load(Ordering::SeqCst),
            "a superseded owner must never execute a read against its frozen state"
        );

        // Superseded, not Conflict: mapping this to a retryable conflict is
        // what left the caller retrying forever against a lease it will never
        // hold again.
        assert!(handle.submit(plan(52, b"after-supersede")).await.is_err());
    }

    #[tokio::test]
    async fn a_provider_blip_must_not_kill_a_rightful_owner() {
        // The property the supersede split exists to PRESERVE. A provider
        // that cannot be reached says nothing about who owns the lease, so
        // the owner must survive it and serve again once the provider
        // recovers. If this ever starts failing, the split has collapsed the
        // two cases back together in the dangerous direction.
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let control = Arc::new(FakeControl::new());
        let publication = Arc::new(FakePublication::new(next));
        let handle = SingleArchiveWalOwner::spawn(store, control, Arc::clone(&publication));

        publication.reject_fresh();
        assert!(matches!(
            handle.read(|_| Ok(())).await,
            Err(WalOwnerError::Conflict)
        ));

        // The provider recovers. The lane is still alive and still ours.
        publication.reject_fresh.store(false, Ordering::SeqCst);
        assert!(
            handle.read(|_| Ok(())).await.unwrap().is_ok(),
            "a transient provider failure must not permanently kill the lane"
        );
    }

    #[tokio::test]
    async fn a_fenced_out_owner_refuses_reads_instead_of_serving_stale_state() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let control = Arc::new(FakeControl::new());
        let publication = Arc::new(FakePublication::new(next));
        let handle = SingleArchiveWalOwner::spawn(store, control, Arc::clone(&publication));

        // While this owner still authenticates the live head, reads serve.
        assert!(handle.read(|_| Ok(())).await.unwrap().is_ok());

        // Another process reacquires after this owner's idle lease expires:
        // the live head no longer authenticates this owner's binding. Reads
        // must refuse rather than answer from frozen local SQLite — before
        // this gate a fenced-out owner served unboundedly stale state as the
        // settled authority, with no error and no staleness bound.
        publication.reject_fresh();
        assert!(matches!(
            handle.read(|_| Ok(())).await,
            Err(WalOwnerError::Conflict)
        ));

        // The refusal is persistent, and — the property that matters — the
        // read closure NEVER runs, so no stale row can escape.
        //
        // Note what `reject_fresh` actually stages: the provider REFUSING,
        // which says nothing about who owns the lease. So Conflict without
        // poisoning is right here, and a rightful owner survives it (see
        // `a_provider_blip_must_not_kill_a_rightful_owner`). A provider that
        // answers with someone else's lease is the other case entirely, and
        // it is terminal — see
        // `a_superseded_owner_stops_instead_of_inviting_an_endless_retry`.
        let served = Arc::new(AtomicBool::new(false));
        let served_in_closure = Arc::clone(&served);
        assert!(matches!(
            handle
                .read(move |_| {
                    served_in_closure.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await,
            Err(WalOwnerError::Conflict)
        ));
        assert!(
            !served.load(Ordering::SeqCst),
            "a fenced-out owner must never execute a read against its frozen state"
        );
        // Writes were already fenced and stay fenced.
        assert!(handle.submit(plan(51, b"after-fence")).await.is_err());
    }

    #[tokio::test]
    async fn control_settlement_failure_never_acknowledges_and_poisons_the_lane() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let control = Arc::new(FakeControl::new().with_witnessed_failure());
        let publication = Arc::new(FakePublication::new(next));
        let handle = SingleArchiveWalOwner::spawn(store, control.clone(), publication);

        // The witness CAS succeeded but the durable control settlement did
        // not: the submitter must observe the failure, never its decoded
        // output, exactly as the Phase-2 admission's
        // acknowledge-after-witness-settlement fact requires.
        assert!(matches!(
            handle.submit(plan(42, b"settlement-loss")).await,
            Err(WalOwnerError::Persistence)
        ));
        let (_, trace) = control.snapshot();
        assert!(trace.contains(&"witnessed-refused"));
        assert!(!trace.contains(&"witnessed"));

        // The lane is poisoned: no later mutation can be acknowledged
        // through this owner, forcing a fresh exact recovery.
        assert!(matches!(
            handle.submit(plan(43, b"after-loss")).await,
            Err(WalOwnerError::Poisoned)
        ));
    }

    #[tokio::test]
    async fn terminal_send_failure_requires_manual_and_never_acknowledges() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let control = Arc::new(FakeControl::new());
        let publication = Arc::new(FakePublication::new(next));
        publication.fail_send_terminal();
        let handle = SingleArchiveWalOwner::spawn(store, control.clone(), publication);

        // A non-publication send error is definitive: the attempt goes to
        // ManualRequired and the submitter never receives its output.
        assert!(matches!(
            handle.submit(plan(44, b"terminal-send")).await,
            Err(WalOwnerError::Corrupt)
        ));
        let (stage, trace) = control.snapshot();
        assert_eq!(stage, WalPublicationStage::ManualRequired);
        assert!(trace.contains(&"manual"));
        assert!(!trace.contains(&"witnessed"));
    }

    /// Structural acknowledgement-ordering pin: the publish path's erased
    /// result may release only after send, durable control settlement, drain
    /// settlement, and store advance, and the only other release site is the
    /// already-settled replay lookup. A reordering that acknowledges from the
    /// local SQLite commit alone must fail this pin before any review.
    #[test]
    fn acknowledgement_release_is_sequenced_strictly_after_witness_settlement() {
        let source = include_str!("archive_v3_wal_owner.rs");
        let release_needle = concat!("result.", "release()");
        let publish_start = source
            .find(concat!("async fn publish_", "applied("))
            .unwrap();
        let publish_body = &source[publish_start..];
        let publish_end = publish_body.find(concat!("\n", "    }")).unwrap();
        let publish_body = &publish_body[..publish_end];
        let send = publish_body.find(concat!("send_", "candidate(")).unwrap();
        let witnessed = publish_body.find(concat!("record_", "witnessed(")).unwrap();
        let settle = publish_body.find(concat!("drain.", "settle(")).unwrap();
        let advance = publish_body.find(concat!("store.", "advance(")).unwrap();
        let release = publish_body.find(release_needle).unwrap();
        assert!(send < witnessed, "settlement must follow the witness send");
        assert!(
            witnessed < settle,
            "drain settles only from control settlement"
        );
        assert!(
            settle < advance,
            "the lane advances only after drain settlement"
        );
        assert!(
            advance < release,
            "acknowledgement releases only after advance"
        );

        // Exactly two release sites exist in the production view: the
        // settled-replay lookup and the post-settlement publish path.
        let production = {
            let mut chars: Vec<char> = source.chars().collect();
            let marker = concat!("mod ", "tests {");
            let tests_start = source.find(marker).unwrap();
            chars.truncate(tests_start);
            chars.into_iter().collect::<String>()
        };
        assert_eq!(production.matches(release_needle).count(), 2);
        let replay = production
            .find(concat!("WalStoreReplay::", "Present(result)"))
            .unwrap();
        let replay_release = production[replay..].find(release_needle).unwrap() + replay;
        let publish_release = publish_start + release;
        assert!(replay_release < publish_release);
    }

    #[tokio::test]
    async fn witnessed_control_without_exact_local_result_never_reapplies_or_acknowledges() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let control = Arc::new(FakeControl::new());
        let first = SingleArchiveWalOwner::spawn(
            crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap(),
            control.clone(),
            Arc::new(FakePublication::new(next.clone())),
        );
        assert_eq!(
            first.submit(plan(51, b"terminal-result")).await.unwrap(),
            b"terminal-result"
        );
        drop(first);

        let reopened_binding = WalOwnerStoreBinding::from_authenticated_witness(&next).unwrap();
        let reopened = SingleArchiveWalOwner::spawn(
            crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(reopened_binding).unwrap(),
            control.clone(),
            Arc::new(FakePublication::new(next)),
        );
        let before = control.snapshot().1;
        assert!(matches!(
            reopened.submit(plan(51, b"terminal-result")).await,
            Err(WalOwnerError::Corrupt)
        ));
        let after = control.snapshot().1;
        assert_eq!(after, before);
    }

    #[tokio::test]
    async fn replay_requires_fresh_exact_active_wal_authoritative_head_before_ack() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let control = Arc::new(FakeControl::new());
        let publication = Arc::new(FakePublication::new(next));
        let handle = SingleArchiveWalOwner::spawn(
            crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap(),
            control.clone(),
            publication.clone(),
        );
        assert_eq!(
            handle.submit(plan(52, b"fresh-only")).await.unwrap(),
            b"fresh-only"
        );
        let before = control.snapshot().1;
        publication.reject_fresh();
        assert!(matches!(
            handle.submit(plan(52, b"fresh-only")).await,
            Err(WalOwnerError::Conflict)
        ));
        let after = control.snapshot().1;
        assert_eq!(after, before);
    }

    #[test]
    fn fresh_head_proof_rejects_deletion_root_key_and_fence_substitution() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        assert!(matches!(
            AuthenticatedWalOwnerHead::for_test(&binding, current.clone()),
            Ok(FreshHead::Authenticated(_))
        ));
        // A substituted record must never authenticate. Rejection now takes
        // one of two shapes, and the shape is pinned per case rather than
        // left to "not authenticated", so a case that silently migrates from
        // one arm to the other is caught:
        //
        // - a record that fails witness authentication outright is an `Err`
        // - a record that authenticates but describes someone else's lease is
        //   `Superseded`, which is terminal and poisons the lane
        //
        // Only an authenticated witness can reach `Superseded`, so a forged
        // record cannot use the poison arm to kill a rightful owner.
        let tombstoned = current.with_deletion_for_test(DeletionState::Tombstoned);
        assert!(
            AuthenticatedWalOwnerHead::for_test(&binding, tombstoned).is_err(),
            "a deletion-marked record must fail authentication, not merely lose the lease"
        );

        for superseding in [
            // The root advanced past ours: someone else wrote.
            next,
            // The key registry rotated out from under this binding.
            current.with_registry_for_test(KeyRegistryReference::new(
                KeyEpoch::from_bytes([70; 16]),
                current.registry().rotation_generation() + 1,
                ObjectId::from_bytes([71; 16]),
                [72; 32],
            )),
            // The fence moved on: a completed takeover.
            current.with_next_fencing_epoch_for_test(
                current.root().owner_fencing_epoch().saturating_add(2),
            ),
        ] {
            assert!(matches!(
                AuthenticatedWalOwnerHead::for_test(&binding, superseding),
                Ok(FreshHead::Superseded)
            ));
        }
    }

    #[test]
    fn candidates_attempts_and_artifacts_reject_substitution_and_zero_facts() {
        assert!(WalOwnerAttempt::from_control(
            crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
            WalOwnerId::from_control_bytes(
                crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
                [1; 16]
            )
            .unwrap(),
            WalOwnerInstanceId::from_control_bytes(
                crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
                [9; 16],
            )
            .unwrap(),
            ShadowSessionId::from_bytes([2; 16]),
            ShadowAttemptId::from_bytes([3; 16]),
            1,
            Some(4),
            WalPublicationStage::Prepared,
            1,
            None,
            None,
            None,
            None,
            None,
        )
        .is_err());
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let context = WalOwnerContext::from_store(
            WalOwnerStoreContext::for_test(),
            binding.clone(),
            WalOperationIdentity::for_test(WalOperationKind::MediaCaptureEvent, 4, 5),
            attempt(
                WalOwnerInstanceId::from_control_bytes(
                    crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
                    [9; 16],
                )
                .unwrap(),
                WalPublicationStage::Prepared,
                1,
                None,
                None,
                None,
                None,
            )
            .owner_id(),
            WalOwnerInstanceId::from_control_bytes(
                crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
                [9; 16],
            )
            .unwrap(),
            CaptureStreamId::from_test_bytes([6; 16]),
            attempt(
                WalOwnerInstanceId::from_control_bytes(
                    crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
                    [9; 16],
                )
                .unwrap(),
                WalPublicationStage::Prepared,
                1,
                None,
                None,
                None,
                None,
            ),
            7,
        )
        .unwrap();
        assert!(WalPublicationCandidate::from_control_persisted(
            crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
            &binding,
            context.identity(),
            context.owner_id(),
            context.owner_instance_id(),
            context.session_id(),
            context.attempt_id(),
            context.attempt(),
            7,
            [1; 32],
            1,
            1,
            1,
            [1; 32],
            next.root().root().sequence(),
            ObjectId::from_bytes([0; 16]),
            next.root().root().ciphertext_hash(),
            next.root().owner_fencing_epoch(),
            *binding.witness_bytes(),
            [1; 32],
        )
        .is_err());
        assert!(WalPublicationArtifact::from_authority(
            &context,
            0,
            &ObjectContext::new(
                context.binding().archive_id(),
                context.binding().database_epoch(),
                context.binding().key_epoch(),
                ObjectRole::RootV3,
                LogicalLocation::Root { root_seq: 1 },
                ObjectId::from_bytes([0; 16]),
                None,
            )
            .unwrap(),
            [1; 32],
        )
        .is_err());
    }

    #[test]
    fn process_settlement_binding_changes_with_capture_stream_but_not_durable_tuple() {
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let instance = WalOwnerInstanceId::from_control_bytes(
            crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
            [61; 16],
        )
        .unwrap();
        let durable_attempt = || {
            attempt(
                instance,
                WalPublicationStage::Prepared,
                1,
                None,
                None,
                None,
                None,
            )
        };
        let identity = WalOperationIdentity::for_test(WalOperationKind::MediaCaptureEvent, 62, 63);
        let first = WalOwnerContext::from_store(
            WalOwnerStoreContext::for_test(),
            binding.clone(),
            identity,
            durable_attempt().owner_id(),
            instance,
            CaptureStreamId::from_test_bytes([64; 16]),
            durable_attempt(),
            1,
        )
        .unwrap();
        let second = WalOwnerContext::from_store(
            WalOwnerStoreContext::for_test(),
            binding.clone(),
            identity,
            durable_attempt().owner_id(),
            instance,
            CaptureStreamId::from_test_bytes([65; 16]),
            durable_attempt(),
            1,
        )
        .unwrap();
        assert_eq!(first.durable_commitment(), second.durable_commitment());
        assert_ne!(first.commitment(), second.commitment());

        let capture = [66; 32];
        let artifact_set = AuthenticatedWalArtifactSet::from_control_validation(
            crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
            &first,
            capture,
            1,
            1,
            1,
            [67; 32],
        )
        .unwrap();
        let candidate = WalPublicationCandidate::for_persistence_test(
            &first,
            capture,
            1,
            1,
            next.root(),
            artifact_set,
        )
        .unwrap();
        let next_binding = WalOwnerStoreBinding::from_authenticated_witness(&next).unwrap();
        let settlement = AuthenticatedWalSettlement::from_control_cas(
            crate::cp::control_store::WalOwnerPersistenceContext::for_test(),
            &first,
            capture,
            &candidate,
            next_binding,
        )
        .unwrap();
        assert!(settlement.authenticates(&first, capture));
        assert!(!settlement.authenticates(&second, capture));
    }

    #[test]
    fn authenticated_staging_rejects_post_proof_file_replacement_before_writable_open() {
        use std::os::unix::fs::PermissionsExt;

        fn private_sqlite(path: &std::path::Path) {
            let connection = rusqlite::Connection::open(path).unwrap();
            connection
                .execute_batch("CREATE TABLE private_state(value BLOB NOT NULL);")
                .unwrap();
            drop(connection);
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let alternate_binding = WalOwnerStoreBinding::from_authenticated_witness(&next).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let capture = crate::store::StoreShadowCapture::shared_for_test();

        let wrong_binding_path = directory.path().join("wal-owner-wrong-binding.sqlite");
        private_sqlite(&wrong_binding_path);
        let wrong_binding_staged =
            crate::archive_v3_shadow_parity::AuthenticatedWalOwnerStaging::for_test(
                wrong_binding_path,
                &binding,
                0,
            )
            .unwrap();
        assert!(
            crate::store::SingleArchiveWalStoreOwner::from_authenticated_staging(
                WalOwnerStoreContext::for_test(),
                wrong_binding_staged,
                alternate_binding,
                capture.clone(),
            )
            .is_err()
        );

        let path = directory.path().join("wal-owner-staging.sqlite");
        private_sqlite(&path);
        let staged = crate::archive_v3_shadow_parity::AuthenticatedWalOwnerStaging::for_test(
            path.clone(),
            &binding,
            0,
        )
        .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let final_index = bytes.len() - 1;
        bytes[final_index] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            crate::store::SingleArchiveWalStoreOwner::from_authenticated_staging(
                WalOwnerStoreContext::for_test(),
                staged,
                binding,
                capture,
            )
            .is_err()
        );
    }

    #[test]
    fn checkpoint_source_consumes_store_owner_closes_sidecars_and_scrubs_on_drop() {
        use std::os::unix::fs::PermissionsExt;

        let (current, _) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wal-owner-checkpoint-source.sqlite");
        let schema_version = crate::store::initialize_wal_owner_store_for_test(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let staged = crate::archive_v3_shadow_parity::AuthenticatedWalOwnerStaging::for_test(
            path.clone(),
            &binding,
            schema_version,
        )
        .unwrap();
        let mut owner = crate::store::SingleArchiveWalStoreOwner::from_authenticated_staging(
            WalOwnerStoreContext::for_test(),
            staged,
            binding.clone(),
            crate::store::StoreShadowCapture::shared_for_test(),
        )
        .unwrap();
        let mut source = owner.take_checkpoint_source().unwrap();
        assert!(owner.is_poisoned());
        let token = WalCheckpointSourceContext::for_test();
        let (length, hash, schema) = source.authenticated_facts(token, &binding).unwrap();
        assert!(length > 0);
        assert_ne!(hash, [0; 32]);
        assert_eq!(schema, schema_version);
        let mut header = [0_u8; 16];
        source.read_checkpoint_exact(token, 0, &mut header).unwrap();
        assert_eq!(&header, b"SQLite format 3\0");
        let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
        let shm = std::path::PathBuf::from(format!("{}-shm", path.display()));
        assert!(!wal.exists());
        assert!(!shm.exists());
        drop(source);
        assert!(!path.exists());
    }

    #[test]
    fn public_surface_stays_inactive_and_provider_sealed() {
        let source = include_str!("archive_v3_wal_owner.rs");
        let publisher = include_str!("archive_v3_wal_owner/publisher.rs");
        for forbidden in [
            concat!("impl WalPublicationAuthority for Fire", "store"),
            concat!("impl WalPublicationAuthority for ", "Gcs"),
            concat!("pub struct SingleArchive", "WalOwner"),
            concat!("pub(crate) struct SingleArchive", "WalOwner"),
            concat!("crate::", "main"),
            concat!("delete_", "exact"),
            concat!("enumer", "ate("),
            concat!("list_", "objects"),
            concat!("Store::", "new"),
        ] {
            assert!(!source.contains(forbidden), "found forbidden {forbidden}");
        }
        for forbidden in [
            concat!("pub(crate) struct SingleArchive", "WalPublisher"),
            concat!("pub fn start", "("),
            concat!("Store::", "new"),
            concat!("delete_", "exact"),
            concat!("list_", "objects"),
            concat!("crate::", "main"),
            concat!("SingleArchiveWalStoreOwner::from_authenticated_", "staging"),
        ] {
            assert!(
                !publisher.contains(forbidden),
                "publisher exposed forbidden {forbidden}"
            );
        }
        assert!(source.contains(concat!("spawn_", "authenticated")));
        assert!(source.contains(concat!(
            "settlement.into_",
            "lane(self.store.liveness()).await"
        )));
        assert_eq!(
            source
                .matches(concat!("send(WalStoreLaneCommand::", "Read"))
                .count(),
            1,
            "lane reads must dispatch only through the actor-called wrapper"
        );
    }

    // ── Group C: in-process relaunch trigger and proof of death ─────────────

    async fn terminal_within(handle: &WalOwnerHandle, label: &str) {
        let deadline = std::time::Duration::from_secs(10);
        tokio::time::timeout(deadline, async {
            while !handle.is_terminal() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{label}: the authority never became terminal"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lane_thread_panic_makes_the_authority_terminal() {
        // Before the lane's exit guard existed this was a silent, total,
        // in-process outage: the trailing `thread_poisoned` store was skipped
        // by the unwind, `is_poisoned()` stayed false, the actor loop's poison
        // check never broke, and the actor future never completed. Every
        // subsequent send failed with `Poisoned` because the receiver had died
        // with the thread, and nothing in the process could observe it.
        let (current, next) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let handle = SingleArchiveWalOwner::spawn(
            store,
            Arc::new(FakeControl::new()),
            Arc::new(FakePublication::new(next)),
        );
        assert!(!handle.is_terminal(), "a fresh authority is not terminal");

        let panicked = handle.submit(plan(91, LANE_PANIC_SENTINEL)).await;
        assert!(
            matches!(panicked, Err(WalOwnerError::Poisoned)),
            "the panicked lane must refuse rather than acknowledge: {panicked:?}"
        );

        // The actor loop's poison check now sees the raised flag and breaks on
        // that very message, so the drop guard inside the actor future raises
        // the termination flag.
        terminal_within(&handle, "lane panic").await;

        // And the successor may be constructed: the actor task resolved and
        // the panicked lane thread left the census after its store owner was
        // dropped, so the SQLite connection is closed and the capture
        // registration is retired and scrubbed.
        handle
            .join_terminated(std::time::Duration::from_secs(10))
            .await
            .expect("a panicked lane is provably dead");

        // Poison remains reachable and fail-closed: the lane is still refusing.
        assert!(matches!(
            handle.submit(plan(92, b"after-the-panic")).await,
            Err(WalOwnerError::Poisoned)
        ));
    }

    struct WedgedCheckpointPublication {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        pending: AtomicBool,
    }

    impl WedgedCheckpointPublication {
        fn new() -> Self {
            Self {
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                pending: AtomicBool::new(true),
            }
        }
    }

    impl sealed::PublicationAuthority for WedgedCheckpointPublication {}

    #[async_trait]
    impl WalPublicationAuthority for WedgedCheckpointPublication {
        async fn read_fresh_head(&self, binding: &WalOwnerStoreBinding) -> Result<FreshHead> {
            let observed = WitnessRecord::decode(binding.witness_bytes())
                .map_err(|_| WalOwnerError::Corrupt)?;
            AuthenticatedWalOwnerHead::from_authority(binding, observed)
        }

        async fn checkpoint_required(&self, _binding: &WalOwnerStoreBinding) -> Result<bool> {
            Ok(false)
        }

        async fn checkpoint_pending(&self, _binding: &WalOwnerStoreBinding) -> Result<bool> {
            Ok(self.pending.swap(false, Ordering::SeqCst))
        }

        async fn refresh_live_binding(
            &self,
            binding: &WalOwnerStoreBinding,
        ) -> Result<WalOwnerStoreBinding> {
            Ok(binding.clone())
        }

        async fn refresh_checkpoint_source_binding(
            &self,
            binding: &WalOwnerStoreBinding,
            _owner_instance_id: WalOwnerInstanceId,
        ) -> Result<WalOwnerStoreBinding> {
            Ok(binding.clone())
        }

        async fn checkpoint_and_recover(
            &self,
            _binding: &WalOwnerStoreBinding,
            _owner_instance_id: WalOwnerInstanceId,
            _source: crate::store::WalOwnerCheckpointSource,
        ) -> Result<WalCheckpointSettlement> {
            // The actor is now mid-root-advance: the lane has been consumed
            // and its poison flag raised, and the successor lane does not
            // exist yet.
            self.entered.notify_waiters();
            self.release.notified().await;
            // A transient publication failure here is the second, independent
            // terminal path (`self.store = settlement.into_lane(..).await?`
            // early-returning onto the consumed, exited lane).
            Err(WalOwnerError::Publication)
        }

        async fn create_candidate(
            &self,
            _context: &WalOwnerContext,
            _captured: &CapturedWalCommit,
            _control: &dyn WalOwnerControl,
        ) -> Result<WalPublicationCandidate> {
            Err(WalOwnerError::Conflict)
        }

        async fn send_candidate(
            &self,
            _context: &WalOwnerContext,
            _candidate: &WalPublicationCandidate,
        ) -> Result<WitnessedWalCandidate> {
            Err(WalOwnerError::Conflict)
        }

        async fn resume_candidate(
            &self,
            _binding: &WalOwnerStoreBinding,
            _identity: WalOperationIdentity,
            _attempt: &WalOwnerAttempt,
            _candidate: &WalPublicationCandidate,
        ) -> Result<WitnessedWalCandidate> {
            Err(WalOwnerError::Conflict)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_checkpoint_in_flight_never_makes_the_authority_terminal() {
        // The poison flag is NOT a safe relaunch trigger.
        // `WalStoreLaneCommand::Checkpoint` raises it unconditionally on the
        // ordinary checkpoint path, and `take_checkpoint_source` raises it on
        // its SUCCESS path, while the actor goes on to `checkpoint_and_recover`
        // and a full witness root advance. A trigger derived from the flag
        // would fire there and spawn a second owner over a live one.
        let source = include_str!("archive_v3_wal_owner.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        let checkpoint_arm = &production[production
            .find("WalStoreLaneCommand::Checkpoint { response } => {")
            .expect("the lane checkpoint arm moved")..];
        let checkpoint_arm = &checkpoint_arm[..checkpoint_arm.find("break;").unwrap()];
        assert!(
            checkpoint_arm.contains("thread_poisoned.store(true, Ordering::Release);")
                && !checkpoint_arm.contains("if store.is_poisoned()"),
            "the checkpoint arm must still raise the poison flag unconditionally, \
             which is exactly why the flag cannot be the relaunch trigger"
        );

        let (current, _) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let store = crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap();
        let publication = Arc::new(WedgedCheckpointPublication::new());
        let entered = publication.entered.notified();
        tokio::pin!(entered);
        entered.as_mut().enable();
        let handle = Arc::new(SingleArchiveWalOwner::spawn(
            store,
            Arc::new(FakeControl::new()),
            Arc::clone(&publication),
        ));
        let submission = tokio::spawn({
            let handle = Arc::clone(&handle);
            async move { handle.submit(plan(93, b"checkpointing")).await }
        });

        tokio::time::timeout(std::time::Duration::from_secs(10), entered)
            .await
            .expect("the actor reaches the root advance");
        // The lane is poisoned right now and the actor is still working. A
        // relaunch here would construct a second owner for this archive.
        assert!(
            !handle.is_terminal(),
            "an in-flight checkpoint must never look terminal"
        );

        publication.release.notify_waiters();
        assert!(matches!(
            submission.await.unwrap(),
            Err(WalOwnerError::Publication)
        ));
        // Only once the actor itself has finished is the slot replaceable.
        terminal_within(&handle, "post-checkpoint").await;
        handle
            .join_terminated(std::time::Duration::from_secs(10))
            .await
            .expect("the consumed lane is provably dead");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn join_terminated_refuses_a_wedged_lane_and_never_proves_death() {
        // Fencing is absolute: a relaunch that races the dying owner must be
        // impossible, not merely unlikely. `is_terminal()` alone does not
        // establish that — the actor future can be over while a blocking lane
        // thread still holds the writable SQLite connection and the capture
        // registration. Refusing is always safe; forcing never is.
        let (handle, release) = WalOwnerHandle::stuck_lane_for_relaunch_test();
        terminal_within(&handle, "wedged lane").await;
        assert!(handle.is_terminal());
        let refused = handle
            .join_terminated(std::time::Duration::from_millis(250))
            .await;
        assert!(
            matches!(refused, Err(WalOwnerError::Persistence)),
            "a wedged lane must refuse the proof of death: {refused:?}"
        );
        // The refusal is not a one-shot: nothing was detached, so once the
        // lane really leaves, the same handle can still be proven dead.
        release.release();
        handle
            .join_terminated(std::time::Duration::from_secs(10))
            .await
            .expect("the released lane is provably dead");
    }

    #[tokio::test]
    async fn a_terminated_authority_is_provably_dead_and_repeatably_joinable() {
        let handle = WalOwnerHandle::terminated_for_relaunch_test().await;
        assert!(handle.is_terminal());
        for _ in 0..3 {
            handle
                .join_terminated(std::time::Duration::from_secs(10))
                .await
                .expect("joining an already-reaped actor is idempotent");
        }
    }

    #[test]
    fn the_relaunch_trigger_is_never_derived_from_the_poison_flag() {
        let source = include_str!("archive_v3_wal_owner.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        let bodies: Vec<&str> = production
            .match_indices("pub(crate) fn is_terminal(&self) -> bool {")
            .map(|(offset, _)| {
                let tail = &production[offset..];
                &tail[..tail.find('}').unwrap()]
            })
            .collect();
        assert!(!bodies.is_empty(), "the trigger moved");
        assert!(
            bodies
                .iter()
                .any(|body| body.contains("self.terminated.load(Ordering::Acquire)")),
            "the trigger must read the actor termination flag"
        );
        for body in &bodies {
            assert!(
                !body.contains("poison"),
                "the trigger must never consult the poison flag: {body}"
            );
        }
        // The flag is raised by a drop guard, so it is set on completion AND
        // on unwind, and it is monotone.
        for required in [
            "struct ActorTerminationOnExit(Arc<AtomicBool>);",
            "let _terminated = ActorTerminationOnExit(actor_terminated);",
            "struct LanePoisonOnExit(Arc<AtomicBool>);",
            "let _exit = LanePoisonOnExit(Arc::clone(&thread_poisoned));",
        ] {
            assert!(production.contains(required), "missing {required}");
        }
        // ACCEPTED-5: `spawn_failed` loops forever and is production-unreachable.
        // Every `SingleArchiveWalOwner::spawn(` call site must stay in tests.
        let boundary = source.find(concat!("mod ", "tests")).unwrap();
        for offset in source.match_indices("SingleArchiveWalOwner::spawn(") {
            assert!(
                offset.0 > boundary,
                "SingleArchiveWalOwner::spawn was wired into production"
            );
        }
    }

    #[tokio::test]
    async fn a_checkpoint_successor_inherits_the_lane_census() {
        // A successor lane must inherit the predecessor's census. Minting a
        // fresh one would let a checkpoint erase a still-running predecessor
        // from the proof of death — the exact hole a per-launch JoinHandle
        // would leave.
        let source = include_str!("archive_v3_wal_owner.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        assert_eq!(
            production
                .matches("settlement.into_lane(self.store.liveness()).await?")
                .count(),
            2,
            "both checkpoint arms must hand the successor the inherited census"
        );

        let (current, _) = authoritative_records();
        let binding = WalOwnerStoreBinding::from_authenticated_witness(&current).unwrap();
        let liveness = LaneLiveness::new();
        assert_eq!(liveness.live_for_test(), 0);
        {
            let lane = WalStoreLane::spawn(
                crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding.clone())
                    .unwrap(),
                liveness.clone(),
            )
            .unwrap();
            assert_eq!(liveness.live_for_test(), 1);
            let successor = WalStoreLane::spawn(
                crate::store::SingleArchiveWalStoreOwner::for_wal_owner_test(binding).unwrap(),
                lane.liveness(),
            )
            .unwrap();
            // Two lanes of one authority are alive at once, and the census
            // sees both.
            assert_eq!(liveness.live_for_test(), 2);
            drop(successor);
            drop(lane);
        }
        let quiet = tokio::task::spawn_blocking(move || {
            liveness.wait_until_quiet(std::time::Duration::from_secs(10))
        })
        .await
        .unwrap();
        assert!(quiet, "both lanes must retire from the census");
    }
}
