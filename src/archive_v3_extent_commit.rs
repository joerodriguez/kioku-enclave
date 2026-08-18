#![allow(
    dead_code,
    reason = "inactive ADR-0022 durable shadow extent commit protocol is compiled and tested before runtime activation"
)]

//! Durable shadow extent commit protocol and authenticated full-tuple CAS attempt state machine.
//!
//! Provides:
//! - The witness-bound 6-stage progression `Prepared -> ObjectsStaged -> CandidateReady ->
//!   WitnessSendStarted -> WitnessAdvanced -> Published`, plus two terminal stages that keep the
//!   ledger honest and live without witness authority:
//!   - `ShadowSettled` (from `CandidateReady`): the only terminal reachable by Phase 3 shadow
//!     commits. It records a locally authenticated, explicitly non-authoritative candidate root.
//!   - `AbortedPreWitness` (from `Prepared`/`ObjectsStaged`/`CandidateReady`): the durable terminal
//!     for interrupted pre-witness attempts, so a crash can never wedge the single-active-attempt
//!     slot.
//! - The witness stages `WitnessSendStarted`/`WitnessAdvanced` are enterable only through sealed
//!   evidence tokens with no production constructor in this slice; the reviewed Phase 4 authority
//!   transition owns the production mint. `Published` therefore cannot exist without a recorded
//!   witness evidence chain.
//! - Versioned durable attempt ledger backed by SQLite with strict row commitments, CHECK
//!   constraints, and full-tuple CAS updates.
//! - A durable staged-object inventory bound to the exact attempt row: every immutable object is
//!   reserved (with its sealed context AAD and ciphertext hash) before upload and marked
//!   materialized only after exact readback, in the same authenticated ledger database.
//! - Enforces exactly one active attempt per `(archive_id, database_epoch, file_type)` tuple.
//! - Monotonic attempt sequence across successive commits for deterministic restart selection.
//! - Exact candidate-root recomputation, decoding, and epoch authentication on every reload.
//! - Strict schema authentication verifying column types and constraint invariants.
//! - Bounded, strictly sorted, unique dirty extent encoding with SHA-256 commitments.
//! - Permanent retention of every terminal state (`Published`, `ShadowSettled`,
//!   `AbortedPreWitness`) across restarts.
//! - Fail-closed restart reconciliation: attempts interrupted in `WitnessSendStarted` or
//!   `WitnessAdvanced` (test-only in this slice) are never adopted optimistically; they require
//!   exact witness reconciliation that this shadow slice deliberately cannot perform.
//! - Row commitments are unkeyed SHA-256 self-commitments over public fields: they detect
//!   corruption and enforce exact CAS shapes, but a writer of the ledger database can forge
//!   them. Ledger terminals are therefore never witness evidence — Phase 4 authority must
//!   treat the external witness as the only source of truth.

use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::archive_v3::{ArchiveId, DatabaseEpoch, KeyEpoch};
use crate::archive_v3_extent::{ExtentTreeError, ShadowExtentRootCandidate};
use crate::archive_v3_extent_vfs::cache::{ExtentFileType, PerUserPageCache};
use crate::archive_v3_shadow_checkpoint::{ShadowCheckpointError, ShadowObjectInventoryError};

pub const EXTENT_ATTEMPT_FORMAT_VERSION: u32 = 1;
pub const MAX_DIRTY_EXTENTS_CAP: usize = 32_768;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ExtentCommitStage {
    Prepared = 1,
    ObjectsStaged = 2,
    CandidateReady = 3,
    WitnessSendStarted = 4,
    WitnessAdvanced = 5,
    Published = 6,
    /// Phase 3 shadow terminal: the candidate root is complete, durably recorded, and adopted
    /// locally for shadow paging only. It carries no witness evidence and no authority.
    ShadowSettled = 7,
    /// Durable terminal for interrupted pre-witness attempts. Retained permanently so restart
    /// selection stays deterministic and the active-attempt slot is released.
    AbortedPreWitness = 8,
}

impl ExtentCommitStage {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Prepared),
            2 => Some(Self::ObjectsStaged),
            3 => Some(Self::CandidateReady),
            4 => Some(Self::WitnessSendStarted),
            5 => Some(Self::WitnessAdvanced),
            6 => Some(Self::Published),
            7 => Some(Self::ShadowSettled),
            8 => Some(Self::AbortedPreWitness),
            _ => None,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Published | Self::ShadowSettled | Self::AbortedPreWitness
        )
    }
}

/// Sealed authority to enter `WitnessSendStarted`. This slice provides no production
/// constructor: Phase 3 shadow commits terminate at `ShadowSettled` and never touch the
/// witness. The separately reviewed Phase 4 extent-authority transition is the intended
/// production minter.
pub struct WitnessSendAuthority {
    _private: (),
}

impl WitnessSendAuthority {
    #[cfg(test)]
    pub(crate) const fn mint_for_test() -> Self {
        Self { _private: () }
    }
}

/// Sealed witness-observed evidence for entering `WitnessAdvanced`. The commitment must be
/// derived from an exact provider witness receipt; this slice provides no production
/// constructor, so `WitnessAdvanced`/`Published` rows cannot record fabricated evidence.
pub struct WitnessObservedEvidence {
    observed_commitment: [u8; 32],
}

impl WitnessObservedEvidence {
    #[cfg(test)]
    pub(crate) const fn mint_for_test(observed_commitment: [u8; 32]) -> Self {
        Self {
            observed_commitment,
        }
    }

    pub fn observed_commitment(&self) -> [u8; 32] {
        self.observed_commitment
    }
}

/// Fully authenticated attempt record persisted in the durable ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowExtentCommitRecord {
    format_version: u32,
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: KeyEpoch,
    operation_id: [u8; 16],
    attempt_id: [u8; 16],
    attempt_sequence: u64,
    file_type: ExtentFileType,
    base_root_commitment: [u8; 32],
    expected_witness_fence: u64,
    expected_witness_revision: u64,
    main_db_size: u64,
    wal_size: u64,
    dirty_extents: Vec<u32>,
    dirty_extents_commitment: [u8; 32],
    candidate_root_bytes: Option<Vec<u8>>,
    candidate_root_commitment: Option<[u8; 32]>,
    witness_request_commitment: Option<[u8; 32]>,
    witness_observed_commitment: Option<[u8; 32]>,
    stage: ExtentCommitStage,
    monotonic_revision: u64,
    row_commitment: [u8; 32],
}

impl ShadowExtentCommitRecord {
    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub fn database_epoch(&self) -> DatabaseEpoch {
        self.database_epoch
    }

    pub fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    pub fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    pub fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    pub fn attempt_sequence(&self) -> u64 {
        self.attempt_sequence
    }

    pub fn file_type(&self) -> ExtentFileType {
        self.file_type
    }

    pub fn base_root_commitment(&self) -> [u8; 32] {
        self.base_root_commitment
    }

    pub fn expected_witness_fence(&self) -> u64 {
        self.expected_witness_fence
    }

    pub fn expected_witness_revision(&self) -> u64 {
        self.expected_witness_revision
    }

    pub fn main_db_size(&self) -> u64 {
        self.main_db_size
    }

    pub fn wal_size(&self) -> u64 {
        self.wal_size
    }

    pub fn dirty_extents(&self) -> &[u32] {
        &self.dirty_extents
    }

    pub fn dirty_extents_commitment(&self) -> [u8; 32] {
        self.dirty_extents_commitment
    }

    pub fn candidate_root_bytes(&self) -> Option<&[u8]> {
        self.candidate_root_bytes.as_deref()
    }

    pub fn candidate_root_commitment(&self) -> Option<[u8; 32]> {
        self.candidate_root_commitment
    }

    pub fn witness_request_commitment(&self) -> Option<[u8; 32]> {
        self.witness_request_commitment
    }

    pub fn witness_observed_commitment(&self) -> Option<[u8; 32]> {
        self.witness_observed_commitment
    }

    pub fn stage(&self) -> ExtentCommitStage {
        self.stage
    }

    pub fn monotonic_revision(&self) -> u64 {
        self.monotonic_revision
    }

    pub fn row_commitment(&self) -> [u8; 32] {
        self.row_commitment
    }
}

#[derive(Debug, Error)]
pub enum ExtentCommitError {
    #[error("extent tree error: {0}")]
    Tree(#[from] ExtentTreeError),
    #[error("shadow inventory error: {0}")]
    Inventory(#[from] ShadowObjectInventoryError),
    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] ShadowCheckpointError),
    #[error("SQLite attempt ledger error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("full-tuple CAS conflict")]
    CasConflict,
    #[error("active attempt already exists for archive/epoch/file")]
    ActiveAttemptExists,
    #[error("unsupported / conflict attempt transition")]
    InvalidTransition,
    #[error("authentication or integrity violation")]
    Authentication,
    #[error("dirty extents capacity exceeded or malformed")]
    InvalidDirtyExtents,
    #[error("dirty extents capacity exceeded: {0} > {MAX_DIRTY_EXTENTS_CAP}")]
    CapacityExceeded(usize),
    #[error("incompatible SQLite schema")]
    IncompatibleSchema,
    #[error("integer overflow / conversion out of range")]
    IntegerOutOfRange,
    #[error("attempt requires exact witness reconciliation that this slice cannot perform")]
    ManualWitnessReconciliationRequired,
    #[error("staged-object inventory capacity exceeded")]
    StagedObjectCapacityExceeded,
    #[error("staged-object inventory conflict")]
    StagedObjectConflict,
}

#[inline]
fn u64_to_i64(v: u64) -> Result<i64, ExtentCommitError> {
    i64::try_from(v).map_err(|_| ExtentCommitError::IntegerOutOfRange)
}

#[inline]
fn i64_to_u64(v: i64) -> Result<u64, ExtentCommitError> {
    u64::try_from(v).map_err(|_| ExtentCommitError::IntegerOutOfRange)
}

/// Compute domain-separated SHA-256 commitment over candidate root bytes.
pub fn compute_candidate_root_commitment(candidate_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"kioku:candidate_root:v1\0");
    hasher.update(candidate_bytes);
    hasher.finalize().into()
}

/// Authenticate candidate root bytes against expected commitment and verify archive/epoch metadata.
pub fn authenticate_candidate_root_bytes(
    candidate_bytes: &[u8],
    expected_commitment: &[u8; 32],
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: KeyEpoch,
) -> Result<ShadowExtentRootCandidate, ExtentCommitError> {
    let computed = compute_candidate_root_commitment(candidate_bytes);
    if &computed != expected_commitment {
        return Err(ExtentCommitError::Authentication);
    }
    let candidate = ShadowExtentRootCandidate::decode(candidate_bytes)
        .map_err(|_| ExtentCommitError::Authentication)?;
    if candidate.archive_id() != archive_id
        || candidate.database_epoch() != database_epoch
        || candidate.key_epoch() != key_epoch
    {
        return Err(ExtentCommitError::Authentication);
    }
    Ok(candidate)
}

/// Compute domain-separated SHA-256 commitment over all canonical fields of an attempt row.
#[allow(clippy::too_many_arguments)]
pub fn compute_attempt_row_commitment(
    format_version: u32,
    archive_id: &ArchiveId,
    database_epoch: &DatabaseEpoch,
    key_epoch: &KeyEpoch,
    operation_id: &[u8; 16],
    attempt_id: &[u8; 16],
    attempt_sequence: u64,
    file_type: ExtentFileType,
    base_root_commitment: &[u8; 32],
    expected_witness_fence: u64,
    expected_witness_revision: u64,
    main_db_size: u64,
    wal_size: u64,
    dirty_extents_commitment: &[u8; 32],
    candidate_root_commitment: Option<&[u8; 32]>,
    witness_request_commitment: Option<&[u8; 32]>,
    witness_observed_commitment: Option<&[u8; 32]>,
    stage: ExtentCommitStage,
    monotonic_revision: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"kioku:extent_commit_attempt_row:v2\0");
    hasher.update(format_version.to_be_bytes());
    hasher.update(archive_id.as_bytes());
    hasher.update(database_epoch.as_bytes());
    hasher.update(key_epoch.as_bytes());
    hasher.update(operation_id);
    hasher.update(attempt_id);
    hasher.update(attempt_sequence.to_be_bytes());
    hasher.update([file_type as u8]);
    hasher.update(base_root_commitment);
    hasher.update(expected_witness_fence.to_be_bytes());
    hasher.update(expected_witness_revision.to_be_bytes());
    hasher.update(main_db_size.to_be_bytes());
    hasher.update(wal_size.to_be_bytes());
    hasher.update(dirty_extents_commitment);
    hasher.update(candidate_root_commitment.unwrap_or(&[0u8; 32]));
    hasher.update(witness_request_commitment.unwrap_or(&[0u8; 32]));
    hasher.update(witness_observed_commitment.unwrap_or(&[0u8; 32]));
    hasher.update([stage as u8]);
    hasher.update(monotonic_revision.to_be_bytes());
    hasher.finalize().into()
}

/// Encode and authenticate sorted unique dirty extent indices.
pub fn encode_and_verify_dirty_extents(
    extents: &[u32],
) -> Result<(Vec<u8>, [u8; 32]), ExtentCommitError> {
    if extents.len() > MAX_DIRTY_EXTENTS_CAP {
        return Err(ExtentCommitError::CapacityExceeded(extents.len()));
    }
    for i in 1..extents.len() {
        if extents[i] <= extents[i - 1] {
            return Err(ExtentCommitError::InvalidDirtyExtents);
        }
    }
    let mut bytes = Vec::with_capacity(4 + extents.len() * 4);
    bytes.extend_from_slice(&(extents.len() as u32).to_be_bytes());
    for &ext in extents {
        bytes.extend_from_slice(&ext.to_be_bytes());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"kioku:dirty_extents:v1\0");
    hasher.update(&bytes);
    let commitment: [u8; 32] = hasher.finalize().into();
    Ok((bytes, commitment))
}

/// Decode and authenticate sorted unique dirty extent indices against expected commitment.
pub fn decode_and_verify_dirty_extents(
    bytes: &[u8],
    expected_commitment: &[u8; 32],
) -> Result<Vec<u32>, ExtentCommitError> {
    if bytes.len() < 4 {
        return Err(ExtentCommitError::InvalidDirtyExtents);
    }
    let count = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if bytes.len() != 4 + count * 4 {
        return Err(ExtentCommitError::InvalidDirtyExtents);
    }
    if count > MAX_DIRTY_EXTENTS_CAP {
        return Err(ExtentCommitError::CapacityExceeded(count));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"kioku:dirty_extents:v1\0");
    hasher.update(bytes);
    let commitment: [u8; 32] = hasher.finalize().into();
    if &commitment != expected_commitment {
        return Err(ExtentCommitError::Authentication);
    }
    let mut extents = Vec::with_capacity(count);
    for chunk in bytes[4..].chunks_exact(4) {
        extents.push(u32::from_be_bytes(chunk.try_into().unwrap()));
    }
    for i in 1..extents.len() {
        if extents[i] <= extents[i - 1] {
            return Err(ExtentCommitError::InvalidDirtyExtents);
        }
    }
    Ok(extents)
}

/// Maximum staged objects per attempt: 32,768 extent slots + 129 internal nodes + 1 root.
/// Kept equal to `crate::archive_v3_operation::MAX_SHADOW_OBJECTS_PER_ATTEMPT`; the SQL DDL
/// mirrors this bound as a literal `ordinal < 32898` CHECK.
pub const MAX_STAGED_OBJECTS_PER_ATTEMPT: usize =
    crate::archive_v3_operation::MAX_SHADOW_OBJECTS_PER_ATTEMPT;
const MAX_STAGED_OBJECT_CONTEXT_BYTES: usize = 512;
const MAX_STAGED_OBJECT_KEY_BYTES: usize = 512;

/// Exact durable facts for one immutable object staged by an extent commit attempt. Every
/// field is real: the sealed context's canonical AAD binds archive, database epoch, key
/// epoch, role, logical location, and object identity, and the ciphertext hash pins the
/// exact sealed bytes. Rows are bound to their authenticated attempt row by `attempt_id`.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtentStagedObjectRecord {
    attempt_id: [u8; 16],
    ordinal: u32,
    object_id: [u8; 16],
    object_role: u8,
    context_aad: Vec<u8>,
    object_key: String,
    ciphertext_hash: [u8; 32],
    materialized: bool,
    row_commitment: [u8; 32],
}

impl std::fmt::Debug for ExtentStagedObjectRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExtentStagedObjectRecord(<opaque>)")
    }
}

impl ExtentStagedObjectRecord {
    pub(crate) fn from_sealed_context(
        attempt_id: [u8; 16],
        ordinal: u32,
        context: &crate::archive_v3::ObjectContext,
        envelope: &crate::archive_v3::CiphertextEnvelope,
    ) -> Result<Self, ExtentCommitError> {
        if usize::try_from(ordinal)
            .ok()
            .is_none_or(|value| value >= MAX_STAGED_OBJECTS_PER_ATTEMPT)
        {
            return Err(ExtentCommitError::StagedObjectCapacityExceeded);
        }
        let context_aad = context.canonical_aad();
        if context_aad.is_empty() || context_aad.len() > MAX_STAGED_OBJECT_CONTEXT_BYTES {
            return Err(ExtentCommitError::Authentication);
        }
        let object_key = context.object_key().as_str().to_owned();
        if object_key.is_empty() || object_key.len() > MAX_STAGED_OBJECT_KEY_BYTES {
            return Err(ExtentCommitError::Authentication);
        }
        let mut record = Self {
            attempt_id,
            ordinal,
            object_id: *context.object_id().as_bytes(),
            object_role: context.role() as u8,
            context_aad,
            object_key,
            ciphertext_hash: envelope.hash(),
            materialized: false,
            row_commitment: [0u8; 32],
        };
        record.row_commitment = record.compute_row_commitment();
        Ok(record)
    }

    fn compute_row_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"kioku:extent_staged_object_row:v1\0");
        hasher.update(self.attempt_id);
        hasher.update(self.ordinal.to_be_bytes());
        hasher.update(self.object_id);
        hasher.update([self.object_role]);
        hasher.update((self.context_aad.len() as u32).to_be_bytes());
        hasher.update(&self.context_aad);
        hasher.update((self.object_key.len() as u32).to_be_bytes());
        hasher.update(self.object_key.as_bytes());
        hasher.update(self.ciphertext_hash);
        hasher.update([u8::from(self.materialized)]);
        hasher.finalize().into()
    }

    fn validate(&self) -> Result<(), ExtentCommitError> {
        if usize::try_from(self.ordinal)
            .ok()
            .is_none_or(|value| value >= MAX_STAGED_OBJECTS_PER_ATTEMPT)
        {
            return Err(ExtentCommitError::StagedObjectCapacityExceeded);
        }
        if self.context_aad.is_empty()
            || self.context_aad.len() > MAX_STAGED_OBJECT_CONTEXT_BYTES
            || self.object_key.is_empty()
            || self.object_key.len() > MAX_STAGED_OBJECT_KEY_BYTES
        {
            return Err(ExtentCommitError::Authentication);
        }
        if self.compute_row_commitment() != self.row_commitment {
            return Err(ExtentCommitError::Authentication);
        }
        Ok(())
    }

    fn with_materialized(&self) -> Self {
        let mut updated = self.clone();
        updated.materialized = true;
        updated.row_commitment = updated.compute_row_commitment();
        updated
    }

    pub fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub fn object_id(&self) -> [u8; 16] {
        self.object_id
    }

    pub fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }

    pub fn materialized(&self) -> bool {
        self.materialized
    }
}

/// Validate complete stage invariants, relationships, and commitments.
fn validate_stage_shape(record: &ShadowExtentCommitRecord) -> Result<(), ExtentCommitError> {
    if record.format_version != EXTENT_ATTEMPT_FORMAT_VERSION {
        return Err(ExtentCommitError::Authentication);
    }
    if record.attempt_sequence == 0 {
        return Err(ExtentCommitError::InvalidTransition);
    }

    match record.stage {
        ExtentCommitStage::Prepared => {
            if record.monotonic_revision != 1
                || record.candidate_root_bytes.is_some()
                || record.candidate_root_commitment.is_some()
                || record.witness_request_commitment.is_some()
                || record.witness_observed_commitment.is_some()
            {
                return Err(ExtentCommitError::InvalidTransition);
            }
        }
        ExtentCommitStage::ObjectsStaged => {
            if record.monotonic_revision != 2
                || record.candidate_root_bytes.is_some()
                || record.candidate_root_commitment.is_some()
                || record.witness_request_commitment.is_some()
                || record.witness_observed_commitment.is_some()
            {
                return Err(ExtentCommitError::InvalidTransition);
            }
        }
        ExtentCommitStage::CandidateReady => {
            if record.monotonic_revision != 3
                || record.candidate_root_bytes.is_none()
                || record.candidate_root_commitment.is_none()
                || record.witness_request_commitment.is_some()
                || record.witness_observed_commitment.is_some()
            {
                return Err(ExtentCommitError::InvalidTransition);
            }
        }
        ExtentCommitStage::WitnessSendStarted => {
            if record.monotonic_revision != 4
                || record.candidate_root_bytes.is_none()
                || record.candidate_root_commitment.is_none()
                || record.witness_request_commitment.is_none()
                || record.witness_observed_commitment.is_some()
                || record.expected_witness_fence == 0
                || record.expected_witness_revision == 0
            {
                return Err(ExtentCommitError::InvalidTransition);
            }
        }
        ExtentCommitStage::WitnessAdvanced => {
            if record.monotonic_revision != 5
                || record.candidate_root_bytes.is_none()
                || record.candidate_root_commitment.is_none()
                || record.witness_request_commitment.is_none()
                || record.witness_observed_commitment.is_none()
                || record.expected_witness_fence == 0
                || record.expected_witness_revision == 0
            {
                return Err(ExtentCommitError::InvalidTransition);
            }
        }
        ExtentCommitStage::Published => {
            if record.monotonic_revision != 6
                || record.candidate_root_bytes.is_none()
                || record.candidate_root_commitment.is_none()
                || record.witness_request_commitment.is_none()
                || record.witness_observed_commitment.is_none()
                || record.expected_witness_fence == 0
                || record.expected_witness_revision == 0
            {
                return Err(ExtentCommitError::InvalidTransition);
            }
        }
        ExtentCommitStage::ShadowSettled => {
            // The Phase 3 shadow terminal records a complete candidate but no witness
            // expectation or evidence of any kind.
            if record.monotonic_revision != 4
                || record.candidate_root_bytes.is_none()
                || record.candidate_root_commitment.is_none()
                || record.witness_request_commitment.is_some()
                || record.witness_observed_commitment.is_some()
                || record.expected_witness_fence != 0
                || record.expected_witness_revision != 0
            {
                return Err(ExtentCommitError::InvalidTransition);
            }
        }
        ExtentCommitStage::AbortedPreWitness => {
            // Aborted rows retain exactly the fields their origin stage had recorded:
            // revision 2|3 (from Prepared/ObjectsStaged, no candidate) or revision 4
            // (from CandidateReady, candidate retained). Witness fields never exist.
            let candidate_present =
                record.candidate_root_bytes.is_some() && record.candidate_root_commitment.is_some();
            let candidate_absent =
                record.candidate_root_bytes.is_none() && record.candidate_root_commitment.is_none();
            let shape_ok = match record.monotonic_revision {
                2 | 3 => candidate_absent,
                4 => candidate_present,
                _ => false,
            };
            if !shape_ok
                || record.witness_request_commitment.is_some()
                || record.witness_observed_commitment.is_some()
            {
                return Err(ExtentCommitError::InvalidTransition);
            }
        }
    }

    if let (Some(ref cb), Some(ref cc)) = (
        &record.candidate_root_bytes,
        &record.candidate_root_commitment,
    ) {
        let _ = authenticate_candidate_root_bytes(
            cb,
            cc,
            record.archive_id,
            record.database_epoch,
            record.key_epoch,
        )?;
    }

    let calculated_commitment = compute_attempt_row_commitment(
        record.format_version,
        &record.archive_id,
        &record.database_epoch,
        &record.key_epoch,
        &record.operation_id,
        &record.attempt_id,
        record.attempt_sequence,
        record.file_type,
        &record.base_root_commitment,
        record.expected_witness_fence,
        record.expected_witness_revision,
        record.main_db_size,
        record.wal_size,
        &record.dirty_extents_commitment,
        record.candidate_root_commitment.as_ref(),
        record.witness_request_commitment.as_ref(),
        record.witness_observed_commitment.as_ref(),
        record.stage,
        record.monotonic_revision,
    );

    if calculated_commitment != record.row_commitment {
        return Err(ExtentCommitError::Authentication);
    }

    Ok(())
}

/// Sealed attempt ledger supertrait.
mod private {
    pub trait Sealed {}
    impl Sealed for super::SqliteExtentAttemptLedger {}
}

/// Sealed durable attempt ledger interface.
pub trait ExtentAttemptLedger: private::Sealed + Send + Sync {
    fn get_next_attempt_sequence(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<u64, ExtentCommitError>;

    fn create_attempt(&self, record: &ShadowExtentCommitRecord) -> Result<(), ExtentCommitError>;

    fn get_active_attempt(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<Option<ShadowExtentCommitRecord>, ExtentCommitError>;

    fn get_latest_attempt(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<Option<ShadowExtentCommitRecord>, ExtentCommitError>;

    fn get_latest_published_attempt(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<Option<ShadowExtentCommitRecord>, ExtentCommitError>;

    /// Latest terminal attempt carrying an adoptable candidate root: `Published`
    /// (witness-evidenced) or `ShadowSettled` (Phase 3 shadow, non-authoritative).
    fn get_latest_settled_attempt(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<Option<ShadowExtentCommitRecord>, ExtentCommitError>;

    fn transition_attempt(
        &self,
        old_record: &ShadowExtentCommitRecord,
        new_record: &ShadowExtentCommitRecord,
    ) -> Result<ShadowExtentCommitRecord, ExtentCommitError>;

    /// Durably reserve one staged object for an attempt before any provider upload. The
    /// insert is refused on ordinal or object-identity conflict and read back exactly
    /// inside the same transaction.
    fn reserve_staged_object(
        &self,
        record: &ExtentStagedObjectRecord,
    ) -> Result<(), ExtentCommitError>;

    /// Mark a previously reserved staged object materialized after exact provider
    /// readback, using a full-tuple CAS on the reserved row.
    fn mark_staged_object_materialized(
        &self,
        reserved: &ExtentStagedObjectRecord,
    ) -> Result<ExtentStagedObjectRecord, ExtentCommitError>;

    /// Load and authenticate every staged-object row for an attempt, ordered by ordinal.
    fn load_staged_objects(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<Vec<ExtentStagedObjectRecord>, ExtentCommitError>;
}

/// SQLite-backed persistent attempt ledger enforcing strict full-tuple CAS updates and schema constraints.
pub struct SqliteExtentAttemptLedger {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteExtentAttemptLedger {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, ExtentCommitError> {
        {
            let guard = conn.lock().map_err(|_| ExtentCommitError::CasConflict)?;
            guard.execute_batch(
                "CREATE TABLE IF NOT EXISTS _kioku_extent_commit_attempts_v3 (
                    format_version INTEGER NOT NULL CHECK(format_version = 1),
                    archive_id BLOB NOT NULL CHECK(length(archive_id) = 16),
                    database_epoch BLOB NOT NULL CHECK(length(database_epoch) = 16),
                    key_epoch BLOB NOT NULL CHECK(length(key_epoch) = 16),
                    operation_id BLOB NOT NULL CHECK(length(operation_id) = 16),
                    attempt_id BLOB NOT NULL PRIMARY KEY CHECK(length(attempt_id) = 16),
                    attempt_sequence INTEGER NOT NULL CHECK(attempt_sequence > 0),
                    file_type INTEGER NOT NULL CHECK(file_type IN (1, 2)),
                    base_root_commitment BLOB NOT NULL CHECK(length(base_root_commitment) = 32),
                    expected_witness_fence INTEGER NOT NULL CHECK(expected_witness_fence >= 0),
                    expected_witness_revision INTEGER NOT NULL CHECK(expected_witness_revision >= 0),
                    main_db_size INTEGER NOT NULL CHECK(main_db_size >= 0),
                    wal_size INTEGER NOT NULL CHECK(wal_size >= 0),
                    dirty_extents BLOB NOT NULL,
                    dirty_extents_commitment BLOB NOT NULL CHECK(length(dirty_extents_commitment) = 32),
                    candidate_root_bytes BLOB,
                    candidate_root_commitment BLOB CHECK(candidate_root_commitment IS NULL OR length(candidate_root_commitment) = 32),
                    witness_request_commitment BLOB CHECK(witness_request_commitment IS NULL OR length(witness_request_commitment) = 32),
                    witness_observed_commitment BLOB CHECK(witness_observed_commitment IS NULL OR length(witness_observed_commitment) = 32),
                    stage INTEGER NOT NULL CHECK(stage BETWEEN 1 AND 8),
                    monotonic_revision INTEGER NOT NULL CHECK(monotonic_revision BETWEEN 1 AND 6),
                    row_commitment BLOB NOT NULL CHECK(length(row_commitment) = 32),
                    CHECK (
                        (stage = 1 AND monotonic_revision = 1 AND candidate_root_bytes IS NULL AND candidate_root_commitment IS NULL AND witness_request_commitment IS NULL AND witness_observed_commitment IS NULL) OR
                        (stage = 2 AND monotonic_revision = 2 AND candidate_root_bytes IS NULL AND candidate_root_commitment IS NULL AND witness_request_commitment IS NULL AND witness_observed_commitment IS NULL) OR
                        (stage = 3 AND monotonic_revision = 3 AND candidate_root_bytes IS NOT NULL AND candidate_root_commitment IS NOT NULL AND witness_request_commitment IS NULL AND witness_observed_commitment IS NULL) OR
                        (stage = 4 AND monotonic_revision = 4 AND candidate_root_bytes IS NOT NULL AND candidate_root_commitment IS NOT NULL AND witness_request_commitment IS NOT NULL AND witness_observed_commitment IS NULL AND expected_witness_fence >= 1 AND expected_witness_revision >= 1) OR
                        (stage = 5 AND monotonic_revision = 5 AND candidate_root_bytes IS NOT NULL AND candidate_root_commitment IS NOT NULL AND witness_request_commitment IS NOT NULL AND witness_observed_commitment IS NOT NULL AND expected_witness_fence >= 1 AND expected_witness_revision >= 1) OR
                        (stage = 6 AND monotonic_revision = 6 AND candidate_root_bytes IS NOT NULL AND candidate_root_commitment IS NOT NULL AND witness_request_commitment IS NOT NULL AND witness_observed_commitment IS NOT NULL AND expected_witness_fence >= 1 AND expected_witness_revision >= 1) OR
                        (stage = 7 AND monotonic_revision = 4 AND candidate_root_bytes IS NOT NULL AND candidate_root_commitment IS NOT NULL AND witness_request_commitment IS NULL AND witness_observed_commitment IS NULL AND expected_witness_fence = 0 AND expected_witness_revision = 0) OR
                        (stage = 8 AND monotonic_revision IN (2, 3) AND candidate_root_bytes IS NULL AND candidate_root_commitment IS NULL AND witness_request_commitment IS NULL AND witness_observed_commitment IS NULL) OR
                        (stage = 8 AND monotonic_revision = 4 AND candidate_root_bytes IS NOT NULL AND candidate_root_commitment IS NOT NULL AND witness_request_commitment IS NULL AND witness_observed_commitment IS NULL)
                    )
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_extent_attempt_active_v3
                ON _kioku_extent_commit_attempts_v3 (archive_id, database_epoch, file_type)
                WHERE stage BETWEEN 1 AND 5;

                CREATE UNIQUE INDEX IF NOT EXISTS idx_extent_attempt_sequence_v3
                ON _kioku_extent_commit_attempts_v3 (archive_id, database_epoch, file_type, attempt_sequence);

                CREATE TABLE IF NOT EXISTS _kioku_extent_staged_objects_v1 (
                    attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 32898),
                    object_id BLOB NOT NULL CHECK(length(object_id) = 16),
                    object_role INTEGER NOT NULL CHECK(object_role BETWEEN 0 AND 255),
                    context_aad BLOB NOT NULL CHECK(length(context_aad) > 0 AND length(context_aad) <= 512),
                    object_key TEXT NOT NULL CHECK(length(object_key) > 0 AND length(object_key) <= 512),
                    ciphertext_hash BLOB NOT NULL CHECK(length(ciphertext_hash) = 32),
                    materialized INTEGER NOT NULL CHECK(materialized IN (0, 1)),
                    row_commitment BLOB NOT NULL CHECK(length(row_commitment) = 32),
                    PRIMARY KEY (attempt_id, ordinal)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_extent_staged_object_identity_v1
                ON _kioku_extent_staged_objects_v1 (attempt_id, object_id);",
            )?;

            // 1. Schema verification: exact column names, types, nullability, and primary key
            let mut stmt = guard.prepare("PRAGMA table_info(_kioku_extent_commit_attempts_v3);")?;
            struct ColCheck {
                name: String,
                col_type: String,
                notnull: bool,
                pk: bool,
            }
            let mut cols = Vec::new();
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                cols.push(ColCheck {
                    name: row.get(1)?,
                    col_type: row.get(2)?,
                    notnull: row.get::<_, i64>(3)? == 1,
                    pk: row.get::<_, i64>(5)? == 1,
                });
            }
            drop(rows);
            drop(stmt);

            let expected_cols: [(&str, &str, bool, bool); 22] = [
                ("format_version", "INTEGER", true, false),
                ("archive_id", "BLOB", true, false),
                ("database_epoch", "BLOB", true, false),
                ("key_epoch", "BLOB", true, false),
                ("operation_id", "BLOB", true, false),
                ("attempt_id", "BLOB", true, true),
                ("attempt_sequence", "INTEGER", true, false),
                ("file_type", "INTEGER", true, false),
                ("base_root_commitment", "BLOB", true, false),
                ("expected_witness_fence", "INTEGER", true, false),
                ("expected_witness_revision", "INTEGER", true, false),
                ("main_db_size", "INTEGER", true, false),
                ("wal_size", "INTEGER", true, false),
                ("dirty_extents", "BLOB", true, false),
                ("dirty_extents_commitment", "BLOB", true, false),
                ("candidate_root_bytes", "BLOB", false, false),
                ("candidate_root_commitment", "BLOB", false, false),
                ("witness_request_commitment", "BLOB", false, false),
                ("witness_observed_commitment", "BLOB", false, false),
                ("stage", "INTEGER", true, false),
                ("monotonic_revision", "INTEGER", true, false),
                ("row_commitment", "BLOB", true, false),
            ];

            if cols.len() != expected_cols.len() {
                return Err(ExtentCommitError::IncompatibleSchema);
            }

            for (actual, (exp_name, exp_type, exp_notnull, exp_pk)) in
                cols.iter().zip(expected_cols.iter())
            {
                if actual.name != *exp_name
                    || actual.col_type != *exp_type
                    || actual.notnull != *exp_notnull
                    || actual.pk != *exp_pk
                {
                    return Err(ExtentCommitError::IncompatibleSchema);
                }
            }

            // 2. Verify DDL CHECK constraints in sqlite_master
            let table_sql: String = guard.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = '_kioku_extent_commit_attempts_v3';",
                [],
                |r| r.get(0),
            )?;
            if !table_sql.contains("CHECK(format_version = 1)")
                || !table_sql.contains("CHECK(attempt_sequence > 0)")
                || !table_sql.contains("CHECK(stage BETWEEN 1 AND 8)")
                || !table_sql.contains("CHECK(monotonic_revision BETWEEN 1 AND 6)")
                || !table_sql.contains(
                    "stage = 7 AND monotonic_revision = 4 AND candidate_root_bytes IS NOT NULL",
                )
                || !table_sql.contains("stage = 8 AND monotonic_revision IN (2, 3)")
                || !table_sql.contains("expected_witness_fence >= 1")
                || !table_sql.contains("expected_witness_fence = 0")
            {
                return Err(ExtentCommitError::IncompatibleSchema);
            }

            // 3. Verify unique indexes in sqlite_master
            let active_index_sql: String = guard.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_extent_attempt_active_v3';",
                [],
                |r| r.get(0),
            )?;
            if !active_index_sql.contains("UNIQUE")
                || !active_index_sql.contains("WHERE stage BETWEEN 1 AND 5")
            {
                return Err(ExtentCommitError::IncompatibleSchema);
            }

            let seq_index_sql: String = guard.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_extent_attempt_sequence_v3';",
                [],
                |r| r.get(0),
            )?;
            if !seq_index_sql.contains("UNIQUE") {
                return Err(ExtentCommitError::IncompatibleSchema);
            }

            // 4. Verify the staged-object inventory table schema and identity index.
            let staged_sql: String = guard.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = '_kioku_extent_staged_objects_v1';",
                [],
                |r| r.get(0),
            )?;
            if !staged_sql.contains("PRIMARY KEY (attempt_id, ordinal)")
                || !staged_sql.contains("CHECK(materialized IN (0, 1))")
                || !staged_sql.contains("CHECK(ordinal >= 0 AND ordinal < 32898)")
                || !staged_sql.contains("CHECK(length(ciphertext_hash) = 32)")
            {
                return Err(ExtentCommitError::IncompatibleSchema);
            }
            let staged_index_sql: String = guard.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_extent_staged_object_identity_v1';",
                [],
                |r| r.get(0),
            )?;
            if !staged_index_sql.contains("UNIQUE") {
                return Err(ExtentCommitError::IncompatibleSchema);
            }
        }
        Ok(Self { conn })
    }

    fn read_row(row: &rusqlite::Row<'_>) -> Result<ShadowExtentCommitRecord, rusqlite::Error> {
        let format_version_raw: i64 = row.get(0)?;
        let archive_bytes: Vec<u8> = row.get(1)?;
        let db_epoch_bytes: Vec<u8> = row.get(2)?;
        let key_epoch_bytes: Vec<u8> = row.get(3)?;
        let op_bytes: Vec<u8> = row.get(4)?;
        let attempt_bytes: Vec<u8> = row.get(5)?;
        let attempt_sequence_raw: i64 = row.get(6)?;
        let file_type_raw: u8 = row.get(7)?;
        let base_root_commitment: [u8; 32] = row.get(8)?;
        let expected_witness_fence_raw: i64 = row.get(9)?;
        let expected_witness_revision_raw: i64 = row.get(10)?;
        let main_db_size_raw: i64 = row.get(11)?;
        let wal_size_raw: i64 = row.get(12)?;
        let dirty_bytes: Vec<u8> = row.get(13)?;
        let dirty_extents_commitment: [u8; 32] = row.get(14)?;
        let candidate_root_bytes: Option<Vec<u8>> = row.get(15)?;
        let candidate_root_commitment: Option<[u8; 32]> = row.get(16)?;
        let witness_request_commitment: Option<[u8; 32]> = row.get(17)?;
        let witness_observed_commitment: Option<[u8; 32]> = row.get(18)?;
        let stage_raw: u8 = row.get(19)?;
        let monotonic_revision_raw: i64 = row.get(20)?;
        let row_commitment: [u8; 32] = row.get(21)?;

        let format_version = u32::try_from(format_version_raw)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, format_version_raw))?;
        let attempt_sequence = i64_to_u64(attempt_sequence_raw)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(6, attempt_sequence_raw))?;
        let expected_witness_fence = i64_to_u64(expected_witness_fence_raw)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(9, expected_witness_fence_raw))?;
        let expected_witness_revision =
            i64_to_u64(expected_witness_revision_raw).map_err(|_| {
                rusqlite::Error::IntegralValueOutOfRange(10, expected_witness_revision_raw)
            })?;
        let main_db_size = i64_to_u64(main_db_size_raw)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(11, main_db_size_raw))?;
        let wal_size = i64_to_u64(wal_size_raw)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(12, wal_size_raw))?;
        let monotonic_revision = i64_to_u64(monotonic_revision_raw)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(20, monotonic_revision_raw))?;

        let archive_id = ArchiveId::from_bytes(
            archive_bytes
                .as_slice()
                .try_into()
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, 16))?,
        );
        let database_epoch = DatabaseEpoch::from_bytes(
            db_epoch_bytes
                .as_slice()
                .try_into()
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, 16))?,
        );
        let key_epoch = KeyEpoch::from_bytes(
            key_epoch_bytes
                .as_slice()
                .try_into()
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, 16))?,
        );
        let operation_id: [u8; 16] = op_bytes
            .as_slice()
            .try_into()
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, 16))?;
        let attempt_id: [u8; 16] = attempt_bytes
            .as_slice()
            .try_into()
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, 16))?;

        let file_type = ExtentFileType::from_u8(file_type_raw).ok_or(
            rusqlite::Error::IntegralValueOutOfRange(7, file_type_raw as i64),
        )?;
        let stage = ExtentCommitStage::from_u8(stage_raw).ok_or(
            rusqlite::Error::IntegralValueOutOfRange(19, stage_raw as i64),
        )?;

        let dirty_extents =
            decode_and_verify_dirty_extents(&dirty_bytes, &dirty_extents_commitment)
                .map_err(|_| rusqlite::Error::ExecuteReturnedResults)?;

        let record = ShadowExtentCommitRecord {
            format_version,
            archive_id,
            database_epoch,
            key_epoch,
            operation_id,
            attempt_id,
            attempt_sequence,
            file_type,
            base_root_commitment,
            expected_witness_fence,
            expected_witness_revision,
            main_db_size,
            wal_size,
            dirty_extents,
            dirty_extents_commitment,
            candidate_root_bytes,
            candidate_root_commitment,
            witness_request_commitment,
            witness_observed_commitment,
            stage,
            monotonic_revision,
            row_commitment,
        };

        validate_stage_shape(&record).map_err(|_| rusqlite::Error::ExecuteReturnedResults)?;

        Ok(record)
    }

    fn read_staged_object_row(
        row: &rusqlite::Row<'_>,
    ) -> Result<ExtentStagedObjectRecord, ExtentCommitError> {
        let attempt_bytes: Vec<u8> = row.get(0)?;
        let ordinal_raw: i64 = row.get(1)?;
        let object_bytes: Vec<u8> = row.get(2)?;
        let object_role: u8 = row.get(3)?;
        let context_aad: Vec<u8> = row.get(4)?;
        let object_key: String = row.get(5)?;
        let ciphertext_hash: [u8; 32] = row.get(6)?;
        let materialized_raw: i64 = row.get(7)?;
        let row_commitment: [u8; 32] = row.get(8)?;

        let attempt_id: [u8; 16] = attempt_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ExtentCommitError::Authentication)?;
        let object_id: [u8; 16] = object_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ExtentCommitError::Authentication)?;
        let ordinal =
            u32::try_from(ordinal_raw).map_err(|_| ExtentCommitError::IntegerOutOfRange)?;
        let materialized = match materialized_raw {
            0 => false,
            1 => true,
            _ => return Err(ExtentCommitError::Authentication),
        };

        Ok(ExtentStagedObjectRecord {
            attempt_id,
            ordinal,
            object_id,
            object_role,
            context_aad,
            object_key,
            ciphertext_hash,
            materialized,
            row_commitment,
        })
    }

    fn read_staged_object_row_by_ordinal(
        tx: &rusqlite::Transaction<'_>,
        attempt_id: [u8; 16],
        ordinal: u32,
    ) -> Result<Option<ExtentStagedObjectRecord>, ExtentCommitError> {
        let mut stmt = tx.prepare(
            "SELECT attempt_id, ordinal, object_id, object_role, context_aad, object_key,
                    ciphertext_hash, materialized, row_commitment
             FROM _kioku_extent_staged_objects_v1
             WHERE attempt_id = ? AND ordinal = ?;",
        )?;
        let mut rows = stmt.query(rusqlite::params![attempt_id.as_slice(), ordinal])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let record = Self::read_staged_object_row(row)?;
        record.validate()?;
        Ok(Some(record))
    }
}

impl ExtentAttemptLedger for SqliteExtentAttemptLedger {
    fn get_next_attempt_sequence(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<u64, ExtentCommitError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let mut stmt = guard.prepare(
            "SELECT MAX(attempt_sequence)
             FROM _kioku_extent_commit_attempts_v3
             WHERE archive_id = ? AND database_epoch = ? AND file_type = ?;",
        )?;

        let max_seq_opt: Option<i64> = stmt.query_row(
            rusqlite::params![
                archive_id.as_bytes().as_slice(),
                database_epoch.as_bytes().as_slice(),
                file_type as u8,
            ],
            |r| r.get(0),
        )?;

        if let Some(max_seq) = max_seq_opt {
            let s = i64_to_u64(max_seq)?;
            Ok(s.saturating_add(1))
        } else {
            Ok(1)
        }
    }

    fn create_attempt(&self, record: &ShadowExtentCommitRecord) -> Result<(), ExtentCommitError> {
        validate_stage_shape(record)?;

        let (dirty_bytes, dirty_commitment) =
            encode_and_verify_dirty_extents(&record.dirty_extents)?;
        if dirty_commitment != record.dirty_extents_commitment {
            return Err(ExtentCommitError::Authentication);
        }

        let mut guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let tx = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let seq_opt: Option<i64> = tx.query_row(
            "SELECT COALESCE(MAX(attempt_sequence), 0) + 1
             FROM _kioku_extent_commit_attempts_v3
             WHERE archive_id = ? AND database_epoch = ? AND file_type = ?;",
            rusqlite::params![
                record.archive_id.as_bytes().as_slice(),
                record.database_epoch.as_bytes().as_slice(),
                record.file_type as u8,
            ],
            |r| r.get(0),
        )?;
        let expected_seq = i64_to_u64(seq_opt.unwrap_or(1))?;
        if record.attempt_sequence != expected_seq {
            return Err(ExtentCommitError::CasConflict);
        }

        let res = tx.execute(
            "INSERT INTO _kioku_extent_commit_attempts_v3 (
                format_version, archive_id, database_epoch, key_epoch, operation_id, attempt_id,
                attempt_sequence, file_type, base_root_commitment, expected_witness_fence,
                expected_witness_revision, main_db_size, wal_size,
                dirty_extents, dirty_extents_commitment,
                candidate_root_bytes, candidate_root_commitment,
                witness_request_commitment, witness_observed_commitment,
                stage, monotonic_revision, row_commitment
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            rusqlite::params![
                record.format_version as i64,
                record.archive_id.as_bytes().as_slice(),
                record.database_epoch.as_bytes().as_slice(),
                record.key_epoch.as_bytes().as_slice(),
                record.operation_id.as_slice(),
                record.attempt_id.as_slice(),
                u64_to_i64(record.attempt_sequence)?,
                record.file_type as u8,
                record.base_root_commitment.as_slice(),
                u64_to_i64(record.expected_witness_fence)?,
                u64_to_i64(record.expected_witness_revision)?,
                u64_to_i64(record.main_db_size)?,
                u64_to_i64(record.wal_size)?,
                dirty_bytes,
                record.dirty_extents_commitment.as_slice(),
                record.candidate_root_bytes,
                record
                    .candidate_root_commitment
                    .as_ref()
                    .map(|c| c.as_slice()),
                record
                    .witness_request_commitment
                    .as_ref()
                    .map(|c| c.as_slice()),
                record
                    .witness_observed_commitment
                    .as_ref()
                    .map(|c| c.as_slice()),
                record.stage as u8,
                u64_to_i64(record.monotonic_revision)?,
                record.row_commitment.as_slice(),
            ],
        );

        match res {
            Ok(1) => {
                // Immediate exact reload before committing transaction
                let mut stmt = tx.prepare(
                    "SELECT format_version, archive_id, database_epoch, key_epoch, operation_id, attempt_id,
                            attempt_sequence, file_type, base_root_commitment, expected_witness_fence,
                            expected_witness_revision, main_db_size, wal_size,
                            dirty_extents, dirty_extents_commitment,
                            candidate_root_bytes, candidate_root_commitment,
                            witness_request_commitment, witness_observed_commitment,
                            stage, monotonic_revision, row_commitment
                     FROM _kioku_extent_commit_attempts_v3
                     WHERE attempt_id = ?;",
                )?;

                let reloaded = stmt.query_row(
                    rusqlite::params![record.attempt_id.as_slice()],
                    Self::read_row,
                )?;
                drop(stmt);

                if &reloaded != record {
                    return Err(ExtentCommitError::Authentication);
                }

                tx.commit()?;
                Ok(())
            }
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(ExtentCommitError::ActiveAttemptExists)
            }
            Err(e) => Err(ExtentCommitError::Sqlite(e)),
            _ => Err(ExtentCommitError::CasConflict),
        }
    }

    fn get_active_attempt(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<Option<ShadowExtentCommitRecord>, ExtentCommitError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let mut stmt = guard.prepare(
            "SELECT format_version, archive_id, database_epoch, key_epoch, operation_id, attempt_id,
                    attempt_sequence, file_type, base_root_commitment, expected_witness_fence,
                    expected_witness_revision, main_db_size, wal_size,
                    dirty_extents, dirty_extents_commitment,
                    candidate_root_bytes, candidate_root_commitment,
                    witness_request_commitment, witness_observed_commitment,
                    stage, monotonic_revision, row_commitment
             FROM _kioku_extent_commit_attempts_v3
             WHERE archive_id = ? AND database_epoch = ? AND file_type = ? AND stage BETWEEN 1 AND 5
             ORDER BY attempt_sequence DESC
             LIMIT 1;",
        )?;

        let row = stmt
            .query_row(
                rusqlite::params![
                    archive_id.as_bytes().as_slice(),
                    database_epoch.as_bytes().as_slice(),
                    file_type as u8,
                ],
                Self::read_row,
            )
            .optional()?;

        Ok(row)
    }

    fn get_latest_attempt(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<Option<ShadowExtentCommitRecord>, ExtentCommitError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let mut stmt = guard.prepare(
            "SELECT format_version, archive_id, database_epoch, key_epoch, operation_id, attempt_id,
                    attempt_sequence, file_type, base_root_commitment, expected_witness_fence,
                    expected_witness_revision, main_db_size, wal_size,
                    dirty_extents, dirty_extents_commitment,
                    candidate_root_bytes, candidate_root_commitment,
                    witness_request_commitment, witness_observed_commitment,
                    stage, monotonic_revision, row_commitment
             FROM _kioku_extent_commit_attempts_v3
             WHERE archive_id = ? AND database_epoch = ? AND file_type = ?
             ORDER BY attempt_sequence DESC, monotonic_revision DESC
             LIMIT 1;",
        )?;

        let row = stmt
            .query_row(
                rusqlite::params![
                    archive_id.as_bytes().as_slice(),
                    database_epoch.as_bytes().as_slice(),
                    file_type as u8,
                ],
                Self::read_row,
            )
            .optional()?;

        Ok(row)
    }

    fn get_latest_published_attempt(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<Option<ShadowExtentCommitRecord>, ExtentCommitError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let mut stmt = guard.prepare(
            "SELECT format_version, archive_id, database_epoch, key_epoch, operation_id, attempt_id,
                    attempt_sequence, file_type, base_root_commitment, expected_witness_fence,
                    expected_witness_revision, main_db_size, wal_size,
                    dirty_extents, dirty_extents_commitment,
                    candidate_root_bytes, candidate_root_commitment,
                    witness_request_commitment, witness_observed_commitment,
                    stage, monotonic_revision, row_commitment
             FROM _kioku_extent_commit_attempts_v3
             WHERE archive_id = ? AND database_epoch = ? AND file_type = ? AND stage = 6
             ORDER BY attempt_sequence DESC
             LIMIT 1;",
        )?;

        let row = stmt
            .query_row(
                rusqlite::params![
                    archive_id.as_bytes().as_slice(),
                    database_epoch.as_bytes().as_slice(),
                    file_type as u8,
                ],
                Self::read_row,
            )
            .optional()?;

        Ok(row)
    }

    fn get_latest_settled_attempt(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        file_type: ExtentFileType,
    ) -> Result<Option<ShadowExtentCommitRecord>, ExtentCommitError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let mut stmt = guard.prepare(
            "SELECT format_version, archive_id, database_epoch, key_epoch, operation_id, attempt_id,
                    attempt_sequence, file_type, base_root_commitment, expected_witness_fence,
                    expected_witness_revision, main_db_size, wal_size,
                    dirty_extents, dirty_extents_commitment,
                    candidate_root_bytes, candidate_root_commitment,
                    witness_request_commitment, witness_observed_commitment,
                    stage, monotonic_revision, row_commitment
             FROM _kioku_extent_commit_attempts_v3
             WHERE archive_id = ? AND database_epoch = ? AND file_type = ? AND stage IN (6, 7)
             ORDER BY attempt_sequence DESC
             LIMIT 1;",
        )?;

        let row = stmt
            .query_row(
                rusqlite::params![
                    archive_id.as_bytes().as_slice(),
                    database_epoch.as_bytes().as_slice(),
                    file_type as u8,
                ],
                Self::read_row,
            )
            .optional()?;

        Ok(row)
    }

    fn transition_attempt(
        &self,
        old_record: &ShadowExtentCommitRecord,
        new_record: &ShadowExtentCommitRecord,
    ) -> Result<ShadowExtentCommitRecord, ExtentCommitError> {
        if new_record.monotonic_revision != old_record.monotonic_revision + 1 {
            return Err(ExtentCommitError::InvalidTransition);
        }
        let allowed = matches!(
            (old_record.stage, new_record.stage),
            (
                ExtentCommitStage::Prepared,
                ExtentCommitStage::ObjectsStaged
            ) | (
                ExtentCommitStage::ObjectsStaged,
                ExtentCommitStage::CandidateReady
            ) | (
                ExtentCommitStage::CandidateReady,
                ExtentCommitStage::WitnessSendStarted
            ) | (
                ExtentCommitStage::WitnessSendStarted,
                ExtentCommitStage::WitnessAdvanced
            ) | (
                ExtentCommitStage::WitnessAdvanced,
                ExtentCommitStage::Published
            ) | (
                ExtentCommitStage::CandidateReady,
                ExtentCommitStage::ShadowSettled
            ) | (
                ExtentCommitStage::Prepared,
                ExtentCommitStage::AbortedPreWitness
            ) | (
                ExtentCommitStage::ObjectsStaged,
                ExtentCommitStage::AbortedPreWitness
            ) | (
                ExtentCommitStage::CandidateReady,
                ExtentCommitStage::AbortedPreWitness
            )
        );
        if !allowed {
            return Err(ExtentCommitError::InvalidTransition);
        }
        if new_record.attempt_id != old_record.attempt_id {
            return Err(ExtentCommitError::InvalidTransition);
        }
        if new_record.attempt_sequence != old_record.attempt_sequence {
            return Err(ExtentCommitError::InvalidTransition);
        }

        validate_stage_shape(new_record)?;

        let (dirty_bytes, dirty_commitment) =
            encode_and_verify_dirty_extents(&new_record.dirty_extents)?;
        if dirty_commitment != new_record.dirty_extents_commitment {
            return Err(ExtentCommitError::Authentication);
        }

        let mut guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let tx = guard.transaction()?;

        let rows_affected = tx.execute(
            "UPDATE _kioku_extent_commit_attempts_v3
             SET stage = ?,
                 monotonic_revision = ?,
                 dirty_extents = ?,
                 dirty_extents_commitment = ?,
                 candidate_root_bytes = ?,
                 candidate_root_commitment = ?,
                 witness_request_commitment = ?,
                 witness_observed_commitment = ?,
                 row_commitment = ?
             WHERE attempt_id = ?
               AND stage = ?
               AND monotonic_revision = ?
               AND row_commitment = ?;",
            rusqlite::params![
                new_record.stage as u8,
                u64_to_i64(new_record.monotonic_revision)?,
                dirty_bytes,
                new_record.dirty_extents_commitment.as_slice(),
                new_record.candidate_root_bytes,
                new_record
                    .candidate_root_commitment
                    .as_ref()
                    .map(|c| c.as_slice()),
                new_record
                    .witness_request_commitment
                    .as_ref()
                    .map(|c| c.as_slice()),
                new_record
                    .witness_observed_commitment
                    .as_ref()
                    .map(|c| c.as_slice()),
                new_record.row_commitment.as_slice(),
                old_record.attempt_id.as_slice(),
                old_record.stage as u8,
                u64_to_i64(old_record.monotonic_revision)?,
                old_record.row_commitment.as_slice(),
            ],
        )?;

        if rows_affected != 1 {
            return Err(ExtentCommitError::CasConflict);
        }

        // Exact post-update reload & authentication inside same transaction
        let mut stmt = tx.prepare(
            "SELECT format_version, archive_id, database_epoch, key_epoch, operation_id, attempt_id,
                    attempt_sequence, file_type, base_root_commitment, expected_witness_fence,
                    expected_witness_revision, main_db_size, wal_size,
                    dirty_extents, dirty_extents_commitment,
                    candidate_root_bytes, candidate_root_commitment,
                    witness_request_commitment, witness_observed_commitment,
                    stage, monotonic_revision, row_commitment
             FROM _kioku_extent_commit_attempts_v3
             WHERE attempt_id = ?;",
        )?;

        let reloaded = stmt.query_row(
            rusqlite::params![new_record.attempt_id.as_slice()],
            Self::read_row,
        )?;

        drop(stmt);

        if &reloaded != new_record {
            return Err(ExtentCommitError::Authentication);
        }

        tx.commit()?;
        Ok(reloaded)
    }

    fn reserve_staged_object(
        &self,
        record: &ExtentStagedObjectRecord,
    ) -> Result<(), ExtentCommitError> {
        record.validate()?;
        if record.materialized {
            return Err(ExtentCommitError::InvalidTransition);
        }

        let mut guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let tx = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let res = tx.execute(
            "INSERT INTO _kioku_extent_staged_objects_v1 (
                attempt_id, ordinal, object_id, object_role, context_aad, object_key,
                ciphertext_hash, materialized, row_commitment
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?);",
            rusqlite::params![
                record.attempt_id.as_slice(),
                record.ordinal,
                record.object_id.as_slice(),
                record.object_role,
                record.context_aad,
                record.object_key,
                record.ciphertext_hash.as_slice(),
                record.row_commitment.as_slice(),
            ],
        );

        match res {
            Ok(1) => {
                let reloaded = Self::read_staged_object_row_by_ordinal(
                    &tx,
                    record.attempt_id,
                    record.ordinal,
                )?
                .ok_or(ExtentCommitError::Authentication)?;
                if &reloaded != record {
                    return Err(ExtentCommitError::Authentication);
                }
                tx.commit()?;
                Ok(())
            }
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(ExtentCommitError::StagedObjectConflict)
            }
            Err(e) => Err(ExtentCommitError::Sqlite(e)),
            _ => Err(ExtentCommitError::CasConflict),
        }
    }

    fn mark_staged_object_materialized(
        &self,
        reserved: &ExtentStagedObjectRecord,
    ) -> Result<ExtentStagedObjectRecord, ExtentCommitError> {
        reserved.validate()?;
        if reserved.materialized {
            return Err(ExtentCommitError::InvalidTransition);
        }
        let updated = reserved.with_materialized();

        let mut guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let tx = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let rows_affected = tx.execute(
            "UPDATE _kioku_extent_staged_objects_v1
             SET materialized = 1, row_commitment = ?
             WHERE attempt_id = ? AND ordinal = ? AND object_id = ? AND object_role = ?
               AND context_aad = ? AND object_key = ? AND ciphertext_hash = ?
               AND materialized = 0 AND row_commitment = ?;",
            rusqlite::params![
                updated.row_commitment.as_slice(),
                reserved.attempt_id.as_slice(),
                reserved.ordinal,
                reserved.object_id.as_slice(),
                reserved.object_role,
                reserved.context_aad,
                reserved.object_key,
                reserved.ciphertext_hash.as_slice(),
                reserved.row_commitment.as_slice(),
            ],
        )?;
        if rows_affected != 1 {
            return Err(ExtentCommitError::CasConflict);
        }

        let reloaded =
            Self::read_staged_object_row_by_ordinal(&tx, reserved.attempt_id, reserved.ordinal)?
                .ok_or(ExtentCommitError::Authentication)?;
        if reloaded != updated {
            return Err(ExtentCommitError::Authentication);
        }

        tx.commit()?;
        Ok(reloaded)
    }

    fn load_staged_objects(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<Vec<ExtentStagedObjectRecord>, ExtentCommitError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| ExtentCommitError::CasConflict)?;
        let mut stmt = guard.prepare(
            "SELECT attempt_id, ordinal, object_id, object_role, context_aad, object_key,
                    ciphertext_hash, materialized, row_commitment
             FROM _kioku_extent_staged_objects_v1
             WHERE attempt_id = ?
             ORDER BY ordinal ASC;",
        )?;
        let mut rows = stmt.query(rusqlite::params![attempt_id.as_slice()])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            if records.len() >= MAX_STAGED_OBJECTS_PER_ATTEMPT {
                return Err(ExtentCommitError::StagedObjectCapacityExceeded);
            }
            let record = Self::read_staged_object_row(row)?;
            record.validate()?;
            records.push(record);
        }
        Ok(records)
    }
}

/// Durable commit coordinator for Extent VFS shadow trees.
pub struct ExtentCommitCoordinator {
    archive_id: ArchiveId,
    database_epoch: DatabaseEpoch,
    key_epoch: KeyEpoch,
    operation_id: [u8; 16],
    ledger: Arc<dyn ExtentAttemptLedger>,
    current_attempt: Option<ShadowExtentCommitRecord>,
}

impl ExtentCommitCoordinator {
    pub fn new(
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        operation_id: [u8; 16],
        ledger: Arc<dyn ExtentAttemptLedger>,
    ) -> Self {
        Self {
            archive_id,
            database_epoch,
            key_epoch,
            operation_id,
            ledger,
            current_attempt: None,
        }
    }

    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub fn current_attempt(&self) -> Option<&ShadowExtentCommitRecord> {
        self.current_attempt.as_ref()
    }

    /// Begin a durable shadow commit attempt in stage `Prepared` and persist to durable ledger.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_attempt(
        &mut self,
        file_type: ExtentFileType,
        base_root: Option<&ShadowExtentRootCandidate>,
        expected_witness_fence: u64,
        expected_witness_revision: u64,
        main_db_size: u64,
        wal_size: u64,
        dirty_extents: Vec<u32>,
    ) -> Result<[u8; 16], ExtentCommitError> {
        let mut attempt_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut attempt_id);

        let attempt_sequence = self.ledger.get_next_attempt_sequence(
            self.archive_id,
            self.database_epoch,
            file_type,
        )?;

        let base_root_commitment = if let Some(root) = base_root {
            let encoded = root.encode();
            let mut hasher = Sha256::new();
            hasher.update(b"kioku:base_root:v1\0");
            hasher.update(&encoded);
            hasher.finalize().into()
        } else {
            [0u8; 32]
        };

        let (_dirty_bytes, dirty_extents_commitment) =
            encode_and_verify_dirty_extents(&dirty_extents)?;

        let stage = ExtentCommitStage::Prepared;
        let monotonic_revision = 1;
        let format_version = EXTENT_ATTEMPT_FORMAT_VERSION;

        let row_commitment = compute_attempt_row_commitment(
            format_version,
            &self.archive_id,
            &self.database_epoch,
            &self.key_epoch,
            &self.operation_id,
            &attempt_id,
            attempt_sequence,
            file_type,
            &base_root_commitment,
            expected_witness_fence,
            expected_witness_revision,
            main_db_size,
            wal_size,
            &dirty_extents_commitment,
            None,
            None,
            None,
            stage,
            monotonic_revision,
        );

        let record = ShadowExtentCommitRecord {
            format_version,
            archive_id: self.archive_id,
            database_epoch: self.database_epoch,
            key_epoch: self.key_epoch,
            operation_id: self.operation_id,
            attempt_id,
            attempt_sequence,
            file_type,
            base_root_commitment,
            expected_witness_fence,
            expected_witness_revision,
            main_db_size,
            wal_size,
            dirty_extents,
            dirty_extents_commitment,
            candidate_root_bytes: None,
            candidate_root_commitment: None,
            witness_request_commitment: None,
            witness_observed_commitment: None,
            stage,
            monotonic_revision,
            row_commitment,
        };

        self.ledger.create_attempt(&record)?;
        self.current_attempt = Some(record);
        Ok(attempt_id)
    }

    /// Recompute the row commitment for `record` from its own canonical fields.
    fn recompute_row_commitment(record: &ShadowExtentCommitRecord) -> [u8; 32] {
        compute_attempt_row_commitment(
            record.format_version,
            &record.archive_id,
            &record.database_epoch,
            &record.key_epoch,
            &record.operation_id,
            &record.attempt_id,
            record.attempt_sequence,
            record.file_type,
            &record.base_root_commitment,
            record.expected_witness_fence,
            record.expected_witness_revision,
            record.main_db_size,
            record.wal_size,
            &record.dirty_extents_commitment,
            record.candidate_root_commitment.as_ref(),
            record.witness_request_commitment.as_ref(),
            record.witness_observed_commitment.as_ref(),
            record.stage,
            record.monotonic_revision,
        )
    }

    /// Advance the in-memory current attempt to `new_stage` through one durable
    /// full-tuple CAS, applying `mutate` to the successor record first.
    fn advance_current(
        &mut self,
        new_stage: ExtentCommitStage,
        mutate: impl FnOnce(&mut ShadowExtentCommitRecord),
    ) -> Result<ShadowExtentCommitRecord, ExtentCommitError> {
        let old_record = self
            .current_attempt
            .as_ref()
            .ok_or(ExtentCommitError::InvalidTransition)?
            .clone();
        let mut new_record = old_record.clone();
        new_record.stage = new_stage;
        new_record.monotonic_revision = old_record.monotonic_revision + 1;
        mutate(&mut new_record);
        new_record.row_commitment = Self::recompute_row_commitment(&new_record);
        let updated = self.ledger.transition_attempt(&old_record, &new_record)?;
        self.current_attempt = Some(updated.clone());
        Ok(updated)
    }

    /// Advance attempt to stage `ObjectsStaged` after all extent leaves & nodes are uploaded.
    pub fn mark_objects_staged(&mut self) -> Result<(), ExtentCommitError> {
        let stage_ok = self
            .current_attempt
            .as_ref()
            .is_some_and(|record| record.stage == ExtentCommitStage::Prepared);
        if !stage_ok {
            return Err(ExtentCommitError::InvalidTransition);
        }
        self.advance_current(ExtentCommitStage::ObjectsStaged, |_| {})?;
        Ok(())
    }

    /// Advance attempt to stage `CandidateReady` once the candidate root is computed and persisted.
    pub fn mark_candidate_ready(
        &mut self,
        candidate_root: &ShadowExtentRootCandidate,
    ) -> Result<(), ExtentCommitError> {
        let stage_ok = self
            .current_attempt
            .as_ref()
            .is_some_and(|record| record.stage == ExtentCommitStage::ObjectsStaged);
        if !stage_ok {
            return Err(ExtentCommitError::InvalidTransition);
        }
        if candidate_root.archive_id() != self.archive_id
            || candidate_root.database_epoch() != self.database_epoch
            || candidate_root.key_epoch() != self.key_epoch
        {
            return Err(ExtentCommitError::Authentication);
        }

        let candidate_bytes = candidate_root.encode();
        let candidate_commitment = compute_candidate_root_commitment(&candidate_bytes);
        self.advance_current(ExtentCommitStage::CandidateReady, |record| {
            record.candidate_root_bytes = Some(candidate_bytes);
            record.candidate_root_commitment = Some(candidate_commitment);
        })?;
        Ok(())
    }

    /// Terminally settle a Phase 3 shadow attempt from `CandidateReady`. The candidate root
    /// is adopted for local shadow paging only; no witness expectation or evidence exists.
    pub fn mark_shadow_settled(&mut self) -> Result<ShadowExtentCommitRecord, ExtentCommitError> {
        let stage_ok = self.current_attempt.as_ref().is_some_and(|record| {
            record.stage == ExtentCommitStage::CandidateReady
                && record.expected_witness_fence == 0
                && record.expected_witness_revision == 0
        });
        if !stage_ok {
            return Err(ExtentCommitError::InvalidTransition);
        }
        self.advance_current(ExtentCommitStage::ShadowSettled, |_| {})
    }

    /// Terminally abort an interrupted pre-witness attempt (`Prepared`, `ObjectsStaged`,
    /// or `CandidateReady`), releasing the single-active-attempt slot durably.
    pub fn abort_pre_witness(&mut self) -> Result<ShadowExtentCommitRecord, ExtentCommitError> {
        let stage_ok = self.current_attempt.as_ref().is_some_and(|record| {
            matches!(
                record.stage,
                ExtentCommitStage::Prepared
                    | ExtentCommitStage::ObjectsStaged
                    | ExtentCommitStage::CandidateReady
            )
        });
        if !stage_ok {
            return Err(ExtentCommitError::InvalidTransition);
        }
        let updated = self.advance_current(ExtentCommitStage::AbortedPreWitness, |_| {})?;
        self.current_attempt = None;
        Ok(updated)
    }

    /// Advance attempt to stage `WitnessSendStarted` prior to external witness CAS. The
    /// sealed `WitnessSendAuthority` has no production constructor in this slice, so this
    /// path is reachable only from tests and, later, the reviewed Phase 4 transition. The
    /// attempt must have recorded a nonzero expected witness fence and revision at begin.
    pub fn mark_witness_send_started(
        &mut self,
        _authority: WitnessSendAuthority,
        witness_request_commitment: [u8; 32],
    ) -> Result<(), ExtentCommitError> {
        let stage_ok = self.current_attempt.as_ref().is_some_and(|record| {
            record.stage == ExtentCommitStage::CandidateReady
                && record.expected_witness_fence != 0
                && record.expected_witness_revision != 0
        });
        if !stage_ok {
            return Err(ExtentCommitError::InvalidTransition);
        }
        self.advance_current(ExtentCommitStage::WitnessSendStarted, |record| {
            record.witness_request_commitment = Some(witness_request_commitment);
        })?;
        Ok(())
    }

    /// Advance attempt to stage `WitnessAdvanced` once witness CAS has succeeded. The
    /// observed commitment can only arrive inside sealed `WitnessObservedEvidence`, which
    /// has no production constructor in this slice.
    pub fn mark_witness_advanced(
        &mut self,
        evidence: WitnessObservedEvidence,
    ) -> Result<(), ExtentCommitError> {
        let stage_ok = self
            .current_attempt
            .as_ref()
            .is_some_and(|record| record.stage == ExtentCommitStage::WitnessSendStarted);
        if !stage_ok {
            return Err(ExtentCommitError::InvalidTransition);
        }
        let observed = evidence.observed_commitment();
        self.advance_current(ExtentCommitStage::WitnessAdvanced, |record| {
            record.witness_observed_commitment = Some(observed);
        })?;
        Ok(())
    }

    /// Advance attempt to stage `Published` once witness update is settled and candidate root is confirmed.
    pub fn mark_published(&mut self) -> Result<ShadowExtentCommitRecord, ExtentCommitError> {
        let stage_ok = self
            .current_attempt
            .as_ref()
            .is_some_and(|record| record.stage == ExtentCommitStage::WitnessAdvanced);
        if !stage_ok {
            return Err(ExtentCommitError::InvalidTransition);
        }
        self.advance_current(ExtentCommitStage::Published, |_| {})
    }

    /// Terminally close any interrupted pre-witness attempt without adopting anything.
    /// This is the mid-session heal: a live SQLite pager sits above the VFS, so adopting
    /// a candidate root here could durably capture a mix of transaction states. Every
    /// pre-witness stage — including a complete `CandidateReady` — aborts durably;
    /// settle-adoption is reserved for install-time reconciliation where no pager
    /// exists. Witness-stage attempts fail closed exactly as in full reconciliation.
    pub fn heal_interrupted_attempt(
        &mut self,
        file_type: ExtentFileType,
        cache: &mut PerUserPageCache,
    ) -> Result<(), ExtentCommitError> {
        let active =
            self.ledger
                .get_active_attempt(self.archive_id, self.database_epoch, file_type)?;
        let Some(record) = active else {
            return Ok(());
        };
        match record.stage {
            ExtentCommitStage::WitnessSendStarted | ExtentCommitStage::WitnessAdvanced => {
                Err(ExtentCommitError::ManualWitnessReconciliationRequired)
            }
            ExtentCommitStage::Prepared
            | ExtentCommitStage::ObjectsStaged
            | ExtentCommitStage::CandidateReady => {
                self.current_attempt = Some(record);
                self.abort_pre_witness()?;
                cache.discard_dirty_pages_for_file(file_type);
                Ok(())
            }
            ExtentCommitStage::Published
            | ExtentCommitStage::ShadowSettled
            | ExtentCommitStage::AbortedPreWitness => Err(ExtentCommitError::Authentication),
        }
    }

    /// Reconcile durable attempt state across process restarts, terminally closing any
    /// interrupted pre-witness attempt so the single-active-attempt slot can never wedge:
    /// - Active `Prepared`/`ObjectsStaged`: durably abort, discard only this file's dirty
    ///   pages, and adopt the latest settled terminal (or `base_candidate_root`).
    /// - Active `CandidateReady` with no witness expectation (a Phase 3 shadow attempt):
    ///   durably settle to `ShadowSettled` and adopt its authenticated candidate root.
    /// - Active `CandidateReady` with a witness expectation (test-only in this slice):
    ///   durably abort — the witness was never contacted, so abort is exact.
    /// - Active `WitnessSendStarted`/`WitnessAdvanced`: fail closed with
    ///   `ManualWitnessReconciliationRequired`. The witness outcome is unknown and this
    ///   shadow slice deliberately has no witness read path, so nothing is adopted.
    /// - Otherwise: adopt the latest settled terminal (`Published` or `ShadowSettled`),
    ///   falling back to `base_candidate_root`.
    pub fn reconcile_from_durable_ledger(
        &mut self,
        file_type: ExtentFileType,
        cache: &mut PerUserPageCache,
        base_candidate_root: Option<ShadowExtentRootCandidate>,
    ) -> Result<Option<ShadowExtentRootCandidate>, ExtentCommitError> {
        let active =
            self.ledger
                .get_active_attempt(self.archive_id, self.database_epoch, file_type)?;

        if let Some(record) = active {
            match record.stage {
                ExtentCommitStage::WitnessSendStarted | ExtentCommitStage::WitnessAdvanced => {
                    // A witness interaction may or may not have happened. Never guess.
                    return Err(ExtentCommitError::ManualWitnessReconciliationRequired);
                }
                ExtentCommitStage::CandidateReady
                    if record.expected_witness_fence == 0
                        && record.expected_witness_revision == 0 =>
                {
                    self.current_attempt = Some(record);
                    let settled = self.mark_shadow_settled()?;
                    cache.discard_dirty_pages_for_file(file_type);
                    if let Some(ref candidate_bytes) = settled.candidate_root_bytes {
                        let candidate = authenticate_candidate_root_bytes(
                            candidate_bytes,
                            settled
                                .candidate_root_commitment
                                .as_ref()
                                .ok_or(ExtentCommitError::Authentication)?,
                            settled.archive_id,
                            settled.database_epoch,
                            settled.key_epoch,
                        )?;
                        return Ok(Some(candidate));
                    }
                    return Err(ExtentCommitError::Authentication);
                }
                ExtentCommitStage::Prepared
                | ExtentCommitStage::ObjectsStaged
                | ExtentCommitStage::CandidateReady => {
                    self.current_attempt = Some(record);
                    self.abort_pre_witness()?;
                    cache.discard_dirty_pages_for_file(file_type);
                }
                ExtentCommitStage::Published
                | ExtentCommitStage::ShadowSettled
                | ExtentCommitStage::AbortedPreWitness => {
                    // Unreachable: the active-attempt query excludes terminal stages.
                    return Err(ExtentCommitError::Authentication);
                }
            }
        }

        // No live attempt remains: adopt the latest settled terminal, if any.
        let latest_settled = self.ledger.get_latest_settled_attempt(
            self.archive_id,
            self.database_epoch,
            file_type,
        )?;
        if let Some(record) = latest_settled {
            if let Some(ref candidate_bytes) = record.candidate_root_bytes {
                let candidate = authenticate_candidate_root_bytes(
                    candidate_bytes,
                    record
                        .candidate_root_commitment
                        .as_ref()
                        .ok_or(ExtentCommitError::Authentication)?,
                    record.archive_id,
                    record.database_epoch,
                    record.key_epoch,
                )?;
                self.current_attempt = None;
                return Ok(Some(candidate));
            }
            return Err(ExtentCommitError::Authentication);
        }

        self.current_attempt = None;
        Ok(base_candidate_root)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_test_record(
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        file_type: ExtentFileType,
        attempt_sequence: u64,
        dirty_extents: Vec<u32>,
    ) -> ShadowExtentCommitRecord {
        let operation_id = [0x11; 16];
        let attempt_id = [0x22; 16];
        let base_root_commitment = [0x33; 32];
        let expected_witness_fence = 100;
        let expected_witness_revision = 1;
        let main_db_size = 4096;
        let wal_size = 0;
        let (_, dirty_extents_commitment) =
            encode_and_verify_dirty_extents(&dirty_extents).unwrap();
        let stage = ExtentCommitStage::Prepared;
        let monotonic_revision = 1;
        let format_version = EXTENT_ATTEMPT_FORMAT_VERSION;

        let row_commitment = compute_attempt_row_commitment(
            format_version,
            &archive_id,
            &database_epoch,
            &key_epoch,
            &operation_id,
            &attempt_id,
            attempt_sequence,
            file_type,
            &base_root_commitment,
            expected_witness_fence,
            expected_witness_revision,
            main_db_size,
            wal_size,
            &dirty_extents_commitment,
            None,
            None,
            None,
            stage,
            monotonic_revision,
        );

        ShadowExtentCommitRecord {
            format_version,
            archive_id,
            database_epoch,
            key_epoch,
            operation_id,
            attempt_id,
            attempt_sequence,
            file_type,
            base_root_commitment,
            expected_witness_fence,
            expected_witness_revision,
            main_db_size,
            wal_size,
            dirty_extents,
            dirty_extents_commitment,
            candidate_root_bytes: None,
            candidate_root_commitment: None,
            witness_request_commitment: None,
            witness_observed_commitment: None,
            stage,
            monotonic_revision,
            row_commitment,
        }
    }

    #[test]
    fn test_attempt_row_independent_column_corruption() {
        let archive_id = ArchiveId::random();
        let database_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();

        // 1. Corrupt row_commitment in isolated connection
        {
            let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
            let ledger = SqliteExtentAttemptLedger::new(conn.clone()).unwrap();
            let record = make_test_record(
                archive_id,
                database_epoch,
                key_epoch,
                ExtentFileType::MainDb,
                1,
                vec![0, 1, 2],
            );
            ledger.create_attempt(&record).unwrap();

            let guard = conn.lock().unwrap();
            guard
                .execute(
                    "UPDATE _kioku_extent_commit_attempts_v3 SET row_commitment = ? WHERE attempt_id = ?;",
                    rusqlite::params![&[0xffu8; 32], record.attempt_id.as_slice()],
                )
                .unwrap();
            drop(guard);

            let fetched =
                ledger.get_active_attempt(archive_id, database_epoch, ExtentFileType::MainDb);
            assert!(fetched.is_err());
        }

        // 2. Corrupt dirty_extents_commitment in isolated connection
        {
            let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
            let ledger = SqliteExtentAttemptLedger::new(conn.clone()).unwrap();
            let record = make_test_record(
                archive_id,
                database_epoch,
                key_epoch,
                ExtentFileType::MainDb,
                1,
                vec![0, 1, 2],
            );
            ledger.create_attempt(&record).unwrap();

            let guard = conn.lock().unwrap();
            guard
                .execute(
                    "UPDATE _kioku_extent_commit_attempts_v3 SET dirty_extents_commitment = ? WHERE attempt_id = ?;",
                    rusqlite::params![&[0xfeu8; 32], record.attempt_id.as_slice()],
                )
                .unwrap();
            drop(guard);

            let fetched =
                ledger.get_active_attempt(archive_id, database_epoch, ExtentFileType::MainDb);
            assert!(fetched.is_err());
        }

        // 3. Corrupt format_version in isolated connection
        {
            let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
            let ledger = SqliteExtentAttemptLedger::new(conn.clone()).unwrap();
            let record = make_test_record(
                archive_id,
                database_epoch,
                key_epoch,
                ExtentFileType::MainDb,
                1,
                vec![0, 1, 2],
            );
            ledger.create_attempt(&record).unwrap();

            let guard = conn.lock().unwrap();
            // CHECK constraint rejects format_version != 1 on UPDATE
            let res = guard.execute(
                "UPDATE _kioku_extent_commit_attempts_v3 SET format_version = 2 WHERE attempt_id = ?;",
                rusqlite::params![record.attempt_id.as_slice()],
            );
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_candidate_root_byte_substitution_and_epoch_mismatch() {
        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();

        let valid_candidate = ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            db_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );
        let candidate_bytes = valid_candidate.encode();
        let commitment = compute_candidate_root_commitment(&candidate_bytes);

        // 1. Authenticate valid bytes succeeds
        let auth = authenticate_candidate_root_bytes(
            &candidate_bytes,
            &commitment,
            archive_id,
            db_epoch,
            key_epoch,
        );
        assert!(auth.is_ok());

        // 2. Tampered candidate bytes fail commitment check
        let mut tampered_bytes = candidate_bytes.clone();
        tampered_bytes[0] ^= 0xff;
        let tampered_auth = authenticate_candidate_root_bytes(
            &tampered_bytes,
            &commitment,
            archive_id,
            db_epoch,
            key_epoch,
        );
        assert!(matches!(
            tampered_auth,
            Err(ExtentCommitError::Authentication)
        ));

        // 3. Candidate encoded for different ArchiveId fails epoch validation
        let other_archive = ArchiveId::random();
        let other_candidate = ShadowExtentRootCandidate::from_uploaded_tree(
            other_archive,
            db_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );
        let other_bytes = other_candidate.encode();
        let other_commitment = compute_candidate_root_commitment(&other_bytes);
        let mismatch_auth = authenticate_candidate_root_bytes(
            &other_bytes,
            &other_commitment,
            archive_id,
            db_epoch,
            key_epoch,
        );
        assert!(matches!(
            mismatch_auth,
            Err(ExtentCommitError::Authentication)
        ));
    }

    #[test]
    fn test_attempt_zero_row_and_multi_row_cas_failure() {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let ledger = SqliteExtentAttemptLedger::new(conn).unwrap();

        let archive_id = ArchiveId::random();
        let database_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let record = make_test_record(
            archive_id,
            database_epoch,
            key_epoch,
            ExtentFileType::MainDb,
            1,
            vec![0],
        );

        ledger.create_attempt(&record).unwrap();

        // CAS with stale revision
        let mut stale_record = record.clone();
        stale_record.monotonic_revision = 999;

        let mut next_record = record.clone();
        next_record.stage = ExtentCommitStage::ObjectsStaged;
        next_record.monotonic_revision = record.monotonic_revision + 1;
        next_record.row_commitment = compute_attempt_row_commitment(
            next_record.format_version,
            &next_record.archive_id,
            &next_record.database_epoch,
            &next_record.key_epoch,
            &next_record.operation_id,
            &next_record.attempt_id,
            next_record.attempt_sequence,
            next_record.file_type,
            &next_record.base_root_commitment,
            next_record.expected_witness_fence,
            next_record.expected_witness_revision,
            next_record.main_db_size,
            next_record.wal_size,
            &next_record.dirty_extents_commitment,
            next_record.candidate_root_commitment.as_ref(),
            next_record.witness_request_commitment.as_ref(),
            next_record.witness_observed_commitment.as_ref(),
            next_record.stage,
            next_record.monotonic_revision,
        );

        let err = ledger.transition_attempt(&stale_record, &next_record);
        assert!(matches!(err, Err(ExtentCommitError::InvalidTransition)));

        // CAS with stage jump (Prepared -> CandidateReady skipping ObjectsStaged)
        let mut jumped_record = record.clone();
        jumped_record.stage = ExtentCommitStage::CandidateReady;
        jumped_record.monotonic_revision = record.monotonic_revision + 1;
        let err_jump = ledger.transition_attempt(&record, &jumped_record);
        assert!(matches!(
            err_jump,
            Err(ExtentCommitError::InvalidTransition)
        ));

        // CAS against actual record works
        let ok = ledger.transition_attempt(&record, &next_record).unwrap();
        assert_eq!(ok.stage(), ExtentCommitStage::ObjectsStaged);
        assert_eq!(ok.monotonic_revision(), 2);
    }

    #[test]
    fn test_two_simultaneous_active_attempts_conflict() {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let ledger = SqliteExtentAttemptLedger::new(conn).unwrap();

        let archive_id = ArchiveId::random();
        let database_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();

        let record1 = make_test_record(
            archive_id,
            database_epoch,
            key_epoch,
            ExtentFileType::MainDb,
            1,
            vec![0],
        );
        ledger.create_attempt(&record1).unwrap();

        // Second attempt with different attempt_id for same archive/epoch/file_type while stage < 6
        let mut record2 = make_test_record(
            archive_id,
            database_epoch,
            key_epoch,
            ExtentFileType::MainDb,
            2,
            vec![1],
        );
        record2.attempt_id = [0x99; 16];
        record2.row_commitment = compute_attempt_row_commitment(
            record2.format_version,
            &record2.archive_id,
            &record2.database_epoch,
            &record2.key_epoch,
            &record2.operation_id,
            &record2.attempt_id,
            record2.attempt_sequence,
            record2.file_type,
            &record2.base_root_commitment,
            record2.expected_witness_fence,
            record2.expected_witness_revision,
            record2.main_db_size,
            record2.wal_size,
            &record2.dirty_extents_commitment,
            None,
            None,
            None,
            record2.stage,
            record2.monotonic_revision,
        );

        let err = ledger.create_attempt(&record2);
        assert!(matches!(err, Err(ExtentCommitError::ActiveAttemptExists)));
    }

    #[test]
    fn test_dirty_extents_strict_ordering_and_cap_boundaries() {
        // Unsorted dirty extents fail
        assert!(encode_and_verify_dirty_extents(&[5, 2, 8]).is_err());
        // Duplicate dirty extents fail
        assert!(encode_and_verify_dirty_extents(&[1, 2, 2, 3]).is_err());

        // Cap exact boundary: MAX_DIRTY_EXTENTS_CAP = 32_768
        let at_cap: Vec<u32> = (0..MAX_DIRTY_EXTENTS_CAP as u32).collect();
        let (bytes, commitment) = encode_and_verify_dirty_extents(&at_cap).unwrap();
        let decoded = decode_and_verify_dirty_extents(&bytes, &commitment).unwrap();
        assert_eq!(decoded.len(), MAX_DIRTY_EXTENTS_CAP);

        // Cap + 1 boundary: 32_769 extents fails
        let over_cap: Vec<u32> = (0..(MAX_DIRTY_EXTENTS_CAP as u32 + 1)).collect();
        let over_err = encode_and_verify_dirty_extents(&over_cap);
        assert!(matches!(
            over_err,
            Err(ExtentCommitError::CapacityExceeded(32769))
        ));
    }

    #[test]
    fn test_multiple_retained_published_terminals_and_active_attempt_precedence() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("lineage_attempts.db");

        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();

        let cand1 = ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            db_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );
        let cand2 = ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            db_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );

        // 1. Commit first terminal attempt (Sequence 1) -> Published (cand1)
        {
            let conn = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            let mut coord =
                ExtentCommitCoordinator::new(archive_id, db_epoch, key_epoch, [0x11; 16], ledger);

            coord
                .begin_attempt(ExtentFileType::MainDb, None, 100, 1, 4096, 0, vec![0])
                .unwrap();
            assert_eq!(coord.current_attempt().unwrap().attempt_sequence(), 1);
            coord.mark_objects_staged().unwrap();
            coord.mark_candidate_ready(&cand1).unwrap();
            coord
                .mark_witness_send_started(WitnessSendAuthority::mint_for_test(), [0x11; 32])
                .unwrap();
            coord
                .mark_witness_advanced(WitnessObservedEvidence::mint_for_test([0x22; 32]))
                .unwrap();
            coord.mark_published().unwrap();
        }

        // 2. Commit second terminal attempt (Sequence 2) -> Published (cand2)
        {
            let conn = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            let mut coord =
                ExtentCommitCoordinator::new(archive_id, db_epoch, key_epoch, [0x22; 16], ledger);

            coord
                .begin_attempt(
                    ExtentFileType::MainDb,
                    Some(&cand1),
                    101,
                    2,
                    8192,
                    0,
                    vec![1],
                )
                .unwrap();
            assert_eq!(coord.current_attempt().unwrap().attempt_sequence(), 2);
            coord.mark_objects_staged().unwrap();
            coord.mark_candidate_ready(&cand2).unwrap();
            coord
                .mark_witness_send_started(WitnessSendAuthority::mint_for_test(), [0x33; 32])
                .unwrap();
            coord
                .mark_witness_advanced(WitnessObservedEvidence::mint_for_test([0x44; 32]))
                .unwrap();
            coord.mark_published().unwrap();
        }

        // 3. Start third in-flight attempt (Sequence 3) -> interrupted in Prepared
        {
            let conn = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            let mut coord =
                ExtentCommitCoordinator::new(archive_id, db_epoch, key_epoch, [0x33; 16], ledger);

            coord
                .begin_attempt(
                    ExtentFileType::MainDb,
                    Some(&cand2),
                    102,
                    3,
                    12288,
                    0,
                    vec![2],
                )
                .unwrap();
            assert_eq!(coord.current_attempt().unwrap().attempt_sequence(), 3);
            assert_eq!(
                coord.current_attempt().unwrap().stage(),
                ExtentCommitStage::Prepared
            );
        }

        // 4. Reopen on fresh process handle: active attempt Sequence 3 was in Prepared ->
        // discards dirty cache and falls back to latest Published terminal (Sequence 2, cand2)
        {
            let conn = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            let mut coord =
                ExtentCommitCoordinator::new(archive_id, db_epoch, key_epoch, [0x44; 16], ledger);

            let mut cache = PerUserPageCache::with_default_capacity();
            cache
                .put(ExtentFileType::MainDb, 2, &[0x99; 4096], true)
                .unwrap();
            assert_eq!(cache.dirty_extents(ExtentFileType::MainDb), vec![0]);

            let recovered = coord
                .reconcile_from_durable_ledger(ExtentFileType::MainDb, &mut cache, None)
                .unwrap();
            assert_eq!(recovered, Some(cand2.clone()));
            assert!(cache.dirty_extents(ExtentFileType::MainDb).is_empty());

            // Wedge regression: reconciliation durably terminalized the interrupted
            // Prepared attempt, so the active slot is free and a new attempt starts.
            let conn2 = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
            let ledger2 = Arc::new(SqliteExtentAttemptLedger::new(conn2).unwrap());
            assert!(ledger2
                .get_active_attempt(archive_id, db_epoch, ExtentFileType::MainDb)
                .unwrap()
                .is_none());
            let mut coord2 = ExtentCommitCoordinator::new(
                archive_id,
                db_epoch,
                key_epoch,
                [0x55; 16],
                Arc::clone(&ledger2) as Arc<dyn ExtentAttemptLedger>,
            );
            coord2
                .begin_attempt(
                    ExtentFileType::MainDb,
                    Some(&cand2),
                    103,
                    3,
                    16384,
                    0,
                    vec![3],
                )
                .unwrap();
            assert_eq!(coord2.current_attempt().unwrap().attempt_sequence(), 4);
        }
    }

    #[test]
    fn test_tampered_schema_rejection() {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        // Pre-create table with missing column / extra column / wrong type
        conn.lock()
            .unwrap()
            .execute_batch(
                "CREATE TABLE _kioku_extent_commit_attempts_v3 (
                    format_version INTEGER,
                    archive_id BLOB,
                    database_epoch BLOB,
                    key_epoch BLOB,
                    operation_id BLOB,
                    attempt_id BLOB PRIMARY KEY,
                    attempt_sequence INTEGER,
                    file_type INTEGER,
                    base_root_commitment BLOB,
                    expected_witness_fence INTEGER,
                    expected_witness_revision INTEGER,
                    main_db_size INTEGER,
                    wal_size INTEGER,
                    dirty_extents BLOB,
                    dirty_extents_commitment BLOB,
                    candidate_root_bytes BLOB,
                    candidate_root_commitment BLOB,
                    witness_request_commitment BLOB,
                    witness_observed_commitment BLOB,
                    stage INTEGER,
                    monotonic_revision INTEGER,
                    row_commitment BLOB,
                    extra_illegal_column TEXT
                );",
            )
            .unwrap();

        let res = SqliteExtentAttemptLedger::new(conn);
        assert!(matches!(res, Err(ExtentCommitError::IncompatibleSchema)));
    }

    fn make_test_context_and_envelope(
        cipher: &crate::archive_v3_extent::tests::TestCipher,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        extent_no: u64,
    ) -> (
        crate::archive_v3::ObjectContext,
        crate::archive_v3::CiphertextEnvelope,
    ) {
        use crate::archive_v3::{LogicalLocation, ObjectContext, ObjectId, ObjectRole};
        let context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no,
                byte_len: 4096,
            },
            ObjectId::random(),
            None,
        )
        .unwrap();
        let envelope =
            crate::archive_v3_extent::ExtentCipher::seal(cipher, &context, &[0xAB; 4096]).unwrap();
        (context, envelope)
    }

    #[test]
    fn test_shadow_settled_flow_reconcile_adoption_and_liveness() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("shadow_settle.db");
        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let cand = ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            db_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );

        {
            let conn = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            let mut coord =
                ExtentCommitCoordinator::new(archive_id, db_epoch, key_epoch, [0x71; 16], ledger);
            // Shadow attempts record no witness expectation.
            coord
                .begin_attempt(ExtentFileType::MainDb, None, 0, 0, 4096, 0, vec![0])
                .unwrap();
            coord.mark_objects_staged().unwrap();
            coord.mark_candidate_ready(&cand).unwrap();
            let settled = coord.mark_shadow_settled().unwrap();
            assert_eq!(settled.stage(), ExtentCommitStage::ShadowSettled);
            assert_eq!(settled.monotonic_revision(), 4);
            assert!(settled.witness_request_commitment().is_none());
            assert!(settled.witness_observed_commitment().is_none());
        }

        // Fresh process: the settled candidate is adopted and a new attempt can begin.
        {
            let conn = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            let latest = ledger
                .get_latest_settled_attempt(archive_id, db_epoch, ExtentFileType::MainDb)
                .unwrap()
                .unwrap();
            assert_eq!(latest.stage(), ExtentCommitStage::ShadowSettled);

            let mut coord = ExtentCommitCoordinator::new(
                archive_id,
                db_epoch,
                key_epoch,
                [0x72; 16],
                Arc::clone(&ledger) as Arc<dyn ExtentAttemptLedger>,
            );
            let mut cache = PerUserPageCache::with_default_capacity();
            let adopted = coord
                .reconcile_from_durable_ledger(ExtentFileType::MainDb, &mut cache, None)
                .unwrap();
            assert_eq!(adopted, Some(cand.clone()));
            coord
                .begin_attempt(ExtentFileType::MainDb, Some(&cand), 0, 0, 8192, 0, vec![1])
                .unwrap();
        }
    }

    #[test]
    fn test_shadow_settle_requires_zero_witness_expectation() {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let cand = ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            db_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );
        let mut coord =
            ExtentCommitCoordinator::new(archive_id, db_epoch, key_epoch, [0x73; 16], ledger);
        // A witness-intent attempt (nonzero fence/revision) can never shadow-settle.
        coord
            .begin_attempt(ExtentFileType::MainDb, None, 7, 3, 4096, 0, vec![0])
            .unwrap();
        coord.mark_objects_staged().unwrap();
        coord.mark_candidate_ready(&cand).unwrap();
        assert!(matches!(
            coord.mark_shadow_settled(),
            Err(ExtentCommitError::InvalidTransition)
        ));
    }

    #[test]
    fn test_witness_stages_require_nonzero_expectation() {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let cand = ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            db_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );
        let mut coord =
            ExtentCommitCoordinator::new(archive_id, db_epoch, key_epoch, [0x74; 16], ledger);
        // A shadow attempt (zero fence/revision) can never enter the witness stages,
        // even holding the sealed test-minted token.
        coord
            .begin_attempt(ExtentFileType::MainDb, None, 0, 0, 4096, 0, vec![0])
            .unwrap();
        coord.mark_objects_staged().unwrap();
        coord.mark_candidate_ready(&cand).unwrap();
        assert!(matches!(
            coord.mark_witness_send_started(WitnessSendAuthority::mint_for_test(), [0x77; 32]),
            Err(ExtentCommitError::InvalidTransition)
        ));
    }

    #[test]
    fn test_reconcile_fails_closed_on_witness_send_started() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("witness_send_crash.db");
        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let cand = ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            db_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );

        {
            let conn = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            let mut coord =
                ExtentCommitCoordinator::new(archive_id, db_epoch, key_epoch, [0x75; 16], ledger);
            coord
                .begin_attempt(ExtentFileType::MainDb, None, 9, 4, 4096, 0, vec![0])
                .unwrap();
            coord.mark_objects_staged().unwrap();
            coord.mark_candidate_ready(&cand).unwrap();
            coord
                .mark_witness_send_started(WitnessSendAuthority::mint_for_test(), [0x88; 32])
                .unwrap();
            // Crash here: the witness may or may not have observed the send.
        }

        {
            let conn = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            let mut coord =
                ExtentCommitCoordinator::new(archive_id, db_epoch, key_epoch, [0x76; 16], ledger);
            let mut cache = PerUserPageCache::with_default_capacity();
            let res = coord.reconcile_from_durable_ledger(ExtentFileType::MainDb, &mut cache, None);
            assert!(matches!(
                res,
                Err(ExtentCommitError::ManualWitnessReconciliationRequired)
            ));
        }
    }

    #[test]
    fn test_reconcile_settles_shadow_candidate_and_aborts_witness_candidate() {
        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let cand = ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            db_epoch,
            key_epoch,
            &crate::archive_v3_extent::tests::make_test_uploaded_tree(),
        );

        // Shadow attempt interrupted at CandidateReady settles on reconcile.
        {
            let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            {
                let mut coord = ExtentCommitCoordinator::new(
                    archive_id,
                    db_epoch,
                    key_epoch,
                    [0x81; 16],
                    Arc::clone(&ledger) as Arc<dyn ExtentAttemptLedger>,
                );
                coord
                    .begin_attempt(ExtentFileType::MainDb, None, 0, 0, 4096, 0, vec![0])
                    .unwrap();
                coord.mark_objects_staged().unwrap();
                coord.mark_candidate_ready(&cand).unwrap();
            }
            let mut coord = ExtentCommitCoordinator::new(
                archive_id,
                db_epoch,
                key_epoch,
                [0x82; 16],
                Arc::clone(&ledger) as Arc<dyn ExtentAttemptLedger>,
            );
            let mut cache = PerUserPageCache::with_default_capacity();
            let adopted = coord
                .reconcile_from_durable_ledger(ExtentFileType::MainDb, &mut cache, None)
                .unwrap();
            assert_eq!(adopted, Some(cand.clone()));
            let latest = ledger
                .get_latest_settled_attempt(archive_id, db_epoch, ExtentFileType::MainDb)
                .unwrap()
                .unwrap();
            assert_eq!(latest.stage(), ExtentCommitStage::ShadowSettled);
        }

        // Witness-intent attempt interrupted at CandidateReady aborts on reconcile
        // (the witness was never contacted, so abort is exact), retaining its
        // candidate in the terminal row shape.
        {
            let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
            let ledger = Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap());
            {
                let mut coord = ExtentCommitCoordinator::new(
                    archive_id,
                    db_epoch,
                    key_epoch,
                    [0x83; 16],
                    Arc::clone(&ledger) as Arc<dyn ExtentAttemptLedger>,
                );
                coord
                    .begin_attempt(ExtentFileType::MainDb, None, 5, 2, 4096, 0, vec![0])
                    .unwrap();
                coord.mark_objects_staged().unwrap();
                coord.mark_candidate_ready(&cand).unwrap();
            }
            let mut coord = ExtentCommitCoordinator::new(
                archive_id,
                db_epoch,
                key_epoch,
                [0x84; 16],
                Arc::clone(&ledger) as Arc<dyn ExtentAttemptLedger>,
            );
            let mut cache = PerUserPageCache::with_default_capacity();
            let adopted = coord
                .reconcile_from_durable_ledger(ExtentFileType::MainDb, &mut cache, None)
                .unwrap();
            assert_eq!(adopted, None, "aborted candidate must not be adopted");
            let latest = ledger
                .get_latest_attempt(archive_id, db_epoch, ExtentFileType::MainDb)
                .unwrap()
                .unwrap();
            assert_eq!(latest.stage(), ExtentCommitStage::AbortedPreWitness);
            assert_eq!(latest.monotonic_revision(), 4);
            assert!(latest.candidate_root_bytes().is_some());
        }
    }

    #[test]
    fn test_staged_object_reserve_materialize_cas_and_capacity() {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let ledger = SqliteExtentAttemptLedger::new(conn).unwrap();
        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let cipher = crate::archive_v3_extent::tests::TestCipher::new(archive_id, key_epoch);
        let attempt_id = [0x91; 16];

        let (context, envelope) =
            make_test_context_and_envelope(&cipher, archive_id, db_epoch, key_epoch, 0);
        let record =
            ExtentStagedObjectRecord::from_sealed_context(attempt_id, 0, &context, &envelope)
                .unwrap();

        // Reserve is durable and exact; a duplicate reservation conflicts.
        ledger.reserve_staged_object(&record).unwrap();
        assert!(matches!(
            ledger.reserve_staged_object(&record),
            Err(ExtentCommitError::StagedObjectConflict)
        ));

        // Same ordinal, different object: primary-key conflict.
        let (context2, envelope2) =
            make_test_context_and_envelope(&cipher, archive_id, db_epoch, key_epoch, 1);
        let same_ordinal =
            ExtentStagedObjectRecord::from_sealed_context(attempt_id, 0, &context2, &envelope2)
                .unwrap();
        assert!(matches!(
            ledger.reserve_staged_object(&same_ordinal),
            Err(ExtentCommitError::StagedObjectConflict)
        ));

        // Materialize with full-tuple CAS; double-materialize fails.
        let materialized = ledger.mark_staged_object_materialized(&record).unwrap();
        assert!(materialized.materialized());
        assert!(matches!(
            ledger.mark_staged_object_materialized(&record),
            Err(ExtentCommitError::CasConflict)
        ));

        // Loading returns the authenticated row in ordinal order.
        let second =
            ExtentStagedObjectRecord::from_sealed_context(attempt_id, 1, &context2, &envelope2)
                .unwrap();
        ledger.reserve_staged_object(&second).unwrap();
        let loaded = ledger.load_staged_objects(attempt_id).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].ordinal(), 0);
        assert!(loaded[0].materialized());
        assert_eq!(loaded[1].ordinal(), 1);
        assert!(!loaded[1].materialized());

        // Ordinal at the capacity bound is rejected before any I/O.
        assert!(matches!(
            ExtentStagedObjectRecord::from_sealed_context(
                attempt_id,
                MAX_STAGED_OBJECTS_PER_ATTEMPT as u32,
                &context,
                &envelope,
            ),
            Err(ExtentCommitError::StagedObjectCapacityExceeded)
        ));
        // The SQL literal in the DDL must stay in lockstep with the Rust constant.
        assert_eq!(MAX_STAGED_OBJECTS_PER_ATTEMPT, 32_898);
    }
}
