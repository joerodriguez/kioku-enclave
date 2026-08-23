#![allow(
    dead_code,
    reason = "active ADR-0022 lifecycle contract retains the type-separated inactive pre-witness branch"
)]

//! Durable, fail-closed lifecycle receipts for archive-v3.
//!
//! This module is deliberately policy and codec only. It constructs no Store,
//! provider, credential, route, environment/config reader, or runtime task. A
//! Each writer must first reserve all immutable identifiers, then durably
//! retain the exact bytes it intends to create. Every provider request consumes
//! a fresh revision-bound admission. Deletion freezes that admission stream and
//! seals a canonical, hash-chained exact-name inventory before key erasure.

use crate::archive_v3::{
    ArchiveId, ArchivePrefix, DatabaseEpoch, KeyEpoch, ObjectId, ObjectKey, ObjectRole,
    MAX_ENCODED_ENVELOPE_BYTES, MAX_WRAPPED_KEY_REGISTRY_BYTES,
};
use crate::archive_v3_gcs::canonical_object_identity;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;
use zeroize::Zeroizing;

/// Version of the bounded lifecycle control anchor. The independently stored
/// inventory-page codec has its own version because those pages never became
/// live and intentionally have no v1 compatibility path.
pub(crate) const LIFECYCLE_FORMAT_VERSION: u16 = 1;
pub(crate) const LIFECYCLE_INVENTORY_PAGE_VERSION: u16 = 2;
pub(crate) const MAX_BOOTSTRAP_WITNESS_BYTES: usize = 4 * 1024;
pub(crate) const MAX_LIFECYCLE_ARTIFACTS: usize = 131_072;
pub(crate) const MAX_LIFECYCLE_PAGE_ENTRIES: usize = 256;
pub(crate) const MAX_LIFECYCLE_PAGES: usize = 4_096;
pub(crate) const MAX_LIFECYCLE_PAGE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_LIFECYCLE_OBJECT_KEY_BYTES: usize = 1_024;
pub(crate) const WITNESS_CREATE_PROTOCOL_V1: u16 = 1;
pub(crate) const PRE_WITNESS_INVENTORY_FORMAT_V1: u16 = 1;

const PAGE_DOMAIN: &[u8] = b"kioku/archive-v3/lifecycle-page/v2\0";
const INVENTORY_DOMAIN: &[u8] = b"kioku/archive-v3/lifecycle-inventory/v2\0";
const PRE_WITNESS_SNAPSHOT_DOMAIN: &[u8] = b"kioku/archive-v3/pre-witness-inventory-snapshot/v1\0";
const PRE_WITNESS_INVENTORY_DOMAIN: &[u8] = b"kioku/archive-v3/pre-witness-deletion-inventory/v1\0";
const ZERO_HASH: [u8; 32] = [0; 32];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BootstrapAttemptId([u8; 16]);

impl BootstrapAttemptId {
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Result<Self, LifecycleError> {
        nonzero(&bytes)
            .then_some(Self(bytes))
            .ok_or(LifecycleError::Malformed)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for BootstrapAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapAttemptId(<opaque>)")
    }
}

/// Identifier-only create-ahead plan. Exact ciphertext is intentionally not
/// available until the reservation carrying this plan is durable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct BootstrapPlan {
    archive_id: ArchiveId,
    attempt_id: BootstrapAttemptId,
    database_epoch: DatabaseEpoch,
    key_epoch: KeyEpoch,
    registry_object_id: ObjectId,
    root_object_id: ObjectId,
}

impl BootstrapPlan {
    pub(crate) fn new(
        archive_id: ArchiveId,
        attempt_id: BootstrapAttemptId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        registry_object_id: ObjectId,
        root_object_id: ObjectId,
    ) -> Result<Self, LifecycleError> {
        if !nonzero(archive_id.as_bytes())
            || !nonzero(database_epoch.as_bytes())
            || !nonzero(key_epoch.as_bytes())
            || !nonzero(registry_object_id.as_bytes())
            || !nonzero(root_object_id.as_bytes())
            || registry_object_id == root_object_id
        {
            return Err(LifecycleError::Malformed);
        }
        Ok(Self {
            archive_id,
            attempt_id,
            database_epoch,
            key_epoch,
            registry_object_id,
            root_object_id,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn attempt_id(&self) -> BootstrapAttemptId {
        self.attempt_id
    }

    pub(crate) const fn database_epoch(&self) -> DatabaseEpoch {
        self.database_epoch
    }

    pub(crate) const fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    pub(crate) const fn registry_object_id(&self) -> ObjectId {
        self.registry_object_id
    }

    pub(crate) const fn root_object_id(&self) -> ObjectId {
        self.root_object_id
    }
}

impl fmt::Debug for BootstrapPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapPlan(<opaque>)")
    }
}

/// Receipt minted only after a plan has been committed to durable storage.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurableBootstrapReservation {
    plan: BootstrapPlan,
    revision: u64,
}

impl DurableBootstrapReservation {
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        plan: BootstrapPlan,
        revision: u64,
    ) -> Result<Self, LifecycleError> {
        (revision > 0)
            .then_some(Self { plan, revision })
            .ok_or(LifecycleError::Malformed)
    }

    #[cfg(test)]
    pub(crate) fn for_test(plan: BootstrapPlan, revision: u64) -> Result<Self, LifecycleError> {
        (revision > 0)
            .then_some(Self { plan, revision })
            .ok_or(LifecycleError::Malformed)
    }

    pub(crate) const fn plan(&self) -> BootstrapPlan {
        self.plan
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }
}

impl fmt::Debug for DurableBootstrapReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableBootstrapReservation(<opaque>)")
    }
}

/// Exact retry-stable bootstrap bytes returned only after both payloads were
/// durably recorded under the reservation.
pub(crate) struct PreparedBootstrap {
    reservation: DurableBootstrapReservation,
    revision: u64,
    wrapped_registry: Zeroizing<Vec<u8>>,
    root_envelope: Zeroizing<Vec<u8>>,
    wrapped_registry_hash: [u8; 32],
    root_envelope_hash: [u8; 32],
}

impl PreparedBootstrap {
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        reservation: DurableBootstrapReservation,
        revision: u64,
        wrapped_registry: Vec<u8>,
        root_envelope: Vec<u8>,
        expected_registry_hash: [u8; 32],
        expected_root_hash: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            reservation,
            revision,
            wrapped_registry,
            root_envelope,
            expected_registry_hash,
            expected_root_hash,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        reservation: DurableBootstrapReservation,
        revision: u64,
        wrapped_registry: Vec<u8>,
        root_envelope: Vec<u8>,
        expected_registry_hash: [u8; 32],
        expected_root_hash: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            reservation,
            revision,
            wrapped_registry,
            root_envelope,
            expected_registry_hash,
            expected_root_hash,
        )
    }

    fn validated(
        reservation: DurableBootstrapReservation,
        revision: u64,
        wrapped_registry: Vec<u8>,
        root_envelope: Vec<u8>,
        expected_registry_hash: [u8; 32],
        expected_root_hash: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if revision <= reservation.revision
            || wrapped_registry.is_empty()
            || wrapped_registry.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
            || root_envelope.is_empty()
            || root_envelope.len() > MAX_ENCODED_ENVELOPE_BYTES
            || digest(&wrapped_registry) != expected_registry_hash
            || digest(&root_envelope) != expected_root_hash
        {
            return Err(LifecycleError::Malformed);
        }
        Ok(Self {
            reservation,
            revision,
            wrapped_registry: Zeroizing::new(wrapped_registry),
            root_envelope: Zeroizing::new(root_envelope),
            wrapped_registry_hash: expected_registry_hash,
            root_envelope_hash: expected_root_hash,
        })
    }

    pub(crate) const fn reservation(&self) -> DurableBootstrapReservation {
        self.reservation
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn wrapped_registry(&self) -> &[u8] {
        &self.wrapped_registry
    }

    pub(crate) fn root_envelope(&self) -> &[u8] {
        &self.root_envelope
    }

    pub(crate) const fn wrapped_registry_hash(&self) -> [u8; 32] {
        self.wrapped_registry_hash
    }

    pub(crate) const fn root_envelope_hash(&self) -> [u8; 32] {
        self.root_envelope_hash
    }
}

impl fmt::Debug for PreparedBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedBootstrap(<opaque>)")
    }
}

/// Exact bootstrap state recovered from the encrypted control anchor without
/// requiring a caller to retain the random plan or a prior opaque receipt.
pub(crate) enum RecoveredBootstrap {
    Reserved(DurableBootstrapReservation),
    Prepared(PreparedBootstrap),
}

impl RecoveredBootstrap {
    pub(crate) const fn reservation(&self) -> DurableBootstrapReservation {
        match self {
            Self::Reserved(reservation) => *reservation,
            Self::Prepared(prepared) => prepared.reservation(),
        }
    }

    pub(crate) fn prepared(&self) -> Option<&PreparedBootstrap> {
        match self {
            Self::Reserved(_) => None,
            Self::Prepared(prepared) => Some(prepared),
        }
    }
}

impl fmt::Debug for RecoveredBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveredBootstrap(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ArtifactCreateState {
    Planned = 1,
    OutcomeUnknown = 2,
    Created = 3,
    ConfirmedAbsent = 4,
}

impl ArtifactCreateState {
    fn decode(value: u8) -> Result<Self, LifecycleError> {
        match value {
            1 => Ok(Self::Planned),
            2 => Ok(Self::OutcomeUnknown),
            3 => Ok(Self::Created),
            4 => Ok(Self::ConfirmedAbsent),
            _ => Err(LifecycleError::Corrupt),
        }
    }

    pub(crate) const fn remains_deletion_work(self) -> bool {
        true
    }
}

/// Exact immutable storage artifact recorded before its provider create.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PlannedArtifact {
    attempt_id: BootstrapAttemptId,
    ordinal: u32,
    key: ObjectKey,
    role: ObjectRole,
    ciphertext_hash: [u8; 32],
    encoded_len: u32,
    create_state: ArtifactCreateState,
}

impl PlannedArtifact {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        archive_id: ArchiveId,
        attempt_id: BootstrapAttemptId,
        ordinal: u32,
        key: ObjectKey,
        role: ObjectRole,
        ciphertext_hash: [u8; 32],
        encoded_len: usize,
        create_state: ArtifactCreateState,
    ) -> Result<Self, LifecycleError> {
        let encoded_len = u32::try_from(encoded_len).map_err(|_| LifecycleError::Limit)?;
        if encoded_len == 0
            || !nonzero(&ciphertext_hash)
            || key.as_str().len() > MAX_LIFECYCLE_OBJECT_KEY_BYTES
            || !key
                .as_str()
                .starts_with(ArchivePrefix::for_archive(archive_id).as_str())
            || canonical_object_identity(key.as_str()) != Some((key.object_id(), role))
        {
            return Err(LifecycleError::Malformed);
        }
        Ok(Self {
            attempt_id,
            ordinal,
            key,
            role,
            ciphertext_hash,
            encoded_len,
            create_state,
        })
    }

    pub(crate) const fn attempt_id(&self) -> BootstrapAttemptId {
        self.attempt_id
    }

    pub(crate) const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub(crate) fn key(&self) -> &ObjectKey {
        &self.key
    }

    pub(crate) const fn role(&self) -> ObjectRole {
        self.role
    }

    pub(crate) const fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }

    pub(crate) const fn encoded_len(&self) -> u32 {
        self.encoded_len
    }

    pub(crate) const fn create_state(&self) -> ArtifactCreateState {
        self.create_state
    }

    /// Remove create-operation state from the immutable deletion fact. The
    /// attempt, ordinal, outcome, and encoded length remain only in the frozen
    /// create-ahead snapshot and never enter final inventory pages.
    pub(crate) fn inventory_object(&self) -> Result<LifecycleInventoryObject, LifecycleError> {
        LifecycleInventoryObject::new(self.key.clone(), self.role, self.ciphertext_hash)
    }
}

impl fmt::Debug for PlannedArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlannedArtifact(<opaque>)")
    }
}

/// Content-free, immutable create-ahead snapshot durably frozen before the
/// authenticated graph walk. It is not a page admission or deletion seal.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FrozenInventorySnapshot {
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    revision: u64,
    create_ahead: Vec<PlannedArtifact>,
    /// Frozen create-ahead facts that are NOT genesis bootstrap artifacts:
    /// every unconsumed WAL publication/checkpoint artifact row and every
    /// durably staged genesis object. These are recorded before the provider
    /// create that names them, so a crashed attempt's uploaded object is
    /// enumerable here even though nothing reaches it from any root.
    ///
    /// They arrive as [`LifecycleInventoryObject`] rather than
    /// [`PlannedArtifact`] deliberately: the create-ahead ledger's
    /// `artifact_ordinal IN (0,1)` CHECK admits only the genesis registry and
    /// root, and `PlannedArtifact::new` demands a nonzero `encoded_len` these
    /// rows do not carry. Neither constraint is relaxed to make them fit.
    widened: Vec<LifecycleInventoryObject>,
}

impl FrozenInventorySnapshot {
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        revision: u64,
        create_ahead: Vec<PlannedArtifact>,
        widened: Vec<LifecycleInventoryObject>,
    ) -> Result<Self, LifecycleError> {
        Self::validated(archive_id, deletion_fence, revision, create_ahead, widened)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        revision: u64,
        create_ahead: Vec<PlannedArtifact>,
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            archive_id,
            deletion_fence,
            revision,
            create_ahead,
            Vec::new(),
        )
    }

    #[cfg(test)]
    pub(crate) fn for_widened_test(
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        revision: u64,
        create_ahead: Vec<PlannedArtifact>,
        widened: Vec<LifecycleInventoryObject>,
    ) -> Result<Self, LifecycleError> {
        Self::validated(archive_id, deletion_fence, revision, create_ahead, widened)
    }

    fn validated(
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        revision: u64,
        create_ahead: Vec<PlannedArtifact>,
        widened: Vec<LifecycleInventoryObject>,
    ) -> Result<Self, LifecycleError> {
        if !nonzero(archive_id.as_bytes())
            || !nonzero(deletion_fence.as_bytes())
            || revision == 0
            || create_ahead.len() > MAX_LIFECYCLE_ARTIFACTS
            || widened.len() > MAX_LIFECYCLE_ARTIFACTS
            || create_ahead
                .len()
                .checked_add(widened.len())
                .is_none_or(|total| total > MAX_LIFECYCLE_ARTIFACTS)
            || create_ahead.iter().any(|artifact| {
                artifact.create_state == ArtifactCreateState::OutcomeUnknown
                    || !artifact
                        .key
                        .as_str()
                        .starts_with(ArchivePrefix::for_archive(archive_id).as_str())
            })
            // The per-entry blast-radius bound the driver enforces at delete
            // time is enforced here too: a widened row can never name an
            // object outside this archive's own prefix.
            || widened.iter().any(|object| {
                !object
                    .key()
                    .as_str()
                    .starts_with(ArchivePrefix::for_archive(archive_id).as_str())
            })
        {
            return Err(LifecycleError::Malformed);
        }
        let mut previous = None;
        for artifact in &create_ahead {
            let current = (artifact.attempt_id, artifact.ordinal, artifact.key.as_str());
            if previous.is_some_and(|value| value >= current) {
                return Err(LifecycleError::Malformed);
            }
            previous = Some(current);
        }
        // Strictly increasing by canonical key: the persisted order is the
        // committed order, so a duplicate or a reordered row is a corrupted
        // snapshot rather than something to silently normalize.
        let mut previous_key: Option<&str> = None;
        for object in &widened {
            let current = object.key().as_str();
            if previous_key.is_some_and(|value| value >= current) {
                return Err(LifecycleError::Malformed);
            }
            previous_key = Some(current);
        }
        Ok(Self {
            archive_id,
            deletion_fence,
            revision,
            create_ahead,
            widened,
        })
    }

    pub(crate) fn widened(&self) -> &[LifecycleInventoryObject] {
        &self.widened
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn deletion_fence(&self) -> ObjectId {
        self.deletion_fence
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn create_ahead(&self) -> &[PlannedArtifact] {
        &self.create_ahead
    }
}

impl fmt::Debug for FrozenInventorySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenInventorySnapshot(<opaque>)")
    }
}

/// Durable, type-separated inventory boundary for a deletion that proved the
/// initial witness send never started. It is intentionally non-cloneable: the
/// first coordinator consumes either the fresh absence receipt into this
/// snapshot or recovers this exact snapshot from encrypted control after a
/// restart. It is not a tombstoned-witness reachability snapshot.
#[derive(PartialEq, Eq)]
pub(crate) struct FrozenPreWitnessInventorySnapshot {
    plan: BootstrapPlan,
    deletion_fence: ObjectId,
    absence_revision: u64,
    revision: u64,
    protocol_version: u16,
    expected_witness_hash: Option<[u8; 32]>,
    expected_witness_len: Option<u32>,
    protocol_commitment: [u8; 32],
    snapshot_commitment: [u8; 32],
    create_ahead: Vec<PlannedArtifact>,
}

impl FrozenPreWitnessInventorySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        plan: BootstrapPlan,
        deletion_fence: ObjectId,
        absence_revision: u64,
        revision: u64,
        protocol_version: u16,
        expected_witness_hash: Option<[u8; 32]>,
        expected_witness_len: Option<u32>,
        protocol_commitment: [u8; 32],
        snapshot_commitment: [u8; 32],
        create_ahead: Vec<PlannedArtifact>,
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            plan,
            deletion_fence,
            absence_revision,
            revision,
            protocol_version,
            expected_witness_hash,
            expected_witness_len,
            protocol_commitment,
            snapshot_commitment,
            create_ahead,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        plan: BootstrapPlan,
        deletion_fence: ObjectId,
        absence_revision: u64,
        revision: u64,
        expected_witness_hash: Option<[u8; 32]>,
        expected_witness_len: Option<u32>,
        protocol_commitment: [u8; 32],
        create_ahead: Vec<PlannedArtifact>,
    ) -> Result<Self, LifecycleError> {
        let snapshot_commitment = pre_witness_snapshot_commitment(
            plan,
            deletion_fence,
            absence_revision,
            revision,
            WITNESS_CREATE_PROTOCOL_V1,
            expected_witness_hash,
            expected_witness_len,
            protocol_commitment,
            &create_ahead,
        )?;
        Self::validated(
            plan,
            deletion_fence,
            absence_revision,
            revision,
            WITNESS_CREATE_PROTOCOL_V1,
            expected_witness_hash,
            expected_witness_len,
            protocol_commitment,
            snapshot_commitment,
            create_ahead,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn validated(
        plan: BootstrapPlan,
        deletion_fence: ObjectId,
        absence_revision: u64,
        revision: u64,
        protocol_version: u16,
        expected_witness_hash: Option<[u8; 32]>,
        expected_witness_len: Option<u32>,
        protocol_commitment: [u8; 32],
        snapshot_commitment: [u8; 32],
        create_ahead: Vec<PlannedArtifact>,
    ) -> Result<Self, LifecycleError> {
        if !nonzero(deletion_fence.as_bytes())
            || absence_revision == 0
            || absence_revision.checked_add(1) != Some(revision)
            || protocol_version != WITNESS_CREATE_PROTOCOL_V1
            || !nonzero(&protocol_commitment)
            || !matches!(
                (expected_witness_hash, expected_witness_len),
                (None, None) | (Some(_), Some(_))
            )
            || expected_witness_hash.is_some_and(|hash| !nonzero(&hash))
            || expected_witness_len == Some(0)
            || create_ahead.len() > MAX_LIFECYCLE_ARTIFACTS
        {
            return Err(LifecycleError::Corrupt);
        }
        let mut previous = None;
        for artifact in &create_ahead {
            let current = (artifact.attempt_id, artifact.ordinal, artifact.key.as_str());
            if artifact.attempt_id != plan.attempt_id()
                || artifact.create_state == ArtifactCreateState::OutcomeUnknown
                || !artifact
                    .key
                    .as_str()
                    .starts_with(ArchivePrefix::for_archive(plan.archive_id()).as_str())
                || previous.is_some_and(|value| value >= current)
            {
                return Err(LifecycleError::Corrupt);
            }
            previous = Some(current);
        }
        let expected = pre_witness_snapshot_commitment(
            plan,
            deletion_fence,
            absence_revision,
            revision,
            protocol_version,
            expected_witness_hash,
            expected_witness_len,
            protocol_commitment,
            &create_ahead,
        )?;
        if snapshot_commitment != expected || !nonzero(&snapshot_commitment) {
            return Err(LifecycleError::Corrupt);
        }
        Ok(Self {
            plan,
            deletion_fence,
            absence_revision,
            revision,
            protocol_version,
            expected_witness_hash,
            expected_witness_len,
            protocol_commitment,
            snapshot_commitment,
            create_ahead,
        })
    }

    pub(crate) const fn plan(&self) -> BootstrapPlan {
        self.plan
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.plan.archive_id()
    }

    pub(crate) const fn deletion_fence(&self) -> ObjectId {
        self.deletion_fence
    }

    pub(crate) const fn absence_revision(&self) -> u64 {
        self.absence_revision
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn expected_witness_hash(&self) -> Option<[u8; 32]> {
        self.expected_witness_hash
    }

    pub(crate) const fn expected_witness_len(&self) -> Option<u32> {
        self.expected_witness_len
    }

    pub(crate) const fn protocol_commitment(&self) -> [u8; 32] {
        self.protocol_commitment
    }

    pub(crate) const fn snapshot_commitment_for_control(
        &self,
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
    ) -> [u8; 32] {
        self.snapshot_commitment
    }

    #[cfg(test)]
    pub(crate) const fn snapshot_commitment_for_test(&self) -> [u8; 32] {
        self.snapshot_commitment
    }

    pub(crate) fn create_ahead(&self) -> &[PlannedArtifact] {
        &self.create_ahead
    }
}

impl fmt::Debug for FrozenPreWitnessInventorySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenPreWitnessInventorySnapshot(<opaque>)")
    }
}

/// Canonical exact-object fact stored in the final deletion inventory.
///
/// This intentionally carries no create-attempt state, caller/account
/// identity, encoded length, or provider capability. Strict canonical parsing
/// binds the key, embedded object ID, role, archive prefix, and ciphertext
/// hash before a fact can participate in paging or deletion.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LifecycleInventoryObject {
    key: ObjectKey,
    role: ObjectRole,
    ciphertext_hash: [u8; 32],
}

impl LifecycleInventoryObject {
    fn new(
        key: ObjectKey,
        role: ObjectRole,
        ciphertext_hash: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        let Some((object_id, canonical_role)) = canonical_object_identity(key.as_str()) else {
            return Err(LifecycleError::Malformed);
        };
        if key.as_str().len() > MAX_LIFECYCLE_OBJECT_KEY_BYTES
            || object_id != key.object_id()
            || canonical_role != role
            || !nonzero(key.object_id().as_bytes())
            || !nonzero(&ciphertext_hash)
        {
            return Err(LifecycleError::Malformed);
        }
        Ok(Self {
            key,
            role,
            ciphertext_hash,
        })
    }

    pub(crate) fn for_archive(
        archive_id: ArchiveId,
        key: ObjectKey,
        role: ObjectRole,
        ciphertext_hash: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if !nonzero(archive_id.as_bytes())
            || !key
                .as_str()
                .starts_with(ArchivePrefix::for_archive(archive_id).as_str())
        {
            return Err(LifecycleError::Malformed);
        }
        Self::new(key, role, ciphertext_hash)
    }

    pub(crate) fn key(&self) -> &ObjectKey {
        &self.key
    }

    pub(crate) const fn role(&self) -> ObjectRole {
        self.role
    }

    pub(crate) const fn ciphertext_hash(&self) -> [u8; 32] {
        self.ciphertext_hash
    }
}

impl fmt::Debug for LifecycleInventoryObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LifecycleInventoryObject(<opaque>)")
    }
}

/// One-shot, fresh CAS admission. Persisted identifiers never authenticate a
/// create; adapters must consume the whole tuple immediately before I/O.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ActiveCreateAdmission {
    archive_id: ArchiveId,
    attempt_id: BootstrapAttemptId,
    revision: u64,
    artifact_ordinal: u32,
    artifact_hash: [u8; 32],
}

impl ActiveCreateAdmission {
    pub(crate) fn from_fresh_cas(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        archive_id: ArchiveId,
        attempt_id: BootstrapAttemptId,
        revision: u64,
        artifact_ordinal: u32,
        artifact_hash: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            archive_id,
            attempt_id,
            revision,
            artifact_ordinal,
            artifact_hash,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        archive_id: ArchiveId,
        attempt_id: BootstrapAttemptId,
        revision: u64,
        artifact_ordinal: u32,
        artifact_hash: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            archive_id,
            attempt_id,
            revision,
            artifact_ordinal,
            artifact_hash,
        )
    }

    fn validated(
        archive_id: ArchiveId,
        attempt_id: BootstrapAttemptId,
        revision: u64,
        artifact_ordinal: u32,
        artifact_hash: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if revision == 0 || !nonzero(&artifact_hash) {
            return Err(LifecycleError::Malformed);
        }
        Ok(Self {
            archive_id,
            attempt_id,
            revision,
            artifact_ordinal,
            artifact_hash,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn attempt_id(&self) -> BootstrapAttemptId {
        self.attempt_id
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn artifact_ordinal(&self) -> u32 {
        self.artifact_ordinal
    }

    pub(crate) const fn artifact_hash(&self) -> [u8; 32] {
        self.artifact_hash
    }
}

impl fmt::Debug for ActiveCreateAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveCreateAdmission(<opaque>)")
    }
}

/// Durable dispatch marker for the one witness create admitted by bootstrap.
///
/// This is deliberately non-Clone and non-serializable. The Firestore adapter
/// may borrow it only for the exact commit whose admission was atomically
/// marked `send_started` in encrypted control state.
pub(crate) struct WitnessSendStarted {
    archive_id: ArchiveId,
    attempt_id: BootstrapAttemptId,
    admission_revision: u64,
    expected_hash: [u8; 32],
    protocol_commitment: [u8; 32],
}

impl WitnessSendStarted {
    pub(crate) fn from_persisted_dispatch(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        admission: &ActiveCreateAdmission,
        protocol_commitment: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if admission.artifact_ordinal() != 2 || !nonzero(&protocol_commitment) {
            return Err(LifecycleError::InvalidState);
        }
        Ok(Self {
            archive_id: admission.archive_id(),
            attempt_id: admission.attempt_id(),
            admission_revision: admission.revision(),
            expected_hash: admission.artifact_hash(),
            protocol_commitment,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        admission: &ActiveCreateAdmission,
        protocol_commitment: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if admission.artifact_ordinal() != 2 || !nonzero(&protocol_commitment) {
            return Err(LifecycleError::InvalidState);
        }
        Ok(Self {
            archive_id: admission.archive_id(),
            attempt_id: admission.attempt_id(),
            admission_revision: admission.revision(),
            expected_hash: admission.artifact_hash(),
            protocol_commitment,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn attempt_id(&self) -> BootstrapAttemptId {
        self.attempt_id
    }

    pub(crate) const fn admission_revision(&self) -> u64 {
        self.admission_revision
    }

    pub(crate) const fn expected_hash(&self) -> [u8; 32] {
        self.expected_hash
    }

    pub(crate) const fn protocol_commitment(&self) -> [u8; 32] {
        self.protocol_commitment
    }
}

impl fmt::Debug for WitnessSendStarted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WitnessSendStarted(<opaque>)")
    }
}

/// Narrow marker boundary that must be crossed after Firestore has begun and
/// validated its exact transaction, but before the commit can be submitted.
#[async_trait]
pub(crate) trait WitnessCreateDispatchLedger: Send + Sync {
    async fn mark_witness_send_started(
        &self,
        admission: &ActiveCreateAdmission,
    ) -> Result<WitnessSendStarted, LifecycleError>;
}

/// Canonical hash-chained page. The encoded bytes are safe to persist only in
/// the control-key-protected lifecycle store.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct InventoryPage {
    archive_id: ArchiveId,
    page_ordinal: u32,
    previous_hash: [u8; 32],
    entries: Vec<LifecycleInventoryObject>,
    encoded: Vec<u8>,
    page_hash: [u8; 32],
    page_id: ObjectId,
}

impl InventoryPage {
    pub(crate) fn build(
        archive_id: ArchiveId,
        page_ordinal: u32,
        previous_hash: [u8; 32],
        entries: Vec<LifecycleInventoryObject>,
    ) -> Result<Self, LifecycleError> {
        if entries.is_empty()
            || entries.len() > MAX_LIFECYCLE_PAGE_ENTRIES
            || usize::try_from(page_ordinal).map_or(true, |ordinal| ordinal >= MAX_LIFECYCLE_PAGES)
            || (page_ordinal == 0) != (previous_hash == ZERO_HASH)
        {
            return Err(LifecycleError::Malformed);
        }
        ensure_entries(archive_id, &entries)?;
        let encoded = encode_page(archive_id, page_ordinal, previous_hash, &entries)?;
        let page_hash = digest_domain(PAGE_DOMAIN, &encoded);
        let page_id = object_id_from_hash(page_hash)?;
        Ok(Self {
            archive_id,
            page_ordinal,
            previous_hash,
            entries,
            encoded,
            page_hash,
            page_id,
        })
    }

    pub(crate) fn decode(
        expected_archive: ArchiveId,
        bytes: &[u8],
    ) -> Result<Self, LifecycleError> {
        if bytes.is_empty() || bytes.len() > MAX_LIFECYCLE_PAGE_BYTES {
            return Err(LifecycleError::Limit);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(4)? != b"KILP" || cursor.u16()? != LIFECYCLE_INVENTORY_PAGE_VERSION {
            return Err(LifecycleError::Corrupt);
        }
        let archive_id = ArchiveId::from_bytes(cursor.array()?);
        let page_ordinal = cursor.u32()?;
        let previous_hash = cursor.array()?;
        let entry_count = usize::from(cursor.u16()?);
        if archive_id != expected_archive
            || entry_count == 0
            || entry_count > MAX_LIFECYCLE_PAGE_ENTRIES
            || usize::try_from(page_ordinal).map_or(true, |ordinal| ordinal >= MAX_LIFECYCLE_PAGES)
            || (page_ordinal == 0) != (previous_hash == ZERO_HASH)
        {
            return Err(LifecycleError::Corrupt);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let role = role(cursor.u8()?)?;
            let object_id = ObjectId::from_bytes(cursor.array()?);
            let ciphertext_hash = cursor.array()?;
            let key_len = usize::from(cursor.u16()?);
            if key_len == 0 || key_len > MAX_LIFECYCLE_OBJECT_KEY_BYTES {
                return Err(LifecycleError::Corrupt);
            }
            let key = std::str::from_utf8(cursor.take(key_len)?)
                .map_err(|_| LifecycleError::Corrupt)?
                .to_owned();
            entries.push(
                LifecycleInventoryObject::for_archive(
                    archive_id,
                    ObjectKey::from_validated_canonical(key, object_id),
                    role,
                    ciphertext_hash,
                )
                .map_err(|_| LifecycleError::Corrupt)?,
            );
        }
        if !cursor.finished() {
            return Err(LifecycleError::Corrupt);
        }
        ensure_entries(archive_id, &entries)?;
        Ok(Self {
            archive_id,
            page_ordinal,
            previous_hash,
            entries,
            encoded: bytes.to_vec(),
            page_hash: digest_domain(PAGE_DOMAIN, bytes),
            page_id: object_id_from_hash(digest_domain(PAGE_DOMAIN, bytes))?,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn page_ordinal(&self) -> u32 {
        self.page_ordinal
    }

    pub(crate) const fn previous_hash(&self) -> [u8; 32] {
        self.previous_hash
    }

    pub(crate) fn entries(&self) -> &[LifecycleInventoryObject] {
        &self.entries
    }

    pub(crate) fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub(crate) const fn page_hash(&self) -> [u8; 32] {
        self.page_hash
    }

    pub(crate) const fn page_id(&self) -> ObjectId {
        self.page_id
    }

    pub(crate) fn reference(&self) -> InventoryPageReference {
        InventoryPageReference {
            archive_id: self.archive_id,
            page_ordinal: self.page_ordinal,
            page_id: self.page_id,
            previous_hash: self.previous_hash,
            page_hash: self.page_hash,
            encoded_len: self.encoded.len() as u32,
        }
    }
}

impl fmt::Debug for InventoryPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InventoryPage(<opaque>)")
    }
}

/// Receipt from immutable, control-key-encrypted page creation and exact
/// readback. The small control anchor may seal only these receipts, never a
/// caller-retained page that might not exist durably.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DurableInventoryPage {
    page: InventoryPage,
}

impl DurableInventoryPage {
    /// Minted only by the encrypted external page producer after the exact
    /// object has been read back, authenticated, decoded, and matched to its
    /// complete control-anchor reference.
    pub(crate) fn from_authenticated_external_readback(
        _producer: &crate::archive_v3_lifecycle_page_store::AuthenticatedPageReadback,
        reference: InventoryPageReference,
        page: InventoryPage,
    ) -> Result<Self, LifecycleError> {
        if page.reference() != reference
            || InventoryPage::decode(reference.archive_id(), page.encoded())? != page
        {
            return Err(LifecycleError::ChainMismatch);
        }
        Ok(Self { page })
    }

    #[cfg(test)]
    pub(crate) fn from_exact_readback(
        page: InventoryPage,
        exact_encoded_readback: &[u8],
    ) -> Result<Self, LifecycleError> {
        if exact_encoded_readback != page.encoded()
            || InventoryPage::decode(page.archive_id(), exact_encoded_readback)? != page
        {
            return Err(LifecycleError::ChainMismatch);
        }
        Ok(Self { page })
    }

    pub(crate) const fn page(&self) -> &InventoryPage {
        &self.page
    }
}

impl fmt::Debug for DurableInventoryPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableInventoryPage(<opaque>)")
    }
}

/// Small control-database anchor for an exact encrypted page. The artifact
/// entries and canonical keys remain in the separately control-key-encrypted
/// page store; the whole control SQLite blob retains only this bounded tuple.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct InventoryPageReference {
    archive_id: ArchiveId,
    page_ordinal: u32,
    page_id: ObjectId,
    previous_hash: [u8; 32],
    page_hash: [u8; 32],
    encoded_len: u32,
}

impl InventoryPageReference {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        archive_id: ArchiveId,
        page_ordinal: u32,
        page_id: ObjectId,
        previous_hash: [u8; 32],
        page_hash: [u8; 32],
        encoded_len: u32,
    ) -> Result<Self, LifecycleError> {
        if !nonzero(page_id.as_bytes())
            || !nonzero(&page_hash)
            || encoded_len == 0
            || usize::try_from(page_ordinal).map_or(true, |ordinal| ordinal >= MAX_LIFECYCLE_PAGES)
            || usize::try_from(encoded_len).map_or(true, |len| len > MAX_LIFECYCLE_PAGE_BYTES)
            || (page_ordinal == 0) != (previous_hash == ZERO_HASH)
            || page_id != object_id_from_hash(page_hash)?
        {
            return Err(LifecycleError::Corrupt);
        }
        Ok(Self {
            archive_id,
            page_ordinal,
            page_id,
            previous_hash,
            page_hash,
            encoded_len,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        archive_id: ArchiveId,
        page_ordinal: u32,
        page_id: ObjectId,
        previous_hash: [u8; 32],
        page_hash: [u8; 32],
        encoded_len: u32,
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            archive_id,
            page_ordinal,
            page_id,
            previous_hash,
            page_hash,
            encoded_len,
        )
    }

    fn validated(
        archive_id: ArchiveId,
        page_ordinal: u32,
        page_id: ObjectId,
        previous_hash: [u8; 32],
        page_hash: [u8; 32],
        encoded_len: u32,
    ) -> Result<Self, LifecycleError> {
        if !nonzero(page_id.as_bytes())
            || !nonzero(&page_hash)
            || encoded_len == 0
            || usize::try_from(page_ordinal).map_or(true, |ordinal| ordinal >= MAX_LIFECYCLE_PAGES)
            || usize::try_from(encoded_len).map_or(true, |len| len > MAX_LIFECYCLE_PAGE_BYTES)
            || (page_ordinal == 0) != (previous_hash == ZERO_HASH)
            || page_id != object_id_from_hash(page_hash)?
        {
            return Err(LifecycleError::Corrupt);
        }
        Ok(Self {
            archive_id,
            page_ordinal,
            page_id,
            previous_hash,
            page_hash,
            encoded_len,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn page_ordinal(&self) -> u32 {
        self.page_ordinal
    }

    pub(crate) const fn page_id(&self) -> ObjectId {
        self.page_id
    }

    pub(crate) const fn previous_hash(&self) -> [u8; 32] {
        self.previous_hash
    }

    pub(crate) const fn page_hash(&self) -> [u8; 32] {
        self.page_hash
    }

    pub(crate) const fn encoded_len(&self) -> u32 {
        self.encoded_len
    }
}

impl fmt::Debug for InventoryPageReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InventoryPageReference(<opaque>)")
    }
}

/// Separate exact page storage. Implementations must encrypt each page under
/// the control key with AAD covering the complete reference, use immutable
/// create-if-absent, reconcile ambiguity only by exact read, and erase payloads
/// only after physical completion. No implementation is constructed here.
#[async_trait]
pub(crate) trait ArchiveLifecyclePageStore: Send + Sync {
    async fn create_exact_page(
        &self,
        deletion_fence: ObjectId,
        page: &InventoryPage,
    ) -> Result<DurableInventoryPage, LifecycleError>;

    async fn read_exact_page(
        &self,
        deletion_fence: ObjectId,
        reference: InventoryPageReference,
    ) -> Result<DurableInventoryPage, LifecycleError>;

    async fn erase_exact_pages_after_physical_completion(
        &self,
        completion: &DurablePhysicalCompletion,
        references: &[InventoryPageReference],
    ) -> Result<ErasedInventoryPages, LifecycleError>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeletionInventorySeal {
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    revision: u64,
    page_count: u32,
    artifact_count: u32,
    terminal_page_hash: [u8; 32],
    inventory_commitment: [u8; 32],
}

impl DeletionInventorySeal {
    pub(crate) fn from_durable_pages(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        revision: u64,
        pages: &[DurableInventoryPage],
    ) -> Result<Self, LifecycleError> {
        Self::validated(archive_id, deletion_fence, revision, pages)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_persisted_anchor(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        revision: u64,
        page_count: u32,
        artifact_count: u32,
        terminal_page_hash: [u8; 32],
        expected_inventory_commitment: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if revision == 0
            || !nonzero(deletion_fence.as_bytes())
            || page_count == 0
            || usize::try_from(page_count).map_or(true, |count| count > MAX_LIFECYCLE_PAGES)
            || artifact_count == 0
            || usize::try_from(artifact_count).map_or(true, |count| count > MAX_LIFECYCLE_ARTIFACTS)
            || !nonzero(&terminal_page_hash)
            || inventory_commitment(
                archive_id,
                deletion_fence,
                page_count,
                artifact_count,
                terminal_page_hash,
            ) != expected_inventory_commitment
        {
            return Err(LifecycleError::Corrupt);
        }
        Ok(Self {
            archive_id,
            deletion_fence,
            revision,
            page_count,
            artifact_count,
            terminal_page_hash,
            inventory_commitment: expected_inventory_commitment,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        revision: u64,
        pages: &[DurableInventoryPage],
    ) -> Result<Self, LifecycleError> {
        Self::validated(archive_id, deletion_fence, revision, pages)
    }

    fn validated(
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        revision: u64,
        pages: &[DurableInventoryPage],
    ) -> Result<Self, LifecycleError> {
        if revision == 0
            || !nonzero(deletion_fence.as_bytes())
            || pages.is_empty()
            || pages.len() > MAX_LIFECYCLE_PAGES
        {
            return Err(LifecycleError::Malformed);
        }
        let mut expected_previous = ZERO_HASH;
        let mut artifact_count = 0usize;
        let mut seen = BTreeMap::<ObjectId, (&str, [u8; 32], ObjectRole)>::new();
        let mut previous_object: Option<LifecycleInventoryObject> = None;
        for (index, durable) in pages.iter().enumerate() {
            let page = durable.page();
            if page.archive_id != archive_id
                || usize::try_from(page.page_ordinal).ok() != Some(index)
                || page.previous_hash != expected_previous
                || InventoryPage::decode(archive_id, &page.encoded)? != *page
            {
                return Err(LifecycleError::ChainMismatch);
            }
            for entry in &page.entries {
                if previous_object
                    .as_ref()
                    .is_some_and(|previous| previous >= entry)
                {
                    return Err(LifecycleError::ChainMismatch);
                }
                if seen
                    .insert(
                        entry.key.object_id(),
                        (entry.key.as_str(), entry.ciphertext_hash, entry.role),
                    )
                    .is_some()
                {
                    return Err(LifecycleError::DuplicateConflict);
                }
                previous_object = Some(entry.clone());
            }
            artifact_count = artifact_count
                .checked_add(page.entries.len())
                .ok_or(LifecycleError::Limit)?;
            if artifact_count > MAX_LIFECYCLE_ARTIFACTS {
                return Err(LifecycleError::Limit);
            }
            expected_previous = page.page_hash;
        }
        let page_count = u32::try_from(pages.len()).map_err(|_| LifecycleError::Limit)?;
        let artifact_count = u32::try_from(artifact_count).map_err(|_| LifecycleError::Limit)?;
        let inventory_commitment = inventory_commitment(
            archive_id,
            deletion_fence,
            page_count,
            artifact_count,
            expected_previous,
        );
        Ok(Self {
            archive_id,
            deletion_fence,
            revision,
            page_count,
            artifact_count,
            terminal_page_hash: expected_previous,
            inventory_commitment,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn deletion_fence(&self) -> ObjectId {
        self.deletion_fence
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn page_count(&self) -> u32 {
        self.page_count
    }

    pub(crate) const fn artifact_count(&self) -> u32 {
        self.artifact_count
    }

    pub(crate) const fn terminal_page_hash(&self) -> [u8; 32] {
        self.terminal_page_hash
    }

    pub(crate) const fn inventory_commitment(&self) -> [u8; 32] {
        self.inventory_commitment
    }
}

impl fmt::Debug for DeletionInventorySeal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeletionInventorySeal(<opaque>)")
    }
}

/// Type-separated durable seal for the branch that proved the initial witness
/// send never started. It cannot be converted into the tombstoned-witness
/// deletion seal and therefore grants no deletion-driver or provider entry
/// capability. The exact reserved-state representation is zero pages, zero
/// artifacts, and a zero terminal hash under a nonzero branch commitment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreWitnessDeletionInventorySeal {
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    snapshot_revision: u64,
    revision: u64,
    snapshot_commitment: [u8; 32],
    page_count: u32,
    artifact_count: u32,
    terminal_page_hash: [u8; 32],
    inventory_commitment: [u8; 32],
}

impl PreWitnessDeletionInventorySeal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_authenticated_pages(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        snapshot: &FrozenPreWitnessInventorySnapshot,
        revision: u64,
        pages: &[DurableInventoryPage],
        references: &[InventoryPageReference],
    ) -> Result<Self, LifecycleError> {
        let (page_count, artifact_count, terminal_page_hash) =
            validate_pre_witness_pages(snapshot.archive_id(), pages, references)?;
        Self::validated(
            snapshot.archive_id(),
            snapshot.deletion_fence(),
            snapshot.revision(),
            revision,
            snapshot.snapshot_commitment,
            page_count,
            artifact_count,
            terminal_page_hash,
            references,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        snapshot_revision: u64,
        revision: u64,
        snapshot_commitment: [u8; 32],
        page_count: u32,
        artifact_count: u32,
        terminal_page_hash: [u8; 32],
        inventory_commitment: [u8; 32],
        references: &[InventoryPageReference],
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            archive_id,
            deletion_fence,
            snapshot_revision,
            revision,
            snapshot_commitment,
            page_count,
            artifact_count,
            terminal_page_hash,
            references,
            Some(inventory_commitment),
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        snapshot: &FrozenPreWitnessInventorySnapshot,
        pages: &[DurableInventoryPage],
    ) -> Result<Self, LifecycleError> {
        let references = pages
            .iter()
            .map(|page| page.page().reference())
            .collect::<Vec<_>>();
        let revision = snapshot
            .revision()
            .checked_add(1)
            .ok_or(LifecycleError::Limit)?;
        let (page_count, artifact_count, terminal_page_hash) =
            validate_pre_witness_pages(snapshot.archive_id(), pages, &references)?;
        Self::validated(
            snapshot.archive_id(),
            snapshot.deletion_fence(),
            snapshot.revision(),
            revision,
            snapshot.snapshot_commitment,
            page_count,
            artifact_count,
            terminal_page_hash,
            &references,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn validated(
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        snapshot_revision: u64,
        revision: u64,
        snapshot_commitment: [u8; 32],
        page_count: u32,
        artifact_count: u32,
        terminal_page_hash: [u8; 32],
        references: &[InventoryPageReference],
        expected_commitment: Option<[u8; 32]>,
    ) -> Result<Self, LifecycleError> {
        if !nonzero(archive_id.as_bytes())
            || !nonzero(deletion_fence.as_bytes())
            || snapshot_revision == 0
            || snapshot_revision.checked_add(1) != Some(revision)
            || !nonzero(&snapshot_commitment)
            || usize::try_from(page_count).ok() != Some(references.len())
            || usize::try_from(page_count).map_or(true, |count| count > MAX_LIFECYCLE_PAGES)
            || usize::try_from(artifact_count).map_or(true, |count| count > MAX_LIFECYCLE_ARTIFACTS)
            || ((page_count == 0 || artifact_count == 0)
                && !(page_count == 0
                    && artifact_count == 0
                    && terminal_page_hash == ZERO_HASH
                    && references.is_empty()))
            || (page_count != 0 && !nonzero(&terminal_page_hash))
        {
            return Err(LifecycleError::Corrupt);
        }
        validate_pre_witness_references(archive_id, page_count, terminal_page_hash, references)?;
        let inventory_commitment = pre_witness_inventory_commitment(
            archive_id,
            deletion_fence,
            snapshot_revision,
            revision,
            snapshot_commitment,
            page_count,
            artifact_count,
            terminal_page_hash,
            references,
        );
        if !nonzero(&inventory_commitment)
            || expected_commitment.is_some_and(|expected| expected != inventory_commitment)
        {
            return Err(LifecycleError::Corrupt);
        }
        Ok(Self {
            archive_id,
            deletion_fence,
            snapshot_revision,
            revision,
            snapshot_commitment,
            page_count,
            artifact_count,
            terminal_page_hash,
            inventory_commitment,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn deletion_fence(&self) -> ObjectId {
        self.deletion_fence
    }

    pub(crate) const fn snapshot_revision(&self) -> u64 {
        self.snapshot_revision
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    const fn snapshot_commitment(&self) -> [u8; 32] {
        self.snapshot_commitment
    }

    pub(crate) const fn page_count(&self) -> u32 {
        self.page_count
    }

    pub(crate) const fn artifact_count(&self) -> u32 {
        self.artifact_count
    }

    pub(crate) const fn terminal_page_hash(&self) -> [u8; 32] {
        self.terminal_page_hash
    }

    pub(crate) const fn inventory_commitment(&self) -> [u8; 32] {
        self.inventory_commitment
    }
}

impl fmt::Debug for PreWitnessDeletionInventorySeal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreWitnessDeletionInventorySeal(<opaque>)")
    }
}

/// Same-commitment completion returned only after the deletion driver has
/// observed the durable witness `PhysicalComplete` transition. This receipt
/// authorizes lifecycle-page erasure, but it does not by itself authorize the
/// control anchor to forget page references or bootstrap payloads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PhysicalDeletionReceipt {
    seal: DeletionInventorySeal,
    provider_drain_commitment: [u8; 32],
}

impl PhysicalDeletionReceipt {
    pub(crate) fn from_verified_transition(
        proof: crate::archive_v3_deletion::VerifiedPhysicalTransition,
    ) -> Result<Self, LifecycleError> {
        let seal = proof.seal();
        let provider_drain_commitment = proof.provider_drain_commitment();
        if !nonzero(&provider_drain_commitment) {
            return Err(LifecycleError::Malformed);
        }
        Ok(Self {
            seal,
            provider_drain_commitment,
        })
    }

    pub(crate) fn from_persisted_control(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        seal: DeletionInventorySeal,
        provider_drain_commitment: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if !nonzero(&provider_drain_commitment) {
            return Err(LifecycleError::Malformed);
        }
        Ok(Self {
            seal,
            provider_drain_commitment,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        seal: DeletionInventorySeal,
        provider_drain_commitment: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if !nonzero(&provider_drain_commitment) {
            return Err(LifecycleError::Malformed);
        }
        Ok(Self {
            seal,
            provider_drain_commitment,
        })
    }

    pub(crate) const fn seal(&self) -> DeletionInventorySeal {
        self.seal
    }

    pub(crate) const fn provider_drain_commitment(&self) -> [u8; 32] {
        self.provider_drain_commitment
    }
}

impl fmt::Debug for PhysicalDeletionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PhysicalDeletionReceipt(<opaque>)")
    }
}

/// Receipt minted only after the encrypted control anchor durably records the
/// exact witness/provider physical-completion receipt. Page erasure requires
/// this stronger receipt so a crash between witness completion and the control
/// CAS cannot discard the restart inventory.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurablePhysicalCompletion {
    physical: PhysicalDeletionReceipt,
    control_revision: u64,
}

impl DurablePhysicalCompletion {
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        physical: PhysicalDeletionReceipt,
        control_revision: u64,
    ) -> Result<Self, LifecycleError> {
        Self::validated(physical, control_revision)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        physical: PhysicalDeletionReceipt,
        control_revision: u64,
    ) -> Result<Self, LifecycleError> {
        Self::validated(physical, control_revision)
    }

    fn validated(
        physical: PhysicalDeletionReceipt,
        control_revision: u64,
    ) -> Result<Self, LifecycleError> {
        if Some(control_revision) != physical.seal().revision().checked_add(1) {
            return Err(LifecycleError::StaleRevision);
        }
        Ok(Self {
            physical,
            control_revision,
        })
    }

    pub(crate) const fn physical_receipt(self) -> PhysicalDeletionReceipt {
        self.physical
    }

    pub(crate) const fn control_revision(self) -> u64 {
        self.control_revision
    }
}

impl fmt::Debug for DurablePhysicalCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurablePhysicalCompletion(<opaque>)")
    }
}

/// Deletion state reconstructed from one validated encrypted control snapshot.
/// The seal always exists; physical completion is present only after the exact
/// provider-drain receipt has been durably CAS-recorded.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoveredDeletionLifecycle {
    seal: DeletionInventorySeal,
    physical_completion: Option<DurablePhysicalCompletion>,
}

impl RecoveredDeletionLifecycle {
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        seal: DeletionInventorySeal,
        physical_completion: Option<DurablePhysicalCompletion>,
    ) -> Result<Self, LifecycleError> {
        if physical_completion
            .is_some_and(|completion| completion.physical_receipt().seal() != seal)
        {
            return Err(LifecycleError::ChainMismatch);
        }
        Ok(Self {
            seal,
            physical_completion,
        })
    }

    pub(crate) const fn seal(self) -> DeletionInventorySeal {
        self.seal
    }

    pub(crate) const fn physical_completion(self) -> Option<DurablePhysicalCompletion> {
        self.physical_completion
    }
}

impl fmt::Debug for RecoveredDeletionLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveredDeletionLifecycle(<opaque>)")
    }
}

/// Exact-page absence receipt from the control-key page store. The store must
/// mint it only after every sealed page's live, noncurrent, and soft-deleted
/// generations are absent. Control payload erasure requires this receipt and
/// the matching physical-completion receipt together.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ErasedInventoryPages {
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    inventory_commitment: [u8; 32],
    page_count: u32,
    terminal_page_hash: [u8; 32],
}

impl ErasedInventoryPages {
    /// Minted only by the external lifecycle-page store after it has verified
    /// all live, noncurrent, and soft-deleted generations absent for every
    /// exact page name authorized by the durable control completion.
    pub(crate) fn from_authenticated_external_absence(
        _producer: &crate::archive_v3_lifecycle_page_store::AuthenticatedPageAbsence,
        completion: &DurablePhysicalCompletion,
        references: &[InventoryPageReference],
    ) -> Result<Self, LifecycleError> {
        Self::validated(completion, references)
    }

    #[cfg(test)]
    pub(crate) fn from_exact_absence(
        completion: &DurablePhysicalCompletion,
        references: &[InventoryPageReference],
    ) -> Result<Self, LifecycleError> {
        Self::validated(completion, references)
    }

    fn validated(
        completion: &DurablePhysicalCompletion,
        references: &[InventoryPageReference],
    ) -> Result<Self, LifecycleError> {
        validate_cleanup_page_chain(completion, references)?;
        let seal = completion.physical_receipt().seal();
        Ok(Self {
            archive_id: seal.archive_id(),
            deletion_fence: seal.deletion_fence(),
            inventory_commitment: seal.inventory_commitment(),
            page_count: seal.page_count(),
            terminal_page_hash: seal.terminal_page_hash(),
        })
    }

    pub(crate) fn matches(self, completion: DurablePhysicalCompletion) -> bool {
        let seal = completion.physical_receipt().seal();
        self.archive_id == seal.archive_id()
            && self.deletion_fence == seal.deletion_fence()
            && self.inventory_commitment == seal.inventory_commitment()
            && self.page_count == seal.page_count()
            && self.terminal_page_hash == seal.terminal_page_hash()
    }
}

/// Validate the complete sealed chain before the page-store implementation
/// performs its first destructive request. This grants no deletion receipt.
pub(crate) fn validate_cleanup_page_chain(
    completion: &DurablePhysicalCompletion,
    references: &[InventoryPageReference],
) -> Result<(), LifecycleError> {
    let seal = completion.physical_receipt().seal();
    if references.is_empty() || usize::try_from(seal.page_count()).ok() != Some(references.len()) {
        return Err(LifecycleError::ChainMismatch);
    }
    let mut previous = ZERO_HASH;
    for (index, reference) in references.iter().enumerate() {
        if reference.archive_id() != seal.archive_id()
            || usize::try_from(reference.page_ordinal()).ok() != Some(index)
            || reference.previous_hash() != previous
        {
            return Err(LifecycleError::ChainMismatch);
        }
        previous = reference.page_hash();
    }
    if previous != seal.terminal_page_hash() {
        return Err(LifecycleError::ChainMismatch);
    }
    Ok(())
}

/// Validate the entire retained reference set before an authenticated loader
/// performs its first exact external read. Unlike cleanup authorization this
/// grants no mutation capability and is valid before physical completion.
pub(crate) fn validate_sealed_page_references(
    seal: &DeletionInventorySeal,
    references: &[InventoryPageReference],
) -> Result<(), LifecycleError> {
    if references.is_empty()
        || references.len() > MAX_LIFECYCLE_PAGES
        || usize::try_from(seal.page_count()).ok() != Some(references.len())
    {
        return Err(LifecycleError::ChainMismatch);
    }
    let mut previous = ZERO_HASH;
    for (index, reference) in references.iter().enumerate() {
        if reference.archive_id() != seal.archive_id()
            || usize::try_from(reference.page_ordinal()).ok() != Some(index)
            || reference.previous_hash() != previous
            || reference.encoded_len() == 0
            || usize::try_from(reference.encoded_len())
                .map_or(true, |length| length > MAX_LIFECYCLE_PAGE_BYTES)
        {
            return Err(LifecycleError::ChainMismatch);
        }
        previous = reference.page_hash();
    }
    if previous != seal.terminal_page_hash() {
        return Err(LifecycleError::ChainMismatch);
    }
    Ok(())
}

impl fmt::Debug for ErasedInventoryPages {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ErasedInventoryPages(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleCreateOutcome {
    Created,
    AlreadyPresentExact,
    OutcomeUnknown,
    ConfirmedAbsent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum LifecycleError {
    #[error("archive lifecycle value is malformed")]
    Malformed,
    #[error("archive lifecycle value exceeded a fixed bound")]
    Limit,
    #[error("archive lifecycle durable state is corrupt")]
    Corrupt,
    #[error("archive lifecycle compare-and-swap failed")]
    StaleRevision,
    #[error("archive lifecycle state does not permit the operation")]
    InvalidState,
    #[error("archive lifecycle inventory page chain does not match")]
    ChainMismatch,
    #[error("archive lifecycle inventory has conflicting object identity")]
    DuplicateConflict,
    /// The durable state permanently refuses the operation: a bound was
    /// exceeded, a name was inventoried twice, a branch conflicts, or a
    /// retained snapshot no longer matches its commitment. Distinct from
    /// [`Self::Unavailable`] because no retry can clear it — after the
    /// deletion tombstone there is no owner and no serving authority left to
    /// settle the conflicting work, so reporting it as transient would loop an
    /// operation nobody is ever paged for.
    #[error("archive lifecycle durable state permanently conflicts")]
    Conflict,
    #[error("archive lifecycle durable store is unavailable")]
    Unavailable,
}

/// Durable interface only. Implementations must perform each method as one
/// compare-and-swap transaction and must never synthesize a receipt from a
/// caller-retained snapshot.
#[async_trait]
pub(crate) trait ArchiveLifecycleLedger: Send + Sync {
    async fn reserve_bootstrap(
        &self,
        plan: BootstrapPlan,
    ) -> Result<DurableBootstrapReservation, LifecycleError>;

    async fn prepare_bootstrap(
        &self,
        reservation: DurableBootstrapReservation,
        exact_wrapped_registry: &[u8],
        exact_root_envelope: &[u8],
    ) -> Result<PreparedBootstrap, LifecycleError>;

    async fn prepare_witness(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        expected_encoded_record: &[u8],
    ) -> Result<u64, LifecycleError>;

    /// Append one exact create-ahead artifact to durable control state before
    /// any immutable-provider request. Final external inventory pages are a
    /// separate, post-freeze v2 projection containing no operation state.
    async fn plan_exact_artifact(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        artifact: PlannedArtifact,
    ) -> Result<u64, LifecycleError>;

    async fn admit_exact_create(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        artifact_ordinal: u32,
    ) -> Result<ActiveCreateAdmission, LifecycleError>;

    async fn reconcile_create(
        &self,
        admission: &ActiveCreateAdmission,
        outcome: LifecycleCreateOutcome,
    ) -> Result<u64, LifecycleError>;

    /// Recover only a retained send-started initial-witness create whose exact
    /// durable candidate is now present. Implementations must atomically
    /// validate the protocol/admission/hash tuple and clear it as created.
    /// A merely preexisting witness with no enrolled candidate fails closed.
    async fn adopt_existing_witness(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        exact_encoded_record: &[u8],
    ) -> Result<u64, LifecycleError>;

    async fn freeze_for_deletion(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        deletion_fence: ObjectId,
    ) -> Result<u64, LifecycleError>;

    /// Atomically prove every create-ahead/witness admission is settled and
    /// bind that immutable snapshot before any external inventory-page create.
    /// Once this succeeds, artifact reconciliation must remain closed.
    async fn freeze_inventory_snapshot(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        deletion_fence: ObjectId,
    ) -> Result<u64, LifecycleError>;

    /// Recover the exact settled create-ahead portion of the frozen snapshot
    /// after cancellation/restart. These values carry no provider authority;
    /// page creation still requires a fresh durable page admission.
    async fn load_inventory_snapshot(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<(u64, Vec<PlannedArtifact>), LifecycleError>;

    async fn load_sealed_inventory(
        &self,
        seal: &DeletionInventorySeal,
    ) -> Result<Vec<InventoryPage>, LifecycleError>;

    async fn revalidate_active(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
    ) -> Result<u64, LifecycleError>;
}

fn ensure_entries(
    archive_id: ArchiveId,
    entries: &[LifecycleInventoryObject],
) -> Result<(), LifecycleError> {
    let prefix = ArchivePrefix::for_archive(archive_id);
    let mut previous: Option<(&str, ObjectRole, [u8; 32])> = None;
    for entry in entries {
        let current = (entry.key.as_str(), entry.role, entry.ciphertext_hash);
        if !entry.key.as_str().starts_with(prefix.as_str())
            || canonical_object_identity(entry.key.as_str())
                != Some((entry.key.object_id(), entry.role))
            || previous.is_some_and(|value| value >= current)
        {
            return Err(LifecycleError::Malformed);
        }
        previous = Some(current);
    }
    Ok(())
}

fn encode_page(
    archive_id: ArchiveId,
    page_ordinal: u32,
    previous_hash: [u8; 32],
    entries: &[LifecycleInventoryObject],
) -> Result<Vec<u8>, LifecycleError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"KILP");
    encoded.extend_from_slice(&LIFECYCLE_INVENTORY_PAGE_VERSION.to_be_bytes());
    encoded.extend_from_slice(archive_id.as_bytes());
    encoded.extend_from_slice(&page_ordinal.to_be_bytes());
    encoded.extend_from_slice(&previous_hash);
    encoded.extend_from_slice(
        &u16::try_from(entries.len())
            .map_err(|_| LifecycleError::Limit)?
            .to_be_bytes(),
    );
    for entry in entries {
        encoded.push(entry.role as u8);
        encoded.extend_from_slice(entry.key.object_id().as_bytes());
        encoded.extend_from_slice(&entry.ciphertext_hash);
        encoded.extend_from_slice(
            &u16::try_from(entry.key.as_str().len())
                .map_err(|_| LifecycleError::Limit)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(entry.key.as_str().as_bytes());
    }
    if encoded.len() > MAX_LIFECYCLE_PAGE_BYTES {
        return Err(LifecycleError::Limit);
    }
    Ok(encoded)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn pre_witness_snapshot_commitment(
    plan: BootstrapPlan,
    deletion_fence: ObjectId,
    absence_revision: u64,
    snapshot_revision: u64,
    protocol_version: u16,
    expected_witness_hash: Option<[u8; 32]>,
    expected_witness_len: Option<u32>,
    protocol_commitment: [u8; 32],
    create_ahead: &[PlannedArtifact],
) -> Result<[u8; 32], LifecycleError> {
    if absence_revision == 0
        || absence_revision.checked_add(1) != Some(snapshot_revision)
        || protocol_version != WITNESS_CREATE_PROTOCOL_V1
        || !nonzero(deletion_fence.as_bytes())
        || !nonzero(&protocol_commitment)
        || !matches!(
            (expected_witness_hash, expected_witness_len),
            (None, None) | (Some(_), Some(_))
        )
        || expected_witness_hash.is_some_and(|hash| !nonzero(&hash))
        || expected_witness_len == Some(0)
        || create_ahead.len() > MAX_LIFECYCLE_ARTIFACTS
    {
        return Err(LifecycleError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(PRE_WITNESS_SNAPSHOT_DOMAIN);
    hasher.update(PRE_WITNESS_INVENTORY_FORMAT_V1.to_be_bytes());
    hasher.update(plan.archive_id().as_bytes());
    hasher.update(deletion_fence.as_bytes());
    hasher.update(absence_revision.to_be_bytes());
    hasher.update(snapshot_revision.to_be_bytes());
    hasher.update(plan.attempt_id().as_bytes());
    hasher.update(plan.database_epoch().as_bytes());
    hasher.update(plan.key_epoch().as_bytes());
    hasher.update(plan.registry_object_id().as_bytes());
    hasher.update(plan.root_object_id().as_bytes());
    hasher.update(protocol_version.to_be_bytes());
    match (expected_witness_hash, expected_witness_len) {
        (None, None) => hasher.update([0]),
        (Some(hash), Some(len)) => {
            hasher.update([1]);
            hasher.update(hash);
            hasher.update(len.to_be_bytes());
        }
        _ => return Err(LifecycleError::Corrupt),
    }
    hasher.update(protocol_commitment);
    hasher.update(
        u32::try_from(create_ahead.len())
            .map_err(|_| LifecycleError::Limit)?
            .to_be_bytes(),
    );
    let mut previous = None;
    for artifact in create_ahead {
        let key = artifact.key().as_str().as_bytes();
        let current = (
            artifact.attempt_id(),
            artifact.ordinal(),
            artifact.key().as_str(),
        );
        if artifact.attempt_id() != plan.attempt_id()
            || artifact.create_state() == ArtifactCreateState::OutcomeUnknown
            || previous.is_some_and(|value| value >= current)
        {
            return Err(LifecycleError::Corrupt);
        }
        previous = Some(current);
        hasher.update(artifact.attempt_id().as_bytes());
        hasher.update(artifact.ordinal().to_be_bytes());
        hasher.update(
            u32::try_from(key.len())
                .map_err(|_| LifecycleError::Limit)?
                .to_be_bytes(),
        );
        hasher.update(key);
        hasher.update([artifact.role() as u8]);
        hasher.update(artifact.ciphertext_hash());
        hasher.update(artifact.encoded_len().to_be_bytes());
        hasher.update([artifact.create_state() as u8]);
    }
    Ok(hasher.finalize().into())
}

fn validate_pre_witness_pages(
    archive_id: ArchiveId,
    pages: &[DurableInventoryPage],
    references: &[InventoryPageReference],
) -> Result<(u32, u32, [u8; 32]), LifecycleError> {
    if pages.len() != references.len() || pages.len() > MAX_LIFECYCLE_PAGES {
        return Err(LifecycleError::ChainMismatch);
    }
    if pages.is_empty() {
        return Ok((0, 0, ZERO_HASH));
    }
    let mut previous_hash = ZERO_HASH;
    let mut previous_object: Option<LifecycleInventoryObject> = None;
    let mut seen = BTreeMap::<ObjectId, LifecycleInventoryObject>::new();
    let mut artifact_count = 0usize;
    for (index, (durable, reference)) in pages.iter().zip(references).enumerate() {
        let page = durable.page();
        if page.archive_id() != archive_id
            || usize::try_from(page.page_ordinal()).ok() != Some(index)
            || page.previous_hash() != previous_hash
            || page.reference() != *reference
            || InventoryPage::decode(archive_id, page.encoded())? != *page
        {
            return Err(LifecycleError::ChainMismatch);
        }
        for object in page.entries() {
            if previous_object
                .as_ref()
                .is_some_and(|previous| previous >= object)
                || seen
                    .insert(object.key().object_id(), object.clone())
                    .is_some()
            {
                return Err(LifecycleError::DuplicateConflict);
            }
            previous_object = Some(object.clone());
        }
        artifact_count = artifact_count
            .checked_add(page.entries().len())
            .ok_or(LifecycleError::Limit)?;
        if artifact_count > MAX_LIFECYCLE_ARTIFACTS {
            return Err(LifecycleError::Limit);
        }
        previous_hash = page.page_hash();
    }
    Ok((
        u32::try_from(pages.len()).map_err(|_| LifecycleError::Limit)?,
        u32::try_from(artifact_count).map_err(|_| LifecycleError::Limit)?,
        previous_hash,
    ))
}

pub(crate) fn validate_pre_witness_sealed_page_references(
    seal: &PreWitnessDeletionInventorySeal,
    references: &[InventoryPageReference],
) -> Result<(), LifecycleError> {
    validate_pre_witness_references(
        seal.archive_id(),
        seal.page_count(),
        seal.terminal_page_hash(),
        references,
    )?;
    let commitment = pre_witness_inventory_commitment(
        seal.archive_id(),
        seal.deletion_fence(),
        seal.snapshot_revision(),
        seal.revision(),
        seal.snapshot_commitment(),
        seal.page_count(),
        seal.artifact_count(),
        seal.terminal_page_hash(),
        references,
    );
    (commitment == seal.inventory_commitment())
        .then_some(())
        .ok_or(LifecycleError::ChainMismatch)
}

fn validate_pre_witness_references(
    archive_id: ArchiveId,
    page_count: u32,
    terminal_page_hash: [u8; 32],
    references: &[InventoryPageReference],
) -> Result<(), LifecycleError> {
    if page_count == 0 {
        return (references.is_empty() && terminal_page_hash == ZERO_HASH)
            .then_some(())
            .ok_or(LifecycleError::ChainMismatch);
    }
    if usize::try_from(page_count).ok() != Some(references.len())
        || references.is_empty()
        || references.len() > MAX_LIFECYCLE_PAGES
    {
        return Err(LifecycleError::ChainMismatch);
    }
    let mut previous = ZERO_HASH;
    for (index, reference) in references.iter().enumerate() {
        if reference.archive_id() != archive_id
            || usize::try_from(reference.page_ordinal()).ok() != Some(index)
            || reference.previous_hash() != previous
        {
            return Err(LifecycleError::ChainMismatch);
        }
        previous = reference.page_hash();
    }
    (previous == terminal_page_hash)
        .then_some(())
        .ok_or(LifecycleError::ChainMismatch)
}

#[allow(clippy::too_many_arguments)]
fn pre_witness_inventory_commitment(
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    snapshot_revision: u64,
    revision: u64,
    snapshot_commitment: [u8; 32],
    page_count: u32,
    artifact_count: u32,
    terminal_page_hash: [u8; 32],
    references: &[InventoryPageReference],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PRE_WITNESS_INVENTORY_DOMAIN);
    hasher.update(PRE_WITNESS_INVENTORY_FORMAT_V1.to_be_bytes());
    hasher.update(archive_id.as_bytes());
    hasher.update(deletion_fence.as_bytes());
    hasher.update(snapshot_revision.to_be_bytes());
    hasher.update(revision.to_be_bytes());
    hasher.update(snapshot_commitment);
    hasher.update(page_count.to_be_bytes());
    hasher.update(artifact_count.to_be_bytes());
    hasher.update(terminal_page_hash);
    hasher.update(
        u32::try_from(references.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for reference in references {
        hasher.update(reference.archive_id().as_bytes());
        hasher.update(reference.page_ordinal().to_be_bytes());
        hasher.update(reference.page_id().as_bytes());
        hasher.update(reference.previous_hash());
        hasher.update(reference.page_hash());
        hasher.update(reference.encoded_len().to_be_bytes());
    }
    hasher.finalize().into()
}

fn inventory_commitment(
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    page_count: u32,
    artifact_count: u32,
    terminal_page_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INVENTORY_DOMAIN);
    hasher.update(archive_id.as_bytes());
    hasher.update(deletion_fence.as_bytes());
    hasher.update(page_count.to_be_bytes());
    hasher.update(artifact_count.to_be_bytes());
    hasher.update(terminal_page_hash);
    hasher.finalize().into()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn digest_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn object_id_from_hash(hash: [u8; 32]) -> Result<ObjectId, LifecycleError> {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash[..16]);
    nonzero(&bytes)
        .then_some(ObjectId::from_bytes(bytes))
        .ok_or(LifecycleError::Malformed)
}

fn nonzero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

fn role(value: u8) -> Result<ObjectRole, LifecycleError> {
    match value {
        1 => Ok(ObjectRole::CheckpointChunkV3),
        2 => Ok(ObjectRole::WalSegmentV3),
        3 => Ok(ObjectRole::ExtentV3),
        4 => Ok(ObjectRole::MerkleNodeV3),
        5 => Ok(ObjectRole::RootV3),
        6 => Ok(ObjectRole::KeyRegistryV3),
        7 => Ok(ObjectRole::StagingV3),
        8 => Ok(ObjectRole::CheckpointManifestV3),
        9 => Ok(ObjectRole::WalCommitDescriptorV3),
        _ => Err(LifecycleError::Corrupt),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], LifecycleError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(LifecycleError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(LifecycleError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], LifecycleError> {
        self.take(N)?
            .try_into()
            .map_err(|_| LifecycleError::Corrupt)
    }

    fn u8(&mut self) -> Result<u8, LifecycleError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, LifecycleError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, LifecycleError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    const fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3::{KeyKind, KeyRegistryContext, LogicalLocation, ObjectContext};
    use std::sync::Mutex;

    #[derive(Clone, Copy)]
    enum PageEraseMode {
        Absent,
        Present,
        OutcomeUnknown,
    }

    struct FakePageStore {
        pages: Mutex<BTreeMap<ObjectId, Vec<u8>>>,
        erase_mode: Mutex<PageEraseMode>,
    }

    impl FakePageStore {
        fn new(mode: PageEraseMode) -> Self {
            Self {
                pages: Mutex::new(BTreeMap::new()),
                erase_mode: Mutex::new(mode),
            }
        }
    }

    #[async_trait]
    impl ArchiveLifecyclePageStore for FakePageStore {
        async fn create_exact_page(
            &self,
            _deletion_fence: ObjectId,
            page: &InventoryPage,
        ) -> Result<DurableInventoryPage, LifecycleError> {
            let mut pages = self.pages.lock().unwrap();
            if let Some(existing) = pages.get(&page.page_id()) {
                if existing != page.encoded() {
                    return Err(LifecycleError::DuplicateConflict);
                }
            } else {
                pages.insert(page.page_id(), page.encoded().to_vec());
            }
            DurableInventoryPage::from_exact_readback(page.clone(), page.encoded())
        }

        async fn read_exact_page(
            &self,
            _deletion_fence: ObjectId,
            reference: InventoryPageReference,
        ) -> Result<DurableInventoryPage, LifecycleError> {
            let encoded = self
                .pages
                .lock()
                .unwrap()
                .get(&reference.page_id())
                .cloned()
                .ok_or(LifecycleError::InvalidState)?;
            if encoded.len() != reference.encoded_len() as usize
                || digest_domain(PAGE_DOMAIN, &encoded) != reference.page_hash()
            {
                return Err(LifecycleError::ChainMismatch);
            }
            let page = InventoryPage::decode(reference.archive_id(), &encoded)?;
            DurableInventoryPage::from_exact_readback(page, &encoded)
        }

        async fn erase_exact_pages_after_physical_completion(
            &self,
            completion: &DurablePhysicalCompletion,
            references: &[InventoryPageReference],
        ) -> Result<ErasedInventoryPages, LifecycleError> {
            match *self.erase_mode.lock().unwrap() {
                PageEraseMode::Present => return Err(LifecycleError::InvalidState),
                PageEraseMode::OutcomeUnknown => return Err(LifecycleError::StaleRevision),
                PageEraseMode::Absent => {}
            }
            let receipt = ErasedInventoryPages::from_exact_absence(completion, references)?;
            let mut pages = self.pages.lock().unwrap();
            for reference in references {
                pages.remove(&reference.page_id());
            }
            Ok(receipt)
        }
    }

    fn attempt(value: u8) -> BootstrapAttemptId {
        BootstrapAttemptId::from_bytes([value; 16]).unwrap()
    }

    fn artifact(
        archive_id: ArchiveId,
        attempt_id: BootstrapAttemptId,
        ordinal: u32,
        object: u8,
        state: ArtifactCreateState,
    ) -> PlannedArtifact {
        let epoch = DatabaseEpoch::from_bytes([2; 16]);
        let key_epoch = KeyEpoch::from_bytes([3; 16]);
        let object_id = ObjectId::from_bytes([object; 16]);
        let context = ObjectContext::new(
            archive_id,
            epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root {
                root_seq: u64::from(ordinal),
            },
            object_id,
            None,
        )
        .unwrap();
        PlannedArtifact::new(
            archive_id,
            attempt_id,
            ordinal,
            context.object_key(),
            ObjectRole::RootV3,
            [object.wrapping_add(1); 32],
            100,
            state,
        )
        .unwrap()
    }

    fn durable(page: InventoryPage) -> DurableInventoryPage {
        let encoded = page.encoded().to_vec();
        DurableInventoryPage::from_exact_readback(page, &encoded).unwrap()
    }

    fn pre_witness_snapshot(
        archive_id: ArchiveId,
        create_ahead: Vec<PlannedArtifact>,
    ) -> FrozenPreWitnessInventorySnapshot {
        let plan = BootstrapPlan::new(
            archive_id,
            attempt(4),
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            ObjectId::from_bytes([5; 16]),
            ObjectId::from_bytes([6; 16]),
        )
        .unwrap();
        FrozenPreWitnessInventorySnapshot::for_test(
            plan,
            ObjectId::from_bytes([7; 16]),
            8,
            9,
            None,
            None,
            [10; 32],
            create_ahead,
        )
        .unwrap()
    }

    fn inventory(artifact: PlannedArtifact) -> LifecycleInventoryObject {
        artifact.inventory_object().unwrap()
    }

    fn role_artifact(
        archive_id: ArchiveId,
        ordinal: u32,
        object: u8,
        role: ObjectRole,
        location: LogicalLocation,
    ) -> PlannedArtifact {
        let context = ObjectContext::new(
            archive_id,
            DatabaseEpoch::from_bytes([2; 16]),
            KeyEpoch::from_bytes([3; 16]),
            role,
            location,
            ObjectId::from_bytes([object; 16]),
            None,
        )
        .unwrap();
        PlannedArtifact::new(
            archive_id,
            attempt(4),
            ordinal,
            context.object_key(),
            role,
            [object.wrapping_add(1); 32],
            100,
            ArtifactCreateState::Created,
        )
        .unwrap()
    }

    #[test]
    fn prepared_bytes_must_exactly_match_durable_hashes() {
        let plan = BootstrapPlan::new(
            ArchiveId::from_bytes([1; 16]),
            attempt(2),
            DatabaseEpoch::from_bytes([3; 16]),
            KeyEpoch::from_bytes([4; 16]),
            ObjectId::from_bytes([5; 16]),
            ObjectId::from_bytes([6; 16]),
        )
        .unwrap();
        let reserved = DurableBootstrapReservation::for_test(plan, 1).unwrap();
        assert!(PreparedBootstrap::for_test(
            reserved,
            2,
            vec![7],
            vec![8],
            digest(&[9]),
            digest(&[8]),
        )
        .is_err());
        let prepared =
            PreparedBootstrap::for_test(reserved, 2, vec![7], vec![8], digest(&[7]), digest(&[8]))
                .unwrap();
        assert_eq!(prepared.wrapped_registry(), &[7]);
        assert_eq!(format!("{prepared:?}"), "PreparedBootstrap(<opaque>)");
    }

    #[test]
    fn pre_witness_snapshot_and_zero_inventory_seal_bind_distinct_domains() {
        let archive = ArchiveId::from_bytes([71; 16]);
        let snapshot = pre_witness_snapshot(archive, vec![]);
        assert_eq!(snapshot.absence_revision(), 8);
        assert_eq!(snapshot.revision(), 9);
        assert_ne!(snapshot.snapshot_commitment_for_test(), ZERO_HASH);
        let seal = PreWitnessDeletionInventorySeal::for_test(&snapshot, &[]).unwrap();
        assert_eq!(seal.page_count(), 0);
        assert_eq!(seal.artifact_count(), 0);
        assert_eq!(seal.terminal_page_hash(), ZERO_HASH);
        assert_ne!(seal.inventory_commitment(), ZERO_HASH);
        assert!(validate_pre_witness_sealed_page_references(&seal, &[]).is_ok());
        assert_ne!(
            seal.inventory_commitment(),
            inventory_commitment(archive, snapshot.deletion_fence(), 0, 0, ZERO_HASH)
        );
        assert_eq!(
            format!("{snapshot:?}"),
            "FrozenPreWitnessInventorySnapshot(<opaque>)"
        );
        assert_eq!(
            format!("{seal:?}"),
            "PreWitnessDeletionInventorySeal(<opaque>)"
        );
    }

    #[test]
    fn pre_witness_nonempty_seal_rejects_reordered_or_alternate_references() {
        let archive = ArchiveId::from_bytes([72; 16]);
        let mut artifacts = vec![
            artifact(archive, attempt(4), 0, 73, ArtifactCreateState::Created),
            artifact(
                archive,
                attempt(4),
                1,
                74,
                ArtifactCreateState::ConfirmedAbsent,
            ),
        ];
        artifacts.sort_by(|left, right| {
            (left.attempt_id(), left.ordinal(), left.key().as_str()).cmp(&(
                right.attempt_id(),
                right.ordinal(),
                right.key().as_str(),
            ))
        });
        let snapshot = pre_witness_snapshot(archive, artifacts.clone());
        let mut entries = artifacts.into_iter().map(inventory).collect::<Vec<_>>();
        entries.sort();
        let first = InventoryPage::build(archive, 0, ZERO_HASH, vec![entries[0].clone()]).unwrap();
        let second =
            InventoryPage::build(archive, 1, first.page_hash(), vec![entries[1].clone()]).unwrap();
        let pages = vec![durable(first.clone()), durable(second.clone())];
        let seal = PreWitnessDeletionInventorySeal::for_test(&snapshot, &pages).unwrap();
        let references = vec![first.reference(), second.reference()];
        assert!(validate_pre_witness_sealed_page_references(&seal, &references).is_ok());
        assert!(validate_pre_witness_sealed_page_references(
            &seal,
            &[references[1], references[0]],
        )
        .is_err());
        let alternate =
            InventoryPage::build(archive, 1, first.page_hash(), vec![entries[0].clone()]).unwrap();
        assert!(validate_pre_witness_sealed_page_references(
            &seal,
            &[references[0], alternate.reference()],
        )
        .is_err());
    }

    #[test]
    fn page_round_trip_binds_order_and_previous_hash() {
        let archive = ArchiveId::from_bytes([11; 16]);
        let first = InventoryPage::build(
            archive,
            0,
            ZERO_HASH,
            vec![inventory(artifact(
                archive,
                attempt(12),
                0,
                13,
                ArtifactCreateState::OutcomeUnknown,
            ))],
        )
        .unwrap();
        let second = InventoryPage::build(
            archive,
            1,
            first.page_hash(),
            vec![inventory(artifact(
                archive,
                attempt(12),
                1,
                14,
                ArtifactCreateState::ConfirmedAbsent,
            ))],
        )
        .unwrap();
        assert_eq!(
            InventoryPage::decode(archive, first.encoded()).unwrap(),
            first
        );
        let mut legacy_v1 = first.encoded().to_vec();
        legacy_v1[4..6].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            InventoryPage::decode(archive, &legacy_v1),
            Err(LifecycleError::Corrupt)
        );
        assert!(InventoryPage::decode(ArchiveId::from_bytes([99; 16]), first.encoded()).is_err());
        let seal = DeletionInventorySeal::for_test(
            archive,
            ObjectId::from_bytes([15; 16]),
            7,
            &[durable(first), durable(second)],
        )
        .unwrap();
        assert_eq!(seal.page_count(), 2);
        assert_eq!(seal.artifact_count(), 2);
        assert_ne!(seal.inventory_commitment(), ZERO_HASH);
    }

    #[test]
    fn page_ordinal_cap_is_enforced_by_build_decode_and_persisted_reference() {
        let archive = ArchiveId::from_bytes([16; 16]);
        let previous = [0x55; 32];
        let max_ordinal = u32::try_from(MAX_LIFECYCLE_PAGES - 1).unwrap();
        let accepted = InventoryPage::build(
            archive,
            max_ordinal,
            previous,
            vec![inventory(artifact(
                archive,
                attempt(12),
                max_ordinal,
                15,
                ArtifactCreateState::Created,
            ))],
        )
        .unwrap();
        assert_eq!(
            InventoryPage::decode(archive, accepted.encoded()).unwrap(),
            accepted
        );
        let rejected_ordinal = u32::try_from(MAX_LIFECYCLE_PAGES).unwrap();
        assert!(InventoryPage::build(
            archive,
            rejected_ordinal,
            previous,
            vec![inventory(artifact(
                archive,
                attempt(12),
                rejected_ordinal,
                16,
                ArtifactCreateState::Created,
            ))],
        )
        .is_err());
        assert!(InventoryPageReference::for_test(
            archive,
            rejected_ordinal,
            accepted.page_id(),
            previous,
            accepted.page_hash(),
            accepted.encoded().len() as u32,
        )
        .is_err());

        let mut tampered = accepted.encoded().to_vec();
        let ordinal_offset = 4 + 2 + 16;
        tampered[ordinal_offset..ordinal_offset + 4]
            .copy_from_slice(&rejected_ordinal.to_be_bytes());
        assert!(InventoryPage::decode(archive, &tampered).is_err());
    }

    #[test]
    fn page_round_trip_preserves_wal_v3_roles_and_rejects_key_role_mismatch() {
        let archive = ArchiveId::from_bytes([17; 16]);
        let wal = role_artifact(
            archive,
            0,
            18,
            ObjectRole::WalSegmentV3,
            LogicalLocation::Wal {
                root_seq: 1,
                wal_generation: 2,
                segment_index: 3,
            },
        );
        let commit = role_artifact(
            archive,
            1,
            19,
            ObjectRole::WalCommitDescriptorV3,
            LogicalLocation::WalCommitDescriptor { root_seq: 1 },
        );
        let mut entries = vec![inventory(wal), inventory(commit)];
        entries.sort();
        let page = InventoryPage::build(archive, 0, ZERO_HASH, entries).unwrap();
        let decoded = InventoryPage::decode(archive, page.encoded()).unwrap();
        let roles = decoded
            .entries()
            .iter()
            .map(LifecycleInventoryObject::role)
            .collect::<Vec<_>>();
        assert!(roles.contains(&ObjectRole::WalSegmentV3));
        assert!(roles.contains(&ObjectRole::WalCommitDescriptorV3));

        let root = artifact(archive, attempt(20), 0, 21, ArtifactCreateState::Created);
        assert!(PlannedArtifact::new(
            archive,
            root.attempt_id(),
            root.ordinal(),
            root.key().clone(),
            ObjectRole::KeyRegistryV3,
            root.ciphertext_hash(),
            root.encoded_len() as usize,
            root.create_state(),
        )
        .is_err());
        let page = InventoryPage::build(archive, 0, ZERO_HASH, vec![inventory(root)]).unwrap();
        let mut tampered = page.encoded().to_vec();
        const FIRST_ENTRY_ROLE_OFFSET: usize = 4 + 2 + 16 + 4 + 32 + 2;
        tampered[FIRST_ENTRY_ROLE_OFFSET] = ObjectRole::KeyRegistryV3 as u8;
        assert!(InventoryPage::decode(archive, &tampered).is_err());
    }

    #[tokio::test]
    async fn exact_page_store_cleanup_fails_closed_on_presence_ambiguity_and_wrong_seal() {
        let archive = ArchiveId::from_bytes([22; 16]);
        let page = InventoryPage::build(
            archive,
            0,
            ZERO_HASH,
            vec![inventory(artifact(
                archive,
                attempt(23),
                0,
                24,
                ArtifactCreateState::OutcomeUnknown,
            ))],
        )
        .unwrap();
        let fence = ObjectId::from_bytes([25; 16]);
        let store = FakePageStore::new(PageEraseMode::Absent);
        let durable_page = store.create_exact_page(fence, &page).await.unwrap();
        let reference = page.reference();
        assert_eq!(
            store.read_exact_page(fence, reference).await.unwrap(),
            durable_page
        );
        let seal = DeletionInventorySeal::for_test(archive, fence, 7, &[durable_page]).unwrap();
        let physical = PhysicalDeletionReceipt::for_test(seal, [26; 32]).unwrap();
        let completion =
            DurablePhysicalCompletion::for_test(physical, seal.revision() + 1).unwrap();

        for mode in [PageEraseMode::Present, PageEraseMode::OutcomeUnknown] {
            let store = FakePageStore::new(mode);
            store.create_exact_page(fence, &page).await.unwrap();
            assert!(store
                .erase_exact_pages_after_physical_completion(&completion, &[reference])
                .await
                .is_err());
            assert!(!store.pages.lock().unwrap().is_empty());
        }

        let wrong_archive_page = InventoryPage::build(
            ArchiveId::from_bytes([27; 16]),
            0,
            ZERO_HASH,
            vec![inventory(artifact(
                ArchiveId::from_bytes([27; 16]),
                attempt(28),
                0,
                29,
                ArtifactCreateState::Created,
            ))],
        )
        .unwrap();
        let wrong_seal = DeletionInventorySeal::for_test(
            ArchiveId::from_bytes([27; 16]),
            fence,
            8,
            &[durable(wrong_archive_page)],
        )
        .unwrap();
        let wrong_physical = PhysicalDeletionReceipt::for_test(wrong_seal, [30; 32]).unwrap();
        let wrong_completion =
            DurablePhysicalCompletion::for_test(wrong_physical, wrong_seal.revision() + 1).unwrap();
        assert!(store
            .erase_exact_pages_after_physical_completion(&wrong_completion, &[reference])
            .await
            .is_err());
        let erased = store
            .erase_exact_pages_after_physical_completion(&completion, &[reference])
            .await
            .unwrap();
        assert!(erased.matches(completion));
        assert!(store.pages.lock().unwrap().is_empty());
    }

    #[test]
    fn reordered_truncated_or_tampered_page_chain_fails_closed() {
        let archive = ArchiveId::from_bytes([21; 16]);
        let first = InventoryPage::build(
            archive,
            0,
            ZERO_HASH,
            vec![inventory(artifact(
                archive,
                attempt(22),
                0,
                23,
                ArtifactCreateState::Planned,
            ))],
        )
        .unwrap();
        let second = InventoryPage::build(
            archive,
            1,
            first.page_hash(),
            vec![inventory(artifact(
                archive,
                attempt(22),
                1,
                24,
                ArtifactCreateState::Created,
            ))],
        )
        .unwrap();
        let fence = ObjectId::from_bytes([25; 16]);
        assert!(DeletionInventorySeal::for_test(
            archive,
            fence,
            3,
            &[durable(second.clone()), durable(first.clone())],
        )
        .is_err());
        assert!(DeletionInventorySeal::for_test(archive, fence, 3, &[durable(second)],).is_err());
        let mut encoded = first.encoded().to_vec();
        *encoded.last_mut().unwrap() ^= 1;
        assert!(InventoryPage::decode(archive, &encoded).is_err());
    }

    #[test]
    fn conflicting_duplicate_object_identity_is_rejected() {
        let archive = ArchiveId::from_bytes([31; 16]);
        let one = artifact(archive, attempt(32), 0, 33, ArtifactCreateState::Created);
        let registry_key =
            KeyRegistryContext::new(archive, KeyKind::Archive, KeyEpoch::from_bytes([34; 16]))
                .object_key(one.key().object_id());
        let conflicting = PlannedArtifact::new(
            archive,
            attempt(32),
            1,
            registry_key,
            ObjectRole::KeyRegistryV3,
            [35; 32],
            99,
            ArtifactCreateState::OutcomeUnknown,
        )
        .unwrap();
        let mut entries = vec![inventory(one), inventory(conflicting)];
        entries.sort();
        let page = InventoryPage::build(archive, 0, ZERO_HASH, entries).unwrap();
        assert_eq!(
            DeletionInventorySeal::for_test(
                archive,
                ObjectId::from_bytes([36; 16]),
                4,
                &[durable(page)],
            ),
            Err(LifecycleError::DuplicateConflict)
        );
    }

    #[test]
    fn planned_and_confirmed_absent_artifacts_remain_deletion_work() {
        assert!(ArtifactCreateState::Planned.remains_deletion_work());
        assert!(ArtifactCreateState::OutcomeUnknown.remains_deletion_work());
        assert!(ArtifactCreateState::Created.remains_deletion_work());
        assert!(ArtifactCreateState::ConfirmedAbsent.remains_deletion_work());
    }

    #[test]
    fn canonical_key_and_embedded_object_id_are_revalidated() {
        let archive = ArchiveId::from_bytes([51; 16]);
        let object_id = ObjectId::from_bytes([52; 16]);
        let forged = ObjectKey::from_validated_canonical(
            format!(
                "{}forged/{:032x}",
                ArchivePrefix::for_archive(archive).as_str(),
                1
            ),
            object_id,
        );
        assert!(PlannedArtifact::new(
            archive,
            attempt(53),
            0,
            forged,
            ObjectRole::RootV3,
            [54; 32],
            10,
            ArtifactCreateState::Planned,
        )
        .is_err());

        let valid = artifact(archive, attempt(53), 1, 55, ArtifactCreateState::Created);
        assert!(LifecycleInventoryObject::for_archive(
            archive,
            valid.key().clone(),
            valid.role(),
            ZERO_HASH,
        )
        .is_err());
        assert!(LifecycleInventoryObject::for_archive(
            ArchiveId::from_bytes([0; 16]),
            valid.key().clone(),
            valid.role(),
            valid.ciphertext_hash(),
        )
        .is_err());
    }

    #[test]
    fn lifecycle_has_no_runtime_or_route_wiring() {
        let runtime = concat!(
            include_str!("main.rs"),
            include_str!("store.rs"),
            include_str!("cp/mod.rs"),
            include_str!("cp/sync.rs"),
            include_str!("cp/query.rs"),
        );
        for forbidden in [
            "ArchiveGenesis::new(",
            "ArchiveV3DeletionDriver::new(",
            ".reserve_archive_bootstrap(",
            ".prepare_archive_bootstrap(",
            ".recover_archive_bootstrap(",
            ".freeze_archive_lifecycle(",
            ".seal_archive_inventory(",
            ".recover_archive_deletion_lifecycle(",
            ".mark_archive_physical_complete(",
            ".erase_archive_lifecycle_payload(",
        ] {
            assert!(
                !runtime.contains(forbidden),
                "inactive lifecycle unexpectedly wired through {forbidden}"
            );
        }
    }

    #[test]
    fn durable_and_cleanup_receipt_factories_are_not_crate_forgeable() {
        let lifecycle = include_str!("archive_v3_lifecycle.rs");
        let control = include_str!("cp/control_store.rs");
        let deletion = include_str!("archive_v3_deletion.rs");
        for test_only_factory in [
            "fn from_exact_readback(",
            "fn from_exact_absence(",
            "fn for_test(",
        ] {
            assert!(lifecycle.contains(test_only_factory));
        }
        assert!(
            lifecycle.contains("_producer: &crate::cp::control_store::LifecyclePersistenceContext")
        );
        assert!(control.contains("pub(crate) struct LifecyclePersistenceContext(())"));
        assert!(control.contains("fn validated() -> Self"));
        assert!(!control.contains("pub(crate) fn validated() -> Self"));
        assert!(deletion.contains("fn new(seal: DeletionInventorySeal"));
        assert!(!deletion.contains("pub(crate) fn new(seal: DeletionInventorySeal"));
    }
}
