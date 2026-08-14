#![allow(
    dead_code,
    reason = "inactive ADR-0022 pre-witness deletion protocol is compiled before destructive producer wiring"
)]

//! Durable, type-separated execution protocol for deletion before the first
//! archive witness send. This module persists authority facts only. It has no
//! provider, page-store, witness, Store, startup, runtime, configuration,
//! route, credential, or destructive-I/O implementation.

use crate::{
    archive_v3::{ArchiveId, ObjectId},
    archive_v3_deletion::{ArchiveDeletionError, CompletePreWitnessDeletionInventory},
    archive_v3_lifecycle::{
        BootstrapAttemptId, LifecycleInventoryObject, PreWitnessDeletionInventorySeal,
    },
};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

pub(crate) const PRE_WITNESS_DELETION_EXECUTION_FORMAT_V1: u16 = 1;
pub(crate) const MAX_PRE_WITNESS_EXECUTION_KEY_BYTES: u64 = 64 * 1024 * 1024;

const INVENTORY_SET_DOMAIN: &[u8] = b"kioku/archive-v3/pre-witness-execution-inventory/v1\0";
const EXECUTION_DOMAIN: &[u8] = b"kioku/archive-v3/pre-witness-deletion-execution/v1\0";
const REGISTRY_EVIDENCE_DOMAIN: &[u8] = b"kioku/archive-v3/pre-witness-registry-erasure/v1\0";
const OBJECTS_EVIDENCE_DOMAIN: &[u8] = b"kioku/archive-v3/pre-witness-objects-absent/v1\0";
const PROVIDER_DRAIN_DOMAIN: &[u8] = b"kioku/archive-v3/pre-witness-provider-drain/v1\0";
const PAYLOAD_CLEANUP_DOMAIN: &[u8] = b"kioku/archive-v3/pre-witness-payload-cleanup/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum PreWitnessDeletionExecutionError {
    #[error("pre-witness deletion inventory is invalid")]
    InvalidInventory,
    #[error("pre-witness deletion execution state is stale or inconsistent")]
    Stale,
    #[error("pre-witness deletion execution state is corrupt")]
    Corrupt,
    #[error("pre-witness deletion execution exceeded a fixed bound")]
    Limit,
    #[error("pre-witness deletion execution control is unavailable")]
    Unavailable,
}

impl From<ArchiveDeletionError> for PreWitnessDeletionExecutionError {
    fn from(_: ArchiveDeletionError) -> Self {
        Self::InvalidInventory
    }
}

pub(crate) type Result<T> = std::result::Result<T, PreWitnessDeletionExecutionError>;

/// Producer token proving that only this module can consume the otherwise
/// inert complete pre-witness inventory into execution state.
pub(crate) struct PreWitnessExecutionInventoryProducer(());

/// Fully authenticated exact-object set, still non-authorizing until encrypted
/// control binds it to one durable random operation.
pub(crate) struct AuthenticatedPreWitnessExecutionInventory {
    seal: PreWitnessDeletionInventorySeal,
    objects: Vec<LifecycleInventoryObject>,
    key_bytes: u64,
    object_set_commitment: [u8; 32],
}

impl AuthenticatedPreWitnessExecutionInventory {
    pub(crate) fn consume(
        complete: CompletePreWitnessDeletionInventory,
        seal: PreWitnessDeletionInventorySeal,
    ) -> Result<Self> {
        let (objects, inventory_commitment, key_bytes, pages) =
            complete.into_pre_witness_execution_parts(&PreWitnessExecutionInventoryProducer(()));
        let key_bytes =
            u64::try_from(key_bytes).map_err(|_| PreWitnessDeletionExecutionError::Limit)?;
        if inventory_commitment != seal.inventory_commitment()
            || objects.len() != usize::try_from(seal.artifact_count()).unwrap_or(usize::MAX)
            || pages != usize::try_from(seal.page_count()).unwrap_or(usize::MAX)
            || key_bytes > MAX_PRE_WITNESS_EXECUTION_KEY_BYTES
            || (objects.is_empty()
                != (seal.page_count() == 0
                    && seal.artifact_count() == 0
                    && seal.terminal_page_hash() == [0; 32]
                    && key_bytes == 0))
        {
            return Err(PreWitnessDeletionExecutionError::InvalidInventory);
        }
        let object_set_commitment = object_set_commitment(&seal, key_bytes, &objects)?;
        Ok(Self {
            seal,
            objects,
            key_bytes,
            object_set_commitment,
        })
    }

    pub(crate) fn control_view(
        &self,
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
    ) -> PreWitnessExecutionInventoryControlView {
        PreWitnessExecutionInventoryControlView {
            seal: self.seal,
            object_count: u32::try_from(self.objects.len()).unwrap_or(u32::MAX),
            key_bytes: self.key_bytes,
            object_set_commitment: self.object_set_commitment,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        seal: PreWitnessDeletionInventorySeal,
        objects: Vec<LifecycleInventoryObject>,
    ) -> Result<Self> {
        let key_bytes = objects.iter().try_fold(0u64, |total, object| {
            total.checked_add(u64::try_from(object.key().as_str().len()).ok()?)
        });
        let key_bytes = key_bytes.ok_or(PreWitnessDeletionExecutionError::Limit)?;
        if objects.len() != usize::try_from(seal.artifact_count()).unwrap_or(usize::MAX)
            || key_bytes > MAX_PRE_WITNESS_EXECUTION_KEY_BYTES
        {
            return Err(PreWitnessDeletionExecutionError::InvalidInventory);
        }
        let object_set_commitment = object_set_commitment(&seal, key_bytes, &objects)?;
        Ok(Self {
            seal,
            objects,
            key_bytes,
            object_set_commitment,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_object_set_commitment_for_test(mut self, value: [u8; 32]) -> Self {
        self.object_set_commitment = value;
        self
    }
}

impl fmt::Debug for AuthenticatedPreWitnessExecutionInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPreWitnessExecutionInventory(<opaque>)")
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PreWitnessExecutionInventoryControlView {
    seal: PreWitnessDeletionInventorySeal,
    object_count: u32,
    key_bytes: u64,
    object_set_commitment: [u8; 32],
}

impl PreWitnessExecutionInventoryControlView {
    pub(crate) const fn seal(&self) -> PreWitnessDeletionInventorySeal {
        self.seal
    }
    pub(crate) const fn object_count(&self) -> u32 {
        self.object_count
    }
    pub(crate) const fn key_bytes(&self) -> u64 {
        self.key_bytes
    }
    pub(crate) const fn object_set_commitment(&self) -> [u8; 32] {
        self.object_set_commitment
    }
}

fn object_set_commitment(
    seal: &PreWitnessDeletionInventorySeal,
    key_bytes: u64,
    objects: &[LifecycleInventoryObject],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(INVENTORY_SET_DOMAIN);
    hasher.update(PRE_WITNESS_DELETION_EXECUTION_FORMAT_V1.to_be_bytes());
    hasher.update(seal.archive_id().as_bytes());
    hasher.update(seal.deletion_fence().as_bytes());
    hasher.update(seal.snapshot_revision().to_be_bytes());
    hasher.update(seal.revision().to_be_bytes());
    hasher.update(seal.page_count().to_be_bytes());
    hasher.update(seal.artifact_count().to_be_bytes());
    hasher.update(key_bytes.to_be_bytes());
    hasher.update(seal.terminal_page_hash());
    hasher.update(seal.inventory_commitment());
    for object in objects {
        let key = object.key().as_str().as_bytes();
        hasher.update((object.role() as u8).to_be_bytes());
        hasher.update(object.key().object_id().as_bytes());
        hasher.update(object.ciphertext_hash());
        hasher.update(
            u16::try_from(key.len())
                .map_err(|_| PreWitnessDeletionExecutionError::Limit)?
                .to_be_bytes(),
        );
        hasher.update(key);
    }
    Ok(hasher.finalize().into())
}

/// Random, durable operation identifier. It is intentionally not Clone/Copy.
pub(crate) struct PreWitnessDeletionOperationId([u8; 16]);

impl PreWitnessDeletionOperationId {
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        value: [u8; 16],
    ) -> Result<Self> {
        value
            .iter()
            .any(|byte| *byte != 0)
            .then_some(Self(value))
            .ok_or(PreWitnessDeletionExecutionError::Corrupt)
    }

    pub(crate) const fn as_bytes_for_control(
        &self,
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
    ) -> &[u8; 16] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(value: [u8; 16]) -> Result<Self> {
        value
            .iter()
            .any(|byte| *byte != 0)
            .then_some(Self(value))
            .ok_or(PreWitnessDeletionExecutionError::Corrupt)
    }
}

impl fmt::Debug for PreWitnessDeletionOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreWitnessDeletionOperationId(<opaque>)")
    }
}

/// Immutable execution tuple bound by encrypted control. It is not compatible
/// with the witnessed deletion driver's execution binding.
pub(crate) struct PreWitnessExecutionBinding {
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    attempt_id: BootstrapAttemptId,
    operation_id: PreWitnessDeletionOperationId,
    snapshot_revision: u64,
    seal_revision: u64,
    snapshot_commitment: [u8; 32],
    inventory_commitment: [u8; 32],
    object_set_commitment: [u8; 32],
    execution_commitment: [u8; 32],
    page_count: u32,
    artifact_count: u32,
    key_bytes: u64,
    terminal_page_hash: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execution_commitment(
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    attempt_id: BootstrapAttemptId,
    operation_id: &[u8; 16],
    snapshot_revision: u64,
    seal_revision: u64,
    snapshot_commitment: [u8; 32],
    page_count: u32,
    artifact_count: u32,
    key_bytes: u64,
    terminal_page_hash: [u8; 32],
    inventory_commitment: [u8; 32],
    object_set_commitment: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EXECUTION_DOMAIN);
    hasher.update(PRE_WITNESS_DELETION_EXECUTION_FORMAT_V1.to_be_bytes());
    hasher.update(archive_id.as_bytes());
    hasher.update(deletion_fence.as_bytes());
    hasher.update(attempt_id.as_bytes());
    hasher.update(operation_id);
    hasher.update(snapshot_revision.to_be_bytes());
    hasher.update(seal_revision.to_be_bytes());
    hasher.update(snapshot_commitment);
    hasher.update(page_count.to_be_bytes());
    hasher.update(artifact_count.to_be_bytes());
    hasher.update(key_bytes.to_be_bytes());
    hasher.update(terminal_page_hash);
    hasher.update(inventory_commitment);
    hasher.update(object_set_commitment);
    hasher.finalize().into()
}

impl PreWitnessExecutionBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_persisted(
        producer: &crate::cp::control_store::LifecyclePersistenceContext,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        attempt_id: BootstrapAttemptId,
        operation_id: [u8; 16],
        snapshot_revision: u64,
        seal_revision: u64,
        snapshot_commitment: [u8; 32],
        page_count: u32,
        artifact_count: u32,
        key_bytes: u64,
        terminal_page_hash: [u8; 32],
        inventory_commitment: [u8; 32],
        object_set_commitment: [u8; 32],
        expected_execution_commitment: [u8; 32],
    ) -> Result<Self> {
        let operation_id = PreWitnessDeletionOperationId::from_persisted(producer, operation_id)?;
        let expected = execution_commitment(
            archive_id,
            deletion_fence,
            attempt_id,
            operation_id.as_bytes_for_control(producer),
            snapshot_revision,
            seal_revision,
            snapshot_commitment,
            page_count,
            artifact_count,
            key_bytes,
            terminal_page_hash,
            inventory_commitment,
            object_set_commitment,
        );
        let zero_geometry = page_count == 0
            && artifact_count == 0
            && key_bytes == 0
            && terminal_page_hash == [0; 32];
        let nonzero_geometry =
            page_count > 0 && artifact_count > 0 && key_bytes > 0 && terminal_page_hash != [0; 32];
        if snapshot_revision == 0
            || snapshot_revision.checked_add(1) != Some(seal_revision)
            || key_bytes > MAX_PRE_WITNESS_EXECUTION_KEY_BYTES
            || !(zero_geometry || nonzero_geometry)
            || [
                snapshot_commitment,
                inventory_commitment,
                object_set_commitment,
                expected,
            ]
            .iter()
            .any(|value| value.iter().all(|byte| *byte == 0))
            || expected != expected_execution_commitment
        {
            return Err(PreWitnessDeletionExecutionError::Corrupt);
        }
        Ok(Self {
            archive_id,
            deletion_fence,
            attempt_id,
            operation_id,
            snapshot_revision,
            seal_revision,
            snapshot_commitment,
            inventory_commitment,
            object_set_commitment,
            execution_commitment: expected,
            page_count,
            artifact_count,
            key_bytes,
            terminal_page_hash,
        })
    }

    pub(crate) fn control_view(
        &self,
        producer: &crate::cp::control_store::LifecyclePersistenceContext,
    ) -> PreWitnessExecutionBindingControlView {
        PreWitnessExecutionBindingControlView {
            archive_id: self.archive_id,
            deletion_fence: self.deletion_fence,
            attempt_id: self.attempt_id,
            operation_id: *self.operation_id.as_bytes_for_control(producer),
            snapshot_revision: self.snapshot_revision,
            seal_revision: self.seal_revision,
            snapshot_commitment: self.snapshot_commitment,
            inventory_commitment: self.inventory_commitment,
            object_set_commitment: self.object_set_commitment,
            execution_commitment: self.execution_commitment,
            page_count: self.page_count,
            artifact_count: self.artifact_count,
            key_bytes: self.key_bytes,
            terminal_page_hash: self.terminal_page_hash,
        }
    }
}

impl fmt::Debug for PreWitnessExecutionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreWitnessExecutionBinding(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreWitnessExecutionBindingControlView {
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    attempt_id: BootstrapAttemptId,
    operation_id: [u8; 16],
    snapshot_revision: u64,
    seal_revision: u64,
    snapshot_commitment: [u8; 32],
    inventory_commitment: [u8; 32],
    object_set_commitment: [u8; 32],
    execution_commitment: [u8; 32],
    page_count: u32,
    artifact_count: u32,
    key_bytes: u64,
    terminal_page_hash: [u8; 32],
}

impl PreWitnessExecutionBindingControlView {
    pub(crate) const fn archive_id(self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn deletion_fence(self) -> ObjectId {
        self.deletion_fence
    }

    pub(crate) const fn attempt_id(self) -> BootstrapAttemptId {
        self.attempt_id
    }

    pub(crate) const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }

    pub(crate) const fn snapshot_revision(self) -> u64 {
        self.snapshot_revision
    }

    pub(crate) const fn seal_revision(self) -> u64 {
        self.seal_revision
    }

    pub(crate) const fn snapshot_commitment(self) -> [u8; 32] {
        self.snapshot_commitment
    }

    pub(crate) const fn inventory_commitment(self) -> [u8; 32] {
        self.inventory_commitment
    }

    pub(crate) const fn object_set_commitment(self) -> [u8; 32] {
        self.object_set_commitment
    }

    pub(crate) const fn execution_commitment(self) -> [u8; 32] {
        self.execution_commitment
    }

    pub(crate) const fn page_count(self) -> u32 {
        self.page_count
    }

    pub(crate) const fn artifact_count(self) -> u32 {
        self.artifact_count
    }

    pub(crate) const fn key_bytes(self) -> u64 {
        self.key_bytes
    }

    pub(crate) const fn terminal_page_hash(self) -> [u8; 32] {
        self.terminal_page_hash
    }
}

pub(crate) struct BoundPreWitnessDeletionExecution {
    inventory: AuthenticatedPreWitnessExecutionInventory,
    binding: PreWitnessExecutionBinding,
}

impl BoundPreWitnessDeletionExecution {
    pub(crate) fn from_persisted(
        producer: &crate::cp::control_store::LifecyclePersistenceContext,
        inventory: AuthenticatedPreWitnessExecutionInventory,
        binding: PreWitnessExecutionBinding,
        authenticated_attempt_id: BootstrapAttemptId,
        authenticated_snapshot_commitment: [u8; 32],
    ) -> Result<Self> {
        let view = inventory.control_view(producer);
        let binding_view = binding.control_view(producer);
        let seal = view.seal();
        if seal.archive_id() != binding_view.archive_id()
            || seal.deletion_fence() != binding_view.deletion_fence()
            || authenticated_attempt_id != binding_view.attempt_id()
            || seal.snapshot_revision() != binding_view.snapshot_revision()
            || seal.revision() != binding_view.seal_revision()
            || authenticated_snapshot_commitment != binding_view.snapshot_commitment()
            || seal.page_count() != binding_view.page_count()
            || seal.artifact_count() != binding_view.artifact_count()
            || seal.terminal_page_hash() != binding_view.terminal_page_hash()
            || seal.inventory_commitment() != binding_view.inventory_commitment()
            || view.object_count() != binding_view.artifact_count()
            || view.key_bytes() != binding_view.key_bytes()
            || view.object_set_commitment() != binding_view.object_set_commitment()
        {
            return Err(PreWitnessDeletionExecutionError::Stale);
        }
        Ok(Self { inventory, binding })
    }

    pub(crate) const fn binding(&self) -> &PreWitnessExecutionBinding {
        &self.binding
    }

    #[cfg(test)]
    pub(crate) fn dimensions_for_test(&self) -> (usize, u64) {
        (self.inventory.objects.len(), self.inventory.key_bytes)
    }
}

impl fmt::Debug for BoundPreWitnessDeletionExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundPreWitnessDeletionExecution(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreWitnessExecutionStage {
    InventoryBound,
    RegistryErased,
    ObjectsAbsent,
    PhysicalComplete,
    PayloadErased,
}

pub(crate) struct VerifiedPreWitnessRegistryErasure {
    binding: PreWitnessExecutionBindingControlView,
    commitment: [u8; 32],
}

pub(crate) struct VerifiedPreWitnessObjectsAbsent {
    binding: PreWitnessExecutionBindingControlView,
    registry_commitment: [u8; 32],
    commitment: [u8; 32],
}

pub(crate) struct VerifiedPreWitnessProviderDrain {
    binding: PreWitnessExecutionBindingControlView,
    registry_commitment: [u8; 32],
    objects_commitment: [u8; 32],
    commitment: [u8; 32],
}

pub(crate) struct PreWitnessPhysicalDeletionReceipt {
    binding: PreWitnessExecutionBindingControlView,
    registry_commitment: [u8; 32],
    objects_commitment: [u8; 32],
    drain_commitment: [u8; 32],
}

pub(crate) struct DurablePreWitnessPhysicalCompletion {
    binding: PreWitnessExecutionBinding,
    registry_commitment: [u8; 32],
    objects_commitment: [u8; 32],
    drain_commitment: [u8; 32],
}

pub(crate) enum RecoveredPreWitnessDeletionExecution {
    InventoryBound(BoundPreWitnessDeletionExecution),
    RegistryErased(BoundPreWitnessDeletionExecution, [u8; 32]),
    ObjectsAbsent(BoundPreWitnessDeletionExecution, [u8; 32], [u8; 32]),
    PhysicalComplete(DurablePreWitnessPhysicalCompletion),
    PayloadErased(BoundPreWitnessDeletionExecution),
}

#[async_trait::async_trait]
pub(crate) trait PreWitnessDeletionExecutionControl: Send + Sync {
    async fn bind_pre_witness_execution_inventory(
        &self,
        inventory: AuthenticatedPreWitnessExecutionInventory,
    ) -> Result<BoundPreWitnessDeletionExecution>;

    /// Recovery deliberately consumes a newly authenticated complete
    /// inventory. Archive/fence/operation identifiers alone are never enough
    /// to reconstruct execution authority.
    async fn recover_pre_witness_deletion_execution(
        &self,
        inventory: AuthenticatedPreWitnessExecutionInventory,
    ) -> Result<RecoveredPreWitnessDeletionExecution>;

    async fn record_pre_witness_registry_erased(
        &self,
        evidence: VerifiedPreWitnessRegistryErasure,
    ) -> Result<()>;

    async fn record_pre_witness_objects_absent(
        &self,
        evidence: VerifiedPreWitnessObjectsAbsent,
    ) -> Result<()>;

    async fn record_pre_witness_physical_complete(
        &self,
        receipt: PreWitnessPhysicalDeletionReceipt,
    ) -> Result<DurablePreWitnessPhysicalCompletion>;
}

impl RecoveredPreWitnessDeletionExecution {
    pub(crate) const fn stage(&self) -> PreWitnessExecutionStage {
        match self {
            Self::InventoryBound(_) => PreWitnessExecutionStage::InventoryBound,
            Self::RegistryErased(_, _) => PreWitnessExecutionStage::RegistryErased,
            Self::ObjectsAbsent(_, _, _) => PreWitnessExecutionStage::ObjectsAbsent,
            Self::PhysicalComplete(_) => PreWitnessExecutionStage::PhysicalComplete,
            Self::PayloadErased(_) => PreWitnessExecutionStage::PayloadErased,
        }
    }

    pub(crate) fn binding(&self) -> &PreWitnessExecutionBinding {
        match self {
            Self::InventoryBound(bound)
            | Self::RegistryErased(bound, _)
            | Self::ObjectsAbsent(bound, _, _)
            | Self::PayloadErased(bound) => bound.binding(),
            Self::PhysicalComplete(durable) => &durable.binding,
        }
    }
}

macro_rules! opaque_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($name)
            }
        }
    };
}

opaque_debug!(
    VerifiedPreWitnessRegistryErasure,
    "VerifiedPreWitnessRegistryErasure(<opaque>)"
);
opaque_debug!(
    VerifiedPreWitnessObjectsAbsent,
    "VerifiedPreWitnessObjectsAbsent(<opaque>)"
);
opaque_debug!(
    VerifiedPreWitnessProviderDrain,
    "VerifiedPreWitnessProviderDrain(<opaque>)"
);
opaque_debug!(
    PreWitnessPhysicalDeletionReceipt,
    "PreWitnessPhysicalDeletionReceipt(<opaque>)"
);
opaque_debug!(
    DurablePreWitnessPhysicalCompletion,
    "DurablePreWitnessPhysicalCompletion(<opaque>)"
);
opaque_debug!(
    RecoveredPreWitnessDeletionExecution,
    "RecoveredPreWitnessDeletionExecution(<opaque>)"
);

impl VerifiedPreWitnessRegistryErasure {
    pub(crate) fn into_control_parts(
        self,
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
    ) -> (PreWitnessExecutionBindingControlView, [u8; 32]) {
        (self.binding, self.commitment)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        binding: &PreWitnessExecutionBinding,
        producer: &crate::cp::control_store::LifecyclePersistenceContext,
        evidence: [u8; 32],
    ) -> Result<Self> {
        let view = binding.control_view(producer);
        Ok(Self {
            binding: view,
            commitment: chained_commitment(
                REGISTRY_EVIDENCE_DOMAIN,
                &[view.execution_commitment],
                evidence,
            )?,
        })
    }
}

impl VerifiedPreWitnessObjectsAbsent {
    pub(crate) fn into_control_parts(
        self,
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
    ) -> (PreWitnessExecutionBindingControlView, [u8; 32], [u8; 32]) {
        (self.binding, self.registry_commitment, self.commitment)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        binding: &PreWitnessExecutionBinding,
        producer: &crate::cp::control_store::LifecyclePersistenceContext,
        registry_commitment: [u8; 32],
        evidence: [u8; 32],
    ) -> Result<Self> {
        let view = binding.control_view(producer);
        Ok(Self {
            binding: view,
            registry_commitment,
            commitment: chained_commitment(
                OBJECTS_EVIDENCE_DOMAIN,
                &[view.execution_commitment, registry_commitment],
                evidence,
            )?,
        })
    }
}

impl VerifiedPreWitnessProviderDrain {
    #[cfg(test)]
    pub(crate) fn for_test(
        binding: &PreWitnessExecutionBinding,
        producer: &crate::cp::control_store::LifecyclePersistenceContext,
        registry_commitment: [u8; 32],
        objects_commitment: [u8; 32],
        evidence: [u8; 32],
    ) -> Result<Self> {
        let view = binding.control_view(producer);
        Ok(Self {
            binding: view,
            registry_commitment,
            objects_commitment,
            commitment: chained_commitment(
                PROVIDER_DRAIN_DOMAIN,
                &[
                    view.execution_commitment,
                    registry_commitment,
                    objects_commitment,
                ],
                evidence,
            )?,
        })
    }

    pub(crate) fn into_physical_receipt(self) -> PreWitnessPhysicalDeletionReceipt {
        PreWitnessPhysicalDeletionReceipt {
            binding: self.binding,
            registry_commitment: self.registry_commitment,
            objects_commitment: self.objects_commitment,
            drain_commitment: self.commitment,
        }
    }
}

impl PreWitnessPhysicalDeletionReceipt {
    pub(crate) fn into_control_parts(
        self,
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
    ) -> (
        PreWitnessExecutionBindingControlView,
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        (
            self.binding,
            self.registry_commitment,
            self.objects_commitment,
            self.drain_commitment,
        )
    }
}

impl DurablePreWitnessPhysicalCompletion {
    pub(crate) fn from_persisted(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        binding: PreWitnessExecutionBinding,
        registry_commitment: [u8; 32],
        objects_commitment: [u8; 32],
        drain_commitment: [u8; 32],
    ) -> Result<Self> {
        if [registry_commitment, objects_commitment, drain_commitment]
            .iter()
            .any(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(PreWitnessDeletionExecutionError::Corrupt);
        }
        Ok(Self {
            binding,
            registry_commitment,
            objects_commitment,
            drain_commitment,
        })
    }
}

fn chained_commitment(domain: &[u8], prior: &[[u8; 32]], evidence: [u8; 32]) -> Result<[u8; 32]> {
    if evidence.iter().all(|byte| *byte == 0)
        || prior
            .iter()
            .any(|value| value.iter().all(|byte| *byte == 0))
    {
        return Err(PreWitnessDeletionExecutionError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for value in prior {
        hasher.update(value);
    }
    hasher.update(evidence);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
pub(crate) fn payload_cleanup_commitment_for_test(
    binding: &PreWitnessExecutionBinding,
    producer: &crate::cp::control_store::LifecyclePersistenceContext,
    registry: [u8; 32],
    objects: [u8; 32],
    drain: [u8; 32],
    evidence: [u8; 32],
) -> Result<[u8; 32]> {
    let view = binding.control_view(producer);
    chained_commitment(
        PAYLOAD_CLEANUP_DOMAIN,
        &[view.execution_commitment, registry, objects, drain],
        evidence,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_id_is_nonzero_nonrevealing_and_not_plain_data() {
        assert!(PreWitnessDeletionOperationId::for_test([0; 16]).is_err());
        let operation = PreWitnessDeletionOperationId::for_test([0xa5; 16]).unwrap();
        assert_eq!(
            format!("{operation:?}"),
            "PreWitnessDeletionOperationId(<opaque>)"
        );
    }

    #[test]
    fn source_has_no_runtime_destructive_or_normal_deletion_bridge() {
        let source = include_str!("archive_v3_pre_witness_deletion.rs");
        for forbidden in [
            concat!("crate::store::", "Store"),
            concat!("std::", "env"),
            concat!("Gcs", "Client"),
            concat!("FirestoreWitness::", "new"),
            concat!("ArchiveV3ExactDeletion", "Provider"),
            concat!("DeletionExecution", "Binding"),
            concat!("AuthorizedDeletion", "Inventory"),
            concat!("impl ", "From<CompletePreWitness", "DeletionInventory"),
            concat!("delete_all_", "generations"),
        ] {
            assert!(!source.contains(forbidden), "found forbidden {forbidden}");
        }
        let runtime = include_str!("main.rs");
        assert!(!runtime.contains(concat!("bind_pre_witness_execution_", "inventory(")));
        assert!(!runtime.contains(concat!("record_pre_witness_physical_", "complete(")));
        let deletion = include_str!("archive_v3_deletion.rs");
        assert!(!deletion.contains(concat!(
            "impl ",
            "From<CompletePreWitnessDeletionInventory",
            ">"
        )));
        assert!(!deletion.contains(concat!(
            "CompletePreWitnessDeletionInventory::",
            "authorize"
        )));
    }
}
