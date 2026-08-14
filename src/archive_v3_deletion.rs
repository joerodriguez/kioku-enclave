#![allow(
    dead_code,
    reason = "inactive ADR-0022 deletion driver is compiled and fake-tested before authority wiring"
)]

//! Inactive, witness-fenced archive-v3 deletion driver.
//!
//! This is deliberately a narrow coordinator, not a control-plane deletion
//! route. It accepts a deletion session only after an exact-current witness
//! tombstone/restart authorization and a durable lifecycle inventory seal; it
//! has no account/user identifiers, raw
//! prefix selector, list-all operation, Store connection, credentials, or
//! constructor I/O. The separate inactive inventory coordinator authenticates
//! exact-name reachability, unions every frozen create-ahead row, and loads the
//! bounded canonical lifecycle-page inventory. The driver then deletes
//! each exact object and its permanent ID claim through all generations using
//! only opaque per-entry capabilities minted from that sealed inventory,
//! reconciling an ambiguous mutation only by an exact absence read/list.
//! Physical completion binds witness evidence to both the inventory commitment
//! and a fresh exact provider-drain commitment, returning an opaque receipt
//! that is required before lifecycle page/bootstrap payload erasure.
//!
//! The current root/manifest formats contain immutable references but do not
//! carry enough location fields to derive every descendant `ObjectContext`
//! from an object ID alone (notably checkpoint IDs/ranges and extent-tree
//! ranges).  Consequently this module intentionally does *not* infer keys or
//! list an archive prefix. The authenticated lifecycle-page loader is compiled
//! but no runtime constructs it or invokes this driver, so the path remains
//! inactive and fails closed.

use crate::{
    archive_v3::{
        ArchiveId, ArchivePrefix, KeyKind, KeyRegistryContext, LogicalLocation, ObjectContext,
        ObjectKey, ObjectRole, ParentReference,
    },
    archive_v3_gcs::{ArchiveV3GcsTransport, GcsArchiveV3DeleteResult, GcsArchiveV3TransportError},
    archive_v3_lifecycle::{
        DeletionInventorySeal, LifecycleInventoryObject, PhysicalDeletionReceipt,
    },
    archive_v3_witness::{
        DeletionAdvance, DeletionAuthorization, DeletionExecutionBinding, DeletionRecovery,
        DeletionStageProof, DeletionState, DeletionWorkerCredential, KeyRegistryReference,
        RootCommitment, TombstoneReceipt, Witness, WitnessError, WitnessRecord,
    },
};
use sha2::{Digest, Sha256};
use std::{fmt, marker::PhantomData, sync::Arc};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum ArchiveDeletionError {
    #[error("archive-v3 deletion is not tombstoned or is already complete")]
    InvalidDeletionState,
    #[error("archive-v3 deletion metadata inventory is malformed")]
    InvalidInventory,
    #[error("archive-v3 deletion metadata inventory exceeded a fixed bound")]
    InventoryLimit,
    #[error("archive-v3 deletion witness transition failed")]
    Witness,
    #[error("archive-v3 deletion session is stale")]
    StaleSession,
    #[error("archive-v3 deletion provider is unavailable")]
    Unavailable,
    #[error("archive-v3 deletion provider mutation outcome remains unknown")]
    OutcomeUnknown,
    #[error("archive-v3 deletion provider exact read/list did not match")]
    ProviderMismatch,
    #[error("archive-v3 deletion provider drain is incomplete")]
    ProviderDrainPending,
}

type Result<T> = std::result::Result<T, ArchiveDeletionError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactDeleteOutcome {
    DeletedAllGenerations,
    AlreadyAbsent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactDeletionProviderError {
    Unavailable,
    OutcomeUnknown,
    Mismatch,
    DrainPending,
}

const PROVIDER_DRAIN_COMMITMENT_DOMAIN: &[u8] = b"kioku:archive:v3:provider-inventory-drain/v2\0";

/// Fresh witness-authenticated destructive capability. Every provider method
/// requires it, so an archive ID or object key alone cannot authorize I/O.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DeletionExecutionContext {
    binding: DeletionExecutionBinding,
    inventory_commitment: [u8; 32],
}

impl fmt::Debug for DeletionExecutionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeletionExecutionContext(<opaque>)")
    }
}

/// Inventory-bound proof returned only after a provider re-verifies exact
/// content and claim absence, including its soft-delete drain semantics.
struct InventoryDrainProof {
    binding: DeletionExecutionBinding,
    inventory_commitment: [u8; 32],
    provider_drain_commitment: [u8; 32],
    retention_stage: DeletionStageProof,
}

pub(crate) struct VerifiedPhysicalTransition {
    seal: DeletionInventorySeal,
    provider_drain_commitment: [u8; 32],
}

impl VerifiedPhysicalTransition {
    fn new(seal: DeletionInventorySeal, provider_drain_commitment: [u8; 32]) -> Self {
        Self {
            seal,
            provider_drain_commitment,
        }
    }

    pub(crate) const fn seal(&self) -> DeletionInventorySeal {
        self.seal
    }

    pub(crate) const fn provider_drain_commitment(&self) -> [u8; 32] {
        self.provider_drain_commitment
    }
}

impl InventoryDrainProof {
    fn into_retention_stage(
        self,
        authorized: &AuthorizedDeletionInventory<'_>,
    ) -> Result<DeletionStageProof> {
        if self.binding != authorized.execution.binding
            || self.inventory_commitment != authorized.inventory.commitment
            || self.provider_drain_commitment != provider_drain_commitment(authorized)
            || self.retention_stage.drain_binding()
                != Some((self.inventory_commitment, self.provider_drain_commitment))
        {
            return Err(ArchiveDeletionError::ProviderMismatch);
        }
        Ok(self.retention_stage)
    }
}

impl fmt::Debug for InventoryDrainProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InventoryDrainProof(<opaque>)")
    }
}

/// A complete inventory paired with the exact fresh witness execution tuple.
/// The private constructor refuses a different inventory commitment.
struct AuthorizedDeletionInventory<'a> {
    execution: DeletionExecutionContext,
    inventory: &'a CompleteDeletionInventory,
}

impl fmt::Debug for AuthorizedDeletionInventory<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedDeletionInventory(<opaque>)")
    }
}

/// Opaque per-entry destructive capability. Only a sealed, authorized
/// inventory can mint one; its index and key are checked again by concrete
/// adapters before any transport call.
#[derive(Clone)]
struct DeletionEntryCapability<'a> {
    binding: DeletionExecutionBinding,
    inventory_commitment: [u8; 32],
    index: usize,
    key: ObjectKey,
    inventory_lifetime: PhantomData<&'a CompleteDeletionInventory>,
}

impl fmt::Debug for DeletionEntryCapability<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeletionEntryCapability(<opaque>)")
    }
}

/// Capability for exact destructive work. Every entry argument is minted by
/// the sealed complete inventory; a raw archive ID, object ID, or key is never
/// accepted by this interface.
#[async_trait::async_trait]
trait ArchiveV3ExactDeletionProvider: Send + Sync {
    async fn delete_content_all_generations(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> std::result::Result<ExactDeleteOutcome, ExactDeletionProviderError>;

    async fn verify_content_absent(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> std::result::Result<bool, ExactDeletionProviderError>;

    async fn delete_claim_all_generations(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> std::result::Result<ExactDeleteOutcome, ExactDeletionProviderError>;

    async fn verify_claim_absent(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> std::result::Result<bool, ExactDeletionProviderError>;

    /// Re-verify the complete sealed inventory and its permanent claims. A
    /// partial inventory cannot be passed here because the type has no
    /// non-test constructor until a full-reachability walker is admitted.
    async fn verify_complete_inventory_drained(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        retention_assertion: &DeletionStageProof,
    ) -> std::result::Result<InventoryDrainProof, ExactDeletionProviderError>;
}

/// Adapter for the existing exact-generation GCS contract.  GCS's transport
/// success already means all live/noncurrent generations are absent and its
/// concrete HTTP implementation rejects soft-delete residue unless the
/// independent drain gate attests it has expired.
struct GcsArchiveV3DeletionProvider {
    transport: Arc<dyn ArchiveV3GcsTransport>,
}

impl GcsArchiveV3DeletionProvider {
    fn new(transport: Arc<dyn ArchiveV3GcsTransport>) -> Self {
        Self { transport }
    }
}

#[async_trait::async_trait]
impl ArchiveV3ExactDeletionProvider for GcsArchiveV3DeletionProvider {
    async fn delete_content_all_generations(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> std::result::Result<ExactDeleteOutcome, ExactDeletionProviderError> {
        let key = validate_entry(authorized, entry)?;
        map_delete(
            self.transport
                .delete_all_generations_exact(key.as_str())
                .await,
        )
    }

    async fn verify_content_absent(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> std::result::Result<bool, ExactDeletionProviderError> {
        let key = validate_entry(authorized, entry)?;
        map_provider(
            self.transport
                .verify_all_generations_absent_exact(key.as_str())
                .await,
        )
    }

    async fn delete_claim_all_generations(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> std::result::Result<ExactDeleteOutcome, ExactDeletionProviderError> {
        let key = validate_entry(authorized, entry)?;
        let prefix = ArchivePrefix::for_archive(authorized.execution.binding.archive_id());
        map_delete(
            self.transport
                .delete_claim_all_generations_exact(prefix.as_str(), key.object_id())
                .await,
        )
    }

    async fn verify_claim_absent(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> std::result::Result<bool, ExactDeletionProviderError> {
        let key = validate_entry(authorized, entry)?;
        let prefix = ArchivePrefix::for_archive(authorized.execution.binding.archive_id());
        map_provider(
            self.transport
                .verify_claim_all_generations_absent_exact(prefix.as_str(), key.object_id())
                .await,
        )
    }

    async fn verify_complete_inventory_drained(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        retention_assertion: &DeletionStageProof,
    ) -> std::result::Result<InventoryDrainProof, ExactDeletionProviderError> {
        for index in 0..authorized.inventory.objects.len() {
            let entry = authorized.entry(index)?;
            if !self.verify_content_absent(authorized, &entry).await?
                || !self.verify_claim_absent(authorized, &entry).await?
            {
                return Err(ExactDeletionProviderError::DrainPending);
            }
        }
        let provider_drain_commitment = provider_drain_commitment(authorized);
        let retention_stage = retention_assertion
            .bind_inventory_drain(authorized.inventory.commitment, provider_drain_commitment)
            .map_err(|_| ExactDeletionProviderError::Mismatch)?;
        Ok(InventoryDrainProof {
            binding: authorized.execution.binding,
            inventory_commitment: authorized.inventory.commitment,
            provider_drain_commitment,
            retention_stage,
        })
    }
}

fn validate_entry<'a>(
    authorized: &'a AuthorizedDeletionInventory<'_>,
    entry: &DeletionEntryCapability<'_>,
) -> std::result::Result<&'a ObjectKey, ExactDeletionProviderError> {
    if entry.binding != authorized.execution.binding
        || entry.inventory_commitment != authorized.inventory.commitment
        || authorized.execution.inventory_commitment != authorized.inventory.commitment
    {
        return Err(ExactDeletionProviderError::Mismatch);
    }
    let object = authorized
        .inventory
        .objects
        .get(entry.index)
        .ok_or(ExactDeletionProviderError::Mismatch)?;
    let key = object.key();
    let prefix = ArchivePrefix::for_archive(authorized.execution.binding.archive_id());
    if key != &entry.key || !key.as_str().starts_with(prefix.as_str()) {
        return Err(ExactDeletionProviderError::Mismatch);
    }
    Ok(key)
}

fn provider_drain_commitment(authorized: &AuthorizedDeletionInventory<'_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_DRAIN_COMMITMENT_DOMAIN);
    hasher.update(authorized.execution.binding.commitment());
    hasher.update(authorized.inventory.commitment);
    hasher.update((authorized.inventory.objects.len() as u64).to_be_bytes());
    hasher.update((authorized.inventory.key_bytes as u64).to_be_bytes());
    hasher.update((authorized.inventory.pages as u64).to_be_bytes());
    hasher.finalize().into()
}

fn map_delete(
    value: std::result::Result<GcsArchiveV3DeleteResult, GcsArchiveV3TransportError>,
) -> std::result::Result<ExactDeleteOutcome, ExactDeletionProviderError> {
    match value {
        Ok(GcsArchiveV3DeleteResult::DeletedAllGenerations) => {
            Ok(ExactDeleteOutcome::DeletedAllGenerations)
        }
        Ok(GcsArchiveV3DeleteResult::Absent) => Ok(ExactDeleteOutcome::AlreadyAbsent),
        Err(error) => Err(map_gcs_error(error)),
    }
}

fn map_provider(
    value: std::result::Result<bool, GcsArchiveV3TransportError>,
) -> std::result::Result<bool, ExactDeletionProviderError> {
    value.map_err(map_gcs_error)
}

fn map_gcs_error(error: GcsArchiveV3TransportError) -> ExactDeletionProviderError {
    match error {
        GcsArchiveV3TransportError::Unavailable | GcsArchiveV3TransportError::NotFound => {
            ExactDeletionProviderError::Unavailable
        }
        GcsArchiveV3TransportError::OutcomeUnknown => ExactDeletionProviderError::OutcomeUnknown,
        GcsArchiveV3TransportError::PreconditionFailed | GcsArchiveV3TransportError::Protocol => {
            ExactDeletionProviderError::Mismatch
        }
        GcsArchiveV3TransportError::TooLarge => ExactDeletionProviderError::Mismatch,
    }
}

/// Witness-derived, content-free authority context.  Only this module can
/// construct it from a witness record; callers cannot substitute an account,
/// prefix, object key, or guessed root.
#[derive(Clone)]
pub(crate) struct AuthenticatedDeletionContext {
    archive_id: ArchiveId,
    root: RootCommitment,
    registry: KeyRegistryReference,
    predecessor_root: Option<RootCommitment>,
    predecessor_registry: Option<KeyRegistryReference>,
}

impl AuthenticatedDeletionContext {
    fn from_record(record: &WitnessRecord) -> Self {
        Self {
            archive_id: record.archive_id(),
            root: record.root(),
            registry: record.registry(),
            predecessor_root: record.predecessor_root(),
            predecessor_registry: record.predecessor_registry(),
        }
    }

    pub(crate) fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }
    fn root(&self) -> RootCommitment {
        self.root
    }
    fn registry(&self) -> KeyRegistryReference {
        self.registry
    }
    fn predecessor_root(&self) -> Option<RootCommitment> {
        self.predecessor_root
    }
    fn predecessor_registry(&self) -> Option<KeyRegistryReference> {
        self.predecessor_registry
    }
}

impl fmt::Debug for AuthenticatedDeletionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedDeletionContext(<opaque>)")
    }
}

/// Loads only a previously durable, authenticated inventory. The pre-erasure
/// coordinator authenticates the witness root graph, unions every create-ahead
/// row, persists canonical pages, and mints the supplied seal. After registry
/// erasure this method may read those sealed pages only; it must never decrypt
/// archive metadata or rediscover by prefix.
#[async_trait::async_trait]
pub(crate) trait SealedArchiveInventoryLedger: Send + Sync {
    async fn load_exact(
        &self,
        context: &AuthenticatedDeletionContext,
        seal: &DeletionInventorySeal,
    ) -> Result<CompleteDeletionInventory>;
}

pub(crate) struct CompleteDeletionInventory {
    objects: Vec<LifecycleInventoryObject>,
    commitment: [u8; 32],
    key_bytes: usize,
    pages: usize,
}

impl CompleteDeletionInventory {
    #[cfg(test)]
    pub(crate) const fn commitment_for_test(&self) -> [u8; 32] {
        self.commitment
    }

    #[cfg(test)]
    pub(crate) fn objects_for_test(&self) -> &[LifecycleInventoryObject] {
        &self.objects
    }

    pub(crate) fn from_authenticated_lifecycle_pages(
        _producer: &crate::archive_v3_inventory_coordinator::AuthenticatedInventoryLoad,
        seal: &DeletionInventorySeal,
        objects: Vec<LifecycleInventoryObject>,
        key_bytes: usize,
    ) -> Result<Self> {
        if objects.is_empty()
            || objects.len() != usize::try_from(seal.artifact_count()).unwrap_or(usize::MAX)
            || key_bytes == 0
        {
            return Err(ArchiveDeletionError::InvalidInventory);
        }
        Ok(Self {
            objects,
            commitment: seal.inventory_commitment(),
            key_bytes,
            pages: usize::try_from(seal.page_count())
                .map_err(|_| ArchiveDeletionError::InventoryLimit)?,
        })
    }

    #[cfg(test)]
    fn for_test(
        seal: &DeletionInventorySeal,
        objects: Vec<LifecycleInventoryObject>,
    ) -> Result<Self> {
        let key_bytes = objects.iter().try_fold(0usize, |total, object| {
            total
                .checked_add(object.key().as_str().len())
                .ok_or(ArchiveDeletionError::InventoryLimit)
        })?;
        if objects.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ArchiveDeletionError::InvalidInventory);
        }
        Self::from_authenticated_lifecycle_pages(
            &crate::archive_v3_inventory_coordinator::AuthenticatedInventoryLoad::for_test(),
            seal,
            objects,
            key_bytes,
        )
    }

    fn authorize(
        &self,
        execution: DeletionExecutionContext,
    ) -> Result<AuthorizedDeletionInventory<'_>> {
        if execution.inventory_commitment != self.commitment {
            return Err(ArchiveDeletionError::ProviderMismatch);
        }
        Ok(AuthorizedDeletionInventory {
            execution,
            inventory: self,
        })
    }
}

impl AuthorizedDeletionInventory<'_> {
    fn entry<'entry>(
        &'entry self,
        index: usize,
    ) -> std::result::Result<DeletionEntryCapability<'entry>, ExactDeletionProviderError> {
        let object = self
            .inventory
            .objects
            .get(index)
            .ok_or(ExactDeletionProviderError::Mismatch)?;
        Ok(DeletionEntryCapability {
            binding: self.execution.binding,
            inventory_commitment: self.inventory.commitment,
            index,
            key: object.key().clone(),
            inventory_lifetime: PhantomData,
        })
    }
}

#[cfg(test)]
impl<'a> DeletionEntryCapability<'a> {
    fn with_binding_for_test(mut self, binding: DeletionExecutionBinding) -> Self {
        self.binding = binding;
        self
    }

    fn with_key_for_test(mut self, key: ObjectKey) -> Self {
        self.key = key;
        self
    }
}

impl fmt::Debug for CompleteDeletionInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompleteDeletionInventory(<opaque>)")
    }
}

/// Fully authenticated create-ahead inventory for the branch where the
/// initial witness send was proven absent. This type is deliberately not a
/// `CompleteDeletionInventory`: it has no `authorize`, entry, provider, or
/// conversion surface and cannot be passed to the deletion driver. Driver
/// integration is a later authority change.
pub(crate) struct CompletePreWitnessDeletionInventory {
    objects: Vec<LifecycleInventoryObject>,
    commitment: [u8; 32],
    key_bytes: usize,
    pages: usize,
}

impl CompletePreWitnessDeletionInventory {
    pub(crate) fn from_authenticated_lifecycle_pages(
        _producer: &crate::archive_v3_inventory_coordinator::AuthenticatedPreWitnessInventoryLoad,
        seal: &crate::archive_v3_lifecycle::PreWitnessDeletionInventorySeal,
        objects: Vec<LifecycleInventoryObject>,
        key_bytes: usize,
    ) -> Result<Self> {
        if objects.len() != usize::try_from(seal.artifact_count()).unwrap_or(usize::MAX)
            || (objects.is_empty()
                && (key_bytes != 0
                    || seal.page_count() != 0
                    || seal.terminal_page_hash() != [0; 32]))
            || (!objects.is_empty() && (key_bytes == 0 || seal.page_count() == 0))
        {
            return Err(ArchiveDeletionError::InvalidInventory);
        }
        Ok(Self {
            objects,
            commitment: seal.inventory_commitment(),
            key_bytes,
            pages: usize::try_from(seal.page_count())
                .map_err(|_| ArchiveDeletionError::InventoryLimit)?,
        })
    }

    /// Consuming conversion gated by the dedicated pre-witness execution
    /// module's private producer token. This never yields a normal deletion
    /// inventory or a provider entry capability.
    pub(crate) fn into_pre_witness_execution_parts(
        self,
        _producer: &crate::archive_v3_pre_witness_deletion::PreWitnessExecutionInventoryProducer,
    ) -> (Vec<LifecycleInventoryObject>, [u8; 32], usize, usize) {
        (self.objects, self.commitment, self.key_bytes, self.pages)
    }

    #[cfg(test)]
    pub(crate) fn objects_for_test(&self) -> &[LifecycleInventoryObject] {
        &self.objects
    }

    #[cfg(test)]
    pub(crate) const fn commitment_for_test(&self) -> [u8; 32] {
        self.commitment
    }

    #[cfg(test)]
    pub(crate) const fn dimensions_for_test(&self) -> (usize, usize) {
        (self.key_bytes, self.pages)
    }
}

impl fmt::Debug for CompletePreWitnessDeletionInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletePreWitnessDeletionInventory(<opaque>)")
    }
}

/// Opaque deletion session reconstructed only from a witness tombstone receipt
/// or deletion-only restart authorization.
#[derive(Clone)]
struct DeletionSession {
    record: WitnessRecord,
    authorization: DeletionAuthorization,
}

impl DeletionSession {
    fn from_tombstone(receipt: &TombstoneReceipt) -> Result<Self> {
        let record = receipt.receipt().record().clone();
        (record.deletion() == DeletionState::Tombstoned)
            .then_some(Self {
                record,
                authorization: receipt.authorization(),
            })
            .ok_or(ArchiveDeletionError::InvalidDeletionState)
    }

    fn from_recovery(recovery: &DeletionRecovery) -> Result<Self> {
        let record = recovery.receipt().record().clone();
        matches!(
            record.deletion(),
            DeletionState::Tombstoned
                | DeletionState::CryptographicallyErased
                | DeletionState::LogicalObjectsAbsent
                | DeletionState::PhysicalComplete
        )
        .then_some(Self {
            record,
            authorization: recovery.authorization(),
        })
        .ok_or(ArchiveDeletionError::InvalidDeletionState)
    }
}

impl fmt::Debug for DeletionSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeletionSession(<opaque>)")
    }
}

/// Provider-authenticated proofs for the three post-tombstone witness stages.
struct DeletionStageProofs<'a> {
    key_erasure: &'a DeletionStageProof,
    inventory: &'a DeletionStageProof,
    retention_assertion: &'a DeletionStageProof,
}

/// Constructs dependencies only. It performs no storage, witness, KMS, or
/// provider I/O. No production caller constructs this inactive coordinator.
struct ArchiveV3DeletionDriver {
    metadata: Arc<dyn SealedArchiveInventoryLedger>,
    provider: Arc<dyn ArchiveV3ExactDeletionProvider>,
}

impl ArchiveV3DeletionDriver {
    fn new(
        metadata: Arc<dyn SealedArchiveInventoryLedger>,
        provider: Arc<dyn ArchiveV3ExactDeletionProvider>,
    ) -> Self {
        Self { metadata, provider }
    }

    /// Advance a tombstoned archive through exact deletion.  Every ambiguous
    /// delete is reconciled once through a non-mutating exact absence proof;
    /// if anything remains or differs, the method returns an opaque error and
    /// a restarted worker must reconstruct a new `DeletionSession` from the
    /// witness rather than guessing/replaying a generation mutation.
    async fn run(
        &self,
        witness: &dyn Witness,
        mut session: DeletionSession,
        credential: &DeletionWorkerCredential,
        proofs: DeletionStageProofs<'_>,
        seal: &DeletionInventorySeal,
    ) -> Result<PhysicalDeletionReceipt> {
        if seal.archive_id() != session.record.archive_id() {
            return Err(ArchiveDeletionError::ProviderMismatch);
        }
        loop {
            match session.record.deletion() {
                DeletionState::Tombstoned => {
                    let context = AuthenticatedDeletionContext::from_record(&session.record);
                    let inventory = self.metadata.load_exact(&context, seal).await?;
                    if inventory.commitment != seal.inventory_commitment() {
                        return Err(ArchiveDeletionError::ProviderMismatch);
                    }
                    let execution =
                        fresh_execution_context(witness, &session, credential, &inventory)?;
                    let authorized = inventory.authorize(execution)?;
                    self.reconcile_registry_inventory(&context, &authorized)
                        .await?;
                    let key_erasure = proofs
                        .key_erasure
                        .bind_inventory_only(seal.inventory_commitment())
                        .map_err(map_witness_error)?;
                    session.record = advance(
                        witness,
                        &session,
                        DeletionState::CryptographicallyErased,
                        credential,
                        &key_erasure,
                    )?;
                }
                DeletionState::CryptographicallyErased => {
                    let inventory = self
                        .metadata
                        .load_exact(
                            &AuthenticatedDeletionContext::from_record(&session.record),
                            seal,
                        )
                        .await?;
                    if inventory.commitment != seal.inventory_commitment() {
                        return Err(ArchiveDeletionError::ProviderMismatch);
                    }
                    let execution =
                        fresh_execution_context(witness, &session, credential, &inventory)?;
                    let authorized = inventory.authorize(execution)?;
                    self.reconcile_exact_inventory(&authorized).await?;
                    session.record = advance(
                        witness,
                        &session,
                        DeletionState::LogicalObjectsAbsent,
                        credential,
                        proofs.inventory,
                    )?;
                }
                DeletionState::LogicalObjectsAbsent => {
                    let inventory = self
                        .metadata
                        .load_exact(
                            &AuthenticatedDeletionContext::from_record(&session.record),
                            seal,
                        )
                        .await?;
                    if inventory.commitment != seal.inventory_commitment() {
                        return Err(ArchiveDeletionError::ProviderMismatch);
                    }
                    let execution =
                        fresh_execution_context(witness, &session, credential, &inventory)?;
                    let authorized = inventory.authorize(execution)?;
                    // Restart-safe final recheck: physical completion is not
                    // inferred from a previous in-memory deletion loop. The
                    // provider must bind its proof to this complete inventory.
                    let drain = self
                        .provider
                        .verify_complete_inventory_drained(&authorized, proofs.retention_assertion)
                        .await
                        .map_err(map_provider_error)?;
                    let drain_commitment = drain.provider_drain_commitment;
                    if drain.binding != authorized.execution.binding
                        || drain.inventory_commitment != inventory.commitment
                        || drain_commitment != provider_drain_commitment(&authorized)
                    {
                        return Err(ArchiveDeletionError::ProviderMismatch);
                    }
                    let retention = drain.into_retention_stage(&authorized)?;
                    let record = advance(
                        witness,
                        &session,
                        DeletionState::PhysicalComplete,
                        credential,
                        &retention,
                    )?;
                    if record.deletion() != DeletionState::PhysicalComplete {
                        return Err(ArchiveDeletionError::Witness);
                    }
                    return PhysicalDeletionReceipt::from_verified_transition(
                        VerifiedPhysicalTransition::new(*seal, drain_commitment),
                    )
                    .map_err(|_| ArchiveDeletionError::ProviderMismatch);
                }
                DeletionState::PhysicalComplete => {
                    let inventory = self
                        .metadata
                        .load_exact(
                            &AuthenticatedDeletionContext::from_record(&session.record),
                            seal,
                        )
                        .await?;
                    if inventory.commitment != seal.inventory_commitment() {
                        return Err(ArchiveDeletionError::ProviderMismatch);
                    }
                    let execution =
                        fresh_execution_context(witness, &session, credential, &inventory)?;
                    let authorized = inventory.authorize(execution)?;
                    let drain = self
                        .provider
                        .verify_complete_inventory_drained(&authorized, proofs.retention_assertion)
                        .await
                        .map_err(map_provider_error)?;
                    let drain_commitment = drain.provider_drain_commitment;
                    if drain.binding != authorized.execution.binding
                        || drain.inventory_commitment != inventory.commitment
                        || drain_commitment != provider_drain_commitment(&authorized)
                    {
                        return Err(ArchiveDeletionError::ProviderMismatch);
                    }
                    let retention = drain.into_retention_stage(&authorized)?;
                    let verified = witness
                        .verify_physical_completion(
                            session.record.archive_id(),
                            credential,
                            &retention,
                        )
                        .map_err(map_witness_error)?;
                    if verified.receipt().record() != &session.record {
                        return Err(ArchiveDeletionError::StaleSession);
                    }
                    return PhysicalDeletionReceipt::from_verified_transition(
                        VerifiedPhysicalTransition::new(*seal, drain_commitment),
                    )
                    .map_err(|_| ArchiveDeletionError::ProviderMismatch);
                }
                DeletionState::Active => return Err(ArchiveDeletionError::InvalidDeletionState),
            }
        }
    }

    async fn reconcile_exact_inventory(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
    ) -> Result<()> {
        if authorized.execution.inventory_commitment != authorized.inventory.commitment {
            return Err(ArchiveDeletionError::ProviderMismatch);
        }
        for index in 0..authorized.inventory.objects.len() {
            if authorized.inventory.objects[index].role() == ObjectRole::KeyRegistryV3 {
                continue;
            }
            let entry = authorized.entry(index).map_err(map_provider_error)?;
            self.delete_content_reconcile(authorized, &entry).await?;
            self.delete_claim_reconcile(authorized, &entry).await?;
        }
        Ok(())
    }

    async fn reconcile_registry_inventory(
        &self,
        context: &AuthenticatedDeletionContext,
        authorized: &AuthorizedDeletionInventory<'_>,
    ) -> Result<()> {
        let mut registry_keys = vec![registry_key(context.archive_id, context.registry)];
        if let Some(registry) = context.predecessor_registry {
            registry_keys.push(registry_key(context.archive_id, registry));
        }
        for required in registry_keys {
            if !authorized.inventory.objects.iter().any(|object| {
                object.role() == ObjectRole::KeyRegistryV3 && object.key() == &required
            }) {
                return Err(ArchiveDeletionError::InvalidInventory);
            }
        }
        let registry_indices = authorized
            .inventory
            .objects
            .iter()
            .enumerate()
            .filter_map(|(index, object)| {
                (object.role() == ObjectRole::KeyRegistryV3).then_some(index)
            })
            .collect::<Vec<_>>();
        if registry_indices.is_empty() {
            return Err(ArchiveDeletionError::InvalidInventory);
        }
        for index in registry_indices {
            let entry = authorized.entry(index).map_err(map_provider_error)?;
            self.delete_content_reconcile(authorized, &entry).await?;
            self.delete_claim_reconcile(authorized, &entry).await?;
            if !self
                .provider
                .verify_content_absent(authorized, &entry)
                .await
                .map_err(map_provider_error)?
                || !self
                    .provider
                    .verify_claim_absent(authorized, &entry)
                    .await
                    .map_err(map_provider_error)?
            {
                return Err(ArchiveDeletionError::ProviderDrainPending);
            }
        }
        Ok(())
    }

    async fn delete_content_reconcile(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> Result<()> {
        match self
            .provider
            .delete_content_all_generations(authorized, entry)
            .await
        {
            Ok(_) => Ok(()),
            Err(ExactDeletionProviderError::OutcomeUnknown) => self
                .provider
                .verify_content_absent(authorized, entry)
                .await
                .map_err(map_provider_error)?
                .then_some(())
                .ok_or(ArchiveDeletionError::OutcomeUnknown),
            Err(error) => Err(map_provider_error(error)),
        }
    }

    async fn delete_claim_reconcile(
        &self,
        authorized: &AuthorizedDeletionInventory<'_>,
        entry: &DeletionEntryCapability<'_>,
    ) -> Result<()> {
        match self
            .provider
            .delete_claim_all_generations(authorized, entry)
            .await
        {
            Ok(_) => Ok(()),
            Err(ExactDeletionProviderError::OutcomeUnknown) => self
                .provider
                .verify_claim_absent(authorized, entry)
                .await
                .map_err(map_provider_error)?
                .then_some(())
                .ok_or(ArchiveDeletionError::OutcomeUnknown),
            Err(error) => Err(map_provider_error(error)),
        }
    }
}

fn advance(
    witness: &dyn Witness,
    session: &DeletionSession,
    next: DeletionState,
    credential: &DeletionWorkerCredential,
    proof: &DeletionStageProof,
) -> Result<WitnessRecord> {
    witness
        .advance_deletion(
            DeletionAdvance::new(
                session.authorization,
                session.record.root(),
                session.record.registry(),
            ),
            next,
            credential,
            proof,
        )
        .map(|receipt| receipt.record().clone())
        .map_err(map_witness_error)
}

fn fresh_execution_context(
    witness: &dyn Witness,
    session: &DeletionSession,
    credential: &DeletionWorkerCredential,
    inventory: &CompleteDeletionInventory,
) -> Result<DeletionExecutionContext> {
    let recovery = witness
        .resume_deletion(session.record.archive_id(), credential)
        .map_err(map_witness_error)?;
    if recovery.receipt().record() != &session.record
        || recovery.authorization() != session.authorization
    {
        return Err(ArchiveDeletionError::StaleSession);
    }
    let binding = recovery.execution_binding().map_err(map_witness_error)?;
    Ok(DeletionExecutionContext {
        binding,
        inventory_commitment: inventory.commitment,
    })
}

fn map_witness_error(_error: WitnessError) -> ArchiveDeletionError {
    ArchiveDeletionError::Witness
}

fn map_provider_error(error: ExactDeletionProviderError) -> ArchiveDeletionError {
    match error {
        ExactDeletionProviderError::Unavailable => ArchiveDeletionError::Unavailable,
        ExactDeletionProviderError::OutcomeUnknown => ArchiveDeletionError::OutcomeUnknown,
        ExactDeletionProviderError::Mismatch => ArchiveDeletionError::ProviderMismatch,
        ExactDeletionProviderError::DrainPending => ArchiveDeletionError::ProviderDrainPending,
    }
}

fn root_key(archive_id: ArchiveId, root: RootCommitment) -> Result<ObjectKey> {
    let parent = root.parent().map(|parent| ParentReference {
        object_id: parent.object_id(),
        envelope_hash: parent.ciphertext_hash(),
    });
    ObjectContext::new(
        archive_id,
        root.database_epoch(),
        root.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root {
            root_seq: root.root().sequence(),
        },
        root.root().object_id(),
        parent,
    )
    .map(|context| context.object_key())
    .map_err(|_| ArchiveDeletionError::InvalidInventory)
}

fn root_reference_key(
    archive_id: ArchiveId,
    database_epoch: crate::archive_v3::DatabaseEpoch,
    key_epoch: crate::archive_v3::KeyEpoch,
    root: crate::archive_v3_witness::RootReference,
) -> Result<ObjectKey> {
    ObjectContext::new(
        archive_id,
        database_epoch,
        key_epoch,
        ObjectRole::RootV3,
        LogicalLocation::Root {
            root_seq: root.sequence(),
        },
        root.object_id(),
        None,
    )
    .map(|context| context.object_key())
    .map_err(|_| ArchiveDeletionError::InvalidInventory)
}

fn registry_key(archive_id: ArchiveId, registry: KeyRegistryReference) -> ObjectKey {
    KeyRegistryContext::with_rotation_generation(
        archive_id,
        KeyKind::Archive,
        registry.key_epoch(),
        registry.rotation_generation(),
    )
    .object_key(registry.object_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3::{DatabaseEpoch, KeyEpoch, ObjectId};
    use crate::archive_v3_gcs::{
        GcsArchiveV3ClaimResult, GcsArchiveV3CreateResult, GcsArchiveV3Page,
    };
    use crate::archive_v3_lifecycle::{DurableInventoryPage, InventoryPage};
    use crate::archive_v3_witness::{deletion_driver_test_fixture, Witness};
    use std::sync::Mutex;

    fn context() -> AuthenticatedDeletionContext {
        let archive = ArchiveId::from_bytes([1; 16]);
        let database = DatabaseEpoch::from_bytes([2; 16]);
        let epoch = KeyEpoch::from_bytes([3; 16]);
        let root = RootCommitment::genesis(
            database,
            epoch,
            crate::archive_v3_witness::RootReference::new(
                0,
                ObjectId::from_bytes([4; 16]),
                [5; 32],
            ),
        );
        let registry = KeyRegistryReference::new(epoch, 0, ObjectId::from_bytes([6; 16]), [7; 32]);
        AuthenticatedDeletionContext {
            archive_id: archive,
            root,
            registry,
            predecessor_root: None,
            predecessor_registry: None,
        }
    }

    fn key(context: &AuthenticatedDeletionContext, id: u8) -> ObjectKey {
        ObjectContext::new(
            context.archive_id,
            context.root.database_epoch(),
            context.root.key_epoch(),
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: u64::from(id),
                byte_len: 4096,
            },
            ObjectId::from_bytes([id; 16]),
            None,
        )
        .unwrap()
        .object_key()
    }

    fn deletion_seal(context: &AuthenticatedDeletionContext) -> DeletionInventorySeal {
        let entries = test_inventory_objects(context, key(context, 8));
        let page = InventoryPage::build(context.archive_id, 0, [0; 32], entries).unwrap();
        let encoded = page.encoded().to_vec();
        let durable = DurableInventoryPage::from_exact_readback(page, &encoded).unwrap();
        DeletionInventorySeal::for_test(
            context.archive_id,
            ObjectId::from_bytes([91; 16]),
            1,
            &[durable],
        )
        .unwrap()
    }

    fn foreign_deletion_seal(archive_id: ArchiveId) -> DeletionInventorySeal {
        let mut foreign = context();
        foreign.archive_id = archive_id;
        deletion_seal(&foreign)
    }

    fn historical_registry_keys(context: &AuthenticatedDeletionContext) -> [ObjectKey; 2] {
        [
            KeyRegistryContext::with_rotation_generation(
                context.archive_id,
                KeyKind::Archive,
                KeyEpoch::from_bytes([60; 16]),
                7,
            )
            .object_key(ObjectId::from_bytes([62; 16])),
            KeyRegistryContext::with_rotation_generation(
                context.archive_id,
                KeyKind::Archive,
                KeyEpoch::from_bytes([61; 16]),
                8,
            )
            .object_key(ObjectId::from_bytes([63; 16])),
        ]
    }

    fn wal_inventory_keys(context: &AuthenticatedDeletionContext) -> [(ObjectKey, ObjectRole); 2] {
        [
            (
                ObjectContext::new(
                    context.archive_id,
                    context.root.database_epoch(),
                    context.root.key_epoch(),
                    ObjectRole::WalSegmentV3,
                    LogicalLocation::Wal {
                        root_seq: 1,
                        wal_generation: 1,
                        segment_index: 0,
                    },
                    ObjectId::from_bytes([70; 16]),
                    None,
                )
                .unwrap()
                .object_key(),
                ObjectRole::WalSegmentV3,
            ),
            (
                ObjectContext::new(
                    context.archive_id,
                    context.root.database_epoch(),
                    context.root.key_epoch(),
                    ObjectRole::WalCommitDescriptorV3,
                    LogicalLocation::WalCommitDescriptor { root_seq: 1 },
                    ObjectId::from_bytes([71; 16]),
                    None,
                )
                .unwrap()
                .object_key(),
                ObjectRole::WalCommitDescriptorV3,
            ),
        ]
    }

    fn test_inventory_objects(
        context: &AuthenticatedDeletionContext,
        extent: ObjectKey,
    ) -> Vec<LifecycleInventoryObject> {
        let mut objects = vec![
            LifecycleInventoryObject::for_archive(
                context.archive_id,
                root_key(context.archive_id, context.root).unwrap(),
                ObjectRole::RootV3,
                context.root.root().ciphertext_hash(),
            )
            .unwrap(),
            LifecycleInventoryObject::for_archive(
                context.archive_id,
                registry_key(context.archive_id, context.registry),
                ObjectRole::KeyRegistryV3,
                context.registry.ciphertext_hash(),
            )
            .unwrap(),
            LifecycleInventoryObject::for_archive(
                context.archive_id,
                extent,
                ObjectRole::ExtentV3,
                [80; 32],
            )
            .unwrap(),
        ];
        if let Some(parent) = context.root.parent() {
            objects.push(
                LifecycleInventoryObject::for_archive(
                    context.archive_id,
                    root_reference_key(
                        context.archive_id,
                        context.root.database_epoch(),
                        context.root.key_epoch(),
                        parent,
                    )
                    .unwrap(),
                    ObjectRole::RootV3,
                    parent.ciphertext_hash(),
                )
                .unwrap(),
            );
        }
        for (index, registry) in historical_registry_keys(context).into_iter().enumerate() {
            objects.push(
                LifecycleInventoryObject::for_archive(
                    context.archive_id,
                    registry,
                    ObjectRole::KeyRegistryV3,
                    [60 + u8::try_from(index).unwrap(); 32],
                )
                .unwrap(),
            );
        }
        for (index, (key, role)) in wal_inventory_keys(context).into_iter().enumerate() {
            objects.push(
                LifecycleInventoryObject::for_archive(
                    context.archive_id,
                    key,
                    role,
                    [70 + u8::try_from(index).unwrap(); 32],
                )
                .unwrap(),
            );
        }
        objects.sort();
        objects
    }

    struct FakeMetadata {
        key: ObjectKey,
        calls: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl SealedArchiveInventoryLedger for FakeMetadata {
        async fn load_exact(
            &self,
            context: &AuthenticatedDeletionContext,
            seal: &DeletionInventorySeal,
        ) -> Result<CompleteDeletionInventory> {
            *self.calls.lock().unwrap() += 1;
            CompleteDeletionInventory::for_test(
                seal,
                test_inventory_objects(context, self.key.clone()),
            )
        }
    }

    #[derive(Clone, Copy)]
    enum LostResponse {
        None,
        Absent,
        Present,
        Mismatch,
        UnavailableOnce,
        UnavailableAfterOne,
    }

    struct FakeProvider {
        lost: Mutex<LostResponse>,
        content_calls: Mutex<usize>,
        claim_calls: Mutex<usize>,
        verify_content_calls: Mutex<usize>,
        verify_claim_calls: Mutex<usize>,
        drain_calls: Mutex<usize>,
        drain: Mutex<bool>,
        content_ids: Mutex<Vec<ObjectId>>,
        constructor_calls: Mutex<usize>,
    }

    impl FakeProvider {
        fn new(lost: LostResponse) -> Self {
            Self {
                lost: Mutex::new(lost),
                content_calls: Mutex::new(0),
                claim_calls: Mutex::new(0),
                verify_content_calls: Mutex::new(0),
                verify_claim_calls: Mutex::new(0),
                drain_calls: Mutex::new(0),
                drain: Mutex::new(true),
                content_ids: Mutex::new(Vec::new()),
                constructor_calls: Mutex::new(0),
            }
        }
    }

    struct CountingGcsTransport {
        calls: Mutex<usize>,
    }

    impl CountingGcsTransport {
        fn new() -> Self {
            Self {
                calls: Mutex::new(0),
            }
        }

        fn called(&self) {
            *self.calls.lock().unwrap() += 1;
        }
    }

    #[async_trait::async_trait]
    impl ArchiveV3GcsTransport for CountingGcsTransport {
        async fn claim_object_id(
            &self,
            _canonical_archive_prefix: &str,
            _object_id: ObjectId,
            _canonical_key: &str,
            _ciphertext_hash: [u8; 32],
        ) -> std::result::Result<GcsArchiveV3ClaimResult, GcsArchiveV3TransportError> {
            self.called();
            Ok(GcsArchiveV3ClaimResult::Reserved)
        }

        async fn mark_object_id_materialized(
            &self,
            _canonical_archive_prefix: &str,
            _object_id: ObjectId,
            _canonical_key: &str,
            _ciphertext_hash: [u8; 32],
        ) -> std::result::Result<(), GcsArchiveV3TransportError> {
            self.called();
            Ok(())
        }

        async fn create_if_absent(
            &self,
            _canonical_key: &str,
            _bytes: &[u8],
        ) -> std::result::Result<GcsArchiveV3CreateResult, GcsArchiveV3TransportError> {
            self.called();
            Ok(GcsArchiveV3CreateResult::Created)
        }

        async fn read_exact(
            &self,
            _canonical_key: &str,
            _max_bytes: usize,
        ) -> std::result::Result<Option<Vec<u8>>, GcsArchiveV3TransportError> {
            self.called();
            Ok(None)
        }

        async fn list_after(
            &self,
            _canonical_prefix: &str,
            _after: Option<&str>,
            _limit: usize,
        ) -> std::result::Result<GcsArchiveV3Page, GcsArchiveV3TransportError> {
            self.called();
            Ok(GcsArchiveV3Page { names: Vec::new() })
        }

        async fn delete_all_generations_exact(
            &self,
            _canonical_key: &str,
        ) -> std::result::Result<GcsArchiveV3DeleteResult, GcsArchiveV3TransportError> {
            self.called();
            Ok(GcsArchiveV3DeleteResult::DeletedAllGenerations)
        }

        async fn verify_all_generations_absent_exact(
            &self,
            _canonical_key: &str,
        ) -> std::result::Result<bool, GcsArchiveV3TransportError> {
            self.called();
            Ok(true)
        }

        async fn delete_claim_all_generations_exact(
            &self,
            _canonical_archive_prefix: &str,
            _object_id: ObjectId,
        ) -> std::result::Result<GcsArchiveV3DeleteResult, GcsArchiveV3TransportError> {
            self.called();
            Ok(GcsArchiveV3DeleteResult::DeletedAllGenerations)
        }

        async fn verify_claim_all_generations_absent_exact(
            &self,
            _canonical_archive_prefix: &str,
            _object_id: ObjectId,
        ) -> std::result::Result<bool, GcsArchiveV3TransportError> {
            self.called();
            Ok(true)
        }
    }

    #[async_trait::async_trait]
    impl ArchiveV3ExactDeletionProvider for FakeProvider {
        async fn delete_content_all_generations(
            &self,
            _authorized: &AuthorizedDeletionInventory<'_>,
            entry: &DeletionEntryCapability<'_>,
        ) -> std::result::Result<ExactDeleteOutcome, ExactDeletionProviderError> {
            let content_call = {
                let mut calls = self.content_calls.lock().unwrap();
                *calls += 1;
                *calls
            };
            self.content_ids.lock().unwrap().push(entry.key.object_id());
            let mut lost = self.lost.lock().unwrap();
            match *lost {
                LostResponse::None => Ok(ExactDeleteOutcome::DeletedAllGenerations),
                LostResponse::Absent | LostResponse::Present | LostResponse::Mismatch => {
                    Err(ExactDeletionProviderError::OutcomeUnknown)
                }
                LostResponse::UnavailableOnce => {
                    *lost = LostResponse::None;
                    Err(ExactDeletionProviderError::Unavailable)
                }
                LostResponse::UnavailableAfterOne => {
                    if content_call == 2 {
                        // The first registry-role object was deleted and its
                        // exact absence verified. Fail the second exact name,
                        // then allow a restarted Tombstoned worker to retry it.
                        *lost = LostResponse::None;
                        Err(ExactDeletionProviderError::Unavailable)
                    } else {
                        Ok(ExactDeleteOutcome::DeletedAllGenerations)
                    }
                }
            }
        }

        async fn verify_content_absent(
            &self,
            _authorized: &AuthorizedDeletionInventory<'_>,
            _entry: &DeletionEntryCapability<'_>,
        ) -> std::result::Result<bool, ExactDeletionProviderError> {
            *self.verify_content_calls.lock().unwrap() += 1;
            match *self.lost.lock().unwrap() {
                LostResponse::Absent => Ok(true),
                LostResponse::Present => Ok(false),
                LostResponse::Mismatch => Err(ExactDeletionProviderError::Mismatch),
                LostResponse::None => Ok(true),
                LostResponse::UnavailableOnce => Err(ExactDeletionProviderError::Unavailable),
                LostResponse::UnavailableAfterOne => Ok(true),
            }
        }

        async fn delete_claim_all_generations(
            &self,
            _authorized: &AuthorizedDeletionInventory<'_>,
            _entry: &DeletionEntryCapability<'_>,
        ) -> std::result::Result<ExactDeleteOutcome, ExactDeletionProviderError> {
            *self.claim_calls.lock().unwrap() += 1;
            Ok(ExactDeleteOutcome::DeletedAllGenerations)
        }

        async fn verify_claim_absent(
            &self,
            _authorized: &AuthorizedDeletionInventory<'_>,
            _entry: &DeletionEntryCapability<'_>,
        ) -> std::result::Result<bool, ExactDeletionProviderError> {
            *self.verify_claim_calls.lock().unwrap() += 1;
            Ok(true)
        }

        async fn verify_complete_inventory_drained(
            &self,
            authorized: &AuthorizedDeletionInventory<'_>,
            retention_assertion: &DeletionStageProof,
        ) -> std::result::Result<InventoryDrainProof, ExactDeletionProviderError> {
            *self.drain_calls.lock().unwrap() += 1;
            if !*self.drain.lock().unwrap() {
                return Err(ExactDeletionProviderError::DrainPending);
            }
            for index in 0..authorized.inventory.objects.len() {
                let entry = authorized.entry(index)?;
                if !self.verify_content_absent(authorized, &entry).await?
                    || !self.verify_claim_absent(authorized, &entry).await?
                {
                    return Err(ExactDeletionProviderError::DrainPending);
                }
            }
            let provider_drain_commitment = provider_drain_commitment(authorized);
            let retention_stage = retention_assertion
                .bind_inventory_drain(authorized.inventory.commitment, provider_drain_commitment)
                .map_err(|_| ExactDeletionProviderError::Mismatch)?;
            Ok(InventoryDrainProof {
                binding: authorized.execution.binding,
                inventory_commitment: authorized.inventory.commitment,
                provider_drain_commitment,
                retention_stage,
            })
        }
    }

    #[tokio::test]
    async fn exact_inventory_deletes_content_and_claims_and_restarts_safely() {
        let fixture = deletion_driver_test_fixture();
        let session = DeletionSession::from_tombstone(&fixture.tombstone).unwrap();
        let context = AuthenticatedDeletionContext::from_record(&session.record);
        let metadata = Arc::new(FakeMetadata {
            key: key(&context, 8),
            calls: Mutex::new(0),
        });
        let provider = Arc::new(FakeProvider::new(LostResponse::UnavailableAfterOne));
        let driver = ArchiveV3DeletionDriver::new(metadata.clone(), provider.clone());
        let seal = deletion_seal(&context);
        let proofs = DeletionStageProofs {
            key_erasure: &fixture.key_erasure,
            inventory: &fixture.inventory,
            retention_assertion: &fixture.retention,
        };
        assert_eq!(
            driver
                .run(
                    &fixture.witness,
                    session,
                    &fixture.credential,
                    proofs,
                    &seal,
                )
                .await,
            Err(ArchiveDeletionError::Unavailable)
        );
        let recovery = fixture
            .witness
            .resume_deletion(context.archive_id, &fixture.credential)
            .unwrap();
        let restarted = DeletionSession::from_recovery(&recovery).unwrap();
        assert_eq!(restarted.record.deletion(), DeletionState::Tombstoned);
        let completion = driver
            .run(
                &fixture.witness,
                restarted,
                &fixture.credential,
                DeletionStageProofs {
                    key_erasure: &fixture.key_erasure,
                    inventory: &fixture.inventory,
                    retention_assertion: &fixture.retention,
                },
                &seal,
            )
            .await
            .unwrap();
        assert_eq!(completion.seal().archive_id(), context.archive_id);
        // Current plus two historical registry epochs are all retried and
        // verified before roots/content. The first run deleted one registry
        // then failed on the next; restart safely repeats that exact name.
        // Five non-registry objects (current + predecessor roots, extent,
        // WAL segment, and WAL commit descriptor) follow the three registry
        // entries. One registry succeeds and the next fails on the first run;
        // restart repeats all three exact registry names before those five.
        assert_eq!(*provider.content_calls.lock().unwrap(), 10);
        assert_eq!(*provider.claim_calls.lock().unwrap(), 9);
        assert_eq!(*provider.verify_content_calls.lock().unwrap(), 12);
        assert_eq!(*provider.verify_claim_calls.lock().unwrap(), 12);
        let registry_ids = [
            context.registry.object_id(),
            ObjectId::from_bytes([62; 16]),
            ObjectId::from_bytes([63; 16]),
        ];
        let content_ids = provider.content_ids.lock().unwrap();
        assert!(content_ids[..5]
            .iter()
            .all(|object_id| registry_ids.contains(object_id)));
        assert!(content_ids[5..]
            .iter()
            .all(|object_id| !registry_ids.contains(object_id)));
        assert!(content_ids.contains(&ObjectId::from_bytes([70; 16])));
        assert!(content_ids.contains(&ObjectId::from_bytes([71; 16])));
        assert!(content_ids.contains(&context.root.parent().unwrap().object_id()));
        // Initial Tombstoned attempt plus Tombstoned, CryptoErased, and
        // LogicalObjectsAbsent restart stages each reload the same exact seal.
        assert_eq!(*metadata.calls.lock().unwrap(), 4);
    }

    #[tokio::test]
    async fn lost_delete_response_is_reconciled_only_by_exact_absence() {
        for (lost, expected_error) in [
            (LostResponse::Absent, None),
            (
                LostResponse::Present,
                Some(ArchiveDeletionError::OutcomeUnknown),
            ),
            (
                LostResponse::Mismatch,
                Some(ArchiveDeletionError::ProviderMismatch),
            ),
        ] {
            let fixture = deletion_driver_test_fixture();
            let session = DeletionSession::from_tombstone(&fixture.tombstone).unwrap();
            let context = AuthenticatedDeletionContext::from_record(&session.record);
            let metadata = Arc::new(FakeMetadata {
                key: key(&context, 8),
                calls: Mutex::new(0),
            });
            let provider = Arc::new(FakeProvider::new(lost));
            let driver = ArchiveV3DeletionDriver::new(metadata, provider);
            let result = driver
                .run(
                    &fixture.witness,
                    session,
                    &fixture.credential,
                    DeletionStageProofs {
                        key_erasure: &fixture.key_erasure,
                        inventory: &fixture.inventory,
                        retention_assertion: &fixture.retention,
                    },
                    &deletion_seal(&context),
                )
                .await;
            assert_eq!(result.err(), expected_error);
        }
    }

    #[tokio::test]
    async fn tombstone_precedes_all_deletes_and_drain_precedes_completion() {
        let fixture = deletion_driver_test_fixture();
        let session = DeletionSession::from_tombstone(&fixture.tombstone).unwrap();
        let context = AuthenticatedDeletionContext::from_record(&session.record);
        let metadata = Arc::new(FakeMetadata {
            key: key(&context, 8),
            calls: Mutex::new(0),
        });
        let provider = Arc::new(FakeProvider::new(LostResponse::None));
        let driver = ArchiveV3DeletionDriver::new(metadata, provider.clone());
        let seal = deletion_seal(&context);
        let first_completion = driver
            .run(
                &fixture.witness,
                session,
                &fixture.credential,
                DeletionStageProofs {
                    key_erasure: &fixture.key_erasure,
                    inventory: &fixture.inventory,
                    retention_assertion: &fixture.retention,
                },
                &seal,
            )
            .await
            .unwrap();
        assert_eq!(
            fixture
                .witness
                .read_current(context.archive_id)
                .unwrap()
                .unwrap()
                .deletion(),
            DeletionState::PhysicalComplete
        );
        assert_eq!(
            provider.content_ids.lock().unwrap().first().copied(),
            Some(context.registry.object_id())
        );
        let recovery = fixture
            .witness
            .resume_deletion(context.archive_id, &fixture.credential)
            .unwrap();
        let restarted_completion = driver
            .run(
                &fixture.witness,
                DeletionSession::from_recovery(&recovery).unwrap(),
                &fixture.credential,
                DeletionStageProofs {
                    key_erasure: &fixture.key_erasure,
                    inventory: &fixture.inventory,
                    retention_assertion: &fixture.retention,
                },
                &seal,
            )
            .await
            .unwrap();
        // A process that has lost the original receipt must re-verify the
        // retained PhysicalComplete evidence without hashing that evidence
        // recursively. Recovery mints the exact same seal/drain binding.
        assert_eq!(restarted_completion.seal(), first_completion.seal());
        assert_eq!(
            restarted_completion.provider_drain_commitment(),
            first_completion.provider_drain_commitment()
        );
        assert!(*provider.drain.lock().unwrap());
    }

    #[tokio::test]
    async fn soft_delete_or_provider_drain_residue_blocks_completion() {
        let fixture = deletion_driver_test_fixture();
        let session = DeletionSession::from_tombstone(&fixture.tombstone).unwrap();
        let context = AuthenticatedDeletionContext::from_record(&session.record);
        let metadata = Arc::new(FakeMetadata {
            key: key(&context, 8),
            calls: Mutex::new(0),
        });
        let provider = Arc::new(FakeProvider::new(LostResponse::None));
        *provider.drain.lock().unwrap() = false;
        let driver = ArchiveV3DeletionDriver::new(metadata, provider);
        assert_eq!(
            driver
                .run(
                    &fixture.witness,
                    session,
                    &fixture.credential,
                    DeletionStageProofs {
                        key_erasure: &fixture.key_erasure,
                        inventory: &fixture.inventory,
                        retention_assertion: &fixture.retention,
                    },
                    &deletion_seal(&context),
                )
                .await,
            Err(ArchiveDeletionError::ProviderDrainPending)
        );
        assert_eq!(
            fixture
                .witness
                .read_current(context.archive_id)
                .unwrap()
                .unwrap()
                .deletion(),
            DeletionState::LogicalObjectsAbsent
        );
    }

    #[tokio::test]
    async fn cross_archive_seal_is_rejected_before_metadata_or_provider_io() {
        let fixture = deletion_driver_test_fixture();
        let session = DeletionSession::from_tombstone(&fixture.tombstone).unwrap();
        let context = AuthenticatedDeletionContext::from_record(&session.record);
        let metadata = Arc::new(FakeMetadata {
            key: key(&context, 8),
            calls: Mutex::new(0),
        });
        let provider = Arc::new(FakeProvider::new(LostResponse::None));
        let driver = ArchiveV3DeletionDriver::new(metadata.clone(), provider.clone());
        assert!(driver
            .run(
                &fixture.witness,
                session,
                &fixture.credential,
                DeletionStageProofs {
                    key_erasure: &fixture.key_erasure,
                    inventory: &fixture.inventory,
                    retention_assertion: &fixture.retention,
                },
                &foreign_deletion_seal(ArchiveId::from_bytes([99; 16])),
            )
            .await
            .is_err());
        assert_eq!(*metadata.calls.lock().unwrap(), 0);
        assert_eq!(*provider.content_calls.lock().unwrap(), 0);
        assert_eq!(*provider.claim_calls.lock().unwrap(), 0);
        assert_eq!(*provider.drain_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn wrong_worker_cannot_reach_destructive_provider_calls() {
        let fixture = deletion_driver_test_fixture();
        let tombstone_record = fixture.tombstone.receipt().record();
        fixture
            .witness
            .advance_deletion(
                DeletionAdvance::new(
                    fixture.tombstone.authorization(),
                    tombstone_record.root(),
                    tombstone_record.registry(),
                ),
                DeletionState::CryptographicallyErased,
                &fixture.credential,
                &fixture
                    .key_erasure
                    .bind_inventory_only(
                        deletion_seal(&AuthenticatedDeletionContext::from_record(tombstone_record))
                            .inventory_commitment(),
                    )
                    .unwrap(),
            )
            .unwrap();
        let recovery = fixture
            .witness
            .resume_deletion(tombstone_record.archive_id(), &fixture.credential)
            .unwrap();
        let session = DeletionSession::from_recovery(&recovery).unwrap();
        let context = AuthenticatedDeletionContext::from_record(&session.record);
        let metadata = Arc::new(FakeMetadata {
            key: key(&context, 8),
            calls: Mutex::new(0),
        });
        let provider = Arc::new(FakeProvider::new(LostResponse::None));
        let driver = ArchiveV3DeletionDriver::new(metadata, provider.clone());
        assert_eq!(
            driver
                .run(
                    &fixture.witness,
                    session,
                    &fixture.wrong_credential,
                    DeletionStageProofs {
                        key_erasure: &fixture.key_erasure,
                        inventory: &fixture.inventory,
                        retention_assertion: &fixture.retention,
                    },
                    &deletion_seal(&context),
                )
                .await,
            Err(ArchiveDeletionError::Witness)
        );
        assert_eq!(*provider.content_calls.lock().unwrap(), 0);
        assert_eq!(*provider.claim_calls.lock().unwrap(), 0);
        assert_eq!(*provider.verify_content_calls.lock().unwrap(), 0);
        assert_eq!(*provider.verify_claim_calls.lock().unwrap(), 0);
        assert_eq!(*provider.drain_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn stale_record_and_fence_cannot_reach_destructive_provider_calls() {
        let fixture = deletion_driver_test_fixture();
        let tombstone_record = fixture.tombstone.receipt().record();
        let erased = fixture
            .witness
            .advance_deletion(
                DeletionAdvance::new(
                    fixture.tombstone.authorization(),
                    tombstone_record.root(),
                    tombstone_record.registry(),
                ),
                DeletionState::CryptographicallyErased,
                &fixture.credential,
                &fixture
                    .key_erasure
                    .bind_inventory_only(
                        deletion_seal(&AuthenticatedDeletionContext::from_record(tombstone_record))
                            .inventory_commitment(),
                    )
                    .unwrap(),
            )
            .unwrap();
        let recovery = fixture
            .witness
            .resume_deletion(tombstone_record.archive_id(), &fixture.credential)
            .unwrap();
        let stale_session = DeletionSession::from_recovery(&recovery).unwrap();
        fixture
            .witness
            .advance_deletion(
                DeletionAdvance::new(
                    fixture.tombstone.authorization(),
                    erased.record().root(),
                    erased.record().registry(),
                ),
                DeletionState::LogicalObjectsAbsent,
                &fixture.credential,
                &fixture.inventory,
            )
            .unwrap();
        let context = AuthenticatedDeletionContext::from_record(&stale_session.record);
        let metadata = Arc::new(FakeMetadata {
            key: key(&context, 8),
            calls: Mutex::new(0),
        });
        let provider = Arc::new(FakeProvider::new(LostResponse::None));
        let driver = ArchiveV3DeletionDriver::new(metadata, provider.clone());
        assert_eq!(
            driver
                .run(
                    &fixture.witness,
                    stale_session,
                    &fixture.credential,
                    DeletionStageProofs {
                        key_erasure: &fixture.key_erasure,
                        inventory: &fixture.inventory,
                        retention_assertion: &fixture.retention,
                    },
                    &deletion_seal(&context),
                )
                .await,
            Err(ArchiveDeletionError::StaleSession)
        );
        assert_eq!(*provider.content_calls.lock().unwrap(), 0);
        assert_eq!(*provider.claim_calls.lock().unwrap(), 0);
        assert_eq!(*provider.verify_content_calls.lock().unwrap(), 0);
        assert_eq!(*provider.verify_claim_calls.lock().unwrap(), 0);
        assert_eq!(*provider.drain_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn mismatched_deletion_fence_cannot_reach_destructive_provider_calls() {
        let fixture = deletion_driver_test_fixture();
        let tombstone_record = fixture.tombstone.receipt().record();
        fixture
            .witness
            .advance_deletion(
                DeletionAdvance::new(
                    fixture.tombstone.authorization(),
                    tombstone_record.root(),
                    tombstone_record.registry(),
                ),
                DeletionState::CryptographicallyErased,
                &fixture.credential,
                &fixture
                    .key_erasure
                    .bind_inventory_only(
                        deletion_seal(&AuthenticatedDeletionContext::from_record(tombstone_record))
                            .inventory_commitment(),
                    )
                    .unwrap(),
            )
            .unwrap();
        let recovery = fixture
            .witness
            .resume_deletion(tombstone_record.archive_id(), &fixture.credential)
            .unwrap();
        let mut session = DeletionSession::from_recovery(&recovery).unwrap();
        session.authorization = session.authorization.with_fencing_epoch_for_test(u64::MAX);
        let context = AuthenticatedDeletionContext::from_record(&session.record);
        let metadata = Arc::new(FakeMetadata {
            key: key(&context, 8),
            calls: Mutex::new(0),
        });
        let provider = Arc::new(FakeProvider::new(LostResponse::None));
        let driver = ArchiveV3DeletionDriver::new(metadata, provider.clone());
        assert_eq!(
            driver
                .run(
                    &fixture.witness,
                    session,
                    &fixture.credential,
                    DeletionStageProofs {
                        key_erasure: &fixture.key_erasure,
                        inventory: &fixture.inventory,
                        retention_assertion: &fixture.retention,
                    },
                    &deletion_seal(&context),
                )
                .await,
            Err(ArchiveDeletionError::StaleSession)
        );
        assert_eq!(*provider.content_calls.lock().unwrap(), 0);
        assert_eq!(*provider.claim_calls.lock().unwrap(), 0);
        assert_eq!(*provider.verify_content_calls.lock().unwrap(), 0);
        assert_eq!(*provider.verify_claim_calls.lock().unwrap(), 0);
        assert_eq!(*provider.drain_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn concrete_gcs_adapter_rejects_forged_entry_capabilities_before_transport() {
        let fixture = deletion_driver_test_fixture();
        let session = DeletionSession::from_tombstone(&fixture.tombstone).unwrap();
        let context = AuthenticatedDeletionContext::from_record(&session.record);
        let seal = deletion_seal(&context);
        let inventory = CompleteDeletionInventory::for_test(
            &seal,
            test_inventory_objects(&context, key(&context, 8)),
        )
        .unwrap();
        let execution =
            fresh_execution_context(&fixture.witness, &session, &fixture.credential, &inventory)
                .unwrap();
        let authorized = inventory.authorize(execution).unwrap();
        let valid = authorized.entry(0).unwrap();
        let transport = Arc::new(CountingGcsTransport::new());
        let provider = GcsArchiveV3DeletionProvider::new(transport.clone());

        let wrong_archive = valid.clone().with_binding_for_test(
            authorized
                .execution
                .binding
                .with_archive_id_for_test(ArchiveId::from_bytes([99; 16])),
        );
        assert_eq!(
            provider
                .delete_content_all_generations(&authorized, &wrong_archive)
                .await,
            Err(ExactDeletionProviderError::Mismatch)
        );

        let wrong_database = valid.clone().with_binding_for_test(
            authorized
                .execution
                .binding
                .with_database_epoch_for_test(DatabaseEpoch::from_bytes([98; 16])),
        );
        assert_eq!(
            provider
                .verify_content_absent(&authorized, &wrong_database)
                .await,
            Err(ExactDeletionProviderError::Mismatch)
        );

        let wrong_fence = valid.clone().with_binding_for_test(
            authorized
                .execution
                .binding
                .with_fencing_epoch_for_test(u64::MAX),
        );
        assert_eq!(
            provider
                .verify_content_absent(&authorized, &wrong_fence)
                .await,
            Err(ExactDeletionProviderError::Mismatch)
        );

        let wrong_worker = valid.clone().with_binding_for_test(
            authorized
                .execution
                .binding
                .with_worker_for_test(ObjectId::from_bytes([90; 16])),
        );
        assert_eq!(
            provider
                .delete_claim_all_generations(&authorized, &wrong_worker)
                .await,
            Err(ExactDeletionProviderError::Mismatch)
        );

        let wrong_operation = valid.clone().with_binding_for_test(
            authorized
                .execution
                .binding
                .with_operation_for_test(ObjectId::from_bytes([91; 16])),
        );
        assert_eq!(
            provider
                .verify_claim_absent(&authorized, &wrong_operation)
                .await,
            Err(ExactDeletionProviderError::Mismatch)
        );

        let same_archive_outside_inventory = valid.with_key_for_test(key(&context, 99));
        assert_eq!(
            provider
                .delete_content_all_generations(&authorized, &same_archive_outside_inventory)
                .await,
            Err(ExactDeletionProviderError::Mismatch)
        );
        assert_eq!(
            provider
                .delete_claim_all_generations(&authorized, &same_archive_outside_inventory)
                .await,
            Err(ExactDeletionProviderError::Mismatch)
        );

        assert_eq!(*transport.calls.lock().unwrap(), 0);
    }

    #[test]
    fn constructor_performs_no_io() {
        let context = context();
        let metadata = Arc::new(FakeMetadata {
            key: key(&context, 8),
            calls: Mutex::new(0),
        });
        let provider = Arc::new(FakeProvider::new(LostResponse::None));
        let _driver = ArchiveV3DeletionDriver::new(metadata.clone(), provider.clone());
        assert_eq!(*metadata.calls.lock().unwrap(), 0);
        assert_eq!(*provider.content_calls.lock().unwrap(), 0);
        assert_eq!(*provider.claim_calls.lock().unwrap(), 0);
        assert_eq!(*provider.constructor_calls.lock().unwrap(), 0);
    }
}
