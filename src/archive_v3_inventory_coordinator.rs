#![allow(
    dead_code,
    reason = "inactive ADR-0022 authenticated inventory coordinator is compiled and fake-tested before runtime wiring"
)]

//! Inactive authenticated deletion-inventory coordinator for ADR-0022.
//!
//! This module joins three already separate authorities without constructing
//! any of them: exact-current deletion witness recovery, the encrypted control
//! lifecycle snapshot, and the exact-name encrypted page store. The normal
//! branch walks only witness-selected current/predecessor roots, unions every
//! settled create-ahead object, and returns only the control-minted
//! [`DeletionInventorySeal`]. A type-separated pre-witness branch consumes a
//! fresh exact-absence receipt into a create-ahead-only page seal and returns
//! no deletion authority. It has no Store, startup, environment/config, route,
//! provider construction, list operation, deletion-driver invocation, or
//! cloud/deployment wiring.

use crate::{
    archive_v3::{ArchiveId, ObjectId, VerifiedArchiveCipher},
    archive_v3_deletion::{
        ArchiveDeletionError, AuthenticatedDeletionContext, CompleteDeletionInventory,
        CompletePreWitnessDeletionInventory, SealedArchiveInventoryLedger,
    },
    archive_v3_firestore_witness::FirestoreWitness,
    archive_v3_lifecycle::{
        validate_pre_witness_sealed_page_references, validate_sealed_page_references,
        ArchiveLifecyclePageStore, DeletionInventorySeal, DurableInventoryPage,
        FrozenInventorySnapshot, FrozenPreWitnessInventorySnapshot, InventoryPage,
        InventoryPageReference, LifecycleError, LifecycleInventoryObject,
        PreWitnessDeletionInventorySeal, MAX_LIFECYCLE_ARTIFACTS, MAX_LIFECYCLE_OBJECT_KEY_BYTES,
        MAX_LIFECYCLE_PAGES,
    },
    archive_v3_lifecycle_page_store::RecoveredPageCreatePlan,
    archive_v3_reachability::{
        visit_witness_reachability, ExactReachabilityReader, ReachabilityError,
    },
    archive_v3_witness::{
        DeletionRecovery, DeletionWorkerCredential, InMemoryWitness, Witness, WitnessError,
    },
    archive_v3_witness_disposition::AuthenticatedPreWitnessAbsence,
};
use async_trait::async_trait;
use std::{collections::BTreeMap, fmt, sync::Arc};
use thiserror::Error;

const MAX_INVENTORY_KEY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum InventoryCoordinatorError {
    #[error("archive-v3 deletion witness snapshot is invalid or stale")]
    Witness,
    #[error("archive-v3 lifecycle snapshot or page state is invalid")]
    Lifecycle,
    #[error("archive-v3 authenticated reachability failed")]
    Reachability,
    #[error("archive-v3 inventory has a conflicting exact object identity")]
    DuplicateConflict,
    #[error("archive-v3 inventory exceeded a fixed combined bound")]
    Limit,
    #[error("archive-v3 inventory changed across a freshness boundary")]
    Freshness,
    /// The lifecycle control plane refused permanently. No retry can clear it,
    /// so the caller must park the operation for a human rather than report it
    /// as transient.
    #[error("archive-v3 lifecycle durable state permanently conflicts")]
    PermanentConflict,
}

impl From<LifecycleError> for InventoryCoordinatorError {
    fn from(error: LifecycleError) -> Self {
        match error {
            // Only the control plane's own permanent-conflict classification
            // is promoted here. Every other variant keeps its existing
            // retryable meaning, so a genuinely transient failure is never
            // parked.
            LifecycleError::Conflict => Self::PermanentConflict,
            _ => Self::Lifecycle,
        }
    }
}

impl From<WitnessError> for InventoryCoordinatorError {
    fn from(_: WitnessError) -> Self {
        Self::Witness
    }
}

impl From<ReachabilityError> for InventoryCoordinatorError {
    fn from(error: ReachabilityError) -> Self {
        match error {
            ReachabilityError::Limit => Self::Limit,
            _ => Self::Reachability,
        }
    }
}

/// Exact-current deletion-only witness boundary. A production implementation
/// reauthenticates the credential on every call; a retained recovery object is
/// never treated as fresh.
#[async_trait]
pub(crate) trait DeletionInventoryWitness: Send + Sync {
    async fn resume_exact_deletion(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> Result<DeletionRecovery, WitnessError>;
}

#[async_trait]
impl DeletionInventoryWitness for InMemoryWitness {
    async fn resume_exact_deletion(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> Result<DeletionRecovery, WitnessError> {
        self.resume_deletion(archive_id, credential)
    }
}

#[async_trait]
impl DeletionInventoryWitness for FirestoreWitness {
    async fn resume_exact_deletion(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> Result<DeletionRecovery, WitnessError> {
        self.resume_deletion_async(archive_id, credential).await
    }
}

/// Encrypted control authority required by the coordinator. Every receipt is
/// loaded or CAS-minted by the implementation; this interface has no factory
/// for reservations, snapshots, admissions, references, or seals.
#[async_trait]
pub(crate) trait DeletionInventoryControl: Send + Sync {
    async fn freeze_snapshot(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        deletion_fence: ObjectId,
    ) -> Result<FrozenInventorySnapshot, LifecycleError>;

    async fn load_snapshot(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<FrozenInventorySnapshot, LifecycleError>;

    async fn recover_page_plan(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<RecoveredPageCreatePlan, LifecycleError>;

    async fn seal_authenticated_pages(
        &self,
        plan: AuthenticatedInventoryPlan,
    ) -> Result<DeletionInventorySeal, LifecycleError>;

    async fn load_sealed_references(
        &self,
        seal: &DeletionInventorySeal,
    ) -> Result<Vec<InventoryPageReference>, LifecycleError>;
}

/// Opaque proof that the coordinator's exact canonical union plan and every
/// authenticated external readback are byte-for-byte identical. Only this
/// module can mint it; control cannot accept caller-selected durable pages.
pub(crate) struct AuthenticatedInventoryPlan {
    snapshot: FrozenInventorySnapshot,
    references: Vec<InventoryPageReference>,
    durable_pages: Vec<DurableInventoryPage>,
}

impl AuthenticatedInventoryPlan {
    fn from_exact_readbacks(
        snapshot: &FrozenInventorySnapshot,
        planned: &[InventoryPage],
        durable_pages: Vec<DurableInventoryPage>,
    ) -> Result<Self, InventoryCoordinatorError> {
        if planned.is_empty()
            || planned.len() != durable_pages.len()
            || planned
                .iter()
                .zip(&durable_pages)
                .any(|(expected, durable)| expected != durable.page())
        {
            return Err(InventoryCoordinatorError::Lifecycle);
        }
        let references = planned.iter().map(InventoryPage::reference).collect();
        Ok(Self {
            snapshot: snapshot.clone(),
            references,
            durable_pages,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        snapshot: &FrozenInventorySnapshot,
        planned: &[InventoryPage],
        durable_pages: Vec<DurableInventoryPage>,
    ) -> Result<Self, InventoryCoordinatorError> {
        Self::from_exact_readbacks(snapshot, planned, durable_pages)
    }

    pub(crate) const fn snapshot(&self) -> &FrozenInventorySnapshot {
        &self.snapshot
    }

    pub(crate) fn references(&self) -> &[InventoryPageReference] {
        &self.references
    }

    pub(crate) fn durable_pages(&self) -> &[DurableInventoryPage] {
        &self.durable_pages
    }
}

impl fmt::Debug for AuthenticatedInventoryPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedInventoryPlan(<opaque>)")
    }
}

/// Producer token accepted only by the deletion inventory constructor after
/// the complete external page chain has been authenticated against the exact
/// durable lifecycle seal.
pub(crate) struct AuthenticatedInventoryLoad(());

impl AuthenticatedInventoryLoad {
    fn validated() -> Self {
        Self(())
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self(())
    }
}

/// Restart state for the distinct pre-witness inventory branch. Encrypted
/// control returns a frozen snapshot until the atomic seal CAS succeeds, then
/// only the type-separated durable seal.
pub(crate) enum RecoveredPreWitnessInventory {
    Frozen(FrozenPreWitnessInventorySnapshot),
    Sealed(PreWitnessDeletionInventorySeal),
}

impl fmt::Debug for RecoveredPreWitnessInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frozen(_) => formatter.write_str("Frozen(<opaque>)"),
            Self::Sealed(_) => formatter.write_str("Sealed(<opaque>)"),
        }
    }
}

/// Encrypted control authority for the pre-witness branch. The initial freeze
/// consumes the fresh exact-absence proof. Restart loads only durable state by
/// opaque archive/fence; it never remints absence or rereads Firestore.
#[async_trait]
pub(crate) trait PreWitnessInventoryControl: Send + Sync {
    async fn freeze_pre_witness_snapshot(
        &self,
        absence: AuthenticatedPreWitnessAbsence,
    ) -> Result<FrozenPreWitnessInventorySnapshot, LifecycleError>;

    async fn recover_pre_witness_inventory(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<RecoveredPreWitnessInventory, LifecycleError>;

    async fn recover_pre_witness_page_plan(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<RecoveredPageCreatePlan, LifecycleError>;

    async fn seal_authenticated_pre_witness_pages(
        &self,
        plan: AuthenticatedPreWitnessInventoryPlan,
    ) -> Result<PreWitnessDeletionInventorySeal, LifecycleError>;

    async fn load_pre_witness_sealed_references(
        &self,
        seal: &PreWitnessDeletionInventorySeal,
    ) -> Result<Vec<InventoryPageReference>, LifecycleError>;
}

/// Coordinator-only one-shot proof that the deterministic create-ahead page
/// plan and every external readback are exact. The frozen snapshot is consumed
/// into this value and cannot be reused for a competing seal.
pub(crate) struct AuthenticatedPreWitnessInventoryPlan {
    snapshot: FrozenPreWitnessInventorySnapshot,
    planned_pages: Vec<InventoryPage>,
    references: Vec<InventoryPageReference>,
    durable_pages: Vec<DurableInventoryPage>,
}

impl AuthenticatedPreWitnessInventoryPlan {
    fn from_exact_readbacks(
        snapshot: FrozenPreWitnessInventorySnapshot,
        planned_pages: Vec<InventoryPage>,
        durable_pages: Vec<DurableInventoryPage>,
    ) -> Result<Self, InventoryCoordinatorError> {
        if planned_pages.len() != durable_pages.len()
            || planned_pages
                .iter()
                .zip(&durable_pages)
                .any(|(expected, durable)| expected != durable.page())
        {
            return Err(InventoryCoordinatorError::Lifecycle);
        }
        let references = planned_pages.iter().map(InventoryPage::reference).collect();
        Ok(Self {
            snapshot,
            planned_pages,
            references,
            durable_pages,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        snapshot: FrozenPreWitnessInventorySnapshot,
        planned_pages: Vec<InventoryPage>,
        durable_pages: Vec<DurableInventoryPage>,
    ) -> Result<Self, InventoryCoordinatorError> {
        Self::from_exact_readbacks(snapshot, planned_pages, durable_pages)
    }

    pub(crate) const fn snapshot(&self) -> &FrozenPreWitnessInventorySnapshot {
        &self.snapshot
    }

    pub(crate) fn planned_pages(&self) -> &[InventoryPage] {
        &self.planned_pages
    }

    pub(crate) fn references(&self) -> &[InventoryPageReference] {
        &self.references
    }

    pub(crate) fn durable_pages(&self) -> &[DurableInventoryPage] {
        &self.durable_pages
    }
}

impl fmt::Debug for AuthenticatedPreWitnessInventoryPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPreWitnessInventoryPlan(<opaque>)")
    }
}

/// Producer token accepted only by the non-authorizing pre-witness complete
/// inventory constructor after the entire sealed page chain is authenticated.
pub(crate) struct AuthenticatedPreWitnessInventoryLoad(());

impl AuthenticatedPreWitnessInventoryLoad {
    fn validated() -> Self {
        Self(())
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self(())
    }
}

/// Authenticate reachability, union the frozen create-ahead snapshot, resume
/// an exact deterministic page plan, and atomically seal it in control.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn seal_deletion_inventory(
    archive_id: ArchiveId,
    expected_revision: u64,
    deletion_fence: ObjectId,
    credential: &DeletionWorkerCredential,
    reader: &dyn ExactReachabilityReader,
    current_cipher: &VerifiedArchiveCipher,
    predecessor_cipher: Option<&VerifiedArchiveCipher>,
    control: &dyn DeletionInventoryControl,
    witness: &dyn DeletionInventoryWitness,
    page_store: &dyn ArchiveLifecyclePageStore,
) -> Result<DeletionInventorySeal, InventoryCoordinatorError> {
    let (recovery, recovery_root, snapshot) = authorize_tombstoned_then_freeze(
        archive_id,
        expected_revision,
        deletion_fence,
        credential,
        control,
        witness,
    )
    .await?;

    // Freeze is itself a freshness boundary. Reauthenticate the exact witness
    // record before the graph walker performs its first external exact GET.
    let fresh_recovery = witness
        .resume_exact_deletion(archive_id, credential)
        .await?;
    let _ = fresh_recovery.tombstoned_recovery_root()?;
    if fresh_recovery != recovery {
        return Err(InventoryCoordinatorError::Freshness);
    }
    let visit =
        visit_witness_reachability(&recovery_root, reader, current_cipher, predecessor_cipher)
            .await?;

    let objects = canonical_union(archive_id, &snapshot, visit.objects())?;
    let pages = canonical_page_plan(archive_id, objects)?;

    persist_and_seal_plan(
        archive_id,
        deletion_fence,
        credential,
        &snapshot,
        &recovery,
        &pages,
        control,
        witness,
        page_store,
    )
    .await
}

async fn authorize_tombstoned_then_freeze(
    archive_id: ArchiveId,
    expected_revision: u64,
    deletion_fence: ObjectId,
    credential: &DeletionWorkerCredential,
    control: &dyn DeletionInventoryControl,
    witness: &dyn DeletionInventoryWitness,
) -> Result<
    (
        DeletionRecovery,
        crate::archive_v3_witness::RecoveryRoot,
        FrozenInventorySnapshot,
    ),
    InventoryCoordinatorError,
> {
    // Credential authentication and exact Tombstoned state precede the first
    // control mutation. Invalid deletion authority therefore has zero effect.
    let recovery = witness
        .resume_exact_deletion(archive_id, credential)
        .await?;
    let recovery_root = recovery.tombstoned_recovery_root()?;
    let snapshot = control
        .freeze_snapshot(archive_id, expected_revision, deletion_fence)
        .await?;
    validate_snapshot_binding(&snapshot, archive_id, deletion_fence)?;
    Ok((recovery, recovery_root, snapshot))
}

#[allow(clippy::too_many_arguments)]
async fn persist_and_seal_plan(
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    credential: &DeletionWorkerCredential,
    snapshot: &FrozenInventorySnapshot,
    recovery: &DeletionRecovery,
    pages: &[InventoryPage],
    control: &dyn DeletionInventoryControl,
    witness: &dyn DeletionInventoryWitness,
    page_store: &dyn ArchiveLifecyclePageStore,
) -> Result<DeletionInventorySeal, InventoryCoordinatorError> {
    // The complete witness and control snapshots are reread immediately before
    // the first page operation. This closes graph-walk races without letting a
    // retained witness/control value authorize external I/O.
    revalidate_fresh(
        archive_id,
        deletion_fence,
        credential,
        snapshot,
        recovery,
        control,
        witness,
    )
    .await?;

    let recovered = control
        .recover_page_plan(archive_id, deletion_fence)
        .await?;
    validate_recovered_plan(pages, &recovered)?;
    let mut durable = Vec::with_capacity(pages.len());
    for reference in recovered.created() {
        durable.push(
            page_store
                .read_exact_page(deletion_fence, *reference)
                .await?,
        );
    }
    let mut next = recovered.created().len();
    if recovered.outcome_unknown().is_some() {
        durable.push(
            page_store
                .create_exact_page(deletion_fence, &pages[next])
                .await?,
        );
        next += 1;
    }
    for page in &pages[next..] {
        durable.push(page_store.create_exact_page(deletion_fence, page).await?);
    }

    revalidate_fresh(
        archive_id,
        deletion_fence,
        credential,
        snapshot,
        recovery,
        control,
        witness,
    )
    .await?;
    let plan = AuthenticatedInventoryPlan::from_exact_readbacks(snapshot, pages, durable)?;
    control
        .seal_authenticated_pages(plan)
        .await
        .map_err(Into::into)
}

fn validate_snapshot_binding(
    snapshot: &FrozenInventorySnapshot,
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
) -> Result<(), InventoryCoordinatorError> {
    if snapshot.archive_id() != archive_id
        || snapshot.deletion_fence() != deletion_fence
        || snapshot.revision() == 0
    {
        return Err(InventoryCoordinatorError::Freshness);
    }
    Ok(())
}

async fn revalidate_fresh(
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    credential: &DeletionWorkerCredential,
    expected_snapshot: &FrozenInventorySnapshot,
    expected_recovery: &DeletionRecovery,
    control: &dyn DeletionInventoryControl,
    witness: &dyn DeletionInventoryWitness,
) -> Result<(), InventoryCoordinatorError> {
    let fresh_recovery = witness
        .resume_exact_deletion(archive_id, credential)
        .await?;
    let _ = fresh_recovery.tombstoned_recovery_root()?;
    let fresh_snapshot = control.load_snapshot(archive_id, deletion_fence).await?;
    if &fresh_recovery != expected_recovery || &fresh_snapshot != expected_snapshot {
        return Err(InventoryCoordinatorError::Freshness);
    }
    Ok(())
}

fn canonical_union(
    archive_id: ArchiveId,
    snapshot: &FrozenInventorySnapshot,
    reachable: &[crate::archive_v3_reachability::ReachableObject],
) -> Result<Vec<LifecycleInventoryObject>, InventoryCoordinatorError> {
    let mut by_id = BTreeMap::new();
    for reached in reachable {
        insert_object(
            &mut by_id,
            LifecycleInventoryObject::for_archive(
                archive_id,
                reached.key().clone(),
                reached.role(),
                reached.ciphertext_hash(),
            )?,
        )?;
    }
    for planned in snapshot.create_ahead() {
        insert_object(&mut by_id, planned.inventory_object()?)?;
    }
    // Every frozen create-ahead row that is not a genesis bootstrap artifact:
    // unconsumed WAL publication/checkpoint artifacts, and the durably staged
    // genesis objects a pre-boundary crash leaves behind. Without this union a
    // crashed attempt's uploaded object is unreachable from every root, never
    // enters the sealed inventory, and survives erasure with no disclosure.
    for object in snapshot.widened() {
        insert_object(&mut by_id, object.clone())?;
    }
    let mut objects = by_id.into_values().collect::<Vec<_>>();
    objects.sort();
    let key_bytes = objects.iter().try_fold(0usize, |total, object| {
        total
            .checked_add(object.key().as_str().len())
            .ok_or(InventoryCoordinatorError::Limit)
    })?;
    validate_combined_bounds(objects.len(), key_bytes)?;
    if objects
        .iter()
        .any(|object| object.key().as_str().len() > MAX_LIFECYCLE_OBJECT_KEY_BYTES)
    {
        return Err(InventoryCoordinatorError::Limit);
    }
    Ok(objects)
}

fn validate_combined_bounds(
    object_count: usize,
    key_bytes: usize,
) -> Result<(), InventoryCoordinatorError> {
    if object_count == 0
        || object_count > MAX_LIFECYCLE_ARTIFACTS
        || key_bytes > MAX_INVENTORY_KEY_BYTES
    {
        return Err(InventoryCoordinatorError::Limit);
    }
    Ok(())
}

fn insert_object(
    objects: &mut BTreeMap<ObjectId, LifecycleInventoryObject>,
    object: LifecycleInventoryObject,
) -> Result<(), InventoryCoordinatorError> {
    match objects.get(&object.key().object_id()) {
        Some(existing) if existing == &object => Ok(()),
        Some(_) => Err(InventoryCoordinatorError::DuplicateConflict),
        None => {
            objects.insert(object.key().object_id(), object);
            Ok(())
        }
    }
}

/// Deterministic canonical paging of a sorted, deduplicated object set. Also
/// used by the encrypted control store to rebuild (and hash-verify) sealed
/// pages whose entries are exactly the retained create-ahead artifacts.
pub(crate) fn canonical_page_plan(
    archive_id: ArchiveId,
    objects: Vec<LifecycleInventoryObject>,
) -> Result<Vec<InventoryPage>, InventoryCoordinatorError> {
    let mut pages = Vec::new();
    let mut current = Vec::new();
    let mut previous_hash = [0; 32];
    for object in objects {
        let ordinal = u32::try_from(pages.len()).map_err(|_| InventoryCoordinatorError::Limit)?;
        if current.len() == crate::archive_v3_lifecycle::MAX_LIFECYCLE_PAGE_ENTRIES {
            let page = InventoryPage::build(archive_id, ordinal, previous_hash, current)?;
            previous_hash = page.page_hash();
            pages.push(page);
            if pages.len() >= MAX_LIFECYCLE_PAGES {
                return Err(InventoryCoordinatorError::Limit);
            }
            current = vec![object];
            let next_ordinal =
                u32::try_from(pages.len()).map_err(|_| InventoryCoordinatorError::Limit)?;
            InventoryPage::build(archive_id, next_ordinal, previous_hash, current.clone())?;
            continue;
        }
        let mut candidate = current.clone();
        candidate.push(object.clone());
        match InventoryPage::build(archive_id, ordinal, previous_hash, candidate) {
            Ok(_) => current.push(object),
            Err(LifecycleError::Limit) if !current.is_empty() => {
                let page = InventoryPage::build(archive_id, ordinal, previous_hash, current)?;
                previous_hash = page.page_hash();
                pages.push(page);
                if pages.len() >= MAX_LIFECYCLE_PAGES {
                    return Err(InventoryCoordinatorError::Limit);
                }
                current = vec![object];
                let next_ordinal =
                    u32::try_from(pages.len()).map_err(|_| InventoryCoordinatorError::Limit)?;
                InventoryPage::build(archive_id, next_ordinal, previous_hash, current.clone())?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    if current.is_empty() {
        return Err(InventoryCoordinatorError::Limit);
    }
    let ordinal = u32::try_from(pages.len()).map_err(|_| InventoryCoordinatorError::Limit)?;
    pages.push(InventoryPage::build(
        archive_id,
        ordinal,
        previous_hash,
        current,
    )?);
    if pages.len() > MAX_LIFECYCLE_PAGES {
        return Err(InventoryCoordinatorError::Limit);
    }
    Ok(pages)
}

fn validate_recovered_plan(
    pages: &[InventoryPage],
    recovered: &RecoveredPageCreatePlan,
) -> Result<(), InventoryCoordinatorError> {
    let recovered_len = recovered.created().len()
        + if recovered.outcome_unknown().is_some() {
            1
        } else {
            0
        };
    if recovered_len > pages.len() {
        return Err(InventoryCoordinatorError::Lifecycle);
    }
    for (index, reference) in recovered.created().iter().enumerate() {
        if pages[index].reference() != *reference {
            return Err(InventoryCoordinatorError::Lifecycle);
        }
    }
    if let Some(unresolved) = recovered.outcome_unknown() {
        if &pages[recovered.created().len()] != unresolved {
            return Err(InventoryCoordinatorError::Lifecycle);
        }
    }
    Ok(())
}

/// Consume one freshly authenticated exact-absence receipt, durably freeze
/// the create-ahead-only branch, and seal its deterministic page plan. This
/// path performs no reachability or archive metadata read.
pub(crate) async fn seal_pre_witness_deletion_inventory(
    absence: AuthenticatedPreWitnessAbsence,
    control: &dyn PreWitnessInventoryControl,
    page_store: &dyn ArchiveLifecyclePageStore,
) -> Result<PreWitnessDeletionInventorySeal, InventoryCoordinatorError> {
    let snapshot = control.freeze_pre_witness_snapshot(absence).await?;
    persist_and_seal_pre_witness_snapshot(snapshot, control, page_store).await
}

/// Resume only after encrypted control already durably owns the pre-witness
/// snapshot. No witness reader or absence-remint boundary is accepted here.
pub(crate) async fn resume_pre_witness_deletion_inventory(
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    control: &dyn PreWitnessInventoryControl,
    page_store: &dyn ArchiveLifecyclePageStore,
) -> Result<PreWitnessDeletionInventorySeal, InventoryCoordinatorError> {
    match control
        .recover_pre_witness_inventory(archive_id, deletion_fence)
        .await?
    {
        RecoveredPreWitnessInventory::Frozen(snapshot) => {
            persist_and_seal_pre_witness_snapshot(snapshot, control, page_store).await
        }
        RecoveredPreWitnessInventory::Sealed(seal) => Ok(seal),
    }
}

async fn persist_and_seal_pre_witness_snapshot(
    snapshot: FrozenPreWitnessInventorySnapshot,
    control: &dyn PreWitnessInventoryControl,
    page_store: &dyn ArchiveLifecyclePageStore,
) -> Result<PreWitnessDeletionInventorySeal, InventoryCoordinatorError> {
    let pages = pre_witness_page_plan_for_snapshot(&snapshot)?;
    revalidate_pre_witness_snapshot(&snapshot, control).await?;
    let recovered = control
        .recover_pre_witness_page_plan(snapshot.archive_id(), snapshot.deletion_fence())
        .await?;
    validate_recovered_plan(&pages, &recovered)?;

    let mut durable = Vec::with_capacity(pages.len());
    for reference in recovered.created() {
        durable.push(
            page_store
                .read_exact_page(snapshot.deletion_fence(), *reference)
                .await?,
        );
    }
    let mut next = recovered.created().len();
    if recovered.outcome_unknown().is_some() {
        durable.push(
            page_store
                .create_exact_page(snapshot.deletion_fence(), &pages[next])
                .await?,
        );
        next += 1;
    }
    for page in &pages[next..] {
        durable.push(
            page_store
                .create_exact_page(snapshot.deletion_fence(), page)
                .await?,
        );
    }

    revalidate_pre_witness_snapshot(&snapshot, control).await?;
    let proof =
        AuthenticatedPreWitnessInventoryPlan::from_exact_readbacks(snapshot, pages, durable)?;
    control
        .seal_authenticated_pre_witness_pages(proof)
        .await
        .map_err(Into::into)
}

async fn revalidate_pre_witness_snapshot(
    expected: &FrozenPreWitnessInventorySnapshot,
    control: &dyn PreWitnessInventoryControl,
) -> Result<(), InventoryCoordinatorError> {
    match control
        .recover_pre_witness_inventory(expected.archive_id(), expected.deletion_fence())
        .await?
    {
        RecoveredPreWitnessInventory::Frozen(current) if &current == expected => Ok(()),
        RecoveredPreWitnessInventory::Frozen(_) | RecoveredPreWitnessInventory::Sealed(_) => {
            Err(InventoryCoordinatorError::Freshness)
        }
    }
}

pub(crate) fn pre_witness_page_plan_for_snapshot(
    snapshot: &FrozenPreWitnessInventorySnapshot,
) -> Result<Vec<InventoryPage>, InventoryCoordinatorError> {
    let mut by_id = BTreeMap::<ObjectId, LifecycleInventoryObject>::new();
    for artifact in snapshot.create_ahead() {
        insert_object(&mut by_id, artifact.inventory_object()?)?;
    }
    let mut objects = by_id.into_values().collect::<Vec<_>>();
    objects.sort();
    let key_bytes = objects.iter().try_fold(0usize, |total, object| {
        total
            .checked_add(object.key().as_str().len())
            .ok_or(InventoryCoordinatorError::Limit)
    })?;
    pre_witness_bounds(objects.len(), key_bytes)?;
    if objects
        .iter()
        .any(|object| object.key().as_str().len() > MAX_LIFECYCLE_OBJECT_KEY_BYTES)
    {
        return Err(InventoryCoordinatorError::Limit);
    }
    if objects.is_empty() {
        return Ok(Vec::new());
    }
    canonical_page_plan(snapshot.archive_id(), objects)
}

fn pre_witness_bounds(
    object_count: usize,
    key_bytes: usize,
) -> Result<(), InventoryCoordinatorError> {
    if object_count > MAX_LIFECYCLE_ARTIFACTS || key_bytes > MAX_INVENTORY_KEY_BYTES {
        return Err(InventoryCoordinatorError::Limit);
    }
    Ok(())
}

/// Load and authenticate the complete type-separated pre-witness inventory.
/// The zero-object representation performs no page-store read. The returned
/// value deliberately has no deletion-driver/provider authorization surface.
pub(crate) async fn load_complete_pre_witness_deletion_inventory(
    control: &dyn PreWitnessInventoryControl,
    page_store: &dyn ArchiveLifecyclePageStore,
    seal: &PreWitnessDeletionInventorySeal,
) -> Result<CompletePreWitnessDeletionInventory, InventoryCoordinatorError> {
    let references = control.load_pre_witness_sealed_references(seal).await?;
    validate_pre_witness_sealed_page_references(seal, &references)?;

    let mut objects = Vec::with_capacity(
        usize::try_from(seal.artifact_count()).map_err(|_| InventoryCoordinatorError::Limit)?,
    );
    let mut key_bytes = 0usize;
    let mut previous_object: Option<LifecycleInventoryObject> = None;
    let mut seen = BTreeMap::<ObjectId, LifecycleInventoryObject>::new();
    for reference in &references {
        let durable = page_store
            .read_exact_page(seal.deletion_fence(), *reference)
            .await?;
        let page = durable.page();
        if page.reference() != *reference {
            return Err(InventoryCoordinatorError::Lifecycle);
        }
        for object in page.entries() {
            if previous_object
                .as_ref()
                .is_some_and(|previous| previous >= object)
                || seen
                    .insert(object.key().object_id(), object.clone())
                    .is_some()
            {
                return Err(InventoryCoordinatorError::DuplicateConflict);
            }
            key_bytes = key_bytes
                .checked_add(object.key().as_str().len())
                .ok_or(InventoryCoordinatorError::Limit)?;
            if objects.len() >= MAX_LIFECYCLE_ARTIFACTS || key_bytes > MAX_INVENTORY_KEY_BYTES {
                return Err(InventoryCoordinatorError::Limit);
            }
            previous_object = Some(object.clone());
            objects.push(object.clone());
        }
    }
    if objects.len() != usize::try_from(seal.artifact_count()).unwrap_or(usize::MAX)
        || (objects.is_empty() != references.is_empty())
    {
        return Err(InventoryCoordinatorError::Lifecycle);
    }
    CompletePreWitnessDeletionInventory::from_authenticated_lifecycle_pages(
        &AuthenticatedPreWitnessInventoryLoad::validated(),
        seal,
        objects,
        key_bytes,
    )
    .map_err(|_| InventoryCoordinatorError::Lifecycle)
}

/// Load and authenticate the complete v2 chain after restart. All control
/// references are validated before the first external GET, and the result's
/// only commitment is the exact lifecycle seal commitment.
pub(crate) async fn load_complete_deletion_inventory(
    control: &dyn DeletionInventoryControl,
    page_store: &dyn ArchiveLifecyclePageStore,
    seal: &DeletionInventorySeal,
) -> Result<CompleteDeletionInventory, InventoryCoordinatorError> {
    let references = control.load_sealed_references(seal).await?;
    validate_sealed_page_references(seal, &references)?;

    let mut objects = Vec::with_capacity(
        usize::try_from(seal.artifact_count()).map_err(|_| InventoryCoordinatorError::Limit)?,
    );
    let mut key_bytes = 0usize;
    let mut previous_object: Option<LifecycleInventoryObject> = None;
    let mut seen = BTreeMap::<ObjectId, LifecycleInventoryObject>::new();
    for reference in &references {
        let durable = page_store
            .read_exact_page(seal.deletion_fence(), *reference)
            .await?;
        let page = durable.page();
        if page.reference() != *reference {
            return Err(InventoryCoordinatorError::Lifecycle);
        }
        for object in page.entries() {
            if previous_object
                .as_ref()
                .is_some_and(|previous| previous >= object)
                || seen
                    .insert(object.key().object_id(), object.clone())
                    .is_some()
            {
                return Err(InventoryCoordinatorError::DuplicateConflict);
            }
            key_bytes = key_bytes
                .checked_add(object.key().as_str().len())
                .ok_or(InventoryCoordinatorError::Limit)?;
            validate_combined_bounds(
                objects
                    .len()
                    .checked_add(1)
                    .ok_or(InventoryCoordinatorError::Limit)?,
                key_bytes,
            )?;
            previous_object = Some(object.clone());
            objects.push(object.clone());
        }
    }
    if objects.len() != usize::try_from(seal.artifact_count()).unwrap_or(usize::MAX) {
        return Err(InventoryCoordinatorError::Lifecycle);
    }
    CompleteDeletionInventory::from_authenticated_lifecycle_pages(
        &AuthenticatedInventoryLoad::validated(),
        seal,
        objects,
        key_bytes,
    )
    .map_err(|_| InventoryCoordinatorError::Lifecycle)
}

/// Dependency-only adapter for the inactive deletion driver. Construction
/// performs no I/O and is not connected to startup or a provider factory.
pub(crate) struct AuthenticatedLifecycleInventoryLedger {
    control: Arc<dyn DeletionInventoryControl>,
    page_store: Arc<dyn ArchiveLifecyclePageStore>,
}

impl AuthenticatedLifecycleInventoryLedger {
    pub(crate) fn new(
        control: Arc<dyn DeletionInventoryControl>,
        page_store: Arc<dyn ArchiveLifecyclePageStore>,
    ) -> Self {
        Self {
            control,
            page_store,
        }
    }
}

impl fmt::Debug for AuthenticatedLifecycleInventoryLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedLifecycleInventoryLedger(<opaque>)")
    }
}

#[async_trait]
impl SealedArchiveInventoryLedger for AuthenticatedLifecycleInventoryLedger {
    async fn load_exact(
        &self,
        context: &AuthenticatedDeletionContext,
        seal: &DeletionInventorySeal,
    ) -> Result<CompleteDeletionInventory, ArchiveDeletionError> {
        if context.archive_id() != seal.archive_id() {
            return Err(ArchiveDeletionError::InvalidInventory);
        }
        load_complete_deletion_inventory(self.control.as_ref(), self.page_store.as_ref(), seal)
            .await
            .map_err(|_| ArchiveDeletionError::InvalidInventory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{DatabaseEpoch, KeyEpoch, LogicalLocation, ObjectContext, ObjectRole},
        archive_v3_lifecycle::{
            ArtifactCreateState, BootstrapAttemptId, BootstrapPlan, DurablePhysicalCompletion,
            ErasedInventoryPages, WITNESS_CREATE_PROTOCOL_V1,
        },
        archive_v3_witness::{active_deletion_test_fixture, deletion_driver_test_fixture, Witness},
        archive_v3_witness_disposition::{ClosedWitnessPhase, ClosedWitnessProtocol},
    };
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };

    fn archive() -> ArchiveId {
        ArchiveId::from_bytes([1; 16])
    }

    fn fence() -> ObjectId {
        ObjectId::from_bytes([2; 16])
    }

    fn object(index: u32) -> LifecycleInventoryObject {
        object_for(archive(), index)
    }

    fn object_for(archive_id: ArchiveId, index: u32) -> LifecycleInventoryObject {
        let mut id = [0; 16];
        id[..4].copy_from_slice(&index.saturating_add(1).to_be_bytes());
        let context = ObjectContext::new(
            archive_id,
            DatabaseEpoch::from_bytes([3; 16]),
            KeyEpoch::from_bytes([4; 16]),
            ObjectRole::ExtentV3,
            LogicalLocation::Extent {
                extent_no: u64::from(index),
                byte_len: 4096,
            },
            ObjectId::from_bytes(id),
            None,
        )
        .unwrap();
        let mut hash = [0x55; 32];
        hash[..4].copy_from_slice(&index.saturating_add(1).to_be_bytes());
        LifecycleInventoryObject::for_archive(
            archive_id,
            context.object_key(),
            ObjectRole::ExtentV3,
            hash,
        )
        .unwrap()
    }

    fn canonical_objects(indices: impl IntoIterator<Item = u32>) -> Vec<LifecycleInventoryObject> {
        let mut objects = indices.into_iter().map(object).collect::<Vec<_>>();
        objects.sort();
        objects
    }

    fn planned(
        index: u32,
        state: ArtifactCreateState,
    ) -> crate::archive_v3_lifecycle::PlannedArtifact {
        let object = object(index);
        crate::archive_v3_lifecycle::PlannedArtifact::new(
            archive(),
            BootstrapAttemptId::from_bytes([9; 16]).unwrap(),
            index,
            object.key().clone(),
            object.role(),
            object.ciphertext_hash(),
            128,
            state,
        )
        .unwrap()
    }

    fn snapshot(
        revision: u64,
        create_ahead: Vec<crate::archive_v3_lifecycle::PlannedArtifact>,
    ) -> FrozenInventorySnapshot {
        snapshot_for(archive(), fence(), revision, create_ahead)
    }

    fn snapshot_for(
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
        revision: u64,
        create_ahead: Vec<crate::archive_v3_lifecycle::PlannedArtifact>,
    ) -> FrozenInventorySnapshot {
        FrozenInventorySnapshot::for_test(archive_id, deletion_fence, revision, create_ahead)
            .unwrap()
    }

    fn pre_witness_snapshot(
        revision: u64,
        create_ahead: Vec<crate::archive_v3_lifecycle::PlannedArtifact>,
    ) -> FrozenPreWitnessInventorySnapshot {
        let plan = BootstrapPlan::new(
            archive(),
            BootstrapAttemptId::from_bytes([9; 16]).unwrap(),
            DatabaseEpoch::from_bytes([3; 16]),
            KeyEpoch::from_bytes([4; 16]),
            ObjectId::from_bytes([5; 16]),
            ObjectId::from_bytes([6; 16]),
        )
        .unwrap();
        FrozenPreWitnessInventorySnapshot::for_test(
            plan,
            fence(),
            revision.checked_sub(1).unwrap(),
            revision,
            None,
            None,
            [0x77; 32],
            create_ahead,
        )
        .unwrap()
    }

    fn pre_witness_absence() -> AuthenticatedPreWitnessAbsence {
        let closed = ClosedWitnessProtocol::for_test(
            archive(),
            BootstrapAttemptId::from_bytes([9; 16]).unwrap(),
            fence(),
            10,
            None,
            None,
            None,
            None,
            WITNESS_CREATE_PROTOCOL_V1,
            [0x66; 32],
            ClosedWitnessPhase::AbsenceConfirmed,
        )
        .unwrap();
        AuthenticatedPreWitnessAbsence::for_test(&closed, [0x77; 32]).unwrap()
    }

    fn durable(page: InventoryPage) -> DurableInventoryPage {
        let encoded = page.encoded().to_vec();
        DurableInventoryPage::from_exact_readback(page, &encoded).unwrap()
    }

    struct FakeControl {
        snapshot: Mutex<FrozenInventorySnapshot>,
        load_sequence: Mutex<VecDeque<FrozenInventorySnapshot>>,
        freeze_calls: Mutex<usize>,
        created: Mutex<Vec<InventoryPageReference>>,
        unresolved: Mutex<Option<InventoryPage>>,
        references: Mutex<Vec<InventoryPageReference>>,
    }

    struct FakePreControl {
        create_ahead: Vec<crate::archive_v3_lifecycle::PlannedArtifact>,
        recovery_revisions: Mutex<VecDeque<u64>>,
        freeze_calls: Mutex<usize>,
        created: Mutex<Vec<InventoryPageReference>>,
        unresolved: Mutex<Option<InventoryPage>>,
        references: Mutex<Vec<InventoryPageReference>>,
        sealed: Mutex<Option<PreWitnessDeletionInventorySeal>>,
    }

    impl FakePreControl {
        fn new(create_ahead: Vec<crate::archive_v3_lifecycle::PlannedArtifact>) -> Self {
            Self {
                create_ahead,
                recovery_revisions: Mutex::new(VecDeque::new()),
                freeze_calls: Mutex::new(0),
                created: Mutex::new(Vec::new()),
                unresolved: Mutex::new(None),
                references: Mutex::new(Vec::new()),
                sealed: Mutex::new(None),
            }
        }

        fn snapshot(&self, revision: u64) -> FrozenPreWitnessInventorySnapshot {
            pre_witness_snapshot(revision, self.create_ahead.clone())
        }
    }

    #[async_trait]
    impl PreWitnessInventoryControl for FakePreControl {
        async fn freeze_pre_witness_snapshot(
            &self,
            _absence: AuthenticatedPreWitnessAbsence,
        ) -> Result<FrozenPreWitnessInventorySnapshot, LifecycleError> {
            *self.freeze_calls.lock().unwrap() += 1;
            Ok(self.snapshot(12))
        }

        async fn recover_pre_witness_inventory(
            &self,
            archive_id: ArchiveId,
            deletion_fence: ObjectId,
        ) -> Result<RecoveredPreWitnessInventory, LifecycleError> {
            if archive_id != archive() || deletion_fence != fence() {
                return Err(LifecycleError::StaleRevision);
            }
            if let Some(seal) = *self.sealed.lock().unwrap() {
                return Ok(RecoveredPreWitnessInventory::Sealed(seal));
            }
            let revision = self
                .recovery_revisions
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(12);
            Ok(RecoveredPreWitnessInventory::Frozen(
                self.snapshot(revision),
            ))
        }

        async fn recover_pre_witness_page_plan(
            &self,
            archive_id: ArchiveId,
            _deletion_fence: ObjectId,
        ) -> Result<RecoveredPageCreatePlan, LifecycleError> {
            RecoveredPageCreatePlan::for_test(
                archive_id,
                self.created.lock().unwrap().clone(),
                self.unresolved.lock().unwrap().clone(),
            )
        }

        async fn seal_authenticated_pre_witness_pages(
            &self,
            plan: AuthenticatedPreWitnessInventoryPlan,
        ) -> Result<PreWitnessDeletionInventorySeal, LifecycleError> {
            let seal =
                PreWitnessDeletionInventorySeal::for_test(plan.snapshot(), plan.durable_pages())?;
            *self.references.lock().unwrap() = plan.references().to_vec();
            *self.sealed.lock().unwrap() = Some(seal);
            Ok(seal)
        }

        async fn load_pre_witness_sealed_references(
            &self,
            seal: &PreWitnessDeletionInventorySeal,
        ) -> Result<Vec<InventoryPageReference>, LifecycleError> {
            if self.sealed.lock().unwrap().as_ref() != Some(seal) {
                return Err(LifecycleError::StaleRevision);
            }
            Ok(self.references.lock().unwrap().clone())
        }
    }

    impl FakeControl {
        fn new(snapshot: FrozenInventorySnapshot) -> Self {
            Self {
                snapshot: Mutex::new(snapshot),
                load_sequence: Mutex::new(VecDeque::new()),
                freeze_calls: Mutex::new(0),
                created: Mutex::new(Vec::new()),
                unresolved: Mutex::new(None),
                references: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl DeletionInventoryControl for FakeControl {
        async fn freeze_snapshot(
            &self,
            archive_id: ArchiveId,
            expected_revision: u64,
            deletion_fence: ObjectId,
        ) -> Result<FrozenInventorySnapshot, LifecycleError> {
            *self.freeze_calls.lock().unwrap() += 1;
            let snapshot = self.snapshot.lock().unwrap().clone();
            if snapshot.archive_id() != archive_id
                || snapshot.deletion_fence() != deletion_fence
                || snapshot.revision() != expected_revision
            {
                return Err(LifecycleError::StaleRevision);
            }
            Ok(snapshot)
        }

        async fn load_snapshot(
            &self,
            archive_id: ArchiveId,
            deletion_fence: ObjectId,
        ) -> Result<FrozenInventorySnapshot, LifecycleError> {
            let snapshot = self
                .load_sequence
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.snapshot.lock().unwrap().clone());
            if snapshot.archive_id() != archive_id || snapshot.deletion_fence() != deletion_fence {
                return Err(LifecycleError::StaleRevision);
            }
            Ok(snapshot)
        }

        async fn recover_page_plan(
            &self,
            archive_id: ArchiveId,
            _deletion_fence: ObjectId,
        ) -> Result<RecoveredPageCreatePlan, LifecycleError> {
            RecoveredPageCreatePlan::for_test(
                archive_id,
                self.created.lock().unwrap().clone(),
                self.unresolved.lock().unwrap().clone(),
            )
        }

        async fn seal_authenticated_pages(
            &self,
            plan: AuthenticatedInventoryPlan,
        ) -> Result<DeletionInventorySeal, LifecycleError> {
            let snapshot = plan.snapshot();
            let pages = plan.durable_pages();
            let seal = DeletionInventorySeal::for_test(
                snapshot.archive_id(),
                snapshot.deletion_fence(),
                snapshot
                    .revision()
                    .checked_add(1)
                    .ok_or(LifecycleError::Limit)?,
                pages,
            )?;
            *self.references.lock().unwrap() =
                pages.iter().map(|page| page.page().reference()).collect();
            Ok(seal)
        }

        async fn load_sealed_references(
            &self,
            _seal: &DeletionInventorySeal,
        ) -> Result<Vec<InventoryPageReference>, LifecycleError> {
            Ok(self.references.lock().unwrap().clone())
        }
    }

    #[derive(Default)]
    struct FakePages {
        pages: Mutex<BTreeMap<u32, InventoryPage>>,
        read_calls: Mutex<usize>,
        create_calls: Mutex<usize>,
    }

    #[derive(Default)]
    struct CountingReader {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ExactReachabilityReader for CountingReader {
        async fn read_exact(
            &self,
            _key: &crate::archive_v3::ObjectKey,
            _max_encoded_bytes: usize,
        ) -> std::result::Result<
            Option<Vec<u8>>,
            crate::archive_v3_reachability::ExactReachabilityReadError,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(crate::archive_v3_reachability::ExactReachabilityReadError::Unavailable)
        }
    }

    #[async_trait]
    impl ArchiveLifecyclePageStore for FakePages {
        async fn create_exact_page(
            &self,
            _deletion_fence: ObjectId,
            page: &InventoryPage,
        ) -> Result<DurableInventoryPage, LifecycleError> {
            *self.create_calls.lock().unwrap() += 1;
            let mut pages = self.pages.lock().unwrap();
            if let Some(existing) = pages.get(&page.page_ordinal()) {
                if existing != page {
                    return Err(LifecycleError::ChainMismatch);
                }
            } else {
                pages.insert(page.page_ordinal(), page.clone());
            }
            Ok(durable(page.clone()))
        }

        async fn read_exact_page(
            &self,
            _deletion_fence: ObjectId,
            reference: InventoryPageReference,
        ) -> Result<DurableInventoryPage, LifecycleError> {
            *self.read_calls.lock().unwrap() += 1;
            let page = self
                .pages
                .lock()
                .unwrap()
                .get(&reference.page_ordinal())
                .cloned()
                .ok_or(LifecycleError::InvalidState)?;
            if page.reference() != reference {
                return Err(LifecycleError::ChainMismatch);
            }
            Ok(durable(page))
        }

        async fn erase_exact_pages_after_physical_completion(
            &self,
            _completion: &DurablePhysicalCompletion,
            _references: &[InventoryPageReference],
        ) -> Result<ErasedInventoryPages, LifecycleError> {
            Err(LifecycleError::InvalidState)
        }
    }

    #[test]
    fn exact_object_union_deduplicates_only_identical_facts() {
        let reached_object = object(0);
        let reached = crate::archive_v3_reachability::ReachableObject::for_test(
            reached_object.key().clone(),
            reached_object.role(),
            reached_object.ciphertext_hash(),
        );
        let frozen = snapshot(7, vec![planned(0, ArtifactCreateState::ConfirmedAbsent)]);
        let union = canonical_union(archive(), &frozen, &[reached]).unwrap();
        assert_eq!(union, vec![reached_object.clone()]);

        let conflicting = crate::archive_v3_reachability::ReachableObject::for_test(
            reached_object.key().clone(),
            reached_object.role(),
            [0x99; 32],
        );
        assert_eq!(
            canonical_union(archive(), &frozen, &[conflicting]),
            Err(InventoryCoordinatorError::DuplicateConflict)
        );
        assert!(LifecycleInventoryObject::for_archive(
            ArchiveId::from_bytes([0xaa; 16]),
            reached_object.key().clone(),
            reached_object.role(),
            reached_object.ciphertext_hash(),
        )
        .is_err());
    }

    #[test]
    fn canonical_plan_is_deterministic_bounded_and_uses_v2_pages() {
        let unsorted = (0..600).map(object).collect::<Vec<_>>();
        assert_eq!(
            canonical_page_plan(archive(), unsorted),
            Err(InventoryCoordinatorError::Lifecycle)
        );
        let objects = canonical_objects(0..600);
        let first = canonical_page_plan(archive(), objects.clone()).unwrap();
        let second = canonical_page_plan(archive(), objects).unwrap();
        assert_eq!(first, second);
        assert!(first.len() > 2);
        assert!(first.len() <= MAX_LIFECYCLE_PAGES);
        assert!(first.iter().all(|page| {
            page.entries().len() <= crate::archive_v3_lifecycle::MAX_LIFECYCLE_PAGE_ENTRIES
                && page.encoded().len() <= crate::archive_v3_lifecycle::MAX_LIFECYCLE_PAGE_BYTES
        }));
        assert!(first
            .iter()
            .enumerate()
            .all(|(ordinal, page)| usize::try_from(page.page_ordinal()).ok() == Some(ordinal)));
        assert_eq!(&first[0].encoded()[..6], b"KILP\0\x02");
    }

    #[test]
    fn combined_bounds_accept_exact_caps_and_reject_plus_one() {
        assert!(validate_combined_bounds(MAX_LIFECYCLE_ARTIFACTS, MAX_INVENTORY_KEY_BYTES).is_ok());
        assert_eq!(
            validate_combined_bounds(MAX_LIFECYCLE_ARTIFACTS + 1, MAX_INVENTORY_KEY_BYTES),
            Err(InventoryCoordinatorError::Limit)
        );
        assert_eq!(
            validate_combined_bounds(MAX_LIFECYCLE_ARTIFACTS, MAX_INVENTORY_KEY_BYTES + 1),
            Err(InventoryCoordinatorError::Limit)
        );
        assert!(pre_witness_bounds(MAX_LIFECYCLE_ARTIFACTS, MAX_INVENTORY_KEY_BYTES).is_ok());
        assert_eq!(
            pre_witness_bounds(MAX_LIFECYCLE_ARTIFACTS + 1, MAX_INVENTORY_KEY_BYTES),
            Err(InventoryCoordinatorError::Limit)
        );
        assert_eq!(
            pre_witness_bounds(MAX_LIFECYCLE_ARTIFACTS, MAX_INVENTORY_KEY_BYTES + 1),
            Err(InventoryCoordinatorError::Limit)
        );
    }

    #[test]
    fn recovered_plan_rejects_an_alternate_split_before_page_io() {
        let pages = canonical_page_plan(archive(), canonical_objects(0..300)).unwrap();
        let alternate = InventoryPage::build(
            archive(),
            0,
            [0; 32],
            pages[0].entries()[..pages[0].entries().len() - 1].to_vec(),
        )
        .unwrap();
        let recovered =
            RecoveredPageCreatePlan::for_test(archive(), vec![], Some(alternate)).unwrap();
        assert_eq!(
            validate_recovered_plan(&pages, &recovered),
            Err(InventoryCoordinatorError::Lifecycle)
        );
    }

    #[test]
    fn authenticated_plan_rejects_subset_superset_and_alternate_readbacks() {
        let planned = canonical_page_plan(archive(), canonical_objects(0..600)).unwrap();
        assert!(planned.len() >= 3);
        let frozen = snapshot(7, vec![]);
        let exact = planned.iter().cloned().map(durable).collect::<Vec<_>>();

        assert!(matches!(
            AuthenticatedInventoryPlan::for_test(
                &frozen,
                &planned,
                exact[..exact.len() - 1].to_vec(),
            ),
            Err(InventoryCoordinatorError::Lifecycle)
        ));
        let mut superset = exact.clone();
        let extra = InventoryPage::build(
            archive(),
            u32::try_from(planned.len()).unwrap(),
            planned.last().unwrap().page_hash(),
            vec![object(900)],
        )
        .unwrap();
        superset.push(durable(extra));
        assert!(matches!(
            AuthenticatedInventoryPlan::for_test(&frozen, &planned, superset),
            Err(InventoryCoordinatorError::Lifecycle)
        ));
        let alternate = canonical_page_plan(archive(), canonical_objects(1..601)).unwrap();
        assert_eq!(alternate.len(), planned.len());
        assert!(matches!(
            AuthenticatedInventoryPlan::for_test(
                &frozen,
                &planned,
                alternate.into_iter().map(durable).collect(),
            ),
            Err(InventoryCoordinatorError::Lifecycle)
        ));
    }

    #[tokio::test]
    async fn sealed_loader_authenticates_exact_chain_and_preserves_seal_commitment() {
        let pages = canonical_page_plan(archive(), canonical_objects(0..300)).unwrap();
        let durable_pages = pages.iter().cloned().map(durable).collect::<Vec<_>>();
        let seal = DeletionInventorySeal::for_test(archive(), fence(), 9, &durable_pages).unwrap();
        let control = FakeControl::new(snapshot(8, vec![]));
        *control.references.lock().unwrap() = pages.iter().map(InventoryPage::reference).collect();
        let page_store = FakePages::default();
        for page in pages {
            page_store
                .pages
                .lock()
                .unwrap()
                .insert(page.page_ordinal(), page);
        }
        let loaded = load_complete_deletion_inventory(&control, &page_store, &seal)
            .await
            .unwrap();
        assert_eq!(loaded.commitment_for_test(), seal.inventory_commitment());
        assert_eq!(loaded.objects_for_test().len(), 300);
        assert_eq!(
            *page_store.read_calls.lock().unwrap(),
            usize::try_from(seal.page_count()).unwrap()
        );
    }

    #[tokio::test]
    async fn current_predecessor_facts_and_create_ahead_extras_seal_reload_exactly() {
        let reachable_objects = (0..300).map(object).collect::<Vec<_>>();
        let reachable = reachable_objects
            .iter()
            .map(|object| {
                crate::archive_v3_reachability::ReachableObject::for_test(
                    object.key().clone(),
                    object.role(),
                    object.ciphertext_hash(),
                )
            })
            .collect::<Vec<_>>();
        let create_ahead = (300..320)
            .map(|index| planned(index, ArtifactCreateState::ConfirmedAbsent))
            .collect::<Vec<_>>();
        let frozen = snapshot(12, create_ahead);
        let union = canonical_union(archive(), &frozen, &reachable).unwrap();
        assert_eq!(union.len(), 320);
        let plan = canonical_page_plan(archive(), union).unwrap();
        let page_store = FakePages::default();
        let mut durable_pages = Vec::new();
        for page in &plan {
            durable_pages.push(page_store.create_exact_page(fence(), page).await.unwrap());
        }
        let control = FakeControl::new(frozen.clone());
        let seal = control
            .seal_authenticated_pages(
                AuthenticatedInventoryPlan::for_test(&frozen, &plan, durable_pages).unwrap(),
            )
            .await
            .unwrap();

        // Model close/reopen by discarding every page/receipt value except the
        // durable control references and exact external objects.
        let loaded = load_complete_deletion_inventory(&control, &page_store, &seal)
            .await
            .unwrap();
        assert_eq!(loaded.commitment_for_test(), seal.inventory_commitment());
        assert_eq!(loaded.objects_for_test().len(), 320);
    }

    #[tokio::test]
    async fn created_prefix_and_unresolved_next_resume_identical_plan() {
        let plan = canonical_page_plan(archive(), canonical_objects(0..600)).unwrap();
        assert!(plan.len() >= 3);
        let control = FakeControl::new(snapshot(7, vec![]));
        *control.created.lock().unwrap() = vec![plan[0].reference()];
        *control.unresolved.lock().unwrap() = Some(plan[1].clone());
        let page_store = FakePages::default();
        page_store.pages.lock().unwrap().insert(0, plan[0].clone());
        let recovered = control.recover_page_plan(archive(), fence()).await.unwrap();
        validate_recovered_plan(&plan, &recovered).unwrap();
        let first = page_store
            .read_exact_page(fence(), recovered.created()[0])
            .await
            .unwrap();
        let second = page_store
            .create_exact_page(fence(), recovered.outcome_unknown().unwrap())
            .await
            .unwrap();
        assert_eq!(first.page(), &plan[0]);
        assert_eq!(second.page(), &plan[1]);
        assert_eq!(second.page().encoded(), plan[1].encoded());
    }

    #[tokio::test]
    async fn bad_later_reference_causes_zero_external_reads() {
        let pages = canonical_page_plan(archive(), canonical_objects(0..300)).unwrap();
        let durable_pages = pages.iter().cloned().map(durable).collect::<Vec<_>>();
        let seal = DeletionInventorySeal::for_test(archive(), fence(), 9, &durable_pages).unwrap();
        let control = FakeControl::new(snapshot(8, vec![]));
        let mut references = pages
            .iter()
            .map(InventoryPage::reference)
            .collect::<Vec<_>>();
        let bad_page = InventoryPage::build(archive(), 1, [0x77; 32], vec![object(700)]).unwrap();
        references[1] = bad_page.reference();
        *control.references.lock().unwrap() = references;
        let page_store = FakePages::default();
        assert!(matches!(
            load_complete_deletion_inventory(&control, &page_store, &seal).await,
            Err(InventoryCoordinatorError::Lifecycle)
        ));
        assert_eq!(*page_store.read_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn fresh_control_snapshot_race_is_rejected() {
        let fixture = deletion_driver_test_fixture();
        let archive_id = fixture.tombstone.receipt().record().archive_id();
        let recovery = fixture
            .witness
            .resume_deletion(archive_id, &fixture.credential)
            .unwrap();
        let expected = FrozenInventorySnapshot::for_test(archive_id, fence(), 7, vec![]).unwrap();
        let changed = FrozenInventorySnapshot::for_test(archive_id, fence(), 8, vec![]).unwrap();
        let control = FakeControl::new(changed);
        assert_eq!(
            revalidate_fresh(
                archive_id,
                fence(),
                &fixture.credential,
                &expected,
                &recovery,
                &control,
                &fixture.witness,
            )
            .await,
            Err(InventoryCoordinatorError::Freshness)
        );
    }

    #[tokio::test]
    async fn wrong_credential_and_active_witness_fail_before_control_or_external_io() {
        let tombstoned = deletion_driver_test_fixture();
        let archive_id = tombstoned.tombstone.receipt().record().archive_id();
        let control = FakeControl::new(snapshot_for(archive_id, fence(), 7, vec![]));
        let downstream = FakePages::default();
        let reader = CountingReader::default();
        let cipher =
            crate::archive_v3_reachability::verified_cipher_for_coordinator_test(archive_id).await;
        assert!(matches!(
            seal_deletion_inventory(
                archive_id,
                7,
                fence(),
                &tombstoned.wrong_credential,
                &reader,
                &cipher,
                None,
                &control,
                &tombstoned.witness,
                &downstream,
            )
            .await,
            Err(InventoryCoordinatorError::Witness)
        ));
        assert_eq!(*control.freeze_calls.lock().unwrap(), 0);
        assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
        assert_eq!(*downstream.read_calls.lock().unwrap(), 0);
        assert_eq!(*downstream.create_calls.lock().unwrap(), 0);

        let (active, active_archive, active_credential) = active_deletion_test_fixture();
        let control = FakeControl::new(snapshot_for(active_archive, fence(), 7, vec![]));
        let cipher =
            crate::archive_v3_reachability::verified_cipher_for_coordinator_test(active_archive)
                .await;
        assert!(matches!(
            seal_deletion_inventory(
                active_archive,
                7,
                fence(),
                &active_credential,
                &reader,
                &cipher,
                None,
                &control,
                &active,
                &downstream,
            )
            .await,
            Err(InventoryCoordinatorError::Witness)
        ));
        assert_eq!(*control.freeze_calls.lock().unwrap(), 0);
        assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
        assert_eq!(*downstream.read_calls.lock().unwrap(), 0);
        assert_eq!(*downstream.create_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn freshness_races_block_before_page_io_and_before_seal() {
        let fixture = deletion_driver_test_fixture();
        let archive_id = fixture.tombstone.receipt().record().archive_id();
        let recovery = fixture
            .witness
            .resume_deletion(archive_id, &fixture.credential)
            .unwrap();
        let expected = snapshot_for(archive_id, fence(), 7, vec![]);
        let changed = snapshot_for(archive_id, fence(), 8, vec![]);
        let pages = canonical_page_plan(archive_id, vec![object_for(archive_id, 0)]).unwrap();

        let before_page = FakeControl::new(expected.clone());
        before_page
            .load_sequence
            .lock()
            .unwrap()
            .push_back(changed.clone());
        let page_store = FakePages::default();
        assert!(matches!(
            persist_and_seal_plan(
                archive_id,
                fence(),
                &fixture.credential,
                &expected,
                &recovery,
                &pages,
                &before_page,
                &fixture.witness,
                &page_store,
            )
            .await,
            Err(InventoryCoordinatorError::Freshness)
        ));
        assert_eq!(*page_store.read_calls.lock().unwrap(), 0);
        assert_eq!(*page_store.create_calls.lock().unwrap(), 0);

        let before_seal = FakeControl::new(expected.clone());
        before_seal
            .load_sequence
            .lock()
            .unwrap()
            .extend([expected.clone(), changed]);
        let page_store = FakePages::default();
        assert!(matches!(
            persist_and_seal_plan(
                archive_id,
                fence(),
                &fixture.credential,
                &expected,
                &recovery,
                &pages,
                &before_seal,
                &fixture.witness,
                &page_store,
            )
            .await,
            Err(InventoryCoordinatorError::Freshness)
        ));
        assert_eq!(*page_store.create_calls.lock().unwrap(), pages.len());
        assert!(before_seal.references.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pre_witness_zero_object_branch_seals_restarts_and_loads_without_page_io() {
        let control = FakePreControl::new(vec![]);
        let page_store = FakePages::default();
        let seal =
            seal_pre_witness_deletion_inventory(pre_witness_absence(), &control, &page_store)
                .await
                .unwrap();
        assert_eq!(seal.page_count(), 0);
        assert_eq!(seal.artifact_count(), 0);
        assert_ne!(seal.inventory_commitment(), [0; 32]);
        assert_eq!(*control.freeze_calls.lock().unwrap(), 1);
        assert_eq!(*page_store.create_calls.lock().unwrap(), 0);
        assert_eq!(*page_store.read_calls.lock().unwrap(), 0);

        let recovered =
            resume_pre_witness_deletion_inventory(archive(), fence(), &control, &page_store)
                .await
                .unwrap();
        assert_eq!(recovered, seal);
        let complete =
            load_complete_pre_witness_deletion_inventory(&control, &page_store, &recovered)
                .await
                .unwrap();
        assert!(complete.objects_for_test().is_empty());
        assert_eq!(complete.commitment_for_test(), seal.inventory_commitment());
        assert_eq!(complete.dimensions_for_test(), (0, 0));
        assert_eq!(*page_store.create_calls.lock().unwrap(), 0);
        assert_eq!(*page_store.read_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn pre_witness_multipage_cancel_restart_recovers_exact_partition_and_commitment() {
        let create_ahead = (0..600)
            .map(|index| planned(index, ArtifactCreateState::ConfirmedAbsent))
            .collect::<Vec<_>>();
        let expected =
            pre_witness_page_plan_for_snapshot(&pre_witness_snapshot(12, create_ahead.clone()))
                .unwrap();
        assert!(expected.len() >= 3);
        let control = FakePreControl::new(create_ahead);
        *control.created.lock().unwrap() = vec![expected[0].reference()];
        *control.unresolved.lock().unwrap() = Some(expected[1].clone());
        let page_store = FakePages::default();
        page_store
            .pages
            .lock()
            .unwrap()
            .insert(0, expected[0].clone());

        let seal = resume_pre_witness_deletion_inventory(archive(), fence(), &control, &page_store)
            .await
            .unwrap();
        assert_eq!(usize::try_from(seal.page_count()).unwrap(), expected.len());
        assert_eq!(seal.artifact_count(), 600);
        assert_eq!(page_store.pages.lock().unwrap().len(), expected.len());
        for expected_page in &expected {
            assert_eq!(
                page_store
                    .pages
                    .lock()
                    .unwrap()
                    .get(&expected_page.page_ordinal())
                    .unwrap()
                    .encoded(),
                expected_page.encoded()
            );
        }
        let complete = load_complete_pre_witness_deletion_inventory(&control, &page_store, &seal)
            .await
            .unwrap();
        assert_eq!(complete.objects_for_test().len(), 600);
        assert_eq!(complete.commitment_for_test(), seal.inventory_commitment());
    }

    #[test]
    fn pre_witness_union_deduplicates_exact_and_rejects_conflicts_before_io() {
        let exact = planned(0, ArtifactCreateState::Created);
        let duplicate = crate::archive_v3_lifecycle::PlannedArtifact::new(
            archive(),
            exact.attempt_id(),
            1,
            exact.key().clone(),
            exact.role(),
            exact.ciphertext_hash(),
            exact.encoded_len() as usize,
            ArtifactCreateState::ConfirmedAbsent,
        )
        .unwrap();
        let mut exact_rows = vec![exact, duplicate];
        exact_rows.sort_by(|left, right| {
            (left.attempt_id(), left.ordinal(), left.key().as_str()).cmp(&(
                right.attempt_id(),
                right.ordinal(),
                right.key().as_str(),
            ))
        });
        let pages =
            pre_witness_page_plan_for_snapshot(&pre_witness_snapshot(12, exact_rows)).unwrap();
        assert_eq!(
            pages.iter().map(|page| page.entries().len()).sum::<usize>(),
            1
        );

        let first = planned(2, ArtifactCreateState::Created);
        let conflict = crate::archive_v3_lifecycle::PlannedArtifact::new(
            archive(),
            first.attempt_id(),
            3,
            first.key().clone(),
            first.role(),
            [0xee; 32],
            first.encoded_len() as usize,
            ArtifactCreateState::ConfirmedAbsent,
        )
        .unwrap();
        let mut conflict_rows = vec![first, conflict];
        conflict_rows.sort_by(|left, right| {
            (left.attempt_id(), left.ordinal(), left.key().as_str()).cmp(&(
                right.attempt_id(),
                right.ordinal(),
                right.key().as_str(),
            ))
        });
        assert_eq!(
            pre_witness_page_plan_for_snapshot(&pre_witness_snapshot(12, conflict_rows)),
            Err(InventoryCoordinatorError::DuplicateConflict)
        );
    }

    #[tokio::test]
    async fn pre_witness_freshness_races_stop_before_page_io_and_before_seal() {
        let create_ahead = vec![planned(0, ArtifactCreateState::Created)];
        let before_page = FakePreControl::new(create_ahead.clone());
        before_page
            .recovery_revisions
            .lock()
            .unwrap()
            .extend([12, 13]);
        let page_store = FakePages::default();
        assert!(matches!(
            resume_pre_witness_deletion_inventory(archive(), fence(), &before_page, &page_store,)
                .await,
            Err(InventoryCoordinatorError::Freshness)
        ));
        assert_eq!(*page_store.create_calls.lock().unwrap(), 0);
        assert_eq!(*page_store.read_calls.lock().unwrap(), 0);

        let before_seal = FakePreControl::new(create_ahead);
        before_seal
            .recovery_revisions
            .lock()
            .unwrap()
            .extend([12, 12, 13]);
        let page_store = FakePages::default();
        assert!(matches!(
            resume_pre_witness_deletion_inventory(archive(), fence(), &before_seal, &page_store,)
                .await,
            Err(InventoryCoordinatorError::Freshness)
        ));
        assert_eq!(*page_store.create_calls.lock().unwrap(), 1);
        assert!(before_seal.sealed.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn pre_witness_bad_later_reference_causes_zero_page_reads() {
        let create_ahead = (0..300)
            .map(|index| planned(index, ArtifactCreateState::Created))
            .collect::<Vec<_>>();
        let snapshot = pre_witness_snapshot(12, create_ahead.clone());
        let pages = pre_witness_page_plan_for_snapshot(&snapshot).unwrap();
        let durable_pages = pages.iter().cloned().map(durable).collect::<Vec<_>>();
        let seal = PreWitnessDeletionInventorySeal::for_test(&snapshot, &durable_pages).unwrap();
        let control = FakePreControl::new(create_ahead);
        *control.sealed.lock().unwrap() = Some(seal);
        let mut references = pages
            .iter()
            .map(InventoryPage::reference)
            .collect::<Vec<_>>();
        let bad = InventoryPage::build(archive(), 1, [0x99; 32], vec![object(900)]).unwrap();
        references[1] = bad.reference();
        *control.references.lock().unwrap() = references;
        let page_store = FakePages::default();
        assert!(
            load_complete_pre_witness_deletion_inventory(&control, &page_store, &seal,)
                .await
                .is_err()
        );
        assert_eq!(*page_store.read_calls.lock().unwrap(), 0);
    }

    #[test]
    fn source_has_no_runtime_or_destructive_wiring() {
        let source = include_str!("archive_v3_inventory_coordinator.rs");
        for forbidden in [
            concat!("crate::store::", "Store"),
            concat!("std::", "env"),
            concat!("Rou", "ter"),
            concat!("heal", "th"),
            concat!("tombstone_", "current"),
            concat!("advance_", "deletion"),
            concat!("delete_all_", "generations"),
            concat!("Gcs", "Client"),
            concat!("FirestoreWitness::", "new"),
        ] {
            assert!(!source.contains(forbidden), "found forbidden {forbidden}");
        }
        let lifecycle = include_str!("archive_v3_lifecycle.rs");
        let control = include_str!("cp/control_store.rs");
        assert!(!lifecycle.contains("async fn seal_inventory("));
        assert!(!control.contains("pub(crate) async fn seal_archive_inventory("));
        assert!(control.contains("seal_archive_inventory_conn(conn, &plan)"));
        let absence_reachability = concat!("visit_witness_", "reachability(&absence");
        assert!(!source.contains(absence_reachability));
        let deletion = include_str!("archive_v3_deletion.rs");
        assert!(!deletion.contains("impl From<CompletePreWitnessDeletionInventory"));
        assert!(!deletion.contains("CompletePreWitnessDeletionInventory::authorize"));
    }
}
