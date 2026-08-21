//! The archive-v3 deletion drive ladder (ADR-0022, group D).
//!
//! `delete_user_fenced` erases only the legacy namespaces. For an archive that
//! reached the `wal_authoritative` terminal the authoritative data lives under
//! `archive/v3/{archive}/`, so letting the legacy sweep run would erase the
//! legacy artifacts, leave every checkpoint, WAL segment, root and key
//! registry intact, and still let finalization stamp the account
//! `physical_complete`. This module is the replacement for that: it drives the
//! reviewed witness deletion FSM, the reviewed inventory coordinator and the
//! reviewed exact-name deletion driver through one crash-resumable ladder.
//!
//! Nothing here is a new destructive authority. The witness deletion FSM
//! remains the sole destructive authority, the sync reconciler remains the
//! only retry engine, and every rung is durable and idempotent: an incomplete
//! rung returns [`WalDeletionOutcome::Pending`] with a stage the reconciler
//! maps to a `DeletionPending` reason, so the account is never reported
//! deleted in between.
//!
//! Two properties are load-bearing and are enforced here rather than assumed:
//!
//!   * **Exact-name only.** No rung lists `archive/v3/{archive}/` and deletes
//!     what it finds. The archive side deletes exactly the names in the sealed
//!     inventory; the media side deletes exactly the names in the frozen media
//!     inventory. A prefix design cannot be correct because media keys live
//!     outside the archive prefix entirely.
//!   * **No fabricated completion.** Completion is returned only when every
//!     inventoried name is *proven* absent — the driver's own drain
//!     re-verification for the archive keyspace, an exact absence read for
//!     every media name. Anything unproven fails closed.

use std::sync::Arc;

use crate::{
    archive_v3::ArchiveId,
    archive_v3_deletion::{ArchiveV3DeletionDriver, DeletionSession, DeletionStageProofs},
    archive_v3_inventory_coordinator::{
        seal_deletion_inventory, DeletionInventoryControl, DeletionInventoryWitness,
        InventoryCoordinatorError,
    },
    archive_v3_lifecycle::{ArchiveLifecyclePageStore, DeletionInventorySeal},
    archive_v3_reachability::ExactReachabilityReader,
    archive_v3_witness::{
        DeletionPrincipal, DeletionPrincipalKey, DeletionState, TombstoneAdvance, Witness,
        WitnessError,
    },
    cp::control_store::ControlStore,
    error::{DeletionPendingReason, EnclaveError, Result},
    store::Store,
};

/// The rung the ladder reached. Each maps to one `DeletionPending` reason, so
/// the operator can see exactly how far a retrying deletion has got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WalDeletionStage {
    /// The media inventory has not been frozen. This is the only rung that
    /// runs before the tombstone, because it is the only one that needs a live
    /// serving authority.
    MediaInventoryPending,
    TombstonePending,
    InventoryPending,
    ErasurePending,
    MediaErasurePending,
    /// Provider soft-delete retention has not expired. Carries the deadline so
    /// the caller can surface an honest `hard_delete_time`.
    DrainPending {
        hard_delete_time: Option<String>,
    },
    ControlCleanupPending,
    /// No retry can clear this: an inventory bound was exceeded, the frozen
    /// archive could not be enumerated, or the frozen ledger holds work
    /// nothing can settle. Key material is deliberately still intact.
    ManualRequired,
}

impl WalDeletionStage {
    pub(crate) const fn reason(&self) -> DeletionPendingReason {
        match self {
            Self::MediaInventoryPending => DeletionPendingReason::ArchiveV3MediaInventoryPending,
            Self::TombstonePending => DeletionPendingReason::ArchiveV3TombstonePending,
            Self::InventoryPending => DeletionPendingReason::ArchiveV3InventoryPending,
            Self::ErasurePending => DeletionPendingReason::ArchiveV3ErasurePending,
            Self::MediaErasurePending => DeletionPendingReason::ArchiveV3MediaErasurePending,
            Self::DrainPending { .. } => DeletionPendingReason::ArchiveV3DrainPending,
            Self::ControlCleanupPending => DeletionPendingReason::ArchiveV3ControlCleanupPending,
            Self::ManualRequired => DeletionPendingReason::ArchiveV3ManualRequired,
        }
    }

    pub(crate) fn into_pending(self) -> EnclaveError {
        let reason = self.reason();
        let hard_delete_time = match self {
            Self::DrainPending { hard_delete_time } => hard_delete_time,
            _ => None,
        };
        EnclaveError::DeletionPending(crate::error::DeletionPending {
            reason,
            retry_after_seconds: (reason != DeletionPendingReason::ArchiveV3ManualRequired)
                .then_some(30),
            hard_delete_time,
        })
    }
}

/// Residue that physical completion **discloses** rather than claims to have
/// erased.
///
/// This is deliberately not a "best effort" hedge. Everything that is
/// enumerable and finite *blocks* completion; only classes that are provably
/// unenumerable at deletion time are disclosed, and each carries its own
/// honest characterisation of what an operator is left holding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResidueDisclosure {
    /// R1 — genesis/publication staging orphans whose create-ahead row never
    /// became durable. Unenumerable by construction. Beneath the opaque
    /// archive prefix and encrypted under a registry this deletion destroyed
    /// (or under a key that was never persisted): storage residue, not
    /// recoverable data. Closable only by bucket-lifecycle expiry.
    pub(crate) genesis_staging_orphans: bool,
    /// R2 — consumed superseded-attempt uploads. When a witnessed checkpoint
    /// or publication is consumed at the next owner-binding transition, *all*
    /// of that cycle's attempt and artifact rows are deleted, so a prior
    /// cycle's failed-attempt upload loses its only enumeration during normal
    /// operation. The widened union covers the current cycle's crash window
    /// only. Same crypto-erased, opaque-prefix argument as R1.
    pub(crate) consumed_superseded_attempts: bool,
    /// R3 — media objects PUT without a durable row. Unlike R1/R2 this is
    /// **not** crypto-erased (each media object carries its own envelope) and
    /// its key path is account-linkable. The content-write fence bounds it at
    /// deletion time; a media create-ahead admission ledger closes it going
    /// forward. This is the wording the data-processing statement must use.
    pub(crate) media_put_without_record: bool,
}

impl ResidueDisclosure {
    /// What a WAL-authoritative deletion discloses today. R1 and R2 are
    /// structural properties of the current ledgers, not per-account
    /// observations, so they are always disclosed; R3 is disclosed until every
    /// one of the account's uploads postdates the media admission ledger,
    /// which does not exist yet.
    pub(crate) const fn current() -> Self {
        Self {
            genesis_staging_orphans: true,
            consumed_superseded_attempts: true,
            media_put_without_record: true,
        }
    }

    /// A stable, content-free flag list for the operation's terminal metadata.
    pub(crate) fn flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.genesis_staging_orphans {
            flags.push("r1_staging_orphans");
        }
        if self.consumed_superseded_attempts {
            flags.push("r2_consumed_superseded_attempts");
        }
        if self.media_put_without_record {
            flags.push("r3_media_put_without_record");
        }
        flags
    }
}

#[derive(Debug)]
pub(crate) enum WalDeletionOutcome {
    /// Every name in the sealed archive inventory and every name in the frozen
    /// media inventory is proven absent, with the soft-delete drain attested.
    Complete(ResidueDisclosure),
    Pending(WalDeletionStage),
}

/// The per-archive archive-v3 runtime one deletion needs.
///
/// This is a seam, not a factory of convenience: the concrete runtime is
/// reconstructed from the image's baked coordinates plus durable control
/// state, and it must be constructible for a *tombstoned* archive — after the
/// tombstone the startup selection scan filters the binding out, so nothing
/// installed at boot survives to serve this.
#[async_trait::async_trait]
pub(crate) trait ArchiveDeletionRuntime: Send + Sync {
    /// The witness handle. It must already carry the production deletion
    /// authority; a handle whose authenticator still denies every worker makes
    /// every rung `Unauthorized`, which is the correct fail-closed default for
    /// an image that has none.
    fn witness(&self) -> Arc<dyn DeletionLaneWitness>;

    /// Exact-name reader for the reachability walk. There is intentionally no
    /// enumerate or prefix operation on this seam.
    fn reader(&self) -> Arc<dyn ExactReachabilityReader>;

    /// The control-key page store holding the sealed inventory pages.
    fn page_store(&self) -> Arc<dyn ArchiveLifecyclePageStore>;

    /// Exact-generation object deletion transport.
    fn transport(&self) -> Arc<dyn crate::archive_v3_gcs::ArchiveV3GcsTransport>;

    /// Resolve the archive ciphers for the tombstoned root's current and
    /// predecessor key registries. Failure here must park the operation
    /// *before* any key erasure, with the registries still intact.
    async fn ciphers(
        &self,
    ) -> Result<(
        crate::archive_v3::VerifiedArchiveCipher,
        Option<crate::archive_v3::VerifiedArchiveCipher>,
    )>;
}

/// The union of the two witness views the ladder needs: the synchronous FSM
/// the driver drives, and the async exact-resume the coordinator authenticates
/// with. Concrete witnesses implement both already, so the blanket impl below
/// is the only implementation anyone needs.
pub(crate) trait DeletionLaneWitness: Send + Sync {
    fn as_witness(&self) -> &dyn Witness;
    fn as_inventory_witness(&self) -> &dyn DeletionInventoryWitness;
}

impl<T> DeletionLaneWitness for T
where
    T: Witness + DeletionInventoryWitness,
{
    fn as_witness(&self) -> &dyn Witness {
        self
    }

    fn as_inventory_witness(&self) -> &dyn DeletionInventoryWitness {
        self
    }
}

/// Everything the ladder needs that is not per-archive.
///
/// It deliberately holds neither the `Store` nor the `ControlStore`: the
/// `Store` owns the installed lane, and the `ControlStore` owns an `Arc<Store>`
/// for the rebind path, so keeping either here would close a reference cycle.
/// Both arrive per call instead.
pub(crate) struct WalDeletionLane {
    principal_key: Arc<DeletionPrincipalKey>,
    runtimes: Arc<dyn ArchiveDeletionRuntimeFactory>,
}

/// Builds the per-archive runtime for exactly one tombstoned archive.
#[async_trait::async_trait]
pub(crate) trait ArchiveDeletionRuntimeFactory: Send + Sync {
    async fn runtime_for(&self, archive_id: ArchiveId) -> Result<Arc<dyn ArchiveDeletionRuntime>>;
}

impl WalDeletionLane {
    #[allow(
        dead_code,
        reason = "the production runtime factory is a named follow-up; until it exists no image installs a lane and the WAL branch keeps failing closed"
    )]
    pub(crate) fn new(
        principal_key: Arc<DeletionPrincipalKey>,
        runtimes: Arc<dyn ArchiveDeletionRuntimeFactory>,
    ) -> Self {
        Self {
            principal_key,
            runtimes,
        }
    }

    /// The pre-tombstone rung. Called from the deletion route while the
    /// account is still `active` and its serving authority is still installed,
    /// because this is the only window in which the archive's logical database
    /// can be read at all.
    pub(crate) async fn freeze_media_inventory(
        &self,
        control: &ControlStore,
        store: &Store,
        user_id: &str,
    ) -> Result<()> {
        let Some(archive_id) = control.wal_deletion_archive(user_id).await? else {
            return Ok(());
        };
        if control
            .frozen_media_deletion_inventory(archive_id)
            .await?
            .is_some()
        {
            // Mint-once: a frozen inventory is never re-read from a database
            // that later mutations may have changed.
            return Ok(());
        }
        let keys = store.freeze_wal_authoritative_media_keys(user_id).await?;
        control
            .freeze_media_deletion_inventory(archive_id, &keys)
            .await
    }

    /// Drive one WAL-authoritative account's deletion as far as it can go.
    pub(crate) async fn drive(
        &self,
        control: &Arc<ControlStore>,
        store: &Store,
        user_id: &str,
    ) -> Result<WalDeletionOutcome> {
        let Some(archive_id) = control.wal_deletion_archive(user_id).await? else {
            return Err(EnclaveError::Conflict(
                "archive-v3 deletion lane requires a bound archive".into(),
            ));
        };
        // W8 fast path. Control cleanup erased the sealed inventory pages, so
        // a retry that re-entered the driver would find nothing to load and
        // could never complete again. A deletion that has fully landed is
        // reported complete from durable control state alone.
        if control.wal_deletion_already_complete(archive_id).await? {
            return Ok(WalDeletionOutcome::Complete(ResidueDisclosure::current()));
        }
        // W1 precondition: the control ledger must already be tombstoned with
        // a fence. `begin_user_deletion` guarantees this before any content
        // work, and the fence is the deletion's only operation identity.
        let Some(deletion_fence) = control.archive_deletion_fence(archive_id).await? else {
            return Ok(WalDeletionOutcome::Pending(
                WalDeletionStage::TombstonePending,
            ));
        };
        // The media inventory must be durable before anything destructive:
        // after the tombstone it can never be recomputed.
        let Some(media_keys) = control.frozen_media_deletion_inventory(archive_id).await? else {
            return Ok(WalDeletionOutcome::Pending(
                WalDeletionStage::MediaInventoryPending,
            ));
        };

        let principal =
            DeletionPrincipal::new(Arc::clone(&self.principal_key), archive_id, deletion_fence)
                .map_err(map_witness)?;
        let runtime = self.runtimes.runtime_for(archive_id).await?;
        let witness = runtime.witness();

        // ── W1 TOMBSTONE ────────────────────────────────────────────────────
        // Exact-current CAS: the witness compares the complete mutable
        // snapshot, revokes the owner, installs the deletion fencing epoch and
        // pins this worker identity. Already-tombstoned resumes instead.
        let credential = principal.credential().map_err(map_witness)?;
        let session = match witness
            .as_witness()
            .read_current(archive_id)
            .map_err(map_witness)?
        {
            Some(record) if record.deletion() == DeletionState::Active => {
                let advance = TombstoneAdvance::from_current(&record).map_err(map_witness)?;
                let proof = principal
                    .stage_proof(DeletionState::Tombstoned)
                    .map_err(map_witness)?;
                match witness
                    .as_witness()
                    .tombstone_current(advance, &credential, &proof)
                {
                    Ok(receipt) => DeletionSession::from_tombstone(&receipt)
                        .map_err(|_| deletion_driver_error())?,
                    // A live owner heartbeat advances the fencing epochs under
                    // us. Never spin: report the rung and let the reconciler's
                    // own interval be the backoff, which also waits the lease
                    // out rather than racing it.
                    Err(WitnessError::CompareFailed) => {
                        return Ok(WalDeletionOutcome::Pending(
                            WalDeletionStage::TombstonePending,
                        ))
                    }
                    Err(error) => return Err(map_witness(error)),
                }
            }
            Some(_) => {
                let recovery = witness
                    .as_witness()
                    .resume_deletion(archive_id, &credential)
                    .map_err(map_witness)?;
                DeletionSession::from_recovery(&recovery).map_err(|_| deletion_driver_error())?
            }
            None => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::TombstonePending,
                ))
            }
        };

        // ── W5 ARCHIVE SEAL ─────────────────────────────────────────────────
        // Freeze the lifecycle snapshot, walk the graph from the tombstoned
        // recovery root, union every frozen create-ahead row, and seal the
        // canonical page plan. Idempotent: a resumed seal revalidates against
        // the same witness record and the same frozen snapshot.
        let seal = match self
            .sealed_inventory(
                control,
                archive_id,
                deletion_fence,
                &principal,
                runtime.as_ref(),
            )
            .await
        {
            Ok(seal) => seal,
            // Materialising or enumerating the archive failed. This happens
            // strictly before key erasure, so every registry is still present
            // and manual recovery is still possible.
            Err(SealFailure::ManualRequired) => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::ManualRequired,
                ))
            }
            Err(SealFailure::Retryable) => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::InventoryPending,
                ))
            }
        };

        // ── W6 DRIVER RUN ───────────────────────────────────────────────────
        // Registries first (cryptographic erasure precedes everything, so a
        // mid-sweep crash leaves only key-less ciphertext), then every
        // non-registry entry's content and permanent ID claim across all
        // generations, then the drain re-verification that mints the receipt.
        let ledger = Arc::new(
            crate::archive_v3_inventory_coordinator::AuthenticatedLifecycleInventoryLedger::new(
                Arc::clone(control) as Arc<dyn DeletionInventoryControl>,
                runtime.page_store(),
            ),
        );
        let driver = ArchiveV3DeletionDriver::for_gcs(ledger, runtime.transport());
        let key_erasure = principal
            .stage_proof(DeletionState::CryptographicallyErased)
            .map_err(map_witness)?;
        let inventory = principal
            .stage_proof(DeletionState::LogicalObjectsAbsent)
            .map_err(map_witness)?;
        let retention = principal
            .stage_proof(DeletionState::PhysicalComplete)
            .map_err(map_witness)?;
        let receipt = match driver
            .run(
                witness.as_witness(),
                session,
                &credential,
                DeletionStageProofs {
                    key_erasure: &key_erasure,
                    inventory: &inventory,
                    retention_assertion: &retention,
                },
                &seal,
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(crate::archive_v3_deletion::ArchiveDeletionError::ProviderDrainPending) => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::DrainPending {
                        hard_delete_time: None,
                    },
                ))
            }
            Err(crate::archive_v3_deletion::ArchiveDeletionError::InventoryLimit) => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::ManualRequired,
                ))
            }
            Err(_) => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::ErasurePending,
                ))
            }
        };

        // ── W7 MEDIA EXECUTION ──────────────────────────────────────────────
        // Gated on the archive receipt. Media keys are outside the archive
        // prefix, so they are erased by this control-side lane rather than
        // being smuggled into the driver's inventory — which would have meant
        // relaxing the driver's per-entry archive-prefix bound.
        match store
            .delete_wal_authoritative_media(user_id, &media_keys)
            .await
        {
            Ok(()) => {}
            Err(EnclaveError::DeletionPending(pending))
                if pending.reason == DeletionPendingReason::SoftDeleteRetention =>
            {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::DrainPending {
                        hard_delete_time: pending.hard_delete_time,
                    },
                ))
            }
            Err(_) => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::MediaErasurePending,
                ))
            }
        }

        // ── W7 CONTROL CLEANUP ──────────────────────────────────────────────
        // Only now, with the receipt in hand: mark the anchor complete, erase
        // the sealed pages, erase the retry payloads, and tear down the WAL
        // bookkeeping whose `object_key` columns are names that must not
        // outlive completion. The tombstoned ledger, the binding tombstone and
        // the PhysicalComplete witness record are retained forever as the
        // content-free resurrection guard.
        let completion = match control.mark_archive_physical_complete(receipt).await {
            Ok(completion) => completion,
            Err(_) => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::ControlCleanupPending,
                ))
            }
        };
        let references = match control.load_sealed_archive_inventory_references(seal).await {
            Ok(references) => references,
            Err(_) => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::ControlCleanupPending,
                ))
            }
        };
        let erased = match runtime
            .page_store()
            .erase_exact_pages_after_physical_completion(&completion, &references)
            .await
        {
            Ok(erased) => erased,
            Err(_) => {
                return Ok(WalDeletionOutcome::Pending(
                    WalDeletionStage::ControlCleanupPending,
                ))
            }
        };
        if control
            .erase_archive_lifecycle_payload(completion, erased)
            .await
            .is_err()
            || control.tear_down_wal_bookkeeping(archive_id).await.is_err()
        {
            return Ok(WalDeletionOutcome::Pending(
                WalDeletionStage::ControlCleanupPending,
            ));
        }
        Ok(WalDeletionOutcome::Complete(ResidueDisclosure::current()))
    }

    async fn sealed_inventory(
        &self,
        control: &ControlStore,
        archive_id: ArchiveId,
        deletion_fence: crate::archive_v3::ObjectId,
        principal: &DeletionPrincipal,
        runtime: &dyn ArchiveDeletionRuntime,
    ) -> std::result::Result<DeletionInventorySeal, SealFailure> {
        let revision = control
            .freeze_archive_lifecycle(
                archive_id,
                self.lifecycle_revision(control, archive_id).await?,
                deletion_fence,
            )
            .await
            .map_err(|_| SealFailure::Retryable)?;
        let (current, predecessor) = runtime
            .ciphers()
            .await
            // An unbootable archive parks BEFORE any key erasure: the
            // registries are still present, so manual recovery stays possible.
            .map_err(|_| SealFailure::ManualRequired)?;
        let credential = principal
            .credential()
            .map_err(|_| SealFailure::ManualRequired)?;
        let witness = runtime.witness();
        seal_deletion_inventory(
            archive_id,
            revision,
            deletion_fence,
            &credential,
            runtime.reader().as_ref(),
            &current,
            predecessor.as_ref(),
            control as &dyn DeletionInventoryControl,
            witness.as_inventory_witness(),
            runtime.page_store().as_ref(),
        )
        .await
        .map_err(|error| match error {
            // A bound was exceeded: never truncate the inventory, park it.
            InventoryCoordinatorError::Limit | InventoryCoordinatorError::DuplicateConflict => {
                SealFailure::ManualRequired
            }
            _ => SealFailure::Retryable,
        })
    }

    async fn lifecycle_revision(
        &self,
        control: &ControlStore,
        archive_id: ArchiveId,
    ) -> std::result::Result<u64, SealFailure> {
        control
            .archive_lifecycle_revision(archive_id)
            .await
            .map_err(|_| SealFailure::Retryable)?
            .ok_or(SealFailure::ManualRequired)
    }
}

enum SealFailure {
    Retryable,
    ManualRequired,
}

fn map_witness(_error: WitnessError) -> EnclaveError {
    // Witness failures are content-free by contract; keep them that way.
    EnclaveError::Store("archive-v3 deletion witness refused".into())
}

fn deletion_driver_error() -> EnclaveError {
    EnclaveError::Store("archive-v3 deletion session is not tombstoned".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cp::control_store::TEST_SIGNUP_LIMIT,
        store::tests::{FakeGcs, FakeKms},
    };

    /// A factory that refuses to build anything. Every rung that runs before
    /// the archive-v3 runtime is needed must complete without touching it, and
    /// this proves it rather than assuming it.
    struct NeverBuildsRuntime;

    #[async_trait::async_trait]
    impl ArchiveDeletionRuntimeFactory for NeverBuildsRuntime {
        async fn runtime_for(
            &self,
            _archive_id: ArchiveId,
        ) -> Result<Arc<dyn ArchiveDeletionRuntime>> {
            panic!("this rung must not construct an archive-v3 deletion runtime")
        }
    }

    fn lane() -> WalDeletionLane {
        WalDeletionLane::new(
            Arc::new(
                DeletionPrincipalKey::derive_from_control_root(&[0x31; 32])
                    .expect("principal key derives"),
            ),
            Arc::new(NeverBuildsRuntime),
        )
    }

    async fn wal_account(control: &Arc<ControlStore>, user_id: &str) -> (String, ArchiveId) {
        let user = control
            .upsert_user(
                user_id,
                &format!("{user_id}@example.com"),
                TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();
        let archive_id = control
            .seed_wal_genesis_terminal_for_test(&user.id)
            .await
            .unwrap();
        (user.id, archive_id)
    }

    #[tokio::test]
    async fn an_untombstoned_ledger_pends_at_the_tombstone_rung_without_a_runtime() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let (user_id, _) = wal_account(&control, "lane-untombstoned").await;
        assert!(matches!(
            lane().drive(&control, &store, &user_id).await.unwrap(),
            WalDeletionOutcome::Pending(WalDeletionStage::TombstonePending)
        ));
    }

    /// The media inventory is frozen before the tombstone because it can never
    /// be recomputed afterwards. If it is somehow missing once the archive is
    /// tombstoned, the ladder must stop *before* anything destructive rather
    /// than erase the archive and leave the account's media behind.
    #[tokio::test]
    async fn a_missing_media_inventory_stops_the_ladder_before_any_erasure() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let (user_id, archive_id) = wal_account(&control, "lane-no-media-inventory").await;
        control.begin_user_deletion(&user_id).await.unwrap();
        assert!(control
            .archive_deletion_fence(archive_id)
            .await
            .unwrap()
            .is_some());
        assert!(matches!(
            lane().drive(&control, &store, &user_id).await.unwrap(),
            WalDeletionOutcome::Pending(WalDeletionStage::MediaInventoryPending)
        ));
    }

    /// Freezing is mint-once. After the tombstone the archive database is
    /// unreadable, so the first durable inventory is the only one there will
    /// ever be; a second freeze must adopt it, never replace it.
    #[tokio::test]
    async fn the_frozen_media_inventory_is_mint_once() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let (_user_id, archive_id) = wal_account(&control, "lane-media-freeze").await;
        control
            .freeze_media_deletion_inventory(
                archive_id,
                &["raw/lane-media-freeze/one.enc".to_string()],
            )
            .await
            .unwrap();
        // Identical re-freeze is idempotent.
        control
            .freeze_media_deletion_inventory(
                archive_id,
                &["raw/lane-media-freeze/one.enc".to_string()],
            )
            .await
            .unwrap();
        // A different key set is a conflict, never a silent replacement.
        assert!(control
            .freeze_media_deletion_inventory(archive_id, &[])
            .await
            .is_err());
        assert_eq!(
            control
                .frozen_media_deletion_inventory(archive_id)
                .await
                .unwrap(),
            Some(vec!["raw/lane-media-freeze/one.enc".to_string()])
        );
    }

    /// Control cleanup erases the sealed inventory pages. A retry that
    /// re-entered the driver would find nothing to load and could never reach
    /// completion again, so a fully landed deletion must be reported complete
    /// from durable control state alone — even with a runtime factory that
    /// refuses to build anything.
    #[tokio::test]
    async fn a_fully_landed_deletion_completes_from_control_state_alone() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let (user_id, archive_id) = wal_account(&control, "lane-already-complete").await;
        control.begin_user_deletion(&user_id).await.unwrap();
        control
            .freeze_media_deletion_inventory(archive_id, &[])
            .await
            .unwrap();
        assert!(!control
            .wal_deletion_already_complete(archive_id)
            .await
            .unwrap());
        control
            .mark_wal_deletion_complete_for_test(archive_id)
            .await
            .unwrap();
        assert!(control
            .wal_deletion_already_complete(archive_id)
            .await
            .unwrap());
        assert!(matches!(
            lane().drive(&control, &store, &user_id).await.unwrap(),
            WalDeletionOutcome::Complete(_)
        ));
    }

    #[test]
    fn every_rung_maps_to_its_own_pending_reason() {
        let cases = [
            (
                WalDeletionStage::MediaInventoryPending,
                "archive_v3_media_inventory_pending",
            ),
            (
                WalDeletionStage::TombstonePending,
                "archive_v3_tombstone_pending",
            ),
            (
                WalDeletionStage::InventoryPending,
                "archive_v3_inventory_pending",
            ),
            (
                WalDeletionStage::ErasurePending,
                "archive_v3_erasure_pending",
            ),
            (
                WalDeletionStage::MediaErasurePending,
                "archive_v3_media_erasure_pending",
            ),
            (
                WalDeletionStage::ControlCleanupPending,
                "archive_v3_control_cleanup_pending",
            ),
            (
                WalDeletionStage::ManualRequired,
                "archive_v3_manual_required",
            ),
        ];
        for (stage, reason) in cases {
            let manual = stage == WalDeletionStage::ManualRequired;
            match stage.into_pending() {
                EnclaveError::DeletionPending(pending) => {
                    assert_eq!(pending.reason.as_str(), reason);
                    // A class no retry can clear must not advertise a retry.
                    assert_eq!(pending.retry_after_seconds.is_none(), manual);
                    assert!(pending.hard_delete_time.is_none());
                }
                other => panic!("expected a pending deletion, got {other:?}"),
            }
        }
        // The drain rung carries the provider's own retention deadline
        // through to the caller rather than inventing one.
        match (WalDeletionStage::DrainPending {
            hard_delete_time: Some("2026-09-01T00:00:00.000Z".into()),
        })
        .into_pending()
        {
            EnclaveError::DeletionPending(pending) => {
                assert_eq!(pending.reason.as_str(), "archive_v3_drain_pending");
                assert_eq!(
                    pending.hard_delete_time.as_deref(),
                    Some("2026-09-01T00:00:00.000Z")
                );
            }
            other => panic!("expected a pending deletion, got {other:?}"),
        }
    }

    /// Residue is disclosed, not dropped. All three surviving classes must be
    /// named on every WAL-authoritative completion until the ledgers that
    /// would make them enumerable exist.
    #[test]
    fn completion_discloses_every_surviving_residue_class() {
        assert_eq!(
            ResidueDisclosure::current().flags(),
            vec![
                "r1_staging_orphans",
                "r2_consumed_superseded_attempts",
                "r3_media_put_without_record",
            ]
        );
        assert!(ResidueDisclosure::default().flags().is_empty());
    }

    /// The disclosure is durable and readable back: an operator answering a
    /// deletion request must be able to say exactly which classes survived.
    #[tokio::test]
    async fn the_residue_disclosure_round_trips_on_the_account_tombstone() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let (user_id, _) = wal_account(&control, "lane-residue").await;
        assert!(control
            .deletion_residue_disclosure(&user_id)
            .await
            .unwrap()
            .is_none());
        control
            .record_deletion_residue_disclosure(&user_id, &ResidueDisclosure::current().flags())
            .await
            .unwrap();
        assert_eq!(
            control
                .deletion_residue_disclosure(&user_id)
                .await
                .unwrap()
                .unwrap(),
            vec![
                "r1_staging_orphans".to_string(),
                "r2_consumed_superseded_attempts".to_string(),
                "r3_media_put_without_record".to_string(),
            ]
        );
    }

    #[test]
    fn the_deletion_lane_installs_once() {
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        assert!(store.wal_deletion_lane().is_none());
        store.install_wal_deletion_lane(Arc::new(lane())).unwrap();
        assert!(store.wal_deletion_lane().is_some());
        assert!(store.install_wal_deletion_lane(Arc::new(lane())).is_err());
    }
}
