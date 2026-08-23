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
//! Re-entry is the normal case, not the exception. Waiting out provider
//! soft-delete retention, media erasure and control cleanup all return to the
//! reconciler and come back through [`WalDeletionLane::drive`], so the ladder
//! must be able to resume from any durable state it left behind. The seal is
//! the one rung whose control-plane transition is not re-runnable — the
//! lifecycle freeze compare-and-swap cannot leave `inventory_sealed` or
//! `physical_complete` — so W5 rebuilds the existing seal from the anchor
//! instead of re-freezing. That CAS is deliberately left exactly as narrow as
//! it was; widening it would let a post-erasure pass walk an archive whose key
//! registries no longer exist.
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
        AsyncDeletionWitness, DeletionPrincipal, DeletionPrincipalKey, DeletionState,
        TombstoneAdvance, WitnessError,
    },
    cp::control_store::ControlStore,
    error::{DeletionPendingReason, EnclaveError, Result},
    store::Store,
};

/// The rung the ladder reached. Each maps to one `DeletionPending` reason, so
/// the operator can see exactly how far a retrying deletion has got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WalDeletionStage {
    /// The media inventory has not been frozen yet, but the account still has
    /// a serving authority installed, so the freeze rung can still mint it on
    /// a later pass. When it cannot, the ladder reports
    /// [`Self::ManualRequired`] instead — an unsatisfiable rung must never
    /// present as a retry.
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
    /// No retry can clear this: an inventory bound was exceeded, a name was
    /// inventoried twice, the frozen archive could not be enumerated, the
    /// frozen ledger holds work nothing can settle, a durable seal no longer
    /// reconstructs, or the account's media inventory was never frozen and no
    /// serving authority survives to freeze it. Key material is deliberately
    /// still intact in every one of those cases, and this is the only rung
    /// that reaches `failed_retryable`, which is what actually pages a human.
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
    /// R3 — media objects PUT without a durable row. Every production media PUT
    /// is now preceded by the retained provider write-intent, and WAL deletion
    /// durably fences/drains that family before proving both owned media
    /// prefixes empty. This bit therefore remains in the stable disclosure
    /// schema for old receipts but is false for current completions.
    pub(crate) media_put_without_record: bool,
}

impl ResidueDisclosure {
    /// What a WAL-authoritative deletion discloses today. R1 and R2 are
    /// structural properties of the current ledgers, not per-account
    /// observations, so they are always disclosed. R3 is closed by the durable
    /// media write-intent plus retained deletion marker and exact prefix drain.
    pub(crate) const fn current() -> Self {
        Self {
            genesis_staging_orphans: true,
            consumed_superseded_attempts: true,
            media_put_without_record: false,
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
    fn as_deletion_witness(&self) -> &dyn AsyncDeletionWitness;
    fn as_inventory_witness(&self) -> &dyn DeletionInventoryWitness;
}

impl<T> DeletionLaneWitness for T
where
    T: AsyncDeletionWitness + DeletionInventoryWitness,
{
    fn as_deletion_witness(&self) -> &dyn AsyncDeletionWitness {
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
    /// because that is the widest window in which the archive's logical
    /// database can be read — and again from the reconciler immediately before
    /// [`Self::drive`], which rescues every account that reached `deleting`
    /// without one (the tombstone filters the *startup* selection scan, not a
    /// live in-memory map, so a same-process account can still be frozen).
    ///
    /// Mint-once and idempotent, so calling it on every pass costs one control
    /// read once the inventory exists.
    ///
    /// **Pre-wiring remediation.** An account that reached `deleting` on an
    /// image with no lane installed has a tombstoned binding and no frozen
    /// media inventory, and after a restart nothing can enumerate its media.
    /// Those accounts are not rescuable by any retry: [`Self::drive`] reports
    /// them as [`WalDeletionStage::ManualRequired`] so an operator is paged.
    /// A release that wires the runtime factory must therefore either drain
    /// the `deleting` backlog first or accept that named manual class.
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
        if !store.is_wal_authoritative(user_id) {
            // `wal_authoritative_read` falls back to the legacy per-user store
            // for an unselected account. For an account whose authority is the
            // archive, those rows are not the answer to "what media was ever
            // named" — freezing them would mint an inventory the ladder would
            // later present as an exact-name proof of erasure. Refuse instead:
            // an inventory that cannot be read authoritatively must not be
            // invented, and the caller surfaces the refusal rather than
            // tombstoning the account into a state no retry can erase.
            return Err(EnclaveError::Store(
                "media inventory needs the account's serving authority".into(),
            ));
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
            // Freezing needs a live serving authority for the archive's
            // logical database. If this process still has one installed the
            // pre-tombstone rung can still mint the inventory, so pend and let
            // the reconciler's next pass do it. If it does not — the binding
            // is tombstoned and the startup selection scan filters tombstoned
            // bindings, so no authority is ever re-registered — then nothing
            // can ever produce it and no retry will help. Park it for a human
            // rather than looping on a `pending` status no operator is shown,
            // and never fabricate an empty inventory to get past this rung:
            // that would erase the archive and silently leave the account's
            // media behind.
            return Ok(WalDeletionOutcome::Pending(
                if store.is_wal_authoritative(user_id) {
                    WalDeletionStage::MediaInventoryPending
                } else {
                    WalDeletionStage::ManualRequired
                },
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
            .as_deletion_witness()
            .read_current_deletion(archive_id)
            .await
            .map_err(map_witness)?
        {
            Some(record) if record.deletion() == DeletionState::Active => {
                let advance = TombstoneAdvance::from_current(&record).map_err(map_witness)?;
                let proof = principal
                    .stage_proof(DeletionState::Tombstoned)
                    .map_err(map_witness)?;
                match witness
                    .as_deletion_witness()
                    .tombstone_current_deletion(advance, &credential, &proof)
                    .await
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
                    .as_deletion_witness()
                    .resume_deletion_async_boundary(archive_id, &credential)
                    .await
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
        // canonical page plan — or, on a re-entry, adopt the seal the first
        // pass already made durable. Both arms bind the same archive, fence
        // and inventory commitment; neither invents one.
        let ladder = match self
            .sealed_inventory(
                control,
                archive_id,
                deletion_fence,
                &principal,
                runtime.as_ref(),
            )
            .await
        {
            Ok(ladder) => ladder,
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

        // A re-entry that finds the drain receipt already durable skips W6 and
        // W7 entirely. That is not a shortcut around proof: the anchor only
        // reaches `physical_complete` after the driver's own drain
        // re-verification minted a `PhysicalDeletionReceipt` for every
        // inventoried archive name AND the media rung proved every frozen
        // media name absent by exact readback. Re-running W6 here would
        // instead fail forever, because the sealed inventory pages this pass
        // is about to erase may already be gone.
        let completion = match ladder {
            LadderInventory::PhysicallyComplete(completion) => completion,
            LadderInventory::Sealed(seal) => {
                match self
                    .erase_and_complete(
                        control,
                        store,
                        user_id,
                        &principal,
                        runtime.as_ref(),
                        session,
                        seal,
                        &media_keys,
                    )
                    .await?
                {
                    CompletionOutcome::Complete(completion) => completion,
                    CompletionOutcome::Pending(stage) => {
                        return Ok(WalDeletionOutcome::Pending(stage))
                    }
                }
            }
        };

        // ── W7 CONTROL CLEANUP ──────────────────────────────────────────────
        // Only now, with the receipt durable: erase the sealed pages, erase
        // the retry payloads, and tear down the WAL bookkeeping whose
        // `object_key` columns are names that must not outlive completion. The
        // tombstoned ledger, the binding tombstone and the PhysicalComplete
        // witness record are retained forever as the content-free
        // resurrection guard.
        let seal = completion.physical_receipt().seal();
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
        let residue = ResidueDisclosure::current();
        if control
            .erase_archive_lifecycle_payload(completion, erased)
            .await
            .is_err()
            || control
                .tear_down_wal_bookkeeping(archive_id, user_id, &residue.flags())
                .await
                .is_err()
        {
            return Ok(WalDeletionOutcome::Pending(
                WalDeletionStage::ControlCleanupPending,
            ));
        }
        Ok(WalDeletionOutcome::Complete(residue))
    }

    /// W6 and W7: erase the archive keyspace, then the account's media, then
    /// record the durable physical completion. Split out of [`Self::drive`] so
    /// a re-entry that already holds a durable completion can skip it whole.
    #[allow(clippy::too_many_arguments)]
    async fn erase_and_complete(
        &self,
        control: &Arc<ControlStore>,
        store: &Store,
        user_id: &str,
        principal: &DeletionPrincipal,
        runtime: &dyn ArchiveDeletionRuntime,
        session: DeletionSession,
        seal: DeletionInventorySeal,
        media_keys: &[String],
    ) -> Result<CompletionOutcome> {
        let witness = runtime.witness();
        let credential = principal.credential().map_err(map_witness)?;
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
                witness.as_deletion_witness(),
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
                return Ok(CompletionOutcome::Pending(WalDeletionStage::DrainPending {
                    hard_delete_time: None,
                }))
            }
            Err(crate::archive_v3_deletion::ArchiveDeletionError::InventoryLimit) => {
                return Ok(CompletionOutcome::Pending(WalDeletionStage::ManualRequired))
            }
            Err(_) => return Ok(CompletionOutcome::Pending(WalDeletionStage::ErasurePending)),
        };

        // ── W7 MEDIA EXECUTION ──────────────────────────────────────────────
        // Gated on the archive receipt. Media keys are outside the archive
        // prefix, so they are erased by this control-side lane rather than
        // being smuggled into the driver's inventory — which would have meant
        // relaxing the driver's per-entry archive-prefix bound.
        match store
            .delete_wal_authoritative_media(user_id, media_keys)
            .await
        {
            Ok(()) => {}
            Err(EnclaveError::DeletionPending(pending))
                if pending.reason == DeletionPendingReason::SoftDeleteRetention =>
            {
                return Ok(CompletionOutcome::Pending(WalDeletionStage::DrainPending {
                    hard_delete_time: pending.hard_delete_time,
                }))
            }
            Err(_) => {
                return Ok(CompletionOutcome::Pending(
                    WalDeletionStage::MediaErasurePending,
                ))
            }
        }

        // Both keyspaces are now proven absent, so the drain receipt can be
        // made durable. From here on a re-entry adopts this completion instead
        // of re-proving it.
        match control.mark_archive_physical_complete(receipt).await {
            Ok(completion) => Ok(CompletionOutcome::Complete(completion)),
            Err(_) => Ok(CompletionOutcome::Pending(
                WalDeletionStage::ControlCleanupPending,
            )),
        }
    }

    /// W5. Produce the inventory this pass will act on.
    ///
    /// **Re-entry comes first, and it does not re-freeze.** The freeze
    /// compare-and-swap advances only from `reserved | objects_prepared |
    /// witness_prepared | witnessed` and re-adopts only `deletion_frozen`, so
    /// once W5 has sealed (`inventory_sealed`) or the tail has completed
    /// (`physical_complete`) it can only ever return `Conflict`. Widening that
    /// CAS would be worse than useless: after W6 the key registries are
    /// destroyed, so `runtime.ciphers()` below would fail and park the account
    /// at `ManualRequired` with its data already gone. The durable seal is
    /// instead rebuilt from the anchor and its retained exact page-reference
    /// chain — which is also why this arm reaches neither `ciphers()` nor the
    /// reachability walk. Re-entry is the *designed* path here, not just the
    /// crash path: provider-drain waits, media erasure and every control
    /// cleanup rung all return to the reconciler and come back through here.
    async fn sealed_inventory(
        &self,
        control: &ControlStore,
        archive_id: ArchiveId,
        deletion_fence: crate::archive_v3::ObjectId,
        principal: &DeletionPrincipal,
        runtime: &dyn ArchiveDeletionRuntime,
    ) -> std::result::Result<LadderInventory, SealFailure> {
        match control
            .recover_archive_deletion_lifecycle(archive_id, deletion_fence)
            .await
        {
            Ok(Some(recovered)) => {
                return Ok(match recovered.physical_completion() {
                    Some(completion) => LadderInventory::PhysicallyComplete(completion),
                    None => LadderInventory::Sealed(recovered.seal()),
                })
            }
            // No seal yet: this is the first pass, so freeze and seal below.
            Ok(None) => {}
            // The anchor is durably sealed but its authority chain does not
            // reconstruct — a mismatched fence, a broken revision chain, an
            // unreadable page-reference chain. No retry can clear that, and
            // the freeze path is closed to this state, so surface it where an
            // operator will see it instead of pending forever.
            Err(_) => return Err(SealFailure::ManualRequired),
        }
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
        .map(LadderInventory::Sealed)
        .map_err(|error| match error {
            // A bound was exceeded, a name was inventoried twice, or the
            // control plane refused permanently: never truncate the inventory,
            // park it. `PermanentConflict` carries the control store's own
            // `Conflict` classification — the widened union's duplicate and
            // bound refusals, a conflicting inventory branch, unresolved
            // create work, a snapshot commitment that no longer recomputes.
            // None of those can settle after the tombstone, because settling
            // them needs the owner this deletion already revoked, so reporting
            // them as retryable would loop an operation nobody is paged for.
            InventoryCoordinatorError::Limit
            | InventoryCoordinatorError::DuplicateConflict
            | InventoryCoordinatorError::PermanentConflict => SealFailure::ManualRequired,
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

/// What W5 hands to the rest of the ladder: either an inventory seal this pass
/// must still act on, or the durable physical completion a previous pass
/// already earned, whose remaining work is control cleanup only.
enum LadderInventory {
    Sealed(DeletionInventorySeal),
    PhysicallyComplete(crate::archive_v3_lifecycle::DurablePhysicalCompletion),
}

/// The result of the destructive rungs: a durable completion, or the rung the
/// ladder stopped on.
enum CompletionOutcome {
    Complete(crate::archive_v3_lifecycle::DurablePhysicalCompletion),
    Pending(WalDeletionStage),
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

    use crate::{
        archive_v3::{
            ArchiveRoot, DatabaseEpoch, KeyEpoch, LogicalLocation, ObjectContext, ObjectId,
            ObjectKey, ObjectRole, VerifiedArchiveCipher, ARCHIVE_FORMAT_VERSION, SQLITE_PAGE_SIZE,
        },
        archive_v3_gcs::{
            ArchiveV3GcsTransport, GcsArchiveV3ClaimResult, GcsArchiveV3CreateResult,
            GcsArchiveV3DeleteResult, GcsArchiveV3Page, GcsArchiveV3TransportError,
        },
        archive_v3_lifecycle::{
            BootstrapAttemptId, BootstrapPlan, DurableInventoryPage, DurablePhysicalCompletion,
            ErasedInventoryPages, InventoryPage, InventoryPageReference, LifecycleError,
        },
        archive_v3_lifecycle_page_store::LifecyclePageAdmissionLedger,
        archive_v3_reachability::ExactReachabilityReadError,
        archive_v3_witness::{InMemoryWitness, RootCommitment, RootReference, WitnessBootstrap},
    };
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex,
        },
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

    // ── A real, fake-backed archive-v3 deletion runtime ─────────────────────
    //
    // W5 through W8 have no coverage at all without one: the lane's only other
    // factory panics on construction, so every existing test parks before the
    // seal. This fixture drives the REAL coordinator, the REAL witness FSM and
    // the REAL control-store lifecycle ladder against in-memory objects, which
    // is what makes the re-entry regressions below mean anything.

    const LADDER_DATABASE_EPOCH: DatabaseEpoch = DatabaseEpoch::from_bytes([0xd1; 16]);
    const LADDER_KEY_EPOCH: KeyEpoch = KeyEpoch::from_bytes([0x61; 16]);
    const LADDER_REGISTRY_OBJECT: ObjectId = ObjectId::from_bytes([0x66; 16]);
    const LADDER_ROOT_OBJECT: ObjectId = ObjectId::from_bytes([0xd3; 16]);
    const LADDER_PRINCIPAL_ROOT: [u8; 32] = [0x31; 32];

    /// Exact-name object map. There is deliberately no enumerate here, exactly
    /// as on the production seam.
    #[derive(Default)]
    struct GraphReader {
        objects: Mutex<BTreeMap<ObjectKey, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl ExactReachabilityReader for GraphReader {
        async fn read_exact(
            &self,
            key: &ObjectKey,
            _max_encoded_bytes: usize,
        ) -> std::result::Result<Option<Vec<u8>>, ExactReachabilityReadError> {
            Ok(self.objects.lock().unwrap().get(key).cloned())
        }
    }

    /// The page store's object side is in memory, but its *control* side is
    /// the real durable admission ledger: admit before the write, authenticate
    /// the exact readback, then reconcile. The seal refuses an unresolved
    /// admission set, so a fake that skipped this would never seal at all.
    struct InMemoryPages {
        control: Arc<ControlStore>,
        pages: Mutex<BTreeMap<u32, InventoryPage>>,
        /// Model a permanent control-plane refusal on the page-create path.
        refuse_creates: AtomicBool,
        /// Model one transient failure of the control-cleanup rung, which is
        /// how a deletion crashes *after* its completion is already durable.
        fail_erase_once: AtomicBool,
    }

    impl InMemoryPages {
        fn new(control: Arc<ControlStore>) -> Self {
            Self {
                control,
                pages: Mutex::new(BTreeMap::new()),
                refuse_creates: AtomicBool::new(false),
                fail_erase_once: AtomicBool::new(false),
            }
        }
    }

    fn durable(page: InventoryPage) -> DurableInventoryPage {
        let encoded = page.encoded().to_vec();
        DurableInventoryPage::from_exact_readback(page, &encoded).expect("page reads back exactly")
    }

    #[async_trait::async_trait]
    impl ArchiveLifecyclePageStore for InMemoryPages {
        async fn create_exact_page(
            &self,
            deletion_fence: crate::archive_v3::ObjectId,
            page: &InventoryPage,
        ) -> std::result::Result<DurableInventoryPage, LifecycleError> {
            if self.refuse_creates.load(Ordering::SeqCst) {
                return Err(LifecycleError::Conflict);
            }
            let reference = page.reference();
            let admission = self.control.admit_page_create(deletion_fence, page).await?;
            if admission.deletion_fence() != deletion_fence || admission.reference() != reference {
                return Err(LifecycleError::Corrupt);
            }
            {
                let mut pages = self.pages.lock().unwrap();
                match pages.get(&page.page_ordinal()) {
                    Some(existing) if existing != page => {
                        return Err(LifecycleError::ChainMismatch)
                    }
                    Some(_) => {}
                    None => {
                        pages.insert(page.page_ordinal(), page.clone());
                    }
                }
            }
            let durable = durable(page.clone());
            self.control
                .reconcile_page_created(admission, &durable)
                .await?;
            Ok(durable)
        }

        async fn read_exact_page(
            &self,
            _deletion_fence: crate::archive_v3::ObjectId,
            reference: InventoryPageReference,
        ) -> std::result::Result<DurableInventoryPage, LifecycleError> {
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
            completion: &DurablePhysicalCompletion,
            references: &[InventoryPageReference],
        ) -> std::result::Result<ErasedInventoryPages, LifecycleError> {
            if self.fail_erase_once.swap(false, Ordering::SeqCst) {
                return Err(LifecycleError::Unavailable);
            }
            // The real store freezes the admission set through control before
            // the first destructive call; mirror that ordering exactly.
            let _frozen = self
                .control
                .authorize_page_cleanup(*completion, references)
                .await?;
            let mut pages = self.pages.lock().unwrap();
            for reference in references {
                pages.remove(&reference.page_ordinal());
            }
            ErasedInventoryPages::from_exact_absence(completion, references)
        }
    }

    /// Exact-name archive transport. `drained` models provider soft-delete
    /// retention: until it expires, absence cannot be proven and the ladder
    /// must park on the drain rung and come back later.
    struct LadderTransport {
        drained: AtomicBool,
        deleted: Mutex<Vec<String>>,
    }

    impl LadderTransport {
        fn new(drained: bool) -> Self {
            Self {
                drained: AtomicBool::new(drained),
                deleted: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl ArchiveV3GcsTransport for LadderTransport {
        async fn claim_object_id(
            &self,
            _canonical_archive_prefix: &str,
            _object_id: ObjectId,
            _canonical_key: &str,
            _ciphertext_hash: [u8; 32],
        ) -> std::result::Result<GcsArchiveV3ClaimResult, GcsArchiveV3TransportError> {
            Ok(GcsArchiveV3ClaimResult::Reserved)
        }

        async fn mark_object_id_materialized(
            &self,
            _canonical_archive_prefix: &str,
            _object_id: ObjectId,
            _canonical_key: &str,
            _ciphertext_hash: [u8; 32],
        ) -> std::result::Result<(), GcsArchiveV3TransportError> {
            Ok(())
        }

        async fn create_if_absent(
            &self,
            _canonical_key: &str,
            _bytes: &[u8],
        ) -> std::result::Result<GcsArchiveV3CreateResult, GcsArchiveV3TransportError> {
            Ok(GcsArchiveV3CreateResult::Created)
        }

        async fn read_exact(
            &self,
            _canonical_key: &str,
            _max_bytes: usize,
        ) -> std::result::Result<Option<Vec<u8>>, GcsArchiveV3TransportError> {
            Ok(None)
        }

        async fn list_after(
            &self,
            _canonical_prefix: &str,
            _after: Option<&str>,
            _limit: usize,
        ) -> std::result::Result<GcsArchiveV3Page, GcsArchiveV3TransportError> {
            // Exact-name only. A deletion that enumerates is a defect, so make
            // it a hard failure rather than something a fake quietly allows.
            panic!("the deletion ladder must never enumerate the archive prefix");
        }

        async fn delete_all_generations_exact(
            &self,
            canonical_key: &str,
        ) -> std::result::Result<GcsArchiveV3DeleteResult, GcsArchiveV3TransportError> {
            self.deleted.lock().unwrap().push(canonical_key.to_owned());
            Ok(GcsArchiveV3DeleteResult::DeletedAllGenerations)
        }

        async fn verify_all_generations_absent_exact(
            &self,
            _canonical_key: &str,
        ) -> std::result::Result<bool, GcsArchiveV3TransportError> {
            Ok(self.drained.load(Ordering::SeqCst))
        }

        async fn delete_claim_all_generations_exact(
            &self,
            _canonical_archive_prefix: &str,
            _object_id: ObjectId,
        ) -> std::result::Result<GcsArchiveV3DeleteResult, GcsArchiveV3TransportError> {
            Ok(GcsArchiveV3DeleteResult::DeletedAllGenerations)
        }

        async fn verify_claim_all_generations_absent_exact(
            &self,
            _canonical_archive_prefix: &str,
            _object_id: ObjectId,
        ) -> std::result::Result<bool, GcsArchiveV3TransportError> {
            Ok(self.drained.load(Ordering::SeqCst))
        }
    }

    struct LadderRuntime {
        archive_id: ArchiveId,
        witness: Arc<InMemoryWitness>,
        reader: Arc<GraphReader>,
        pages: Arc<InMemoryPages>,
        transport: Arc<LadderTransport>,
        cipher_calls: AtomicUsize,
        /// Once the key registries are erased no cipher can ever be resolved
        /// again. A re-entry that still needs one is exactly the defect F1
        /// describes, so make it impossible to pass by accident.
        registries_erased: AtomicBool,
    }

    #[async_trait::async_trait]
    impl ArchiveDeletionRuntime for LadderRuntime {
        fn witness(&self) -> Arc<dyn DeletionLaneWitness> {
            Arc::clone(&self.witness) as Arc<dyn DeletionLaneWitness>
        }

        fn reader(&self) -> Arc<dyn ExactReachabilityReader> {
            Arc::clone(&self.reader) as Arc<dyn ExactReachabilityReader>
        }

        fn page_store(&self) -> Arc<dyn ArchiveLifecyclePageStore> {
            Arc::clone(&self.pages) as Arc<dyn ArchiveLifecyclePageStore>
        }

        fn transport(&self) -> Arc<dyn crate::archive_v3_gcs::ArchiveV3GcsTransport> {
            Arc::clone(&self.transport) as Arc<dyn crate::archive_v3_gcs::ArchiveV3GcsTransport>
        }

        async fn ciphers(&self) -> Result<(VerifiedArchiveCipher, Option<VerifiedArchiveCipher>)> {
            self.cipher_calls.fetch_add(1, Ordering::SeqCst);
            if self.registries_erased.load(Ordering::SeqCst) {
                return Err(EnclaveError::Store(
                    "the key registries this archive was encrypted under are gone".into(),
                ));
            }
            let (_registry, cipher, _wrapped) =
                crate::archive_v3_reachability::registry_binding_for_deletion_test(
                    self.archive_id,
                    LADDER_KEY_EPOCH,
                    LADDER_REGISTRY_OBJECT,
                )
                .await;
            Ok((cipher, None))
        }
    }

    struct LadderFactory {
        runtime: Arc<LadderRuntime>,
    }

    #[async_trait::async_trait]
    impl ArchiveDeletionRuntimeFactory for LadderFactory {
        async fn runtime_for(
            &self,
            _archive_id: ArchiveId,
        ) -> Result<Arc<dyn ArchiveDeletionRuntime>> {
            Ok(Arc::clone(&self.runtime) as Arc<dyn ArchiveDeletionRuntime>)
        }
    }

    struct Ladder {
        control: Arc<ControlStore>,
        store: Store,
        lane: WalDeletionLane,
        runtime: Arc<LadderRuntime>,
        user_id: String,
        archive_id: ArchiveId,
    }

    /// Build one WAL-authoritative account that is tombstoned, has a frozen
    /// (empty) media inventory, and whose lifecycle anchor, witness record and
    /// object graph all agree — the state the reconciler hands to `drive`.
    async fn ladder(user_id: &str, drained: bool) -> Ladder {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let (user_id, archive_id) = wal_account(&control, user_id).await;

        // One registry, one root, nothing else reachable: the smallest graph
        // that still exercises a real walk, a real union and a real page plan.
        let (registry, cipher, wrapped_registry) =
            crate::archive_v3_reachability::registry_binding_for_deletion_test(
                archive_id,
                LADDER_KEY_EPOCH,
                LADDER_REGISTRY_OBJECT,
            )
            .await;
        let root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: LADDER_DATABASE_EPOCH,
            key_epoch: LADDER_KEY_EPOCH,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: 0,
            logical_file_length: 0,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        let root_context = ObjectContext::new(
            archive_id,
            LADDER_DATABASE_EPOCH,
            LADDER_KEY_EPOCH,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            LADDER_ROOT_OBJECT,
            None,
        )
        .expect("root context");
        let root_envelope = cipher
            .seal(&root_context, &root.encode().expect("root encodes"))
            .expect("root seals");
        let reader = Arc::new(GraphReader::default());
        reader
            .objects
            .lock()
            .unwrap()
            .insert(root_context.object_key(), root_envelope.encode());

        // The lifecycle create-ahead rows name the same two objects with the
        // same hashes, so the union deduplicates instead of conflicting.
        control
            .seed_archive_lifecycle_for_test(
                BootstrapPlan::new(
                    archive_id,
                    BootstrapAttemptId::from_bytes([0xd4; 16]).expect("attempt id"),
                    LADDER_DATABASE_EPOCH,
                    LADDER_KEY_EPOCH,
                    LADDER_REGISTRY_OBJECT,
                    LADDER_ROOT_OBJECT,
                )
                .expect("bootstrap plan"),
                wrapped_registry,
                root_envelope.encode(),
            )
            .await
            .expect("lifecycle anchor seeds");

        let principal_key = Arc::new(
            DeletionPrincipalKey::derive_from_control_root(&LADDER_PRINCIPAL_ROOT)
                .expect("principal key derives"),
        );
        // The witness accepts the production deletion authority derived from
        // the same control root the lane holds — not a stub that says yes.
        let authenticator = DeletionPrincipal::new(
            Arc::clone(&principal_key),
            archive_id,
            ObjectId::from_bytes([0xd5; 16]),
        )
        .expect("principal")
        .authenticator();
        let witness = Arc::new(InMemoryWitness::with_deletion_authenticator_for_test(
            authenticator,
        ));
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                LADDER_DATABASE_EPOCH,
                RootCommitment::genesis(
                    LADDER_DATABASE_EPOCH,
                    LADDER_KEY_EPOCH,
                    RootReference::new(0, LADDER_ROOT_OBJECT, root_envelope.hash()),
                ),
                registry,
            ))
            .expect("witness bootstraps");

        control.begin_user_deletion(&user_id).await.unwrap();
        control
            .freeze_media_deletion_inventory(archive_id, &[])
            .await
            .unwrap();

        let runtime = Arc::new(LadderRuntime {
            archive_id,
            witness,
            reader,
            pages: Arc::new(InMemoryPages::new(Arc::clone(&control))),
            transport: Arc::new(LadderTransport::new(drained)),
            cipher_calls: AtomicUsize::new(0),
            registries_erased: AtomicBool::new(false),
        });
        let lane = WalDeletionLane::new(
            principal_key,
            Arc::new(LadderFactory {
                runtime: Arc::clone(&runtime),
            }),
        );
        Ladder {
            control,
            store,
            lane,
            runtime,
            user_id,
            archive_id,
        }
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
    /// be recomputed afterwards. If it is missing once the archive is
    /// tombstoned, the ladder must stop *before* anything destructive rather
    /// than erase the archive and leave the account's media behind.
    ///
    /// Which rung it stops on is the whole point. With no serving authority
    /// installed — every account that reached `deleting` on an image with no
    /// lane, and every account after a restart — nothing can ever mint the
    /// inventory, so this is `ManualRequired`. Reporting it as a retryable
    /// media pend would loop the account at status `pending` forever with no
    /// operator ever paged: an unerasable account that looks like progress.
    #[tokio::test]
    async fn a_media_inventory_nothing_can_mint_parks_for_an_operator() {
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
        assert!(!store.is_wal_authoritative(&user_id));
        let outcome = lane().drive(&control, &store, &user_id).await.unwrap();
        assert!(
            matches!(
                outcome,
                WalDeletionOutcome::Pending(WalDeletionStage::ManualRequired)
            ),
            "an inventory nothing can mint must not present as a retryable rung: {outcome:?}"
        );
    }

    /// The same missing inventory is genuinely retryable while this process
    /// still holds the account's selection: the pre-tombstone freeze rung can
    /// still read the archive, so the next reconciler pass mints it.
    #[tokio::test]
    async fn a_media_inventory_the_freeze_rung_can_still_mint_stays_retryable() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let (user_id, archive_id) = wal_account(&control, "lane-media-selected").await;
        store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    &user_id, archive_id,
                ),
            )
            .unwrap();
        control.begin_user_deletion(&user_id).await.unwrap();
        assert!(store.is_wal_authoritative(&user_id));
        assert!(matches!(
            lane().drive(&control, &store, &user_id).await.unwrap(),
            WalDeletionOutcome::Pending(WalDeletionStage::MediaInventoryPending)
        ));
    }

    /// The frozen inventory has to come from the account's own serving
    /// authority. `wal_authoritative_read` falls back to the legacy per-user
    /// store for an unselected account, and for a WAL-authoritative account
    /// those rows are not the answer to "what media was ever named" — a
    /// deletion that froze them would later present them as an exact-name
    /// proof of erasure. The freeze must refuse instead of inventing one.
    #[tokio::test]
    async fn an_unselected_account_never_freezes_an_inventory_from_the_legacy_store() {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let store = Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new()));
        let (user_id, archive_id) = wal_account(&control, "lane-unselected-freeze").await;
        assert!(!store.is_wal_authoritative(&user_id));
        assert!(lane()
            .freeze_media_inventory(&control, &store, &user_id)
            .await
            .is_err());
        assert!(control
            .frozen_media_deletion_inventory(archive_id)
            .await
            .unwrap()
            .is_none());
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

    /// F1. The ladder must survive its own designed multi-pass shape.
    ///
    /// Pass 1 seals the inventory and then parks on the provider drain, which
    /// is the *expected* outcome while GCS soft-delete retention is unexpired.
    /// Pass 2 must adopt that durable seal and finish. Before the recovery
    /// dispatch existed, pass 2 re-entered the freeze compare-and-swap, which
    /// cannot leave `inventory_sealed`, and every later pass reported
    /// `InventoryPending` on a 30s retry forever.
    #[tokio::test]
    async fn a_sealed_ladder_resumes_across_passes_instead_of_pending_on_the_inventory() {
        let fixture = ladder("lane-resumes-after-seal", false).await;
        let first = fixture
            .lane
            .drive(&fixture.control, &fixture.store, &fixture.user_id)
            .await
            .unwrap();
        assert!(
            matches!(
                first,
                WalDeletionOutcome::Pending(WalDeletionStage::DrainPending { .. })
            ),
            "pass 1 must seal and then park on the provider drain: {first:?}"
        );
        // The seal is durable now, so the freeze CAS can never match again.
        assert!(fixture
            .control
            .recover_archive_deletion_lifecycle(
                fixture.archive_id,
                fixture
                    .control
                    .archive_deletion_fence(fixture.archive_id)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .await
            .unwrap()
            .is_some());

        // Retention expires. Nothing else changes — in particular the archive
        // is never re-walked, so the resumed pass must not need a cipher.
        fixture
            .runtime
            .transport
            .drained
            .store(true, Ordering::SeqCst);
        let ciphers_before = fixture.runtime.cipher_calls.load(Ordering::SeqCst);
        fixture
            .runtime
            .registries_erased
            .store(true, Ordering::SeqCst);

        let outcome = fixture
            .lane
            .drive(&fixture.control, &fixture.store, &fixture.user_id)
            .await
            .unwrap();
        assert!(
            !matches!(
                outcome,
                WalDeletionOutcome::Pending(WalDeletionStage::InventoryPending)
            ),
            "a resumed pass must never report the inventory rung: {outcome:?}"
        );
        assert!(matches!(outcome, WalDeletionOutcome::Complete(_)));
        assert_eq!(
            fixture.runtime.cipher_calls.load(Ordering::SeqCst),
            ciphers_before,
            "the recovery arm must skip ciphers() and the reachability walk"
        );
        assert!(fixture
            .control
            .wal_deletion_already_complete(fixture.archive_id)
            .await
            .unwrap());
    }

    /// F1, tail half. A crash between the durable physical completion and the
    /// control cleanup must also resume: the completion is already proof that
    /// every inventoried name is absent, and the sealed pages it is about to
    /// erase may already be gone, so the resumed pass adopts the completion
    /// rather than re-running the driver over a half-erased inventory.
    #[tokio::test]
    async fn a_completion_that_crashed_before_control_cleanup_resumes_from_the_anchor() {
        let fixture = ladder("lane-resumes-after-completion", true).await;
        fixture
            .runtime
            .pages
            .fail_erase_once
            .store(true, Ordering::SeqCst);
        let first = fixture
            .lane
            .drive(&fixture.control, &fixture.store, &fixture.user_id)
            .await
            .unwrap();
        assert!(
            matches!(
                first,
                WalDeletionOutcome::Pending(WalDeletionStage::ControlCleanupPending)
            ),
            "pass 1 must record its completion and then stop on cleanup: {first:?}"
        );
        assert!(!fixture
            .control
            .wal_deletion_already_complete(fixture.archive_id)
            .await
            .unwrap());

        // Everything the archive was encrypted under is gone by now.
        fixture
            .runtime
            .registries_erased
            .store(true, Ordering::SeqCst);
        let deleted_before = fixture.runtime.transport.deleted.lock().unwrap().len();
        let resumed = fixture
            .lane
            .drive(&fixture.control, &fixture.store, &fixture.user_id)
            .await
            .unwrap();
        assert!(
            matches!(resumed, WalDeletionOutcome::Complete(_)),
            "a durable completion must be adopted, not re-proven: {resumed:?}"
        );
        assert_eq!(
            fixture.runtime.transport.deleted.lock().unwrap().len(),
            deleted_before,
            "an adopted completion must not re-issue provider deletions"
        );
    }

    /// F4. The residue disclosure is written in the same transaction as the
    /// teardown that deletes the lane's own routing predicate, so a crash
    /// immediately after completion cannot leave an account that took the
    /// archive-v3 lane with no record of what survived.
    #[tokio::test]
    async fn completion_durably_discloses_residue_without_a_second_write() {
        let fixture = ladder("lane-discloses-on-teardown", true).await;
        assert!(matches!(
            fixture
                .lane
                .drive(&fixture.control, &fixture.store, &fixture.user_id)
                .await
                .unwrap(),
            WalDeletionOutcome::Complete(_)
        ));
        // `drive` is called here directly, so nothing but the teardown
        // transaction could have written this row.
        assert_eq!(
            fixture
                .control
                .deletion_residue_disclosure(&fixture.user_id)
                .await
                .unwrap()
                .expect("the teardown transaction must have disclosed the residue"),
            vec![
                "r1_staging_orphans".to_string(),
                "r2_consumed_superseded_attempts".to_string(),
            ]
        );
    }

    /// F3 at the control boundary. The deletion inventory control plane must
    /// distinguish a permanent refusal from an unavailable store: everything
    /// it can refuse after the tombstone — a duplicate name, an exceeded
    /// bound, a conflicting branch, a snapshot whose commitment no longer
    /// recomputes — needs an owner that this deletion already revoked, so
    /// collapsing them into "unavailable" would loop the deletion forever.
    #[tokio::test]
    async fn the_deletion_inventory_control_distinguishes_permanent_conflicts() {
        let fixture = ladder("lane-inventory-conflict", true).await;
        let fence = fixture
            .control
            .archive_deletion_fence(fixture.archive_id)
            .await
            .unwrap()
            .unwrap();
        let error = DeletionInventoryControl::load_snapshot(
            fixture.control.as_ref(),
            fixture.archive_id,
            fence,
        )
        .await
        .expect_err("no frozen inventory snapshot exists on this anchor");
        assert_eq!(error, LifecycleError::Conflict);
        assert_eq!(
            InventoryCoordinatorError::from(error),
            InventoryCoordinatorError::PermanentConflict
        );
    }

    /// F3. A permanent control-plane refusal on the seal path must reach the
    /// one rung that is surfaced as `failed_retryable`. Reported as a
    /// retryable inventory pend it would loop every 30s forever with no
    /// operator ever paged — and the key material is deliberately still
    /// intact, which is precisely the class a human has to look at.
    #[tokio::test]
    async fn a_permanent_seal_conflict_parks_for_an_operator_instead_of_retrying() {
        let fixture = ladder("lane-permanent-seal-conflict", true).await;
        fixture
            .runtime
            .pages
            .refuse_creates
            .store(true, Ordering::SeqCst);
        let outcome = fixture
            .lane
            .drive(&fixture.control, &fixture.store, &fixture.user_id)
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                WalDeletionOutcome::Pending(WalDeletionStage::ManualRequired)
            ),
            "a permanent control refusal must reach the operator surface: {outcome:?}"
        );
        assert!(
            fixture.runtime.transport.deleted.lock().unwrap().is_empty(),
            "nothing may be deleted when the inventory could not be sealed"
        );
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

    /// Residue is disclosed, not dropped. The two crypto-erased archive upload
    /// classes remain named; the retained media write-intent closes R3.
    #[test]
    fn completion_discloses_only_the_surviving_residue_classes() {
        assert_eq!(
            ResidueDisclosure::current().flags(),
            vec!["r1_staging_orphans", "r2_consumed_superseded_attempts",]
        );
        assert!(!ResidueDisclosure::current().media_put_without_record);
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
