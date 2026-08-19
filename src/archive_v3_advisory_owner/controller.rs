//! Inactive Phase-1 single-archive advisory canary controller.
//!
//! Orchestrates the restart-safe, cancellation-owned Phase-1 advisory canary pipeline:
//! 1. Pre-import window intent registration and preflight memory eligibility under
//!    the exact acquired Store maintenance transition (`Phase1TmpfsPolicyV1`).
//! 2. Maintenance import execution to reach verified `ShadowWal`.
//! 3. Continuous window observer validation and three-root authorization verification.
//! 4. Advisory owner reservation, marker deletion, local admission resumption,
//!    comparison settlement, and capture retirement.
//! 5. Bounded, commitment-only asynchronous telemetry with panic/overflow isolation.
//! 6. Orderly abort handling across pre-owner, post-release, and post-resume boundaries.
//!
//! Privacy Invariants:
//! - Content-free telemetry is emitted across all lifecycle transitions using domain-separated hashes.
//! - Raw user identifiers, plaintext databases, queries, and cryptographic keys
//!   are never logged, formatted, or exposed.

use std::{sync::Arc, time::Instant};

use sha2::{Digest, Sha256};

use super::{
    telemetry::{Phase1CanaryTelemetrySink, Phase1TelemetryRecorder},
    window::{HeldPhase1Window, Phase1WindowObserver},
    AdvisoryAbortReason, AdvisoryOwnerError, LocallyResumedSingleArchiveAdvisoryOwner, Result,
    SingleArchiveAdvisoryOwner, VerifiedAdvisoryCanaryAuthorization,
};
use crate::{
    archive_v3::ArchiveId,
    archive_v3_maintenance_import::{
        MaintenanceImportOperationId, MaintenanceImportPersistence,
        SingleArchiveMaintenanceImporter,
    },
    archive_v3_shadow_runtime::SealedSingleArchiveWalRuntime,
    cp::control_store::{AdvisoryControllerRunRecord, AdvisoryControllerRunStage, ControlStore},
    store::Store,
};

/// Maximum allowable total tmpfs memory for Phase-1 canary (4 GiB).
pub(super) const MAX_PHASE1_TMPFS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Worst-case WAL allowance for Phase-1 canary (64 MiB).
pub(super) const WORST_CASE_WAL_BYTES: u64 = 64 * 1024 * 1024;
/// SQLite scratch memory overhead allowance (64 MiB).
pub(super) const SQLITE_SCRATCH_BYTES: u64 = 64 * 1024 * 1024;
/// Model working set memory allowance (256 MiB).
pub(super) const MODEL_WORKING_SET_BYTES: u64 = 256 * 1024 * 1024;

/// Non-configurable Phase-1 tmpfs memory eligibility policy.
pub(super) struct Phase1TmpfsPolicyV1;

impl Phase1TmpfsPolicyV1 {
    /// Policy format version.
    pub(super) const POLICY_VERSION: u32 = 1;
    pub(super) const DB_COPY_MULTIPLIER: u64 = 2;
    pub(super) const VM_FRACTION_DENOMINATOR: u64 = 4;

    /// Evaluate strict tmpfs memory bounds with checked arithmetic:
    /// total = (database * DB_COPY_MULTIPLIER) + worst_case_wal + sqlite_scratch + model_working_set
    /// total < 4 GiB (strict inequality)
    /// total * VM_FRACTION_DENOMINATOR < authenticated_vm_bytes (strict < 25% of measured VM memory)
    pub(super) fn evaluate(database_bytes: u64, vm_bytes: u64) -> Result<u64> {
        if database_bytes == 0 || vm_bytes == 0 {
            return Err(AdvisoryOwnerError::Conflict);
        }

        // Account for simultaneous database copies (legacy + recovered staging)
        let db_copies = database_bytes
            .checked_mul(Self::DB_COPY_MULTIPLIER)
            .ok_or(AdvisoryOwnerError::Conflict)?;

        let total = db_copies
            .checked_add(WORST_CASE_WAL_BYTES)
            .and_then(|t| t.checked_add(SQLITE_SCRATCH_BYTES))
            .and_then(|t| t.checked_add(MODEL_WORKING_SET_BYTES))
            .ok_or(AdvisoryOwnerError::Conflict)?;

        if total >= MAX_PHASE1_TMPFS_BYTES {
            return Err(AdvisoryOwnerError::Conflict);
        }

        let quad_total = total
            .checked_mul(Self::VM_FRACTION_DENOMINATOR)
            .ok_or(AdvisoryOwnerError::Conflict)?;

        if quad_total >= vm_bytes {
            return Err(AdvisoryOwnerError::Conflict);
        }

        Ok(total)
    }

    /// Compute domain-separated cryptographic commitment to the policy parameters.
    pub(super) fn policy_commitment() -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"kioku/archive-v3/phase1-tmpfs-policy/v1\0");
        hasher.update(Self::POLICY_VERSION.to_be_bytes());
        hasher.update(Self::DB_COPY_MULTIPLIER.to_be_bytes());
        hasher.update(MAX_PHASE1_TMPFS_BYTES.to_be_bytes());
        hasher.update(WORST_CASE_WAL_BYTES.to_be_bytes());
        hasher.update(SQLITE_SCRATCH_BYTES.to_be_bytes());
        hasher.update(MODEL_WORKING_SET_BYTES.to_be_bytes());
        hasher.update(Self::VM_FRACTION_DENOMINATOR.to_be_bytes());
        hasher.finalize().into()
    }
}

/// Provider for authenticated VM physical memory measurement.
#[async_trait::async_trait]
pub(super) trait TrustedVmMemoryProvider: Send + Sync {
    async fn authenticated_vm_bytes(&self) -> Result<u64>;
}

/// Production VM memory provider reading MemTotal from /proc/meminfo inside the
/// SEV-protected guest. The measurement is bound to the signed runtime admission's
/// expectations by the caller; a missing or malformed /proc/meminfo (any
/// non-Linux host) fails closed rather than guessing.
pub(crate) struct ProcMeminfoVmMemoryProvider;

#[async_trait::async_trait]
impl TrustedVmMemoryProvider for ProcMeminfoVmMemoryProvider {
    async fn authenticated_vm_bytes(&self) -> Result<u64> {
        let raw = tokio::fs::read_to_string("/proc/meminfo")
            .await
            .map_err(|_| AdvisoryOwnerError::Persistence)?;
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kib: u64 = rest
                    .trim()
                    .trim_end_matches("kB")
                    .trim()
                    .parse()
                    .map_err(|_| AdvisoryOwnerError::Corrupt)?;
                if kib == 0 {
                    return Err(AdvisoryOwnerError::Corrupt);
                }
                return kib.checked_mul(1024).ok_or(AdvisoryOwnerError::Corrupt);
            }
        }
        Err(AdvisoryOwnerError::Corrupt)
    }
}

/// Test VM memory provider returning a configured byte capacity.
#[cfg(test)]
pub(super) struct TestVmMemoryProvider {
    bytes: u64,
}

#[cfg(test)]
impl TestVmMemoryProvider {
    pub(super) fn new(bytes: u64) -> Self {
        Self { bytes }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl TrustedVmMemoryProvider for TestVmMemoryProvider {
    async fn authenticated_vm_bytes(&self) -> Result<u64> {
        Ok(self.bytes)
    }
}

/// Restart-safe Phase-1 advisory canary controller.
pub(super) struct SingleArchivePhase1AdvisoryController {
    control: Arc<ControlStore>,
    store: Arc<Store>,
    window_observer: Arc<dyn Phase1WindowObserver>,
    memory_provider: Arc<dyn TrustedVmMemoryProvider>,
    telemetry: Phase1TelemetryRecorder,
}

/// Type alias for 16-byte advisory controller run identity.
pub(super) type AdvisoryRunId = [u8; 16];

impl SingleArchivePhase1AdvisoryController {
    pub(super) fn new(
        control: Arc<ControlStore>,
        store: Arc<Store>,
        window_observer: Arc<dyn Phase1WindowObserver>,
        memory_provider: Arc<dyn TrustedVmMemoryProvider>,
        telemetry_sink: Option<Arc<dyn Phase1CanaryTelemetrySink>>,
    ) -> Self {
        Self {
            control,
            store,
            window_observer,
            memory_provider,
            telemetry: Phase1TelemetryRecorder::new(telemetry_sink),
        }
    }

    pub(super) fn telemetry(&self) -> &Phase1TelemetryRecorder {
        &self.telemetry
    }

    /// Execute the complete, restart-safe Phase-1 advisory canary lifecycle inside an owned task.
    pub(super) async fn execute_canary_run(
        self: Arc<Self>,
        run_id: AdvisoryRunId,
        user_id: &str,
        runtime: SealedSingleArchiveWalRuntime,
        held_window: HeldPhase1Window,
        authorization: Option<VerifiedAdvisoryCanaryAuthorization>,
    ) -> Result<AdvisoryControllerRunRecord> {
        let user_id = user_id.to_string();
        let handle = tokio::spawn(async move {
            let (operation_id, resumed, held_window) = self
                .execute_canary_admission(run_id, &user_id, runtime, held_window, authorization)
                .await?;
            self.settle_canary_admission(operation_id, resumed, held_window)
                .await
        });

        handle.await.map_err(|_| AdvisoryOwnerError::Conflict)?
    }

    /// Progress through preparation, preflight memory eligibility, maintenance import,
    /// canary authorization, and resume local SQLite VFS capture admission under continuous
    /// window revalidation.
    pub(super) async fn execute_canary_admission(
        &self,
        run_id: AdvisoryRunId,
        user_id: &str,
        runtime: SealedSingleArchiveWalRuntime,
        held_window: HeldPhase1Window,
        authorization: Option<VerifiedAdvisoryCanaryAuthorization>,
    ) -> Result<(
        MaintenanceImportOperationId,
        LocallyResumedSingleArchiveAdvisoryOwner,
        HeldPhase1Window,
    )> {
        let plan = self
            .control
            .prepare_archive_v3_maintenance_import(user_id)
            .await
            .map_err(|_| AdvisoryOwnerError::Conflict)?;

        let archive_id = plan.plan_archive_id();
        let operation_id = plan.plan_operation_id();
        let plan_fence_authority = plan.fence_authority().to_string();

        let run_record = self
            .control
            .prepare_advisory_controller_run(
                run_id,
                user_id,
                archive_id,
                operation_id,
                held_window.maintenance_window_id(),
                held_window.intent_commitment(),
            )
            .await
            .map_err(|_| AdvisoryOwnerError::Conflict)?;

        if run_record.stage != AdvisoryControllerRunStage::Prepared {
            let _ = self.reconcile_retained_run(user_id, operation_id).await?;
            return Err(AdvisoryOwnerError::Conflict);
        }

        // Step 1: Pre-import window validation and preflight memory check BEFORE running import!
        let proof = self.window_observer.revalidate_window(&held_window).await?;
        held_window.verify_revalidation_proof(&proof)?;

        // Construct maintenance importer
        let importer = runtime
            .into_advisory_shadow_importer(plan, Arc::clone(&self.control), Arc::clone(&self.store))
            .map_err(|_| AdvisoryOwnerError::Conflict)?;

        let (database_bytes, preflighted) = match importer.preflight().await {
            Ok(res) => res,
            Err(_) => {
                let _ = self
                    .control
                    .advance_advisory_controller_aborted(operation_id, "preflight_failed")
                    .await;
                self.telemetry.emit_aborted(
                    *operation_id.as_bytes(),
                    "preflight",
                    "preflight_failed",
                );
                return Err(AdvisoryOwnerError::Conflict);
            }
        };

        let vm_bytes = self.memory_provider.authenticated_vm_bytes().await?;
        let total_tmpfs_bytes = match Phase1TmpfsPolicyV1::evaluate(database_bytes, vm_bytes) {
            Ok(total) => total,
            Err(e) => {
                let _ = preflighted.abort_pre_owner().await;
                let _ = self
                    .control
                    .advance_advisory_controller_aborted(operation_id, "tmpfs_policy_ineligible")
                    .await;
                self.telemetry.emit_aborted(
                    *operation_id.as_bytes(),
                    "preflight",
                    "tmpfs_policy_ineligible",
                );
                return Err(e);
            }
        };

        let _ = self
            .control
            .advance_advisory_controller_eligible(
                operation_id,
                database_bytes,
                total_tmpfs_bytes,
                vm_bytes,
            )
            .await
            .map_err(|_| AdvisoryOwnerError::Conflict)?;

        // Step 2: Revalidate window immediately before import
        let proof = self.window_observer.revalidate_window(&held_window).await;
        if let Err(e) = proof.and_then(|p| held_window.verify_revalidation_proof(&p)) {
            let _ = preflighted.abort_pre_owner().await;
            let _ = self
                .control
                .advance_advisory_controller_aborted(operation_id, "window_lost")
                .await;
            self.telemetry
                .emit_aborted(*operation_id.as_bytes(), "pre_import", "window_lost");
            return Err(e);
        }

        let start_import = Instant::now();
        let handoff = match preflighted.run().await {
            Ok(h) => h,
            Err(_e) => {
                let _ = self
                    .control
                    .advance_advisory_controller_aborted(operation_id, "import_failed")
                    .await;
                self.telemetry
                    .emit_aborted(*operation_id.as_bytes(), "import", "import_failed");
                return Err(AdvisoryOwnerError::Publication);
            }
        };

        let _ = self
            .control
            .advance_advisory_controller_imported(operation_id)
            .await
            .map_err(|_| AdvisoryOwnerError::Conflict)?;

        self.telemetry
            .emit_maintenance_import_completed(*operation_id.as_bytes(), start_import.elapsed());

        // Step 3: Revalidate window before authorization
        let proof = self.window_observer.revalidate_window(&held_window).await;
        if let Err(e) = proof.and_then(|p| held_window.verify_revalidation_proof(&p)) {
            let _ = self
                .abort_pre_owner(user_id, archive_id, operation_id, &plan_fence_authority)
                .await;
            return Err(e);
        }

        let (scope_id, operator_statement_commitment, release_image_digest, canary) =
            match authorization {
                Some(ref auth) => {
                    if let Err(e) = held_window.verify_matches_authorization(auth) {
                        let _ = self
                            .abort_pre_owner(
                                user_id,
                                archive_id,
                                operation_id,
                                &plan_fence_authority,
                            )
                            .await;
                        return Err(e);
                    }
                    let canary = match self
                        .control
                        .authorize_verified_advisory_canary(auth, handoff.test_terminal_witness())
                        .await
                    {
                        Ok(c) => c,
                        Err(_) => {
                            let _ = self
                                .abort_pre_owner(
                                    user_id,
                                    archive_id,
                                    operation_id,
                                    &plan_fence_authority,
                                )
                                .await;
                            return Err(AdvisoryOwnerError::Conflict);
                        }
                    };
                    (
                        canary.scope_id(),
                        canary.operator_statement_commitment(),
                        canary.release_image_digest(),
                        canary,
                    )
                }
                None => {
                    #[cfg(test)]
                    {
                        let canary = match self
                            .control
                            .authorize_advisory_canary_for_test(
                                operation_id,
                                handoff.test_terminal_witness(),
                                [0xaa; 32],
                                [0xbb; 32],
                            )
                            .await
                        {
                            Ok(c) => c,
                            Err(_) => {
                                let _ = self
                                    .abort_pre_owner(
                                        user_id,
                                        archive_id,
                                        operation_id,
                                        &plan_fence_authority,
                                    )
                                    .await;
                                return Err(AdvisoryOwnerError::Conflict);
                            }
                        };
                        (
                            canary.scope_id(),
                            canary.operator_statement_commitment(),
                            canary.release_image_digest(),
                            canary,
                        )
                    }
                    #[cfg(not(test))]
                    {
                        let _ = self
                            .abort_pre_owner(
                                user_id,
                                archive_id,
                                operation_id,
                                &plan_fence_authority,
                            )
                            .await;
                        return Err(AdvisoryOwnerError::Conflict);
                    }
                }
            };

        let _ = self
            .control
            .advance_advisory_controller_authorized(operation_id, scope_id)
            .await
            .map_err(|_| AdvisoryOwnerError::Conflict)?;

        self.telemetry.emit_preflight_verified(
            scope_id,
            held_window.maintenance_window_id(),
            operator_statement_commitment,
            release_image_digest,
        );

        // Step 4: Revalidate window immediately before owner start & release
        let proof = self.window_observer.revalidate_window(&held_window).await;
        if let Err(e) = proof.and_then(|p| held_window.verify_revalidation_proof(&p)) {
            let _ = self
                .abort_pre_owner(user_id, archive_id, operation_id, &plan_fence_authority)
                .await;
            return Err(e);
        }

        let owner = match SingleArchiveAdvisoryOwner::start(handoff, canary).await {
            Ok(o) => o,
            Err(e) => {
                let _ = self
                    .abort_pre_owner(user_id, archive_id, operation_id, &plan_fence_authority)
                    .await;
                return Err(e);
            }
        };

        self.telemetry.emit_advisory_owner_bound(
            *owner.operation_id().as_bytes(),
            *owner.owner_id().as_bytes(),
            super::ADVISORY_OWNER_LEASE_TICKS,
        );

        // Revalidate window before releasing legacy fence (owner is now bound!)
        let proof = self.window_observer.revalidate_window(&held_window).await;
        if let Err(e) = proof.and_then(|p| held_window.verify_revalidation_proof(&p)) {
            let _ = self
                .control
                .advance_advisory_controller_manual_required(operation_id, "window_lost")
                .await;
            self.telemetry.emit_aborted(
                *operation_id.as_bytes(),
                "bound",
                "window_lost_manual_required",
            );
            return Err(e);
        }

        let released = match owner.release_legacy_fence().await {
            Ok(r) => r,
            Err(e) => {
                let _ = self
                    .control
                    .advance_advisory_controller_manual_required(operation_id, "release_failed")
                    .await;
                self.telemetry.emit_aborted(
                    *operation_id.as_bytes(),
                    "bound",
                    "release_failed_manual_required",
                );
                return Err(e);
            }
        };

        let marker_gen = if released.marker_generation() > 0 {
            Some(released.marker_generation() as u64)
        } else {
            None
        };
        self.telemetry
            .emit_legacy_fence_released(*released.operation_id().as_bytes(), marker_gen);

        // Step 5: Revalidate window before resuming local admission
        let proof = self.window_observer.revalidate_window(&held_window).await;
        if let Err(e) = proof.and_then(|p| held_window.verify_revalidation_proof(&p)) {
            let _ = released
                .abort_before_local_resume(AdvisoryAbortReason::StopRequested)
                .await;
            let _ = self
                .control
                .advance_advisory_controller_aborted(operation_id, "window_lost")
                .await;
            self.telemetry
                .emit_aborted(*operation_id.as_bytes(), "released", "window_lost");
            return Err(e);
        }

        let resumed = match released.resume_local_admission().await {
            Ok(r) => r,
            Err(e) => {
                let _ = self
                    .control
                    .advance_advisory_controller_aborted(operation_id, "resume_failed")
                    .await;
                self.telemetry
                    .emit_aborted(*operation_id.as_bytes(), "released", "resume_failed");
                return Err(e);
            }
        };

        let owner_id = *resumed.owner_id().as_bytes();
        self.telemetry
            .emit_local_admission_resumed(*resumed.operation_id().as_bytes());

        let _ = self
            .control
            .advance_advisory_controller_owner_admitted(operation_id, owner_id)
            .await
            .map_err(|_| AdvisoryOwnerError::Conflict)?;

        Ok((operation_id, resumed, held_window))
    }

    /// Settle comparison for a locally resumed advisory owner or record abort on mismatch.
    pub(super) async fn settle_canary_admission(
        &self,
        operation_id: MaintenanceImportOperationId,
        resumed: LocallyResumedSingleArchiveAdvisoryOwner,
        held_window: HeldPhase1Window,
    ) -> Result<AdvisoryControllerRunRecord> {
        // Revalidate window before comparison settlement
        let proof = self.window_observer.revalidate_window(&held_window).await;
        if let Err(e) = proof.and_then(|p| held_window.verify_revalidation_proof(&p)) {
            let _ = resumed
                .abort_resumed(AdvisoryAbortReason::StopRequested)
                .await;
            let _ = self
                .control
                .advance_advisory_controller_aborted(operation_id, "window_lost")
                .await;
            self.telemetry
                .emit_aborted(*operation_id.as_bytes(), "resumed", "window_lost");
            return Err(e);
        }

        let start_comparison = Instant::now();
        match resumed.settle_comparison().await? {
            super::AdvisorySettlementOutcome::Settled(settlement) => {
                let evidence_commitment = settlement.evidence_commitment();
                let run_record = self
                    .control
                    .advance_advisory_controller_retired(operation_id, evidence_commitment)
                    .await
                    .map_err(|_| AdvisoryOwnerError::Conflict)?;

                self.telemetry.emit_comparison_settled(
                    *settlement.operation_id().as_bytes(),
                    start_comparison.elapsed(),
                    evidence_commitment,
                );
                self.telemetry
                    .emit_capture_retired(*settlement.operation_id().as_bytes());

                Ok(run_record)
            }
            super::AdvisorySettlementOutcome::Aborted(aborted) => {
                let reason_str = match aborted.reason() {
                    AdvisoryAbortReason::ComparisonMismatch => "comparison_mismatch",
                    AdvisoryAbortReason::StopRequested => "stop_requested",
                };
                let run_record = self
                    .control
                    .advance_advisory_controller_aborted(operation_id, reason_str)
                    .await
                    .map_err(|_| AdvisoryOwnerError::Conflict)?;

                self.telemetry
                    .emit_aborted(*operation_id.as_bytes(), "resumed", reason_str);
                self.telemetry
                    .emit_capture_retired(*aborted.operation_id().as_bytes());

                Ok(run_record)
            }
        }
    }

    /// Reconcile an existing retained controller run upon process restart or retry.
    pub(crate) async fn reconcile_retained_run(
        &self,
        user_id: &str,
        operation_id: MaintenanceImportOperationId,
    ) -> Result<AdvisoryControllerRunRecord> {
        let record = self
            .control
            .load_advisory_controller_run(operation_id)
            .await
            .map_err(|_| AdvisoryOwnerError::Persistence)?
            .ok_or(AdvisoryOwnerError::Conflict)?;

        if record.user_id != user_id {
            return Err(AdvisoryOwnerError::Conflict);
        }

        // Check if an inner comparison has settled (reconcile lost outer Retired write)
        if let Some(settled_comparison) = self
            .control
            .load_retained_advisory_comparison_exact(record.archive_id)
            .await
            .map_err(|_| AdvisoryOwnerError::Persistence)?
        {
            if settled_comparison.operation_id() == operation_id {
                // Reconcile and prove that Store capture is retired before writing outer Retired
                self.store
                    .reconcile_advisory_capture_retired(user_id, &settled_comparison)
                    .await
                    .map_err(|_| AdvisoryOwnerError::Conflict)?;
                let evidence_commitment = settled_comparison.evidence_commitment();
                let _ = self
                    .control
                    .advance_advisory_controller_retired(operation_id, evidence_commitment)
                    .await;
                return self
                    .control
                    .load_advisory_controller_run(operation_id)
                    .await
                    .map_err(|_| AdvisoryOwnerError::Persistence)?
                    .ok_or(AdvisoryOwnerError::Conflict);
            }
        }

        // Check if an inner abort is recorded
        if let Some(aborted) = self
            .control
            .load_retained_advisory_abort_exact(record.archive_id)
            .await
            .map_err(|_| AdvisoryOwnerError::Persistence)?
        {
            if aborted.operation_id() == operation_id {
                let reason_str = match aborted.reason() {
                    AdvisoryAbortReason::StopRequested => "stop_requested",
                    AdvisoryAbortReason::ComparisonMismatch => "comparison_mismatch",
                };
                let _ = self
                    .control
                    .advance_advisory_controller_aborted(operation_id, reason_str)
                    .await;
                return self
                    .control
                    .load_advisory_controller_run(operation_id)
                    .await
                    .map_err(|_| AdvisoryOwnerError::Persistence)?
                    .ok_or(AdvisoryOwnerError::Conflict);
            }
        }

        match record.stage {
            AdvisoryControllerRunStage::Retired => Ok(record),
            AdvisoryControllerRunStage::Aborted => Ok(record),
            AdvisoryControllerRunStage::ManualRequired => Ok(record),
            AdvisoryControllerRunStage::Prepared
            | AdvisoryControllerRunStage::Eligible
            | AdvisoryControllerRunStage::Imported
            | AdvisoryControllerRunStage::Authorized => {
                // Reconcile pre-owner abort with control
                let _ = self.control.abort_pre_owner(operation_id).await;
                let _ = self
                    .control
                    .advance_advisory_controller_aborted(operation_id, "restart_reconciliation")
                    .await;
                self.control
                    .load_advisory_controller_run(operation_id)
                    .await
                    .map_err(|_| AdvisoryOwnerError::Persistence)?
                    .ok_or(AdvisoryOwnerError::Conflict)
            }
            AdvisoryControllerRunStage::OwnerAdmitted => {
                // Live owner state is ambiguous without inner settlement or inner abort:
                // transition to ManualRequired
                let _ = self
                    .control
                    .advance_advisory_controller_manual_required(
                        operation_id,
                        "owner_restart_ambiguous",
                    )
                    .await;
                self.control
                    .load_advisory_controller_run(operation_id)
                    .await
                    .map_err(|_| AdvisoryOwnerError::Persistence)?
                    .ok_or(AdvisoryOwnerError::Conflict)
            }
        }
    }

    /// Abort an in-flight maintenance import before reaching advisory owner state.
    pub(super) async fn abort_pre_owner(
        &self,
        user_id: &str,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        fence_authority: &str,
    ) -> Result<()> {
        SingleArchiveMaintenanceImporter::abort_pre_owner(
            &self.store,
            &self.control,
            user_id,
            archive_id,
            operation_id,
            fence_authority,
        )
        .await
        .map_err(|_| AdvisoryOwnerError::Conflict)?;

        let _ = self
            .control
            .advance_advisory_controller_aborted(operation_id, "stop_requested")
            .await;

        self.telemetry.emit_aborted(
            *operation_id.as_bytes(),
            "pre_owner",
            "manual_stop_requested",
        );
        Ok(())
    }

    /// Abort a locally resumed advisory canary, retiring the capture selector
    /// and durably transitioning to `Aborted`.
    pub(super) async fn abort_resumed(
        &self,
        resumed: super::LocallyResumedSingleArchiveAdvisoryOwner,
        reason: AdvisoryAbortReason,
    ) -> Result<super::AbortedSingleArchiveAdvisoryOwner> {
        let op_id = *resumed.operation_id().as_bytes();
        let operation_id = resumed.operation_id();
        let reason_str = match reason {
            AdvisoryAbortReason::StopRequested => "stop_requested",
            AdvisoryAbortReason::ComparisonMismatch => "comparison_mismatch",
        };

        let aborted = resumed.abort_resumed(reason).await?;

        let _ = self
            .control
            .advance_advisory_controller_aborted(operation_id, reason_str)
            .await;

        self.telemetry.emit_aborted(op_id, "resumed", reason_str);
        Ok(aborted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{
            resolve_archive_cipher, ArchiveDek, DatabaseEpoch, ImmutableObjectBackend,
            InMemoryImmutableBackend, KeyEpoch, KeyKind, KeyRegistryContext, KeyRegistryPlaintext,
            LogicalLocation, ObjectContext, ObjectId, ObjectRole,
        },
        archive_v3_advisory_owner::window::{TestPhase1WindowObserver, VerifiedWindowRevalidation},
        archive_v3_maintenance_import::tests::{InMemoryMaintenanceWitness, TestRegistry},
        archive_v3_witness::{InMemoryWitness, RootCommitment, RootReference, WitnessBootstrap},
        store::tests::{FakeGcs, FakeKms},
    };

    #[test]
    fn test_tmpfs_policy_enforces_strict_sub_4gib_and_quarter_vm_memory() {
        let vm_16gib = 16 * 1024 * 1024 * 1024;
        let db_100mib = 100 * 1024 * 1024;
        let res = Phase1TmpfsPolicyV1::evaluate(db_100mib, vm_16gib).unwrap();
        assert_eq!(
            res,
            (db_100mib * 2) + WORST_CASE_WAL_BYTES + SQLITE_SCRATCH_BYTES + MODEL_WORKING_SET_BYTES
        );

        // Rejects exactly 4 GiB and above
        let db_huge = 4 * 1024 * 1024 * 1024;
        assert!(Phase1TmpfsPolicyV1::evaluate(db_huge, vm_16gib * 2).is_err());

        // Rejects if memory demand is >= 25% of VM memory
        let vm_tiny = 1024 * 1024 * 1024; // 1 GiB VM
        assert!(Phase1TmpfsPolicyV1::evaluate(db_100mib, vm_tiny).is_err());

        // Rejects zero or overflow
        assert!(Phase1TmpfsPolicyV1::evaluate(0, vm_16gib).is_err());
        assert!(Phase1TmpfsPolicyV1::evaluate(db_100mib, 0).is_err());
        assert!(Phase1TmpfsPolicyV1::evaluate(u64::MAX, vm_16gib).is_err());

        // Policy commitment is non-zero
        let comm = Phase1TmpfsPolicyV1::policy_commitment();
        assert_ne!(comm, [0; 32]);
    }

    async fn setup_test_environment(
        username: &str,
    ) -> (
        Arc<ControlStore>,
        Arc<Store>,
        String,
        ArchiveId,
        SealedSingleArchiveWalRuntime,
        Arc<super::super::telemetry::InMemoryPhase1TelemetrySink>,
    ) {
        let control_gcs = Arc::new(FakeGcs::new());
        let control = Arc::new(ControlStore::new(Arc::new(FakeKms), control_gcs.clone()));
        let legacy_gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(Arc::new(FakeKms), legacy_gcs.clone()));
        let sink = Arc::new(super::super::telemetry::InMemoryPhase1TelemetrySink::new());

        let user = control
            .upsert_user(
                username,
                &format!("{}@example.com", username),
                crate::cp::control_store::TEST_SIGNUP_LIMIT,
            )
            .await
            .unwrap();

        store
            .with_user(&user.id, |conn| {
                conn.execute(
                    "INSERT INTO app_metadata (key, value) VALUES (?1, ?2)",
                    ["controller_test", "full_flow"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(&user.id).await.unwrap();

        let archive_id = control
            .read({
                let user_id = user.id.clone();
                move |conn| {
                    let bytes: Vec<u8> = conn.query_row(
                        "SELECT archive_id FROM archive_bindings WHERE user_id = ?1",
                        [&user_id],
                        |r| r.get(0),
                    )?;
                    let arr: [u8; 16] = bytes.try_into().map_err(|_| {
                        crate::error::EnclaveError::Conflict("archive_id length".into())
                    })?;
                    Ok(ArchiveId::from_bytes(arr))
                }
            })
            .await
            .unwrap();

        let database_epoch = DatabaseEpoch::from_bytes([0x61; 16]);
        let key_epoch = KeyEpoch::from_bytes([0x62; 16]);
        let registry_object_id = ObjectId::from_bytes([0x63; 16]);
        let wrapped = b"controller-registry-envelope".to_vec();
        let registry_context = KeyRegistryContext::new(archive_id, KeyKind::Archive, key_epoch);
        let plaintext = KeyRegistryPlaintext::encode_archive(
            &registry_context,
            &ArchiveDek::from_bytes([0x64; 32]),
        )
        .unwrap()
        .to_vec();
        let registries = Arc::new(TestRegistry {
            object_id: registry_object_id,
            wrapped: wrapped.clone(),
            plaintext,
        });
        let cipher = resolve_archive_cipher(
            &registry_context,
            registry_object_id,
            Sha256::digest(&wrapped).into(),
            registries.as_ref(),
        )
        .await
        .unwrap();

        let backend = Arc::new(InMemoryImmutableBackend::new());
        let initial_root_id = ObjectId::from_bytes([0x65; 16]);
        let initial_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            initial_root_id,
            None,
        )
        .unwrap();

        let initial_root = crate::archive_v3::ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: crate::archive_v3::SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: 0,
            logical_file_length: 0,
            user_schema_version: 0,
            storage_format_version: crate::archive_v3::ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        let initial_envelope = cipher
            .seal(&initial_context, &initial_root.encode().unwrap())
            .unwrap();
        backend
            .create_if_absent(initial_context.object_key(), initial_envelope.clone())
            .await
            .unwrap();

        let witness = InMemoryWitness::with_incrementing_clock_for_test(1);
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(
                    database_epoch,
                    key_epoch,
                    RootReference::new(0, initial_root_id, initial_envelope.hash()),
                ),
                crate::archive_v3_witness::KeyRegistryReference::new(
                    key_epoch,
                    0,
                    registry_object_id,
                    Sha256::digest(&wrapped).into(),
                ),
            ))
            .unwrap();
        let witness = Arc::new(InMemoryMaintenanceWitness::with_advisory_outcome_unknown(
            witness,
        ));

        let runtime =
            SealedSingleArchiveWalRuntime::for_test(archive_id, backend, registries, witness);

        (control, store, user.id, archive_id, runtime, sink)
    }

    #[tokio::test]
    async fn test_controller_canary_flow_emits_telemetry_and_persists_durable_stages() {
        let (control, store, user_id, _archive_id, runtime, sink) =
            setup_test_environment("controller-full-user").await;

        let window_observer = Arc::new(TestPhase1WindowObserver::new());
        let memory_provider = Arc::new(TestVmMemoryProvider::new(16 * 1024 * 1024 * 1024));

        let controller = Arc::new(SingleArchivePhase1AdvisoryController::new(
            Arc::clone(&control),
            Arc::clone(&store),
            window_observer,
            memory_provider,
            Some(Arc::clone(&sink) as Arc<dyn Phase1CanaryTelemetrySink>),
        ));

        let held_window = HeldPhase1Window::new(
            [0x11; 16],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            [0xee; 32],
            1_600_000_000,
            1_800_000_000,
        )
        .unwrap();

        let (operation_id, resumed, held_window) = controller
            .execute_canary_admission([0x01; 16], &user_id, runtime, held_window, None)
            .await
            .unwrap();

        // Perform a live write through store while admitted to simulate user traffic
        store
            .with_user(&user_id, |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO app_metadata (key, value) VALUES ('canary_test_live_write', '1')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let run_record = controller
            .settle_canary_admission(operation_id, resumed, held_window)
            .await
            .unwrap();

        assert_eq!(run_record.stage, AdvisoryControllerRunStage::Retired);
        assert!(run_record.measured_database_bytes.is_some());
        assert!(run_record.settlement_commitment.is_some());

        // Wait for asynchronous telemetry worker to flush
        for _ in 0..50 {
            if sink.events().len() >= 6 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(sink.events().len() >= 6);
    }

    #[tokio::test]
    async fn test_controller_aborts_when_window_revalidation_fails() {
        let (control, store, user_id, _archive_id, runtime, sink) =
            setup_test_environment("controller-window-fail-user").await;

        let window_observer = Arc::new(TestPhase1WindowObserver::with_failing_revalidation());
        let memory_provider = Arc::new(TestVmMemoryProvider::new(16 * 1024 * 1024 * 1024));

        let controller = Arc::new(SingleArchivePhase1AdvisoryController::new(
            Arc::clone(&control),
            Arc::clone(&store),
            window_observer,
            memory_provider,
            Some(Arc::clone(&sink) as Arc<dyn Phase1CanaryTelemetrySink>),
        ));

        let held_window = HeldPhase1Window::new(
            [0x11; 16],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            [0xee; 32],
            1_600_000_000,
            1_800_000_000,
        )
        .unwrap();

        let res = controller
            .execute_canary_run([0x02; 16], &user_id, runtime, held_window, None)
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_controller_aborts_when_memory_eligibility_fails() {
        let (control, store, user_id, _archive_id, runtime, sink) =
            setup_test_environment("controller-mem-fail-user").await;

        let window_observer = Arc::new(TestPhase1WindowObserver::new());
        // VM with only 1 MiB memory - preflight eligibility will strictly fail (< 25% constraint)
        let memory_provider = Arc::new(TestVmMemoryProvider::new(1024 * 1024));

        let controller = Arc::new(SingleArchivePhase1AdvisoryController::new(
            Arc::clone(&control),
            Arc::clone(&store),
            window_observer,
            memory_provider,
            Some(Arc::clone(&sink) as Arc<dyn Phase1CanaryTelemetrySink>),
        ));

        let held_window = HeldPhase1Window::new(
            [0x11; 16],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            [0xee; 32],
            1_600_000_000,
            1_800_000_000,
        )
        .unwrap();

        let res = controller
            .execute_canary_run([0x03; 16], &user_id, runtime, held_window, None)
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_terminal_immutability_and_reason_rewrite_rejection() {
        let (control, _store, user_id, archive_id, _runtime, _sink) =
            setup_test_environment("controller-terminal-user").await;

        let plan = control
            .prepare_archive_v3_maintenance_import(&user_id)
            .await
            .unwrap();
        let operation_id = plan.plan_operation_id();
        let run_id = [0x42; 16];
        let window_id = [0x43; 16];
        let intent_commitment = [0x44; 32];

        // Prepare run
        control
            .prepare_advisory_controller_run(
                run_id,
                &user_id,
                archive_id,
                operation_id,
                window_id,
                intent_commitment,
            )
            .await
            .unwrap();

        // Advance to Aborted
        control
            .advance_advisory_controller_aborted(operation_id, "first_abort_reason")
            .await
            .unwrap();

        // Idempotent re-abort with identical reason succeeds
        let re_aborted = control
            .advance_advisory_controller_aborted(operation_id, "first_abort_reason")
            .await
            .unwrap();
        assert_eq!(
            re_aborted.abort_reason.as_deref(),
            Some("first_abort_reason")
        );

        // Attempting to rewrite abort reason fails with Conflict
        let rewrite = control
            .advance_advisory_controller_aborted(operation_id, "different_reason")
            .await;
        assert!(rewrite.is_err());

        // Attempting to advance an aborted run to Eligible fails
        let eligible = control
            .advance_advisory_controller_eligible(operation_id, 1000, 2000, 1000000)
            .await;
        assert!(eligible.is_err());
    }

    #[tokio::test]
    async fn test_reconcile_retained_run_from_aborted_or_pre_owner() {
        let (control, store, user_id, archive_id, _runtime, sink) =
            setup_test_environment("controller-reconcile-user").await;

        let window_observer = Arc::new(TestPhase1WindowObserver::new());
        let memory_provider = Arc::new(TestVmMemoryProvider::new(16 * 1024 * 1024 * 1024));

        let controller = Arc::new(SingleArchivePhase1AdvisoryController::new(
            Arc::clone(&control),
            Arc::clone(&store),
            window_observer,
            memory_provider,
            Some(Arc::clone(&sink) as Arc<dyn Phase1CanaryTelemetrySink>),
        ));

        let plan = control
            .prepare_archive_v3_maintenance_import(&user_id)
            .await
            .unwrap();
        let operation_id = plan.plan_operation_id();
        let run_id = [0x56; 16];
        let window_id = [0x57; 16];
        let intent_commitment = [0x58; 32];

        // Prepare run
        control
            .prepare_advisory_controller_run(
                run_id,
                &user_id,
                archive_id,
                operation_id,
                window_id,
                intent_commitment,
            )
            .await
            .unwrap();

        // Reconcile prepared run -> transitions cleanly to aborted and cleans pre-owner state
        let reconciled = controller
            .reconcile_retained_run(&user_id, operation_id)
            .await
            .unwrap();
        assert_eq!(reconciled.stage, AdvisoryControllerRunStage::Aborted);
    }

    #[tokio::test]
    async fn test_reconcile_retained_run_reconciles_lost_retired_write_from_settled_comparison() {
        let (control, store, user_id, _archive_id, runtime, sink) =
            setup_test_environment("controller-lost-retired-user").await;

        let window_observer = Arc::new(TestPhase1WindowObserver::new());
        let memory_provider = Arc::new(TestVmMemoryProvider::new(16 * 1024 * 1024 * 1024));

        let controller = Arc::new(SingleArchivePhase1AdvisoryController::new(
            Arc::clone(&control),
            Arc::clone(&store),
            window_observer,
            memory_provider,
            Some(Arc::clone(&sink) as Arc<dyn Phase1CanaryTelemetrySink>),
        ));

        let held_window = HeldPhase1Window::new(
            [0x11; 16],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            [0xee; 32],
            1_600_000_000,
            1_800_000_000,
        )
        .unwrap();

        let (operation_id, resumed, _held_window) = controller
            .execute_canary_admission([0x04; 16], &user_id, runtime, held_window, None)
            .await
            .unwrap();

        // Perform a live write through store while admitted to simulate user traffic
        store
            .with_user(&user_id, |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO app_metadata (key, value) VALUES ('canary_test_live_write', '1')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        // Inner comparison settles directly (e.g. outer write lost / process restart before outer update)
        let outcome = resumed.settle_comparison().await.unwrap();
        let settlement = match outcome {
            super::super::AdvisorySettlementOutcome::Settled(s) => s,
            super::super::AdvisorySettlementOutcome::Aborted(_) => panic!("expected settled"),
        };
        let expected_evidence = settlement.evidence_commitment();

        // Outer run is still OwnerAdmitted prior to reconciliation
        let outer_before = control
            .load_advisory_controller_run(operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outer_before.stage,
            AdvisoryControllerRunStage::OwnerAdmitted
        );

        // Reconcile retained run -> verifies Store retirement and advances outer run to Retired
        let reconciled = controller
            .reconcile_retained_run(&user_id, operation_id)
            .await
            .unwrap();
        assert_eq!(reconciled.stage, AdvisoryControllerRunStage::Retired);
        assert_eq!(reconciled.settlement_commitment, Some(expected_evidence));

        // Reconcile with mismatched user ID fails closed with Conflict
        let mismatch = controller
            .reconcile_retained_run("wrong_user_id", operation_id)
            .await;
        assert!(mismatch.is_err());
    }

    #[tokio::test]
    async fn test_controller_abort_resumed_flow() {
        let (control, store, user_id, _archive_id, runtime, sink) =
            setup_test_environment("controller-abort-resumed-user").await;

        let window_observer = Arc::new(TestPhase1WindowObserver::new());
        let memory_provider = Arc::new(TestVmMemoryProvider::new(16 * 1024 * 1024 * 1024));

        let controller = Arc::new(SingleArchivePhase1AdvisoryController::new(
            Arc::clone(&control),
            Arc::clone(&store),
            window_observer,
            memory_provider,
            Some(Arc::clone(&sink) as Arc<dyn Phase1CanaryTelemetrySink>),
        ));

        let held_window = HeldPhase1Window::new(
            [0x11; 16],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            [0xee; 32],
            1_600_000_000,
            1_800_000_000,
        )
        .unwrap();

        let (operation_id, resumed, _held_window) = controller
            .execute_canary_admission([0x05; 16], &user_id, runtime, held_window, None)
            .await
            .unwrap();

        let aborted = controller
            .abort_resumed(resumed, AdvisoryAbortReason::StopRequested)
            .await
            .unwrap();
        assert_eq!(aborted.reason(), AdvisoryAbortReason::StopRequested);

        let run_record = control
            .load_advisory_controller_run(operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run_record.stage, AdvisoryControllerRunStage::Aborted);
        assert_eq!(run_record.abort_reason.as_deref(), Some("stop_requested"));

        let reconciled = controller
            .reconcile_retained_run(&user_id, operation_id)
            .await
            .unwrap();
        assert_eq!(reconciled.stage, AdvisoryControllerRunStage::Aborted);
    }

    #[tokio::test]
    async fn test_reconcile_retained_run_owner_admitted_without_settlement_becomes_manual_required()
    {
        let (control, store, user_id, _archive_id, runtime, sink) =
            setup_test_environment("controller-owner-ambiguous-user").await;

        let window_observer = Arc::new(TestPhase1WindowObserver::new());
        let memory_provider = Arc::new(TestVmMemoryProvider::new(16 * 1024 * 1024 * 1024));

        let controller = Arc::new(SingleArchivePhase1AdvisoryController::new(
            Arc::clone(&control),
            Arc::clone(&store),
            window_observer,
            memory_provider,
            Some(Arc::clone(&sink) as Arc<dyn Phase1CanaryTelemetrySink>),
        ));

        let held_window = HeldPhase1Window::new(
            [0x11; 16],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            [0xee; 32],
            1_600_000_000,
            1_800_000_000,
        )
        .unwrap();

        let (operation_id, _resumed, _held_window) = controller
            .execute_canary_admission([0x06; 16], &user_id, runtime, held_window, None)
            .await
            .unwrap();

        // Process restarted while OwnerAdmitted before settlement or abort
        let reconciled = controller
            .reconcile_retained_run(&user_id, operation_id)
            .await
            .unwrap();
        assert_eq!(reconciled.stage, AdvisoryControllerRunStage::ManualRequired);
    }

    #[tokio::test]
    async fn test_window_proof_rejects_stale_replayed_or_out_of_bounds() {
        let window = HeldPhase1Window::new(
            [0x11; 16],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            [0xee; 32],
            1_600_000_000,
            1_800_000_000,
        )
        .unwrap();

        // Sequence 1 is accepted
        let proof1 = VerifiedWindowRevalidation::mint_for_verified_observer(
            &window,
            1,
            [0xee; 32],
            1_650_000_000,
        )
        .unwrap();
        assert!(window.verify_revalidation_proof(&proof1).is_ok());

        // Replaying sequence 1 fails closed
        assert!(window.verify_revalidation_proof(&proof1).is_err());

        // Sequence 0 (< last sequence) fails closed
        let stale_seq = VerifiedWindowRevalidation::mint_for_verified_observer(
            &window,
            0,
            [0xee; 32],
            1_660_000_000,
        )
        .unwrap();
        assert!(window.verify_revalidation_proof(&stale_seq).is_err());

        // Timestamp regression (< last timestamp) fails closed
        let stale_time = VerifiedWindowRevalidation::mint_for_verified_observer(
            &window,
            2,
            [0xee; 32],
            1_640_000_000,
        )
        .unwrap();
        assert!(window.verify_revalidation_proof(&stale_time).is_err());

        // Timestamp out of window bounds fails closed
        let out_of_bounds = VerifiedWindowRevalidation::mint_for_verified_observer(
            &window,
            3,
            [0xee; 32],
            1_900_000_000,
        )
        .unwrap();
        assert!(window.verify_revalidation_proof(&out_of_bounds).is_err());

        // Mismatched zero-replica digest fails closed
        let wrong_replica = VerifiedWindowRevalidation::mint_for_verified_observer(
            &window,
            4,
            [0xff; 32],
            1_700_000_000,
        )
        .unwrap();
        assert!(window.verify_revalidation_proof(&wrong_replica).is_err());
    }

    #[tokio::test]
    async fn test_tampered_policy_commitment_rejected() {
        let (control, _store, user_id, archive_id, _runtime, _sink) =
            setup_test_environment("controller-tampered-policy-user").await;

        let plan = control
            .prepare_archive_v3_maintenance_import(&user_id)
            .await
            .unwrap();
        let operation_id = plan.plan_operation_id();
        let run_id = [0x51; 16];
        let window_id = [0x52; 16];
        let intent_commitment = [0x53; 32];

        control
            .prepare_advisory_controller_run(
                run_id,
                &user_id,
                archive_id,
                operation_id,
                window_id,
                intent_commitment,
            )
            .await
            .unwrap();

        // Tamper with the policy_commitment in SQLite directly
        control
            .write({
                move |conn| {
                    conn.execute(
                        "UPDATE archive_v3_advisory_controller_runs SET policy_commitment = ?1 WHERE maintenance_operation_id = ?2",
                        rusqlite::params![[0xbau8; 32].as_slice(), operation_id.as_bytes().as_slice()],
                    )?;
                    Ok(())
                }
            })
            .await
            .unwrap();

        // Loading the controller run must fail closed due to policy commitment mismatch
        let load_res = control.load_advisory_controller_run(operation_id).await;
        assert!(load_res.is_err());
    }

    #[tokio::test]
    async fn test_tampered_canary_scope_or_owner_tuple_rejected() {
        let (control, _store, user_id, archive_id, _runtime, _sink) =
            setup_test_environment("controller-tampered-scope-user").await;

        let plan = control
            .prepare_archive_v3_maintenance_import(&user_id)
            .await
            .unwrap();
        let operation_id = plan.plan_operation_id();
        let run_id = [0x61; 16];
        let window_id = [0x62; 16];
        let intent_commitment = [0x63; 32];

        control
            .prepare_advisory_controller_run(
                run_id,
                &user_id,
                archive_id,
                operation_id,
                window_id,
                intent_commitment,
            )
            .await
            .unwrap();

        // Advance to authorized with a fake/unpersisted scope_id must fail closed
        let fake_scope_id = [0x99; 16];
        let advance_res = control
            .advance_advisory_controller_authorized(operation_id, fake_scope_id)
            .await;
        assert!(advance_res.is_err());

        // Advance to owner_admitted with a fake/unreserved owner_id must fail closed
        let fake_owner_id = [0x88; 16];
        let owner_res = control
            .advance_advisory_controller_owner_admitted(operation_id, fake_owner_id)
            .await;
        assert!(owner_res.is_err());
    }
}
