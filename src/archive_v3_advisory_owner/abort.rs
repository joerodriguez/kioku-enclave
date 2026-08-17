//! Owner-private durable abort terminal for a released Phase-1 canary.
//!
//! Control distinguishes the already-resumed capture locus from the released-
//! before-resume locus without changing the historical resumed commitment
//! bytes. It records `Prepared` before Store mutation and records `Aborted`
//! only after an opaque exact-target retirement, released-gate restoration, or
//! restart-only local-absence proof while its user lifecycle remains held. The terminal is mutually
//! exclusive with successful comparison settlement and
//! grants no provider, acknowledgement, database, launcher, list, or delete
//! authority.

use sha2::{Digest, Sha256};

use super::{
    AdvisoryAbortContext, AdvisoryOwnerError, AdvisoryOwnerRuntimeContext, AdvisoryRelease,
    AdvisoryReleaseStage, BoundAdvisoryOwner, Result,
};

const ADVISORY_ABORT_COMMITMENT_DOMAIN: &[u8] = b"kioku/archive-v3/advisory-resumed-abort/v1\0";
const RELEASED_ADVISORY_ABORT_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-released-before-resume-abort/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum AdvisoryAbortLocus {
    ResumedCapture = 1,
    ReleasedBeforeResume = 2,
}

impl AdvisoryAbortLocus {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::ResumedCapture => "resumed_capture",
            Self::ReleasedBeforeResume => "released_before_resume",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self> {
        match value {
            "resumed_capture" => Ok(Self::ResumedCapture),
            "released_before_resume" => Ok(Self::ReleasedBeforeResume),
            _ => Err(AdvisoryOwnerError::Corrupt),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum AdvisoryAbortReason {
    StopRequested = 1,
    ComparisonMismatch = 2,
}

impl AdvisoryAbortReason {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::StopRequested => "stop_requested",
            Self::ComparisonMismatch => "comparison_mismatch",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self> {
        match value {
            "stop_requested" => Ok(Self::StopRequested),
            "comparison_mismatch" => Ok(Self::ComparisonMismatch),
            _ => Err(AdvisoryOwnerError::Corrupt),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum AdvisoryAbortStage {
    Prepared = 1,
    Aborted = 2,
}

impl AdvisoryAbortStage {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Aborted => "aborted",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "aborted" => Ok(Self::Aborted),
            _ => Err(AdvisoryOwnerError::Corrupt),
        }
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct AdvisoryAbortTerminal {
    archive_id: crate::archive_v3::ArchiveId,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    owner_id: super::AdvisoryOwnerId,
    owner_witness: crate::archive_v3_witness::WitnessRecord,
    owner_revision: u64,
    owner_commitment: [u8; 32],
    release_commitment: [u8; 32],
    locus: AdvisoryAbortLocus,
    reason: AdvisoryAbortReason,
    stage: AdvisoryAbortStage,
    retirement_commitment: Option<[u8; 32]>,
    commitment: [u8; 32],
}

/// Opaque restart capability reconstructed only by encrypted Control after it
/// authenticates the complete retained abort/release/owner/import chain. The
/// private user identity is visible only through Store's retirement token.
pub(crate) struct PreparedAdvisoryAbortRecovery {
    user_id: String,
    terminal: AdvisoryAbortTerminal,
}

pub(crate) enum AdvisoryAbortRecoveryState {
    Prepared(PreparedAdvisoryAbortRecovery),
    Aborted(AdvisoryAbortTerminal),
}

pub(crate) struct AdvisoryAbortRecoveryStoreView<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) archive_id: crate::archive_v3::ArchiveId,
    pub(crate) operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
}

pub(crate) struct AdvisoryAbortControlView<'a> {
    pub(crate) archive_id: crate::archive_v3::ArchiveId,
    pub(crate) operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    pub(crate) owner_id: super::AdvisoryOwnerId,
    pub(crate) owner_witness: &'a crate::archive_v3_witness::WitnessRecord,
    pub(crate) owner_revision: u64,
    pub(crate) owner_commitment: [u8; 32],
    pub(crate) release_commitment: [u8; 32],
    pub(crate) locus: AdvisoryAbortLocus,
    pub(crate) reason: AdvisoryAbortReason,
    pub(crate) stage: AdvisoryAbortStage,
    pub(crate) retirement_commitment: Option<[u8; 32]>,
    pub(crate) commitment: [u8; 32],
}

impl AdvisoryAbortTerminal {
    pub(crate) const fn reason(&self) -> AdvisoryAbortReason {
        self.reason
    }

    pub(crate) const fn stage(&self) -> AdvisoryAbortStage {
        self.stage
    }

    pub(crate) const fn locus(&self) -> AdvisoryAbortLocus {
        self.locus
    }

    pub(crate) fn prepared_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        owner: &BoundAdvisoryOwner,
        release: &AdvisoryRelease,
        reason: AdvisoryAbortReason,
    ) -> Result<Self> {
        let (operation_id, owner_id, _, _, observed, _, owner_revision, owner_commitment) =
            owner.control_view(token);
        let release_view = release.control_view(token);
        if release_view.stage != AdvisoryReleaseStage::Released
            || release_view.archive_id != observed.archive_id()
            || release_view.operation_id != operation_id
            || release_view.owner_id != owner_id
            || release_view.owner_witness != observed
            || release_view.owner_revision != owner_revision
            || release_view.owner_commitment != owner_commitment
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let commitment = advisory_abort_commitment(
            release_view.archive_id,
            operation_id,
            owner_id,
            observed,
            owner_revision,
            owner_commitment,
            release_view.commitment,
            AdvisoryAbortLocus::ResumedCapture,
            reason,
            AdvisoryAbortStage::Prepared,
            None,
        );
        Self::from_control(
            token,
            release_view.archive_id,
            operation_id,
            owner_id,
            observed.clone(),
            owner_revision,
            owner_commitment,
            release_view.commitment,
            AdvisoryAbortLocus::ResumedCapture,
            reason,
            AdvisoryAbortStage::Prepared,
            None,
            commitment,
        )
    }

    pub(crate) fn prepared_released_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        owner: &BoundAdvisoryOwner,
        release: &AdvisoryRelease,
        admission: &crate::store::StoreReleasedAbortAdmission,
    ) -> Result<Self> {
        let prepared =
            Self::prepared_for_control(token, owner, release, AdvisoryAbortReason::StopRequested)?;
        admission
            .authenticate_for_advisory_abort(
                AdvisoryAbortContext(()),
                prepared.archive_id,
                prepared.operation_id,
                prepared.release_commitment,
            )
            .map_err(|_| AdvisoryOwnerError::Conflict)?;
        let commitment = advisory_abort_commitment(
            prepared.archive_id,
            prepared.operation_id,
            prepared.owner_id,
            &prepared.owner_witness,
            prepared.owner_revision,
            prepared.owner_commitment,
            prepared.release_commitment,
            AdvisoryAbortLocus::ReleasedBeforeResume,
            prepared.reason,
            prepared.stage,
            None,
        );
        Self::from_control(
            token,
            prepared.archive_id,
            prepared.operation_id,
            prepared.owner_id,
            prepared.owner_witness,
            prepared.owner_revision,
            prepared.owner_commitment,
            prepared.release_commitment,
            AdvisoryAbortLocus::ReleasedBeforeResume,
            prepared.reason,
            prepared.stage,
            None,
            commitment,
        )
    }

    pub(crate) fn aborted_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        prepared: &Self,
        retired: &crate::store::StoreAdvisoryCaptureRetired,
    ) -> Result<Self> {
        if prepared.stage != AdvisoryAbortStage::Prepared
            || prepared.locus != AdvisoryAbortLocus::ResumedCapture
            || prepared.retirement_commitment.is_some()
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let retirement_commitment = retired
            .commitment_for_advisory_abort(
                AdvisoryAbortContext(()),
                prepared.archive_id,
                prepared.operation_id,
            )
            .map_err(|_| AdvisoryOwnerError::Conflict)?;
        let commitment = advisory_abort_commitment(
            prepared.archive_id,
            prepared.operation_id,
            prepared.owner_id,
            &prepared.owner_witness,
            prepared.owner_revision,
            prepared.owner_commitment,
            prepared.release_commitment,
            prepared.locus,
            prepared.reason,
            AdvisoryAbortStage::Aborted,
            Some(retirement_commitment),
        );
        Self::from_control(
            token,
            prepared.archive_id,
            prepared.operation_id,
            prepared.owner_id,
            prepared.owner_witness.clone(),
            prepared.owner_revision,
            prepared.owner_commitment,
            prepared.release_commitment,
            prepared.locus,
            prepared.reason,
            AdvisoryAbortStage::Aborted,
            Some(retirement_commitment),
            commitment,
        )
    }

    pub(crate) fn aborted_released_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        prepared: &Self,
        restored: &crate::store::StoreReleasedAbortRestored,
    ) -> Result<Self> {
        if prepared.stage != AdvisoryAbortStage::Prepared
            || prepared.locus != AdvisoryAbortLocus::ReleasedBeforeResume
            || prepared.reason != AdvisoryAbortReason::StopRequested
            || prepared.retirement_commitment.is_some()
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let local_terminal_commitment = restored
            .commitment_for_advisory_abort(AdvisoryAbortContext(()), prepared)
            .map_err(|_| AdvisoryOwnerError::Conflict)?;
        let commitment = advisory_abort_commitment(
            prepared.archive_id,
            prepared.operation_id,
            prepared.owner_id,
            &prepared.owner_witness,
            prepared.owner_revision,
            prepared.owner_commitment,
            prepared.release_commitment,
            prepared.locus,
            prepared.reason,
            AdvisoryAbortStage::Aborted,
            Some(local_terminal_commitment),
        );
        Self::from_control(
            token,
            prepared.archive_id,
            prepared.operation_id,
            prepared.owner_id,
            prepared.owner_witness.clone(),
            prepared.owner_revision,
            prepared.owner_commitment,
            prepared.release_commitment,
            prepared.locus,
            prepared.reason,
            AdvisoryAbortStage::Aborted,
            Some(local_terminal_commitment),
            commitment,
        )
    }

    pub(crate) fn aborted_from_recovery_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        recovery: &PreparedAdvisoryAbortRecovery,
        absence: &crate::store::StorePreparedAdvisoryAbortAbsent,
    ) -> Result<Self> {
        let prepared = recovery.terminal(AdvisoryOwnerRuntimeContext(()));
        if prepared.stage != AdvisoryAbortStage::Prepared
            || prepared.retirement_commitment.is_some()
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let retirement_commitment = absence
            .commitment_for_advisory_abort_recovery(AdvisoryAbortContext(()), recovery)
            .map_err(|_| AdvisoryOwnerError::Conflict)?;
        let commitment = advisory_abort_commitment(
            prepared.archive_id,
            prepared.operation_id,
            prepared.owner_id,
            &prepared.owner_witness,
            prepared.owner_revision,
            prepared.owner_commitment,
            prepared.release_commitment,
            prepared.locus,
            prepared.reason,
            AdvisoryAbortStage::Aborted,
            Some(retirement_commitment),
        );
        Self::from_control(
            token,
            prepared.archive_id,
            prepared.operation_id,
            prepared.owner_id,
            prepared.owner_witness.clone(),
            prepared.owner_revision,
            prepared.owner_commitment,
            prepared.release_commitment,
            prepared.locus,
            prepared.reason,
            AdvisoryAbortStage::Aborted,
            Some(retirement_commitment),
            commitment,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control(
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        archive_id: crate::archive_v3::ArchiveId,
        operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
        owner_id: super::AdvisoryOwnerId,
        owner_witness: crate::archive_v3_witness::WitnessRecord,
        owner_revision: u64,
        owner_commitment: [u8; 32],
        release_commitment: [u8; 32],
        locus: AdvisoryAbortLocus,
        reason: AdvisoryAbortReason,
        stage: AdvisoryAbortStage,
        retirement_commitment: Option<[u8; 32]>,
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        if archive_id != owner_witness.archive_id()
            || owner_witness.deletion() != crate::archive_v3_witness::DeletionState::Active
            || owner_witness.migration() != crate::archive_v3_witness::MigrationState::ShadowWal
            || owner_revision == 0
            || owner_commitment == [0; 32]
            || release_commitment == [0; 32]
            || retirement_commitment.is_some_and(|value| value == [0; 32])
            || (locus == AdvisoryAbortLocus::ReleasedBeforeResume
                && reason != AdvisoryAbortReason::StopRequested)
            || (stage == AdvisoryAbortStage::Prepared && retirement_commitment.is_some())
            || (stage == AdvisoryAbortStage::Aborted && retirement_commitment.is_none())
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        let commitment = advisory_abort_commitment(
            archive_id,
            operation_id,
            owner_id,
            &owner_witness,
            owner_revision,
            owner_commitment,
            release_commitment,
            locus,
            reason,
            stage,
            retirement_commitment,
        );
        if commitment == [0; 32] || commitment != persisted_commitment {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            archive_id,
            operation_id,
            owner_id,
            owner_witness,
            owner_revision,
            owner_commitment,
            release_commitment,
            locus,
            reason,
            stage,
            retirement_commitment,
            commitment,
        })
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> AdvisoryAbortControlView<'_> {
        AdvisoryAbortControlView {
            archive_id: self.archive_id,
            operation_id: self.operation_id,
            owner_id: self.owner_id,
            owner_witness: &self.owner_witness,
            owner_revision: self.owner_revision,
            owner_commitment: self.owner_commitment,
            release_commitment: self.release_commitment,
            locus: self.locus,
            reason: self.reason,
            stage: self.stage,
            retirement_commitment: self.retirement_commitment,
            commitment: self.commitment,
        }
    }

    pub(crate) fn authenticate_store_target(
        &self,
        _token: crate::store::StoreAdvisoryRetirementContext,
        archive_id: crate::archive_v3::ArchiveId,
        operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    ) -> Result<()> {
        if self.archive_id != archive_id || self.operation_id != operation_id {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(())
    }

    pub(crate) const fn operation_id(
        &self,
    ) -> crate::archive_v3_maintenance_import::MaintenanceImportOperationId {
        self.operation_id
    }

    pub(crate) const fn prepared_commitment_for_store(&self) -> [u8; 32] {
        self.commitment
    }
}

impl PreparedAdvisoryAbortRecovery {
    pub(crate) fn from_control(
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        user_id: String,
        terminal: AdvisoryAbortTerminal,
    ) -> Result<Self> {
        crate::store::validate_user_id(&user_id).map_err(|_| AdvisoryOwnerError::Corrupt)?;
        if terminal.stage != AdvisoryAbortStage::Prepared {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(Self { user_id, terminal })
    }

    pub(crate) fn store_view(
        &self,
        _token: crate::store::StoreAdvisoryRetirementContext,
    ) -> AdvisoryAbortRecoveryStoreView<'_> {
        AdvisoryAbortRecoveryStoreView {
            user_id: &self.user_id,
            archive_id: self.terminal.archive_id,
            operation_id: self.terminal.operation_id,
        }
    }

    pub(crate) const fn prepared_commitment(&self) -> [u8; 32] {
        self.terminal.commitment
    }

    pub(crate) const fn terminal(
        &self,
        _token: super::AdvisoryOwnerRuntimeContext,
    ) -> &AdvisoryAbortTerminal {
        &self.terminal
    }

    pub(crate) const fn terminal_for_control(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> &AdvisoryAbortTerminal {
        &self.terminal
    }
}

#[allow(clippy::too_many_arguments)]
fn advisory_abort_commitment(
    archive_id: crate::archive_v3::ArchiveId,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    owner_id: super::AdvisoryOwnerId,
    owner_witness: &crate::archive_v3_witness::WitnessRecord,
    owner_revision: u64,
    owner_commitment: [u8; 32],
    release_commitment: [u8; 32],
    locus: AdvisoryAbortLocus,
    reason: AdvisoryAbortReason,
    stage: AdvisoryAbortStage,
    retirement_commitment: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(match locus {
        AdvisoryAbortLocus::ResumedCapture => ADVISORY_ABORT_COMMITMENT_DOMAIN,
        AdvisoryAbortLocus::ReleasedBeforeResume => RELEASED_ADVISORY_ABORT_COMMITMENT_DOMAIN,
    });
    hasher.update(1_u16.to_be_bytes());
    hasher.update(archive_id.as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(owner_id.as_bytes());
    hasher.update(owner_witness.encode());
    hasher.update(owner_revision.to_be_bytes());
    hasher.update(owner_commitment);
    hasher.update(release_commitment);
    if locus == AdvisoryAbortLocus::ReleasedBeforeResume {
        hasher.update([locus as u8]);
    }
    hasher.update([reason as u8, stage as u8]);
    match retirement_commitment {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value);
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}
