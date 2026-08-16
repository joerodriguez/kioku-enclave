//! Owner-private Phase-1 comparison worker.
//!
//! The worker reauthenticates the exact maintenance source, released owner
//! row, and current ShadowWal witness on both sides of local work. It recovers
//! only the witness-nominated immutable graph, consumes an opaque Store
//! snapshot/drain pair, and retains only one domain-separated commitment.
//! A successful opaque result alone can enter a one-shot content-free Control
//! settlement that exact-loads after a lost response or owner restart. There
//! is deliberately no drain settlement, acknowledgement, provider mutation,
//! launcher, route, task, list, or delete capability in this child.

use sha2::{Digest, Sha256};

use super::{
    AdvisoryComparisonContext, AdvisoryOwnerControl, AdvisoryOwnerError,
    AdvisoryOwnerRuntimeContext, AdvisoryReleaseStage, LocallyResumedSingleArchiveAdvisoryOwner,
    Result,
};
use crate::archive_v3_maintenance_import::MaintenanceImportPersistence;

const ADVISORY_COMPARISON_EVIDENCE_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-captured-prefix-evidence/v1\0";
const ADVISORY_COMPARISON_SETTLEMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-comparison-settlement/v1\0";

/// Content-free local evidence. It is intentionally non-cloneable and has no
/// production getter; only the exact one-shot Control settlement can consume
/// an instance.
pub(crate) struct AdvisoryComparisonEvidence {
    _commitment: [u8; 32],
}

#[cfg(test)]
impl AdvisoryComparisonEvidence {
    pub(crate) fn for_control_test(commitment: [u8; 32]) -> Result<Self> {
        if commitment == [0; 32] {
            return Err(super::AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            _commitment: commitment,
        })
    }
}

/// Durable, content-free terminal for one successful advisory comparison.
/// It is deliberately non-cloneable and has no acknowledgement, capture,
/// provider, or authority-conversion operation. Control can only reconstruct
/// it from the exact persisted tuple after reauthenticating its released owner
/// predecessor.
#[derive(PartialEq, Eq)]
pub(crate) struct AdvisoryComparisonSettlement {
    archive_id: crate::archive_v3::ArchiveId,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    owner_id: super::AdvisoryOwnerId,
    owner_witness: crate::archive_v3_witness::WitnessRecord,
    owner_revision: u64,
    owner_commitment: [u8; 32],
    release_commitment: [u8; 32],
    evidence_commitment: [u8; 32],
    commitment: [u8; 32],
}

pub(crate) struct AdvisoryComparisonSettlementControlView<'a> {
    pub(crate) archive_id: crate::archive_v3::ArchiveId,
    pub(crate) operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    pub(crate) owner_id: super::AdvisoryOwnerId,
    pub(crate) owner_witness: &'a crate::archive_v3_witness::WitnessRecord,
    pub(crate) owner_revision: u64,
    pub(crate) owner_commitment: [u8; 32],
    pub(crate) release_commitment: [u8; 32],
    pub(crate) evidence_commitment: [u8; 32],
    pub(crate) commitment: [u8; 32],
}

impl AdvisoryComparisonSettlement {
    pub(crate) fn from_evidence_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        owner: &super::BoundAdvisoryOwner,
        release: &super::AdvisoryRelease,
        evidence: AdvisoryComparisonEvidence,
    ) -> Result<Self> {
        let (operation_id, owner_id, _, _, observed, _, owner_revision, owner_commitment) =
            owner.control_view(token);
        let release_view = release.control_view(token);
        if release_view.stage != super::AdvisoryReleaseStage::Released
            || release_view.archive_id != observed.archive_id()
            || release_view.operation_id != operation_id
            || release_view.owner_id != owner_id
            || release_view.owner_witness != observed
            || release_view.owner_revision != owner_revision
            || release_view.owner_commitment != owner_commitment
        {
            return Err(super::AdvisoryOwnerError::Conflict);
        }
        Self::from_control(
            token,
            release_view.archive_id,
            operation_id,
            owner_id,
            observed.clone(),
            owner_revision,
            owner_commitment,
            release_view.commitment,
            evidence._commitment,
            advisory_comparison_settlement_commitment(
                release_view.archive_id,
                operation_id,
                owner_id,
                observed,
                owner_revision,
                owner_commitment,
                release_view.commitment,
                evidence._commitment,
            ),
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
        evidence_commitment: [u8; 32],
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        if archive_id != owner_witness.archive_id()
            || owner_witness.deletion() != crate::archive_v3_witness::DeletionState::Active
            || owner_witness.migration() != crate::archive_v3_witness::MigrationState::ShadowWal
            || owner_revision == 0
            || owner_commitment == [0; 32]
            || release_commitment == [0; 32]
            || evidence_commitment == [0; 32]
        {
            return Err(super::AdvisoryOwnerError::Corrupt);
        }
        let commitment = advisory_comparison_settlement_commitment(
            archive_id,
            operation_id,
            owner_id,
            &owner_witness,
            owner_revision,
            owner_commitment,
            release_commitment,
            evidence_commitment,
        );
        if commitment == [0; 32] || commitment != persisted_commitment {
            return Err(super::AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            archive_id,
            operation_id,
            owner_id,
            owner_witness,
            owner_revision,
            owner_commitment,
            release_commitment,
            evidence_commitment,
            commitment,
        })
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> AdvisoryComparisonSettlementControlView<'_> {
        AdvisoryComparisonSettlementControlView {
            archive_id: self.archive_id,
            operation_id: self.operation_id,
            owner_id: self.owner_id,
            owner_witness: &self.owner_witness,
            owner_revision: self.owner_revision,
            owner_commitment: self.owner_commitment,
            release_commitment: self.release_commitment,
            evidence_commitment: self.evidence_commitment,
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
            return Err(super::AdvisoryOwnerError::Conflict);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn advisory_comparison_settlement_commitment(
    archive_id: crate::archive_v3::ArchiveId,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    owner_id: super::AdvisoryOwnerId,
    owner_witness: &crate::archive_v3_witness::WitnessRecord,
    owner_revision: u64,
    owner_commitment: [u8; 32],
    release_commitment: [u8; 32],
    evidence_commitment: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ADVISORY_COMPARISON_SETTLEMENT_DOMAIN);
    hasher.update(1_u16.to_be_bytes());
    hasher.update(archive_id.as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(owner_id.as_bytes());
    hasher.update(owner_witness.encode());
    hasher.update(owner_revision.to_be_bytes());
    hasher.update(owner_commitment);
    hasher.update(release_commitment);
    hasher.update(evidence_commitment);
    hasher.finalize().into()
}

pub(super) async fn compare_captured_prefix(
    owner: &LocallyResumedSingleArchiveAdvisoryOwner,
) -> Result<AdvisoryComparisonEvidence> {
    let token = AdvisoryComparisonContext(());
    reauthenticate_boundary(owner).await?;
    let drain = owner.begin_capture_drain().await?;
    let expected = owner._owner._bound.observed().clone();
    let recovered = owner
        ._owner
        ._runtime
        .recover_advisory_comparison_staging(&token, &expected)
        .await
        .map_err(|_| AdvisoryOwnerError::Publication)?;
    let local = drain
        .compare_recovered_advisory(token, recovered)
        .await
        .map_err(super::map_advisory_store_error)?;
    reauthenticate_boundary(owner).await?;

    Ok(bind_evidence(owner, token, local))
}

#[cfg(test)]
pub(super) async fn compare_captured_prefix_with_stall(
    owner: &LocallyResumedSingleArchiveAdvisoryOwner,
    stall: std::sync::Arc<crate::store::AdvisoryComparisonStall>,
) -> Result<AdvisoryComparisonEvidence> {
    let token = AdvisoryComparisonContext(());
    reauthenticate_boundary(owner).await?;
    let drain = owner.begin_capture_drain().await?;
    let expected = owner._owner._bound.observed().clone();
    let recovered = owner
        ._owner
        ._runtime
        .recover_advisory_comparison_staging(&token, &expected)
        .await
        .map_err(|_| AdvisoryOwnerError::Publication)?;
    let local = drain
        .compare_recovered_advisory_stalled_for_test(token, recovered, stall)
        .await
        .map_err(super::map_advisory_store_error)?;
    reauthenticate_boundary(owner).await?;

    Ok(bind_evidence(owner, token, local))
}

fn bind_evidence(
    owner: &LocallyResumedSingleArchiveAdvisoryOwner,
    token: AdvisoryComparisonContext,
    local: crate::store::StoreAdvisoryComparisonEvidence,
) -> AdvisoryComparisonEvidence {
    let mut hasher = Sha256::new();
    hasher.update(ADVISORY_COMPARISON_EVIDENCE_DOMAIN);
    hasher.update(
        owner
            ._owner
            ._parity
            .operation_id_for_advisory_owner(AdvisoryOwnerRuntimeContext(()))
            .as_bytes(),
    );
    hasher.update(owner._owner._bound.commitment);
    hasher.update(owner._release.commitment);
    hasher.update(owner._owner._bound.observed().encode());
    hasher.update(local.commitment_for_advisory_owner(token));
    AdvisoryComparisonEvidence {
        _commitment: hasher.finalize().into(),
    }
}

pub(super) async fn reauthenticate_boundary(
    owner: &LocallyResumedSingleArchiveAdvisoryOwner,
) -> Result<()> {
    let operation_id = owner
        ._owner
        ._parity
        .operation_id_for_advisory_owner(AdvisoryOwnerRuntimeContext(()));
    let terminal =
        MaintenanceImportPersistence::load_exact(owner._owner._control.as_ref(), operation_id)
            .await
            .map_err(|_| AdvisoryOwnerError::Persistence)?;
    owner
        ._owner
        ._parity
        .reauthenticate_for_advisory_owner(
            AdvisoryOwnerRuntimeContext(()),
            &terminal,
            &owner._owner._bound.expected,
        )
        .map_err(|_| AdvisoryOwnerError::Conflict)?;
    let release = owner
        ._owner
        ._control
        .load_advisory_release(AdvisoryOwnerRuntimeContext(()), &owner._owner._bound)
        .await?
        .ok_or(AdvisoryOwnerError::Conflict)?;
    if release.stage != AdvisoryReleaseStage::Released || release != owner._release {
        return Err(AdvisoryOwnerError::Conflict);
    }
    let current = owner
        ._owner
        ._runtime
        .read_advisory_owner_current_exact(
            &AdvisoryOwnerRuntimeContext(()),
            owner._owner._bound.observed().archive_id(),
        )
        .await
        .map_err(|_| AdvisoryOwnerError::Publication)?;
    if current != *owner._owner._bound.observed() {
        return Err(AdvisoryOwnerError::Conflict);
    }
    Ok(())
}

impl std::fmt::Debug for AdvisoryComparisonEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdvisoryComparisonEvidence(<opaque>)")
    }
}

impl std::fmt::Debug for AdvisoryComparisonSettlement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdvisoryComparisonSettlement(<opaque>)")
    }
}
