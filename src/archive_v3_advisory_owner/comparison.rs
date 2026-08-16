//! Owner-private Phase-1 comparison worker.
//!
//! The worker reauthenticates the exact maintenance source, released owner
//! row, and current ShadowWal witness on both sides of local work. It recovers
//! only the witness-nominated immutable graph, consumes an opaque Store
//! snapshot/drain pair, and retains only one domain-separated commitment.
//! There is deliberately no settlement, acknowledgement, provider mutation,
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

/// Content-free local evidence. It is intentionally non-cloneable and has no
/// production getter in this slice; a later durable-settlement review must
/// define how an exact instance can be consumed.
pub(super) struct AdvisoryComparisonEvidence {
    _commitment: [u8; 32],
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

async fn reauthenticate_boundary(owner: &LocallyResumedSingleArchiveAdvisoryOwner) -> Result<()> {
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
