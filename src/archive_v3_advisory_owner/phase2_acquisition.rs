//! Inactive Phase-2 WAL-authority acquisition driver.
//!
//! This child consumes one pinned-root-verified Phase-2 authorization and
//! turns it into the sole durable acquisition fact the authority importer's
//! gate re-reads. It holds the same per-user Store lifecycle lock the
//! maintenance admission and inactive release executor serialize on, freshly
//! reauthenticates the frozen advisory owner witness against the live runtime
//! reader inside that lock, and only then asks encrypted control to mint (or
//! exactly re-adopt) the one-shot acquisition row. There is no durable
//! resumed-local-admission marker; the retired advisory controller run that
//! control's mint requires is the strongest durable proxy for the fully
//! settled advisory terminal, and the doc contract of every type here says so
//! rather than pretending a resumed marker exists. The driver has no route,
//! startup hook, provider, serving, or acknowledgement capability, and it
//! cannot itself select `MaintenanceImportTarget::WalAuthoritative`.

use sha2::{Digest, Sha256};

use super::{
    map_advisory_store_error, AdvisoryOwnerError, AdvisoryOwnerRuntimeContext,
    AdvisoryOwnerWitnessProvider, Result, VerifiedPhase2AuthorityAuthorization,
};
use crate::archive_v3_maintenance_import::Phase2AcquiredAuthorityPlan;
use crate::cp::control_store::{ControlStore, Phase2AuthorityAcquisition};

/// Acquire Phase-2 WAL authority for one fully settled advisory terminal.
///
/// Order of operations, all under one exclusive user lifecycle guard:
/// 1. take `Store::lock_user_lifecycle` first, exactly like the maintenance
///    admission and the inactive release executor, so no stale waiter can
///    interleave with the durable transition;
/// 2. exact-load the durable bound advisory owner through encrypted control
///    (archive-keyed), freshly read the live witness through the same runtime
///    reader seam `reauthenticate_boundary` uses, and require byte equality
///    with the frozen `observed_witness` plus SHA-256 equality with the
///    verified statement's terminal witness hash;
/// 3. let control mint or exactly re-adopt the one-shot acquisition row (the
///    complete advisory-terminal predicate list lives with the control mint);
/// 4. seal the acquisition into the non-cloneable importer plan.
///
/// The guard drops only after the acquisition row is durable and the sealed
/// plan is built.
pub(crate) async fn acquire_phase2_authority(
    control: &ControlStore,
    store: &crate::store::Store,
    witness_reader: &dyn AdvisoryOwnerWitnessProvider,
    user_id: &str,
    authorization: &VerifiedPhase2AuthorityAuthorization,
) -> Result<(Phase2AcquiredAuthorityPlan, Phase2AuthorityAcquisition)> {
    let lifecycle_guard = store
        .lock_user_lifecycle(user_id)
        .await
        .map_err(map_advisory_store_error)?;
    let archive_id = authorization.statement().archive_id;
    let durable_owner = control
        .load_retained_advisory_owner_for_archive(AdvisoryOwnerRuntimeContext(()), archive_id)
        .await?;
    let current = witness_reader
        .read_current_exact(archive_id)
        .await
        .map_err(|_| AdvisoryOwnerError::Publication)?;
    if current != *durable_owner.observed() {
        return Err(AdvisoryOwnerError::Conflict);
    }
    let current_hash: [u8; 32] = Sha256::digest(current.encode()).into();
    if current_hash != authorization.statement().terminal_witness_hash {
        return Err(AdvisoryOwnerError::Conflict);
    }
    let (acquisition, _created) = control
        .acquire_phase2_authority(user_id, authorization.acquisition_evidence())
        .await
        .map_err(map_advisory_store_error)?;
    let plan = Phase2AcquiredAuthorityPlan::from_acquisition(
        acquisition.persistence_context(),
        user_id,
        &acquisition,
    )
    .map_err(|_| AdvisoryOwnerError::Corrupt)?;
    drop(lifecycle_guard);
    Ok((plan, acquisition))
}
