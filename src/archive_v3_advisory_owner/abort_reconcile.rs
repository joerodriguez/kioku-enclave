//! Private restart reconciliation for a retained resumed-canary abort.
//!
//! This worker can only exact-load an existing Control terminal. A retained
//! `Prepared` row authorizes a read-only proof that the controller-owned Store
//! has no capture selector or registration; it cannot construct a Store,
//! mutate a provider, open a database, or synthesize a missing abort.

use std::sync::Arc;

use super::{
    AdvisoryAbortRecoveryState, AdvisoryAbortTerminal, AdvisoryOwnerControl, AdvisoryOwnerError,
    AdvisoryOwnerRuntimeContext, Result,
};

pub(super) async fn reconcile_prepared_abort(
    control: Arc<dyn AdvisoryOwnerControl>,
    store: Arc<crate::store::Store>,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
) -> Result<AdvisoryAbortTerminal> {
    tokio::spawn(async move { reconcile_prepared_abort_owned(control, store, operation_id).await })
        .await
        .map_err(|_| AdvisoryOwnerError::Publication)?
}

#[cfg(test)]
pub(super) async fn reconcile_prepared_abort_with_started(
    control: Arc<dyn AdvisoryOwnerControl>,
    store: Arc<crate::store::Store>,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    started: Arc<tokio::sync::Semaphore>,
) -> Result<AdvisoryAbortTerminal> {
    let task =
        tokio::spawn(
            async move { reconcile_prepared_abort_owned(control, store, operation_id).await },
        );
    started.add_permits(1);
    task.await.map_err(|_| AdvisoryOwnerError::Publication)?
}

async fn reconcile_prepared_abort_owned(
    control: Arc<dyn AdvisoryOwnerControl>,
    store: Arc<crate::store::Store>,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
) -> Result<AdvisoryAbortTerminal> {
    let recovery = loop {
        match control
            .load_advisory_abort_recovery(AdvisoryOwnerRuntimeContext(()), operation_id)
            .await
        {
            Ok(Some(AdvisoryAbortRecoveryState::Aborted(terminal))) => return Ok(terminal),
            Ok(Some(AdvisoryAbortRecoveryState::Prepared(recovery))) => break recovery,
            Ok(None) => return Err(AdvisoryOwnerError::Conflict),
            Err(AdvisoryOwnerError::Persistence) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    };
    let absence = loop {
        match store
            .prove_prepared_advisory_abort_local_absence(&recovery)
            .await
            .map_err(super::map_advisory_store_error)
        {
            Ok(absence) => break absence,
            Err(AdvisoryOwnerError::Publication) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    };
    loop {
        match control
            .finalize_advisory_abort_recovery(AdvisoryOwnerRuntimeContext(()), &recovery, &absence)
            .await
        {
            Ok(terminal) => return Ok(terminal),
            Err(AdvisoryOwnerError::Persistence) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    }
}
