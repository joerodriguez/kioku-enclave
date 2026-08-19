//! Config-gated startup relaunch of WAL serving authorities (ADR-0022,
//! docs/adr/0022-solo-operator-activation.md).
//!
//! For every user whose archive durably reached the `wal_authoritative`
//! terminal, serving startup reconstructs the WAL-owner handoff from durable
//! state through the image-baked runtime coordinates, launches the serving
//! authority (owner reservation/renewal with lost-response adoption inside
//! the publisher), and registers it with the Store so the routed dual-path
//! read serves the settled lane. Fail-closed agreement between config and
//! durable state: an off-config image with selected users refuses startup —
//! a WAL-authoritative user must never come up silently unavailable, and can
//! never be served the stale legacy snapshot. This module is the only
//! serving-path consumer of the baked coordinates; the pre-serving canary
//! argv path reads them separately and returns before any listener binds.

use std::sync::Arc;

use crate::{
    archive_v3_shadow_runtime::{
        ArchiveV3ShadowRuntimeDeployment, DurableSingleArchiveBinding,
        PendingSingleArchiveWalRuntime,
    },
    cp::control_store::ControlStore,
    crypto::GcpKmsClient,
    error::{EnclaveError, Result},
    store::Store,
};

/// Fail-closed agreement between the baked config and durable state: an
/// off-config image with WAL-authoritative users refuses startup — such a
/// user must never come up silently unavailable, and can never be served the
/// stale legacy snapshot.
fn require_config_agreement(selected_users: usize, deployment_active: bool) -> Result<()> {
    if selected_users > 0 && !deployment_active {
        return Err(EnclaveError::Conflict(
            "wal-authoritative users exist but the image's archive-v3 runtime mode is off".into(),
        ));
    }
    Ok(())
}

/// Relaunch every selected user's WAL serving authority before request
/// admission. Returns the number relaunched; every refusal fails startup
/// closed. Logging stays content-free: the caller reports the count only.
pub(crate) async fn relaunch_wal_serving_authorities(
    kms: impl FnOnce() -> Result<Arc<GcpKmsClient>>,
    control: Arc<ControlStore>,
    store: Arc<Store>,
) -> Result<usize> {
    let selections = control
        .load_wal_authoritative_persistence_selections()
        .await?;
    let deployment = ArchiveV3ShadowRuntimeDeployment::from_baked_env().map_err(|_| {
        EnclaveError::Store("baked archive-v3 runtime coordinates are invalid".into())
    })?;
    require_config_agreement(selections.len(), deployment.is_some())?;
    if selections.is_empty() {
        // No WAL-authoritative user exists; active or off, the image serves
        // the legacy path for everyone and nothing relaunches.
        return Ok(0);
    }
    // KMS is consumed lazily: the no-op and refusal paths above never
    // construct it, which the unit tests pin.
    let kms = kms()?;
    let mut relaunched = 0usize;
    for selection in selections {
        // One bound runtime per archive: the pending runtime is bind-once, so
        // re-read the baked deployment for each selection.
        let deployment = ArchiveV3ShadowRuntimeDeployment::from_baked_env()
            .map_err(|_| {
                EnclaveError::Store("baked archive-v3 runtime coordinates are invalid".into())
            })?
            .ok_or_else(|| {
                EnclaveError::Store("baked archive-v3 runtime coordinates changed".into())
            })?;
        let pending = PendingSingleArchiveWalRuntime::new(deployment, Arc::clone(&kms))
            .map_err(|_| EnclaveError::Store("archive-v3 runtime construction failed".into()))?;
        let binding = control.active_archive_binding(selection.user_id()).await?;
        let sealed = pending
            .bind_once(DurableSingleArchiveBinding::from_control_store(binding))
            .map_err(|_| {
                EnclaveError::Conflict(
                    "the bound archive does not match the image's baked binding commitment".into(),
                )
            })?;
        let handoff = sealed
            .reconstruct_wal_serving_handoff(Arc::clone(&control))
            .await
            .map_err(|_| {
                EnclaveError::Conflict(
                    "the durable WAL-owner handoff could not be reconstructed".into(),
                )
            })?;
        let authority =
            crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::launch(handoff)
                .await
                .map_err(|_| {
                    EnclaveError::Store("the WAL serving authority failed to launch".into())
                })?;
        store.install_wal_serving_authority(selection.user_id(), Arc::new(authority))?;
        relaunched += 1;
    }
    Ok(relaunched)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_agreement_refuses_selected_users_on_an_off_image() {
        require_config_agreement(0, false).unwrap();
        require_config_agreement(0, true).unwrap();
        require_config_agreement(1, true).unwrap();
        assert!(matches!(
            require_config_agreement(1, false),
            Err(EnclaveError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn relaunch_is_a_no_op_without_selected_users() {
        use crate::store::tests::{FakeGcs, FakeKms};
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let store = Arc::new(Store::new(Arc::new(FakeKms), Arc::new(FakeGcs::new())));
        // The test environment has no baked coordinates (mode off) and no
        // selected users: the relaunch is an exact no-op. KMS is consumed
        // lazily and this closure proves the no-op path never constructs it.
        let relaunched = relaunch_wal_serving_authorities(
            || panic!("the no-op relaunch path must not construct KMS"),
            control,
            store,
        )
        .await
        .unwrap();
        assert_eq!(relaunched, 0);
    }

    #[test]
    fn relaunch_surface_is_startup_only_and_content_free() {
        let source = include_str!("archive_v3_serving_relaunch.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        for required in [
            "load_wal_authoritative_persistence_selections",
            concat!("from_baked_", "env()"),
            concat!("bind_", "once("),
            "reconstruct_wal_serving_handoff",
            "install_wal_serving_authority",
            concat!("archive-v3 runtime mode is ", "off"),
        ] {
            assert!(source.contains(required), "missing {required}");
        }
        for forbidden in [
            concat!("Store::", "new"),
            concat!("list_", "objects"),
            concat!("delete_", "exact"),
            concat!("std::env::", "var"),
            concat!("user_id ", "="),
            concat!("info!", "("),
            concat!("warn!", "("),
        ] {
            assert!(
                !production.contains(forbidden),
                "found forbidden {forbidden}"
            );
        }
    }
}
