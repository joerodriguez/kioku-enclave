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
/// admission. Returns `(relaunched, unavailable)`.
///
/// A refusal that is scoped to one selection contains itself: that user comes
/// up unavailable and the rest of the fleet is admitted. This is safe rather
/// than lenient because `install_wal_authority_persistence` has already run
/// for *every* selection by the time this is called, so a user skipped here
/// still resolves to the WAL-only persistence policy — reads are refused as
/// routed, and the routed read finds no authority. Such a user can never be
/// served the stale legacy snapshot, which is the property that matters.
///
/// Failures that are *not* scoped to one selection — config disagreement,
/// loading the selections, reading the baked coordinates — still fail startup
/// closed for the whole process.
///
/// Logging stays content-free: the caller reports the counts only.
pub(crate) async fn relaunch_wal_serving_authorities(
    kms: impl FnOnce() -> Result<Arc<GcpKmsClient>>,
    control: Arc<ControlStore>,
    store: Arc<Store>,
) -> Result<(usize, usize)> {
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
        return Ok((0, 0));
    }
    // KMS is consumed lazily: the no-op and refusal paths above never
    // construct it, which the unit tests pin.
    let kms = kms()?;
    let mut relaunched = 0usize;
    let mut unavailable = 0usize;
    for selection in selections {
        let outcome = relaunch_one(&kms, &control, &store, &selection).await;
        count_outcome(outcome, &mut relaunched, &mut unavailable);
    }
    Ok((relaunched, unavailable))
}

/// Fold one selection's outcome into the counts.
///
/// Extracted so the containment decision is testable on its own: a
/// per-selection failure becomes a count, never an early return. The user is
/// left without a serving authority, which the routed read refuses; every
/// other selection still launches.
fn count_outcome(outcome: Result<()>, relaunched: &mut usize, unavailable: &mut usize) {
    match outcome {
        Ok(()) => *relaunched += 1,
        Err(_) => *unavailable += 1,
    }
}

/// Relaunch exactly one selection. Every failure here is scoped to this user.
async fn relaunch_one(
    kms: &Arc<GcpKmsClient>,
    control: &Arc<ControlStore>,
    store: &Arc<Store>,
    selection: &crate::cp::control_store::WalAuthoritativePersistenceSelection,
) -> Result<()> {
    // One bound runtime per archive: the pending runtime is bind-once, so
    // re-read the baked deployment for each selection.
    let deployment = ArchiveV3ShadowRuntimeDeployment::from_baked_env()
        .map_err(|_| {
            EnclaveError::Store("baked archive-v3 runtime coordinates are invalid".into())
        })?
        .ok_or_else(|| {
            EnclaveError::Store("baked archive-v3 runtime coordinates changed".into())
        })?;
    let pending = PendingSingleArchiveWalRuntime::new(deployment, Arc::clone(kms))
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
        .reconstruct_wal_serving_handoff(Arc::clone(control))
        .await
        .map_err(|_| {
            EnclaveError::Conflict(
                "the durable WAL-owner handoff could not be reconstructed".into(),
            )
        })?;
    let authority = crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::launch(handoff)
        .await
        .map_err(|_| EnclaveError::Store("the WAL serving authority failed to launch".into()))?;
    store.install_wal_serving_authority(selection.user_id(), Arc::new(authority))?;
    Ok(())
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
        let (relaunched, unavailable) = relaunch_wal_serving_authorities(
            || panic!("the no-op relaunch path must not construct KMS"),
            control,
            store,
        )
        .await
        .unwrap();
        assert_eq!((relaunched, unavailable), (0, 0));
    }

    #[test]
    fn a_failed_selection_is_counted_unavailable_and_never_propagates() {
        let (mut relaunched, mut unavailable) = (0usize, 0usize);
        count_outcome(Ok(()), &mut relaunched, &mut unavailable);
        count_outcome(
            Err(EnclaveError::Conflict("reconstruction failed".into())),
            &mut relaunched,
            &mut unavailable,
        );
        count_outcome(
            Err(EnclaveError::Store("the authority failed to launch".into())),
            &mut relaunched,
            &mut unavailable,
        );
        count_outcome(Ok(()), &mut relaunched, &mut unavailable);
        // Two users are unavailable and two are serving. Before containment
        // the first failure ended startup for the entire fleet.
        assert_eq!((relaunched, unavailable), (2, 2));
    }

    #[test]
    fn per_selection_failures_are_contained_rather_than_fleet_fatal() {
        // The containment is structural, so it is asserted structurally: the
        // loop must dispatch to `relaunch_one` and turn its `Err` into a
        // count, never into an early return. A `?` on per-selection work
        // inside the loop would take startup down for every user, including
        // users who are not WAL-authoritative at all.
        let source = include_str!("archive_v3_serving_relaunch.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        let loop_body = &production[production
            .find("for selection in selections {")
            .expect("the per-selection loop moved")..];
        let loop_body = &loop_body[..loop_body
            .find("\n    Ok((relaunched, unavailable))")
            .unwrap()];
        assert!(loop_body.contains("relaunch_one("));
        assert!(
            loop_body.contains("count_outcome(outcome, &mut relaunched, &mut unavailable)"),
            "a per-selection failure must be counted, not propagated"
        );
        assert!(
            !loop_body.contains('?'),
            "no per-selection failure may propagate out of the relaunch loop"
        );
        // What must stay fleet-fatal: an off-config image with selected users,
        // and loading the selections at all. Both sit before the loop.
        let preamble = &production[..production.find("for selection in selections {").unwrap()];
        assert!(
            preamble.contains("require_config_agreement(selections.len(), deployment.is_some())?")
        );
        assert!(preamble.contains("load_wal_authoritative_persistence_selections()"));
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
