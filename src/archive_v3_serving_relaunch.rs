//! Config-gated startup relaunch of WAL serving authorities (ADR-0022,
//! docs/adr/0022-solo-operator-activation.md).
//!
//! For every user whose archive durably reached the `wal_authoritative`
//! terminal — on the maintenance-import ledger or the genesis control
//! ledger — serving startup reconstructs the WAL-owner handoff from durable
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

/// What one selection's relaunch actually achieved.
///
/// The two variants differ in the archive's epoch, never in whether the user
/// is being served: both mean an authority is installed and every routed read
/// and submit will reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelaunchOutcome {
    /// Installed, serving, and at this binary's target epoch.
    Serving { advanced: bool },
    /// Installed and serving, at the epoch the archive recorded. Every
    /// intermediate epoch is a complete servable state, so this is a degraded
    /// but correct outcome — not an outage.
    ServingBehindTarget { advanced: bool },
    /// Installed and serving, at an epoch this binary cannot describe.
    /// Structurally unreachable — see [`advance_to_target_epoch`].
    ServingUnservableEpoch { advanced: bool },
}

/// Content-free startup counts. Counts only — never a user id or an epoch.
///
/// `relaunched + unavailable` is every selection. `behind_target` and
/// `unservable_epoch` are SUBSETS of `relaunched`: those users are serving,
/// which is exactly why they must not be counted as unavailable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RelaunchCounts {
    pub(crate) relaunched: usize,
    pub(crate) unavailable: usize,
    /// Selections whose durably re-read epoch marker is at or beyond this
    /// binary's target. Unlike `advanced`, this remains true after a process
    /// exits between settling the advance and emitting the startup metric.
    pub(crate) at_target: usize,
    /// Selections whose durable schema marker advanced by at least one rung
    /// during this exact process launch.
    pub(crate) advanced: usize,
    pub(crate) behind_target: usize,
    pub(crate) unservable_epoch: usize,
}

impl RelaunchCounts {
    /// Every durable selection lands in exactly one of relaunched/unavailable.
    pub(crate) fn selected(self) -> usize {
        self.relaunched
            .checked_add(self.unavailable)
            .expect("relaunch subsets cannot exceed the loaded selection set")
    }
}

/// Relaunch every selected user's WAL serving authority before request
/// admission.
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
) -> Result<RelaunchCounts> {
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
        return Ok(RelaunchCounts::default());
    }
    // KMS is consumed lazily: the no-op and refusal paths above never
    // construct it, which the unit tests pin.
    let kms = kms()?;
    let mut counts = RelaunchCounts::default();
    for selection in selections {
        let outcome = relaunch_one(&kms, &control, &store, &selection).await;
        count_outcome(outcome, &mut counts);
    }
    Ok(counts)
}

/// Fold one selection's outcome into the counts.
///
/// Extracted so the containment decision is testable on its own: a
/// per-selection failure becomes a count, never an early return; every other
/// selection still launches.
///
/// `Err` here means the authority was never installed, and only that. The user
/// is then left without a serving authority, which the routed read refuses.
/// **A failure that happens after the install is not an `Err` and must never
/// become one** — see [`relaunch_one`].
fn count_outcome(outcome: Result<RelaunchOutcome>, counts: &mut RelaunchCounts) {
    match outcome {
        Ok(reached) => {
            counts.relaunched += 1;
            match reached {
                RelaunchOutcome::Serving { advanced } => {
                    counts.at_target += 1;
                    counts.advanced += usize::from(advanced);
                }
                RelaunchOutcome::ServingBehindTarget { advanced } => {
                    counts.advanced += usize::from(advanced);
                    counts.behind_target += 1;
                }
                RelaunchOutcome::ServingUnservableEpoch { advanced } => {
                    counts.advanced += usize::from(advanced);
                    counts.behind_target += 1;
                    counts.unservable_epoch += 1;
                }
            }
        }
        Err(_) => counts.unavailable += 1,
    }
}

/// Relaunch exactly one selection. Every failure here is scoped to this user.
///
/// # Why nothing after the install may return `Err`
///
/// `install_wal_serving_authority` is install-once and there is deliberately
/// **no removal API** — `WalServingLane` holds exactly one authority for its
/// whole life, so no code path can leave a registered user unregistered. The
/// consequence is unavoidable and load-bearing: once line-by-line control
/// passes the install, this user IS being served. `wal_serving_lane` will
/// resolve for them, and every routed read and submit reaches the authority.
///
/// So an `Err` returned after the install would be counted `unavailable` and
/// logged as offline while the lane served every request for the whole process
/// lifetime — a health signal that says the exact opposite of the truth, and
/// nothing retries, because relaunch runs once at startup and a second install
/// refuses with `Conflict`. That is why [`advance_to_target_epoch`] is
/// infallible: the epoch advance decides how far the archive got, never
/// whether the user exists.
async fn relaunch_one(
    kms: &Arc<GcpKmsClient>,
    control: &Arc<ControlStore>,
    store: &Arc<Store>,
    selection: &crate::cp::control_store::WalAuthoritativePersistenceSelection,
) -> Result<RelaunchOutcome> {
    let (archive_id, authority) =
        build_wal_serving_authority(kms, control, selection.user_id()).await?;
    store.install_wal_serving_authority(selection.user_id(), archive_id, Arc::new(authority))?;
    // Past this line the user is registered and serving. Nothing below may
    // propagate: it reports how far the ladder got, and that is all.
    Ok(advance_to_target_epoch(store, selection.user_id()).await)
}

/// Carry this archive to the epoch this binary drives to, one step per
/// transaction, before any product request is admitted.
///
/// Placed here and not on the request path on purpose: the authority is
/// installed immediately above, so the routed submit has somewhere to go.
///
/// # Infallible by construction
///
/// Not a swallowed error — a refusal to make this a failure at all. Every way
/// the loop can stop short leaves the archive **exactly** at the epoch its
/// marker records, which is a complete servable state: a step is one
/// all-or-nothing transaction, the owner is not poisoned by a refused apply,
/// and `SCHEMA_EPOCH_MIN_SERVABLE` is only raised (runbook step 8) once every
/// archive reports the new epoch, so an archive that stalls at `N-1` never
/// becomes unservable. Reporting that as an outage would be false, and — since
/// the lane cannot be uninstalled — would also be unactionable.
///
/// The stall is instead an operator signal: `behind_target` is what blocks
/// runbook step 8, and a step that no archive can take is a step to be split
/// or withdrawn, never one to be forced. There is no path that applies a step
/// larger than one publishable commit without poisoning the owner, which is
/// what the write budget in `cp::schema_epoch::wal::advance` refuses ahead of.
///
/// The loop is bounded by the ladder, not by a retry budget: each iteration
/// advances exactly one epoch, and `AlreadyAtTarget` is reached in at most
/// `SCHEMA_EPOCH_TARGET` steps. An `Err` from the driver stops it — the
/// archive did not move, and re-attempting the identical plan in the same
/// process would fail identically.
///
/// `RefusedNotServable` is reported distinctly and is structurally unreachable
/// here: the owner's own open runs `validate_servable_epoch` on the same
/// marker (`store::open_wal_owner_connection`), so an archive this binary
/// cannot describe fails `build_wal_serving_authority` and is counted
/// `unavailable` before the install. It is retained as a second line and given
/// its own counter so that, if it ever did fire, it would be visible rather
/// than folded into the ordinary stall.
async fn advance_to_target_epoch(store: &Arc<Store>, user_id: &str) -> RelaunchOutcome {
    use crate::cp::schema_epoch::wal::{advance_one_epoch, AdvanceOutcome};

    // Every intermediate epoch is a complete, servable state, so an
    // interruption anywhere in this loop leaves a servable archive at a
    // well-defined epoch and the next relaunch resumes from its marker.
    let mut advanced = false;
    loop {
        match advance_one_epoch(store, user_id).await {
            Ok(AdvanceOutcome::Advanced { .. }) => {
                advanced = true;
                continue;
            }
            Ok(AdvanceOutcome::AlreadyAtTarget(_)) => return RelaunchOutcome::Serving { advanced },
            Ok(AdvanceOutcome::RefusedNotServable(_)) => {
                return RelaunchOutcome::ServingUnservableEpoch { advanced }
            }
            Err(_) => return RelaunchOutcome::ServingBehindTarget { advanced },
        }
    }
}

/// Build one user's serving authority from durable state.
///
/// This is the whole launch ladder, extracted verbatim from the startup loop
/// body so startup and the in-process relaunch driver share it byte for byte:
/// `from_baked_env` -> `PendingSingleArchiveWalRuntime::new` ->
/// `active_archive_binding` -> `bind_once` -> `reconstruct_wal_serving_handoff`
/// -> `SingleArchiveWalServingAuthority::launch`. Startup calls this and then
/// installs the slot; the driver calls this and then replaces the authority
/// inside an already-installed slot. ONE ladder, ONE set of predicates, ONE
/// code path — the driver adds no branch, no witness read, no lease call, and
/// no Control write of its own, so any provider or Control interleaving it can
/// produce is one the startup relaunch can already produce.
///
/// Returns the archive id the authority actually bound, so the slot can refuse
/// a successor built for a different archive.
pub(crate) async fn build_wal_serving_authority(
    kms: &Arc<GcpKmsClient>,
    control: &Arc<ControlStore>,
    user_id: &str,
) -> Result<(
    [u8; 16],
    crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority,
)> {
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
    let binding = control.active_archive_binding(user_id).await?;
    let archive_id = *binding.archive_id().as_bytes();
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
    Ok((archive_id, authority))
}

/// The in-process relaunch driver. It holds the same two dependencies the
/// startup relaunch holds and does exactly one thing: call the shared ladder.
pub(crate) struct StartupWalServingRelaunch {
    kms: Arc<GcpKmsClient>,
    control: Arc<ControlStore>,
}

impl StartupWalServingRelaunch {
    pub(crate) const fn new(kms: Arc<GcpKmsClient>, control: Arc<ControlStore>) -> Self {
        Self { kms, control }
    }
}

#[async_trait::async_trait]
impl crate::store::WalServingRelaunch for StartupWalServingRelaunch {
    async fn rebuild(
        &self,
        user_id: &str,
    ) -> Result<(
        [u8; 16],
        Arc<crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority>,
    )> {
        let (archive_id, authority) =
            build_wal_serving_authority(&self.kms, &self.control, user_id).await?;
        Ok((archive_id, Arc::new(authority)))
    }
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
        let counts = relaunch_wal_serving_authorities(
            || panic!("the no-op relaunch path must not construct KMS"),
            control,
            store,
        )
        .await
        .unwrap();
        assert_eq!(counts, RelaunchCounts::default());
        assert_eq!((counts.selected(), counts.advanced), (0, 0));
    }

    #[test]
    fn the_rollout_metric_is_content_free_complete_and_before_request_admission() {
        let source = include_str!("main.rs");
        let start = source
            .find("metric = \"archive_v3_schema_epoch_rollout\"")
            .expect("schema rollout metric is missing");
        let block = &source[start
            ..source[start..]
                .find("    );")
                .map(|end| start + end + 7)
                .expect("schema rollout metric is unterminated")];
        for field in [
            "schema_epoch_head",
            "schema_epoch_target",
            "schema_epoch_min_servable",
            "selected",
            "relaunched",
            "at_target",
            "advanced",
            "behind_target",
            "unservable_epoch",
            "unavailable",
        ] {
            assert!(block.contains(field), "rollout metric omitted {field}");
        }
        for forbidden in ["user_id", "archive_id", "account_id", "step_id", "step_sql"] {
            assert!(
                !block.contains(forbidden),
                "rollout metric contains sensitive/per-account field {forbidden}"
            );
        }
        let relaunch = source
            .find("archive_v3_serving_relaunch::relaunch_wal_serving_authorities(")
            .expect("startup relaunch moved");
        let admission = source
            .find("install_wal_serving_relaunch(")
            .expect("startup serving supervisor moved");
        assert!(
            relaunch < start && start < admission,
            "the aggregate must authenticate the completed startup relaunch before admission plumbing"
        );
    }

    #[test]
    fn only_a_durable_advanced_outcome_sets_the_advanced_count() {
        let source = include_str!("archive_v3_serving_relaunch.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        let advance = &production[production
            .find("async fn advance_to_target_epoch(")
            .expect("advance function moved")..];
        let applied = advance
            .find("Ok(AdvanceOutcome::Advanced { .. })")
            .expect("durable advanced outcome moved");
        let mark = advance
            .find("advanced = true")
            .expect("advanced marker moved");
        let already = advance
            .find("Ok(AdvanceOutcome::AlreadyAtTarget(_))")
            .expect("already-at-target outcome moved");
        assert!(applied < mark && mark < already);
        assert_eq!(advance.matches("advanced = true").count(), 1);
    }

    #[test]
    fn a_failed_selection_is_counted_unavailable_and_never_propagates() {
        let mut counts = RelaunchCounts::default();
        count_outcome(
            Ok(RelaunchOutcome::Serving { advanced: false }),
            &mut counts,
        );
        count_outcome(
            Err(EnclaveError::Conflict("reconstruction failed".into())),
            &mut counts,
        );
        count_outcome(
            Err(EnclaveError::Store("the authority failed to launch".into())),
            &mut counts,
        );
        count_outcome(Ok(RelaunchOutcome::Serving { advanced: true }), &mut counts);
        // Two users are unavailable and two are serving. Before containment
        // the first failure ended startup for the entire fleet.
        assert_eq!((counts.relaunched, counts.unavailable), (2, 2));
        assert_eq!(
            (counts.selected(), counts.at_target, counts.advanced),
            (4, 2, 1)
        );
        assert_eq!((counts.behind_target, counts.unservable_epoch), (0, 0));
    }

    #[test]
    fn at_target_survives_a_crash_after_the_durable_advance_before_the_metric() {
        // Direct TARGET launch: this process observed the durable apply and
        // then re-read the marker at target.
        let mut direct = RelaunchCounts::default();
        count_outcome(Ok(RelaunchOutcome::Serving { advanced: true }), &mut direct);
        assert_eq!((direct.at_target, direct.advanced), (1, 1));

        // Lost startup metric: the first process may exit after the durable
        // 0 -> 1 commit but before logging. Its replacement re-reads the
        // marker as AlreadyAtTarget and must retain the proof-bearing state
        // without pretending that the replacement performed the commit.
        let mut replacement = RelaunchCounts::default();
        count_outcome(
            Ok(RelaunchOutcome::Serving { advanced: false }),
            &mut replacement,
        );
        assert_eq!((replacement.at_target, replacement.advanced), (1, 0));
    }

    #[test]
    fn an_archive_that_did_not_reach_the_target_is_counted_serving_not_unavailable() {
        // The health signal has to match what the lane actually does. The
        // authority is installed before the epoch advance runs and there is no
        // removal API, so a user whose advance failed IS served by every routed
        // read and submit for the whole process lifetime. Counting them
        // `unavailable` said the exact opposite, and nothing retried.
        let mut counts = RelaunchCounts::default();
        count_outcome(
            Ok(RelaunchOutcome::ServingBehindTarget { advanced: true }),
            &mut counts,
        );
        count_outcome(
            Ok(RelaunchOutcome::ServingUnservableEpoch { advanced: false }),
            &mut counts,
        );
        count_outcome(
            Ok(RelaunchOutcome::Serving { advanced: false }),
            &mut counts,
        );
        assert_eq!(
            counts,
            RelaunchCounts {
                relaunched: 3,
                unavailable: 0,
                at_target: 1,
                advanced: 1,
                behind_target: 2,
                unservable_epoch: 1,
            },
            "a stalled ladder is a degraded epoch, never an outage"
        );
        // `behind_target` and `unservable_epoch` are strict subsets of the
        // users who ARE serving, and every selection lands in exactly one of
        // `relaunched` / `unavailable`.
        assert!(counts.behind_target <= counts.relaunched);
        assert!(counts.unservable_epoch <= counts.behind_target);
        assert_eq!(counts.at_target + counts.behind_target, counts.relaunched);
        assert!(counts.advanced <= counts.relaunched);
    }

    #[test]
    fn the_epoch_advance_can_never_make_a_registered_user_unavailable() {
        // Structural, because the property is structural: the install happens
        // first and cannot be undone, so `relaunch_one` must not carry a `?`
        // past it. A `?` on the advance is exactly the defect this test
        // exists to keep out.
        let source = include_str!("archive_v3_serving_relaunch.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        let body = &production[production
            .find("async fn relaunch_one(")
            .expect("relaunch_one moved")..];
        let body = &body[..body
            .find("/// Carry this archive to the epoch")
            .expect("advance_to_target_epoch moved")];
        let after_install = &body[body
            .find("install_wal_serving_authority(")
            .expect("the install moved")..];
        assert!(
            after_install.contains("advance_to_target_epoch(store, selection.user_id()).await)"),
            "the advance must be returned as an outcome, not propagated"
        );
        assert!(
            !after_install.contains("advance_to_target_epoch(store, selection.user_id()).await?"),
            "a `?` on the epoch advance counts a serving user as unavailable"
        );
        // And the advance itself must not be able to produce an `Err` at all.
        let advance = &production[production
            .find("async fn advance_to_target_epoch(")
            .expect("advance_to_target_epoch moved")..];
        assert!(
            advance.starts_with(
                "async fn advance_to_target_epoch(store: &Arc<Store>, user_id: &str) \
                 -> RelaunchOutcome {"
            ),
            "advance_to_target_epoch must be infallible by signature"
        );
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
            .find("\n    Ok(counts)")
            .expect("the relaunch loop's return moved")];
        assert!(loop_body.contains("relaunch_one("));
        assert!(
            loop_body.contains("count_outcome(outcome, &mut counts)"),
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
            "build_wal_serving_authority",
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

    #[test]
    fn the_driver_adds_no_launch_branch() {
        // The relaunch driver's entire value rests on it having no ladder of
        // its own: it must reach durable state only through the same
        // `build_wal_serving_authority` the startup relaunch uses, so the
        // durable stage picks the predicate and no lease, witness, or evidence
        // can be fabricated for a successor. Structural, because the property
        // is structural.
        let source = include_str!("archive_v3_serving_relaunch.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        let ladder = &production[production
            .find("pub(crate) async fn build_wal_serving_authority(")
            .expect("the shared ladder moved")..];
        let ladder = &ladder[..ladder
            .find("pub(crate) struct StartupWalServingRelaunch")
            .expect("the driver moved")];
        for required in [
            concat!("from_baked_", "env()"),
            concat!("bind_", "once("),
            "reconstruct_wal_serving_handoff",
            "SingleArchiveWalServingAuthority::launch",
        ] {
            assert!(ladder.contains(required), "the ladder lost {required}");
        }
        let driver = &production[production
            .find("pub(crate) struct StartupWalServingRelaunch")
            .unwrap()..];
        assert!(
            driver.contains("build_wal_serving_authority(&self.kms, &self.control, user_id)"),
            "the driver must construct only through the shared ladder"
        );
        for forbidden in [
            concat!("acquire_owner_", "lease"),
            concat!("reacquire_owner_", "lease"),
            concat!("maintain_owner_", "lease"),
            concat!("read_current_", "exact"),
            concat!("persist_owner_", "renewal"),
            concat!("rebind_owner_after_", "expiry"),
            concat!("bind_", "owner("),
            concat!("mark_owner_send_", "started"),
        ] {
            assert!(
                !driver.contains(forbidden),
                "the driver grew its own {forbidden} call"
            );
        }
    }
}
