//! Config-gated ADR-0022 genesis trigger at sign-in (genesis spine G9).
//!
//! Every interactive sign-in already lands on the encrypted control store's
//! `create_active_archive_binding_conn` path, which mints one `active_legacy`
//! archive binding for a new account. This module hangs the genesis spine off
//! that path: after the sign-in transaction has durably committed, a
//! detached convergence pass brings the bound archive from "binding row only"
//! to "durably `wal_authoritative`, selected, and served", and then stops.
//!
//! Three properties are load-bearing, and each is a separate design decision:
//!
//! 1. **Gated.** [`genesis_wal_native_from_baked_env`] defaults to FALSE, and
//!    genesis additionally requires the image-baked archive-v3 runtime
//!    coordinates. Production images bake `ARCHIVE_V3_SHADOW_RUNTIME_MODE=off`
//!    (the release tooling refuses to roll otherwise), so on a production
//!    image today the gate is structurally false no matter what the ambient
//!    environment says. `GENESIS_WAL_NATIVE` is itself an allowlisted baked
//!    image key: `load_baked_image_configuration` overwrites the ambient value
//!    with the image's before any of this runs, and refuses to start an image
//!    that omits it. Flipping the gate is therefore an image rebuild and
//!    redeploy under a new attested digest — not a restart, not an env change,
//!    and not a deploy accident.
//! 2. **Never blocking.** [`spawn_genesis_convergence`] detaches. Sign-in
//!    completes on the ordinary path whether genesis succeeds, fails, or never
//!    runs at all. A wedged, unavailable, or refused genesis costs a user
//!    nothing they had before it.
//! 3. **Idempotent and resumable.** Every step is either an exact durable
//!    replay or a fresh clean retry, so a half-genesis user converges on their
//!    next request instead of wedging. The convergence pass is safe to run any
//!    number of times, concurrently or after any crash.
//!
//! ## Crash points, and why each converges
//!
//! **Before `prepare_archive_bootstrap`, a crash orphans one checkpoint's
//! objects and the retry mints a fresh DEK. After it, replay is byte-exact.**
//! Those orphans are durably named: every object is reserved in the encrypted
//! control store's genesis staging inventory before its provider create, so
//! the existing inventory/reachability family can enumerate them by exact
//! canonical key instead of facing unnameable residue.
//!
//! Which side of that boundary a pass is on is decided by the DURABLE anchor,
//! not by the pass: [`run_durable_genesis`] recovers before it produces, and a
//! recovered `Prepared` anchor skips byte production and the prepare entirely.
//! Stating only "replay is byte-exact" would be materially incomplete, because
//! a post-boundary pass does not produce-then-replay — it produces nothing.
//! That is load-bearing rather than merely thrifty. `prepare_archive_bootstrap`
//! returns the STORED payloads at `objects_prepared`, `witness_prepared`, and
//! `witnessed`, so bytes produced after the boundary are discarded; but a fresh
//! `ArchiveDek` yields a different wrapped registry, and the staging binding is
//! derived from that registry's hash. Producing anyway would latch the
//! producer's staging phase to a binding the witness ladder — which builds its
//! binding from the stored hash — could never present, wedging every later
//! pass. It would also cost one DEK, one full checkpoint upload, and several
//! encrypted control-DB generations on every `token_refresh` that reached a
//! non-terminal archive, and would eventually exhaust the deliberately bounded
//! `staging_ordinal` domain.
//!
//! * **C0 — after the sign-in transaction commits the binding, before (or
//!   instead of) the convergence pass.** Nothing genesis-durable exists. The
//!   binding is `active_legacy` with no genesis ledger row; the next sign-in
//!   re-enters convergence and starts from the beginning. No duplicate, no
//!   wedge, and the user keeps the ordinary legacy path meanwhile.
//! * **C1 — inside the bootstrap reservation, after its compare-and-swap
//!   committed but before the driver observed the outcome.** The lifecycle
//!   anchor now holds exactly one random plan for this archive. The retry
//!   recovers that exact reserved plan first and re-adopts it; the reservation
//!   CAS refuses any competing plan for the same archive, so one archive can
//!   never acquire two bootstrap attempts.
//! * **C2 — during byte production, after one or more checkpoint objects were
//!   created.** This is the pre-boundary window quoted above, and the only
//!   window in which a pass produces bytes twice: the anchor is still merely
//!   `Reserved`, so the retry re-adopts the same reservation, mints a fresh
//!   DEK, and stages new object identities at new staging ordinals under a
//!   fresh producer inventory. The staging log is append-only and never
//!   rewrites the dead attempt's rows, so the orphans stay enumerable. No
//!   witness exists yet, so there is nothing to duplicate.
//! * **C3 — at `prepare_archive_bootstrap` with the outcome unknown.** The
//!   prepare is one encrypted-control transaction: it either durably recorded
//!   both exact byte payloads under the reservation or it did not. If it did,
//!   the retry recovers a `Prepared` anchor and resumes from those exact
//!   stored bytes, producing none of its own; if it did not, the anchor is
//!   still `Reserved` and the retry produces and prepares fresh bytes. Either
//!   way exactly one prepared bootstrap survives, and the retry never holds
//!   bytes that disagree with it.
//! * **C4 — during genesis resolution (registry object, root object, initial
//!   witness).** The anchor is `Prepared`, so the retry resumes from the
//!   stored payloads rather than producing. Every object create is
//!   create-if-absent plus byte-exact readback, and the witness create runs
//!   the sealed send-started protocol, so the retry converges on the same
//!   registry, the same root, and the same witness. Never two witnesses, and
//!   never a second DEK.
//! * **C5 — after resolution, before the `genesis_created` ledger stage.**
//!   The witness rests at `Legacy`/root sequence 0 and no ledger row exists.
//!   The retry resumes from the same `Prepared` anchor, re-resolves
//!   (idempotent), reads the same sequence-0 record, and records the stage.
//!   Recording `genesis_created` strictly before the ladder is entered is what
//!   makes this safe: a witness observed beyond genesis therefore always has a
//!   ledger row to resume from, and can never demand the sequence-0 bytes the
//!   ladder has already overwritten.
//! * **C6 — between the two ladder advances (witness at `ShadowWal`, root
//!   sequence 1).** The ladder re-reads the witness and resumes at the second
//!   advance. Its owner identity is derived from the durably reserved attempt,
//!   so a restarted driver validates and reuses its own retained lease instead
//!   of fencing itself out. Its staging binding is derived from the anchor's
//!   stored wrapped-registry hash, which the resumed pass carries unchanged,
//!   so the rung stages against the one binding its own inventory instance
//!   latches. Exactly two ladder roots are ever published.
//! * **C7 — after the terminal advance, before or during the terminal lease
//!   release.** The ladder re-reads, sees `WalAuthoritative`, and either
//!   releases its own retained lease or adopts an already-released terminal.
//!   It never clears another actor's lease.
//! * **C8 — after the released terminal, before the `wal_authoritative`
//!   ledger stage.** The row is still `genesis_created`. The retry re-runs the
//!   ladder, which converges on the same released terminal without a third
//!   root, and records it. The stage advance is a full-row compare-and-swap
//!   with a lineage check against the pinned created record, so a terminal
//!   from an unrelated history can never advance the row.
//! * **C9 — after the terminal is recorded, before this process installed the
//!   persistence selection and serving authority.** Both installs are
//!   process-local. Startup relaunch installs them for every durable terminal
//!   before request admission, and the next sign-in re-enters convergence,
//!   observes the terminal stage, and skips straight to the install/launch
//!   tail. Re-recording the same stage with identical bytes is an idempotent
//!   replay, never an overwrite.
//! * **C10 — between the persistence-selection install and the serving
//!   authority launch.** Nothing durable changed. The selection install is
//!   idempotent for the same archive and the launch is retried by the next
//!   convergence pass or the next restart. Until an authority is registered
//!   the routed read refuses as unavailable, so such a user is never served
//!   the stale legacy snapshot.
//!
//! One consequence of C9/C10 is worth stating plainly, because the
//! end-to-end smoke is where it was first observed rather than reasoned
//! about: a restart that follows the crash of an owner which had **already
//! published** cannot relaunch immediately. The dead owner's own WAL-owner
//! lease is still standing in the witness, and the restart cannot distinguish
//! its own corpse from a live competitor. `exact_wal_owner_renewal_from`
//! cannot apply — the live record and the durable owner binding are the same
//! bytes, so no tick inside the record advanced — which leaves only the
//! provider reacquire, and `exact_wal_owner_reacquire_from` admits that only
//! once trusted time is past the dead lease's expiry. Such a user is refused
//! as unavailable for at most one owner-lease duration and then converges on
//! the next pass. That is the designed fencing cost of a restart, not a
//! wedge, and it is why the startup relaunch counts a scoped failure instead
//! of failing the fleet.
//!
//! Logging here stays content-free: counts and outcomes only, never a user
//! identifier, archive identifier, or provider detail.

use std::sync::Arc;

use thiserror::Error;
use tracing::{error, info};

use crate::{
    archive_v3::ArchiveId,
    archive_v3_genesis_backend::{
        ControlPlaneGenesisBackend, GenesisBackendRuntimeContext, GenesisRegistryStore,
    },
    archive_v3_shadow_runtime::{
        ArchiveV3ShadowRuntimeDeployment, DurableSingleArchiveBinding,
        PendingSingleArchiveWalRuntime,
    },
    archive_v3_wal_genesis::{
        prepare_genesis_bootstrap, produce_genesis_bytes, resolve_genesis, run_witness_ladder,
        start_genesis_bootstrap, GenesisBootstrapStart, ReleasedGenesisRegistryWrap,
        WalGenesisAuthority,
    },
    cp::control_store::{ControlStore, GenesisStagingInventory, WalGenesisStage},
    crypto::GcpKmsClient,
    error::{EnclaveError, Result},
    store::Store,
};

/// Producer token proving that genesis provider authority was released to this
/// reviewed trigger rather than assembled by a sibling module. Its field is
/// private to this module, so this file is the only place in the tree that can
/// mint a [`GenesisBackendRuntimeContext`].
pub(crate) struct GenesisTriggerContext(());

impl std::fmt::Debug for GenesisTriggerContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GenesisTriggerContext(<opaque>)")
    }
}

/// Redacted trigger outcome. Storage- and provider-layer detail is collapsed
/// deliberately: a caller reconciles by rerunning convergence, never by
/// branching on why a previous attempt stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum GenesisTriggerError {
    #[error("archive genesis configuration disagrees with the image")]
    Config,
    #[error("archive genesis authority is unavailable")]
    Unavailable,
    #[error("archive genesis found competing durable state")]
    Conflict,
}

/// What one convergence pass settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenesisConvergence {
    /// The gate is off, so nothing ran and nothing durable changed.
    Disabled,
    /// The archive already rested at the durable terminal; this pass only
    /// completed the process-local install and launch.
    AlreadyTerminal,
    /// This pass produced or resumed genesis to the durable terminal.
    Converged,
}

/// Read the genesis cutover gate from the baked image configuration.
///
/// `GENESIS_WAL_NATIVE` is an allowlisted baked image key, so on any real
/// image `load_baked_image_configuration` has already overwritten the ambient
/// value with the image's own and has already refused to start an image that
/// omits it. The pre-cutover image shape is the explicit `off`; the build
/// tooling rejects an empty value outright.
///
/// The grammar mirrors the archive-v3 runtime mode: `off` is shut, `on` is the
/// cutover, and anything else fails closed rather than being guessed at. The
/// empty arm is retained deliberately and is *not* an image shape — it is the
/// answer for the only callers that can still reach it (unit tests, and any
/// invocation outside the image where the baked loader never ran). Its value
/// is FALSE, the shut position, so keeping it cannot arm anything.
pub(crate) fn genesis_wal_native_from_baked_env() -> std::result::Result<bool, GenesisTriggerError>
{
    genesis_wal_native_from_mode(&std::env::var("GENESIS_WAL_NATIVE").unwrap_or_default())
}

/// Environment-free core of [`genesis_wal_native_from_baked_env`].
pub(crate) fn genesis_wal_native_from_mode(
    mode: &str,
) -> std::result::Result<bool, GenesisTriggerError> {
    match mode {
        "" | "off" => Ok(false),
        "on" => Ok(true),
        _ => Err(GenesisTriggerError::Config),
    }
}

/// Fail-closed agreement between the genesis gate and the image's archive-v3
/// runtime coordinates: genesis mints a real archive through real providers,
/// so an image that claims the gate without baked coordinates has nothing to
/// mint it with and must refuse startup rather than silently never firing.
///
/// This is deliberately a separate predicate from the serving relaunch's own
/// config agreement, which stays untouched: that one protects existing
/// WAL-authoritative users from an off-config image, this one protects the
/// operator from a gate that cannot do what it claims.
pub(crate) fn require_genesis_config_agreement(
    genesis_native: bool,
    deployment_active: bool,
) -> Result<()> {
    if genesis_native && !deployment_active {
        return Err(EnclaveError::Conflict(
            "genesis-native sign-in is enabled but the image's archive-v3 runtime mode is off"
                .into(),
        ));
    }
    Ok(())
}

/// Validate the genesis configuration before request admission and report
/// whether new-user genesis is armed. Content-free: a boolean only.
pub(crate) fn genesis_startup_agreement() -> Result<bool> {
    let genesis_native = genesis_wal_native_from_baked_env()
        .map_err(|_| EnclaveError::Config("GENESIS_WAL_NATIVE must be on or off".into()))?;
    let deployment = ArchiveV3ShadowRuntimeDeployment::from_baked_env().map_err(|_| {
        EnclaveError::Store("baked archive-v3 runtime coordinates are invalid".into())
    })?;
    require_genesis_config_agreement(genesis_native, deployment.is_some())?;
    Ok(genesis_native)
}

/// Hang one detached convergence pass off a completed sign-in.
///
/// This never blocks the caller and never propagates a failure into the
/// sign-in response: a user whose genesis is unavailable, refused, or still
/// half-done keeps the account they already had, and the next sign-in runs
/// convergence again. That is the whole idempotence contract, expressed at the
/// call site.
pub(crate) fn spawn_genesis_convergence(
    control: Arc<ControlStore>,
    store: Arc<Store>,
    user_id: &str,
) {
    let user_id = user_id.to_owned();
    tokio::spawn(async move {
        match converge_genesis_for_user(&control, &store, &user_id).await {
            Ok(GenesisConvergence::Disabled) => {}
            Ok(outcome) => info!(
                outcome = ?outcome,
                "converged an archive-v3 genesis archive at sign-in"
            ),
            // Contained, not ignored. Sign-in already succeeded; this user
            // simply stays on the path they were on until the next pass.
            Err(_) => error!("archive-v3 genesis convergence did not complete; it will retry"),
        }
    });
}

/// Bring one signed-in user's bound archive to the durable `wal_authoritative`
/// terminal and, in this process, to a launched serving authority.
///
/// Safe to call any number of times: an already-terminal archive skips
/// straight to the process-local tail, and a half-finished genesis resumes
/// from whatever the durable state actually says rather than from a caller's
/// memory of where it was.
pub(crate) async fn converge_genesis_for_user(
    control: &Arc<ControlStore>,
    store: &Arc<Store>,
    user_id: &str,
) -> std::result::Result<GenesisConvergence, GenesisTriggerError> {
    converge_genesis_over(&BakedImageGenesisRuntime, control, store, user_id).await
}

/// Convergence over an explicit provider source. Production has exactly one
/// source, [`BakedImageGenesisRuntime`]; see [`GenesisRuntimeSource`] for why
/// the seam exists at all.
async fn converge_genesis_over(
    source: &dyn GenesisRuntimeSource,
    control: &Arc<ControlStore>,
    store: &Arc<Store>,
    user_id: &str,
) -> std::result::Result<GenesisConvergence, GenesisTriggerError> {
    // The gate is read first so a disabled image does exactly nothing: no
    // coordinate parsing, no control-store read, no task-local state.
    if !source.armed()? {
        return Ok(GenesisConvergence::Disabled);
    }
    // One pass per user per process. Concurrent sign-ins would otherwise both
    // launch a serving authority, and the loser's WAL-owner lease acquisition
    // would fence the winner. Cross-process concurrency is still handled by
    // the durable compare-and-swap predicates every step below goes through;
    // this only removes the self-inflicted case.
    let Some(_pass) = SingleGenesisPass::claim(user_id) else {
        return Ok(GenesisConvergence::AlreadyTerminal);
    };
    let binding = control
        .active_archive_binding(user_id)
        .await
        .map_err(map_control)?;
    let archive_id = binding.archive_id();
    let already_terminal = control
        .wal_genesis_ledger_stage(archive_id)
        .await
        .map_err(map_control)?
        == Some(WalGenesisStage::WalAuthoritative);
    let birth_witness = if already_terminal {
        None
    } else {
        run_durable_genesis(control, source, binding, user_id, archive_id).await?
    };
    install_and_launch(control, store, source, user_id).await?;
    if birth_witness.is_some() {
        info!(
            metric = "archive_v3_genesis_birth_witness",
            schema_epoch = crate::schema_ladder::SCHEMA_EPOCH_TARGET,
            allocator_tables = 3_u64,
            valid = true,
            "validated a fresh archive-v3 genesis birth after durable publication and serving launch"
        );
    }
    Ok(if already_terminal {
        GenesisConvergence::AlreadyTerminal
    } else {
        GenesisConvergence::Converged
    })
}

/// The provider set one genesis pass drives, already released and bound to
/// exactly one archive. It carries no witness record, no lease and no durable
/// authority: every handle still enforces its own exact-context, CAS and
/// readback predicates, exactly as [`GenesisRuntimeParts`] does.
///
/// [`GenesisRuntimeParts`]: crate::archive_v3_shadow_runtime::GenesisRuntimeParts
struct GenesisDriverProviders {
    archive_id: ArchiveId,
    backend: Box<dyn crate::archive_v3_genesis::ArchiveGenesisBackend>,
    objects: Arc<dyn crate::archive_v3::ImmutableObjectBackend>,
    registry_wrap: Box<dyn crate::archive_v3_wal_genesis::GenesisRegistryWrapAuthority>,
    witness_advance: Arc<dyn crate::archive_v3_root_advance::ArchiveWitnessAdvanceProvider>,
}

impl std::fmt::Debug for GenesisDriverProviders {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GenesisDriverProviders(<opaque>)")
    }
}

/// The seam between the reviewed convergence driver below and the image's
/// real GCS/KMS/Firestore coordinates.
///
/// It exists for exactly one reason: without it neither
/// [`run_durable_genesis`] nor [`install_and_launch`] can be executed by any
/// test in the tree, because both reach a live bucket, a live KMS key
/// version and a live Firestore database on their first statement. Everything
/// downstream of the seam — the durable recovery decision, the crash
/// boundary, the ledger stages, the witness ladder, the owner reservation and
/// the launch — is unchanged and is what the end-to-end smoke (G10) actually
/// runs.
///
/// The seam moves composition, never a predicate. `armed` is the same pair of
/// fail-closed reads it replaced, in the same order; the durable
/// compare-and-swaps, the witness predicates and the CHECK constraints below
/// are untouched and are enforced by the same production code either way.
/// Production has exactly one implementation, and the alternative one is
/// `#[cfg(test)]` — the same containment `for_publisher_test` and
/// `create_genesis_test_binding` already rely on one layer down.
#[async_trait::async_trait]
trait GenesisRuntimeSource: Send + Sync {
    /// Whether new-user genesis is armed for this image. Fails closed.
    fn armed(&self) -> std::result::Result<bool, GenesisTriggerError>;

    /// Release the provider set for one archive's genesis run.
    fn genesis_providers(
        &self,
        control: &Arc<ControlStore>,
        binding: crate::cp::control_store::ArchiveBinding,
    ) -> std::result::Result<GenesisDriverProviders, GenesisTriggerError>;

    /// Reconstruct the launchable WAL serving handoff for one archive from
    /// durable state alone.
    async fn serving_handoff(
        &self,
        control: Arc<ControlStore>,
        binding: crate::cp::control_store::ArchiveBinding,
    ) -> std::result::Result<crate::archive_v3_shadow_runtime::WalServingHandoff, GenesisTriggerError>;
}

/// The one production source: the image-baked gate and coordinates.
struct BakedImageGenesisRuntime;

impl BakedImageGenesisRuntime {
    /// The image's archive-v3 runtime coordinates, or a fail-closed refusal.
    /// Re-read per composition because the pending runtime is bind-once, in
    /// the same shape the startup relaunch re-reads them per selection.
    fn deployment() -> std::result::Result<ArchiveV3ShadowRuntimeDeployment, GenesisTriggerError> {
        ArchiveV3ShadowRuntimeDeployment::from_baked_env()
            .map_err(|_| GenesisTriggerError::Config)?
            .ok_or(GenesisTriggerError::Config)
    }

    /// One bound, inert runtime capability for this archive.
    fn sealed(
        binding: crate::cp::control_store::ArchiveBinding,
    ) -> std::result::Result<
        crate::archive_v3_shadow_runtime::SealedSingleArchiveWalRuntime,
        GenesisTriggerError,
    > {
        let kms = Arc::new(GcpKmsClient::from_env().map_err(|_| GenesisTriggerError::Unavailable)?);
        PendingSingleArchiveWalRuntime::new(Self::deployment()?, kms)
            .map_err(|_| GenesisTriggerError::Unavailable)?
            .bind_once(DurableSingleArchiveBinding::from_control_store(binding))
            .map_err(|_| GenesisTriggerError::Config)
    }
}

#[async_trait::async_trait]
impl GenesisRuntimeSource for BakedImageGenesisRuntime {
    fn armed(&self) -> std::result::Result<bool, GenesisTriggerError> {
        if !genesis_wal_native_from_baked_env()? {
            return Ok(false);
        }
        // Startup already refuses this combination; refuse here too rather
        // than trusting that startup ran in this build.
        Self::deployment().map(|_| true)
    }

    fn genesis_providers(
        &self,
        control: &Arc<ControlStore>,
        binding: crate::cp::control_store::ArchiveBinding,
    ) -> std::result::Result<GenesisDriverProviders, GenesisTriggerError> {
        let parts = Self::sealed(binding)?
            .into_genesis_parts(&GenesisBackendRuntimeContext::for_genesis_trigger(
                &GenesisTriggerContext(()),
            ))
            .map_err(|_| GenesisTriggerError::Unavailable)?;
        let registries: Arc<dyn GenesisRegistryStore> =
            Arc::<_>::clone(&parts.registries) as Arc<_>;
        let backend = ControlPlaneGenesisBackend::new(
            GenesisBackendRuntimeContext::for_genesis_trigger(&GenesisTriggerContext(())),
            Arc::clone(control),
            Arc::clone(&parts.objects),
            Arc::clone(&parts.roots),
            registries,
            Arc::clone(&parts.witness),
        );
        let registry_wrap = ReleasedGenesisRegistryWrap::new(
            GenesisBackendRuntimeContext::for_genesis_trigger(&GenesisTriggerContext(())),
            Arc::clone(&parts.registries),
        );
        Ok(GenesisDriverProviders {
            archive_id: parts.archive_id,
            backend: Box::new(backend),
            objects: parts.objects,
            registry_wrap: Box::new(registry_wrap),
            witness_advance: parts.witness_advance,
        })
    }

    async fn serving_handoff(
        &self,
        control: Arc<ControlStore>,
        binding: crate::cp::control_store::ArchiveBinding,
    ) -> std::result::Result<crate::archive_v3_shadow_runtime::WalServingHandoff, GenesisTriggerError>
    {
        Self::sealed(binding)?
            .reconstruct_wal_serving_handoff(control)
            .await
            .map_err(|_| GenesisTriggerError::Conflict)
    }
}

/// Drive the durable half of the spine: reserve, produce, prepare, resolve,
/// record `genesis_created`, run the witness ladder, record the released
/// `wal_authoritative` terminal.
///
/// The stage recording is deliberately interleaved with the driver rather than
/// appended after it, because the ledger's `genesis_created` row is what a
/// resumed run needs in order to prove that a witness found beyond genesis is
/// its own. See C5 in the module documentation.
async fn run_durable_genesis(
    control: &Arc<ControlStore>,
    source: &dyn GenesisRuntimeSource,
    binding: crate::cp::control_store::ArchiveBinding,
    user_id: &str,
    archive_id: ArchiveId,
) -> std::result::Result<Option<crate::store::GenesisBirthWitness>, GenesisTriggerError> {
    let parts = source.genesis_providers(control, binding)?;
    if parts.archive_id != archive_id {
        return Err(GenesisTriggerError::Conflict);
    }
    let backend = parts.backend.as_ref();
    let registry_wrap = parts.registry_wrap.as_ref();

    // Recover before producing anything. Only the durable bootstrap anchor can
    // say whether this archive is still short of the prepare crash boundary;
    // this pass's own memory cannot, because it may be the first pass after a
    // crash or an ordinary `token_refresh` on a half-built archive. Recovery
    // and the reservation compare-and-swap both stage zero objects, so neither
    // touches a staging inventory.
    let start = {
        let authority = WalGenesisAuthority {
            recovery: control.as_ref(),
            backend,
            objects: parts.objects.as_ref(),
            registry_wrap,
            inventory: &UnstagedGenesisInventory,
            witness_advance: parts.witness_advance.as_ref(),
        };
        start_genesis_bootstrap(&authority, archive_id)
            .await
            .map_err(map_genesis)?
    };
    let mut birth_witness = None;
    let prepared = match start {
        // Past the boundary. The prepared payloads are the only correct bytes
        // for this archive — a post-boundary prepare replays them and discards
        // whatever it is handed — so this pass produces nothing: no second DEK,
        // no second checkpoint upload, no staging binding the ladder could
        // never rebuild. See C3-C6.
        GenesisBootstrapStart::Resume(prepared) => prepared,
        GenesisBootstrapStart::Produce(reservation) => {
            // The producer's staging phase gets its own inventory instance.
            // Its binding carries THIS attempt's freshly wrapped registry
            // hash, and the latch exists to pin one staging phase to one
            // binding — not to force two phases that legitimately carry
            // different bindings through a single latch.
            let producer_inventory = GenesisStagingInventory::new(
                Arc::clone(control),
                archive_id,
                reservation.plan().attempt_id(),
            );
            let authority = WalGenesisAuthority {
                recovery: control.as_ref(),
                backend,
                objects: parts.objects.as_ref(),
                registry_wrap,
                inventory: &producer_inventory,
                witness_advance: parts.witness_advance.as_ref(),
            };
            let produced = produce_genesis_bytes(&authority, &std::env::temp_dir(), reservation)
                .await
                .map_err(map_genesis)?;
            birth_witness = Some(produced.birth_witness());
            // ◄── CRASH BOUNDARY.
            prepare_genesis_bootstrap(&authority, produced)
                .await
                .map_err(map_genesis)?
        }
    };
    let plan = prepared.reservation().plan();
    let wrapped_registry_hash = prepared.wrapped_registry_hash();
    // The ladder is a second staging phase, and its binding is built from the
    // DURABLY PREPARED registry hash, which is the producer's only on a pass
    // that produced. It gets its own instance so the two phases never contend
    // for one latch; both still record into the same durable append-only
    // staging log under the same reserved attempt.
    let ladder_inventory =
        GenesisStagingInventory::new(Arc::clone(control), archive_id, plan.attempt_id());
    let authority = WalGenesisAuthority {
        recovery: control.as_ref(),
        backend,
        objects: parts.objects.as_ref(),
        registry_wrap,
        inventory: &ladder_inventory,
        witness_advance: parts.witness_advance.as_ref(),
    };
    let (_resolution, record) = resolve_genesis(&authority, prepared)
        .await
        .map_err(map_genesis)?;
    // Record the created stage before the ladder can move the witness. An
    // already-recorded row means a prior pass got here first, and the observed
    // record may legitimately be beyond genesis by now.
    if control
        .wal_genesis_ledger_stage(archive_id)
        .await
        .map_err(map_control)?
        .is_none()
    {
        control
            .record_genesis_stage(
                user_id,
                archive_id,
                WalGenesisStage::GenesisCreated,
                record.encode(),
            )
            .await
            .map_err(map_control)?;
    }
    let terminal = run_witness_ladder(&authority, plan, wrapped_registry_hash)
        .await
        .map_err(map_genesis)?;
    control
        .record_genesis_stage(
            user_id,
            archive_id,
            WalGenesisStage::WalAuthoritative,
            terminal.encode(),
        )
        .await
        .map_err(map_control)?;
    Ok(birth_witness)
}

/// Process-local tail: install the durable-terminal persistence selection and
/// launch this user's WAL serving authority, mirroring exactly what startup
/// relaunch does for an already-terminal user. Both installs are idempotent
/// for an unchanged archive, and neither writes durable state.
async fn install_and_launch(
    control: &Arc<ControlStore>,
    store: &Arc<Store>,
    source: &dyn GenesisRuntimeSource,
    user_id: &str,
) -> std::result::Result<(), GenesisTriggerError> {
    if store.has_wal_serving_authority(user_id) {
        return Ok(());
    }
    let selection = control
        .load_wal_authoritative_persistence_selection(user_id)
        .await
        .map_err(map_control)?;
    store
        .install_wal_authority_persistence(selection)
        .map_err(map_control)?;
    let binding = control
        .active_archive_binding(user_id)
        .await
        .map_err(map_control)?;
    // The archive the slot is pinned to. A later in-process relaunch that
    // rebuilds a different archive for this user is refused rather than
    // swapped in.
    let archive_id = *binding.archive_id().as_bytes();
    let handoff = source.serving_handoff(Arc::clone(control), binding).await?;
    let authority = crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::launch(handoff)
        .await
        .map_err(|_| GenesisTriggerError::Unavailable)?;
    store
        .install_wal_serving_authority(user_id, archive_id, Arc::new(authority))
        .map_err(map_control)
}

/// Process-local single-flight over one user's convergence pass. Dropping the
/// guard releases the claim, including on panic, so a failed pass never locks
/// a user out of converging later.
struct SingleGenesisPass {
    user_id: String,
}

impl SingleGenesisPass {
    fn in_flight() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
        static IN_FLIGHT: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
            std::sync::OnceLock::new();
        IN_FLIGHT.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
    }

    fn claim(user_id: &str) -> Option<Self> {
        let mut in_flight = Self::in_flight().lock().ok()?;
        in_flight.insert(user_id.to_owned()).then(|| Self {
            user_id: user_id.to_owned(),
        })
    }
}

impl Drop for SingleGenesisPass {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = Self::in_flight().lock() {
            in_flight.remove(&self.user_id);
        }
    }
}

/// Inventory used only for the reservation step, which stages no object. Any
/// call is a defect in the ordering above, so every method refuses rather than
/// silently accepting an unrecorded object.
struct UnstagedGenesisInventory;

#[async_trait::async_trait]
impl crate::archive_v3_shadow_checkpoint::ShadowObjectInventory for UnstagedGenesisInventory {
    async fn reserve_exact(
        &self,
        _session_id: crate::archive_v3_shadow_session::ShadowSessionId,
        _attempt_id: crate::archive_v3_shadow_session::ShadowAttemptId,
        _binding: crate::archive_v3_shadow_session::ShadowSessionBinding,
        _facts: crate::archive_v3_operation::ShadowObjectFacts,
    ) -> std::result::Result<
        crate::archive_v3_operation::RecordOutcome,
        crate::archive_v3_shadow_checkpoint::ShadowObjectInventoryError,
    > {
        Err(crate::archive_v3_shadow_checkpoint::ShadowObjectInventoryError::Conflict)
    }

    async fn mark_materialized_exact(
        &self,
        _session_id: crate::archive_v3_shadow_session::ShadowSessionId,
        _attempt_id: crate::archive_v3_shadow_session::ShadowAttemptId,
        _binding: crate::archive_v3_shadow_session::ShadowSessionBinding,
        _facts: crate::archive_v3_operation::ShadowObjectFacts,
    ) -> std::result::Result<
        crate::archive_v3_operation::RecordOutcome,
        crate::archive_v3_shadow_checkpoint::ShadowObjectInventoryError,
    > {
        Err(crate::archive_v3_shadow_checkpoint::ShadowObjectInventoryError::Conflict)
    }

    async fn load_exact_attempt_page(
        &self,
        _session_id: crate::archive_v3_shadow_session::ShadowSessionId,
        _attempt_id: crate::archive_v3_shadow_session::ShadowAttemptId,
        _binding: crate::archive_v3_shadow_session::ShadowSessionBinding,
        _after_ordinal: Option<u32>,
    ) -> std::result::Result<
        crate::archive_v3_operation::ShadowObjectInventoryPage,
        crate::archive_v3_shadow_checkpoint::ShadowObjectInventoryError,
    > {
        Err(crate::archive_v3_shadow_checkpoint::ShadowObjectInventoryError::Conflict)
    }
}

fn map_control(_error: EnclaveError) -> GenesisTriggerError {
    GenesisTriggerError::Conflict
}

fn map_genesis(error: crate::archive_v3_wal_genesis::WalGenesisError) -> GenesisTriggerError {
    match error {
        crate::archive_v3_wal_genesis::WalGenesisError::Unavailable
        | crate::archive_v3_wal_genesis::WalGenesisError::OutcomeUnknown => {
            GenesisTriggerError::Unavailable
        }
        _ => GenesisTriggerError::Conflict,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn the_gate_defaults_to_false_and_refuses_anything_it_cannot_read() {
        // The pre-cutover image shape is the explicit `off`; the baked-key
        // build tooling refuses an empty value, so the empty arm is no longer
        // reachable from an image at all. It stays FALSE because FALSE is the
        // shut position: the callers that can still reach it are unit tests
        // and out-of-image invocations, and neither may arm genesis.
        assert_eq!(genesis_wal_native_from_mode(""), Ok(false));
        assert_eq!(genesis_wal_native_from_mode("off"), Ok(false));
        assert_eq!(genesis_wal_native_from_mode("on"), Ok(true));
        // Everything a typo or a truthy-looking value could be must fail
        // closed rather than be guessed at in either direction.
        for hostile in ["1", "true", "ON", "On", "yes", "enabled", " on", "on "] {
            assert_eq!(
                genesis_wal_native_from_mode(hostile),
                Err(GenesisTriggerError::Config),
                "{hostile} must fail closed"
            );
        }
    }

    #[test]
    fn config_agreement_refuses_an_armed_gate_on_an_off_image() {
        require_genesis_config_agreement(false, false).unwrap();
        require_genesis_config_agreement(false, true).unwrap();
        require_genesis_config_agreement(true, true).unwrap();
        assert!(matches!(
            require_genesis_config_agreement(true, false),
            Err(EnclaveError::Conflict(_))
        ));
    }

    /// The ordering that makes a half-genesis user converge instead of wedge
    /// is structural, so it is asserted structurally. `genesis_created` must
    /// be recorded before the witness ladder is entered: once the ladder
    /// advances, the sequence-0 record the ledger demands for that stage no
    /// longer exists anywhere, and a run that reaches the ladder without the
    /// row can never record it again (C5).
    #[test]
    fn the_created_stage_is_recorded_before_the_ladder_is_entered() {
        let source = include_str!("archive_v3_genesis_trigger.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        let body = &production[production
            .find("async fn run_durable_genesis(")
            .expect("the durable genesis driver moved")..];
        let created = body
            .find("WalGenesisStage::GenesisCreated")
            .expect("the created stage recording moved");
        let ladder = body
            .find("run_witness_ladder(")
            .expect("the witness ladder call moved");
        assert!(
            created < ladder,
            "genesis_created must be recorded before the ladder advances the witness"
        );
        let terminal = body
            .find("WalGenesisStage::WalAuthoritative")
            .expect("the terminal stage recording moved");
        assert!(
            ladder < terminal,
            "the terminal stage must be recorded from the ladder's own released terminal"
        );
        // The prepare call is the crash boundary, and byte production must
        // precede it or the retry would not be byte-exact afterwards.
        let produce = body.find("produce_genesis_bytes(").unwrap();
        let prepare = body.find("prepare_genesis_bootstrap(").unwrap();
        assert!(produce < prepare && prepare < created);
    }

    /// The C3-C6 convergence claim is structural as well: byte production must
    /// sit BEHIND the durable recovery decision, never in front of it. A pass
    /// that produced first would mint a second DEK on every resume, hash a
    /// second wrapped registry, and stage its checkpoint under a binding the
    /// witness ladder — which derives its own from the durably stored hash —
    /// can never present, wedging the ladder permanently (G9-1) while burning
    /// a checkpoint upload per request (G9-2).
    #[test]
    fn byte_production_sits_behind_the_durable_recovery_decision() {
        let source = include_str!("archive_v3_genesis_trigger.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        let body = &production[production
            .find("async fn run_durable_genesis(")
            .expect("the durable genesis driver moved")..];
        let recover = body
            .find("start_genesis_bootstrap(")
            .expect("the durable recovery decision moved");
        let resume = body
            .find("GenesisBootstrapStart::Resume(prepared) => prepared")
            .expect("the resume arm must adopt the recovered prepared bootstrap as-is");
        let produce = body
            .find("produce_genesis_bytes(")
            .expect("the byte producer moved");
        assert!(
            recover < resume && resume < produce,
            "byte production must sit inside the not-yet-prepared arm"
        );
        // Two staging phases, two inventory instances. The producer's binding
        // carries this attempt's freshly wrapped registry hash and the ladder's
        // carries the durably prepared one; on a resumed pass only the ladder
        // stages at all. The latch still pins each phase to one binding.
        assert_eq!(body.matches("GenesisStagingInventory::new(").count(), 2);
        assert!(body.contains("inventory: &producer_inventory"));
        assert!(body.contains("inventory: &ladder_inventory"));
    }

    /// Sign-in must never block on, or fail because of, genesis. The trigger
    /// call the routes use detaches and swallows the outcome; if that ever
    /// becomes an awaited fallible call, a wedged genesis starts costing users
    /// their sign-in.
    #[test]
    fn the_sign_in_trigger_detaches_and_never_propagates() {
        let source = include_str!("archive_v3_genesis_trigger.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        let spawn = &production[production
            .find("pub(crate) fn spawn_genesis_convergence")
            .unwrap()..];
        let spawn = &spawn[..spawn.find("\n}\n").unwrap()];
        let (signature, body) = spawn.split_once('{').unwrap();
        assert!(
            !signature.contains("->"),
            "the sign-in trigger must not return anything a route could branch on"
        );
        assert!(body.contains(concat!("tokio::", "spawn(")));
        assert!(
            !body.contains("?;") && !body.contains("await?") && !body.contains(".unwrap()"),
            "the sign-in trigger must not propagate or panic on any genesis failure"
        );
        // Both resumption points call it, and neither awaits it.
        let oauth = include_str!("cp/oauth.rs");
        assert_eq!(
            oauth
                .matches("archive_v3_genesis_trigger::spawn_genesis_convergence")
                .count(),
            2
        );
        // The module doc carries the crash boundary verbatim, and the
        // enumeration a reviewer checks it against.
        assert!(source.contains(
            "Before `prepare_archive_bootstrap`, a crash orphans one checkpoint's\n//! objects and the retry mints a fresh DEK. After it, replay is byte-exact."
        ));
        for point in [
            "C0 ", "C1 ", "C2 ", "C3 ", "C4 ", "C5 ", "C6 ", "C7 ", "C8 ", "C9 ", "C10 ",
        ] {
            assert!(
                source.contains(point),
                "crash point {point} is not enumerated"
            );
        }
    }

    /// The trigger is the tree's only minter of genesis provider authority.
    #[test]
    fn the_genesis_provider_token_has_exactly_one_production_minter() {
        let backend = include_str!("archive_v3_genesis_backend.rs");
        assert_eq!(backend.matches("for_genesis_trigger").count(), 1);
        assert!(
            backend.contains("_token: &crate::archive_v3_genesis_trigger::GenesisTriggerContext")
        );
        let trigger = include_str!("archive_v3_genesis_trigger.rs");
        assert!(trigger.contains("pub(crate) struct GenesisTriggerContext(());"));
    }

    /// The composition seam moves composition only, and the alternative
    /// source is structurally confined to test builds. Both halves are
    /// asserted structurally because both are the kind of thing a later edit
    /// erodes silently: a second production source, or a test source that
    /// stops being `#[cfg(test)]`, would each turn the seam into a way to run
    /// genesis against providers no reviewer chose.
    #[test]
    fn the_runtime_seam_has_one_production_source_and_moves_no_predicate() {
        let source = include_str!("archive_v3_genesis_trigger.rs");
        let production = &source[..source.find(concat!("mod ", "tests")).unwrap()];
        // Exactly one production implementation of the seam.
        assert_eq!(
            production
                .matches(concat!("impl GenesisRuntimeSource ", "for "))
                .count(),
            1
        );
        assert!(production.contains(concat!(
            "impl GenesisRuntimeSource ",
            "for BakedImageGenesisRuntime"
        )));
        // The production source still reads the gate and the coordinates
        // itself, in that order, and still fails closed on both.
        let armed = &production[production
            .find("fn armed(&self) -> std::result::Result<bool, GenesisTriggerError> {")
            .expect("the production arming decision moved")..];
        let armed = &armed[..armed.find("\n    }\n").unwrap()];
        let gate = armed
            .find("genesis_wal_native_from_baked_env()?")
            .expect("the gate read moved out of the production source");
        let coordinates = armed
            .find("Self::deployment()")
            .expect("the coordinate agreement moved out of the production source");
        assert!(gate < coordinates);
        assert!(armed.contains("return Ok(false)"));
        // Every alternative source lives behind `cfg(test)`.
        assert!(
            !production.contains("SmokeGenesisRuntime"),
            "the smoke source must not be reachable from production"
        );
        assert!(
            source.contains(concat!("#[cfg(test)]\npub(crate) mod ", "tests {")),
            "the smoke source's whole module must stay cfg(test)"
        );
        // The durable driver takes the seam, never a raw provider graph.
        assert!(production.contains("source: &dyn GenesisRuntimeSource"));
        assert!(production.contains("converge_genesis_over(&BakedImageGenesisRuntime,"));
        // The seam widens nothing. Every type it introduces is private to
        // this module, so the only production surface that leaves the file is
        // still exactly what left it before the seam existed.
        for private in [
            concat!("struct GenesisDriver", "Providers {"),
            concat!("trait GenesisRuntime", "Source: Send + Sync {"),
            concat!("struct BakedImageGenesis", "Runtime;"),
        ] {
            assert!(production.contains(private), "missing {private}");
            assert!(
                !production.contains(&format!("pub(crate) {private}")),
                "{private} must stay private to this module"
            );
        }
    }

    // ------------------------------------------------------------------
    // G10: the end-to-end smoke harness.
    //
    // `run_durable_genesis` and `install_and_launch` reach a live bucket, a
    // live KMS key version and a live Firestore database on their first
    // statement, so until this harness existed neither had ever been
    // executed by a test — only compile-checked and structurally pinned.
    // Everything below composes the tree's existing in-memory providers into
    // the exact shapes the seam releases, so the reviewed driver runs
    // unchanged. The smoke test that drives it lives with the probe it
    // submits, in `cp/reviewer.rs`.
    // ------------------------------------------------------------------

    use crate::{
        archive_v3::{
            ArchiveV3Error, CiphertextEnvelope, CreateIfAbsent, ExactKeyRegistryProvider,
            ImmutableObjectBackend, InMemoryImmutableBackend, KeyRegistryContext, ObjectContext,
            ObjectId, ObjectRole,
        },
        archive_v3_firestore_shadow::FirestoreShadowWitness,
        archive_v3_firestore_witness::{test_transport, FirestoreWitness},
        archive_v3_genesis_backend::GenesisRegistryStore as _GenesisRegistryStore,
        archive_v3_wal_genesis::GenesisRegistryWrapAuthority,
        archive_v3_witness::{ExactRootProvider, WitnessError},
        store::tests::{FakeGcs, FakeKms},
    };
    use std::{collections::BTreeMap, sync::Mutex};

    const SMOKE_WRAP_PREFIX: &[u8] = b"smoke-kms-wrap:";

    /// Round-tripping registry provider over an exact-bytes CAS, mirroring
    /// the production create-if-absent and wrap/unwrap semantics. It stands
    /// in for the archive bucket's wrapped-registry object plus the KMS key
    /// version that wraps it, and it is durable substrate: a process death
    /// leaves it exactly as it was.
    #[derive(Default)]
    pub(crate) struct SmokeRegistryStore {
        objects: Mutex<BTreeMap<ObjectId, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl ExactKeyRegistryProvider for SmokeRegistryStore {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            let value = self
                .objects
                .lock()
                .unwrap()
                .get(&object_id)
                .cloned()
                .ok_or(ArchiveV3Error::Unavailable)?;
            if value.len() > destination.len() {
                return Err(ArchiveV3Error::TooLarge("wrapped key registry"));
            }
            destination[..value.len()].copy_from_slice(&value);
            Ok(value.len())
        }

        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            wrapped: &[u8],
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            let plaintext = wrapped
                .strip_prefix(SMOKE_WRAP_PREFIX)
                .ok_or(ArchiveV3Error::InvalidContext)?;
            if plaintext.len() > destination.len() {
                return Err(ArchiveV3Error::TooLarge("key registry plaintext"));
            }
            destination[..plaintext.len()].copy_from_slice(plaintext);
            Ok(plaintext.len())
        }
    }

    #[async_trait::async_trait]
    impl _GenesisRegistryStore for SmokeRegistryStore {
        async fn create_wrapped_if_absent(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            wrapped_registry_ciphertext: &[u8],
        ) -> crate::archive_v3::Result<CreateIfAbsent> {
            let mut objects = self.objects.lock().unwrap();
            if let Some(existing) = objects.get(&object_id) {
                return if existing == wrapped_registry_ciphertext {
                    Ok(CreateIfAbsent::AlreadyPresentIdentical)
                } else {
                    Err(ArchiveV3Error::Conflict)
                };
            }
            objects.insert(object_id, wrapped_registry_ciphertext.to_vec());
            Ok(CreateIfAbsent::Created)
        }
    }

    #[async_trait::async_trait]
    impl GenesisRegistryWrapAuthority for SmokeRegistryStore {
        async fn wrap_registry(
            &self,
            _context: &KeyRegistryContext,
            registry_plaintext: &[u8],
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            let length = SMOKE_WRAP_PREFIX.len() + registry_plaintext.len();
            if length > destination.len() {
                return Err(ArchiveV3Error::TooLarge("wrapped key registry"));
            }
            destination[..SMOKE_WRAP_PREFIX.len()].copy_from_slice(SMOKE_WRAP_PREFIX);
            destination[SMOKE_WRAP_PREFIX.len()..length].copy_from_slice(registry_plaintext);
            Ok(length)
        }
    }

    /// Exact-root reads over the same immutable object store the composite
    /// writes through.
    struct SmokeRootProvider(Arc<InMemoryImmutableBackend>);

    #[async_trait::async_trait]
    impl ExactRootProvider for SmokeRootProvider {
        async fn read_exact(
            &self,
            context: &ObjectContext,
        ) -> std::result::Result<CiphertextEnvelope, WitnessError> {
            if context.role() != ObjectRole::RootV3 {
                return Err(WitnessError::Malformed);
            }
            match self.0.get(&context.object_key()).await {
                Ok(Some(envelope)) => Ok(envelope),
                Ok(None) => Err(WitnessError::MissingRootObject),
                Err(ArchiveV3Error::Unavailable) => Err(WitnessError::Unavailable),
                Err(_) => Err(WitnessError::Malformed),
            }
        }
    }

    /// Everything a process death leaves behind: the encrypted control
    /// object, the user object store, the archive's immutable objects, the
    /// wrapped-registry CAS and the witness database. A relaunch rebuilds
    /// every in-memory handle from exactly this and nothing else.
    pub(crate) struct GenesisSmokeSubstrate {
        control_gcs: Arc<FakeGcs>,
        store_gcs: Arc<FakeGcs>,
        objects: Arc<InMemoryImmutableBackend>,
        registries: Arc<SmokeRegistryStore>,
        witness_transport: Arc<test_transport::FakeTransport>,
    }

    /// One process's worth of in-memory handles. Dropping it is the harness's
    /// stand-in for process death: the control store, the user store, every
    /// launched serving authority and every provider client go with it.
    pub(crate) struct GenesisSmokeProcess {
        pub(crate) control: Arc<ControlStore>,
        pub(crate) store: Arc<Store>,
    }

    impl Default for GenesisSmokeSubstrate {
        fn default() -> Self {
            Self::new()
        }
    }

    impl GenesisSmokeSubstrate {
        pub(crate) fn new() -> Self {
            Self {
                control_gcs: Arc::new(FakeGcs::new()),
                store_gcs: Arc::new(FakeGcs::new()),
                objects: Arc::new(InMemoryImmutableBackend::new()),
                registries: Arc::new(SmokeRegistryStore::default()),
                witness_transport: Arc::new(test_transport::FakeTransport::new(None, [])),
            }
        }

        /// Failure-injection handle for owner-level tests that must exercise
        /// an asymmetric Control/archive persistence boundary after genesis.
        pub(crate) fn control_gcs(&self) -> Arc<FakeGcs> {
            Arc::clone(&self.control_gcs)
        }

        /// Boot a process over the durable substrate. Nothing carries over
        /// from a previous one.
        pub(crate) fn boot(&self) -> GenesisSmokeProcess {
            GenesisSmokeProcess {
                control: Arc::new(ControlStore::new(
                    Arc::new(FakeKms),
                    Arc::clone(&self.control_gcs) as Arc<dyn crate::store::GcsClient>,
                )),
                store: Arc::new(Store::new(
                    Arc::new(FakeKms),
                    Arc::clone(&self.store_gcs) as Arc<dyn crate::store::GcsClient>,
                )),
            }
        }

        /// Advance the witness database's trusted clock.
        ///
        /// A real restart takes wall time; the fake transport's clock is
        /// otherwise frozen at one instant. Without this a crashed owner's
        /// lease can never expire, and the restarted owner is correctly —
        /// but permanently — fenced by its own corpse. Moving the clock is
        /// the harness modelling elapsed time, not relaxing a predicate: the
        /// reacquire still goes through the provider compare-and-swap and
        /// `exact_wal_owner_reacquire_from` unchanged.
        pub(crate) fn advance_witness_clock(&self, rfc3339_millis: &str) {
            self.witness_transport.0.lock().unwrap().time = rfc3339_millis.to_owned();
        }

        /// A fresh witness client over the durable witness database.
        fn witness(&self) -> Arc<FirestoreWitness> {
            Arc::new(test_transport::witness_over_fake(Arc::clone(
                &self.witness_transport,
            )))
        }

        /// The provider source this process hands the reviewed driver.
        pub(crate) fn runtime(&self) -> SmokeGenesisRuntime {
            SmokeGenesisRuntime {
                objects: Arc::clone(&self.objects),
                registries: Arc::clone(&self.registries),
                witness: self.witness(),
            }
        }
    }

    /// The `#[cfg(test)]` provider source. It composes the same reviewed
    /// production types the baked source does — `ControlPlaneGenesisBackend`
    /// over the encrypted control store, `FirestoreShadowWitness` for the
    /// witness ladder, `SealedSingleArchiveWalRuntime` for the serving
    /// handoff — with in-memory providers underneath instead of GCS, KMS and
    /// Firestore. No predicate, CAS, gate or failure handler differs.
    pub(crate) struct SmokeGenesisRuntime {
        objects: Arc<InMemoryImmutableBackend>,
        registries: Arc<SmokeRegistryStore>,
        witness: Arc<FirestoreWitness>,
    }

    impl SmokeGenesisRuntime {
        fn shadow_witness(&self) -> Arc<FirestoreShadowWitness> {
            Arc::new(FirestoreShadowWitness::from_witness_for_test(Arc::clone(
                &self.witness,
            )))
        }
    }

    #[async_trait::async_trait]
    impl GenesisRuntimeSource for SmokeGenesisRuntime {
        fn armed(&self) -> std::result::Result<bool, GenesisTriggerError> {
            Ok(true)
        }

        fn genesis_providers(
            &self,
            control: &Arc<ControlStore>,
            binding: crate::cp::control_store::ArchiveBinding,
        ) -> std::result::Result<GenesisDriverProviders, GenesisTriggerError> {
            let archive_id = binding.archive_id();
            let objects: Arc<dyn ImmutableObjectBackend> = Arc::clone(&self.objects) as Arc<_>;
            let backend = ControlPlaneGenesisBackend::new(
                GenesisBackendRuntimeContext::for_test(),
                Arc::clone(control),
                Arc::clone(&objects),
                Arc::new(SmokeRootProvider(Arc::clone(&self.objects))),
                Arc::clone(&self.registries) as Arc<dyn GenesisRegistryStore>,
                Arc::clone(&self.witness),
            );
            Ok(GenesisDriverProviders {
                archive_id,
                backend: Box::new(backend),
                objects,
                registry_wrap: Box::new(SmokeRegistryWrap(Arc::clone(&self.registries))),
                witness_advance: self.shadow_witness()
                    as Arc<dyn crate::archive_v3_root_advance::ArchiveWitnessAdvanceProvider>,
            })
        }

        async fn serving_handoff(
            &self,
            control: Arc<ControlStore>,
            binding: crate::cp::control_store::ArchiveBinding,
        ) -> std::result::Result<
            crate::archive_v3_shadow_runtime::WalServingHandoff,
            GenesisTriggerError,
        > {
            crate::archive_v3_shadow_runtime::SealedSingleArchiveWalRuntime::for_publisher_test(
                binding,
                Arc::clone(&self.objects) as Arc<dyn ImmutableObjectBackend>,
                Arc::clone(&self.registries) as Arc<dyn ExactKeyRegistryProvider>,
                self.shadow_witness(),
                self.shadow_witness(),
            )
            .reconstruct_wal_serving_handoff(control)
            .await
            .map_err(|_| GenesisTriggerError::Conflict)
        }
    }

    /// Owned wrap authority over the shared registry CAS, mirroring what
    /// `ReleasedGenesisRegistryWrap` is on the production source.
    struct SmokeRegistryWrap(Arc<SmokeRegistryStore>);

    #[async_trait::async_trait]
    impl GenesisRegistryWrapAuthority for SmokeRegistryWrap {
        async fn wrap_registry(
            &self,
            context: &KeyRegistryContext,
            registry_plaintext: &[u8],
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            self.0
                .wrap_registry(context, registry_plaintext, destination)
                .await
        }
    }

    /// Converge one user over an explicit source. This is the production
    /// entry point with the seam made visible; `converge_genesis_for_user`
    /// is exactly this over [`BakedImageGenesisRuntime`].
    pub(crate) async fn converge_for_smoke(
        source: &SmokeGenesisRuntime,
        control: &Arc<ControlStore>,
        store: &Arc<Store>,
        user_id: &str,
    ) -> std::result::Result<GenesisConvergence, GenesisTriggerError> {
        converge_genesis_over(source, control, store, user_id).await
    }
}
