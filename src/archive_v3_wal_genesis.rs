#![allow(
    dead_code,
    reason = "inactive ADR-0022 genesis driver is compiled and fake-tested before authority wiring"
)]

//! Inactive ADR-0022 genesis bytes producer and witness-ladder driver
//! (genesis spine G5/G6).
//!
//! G5 produces the exact bytes of a fresh one-user archive in the reviewed
//! order: reserve the durable bootstrap, mint a DEK into a local cipher, wrap
//! the registry (bytes only — no object is written), materialize a temporary
//! empty schema-current database, upload it as an owned checkpoint (no lease,
//! no witness), build the canonical checkpoint-only `0/0/0` zero-WAL genesis
//! root, seal it, durably prepare both byte payloads, and resolve genesis.
//! Before `prepare_archive_bootstrap`, a crash orphans one checkpoint's objects and the retry mints a fresh DEK. After it, replay is byte-exact.
//!
//! That boundary is decided by the durable anchor, not by the caller:
//! [`start_genesis_bootstrap`] recovers first, and a pass that finds a
//! prepared anchor resumes from the stored payloads and produces nothing at
//! all — no second DEK, no second checkpoint, no second staging binding. This
//! is not merely an efficiency: the control ledger ignores the bytes a
//! post-boundary prepare is handed and replays the stored ones, so a
//! re-producing pass would stage its objects under a binding built from a
//! wrapped-registry hash the ladder can never rebuild.
//!
//! Orphan accounting: staged-object rows are offered to the injected
//! `ShadowObjectInventory` seam reserve-first, and G9's
//! `GenesisStagingInventory` is the durable production recorder that accepts a
//! genesis binding (the ControlStore's maintenance inventory is
//! maintenance-operation-bound and cannot, and the reachability sweep starts
//! only from witness-selected roots). Pre-prepare crash orphans are therefore
//! durably named by exact canonical key rather than unenumerable; they are
//! also undecryptable — the crashed attempt's DEK dies with the process — so
//! the residual exposure is storage residue, not data.
//!
//! G6 then runs the witness ladder (Variant B) on the freshly read witness:
//! acquire the exact lease, advance Legacy → ShadowWal with a zero-WAL
//! candidate at root sequence 1 over the same checkpoint, advance
//! ShadowWal → WalAuthoritative at root sequence 2 over the same checkpoint,
//! and release the terminal maintenance lease. The terminal witness is
//! Active, WalAuthoritative, unowned with a zero lease expiry at root
//! sequence 2, and satisfies the untouched WAL-owner acquire predicate. A
//! restart between the two advances resumes at the second advance; rerunning
//! the completed ladder converges without a third root.
//!
//! This module deliberately owns no provider construction: every authority is
//! an injected, already-released provider handle, and nothing in startup,
//! Store, or routes constructs the driver. Kill-and-restart at every
//! boundary yields either the same archive or a clean retry — never two
//! witnesses, and never a root whose envelope hash disagrees with the
//! durably prepared bytes.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    archive_v3::{
        resolve_archive_cipher, ArchiveCipher, ArchiveDek, ArchiveId, ArchiveRoot, ArchiveV3Error,
        CiphertextEnvelope, DatabaseEpoch, ImmutableObjectBackend, KeyEpoch, KeyKind,
        KeyRegistryContext, KeyRegistryPlaintext, LogicalLocation, ObjectContext, ObjectId,
        ObjectRole, VerifiedArchiveCipher, ARCHIVE_FORMAT_VERSION, MAX_WRAPPED_KEY_REGISTRY_BYTES,
        SQLITE_PAGE_SIZE,
    },
    archive_v3_gcs::GcsArchiveV3RegistryProvider,
    archive_v3_genesis::{
        ArchiveGenesis, ArchiveGenesisBackend, BootstrapError, GenesisResolution,
    },
    archive_v3_genesis_backend::GenesisBackendRuntimeContext,
    archive_v3_lifecycle::{
        BootstrapAttemptId, BootstrapPlan, DurableBootstrapReservation, LifecycleError,
        PreparedBootstrap, RecoveredBootstrap,
    },
    archive_v3_root_advance::{
        build_zero_wal_candidate, ArchiveWitnessAdvanceProvider, RootAdvanceError,
        WitnessAdvanceCommitError,
    },
    archive_v3_shadow_checkpoint::{
        recover_checkpoint_from_recovery_root, upload_owned_checkpoint, CheckpointCipher,
        CheckpointSink, OwnedCheckpointSource, Result as CheckpointResult, ShadowCheckpointError,
        ShadowObjectInventory, ShadowObjectInventoryError, ShadowObjectStaging, UploadedCheckpoint,
    },
    archive_v3_shadow_session::{ShadowAttemptId, ShadowSessionBinding, ShadowSessionId},
    archive_v3_witness::{
        DeletionState, MigrationState, RecoveryRoot, WitnessError, WitnessRecord,
    },
    cp::control_store::ControlStore,
    store::{initialize_genesis_store, GenesisStoreFacts},
};

/// Ladder lease duration, matching the offline maintenance importer's ticks.
const GENESIS_LEASE_TICKS: u64 = 86_400;

/// The durable reservation CAS is always revision 1 (the control ledger pins
/// it); the genesis staging binding reuses that revision as its fence.
const GENESIS_RESERVATION_REVISION: u64 = 1;

/// Derivation domain for the stable per-attempt ladder owner identity. A
/// restarted driver derives the same owner from the durably reserved attempt,
/// so it can validate and release its own retained lease instead of fencing
/// itself out.
const GENESIS_OWNER_DOMAIN: &[u8] = b"kioku:archive:v3:genesis-ladder-owner/v1\0";

/// Defensive ceiling for the genesis database. The empty schema-current
/// database is a few megabytes; anything larger than this is not a genesis
/// archive and fails closed before unbounded memory is committed.
const MAX_GENESIS_DATABASE_BYTES: u64 = 64 * 1024 * 1024;

/// Producer token for the genesis-only zero-WAL staging binding. It has no
/// public or sibling constructor, so only this module's reviewed driver can
/// mint the binding shape that carries no witness, lease, or sealed base
/// root.
pub(crate) struct GenesisZeroWalBindingContext(());

impl fmt::Debug for GenesisZeroWalBindingContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenesisZeroWalBindingContext(<opaque>)")
    }
}

/// Redacted genesis driver error. Storage-layer failure detail is deliberately
/// collapsed so callers reconcile only through exact durable rereads and
/// reruns, never through error-variant guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum WalGenesisError {
    #[error("archive genesis authority is unavailable")]
    Unavailable,
    #[error("archive genesis found competing durable state")]
    Conflict,
    #[error("archive genesis durable state is corrupt")]
    Corrupt,
    #[error("archive genesis provider outcome is unknown; rerun to converge")]
    OutcomeUnknown,
}

fn map_lifecycle(error: LifecycleError) -> WalGenesisError {
    match error {
        LifecycleError::Unavailable => WalGenesisError::Unavailable,
        LifecycleError::StaleRevision | LifecycleError::InvalidState => WalGenesisError::Conflict,
        _ => WalGenesisError::Corrupt,
    }
}

fn map_archive(error: ArchiveV3Error) -> WalGenesisError {
    match error {
        ArchiveV3Error::Unavailable => WalGenesisError::Unavailable,
        ArchiveV3Error::Conflict => WalGenesisError::Conflict,
        _ => WalGenesisError::Corrupt,
    }
}

fn map_witness(error: WitnessError) -> WalGenesisError {
    match error {
        WitnessError::Unavailable => WalGenesisError::Unavailable,
        WitnessError::Fenced
        | WitnessError::CompareFailed
        | WitnessError::InvalidTransition
        | WitnessError::AlreadyExists => WalGenesisError::Conflict,
        _ => WalGenesisError::Corrupt,
    }
}

fn map_bootstrap(error: BootstrapError) -> WalGenesisError {
    match error {
        BootstrapError::OutcomeUnknown => WalGenesisError::OutcomeUnknown,
        BootstrapError::Conflict | BootstrapError::Tombstoned | BootstrapError::WitnessChanged => {
            WalGenesisError::Conflict
        }
        BootstrapError::MalformedCandidate => WalGenesisError::Corrupt,
        BootstrapError::Archive(error) => map_archive(error),
        BootstrapError::Witness(error) => map_witness(error),
        BootstrapError::Lifecycle(error) => map_lifecycle(error),
    }
}

fn map_checkpoint(error: ShadowCheckpointError) -> WalGenesisError {
    match error {
        ShadowCheckpointError::Archive(error) => map_archive(error),
        ShadowCheckpointError::Witness(error) => map_witness(error),
        ShadowCheckpointError::Inventory(ShadowObjectInventoryError::Unavailable) => {
            WalGenesisError::Unavailable
        }
        ShadowCheckpointError::Inventory(_) => WalGenesisError::Conflict,
        ShadowCheckpointError::MissingObject
        | ShadowCheckpointError::Source
        | ShadowCheckpointError::Sink => WalGenesisError::Corrupt,
    }
}

fn map_root_advance(error: RootAdvanceError) -> WalGenesisError {
    match error {
        RootAdvanceError::Unavailable => WalGenesisError::Unavailable,
        RootAdvanceError::Corrupt => WalGenesisError::Corrupt,
    }
}

/// Durable bootstrap-anchor recovery seam. The driver must reuse the durably
/// reserved random plan on retry instead of minting a competing one; only the
/// encrypted control ledger can answer whether a reservation already exists.
#[async_trait]
pub(crate) trait GenesisBootstrapRecovery: Send + Sync {
    async fn recover_reserved_bootstrap(
        &self,
        archive_id: ArchiveId,
    ) -> Result<Option<RecoveredBootstrap>, LifecycleError>;
}

#[async_trait]
impl GenesisBootstrapRecovery for ControlStore {
    async fn recover_reserved_bootstrap(
        &self,
        archive_id: ArchiveId,
    ) -> Result<Option<RecoveredBootstrap>, LifecycleError> {
        self.recover_archive_bootstrap_if_reserved(archive_id)
            .await
            .map_err(|_| LifecycleError::Unavailable)
    }
}

/// Wrapped-registry production seam: produce the exact KMS-wrapped registry
/// bytes for the typed context without writing any object. The production
/// implementation is the released concrete GCS registry provider behind its
/// genesis token; contract tests substitute a round-tripping fake.
#[async_trait]
pub(crate) trait GenesisRegistryWrapAuthority: Send + Sync {
    async fn wrap_registry(
        &self,
        context: &KeyRegistryContext,
        registry_plaintext: &[u8],
        destination: &mut [u8],
    ) -> crate::archive_v3::Result<usize>;
}

/// Released production wrap authority. Constructing it consumes a genesis
/// backend token, which has no production minter today, so sibling modules
/// cannot assemble raw registry-wrap authority through this seam.
pub(crate) struct ReleasedGenesisRegistryWrap {
    provider: Arc<GcsArchiveV3RegistryProvider>,
    token: GenesisBackendRuntimeContext,
}

impl ReleasedGenesisRegistryWrap {
    pub(crate) fn new(
        token: GenesisBackendRuntimeContext,
        provider: Arc<GcsArchiveV3RegistryProvider>,
    ) -> Self {
        Self { provider, token }
    }
}

impl fmt::Debug for ReleasedGenesisRegistryWrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReleasedGenesisRegistryWrap(<inactive>)")
    }
}

#[async_trait]
impl GenesisRegistryWrapAuthority for ReleasedGenesisRegistryWrap {
    async fn wrap_registry(
        &self,
        context: &KeyRegistryContext,
        registry_plaintext: &[u8],
        destination: &mut [u8],
    ) -> crate::archive_v3::Result<usize> {
        self.provider
            .wrap_registry(&self.token, context, registry_plaintext, destination)
            .await
    }
}

/// Injected, already-released provider set for one genesis run. The driver
/// composes these but constructs none of them; a future reviewed launcher
/// (G9) supplies production handles, and until then nothing reaches this.
pub(crate) struct WalGenesisAuthority<'a> {
    pub(crate) recovery: &'a dyn GenesisBootstrapRecovery,
    pub(crate) backend: &'a dyn ArchiveGenesisBackend,
    pub(crate) objects: &'a dyn ImmutableObjectBackend,
    pub(crate) registry_wrap: &'a dyn GenesisRegistryWrapAuthority,
    pub(crate) inventory: &'a dyn ShadowObjectInventory,
    pub(crate) witness_advance: &'a dyn ArchiveWitnessAdvanceProvider,
}

impl fmt::Debug for WalGenesisAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalGenesisAuthority(<inactive>)")
    }
}

/// Result of one complete genesis run.
pub(crate) struct WalGenesisOutcome {
    pub(crate) resolution: GenesisResolution,
    pub(crate) terminal_witness: WitnessRecord,
}

impl fmt::Debug for WalGenesisOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalGenesisOutcome(<opaque>)")
    }
}

/// Exact retry-stable genesis bytes staged for `prepare_archive_bootstrap`.
pub(crate) struct ProducedGenesisBytes {
    reservation: DurableBootstrapReservation,
    wrapped_registry: Zeroizing<Vec<u8>>,
    root_envelope: Vec<u8>,
}

impl ProducedGenesisBytes {
    pub(crate) const fn reservation(&self) -> DurableBootstrapReservation {
        self.reservation
    }

    pub(crate) fn root_envelope_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.root_envelope).into()
    }
}

impl fmt::Debug for ProducedGenesisBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProducedGenesisBytes(<opaque>)")
    }
}

/// Run the complete genesis: reserve, produce, prepare, resolve, and the
/// witness ladder. Rerunning after a kill at any boundary converges to the
/// same archive or performs a clean fresh-bytes retry, per the module
/// contract above.
pub(crate) async fn run_wal_genesis(
    authority: &WalGenesisAuthority<'_>,
    scratch_dir: &Path,
    archive_id: ArchiveId,
) -> Result<WalGenesisOutcome, WalGenesisError> {
    let prepared = match start_genesis_bootstrap(authority, archive_id).await? {
        GenesisBootstrapStart::Resume(prepared) => prepared,
        GenesisBootstrapStart::Produce(reservation) => {
            let produced = produce_genesis_bytes(authority, scratch_dir, reservation).await?;
            // ◄── CRASH BOUNDARY.
            prepare_genesis_bootstrap(authority, produced).await?
        }
    };
    let plan = prepared.reservation().plan();
    let wrapped_registry_hash = prepared.wrapped_registry_hash();
    let (resolution, _record) = resolve_genesis(authority, prepared).await?;
    let terminal_witness = run_witness_ladder(authority, plan, wrapped_registry_hash).await?;
    // Genesis publishes root sequence 0 and the ladder adds exactly two
    // zero-WAL roots; any other terminal sequence is not this archive.
    if terminal_witness.migration() != MigrationState::WalAuthoritative
        || terminal_witness.deletion() != DeletionState::Active
        || terminal_witness.root().root().sequence() != 2
    {
        return Err(WalGenesisError::Conflict);
    }
    Ok(WalGenesisOutcome {
        resolution,
        terminal_witness,
    })
}

/// Reserve (or exactly re-adopt) the durable bootstrap plan for one archive.
/// A fresh archive mints random plan identifiers; a retry recovers the exact
/// durably reserved plan first, because the reservation CAS refuses any
/// competing plan for the same archive.
pub(crate) async fn reserve_genesis_bootstrap(
    authority: &WalGenesisAuthority<'_>,
    archive_id: ArchiveId,
) -> Result<DurableBootstrapReservation, WalGenesisError> {
    let plan = match authority
        .recovery
        .recover_reserved_bootstrap(archive_id)
        .await
        .map_err(map_lifecycle)?
    {
        Some(recovered) => {
            let plan = recovered.reservation().plan();
            if plan.archive_id() != archive_id {
                return Err(WalGenesisError::Corrupt);
            }
            plan
        }
        None => mint_bootstrap_plan(archive_id)?,
    };
    let reservation = authority
        .backend
        .reserve_bootstrap(plan)
        .await
        .map_err(map_lifecycle)?;
    if reservation.plan() != plan || reservation.revision() != GENESIS_RESERVATION_REVISION {
        return Err(WalGenesisError::Corrupt);
    }
    Ok(reservation)
}

/// Where one convergence pass must start, decided by the durable bootstrap
/// anchor rather than by a caller's memory of how far a previous pass got.
///
/// The distinction is load-bearing precisely at the prepare crash boundary.
/// Once `prepare_archive_bootstrap` has committed, the stored payloads are the
/// only correct bytes for this archive: the control ledger replays them and
/// *ignores* whatever a later pass hands it, while the witness ladder rebuilds
/// its staging binding from the STORED wrapped-registry hash. A resumed pass
/// that re-produced anyway would mint a second DEK, hash a second wrapped
/// registry, and stage its checkpoint under a binding derived from that
/// discarded hash — leaving the ladder unable to stage anything under the
/// binding it is required to use, on every subsequent pass. Recovering first
/// deletes that branch instead of trying to reconcile it.
pub(crate) enum GenesisBootstrapStart {
    /// Nothing is durably prepared yet, so this pass produces the bytes under
    /// the freshly minted or exactly re-adopted reservation.
    Produce(DurableBootstrapReservation),
    /// The anchor is already past the crash boundary: resume from the durable
    /// payloads and produce nothing at all.
    Resume(PreparedBootstrap),
}

impl fmt::Debug for GenesisBootstrapStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenesisBootstrapStart(<opaque>)")
    }
}

/// Recover the durable bootstrap anchor first and report where this pass
/// starts. A prepared anchor resumes; anything else takes the unchanged
/// reserve path.
pub(crate) async fn start_genesis_bootstrap(
    authority: &WalGenesisAuthority<'_>,
    archive_id: ArchiveId,
) -> Result<GenesisBootstrapStart, WalGenesisError> {
    if let Some(recovered) = authority
        .recovery
        .recover_reserved_bootstrap(archive_id)
        .await
        .map_err(map_lifecycle)?
    {
        // Same two invariants the reserve path asserts on its own receipt:
        // the anchor is this archive's, and it sits at the pinned reservation
        // revision the staging binding fences on.
        if recovered.reservation().plan().archive_id() != archive_id
            || recovered.reservation().revision() != GENESIS_RESERVATION_REVISION
        {
            return Err(WalGenesisError::Corrupt);
        }
        if recovered.prepared().is_some() {
            return match recovered {
                RecoveredBootstrap::Prepared(prepared) => {
                    Ok(GenesisBootstrapStart::Resume(prepared))
                }
                // Unreachable given the check above; refuse rather than assume.
                RecoveredBootstrap::Reserved(_) => Err(WalGenesisError::Corrupt),
            };
        }
    }
    // Not prepared: today's reserve path, unchanged. It recovers again so the
    // exact reserved-plan re-adoption lives in exactly one place.
    Ok(GenesisBootstrapStart::Produce(
        reserve_genesis_bootstrap(authority, archive_id).await?,
    ))
}

/// Produce the exact genesis bytes for one attempt, in the reviewed order:
/// mint DEK → local cipher → wrap registry (bytes, no object) → materialize
/// the temporary empty schema-current database → upload it as an owned
/// checkpoint (no lease, no witness) → build and seal the canonical
/// checkpoint-only zero-WAL genesis root. Everything here precedes the
/// prepare crash boundary, so a kill leaves only sweepable orphans and the
/// retry mints a fresh DEK.
pub(crate) async fn produce_genesis_bytes(
    authority: &WalGenesisAuthority<'_>,
    scratch_dir: &Path,
    reservation: DurableBootstrapReservation,
) -> Result<ProducedGenesisBytes, WalGenesisError> {
    let plan = reservation.plan();

    // Mint DEK → local cipher. The DEK bytes come from the system CSPRNG and
    // exist only in this attempt's memory until the wrapped registry is
    // durably prepared.
    let dek = ArchiveDek::generate();
    let registry_context =
        KeyRegistryContext::new(plan.archive_id(), KeyKind::Archive, plan.key_epoch());
    let registry_plaintext =
        KeyRegistryPlaintext::encode_archive(&registry_context, &dek).map_err(map_archive)?;
    let cipher = GenesisSealCipher {
        archive_id: plan.archive_id(),
        key_epoch: plan.key_epoch(),
        cipher: ArchiveCipher::new(dek),
    };

    // wrap_registry produces bytes and writes NO object; the registry object
    // is created only by `ArchiveGenesis::resolve` after prepare.
    let mut wrapped = Zeroizing::new(vec![0u8; MAX_WRAPPED_KEY_REGISTRY_BYTES]);
    let wrapped_len = authority
        .registry_wrap
        .wrap_registry(
            &registry_context,
            registry_plaintext.as_slice(),
            wrapped.as_mut_slice(),
        )
        .await
        .map_err(map_archive)?;
    if wrapped_len == 0 || wrapped_len > wrapped.len() {
        return Err(WalGenesisError::Corrupt);
    }
    let wrapped_registry = Zeroizing::new(wrapped[..wrapped_len].to_vec());
    let wrapped_registry_hash: [u8; 32] = Sha256::digest(wrapped_registry.as_slice()).into();

    // Temporary empty schema-current database, measured and then removed; the
    // published facts must describe the uploaded bytes exactly.
    let source = materialize_genesis_source(scratch_dir).await?;

    // Owned checkpoint upload: verified untokened, no lease and no witness.
    let binding = genesis_binding(&plan, wrapped_registry_hash)?;
    let session_id = genesis_session_id(&plan)?;
    let staging = ShadowObjectStaging::new(
        authority.inventory,
        session_id,
        ShadowAttemptId::random(),
        binding,
    );
    let checkpoint = upload_owned_checkpoint(
        authority.objects,
        &cipher,
        plan.archive_id(),
        plan.database_epoch(),
        &source,
        staging,
    )
    .await
    .map_err(map_checkpoint)?;

    // The canonical producer-gated checkpoint-only `0/0/0` zero-WAL geometry
    // that maintenance zero-WAL recovery blesses: no WAL tuple, no extent
    // tree, no commit tail, and the checkpoint length equal to the logical
    // length. Target that shape exactly so no recovery code changes.
    let root = ArchiveRoot {
        root_seq: 0,
        parent: None,
        database_epoch: plan.database_epoch(),
        key_epoch: plan.key_epoch(),
        owner_fencing_epoch: 0,
        sqlite_page_size: SQLITE_PAGE_SIZE,
        checkpoint_logical_file_length: checkpoint.logical_file_length(),
        logical_file_length: checkpoint.logical_file_length(),
        user_schema_version: checkpoint.user_schema_version(),
        storage_format_version: ARCHIVE_FORMAT_VERSION,
        wal_generation: 0,
        wal_commit_count: 0,
        wal_segment_count: 0,
        wal_tail_bytes: 0,
        checkpoint_root: Some(checkpoint.root().clone()),
        extent_tree_root: None,
        wal_commit_tail: None,
    };
    let root_context = ObjectContext::new(
        plan.archive_id(),
        plan.database_epoch(),
        plan.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root { root_seq: 0 },
        plan.root_object_id(),
        None,
    )
    .map_err(map_archive)?;
    let encoded_root = root.encode().map_err(map_archive)?;
    let envelope =
        CheckpointCipher::seal(&cipher, &root_context, &encoded_root).map_err(map_archive)?;
    Ok(ProducedGenesisBytes {
        reservation,
        wrapped_registry,
        root_envelope: envelope.encode(),
    })
}

/// ◄── CRASH BOUNDARY. Durably record both exact byte payloads under the
/// reservation. Before this call a crash orphans the attempt's checkpoint
/// objects and the retry mints fresh bytes; from this call on, the control
/// ledger replays the stored bytes and every retry is byte-exact.
pub(crate) async fn prepare_genesis_bootstrap(
    authority: &WalGenesisAuthority<'_>,
    produced: ProducedGenesisBytes,
) -> Result<PreparedBootstrap, WalGenesisError> {
    authority
        .backend
        .prepare_bootstrap(
            produced.reservation,
            produced.wrapped_registry.as_slice(),
            &produced.root_envelope,
        )
        .await
        .map_err(map_lifecycle)
}

/// Resolve genesis against the injected backend, then read the witness back.
/// `ArchiveGenesis::resolve` returns a fieldless enum by design, so the
/// driver re-reads the exact record it will hand to the ladder.
///
/// A witness already beyond the exact initial record means genesis resolved
/// on a prior run and the ladder has begun: the lifecycle ledger's adopt CAS
/// accepts only the byte-exact retained initial candidate (by design), so
/// the driver authenticates the exact prepared genesis lineage on the
/// current record instead of re-entering `resolve`, and every subsequent
/// authority still flows through the untouched cipher-resolution, recovery,
/// and witness CAS predicates.
pub(crate) async fn resolve_genesis(
    authority: &WalGenesisAuthority<'_>,
    prepared: PreparedBootstrap,
) -> Result<(GenesisResolution, WitnessRecord), WalGenesisError> {
    let plan = prepared.reservation().plan();
    let archive_id = plan.archive_id();
    let wrapped_registry_hash = prepared.wrapped_registry_hash();
    if let Some(record) = authority
        .backend
        .read_witness(archive_id)
        .await
        .map_err(map_bootstrap)?
    {
        let beyond_genesis =
            record.migration() != MigrationState::Legacy || record.root().root().sequence() != 0;
        if beyond_genesis {
            let registry = record.registry();
            if record.deletion() != DeletionState::Active
                || record.archive_id() != archive_id
                || record.database_epoch() != plan.database_epoch()
                || record.database_epoch_generation() != 0
                || registry.key_epoch() != plan.key_epoch()
                || registry.object_id() != plan.registry_object_id()
                || registry.rotation_generation() != 0
                || registry.ciphertext_hash() != wrapped_registry_hash
            {
                return Err(WalGenesisError::Conflict);
            }
            return Ok((GenesisResolution::Existing, record));
        }
    }
    let genesis = ArchiveGenesis::new(prepared).map_err(map_bootstrap)?;
    let resolution = genesis
        .resolve(authority.backend)
        .await
        .map_err(map_bootstrap)?;
    let record = authority
        .backend
        .read_witness(archive_id)
        .await
        .map_err(map_bootstrap)?
        .ok_or(WalGenesisError::Corrupt)?;
    Ok((resolution, record))
}

/// Run the G6 witness ladder (Variant B) to its released terminal. The loop
/// converges from any restart point: a Legacy witness performs both
/// advances, a ShadowWal witness resumes at the second advance, and a
/// WalAuthoritative witness only releases (or adopts) the terminal.
pub(crate) async fn run_witness_ladder(
    authority: &WalGenesisAuthority<'_>,
    plan: BootstrapPlan,
    wrapped_registry_hash: [u8; 32],
) -> Result<WitnessRecord, WalGenesisError> {
    let archive_id = plan.archive_id();
    let owner_id = genesis_owner_id(plan.attempt_id())?;
    // Legacy → ShadowWal, ShadowWal → WalAuthoritative, terminal release:
    // three productive iterations; a fourth means the witness regressed.
    for _ in 0..3 {
        let current = read_active(authority, archive_id).await?;
        match current.migration() {
            MigrationState::Legacy | MigrationState::ShadowWal => {
                advance_genesis_ladder_once(authority, plan, wrapped_registry_hash).await?;
            }
            MigrationState::WalAuthoritative => {
                return finish_terminal(authority, archive_id, owner_id, current).await;
            }
            _ => return Err(WalGenesisError::Conflict),
        }
    }
    Err(WalGenesisError::Conflict)
}

/// Perform exactly one zero-WAL migration advance from the current witness
/// state: Legacy → ShadowWal at root sequence 1, or ShadowWal →
/// WalAuthoritative at root sequence 2, each publishing a new zero-WAL root
/// over the checkpoint the current witness root nominates. Returns the
/// witness record observed equal to the sent candidate.
pub(crate) async fn advance_genesis_ladder_once(
    authority: &WalGenesisAuthority<'_>,
    plan: BootstrapPlan,
    wrapped_registry_hash: [u8; 32],
) -> Result<WitnessRecord, WalGenesisError> {
    let archive_id = plan.archive_id();
    let owner_id = genesis_owner_id(plan.attempt_id())?;
    let current = read_active(authority, archive_id).await?;
    let next = match current.migration() {
        MigrationState::Legacy => MigrationState::ShadowWal,
        MigrationState::ShadowWal => MigrationState::WalAuthoritative,
        _ => return Err(WalGenesisError::Conflict),
    };

    // Reuse the exact retained lease when this stable owner already holds it
    // (a restart between the two advances, or the second advance under the
    // first advance's lease); otherwise acquire fresh. The validate-first
    // order never mutates the record when the lease is already ours.
    let (leased, lease) = match authority
        .witness_advance
        .validate_exact_lease(&current, owner_id)
        .await
    {
        Ok(lease) => (current, lease),
        Err(_) => {
            let lease = authority
                .witness_advance
                .acquire_lease_exact(&current, owner_id, GENESIS_LEASE_TICKS)
                .await
                .map_err(map_witness)?;
            let leased = read_active(authority, archive_id).await?;
            if leased.migration() != next_predecessor(next)
                || !leased.authorizes_lease(lease)
                || leased.root() != current.root()
            {
                // The acquire landed on state this rung must not advance
                // (including the stale-read race onto an already-released
                // terminal): clear our own lease before failing, or it
                // blocks WAL-owner acquisition for the full lease term.
                release_abandoned_ladder_lease(authority, archive_id, owner_id).await;
                return Err(WalGenesisError::Conflict);
            }
            (leased, lease)
        }
    };

    let rung = async {
        // Same checkpoint: the candidate is built over the checkpoint nominated
        // by the current witness root, recovered and re-authenticated — never
        // over any retained in-memory upload from a prior attempt.
        let cipher = resolve_ladder_cipher(authority, &leased).await?;
        let checkpoint = recover_genesis_checkpoint(authority, &cipher, &leased).await?;
        let binding = genesis_binding(&plan, wrapped_registry_hash)?;
        let session_id = genesis_session_id(&plan)?;
        let staging = ShadowObjectStaging::new(
            authority.inventory,
            session_id,
            ShadowAttemptId::random(),
            binding,
        );
        let advance = build_zero_wal_candidate(
            authority.objects,
            &cipher,
            &leased,
            lease,
            &checkpoint,
            &staging,
        )
        .await
        .map_err(map_root_advance)?;
        let candidate = leased
            .exact_migration_candidate(&advance, next)
            .map_err(map_witness)?;
        let outcome = authority
            .witness_advance
            .advance_migration_unresolved(leased.clone(), candidate.clone(), advance, next)
            .await;
        // Reconcile only by an exact reread: the candidate byte-equal in the
        // provider is the sole success, an unchanged predecessor maps the send
        // outcome, and anything else is competing state.
        let observed = authority
            .witness_advance
            .read_current_exact(archive_id)
            .await
            .map_err(|_| WalGenesisError::OutcomeUnknown)?;
        if observed == candidate {
            return Ok(observed);
        }
        if observed != leased {
            return Err(WalGenesisError::Conflict);
        }
        Err(match outcome {
            Err(WitnessAdvanceCommitError::Rejected) => WalGenesisError::Conflict,
            Err(WitnessAdvanceCommitError::DefinitelyFailed) => WalGenesisError::Unavailable,
            Err(WitnessAdvanceCommitError::OutcomeUnknown) | Ok(()) => {
                WalGenesisError::OutcomeUnknown
            }
        })
    }
    .await;
    if rung.is_err() {
        // A failed rung after a successful acquire must not strand the
        // lease; the provider's byte-exact retained-record validation
        // makes this a no-op for anything that is not ours.
        release_abandoned_ladder_lease(authority, archive_id, owner_id).await;
    }
    rung
}

/// Best-effort release of this driver's own abandoned ladder lease after a
/// failed rung. The provider validates the retained record byte-exactly and
/// the release arms are migration-scoped, so this can only ever clear a
/// lease the current stored record grants to THIS derived owner — a lease
/// another actor holds, or a record that advanced, refuses harmlessly.
/// Without this, a rung failure after a successful acquire (including the
/// stale-read race where the acquire lands on an already-released terminal)
/// abandons an 86,400-tick lease that blocks WAL-owner acquisition.
async fn release_abandoned_ladder_lease(
    authority: &WalGenesisAuthority<'_>,
    archive_id: ArchiveId,
    owner_id: ObjectId,
) {
    let Ok(record) = authority
        .witness_advance
        .read_current_exact(archive_id)
        .await
    else {
        return;
    };
    let _ = match record.migration() {
        MigrationState::WalAuthoritative => {
            authority
                .witness_advance
                .release_terminal_lease_unresolved(record, owner_id)
                .await
        }
        _ => {
            authority
                .witness_advance
                .release_advisory_lease_unresolved(record, owner_id)
                .await
        }
    };
}

const fn next_predecessor(next: MigrationState) -> MigrationState {
    match next {
        MigrationState::WalAuthoritative => MigrationState::ShadowWal,
        _ => MigrationState::Legacy,
    }
}

/// Release the terminal maintenance lease (when this driver's stable owner
/// holds it) and authenticate the released successor. A terminal that is not
/// leased by this owner is adopted as already-converged: this driver never
/// clears anyone else's lease, and the WAL-owner acquire predicate remains
/// the fail-closed enforcement point for any non-terminal shape.
async fn finish_terminal(
    authority: &WalGenesisAuthority<'_>,
    archive_id: ArchiveId,
    owner_id: ObjectId,
    current: WitnessRecord,
) -> Result<WitnessRecord, WalGenesisError> {
    if current.migration() != MigrationState::WalAuthoritative
        || current.deletion() != DeletionState::Active
    {
        return Err(WalGenesisError::Conflict);
    }
    if current.exact_active_lease_for_owner(owner_id).is_err() {
        return Ok(current);
    }
    let release = authority
        .witness_advance
        .release_terminal_lease_unresolved(current.clone(), owner_id)
        .await;
    let released = authority
        .witness_advance
        .read_current_exact(archive_id)
        .await
        .map_err(|_| WalGenesisError::OutcomeUnknown)?;
    let requires_release = released
        .exact_maintenance_terminal_or_release_from(&current, owner_id)
        .map_err(map_witness)?;
    if requires_release {
        return Err(match release {
            Err(WitnessAdvanceCommitError::DefinitelyFailed) => WalGenesisError::Unavailable,
            Err(WitnessAdvanceCommitError::Rejected) => WalGenesisError::Conflict,
            Err(WitnessAdvanceCommitError::OutcomeUnknown) | Ok(()) => {
                WalGenesisError::OutcomeUnknown
            }
        });
    }
    Ok(released)
}

async fn read_active(
    authority: &WalGenesisAuthority<'_>,
    archive_id: ArchiveId,
) -> Result<WitnessRecord, WalGenesisError> {
    let record = authority
        .witness_advance
        .read_current_exact(archive_id)
        .await
        .map_err(map_witness)?;
    if record.archive_id() != archive_id || record.deletion() != DeletionState::Active {
        return Err(WalGenesisError::Conflict);
    }
    Ok(record)
}

async fn resolve_ladder_cipher(
    authority: &WalGenesisAuthority<'_>,
    record: &WitnessRecord,
) -> Result<VerifiedArchiveCipher, WalGenesisError> {
    let registry = record.registry();
    let context = KeyRegistryContext::with_rotation_generation(
        record.archive_id(),
        KeyKind::Archive,
        registry.key_epoch(),
        registry.rotation_generation(),
    );
    resolve_archive_cipher(
        &context,
        registry.object_id(),
        registry.ciphertext_hash(),
        authority.backend,
    )
    .await
    .map_err(map_archive)
}

async fn recover_genesis_checkpoint(
    authority: &WalGenesisAuthority<'_>,
    cipher: &VerifiedArchiveCipher,
    record: &WitnessRecord,
) -> Result<UploadedCheckpoint, WalGenesisError> {
    let recovery = RecoveryRoot::from_exact_active_record(record).map_err(map_witness)?;
    let mut sink = BoundedMemorySink::new(MAX_GENESIS_DATABASE_BYTES);
    recover_checkpoint_from_recovery_root(
        &recovery,
        authority.objects,
        cipher,
        record.archive_id(),
        &mut sink,
    )
    .await
    .map_err(map_checkpoint)
}

fn genesis_session_id(plan: &BootstrapPlan) -> Result<ShadowSessionId, WalGenesisError> {
    ShadowSessionId::for_operation(*plan.attempt_id().as_bytes())
        .map_err(|_| WalGenesisError::Corrupt)
}

fn genesis_binding(
    plan: &BootstrapPlan,
    wrapped_registry_hash: [u8; 32],
) -> Result<ShadowSessionBinding, WalGenesisError> {
    ShadowSessionBinding::from_genesis_bootstrap(
        GenesisZeroWalBindingContext(()),
        *plan.archive_id().as_bytes(),
        *plan.database_epoch().as_bytes(),
        *plan.key_epoch().as_bytes(),
        *plan.registry_object_id().as_bytes(),
        wrapped_registry_hash,
        *plan.root_object_id().as_bytes(),
        *plan.attempt_id().as_bytes(),
        GENESIS_RESERVATION_REVISION,
    )
    .map_err(|_| WalGenesisError::Corrupt)
}

fn genesis_owner_id(attempt_id: BootstrapAttemptId) -> Result<ObjectId, WalGenesisError> {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_OWNER_DOMAIN);
    hasher.update(attempt_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    if bytes == [0; 16] {
        return Err(WalGenesisError::Corrupt);
    }
    Ok(ObjectId::from_bytes(bytes))
}

fn mint_bootstrap_plan(archive_id: ArchiveId) -> Result<BootstrapPlan, WalGenesisError> {
    let attempt_id = BootstrapAttemptId::from_bytes(random_nonzero_16()?)
        .map_err(|_| WalGenesisError::Corrupt)?;
    let registry_object_id = ObjectId::random();
    let root_object_id = ObjectId::random();
    BootstrapPlan::new(
        archive_id,
        attempt_id,
        DatabaseEpoch::from_bytes(random_nonzero_16()?),
        KeyEpoch::from_bytes(random_nonzero_16()?),
        registry_object_id,
        root_object_id,
    )
    .map_err(|_| WalGenesisError::Corrupt)
}

fn random_nonzero_16() -> Result<[u8; 16], WalGenesisError> {
    for _ in 0..4 {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        if bytes != [0; 16] {
            return Ok(bytes);
        }
    }
    Err(WalGenesisError::Corrupt)
}

/// Genesis-only sealing cipher over the freshly minted DEK, bound to exactly
/// one archive and key epoch. Every other production cipher comes from
/// `resolve_archive_cipher`, which unwraps an already-stored registry; a
/// genesis archive has no registry to unwrap yet.
struct GenesisSealCipher {
    archive_id: ArchiveId,
    key_epoch: KeyEpoch,
    cipher: ArchiveCipher,
}

impl GenesisSealCipher {
    fn validate_context(&self, context: &ObjectContext) -> crate::archive_v3::Result<()> {
        if context.archive_id() != self.archive_id || context.key_epoch() != self.key_epoch {
            return Err(ArchiveV3Error::InvalidContext);
        }
        Ok(())
    }
}

impl CheckpointCipher for GenesisSealCipher {
    fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    fn key_epoch(&self) -> KeyEpoch {
        self.key_epoch
    }

    fn seal(
        &self,
        context: &ObjectContext,
        plaintext: &[u8],
    ) -> crate::archive_v3::Result<CiphertextEnvelope> {
        self.validate_context(context)?;
        self.cipher.seal(context, plaintext)
    }

    fn open(
        &self,
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
    ) -> crate::archive_v3::Result<Vec<u8>> {
        self.validate_context(context)?;
        self.cipher.open(context, envelope)
    }
}

/// Materialize the temporary empty schema-current database in the private
/// scratch directory, measure it, load its exact bytes, and remove the file
/// family before returning. The bytes never outlive the returned source and
/// the on-disk copy never outlives this function.
async fn materialize_genesis_source(
    scratch_dir: &Path,
) -> Result<GenesisCheckpointSource, WalGenesisError> {
    let scratch_dir = scratch_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let path = fresh_genesis_store_path(&scratch_dir)?;
        let result = (|| {
            let facts =
                initialize_genesis_store(&path).map_err(|_| WalGenesisError::Unavailable)?;
            let bytes = std::fs::read(&path).map_err(|_| WalGenesisError::Unavailable)?;
            GenesisCheckpointSource::from_measured(facts, Zeroizing::new(bytes))
        })();
        remove_sqlite_family(&path);
        result
    })
    .await
    .map_err(|_| WalGenesisError::Unavailable)?
}

fn fresh_genesis_store_path(scratch_dir: &Path) -> Result<PathBuf, WalGenesisError> {
    if !scratch_dir.is_dir() {
        return Err(WalGenesisError::Unavailable);
    }
    for _ in 0..16 {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let mut suffix = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(&mut suffix, "{byte:02x}");
        }
        let path = scratch_dir.join(format!(".kioku-v3-genesis-{suffix}.db"));
        if !path.exists()
            && !sqlite_sidecar_path(&path, "-wal").exists()
            && !sqlite_sidecar_path(&path, "-shm").exists()
        {
            return Ok(path);
        }
    }
    Err(WalGenesisError::Unavailable)
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn remove_sqlite_family(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(sqlite_sidecar_path(path, "-wal"));
    let _ = std::fs::remove_file(sqlite_sidecar_path(path, "-shm"));
}

/// Cleanup-owning in-memory genesis checkpoint source. It re-verifies the
/// published facts against the exact loaded bytes, so the owned upload can
/// never publish facts that disagree with what the WAL owner will later
/// authenticate on open.
struct GenesisCheckpointSource {
    facts: GenesisStoreFacts,
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for GenesisCheckpointSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenesisCheckpointSource(<opaque>)")
    }
}

impl GenesisCheckpointSource {
    fn from_measured(
        facts: GenesisStoreFacts,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, WalGenesisError> {
        let length = u64::try_from(bytes.len()).map_err(|_| WalGenesisError::Corrupt)?;
        if length == 0
            || length != facts.logical_file_length
            || length > MAX_GENESIS_DATABASE_BYTES
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != facts.plaintext_sha256
        {
            return Err(WalGenesisError::Corrupt);
        }
        Ok(Self { facts, bytes })
    }
}

#[async_trait]
impl OwnedCheckpointSource for GenesisCheckpointSource {
    fn authenticated_facts(&self) -> CheckpointResult<(u64, [u8; 32], u32)> {
        Ok((
            self.facts.logical_file_length,
            self.facts.plaintext_sha256,
            self.facts.user_version,
        ))
    }

    async fn read_exact_owned(
        &self,
        logical_offset: u64,
        length: usize,
    ) -> CheckpointResult<Zeroizing<Vec<u8>>> {
        let start = usize::try_from(logical_offset).map_err(|_| ShadowCheckpointError::Source)?;
        let end = start
            .checked_add(length)
            .ok_or(ShadowCheckpointError::Source)?;
        if length == 0 || end > self.bytes.len() {
            return Err(ShadowCheckpointError::Source);
        }
        Ok(Zeroizing::new(self.bytes[start..end].to_vec()))
    }
}

/// Bounded, zeroizing in-memory recovery sink for the genesis-sized
/// checkpoint. Recovery of anything larger than a genesis database fails
/// closed before unbounded memory is committed.
struct BoundedMemorySink {
    bytes: Zeroizing<Vec<u8>>,
    capacity: u64,
    committed: bool,
    aborted: bool,
}

impl BoundedMemorySink {
    fn new(capacity: u64) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            capacity,
            committed: false,
            aborted: false,
        }
    }
}

impl CheckpointSink for BoundedMemorySink {
    fn write_exact(&mut self, logical_offset: u64, bytes: &[u8]) -> CheckpointResult<()> {
        if self.aborted || self.committed || bytes.is_empty() {
            return Err(ShadowCheckpointError::Sink);
        }
        let end = logical_offset
            .checked_add(bytes.len() as u64)
            .ok_or(ShadowCheckpointError::Sink)?;
        if end > self.capacity {
            return Err(ShadowCheckpointError::Sink);
        }
        let start = usize::try_from(logical_offset).map_err(|_| ShadowCheckpointError::Sink)?;
        let end = usize::try_from(end).map_err(|_| ShadowCheckpointError::Sink)?;
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
        }
        self.bytes[start..end].copy_from_slice(bytes);
        Ok(())
    }

    fn commit(&mut self, logical_file_length: u64) -> CheckpointResult<()> {
        if self.aborted
            || self.committed
            || u64::try_from(self.bytes.len()).ok() != Some(logical_file_length)
        {
            return Err(ShadowCheckpointError::Sink);
        }
        self.committed = true;
        Ok(())
    }

    fn abort(&mut self) {
        self.aborted = true;
        self.bytes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{CreateIfAbsent, InMemoryImmutableBackend},
        archive_v3_firestore_shadow::FirestoreShadowWitness,
        archive_v3_firestore_witness::{test_transport, FirestoreWitness},
        archive_v3_genesis_backend::{ControlPlaneGenesisBackend, GenesisRegistryStore},
        archive_v3_operation::{RecordOutcome, ShadowObjectFacts, ShadowObjectInventoryPage},
        archive_v3_witness::{ExactRootProvider, RootAdvance, WitnessLease},
        cp::control_store::GenesisStagingInventory,
        store::tests::{FakeGcs, FakeKms},
    };
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };

    const FAKE_WRAP_PREFIX: &[u8] = b"fake-kms-wrap:";

    /// Round-tripping registry provider: wrap prefixes the plaintext,
    /// unwrap strips it, and the wrapped object store is an exact-bytes CAS,
    /// mirroring the production create-if-absent semantics.
    #[derive(Default)]
    struct RoundTripRegistryStore {
        objects: Mutex<BTreeMap<ObjectId, Vec<u8>>>,
    }

    #[async_trait]
    impl crate::archive_v3::ExactKeyRegistryProvider for RoundTripRegistryStore {
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
                .strip_prefix(FAKE_WRAP_PREFIX)
                .ok_or(ArchiveV3Error::InvalidContext)?;
            if plaintext.len() > destination.len() {
                return Err(ArchiveV3Error::TooLarge("key registry plaintext"));
            }
            destination[..plaintext.len()].copy_from_slice(plaintext);
            Ok(plaintext.len())
        }
    }

    #[async_trait]
    impl GenesisRegistryStore for RoundTripRegistryStore {
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

    #[async_trait]
    impl GenesisRegistryWrapAuthority for RoundTripRegistryStore {
        async fn wrap_registry(
            &self,
            _context: &KeyRegistryContext,
            registry_plaintext: &[u8],
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            let length = FAKE_WRAP_PREFIX.len() + registry_plaintext.len();
            if length > destination.len() {
                return Err(ArchiveV3Error::TooLarge("wrapped key registry"));
            }
            destination[..FAKE_WRAP_PREFIX.len()].copy_from_slice(FAKE_WRAP_PREFIX);
            destination[FAKE_WRAP_PREFIX.len()..length].copy_from_slice(registry_plaintext);
            Ok(length)
        }
    }

    /// Exact-root reads over the same in-memory immutable object store the
    /// composite writes through, mirroring the G4 test provider.
    struct InMemoryRootProvider(Arc<InMemoryImmutableBackend>);

    #[async_trait]
    impl ExactRootProvider for InMemoryRootProvider {
        async fn read_exact(
            &self,
            context: &ObjectContext,
        ) -> Result<CiphertextEnvelope, WitnessError> {
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

    /// Accepting in-memory staging inventory that records every reserved
    /// fact, in the style of the extent module's contract-test inventories.
    #[derive(Default)]
    struct RecordingInventory {
        reserved: Mutex<Vec<(ShadowAttemptId, ShadowObjectFacts)>>,
    }

    impl RecordingInventory {
        fn reserved_count(&self) -> usize {
            self.reserved.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl ShadowObjectInventory for RecordingInventory {
        async fn reserve_exact(
            &self,
            _session_id: ShadowSessionId,
            attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            facts: ShadowObjectFacts,
        ) -> Result<RecordOutcome, ShadowObjectInventoryError> {
            self.reserved.lock().unwrap().push((attempt_id, facts));
            Ok(RecordOutcome::Recorded)
        }

        async fn mark_materialized_exact(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _facts: ShadowObjectFacts,
        ) -> Result<RecordOutcome, ShadowObjectInventoryError> {
            Ok(RecordOutcome::Recorded)
        }

        async fn load_exact_attempt_page(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _after_ordinal: Option<u32>,
        ) -> Result<ShadowObjectInventoryPage, ShadowObjectInventoryError> {
            // The genesis driver never reconciles a prior attempt's staged
            // objects; fail closed if anything tries.
            Err(ShadowObjectInventoryError::Unavailable)
        }
    }

    /// Counting wrapper over the in-memory immutable backend, so tests can
    /// prove "no third root" and "orphaned, not adopted" from create calls.
    struct CountingBackend {
        inner: Arc<InMemoryImmutableBackend>,
        root_creates: AtomicUsize,
        chunk_creates: AtomicUsize,
    }

    impl CountingBackend {
        fn new(inner: Arc<InMemoryImmutableBackend>) -> Self {
            Self {
                inner,
                root_creates: AtomicUsize::new(0),
                chunk_creates: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl ImmutableObjectBackend for CountingBackend {
        async fn create_if_absent(
            &self,
            key: crate::archive_v3::ObjectKey,
            value: CiphertextEnvelope,
        ) -> crate::archive_v3::Result<CreateIfAbsent> {
            if key.as_str().contains("/root-candidates/") {
                self.root_creates.fetch_add(1, Ordering::Relaxed);
            }
            if key.as_str().contains("/chunks/") {
                self.chunk_creates.fetch_add(1, Ordering::Relaxed);
            }
            self.inner.create_if_absent(key, value).await
        }

        async fn get(
            &self,
            key: &crate::archive_v3::ObjectKey,
        ) -> crate::archive_v3::Result<Option<CiphertextEnvelope>> {
            self.inner.get(key).await
        }

        async fn enumerate(
            &self,
            prefix: &crate::archive_v3::ArchivePrefix,
            cursor: Option<&crate::archive_v3::EnumerationCursor>,
            limit: crate::archive_v3::EnumerationLimit,
        ) -> crate::archive_v3::Result<crate::archive_v3::EnumerationPage> {
            self.inner.enumerate(prefix, cursor, limit).await
        }

        async fn delete_exact(
            &self,
            key: &crate::archive_v3::ObjectKey,
        ) -> crate::archive_v3::Result<bool> {
            self.inner.delete_exact(key).await
        }
    }

    struct Harness {
        control: Arc<ControlStore>,
        backend: ControlPlaneGenesisBackend,
        objects: Arc<CountingBackend>,
        registries: Arc<RoundTripRegistryStore>,
        inventory: RecordingInventory,
        witness_advance: FirestoreShadowWitness,
        firestore_witness: Arc<FirestoreWitness>,
        archive_id: ArchiveId,
        scratch: tempfile::TempDir,
    }

    impl Harness {
        async fn new() -> Self {
            let control = Arc::new(ControlStore::new(
                Arc::new(FakeKms),
                Arc::new(FakeGcs::new()),
            ));
            let binding = control
                .create_genesis_test_binding("11111111-1111-4111-8111-111111111111")
                .await
                .unwrap();
            let archive_id = binding.archive_id();
            let transport = Arc::new(test_transport::FakeTransport::new(None, []));
            let firestore_witness = Arc::new(test_transport::witness_over_fake(transport));
            let inner_objects = Arc::new(InMemoryImmutableBackend::new());
            let objects = Arc::new(CountingBackend::new(Arc::clone(&inner_objects)));
            let registries = Arc::new(RoundTripRegistryStore::default());
            let backend = ControlPlaneGenesisBackend::new(
                GenesisBackendRuntimeContext::for_test(),
                Arc::clone(&control),
                Arc::clone(&objects) as Arc<dyn ImmutableObjectBackend>,
                Arc::new(InMemoryRootProvider(inner_objects)),
                Arc::clone(&registries) as Arc<dyn GenesisRegistryStore>,
                Arc::clone(&firestore_witness),
            );
            let witness_advance =
                FirestoreShadowWitness::from_witness_for_test(Arc::clone(&firestore_witness));
            Self {
                control,
                backend,
                objects,
                registries,
                inventory: RecordingInventory::default(),
                witness_advance,
                firestore_witness,
                archive_id,
                scratch: tempfile::tempdir().unwrap(),
            }
        }

        fn authority(&self) -> WalGenesisAuthority<'_> {
            WalGenesisAuthority {
                recovery: self.control.as_ref(),
                backend: &self.backend,
                objects: self.objects.as_ref(),
                registry_wrap: self.registries.as_ref(),
                inventory: &self.inventory,
                witness_advance: &self.witness_advance,
            }
        }

        /// The same authority over a caller-supplied inventory, so a test can
        /// substitute the production binding-ENFORCING
        /// [`GenesisStagingInventory`] for the binding-discarding
        /// `RecordingInventory`.
        fn authority_over<'a>(
            &'a self,
            inventory: &'a dyn ShadowObjectInventory,
        ) -> WalGenesisAuthority<'a> {
            WalGenesisAuthority {
                inventory,
                ..self.authority()
            }
        }

        /// A fresh production staging-inventory instance for one attempt. Fresh
        /// matters: the binding latch is process-local, so a new instance is
        /// exactly what a restarted driver builds.
        fn staging_inventory(&self, attempt_id: BootstrapAttemptId) -> GenesisStagingInventory {
            GenesisStagingInventory::new(Arc::clone(&self.control), self.archive_id, attempt_id)
        }

        fn scratch_dir(&self) -> &Path {
            self.scratch.path()
        }

        fn scratch_is_empty(&self) -> bool {
            std::fs::read_dir(self.scratch.path()).unwrap().count() == 0
        }
    }

    /// Delegating witness-advance provider that serves ONE captured stale
    /// read — the exact race the adversarial review proved: a rung reads a
    /// mid-ladder record while the ladder completes, then acquires onto the
    /// released terminal.
    struct StaleFirstRead<'a> {
        inner: &'a FirestoreShadowWitness,
        stale: Mutex<Option<WitnessRecord>>,
    }

    #[async_trait]
    impl ArchiveWitnessAdvanceProvider for StaleFirstRead<'_> {
        async fn read_current_exact(
            &self,
            archive_id: ArchiveId,
        ) -> Result<WitnessRecord, WitnessError> {
            if let Some(stale) = self.stale.lock().unwrap().take() {
                return Ok(stale);
            }
            self.inner.read_current_exact(archive_id).await
        }

        async fn acquire_lease_exact(
            &self,
            record: &WitnessRecord,
            owner: ObjectId,
            duration_ticks: u64,
        ) -> Result<WitnessLease, WitnessError> {
            self.inner
                .acquire_lease_exact(record, owner, duration_ticks)
                .await
        }

        async fn validate_exact_lease(
            &self,
            record: &WitnessRecord,
            owner: ObjectId,
        ) -> Result<WitnessLease, WitnessError> {
            self.inner.validate_exact_lease(record, owner).await
        }

        async fn renew_lease_exact(
            &self,
            lease: WitnessLease,
            duration_ticks: u64,
        ) -> Result<WitnessLease, WitnessError> {
            self.inner.renew_lease_exact(lease, duration_ticks).await
        }

        async fn release_terminal_lease_unresolved(
            &self,
            retained: WitnessRecord,
            owner: ObjectId,
        ) -> Result<(), WitnessAdvanceCommitError> {
            self.inner
                .release_terminal_lease_unresolved(retained, owner)
                .await
        }

        async fn release_advisory_lease_unresolved(
            &self,
            retained: WitnessRecord,
            owner: ObjectId,
        ) -> Result<(), WitnessAdvanceCommitError> {
            self.inner
                .release_advisory_lease_unresolved(retained, owner)
                .await
        }

        async fn advance_migration_unresolved(
            &self,
            expected: WitnessRecord,
            candidate: WitnessRecord,
            advance: RootAdvance,
            next: MigrationState,
        ) -> Result<(), WitnessAdvanceCommitError> {
            self.inner
                .advance_migration_unresolved(expected, candidate, advance, next)
                .await
        }
    }

    /// The review's surviving race, closed: a rung whose read was stale
    /// (mid-ladder ShadowWal) while the store already holds the released
    /// terminal acquires the terminal's lease, Conflicts on revalidation —
    /// and must RELEASE that lease before returning, or serving acquisition
    /// is blocked for the full 86,400-tick lease term.
    #[tokio::test]
    async fn a_stale_read_rung_onto_the_released_terminal_releases_its_lease() {
        let harness = Harness::new().await;
        let authority = harness.authority();
        let reservation = reserve_genesis_bootstrap(&authority, harness.archive_id)
            .await
            .unwrap();
        let produced = produce_genesis_bytes(&authority, harness.scratch_dir(), reservation)
            .await
            .unwrap();
        let prepared = prepare_genesis_bootstrap(&authority, produced)
            .await
            .unwrap();
        let plan = prepared.reservation().plan();
        let wrapped_registry_hash = prepared.wrapped_registry_hash();
        let (_, _) = resolve_genesis(&authority, prepared).await.unwrap();
        let shadow = advance_genesis_ladder_once(&authority, plan, wrapped_registry_hash)
            .await
            .unwrap();
        assert_eq!(shadow.migration(), MigrationState::ShadowWal);
        // The ladder completes (advance 2 + terminal release). The contract
        // helper is NOT called here — it acquires a WAL-owner lease it never
        // releases, which would block the raced acquire below.
        let outcome = run_wal_genesis(&authority, harness.scratch_dir(), harness.archive_id)
            .await
            .unwrap();
        assert_eq!(
            outcome.terminal_witness.migration(),
            MigrationState::WalAuthoritative
        );
        // A racing rung then runs against the CAPTURED stale ShadowWal
        // record.
        let stale_provider = StaleFirstRead {
            inner: &harness.witness_advance,
            stale: Mutex::new(Some(shadow)),
        };
        let racing = WalGenesisAuthority {
            recovery: harness.control.as_ref(),
            backend: &harness.backend,
            objects: harness.objects.as_ref(),
            registry_wrap: harness.registries.as_ref(),
            inventory: &harness.inventory,
            witness_advance: &stale_provider,
        };
        let raced = advance_genesis_ladder_once(&racing, plan, wrapped_registry_hash).await;
        assert!(matches!(raced, Err(WalGenesisError::Conflict)));
        // The terminal must still satisfy the WAL-owner acquire contract:
        // the racing rung released its own planted lease.
        let terminal = harness
            .witness_advance
            .read_current_exact(harness.archive_id)
            .await
            .unwrap();
        assert_terminal_contract(&harness, &terminal).await;
    }

    /// Prove the terminal witness satisfies the untouched WAL-owner acquire
    /// predicate: the provider acquire commits only through
    /// `exact_wal_owner_acquire_from`-shaped state, and the successor is
    /// revalidated against the terminal with that exact predicate.
    async fn assert_terminal_contract(harness: &Harness, terminal: &WitnessRecord) {
        assert_eq!(terminal.migration(), MigrationState::WalAuthoritative);
        assert_eq!(terminal.deletion(), DeletionState::Active);
        assert_eq!(terminal.root().root().sequence(), 2);
        let wal_owner = ObjectId::from_bytes([0x77; 16]);
        let Ok((successor, lease)) = harness
            .firestore_witness
            .acquire_exact_wal_owner_lease_unresolved_async(terminal.clone(), wal_owner, 600)
            .await
        else {
            panic!("terminal witness must admit the WAL-owner acquire");
        };
        let validated = successor
            .exact_wal_owner_acquire_from(terminal, wal_owner.as_bytes())
            .expect("successor must satisfy exact_wal_owner_acquire_from");
        assert_eq!(validated, lease);
    }

    /// (1) Full happy path: a fresh archive resolves Created, the ladder
    /// ends at the released terminal contract, and the scratch directory is
    /// left empty.
    #[tokio::test]
    async fn full_genesis_run_ends_at_terminal_wal_owner_contract() {
        let harness = Harness::new().await;
        let outcome = run_wal_genesis(
            &harness.authority(),
            harness.scratch_dir(),
            harness.archive_id,
        )
        .await
        .unwrap();
        assert_eq!(outcome.resolution, GenesisResolution::Created);
        assert_terminal_contract(&harness, &outcome.terminal_witness).await;
        // Exactly three root objects: genesis root 0 created by resolve plus
        // the ladder's two zero-WAL roots.
        assert_eq!(harness.objects.root_creates.load(Ordering::Relaxed), 3);
        assert!(harness.objects.chunk_creates.load(Ordering::Relaxed) >= 1);
        assert!(harness.scratch_is_empty());
    }

    /// (2) Crash before prepare: the checkpoint upload is durable in the
    /// object store but nothing was prepared. The retry reuses the durably
    /// reserved plan, mints a fresh DEK and a fresh checkpoint (the crashed
    /// attempt's objects stay orphaned, not adopted), and completes a fresh
    /// archive whose prepared bytes differ from the crashed attempt's.
    #[tokio::test]
    async fn crash_before_prepare_retries_with_fresh_bytes_and_orphans_old_objects() {
        let harness = Harness::new().await;
        let authority = harness.authority();
        let reservation = reserve_genesis_bootstrap(&authority, harness.archive_id)
            .await
            .unwrap();
        let produced = produce_genesis_bytes(&authority, harness.scratch_dir(), reservation)
            .await
            .unwrap();
        let first_attempt_root_hash = produced.root_envelope_hash();
        let chunks_before = harness.objects.chunk_creates.load(Ordering::Relaxed);
        let inventory_before = harness.inventory.reserved_count();
        drop(produced); // crash: the produced bytes are lost before prepare

        let outcome = run_wal_genesis(&authority, harness.scratch_dir(), harness.archive_id)
            .await
            .unwrap();
        assert_eq!(outcome.resolution, GenesisResolution::Created);
        assert_terminal_contract(&harness, &outcome.terminal_witness).await;
        // The durably prepared bytes are the retry's fresh bytes, not the
        // crashed attempt's.
        let recovered = harness
            .control
            .recover_archive_bootstrap(harness.archive_id)
            .await
            .unwrap();
        let prepared = recovered.prepared().expect("prepared after retry");
        assert_ne!(prepared.root_envelope_hash(), first_attempt_root_hash);
        // A second complete checkpoint was uploaded and the first attempt's
        // reserved objects remain in the inventory as orphans.
        assert!(harness.objects.chunk_creates.load(Ordering::Relaxed) > chunks_before);
        assert!(harness.inventory.reserved_count() > inventory_before);
    }

    /// (3) Crash after prepare: the retry recovers a `Prepared` anchor and
    /// resumes from the stored bytes without producing any of its own, so the
    /// resolved archive is byte-exact the crashed attempt's — same wrapped
    /// registry, same root envelope — with no second DEK and no second
    /// checkpoint upload to orphan.
    #[tokio::test]
    async fn crash_after_prepare_replays_byte_exact_to_the_same_archive() {
        let harness = Harness::new().await;
        let authority = harness.authority();
        let reservation = reserve_genesis_bootstrap(&authority, harness.archive_id)
            .await
            .unwrap();
        let produced = produce_genesis_bytes(&authority, harness.scratch_dir(), reservation)
            .await
            .unwrap();
        let prepared = prepare_genesis_bootstrap(&authority, produced)
            .await
            .unwrap();
        let stored_registry_hash = prepared.wrapped_registry_hash();
        let stored_root_hash = prepared.root_envelope_hash();
        let chunks_before = harness.objects.chunk_creates.load(Ordering::Relaxed);
        drop(prepared); // crash: after the durable prepare, before resolve

        let outcome = run_wal_genesis(&authority, harness.scratch_dir(), harness.archive_id)
            .await
            .unwrap();
        // The witness did not exist before the crash, so the byte-exact
        // replay still creates it.
        assert_eq!(outcome.resolution, GenesisResolution::Created);
        assert_terminal_contract(&harness, &outcome.terminal_witness).await;
        // Byte-exact: the archive's registry is the crashed attempt's exact
        // wrapped bytes, and the durable prepared payloads are unchanged.
        assert_eq!(
            outcome.terminal_witness.registry().ciphertext_hash(),
            stored_registry_hash
        );
        let recovered = harness
            .control
            .recover_archive_bootstrap(harness.archive_id)
            .await
            .unwrap();
        let replayed = recovered.prepared().expect("prepared state persists");
        assert_eq!(replayed.wrapped_registry_hash(), stored_registry_hash);
        assert_eq!(replayed.root_envelope_hash(), stored_root_hash);
        assert_eq!(
            harness.objects.chunk_creates.load(Ordering::Relaxed),
            chunks_before,
            "a post-boundary retry must not upload a second checkpoint"
        );
    }

    /// G9-1 regression. The witness ladder derives its staging binding from
    /// the DURABLY PREPARED wrapped-registry hash, while byte production
    /// derives its own from the hash of the registry it just wrapped under a
    /// freshly minted DEK. A post-boundary pass that produced anyway would
    /// therefore latch its staging inventory to a binding the ladder can never
    /// present, and the ladder would refuse — permanently, on every later
    /// pass, at exactly the crash points (C3-C6) the trigger's module doc
    /// claims converge.
    ///
    /// The pre-existing convergence tests above cannot observe this: their
    /// `RecordingInventory` takes `_binding` and throws it away. This one
    /// drives the production [`GenesisStagingInventory`], which enforces the
    /// binding, and gives the resumed pass a FRESH instance because the latch
    /// is process-local — which is precisely what a restarted driver builds.
    #[tokio::test]
    async fn a_post_boundary_resume_converges_under_a_binding_enforcing_inventory() {
        let harness = Harness::new().await;
        // Attempt 1, staged end-to-end through the binding-enforcing
        // production inventory and killed right after the durable prepare.
        let reservation = {
            let authority = harness.authority();
            reserve_genesis_bootstrap(&authority, harness.archive_id)
                .await
                .unwrap()
        };
        let attempt_id = reservation.plan().attempt_id();
        let (stored_registry_hash, stored_root_hash) = {
            let crashed = harness.staging_inventory(attempt_id);
            let authority = harness.authority_over(&crashed);
            let produced = produce_genesis_bytes(&authority, harness.scratch_dir(), reservation)
                .await
                .unwrap();
            let prepared = prepare_genesis_bootstrap(&authority, produced)
                .await
                .unwrap();
            (
                prepared.wrapped_registry_hash(),
                prepared.root_envelope_hash(),
            )
        };
        // ...crash. The producer's latch dies with the process; the durable
        // staging rows and the prepared anchor do not.
        let chunks_after_crash = harness.objects.chunk_creates.load(Ordering::Relaxed);
        assert!(chunks_after_crash > 0, "attempt 1 uploaded a checkpoint");

        // The decision under test: a durably prepared anchor resumes.
        let start = {
            let authority = harness.authority();
            start_genesis_bootstrap(&authority, harness.archive_id)
                .await
                .unwrap()
        };
        let GenesisBootstrapStart::Resume(recovered) = start else {
            panic!("a durably prepared anchor must resume, never re-produce");
        };
        assert_eq!(recovered.wrapped_registry_hash(), stored_registry_hash);
        assert_eq!(recovered.root_envelope_hash(), stored_root_hash);
        assert_eq!(recovered.reservation().plan().attempt_id(), attempt_id);
        drop(recovered);

        // The resumed pass, under a fresh binding-enforcing instance. Before
        // the fix this failed with `ShadowObjectInventoryError::Conflict` from
        // the ladder's first staged root object, and did so on every rerun.
        let resumed = harness.staging_inventory(attempt_id);
        let authority = harness.authority_over(&resumed);
        let outcome = run_wal_genesis(&authority, harness.scratch_dir(), harness.archive_id)
            .await
            .expect(
                "a post-boundary resume must converge; a failure here is the G9-1 wedge \
                 (the staging latch refuses the ladder's binding, and \
                 build_zero_wal_candidate reports it as Unavailable)",
            );
        assert_eq!(outcome.resolution, GenesisResolution::Created);
        assert_eq!(
            outcome.terminal_witness.registry().ciphertext_hash(),
            stored_registry_hash,
            "the resumed archive must carry the crashed attempt's exact registry"
        );
        // G9-2: the resumed pass minted no DEK and uploaded no checkpoint.
        assert_eq!(
            harness.objects.chunk_creates.load(Ordering::Relaxed),
            chunks_after_crash,
            "a post-boundary resume must not upload a second checkpoint"
        );
        // And a further pass over the terminal archive is likewise free.
        let roots_after_ladder = harness.objects.root_creates.load(Ordering::Relaxed);
        let again = run_wal_genesis(&authority, harness.scratch_dir(), harness.archive_id)
            .await
            .unwrap();
        assert_eq!(again.terminal_witness, outcome.terminal_witness);
        assert_eq!(
            harness.objects.chunk_creates.load(Ordering::Relaxed),
            chunks_after_crash
        );
        assert_eq!(
            harness.objects.root_creates.load(Ordering::Relaxed),
            roots_after_ladder
        );
        assert!(harness.scratch_is_empty());
        // Acquires a WAL-owner lease it never releases, so it goes last.
        assert_terminal_contract(&harness, &outcome.terminal_witness).await;
    }

    /// (4) Restart between the two advances: after Legacy → ShadowWal, a
    /// full rerun converges — genesis resolves Existing, the ladder resumes
    /// at the second advance over the same checkpoint, and the terminal sits
    /// at root sequence 2 (not 3).
    #[tokio::test]
    async fn restart_between_advances_resumes_at_second_advance_over_same_checkpoint() {
        let harness = Harness::new().await;
        let authority = harness.authority();
        let reservation = reserve_genesis_bootstrap(&authority, harness.archive_id)
            .await
            .unwrap();
        let produced = produce_genesis_bytes(&authority, harness.scratch_dir(), reservation)
            .await
            .unwrap();
        let prepared = prepare_genesis_bootstrap(&authority, produced)
            .await
            .unwrap();
        let plan = prepared.reservation().plan();
        let wrapped_registry_hash = prepared.wrapped_registry_hash();
        let (resolution, genesis_record) = resolve_genesis(&authority, prepared).await.unwrap();
        assert_eq!(resolution, GenesisResolution::Created);
        assert_eq!(genesis_record.migration(), MigrationState::Legacy);
        let shadow = advance_genesis_ladder_once(&authority, plan, wrapped_registry_hash)
            .await
            .unwrap();
        assert_eq!(shadow.migration(), MigrationState::ShadowWal);
        assert_eq!(shadow.root().root().sequence(), 1);
        // Restart: the full driver reruns from the top.
        let outcome = run_wal_genesis(&authority, harness.scratch_dir(), harness.archive_id)
            .await
            .unwrap();
        assert_eq!(outcome.resolution, GenesisResolution::Existing);
        assert_terminal_contract(&harness, &outcome.terminal_witness).await;
        // Same checkpoint at every rung: recover the checkpoint nominated by
        // the genesis root and by the terminal root and compare the exact
        // manifest-root reference and plaintext hash.
        let cipher = resolve_ladder_cipher(&authority, &outcome.terminal_witness)
            .await
            .unwrap();
        let genesis_checkpoint = recover_genesis_checkpoint(&authority, &cipher, &genesis_record)
            .await
            .unwrap();
        let terminal_recovery =
            RecoveryRoot::from_exact_wal_authoritative_record(&outcome.terminal_witness).unwrap();
        let mut sink = BoundedMemorySink::new(MAX_GENESIS_DATABASE_BYTES);
        let terminal_checkpoint = recover_checkpoint_from_recovery_root(
            &terminal_recovery,
            authority.objects,
            &cipher,
            harness.archive_id,
            &mut sink,
        )
        .await
        .unwrap();
        assert_eq!(terminal_checkpoint.root(), genesis_checkpoint.root());
        assert_eq!(
            terminal_checkpoint.database_plaintext_hash(),
            genesis_checkpoint.database_plaintext_hash()
        );
    }

    /// (5) Rerunning the completed ladder is a no-op: it converges to the
    /// byte-identical terminal and publishes no third root; a full driver
    /// rerun likewise resolves Existing with the same terminal.
    #[tokio::test]
    async fn rerunning_completed_ladder_is_a_no_op_with_no_third_root() {
        let harness = Harness::new().await;
        let authority = harness.authority();
        let outcome = run_wal_genesis(&authority, harness.scratch_dir(), harness.archive_id)
            .await
            .unwrap();
        let recovered = harness
            .control
            .recover_archive_bootstrap(harness.archive_id)
            .await
            .unwrap();
        let prepared = recovered.prepared().expect("prepared after completion");
        let plan = recovered.reservation().plan();
        let wrapped_registry_hash = prepared.wrapped_registry_hash();
        let roots_before = harness.objects.root_creates.load(Ordering::Relaxed);
        let terminal_again = run_witness_ladder(&authority, plan, wrapped_registry_hash)
            .await
            .unwrap();
        assert_eq!(terminal_again, outcome.terminal_witness);
        assert_eq!(
            harness.objects.root_creates.load(Ordering::Relaxed),
            roots_before,
            "a completed ladder must not publish a third root"
        );
        let rerun = run_wal_genesis(&authority, harness.scratch_dir(), harness.archive_id)
            .await
            .unwrap();
        assert_eq!(rerun.resolution, GenesisResolution::Existing);
        assert_eq!(rerun.terminal_witness, outcome.terminal_witness);
        assert_eq!(
            harness.objects.root_creates.load(Ordering::Relaxed),
            roots_before
        );
        assert_terminal_contract(&harness, &rerun.terminal_witness).await;
    }

    #[tokio::test]
    async fn genesis_checkpoint_source_serves_only_exact_measured_bytes() {
        let facts = GenesisStoreFacts {
            logical_file_length: 4,
            plaintext_sha256: Sha256::digest([1u8, 2, 3, 4]).into(),
            user_version: 7,
        };
        let source =
            GenesisCheckpointSource::from_measured(facts, Zeroizing::new(vec![1, 2, 3, 4]))
                .unwrap();
        assert_eq!(
            source.authenticated_facts().unwrap(),
            (4, facts.plaintext_sha256, 7)
        );
        assert_eq!(&*source.read_exact_owned(1, 2).await.unwrap(), &[2, 3]);
        assert!(source.read_exact_owned(3, 2).await.is_err());
        assert!(source.read_exact_owned(0, 0).await.is_err());
        let mismatched = GenesisStoreFacts {
            logical_file_length: 5,
            ..facts
        };
        assert_eq!(
            GenesisCheckpointSource::from_measured(mismatched, Zeroizing::new(vec![1, 2, 3, 4]))
                .unwrap_err(),
            WalGenesisError::Corrupt
        );
    }

    #[test]
    fn bounded_memory_sink_fails_closed_beyond_capacity_and_after_abort() {
        let mut sink = BoundedMemorySink::new(8);
        sink.write_exact(0, &[1, 2, 3, 4]).unwrap();
        assert!(sink.write_exact(6, &[9, 9, 9]).is_err());
        sink.write_exact(4, &[5, 6, 7, 8]).unwrap();
        assert!(sink.commit(7).is_err());
        sink.abort();
        assert!(sink.write_exact(0, &[1]).is_err());
        let mut committed = BoundedMemorySink::new(8);
        committed.write_exact(0, &[1, 2]).unwrap();
        committed.commit(2).unwrap();
        assert!(committed.write_exact(2, &[3]).is_err());
    }

    // ------------------------------------------------------------------
    // G8: genesis handoff → WAL-owner launch, over the same fakes.
    // ------------------------------------------------------------------

    /// The harness binding's fixed user, minted by `Harness::new`.
    const GENESIS_TEST_USER: &str = "11111111-1111-4111-8111-111111111111";

    /// Drive the genesis spine to its released terminal and record both
    /// control-ledger stages — the exact flow the G9 trigger will run.
    /// Returns `(terminal, created)`: the released `WalAuthoritative`
    /// terminal and the sequence-0 created record the ledger pinned first.
    async fn run_genesis_and_record_ledger(harness: &Harness) -> (WitnessRecord, WitnessRecord) {
        let authority = harness.authority();
        let reservation = reserve_genesis_bootstrap(&authority, harness.archive_id)
            .await
            .unwrap();
        let produced = produce_genesis_bytes(&authority, harness.scratch_dir(), reservation)
            .await
            .unwrap();
        let prepared = prepare_genesis_bootstrap(&authority, produced)
            .await
            .unwrap();
        let plan = prepared.reservation().plan();
        let wrapped_registry_hash = prepared.wrapped_registry_hash();
        let (resolution, created) = resolve_genesis(&authority, prepared).await.unwrap();
        assert_eq!(resolution, GenesisResolution::Created);
        harness
            .control
            .record_genesis_stage(
                GENESIS_TEST_USER,
                harness.archive_id,
                crate::cp::control_store::WalGenesisStage::GenesisCreated,
                created.encode(),
            )
            .await
            .unwrap();
        let terminal = run_witness_ladder(&authority, plan, wrapped_registry_hash)
            .await
            .unwrap();
        harness
            .control
            .record_genesis_stage(
                GENESIS_TEST_USER,
                harness.archive_id,
                crate::cp::control_store::WalGenesisStage::WalAuthoritative,
                terminal.encode(),
            )
            .await
            .unwrap();
        (terminal, created)
    }

    /// Publisher-capable runtime bundle over the harness's own providers,
    /// mirroring the production bundle shape the WAL-owner launch consumes.
    fn publisher_bundle(
        harness: &Harness,
    ) -> crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle {
        crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle::from_publisher_test_components(
            Arc::clone(&harness.objects) as Arc<dyn ImmutableObjectBackend>,
            Arc::clone(&harness.registries) as Arc<dyn crate::archive_v3::ExactKeyRegistryProvider>,
            Arc::new(FirestoreShadowWitness::from_witness_for_test(Arc::clone(
                &harness.firestore_witness,
            ))),
            Arc::new(FirestoreShadowWitness::from_witness_for_test(Arc::clone(
                &harness.firestore_witness,
            ))),
        )
    }

    /// One settled read through the launched serving authority: the owner
    /// re-reads and re-authenticates the live witness head before the lane
    /// answers from the recovered genesis database.
    async fn assert_owner_serves_settled_read(
        authority: &crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority,
    ) {
        let tables = authority
            .read(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| crate::error::EnclaveError::Store("settled read failed".into()))
            })
            .await
            .unwrap()
            .unwrap();
        assert!(
            tables > 0,
            "the recovered genesis database must be schema-current"
        );
    }

    /// (G8-a) A genesis-ledger handoff launches the real publisher over the
    /// same fake providers — durable reservation re-adoption, send marker,
    /// provider-CAS owner acquire, cipher resolution, checkpoint staging
    /// recovery — and the launched owner serves a settled read round-trip
    /// from the genesis database.
    #[tokio::test]
    async fn genesis_handoff_launches_wal_owner_and_serves_settled_reads() {
        let harness = Harness::new().await;
        let (terminal, _) = run_genesis_and_record_ledger(&harness).await;
        let reserved = harness
            .control
            .reserve_owner_from_genesis(&terminal)
            .await
            .unwrap();
        let binding = harness
            .control
            .active_archive_binding(GENESIS_TEST_USER)
            .await
            .unwrap();
        let handoff = crate::archive_v3_shadow_runtime::GenesisWalHandoff::from_reservation(
            publisher_bundle(&harness),
            crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding::from_control_store(
                binding,
            ),
            terminal.clone(),
            reserved,
            Arc::clone(&harness.control),
        )
        .unwrap();
        let authority = crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::launch(
            crate::archive_v3_shadow_runtime::WalServingHandoff::Genesis(handoff),
        )
        .await
        .unwrap();
        assert_owner_serves_settled_read(&authority).await;
        // The launch bound the durable reservation: a fresh adoption returns
        // the same owner rather than minting a competitor.
        harness
            .control
            .reserve_owner_from_genesis(&terminal)
            .await
            .unwrap();
    }

    /// (G8-b) Restart relaunch: with the genesis ledger at its durable
    /// terminal and the owner reserved by "process one", the startup
    /// selection scan admits the user and the sealed runtime reconstructs
    /// the genesis serving handoff from durable state alone — the exact
    /// serving-relaunch flow — and the relaunched owner serves settled
    /// reads.
    #[tokio::test]
    async fn genesis_relaunch_reconstructs_from_durable_ledger_and_serves() {
        let harness = Harness::new().await;
        let (terminal, _) = run_genesis_and_record_ledger(&harness).await;
        harness
            .control
            .reserve_owner_from_genesis(&terminal)
            .await
            .unwrap();
        let selections = harness
            .control
            .load_wal_authoritative_persistence_selections()
            .await
            .unwrap();
        assert_eq!(selections.len(), 1, "the genesis-ledger user is selected");
        let binding = harness
            .control
            .active_archive_binding(GENESIS_TEST_USER)
            .await
            .unwrap();
        let sealed =
            crate::archive_v3_shadow_runtime::SealedSingleArchiveWalRuntime::for_publisher_test(
                binding,
                Arc::clone(&harness.objects) as Arc<dyn ImmutableObjectBackend>,
                Arc::clone(&harness.registries)
                    as Arc<dyn crate::archive_v3::ExactKeyRegistryProvider>,
                Arc::new(FirestoreShadowWitness::from_witness_for_test(Arc::clone(
                    &harness.firestore_witness,
                ))),
                Arc::new(FirestoreShadowWitness::from_witness_for_test(Arc::clone(
                    &harness.firestore_witness,
                ))),
            );
        let handoff = sealed
            .reconstruct_wal_serving_handoff(Arc::clone(&harness.control))
            .await
            .unwrap();
        assert!(matches!(
            handoff,
            crate::archive_v3_shadow_runtime::WalServingHandoff::Genesis(_)
        ));
        let authority =
            crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::launch(handoff)
                .await
                .unwrap();
        assert_owner_serves_settled_read(&authority).await;
    }

    /// (G8-d) Guard: the genesis handoff constructor refuses any witness
    /// that is not the archive's released `WalAuthoritative` terminal —
    /// here the sequence-0 created record the ledger pinned at
    /// `genesis_created`.
    #[tokio::test]
    async fn genesis_handoff_refuses_a_non_terminal_witness() {
        let harness = Harness::new().await;
        let (terminal, created) = run_genesis_and_record_ledger(&harness).await;
        let reserved = harness
            .control
            .reserve_owner_from_genesis(&terminal)
            .await
            .unwrap();
        let binding = harness
            .control
            .active_archive_binding(GENESIS_TEST_USER)
            .await
            .unwrap();
        assert!(
            crate::archive_v3_shadow_runtime::GenesisWalHandoff::from_reservation(
                publisher_bundle(&harness),
                crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding::from_control_store(
                    binding,
                ),
                created,
                reserved,
                Arc::clone(&harness.control),
            )
            .is_err(),
            "a non-terminal witness must never compose a launchable handoff"
        );
    }
}
