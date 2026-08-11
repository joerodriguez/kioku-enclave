#![allow(
    dead_code,
    reason = "inactive ADR-0022 shadow publication is compiled and tested before any authority wiring"
)]

//! Inactive, fail-closed ADR-0022 shadow checkpoint publication coordinator.
//!
//! The coordinator is deliberately a composition seam, not runtime authority:
//! it uploads immutable checkpoint objects, seals and reads back one immutable
//! root candidate, and only then asks an injected async witness transaction to
//! compare-and-advance.  It never lists objects, truncates WAL, mutates the
//! legacy store, or deletes orphaned immutable objects after a failed attempt.
//! The owned task protects caller-future cancellation only while this runtime
//! remains alive. Before CAS, the exact candidate is persisted in a bounded
//! stable-session/attempt ledger; restart compares only that attempt with the
//! independent witness. No runtime constructs this seam yet.

use async_trait::async_trait;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    archive_v3::{
        ArchiveId, ArchiveRoot, ArchiveV3Error, CiphertextEnvelope, ImmutableObjectBackend,
        LogicalLocation, ObjectContext, ObjectId, ObjectRole, ParentReference,
        VerifiedArchiveCipher, ARCHIVE_FORMAT_VERSION, SQLITE_PAGE_SIZE,
    },
    archive_v3_operation::{
        OperationLedger, OperationLedgerError, OperationRecord, RecordOutcome, ShadowObjectFacts,
    },
    archive_v3_shadow_checkpoint::{
        upload_checkpoint, CheckpointSource, ShadowCheckpointError, ShadowObjectInventory,
        ShadowObjectInventoryError, ShadowObjectStaging, UploadedCheckpoint,
    },
    archive_v3_shadow_session::{
        ShadowAttemptId, ShadowCandidate, ShadowReconcileDecision, ShadowSessionBinding,
        ShadowSessionId, ShadowSessionRecord, ShadowSessionState,
    },
    archive_v3_witness::{
        ExactRootProvider, RootAdvance, RootReference, WitnessError, WitnessLease, WitnessReceipt,
        WitnessRecord,
    },
};

#[derive(Debug, Error)]
pub enum ShadowCoordinatorError {
    #[error(transparent)]
    Archive(#[from] ArchiveV3Error),
    #[error(transparent)]
    Checkpoint(#[from] ShadowCheckpointError),
    #[error("shadow witness rejected the candidate")]
    Witness(#[source] WitnessError),
    #[error("shadow witness outcome requires exact reconciliation")]
    ReconciliationRequired(Box<ShadowReconciliation>),
    #[error("shadow publication request is not fenced to the exact witness state")]
    StaleAuthority,
    #[error("durable shadow-session persistence failed closed")]
    SessionPersistence(#[source] ShadowSessionPersistenceError),
}

pub type Result<T> = std::result::Result<T, ShadowCoordinatorError>;

/// Opaque in-memory continuation for an exact post-send witness reread. This
/// is not durable local state and contains no database content.
#[derive(Clone, PartialEq, Eq)]
pub struct ShadowReconciliation {
    archive_id: ArchiveId,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    candidate: RootReference,
    expected: WitnessRecord,
    lease_fence: u64,
    binding: ShadowSessionBinding,
}
impl std::fmt::Debug for ShadowReconciliation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShadowReconciliation(<opaque>)")
    }
}

/// The outcome is unknown only after a request may have reached the witness.
/// Callers must reconcile that case through `read_current_exact`; retrying
/// a create-root operation would make a new candidate and is forbidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowWitnessCommitError {
    Rejected(WitnessError),
    Failed(WitnessError),
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ShadowSessionPersistenceError {
    #[error("durable shadow-session state is unavailable")]
    Unavailable,
    #[error("durable shadow-session state conflicts with the requested publication")]
    Conflict,
}

/// Durable, content-free session boundary. A runtime adapter must persist into
/// the encrypted archive ledger; this inactive coordinator has no concrete
/// Store, filesystem, or connection construction.
#[async_trait]
pub(crate) trait ShadowSessionPersistence: ShadowObjectInventory + Send + Sync {
    async fn load_exact(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
    ) -> std::result::Result<ShadowSessionRecord, ShadowSessionPersistenceError>;

    async fn persist_candidate(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        candidate: ShadowCandidate,
        root_facts: ShadowObjectFacts,
    ) -> std::result::Result<ShadowSessionRecord, ShadowSessionPersistenceError>;

    async fn require_reconciliation(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
    ) -> std::result::Result<(), ShadowSessionPersistenceError>;

    async fn mark_superseded(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
    ) -> std::result::Result<(), ShadowSessionPersistenceError>;

    async fn complete_witnessed(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        completion: OperationRecord,
    ) -> std::result::Result<RecordOutcome, ShadowSessionPersistenceError>;
}

/// Concrete but inactive adapter for the encrypted archive SQLite ledger.
/// Every SQLite call is moved to Tokio's blocking lane; this type does not open
/// a file, install a VFS, or construct production authority.
pub(crate) struct EncryptedSqliteShadowSessionPersistence {
    connection: Arc<Mutex<Connection>>,
}

impl EncryptedSqliteShadowSessionPersistence {
    pub(crate) fn new(connection: Arc<Mutex<Connection>>) -> Self {
        Self { connection }
    }

    async fn run_blocking<T, F>(
        &self,
        operation: F,
    ) -> std::result::Result<T, ShadowSessionPersistenceError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> std::result::Result<T, OperationLedgerError> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| ShadowSessionPersistenceError::Unavailable)?;
            operation(&mut connection).map_err(map_session_ledger_error)
        })
        .await
        .map_err(|_| ShadowSessionPersistenceError::Unavailable)?
    }
}

fn map_session_ledger_error(error: OperationLedgerError) -> ShadowSessionPersistenceError {
    match error {
        OperationLedgerError::FingerprintConflict
        | OperationLedgerError::ResultConflict
        | OperationLedgerError::ShadowSession(_) => ShadowSessionPersistenceError::Conflict,
        _ => ShadowSessionPersistenceError::Unavailable,
    }
}

fn map_inventory_ledger_error(error: OperationLedgerError) -> ShadowObjectInventoryError {
    match error {
        OperationLedgerError::FingerprintConflict
        | OperationLedgerError::ResultConflict
        | OperationLedgerError::ShadowSession(_)
        | OperationLedgerError::TooLarge(_) => ShadowObjectInventoryError::Conflict,
        _ => ShadowObjectInventoryError::Unavailable,
    }
}

#[async_trait]
impl ShadowObjectInventory for EncryptedSqliteShadowSessionPersistence {
    async fn reserve_exact(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        facts: ShadowObjectFacts,
    ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| ShadowObjectInventoryError::Unavailable)?;
            OperationLedger::reserve_shadow_object(
                &mut connection,
                session_id,
                attempt_id,
                binding,
                &facts,
            )
            .map_err(map_inventory_ledger_error)
        })
        .await
        .map_err(|_| ShadowObjectInventoryError::Unavailable)?
    }

    async fn mark_materialized_exact(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        facts: ShadowObjectFacts,
    ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| ShadowObjectInventoryError::Unavailable)?;
            OperationLedger::mark_shadow_object_materialized(
                &mut connection,
                session_id,
                attempt_id,
                binding,
                &facts,
            )
            .map_err(map_inventory_ledger_error)
        })
        .await
        .map_err(|_| ShadowObjectInventoryError::Unavailable)?
    }

    async fn load_exact_attempt_page(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        after_ordinal: Option<u32>,
    ) -> std::result::Result<
        crate::archive_v3_operation::ShadowObjectInventoryPage,
        ShadowObjectInventoryError,
    > {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let connection = connection
                .lock()
                .map_err(|_| ShadowObjectInventoryError::Unavailable)?;
            OperationLedger::load_exact_shadow_object_page(
                &connection,
                session_id,
                attempt_id,
                binding,
                after_ordinal,
            )
            .map_err(map_inventory_ledger_error)
        })
        .await
        .map_err(|_| ShadowObjectInventoryError::Unavailable)?
    }
}

#[async_trait]
impl ShadowSessionPersistence for EncryptedSqliteShadowSessionPersistence {
    async fn load_exact(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
    ) -> std::result::Result<ShadowSessionRecord, ShadowSessionPersistenceError> {
        self.run_blocking(move |connection| {
            OperationLedger::load_shadow_session(connection, session_id, attempt_id)?.ok_or(
                OperationLedgerError::ShadowSession(
                    crate::archive_v3_shadow_session::ShadowSessionError::BindingConflict,
                ),
            )
        })
        .await
    }

    async fn persist_candidate(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        candidate: ShadowCandidate,
        root_facts: ShadowObjectFacts,
    ) -> std::result::Result<ShadowSessionRecord, ShadowSessionPersistenceError> {
        self.run_blocking(move |connection| {
            OperationLedger::persist_shadow_candidate(
                connection,
                session_id,
                attempt_id,
                binding,
                candidate,
                &root_facts,
            )
        })
        .await
    }

    async fn require_reconciliation(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
    ) -> std::result::Result<(), ShadowSessionPersistenceError> {
        self.run_blocking(move |connection| {
            OperationLedger::transition_shadow_session(
                connection,
                session_id,
                attempt_id,
                binding,
                ShadowSessionState::ReconcileRequired,
            )
            .map(|_| ())
        })
        .await
    }

    async fn mark_superseded(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
    ) -> std::result::Result<(), ShadowSessionPersistenceError> {
        self.run_blocking(move |connection| {
            OperationLedger::transition_shadow_session(
                connection,
                session_id,
                attempt_id,
                binding,
                ShadowSessionState::Superseded,
            )
            .map(|_| ())
        })
        .await
    }

    async fn complete_witnessed(
        &self,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
        binding: ShadowSessionBinding,
        completion: OperationRecord,
    ) -> std::result::Result<RecordOutcome, ShadowSessionPersistenceError> {
        self.run_blocking(move |connection| {
            OperationLedger::record_shadow_completion(
                connection,
                session_id,
                attempt_id,
                binding,
                &completion,
            )
        })
        .await
    }
}

/// Async transaction boundary designed for the Firestore witness adapter. A
/// future adapter must return a provider-derived exact current record and keep
/// `OutcomeUnknown` distinct from an ordinary CAS rejection.
#[async_trait]
pub(crate) trait ShadowCheckpointWitnessProvider: Send + Sync {
    async fn read_current_exact(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<WitnessRecord, WitnessError>;

    async fn compare_and_advance_root(
        &self,
        advance: RootAdvance,
    ) -> std::result::Result<WitnessReceipt, ShadowWitnessCommitError>;
}

/// Caller-selected state is limited to archive identity and a witness lease.
/// Database/key/schema identity always comes from authenticated state.
#[derive(Clone, Copy)]
pub(crate) struct ShadowCheckpointPublishRequest {
    archive_id: ArchiveId,
    lease: WitnessLease,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
}

impl ShadowCheckpointPublishRequest {
    pub(crate) const fn new(
        archive_id: ArchiveId,
        lease: WitnessLease,
        session_id: ShadowSessionId,
        attempt_id: ShadowAttemptId,
    ) -> Self {
        Self {
            archive_id,
            lease,
            session_id,
            attempt_id,
        }
    }
}

/// Opaque publication result. `reconciled` means only that a lost
/// witness response was resolved by an exact reread of this same root.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ShadowCheckpointPublication {
    checkpoint: UploadedCheckpoint,
    root: RootReference,
    reconciled: bool,
}
impl std::fmt::Debug for ShadowCheckpointPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShadowCheckpointPublication(<opaque>)")
    }
}

impl ShadowCheckpointPublication {
    pub(crate) fn checkpoint(&self) -> &UploadedCheckpoint {
        &self.checkpoint
    }
    pub(crate) fn root(&self) -> RootReference {
        self.root
    }
    pub(crate) fn reconciled(&self) -> bool {
        self.reconciled
    }
}

/// Publishes one inactive checkpoint candidate. A pre-witness error may leave
/// only unreachable immutable objects; this function intentionally performs no
/// cleanup because deletion/GC is a later separately-authorized phase.
pub(crate) async fn publish_shadow_checkpoint(
    witness: Arc<dyn ShadowCheckpointWitnessProvider>,
    sessions: Arc<dyn ShadowSessionPersistence>,
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    request: ShadowCheckpointPublishRequest,
    completion: OperationRecord,
    source: &mut dyn CheckpointSource,
) -> Result<ShadowCheckpointPublication> {
    // This read is the required authority input, not a mutation.  No witness
    // compare-and-advance happens until upload, root create, and exact root
    // readback below all succeed.
    let current = witness
        .read_current_exact(request.archive_id)
        .await
        .map_err(ShadowCoordinatorError::Witness)?;
    validate_authority(&current, cipher, request)?;
    let prepared = sessions
        .load_exact(request.session_id, request.attempt_id)
        .await
        .map_err(ShadowCoordinatorError::SessionPersistence)?;
    prepared
        .require_prepared_authority(&current, request.lease)
        .map_err(|_| ShadowCoordinatorError::StaleAuthority)?;
    let session_binding = prepared.binding();
    let next_root_seq = current
        .root()
        .root()
        .sequence()
        .checked_add(1)
        .ok_or(ArchiveV3Error::Malformed("root sequence overflow"))?;
    if session_binding.operation_id() != *completion.operation_id().as_bytes()
        || session_binding.request_fingerprint() != *completion.request_fingerprint().as_bytes()
        || completion.committed_root_seq() != next_root_seq
    {
        return Err(ShadowCoordinatorError::StaleAuthority);
    }
    let current_root = load_current_root(backend, cipher, request.archive_id, &current).await?;

    let staging = ShadowObjectStaging::new(
        sessions.as_ref(),
        request.session_id,
        request.attempt_id,
        session_binding,
    );
    let checkpoint = upload_checkpoint(
        backend,
        cipher,
        request.archive_id,
        current.root().database_epoch(),
        source,
        staging.clone(),
    )
    .await?;

    if checkpoint.user_schema_version() < current_root.user_schema_version {
        return Err(ShadowCoordinatorError::StaleAuthority);
    }
    let expected = current.root();
    let root_seq = next_root_seq;
    let parent = ParentReference {
        object_id: expected.root().object_id(),
        envelope_hash: expected.root().ciphertext_hash(),
    };
    let context = ObjectContext::new(
        request.archive_id,
        expected.database_epoch(),
        expected.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root { root_seq },
        ObjectId::random(),
        Some(parent.clone()),
    )?;
    let root = ArchiveRoot {
        root_seq,
        parent: Some(parent),
        database_epoch: expected.database_epoch(),
        key_epoch: expected.key_epoch(),
        owner_fencing_epoch: request.lease.fencing_epoch(),
        sqlite_page_size: SQLITE_PAGE_SIZE,
        logical_file_length: checkpoint.logical_file_length(),
        user_schema_version: checkpoint.user_schema_version(),
        storage_format_version: ARCHIVE_FORMAT_VERSION,
        wal_generation: 0,
        wal_segment_count: 0,
        checkpoint_root: Some(checkpoint.root().clone()),
        extent_tree_root: None,
        wal_chain_root: None,
    };
    let envelope = cipher.seal(&context, &root.encode()?)?;
    let root_facts = staging
        .create_and_readback(backend, &context, envelope.clone())
        .await?;
    let candidate = RootReference::new(root_seq, context.object_id(), envelope.hash());

    // This builder performs the required exact immutable readback, hash/AEAD
    // validation, root-context validation, and parent/sequence reconstruction.
    let provider = BackendRootProvider { backend };
    let advance = RootAdvance::from_authenticated_candidate(
        request.lease,
        expected,
        current.registry(),
        current.registry(),
        &context,
        &provider,
        cipher,
    )
    .await
    .map_err(ShadowCoordinatorError::Witness)?;

    // The exact candidate must be durable before a witness request can leave
    // the process. A failed persistence call prevents the CAS entirely.
    let session_candidate = ShadowCandidate::from_root_reference(candidate)
        .map_err(|_| ShadowCoordinatorError::StaleAuthority)?;
    let persisted = sessions
        .persist_candidate(
            request.session_id,
            request.attempt_id,
            session_binding,
            session_candidate,
            root_facts,
        )
        .await
        .map_err(ShadowCoordinatorError::SessionPersistence)?;
    if persisted.state() != ShadowSessionState::CandidatePersisted
        || persisted.candidate() != Some(session_candidate)
        || persisted.require_binding(session_binding).is_err()
    {
        return Err(ShadowCoordinatorError::SessionPersistence(
            ShadowSessionPersistenceError::Conflict,
        ));
    }

    let archive_id = request.archive_id;
    let lease_fence = request.lease.fencing_epoch();
    let reconciliation = ShadowReconciliation {
        archive_id,
        session_id: request.session_id,
        attempt_id: request.attempt_id,
        candidate,
        expected: current,
        lease_fence,
        binding: session_binding,
    };
    let reconciliation_for_task = reconciliation.clone();
    let completion_for_task = completion.clone();
    let phase = tokio::spawn(async move {
        let outcome = witness.compare_and_advance_root(advance).await;
        if let Err(ShadowWitnessCommitError::Rejected(error)) = outcome {
            sessions
                .mark_superseded(
                    reconciliation_for_task.session_id,
                    reconciliation_for_task.attempt_id,
                    reconciliation_for_task.binding,
                )
                .await
                .map_err(ShadowCoordinatorError::SessionPersistence)?;
            return Err(ShadowCoordinatorError::Witness(error));
        }
        if let Err(ShadowWitnessCommitError::Failed(error)) = outcome {
            return Err(ShadowCoordinatorError::Witness(error));
        }
        let reconciled = matches!(outcome, Err(ShadowWitnessCommitError::OutcomeUnknown));
        if reconciled {
            sessions
                .require_reconciliation(
                    reconciliation_for_task.session_id,
                    reconciliation_for_task.attempt_id,
                    session_binding,
                )
                .await
                .map_err(ShadowCoordinatorError::SessionPersistence)?;
        }
        let observed = match witness.read_current_exact(archive_id).await {
            Ok(observed) => observed,
            Err(_) => {
                if !reconciled {
                    sessions
                        .require_reconciliation(
                            reconciliation_for_task.session_id,
                            reconciliation_for_task.attempt_id,
                            session_binding,
                        )
                        .await
                        .map_err(ShadowCoordinatorError::SessionPersistence)?;
                }
                return Err(ShadowCoordinatorError::ReconciliationRequired(Box::new(
                    reconciliation_for_task,
                )));
            }
        };
        if record_nominates(
            &observed,
            reconciliation_for_task.candidate,
            &reconciliation_for_task.expected,
            reconciliation_for_task.lease_fence,
        ) {
            match sessions
                .complete_witnessed(
                    reconciliation_for_task.session_id,
                    reconciliation_for_task.attempt_id,
                    reconciliation_for_task.binding,
                    completion_for_task,
                )
                .await
            {
                Ok(_) => Ok(reconciled),
                Err(_) => {
                    sessions
                        .require_reconciliation(
                            reconciliation_for_task.session_id,
                            reconciliation_for_task.attempt_id,
                            reconciliation_for_task.binding,
                        )
                        .await
                        .map_err(ShadowCoordinatorError::SessionPersistence)?;
                    Err(ShadowCoordinatorError::ReconciliationRequired(Box::new(
                        reconciliation_for_task,
                    )))
                }
            }
        } else {
            if !reconciled {
                sessions
                    .require_reconciliation(
                        reconciliation_for_task.session_id,
                        reconciliation_for_task.attempt_id,
                        session_binding,
                    )
                    .await
                    .map_err(ShadowCoordinatorError::SessionPersistence)?;
            }
            Err(ShadowCoordinatorError::ReconciliationRequired(Box::new(
                reconciliation_for_task,
            )))
        }
    });
    let reconciled = phase
        .await
        .map_err(|_| ShadowCoordinatorError::ReconciliationRequired(Box::new(reconciliation)))??;
    Ok(ShadowCheckpointPublication {
        checkpoint,
        root: candidate,
        reconciled,
    })
}

/// Reconciles a post-send outcome by rereading only the exact independent
/// witness record encoded by `handle`. It never lists immutable storage.
pub(crate) async fn reconcile_shadow_checkpoint(
    witness: Arc<dyn ShadowCheckpointWitnessProvider>,
    sessions: Arc<dyn ShadowSessionPersistence>,
    handle: &ShadowReconciliation,
    completion: OperationRecord,
) -> Result<()> {
    let observed = witness
        .read_current_exact(handle.archive_id)
        .await
        .map_err(|_| ShadowCoordinatorError::ReconciliationRequired(Box::new(handle.clone())))?;
    if record_nominates(
        &observed,
        handle.candidate,
        &handle.expected,
        handle.lease_fence,
    ) {
        sessions
            .complete_witnessed(
                handle.session_id,
                handle.attempt_id,
                handle.binding,
                completion,
            )
            .await
            .map(|_| ())
            .map_err(ShadowCoordinatorError::SessionPersistence)
    } else {
        Err(ShadowCoordinatorError::ReconciliationRequired(Box::new(
            handle.clone(),
        )))
    }
}

/// Restart path for a persisted attempt. This reads one exact session and one
/// exact witness document; it never creates a new candidate, lists storage, or
/// grants write authority. `RetrySameCandidate` still requires a fresh valid
/// lease check by the caller.
pub(crate) async fn reconcile_durable_shadow_session(
    witness: Arc<dyn ShadowCheckpointWitnessProvider>,
    sessions: Arc<dyn ShadowSessionPersistence>,
    session_id: ShadowSessionId,
    attempt_id: ShadowAttemptId,
    completion: OperationRecord,
) -> Result<ShadowReconcileDecision> {
    let session = sessions
        .load_exact(session_id, attempt_id)
        .await
        .map_err(ShadowCoordinatorError::SessionPersistence)?;
    let binding = session.binding();
    if binding.operation_id() != *completion.operation_id().as_bytes()
        || binding.request_fingerprint() != *completion.request_fingerprint().as_bytes()
        || session
            .candidate()
            .is_some_and(|candidate| candidate.root_seq() != completion.committed_root_seq())
    {
        return Err(ShadowCoordinatorError::StaleAuthority);
    }
    match session.state() {
        ShadowSessionState::Witnessed => {
            sessions
                .complete_witnessed(session_id, attempt_id, binding, completion)
                .await
                .map_err(ShadowCoordinatorError::SessionPersistence)?;
            return Ok(ShadowReconcileDecision::Witnessed);
        }
        ShadowSessionState::Superseded => return Ok(ShadowReconcileDecision::Superseded),
        ShadowSessionState::Prepared | ShadowSessionState::Aborted => {
            return Err(ShadowCoordinatorError::StaleAuthority);
        }
        ShadowSessionState::CandidatePersisted | ShadowSessionState::ReconcileRequired => {}
    }
    let archive_id = ArchiveId::from_bytes(session.binding().archive_id());
    let observed = witness
        .read_current_exact(archive_id)
        .await
        .map_err(ShadowCoordinatorError::Witness)?;
    let decision = session
        .reconcile_against(&observed)
        .map_err(|_| ShadowCoordinatorError::StaleAuthority)?;
    match decision {
        ShadowReconcileDecision::Witnessed => {
            sessions
                .complete_witnessed(session_id, attempt_id, binding, completion)
                .await
                .map_err(ShadowCoordinatorError::SessionPersistence)?;
        }
        ShadowReconcileDecision::Superseded => {
            sessions
                .mark_superseded(session_id, attempt_id, binding)
                .await
                .map_err(ShadowCoordinatorError::SessionPersistence)?;
        }
        ShadowReconcileDecision::RetrySameCandidate => {}
    }
    Ok(decision)
}

fn validate_authority(
    current: &WitnessRecord,
    cipher: &VerifiedArchiveCipher,
    request: ShadowCheckpointPublishRequest,
) -> Result<()> {
    let root = current.root();
    let registry = current.registry();
    if current.archive_id() != request.archive_id
        || request.lease.archive_id() != request.archive_id
        || request.lease.database_epoch() != root.database_epoch()
        || request.lease.key_epoch() != root.key_epoch()
        || request.lease.fencing_epoch() == 0
        || cipher.archive_id() != request.archive_id
        || cipher.key_epoch() != root.key_epoch()
        || registry.key_epoch() != root.key_epoch()
        || cipher.registry_rotation_generation() != registry.rotation_generation()
        || cipher.registry_object_id() != registry.object_id()
        || cipher.registry_ciphertext_hash() != registry.ciphertext_hash()
    {
        return Err(ShadowCoordinatorError::StaleAuthority);
    }
    Ok(())
}

fn record_nominates(
    observed: &WitnessRecord,
    candidate: RootReference,
    expected: &WitnessRecord,
    lease_fence: u64,
) -> bool {
    observed.archive_id() == expected.archive_id()
        && observed.database_epoch() == expected.database_epoch()
        && observed.database_epoch_generation() == expected.database_epoch_generation()
        && observed.root().root() == candidate
        && observed.root().parent() == Some(expected.root().root())
        && observed.root().database_epoch() == expected.root().database_epoch()
        && observed.root().key_epoch() == expected.root().key_epoch()
        && observed.root().owner_fencing_epoch() == lease_fence
        && observed.registry() == expected.registry()
        && observed.migration() == expected.migration()
        && observed.deletion() == expected.deletion()
        && observed.predecessor_root() == expected.predecessor_root()
        && observed.predecessor_registry() == expected.predecessor_registry()
}

async fn load_current_root(
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    archive_id: ArchiveId,
    current: &WitnessRecord,
) -> Result<ArchiveRoot> {
    let commitment = current.root();
    let reference = commitment.root();
    let parent = commitment.parent().map(|value| ParentReference {
        object_id: value.object_id(),
        envelope_hash: value.ciphertext_hash(),
    });
    let context = ObjectContext::new(
        archive_id,
        commitment.database_epoch(),
        commitment.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root {
            root_seq: reference.sequence(),
        },
        reference.object_id(),
        parent,
    )?;
    let envelope = backend
        .get(&context.object_key())
        .await?
        .ok_or(ArchiveV3Error::Malformed("current root absent"))?;
    if envelope.hash() != reference.ciphertext_hash() {
        return Err(ArchiveV3Error::Authentication.into());
    }
    let plaintext = Zeroizing::new(cipher.open(&context, &envelope)?);
    let root = ArchiveRoot::decode(plaintext.as_slice())?;
    root.validate_for_context(&context)?;
    if root.root_seq != reference.sequence()
        || root.database_epoch != commitment.database_epoch()
        || root.key_epoch != commitment.key_epoch()
        || root.owner_fencing_epoch != commitment.owner_fencing_epoch()
    {
        return Err(ArchiveV3Error::Authentication.into());
    }
    Ok(root)
}

struct BackendRootProvider<'a> {
    backend: &'a dyn ImmutableObjectBackend,
}

#[async_trait]
impl ExactRootProvider for BackendRootProvider<'_> {
    async fn read_exact(
        &self,
        context: &ObjectContext,
    ) -> std::result::Result<CiphertextEnvelope, WitnessError> {
        if context.role() != ObjectRole::RootV3 {
            return Err(WitnessError::Malformed);
        }
        match self.backend.get(&context.object_key()).await {
            Ok(Some(envelope)) => Ok(envelope),
            Ok(None) => Err(WitnessError::MissingRootObject),
            Err(ArchiveV3Error::Unavailable) => Err(WitnessError::Unavailable),
            Err(_) => Err(WitnessError::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        vec::Vec,
    };
    use tokio::{
        sync::Notify,
        time::{timeout, Duration},
    };

    use super::*;
    use crate::archive_v3::{
        resolve_archive_cipher, ArchiveDek, CreateIfAbsent, ExactKeyRegistryProvider,
        InMemoryImmutableBackend, KeyEpoch, KeyKind, KeyRegistryContext, KeyRegistryPlaintext,
        ObjectKey,
    };
    use crate::archive_v3_operation::{
        BoundedOperationResult, OperationId, OperationResultStatus, RequestFingerprint,
        RetentionClass,
    };
    use crate::archive_v3_witness::{
        InMemoryWitness, KeyRegistryReference, RootCommitment, Witness, WitnessBootstrap,
    };
    use sha2::{Digest, Sha256};

    const WRAPPED: &[u8] = b"test-wrapped-registry";

    struct RegistryProvider {
        plaintext: Vec<u8>,
    }
    #[async_trait]
    impl ExactKeyRegistryProvider for RegistryProvider {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            _object_id: ObjectId,
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            destination[..WRAPPED.len()].copy_from_slice(WRAPPED);
            Ok(WRAPPED.len())
        }
        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            _wrapped: &[u8],
            destination: &mut [u8],
        ) -> crate::archive_v3::Result<usize> {
            destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            Ok(self.plaintext.len())
        }
    }

    async fn cipher(
        archive: ArchiveId,
        key: KeyEpoch,
        registry_id: ObjectId,
    ) -> VerifiedArchiveCipher {
        let context = KeyRegistryContext::new(archive, KeyKind::Archive, key);
        let plaintext =
            KeyRegistryPlaintext::encode_archive(&context, &ArchiveDek::from_bytes([7; 32]))
                .unwrap()
                .to_vec();
        let provider = RegistryProvider { plaintext };
        resolve_archive_cipher(
            &context,
            registry_id,
            Sha256::digest(WRAPPED).into(),
            &provider,
        )
        .await
        .unwrap()
    }

    #[derive(Clone, Copy, Default)]
    enum BackendFault {
        #[default]
        None,
        CheckpointChunkCreateFails,
        CheckpointManifestCreateFails,
        CurrentRootReadMissing,
        RootCreateFails,
        RootReadCorrupt,
    }
    struct Backend {
        inner: InMemoryImmutableBackend,
        fault: Mutex<BackendFault>,
        fallback: Mutex<Option<CiphertextEnvelope>>,
        events: Arc<Mutex<Vec<&'static str>>>,
        root_reads: AtomicUsize,
    }
    impl Backend {
        fn new(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                inner: InMemoryImmutableBackend::new(),
                fault: Mutex::new(BackendFault::None),
                fallback: Mutex::new(None),
                events,
                root_reads: AtomicUsize::new(0),
            }
        }
    }
    #[async_trait]
    impl ImmutableObjectBackend for Backend {
        async fn create_if_absent(
            &self,
            key: ObjectKey,
            value: CiphertextEnvelope,
        ) -> crate::archive_v3::Result<CreateIfAbsent> {
            self.events.lock().unwrap().push("create");
            let fault = *self.fault.lock().unwrap();
            if matches!(fault, BackendFault::CheckpointChunkCreateFails)
                && key.as_str().contains("/chunks/")
            {
                return Err(ArchiveV3Error::Unavailable);
            }
            if matches!(fault, BackendFault::CheckpointManifestCreateFails)
                && key.as_str().contains("/manifest/")
            {
                return Err(ArchiveV3Error::Unavailable);
            }
            if matches!(fault, BackendFault::RootCreateFails)
                && key.as_str().contains("/root-candidates/")
            {
                return Err(ArchiveV3Error::Unavailable);
            }
            self.inner.create_if_absent(key, value).await
        }
        async fn get(
            &self,
            key: &ObjectKey,
        ) -> crate::archive_v3::Result<Option<CiphertextEnvelope>> {
            self.events.lock().unwrap().push("read");
            let fault = *self.fault.lock().unwrap();
            if key.as_str().contains("/root-candidates/") {
                let read_no = self.root_reads.fetch_add(1, Ordering::SeqCst);
                if matches!(fault, BackendFault::CurrentRootReadMissing) && read_no == 0 {
                    return Ok(None);
                }
                if matches!(fault, BackendFault::RootReadCorrupt) && read_no > 0 {
                    return Ok(self.fallback.lock().unwrap().clone());
                }
            }
            self.inner.get(key).await
        }
        async fn enumerate(
            &self,
            prefix: &crate::archive_v3::ArchivePrefix,
            cursor: Option<&crate::archive_v3::EnumerationCursor>,
            limit: crate::archive_v3::EnumerationLimit,
        ) -> crate::archive_v3::Result<crate::archive_v3::EnumerationPage> {
            let _ = (prefix, cursor, limit);
            panic!("shadow coordinator must never enumerate storage")
        }
        async fn delete_exact(&self, key: &ObjectKey) -> crate::archive_v3::Result<bool> {
            let _ = key;
            panic!("shadow coordinator must never delete storage")
        }
    }

    #[derive(Clone, Copy)]
    enum Outcome {
        Ok,
        Reject,
        ProviderFailed,
        UnknownCommitted,
        UnknownUncommitted,
        UnknownDelayedCommitted,
        OkWithStaleReread,
        OkWithForgedRegistryReread,
        OkWithRereadError,
        PanicAfterCommitted,
    }
    struct FakeWitness {
        inner: InMemoryWitness,
        outcome: Mutex<Outcome>,
        commits: Mutex<usize>,
        events: Arc<Mutex<Vec<&'static str>>>,
        reads: AtomicUsize,
        after_send: Mutex<Option<(Arc<Notify>, Arc<Notify>)>>,
        during_reread: Mutex<Option<(Arc<Notify>, Arc<Notify>)>>,
        reread_complete: Mutex<Option<Arc<Notify>>>,
        stale_reread: Mutex<Option<WitnessRecord>>,
        delayed_advance: Mutex<Option<RootAdvance>>,
        wrong_archive_initial_read: Mutex<bool>,
    }

    struct FakeSessions {
        record: Mutex<ShadowSessionRecord>,
        completion: Mutex<Option<OperationRecord>>,
        events: Arc<Mutex<Vec<&'static str>>>,
        fail_candidate_persist: Mutex<bool>,
        fail_completion: Mutex<bool>,
    }

    #[async_trait]
    impl ShadowObjectInventory for FakeSessions {
        async fn reserve_exact(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _facts: ShadowObjectFacts,
        ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
            self.events.lock().unwrap().push("reserve");
            Ok(RecordOutcome::Recorded)
        }

        async fn mark_materialized_exact(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _facts: ShadowObjectFacts,
        ) -> std::result::Result<RecordOutcome, ShadowObjectInventoryError> {
            self.events.lock().unwrap().push("materialize");
            Ok(RecordOutcome::Recorded)
        }

        async fn load_exact_attempt_page(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _after_ordinal: Option<u32>,
        ) -> std::result::Result<
            crate::archive_v3_operation::ShadowObjectInventoryPage,
            ShadowObjectInventoryError,
        > {
            Ok(crate::archive_v3_operation::ShadowObjectInventoryPage::empty())
        }
    }

    #[async_trait]
    impl ShadowSessionPersistence for FakeSessions {
        async fn load_exact(
            &self,
            session_id: ShadowSessionId,
            attempt_id: ShadowAttemptId,
        ) -> std::result::Result<ShadowSessionRecord, ShadowSessionPersistenceError> {
            self.events.lock().unwrap().push("load_session");
            let record = self.record.lock().unwrap().clone();
            if record.session_id() != session_id || record.attempt_id() != attempt_id {
                return Err(ShadowSessionPersistenceError::Conflict);
            }
            Ok(record)
        }

        async fn persist_candidate(
            &self,
            session_id: ShadowSessionId,
            attempt_id: ShadowAttemptId,
            binding: ShadowSessionBinding,
            candidate: ShadowCandidate,
            _root_facts: ShadowObjectFacts,
        ) -> std::result::Result<ShadowSessionRecord, ShadowSessionPersistenceError> {
            self.events.lock().unwrap().push("persist_candidate");
            if *self.fail_candidate_persist.lock().unwrap() {
                return Err(ShadowSessionPersistenceError::Unavailable);
            }
            let mut record = self.record.lock().unwrap();
            if record.session_id() != session_id
                || record.attempt_id() != attempt_id
                || record.require_binding(binding).is_err()
            {
                return Err(ShadowSessionPersistenceError::Conflict);
            }
            record
                .persist_candidate(candidate)
                .map_err(|_| ShadowSessionPersistenceError::Conflict)?;
            Ok(record.clone())
        }

        async fn require_reconciliation(
            &self,
            session_id: ShadowSessionId,
            attempt_id: ShadowAttemptId,
            binding: ShadowSessionBinding,
        ) -> std::result::Result<(), ShadowSessionPersistenceError> {
            self.events.lock().unwrap().push("persist_reconcile");
            let mut record = self.record.lock().unwrap();
            if record.session_id() != session_id
                || record.attempt_id() != attempt_id
                || record.require_binding(binding).is_err()
            {
                return Err(ShadowSessionPersistenceError::Conflict);
            }
            if record.state() != ShadowSessionState::ReconcileRequired {
                record
                    .transition(ShadowSessionState::ReconcileRequired)
                    .map_err(|_| ShadowSessionPersistenceError::Conflict)?;
            }
            Ok(())
        }

        async fn mark_superseded(
            &self,
            session_id: ShadowSessionId,
            attempt_id: ShadowAttemptId,
            binding: ShadowSessionBinding,
        ) -> std::result::Result<(), ShadowSessionPersistenceError> {
            self.events.lock().unwrap().push("persist_superseded");
            let mut record = self.record.lock().unwrap();
            if record.session_id() != session_id
                || record.attempt_id() != attempt_id
                || record.require_binding(binding).is_err()
            {
                return Err(ShadowSessionPersistenceError::Conflict);
            }
            if record.state() != ShadowSessionState::Superseded {
                record
                    .transition(ShadowSessionState::Superseded)
                    .map_err(|_| ShadowSessionPersistenceError::Conflict)?;
            }
            Ok(())
        }

        async fn complete_witnessed(
            &self,
            session_id: ShadowSessionId,
            attempt_id: ShadowAttemptId,
            binding: ShadowSessionBinding,
            completion: OperationRecord,
        ) -> std::result::Result<RecordOutcome, ShadowSessionPersistenceError> {
            self.events.lock().unwrap().push("complete_witnessed");
            if *self.fail_completion.lock().unwrap() {
                return Err(ShadowSessionPersistenceError::Unavailable);
            }
            let mut record = self.record.lock().unwrap();
            if record.session_id() != session_id
                || record.attempt_id() != attempt_id
                || record.require_binding(binding).is_err()
                || record.binding().operation_id() != *completion.operation_id().as_bytes()
                || record.binding().request_fingerprint()
                    != *completion.request_fingerprint().as_bytes()
                || record.candidate().map(ShadowCandidate::root_seq)
                    != Some(completion.committed_root_seq())
            {
                return Err(ShadowSessionPersistenceError::Conflict);
            }
            let mut persisted_completion = self.completion.lock().unwrap();
            if record.state() == ShadowSessionState::Witnessed {
                return if persisted_completion.as_ref() == Some(&completion) {
                    Ok(RecordOutcome::AlreadyRecorded)
                } else {
                    Err(ShadowSessionPersistenceError::Conflict)
                };
            }
            record
                .transition(ShadowSessionState::Witnessed)
                .map_err(|_| ShadowSessionPersistenceError::Conflict)?;
            *persisted_completion = Some(completion);
            Ok(RecordOutcome::Recorded)
        }
    }

    #[async_trait]
    impl ShadowCheckpointWitnessProvider for FakeWitness {
        async fn read_current_exact(
            &self,
            archive: ArchiveId,
        ) -> std::result::Result<WitnessRecord, WitnessError> {
            self.events.lock().unwrap().push("read_witness");
            let read_no = self.reads.fetch_add(1, Ordering::SeqCst);
            let barrier = self.during_reread.lock().unwrap().clone();
            if read_no > 0 {
                if let Some((entered, release)) = barrier {
                    entered.notify_one();
                    release.notified().await;
                }
            }
            let outcome = *self.outcome.lock().unwrap();
            if read_no > 1 && matches!(outcome, Outcome::UnknownDelayedCommitted) {
                if let Some(advance) = self.delayed_advance.lock().unwrap().take() {
                    let _ = self.inner.compare_and_advance_root(advance)?;
                }
            }
            let record = self
                .inner
                .read_current(archive)?
                .ok_or(WitnessError::MissingArchive)?;
            if read_no > 0 && matches!(outcome, Outcome::OkWithRereadError) {
                *self.outcome.lock().unwrap() = Outcome::Ok;
                return Err(WitnessError::Unavailable);
            }
            let mut record = if read_no == 1 {
                match outcome {
                    Outcome::OkWithStaleReread => self
                        .stale_reread
                        .lock()
                        .unwrap()
                        .clone()
                        .ok_or(WitnessError::Synchronization)?,
                    Outcome::OkWithForgedRegistryReread => {
                        let registry = record.registry();
                        record.with_registry_for_test(KeyRegistryReference::new(
                            registry.key_epoch(),
                            registry.rotation_generation(),
                            ObjectId::from_bytes([0x81; 16]),
                            [0x82; 32],
                        ))
                    }
                    _ => record,
                }
            } else {
                record
            };
            if read_no == 0 && *self.wrong_archive_initial_read.lock().unwrap() {
                record = record.with_archive_id_for_test(ArchiveId::from_bytes([0x83; 16]));
            }
            if read_no > 0 {
                if let Some(completed) = self.reread_complete.lock().unwrap().clone() {
                    completed.notify_one();
                }
            }
            Ok(record)
        }
        async fn compare_and_advance_root(
            &self,
            advance: RootAdvance,
        ) -> std::result::Result<WitnessReceipt, ShadowWitnessCommitError> {
            self.events.lock().unwrap().push("commit_witness");
            *self.commits.lock().unwrap() += 1;
            let outcome = *self.outcome.lock().unwrap();
            let result = match outcome {
                Outcome::Ok
                | Outcome::OkWithStaleReread
                | Outcome::OkWithForgedRegistryReread
                | Outcome::OkWithRereadError => {
                    if matches!(outcome, Outcome::OkWithStaleReread) {
                        *self.stale_reread.lock().unwrap() =
                            self.inner.read_current(advance.archive_id()).ok().flatten();
                    }
                    self.inner
                        .compare_and_advance_root(advance)
                        .map_err(ShadowWitnessCommitError::Rejected)
                }
                Outcome::Reject => Err(ShadowWitnessCommitError::Rejected(
                    WitnessError::CompareFailed,
                )),
                Outcome::ProviderFailed => {
                    Err(ShadowWitnessCommitError::Failed(WitnessError::Unavailable))
                }
                Outcome::UnknownCommitted => {
                    let _ = self
                        .inner
                        .compare_and_advance_root(advance)
                        .map_err(ShadowWitnessCommitError::Rejected)?;
                    Err(ShadowWitnessCommitError::OutcomeUnknown)
                }
                Outcome::UnknownUncommitted => Err(ShadowWitnessCommitError::OutcomeUnknown),
                Outcome::UnknownDelayedCommitted => {
                    *self.delayed_advance.lock().unwrap() = Some(advance);
                    Err(ShadowWitnessCommitError::OutcomeUnknown)
                }
                Outcome::PanicAfterCommitted => {
                    let _ = self
                        .inner
                        .compare_and_advance_root(advance)
                        .map_err(ShadowWitnessCommitError::Rejected)?;
                    panic!("injected post-commit witness task failure")
                }
            };
            let barrier = self.after_send.lock().unwrap().clone();
            if let Some((entered, release)) = barrier {
                entered.notify_one();
                release.notified().await;
            }
            result
        }
    }
    struct Source(Vec<u8>);
    impl CheckpointSource for Source {
        fn logical_file_length(&self) -> crate::archive_v3_shadow_checkpoint::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn read_exact(
            &mut self,
            offset: u64,
            destination: &mut [u8],
        ) -> crate::archive_v3_shadow_checkpoint::Result<()> {
            let start = offset as usize;
            destination.copy_from_slice(
                self.0
                    .get(start..start + destination.len())
                    .ok_or(ShadowCheckpointError::Source)?,
            );
            Ok(())
        }
    }

    async fn setup(
        outcome: Outcome,
    ) -> (
        Backend,
        VerifiedArchiveCipher,
        Arc<FakeWitness>,
        Arc<FakeSessions>,
        ShadowCheckpointPublishRequest,
        Arc<Mutex<Vec<&'static str>>>,
    ) {
        let archive = ArchiveId::from_bytes([1; 16]);
        let database = crate::archive_v3::DatabaseEpoch::from_bytes([2; 16]);
        let key = KeyEpoch::from_bytes([3; 16]);
        let registry_id = ObjectId::from_bytes([4; 16]);
        let cipher = cipher(archive, key, registry_id).await;
        let events = Arc::new(Mutex::new(Vec::new()));
        let backend = Backend::new(events.clone());
        let root_context = ObjectContext::new(
            archive,
            database,
            key,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ObjectId::from_bytes([5; 16]),
            None,
        )
        .unwrap();
        let root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: database,
            key_epoch: key,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: 0,
            user_schema_version: 1,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_chain_root: None,
        };
        let envelope = cipher.seal(&root_context, &root.encode().unwrap()).unwrap();
        backend
            .inner
            .create_if_absent(root_context.object_key(), envelope.clone())
            .await
            .unwrap();
        *backend.fallback.lock().unwrap() = Some(envelope.clone());
        let witness = InMemoryWitness::new();
        let registry =
            KeyRegistryReference::new(key, 0, registry_id, cipher.registry_ciphertext_hash());
        witness
            .bootstrap(WitnessBootstrap::new(
                archive,
                database,
                RootCommitment::genesis(
                    database,
                    key,
                    RootReference::new(0, root_context.object_id(), envelope.hash()),
                ),
                registry,
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(archive, database, key, ObjectId::from_bytes([6; 16]), 60)
            .unwrap();
        let operation_id = [7; 16];
        let session_id = ShadowSessionId::for_operation(operation_id).unwrap();
        let attempt_id = ShadowAttemptId::from_bytes([8; 16]);
        let current = witness.read_current(archive).unwrap().unwrap();
        let session = ShadowSessionRecord::prepared(
            session_id,
            attempt_id,
            ShadowSessionBinding::from_witness(&current, lease, operation_id, [9; 32], 1, 1, 1)
                .unwrap(),
        )
        .unwrap();
        let sessions = Arc::new(FakeSessions {
            record: Mutex::new(session),
            completion: Mutex::new(None),
            events: events.clone(),
            fail_candidate_persist: Mutex::new(false),
            fail_completion: Mutex::new(false),
        });
        let request = ShadowCheckpointPublishRequest::new(archive, lease, session_id, attempt_id);
        (
            backend,
            cipher,
            Arc::new(FakeWitness {
                inner: witness,
                outcome: Mutex::new(outcome),
                commits: Mutex::new(0),
                events: events.clone(),
                reads: AtomicUsize::new(0),
                after_send: Mutex::new(None),
                during_reread: Mutex::new(None),
                reread_complete: Mutex::new(None),
                stale_reread: Mutex::new(None),
                delayed_advance: Mutex::new(None),
                wrong_archive_initial_read: Mutex::new(false),
            }),
            sessions,
            request,
            events,
        )
    }
    fn source() -> Source {
        let mut bytes = vec![9; SQLITE_PAGE_SIZE as usize];
        bytes[..16].copy_from_slice(b"SQLite format 3\0");
        bytes[16..18].copy_from_slice(&(SQLITE_PAGE_SIZE as u16).to_be_bytes());
        bytes[60..64].copy_from_slice(&1u32.to_be_bytes());
        Source(bytes)
    }

    fn completion() -> OperationRecord {
        OperationRecord::new(
            OperationId::from_bytes([7; 16]),
            RequestFingerprint::from_bytes([9; 32]),
            1,
            OperationResultStatus::Succeeded,
            BoundedOperationResult::inline(
                OperationResultStatus::Succeeded,
                b"shadow-checkpoint-result".to_vec(),
            )
            .unwrap(),
            RetentionClass::RetryWindow,
            101,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn publishes_only_after_immutable_upload_root_create_and_readback() {
        let (backend, cipher, witness, sessions, request, events) = setup(Outcome::Ok).await;
        let published = publish_shadow_checkpoint(
            witness.clone(),
            sessions.clone(),
            &backend,
            &cipher,
            request,
            completion(),
            &mut source(),
        )
        .await
        .unwrap();
        assert!(!published.reconciled());
        assert_eq!(published.root().sequence(), 1);
        let events = events.lock().unwrap();
        let commit = events.iter().position(|x| *x == "commit_witness").unwrap();
        assert_eq!(events.first(), Some(&"read_witness"));
        assert_eq!(events.get(1), Some(&"load_session"));
        assert_eq!(events.get(2), Some(&"read"));
        let reserve = events.iter().position(|x| *x == "reserve").unwrap();
        let create = events.iter().position(|x| *x == "create").unwrap();
        let materialize = events.iter().position(|x| *x == "materialize").unwrap();
        assert!(reserve < create && create < materialize && materialize < commit);
        assert_eq!(
            events.get(commit.wrapping_sub(1)),
            Some(&"persist_candidate")
        );
        assert_eq!(events.get(commit + 1), Some(&"read_witness"));
        assert_eq!(events.get(commit + 2), Some(&"complete_witnessed"));
        assert_eq!(
            sessions.record.lock().unwrap().state(),
            ShadowSessionState::Witnessed
        );
    }
    #[tokio::test]
    async fn failures_and_cas_rejection_never_publish_authority() {
        for fault in [
            BackendFault::CheckpointChunkCreateFails,
            BackendFault::CheckpointManifestCreateFails,
            BackendFault::CurrentRootReadMissing,
            BackendFault::RootCreateFails,
            BackendFault::RootReadCorrupt,
        ] {
            let (backend, cipher, witness, sessions, request, events) = setup(Outcome::Ok).await;
            *backend.fault.lock().unwrap() = fault;
            assert!(publish_shadow_checkpoint(
                witness.clone(),
                sessions,
                &backend,
                &cipher,
                request,
                completion(),
                &mut source()
            )
            .await
            .is_err());
            assert_eq!(*witness.commits.lock().unwrap(), 0);
            if matches!(fault, BackendFault::CurrentRootReadMissing) {
                assert!(!events.lock().unwrap().contains(&"create"));
            }
        }
        let (backend, reject_cipher, witness, sessions, request, _) = setup(Outcome::Reject).await;
        assert!(matches!(
            publish_shadow_checkpoint(
                witness.clone(),
                sessions.clone(),
                &backend,
                &reject_cipher,
                request,
                completion(),
                &mut source()
            )
            .await,
            Err(ShadowCoordinatorError::Witness(WitnessError::CompareFailed))
        ));
        assert_eq!(*witness.commits.lock().unwrap(), 1);
        assert_eq!(
            sessions.record.lock().unwrap().state(),
            ShadowSessionState::Superseded
        );

        let (backend, failed_cipher, witness, sessions, request, events) =
            setup(Outcome::ProviderFailed).await;
        assert!(matches!(
            publish_shadow_checkpoint(
                witness,
                sessions.clone(),
                &backend,
                &failed_cipher,
                request,
                completion(),
                &mut source(),
            )
            .await,
            Err(ShadowCoordinatorError::Witness(WitnessError::Unavailable))
        ));
        assert_eq!(
            sessions.record.lock().unwrap().state(),
            ShadowSessionState::CandidatePersisted
        );
        assert!(!events.lock().unwrap().contains(&"persist_superseded"));

        let (backend, _cipher, witness, sessions, request, _) = setup(Outcome::Ok).await;
        let stale = cipher(
            ArchiveId::from_bytes([1; 16]),
            KeyEpoch::from_bytes([99; 16]),
            ObjectId::from_bytes([4; 16]),
        )
        .await;
        assert!(matches!(
            publish_shadow_checkpoint(
                witness.clone(),
                sessions,
                &backend,
                &stale,
                request,
                completion(),
                &mut source(),
            )
            .await,
            Err(ShadowCoordinatorError::StaleAuthority)
        ));
        assert_eq!(*witness.commits.lock().unwrap(), 0);

        let (backend, cipher, witness, sessions, request, events) = setup(Outcome::Ok).await;
        *sessions.fail_candidate_persist.lock().unwrap() = true;
        assert!(matches!(
            publish_shadow_checkpoint(
                witness.clone(),
                sessions,
                &backend,
                &cipher,
                request,
                completion(),
                &mut source(),
            )
            .await,
            Err(ShadowCoordinatorError::SessionPersistence(
                ShadowSessionPersistenceError::Unavailable
            ))
        ));
        assert_eq!(*witness.commits.lock().unwrap(), 0);
        assert!(events.lock().unwrap().contains(&"persist_candidate"));

        let (backend, cipher, witness, sessions, request, events) = setup(Outcome::Ok).await;
        *witness.wrong_archive_initial_read.lock().unwrap() = true;
        assert!(matches!(
            publish_shadow_checkpoint(
                witness.clone(),
                sessions,
                &backend,
                &cipher,
                request,
                completion(),
                &mut source(),
            )
            .await,
            Err(ShadowCoordinatorError::StaleAuthority)
        ));
        assert_eq!(*witness.commits.lock().unwrap(), 0);
        assert!(!events.lock().unwrap().contains(&"create"));

        let (backend, cipher, witness, sessions, request, _) = setup(Outcome::Ok).await;
        let mut downgraded = source();
        downgraded.0[60..64].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            publish_shadow_checkpoint(
                witness.clone(),
                sessions,
                &backend,
                &cipher,
                request,
                completion(),
                &mut downgraded,
            )
            .await,
            Err(ShadowCoordinatorError::StaleAuthority)
        ));
        assert_eq!(*witness.commits.lock().unwrap(), 0);
    }
    #[tokio::test]
    async fn non_nominating_post_send_reads_retain_exact_reconciliation() {
        let (backend, cipher, witness, sessions, request, _) =
            setup(Outcome::UnknownCommitted).await;
        assert!(publish_shadow_checkpoint(
            witness.clone(),
            sessions.clone(),
            &backend,
            &cipher,
            request,
            completion(),
            &mut source()
        )
        .await
        .unwrap()
        .reconciled());
        assert_eq!(
            sessions.record.lock().unwrap().state(),
            ShadowSessionState::Witnessed
        );
        assert_eq!(
            reconcile_durable_shadow_session(
                witness.clone(),
                sessions.clone(),
                request.session_id,
                request.attempt_id,
                completion(),
            )
            .await
            .unwrap(),
            ShadowReconcileDecision::Witnessed
        );
        let (backend, cipher, witness, sessions, request, _) =
            setup(Outcome::UnknownUncommitted).await;
        let result = publish_shadow_checkpoint(
            witness.clone(),
            sessions.clone(),
            &backend,
            &cipher,
            request,
            completion(),
            &mut source(),
        )
        .await;
        assert!(matches!(
            result,
            Err(ShadowCoordinatorError::ReconciliationRequired(_))
        ));
        assert_eq!(
            sessions.record.lock().unwrap().state(),
            ShadowSessionState::ReconcileRequired
        );
        assert_eq!(
            reconcile_durable_shadow_session(
                witness,
                sessions,
                request.session_id,
                request.attempt_id,
                completion(),
            )
            .await
            .unwrap(),
            ShadowReconcileDecision::RetrySameCandidate
        );

        for outcome in [
            Outcome::UnknownDelayedCommitted,
            Outcome::OkWithStaleReread,
            Outcome::OkWithForgedRegistryReread,
        ] {
            let (backend, cipher, witness, sessions, request, _) = setup(outcome).await;
            let handle = match publish_shadow_checkpoint(
                witness.clone(),
                sessions.clone(),
                &backend,
                &cipher,
                request,
                completion(),
                &mut source(),
            )
            .await
            {
                Err(ShadowCoordinatorError::ReconciliationRequired(handle)) => handle,
                other => panic!("expected retained exact handle, got {other:?}"),
            };
            timeout(
                Duration::from_secs(5),
                reconcile_shadow_checkpoint(witness, sessions, &handle, completion()),
            )
            .await
            .expect("later exact reread must remain bounded")
            .unwrap();
        }
    }

    #[tokio::test]
    async fn failed_atomic_completion_is_reconciled_and_retried_idempotently() {
        let (backend, cipher, witness, sessions, request, _) = setup(Outcome::Ok).await;
        *sessions.fail_completion.lock().unwrap() = true;
        assert!(matches!(
            publish_shadow_checkpoint(
                witness.clone(),
                sessions.clone(),
                &backend,
                &cipher,
                request,
                completion(),
                &mut source(),
            )
            .await,
            Err(ShadowCoordinatorError::ReconciliationRequired(_))
        ));
        assert_eq!(
            sessions.record.lock().unwrap().state(),
            ShadowSessionState::ReconcileRequired
        );
        *sessions.fail_completion.lock().unwrap() = false;
        for _ in 0..2 {
            assert_eq!(
                reconcile_durable_shadow_session(
                    witness.clone(),
                    sessions.clone(),
                    request.session_id,
                    request.attempt_id,
                    completion(),
                )
                .await
                .unwrap(),
                ShadowReconcileDecision::Witnessed
            );
        }
        assert_eq!(
            sessions.record.lock().unwrap().state(),
            ShadowSessionState::Witnessed
        );
        assert_eq!(
            sessions.completion.lock().unwrap().as_ref(),
            Some(&completion())
        );
    }

    #[tokio::test]
    async fn rejected_attempt_is_terminal_across_restart_before_new_attempt() {
        let (backend, cipher, witness, prepared, request, _) = setup(Outcome::Reject).await;
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&connection).unwrap();
        let prepared_record = prepared.record.lock().unwrap().clone();
        OperationLedger::prepare_shadow_session(&connection, &prepared_record).unwrap();
        let sessions = Arc::new(EncryptedSqliteShadowSessionPersistence::new(Arc::new(
            Mutex::new(connection),
        )));
        assert!(matches!(
            publish_shadow_checkpoint(
                witness.clone(),
                sessions.clone(),
                &backend,
                &cipher,
                request,
                completion(),
                &mut source(),
            )
            .await,
            Err(ShadowCoordinatorError::Witness(WitnessError::CompareFailed))
        ));
        drop(sessions);

        let reopened = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&reopened).unwrap();
        assert_eq!(
            OperationLedger::load_shadow_session(
                &reopened,
                request.session_id,
                request.attempt_id,
            )
            .unwrap()
            .unwrap()
            .state(),
            ShadowSessionState::Superseded
        );
        let shared = Arc::new(Mutex::new(reopened));
        let restarted = Arc::new(EncryptedSqliteShadowSessionPersistence::new(shared.clone()));
        assert_eq!(
            reconcile_durable_shadow_session(
                witness,
                restarted,
                request.session_id,
                request.attempt_id,
                completion(),
            )
            .await
            .unwrap(),
            ShadowReconcileDecision::Superseded
        );
        let next = ShadowSessionRecord::prepared(
            prepared_record.session_id(),
            ShadowAttemptId::from_bytes([0x44; 16]),
            prepared_record.binding(),
        )
        .unwrap();
        assert_eq!(
            OperationLedger::prepare_shadow_session(&shared.lock().unwrap(), &next).unwrap(),
            RecordOutcome::Recorded
        );
    }

    #[tokio::test]
    async fn encrypted_sqlite_candidate_and_reconciliation_survive_process_restart() {
        let (backend, cipher, witness, prepared, request, _) =
            setup(Outcome::UnknownUncommitted).await;
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&connection).unwrap();
        let prepared_record = prepared.record.lock().unwrap().clone();
        OperationLedger::prepare_shadow_session(&connection, &prepared_record).unwrap();
        let sessions = Arc::new(EncryptedSqliteShadowSessionPersistence::new(Arc::new(
            Mutex::new(connection),
        )));
        assert!(matches!(
            publish_shadow_checkpoint(
                witness.clone(),
                sessions.clone(),
                &backend,
                &cipher,
                request,
                completion(),
                &mut source(),
            )
            .await,
            Err(ShadowCoordinatorError::ReconciliationRequired(_))
        ));
        drop(sessions);

        let reopened = Connection::open(temporary.path()).unwrap();
        OperationLedger::initialize(&reopened).unwrap();
        assert_eq!(
            OperationLedger::load_shadow_session(
                &reopened,
                request.session_id,
                request.attempt_id,
            )
            .unwrap()
            .unwrap()
            .state(),
            ShadowSessionState::ReconcileRequired
        );
        let restarted = Arc::new(EncryptedSqliteShadowSessionPersistence::new(Arc::new(
            Mutex::new(reopened),
        )));
        assert_eq!(
            reconcile_durable_shadow_session(
                witness,
                restarted,
                request.session_id,
                request.attempt_id,
                completion(),
            )
            .await
            .unwrap(),
            ShadowReconcileDecision::RetrySameCandidate
        );
    }

    #[tokio::test]
    async fn post_send_failures_return_an_exact_reconciliation_handle() {
        for outcome in [Outcome::OkWithRereadError, Outcome::PanicAfterCommitted] {
            let (backend, cipher, witness, sessions, request, _) = setup(outcome).await;
            let result = timeout(
                Duration::from_secs(5),
                publish_shadow_checkpoint(
                    witness.clone(),
                    sessions.clone(),
                    &backend,
                    &cipher,
                    request,
                    completion(),
                    &mut source(),
                ),
            )
            .await
            .expect("post-send publication must remain bounded");
            let handle = match result {
                Err(ShadowCoordinatorError::ReconciliationRequired(handle)) => handle,
                other => panic!("expected reconciliation handle, got {other:?}"),
            };
            assert_eq!(format!("{handle:?}"), "ShadowReconciliation(<opaque>)");
            timeout(
                Duration::from_secs(5),
                reconcile_shadow_checkpoint(witness.clone(), sessions, &handle, completion()),
            )
            .await
            .expect("exact witness reread must remain bounded")
            .unwrap();
            assert_eq!(*witness.commits.lock().unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn committing_phase_survives_cancellation_after_send_and_during_reread() {
        for during_reread in [false, true] {
            let (backend, cipher, witness, sessions, request, _) =
                setup(Outcome::UnknownCommitted).await;
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let completed = Arc::new(Notify::new());
            *witness.reread_complete.lock().unwrap() = Some(completed.clone());
            if during_reread {
                *witness.during_reread.lock().unwrap() = Some((entered.clone(), release.clone()));
            } else {
                *witness.after_send.lock().unwrap() = Some((entered.clone(), release.clone()));
            }
            let witness_for_call: Arc<dyn ShadowCheckpointWitnessProvider> = witness.clone();
            let sessions_for_call = sessions.clone();
            let call = tokio::spawn(async move {
                publish_shadow_checkpoint(
                    witness_for_call,
                    sessions_for_call,
                    &backend,
                    &cipher,
                    request,
                    completion(),
                    &mut source(),
                )
                .await
            });
            timeout(Duration::from_secs(5), entered.notified())
                .await
                .expect("committing phase must reach the cancellation barrier");
            call.abort();
            timeout(Duration::from_secs(5), call)
                .await
                .expect("aborted caller task join must remain bounded")
                .expect_err("caller task must report cancellation");
            release.notify_one();
            timeout(Duration::from_secs(5), completed.notified())
                .await
                .expect("owned exact reread must finish after caller cancellation");
            assert_eq!(
                witness
                    .inner
                    .recovery_root(request.archive_id)
                    .unwrap()
                    .root()
                    .root()
                    .sequence(),
                1
            );
            assert_eq!(*witness.commits.lock().unwrap(), 1);
            assert_eq!(witness.reads.load(Ordering::SeqCst), 2);
            assert_eq!(
                sessions.record.lock().unwrap().state(),
                ShadowSessionState::Witnessed
            );
        }
    }
}
