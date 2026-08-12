//! Private, inactive legacy SQLite extent-candidate composition.
//!
//! This is deliberately the last non-authoritative conversion step.  It
//! authenticates a pinned historic blob, writes provisional plaintext only
//! through the sealed immutable staging seam, and persists a durable
//! `CandidateReady` record.  It does not CAS a witness, publish a root, touch
//! a Store/VFS, construct a provider, or schedule deletion/GC.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use thiserror::Error;

use crate::{
    archive_v3::{
        ArchiveRoot, DatabaseEpoch, ImmutableObjectBackend, LogicalLocation, ObjectContext,
        ObjectId, ObjectRole, ParentReference, VerifiedArchiveCipher, ARCHIVE_FORMAT_VERSION,
        SQLITE_PAGE_SIZE,
    },
    archive_v3_extent::{
        upload_extent_tree, ExtentSource, LegacyExtentObjectStaging, EXTENT_BYTES,
    },
    archive_v3_legacy_extent_session::{
        LegacyExtentAttemptId, LegacyExtentSessionBinding, LegacyExtentSessionError,
        LegacyExtentSessionId, LegacyExtentSessionRecord,
    },
    archive_v3_operation::{
        OperationId, OperationLedger, OperationLedgerError, RequestFingerprint,
    },
    archive_v3_witness::{WitnessError, WitnessLease, WitnessRecord},
    crypto::Dek,
    error::EnclaveError,
};

use super::{
    super::{
        authenticate_legacy_source, ExactLegacyWitness, LegacyGcmAad, LegacySourceIdentity,
        PinnedLegacyRangeReader,
    },
    LegacySqliteExtentSource,
};

#[derive(Debug, Error)]
enum CandidateCoordinatorError {
    #[error(transparent)]
    Legacy(#[from] EnclaveError),
    #[error(transparent)]
    Witness(#[from] WitnessError),
    #[error(transparent)]
    Session(#[from] LegacyExtentSessionError),
    #[error(transparent)]
    Ledger(#[from] OperationLedgerError),
    #[error(transparent)]
    Extent(#[from] crate::archive_v3_extent::ExtentTreeError),
    #[error(transparent)]
    Archive(#[from] crate::archive_v3::ArchiveV3Error),
    #[error("legacy extent candidate ledger task became unavailable")]
    LedgerUnavailable,
    #[error("legacy witness changed while staging a candidate")]
    WitnessChanged,
    #[error("legacy archive cipher is not the exact witness registry cipher")]
    CipherBinding,
    #[error("the authenticated legacy SQLite schema would roll back")]
    SchemaRollback,
    #[error("legacy extent attempt is not in a stageable state")]
    AttemptState,
    #[error("durable legacy extent attempt is absent or no longer reconcilable")]
    AttemptMissing,
}

type Result<T> = std::result::Result<T, CandidateCoordinatorError>;

/// Opaque, deliberately non-authoritative confirmation of durable
/// `CandidateReady`.  No root reference or witness-advance capability escapes
/// this private composition.
#[derive(Debug)]
struct CandidateReady;

/// Caller-retained durable-attempt identity.  It is deliberately neither
/// cloneable nor forgeable from raw IDs.  A cancelled borrowed future leaves
/// this handle with any blocking ledger task still attached so reconciliation
/// can determine the exact durable result rather than retrying the attempt.
struct LegacyExtentCandidateAttempt {
    session_id: LegacyExtentSessionId,
    attempt_id: LegacyExtentAttemptId,
    binding: LegacyExtentSessionBinding,
    base_user_schema_version: u32,
    prepare_started: bool,
    stage_started: bool,
    prepare_task: Option<tokio::task::JoinHandle<Result<()>>>,
    persist_task: Option<tokio::task::JoinHandle<Result<()>>>,
    #[cfg(test)]
    persist_gate: Option<Arc<TestBlockingGate>>,
}

#[cfg(test)]
struct TestBlockingGate {
    state: Mutex<(bool, bool)>,
    changed: std::sync::Condvar,
}

#[cfg(test)]
impl TestBlockingGate {
    fn new() -> Self {
        Self {
            state: Mutex::new((false, false)),
            changed: std::sync::Condvar::new(),
        }
    }

    fn block(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn entered(&self) -> bool {
        self.state.lock().unwrap().0
    }

    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

impl LegacyExtentCandidateAttempt {
    fn recovery_handle(&self) -> LegacyExtentRecoveryHandle {
        LegacyExtentRecoveryHandle {
            session_id: self.session_id,
            attempt_id: self.attempt_id,
            binding: self.binding,
        }
    }
}

/// Content-free persisted identity minted only from an exact decoded ledger
/// record or an already-owned live attempt.
struct LegacyExtentRecoveryHandle {
    session_id: LegacyExtentSessionId,
    attempt_id: LegacyExtentAttemptId,
    binding: LegacyExtentSessionBinding,
}

/// Restart-only ledger reconciler. A future inactive caller must hold
/// exclusive ownership for the stable session family while using it.
struct LegacyExtentRestartReconciler {
    connection: Arc<Mutex<Connection>>,
}

enum ReconciledAttempt {
    CandidateReady(CandidateReady),
    Orphaned,
}

/// Every dependency is injected.  In particular, this type cannot construct a
/// GCS reader/backend, a Firestore witness, a runtime cipher/provider, or a
/// database connection.
struct LegacyExtentCandidateCoordinator<'a, R: PinnedLegacyRangeReader> {
    witness: &'a dyn ExactLegacyWitness,
    reader: &'a mut R,
    dek: &'a Dek,
    aad: LegacyGcmAad<'a>,
    source_identity: &'a LegacySourceIdentity,
    cipher: &'a VerifiedArchiveCipher,
    backend: &'a dyn ImmutableObjectBackend,
    connection: Arc<Mutex<Connection>>,
    lease: WitnessLease,
    operation_id: OperationId,
    request_fingerprint: RequestFingerprint,
}

impl<'a, R: PinnedLegacyRangeReader> LegacyExtentCandidateCoordinator<'a, R> {
    /// Authenticate/pin once and derive a caller-retained attempt plan.  No
    /// ledger or immutable object exists yet, so cancellation before return is
    /// not an attempt to reconcile.
    async fn plan_attempt(&mut self) -> Result<LegacyExtentCandidateAttempt> {
        let mut source =
            authenticate_legacy_source(self.reader, self.dek, self.aad, self.source_identity)
                .await?;
        let prebinding = source.binding();
        let plaintext_len = source.plaintext_len();
        let before = self
            .witness
            .read_exact_legacy(self.lease.archive_id())
            .await?;
        Self::validate_cipher(self.cipher, &before)?;
        let binding = LegacyExtentSessionBinding::from_witness(
            &before,
            self.lease,
            self.operation_id,
            self.request_fingerprint,
            prebinding.0,
            plaintext_len,
        )?;
        let base_root = Self::authenticate_base_root(self.backend, self.cipher, &before).await?;
        let header = {
            let mut extents = LegacySqliteExtentSource::new(&mut source)?;
            let mut buffer = zeroize::Zeroizing::new(vec![0u8; EXTENT_BYTES as usize]);
            while extents.next_extent(buffer.as_mut_slice()).await?.is_some() {
                buffer.fill(0);
            }
            buffer.fill(0);
            extents
                .header()
                .ok_or(crate::archive_v3_extent::ExtentTreeError::Source)?
        };
        source.finish().await?.verify_binding(prebinding)?;
        let user_schema_version = u32::from_be_bytes(header.user_version);
        if user_schema_version < base_root.user_schema_version {
            return Err(CandidateCoordinatorError::SchemaRollback);
        }
        let session_id = LegacyExtentSessionId::for_binding(binding)?;
        let attempt_id = LegacyExtentAttemptId::random();
        Ok(LegacyExtentCandidateAttempt {
            session_id,
            attempt_id,
            binding,
            base_user_schema_version: base_root.user_schema_version,
            prepare_started: false,
            stage_started: false,
            prepare_task: None,
            persist_task: None,
            #[cfg(test)]
            persist_gate: None,
        })
    }

    fn start_prepare(&self, attempt: &mut LegacyExtentCandidateAttempt) -> Result<()> {
        if attempt.prepare_started {
            return Err(CandidateCoordinatorError::AttemptState);
        }
        let record = LegacyExtentSessionRecord::prepared(
            attempt.session_id,
            attempt.attempt_id,
            attempt.binding,
        )?;
        attempt.prepare_started = true;
        attempt.prepare_task = Some(spawn_prepare(Arc::clone(&self.connection), record));
        Ok(())
    }

    async fn await_prepare(&self, attempt: &mut LegacyExtentCandidateAttempt) -> Result<()> {
        let Some(task) = attempt.prepare_task.as_mut() else {
            return attempt
                .prepare_started
                .then_some(())
                .ok_or(CandidateCoordinatorError::AttemptState);
        };
        let outcome = task
            .await
            .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)?;
        attempt.prepare_task = None;
        outcome
    }

    async fn stage_attempt(
        &mut self,
        attempt: &mut LegacyExtentCandidateAttempt,
    ) -> Result<CandidateReady> {
        self.await_prepare(attempt).await?;
        if attempt.stage_started {
            return Err(CandidateCoordinatorError::AttemptState);
        }
        attempt.stage_started = true;

        let mut source =
            authenticate_legacy_source(self.reader, self.dek, self.aad, self.source_identity)
                .await?;
        let prebinding = source.binding();
        let plaintext_len = source.plaintext_len();
        if prebinding.0 != attempt.binding.legacy_source_binding()
            || plaintext_len != attempt.binding.plaintext_len()
        {
            return Err(CandidateCoordinatorError::AttemptState);
        }
        let before = self
            .witness
            .read_exact_legacy(self.lease.archive_id())
            .await?;
        Self::validate_cipher(self.cipher, &before)?;
        let expected_binding = LegacyExtentSessionBinding::from_witness(
            &before,
            self.lease,
            self.operation_id,
            self.request_fingerprint,
            prebinding.0,
            plaintext_len,
        )?;
        if expected_binding != attempt.binding {
            return Err(CandidateCoordinatorError::WitnessChanged);
        }
        let base_root = Self::authenticate_base_root(self.backend, self.cipher, &before).await?;
        if base_root.user_schema_version != attempt.base_user_schema_version {
            return Err(CandidateCoordinatorError::WitnessChanged);
        }

        let staging = LegacyExtentObjectStaging::new(
            Arc::clone(&self.connection),
            attempt.session_id,
            attempt.attempt_id,
            attempt.binding,
        );

        let (tree, header) = {
            let mut extents = LegacySqliteExtentSource::new(&mut source)?;
            let tree = upload_extent_tree(
                self.backend,
                self.cipher,
                before.archive_id(),
                before.database_epoch(),
                &mut extents,
                staging.clone(),
            )
            .await?;
            let header = extents
                .header()
                .ok_or(crate::archive_v3_extent::ExtentTreeError::Source)?;
            (tree, header)
        };

        source.finish().await?.verify_binding(prebinding)?;
        drop(source);
        let user_schema_version = u32::from_be_bytes(header.user_version);
        if user_schema_version < base_root.user_schema_version {
            return Err(CandidateCoordinatorError::SchemaRollback);
        }

        let after = self
            .witness
            .read_exact_legacy(self.lease.archive_id())
            .await?;
        if after != before || !after.authorizes_lease(self.lease) {
            return Err(CandidateCoordinatorError::WitnessChanged);
        }

        let root_seq = attempt
            .binding
            .base_root_seq()
            .checked_add(1)
            .ok_or(LegacyExtentSessionError::Malformed("root sequence"))?;
        let root = ArchiveRoot {
            root_seq,
            parent: Some(ParentReference {
                object_id: ObjectId::from_bytes(attempt.binding.base_root_object_id()),
                envelope_hash: attempt.binding.base_root_ciphertext_hash(),
            }),
            database_epoch: DatabaseEpoch::from_bytes(attempt.binding.database_epoch()),
            key_epoch: crate::archive_v3::KeyEpoch::from_bytes(attempt.binding.key_epoch()),
            owner_fencing_epoch: attempt.binding.owner_fence(),
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: plaintext_len,
            user_schema_version,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: Some(tree.root().clone()),
            wal_chain_root: None,
        };
        let context = ObjectContext::new(
            before.archive_id(),
            before.database_epoch(),
            self.cipher.key_epoch(),
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq },
            ObjectId::random(),
            root.parent.clone(),
        )?;
        let envelope = self.cipher.seal(&context, &root.encode()?)?;
        let (root_facts, admission) = staging
            .create_root_and_readback_admitted(self.backend, self.cipher, &tree, &context, envelope)
            .await?;

        attempt.persist_task = Some(spawn_persist(
            Arc::clone(&self.connection),
            attempt.session_id,
            attempt.attempt_id,
            attempt.binding,
            admission,
            root_facts,
            #[cfg(test)]
            attempt.persist_gate.clone(),
        ));
        self.await_persist(attempt).await
    }

    async fn await_persist(
        &self,
        attempt: &mut LegacyExtentCandidateAttempt,
    ) -> Result<CandidateReady> {
        let Some(task) = attempt.persist_task.as_mut() else {
            return Err(CandidateCoordinatorError::AttemptState);
        };
        let outcome = task
            .await
            .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)?;
        attempt.persist_task = None;
        outcome?;
        Ok(CandidateReady)
    }

    async fn reconcile_orphan(
        &self,
        attempt: &mut LegacyExtentCandidateAttempt,
    ) -> Result<ReconciledAttempt> {
        wait_task(&mut attempt.prepare_task).await;
        wait_task(&mut attempt.persist_task).await;
        LegacyExtentRestartReconciler {
            connection: Arc::clone(&self.connection),
        }
        .reconcile(attempt.recovery_handle())
        .await
    }

    fn validate_cipher(cipher: &VerifiedArchiveCipher, witness: &WitnessRecord) -> Result<()> {
        let registry = witness.registry();
        (cipher.archive_id() == witness.archive_id()
            && cipher.key_epoch() == registry.key_epoch()
            && cipher.registry_rotation_generation() == registry.rotation_generation()
            && cipher.registry_object_id() == registry.object_id()
            && cipher.registry_ciphertext_hash() == registry.ciphertext_hash())
        .then_some(())
        .ok_or(CandidateCoordinatorError::CipherBinding)
    }

    async fn authenticate_base_root(
        backend: &dyn ImmutableObjectBackend,
        cipher: &VerifiedArchiveCipher,
        witness: &WitnessRecord,
    ) -> Result<ArchiveRoot> {
        let commitment = witness.root();
        let reference = commitment.root();
        let parent = commitment.parent().map(|parent| ParentReference {
            object_id: parent.object_id(),
            envelope_hash: parent.ciphertext_hash(),
        });
        let context = ObjectContext::new(
            witness.archive_id(),
            witness.database_epoch(),
            witness.registry().key_epoch(),
            ObjectRole::RootV3,
            LogicalLocation::Root {
                root_seq: reference.sequence(),
            },
            reference.object_id(),
            parent.clone(),
        )?;
        let envelope = backend
            .get(&context.object_key())
            .await?
            .ok_or(crate::archive_v3_extent::ExtentTreeError::MissingObject)?;
        if envelope.hash() != reference.ciphertext_hash() {
            return Err(CandidateCoordinatorError::Archive(
                crate::archive_v3::ArchiveV3Error::Authentication,
            ));
        }
        let root = ArchiveRoot::decode(&cipher.open(&context, &envelope)?)?;
        root.validate_for_context(&context)?;
        if root.root_seq != reference.sequence()
            || root.database_epoch != witness.database_epoch()
            || root.key_epoch != witness.registry().key_epoch()
            || root.owner_fencing_epoch != commitment.owner_fencing_epoch()
            || root.parent != parent
        {
            return Err(CandidateCoordinatorError::WitnessChanged);
        }
        Ok(root)
    }
}

impl LegacyExtentRestartReconciler {
    async fn discover(
        &self,
        archive_id: crate::archive_v3::ArchiveId,
        database_epoch: DatabaseEpoch,
        operation_id: OperationId,
    ) -> Result<Vec<LegacyExtentRecoveryHandle>> {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let connection = connection
                .lock()
                .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)?;
            OperationLedger::discover_legacy_extent_session_family(
                &connection,
                *archive_id.as_bytes(),
                *database_epoch.as_bytes(),
                *operation_id.as_bytes(),
            )?
            .into_iter()
            .map(|record| {
                Ok(LegacyExtentRecoveryHandle {
                    session_id: record.session_id(),
                    attempt_id: record.attempt_id(),
                    binding: record.binding(),
                })
            })
            .collect::<Result<Vec<_>>>()
        })
        .await
        .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)?
    }

    async fn reconcile(&self, handle: LegacyExtentRecoveryHandle) -> Result<ReconciledAttempt> {
        let connection = Arc::clone(&self.connection);
        let session_id = handle.session_id;
        let attempt_id = handle.attempt_id;
        let binding = handle.binding;
        let record =
            tokio::task::spawn_blocking(move || -> Result<Option<LegacyExtentSessionRecord>> {
                let connection = connection
                    .lock()
                    .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)?;
                Ok(OperationLedger::load_legacy_extent_session(
                    &connection,
                    session_id,
                    attempt_id,
                )?)
            })
            .await
            .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)??;
        let record = record.ok_or(CandidateCoordinatorError::AttemptMissing)?;
        record.require_binding(binding)?;
        match record.state() {
            crate::archive_v3_legacy_extent_session::LegacyExtentSessionState::CandidateReady => {
                Ok(ReconciledAttempt::CandidateReady(CandidateReady))
            }
            crate::archive_v3_legacy_extent_session::LegacyExtentSessionState::Prepared => {
                orphan_prepared_attempt(
                    Arc::clone(&self.connection),
                    session_id,
                    attempt_id,
                    binding,
                )
                .await?;
                Ok(ReconciledAttempt::Orphaned)
            }
            crate::archive_v3_legacy_extent_session::LegacyExtentSessionState::OrphanPendingGrace => {
                Ok(ReconciledAttempt::Orphaned)
            }
        }
    }
}

fn spawn_prepare(
    connection: Arc<Mutex<Connection>>,
    record: LegacyExtentSessionRecord,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::task::spawn_blocking(move || {
        let mut connection = connection
            .lock()
            .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)?;
        OperationLedger::prepare_legacy_extent_session(&mut connection, &record)?;
        Ok(())
    })
}

fn spawn_persist(
    connection: Arc<Mutex<Connection>>,
    session_id: LegacyExtentSessionId,
    attempt_id: LegacyExtentAttemptId,
    binding: LegacyExtentSessionBinding,
    admission: crate::archive_v3_legacy_extent_session::LegacyExtentRootAdmission,
    root_facts: crate::archive_v3_operation::LegacyExtentObjectFacts,
    #[cfg(test)] gate: Option<Arc<TestBlockingGate>>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        if let Some(gate) = gate {
            gate.block();
        }
        let mut connection = connection
            .lock()
            .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)?;
        OperationLedger::persist_legacy_extent_candidate(
            &mut connection,
            session_id,
            attempt_id,
            binding,
            admission,
            &root_facts,
        )?;
        Ok(())
    })
}

async fn wait_task(task: &mut Option<tokio::task::JoinHandle<Result<()>>>) {
    if let Some(task) = task.as_mut() {
        let _ = task.await;
    }
    *task = None;
}

// Restart/orphan handling deliberately accepts only a persisted exact binding
// and scans ledger pages, never storage listings.  A future reconciler may use
// it only while the exact page count remains within the ledger's fixed attempt
// bound; large-inventory/provider cleanup is explicitly deferred rather than
// silently broadening this inactive converter into a GC path.
async fn orphan_prepared_attempt(
    connection: Arc<Mutex<Connection>>,
    session_id: LegacyExtentSessionId,
    attempt_id: LegacyExtentAttemptId,
    binding: LegacyExtentSessionBinding,
) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut connection = connection
            .lock()
            .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)?;
        let mut cursor = None;
        loop {
            let page = OperationLedger::load_exact_legacy_extent_object_page(
                &connection,
                session_id,
                attempt_id,
                binding,
                cursor,
            )?;
            cursor = page.next_cursor();
            if cursor.is_none() {
                break;
            }
        }
        OperationLedger::orphan_legacy_extent_attempt(
            &mut connection,
            session_id,
            attempt_id,
            binding,
        )?;
        Ok(())
    })
    .await
    .map_err(|_| CandidateCoordinatorError::LedgerUnavailable)?
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    use async_trait::async_trait;
    use rusqlite::params;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        archive_v3::{
            resolve_archive_cipher, ArchiveDek, ArchiveId, ArchivePrefix, ArchiveV3Error,
            CiphertextEnvelope, CreateIfAbsent, EnumerationCursor, EnumerationLimit,
            EnumerationPage, ExactKeyRegistryProvider, InMemoryImmutableBackend, KeyEpoch, KeyKind,
            KeyRegistryContext, KeyRegistryPlaintext, ObjectContext, ObjectKey,
        },
        archive_v3_witness::{
            DeletionState, InMemoryWitness, KeyRegistryReference, MigrationState, RootCommitment,
            RootReference, Witness, WitnessBootstrap,
        },
        legacy_gcm::{
            sealed, LegacyEmptyAad, LegacyGcmAad, LegacyGeneration, LegacyRangeReceipt,
            PinnedLegacyObject,
        },
    };

    const WRAPPED_REGISTRY: &[u8] = b"legacy-extent-coordinator-registry";

    struct FakeExactWitness {
        record: WitnessRecord,
        events: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    #[async_trait]
    impl ExactLegacyWitness for FakeExactWitness {
        async fn read_exact_legacy(
            &self,
            archive_id: ArchiveId,
        ) -> std::result::Result<WitnessRecord, WitnessError> {
            if let Some(events) = &self.events {
                events.lock().unwrap().push("witness_read");
            }
            (self.record.archive_id() == archive_id)
                .then_some(self.record.clone())
                .ok_or(WitnessError::MissingArchive)
        }
    }

    struct FakeReader {
        bytes: Vec<u8>,
        identity: LegacySourceIdentity,
        generation: LegacyGeneration,
        events: Option<Arc<Mutex<Vec<&'static str>>>>,
        pins: usize,
        replace_on_second_pin: Option<Vec<u8>>,
    }

    impl sealed::RangeReader for FakeReader {}

    #[async_trait]
    impl PinnedLegacyRangeReader for FakeReader {
        async fn pin_legacy_object(&mut self) -> crate::error::Result<PinnedLegacyObject> {
            self.pins += 1;
            if self.pins == 2 {
                if let Some(replacement) = self.replace_on_second_pin.take() {
                    self.bytes = replacement;
                }
            }
            if let Some(events) = &self.events {
                events.lock().unwrap().push("source_pin");
            }
            Ok(PinnedLegacyObject::new(
                &self.identity,
                self.generation,
                self.bytes.len() as u64,
            ))
        }

        async fn read_pinned_exact(
            &mut self,
            object: &PinnedLegacyObject,
            offset: u64,
            destination: &mut [u8],
        ) -> crate::error::Result<LegacyRangeReceipt> {
            if let Some(events) = &self.events {
                events.lock().unwrap().push("source_read");
            }
            let start = usize::try_from(offset)
                .map_err(|_| crate::error::EnclaveError::Crypto("test offset".into()))?;
            let end = start
                .checked_add(destination.len())
                .ok_or_else(|| crate::error::EnclaveError::Crypto("test range overflow".into()))?;
            if end > self.bytes.len() {
                return Err(crate::error::EnclaveError::Crypto(
                    "test range unavailable".into(),
                ));
            }
            destination.copy_from_slice(&self.bytes[start..end]);
            Ok(LegacyRangeReceipt::new(
                object.clone(),
                offset,
                destination.len() as u64,
            ))
        }
    }

    struct FakeKeyRegistryProvider {
        object_id: ObjectId,
        plaintext: Vec<u8>,
    }

    struct NoWriteBackend {
        inner: InMemoryImmutableBackend,
        events: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    type GetHook = (usize, Arc<dyn Fn() + Send + Sync>);

    struct FaultBackend {
        inner: InMemoryImmutableBackend,
        creates: AtomicUsize,
        gets: AtomicUsize,
        fail_create: Option<usize>,
        fail_get: Option<usize>,
        on_get: Mutex<Option<GetHook>>,
    }

    #[async_trait]
    impl ImmutableObjectBackend for FaultBackend {
        async fn create_if_absent(
            &self,
            key: ObjectKey,
            value: CiphertextEnvelope,
        ) -> std::result::Result<CreateIfAbsent, ArchiveV3Error> {
            let call = self.creates.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_create == Some(call) {
                return Err(ArchiveV3Error::Unavailable);
            }
            self.inner.create_if_absent(key, value).await
        }

        async fn get(
            &self,
            key: &ObjectKey,
        ) -> std::result::Result<Option<CiphertextEnvelope>, ArchiveV3Error> {
            let call = self.gets.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_get == Some(call) {
                return Err(ArchiveV3Error::Unavailable);
            }
            let callback = self
                .on_get
                .lock()
                .unwrap()
                .as_ref()
                .filter(|(at, _)| *at == call)
                .map(|(_, callback)| Arc::clone(callback));
            if let Some(callback) = callback {
                callback();
            }
            self.inner.get(key).await
        }

        async fn enumerate(
            &self,
            prefix: &ArchivePrefix,
            cursor: Option<&EnumerationCursor>,
            limit: EnumerationLimit,
        ) -> std::result::Result<EnumerationPage, ArchiveV3Error> {
            self.inner.enumerate(prefix, cursor, limit).await
        }

        async fn delete_exact(&self, key: &ObjectKey) -> std::result::Result<bool, ArchiveV3Error> {
            self.inner.delete_exact(key).await
        }
    }

    #[derive(Clone, Copy)]
    enum BaseFault {
        None,
        Missing,
        HashSubstitution,
    }

    #[derive(Clone, Copy)]
    enum PreWitnessFault {
        None,
        Tombstoned,
        Migrated,
        StaleLease,
    }

    #[async_trait]
    impl ImmutableObjectBackend for NoWriteBackend {
        async fn create_if_absent(
            &self,
            _key: ObjectKey,
            _value: CiphertextEnvelope,
        ) -> std::result::Result<CreateIfAbsent, ArchiveV3Error> {
            panic!("preflight must not create immutable objects")
        }

        async fn get(
            &self,
            key: &ObjectKey,
        ) -> std::result::Result<Option<CiphertextEnvelope>, ArchiveV3Error> {
            if let Some(events) = &self.events {
                events.lock().unwrap().push("base_get");
            }
            self.inner.get(key).await
        }

        async fn enumerate(
            &self,
            _prefix: &ArchivePrefix,
            _cursor: Option<&EnumerationCursor>,
            _limit: EnumerationLimit,
        ) -> std::result::Result<EnumerationPage, ArchiveV3Error> {
            panic!("preflight must not enumerate immutable objects")
        }

        async fn delete_exact(
            &self,
            _key: &ObjectKey,
        ) -> std::result::Result<bool, ArchiveV3Error> {
            panic!("preflight must not delete immutable objects")
        }
    }

    #[async_trait]
    impl ExactKeyRegistryProvider for FakeKeyRegistryProvider {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            destination: &mut [u8],
        ) -> std::result::Result<usize, ArchiveV3Error> {
            if object_id != self.object_id {
                return Err(ArchiveV3Error::InvalidContext);
            }
            destination[..WRAPPED_REGISTRY.len()].copy_from_slice(WRAPPED_REGISTRY);
            Ok(WRAPPED_REGISTRY.len())
        }

        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            wrapped: &[u8],
            destination: &mut [u8],
        ) -> std::result::Result<usize, ArchiveV3Error> {
            if wrapped != WRAPPED_REGISTRY {
                return Err(ArchiveV3Error::InvalidContext);
            }
            destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            Ok(self.plaintext.len())
        }
    }

    fn sqlite_plaintext() -> Vec<u8> {
        let mut bytes = vec![0u8; SQLITE_PAGE_SIZE as usize];
        bytes[..16].copy_from_slice(b"SQLite format 3\0");
        bytes[16..18].copy_from_slice(&(SQLITE_PAGE_SIZE as u16).to_be_bytes());
        bytes[18] = 1;
        bytes[19] = 1;
        bytes[21..24].copy_from_slice(&[64, 32, 32]);
        bytes[24..28].copy_from_slice(&9u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
        bytes[44..48].copy_from_slice(&4u32.to_be_bytes());
        bytes[56..60].copy_from_slice(&1u32.to_be_bytes());
        bytes[60..64].copy_from_slice(&73u32.to_be_bytes());
        bytes[92..96].copy_from_slice(&9u32.to_be_bytes());
        bytes
    }

    fn legacy_envelope(plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&[7; 32]).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&[3; 12]),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .unwrap();
        let mut result = vec![3; 12];
        result.extend_from_slice(&encrypted);
        result
    }

    async fn verified_cipher(
        archive_id: ArchiveId,
        key_epoch: KeyEpoch,
        registry: KeyRegistryReference,
    ) -> VerifiedArchiveCipher {
        let context = KeyRegistryContext::with_rotation_generation(
            archive_id,
            KeyKind::Archive,
            key_epoch,
            registry.rotation_generation(),
        );
        let provider = FakeKeyRegistryProvider {
            object_id: registry.object_id(),
            plaintext: KeyRegistryPlaintext::encode_archive(
                &context,
                &ArchiveDek::from_bytes([11; 32]),
            )
            .unwrap()
            .to_vec(),
        };
        resolve_archive_cipher(
            &context,
            registry.object_id(),
            registry.ciphertext_hash(),
            &provider,
        )
        .await
        .unwrap()
    }

    struct StageFixture {
        cipher: VerifiedArchiveCipher,
        backend: FaultBackend,
        witness: FakeExactWitness,
        reader: FakeReader,
        identity: LegacySourceIdentity,
        connection: Arc<Mutex<Connection>>,
        lease: WitnessLease,
    }

    async fn stage_fixture(fail_create: Option<usize>, fail_get: Option<usize>) -> StageFixture {
        let archive_id = ArchiveId::from_bytes([71; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([72; 16]);
        let key_epoch = KeyEpoch::from_bytes([73; 16]);
        let registry = KeyRegistryReference::new(
            key_epoch,
            1,
            ObjectId::from_bytes([74; 16]),
            Sha256::digest(WRAPPED_REGISTRY).into(),
        );
        let cipher = verified_cipher(archive_id, key_epoch, registry).await;
        let inner = InMemoryImmutableBackend::new();
        let base_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ObjectId::from_bytes([75; 16]),
            None,
        )
        .unwrap();
        let base_root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: 0,
            user_schema_version: 70,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_chain_root: None,
        };
        let base_envelope = cipher
            .seal(&base_context, &base_root.encode().unwrap())
            .unwrap();
        inner
            .create_if_absent(base_context.object_key(), base_envelope.clone())
            .await
            .unwrap();
        let backend = FaultBackend {
            inner,
            creates: AtomicUsize::new(0),
            gets: AtomicUsize::new(0),
            fail_create,
            fail_get,
            on_get: Mutex::new(None),
        };
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(
                    database_epoch,
                    key_epoch,
                    RootReference::new(0, base_context.object_id(), base_envelope.hash()),
                ),
                registry,
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(
                archive_id,
                database_epoch,
                key_epoch,
                ObjectId::from_bytes([76; 16]),
                60,
            )
            .unwrap();
        let identity = LegacySourceIdentity::new(b"legacy-stage-fault-test").unwrap();
        let reader = FakeReader {
            bytes: legacy_envelope(&sqlite_plaintext()),
            identity: identity.clone(),
            generation: LegacyGeneration::new(1).unwrap(),
            events: None,
            pins: 0,
            replace_on_second_pin: None,
        };
        let connection = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        OperationLedger::initialize(&connection.lock().unwrap()).unwrap();
        StageFixture {
            cipher,
            backend,
            witness: FakeExactWitness {
                record: witness.read_current(archive_id).unwrap().unwrap(),
                events: None,
            },
            reader,
            identity,
            connection,
            lease,
        }
    }

    async fn preflight_only(
        plaintext: Vec<u8>,
        base_schema: u32,
        base_fault: BaseFault,
        wrong_cipher: bool,
        prewitness_fault: PreWitnessFault,
    ) -> (
        Result<LegacyExtentCandidateAttempt>,
        Arc<Mutex<Connection>>,
        Arc<Mutex<Vec<&'static str>>>,
    ) {
        let archive_id = ArchiveId::from_bytes([41; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([42; 16]);
        let key_epoch = KeyEpoch::from_bytes([43; 16]);
        let registry = KeyRegistryReference::new(
            key_epoch,
            1,
            ObjectId::from_bytes([44; 16]),
            Sha256::digest(WRAPPED_REGISTRY).into(),
        );
        let cipher = verified_cipher(archive_id, key_epoch, registry).await;
        let inner = InMemoryImmutableBackend::new();
        let context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ObjectId::from_bytes([45; 16]),
            None,
        )
        .unwrap();
        let root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: 0,
            user_schema_version: base_schema,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_chain_root: None,
        };
        let envelope = cipher.seal(&context, &root.encode().unwrap()).unwrap();
        if !matches!(base_fault, BaseFault::Missing) {
            inner
                .create_if_absent(context.object_key(), envelope.clone())
                .await
                .unwrap();
        }
        let witness_hash = if matches!(base_fault, BaseFault::HashSubstitution) {
            [99; 32]
        } else {
            envelope.hash()
        };
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(
                    database_epoch,
                    key_epoch,
                    RootReference::new(0, context.object_id(), witness_hash),
                ),
                registry,
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(
                archive_id,
                database_epoch,
                key_epoch,
                ObjectId::from_bytes([46; 16]),
                60,
            )
            .unwrap();
        if matches!(prewitness_fault, PreWitnessFault::StaleLease) {
            witness.revoke_lease(lease).unwrap();
            witness
                .acquire_lease(
                    archive_id,
                    database_epoch,
                    key_epoch,
                    ObjectId::from_bytes([46; 16]),
                    60,
                )
                .unwrap();
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        let record = witness.read_current(archive_id).unwrap().unwrap();
        let record = match prewitness_fault {
            PreWitnessFault::None => record,
            PreWitnessFault::Tombstoned => record.with_deletion_for_test(DeletionState::Tombstoned),
            PreWitnessFault::Migrated => {
                record.with_migration_for_test(MigrationState::ShadowExtents)
            }
            PreWitnessFault::StaleLease => record,
        };
        let exact_witness = FakeExactWitness {
            record,
            events: Some(Arc::clone(&events)),
        };
        let identity = LegacySourceIdentity::new(b"legacy-preflight-order-test").unwrap();
        let mut reader = FakeReader {
            bytes: legacy_envelope(&plaintext),
            identity: identity.clone(),
            generation: LegacyGeneration::new(1).unwrap(),
            events: Some(Arc::clone(&events)),
            pins: 0,
            replace_on_second_pin: None,
        };
        let connection = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        OperationLedger::initialize(&connection.lock().unwrap()).unwrap();
        let backend = NoWriteBackend {
            inner,
            events: Some(Arc::clone(&events)),
        };
        let wrong_registry = KeyRegistryReference::new(
            key_epoch,
            1,
            ObjectId::from_bytes([49; 16]),
            Sha256::digest(WRAPPED_REGISTRY).into(),
        );
        let wrong = if wrong_cipher {
            Some(verified_cipher(ArchiveId::from_bytes([50; 16]), key_epoch, wrong_registry).await)
        } else {
            None
        };
        let mut coordinator = LegacyExtentCandidateCoordinator {
            witness: &exact_witness,
            reader: &mut reader,
            dek: &Dek([7; 32]),
            aad: LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            source_identity: &identity,
            cipher: wrong.as_ref().unwrap_or(&cipher),
            backend: &backend,
            connection: Arc::clone(&connection),
            lease,
            operation_id: OperationId::from_bytes([47; 16]),
            request_fingerprint: RequestFingerprint::from_bytes([48; 32]),
        };
        (coordinator.plan_attempt().await, connection, events)
    }

    #[tokio::test]
    async fn bad_header_and_schema_rollback_precede_prepare_and_provider_writes() {
        let mut bad_header = sqlite_plaintext();
        bad_header[0] ^= 1;
        for (plaintext, base_schema, expected_rollback) in
            [(bad_header, 0, false), (sqlite_plaintext(), 74, true)]
        {
            let (result, connection, _) = preflight_only(
                plaintext,
                base_schema,
                BaseFault::None,
                false,
                PreWitnessFault::None,
            )
            .await;
            if expected_rollback {
                assert!(matches!(
                    result,
                    Err(CandidateCoordinatorError::SchemaRollback)
                ));
            } else {
                assert!(matches!(result, Err(CandidateCoordinatorError::Extent(_))));
            }
            let count: i64 = connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_legacy_extent_sessions",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
        }
    }

    #[tokio::test]
    async fn missing_or_substituted_base_root_fails_before_prepare_or_writes() {
        for fault in [BaseFault::Missing, BaseFault::HashSubstitution] {
            let (result, connection, _) =
                preflight_only(sqlite_plaintext(), 70, fault, false, PreWitnessFault::None).await;
            assert!(result.is_err());
            let count: i64 = connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM archive_v3_legacy_extent_sessions",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
        }
    }

    #[tokio::test]
    async fn lifecycle_and_cipher_validation_precede_base_root_get() {
        let (result, connection, events) = preflight_only(
            sqlite_plaintext(),
            70,
            BaseFault::None,
            true,
            PreWitnessFault::None,
        )
        .await;
        assert!(matches!(
            result,
            Err(CandidateCoordinatorError::CipherBinding)
        ));
        {
            let events = events.lock().unwrap();
            let witness = events
                .iter()
                .position(|event| *event == "witness_read")
                .unwrap();
            assert!(events[..witness].contains(&"source_read"));
            assert!(!events.contains(&"base_get"));
        }
        let count: i64 = connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM archive_v3_legacy_extent_sessions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);

        for fault in [
            PreWitnessFault::Tombstoned,
            PreWitnessFault::Migrated,
            PreWitnessFault::StaleLease,
        ] {
            let (result, _, events) =
                preflight_only(sqlite_plaintext(), 70, BaseFault::None, false, fault).await;
            assert!(matches!(result, Err(CandidateCoordinatorError::Session(_))));
            assert!(!events.lock().unwrap().contains(&"base_get"));
        }

        let (result, _, events) = preflight_only(
            sqlite_plaintext(),
            70,
            BaseFault::None,
            false,
            PreWitnessFault::None,
        )
        .await;
        assert!(result.is_ok());
        let events = events.lock().unwrap();
        let witness = events
            .iter()
            .position(|event| *event == "witness_read")
            .unwrap();
        let base_get = events
            .iter()
            .position(|event| *event == "base_get")
            .unwrap();
        assert!(witness < base_get);
    }

    #[tokio::test]
    async fn source_mutation_between_preflight_and_upload_is_orphaned() {
        let archive_id = ArchiveId::from_bytes([61; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([62; 16]);
        let key_epoch = KeyEpoch::from_bytes([63; 16]);
        let registry = KeyRegistryReference::new(
            key_epoch,
            1,
            ObjectId::from_bytes([64; 16]),
            Sha256::digest(WRAPPED_REGISTRY).into(),
        );
        let cipher = verified_cipher(archive_id, key_epoch, registry).await;
        let backend = InMemoryImmutableBackend::new();
        let base_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ObjectId::from_bytes([65; 16]),
            None,
        )
        .unwrap();
        let base_root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: 0,
            user_schema_version: 70,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_chain_root: None,
        };
        let base_envelope = cipher
            .seal(&base_context, &base_root.encode().unwrap())
            .unwrap();
        backend
            .create_if_absent(base_context.object_key(), base_envelope.clone())
            .await
            .unwrap();
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(
                    database_epoch,
                    key_epoch,
                    RootReference::new(0, base_context.object_id(), base_envelope.hash()),
                ),
                registry,
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(
                archive_id,
                database_epoch,
                key_epoch,
                ObjectId::from_bytes([66; 16]),
                60,
            )
            .unwrap();
        let async_witness = FakeExactWitness {
            record: witness.read_current(archive_id).unwrap().unwrap(),
            events: None,
        };
        let identity = LegacySourceIdentity::new(b"legacy-source-mutation-test").unwrap();
        let mut changed = sqlite_plaintext();
        changed[60..64].copy_from_slice(&74u32.to_be_bytes());
        let mut reader = FakeReader {
            bytes: legacy_envelope(&sqlite_plaintext()),
            identity: identity.clone(),
            generation: LegacyGeneration::new(1).unwrap(),
            events: None,
            pins: 0,
            replace_on_second_pin: Some(legacy_envelope(&changed)),
        };
        let connection = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        OperationLedger::initialize(&connection.lock().unwrap()).unwrap();
        let mut coordinator = LegacyExtentCandidateCoordinator {
            witness: &async_witness,
            reader: &mut reader,
            dek: &Dek([7; 32]),
            aad: LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            source_identity: &identity,
            cipher: &cipher,
            backend: &backend,
            connection: Arc::clone(&connection),
            lease,
            operation_id: OperationId::from_bytes([67; 16]),
            request_fingerprint: RequestFingerprint::from_bytes([68; 32]),
        };
        let mut attempt = coordinator.plan_attempt().await.unwrap();
        coordinator.start_prepare(&mut attempt).unwrap();
        assert!(matches!(
            coordinator.stage_attempt(&mut attempt).await,
            Err(CandidateCoordinatorError::AttemptState)
        ));
        assert!(matches!(
            coordinator.reconcile_orphan(&mut attempt).await.unwrap(),
            ReconciledAttempt::Orphaned
        ));
    }

    #[tokio::test]
    async fn reserve_materialize_and_root_provider_failures_reconcile_to_orphan() {
        // One-page upload order after the two base-root gets is:
        // extent create/get, leaf-node create/get, root create/get.
        for (fail_create, fail_get) in [
            (Some(1), None), // extent was reserved, create failed
            (None, Some(3)), // extent create succeeded, readback/materialize failed
            (Some(3), None), // root was reserved, create failed
            (None, Some(5)), // root create succeeded, exact readback failed
        ] {
            let mut fixture = stage_fixture(fail_create, fail_get).await;
            let mut coordinator = LegacyExtentCandidateCoordinator {
                witness: &fixture.witness,
                reader: &mut fixture.reader,
                dek: &Dek([7; 32]),
                aad: LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
                source_identity: &fixture.identity,
                cipher: &fixture.cipher,
                backend: &fixture.backend,
                connection: Arc::clone(&fixture.connection),
                lease: fixture.lease,
                operation_id: OperationId::from_bytes([77; 16]),
                request_fingerprint: RequestFingerprint::from_bytes([78; 32]),
            };
            let mut attempt = coordinator.plan_attempt().await.unwrap();
            coordinator.start_prepare(&mut attempt).unwrap();
            assert!(coordinator.stage_attempt(&mut attempt).await.is_err());
            assert!(matches!(
                coordinator.reconcile_orphan(&mut attempt).await.unwrap(),
                ReconciledAttempt::Orphaned
            ));
            let state: i64 = fixture
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT state FROM archive_v3_legacy_extent_sessions",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(state, 3);
        }
    }

    #[tokio::test]
    async fn reserve_and_materialize_ledger_failures_reconcile_idempotently() {
        // Orphaning after prepare makes the first exact reservation fail.
        let mut fixture = stage_fixture(None, None).await;
        let mut coordinator = LegacyExtentCandidateCoordinator {
            witness: &fixture.witness,
            reader: &mut fixture.reader,
            dek: &Dek([7; 32]),
            aad: LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            source_identity: &fixture.identity,
            cipher: &fixture.cipher,
            backend: &fixture.backend,
            connection: Arc::clone(&fixture.connection),
            lease: fixture.lease,
            operation_id: OperationId::from_bytes([81; 16]),
            request_fingerprint: RequestFingerprint::from_bytes([82; 32]),
        };
        let mut attempt = coordinator.plan_attempt().await.unwrap();
        coordinator.start_prepare(&mut attempt).unwrap();
        coordinator.await_prepare(&mut attempt).await.unwrap();
        OperationLedger::orphan_legacy_extent_attempt(
            &mut fixture.connection.lock().unwrap(),
            attempt.session_id,
            attempt.attempt_id,
            attempt.binding,
        )
        .unwrap();
        assert!(coordinator.stage_attempt(&mut attempt).await.is_err());
        assert!(matches!(
            coordinator.reconcile_orphan(&mut attempt).await.unwrap(),
            ReconciledAttempt::Orphaned
        ));

        // Orphan exactly after extent readback but before materialization.
        let mut fixture = stage_fixture(None, None).await;
        let mut coordinator = LegacyExtentCandidateCoordinator {
            witness: &fixture.witness,
            reader: &mut fixture.reader,
            dek: &Dek([7; 32]),
            aad: LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            source_identity: &fixture.identity,
            cipher: &fixture.cipher,
            backend: &fixture.backend,
            connection: Arc::clone(&fixture.connection),
            lease: fixture.lease,
            operation_id: OperationId::from_bytes([83; 16]),
            request_fingerprint: RequestFingerprint::from_bytes([84; 32]),
        };
        let mut attempt = coordinator.plan_attempt().await.unwrap();
        coordinator.start_prepare(&mut attempt).unwrap();
        coordinator.await_prepare(&mut attempt).await.unwrap();
        let connection = Arc::clone(&fixture.connection);
        let session_id = attempt.session_id;
        let attempt_id = attempt.attempt_id;
        let binding = attempt.binding;
        *fixture.backend.on_get.lock().unwrap() = Some((
            3,
            Arc::new(move || {
                OperationLedger::orphan_legacy_extent_attempt(
                    &mut connection.lock().unwrap(),
                    session_id,
                    attempt_id,
                    binding,
                )
                .unwrap();
            }),
        ));
        assert!(coordinator.stage_attempt(&mut attempt).await.is_err());
        assert!(matches!(
            coordinator.reconcile_orphan(&mut attempt).await.unwrap(),
            ReconciledAttempt::Orphaned
        ));
    }

    #[tokio::test]
    async fn cancellation_at_persist_is_resolved_as_candidate_ready() {
        let mut fixture = stage_fixture(None, None).await;
        let mut coordinator = LegacyExtentCandidateCoordinator {
            witness: &fixture.witness,
            reader: &mut fixture.reader,
            dek: &Dek([7; 32]),
            aad: LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            source_identity: &fixture.identity,
            cipher: &fixture.cipher,
            backend: &fixture.backend,
            connection: Arc::clone(&fixture.connection),
            lease: fixture.lease,
            operation_id: OperationId::from_bytes([79; 16]),
            request_fingerprint: RequestFingerprint::from_bytes([80; 32]),
        };
        let mut attempt = coordinator.plan_attempt().await.unwrap();
        coordinator.start_prepare(&mut attempt).unwrap();
        let gate = Arc::new(TestBlockingGate::new());
        attempt.persist_gate = Some(Arc::clone(&gate));
        let mut future = Box::pin(coordinator.stage_attempt(&mut attempt));
        while !gate.entered() {
            tokio::select! {
                result = &mut future => panic!("persist unexpectedly completed: {result:?}"),
                () = tokio::task::yield_now() => {}
            }
        }
        drop(future);
        gate.release();
        assert!(matches!(
            coordinator.reconcile_orphan(&mut attempt).await.unwrap(),
            ReconciledAttempt::CandidateReady(_)
        ));
    }

    #[tokio::test]
    async fn durable_candidate_is_exact_extent_only_root() {
        let archive_id = ArchiveId::from_bytes([1; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([2; 16]);
        let key_epoch = KeyEpoch::from_bytes([3; 16]);
        let registry = KeyRegistryReference::new(
            key_epoch,
            1,
            ObjectId::from_bytes([4; 16]),
            Sha256::digest(WRAPPED_REGISTRY).into(),
        );
        let cipher = verified_cipher(archive_id, key_epoch, registry).await;
        let backend = InMemoryImmutableBackend::new();
        let base_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ObjectId::from_bytes([6; 16]),
            None,
        )
        .unwrap();
        let base_root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch,
            key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            logical_file_length: 0,
            user_schema_version: 70,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_segment_count: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_chain_root: None,
        };
        let base_envelope = cipher
            .seal(&base_context, &base_root.encode().unwrap())
            .unwrap();
        backend
            .create_if_absent(base_context.object_key(), base_envelope.clone())
            .await
            .unwrap();
        let base = RootReference::new(0, base_context.object_id(), base_envelope.hash());
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(database_epoch, key_epoch, base),
                registry,
            ))
            .unwrap();
        let lease = witness
            .acquire_lease(
                archive_id,
                database_epoch,
                key_epoch,
                ObjectId::from_bytes([8; 16]),
                60,
            )
            .unwrap();
        let async_witness = FakeExactWitness {
            record: witness.read_current(archive_id).unwrap().unwrap(),
            events: None,
        };
        let source_identity = LegacySourceIdentity::new(b"legacy-extent-coordinator-test").unwrap();
        let mut reader = FakeReader {
            bytes: legacy_envelope(&sqlite_plaintext()),
            identity: source_identity.clone(),
            generation: LegacyGeneration::new(1).unwrap(),
            events: None,
            pins: 0,
            replace_on_second_pin: None,
        };
        let connection = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        OperationLedger::initialize(&connection.lock().unwrap()).unwrap();

        let mut coordinator = LegacyExtentCandidateCoordinator {
            witness: &async_witness,
            reader: &mut reader,
            dek: &Dek([7; 32]),
            aad: LegacyGcmAad::Empty(LegacyEmptyAad::Sqlite),
            source_identity: &source_identity,
            cipher: &cipher,
            backend: &backend,
            connection: Arc::clone(&connection),
            lease,
            operation_id: OperationId::from_bytes([9; 16]),
            request_fingerprint: RequestFingerprint::from_bytes([10; 32]),
        };
        let mut attempt = coordinator.plan_attempt().await.unwrap();
        coordinator.start_prepare(&mut attempt).unwrap();
        coordinator.stage_attempt(&mut attempt).await.unwrap();
        assert!(matches!(
            LegacyExtentRestartReconciler {
                connection: Arc::clone(&connection),
            }
            .reconcile(attempt.recovery_handle())
            .await
            .unwrap(),
            ReconciledAttempt::CandidateReady(_)
        ));

        let (aad, object_key): (Vec<u8>, String) = {
            let connection = connection.lock().unwrap();
            let state: i64 = connection
                .query_row(
                    "SELECT state FROM archive_v3_legacy_extent_sessions",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(state, 2, "only CandidateReady is persisted");
            connection
                .query_row(
                    "SELECT context_aad, object_key FROM archive_v3_legacy_extent_objects WHERE object_role = ?",
                    params![ObjectRole::RootV3 as i64],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap()
        };
        let context = ObjectContext::decode_canonical_aad(&aad).unwrap();
        assert_eq!(context.role(), ObjectRole::RootV3);
        assert_eq!(context.object_key().as_str(), object_key);
        let envelope: CiphertextEnvelope =
            backend.get(&context.object_key()).await.unwrap().unwrap();
        let root = ArchiveRoot::decode(&cipher.open(&context, &envelope).unwrap()).unwrap();
        assert_eq!(root.root_seq, 1);
        assert_eq!(root.parent.as_ref().unwrap().object_id, base.object_id());
        assert_eq!(
            root.parent.as_ref().unwrap().envelope_hash,
            base.ciphertext_hash()
        );
        assert_eq!(root.database_epoch, database_epoch);
        assert_eq!(root.key_epoch, key_epoch);
        assert_eq!(root.owner_fencing_epoch, lease.fencing_epoch());
        assert_eq!(root.sqlite_page_size, SQLITE_PAGE_SIZE);
        assert_eq!(root.logical_file_length, u64::from(SQLITE_PAGE_SIZE));
        assert_eq!(root.user_schema_version, 73);
        assert_eq!(root.storage_format_version, ARCHIVE_FORMAT_VERSION);
        assert_eq!((root.wal_generation, root.wal_segment_count), (0, 0));
        assert!(root.checkpoint_root.is_none());
        assert!(root.wal_chain_root.is_none());
        assert!(root.extent_tree_root.is_some());
    }

    #[tokio::test]
    async fn restart_ignores_changed_root_registry_lease_migration_and_deletion_by_accepting_no_witness(
    ) {
        let connection = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        OperationLedger::initialize(&connection.lock().unwrap()).unwrap();
        let binding = LegacyExtentSessionBinding::fixture_for_test(
            [21; 16], [22; 16], [23; 16], [24; 16], [25; 32],
        );
        let session_id = LegacyExtentSessionId::for_binding(binding).unwrap();
        let attempt_id = LegacyExtentAttemptId::from_bytes_for_test([26; 16]);
        let record = LegacyExtentSessionRecord::prepared(session_id, attempt_id, binding).unwrap();
        OperationLedger::prepare_legacy_extent_session(&mut connection.lock().unwrap(), &record)
            .unwrap();

        let reconciler = LegacyExtentRestartReconciler {
            connection: Arc::clone(&connection),
        };
        let family = reconciler
            .discover(
                ArchiveId::from_bytes(binding.archive_id()),
                DatabaseEpoch::from_bytes(binding.database_epoch()),
                OperationId::from_bytes(binding.operation_id()),
            )
            .await
            .unwrap();
        assert_eq!(family.len(), 1);
        assert!(matches!(
            reconciler
                .reconcile(family.into_iter().next().unwrap())
                .await
                .unwrap(),
            ReconciledAttempt::Orphaned
        ));
        let family = reconciler
            .discover(
                ArchiveId::from_bytes(binding.archive_id()),
                DatabaseEpoch::from_bytes(binding.database_epoch()),
                OperationId::from_bytes(binding.operation_id()),
            )
            .await
            .unwrap();
        assert!(matches!(
            reconciler
                .reconcile(family.into_iter().next().unwrap())
                .await
                .unwrap(),
            ReconciledAttempt::Orphaned
        ));
    }

    #[tokio::test]
    async fn retained_prepare_task_is_joined_before_cancel_reconciliation() {
        let connection = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        OperationLedger::initialize(&connection.lock().unwrap()).unwrap();
        let binding = LegacyExtentSessionBinding::fixture_for_test(
            [51; 16], [52; 16], [53; 16], [54; 16], [55; 32],
        );
        let session_id = LegacyExtentSessionId::for_binding(binding).unwrap();
        let attempt_id = LegacyExtentAttemptId::from_bytes_for_test([56; 16]);
        let record = LegacyExtentSessionRecord::prepared(session_id, attempt_id, binding).unwrap();
        let mut attempt = LegacyExtentCandidateAttempt {
            session_id,
            attempt_id,
            binding,
            base_user_schema_version: 0,
            prepare_started: true,
            stage_started: false,
            prepare_task: Some(spawn_prepare(Arc::clone(&connection), record)),
            persist_task: None,
            persist_gate: None,
        };
        let reconciler = LegacyExtentRestartReconciler {
            connection: Arc::clone(&connection),
        };
        wait_task(&mut attempt.prepare_task).await;
        assert!(matches!(
            reconciler
                .reconcile(attempt.recovery_handle())
                .await
                .unwrap(),
            ReconciledAttempt::Orphaned
        ));
    }

    #[test]
    fn orphaned_attempt_allows_retry_but_seventeenth_attempt_fails_closed() {
        let mut connection = Connection::open_in_memory().unwrap();
        OperationLedger::initialize(&connection).unwrap();
        let binding = LegacyExtentSessionBinding::fixture_for_test(
            [31; 16], [32; 16], [33; 16], [34; 16], [35; 32],
        );
        let session_id = LegacyExtentSessionId::for_binding(binding).unwrap();
        for value in 1..=16 {
            let attempt_id = LegacyExtentAttemptId::from_bytes_for_test([value; 16]);
            let record =
                LegacyExtentSessionRecord::prepared(session_id, attempt_id, binding).unwrap();
            OperationLedger::prepare_legacy_extent_session(&mut connection, &record).unwrap();
            OperationLedger::orphan_legacy_extent_attempt(
                &mut connection,
                session_id,
                attempt_id,
                binding,
            )
            .unwrap();
        }
        let attempt_id = LegacyExtentAttemptId::from_bytes_for_test([17; 16]);
        let record = LegacyExtentSessionRecord::prepared(session_id, attempt_id, binding).unwrap();
        assert!(matches!(
            OperationLedger::prepare_legacy_extent_session(&mut connection, &record),
            Err(OperationLedgerError::TooLarge(
                "legacy extent session attempts"
            ))
        ));
        assert_eq!(
            OperationLedger::discover_legacy_extent_session_family(
                &connection,
                binding.archive_id(),
                binding.database_epoch(),
                binding.operation_id(),
            )
            .unwrap()
            .len(),
            16
        );
    }

    #[test]
    fn injected_corrupt_or_seventeen_row_restart_family_fails_closed() {
        let binding = LegacyExtentSessionBinding::fixture_for_test(
            [81; 16], [82; 16], [83; 16], [84; 16], [85; 32],
        );
        let session_id = LegacyExtentSessionId::for_binding(binding).unwrap();

        let mut corrupt = Connection::open_in_memory().unwrap();
        OperationLedger::initialize(&corrupt).unwrap();
        let attempt_id = LegacyExtentAttemptId::from_bytes_for_test([86; 16]);
        let record = LegacyExtentSessionRecord::prepared(session_id, attempt_id, binding).unwrap();
        OperationLedger::prepare_legacy_extent_session(&mut corrupt, &record).unwrap();
        corrupt
            .execute(
                "UPDATE archive_v3_legacy_extent_sessions SET archive_id = ?",
                params![[99u8; 16].as_slice()],
            )
            .unwrap();
        assert!(matches!(
            OperationLedger::discover_legacy_extent_session_family(
                &corrupt,
                binding.archive_id(),
                binding.database_epoch(),
                binding.operation_id(),
            ),
            Err(OperationLedgerError::Corrupt)
        ));

        let injected = Connection::open_in_memory().unwrap();
        OperationLedger::initialize(&injected).unwrap();
        for value in 1..=17u8 {
            let attempt_id = LegacyExtentAttemptId::from_bytes_for_test([value; 16]);
            let record =
                LegacyExtentSessionRecord::prepared(session_id, attempt_id, binding).unwrap();
            let encoded = record.encode().unwrap();
            injected
                .execute(
                    "INSERT INTO archive_v3_legacy_extent_sessions
                     (session_id,attempt_id,archive_id,database_epoch,operation_id,request_fingerprint,state,record)
                     VALUES (?,?,?,?,?,?,?,?)",
                    params![
                        session_id.as_bytes().as_slice(),
                        attempt_id.as_bytes().as_slice(),
                        binding.archive_id().as_slice(),
                        binding.database_epoch().as_slice(),
                        binding.operation_id().as_slice(),
                        binding.request_fingerprint().as_slice(),
                        1i64,
                        encoded.as_slice(),
                    ],
                )
                .unwrap();
        }
        assert!(matches!(
            OperationLedger::discover_legacy_extent_session_family(
                &injected,
                binding.archive_id(),
                binding.database_epoch(),
                binding.operation_id(),
            ),
            Err(OperationLedgerError::TooLarge(
                "legacy extent session attempts"
            ))
        ));
    }
}
