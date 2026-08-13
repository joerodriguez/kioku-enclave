#![allow(
    dead_code,
    reason = "inactive ADR-0022 archive bootstrap seam is compiled and fake-tested before authority wiring"
)]

//! Restart-safe, inactive archive-v3 genesis coordination.
//!
//! This module deliberately owns no provider construction. A control-plane
//! lifecycle ledger supplies a durable reservation and the exact already-
//! prepared immutable bytes. Construction is synchronous and performs no
//! provider I/O; the injected backend is used only by [`ArchiveGenesis::resolve`].
//! In particular, this is not a Store, VFS, route, credential, or feature-flag
//! integration.
//!
//! `resolve` requires a fresh revision-bound create admission before each
//! registry, root, or witness provider request. It persists the exact witness
//! bytes before witness create, reconciles ambiguity through exact readback,
//! and performs a final active-ledger reread. Partial pre-witness creates stay
//! in the lifecycle deletion inventory. No production ledger/backend composite
//! is constructed here, so the seam remains inactive.

use crate::{
    archive_v3::{
        resolve_archive_cipher, ArchiveId, ArchiveV3Error, CiphertextEnvelope, DatabaseEpoch,
        ExactKeyRegistryProvider, KeyEpoch, KeyKind, KeyRegistryContext, LogicalLocation,
        ObjectContext, ObjectId, ObjectRole, ParentReference, MAX_ENCODED_ENVELOPE_BYTES,
        MAX_WRAPPED_KEY_REGISTRY_BYTES,
    },
    archive_v3_lifecycle::{
        ActiveCreateAdmission, ArchiveLifecycleLedger, BootstrapAttemptId,
        DurableBootstrapReservation, LifecycleCreateOutcome, LifecycleError, PreparedBootstrap,
    },
    archive_v3_witness::{
        DeletionState, ExactRootProvider, KeyRegistryReference, RootCommitment, RootReference,
        WitnessBootstrap, WitnessError, WitnessRecord,
    },
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// A control-plane-owned, opaque persistent archive binding.  It intentionally
/// accepts neither a user ID nor a value derived from one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArchiveBinding {
    archive_id: ArchiveId,
}

impl ArchiveBinding {
    #[cfg(test)]
    pub(crate) fn new(archive_id: ArchiveId) -> Result<Self, BootstrapError> {
        if archive_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(BootstrapError::MalformedCandidate);
        }
        Ok(Self { archive_id })
    }

    fn from_reservation(reservation: DurableBootstrapReservation) -> Self {
        Self {
            archive_id: reservation.plan().archive_id(),
        }
    }

    pub(crate) const fn archive_id(self) -> ArchiveId {
        self.archive_id
    }
}

impl fmt::Debug for ArchiveBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveBinding(<opaque>)")
    }
}

/// A stable set of preallocated opaque IDs.  Retrying a bootstrap must retain
/// this material; generating replacements after an ambiguous provider outcome
/// would create an unresolvable competing candidate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenesisIds {
    pub database_epoch: DatabaseEpoch,
    pub key_epoch: KeyEpoch,
    pub registry_object_id: ObjectId,
    pub root_object_id: ObjectId,
}

impl fmt::Debug for GenesisIds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GenesisIds(<opaque>)")
    }
}

/// Immutable, retry-stable genesis bytes. Wrapped registry ciphertext is never
/// archive-encrypted; the root envelope uses the existing archive-v3 AAD.
pub(crate) struct GenesisCandidate {
    binding: ArchiveBinding,
    attempt_id: BootstrapAttemptId,
    ids: GenesisIds,
    registry_context: KeyRegistryContext,
    registry: KeyRegistryReference,
    root_context: ObjectContext,
    root_envelope: CiphertextEnvelope,
    wrapped_registry: Zeroizing<Vec<u8>>,
    lifecycle_revision: u64,
}

impl GenesisCandidate {
    fn from_prepared(prepared: PreparedBootstrap) -> Result<Self, BootstrapError> {
        let reservation = prepared.reservation();
        let plan = reservation.plan();
        let root_envelope = CiphertextEnvelope::decode(prepared.root_envelope())
            .map_err(BootstrapError::Archive)?;
        let registry_hash: [u8; 32] = Sha256::digest(prepared.wrapped_registry()).into();
        if root_envelope.hash() != prepared.root_envelope_hash()
            || registry_hash != prepared.wrapped_registry_hash()
        {
            return Err(BootstrapError::MalformedCandidate);
        }
        Self::new(
            ArchiveBinding::from_reservation(reservation),
            plan.attempt_id(),
            GenesisIds {
                database_epoch: plan.database_epoch(),
                key_epoch: plan.key_epoch(),
                registry_object_id: plan.registry_object_id(),
                root_object_id: plan.root_object_id(),
            },
            prepared.wrapped_registry(),
            root_envelope,
            prepared.revision(),
        )
    }

    /// Performs only bounded local validation.  It never reads, writes, or
    /// constructs a provider, KMS client, credential, or network authority.
    pub(crate) fn new(
        binding: ArchiveBinding,
        attempt_id: BootstrapAttemptId,
        ids: GenesisIds,
        wrapped_registry: &[u8],
        root_envelope: CiphertextEnvelope,
        lifecycle_revision: u64,
    ) -> Result<Self, BootstrapError> {
        if ids.database_epoch.as_bytes().iter().all(|byte| *byte == 0)
            || ids.key_epoch.as_bytes().iter().all(|byte| *byte == 0)
            || ids
                .registry_object_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || ids.root_object_id.as_bytes().iter().all(|byte| *byte == 0)
            || ids.registry_object_id == ids.root_object_id
            || wrapped_registry.is_empty()
            || wrapped_registry.len() > MAX_WRAPPED_KEY_REGISTRY_BYTES
            || root_envelope.encode().len() > MAX_ENCODED_ENVELOPE_BYTES
            || lifecycle_revision == 0
        {
            return Err(BootstrapError::MalformedCandidate);
        }
        let registry_context =
            KeyRegistryContext::new(binding.archive_id(), KeyKind::Archive, ids.key_epoch);
        let registry = KeyRegistryReference::new(
            ids.key_epoch,
            registry_context.rotation_generation(),
            ids.registry_object_id,
            Sha256::digest(wrapped_registry).into(),
        );
        let root_context = ObjectContext::new(
            binding.archive_id(),
            ids.database_epoch,
            ids.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ids.root_object_id,
            None,
        )
        .map_err(BootstrapError::Archive)?;
        Ok(Self {
            binding,
            attempt_id,
            ids,
            registry_context,
            registry,
            root_context,
            root_envelope,
            wrapped_registry: Zeroizing::new(wrapped_registry.to_vec()),
            lifecycle_revision,
        })
    }

    fn validate_admission(
        &self,
        admission: &ActiveCreateAdmission,
        expected_revision: u64,
        artifact_ordinal: u32,
        artifact_hash: [u8; 32],
    ) -> Result<(), BootstrapError> {
        // A fresh admission advances the anchor once. An exact retry of the
        // one still-unreconciled provider request replays that same receipt at
        // the current anchor revision; no older or future receipt is valid.
        if admission.revision() != expected_revision
            && Some(admission.revision()) != expected_revision.checked_add(1)
            || admission.archive_id() != self.binding.archive_id()
            || admission.attempt_id() != self.attempt_id
            || admission.artifact_ordinal() != artifact_ordinal
            || admission.artifact_hash() != artifact_hash
        {
            return Err(BootstrapError::Lifecycle(LifecycleError::InvalidState));
        }
        Ok(())
    }

    fn expected_root(&self) -> RootCommitment {
        RootCommitment::genesis(
            self.ids.database_epoch,
            self.ids.key_epoch,
            RootReference::new(0, self.ids.root_object_id, self.root_envelope.hash()),
        )
    }

    async fn authenticated_bootstrap(
        &self,
        backend: &dyn ArchiveGenesisBackend,
    ) -> Result<WitnessBootstrap, BootstrapError> {
        let cipher = resolve_archive_cipher(
            &self.registry_context,
            self.ids.registry_object_id,
            self.registry.ciphertext_hash(),
            backend,
        )
        .await
        .map_err(BootstrapError::Archive)?;
        WitnessBootstrap::from_authenticated_genesis(
            self.binding.archive_id(),
            self.registry,
            &self.root_context,
            backend,
            &cipher,
        )
        .await
        .map_err(BootstrapError::Witness)
    }
}

impl fmt::Debug for GenesisCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GenesisCandidate(<opaque>)")
    }
}

/// The only create outcomes this seam accepts. Provider ambiguity remains an
/// error until an exact read establishes byte-for-byte equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootstrapCreate {
    Created,
    AlreadyPresent,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub(crate) enum BootstrapError {
    #[error("archive genesis candidate is malformed")]
    MalformedCandidate,
    #[error("archive genesis object conflicts with an existing immutable object")]
    Conflict,
    #[error("archive genesis provider outcome is unknown; resolve with an exact read")]
    OutcomeUnknown,
    #[error("archive genesis cannot proceed from a tombstoned/deleting witness")]
    Tombstoned,
    #[error("archive genesis witness changed during exact authentication")]
    WitnessChanged,
    #[error("archive genesis provider data is invalid")]
    Archive(ArchiveV3Error),
    #[error("archive genesis witness data is invalid")]
    Witness(WitnessError),
    #[error("archive genesis durable lifecycle admission failed")]
    Lifecycle(LifecycleError),
}

/// Narrow injected provider boundary.  Implementations must use immutable,
/// create-if-absent semantics.  No implementation is constructed here.
#[async_trait]
pub(crate) trait ArchiveGenesisBackend:
    ExactRootProvider + ExactKeyRegistryProvider + ArchiveLifecycleLedger
{
    async fn read_witness(
        &self,
        archive_id: ArchiveId,
    ) -> Result<Option<WitnessRecord>, BootstrapError>;

    async fn create_registry_if_absent(
        &self,
        admission: &ActiveCreateAdmission,
        context: &KeyRegistryContext,
        object_id: ObjectId,
        wrapped_registry: &[u8],
    ) -> Result<BootstrapCreate, BootstrapError>;

    async fn create_root_if_absent(
        &self,
        admission: &ActiveCreateAdmission,
        context: &ObjectContext,
        envelope: &CiphertextEnvelope,
    ) -> Result<BootstrapCreate, BootstrapError>;

    async fn create_witness_if_absent(
        &self,
        admission: &ActiveCreateAdmission,
        bootstrap: WitnessBootstrap,
    ) -> Result<BootstrapCreate, BootstrapError>;
}

/// Result only reveals the state transition, never archive identifiers or
/// content.  Both variants have authenticated the exact witness/root/registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenesisResolution {
    Existing,
    Created,
}

/// Inactive coordinator. Its constructor is intentionally I/O-free; `resolve`
/// is the sole method that can invoke an injected provider.
pub(crate) struct ArchiveGenesis {
    candidate: GenesisCandidate,
}

impl ArchiveGenesis {
    pub(crate) fn new(prepared: PreparedBootstrap) -> Result<Self, BootstrapError> {
        Ok(Self {
            candidate: GenesisCandidate::from_prepared(prepared)?,
        })
    }

    #[cfg(test)]
    const fn from_candidate_for_test(candidate: GenesisCandidate) -> Self {
        Self { candidate }
    }

    pub(crate) async fn resolve(
        &self,
        backend: &dyn ArchiveGenesisBackend,
    ) -> Result<GenesisResolution, BootstrapError> {
        let lifecycle_revision = backend
            .revalidate_active(
                self.candidate.binding.archive_id(),
                self.candidate.lifecycle_revision,
            )
            .await
            .map_err(BootstrapError::Lifecycle)?;
        if let Some(record) = backend
            .read_witness(self.candidate.binding.archive_id())
            .await?
        {
            self.authenticate_stable_record(backend, &record).await?;
            let fresh_revision = backend
                .revalidate_active(self.candidate.binding.archive_id(), lifecycle_revision)
                .await
                .map_err(BootstrapError::Lifecycle)?;
            if fresh_revision != lifecycle_revision {
                return Err(BootstrapError::Lifecycle(LifecycleError::StaleRevision));
            }
            return Ok(GenesisResolution::Existing);
        }

        let revision = self
            .create_or_compare_registry(backend, lifecycle_revision)
            .await?;
        let revision = self.create_or_compare_root(backend, revision).await?;
        let bootstrap = self.candidate.authenticated_bootstrap(backend).await?;
        let expected_record = bootstrap
            .expected_initial_record_bytes()
            .map_err(BootstrapError::Witness)?;
        let revision = backend
            .prepare_witness(
                self.candidate.binding.archive_id(),
                revision,
                &expected_record,
            )
            .await
            .map_err(BootstrapError::Lifecycle)?;
        let admission = backend
            .admit_exact_create(self.candidate.binding.archive_id(), revision, 2)
            .await
            .map_err(BootstrapError::Lifecycle)?;
        self.candidate.validate_admission(
            &admission,
            revision,
            2,
            Sha256::digest(expected_record).into(),
        )?;
        let outcome = backend
            .create_witness_if_absent(&admission, bootstrap)
            .await;
        let reconciliation = match &outcome {
            Ok(BootstrapCreate::Created) => Some(LifecycleCreateOutcome::Created),
            Ok(BootstrapCreate::AlreadyPresent) | Err(BootstrapError::OutcomeUnknown) => {
                Some(LifecycleCreateOutcome::AlreadyPresentExact)
            }
            Err(_) => None,
        };
        match outcome {
            Ok(BootstrapCreate::Created)
            | Ok(BootstrapCreate::AlreadyPresent)
            | Err(BootstrapError::OutcomeUnknown) => {
                let record = backend
                    .read_witness(self.candidate.binding.archive_id())
                    .await?
                    .ok_or(BootstrapError::OutcomeUnknown)?;
                if record.root() != self.candidate.expected_root()
                    || record.registry() != self.candidate.registry
                {
                    return Err(BootstrapError::Conflict);
                }
                let revision = backend
                    .reconcile_create(
                        &admission,
                        reconciliation.expect("matched exact witness create outcomes"),
                    )
                    .await
                    .map_err(BootstrapError::Lifecycle)?;
                self.authenticate_stable_record(backend, &record).await?;
                let fresh_revision = backend
                    .revalidate_active(self.candidate.binding.archive_id(), revision)
                    .await
                    .map_err(BootstrapError::Lifecycle)?;
                if fresh_revision != revision {
                    return Err(BootstrapError::Lifecycle(LifecycleError::StaleRevision));
                }
                Ok(GenesisResolution::Created)
            }
            Err(error) => Err(error),
        }
    }

    async fn create_or_compare_registry(
        &self,
        backend: &dyn ArchiveGenesisBackend,
        expected_revision: u64,
    ) -> Result<u64, BootstrapError> {
        let admission = backend
            .admit_exact_create(self.candidate.binding.archive_id(), expected_revision, 0)
            .await
            .map_err(BootstrapError::Lifecycle)?;
        self.candidate.validate_admission(
            &admission,
            expected_revision,
            0,
            self.candidate.registry.ciphertext_hash(),
        )?;
        let outcome = backend
            .create_registry_if_absent(
                &admission,
                &self.candidate.registry_context,
                self.candidate.ids.registry_object_id,
                &self.candidate.wrapped_registry,
            )
            .await;
        let reconciliation = match &outcome {
            Ok(BootstrapCreate::Created) => Some(LifecycleCreateOutcome::Created),
            Ok(BootstrapCreate::AlreadyPresent) | Err(BootstrapError::OutcomeUnknown) => {
                Some(LifecycleCreateOutcome::AlreadyPresentExact)
            }
            Err(_) => None,
        };
        match outcome {
            Ok(BootstrapCreate::Created)
            | Ok(BootstrapCreate::AlreadyPresent)
            | Err(BootstrapError::OutcomeUnknown) => {
                let mut actual = Zeroizing::new([0u8; MAX_WRAPPED_KEY_REGISTRY_BYTES]);
                let len = backend
                    .read_exact_wrapped(
                        &self.candidate.registry_context,
                        self.candidate.ids.registry_object_id,
                        actual.as_mut_slice(),
                    )
                    .await
                    .map_err(BootstrapError::Archive)?;
                if len > actual.len() {
                    return Err(BootstrapError::Archive(ArchiveV3Error::TooLarge(
                        "wrapped key registry",
                    )));
                }
                if actual[..len] != *self.candidate.wrapped_registry {
                    return Err(BootstrapError::Conflict);
                }
                backend
                    .reconcile_create(
                        &admission,
                        reconciliation.expect("matched exact registry create outcomes"),
                    )
                    .await
                    .map_err(BootstrapError::Lifecycle)
            }
            Err(error) => Err(error),
        }
    }

    async fn create_or_compare_root(
        &self,
        backend: &dyn ArchiveGenesisBackend,
        expected_revision: u64,
    ) -> Result<u64, BootstrapError> {
        let admission = backend
            .admit_exact_create(self.candidate.binding.archive_id(), expected_revision, 1)
            .await
            .map_err(BootstrapError::Lifecycle)?;
        self.candidate.validate_admission(
            &admission,
            expected_revision,
            1,
            self.candidate.root_envelope.hash(),
        )?;
        let outcome = backend
            .create_root_if_absent(
                &admission,
                &self.candidate.root_context,
                &self.candidate.root_envelope,
            )
            .await;
        let reconciliation = match &outcome {
            Ok(BootstrapCreate::Created) => Some(LifecycleCreateOutcome::Created),
            Ok(BootstrapCreate::AlreadyPresent) | Err(BootstrapError::OutcomeUnknown) => {
                Some(LifecycleCreateOutcome::AlreadyPresentExact)
            }
            Err(_) => None,
        };
        match outcome {
            Ok(BootstrapCreate::Created)
            | Ok(BootstrapCreate::AlreadyPresent)
            | Err(BootstrapError::OutcomeUnknown) => {
                let actual = backend
                    .read_exact(&self.candidate.root_context)
                    .await
                    .map_err(BootstrapError::Witness)?;
                if actual != self.candidate.root_envelope {
                    return Err(BootstrapError::Conflict);
                }
                backend
                    .reconcile_create(
                        &admission,
                        reconciliation.expect("matched exact root create outcomes"),
                    )
                    .await
                    .map_err(BootstrapError::Lifecycle)
            }
            Err(error) => Err(error),
        }
    }

    async fn authenticate_existing(
        &self,
        backend: &dyn ArchiveGenesisBackend,
        record: &WitnessRecord,
    ) -> Result<(), BootstrapError> {
        if record.archive_id() != self.candidate.binding.archive_id() {
            return Err(BootstrapError::Conflict);
        }
        if record.deletion() != DeletionState::Active {
            return Err(BootstrapError::Tombstoned);
        }
        let registry = record.registry();
        let registry_context = KeyRegistryContext::with_rotation_generation(
            record.archive_id(),
            KeyKind::Archive,
            registry.key_epoch(),
            registry.rotation_generation(),
        );
        let cipher = resolve_archive_cipher(
            &registry_context,
            registry.object_id(),
            registry.ciphertext_hash(),
            backend,
        )
        .await
        .map_err(BootstrapError::Archive)?;
        let root = record.root();
        let context = ObjectContext::new(
            record.archive_id(),
            record.database_epoch(),
            registry.key_epoch(),
            ObjectRole::RootV3,
            LogicalLocation::Root {
                root_seq: root.root().sequence(),
            },
            root.root().object_id(),
            root.parent().map(|parent| ParentReference {
                object_id: parent.object_id(),
                envelope_hash: parent.ciphertext_hash(),
            }),
        )
        .map_err(BootstrapError::Archive)?;
        let authenticated = RootCommitment::from_authenticated_provider_object(
            record.archive_id(),
            registry,
            &context,
            backend,
            &cipher,
        )
        .await
        .map_err(BootstrapError::Witness)?;
        (authenticated == root)
            .then_some(())
            .ok_or(BootstrapError::Conflict)
    }

    /// Authenticate one exact snapshot, then make a final exact witness read.
    /// Both paths use this helper so no successful return crosses an await
    /// after the final active/equality decision.
    async fn authenticate_stable_record(
        &self,
        backend: &dyn ArchiveGenesisBackend,
        snapshot: &WitnessRecord,
    ) -> Result<(), BootstrapError> {
        self.authenticate_existing(backend, snapshot).await?;
        let Some(current) = backend
            .read_witness(self.candidate.binding.archive_id())
            .await?
        else {
            return Err(BootstrapError::WitnessChanged);
        };
        if current.deletion() != DeletionState::Active {
            return Err(BootstrapError::Tombstoned);
        }
        if &current != snapshot {
            return Err(BootstrapError::WitnessChanged);
        }
        Ok(())
    }
}

impl fmt::Debug for ArchiveGenesis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveGenesis(<opaque>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{
            ArchiveCipher, ArchiveDek, ArchiveRoot, ARCHIVE_FORMAT_VERSION, SQLITE_PAGE_SIZE,
        },
        archive_v3_witness::{InMemoryWitness, Witness},
    };
    use std::{collections::BTreeMap, sync::Mutex};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum WriteMode {
        Normal,
        LostResponse,
        LostResponseMismatch,
        Collision,
    }

    #[derive(Clone, Copy)]
    enum WitnessInterleave {
        Tombstone,
        RootAdvance,
        RegistryAdvance,
    }

    #[derive(Clone, Copy)]
    enum AdmissionFault {
        Archive,
        Attempt,
        StaleRevision,
        FutureRevision,
        Ordinal,
        Hash,
    }

    struct FakeBackend {
        witness: InMemoryWitness,
        forced_record: Mutex<Option<WitnessRecord>>,
        roots: Mutex<BTreeMap<ObjectId, CiphertextEnvelope>>,
        registries: Mutex<BTreeMap<ObjectId, Vec<u8>>>,
        registry_plaintext: Vec<u8>,
        registry_mode: WriteMode,
        root_mode: WriteMode,
        witness_mode: WriteMode,
        interleave: Mutex<Option<WitnessInterleave>>,
        io: Mutex<usize>,
        events: Mutex<Vec<&'static str>>,
        lifecycle_revision: Mutex<u64>,
        revalidate_calls: Mutex<usize>,
        freeze_on_revalidate_call: Mutex<Option<usize>>,
        expected_registry_hash: [u8; 32],
        expected_root_hash: [u8; 32],
        prepared_witness_hash: Mutex<Option<[u8; 32]>>,
        admission_fault: Mutex<Option<(u32, AdmissionFault)>>,
    }

    impl FakeBackend {
        fn new(genesis: &ArchiveGenesis, plaintext: Vec<u8>) -> Self {
            Self {
                witness: InMemoryWitness::new(),
                forced_record: Mutex::new(None),
                roots: Mutex::new(BTreeMap::new()),
                registries: Mutex::new(BTreeMap::new()),
                registry_plaintext: plaintext,
                registry_mode: WriteMode::Normal,
                root_mode: WriteMode::Normal,
                witness_mode: WriteMode::Normal,
                interleave: Mutex::new(None),
                io: Mutex::new(0),
                events: Mutex::new(Vec::new()),
                lifecycle_revision: Mutex::new(2),
                revalidate_calls: Mutex::new(0),
                freeze_on_revalidate_call: Mutex::new(None),
                expected_registry_hash: genesis.candidate.registry.ciphertext_hash(),
                expected_root_hash: genesis.candidate.root_envelope.hash(),
                prepared_witness_hash: Mutex::new(None),
                admission_fault: Mutex::new(None),
            }
        }

        fn fault_admission(&self, ordinal: u32, fault: AdmissionFault) {
            *self.admission_fault.lock().unwrap() = Some((ordinal, fault));
        }
        fn io_count(&self) -> usize {
            *self.io.lock().unwrap()
        }
        fn hit(&self) {
            *self.io.lock().unwrap() += 1;
        }
        fn event(&self, event: &'static str) {
            self.events.lock().unwrap().push(event);
        }
        fn freeze_on_final_revalidate(&self) {
            let calls = *self.revalidate_calls.lock().unwrap();
            *self.freeze_on_revalidate_call.lock().unwrap() = Some(calls + 2);
        }
        fn result_for(mode: WriteMode, inserted: bool) -> Result<BootstrapCreate, BootstrapError> {
            if matches!(
                mode,
                WriteMode::LostResponse | WriteMode::LostResponseMismatch
            ) && inserted
            {
                Err(BootstrapError::OutcomeUnknown)
            } else if inserted {
                Ok(BootstrapCreate::Created)
            } else {
                Ok(BootstrapCreate::AlreadyPresent)
            }
        }

        fn mismatched_envelope(envelope: &CiphertextEnvelope) -> CiphertextEnvelope {
            let mut encoded = envelope.encode();
            // The nonce is inside the canonical envelope framing, so this is
            // a bounded, parseable, byte-inequal immutable collision.
            encoded[9] ^= 1;
            CiphertextEnvelope::decode(&encoded).expect("bounded envelope")
        }

        fn set_interleave(&self, action: WitnessInterleave) {
            *self.interleave.lock().unwrap() = Some(action);
        }

        fn interleave_witness_after_auth_read(&self, archive_id: ArchiveId) {
            let Some(record) = self.witness.read_current(archive_id).unwrap() else {
                // On the create path, leave the action armed until the witness
                // has actually been created and its root is authenticated.
                return;
            };
            let Some(action) = self.interleave.lock().unwrap().take() else {
                return;
            };
            let changed = match action {
                WitnessInterleave::Tombstone => record.tombstoned_for_test(),
                WitnessInterleave::RootAdvance => {
                    record.with_root_for_test(RootCommitment::genesis(
                        record.database_epoch(),
                        record.registry().key_epoch(),
                        RootReference::new(0, ObjectId::from_bytes([14; 16]), [15; 32]),
                    ))
                }
                WitnessInterleave::RegistryAdvance => {
                    record.with_registry_for_test(KeyRegistryReference::new(
                        record.registry().key_epoch(),
                        record.registry().rotation_generation() + 1,
                        ObjectId::from_bytes([16; 16]),
                        [17; 32],
                    ))
                }
            };
            *self.forced_record.lock().unwrap() = Some(changed);
        }
    }

    #[async_trait]
    impl ExactRootProvider for FakeBackend {
        async fn read_exact(
            &self,
            context: &ObjectContext,
        ) -> std::result::Result<CiphertextEnvelope, WitnessError> {
            self.hit();
            let envelope = self
                .roots
                .lock()
                .unwrap()
                .get(&context.object_id())
                .cloned()
                .ok_or(WitnessError::MissingRootObject)?;
            self.interleave_witness_after_auth_read(context.archive_id());
            Ok(envelope)
        }
    }
    #[async_trait]
    impl ExactKeyRegistryProvider for FakeBackend {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            destination: &mut [u8],
        ) -> std::result::Result<usize, ArchiveV3Error> {
            self.hit();
            let value = self
                .registries
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
            _wrapped: &[u8],
            destination: &mut [u8],
        ) -> std::result::Result<usize, ArchiveV3Error> {
            self.hit();
            if self.registry_plaintext.len() > destination.len() {
                return Err(ArchiveV3Error::TooLarge("key registry plaintext"));
            }
            destination[..self.registry_plaintext.len()].copy_from_slice(&self.registry_plaintext);
            Ok(self.registry_plaintext.len())
        }
    }
    #[async_trait]
    impl ArchiveLifecycleLedger for FakeBackend {
        async fn reserve_bootstrap(
            &self,
            _plan: crate::archive_v3_lifecycle::BootstrapPlan,
        ) -> std::result::Result<DurableBootstrapReservation, LifecycleError> {
            Err(LifecycleError::InvalidState)
        }

        async fn prepare_bootstrap(
            &self,
            _reservation: DurableBootstrapReservation,
            _exact_wrapped_registry: &[u8],
            _exact_root_envelope: &[u8],
        ) -> std::result::Result<PreparedBootstrap, LifecycleError> {
            Err(LifecycleError::InvalidState)
        }

        async fn prepare_witness(
            &self,
            archive_id: ArchiveId,
            expected_revision: u64,
            expected_encoded_record: &[u8],
        ) -> std::result::Result<u64, LifecycleError> {
            self.event("prepare_witness");
            if archive_id != ArchiveId::from_bytes([1; 16]) || expected_encoded_record.is_empty() {
                return Err(LifecycleError::Malformed);
            }
            *self.prepared_witness_hash.lock().unwrap() =
                Some(Sha256::digest(expected_encoded_record).into());
            let mut revision = self.lifecycle_revision.lock().unwrap();
            if *revision != expected_revision {
                return Err(LifecycleError::StaleRevision);
            }
            *revision += 1;
            Ok(*revision)
        }

        async fn admit_exact_create(
            &self,
            archive_id: ArchiveId,
            expected_revision: u64,
            artifact_ordinal: u32,
        ) -> std::result::Result<ActiveCreateAdmission, LifecycleError> {
            if archive_id != ArchiveId::from_bytes([1; 16]) {
                return Err(LifecycleError::InvalidState);
            }
            self.event(match artifact_ordinal {
                0 => "admit_registry",
                1 => "admit_root",
                2 => "admit_witness",
                _ => "admit_invalid",
            });
            let mut revision = self.lifecycle_revision.lock().unwrap();
            if *revision != expected_revision {
                return Err(LifecycleError::StaleRevision);
            }
            *revision += 1;
            let artifact_hash = match artifact_ordinal {
                0 => self.expected_registry_hash,
                1 => self.expected_root_hash,
                2 => self
                    .prepared_witness_hash
                    .lock()
                    .unwrap()
                    .ok_or(LifecycleError::InvalidState)?,
                _ => return Err(LifecycleError::Malformed),
            };
            let mut receipt_archive = ArchiveId::from_bytes([1; 16]);
            let mut receipt_attempt = BootstrapAttemptId::from_bytes([20; 16])?;
            let mut receipt_revision = *revision;
            let mut receipt_ordinal = artifact_ordinal;
            let mut receipt_hash = artifact_hash;
            let admission_fault = { self.admission_fault.lock().unwrap().take() };
            if let Some((target, fault)) = admission_fault {
                if target == artifact_ordinal {
                    match fault {
                        AdmissionFault::Archive => {
                            receipt_archive = ArchiveId::from_bytes([99; 16])
                        }
                        AdmissionFault::Attempt => {
                            receipt_attempt = BootstrapAttemptId::from_bytes([98; 16])?
                        }
                        AdmissionFault::StaleRevision => {
                            receipt_revision = expected_revision.saturating_sub(1)
                        }
                        AdmissionFault::FutureRevision => {
                            receipt_revision = expected_revision
                                .checked_add(2)
                                .ok_or(LifecycleError::Malformed)?
                        }
                        AdmissionFault::Ordinal => receipt_ordinal = (artifact_ordinal + 1) % 3,
                        AdmissionFault::Hash => receipt_hash[0] ^= 0xff,
                    }
                } else {
                    *self.admission_fault.lock().unwrap() = Some((target, fault));
                }
            }
            ActiveCreateAdmission::for_test(
                receipt_archive,
                receipt_attempt,
                receipt_revision,
                receipt_ordinal,
                receipt_hash,
            )
        }

        async fn plan_exact_artifact(
            &self,
            _archive_id: ArchiveId,
            _expected_revision: u64,
            _artifact: crate::archive_v3_lifecycle::PlannedArtifact,
        ) -> std::result::Result<u64, LifecycleError> {
            Err(LifecycleError::InvalidState)
        }

        async fn reconcile_create(
            &self,
            admission: &ActiveCreateAdmission,
            _outcome: LifecycleCreateOutcome,
        ) -> std::result::Result<u64, LifecycleError> {
            let mut revision = self.lifecycle_revision.lock().unwrap();
            if *revision != admission.revision()
                || admission.archive_id() != ArchiveId::from_bytes([1; 16])
            {
                return Err(LifecycleError::StaleRevision);
            }
            *revision += 1;
            Ok(*revision)
        }

        async fn freeze_for_deletion(
            &self,
            _archive_id: ArchiveId,
            _expected_revision: u64,
            _deletion_fence: ObjectId,
        ) -> std::result::Result<u64, LifecycleError> {
            Err(LifecycleError::InvalidState)
        }

        async fn seal_inventory(
            &self,
            _archive_id: ArchiveId,
            _expected_revision: u64,
            _deletion_fence: ObjectId,
            _pages: &[crate::archive_v3_lifecycle::DurableInventoryPage],
        ) -> std::result::Result<crate::archive_v3_lifecycle::DeletionInventorySeal, LifecycleError>
        {
            Err(LifecycleError::InvalidState)
        }

        async fn load_sealed_inventory(
            &self,
            _seal: &crate::archive_v3_lifecycle::DeletionInventorySeal,
        ) -> std::result::Result<Vec<crate::archive_v3_lifecycle::InventoryPage>, LifecycleError>
        {
            Err(LifecycleError::InvalidState)
        }

        async fn revalidate_active(
            &self,
            archive_id: ArchiveId,
            expected_revision: u64,
        ) -> std::result::Result<u64, LifecycleError> {
            let call = {
                let mut calls = self.revalidate_calls.lock().unwrap();
                *calls += 1;
                *calls
            };
            if *self.freeze_on_revalidate_call.lock().unwrap() == Some(call) {
                return Err(LifecycleError::InvalidState);
            }
            let revision = *self.lifecycle_revision.lock().unwrap();
            if archive_id != ArchiveId::from_bytes([1; 16]) || revision < expected_revision {
                return Err(LifecycleError::StaleRevision);
            }
            Ok(revision)
        }
    }

    #[async_trait]
    impl ArchiveGenesisBackend for FakeBackend {
        async fn read_witness(
            &self,
            archive: ArchiveId,
        ) -> Result<Option<WitnessRecord>, BootstrapError> {
            self.hit();
            if let Some(record) = self.forced_record.lock().unwrap().clone() {
                return Ok(Some(record));
            }
            self.witness
                .read_current(archive)
                .map_err(BootstrapError::Witness)
        }
        async fn create_registry_if_absent(
            &self,
            admission: &ActiveCreateAdmission,
            _context: &KeyRegistryContext,
            id: ObjectId,
            bytes: &[u8],
        ) -> Result<BootstrapCreate, BootstrapError> {
            if admission.artifact_ordinal() != 0 {
                return Err(BootstrapError::Lifecycle(LifecycleError::InvalidState));
            }
            self.event("create_registry");
            self.hit();
            let mut values = self.registries.lock().unwrap();
            if let Some(existing) = values.get(&id) {
                return if existing == bytes {
                    Ok(BootstrapCreate::AlreadyPresent)
                } else {
                    Err(BootstrapError::Conflict)
                };
            }
            if matches!(
                self.registry_mode,
                WriteMode::Collision | WriteMode::LostResponseMismatch
            ) {
                values.insert(id, vec![7]);
            } else {
                values.insert(id, bytes.to_vec());
            }
            Self::result_for(self.registry_mode, true)
        }
        async fn create_root_if_absent(
            &self,
            admission: &ActiveCreateAdmission,
            context: &ObjectContext,
            envelope: &CiphertextEnvelope,
        ) -> Result<BootstrapCreate, BootstrapError> {
            if admission.artifact_ordinal() != 1 {
                return Err(BootstrapError::Lifecycle(LifecycleError::InvalidState));
            }
            self.event("create_root");
            self.hit();
            let mut values = self.roots.lock().unwrap();
            let id = context.object_id();
            if let Some(existing) = values.get(&id) {
                return if existing == envelope {
                    Ok(BootstrapCreate::AlreadyPresent)
                } else {
                    Err(BootstrapError::Conflict)
                };
            }
            if matches!(
                self.root_mode,
                WriteMode::Collision | WriteMode::LostResponseMismatch
            ) {
                values.insert(id, Self::mismatched_envelope(envelope));
            } else {
                values.insert(id, envelope.clone());
            }
            if self.root_mode == WriteMode::Collision {
                return Err(BootstrapError::Conflict);
            }
            Self::result_for(self.root_mode, true)
        }
        async fn create_witness_if_absent(
            &self,
            admission: &ActiveCreateAdmission,
            bootstrap: WitnessBootstrap,
        ) -> Result<BootstrapCreate, BootstrapError> {
            if admission.artifact_ordinal() != 2 {
                return Err(BootstrapError::Lifecycle(LifecycleError::InvalidState));
            }
            self.event("create_witness");
            self.hit();
            let result = self
                .witness
                .bootstrap(bootstrap)
                .map_err(|error| match error {
                    WitnessError::AlreadyExists => BootstrapError::Conflict,
                    other => BootstrapError::Witness(other),
                })?;
            let _ = result;
            Self::result_for(self.witness_mode, true)
        }
    }

    fn candidate() -> (ArchiveGenesis, Vec<u8>) {
        let binding = ArchiveBinding::new(ArchiveId::from_bytes([1; 16])).unwrap();
        let ids = GenesisIds {
            database_epoch: DatabaseEpoch::from_bytes([2; 16]),
            key_epoch: KeyEpoch::from_bytes([3; 16]),
            registry_object_id: ObjectId::from_bytes([4; 16]),
            root_object_id: ObjectId::from_bytes([5; 16]),
        };
        let registry_context =
            KeyRegistryContext::new(binding.archive_id(), KeyKind::Archive, ids.key_epoch);
        let plaintext = crate::archive_v3::KeyRegistryPlaintext::encode_archive(
            &registry_context,
            &ArchiveDek::from_bytes([9; 32]),
        )
        .unwrap()
        .to_vec();
        let cipher = ArchiveCipher::new(ArchiveDek::from_bytes([9; 32]));
        let root_context = ObjectContext::new(
            binding.archive_id(),
            ids.database_epoch,
            ids.key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            ids.root_object_id,
            None,
        )
        .unwrap();
        let root = ArchiveRoot {
            root_seq: 0,
            parent: None,
            database_epoch: ids.database_epoch,
            key_epoch: ids.key_epoch,
            owner_fencing_epoch: 0,
            sqlite_page_size: SQLITE_PAGE_SIZE,
            checkpoint_logical_file_length: 0,
            logical_file_length: 0,
            user_schema_version: 0,
            storage_format_version: ARCHIVE_FORMAT_VERSION,
            wal_generation: 0,
            wal_commit_count: 0,
            wal_segment_count: 0,
            wal_tail_bytes: 0,
            checkpoint_root: None,
            extent_tree_root: None,
            wal_commit_tail: None,
        };
        let envelope = cipher.seal(&root_context, &root.encode().unwrap()).unwrap();
        (
            ArchiveGenesis::from_candidate_for_test(
                GenesisCandidate::new(
                    binding,
                    BootstrapAttemptId::from_bytes([20; 16]).unwrap(),
                    ids,
                    b"wrapped-registry",
                    envelope,
                    2,
                )
                .unwrap(),
            ),
            plaintext,
        )
    }

    #[tokio::test]
    async fn first_genesis_is_authenticated_and_constructor_does_no_io() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(&genesis, plaintext);
        assert_eq!(backend.io_count(), 0);
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        assert!(backend.io_count() > 0);
        assert_eq!(
            *backend.events.lock().unwrap(),
            [
                "admit_registry",
                "create_registry",
                "admit_root",
                "create_root",
                "prepare_witness",
                "admit_witness",
                "create_witness",
            ]
        );
    }

    #[tokio::test]
    async fn every_create_rejects_unbound_admission_before_its_provider_io() {
        for ordinal in 0..=2 {
            for fault in [
                AdmissionFault::Archive,
                AdmissionFault::Attempt,
                AdmissionFault::StaleRevision,
                AdmissionFault::FutureRevision,
                AdmissionFault::Ordinal,
                AdmissionFault::Hash,
            ] {
                let (genesis, plaintext) = candidate();
                let backend = FakeBackend::new(&genesis, plaintext);
                backend.fault_admission(ordinal, fault);
                assert_eq!(
                    genesis.resolve(&backend).await,
                    Err(BootstrapError::Lifecycle(LifecycleError::InvalidState))
                );
                let forbidden = match ordinal {
                    0 => "create_registry",
                    1 => "create_root",
                    2 => "create_witness",
                    _ => unreachable!(),
                };
                assert!(!backend.events.lock().unwrap().contains(&forbidden));
            }
        }
    }

    #[tokio::test]
    async fn production_constructor_consumes_exact_durable_prepared_bytes() {
        let (candidate, plaintext) = candidate();
        let plan = crate::archive_v3_lifecycle::BootstrapPlan::new(
            candidate.candidate.binding.archive_id(),
            crate::archive_v3_lifecycle::BootstrapAttemptId::from_bytes([20; 16]).unwrap(),
            candidate.candidate.ids.database_epoch,
            candidate.candidate.ids.key_epoch,
            candidate.candidate.ids.registry_object_id,
            candidate.candidate.ids.root_object_id,
        )
        .unwrap();
        let reservation = DurableBootstrapReservation::for_test(plan, 1).unwrap();
        let registry = candidate.candidate.wrapped_registry.to_vec();
        let root = candidate.candidate.root_envelope.encode();
        let prepared = PreparedBootstrap::for_test(
            reservation,
            2,
            registry.clone(),
            root.clone(),
            Sha256::digest(&registry).into(),
            Sha256::digest(&root).into(),
        )
        .unwrap();
        let genesis = ArchiveGenesis::new(prepared).unwrap();
        assert_eq!(
            genesis
                .resolve(&FakeBackend::new(&genesis, plaintext))
                .await
                .unwrap(),
            GenesisResolution::Created
        );
    }
    #[tokio::test]
    async fn restart_reads_existing_exact_state() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(&genesis, plaintext);
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Existing
        );
    }
    #[tokio::test]
    async fn existing_path_rejects_freeze_before_final_lifecycle_reread() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(&genesis, plaintext);
        genesis.resolve(&backend).await.unwrap();
        backend.freeze_on_final_revalidate();
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Lifecycle(LifecycleError::InvalidState))
        );
    }
    #[tokio::test]
    async fn existing_path_rejects_tombstone_during_authentication() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(&genesis, plaintext);
        genesis.resolve(&backend).await.unwrap();
        backend.set_interleave(WitnessInterleave::Tombstone);
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Tombstoned)
        );
    }
    #[tokio::test]
    async fn existing_path_rejects_root_and_registry_advance_during_authentication() {
        for action in [
            WitnessInterleave::RootAdvance,
            WitnessInterleave::RegistryAdvance,
        ] {
            let (genesis, plaintext) = candidate();
            let backend = FakeBackend::new(&genesis, plaintext);
            genesis.resolve(&backend).await.unwrap();
            backend.set_interleave(action);
            assert_eq!(
                genesis.resolve(&backend).await,
                Err(BootstrapError::WitnessChanged)
            );
        }
    }
    #[tokio::test]
    async fn create_path_rejects_finalization_interleave() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(&genesis, plaintext);
        backend.set_interleave(WitnessInterleave::Tombstone);
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Tombstoned)
        );
    }
    #[tokio::test]
    async fn collision_and_lost_response_are_reconciled_only_by_equality() {
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend {
            registry_mode: WriteMode::LostResponse,
            root_mode: WriteMode::LostResponse,
            witness_mode: WriteMode::LostResponse,
            ..FakeBackend::new(&genesis, plaintext)
        };
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend {
            registry_mode: WriteMode::Collision,
            ..FakeBackend::new(&genesis, plaintext)
        };
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Conflict)
        );
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend {
            root_mode: WriteMode::LostResponseMismatch,
            ..FakeBackend::new(&genesis, plaintext)
        };
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Conflict)
        );
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(&genesis, plaintext);
        backend.roots.lock().unwrap().insert(
            genesis.candidate.root_context.object_id(),
            genesis.candidate.root_envelope.clone(),
        );
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend {
            registry_mode: WriteMode::LostResponseMismatch,
            ..FakeBackend::new(&genesis, plaintext)
        };
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Conflict)
        );
    }
    #[tokio::test]
    async fn malformed_provider_data_and_tombstones_fail_closed() {
        let (genesis, mut plaintext) = candidate();
        plaintext.push(1);
        let backend = FakeBackend::new(&genesis, plaintext);
        assert!(matches!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Archive(_))
        ));
        let (genesis, plaintext) = candidate();
        let backend = FakeBackend::new(&genesis, plaintext);
        assert_eq!(
            genesis.resolve(&backend).await.unwrap(),
            GenesisResolution::Created
        );
        *backend.forced_record.lock().unwrap() = backend
            .witness
            .read_current(genesis.candidate.binding.archive_id())
            .unwrap()
            .map(|record| record.tombstoned_for_test());
        assert_eq!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Tombstoned)
        );
        let (genesis, _) = candidate();
        let backend = FakeBackend::new(&genesis, vec![0; MAX_WRAPPED_KEY_REGISTRY_BYTES + 1]);
        assert!(matches!(
            genesis.resolve(&backend).await,
            Err(BootstrapError::Archive(ArchiveV3Error::TooLarge(_)))
        ));
    }
}
