#![allow(
    dead_code,
    reason = "inactive ADR-0022 genesis backend composite is compiled and contract-tested before authority wiring"
)]

//! Inactive ADR-0022 genesis backend adapter.
//!
//! This module composes the encrypted control-store archive-lifecycle ledger
//! with injected immutable-object, exact-root, wrapped-registry, and Firestore
//! witness providers into the one [`ArchiveGenesisBackend`] that
//! [`crate::archive_v3_genesis::ArchiveGenesis::resolve`] accepts. Construction
//! is synchronous and performs no provider I/O. Nothing in startup, Store, or
//! routes constructs it: the provider-release token below has no production
//! minter yet, so the bundle accessors it gates stay unreachable until a later
//! reviewed launcher in this module mints one.

use std::{fmt, sync::Arc};

use async_trait::async_trait;

use crate::{
    archive_v3::{
        ArchiveId, ArchiveV3Error, CiphertextEnvelope, CreateIfAbsent, ExactKeyRegistryProvider,
        ImmutableObjectBackend, KeyRegistryContext, ObjectContext, ObjectId,
    },
    archive_v3_firestore_witness::FirestoreWitness,
    archive_v3_gcs::GcsArchiveV3RegistryProvider,
    archive_v3_genesis::{
        ArchiveGenesisBackend, BootstrapCreate, BootstrapError, WitnessBootstrapCreator,
    },
    archive_v3_lifecycle::{
        ActiveCreateAdmission, ArchiveLifecycleLedger, BootstrapPlan, DeletionInventorySeal,
        DurableBootstrapReservation, InventoryPage, LifecycleCreateOutcome, LifecycleError,
        PlannedArtifact, PreparedBootstrap, WitnessCreateDispatchLedger, WitnessSendStarted,
    },
    archive_v3_witness::{ExactRootProvider, WitnessError, WitnessRecord},
    cp::control_store::ControlStore,
};

/// Producer token proving that bundle-withheld genesis providers were released
/// to this reviewed composition rather than assembled by a sibling module. It
/// has no public or sibling constructor and no production minter today.
pub(crate) struct GenesisBackendRuntimeContext(());

impl GenesisBackendRuntimeContext {
    /// The single production minter. It consumes the genesis sign-in
    /// trigger's own private token, which that module alone can construct, so
    /// the bundle accessors this token gates stay reachable from exactly one
    /// reviewed launcher and from nowhere else in startup, Store, or routes.
    pub(crate) const fn for_genesis_trigger(
        _token: &crate::archive_v3_genesis_trigger::GenesisTriggerContext,
    ) -> Self {
        Self(())
    }

    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self(())
    }
}

impl fmt::Debug for GenesisBackendRuntimeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenesisBackendRuntimeContext(<opaque>)")
    }
}

/// Narrow wrapped-registry storage seam the genesis backend needs beyond the
/// exact-read trait: the immutable create for the wrapped key registry. The
/// production implementation is the GCS registry provider; the trait exists so
/// contract tests can substitute an in-memory provider without widening the
/// registry write surface.
#[async_trait]
pub(crate) trait GenesisRegistryStore: ExactKeyRegistryProvider {
    async fn create_wrapped_if_absent(
        &self,
        context: &KeyRegistryContext,
        object_id: ObjectId,
        wrapped_registry_ciphertext: &[u8],
    ) -> crate::archive_v3::Result<CreateIfAbsent>;
}

#[async_trait]
impl GenesisRegistryStore for GcsArchiveV3RegistryProvider {
    async fn create_wrapped_if_absent(
        &self,
        context: &KeyRegistryContext,
        object_id: ObjectId,
        wrapped_registry_ciphertext: &[u8],
    ) -> crate::archive_v3::Result<CreateIfAbsent> {
        GcsArchiveV3RegistryProvider::create_wrapped_if_absent(
            self,
            context,
            object_id,
            wrapped_registry_ciphertext,
        )
        .await
    }
}

/// Map an immutable-provider create outcome onto the only outcomes the
/// genesis seam accepts. Ambiguity stays ambiguous: `resolve` reconciles it
/// through an exact read, never through this adapter guessing.
fn map_create(
    outcome: crate::archive_v3::Result<CreateIfAbsent>,
) -> Result<BootstrapCreate, BootstrapError> {
    match outcome {
        Ok(CreateIfAbsent::Created) => Ok(BootstrapCreate::Created),
        Ok(CreateIfAbsent::AlreadyPresentIdentical) => Ok(BootstrapCreate::AlreadyPresent),
        Err(ArchiveV3Error::Conflict) => Err(BootstrapError::Conflict),
        Err(ArchiveV3Error::Unavailable) => Err(BootstrapError::OutcomeUnknown),
        Err(error) => Err(BootstrapError::Archive(error)),
    }
}

/// Composite production genesis backend: the encrypted control store is the
/// durable lifecycle ledger and witness-dispatch ledger, while archive object,
/// root, registry, and witness authority delegate to the injected providers.
/// Constructing it grants nothing beyond what the released providers already
/// carry, and no startup caller exists.
pub(crate) struct ControlPlaneGenesisBackend {
    control: Arc<ControlStore>,
    objects: Arc<dyn ImmutableObjectBackend>,
    roots: Arc<dyn ExactRootProvider>,
    registries: Arc<dyn GenesisRegistryStore>,
    witness: Arc<FirestoreWitness>,
}

impl ControlPlaneGenesisBackend {
    /// Compose the backend from the control store and released providers.
    /// Synchronous and I/O-free; the consumed token is mintable only by this
    /// module (and tests), so sibling modules cannot assemble raw authority.
    pub(crate) fn new(
        _token: GenesisBackendRuntimeContext,
        control: Arc<ControlStore>,
        objects: Arc<dyn ImmutableObjectBackend>,
        roots: Arc<dyn ExactRootProvider>,
        registries: Arc<dyn GenesisRegistryStore>,
        witness: Arc<FirestoreWitness>,
    ) -> Self {
        Self {
            control,
            objects,
            roots,
            registries,
            witness,
        }
    }
}

impl fmt::Debug for ControlPlaneGenesisBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlPlaneGenesisBackend(<inactive>)")
    }
}

#[async_trait]
impl ExactRootProvider for ControlPlaneGenesisBackend {
    async fn read_exact(
        &self,
        context: &ObjectContext,
    ) -> Result<CiphertextEnvelope, WitnessError> {
        self.roots.read_exact(context).await
    }
}

#[async_trait]
impl ExactKeyRegistryProvider for ControlPlaneGenesisBackend {
    async fn read_exact_wrapped(
        &self,
        context: &KeyRegistryContext,
        object_id: ObjectId,
        destination: &mut [u8],
    ) -> Result<usize, ArchiveV3Error> {
        self.registries
            .read_exact_wrapped(context, object_id, destination)
            .await
    }

    async fn kms_unwrap_exact(
        &self,
        context: &KeyRegistryContext,
        wrapped_registry_ciphertext: &[u8],
        destination: &mut [u8],
    ) -> Result<usize, ArchiveV3Error> {
        self.registries
            .kms_unwrap_exact(context, wrapped_registry_ciphertext, destination)
            .await
    }
}

#[async_trait]
impl ArchiveLifecycleLedger for ControlPlaneGenesisBackend {
    async fn reserve_bootstrap(
        &self,
        plan: BootstrapPlan,
    ) -> Result<DurableBootstrapReservation, LifecycleError> {
        self.control.reserve_bootstrap(plan).await
    }

    async fn prepare_bootstrap(
        &self,
        reservation: DurableBootstrapReservation,
        exact_wrapped_registry: &[u8],
        exact_root_envelope: &[u8],
    ) -> Result<PreparedBootstrap, LifecycleError> {
        self.control
            .prepare_bootstrap(reservation, exact_wrapped_registry, exact_root_envelope)
            .await
    }

    async fn prepare_witness(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        expected_encoded_record: &[u8],
    ) -> Result<u64, LifecycleError> {
        self.control
            .prepare_witness(archive_id, expected_revision, expected_encoded_record)
            .await
    }

    async fn plan_exact_artifact(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        artifact: PlannedArtifact,
    ) -> Result<u64, LifecycleError> {
        self.control
            .plan_exact_artifact(archive_id, expected_revision, artifact)
            .await
    }

    async fn admit_exact_create(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        artifact_ordinal: u32,
    ) -> Result<ActiveCreateAdmission, LifecycleError> {
        self.control
            .admit_exact_create(archive_id, expected_revision, artifact_ordinal)
            .await
    }

    async fn reconcile_create(
        &self,
        admission: &ActiveCreateAdmission,
        outcome: LifecycleCreateOutcome,
    ) -> Result<u64, LifecycleError> {
        self.control.reconcile_create(admission, outcome).await
    }

    async fn adopt_existing_witness(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        exact_encoded_record: &[u8],
    ) -> Result<u64, LifecycleError> {
        self.control
            .adopt_existing_witness(archive_id, expected_revision, exact_encoded_record)
            .await
    }

    async fn freeze_for_deletion(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        deletion_fence: ObjectId,
    ) -> Result<u64, LifecycleError> {
        self.control
            .freeze_for_deletion(archive_id, expected_revision, deletion_fence)
            .await
    }

    async fn freeze_inventory_snapshot(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
        deletion_fence: ObjectId,
    ) -> Result<u64, LifecycleError> {
        self.control
            .freeze_inventory_snapshot(archive_id, expected_revision, deletion_fence)
            .await
    }

    async fn load_inventory_snapshot(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<(u64, Vec<PlannedArtifact>), LifecycleError> {
        self.control
            .load_inventory_snapshot(archive_id, deletion_fence)
            .await
    }

    async fn load_sealed_inventory(
        &self,
        seal: &DeletionInventorySeal,
    ) -> Result<Vec<InventoryPage>, LifecycleError> {
        self.control.load_sealed_inventory(seal).await
    }

    async fn revalidate_active(
        &self,
        archive_id: ArchiveId,
        expected_revision: u64,
    ) -> Result<u64, LifecycleError> {
        self.control
            .revalidate_active(archive_id, expected_revision)
            .await
    }
}

#[async_trait]
impl WitnessCreateDispatchLedger for ControlPlaneGenesisBackend {
    async fn mark_witness_send_started(
        &self,
        admission: &ActiveCreateAdmission,
    ) -> Result<WitnessSendStarted, LifecycleError> {
        self.control.mark_witness_send_started(admission).await
    }
}

#[async_trait]
impl ArchiveGenesisBackend for ControlPlaneGenesisBackend {
    fn witness_bootstrap_creator(&self) -> &dyn WitnessBootstrapCreator {
        self.witness.as_ref()
    }

    async fn read_witness(
        &self,
        archive_id: ArchiveId,
    ) -> Result<Option<WitnessRecord>, BootstrapError> {
        self.witness
            .read_current_async(archive_id)
            .await
            .map_err(BootstrapError::Witness)
    }

    async fn create_registry_if_absent(
        &self,
        admission: &ActiveCreateAdmission,
        context: &KeyRegistryContext,
        object_id: ObjectId,
        wrapped_registry: &[u8],
    ) -> Result<BootstrapCreate, BootstrapError> {
        if admission.artifact_ordinal() != 0 {
            return Err(BootstrapError::Lifecycle(LifecycleError::InvalidState));
        }
        map_create(
            self.registries
                .create_wrapped_if_absent(context, object_id, wrapped_registry)
                .await,
        )
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
        map_create(
            self.objects
                .create_if_absent(context.object_key(), envelope.clone())
                .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{
            ArchiveCipher, ArchiveDek, ArchiveRoot, DatabaseEpoch, InMemoryImmutableBackend,
            KeyEpoch, KeyKind, KeyRegistryPlaintext, LogicalLocation, ObjectRole,
            ARCHIVE_FORMAT_VERSION, SQLITE_PAGE_SIZE,
        },
        archive_v3_firestore_witness::test_transport,
        archive_v3_genesis::{ArchiveGenesis, GenesisResolution},
        archive_v3_lifecycle::BootstrapAttemptId,
        store::tests::{FakeGcs, FakeKms},
    };
    use std::{collections::BTreeMap, sync::Mutex};

    /// Exact-root reads over the same in-memory immutable object store the
    /// composite writes through, mirroring the production root provider's
    /// missing/unavailable mapping.
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

    /// In-memory wrapped-registry store mirroring the genesis FakeBackend's
    /// registry provider bodies (exact bytes, bounded reads, fake unwrap).
    struct FakeRegistryStore {
        registries: Mutex<BTreeMap<ObjectId, Vec<u8>>>,
        plaintext: Vec<u8>,
    }

    #[async_trait]
    impl ExactKeyRegistryProvider for FakeRegistryStore {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            destination: &mut [u8],
        ) -> Result<usize, ArchiveV3Error> {
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
        ) -> Result<usize, ArchiveV3Error> {
            if self.plaintext.len() > destination.len() {
                return Err(ArchiveV3Error::TooLarge("key registry plaintext"));
            }
            destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            Ok(self.plaintext.len())
        }
    }

    #[async_trait]
    impl GenesisRegistryStore for FakeRegistryStore {
        async fn create_wrapped_if_absent(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            wrapped_registry_ciphertext: &[u8],
        ) -> crate::archive_v3::Result<CreateIfAbsent> {
            let mut values = self.registries.lock().unwrap();
            if let Some(existing) = values.get(&object_id) {
                return if existing == wrapped_registry_ciphertext {
                    Ok(CreateIfAbsent::AlreadyPresentIdentical)
                } else {
                    Err(ArchiveV3Error::Conflict)
                };
            }
            values.insert(object_id, wrapped_registry_ciphertext.to_vec());
            Ok(CreateIfAbsent::Created)
        }
    }

    struct Fixture {
        control: Arc<ControlStore>,
        backend: ControlPlaneGenesisBackend,
        genesis: ArchiveGenesis,
        reservation: DurableBootstrapReservation,
        wrapped_registry: Vec<u8>,
        root_envelope: Vec<u8>,
    }

    async fn fixture() -> Fixture {
        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let binding = control
            .create_genesis_test_binding("11111111-1111-4111-8111-111111111111")
            .await
            .unwrap();
        let archive_id = binding.archive_id();
        let database_epoch = DatabaseEpoch::from_bytes([2; 16]);
        let key_epoch = KeyEpoch::from_bytes([3; 16]);
        let registry_object_id = ObjectId::from_bytes([4; 16]);
        let root_object_id = ObjectId::from_bytes([5; 16]);
        let plan = BootstrapPlan::new(
            archive_id,
            BootstrapAttemptId::from_bytes([20; 16]).unwrap(),
            database_epoch,
            key_epoch,
            registry_object_id,
            root_object_id,
        )
        .unwrap();

        let registry_context = KeyRegistryContext::new(archive_id, KeyKind::Archive, key_epoch);
        let plaintext = KeyRegistryPlaintext::encode_archive(
            &registry_context,
            &ArchiveDek::from_bytes([9; 32]),
        )
        .unwrap()
        .to_vec();
        let cipher = ArchiveCipher::new(ArchiveDek::from_bytes([9; 32]));
        let root_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            root_object_id,
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
        let root_envelope = cipher
            .seal(&root_context, &root.encode().unwrap())
            .unwrap()
            .encode();
        let wrapped_registry = b"wrapped-registry".to_vec();

        let ledger: &dyn ArchiveLifecycleLedger = control.as_ref();
        let reservation = ledger.reserve_bootstrap(plan).await.unwrap();
        let prepared = ledger
            .prepare_bootstrap(reservation, &wrapped_registry, &root_envelope)
            .await
            .unwrap();
        let genesis = ArchiveGenesis::new(prepared).unwrap();

        let objects = Arc::new(InMemoryImmutableBackend::new());
        let witness = Arc::new(test_transport::witness_over_fake(Arc::new(
            test_transport::FakeTransport::new(None, []),
        )));
        let backend = ControlPlaneGenesisBackend::new(
            GenesisBackendRuntimeContext::for_test(),
            Arc::clone(&control),
            Arc::clone(&objects) as Arc<dyn ImmutableObjectBackend>,
            Arc::new(InMemoryRootProvider(objects)),
            Arc::new(FakeRegistryStore {
                registries: Mutex::new(BTreeMap::new()),
                plaintext,
            }),
            witness,
        );
        Fixture {
            control,
            backend,
            genesis,
            reservation,
            wrapped_registry,
            root_envelope,
        }
    }

    #[tokio::test]
    async fn resolve_against_real_control_ledger_creates_then_adopts_existing() {
        let fixture = fixture().await;
        assert_eq!(
            fixture.genesis.resolve(&fixture.backend).await.unwrap(),
            GenesisResolution::Created
        );
        assert_eq!(
            fixture.genesis.resolve(&fixture.backend).await.unwrap(),
            GenesisResolution::Existing
        );
    }

    #[tokio::test]
    async fn resolve_after_durable_prepared_bootstrap_replay_adopts_existing() {
        let fixture = fixture().await;
        assert_eq!(
            fixture.genesis.resolve(&fixture.backend).await.unwrap(),
            GenesisResolution::Created
        );
        // A restart recovers the exact durable prepared bytes and revision;
        // the rerun authenticates the existing witness instead of recreating.
        let ledger: &dyn ArchiveLifecycleLedger = fixture.control.as_ref();
        let replayed = ledger
            .prepare_bootstrap(
                fixture.reservation,
                &fixture.wrapped_registry,
                &fixture.root_envelope,
            )
            .await
            .unwrap();
        let rerun = ArchiveGenesis::new(replayed).unwrap();
        assert_eq!(
            rerun.resolve(&fixture.backend).await.unwrap(),
            GenesisResolution::Existing
        );
    }

    #[tokio::test]
    async fn create_hooks_reject_admissions_for_other_ordinals() {
        let fixture = fixture().await;
        assert_eq!(
            fixture.genesis.resolve(&fixture.backend).await.unwrap(),
            GenesisResolution::Created
        );
        let admission = crate::archive_v3_lifecycle::ActiveCreateAdmission::for_test(
            crate::archive_v3::ArchiveId::from_bytes([1; 16]),
            BootstrapAttemptId::from_bytes([20; 16]).unwrap(),
            3,
            2,
            [7; 32],
        )
        .unwrap();
        let context = KeyRegistryContext::new(
            crate::archive_v3::ArchiveId::from_bytes([1; 16]),
            KeyKind::Archive,
            KeyEpoch::from_bytes([3; 16]),
        );
        assert_eq!(
            fixture
                .backend
                .create_registry_if_absent(
                    &admission,
                    &context,
                    ObjectId::from_bytes([4; 16]),
                    b"wrapped-registry",
                )
                .await,
            Err(BootstrapError::Lifecycle(LifecycleError::InvalidState))
        );
    }
}
