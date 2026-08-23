#![allow(
    dead_code,
    reason = "the conditionally active runtime retains sealed migration-only capability variants"
)]

//! Sealed ADR-0022 single-archive WAL runtime composition.
//!
//! This module accepts only typed deployment fragments and builds the fixed
//! archive-GCS, registry-KMS, and named-Firestore provider graph. Construction
//! is synchronous and performs no provider request. The graph remains pending
//! until it consumes one opaque durable control-store archive binding whose
//! domain-separated commitment exactly matches the image-baked deployment
//! claim. Before a typed consuming transition, every capability remains behind
//! private fields: there is no handle, getter, callback, task, worker,
//! acknowledgement, persistent-state/VFS hook, route, health signal,
//! admission input, or deletion driver. The GCS
//! hard-delete gate is permanently false until a later independently audited
//! slice supplies authenticated lifecycle evidence.
//! The sealed owner has two type-separated consumers: an advisory importer
//! that can stop only at verified ShadowWal, and the later authority importer.
//! The signed active image profile is consumed only by startup relaunch and the
//! Genesis trigger. The deleted advisory path cannot be reconstructed; the
//! surviving maintenance-only variants remain token-gated and are not selected
//! by the Genesis-first rollout.

use std::{fmt, sync::Arc};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    archive_v3::{
        resolve_archive_cipher, ArchiveId, ExactKeyRegistryProvider, ImmutableObjectBackend,
        KeyKind, KeyRegistryContext, ObjectId, VerifiedArchiveCipher,
    },
    archive_v3_deletion_lane::{ArchiveDeletionRuntime, ArchiveDeletionRuntimeFactory},
    archive_v3_firestore_shadow::FirestoreShadowWitness,
    archive_v3_firestore_witness::{
        FirestoreWitness, FirestoreWitnessCommitError, FirestoreWitnessConfig,
    },
    archive_v3_gcs::{
        ArchiveV3GcsTransport, GcsArchiveV3Backend, GcsArchiveV3RegistryProvider,
        GcsArchiveV3RootProvider, GcsExactReachabilityReader,
    },
    archive_v3_gcs_auth::{ArchiveV3GcsAttestationBearer, ArchiveV3GcsAudience},
    archive_v3_gcs_http::{
        valid_archive_v3_bucket_name, ArchiveV3SoftDeleteDrainGate, GcpArchiveV3HttpTransport,
        GcpLifecyclePageHttpTransport,
    },
    archive_v3_lifecycle::ArchiveLifecyclePageStore,
    archive_v3_lifecycle_page_store::{EncryptedLifecyclePageStore, LifecyclePageControlKey},
    archive_v3_maintenance_import::{
        AuthenticatedMaintenanceImportPlan, MaintenanceImportError,
        MaintenanceImportWitnessProvider, SingleArchiveMaintenanceImporter,
    },
    archive_v3_reachability::ExactReachabilityReader,
    archive_v3_registry_kms::GcpArchiveV3RegistryKms,
    archive_v3_shadow_coordinator::ShadowCheckpointWitnessProvider,
    archive_v3_witness::{
        control_deletion_authenticator, DeletionPrincipalKey, ExactRootProvider, RootAdvance,
        WitnessError, WitnessLease, WitnessRecord,
    },
    cp::control_store::{ArchiveBinding, ControlStore},
    crypto::GcpKmsClient,
};

struct WalPublisherExactObjects {
    inner: Arc<dyn ImmutableObjectBackend>,
}

#[async_trait::async_trait]
impl crate::archive_v3_shadow_checkpoint::ExactImmutableObjectBackend for WalPublisherExactObjects {
    async fn create_if_absent(
        &self,
        key: crate::archive_v3::ObjectKey,
        value: crate::archive_v3::CiphertextEnvelope,
    ) -> crate::archive_v3::Result<crate::archive_v3::CreateIfAbsent> {
        self.inner.create_if_absent(key, value).await
    }

    async fn get(
        &self,
        key: &crate::archive_v3::ObjectKey,
    ) -> crate::archive_v3::Result<Option<crate::archive_v3::CiphertextEnvelope>> {
        self.inner.get(key).await
    }
}

const ARCHIVE_BINDING_COMMITMENT_DOMAIN: &[u8] =
    b"kioku/archive-v3/single-archive-wal-runtime-binding/v1\0";

/// Redacted construction result. It never carries provider paths, deployment
/// identifiers, bearer material, or response bodies.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum ArchiveV3ShadowRuntimeConstructionError {
    #[error("archive-v3 shadow runtime deployment is invalid")]
    InvalidDeployment,
    #[error("archive-v3 shadow runtime construction is unavailable")]
    Unavailable,
}

/// Image-baked commitment to exactly one opaque durable archive identity.
/// The commitment has no archive-ID getter and its Debug output is redacted.
#[derive(PartialEq, Eq)]
pub(crate) struct ArchiveV3ArchiveBindingCommitment([u8; 32]);

impl ArchiveV3ArchiveBindingCommitment {
    fn from_lower_hex(value: &str) -> Result<Self, ArchiveV3ShadowRuntimeConstructionError> {
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || value.bytes().all(|byte| byte == b'0')
        {
            return Err(ArchiveV3ShadowRuntimeConstructionError::InvalidDeployment);
        }
        let mut decoded = [0u8; 32];
        for (output, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *output = (lower_hex_nibble(pair[0]) << 4) | lower_hex_nibble(pair[1]);
        }
        Ok(Self(decoded))
    }

    fn for_archive(archive_id: ArchiveId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ARCHIVE_BINDING_COMMITMENT_DOMAIN);
        hasher.update(archive_id.as_bytes());
        Self(hasher.finalize().into())
    }
}

/// Return the image-configuration value for one already durable Control
/// binding without exposing its opaque archive identifier. This is used only
/// by the authenticated, administrator-only activation bootstrap route while
/// the baked runtime profile is still off.
pub(crate) fn activation_binding_commitment(binding: ArchiveBinding) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let commitment = ArchiveV3ArchiveBindingCommitment::for_archive(binding.archive_id());
    let mut encoded = String::with_capacity(64);
    for byte in commitment.0 {
        encoded.push(LOWER_HEX[usize::from(byte >> 4)] as char);
        encoded.push(LOWER_HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

impl fmt::Debug for ArchiveV3ArchiveBindingCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveV3ArchiveBindingCommitment(<redacted>)")
    }
}

/// Exact, image-bound fragments from which all provider coordinates are
/// derived. Full GCS endpoints, WIF audiences, KMS resource names, and
/// Firestore document paths are deliberately not accepted.
pub(crate) struct ArchiveV3ShadowRuntimeDeployment {
    archive_bucket: String,
    archive_gcs_project_number: String,
    registry_kms_version: String,
    witness_project_id: String,
    witness_project_number: String,
    witness_database_id: String,
    archive_binding_commitment: ArchiveV3ArchiveBindingCommitment,
}

impl ArchiveV3ShadowRuntimeDeployment {
    /// Read the image-baked shadow-runtime deployment from the allowlisted
    /// environment installed by `load_baked_image_configuration`.
    ///
    /// Semantics mirror the config grammar exactly: mode `off` (or an entirely
    /// absent mode, the pre-activation image shape) requires every coordinate to
    /// be empty and yields `None`; any stray fragment alongside `off` fails
    /// closed. Only the exact mode `single-archive-wal-v1` constructs a
    /// deployment, revalidating every coordinate through `Self::new`.
    pub(crate) fn from_baked_env() -> Result<Option<Self>, ArchiveV3ShadowRuntimeConstructionError>
    {
        fn baked(name: &str) -> String {
            std::env::var(name).unwrap_or_default()
        }
        let mode = baked("ARCHIVE_V3_SHADOW_RUNTIME_MODE");
        let coordinates = [
            baked("ARCHIVE_V3_ARCHIVE_BUCKET"),
            baked("ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER"),
            baked("ARCHIVE_V3_REGISTRY_KMS_VERSION"),
            baked("ARCHIVE_V3_WITNESS_PROJECT_ID"),
            baked("ARCHIVE_V3_WITNESS_PROJECT_NUMBER"),
            baked("ARCHIVE_V3_WITNESS_DATABASE_ID"),
            baked("ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT"),
        ];
        Self::from_mode_and_coordinates(
            &mode,
            [
                &coordinates[0],
                &coordinates[1],
                &coordinates[2],
                &coordinates[3],
                &coordinates[4],
                &coordinates[5],
                &coordinates[6],
            ],
        )
    }

    /// Environment-free core of [`Self::from_baked_env`], shared with tests.
    pub(crate) fn from_mode_and_coordinates(
        mode: &str,
        coordinates: [&str; 7],
    ) -> Result<Option<Self>, ArchiveV3ShadowRuntimeConstructionError> {
        match mode {
            "" | "off" => {
                if coordinates.iter().any(|value| !value.is_empty()) {
                    return Err(ArchiveV3ShadowRuntimeConstructionError::InvalidDeployment);
                }
                Ok(None)
            }
            "single-archive-wal-v1" => Self::new(
                coordinates[0],
                coordinates[1],
                coordinates[2],
                coordinates[3],
                coordinates[4],
                coordinates[5],
                coordinates[6],
            )
            .map(Some),
            _ => Err(ArchiveV3ShadowRuntimeConstructionError::InvalidDeployment),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        archive_bucket: &str,
        archive_gcs_project_number: &str,
        registry_kms_version: &str,
        witness_project_id: &str,
        witness_project_number: &str,
        witness_database_id: &str,
        archive_binding_commitment: &str,
    ) -> Result<Self, ArchiveV3ShadowRuntimeConstructionError> {
        if !valid_archive_v3_bucket_name(archive_bucket)
            || !canonical_numeric_id(archive_gcs_project_number)
            || !canonical_numeric_id(registry_kms_version)
            || !canonical_numeric_id(witness_project_number)
            || ArchiveV3GcsAudience::for_project_number(archive_gcs_project_number).is_err()
            || FirestoreWitnessConfig::new(
                witness_project_id,
                witness_project_number,
                witness_database_id,
            )
            .is_err()
        {
            return Err(ArchiveV3ShadowRuntimeConstructionError::InvalidDeployment);
        }
        let archive_binding_commitment =
            ArchiveV3ArchiveBindingCommitment::from_lower_hex(archive_binding_commitment)?;
        Ok(Self {
            archive_bucket: archive_bucket.to_owned(),
            archive_gcs_project_number: archive_gcs_project_number.to_owned(),
            registry_kms_version: registry_kms_version.to_owned(),
            witness_project_id: witness_project_id.to_owned(),
            witness_project_number: witness_project_number.to_owned(),
            witness_database_id: witness_database_id.to_owned(),
            archive_binding_commitment,
        })
    }
}

impl fmt::Debug for ArchiveV3ShadowRuntimeDeployment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveV3ShadowRuntimeDeployment(<redacted>)")
    }
}

/// Private-field token proving deletion providers came from this sealed
/// runtime composer rather than being released from the Firestore bundle by a
/// route or Store helper.
pub(crate) struct DeletionRuntimeContext(());

/// Production factory for the one image-bound archive deletion runtime.
/// Construction is provider-I/O-free; every per-archive call revalidates the
/// baked commitment before releasing exact-name read/delete capabilities.
pub(crate) struct ProductionArchiveDeletionRuntimeFactory {
    deployment: Arc<ArchiveV3ShadowRuntimeDeployment>,
    kms: Arc<GcpKmsClient>,
    control: Arc<ControlStore>,
    lifecycle_page_key: Arc<LifecyclePageControlKey>,
    principal_key: Arc<DeletionPrincipalKey>,
}

impl ProductionArchiveDeletionRuntimeFactory {
    pub(crate) fn new(
        deployment: ArchiveV3ShadowRuntimeDeployment,
        kms: Arc<GcpKmsClient>,
        control: Arc<ControlStore>,
        lifecycle_page_key: Arc<LifecyclePageControlKey>,
        principal_key: Arc<DeletionPrincipalKey>,
    ) -> Self {
        Self {
            deployment: Arc::new(deployment),
            kms,
            control,
            lifecycle_page_key,
            principal_key,
        }
    }
}

struct ProductionArchiveDeletionRuntime {
    archive_id: ArchiveId,
    witness: Arc<FirestoreWitness>,
    reader: Arc<GcsExactReachabilityReader>,
    pages: Arc<EncryptedLifecyclePageStore>,
    transport: Arc<dyn ArchiveV3GcsTransport>,
    registries: Arc<GcsArchiveV3RegistryProvider>,
}

#[async_trait::async_trait]
impl ArchiveDeletionRuntimeFactory for ProductionArchiveDeletionRuntimeFactory {
    async fn runtime_for(
        &self,
        archive_id: ArchiveId,
    ) -> crate::error::Result<Arc<dyn ArchiveDeletionRuntime>> {
        if ArchiveV3ArchiveBindingCommitment::for_archive(archive_id)
            != self.deployment.archive_binding_commitment
        {
            return Err(crate::error::EnclaveError::Store(
                "archive deletion binding does not match the baked runtime".into(),
            ));
        }
        let audience =
            ArchiveV3GcsAudience::for_project_number(&self.deployment.archive_gcs_project_number)
                .map_err(|_| {
                crate::error::EnclaveError::Store("archive deletion runtime unavailable".into())
            })?;
        let bearer = Arc::new(ArchiveV3GcsAttestationBearer::new(audience).map_err(|_| {
            crate::error::EnclaveError::Store("archive deletion runtime unavailable".into())
        })?);
        let concrete_transport = Arc::new(
            GcpArchiveV3HttpTransport::new(
                self.deployment.archive_bucket.clone(),
                bearer,
                Arc::new(ConstructionOnlyDrainGate),
            )
            .map_err(|_| {
                crate::error::EnclaveError::Store("archive deletion runtime unavailable".into())
            })?,
        );
        let transport: Arc<dyn ArchiveV3GcsTransport> = concrete_transport.clone();
        let registry_kms = Arc::new(
            GcpArchiveV3RegistryKms::new(
                Arc::clone(&self.kms),
                &self.deployment.registry_kms_version,
            )
            .map_err(|_| {
                crate::error::EnclaveError::Store("archive deletion runtime unavailable".into())
            })?,
        );
        let registries = Arc::new(GcsArchiveV3RegistryProvider::new(
            Arc::clone(&transport),
            registry_kms,
        ));
        let witness_config = FirestoreWitnessConfig::new(
            &self.deployment.witness_project_id,
            &self.deployment.witness_project_number,
            &self.deployment.witness_database_id,
        )
        .map_err(|_| {
            crate::error::EnclaveError::Store("archive deletion runtime unavailable".into())
        })?;
        let witness_owner = FirestoreShadowWitness::new_with_deletion_authority(
            witness_config,
            control_deletion_authenticator(Arc::clone(&self.principal_key)),
        )
        .map_err(|_| {
            crate::error::EnclaveError::Store("archive deletion runtime unavailable".into())
        })?;
        let witness = witness_owner.deletion_firestore_witness(&DeletionRuntimeContext(()));
        let lifecycle_transport = Arc::new(GcpLifecyclePageHttpTransport::new(concrete_transport));
        let admissions: Arc<
            dyn crate::archive_v3_lifecycle_page_store::LifecyclePageAdmissionLedger,
        > = self.control.clone();
        let pages = Arc::new(EncryptedLifecyclePageStore::new(
            Arc::clone(&self.lifecycle_page_key),
            lifecycle_transport,
            admissions,
        ));
        Ok(Arc::new(ProductionArchiveDeletionRuntime {
            archive_id,
            witness,
            reader: Arc::new(GcsExactReachabilityReader::new(Arc::clone(&transport))),
            pages,
            transport,
            registries,
        }))
    }
}

#[async_trait::async_trait]
impl ArchiveDeletionRuntime for ProductionArchiveDeletionRuntime {
    fn witness(&self) -> Arc<dyn crate::archive_v3_deletion_lane::DeletionLaneWitness> {
        self.witness.clone()
    }

    fn reader(&self) -> Arc<dyn ExactReachabilityReader> {
        self.reader.clone()
    }

    fn page_store(&self) -> Arc<dyn ArchiveLifecyclePageStore> {
        self.pages.clone()
    }

    fn transport(&self) -> Arc<dyn ArchiveV3GcsTransport> {
        Arc::clone(&self.transport)
    }

    async fn ciphers(
        &self,
    ) -> crate::error::Result<(VerifiedArchiveCipher, Option<VerifiedArchiveCipher>)> {
        let record = self
            .witness
            .read_current_async(self.archive_id)
            .await
            .map_err(|_| {
                crate::error::EnclaveError::Store("archive deletion witness unavailable".into())
            })?
            .ok_or_else(|| {
                crate::error::EnclaveError::Store("archive deletion witness missing".into())
            })?;
        let current =
            resolve_deletion_cipher(self.archive_id, record.registry(), self.registries.as_ref())
                .await?;
        let predecessor = match record.predecessor_registry() {
            Some(registry) => Some(
                resolve_deletion_cipher(self.archive_id, registry, self.registries.as_ref())
                    .await?,
            ),
            None => None,
        };
        Ok((current, predecessor))
    }
}

async fn resolve_deletion_cipher(
    archive_id: ArchiveId,
    registry: crate::archive_v3_witness::KeyRegistryReference,
    provider: &dyn ExactKeyRegistryProvider,
) -> crate::error::Result<VerifiedArchiveCipher> {
    let context = KeyRegistryContext::with_rotation_generation(
        archive_id,
        KeyKind::Archive,
        registry.key_epoch(),
        registry.rotation_generation(),
    );
    resolve_archive_cipher(
        &context,
        registry.object_id(),
        registry.ciphertext_hash(),
        provider,
    )
    .await
    .map_err(|_| crate::error::EnclaveError::Store("archive deletion registry unavailable".into()))
}

/// Private provider owner. It is never returned without exact durable binding.
pub(crate) struct ArchiveV3ShadowRuntimeBundle {
    objects: Arc<dyn ImmutableObjectBackend>,
    roots: Arc<dyn ExactRootProvider>,
    registries: Arc<dyn ExactKeyRegistryProvider>,
    /// Concrete registry provider retained beside its erased trait handle so
    /// the token-gated genesis accessor can release wrap/create capability
    /// that does not survive the `Arc<dyn ExactKeyRegistryProvider>` erasure.
    /// Only the production constructor populates it.
    genesis_registries: Option<Arc<GcsArchiveV3RegistryProvider>>,
    _witness: Arc<dyn ShadowCheckpointWitnessProvider>,
    maintenance_witness: Option<Arc<dyn MaintenanceImportWitnessProvider>>,
    wal_owner_witness: Option<Arc<FirestoreShadowWitness>>,
}

impl ArchiveV3ShadowRuntimeBundle {
    /// Build fixed-origin clients without reading environment or performing
    /// provider I/O. Merely constructing this inert owner grants no operation
    /// that can read, create, delete, witness, route, or influence authority.
    fn new(
        deployment: &ArchiveV3ShadowRuntimeDeployment,
        kms: Arc<GcpKmsClient>,
    ) -> Result<Self, ArchiveV3ShadowRuntimeConstructionError> {
        let audience =
            ArchiveV3GcsAudience::for_project_number(&deployment.archive_gcs_project_number)
                .map_err(map_gcs_construction_error)?;
        let bearer = Arc::new(
            ArchiveV3GcsAttestationBearer::new(audience).map_err(map_gcs_construction_error)?,
        );
        let drain = Arc::new(ConstructionOnlyDrainGate);
        let transport: Arc<dyn ArchiveV3GcsTransport> = Arc::new(
            GcpArchiveV3HttpTransport::new(deployment.archive_bucket.clone(), bearer, drain)
                .map_err(map_gcs_construction_error)?,
        );
        let registry_kms = Arc::new(
            GcpArchiveV3RegistryKms::new(kms, &deployment.registry_kms_version)
                .map_err(map_gcs_construction_error)?,
        );
        let witness_config = FirestoreWitnessConfig::new(
            &deployment.witness_project_id,
            &deployment.witness_project_number,
            &deployment.witness_database_id,
        )
        .map_err(|_| ArchiveV3ShadowRuntimeConstructionError::InvalidDeployment)?;
        let objects: Arc<dyn ImmutableObjectBackend> =
            Arc::new(GcsArchiveV3Backend::new(Arc::clone(&transport)));
        let witness: Arc<FirestoreShadowWitness> = Arc::new(
            FirestoreShadowWitness::new(witness_config)
                .map_err(|_| ArchiveV3ShadowRuntimeConstructionError::Unavailable)?,
        );
        let genesis_registries = Arc::new(GcsArchiveV3RegistryProvider::new(
            Arc::clone(&transport),
            registry_kms,
        ));
        Ok(Self {
            objects,
            roots: Arc::new(GcsArchiveV3RootProvider::new(transport)),
            registries: genesis_registries.clone(),
            genesis_registries: Some(genesis_registries),
            _witness: witness.clone(),
            maintenance_witness: Some(witness.clone()),
            wal_owner_witness: Some(witness),
        })
    }

    fn from_components(components: ShadowRuntimeComponents) -> Self {
        Self {
            objects: components.objects,
            roots: components.roots,
            registries: components.registries,
            genesis_registries: None,
            _witness: components.witness,
            maintenance_witness: None,
            wal_owner_witness: None,
        }
    }

    pub(crate) fn maintenance_objects_owned(
        &self,
        _token: &MaintenanceRuntimeContext,
    ) -> Arc<dyn ImmutableObjectBackend> {
        Arc::clone(&self.objects)
    }

    pub(crate) fn maintenance_registries(
        &self,
        _token: &MaintenanceRuntimeContext,
    ) -> &dyn ExactKeyRegistryProvider {
        self.registries.as_ref()
    }

    pub(crate) fn maintenance_witness(
        &self,
        _token: &MaintenanceRuntimeContext,
    ) -> Option<&Arc<dyn MaintenanceImportWitnessProvider>> {
        self.maintenance_witness.as_ref()
    }

    /// Token-gated release of the exact-root reader for the reviewed genesis
    /// backend composition. The Genesis trigger is the token's sole
    /// production minter.
    pub(crate) fn genesis_exact_roots(
        &self,
        _token: &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext,
    ) -> Arc<dyn ExactRootProvider> {
        Arc::clone(&self.roots)
    }

    /// Token-gated release of the concrete registry provider (wrap/create
    /// capability included) that the bundle's erased trait handle withholds.
    /// `None` outside the production constructor.
    pub(crate) fn genesis_registry_provider(
        &self,
        _token: &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext,
    ) -> Option<Arc<GcsArchiveV3RegistryProvider>> {
        self.genesis_registries.clone()
    }

    /// Token-gated release of the immutable-object backend for the reviewed
    /// genesis producer. It is the same handle the maintenance importer
    /// receives; the separate accessor exists so the genesis composition never
    /// has to mint a maintenance token to reach it.
    pub(crate) fn genesis_objects(
        &self,
        _token: &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext,
    ) -> Arc<dyn ImmutableObjectBackend> {
        Arc::clone(&self.objects)
    }

    /// Token-gated release of the Firestore witness adapter the genesis
    /// backend needs for the sealed initial-witness create protocol. `None`
    /// outside the production constructor.
    pub(crate) fn genesis_firestore_witness(
        &self,
        token: &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext,
    ) -> Option<Arc<crate::archive_v3_firestore_witness::FirestoreWitness>> {
        self.wal_owner_witness
            .as_ref()
            .map(|witness| witness.genesis_firestore_witness(token))
    }

    /// Token-gated release of the exact witness-advance provider for the
    /// reviewed genesis witness ladder (G6). Like the accessors above, this is
    /// reachable only through the Genesis trigger's private token. `None`
    /// outside the production constructor.
    pub(crate) fn genesis_witness_advance(
        &self,
        _token: &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext,
    ) -> Option<Arc<dyn crate::archive_v3_root_advance::ArchiveWitnessAdvanceProvider>> {
        self.wal_owner_witness.clone().map(|witness| {
            witness as Arc<dyn crate::archive_v3_root_advance::ArchiveWitnessAdvanceProvider>
        })
    }

    pub(crate) fn into_wal_publisher(
        self,
        _token: crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
    ) -> Result<WalPublisherRuntimeOwner, ArchiveV3ShadowRuntimeConstructionError> {
        if self.wal_owner_witness.is_none() {
            return Err(ArchiveV3ShadowRuntimeConstructionError::Unavailable);
        }
        Ok(WalPublisherRuntimeOwner { bundle: self })
    }

    /// Test-only publisher-capable bundle over the shared fake Firestore
    /// witness, for the WAL-owner launch end-to-end tests. Identical to the
    /// maintenance test bundle plus the publisher witness the production
    /// constructor bakes.
    #[cfg(test)]
    pub(crate) fn from_publisher_test_components<W>(
        objects: Arc<dyn ImmutableObjectBackend>,
        registries: Arc<dyn ExactKeyRegistryProvider>,
        witness: Arc<W>,
        wal_owner_witness: Arc<crate::archive_v3_firestore_shadow::FirestoreShadowWitness>,
    ) -> Self
    where
        W: crate::archive_v3_maintenance_import::MaintenanceImportWitnessProvider + 'static,
    {
        let mut bundle = Self::from_maintenance_test_components(objects, registries, witness);
        bundle.wal_owner_witness = Some(wal_owner_witness);
        bundle
    }

    #[cfg(test)]
    pub(crate) fn from_maintenance_test_components<W>(
        objects: Arc<dyn ImmutableObjectBackend>,
        registries: Arc<dyn ExactKeyRegistryProvider>,
        witness: Arc<W>,
    ) -> Self
    where
        W: MaintenanceImportWitnessProvider + 'static,
    {
        let maintenance_witness: Arc<dyn MaintenanceImportWitnessProvider> = witness.clone();
        Self {
            objects,
            roots: Arc::new(UnavailableRootProvider),
            registries,
            genesis_registries: None,
            _witness: Arc::new(UnavailableShadowWitnessProvider),
            maintenance_witness: Some(maintenance_witness),
            wal_owner_witness: None,
        }
    }
}

/// Opaque consuming runtime view. It owns the whole original bundle and
/// exposes only operations needed by the private publisher child.
pub(crate) struct WalPublisherRuntimeOwner {
    bundle: ArchiveV3ShadowRuntimeBundle,
}

impl WalPublisherRuntimeOwner {
    pub(crate) fn objects_owned(
        &self,
        _token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
    ) -> Arc<dyn crate::archive_v3_shadow_checkpoint::ExactImmutableObjectBackend> {
        Arc::new(WalPublisherExactObjects {
            inner: Arc::clone(&self.bundle.objects),
        })
    }

    fn wal_owner_witness(&self) -> &FirestoreShadowWitness {
        self.bundle
            .wal_owner_witness
            .as_deref()
            .expect("validated by consuming constructor")
    }

    pub(crate) async fn resolve_wal_owner_cipher(
        &self,
        _token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        witness: &WitnessRecord,
    ) -> crate::archive_v3::Result<VerifiedArchiveCipher> {
        let registry = witness.registry();
        let context = KeyRegistryContext::with_rotation_generation(
            witness.archive_id(),
            KeyKind::Archive,
            registry.key_epoch(),
            registry.rotation_generation(),
        );
        resolve_archive_cipher(
            &context,
            registry.object_id(),
            registry.ciphertext_hash(),
            self.bundle.registries.as_ref(),
        )
        .await
    }

    pub(crate) async fn read_wal_owner_current_exact(
        &self,
        token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        archive_id: ArchiveId,
    ) -> Result<WitnessRecord, WitnessError> {
        self.wal_owner_witness()
            .wal_owner_read_current_exact(token, archive_id)
            .await
    }

    pub(crate) async fn acquire_wal_owner_lease_unresolved(
        &self,
        token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        expected: WitnessRecord,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        self.wal_owner_witness()
            .wal_owner_acquire_unresolved(token, expected, owner, duration_ticks)
            .await
    }

    pub(crate) async fn renew_wal_owner_lease_unresolved(
        &self,
        token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        retained: WitnessRecord,
        lease: WitnessLease,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        self.wal_owner_witness()
            .wal_owner_renew_unresolved(token, retained, lease, duration_ticks)
            .await
    }

    pub(crate) async fn reacquire_wal_owner_lease_unresolved(
        &self,
        token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        previous: WitnessRecord,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        self.wal_owner_witness()
            .wal_owner_reacquire_unresolved(token, previous, owner, duration_ticks)
            .await
    }

    pub(crate) async fn maintain_wal_owner_lease_unresolved(
        &self,
        token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        previous: WitnessRecord,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        self.wal_owner_witness()
            .wal_owner_maintain_unresolved(token, previous, owner, duration_ticks)
            .await
    }

    pub(crate) async fn advance_wal_owner_root_unresolved(
        &self,
        token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        expected: &WitnessRecord,
        advance: RootAdvance,
    ) -> Result<(), FirestoreWitnessCommitError> {
        self.wal_owner_witness()
            .wal_owner_advance_unresolved(token, expected, advance)
            .await
    }
}

impl fmt::Debug for WalPublisherRuntimeOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalPublisherRuntimeOwner(<inactive>)")
    }
}

/// Pending, non-cloneable single-archive runtime capability. It owns the
/// provider graph but exposes no operation before consuming the durable
/// binding, and consumption makes a second bind impossible.
pub(crate) struct PendingSingleArchiveWalRuntime {
    bundle: ArchiveV3ShadowRuntimeBundle,
    expected_binding: ArchiveV3ArchiveBindingCommitment,
}

impl PendingSingleArchiveWalRuntime {
    pub(crate) fn new(
        deployment: ArchiveV3ShadowRuntimeDeployment,
        kms: Arc<GcpKmsClient>,
    ) -> Result<Self, ArchiveV3ShadowRuntimeConstructionError> {
        let bundle = ArchiveV3ShadowRuntimeBundle::new(&deployment, kms)?;
        Ok(Self {
            bundle,
            expected_binding: deployment.archive_binding_commitment,
        })
    }

    /// Synchronously bind this one-shot capability to the exact durable
    /// archive identity committed by the image. This performs no provider I/O.
    pub(crate) fn bind_once(
        self,
        binding: DurableSingleArchiveBinding,
    ) -> Result<SealedSingleArchiveWalRuntime, ArchiveV3ShadowRuntimeConstructionError> {
        if ArchiveV3ArchiveBindingCommitment::for_archive(binding.binding.archive_id())
            != self.expected_binding
        {
            return Err(ArchiveV3ShadowRuntimeConstructionError::InvalidDeployment);
        }
        Ok(SealedSingleArchiveWalRuntime {
            binding,
            bundle: self.bundle,
        })
    }

    #[cfg(test)]
    fn from_test_components(
        expected_binding: ArchiveV3ArchiveBindingCommitment,
        components: ShadowRuntimeComponents,
    ) -> Self {
        Self {
            bundle: ArchiveV3ShadowRuntimeBundle::from_components(components),
            expected_binding,
        }
    }
}

impl fmt::Debug for PendingSingleArchiveWalRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingSingleArchiveWalRuntime(<inactive>)")
    }
}

/// Opaque durable-binding capability. Production construction accepts only
/// the encrypted control store's private `ArchiveBinding`, never a user ID,
/// account ID, string, or caller-supplied raw archive bytes.
pub(crate) struct DurableSingleArchiveBinding {
    binding: ArchiveBinding,
}

impl DurableSingleArchiveBinding {
    pub(crate) fn from_control_store(binding: ArchiveBinding) -> Self {
        Self { binding }
    }
}

impl fmt::Debug for DurableSingleArchiveBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableSingleArchiveBinding(<opaque>)")
    }
}

/// Bound but deliberately inert runtime owner. Its archive identity and all
/// providers remain private and it exposes no read, write, capture, witness,
/// acknowledgement, task, callback, or deletion operation.
pub(crate) struct SealedSingleArchiveWalRuntime {
    binding: DurableSingleArchiveBinding,
    bundle: ArchiveV3ShadowRuntimeBundle,
}

/// Private-field token proving that raw runtime providers were consumed by
/// the sealed runtime rather than assembled by a sibling module.
pub(crate) struct MaintenanceRuntimeContext(());

#[cfg(test)]
impl MaintenanceRuntimeContext {
    pub(crate) const fn for_test() -> Self {
        Self(())
    }
}

impl SealedSingleArchiveWalRuntime {
    #[cfg(test)]
    pub(crate) fn for_test<W>(
        archive_id: ArchiveId,
        objects: Arc<dyn ImmutableObjectBackend>,
        registries: Arc<dyn ExactKeyRegistryProvider>,
        witness: Arc<W>,
    ) -> Self
    where
        W: MaintenanceImportWitnessProvider + 'static,
    {
        let bundle = ArchiveV3ShadowRuntimeBundle::from_maintenance_test_components(
            objects, registries, witness,
        );
        let binding = DurableSingleArchiveBinding::from_control_store(
            crate::cp::control_store::ArchiveBinding::for_runtime_test(archive_id),
        );
        Self { binding, bundle }
    }

    /// Publisher-capable sealed runtime over the shared fakes plus the
    /// durable control-store archive binding, for the genesis relaunch
    /// end-to-end tests.
    #[cfg(test)]
    pub(crate) fn for_publisher_test<W>(
        binding: ArchiveBinding,
        objects: Arc<dyn ImmutableObjectBackend>,
        registries: Arc<dyn ExactKeyRegistryProvider>,
        witness: Arc<W>,
        wal_owner_witness: Arc<FirestoreShadowWitness>,
    ) -> Self
    where
        W: MaintenanceImportWitnessProvider + 'static,
    {
        Self {
            binding: DurableSingleArchiveBinding::from_control_store(binding),
            bundle: ArchiveV3ShadowRuntimeBundle::from_publisher_test_components(
                objects,
                registries,
                witness,
                wal_owner_witness,
            ),
        }
    }

    /// Startup-relaunch composition: reconstruct the WAL-owner serving
    /// handoff from durable state for this sealed runtime's exact bound
    /// archive, from whichever control ledger holds the durable
    /// `wal_authoritative` terminal — the maintenance-import ledger or the
    /// genesis control ledger (mutually exclusive authorities; coexistence
    /// refuses). Consumes the seal — the bundle and binding leave only inside
    /// the handoff, whose sole consumer is the serving-authority launch.
    pub(crate) async fn reconstruct_wal_serving_handoff(
        self,
        control: Arc<ControlStore>,
    ) -> Result<WalServingHandoff, crate::archive_v3_maintenance_import::MaintenanceImportError>
    {
        let archive_id = self.binding.binding.archive_id();
        if let Some(terminal) = control
            .wal_genesis_authoritative_terminal_for_archive(archive_id)
            .await
            .map_err(|_| crate::archive_v3_maintenance_import::MaintenanceImportError::Conflict)?
        {
            // Genesis lane. The ledger row pins the exact released terminal
            // bytes (never a still-leased record), so no live release
            // authentication is needed here; the durable owner reservation is
            // minted — or exactly re-adopted — off those bytes, and the
            // publisher re-adopts and revalidates it durably at launch before
            // any provider work.
            let reserved = control
                .reserve_owner_from_genesis(&terminal)
                .await
                .map_err(|_| {
                    crate::archive_v3_maintenance_import::MaintenanceImportError::Conflict
                })?;
            return GenesisWalHandoff::from_reservation(
                self.bundle,
                self.binding,
                terminal,
                reserved,
                control,
            )
            .map(WalServingHandoff::Genesis)
            .map_err(|_| crate::archive_v3_maintenance_import::MaintenanceImportError::Conflict);
        }
        let operation = control
            .wal_authoritative_operation_for_archive(archive_id)
            .await
            .map_err(|_| crate::archive_v3_maintenance_import::MaintenanceImportError::Conflict)?;
        // Clone the witness handle before the bundle moves into the handoff:
        // reconstruction authenticates the live released terminal through it.
        let witness = {
            let provider = self
                .bundle
                .maintenance_witness(&MaintenanceRuntimeContext(()))
                .ok_or(crate::archive_v3_maintenance_import::MaintenanceImportError::Unavailable)?;
            Arc::clone(provider)
        };
        crate::archive_v3_maintenance_import::CompletedMaintenanceWalHandoff::reconstruct_from_durable(
            self.bundle,
            self.binding,
            control,
            operation,
            witness.as_ref(),
        )
        .await
        .map(WalServingHandoff::Maintenance)
    }

    /// Genesis composition: consume the seal and release exactly the provider
    /// handles the reviewed genesis producer and witness ladder need, bound to
    /// this sealed runtime's own archive. Like the serving handoff, this
    /// consumes `self`, so one sealed runtime can be spent on genesis or on
    /// serving, never both. The token has one production minter, held by the
    /// reviewed genesis sign-in trigger.
    pub(crate) fn into_genesis_parts(
        self,
        token: &crate::archive_v3_genesis_backend::GenesisBackendRuntimeContext,
    ) -> Result<GenesisRuntimeParts, ArchiveV3ShadowRuntimeConstructionError> {
        let archive_id = self.binding.binding.archive_id();
        let registries = self
            .bundle
            .genesis_registry_provider(token)
            .ok_or(ArchiveV3ShadowRuntimeConstructionError::Unavailable)?;
        let witness = self
            .bundle
            .genesis_firestore_witness(token)
            .ok_or(ArchiveV3ShadowRuntimeConstructionError::Unavailable)?;
        let witness_advance = self
            .bundle
            .genesis_witness_advance(token)
            .ok_or(ArchiveV3ShadowRuntimeConstructionError::Unavailable)?;
        Ok(GenesisRuntimeParts {
            archive_id,
            objects: self.bundle.genesis_objects(token),
            roots: self.bundle.genesis_exact_roots(token),
            registries,
            witness,
            witness_advance,
        })
    }

    /// One-shot inactive composition. This has no startup caller and returns
    /// only the private maintenance state machine, never raw providers.
    pub(crate) fn into_maintenance_importer(
        self,
        plan: AuthenticatedMaintenanceImportPlan,
        persistence: Arc<ControlStore>,
        store: Arc<crate::store::Store>,
    ) -> Result<SingleArchiveMaintenanceImporter, MaintenanceImportError> {
        SingleArchiveMaintenanceImporter::from_sealed_runtime(
            MaintenanceRuntimeContext(()),
            self.binding.binding.archive_id(),
            self.binding,
            self.bundle,
            persistence,
            store,
            plan,
        )
    }
}

impl fmt::Debug for SealedSingleArchiveWalRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedSingleArchiveWalRuntime(<inactive>)")
    }
}

/// Released provider set for exactly one archive's genesis run. It carries no
/// witness record, no lease, and no durable authority: every one of these
/// handles still enforces its own exact-context, CAS, and readback predicates.
pub(crate) struct GenesisRuntimeParts {
    pub(crate) archive_id: ArchiveId,
    pub(crate) objects: Arc<dyn ImmutableObjectBackend>,
    pub(crate) roots: Arc<dyn ExactRootProvider>,
    pub(crate) registries: Arc<GcsArchiveV3RegistryProvider>,
    pub(crate) witness: Arc<crate::archive_v3_firestore_witness::FirestoreWitness>,
    pub(crate) witness_advance:
        Arc<dyn crate::archive_v3_root_advance::ArchiveWitnessAdvanceProvider>,
}

impl fmt::Debug for GenesisRuntimeParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenesisRuntimeParts(<opaque>)")
    }
}

/// The one serving handoff the private WAL launcher consumes: either the
/// parity-certified completed maintenance handoff or the genesis-ledger
/// handoff minted from a durable genesis owner reservation. Non-cloneable by
/// composition; each variant is consumed exactly once at launch.
pub(crate) enum WalServingHandoff {
    Maintenance(crate::archive_v3_maintenance_import::CompletedMaintenanceWalHandoff),
    Genesis(GenesisWalHandoff),
}

impl fmt::Debug for WalServingHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalServingHandoff(<offline>)")
    }
}

/// Non-cloneable genesis WAL-owner handoff. It carries exactly what launch
/// needs from a durable genesis reservation: the sealed provider bundle, the
/// genesis control ledger's exact released terminal witness, the opaque
/// durable archive binding, the reserved owner lease minted (or exactly
/// re-adopted) by the genesis-ledger owner reservation, and the encrypted
/// Control handle. There are no field getters and no Store admission fence —
/// a genesis archive has no legacy snapshot to pin, matching the fenceless
/// maintenance restart path — and only the WAL-owner module can obtain the
/// consuming view by presenting its private Store-owner token. At launch the
/// publisher re-adopts the durable reservation off the ledger row's exact
/// terminal bytes and requires exact equality with the carried reservation
/// before any provider work.
pub(crate) struct GenesisWalHandoff {
    runtime: ArchiveV3ShadowRuntimeBundle,
    terminal_witness: WitnessRecord,
    archive_binding: DurableSingleArchiveBinding,
    reserved: crate::archive_v3_wal_owner::ReservedWalOwnerLease,
    control: Arc<ControlStore>,
}

pub(crate) struct GenesisWalHandoffView {
    pub(crate) runtime: ArchiveV3ShadowRuntimeBundle,
    pub(crate) terminal_witness: WitnessRecord,
    pub(crate) archive_binding: DurableSingleArchiveBinding,
    pub(crate) reserved: crate::archive_v3_wal_owner::ReservedWalOwnerLease,
    pub(crate) control: Arc<ControlStore>,
}

impl GenesisWalHandoff {
    /// Compose the launchable genesis handoff from a durable genesis owner
    /// reservation. The terminal must be the archive's own released
    /// `WalAuthoritative` terminal — the exact unleased shape at root
    /// sequence 2 that the witness ladder ends at and the genesis control
    /// ledger pins — or construction refuses. The reservation's own exact
    /// binding to these terminal bytes is revalidated durably at launch,
    /// where the publisher's re-adoption must equal it byte for byte.
    pub(crate) fn from_reservation(
        runtime: ArchiveV3ShadowRuntimeBundle,
        archive_binding: DurableSingleArchiveBinding,
        terminal_witness: WitnessRecord,
        reserved: crate::archive_v3_wal_owner::ReservedWalOwnerLease,
        control: Arc<ControlStore>,
    ) -> Result<Self, ArchiveV3ShadowRuntimeConstructionError> {
        // Genesis publishes root sequence 0 and the ladder adds exactly two
        // zero-WAL roots, so the released terminal rests at sequence 2.
        if terminal_witness.archive_id() != archive_binding.binding.archive_id()
            || !terminal_witness.is_exact_unleased_wal_authoritative_terminal()
            || terminal_witness.root().root().sequence() != 2
        {
            return Err(ArchiveV3ShadowRuntimeConstructionError::InvalidDeployment);
        }
        Ok(Self {
            runtime,
            terminal_witness,
            archive_binding,
            reserved,
            control,
        })
    }

    pub(crate) fn into_wal_owner(
        self,
        _token: crate::archive_v3_wal_owner::WalOwnerStoreContext,
    ) -> GenesisWalHandoffView {
        GenesisWalHandoffView {
            runtime: self.runtime,
            terminal_witness: self.terminal_witness,
            archive_binding: self.archive_binding,
            reserved: self.reserved,
            control: self.control,
        }
    }
}

impl fmt::Debug for GenesisWalHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenesisWalHandoff(<offline>)")
    }
}

impl fmt::Debug for ArchiveV3ShadowRuntimeBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveV3ShadowRuntimeBundle(<inactive>)")
    }
}

struct ShadowRuntimeComponents {
    objects: Arc<dyn ImmutableObjectBackend>,
    roots: Arc<dyn ExactRootProvider>,
    registries: Arc<dyn ExactKeyRegistryProvider>,
    witness: Arc<dyn ShadowCheckpointWitnessProvider>,
}

#[cfg(test)]
struct UnavailableRootProvider;

#[cfg(test)]
#[async_trait::async_trait]
impl ExactRootProvider for UnavailableRootProvider {
    async fn read_exact(
        &self,
        _context: &crate::archive_v3::ObjectContext,
    ) -> Result<crate::archive_v3::CiphertextEnvelope, crate::archive_v3_witness::WitnessError>
    {
        Err(crate::archive_v3_witness::WitnessError::Unavailable)
    }
}

#[cfg(test)]
struct UnavailableShadowWitnessProvider;

#[cfg(test)]
#[async_trait::async_trait]
impl ShadowCheckpointWitnessProvider for UnavailableShadowWitnessProvider {
    async fn read_current_exact(
        &self,
        _archive_id: ArchiveId,
    ) -> Result<crate::archive_v3_witness::WitnessRecord, crate::archive_v3_witness::WitnessError>
    {
        Err(crate::archive_v3_witness::WitnessError::Unavailable)
    }

    async fn compare_and_advance_root(
        &self,
        _advance: crate::archive_v3_witness::RootAdvance,
    ) -> Result<
        crate::archive_v3_witness::WitnessReceipt,
        crate::archive_v3_shadow_coordinator::ShadowWitnessCommitError,
    > {
        Err(
            crate::archive_v3_shadow_coordinator::ShadowWitnessCommitError::Failed(
                crate::archive_v3_witness::WitnessError::Unavailable,
            ),
        )
    }
}

/// This is intentionally not configurable. The active deletion runtime lists
/// actual soft-deleted generations while bucket soft delete is enabled. If the
/// provider reports that policy disabled, this conservative fallback refuses
/// completion until a separately reviewed authenticated drain proof exists.
struct ConstructionOnlyDrainGate;

#[async_trait::async_trait]
impl ArchiveV3SoftDeleteDrainGate for ConstructionOnlyDrainGate {
    async fn disabled_and_drained(
        &self,
        _canonical_bucket: &str,
    ) -> Result<bool, crate::archive_v3_gcs::GcsArchiveV3TransportError> {
        Ok(false)
    }
}

fn canonical_numeric_id(value: &str) -> bool {
    (1..=20).contains(&value.len())
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}

const fn lower_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn map_gcs_construction_error(
    error: crate::archive_v3_gcs::GcsArchiveV3TransportError,
) -> ArchiveV3ShadowRuntimeConstructionError {
    match error {
        crate::archive_v3_gcs::GcsArchiveV3TransportError::Protocol => {
            ArchiveV3ShadowRuntimeConstructionError::InvalidDeployment
        }
        _ => ArchiveV3ShadowRuntimeConstructionError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{
            ArchivePrefix, ArchiveV3Error, CiphertextEnvelope, CreateIfAbsent, EnumerationCursor,
            EnumerationLimit, EnumerationPage, KeyRegistryContext, ObjectContext, ObjectId,
            ObjectKey,
        },
        archive_v3_shadow_coordinator::ShadowWitnessCommitError,
        archive_v3_witness::{RootAdvance, WitnessError, WitnessReceipt, WitnessRecord},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn deployment() -> ArchiveV3ShadowRuntimeDeployment {
        ArchiveV3ShadowRuntimeDeployment::new(
            "archive-shadow-1",
            "123456789",
            "7",
            "project-1",
            "987654321",
            "witness-db",
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap()
    }

    #[test]
    fn deployment_accepts_only_exact_fragments_and_debug_is_redacted() {
        let deployment = deployment();
        assert_eq!(
            format!("{deployment:?}"),
            "ArchiveV3ShadowRuntimeDeployment(<redacted>)"
        );
        for invalid in ["", "12", "192.168.1.1", "goog-shadow"] {
            assert!(ArchiveV3ShadowRuntimeDeployment::new(
                invalid,
                "123456789",
                "7",
                "project-1",
                "987654321",
                "witness-db",
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .is_err());
        }
        for invalid in [
            "",
            "0",
            "01",
            "18446744073709551616",
            "123456789012345678901",
        ] {
            assert!(ArchiveV3ShadowRuntimeDeployment::new(
                "archive-shadow-1",
                "123456789",
                invalid,
                "project-1",
                "987654321",
                "witness-db",
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .is_err());
            assert!(ArchiveV3ShadowRuntimeDeployment::new(
                "archive-shadow-1",
                invalid,
                "7",
                "project-1",
                "987654321",
                "witness-db",
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .is_err());
            assert!(ArchiveV3ShadowRuntimeDeployment::new(
                "archive-shadow-1",
                "123456789",
                "7",
                "project-1",
                invalid,
                "witness-db",
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .is_err());
        }
        assert!(ArchiveV3ShadowRuntimeDeployment::new(
            "archive-shadow-1",
            "123456789",
            "7",
            "project-1",
            "987654321",
            "(default)",
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .is_err());
        assert!(ArchiveV3ShadowRuntimeDeployment::new(
            "archive-shadow-1",
            "arbitrary/audience",
            "7",
            "project-1",
            "987654321",
            "witness-db",
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .is_err());
        for invalid in [
            "",
            "0",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "111111111111111111111111111111111111111111111111111111111111111g",
        ] {
            assert!(ArchiveV3ShadowRuntimeDeployment::new(
                "archive-shadow-1",
                "123456789",
                "7",
                "project-1",
                "987654321",
                "witness-db",
                invalid,
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn construction_only_drain_gate_always_denies() {
        assert!(!ConstructionOnlyDrainGate
            .disabled_and_drained("archive-shadow-1")
            .await
            .unwrap());
    }

    struct NeverCalled {
        calls: Arc<AtomicUsize>,
    }
    impl NeverCalled {
        fn called<T>(&self) -> Result<T, ArchiveV3Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ArchiveV3Error::Unavailable)
        }
    }

    #[async_trait::async_trait]
    impl ImmutableObjectBackend for NeverCalled {
        async fn create_if_absent(
            &self,
            _key: ObjectKey,
            _value: CiphertextEnvelope,
        ) -> Result<CreateIfAbsent, ArchiveV3Error> {
            self.called()
        }
        async fn get(
            &self,
            _key: &ObjectKey,
        ) -> Result<Option<CiphertextEnvelope>, ArchiveV3Error> {
            self.called()
        }
        async fn enumerate(
            &self,
            _prefix: &ArchivePrefix,
            _cursor: Option<&EnumerationCursor>,
            _limit: EnumerationLimit,
        ) -> Result<EnumerationPage, ArchiveV3Error> {
            self.called()
        }
        async fn delete_exact(&self, _key: &ObjectKey) -> Result<bool, ArchiveV3Error> {
            self.called()
        }
    }

    #[async_trait::async_trait]
    impl ExactRootProvider for NeverCalled {
        async fn read_exact(
            &self,
            _context: &ObjectContext,
        ) -> Result<CiphertextEnvelope, WitnessError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(WitnessError::Unavailable)
        }
    }

    #[async_trait::async_trait]
    impl ExactKeyRegistryProvider for NeverCalled {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            _object_id: ObjectId,
            _destination: &mut [u8],
        ) -> Result<usize, ArchiveV3Error> {
            self.called()
        }
        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            _wrapped_registry_ciphertext: &[u8],
            _destination: &mut [u8],
        ) -> Result<usize, ArchiveV3Error> {
            self.called()
        }
    }

    #[async_trait::async_trait]
    impl ShadowCheckpointWitnessProvider for NeverCalled {
        async fn read_current_exact(
            &self,
            _archive_id: crate::archive_v3::ArchiveId,
        ) -> Result<WitnessRecord, WitnessError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(WitnessError::Unavailable)
        }
        async fn compare_and_advance_root(
            &self,
            _advance: RootAdvance,
        ) -> Result<WitnessReceipt, ShadowWitnessCommitError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ShadowWitnessCommitError::Failed(WitnessError::Unavailable))
        }
    }

    #[test]
    fn pending_binding_is_one_shot_exact_and_performs_zero_provider_calls() {
        let calls = Arc::new(AtomicUsize::new(0));
        let components = || {
            Arc::new(NeverCalled {
                calls: Arc::clone(&calls),
            })
        };
        let archive_id = crate::archive_v3::ArchiveId::from_bytes([19; 16]);
        let pending = PendingSingleArchiveWalRuntime::from_test_components(
            ArchiveV3ArchiveBindingCommitment::for_archive(archive_id),
            ShadowRuntimeComponents {
                objects: components(),
                roots: components(),
                registries: components(),
                witness: components(),
            },
        );
        assert_eq!(
            format!("{pending:?}"),
            "PendingSingleArchiveWalRuntime(<inactive>)"
        );
        let binding = DurableSingleArchiveBinding::from_control_store(
            crate::cp::control_store::ArchiveBinding::for_runtime_test(archive_id),
        );
        assert_eq!(
            format!("{binding:?}"),
            "DurableSingleArchiveBinding(<opaque>)"
        );
        let sealed = pending.bind_once(binding).unwrap();
        assert_eq!(
            format!("{sealed:?}"),
            "SealedSingleArchiveWalRuntime(<inactive>)"
        );
        drop(sealed);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn wrong_binding_is_rejected_without_invoking_or_returning_components() {
        let calls = Arc::new(AtomicUsize::new(0));
        let component = || {
            Arc::new(NeverCalled {
                calls: Arc::clone(&calls),
            })
        };
        let expected = crate::archive_v3::ArchiveId::from_bytes([21; 16]);
        let wrong = crate::archive_v3::ArchiveId::from_bytes([22; 16]);
        let pending = PendingSingleArchiveWalRuntime::from_test_components(
            ArchiveV3ArchiveBindingCommitment::for_archive(expected),
            ShadowRuntimeComponents {
                objects: component(),
                roots: component(),
                registries: component(),
                witness: component(),
            },
        );
        let binding = DurableSingleArchiveBinding::from_control_store(
            crate::cp::control_store::ArchiveBinding::for_runtime_test(wrong),
        );
        assert!(matches!(
            pending.bind_once(binding),
            Err(ArchiveV3ShadowRuntimeConstructionError::InvalidDeployment)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn commitment_is_domain_separated_and_capabilities_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PendingSingleArchiveWalRuntime>();
        assert_send_sync::<DurableSingleArchiveBinding>();
        assert_send_sync::<SealedSingleArchiveWalRuntime>();
        assert_ne!(
            ArchiveV3ArchiveBindingCommitment::for_archive(ArchiveId::from_bytes([1; 16])),
            ArchiveV3ArchiveBindingCommitment::for_archive(ArchiveId::from_bytes([2; 16]))
        );
        assert_eq!(
            ArchiveV3ArchiveBindingCommitment::for_archive(ArchiveId::from_bytes([1; 16])).0,
            [
                0xc4, 0xb0, 0x1e, 0xae, 0x95, 0xc1, 0x37, 0xef, 0x5d, 0x77, 0xf9, 0x08, 0x49, 0x6a,
                0xf2, 0xcd, 0x87, 0xd1, 0xa9, 0x73, 0x82, 0xc0, 0x97, 0xed, 0xc3, 0xdf, 0xfa, 0x3a,
                0xeb, 0x11, 0xc7, 0xe1,
            ]
        );
        assert_eq!(
            format!(
                "{:?}",
                ArchiveV3ArchiveBindingCommitment::for_archive(ArchiveId::from_bytes([1; 16]))
            ),
            "ArchiveV3ArchiveBindingCommitment(<redacted>)"
        );
        assert_eq!(
            activation_binding_commitment(
                crate::cp::control_store::ArchiveBinding::for_runtime_test(ArchiveId::from_bytes(
                    [1; 16]
                ))
            ),
            "c4b01eae95c137ef5d77f908496af2cd87d1a97382c097edc3dffa3aeb11c7e1"
        );
    }

    #[test]
    fn source_exposes_only_token_gated_serving_and_deletion_operations() {
        let source = include_str!("archive_v3_shadow_runtime.rs");
        let main = include_str!("main.rs");
        let control = include_str!("cp/control_store.rs");
        for type_name in [
            "ArchiveV3ArchiveBindingCommitment",
            "PendingSingleArchiveWalRuntime",
            "DurableSingleArchiveBinding",
            "SealedSingleArchiveWalRuntime",
            "GenesisWalHandoff",
        ] {
            let declaration = source
                .find(&format!("struct {type_name}"))
                .expect("capability declaration");
            let attributes = &source[source[..declaration]
                .rfind("\n\n")
                .map_or(0, |offset| offset + 2)..declaration];
            assert!(
                !attributes.contains("Clone") && !attributes.contains("Copy"),
                "{type_name} must remain non-cloneable"
            );
        }
        for forbidden in [
            concat!("impl Clone", " for PendingSingleArchiveWalRuntime"),
            concat!("impl Clone", " for DurableSingleArchiveBinding"),
            concat!("impl Clone", " for SealedSingleArchiveWalRuntime"),
            concat!("impl Clone", " for GenesisWalHandoff"),
            concat!("impl Copy", " for GenesisWalHandoff"),
            concat!("impl Clone", " for WalServingHandoff"),
            concat!("impl Copy", " for WalServingHandoff"),
            concat!("pub(crate) fn terminal_", "witness"),
            concat!("pub(crate) fn reserve", "d("),
            concat!("pub(crate) fn archive_", "id(&self)"),
            concat!("pub(crate) fn object", "s("),
            concat!("pub(crate) fn root", "s("),
            concat!("pub(crate) fn registr", "ies("),
            concat!("pub(crate) fn wit", "ness("),
            concat!("tokio::", "spawn"),
            concat!("std::thread::", "spawn"),
            concat!("with_", "user"),
            concat!("WalLogical", "Only"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
        assert!(source.contains(concat!("impl SealedSingleArchiveWal", "Runtime {")));
        // G8: the genesis handoff mirrors the maintenance handoff's authority
        // discipline — opaque Debug, a token-gated consuming view presented
        // only by the private WAL-owner family, and no witness or transport
        // leakage beyond that view.
        assert!(source.contains(concat!("GenesisWalHandoff", "(<offline>)")));
        assert!(source.contains(concat!("WalServingHandoff", "(<offline>)")));
        assert!(source.contains(concat!("fn into_wal_", "owner(")));
        assert_eq!(
            source
                .matches(concat!(
                    "_token: crate::archive_v3_wal_owner::WalOwnerStore",
                    "Context"
                ))
                .count(),
            1,
            "the genesis handoff view must stay token-gated and single-doored"
        );
        assert!(source.contains("fn into_advisory_shadow_importer("));
        assert!(source.contains("fn into_advisory_owner("));
        assert!(source.contains("read_advisory_owner_current_exact("));
        assert!(source.contains("acquire_advisory_owner_lease_unresolved("));
        assert!(source.contains("fn into_maintenance_importer("));
        let factory = source
            .find("fn from_control_store(")
            .expect("durable binding factory");
        let signature_end = source[factory..]
            .find('{')
            .map(|offset| factory + offset)
            .expect("durable binding factory body");
        let signature = &source[factory..signature_end];
        assert!(signature.contains("binding: ArchiveBinding"));
        for forbidden in ["ArchiveId", "[u8", "str", "user", "account"] {
            assert!(!signature.contains(forbidden));
        }
        let test_factory = control
            .find("fn for_runtime_test(")
            .expect("control-store test binding factory");
        assert!(control[test_factory.saturating_sub(80)..test_factory].contains("#[cfg(test)]"));
        for forbidden in [
            "PendingSingleArchiveWalRuntime::new",
            "DurableSingleArchiveBinding::from_control_store",
            "SealedSingleArchiveWalRuntime",
            "into_advisory_shadow_importer",
            "into_advisory_owner",
        ] {
            assert!(!main.contains(forbidden), "live wiring: {forbidden}");
        }
        assert!(main.contains("archive_deletion_runtime_secrets()"));
        assert!(main.contains("ProductionArchiveDeletionRuntimeFactory::new("));
        assert!(main.contains("install_wal_deletion_lane("));
        assert!(source.contains("impl ArchiveDeletionRuntimeFactory"));
        assert!(source.contains("control_deletion_authenticator("));

        // The deletion authority must exist before any selected persistence
        // selection, serving relaunch, or account-deletion reconciler can
        // observe work. These are source-order seals over the one production
        // startup owner; moving any boundary requires an explicit review.
        let secrets = main
            .find("archive_deletion_runtime_secrets()")
            .expect("deletion roots are derived");
        let factory = main
            .find("ProductionArchiveDeletionRuntimeFactory::new(")
            .expect("deletion factory is constructed");
        let install = main
            .find("install_wal_deletion_lane(")
            .expect("deletion lane is installed");
        let selections = main
            .find("load_wal_authoritative_persistence_selections()")
            .expect("WAL selections are loaded");
        let relaunch = main
            .find("relaunch_wal_serving_authorities(")
            .expect("serving authorities are relaunched");
        let deletion_reconciler = main
            .find("spawn_account_deletion_reconciler(")
            .expect("account deletion reconciler is launched");
        assert!(
            secrets < factory
                && factory < install
                && install < selections
                && selections < relaunch
                && relaunch < deletion_reconciler
        );
        assert_eq!(main.matches("install_wal_deletion_lane(").count(), 1);
        assert_eq!(
            main.matches("Arc::clone(&secrets.principal_key)").count(),
            1,
            "the factory must authenticate deletion workers with the installed lane's key"
        );
        assert_eq!(main.matches("secrets.principal_key,").count(), 1);
    }
    #[test]
    fn baked_deployment_off_semantics_are_exact() {
        // Absent or off mode with every coordinate empty is the pre-activation shape.
        assert!(matches!(
            ArchiveV3ShadowRuntimeDeployment::from_mode_and_coordinates(
                "",
                ["", "", "", "", "", "", ""]
            ),
            Ok(None)
        ));
        assert!(matches!(
            ArchiveV3ShadowRuntimeDeployment::from_mode_and_coordinates(
                "off",
                ["", "", "", "", "", "", ""]
            ),
            Ok(None)
        ));
        // Any stray fragment alongside off fails closed.
        assert!(ArchiveV3ShadowRuntimeDeployment::from_mode_and_coordinates(
            "off",
            ["kioku-joerodriguez-archive-v3", "", "", "", "", "", ""]
        )
        .is_err());
        // Unknown modes fail closed.
        assert!(ArchiveV3ShadowRuntimeDeployment::from_mode_and_coordinates(
            "single-archive-wal-v2",
            ["", "", "", "", "", "", ""]
        )
        .is_err());
        // The exact active mode revalidates every coordinate through Self::new.
        let commitment = "11".repeat(32);
        let active = ArchiveV3ShadowRuntimeDeployment::from_mode_and_coordinates(
            "single-archive-wal-v1",
            [
                "kioku-joerodriguez-archive-v3",
                "640329636251",
                "1",
                "kioku-joerodriguez",
                "640329636251",
                "archive-v3-witness",
                &commitment,
            ],
        );
        assert!(active.expect("valid coordinates").is_some());
        // An invalid coordinate under the active mode fails closed.
        assert!(ArchiveV3ShadowRuntimeDeployment::from_mode_and_coordinates(
            "single-archive-wal-v1",
            [
                "kioku-joerodriguez-archive-v3",
                "0640329636251",
                "1",
                "kioku-joerodriguez",
                "640329636251",
                "archive-v3-witness",
                &commitment,
            ],
        )
        .is_err());
    }
}
