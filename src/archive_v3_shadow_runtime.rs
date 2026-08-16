#![allow(
    dead_code,
    reason = "construction-only ADR-0022 runtime bundle is intentionally not wired to startup or authority"
)]

//! Sealed, inactive ADR-0022 single-archive shadow/WAL runtime composition.
//!
//! This module accepts only typed deployment fragments and builds the fixed
//! archive-GCS, registry-KMS, and named-Firestore provider graph. Construction
//! is synchronous and performs no provider request. The graph remains pending
//! until it consumes one opaque durable control-store archive binding whose
//! domain-separated commitment exactly matches the image-baked deployment
//! claim. Every capability remains behind private fields: there is no handle,
//! getter, callback, task, worker, operation, acknowledgement, persistent-state/VFS hook,
//! route, health signal, admission input, or deletion driver. The GCS
//! hard-delete gate is permanently false until a later independently audited
//! slice supplies authenticated lifecycle evidence.
//! The sealed owner has two type-separated consumers: an advisory importer
//! that can stop only at verified ShadowWal, and the later authority importer.
//! Neither has a startup caller.

use std::{fmt, sync::Arc};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    archive_v3::{
        resolve_archive_cipher, ArchiveId, ExactKeyRegistryProvider, ImmutableObjectBackend,
        KeyKind, KeyRegistryContext, ObjectId, VerifiedArchiveCipher,
    },
    archive_v3_firestore_shadow::FirestoreShadowWitness,
    archive_v3_firestore_witness::{FirestoreWitnessCommitError, FirestoreWitnessConfig},
    archive_v3_gcs::{
        ArchiveV3GcsTransport, GcsArchiveV3Backend, GcsArchiveV3RegistryProvider,
        GcsArchiveV3RootProvider,
    },
    archive_v3_gcs_auth::{ArchiveV3GcsAttestationBearer, ArchiveV3GcsAudience},
    archive_v3_gcs_http::{
        valid_archive_v3_bucket_name, ArchiveV3SoftDeleteDrainGate, GcpArchiveV3HttpTransport,
    },
    archive_v3_maintenance_import::{
        AuthenticatedMaintenanceImportPlan, MaintenanceImportError,
        MaintenanceImportWitnessProvider, SingleArchiveAdvisoryShadowImporter,
        SingleArchiveMaintenanceImporter,
    },
    archive_v3_registry_kms::GcpArchiveV3RegistryKms,
    archive_v3_shadow_coordinator::ShadowCheckpointWitnessProvider,
    archive_v3_witness::{
        ExactRootProvider, RootAdvance, WitnessError, WitnessLease, WitnessRecord,
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

/// Private provider owner. It is never returned without exact durable binding.
pub(crate) struct ArchiveV3ShadowRuntimeBundle {
    objects: Arc<dyn ImmutableObjectBackend>,
    _roots: Arc<dyn ExactRootProvider>,
    registries: Arc<dyn ExactKeyRegistryProvider>,
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
        Ok(Self {
            objects,
            _roots: Arc::new(GcsArchiveV3RootProvider::new(Arc::clone(&transport))),
            registries: Arc::new(GcsArchiveV3RegistryProvider::new(transport, registry_kms)),
            _witness: witness.clone(),
            maintenance_witness: Some(witness.clone()),
            wal_owner_witness: Some(witness),
        })
    }

    fn from_components(components: ShadowRuntimeComponents) -> Self {
        Self {
            objects: components.objects,
            _roots: components.roots,
            registries: components.registries,
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

    pub(crate) fn into_wal_publisher(
        self,
        _token: crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
    ) -> Result<WalPublisherRuntimeOwner, ArchiveV3ShadowRuntimeConstructionError> {
        if self.wal_owner_witness.is_none() {
            return Err(ArchiveV3ShadowRuntimeConstructionError::Unavailable);
        }
        Ok(WalPublisherRuntimeOwner { bundle: self })
    }

    #[cfg(test)]
    pub(crate) fn from_maintenance_test_components(
        objects: Arc<dyn ImmutableObjectBackend>,
        registries: Arc<dyn ExactKeyRegistryProvider>,
        witness: Arc<dyn MaintenanceImportWitnessProvider>,
    ) -> Self {
        Self {
            objects,
            _roots: Arc::new(UnavailableRootProvider),
            registries,
            _witness: Arc::new(UnavailableShadowWitnessProvider),
            maintenance_witness: Some(witness),
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
    /// One-shot Phase-1 composition. The returned type can stop only at the
    /// verified advisory ShadowWal handoff and exposes no WalAuthoritative
    /// transition method.
    pub(crate) fn into_advisory_shadow_importer(
        self,
        plan: AuthenticatedMaintenanceImportPlan,
        persistence: Arc<ControlStore>,
        store: Arc<crate::store::Store>,
    ) -> Result<SingleArchiveAdvisoryShadowImporter, MaintenanceImportError> {
        let importer = SingleArchiveMaintenanceImporter::from_sealed_runtime(
            MaintenanceRuntimeContext(()),
            self.binding.binding.archive_id(),
            self.binding,
            self.bundle,
            persistence,
            store,
            plan,
        )?;
        Ok(SingleArchiveAdvisoryShadowImporter::from_maintenance_importer(importer))
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

/// This is intentionally not configurable. A future deletion-capable runtime
/// must replace it only with authenticated lifecycle-ledger evidence.
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
    }

    #[test]
    fn source_exposes_no_runtime_operation_or_live_wiring() {
        let source = include_str!("archive_v3_shadow_runtime.rs");
        let main = include_str!("main.rs");
        let control = include_str!("cp/control_store.rs");
        for type_name in [
            "ArchiveV3ArchiveBindingCommitment",
            "PendingSingleArchiveWalRuntime",
            "DurableSingleArchiveBinding",
            "SealedSingleArchiveWalRuntime",
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
            concat!("pub(crate) fn archive_", "id(&self)"),
            concat!("pub(crate) fn object", "s("),
            concat!("pub(crate) fn root", "s("),
            concat!("pub(crate) fn registr", "ies("),
            concat!("pub(crate) fn wit", "ness("),
            concat!("tokio::", "spawn"),
            concat!("std::thread::", "spawn"),
            concat!("Store", "::"),
            concat!("with_", "user"),
            concat!("WalLogical", "Only"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
        assert!(source.contains(concat!("impl SealedSingleArchiveWal", "Runtime {")));
        assert!(source.contains("fn into_advisory_shadow_importer("));
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
        ] {
            assert!(!main.contains(forbidden), "live wiring: {forbidden}");
        }
    }
}
