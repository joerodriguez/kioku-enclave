#![allow(
    dead_code,
    reason = "construction-only ADR-0022 runtime bundle is intentionally not wired to startup or authority"
)]

//! Construction-only ADR-0022 shadow runtime composition.
//!
//! This module accepts only typed deployment fragments and builds the fixed
//! archive-GCS, registry-KMS, and named-Firestore provider graph. Construction
//! is synchronous and performs no provider request. Every capability remains
//! behind private fields: there is no handle, getter, task, worker, Store/VFS
//! hook, route, health signal, admission input, or deletion driver. The GCS
//! hard-delete gate is permanently false until a later independently audited
//! slice supplies authenticated lifecycle evidence.

use std::{fmt, sync::Arc};

use thiserror::Error;

use crate::{
    archive_v3::{ExactKeyRegistryProvider, ImmutableObjectBackend},
    archive_v3_firestore_shadow::FirestoreShadowWitness,
    archive_v3_firestore_witness::FirestoreWitnessConfig,
    archive_v3_gcs::{
        ArchiveV3GcsTransport, GcsArchiveV3Backend, GcsArchiveV3RegistryProvider,
        GcsArchiveV3RootProvider,
    },
    archive_v3_gcs_auth::{ArchiveV3GcsAttestationBearer, ArchiveV3GcsAudience},
    archive_v3_gcs_http::{
        valid_archive_v3_bucket_name, ArchiveV3SoftDeleteDrainGate, GcpArchiveV3HttpTransport,
    },
    archive_v3_registry_kms::GcpArchiveV3RegistryKms,
    archive_v3_shadow_coordinator::ShadowCheckpointWitnessProvider,
    archive_v3_witness::ExactRootProvider,
    crypto::GcpKmsClient,
};

/// Redacted construction result. It never carries provider paths, deployment
/// identifiers, bearer material, or response bodies.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum ArchiveV3ShadowRuntimeConstructionError {
    #[error("archive-v3 shadow runtime deployment is invalid")]
    InvalidDeployment,
    #[error("archive-v3 shadow runtime construction is unavailable")]
    Unavailable,
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
    ) -> Result<Self, ArchiveV3ShadowRuntimeConstructionError> {
        if !valid_archive_v3_bucket_name(archive_bucket)
            || !canonical_numeric_id(registry_kms_version)
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
        Ok(Self {
            archive_bucket: archive_bucket.to_owned(),
            archive_gcs_project_number: archive_gcs_project_number.to_owned(),
            registry_kms_version: registry_kms_version.to_owned(),
            witness_project_id: witness_project_id.to_owned(),
            witness_project_number: witness_project_number.to_owned(),
            witness_database_id: witness_database_id.to_owned(),
        })
    }
}

impl fmt::Debug for ArchiveV3ShadowRuntimeDeployment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArchiveV3ShadowRuntimeDeployment(<redacted>)")
    }
}

/// Construction-only capability container. Private fields, lack of getters,
/// and lack of `Clone` prevent callers from extracting an independently usable
/// provider or runtime handle.
pub(crate) struct ArchiveV3ShadowRuntimeBundle {
    _objects: Arc<dyn ImmutableObjectBackend>,
    _roots: Arc<dyn ExactRootProvider>,
    _registries: Arc<dyn ExactKeyRegistryProvider>,
    _witness: Arc<dyn ShadowCheckpointWitnessProvider>,
}

impl ArchiveV3ShadowRuntimeBundle {
    /// Build fixed-origin clients without reading environment or performing
    /// provider I/O. Merely constructing this inert owner grants no operation
    /// that can read, create, delete, witness, route, or influence authority.
    pub(crate) fn new(
        deployment: ArchiveV3ShadowRuntimeDeployment,
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
            GcpArchiveV3HttpTransport::new(deployment.archive_bucket, bearer, drain)
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
        let witness = Arc::new(
            FirestoreShadowWitness::new(witness_config)
                .map_err(|_| ArchiveV3ShadowRuntimeConstructionError::Unavailable)?,
        );

        Ok(Self::from_components(ShadowRuntimeComponents {
            objects: Arc::new(GcsArchiveV3Backend::new(Arc::clone(&transport))),
            roots: Arc::new(GcsArchiveV3RootProvider::new(Arc::clone(&transport))),
            registries: Arc::new(GcsArchiveV3RegistryProvider::new(transport, registry_kms)),
            witness,
        }))
    }

    fn from_components(components: ShadowRuntimeComponents) -> Self {
        Self {
            _objects: components.objects,
            _roots: components.roots,
            _registries: components.registries,
            _witness: components.witness,
        }
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
        )
        .is_err());
        assert!(ArchiveV3ShadowRuntimeDeployment::new(
            "archive-shadow-1",
            "arbitrary/audience",
            "7",
            "project-1",
            "987654321",
            "witness-db",
        )
        .is_err());
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
    fn bundle_owns_private_components_without_invoking_them() {
        let calls = Arc::new(AtomicUsize::new(0));
        let components = || {
            Arc::new(NeverCalled {
                calls: Arc::clone(&calls),
            })
        };
        let bundle = ArchiveV3ShadowRuntimeBundle::from_components(ShadowRuntimeComponents {
            objects: components(),
            roots: components(),
            registries: components(),
            witness: components(),
        });
        assert_eq!(
            format!("{bundle:?}"),
            "ArchiveV3ShadowRuntimeBundle(<inactive>)"
        );
        drop(bundle);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn bundle_is_send_and_sync_but_exposes_no_runtime_handle() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ArchiveV3ShadowRuntimeBundle>();
    }
}
