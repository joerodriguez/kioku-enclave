#![allow(
    dead_code,
    reason = "inactive ADR-0022 Firestore composition is compiled and tested before runtime wiring"
)]

//! Inactive, no-I/O composition seam for the ADR-0022 Firestore witness.
//!
//! One validated [`FirestoreWitnessConfig`] supplies both the exact named
//! database namespace and its dedicated attestation audience.  Construction
//! creates fixed-origin clients but performs no network request.  This module
//! is not connected to Store, startup, routes, environment variables, archive
//! bootstrap, or production authority.

use std::{fmt, sync::Arc};

use async_trait::async_trait;

use crate::{
    archive_v3::ArchiveId,
    archive_v3_firestore_auth::FirestoreWitnessAttestationBearer,
    archive_v3_firestore_http::FirestoreWitnessRestTransport,
    archive_v3_firestore_witness::{
        FirestoreWitness, FirestoreWitnessCommitError, FirestoreWitnessConfig,
        FirestoreWitnessTransportError,
    },
    archive_v3_shadow_coordinator::{ShadowCheckpointWitnessProvider, ShadowWitnessCommitError},
    archive_v3_witness::{RootAdvance, WitnessError, WitnessReceipt, WitnessRecord},
};

/// Concrete provider bundle for the shadow coordinator.  Its fields remain
/// private so runtime code cannot independently replace the database, bearer,
/// or transport after construction.
pub(crate) struct FirestoreShadowWitness {
    witness: Arc<FirestoreWitness>,
}

impl FirestoreShadowWitness {
    /// Build the fixed production-origin clients without performing I/O or
    /// granting authority. The config has one typed namespace/audience pair.
    pub(crate) fn new(config: FirestoreWitnessConfig) -> Result<Self, WitnessError> {
        let bearer = Arc::new(
            FirestoreWitnessAttestationBearer::new(config.provider_audience())
                .map_err(map_construction_error)?,
        );
        let transport = Arc::new(
            FirestoreWitnessRestTransport::new(config.namespace())
                .map_err(map_construction_error)?,
        );
        let witness = Arc::new(FirestoreWitness::new(config, bearer, transport)?);
        Ok(Self { witness })
    }
}

impl fmt::Debug for FirestoreShadowWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirestoreShadowWitness(<inactive>)")
    }
}

#[async_trait]
impl ShadowCheckpointWitnessProvider for FirestoreShadowWitness {
    async fn read_current_exact(
        &self,
        archive_id: ArchiveId,
    ) -> Result<WitnessRecord, WitnessError> {
        self.witness
            .read_current_async(archive_id)
            .await?
            .ok_or(WitnessError::MissingArchive)
    }

    async fn compare_and_advance_root(
        &self,
        advance: RootAdvance,
    ) -> Result<WitnessReceipt, ShadowWitnessCommitError> {
        self.witness
            .compare_and_advance_root_unresolved_async(advance)
            .await
            .map_err(|error| match error {
                FirestoreWitnessCommitError::Rejected(error) => {
                    ShadowWitnessCommitError::Rejected(error)
                }
                FirestoreWitnessCommitError::Failed(error) => {
                    ShadowWitnessCommitError::Failed(error)
                }
                FirestoreWitnessCommitError::OutcomeUnknown => {
                    ShadowWitnessCommitError::OutcomeUnknown
                }
            })
    }
}

fn map_construction_error(error: FirestoreWitnessTransportError) -> WitnessError {
    match error {
        FirestoreWitnessTransportError::Protocol => WitnessError::Malformed,
        _ => WitnessError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_is_fixed_typed_no_io_and_redacted() {
        let config = FirestoreWitnessConfig::new("project-1", "123456789", "witness-db").unwrap();
        let provider = FirestoreShadowWitness::new(config).unwrap();
        assert_eq!(
            format!("{provider:?}"),
            "FirestoreShadowWitness(<inactive>)"
        );
    }

    #[test]
    fn config_rejects_default_database_and_non_numeric_provider_project() {
        assert!(FirestoreWitnessConfig::new("project-1", "123456789", "(default)").is_err());
        assert!(FirestoreWitnessConfig::new("project-1", "project-1", "witness-db").is_err());
    }
}
