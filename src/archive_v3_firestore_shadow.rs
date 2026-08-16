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
    archive_v3_advisory_owner::{
        AdvisoryOwnerCommitError, AdvisoryOwnerId, AdvisoryOwnerWitnessProvider,
    },
    archive_v3_firestore_auth::FirestoreWitnessAttestationBearer,
    archive_v3_firestore_http::FirestoreWitnessRestTransport,
    archive_v3_firestore_witness::{
        FirestoreWitness, FirestoreWitnessCommitError, FirestoreWitnessConfig,
        FirestoreWitnessTransportError,
    },
    archive_v3_maintenance_import::{
        MaintenanceImportWitnessProvider, MaintenanceWitnessCommitError,
    },
    archive_v3_shadow_coordinator::{ShadowCheckpointWitnessProvider, ShadowWitnessCommitError},
    archive_v3_witness::{
        DeletionState, MigrationState, RootAdvance, WitnessError, WitnessLease, WitnessReceipt,
        WitnessRecord,
    },
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

    pub(crate) async fn wal_owner_read_current_exact(
        &self,
        _token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        archive_id: ArchiveId,
    ) -> Result<WitnessRecord, WitnessError> {
        self.witness
            .read_current_async(archive_id)
            .await?
            .ok_or(WitnessError::MissingArchive)
    }

    pub(crate) async fn wal_owner_acquire_unresolved(
        &self,
        _token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        expected: WitnessRecord,
        owner: crate::archive_v3::ObjectId,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        self.witness
            .acquire_exact_wal_owner_lease_unresolved_async(expected, owner, duration_ticks)
            .await
    }

    pub(crate) async fn wal_owner_renew_unresolved(
        &self,
        _token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        retained: WitnessRecord,
        lease: WitnessLease,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        if retained
            .exact_active_lease_for_wal_owner_bytes(lease.owner().as_bytes())
            .ok()
            != Some(lease)
        {
            return Err(FirestoreWitnessCommitError::Rejected(WitnessError::Fenced));
        }
        self.witness
            .renew_exact_wal_owner_lease_unresolved_async(retained, lease, duration_ticks)
            .await
    }

    pub(crate) async fn wal_owner_reacquire_unresolved(
        &self,
        _token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        previous: WitnessRecord,
        owner: crate::archive_v3::ObjectId,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        self.witness
            .reacquire_exact_wal_owner_lease_unresolved_async(previous, owner, duration_ticks)
            .await
    }

    pub(crate) async fn wal_owner_maintain_unresolved(
        &self,
        _token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        previous: WitnessRecord,
        owner: crate::archive_v3::ObjectId,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        self.witness
            .maintain_exact_wal_owner_lease_unresolved_async(previous, owner, duration_ticks)
            .await
    }

    pub(crate) async fn wal_owner_advance_unresolved(
        &self,
        _token: &crate::archive_v3_wal_owner::WalPublisherRuntimeContext,
        expected: &WitnessRecord,
        advance: RootAdvance,
    ) -> Result<(), FirestoreWitnessCommitError> {
        if expected.archive_id() != advance.archive_id() {
            return Err(FirestoreWitnessCommitError::Rejected(
                WitnessError::CompareFailed,
            ));
        }
        self.witness
            .compare_and_advance_exact_wal_owner_root_unresolved_async(expected.clone(), advance)
            .await
            .map(|_| ())
    }
}

impl fmt::Debug for FirestoreShadowWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirestoreShadowWitness(<inactive>)")
    }
}

#[async_trait]
impl AdvisoryOwnerWitnessProvider for FirestoreShadowWitness {
    async fn read_current_exact(
        &self,
        archive_id: ArchiveId,
    ) -> Result<WitnessRecord, WitnessError> {
        self.witness
            .read_current_async(archive_id)
            .await?
            .ok_or(WitnessError::MissingArchive)
    }

    async fn acquire_owner_lease(
        &self,
        expected: &WitnessRecord,
        owner: AdvisoryOwnerId,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), AdvisoryOwnerCommitError> {
        self.witness
            .acquire_exact_advisory_owner_lease_unresolved_async(
                expected.clone(),
                crate::archive_v3::ObjectId::from_bytes(*owner.as_bytes()),
                duration_ticks,
            )
            .await
            .map_err(|error| match error {
                FirestoreWitnessCommitError::Rejected(_) => AdvisoryOwnerCommitError::Rejected,
                FirestoreWitnessCommitError::Failed(_) => {
                    AdvisoryOwnerCommitError::DefinitelyFailed
                }
                FirestoreWitnessCommitError::OutcomeUnknown => {
                    AdvisoryOwnerCommitError::OutcomeUnknown
                }
            })
    }

    async fn maintain_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: AdvisoryOwnerId,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), AdvisoryOwnerCommitError> {
        self.witness
            .maintain_exact_advisory_owner_lease_unresolved_async(
                previous.clone(),
                crate::archive_v3::ObjectId::from_bytes(*owner.as_bytes()),
                duration_ticks,
            )
            .await
            .map_err(|error| match error {
                FirestoreWitnessCommitError::Rejected(_) => AdvisoryOwnerCommitError::Rejected,
                FirestoreWitnessCommitError::Failed(_) => {
                    AdvisoryOwnerCommitError::DefinitelyFailed
                }
                FirestoreWitnessCommitError::OutcomeUnknown => {
                    AdvisoryOwnerCommitError::OutcomeUnknown
                }
            })
    }

    async fn reacquire_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: AdvisoryOwnerId,
        duration_ticks: u64,
    ) -> Result<(WitnessRecord, WitnessLease), AdvisoryOwnerCommitError> {
        self.witness
            .reacquire_exact_advisory_owner_lease_unresolved_async(
                previous.clone(),
                crate::archive_v3::ObjectId::from_bytes(*owner.as_bytes()),
                duration_ticks,
            )
            .await
            .map_err(|error| match error {
                FirestoreWitnessCommitError::Rejected(_) => AdvisoryOwnerCommitError::Rejected,
                FirestoreWitnessCommitError::Failed(_) => {
                    AdvisoryOwnerCommitError::DefinitelyFailed
                }
                FirestoreWitnessCommitError::OutcomeUnknown => {
                    AdvisoryOwnerCommitError::OutcomeUnknown
                }
            })
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

#[async_trait]
impl MaintenanceImportWitnessProvider for FirestoreShadowWitness {
    async fn read_current_exact(
        &self,
        archive_id: ArchiveId,
    ) -> Result<WitnessRecord, WitnessError> {
        self.witness
            .read_current_async(archive_id)
            .await?
            .ok_or(WitnessError::MissingArchive)
    }

    async fn acquire_lease_exact(
        &self,
        record: &WitnessRecord,
        owner: crate::archive_v3::ObjectId,
        duration_ticks: u64,
    ) -> Result<WitnessLease, WitnessError> {
        if !matches!(
            record.migration(),
            MigrationState::Legacy | MigrationState::ShadowWal
        ) || record.deletion() != DeletionState::Active
        {
            return Err(WitnessError::InvalidTransition);
        }
        self.witness
            .acquire_lease_async(
                record.archive_id(),
                record.database_epoch(),
                record.registry().key_epoch(),
                owner,
                duration_ticks,
            )
            .await
    }

    async fn validate_exact_lease(
        &self,
        record: &WitnessRecord,
        owner: crate::archive_v3::ObjectId,
    ) -> Result<WitnessLease, WitnessError> {
        self.witness
            .validate_exact_maintenance_lease_async(record, owner)
            .await
    }

    async fn renew_lease_exact(
        &self,
        lease: WitnessLease,
        duration_ticks: u64,
    ) -> Result<WitnessLease, WitnessError> {
        self.witness.renew_lease_async(lease, duration_ticks).await
    }

    async fn release_terminal_lease_unresolved(
        &self,
        retained: WitnessRecord,
        owner: crate::archive_v3::ObjectId,
    ) -> Result<(), MaintenanceWitnessCommitError> {
        self.witness
            .release_exact_maintenance_terminal_unresolved_async(retained, owner)
            .await
            .map_err(|error| match error {
                FirestoreWitnessCommitError::Rejected(_) => MaintenanceWitnessCommitError::Rejected,
                FirestoreWitnessCommitError::Failed(_) => {
                    MaintenanceWitnessCommitError::DefinitelyFailed
                }
                FirestoreWitnessCommitError::OutcomeUnknown => {
                    MaintenanceWitnessCommitError::OutcomeUnknown
                }
            })
    }

    async fn release_advisory_lease_unresolved(
        &self,
        retained: WitnessRecord,
        owner: crate::archive_v3::ObjectId,
    ) -> Result<(), MaintenanceWitnessCommitError> {
        self.witness
            .release_exact_maintenance_advisory_unresolved_async(retained, owner)
            .await
            .map_err(|error| match error {
                FirestoreWitnessCommitError::Rejected(_) => MaintenanceWitnessCommitError::Rejected,
                FirestoreWitnessCommitError::Failed(_) => {
                    MaintenanceWitnessCommitError::DefinitelyFailed
                }
                FirestoreWitnessCommitError::OutcomeUnknown => {
                    MaintenanceWitnessCommitError::OutcomeUnknown
                }
            })
    }

    async fn advance_migration_unresolved(
        &self,
        expected: WitnessRecord,
        candidate: WitnessRecord,
        advance: RootAdvance,
        next: MigrationState,
    ) -> Result<(), MaintenanceWitnessCommitError> {
        self.witness
            .advance_exact_migration_candidate_unresolved_async(expected, candidate, advance, next)
            .await
            .map_err(|error| match error {
                FirestoreWitnessCommitError::Rejected(_) => MaintenanceWitnessCommitError::Rejected,
                FirestoreWitnessCommitError::Failed(_) => {
                    MaintenanceWitnessCommitError::DefinitelyFailed
                }
                FirestoreWitnessCommitError::OutcomeUnknown => {
                    MaintenanceWitnessCommitError::OutcomeUnknown
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
