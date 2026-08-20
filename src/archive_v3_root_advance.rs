#![allow(
    dead_code,
    reason = "inactive ADR-0022 root-advance core is compiled and tested before any external launcher or serving wiring"
)]

//! ADR-0022 root-advance core (genesis spine G1).
//!
//! Extracted verbatim from the inactive single-archive importer: the exact
//! witness-advance provider boundary and the zero-WAL root-candidate builder.
//! This module has no Store, VFS, startup, route, flag, provider-construction,
//! or authority wiring, and its surface is pinned free of importer-only types
//! by a self-source test.

use async_trait::async_trait;
use thiserror::Error;

use crate::{
    archive_v3::{
        ArchiveId, ArchiveRoot, CiphertextEnvelope, ImmutableObjectBackend, LogicalLocation,
        ObjectContext, ObjectId, ObjectRole, ParentReference, VerifiedArchiveCipher,
        ARCHIVE_FORMAT_VERSION, SQLITE_PAGE_SIZE,
    },
    archive_v3_shadow_checkpoint::{ShadowObjectStaging, UploadedCheckpoint},
    archive_v3_witness::{
        ExactRootProvider, MigrationState, RootAdvance, WitnessError, WitnessLease, WitnessRecord,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WitnessAdvanceCommitError {
    Rejected,
    DefinitelyFailed,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum RootAdvanceError {
    #[error("root advance authority is unavailable")]
    Unavailable,
    #[error("root advance durable state is corrupt")]
    Corrupt,
}

/// Exact witness boundary for advancing an archive root. Implementors may not
/// return raw transports or accept a caller-created recovery root.
#[async_trait]
pub(crate) trait ArchiveWitnessAdvanceProvider: Send + Sync {
    async fn read_current_exact(
        &self,
        archive_id: ArchiveId,
    ) -> Result<WitnessRecord, WitnessError>;

    async fn acquire_lease_exact(
        &self,
        record: &WitnessRecord,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> Result<WitnessLease, WitnessError>;

    /// Re-read the exact stored record and evaluate its retained lease at the
    /// provider's trusted read time without mutating the record bytes. This is
    /// the only precondition that permits retrying a durable send candidate.
    async fn validate_exact_lease(
        &self,
        record: &WitnessRecord,
        owner: ObjectId,
    ) -> Result<WitnessLease, WitnessError>;

    async fn renew_lease_exact(
        &self,
        lease: WitnessLease,
        duration_ticks: u64,
    ) -> Result<WitnessLease, WitnessError>;

    async fn release_terminal_lease_unresolved(
        &self,
        retained: WitnessRecord,
        owner: ObjectId,
    ) -> Result<(), WitnessAdvanceCommitError>;

    async fn release_advisory_lease_unresolved(
        &self,
        retained: WitnessRecord,
        owner: ObjectId,
    ) -> Result<(), WitnessAdvanceCommitError>;

    async fn advance_migration_unresolved(
        &self,
        expected: WitnessRecord,
        candidate: WitnessRecord,
        advance: RootAdvance,
        next: MigrationState,
    ) -> Result<(), WitnessAdvanceCommitError>;
}

struct BackendRootReader<'a> {
    backend: &'a dyn ImmutableObjectBackend,
}

#[async_trait]
impl ExactRootProvider for BackendRootReader<'_> {
    async fn read_exact(
        &self,
        context: &ObjectContext,
    ) -> Result<CiphertextEnvelope, WitnessError> {
        self.backend
            .get(&context.object_key())
            .await
            .map_err(|_| WitnessError::Unavailable)?
            .ok_or(WitnessError::MissingArchive)
    }
}

pub(crate) async fn build_zero_wal_candidate(
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    current: &WitnessRecord,
    lease: WitnessLease,
    checkpoint: &UploadedCheckpoint,
    staging: &ShadowObjectStaging<'_>,
) -> Result<RootAdvance, RootAdvanceError> {
    let expected = current.root();
    let root_seq = expected
        .root()
        .sequence()
        .checked_add(1)
        .ok_or(RootAdvanceError::Corrupt)?;
    let parent = ParentReference {
        object_id: expected.root().object_id(),
        envelope_hash: expected.root().ciphertext_hash(),
    };
    let context = ObjectContext::new(
        current.archive_id(),
        current.database_epoch(),
        current.registry().key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root { root_seq },
        ObjectId::random(),
        Some(parent.clone()),
    )
    .map_err(|_| RootAdvanceError::Corrupt)?;
    let root = ArchiveRoot {
        root_seq,
        parent: Some(parent),
        database_epoch: current.database_epoch(),
        key_epoch: current.registry().key_epoch(),
        owner_fencing_epoch: lease.fencing_epoch(),
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
    let envelope = cipher
        .seal(
            &context,
            &root.encode().map_err(|_| RootAdvanceError::Corrupt)?,
        )
        .map_err(|_| RootAdvanceError::Corrupt)?;
    staging
        .create_and_readback(backend, &context, envelope)
        .await
        .map_err(|_| RootAdvanceError::Unavailable)?;
    RootAdvance::from_authenticated_candidate(
        lease,
        expected,
        current.registry(),
        current.registry(),
        &context,
        &BackendRootReader { backend },
        cipher,
    )
    .await
    .map_err(|_| RootAdvanceError::Corrupt)
}

#[cfg(test)]
mod tests {
    #[test]
    fn root_advance_surface_has_no_importer_only_types() {
        let source = include_str!("archive_v3_root_advance.rs");
        for forbidden in [
            concat!("Mainten", "ance"),
            concat!("PinnedLegacy", "Snapshot"),
            concat!("CompletedMainten", "ance", "ParityEvidence"),
            concat!("Mainten", "ance", "SourceBinding"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden root-advance surface: {forbidden}"
            );
        }
    }
}
