#![allow(
    dead_code,
    reason = "inactive ADR-0022 maintenance import is compiled and tested before any external launcher or serving wiring"
)]

//! Inactive, single-archive ADR-0022 maintenance importer and Phase-1
//! advisory-shadow bootstrap.
//!
//! This module is the sole owner of the maintenance state machine. It accepts
//! only a sealed image-bound runtime, an encrypted-control plan, and a
//! Store-owned pinned legacy snapshot. It has no route, startup hook, serving
//! result, delete operation, prefix listing, or production policy switch.
//! Every provider-visible candidate is durable before send and every ambiguous
//! send is reconciled from the exact witness record before another candidate
//! can exist. A type-separated advisory owner stops after full parity at
//! ShadowWal, releases only that exact maintenance lease, drops its owned Store
//! guards, and cannot request the later WalAuthoritative transition. The
//! permanent legacy provider fence and fail-closed Store/barrier blocks remain
//! until the separately reviewed inactive advisory release and exact local-
//! resume transitions restore legacy admission; neither has a live caller.

use std::{
    fmt,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    archive_v3::{
        resolve_archive_cipher, ArchiveId, ArchiveRoot, CiphertextEnvelope,
        ExactKeyRegistryProvider, ImmutableObjectBackend, KeyKind, KeyRegistryContext,
        LogicalLocation, ObjectContext, ObjectId, ObjectRole, ParentReference,
        VerifiedArchiveCipher, ARCHIVE_FORMAT_VERSION, SQLITE_PAGE_SIZE,
    },
    archive_v3_shadow_checkpoint::{
        reconcile_reserved_shadow_objects, upload_checkpoint, MaintenanceCheckpointSource,
        ShadowObjectInventory, ShadowObjectStaging, UploadedCheckpoint,
    },
    archive_v3_shadow_parity::{
        PrivateStagedSqliteCopy, ShadowParityResult, ShadowParityRunControl, ShadowParityVerifier,
    },
    archive_v3_shadow_session::{ShadowSessionBinding, ShadowSessionId},
    archive_v3_shadow_wal::recover_owned_maintenance_staging,
    archive_v3_witness::{
        DeletionState, ExactRootProvider, MigrationState, RecoveryRoot, RootAdvance, WitnessError,
        WitnessLease, WitnessRecord,
    },
};

const IMPORT_OPERATION_DOMAIN: &[u8] = b"kioku/archive-v3/maintenance-import-operation/v1\0";
const IMPORT_SOURCE_DOMAIN: &[u8] = b"kioku/archive-v3/maintenance-import-source/v1\0";
const IMPORT_PARITY_DOMAIN: &[u8] = b"kioku/archive-v3/maintenance-import-parity/v1\0";
pub(crate) const MAX_MAINTENANCE_IMPORT_ATTEMPTS: u32 = 16;
const MAINTENANCE_LEASE_TICKS: u64 = 86_400;

pub(crate) struct MaintenanceStagingContext(());
pub(crate) struct MaintenanceWitnessRecoveryContext(());
pub(crate) struct MaintenanceCoordinatorContext(());
pub(crate) struct MaintenanceZeroWalBindingContext(());

impl MaintenanceZeroWalBindingContext {
    pub(crate) const fn from_control(
        _token: crate::cp::control_store::MaintenancePersistenceContext,
    ) -> Self {
        Self(())
    }

    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self(())
    }
}

impl MaintenanceCoordinatorContext {
    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MaintenanceImportStage {
    Prepared = 1,
    Fencing = 2,
    LegacyPinned = 3,
    ShadowUploading = 4,
    ShadowSendUnknown = 5,
    ShadowWal = 6,
    ParityVerified = 7,
    AuthoritativeUploading = 8,
    AuthoritativeSendUnknown = 9,
    WalAuthoritative = 10,
    ManualRequired = 11,
}

impl MaintenanceImportStage {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Fencing => "fencing",
            Self::LegacyPinned => "legacy_pinned",
            Self::ShadowUploading => "shadow_uploading",
            Self::ShadowSendUnknown => "shadow_send_unknown",
            Self::ShadowWal => "shadow_wal",
            Self::ParityVerified => "parity_verified",
            Self::AuthoritativeUploading => "authoritative_uploading",
            Self::AuthoritativeSendUnknown => "authoritative_send_unknown",
            Self::WalAuthoritative => "wal_authoritative",
            Self::ManualRequired => "manual_required",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self, MaintenanceImportError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "fencing" => Ok(Self::Fencing),
            "legacy_pinned" => Ok(Self::LegacyPinned),
            "shadow_uploading" => Ok(Self::ShadowUploading),
            "shadow_send_unknown" => Ok(Self::ShadowSendUnknown),
            "shadow_wal" => Ok(Self::ShadowWal),
            "parity_verified" => Ok(Self::ParityVerified),
            "authoritative_uploading" => Ok(Self::AuthoritativeUploading),
            "authoritative_send_unknown" => Ok(Self::AuthoritativeSendUnknown),
            "wal_authoritative" => Ok(Self::WalAuthoritative),
            "manual_required" => Ok(Self::ManualRequired),
            _ => Err(MaintenanceImportError::Corrupt),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaintenanceImportOperationId([u8; 16]);

impl MaintenanceImportOperationId {
    fn random() -> Self {
        Self(*ObjectId::random().as_bytes())
    }

    pub(crate) fn random_for_control(
        _token: crate::cp::control_store::MaintenancePersistenceContext,
    ) -> Self {
        Self::random()
    }

    pub(crate) const fn from_control(
        _token: crate::cp::control_store::MaintenancePersistenceContext,
        bytes: [u8; 16],
    ) -> Result<Self, MaintenanceImportError> {
        if zero(&bytes) {
            return Err(MaintenanceImportError::Corrupt);
        }
        Ok(Self(bytes))
    }

    #[cfg(test)]
    pub(crate) const fn from_bytes_for_test(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for MaintenanceImportOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaintenanceImportOperationId(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaintenanceSourceBinding {
    generation: i64,
    plaintext_hash: [u8; 32],
    plaintext_len: u64,
    sqlite_schema_version: u32,
    wrapped_dek_commitment: [u8; 32],
    commitment: [u8; 32],
}

impl MaintenanceSourceBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_pinned(
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        generation: i64,
        plaintext_hash: [u8; 32],
        plaintext_len: u64,
        sqlite_schema_version: u32,
        wrapped_dek_commitment: [u8; 32],
    ) -> Result<Self, MaintenanceImportError> {
        if generation <= 0
            || plaintext_len == 0
            || !plaintext_len.is_multiple_of(4096)
            || plaintext_len > crate::archive_v3::MAX_DATABASE_BYTES
            || zero(&plaintext_hash)
            || zero(&wrapped_dek_commitment)
        {
            return Err(MaintenanceImportError::Corrupt);
        }
        let mut hasher = Sha256::new();
        hasher.update(IMPORT_SOURCE_DOMAIN);
        hasher.update(archive_id.as_bytes());
        hasher.update(operation_id.as_bytes());
        hasher.update(generation.to_be_bytes());
        hasher.update(plaintext_hash);
        hasher.update(plaintext_len.to_be_bytes());
        hasher.update(sqlite_schema_version.to_be_bytes());
        hasher.update(wrapped_dek_commitment);
        let commitment = hasher.finalize().into();
        Ok(Self {
            generation,
            plaintext_hash,
            plaintext_len,
            sqlite_schema_version,
            wrapped_dek_commitment,
            commitment,
        })
    }

    pub(crate) fn store_view(
        self,
        _token: crate::store::StoreMaintenanceContext,
    ) -> MaintenanceSourceStoreView {
        MaintenanceSourceStoreView {
            generation: self.generation,
            plaintext_hash: self.plaintext_hash,
            plaintext_len: self.plaintext_len,
            sqlite_schema_version: self.sqlite_schema_version,
            wrapped_dek_commitment: self.wrapped_dek_commitment,
            commitment: self.commitment,
        }
    }

    pub(crate) fn control_view(
        self,
        _token: crate::cp::control_store::MaintenancePersistenceContext,
    ) -> MaintenanceSourceControlView {
        MaintenanceSourceControlView {
            generation: self.generation,
            plaintext_hash: self.plaintext_hash,
            plaintext_len: self.plaintext_len,
            sqlite_schema_version: self.sqlite_schema_version,
            wrapped_dek_commitment: self.wrapped_dek_commitment,
            commitment: self.commitment,
        }
    }
}

pub(crate) struct MaintenanceSourceControlView {
    pub(crate) generation: i64,
    pub(crate) plaintext_hash: [u8; 32],
    pub(crate) plaintext_len: u64,
    pub(crate) sqlite_schema_version: u32,
    pub(crate) wrapped_dek_commitment: [u8; 32],
    pub(crate) commitment: [u8; 32],
}

pub(crate) struct MaintenanceSourceStoreView {
    pub(crate) generation: i64,
    pub(crate) plaintext_hash: [u8; 32],
    pub(crate) plaintext_len: u64,
    pub(crate) sqlite_schema_version: u32,
    pub(crate) wrapped_dek_commitment: [u8; 32],
    pub(crate) commitment: [u8; 32],
}

impl fmt::Debug for MaintenanceSourceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaintenanceSourceBinding(<opaque>)")
    }
}

/// One-shot control capability. The user and archive identities have no
/// getters; Store and sealed-runtime consumption use producer tokens rather
/// than caller-supplied identifiers.
#[derive(Clone)]
pub(crate) struct AuthenticatedMaintenanceImportPlan {
    user_id: String,
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    owner_id: ObjectId,
    attempt: u32,
    attempt_id: crate::archive_v3_shadow_session::ShadowAttemptId,
    fence_authority: String,
    operation_commitment: [u8; 32],
}

impl AuthenticatedMaintenanceImportPlan {
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated maintenance tuple; grouping would obscure exact binding"
    )]
    pub(crate) fn from_control(
        _token: crate::cp::control_store::MaintenancePersistenceContext,
        user_id: String,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        owner_id: ObjectId,
        attempt: u32,
        attempt_id: crate::archive_v3_shadow_session::ShadowAttemptId,
        fence_authority: String,
    ) -> Result<Self, MaintenanceImportError> {
        if user_id.is_empty()
            || zero(archive_id.as_bytes())
            || zero(owner_id.as_bytes())
            || attempt == 0
            || attempt > MAX_MAINTENANCE_IMPORT_ATTEMPTS
            || zero(attempt_id.as_bytes())
            || fence_authority.len() != 72
            || !fence_authority.starts_with("archive_")
            || !fence_authority[8..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(MaintenanceImportError::Corrupt);
        }
        let operation_commitment =
            operation_commitment_for(archive_id, operation_id, owner_id, &fence_authority);
        Ok(Self {
            user_id,
            archive_id,
            operation_id,
            owner_id,
            attempt,
            attempt_id,
            fence_authority,
            operation_commitment,
        })
    }

    pub(crate) fn plan_user_id(&self) -> &str {
        &self.user_id
    }

    pub(crate) fn fence_authority(&self) -> &str {
        &self.fence_authority
    }

    pub(crate) const fn plan_operation_commitment(&self) -> [u8; 32] {
        self.operation_commitment
    }

    pub(crate) const fn plan_archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn plan_operation_id(&self) -> MaintenanceImportOperationId {
        self.operation_id
    }

    #[cfg(test)]
    pub(crate) fn components_for_test(
        &self,
    ) -> (&str, ArchiveId, MaintenanceImportOperationId, &str) {
        (
            &self.user_id,
            self.archive_id,
            self.operation_id,
            &self.fence_authority,
        )
    }

    pub(crate) fn into_store_view(
        self,
        _token: crate::store::StoreMaintenanceContext,
    ) -> MaintenanceStorePlanView {
        MaintenanceStorePlanView {
            user_id: self.user_id,
            archive_id: self.archive_id,
            operation_id: self.operation_id,
            owner_id: self.owner_id,
            attempt: self.attempt,
            attempt_id: self.attempt_id,
            fence_authority: self.fence_authority,
            operation_commitment: self.operation_commitment,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        user_id: &str,
        archive_id: ArchiveId,
        operation_id: [u8; 16],
        owner_id: ObjectId,
    ) -> Self {
        Self::from_control(
            crate::cp::control_store::MaintenancePersistenceContext::for_test(),
            user_id.to_owned(),
            archive_id,
            MaintenanceImportOperationId::from_control(
                crate::cp::control_store::MaintenancePersistenceContext::for_test(),
                operation_id,
            )
            .expect("test operation ID"),
            owner_id,
            1,
            crate::archive_v3_shadow_session::ShadowAttemptId::from_bytes([0x44; 16]),
            format!("archive_{}", "5".repeat(64)),
        )
        .expect("test maintenance plan")
    }
}

impl fmt::Debug for AuthenticatedMaintenanceImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedMaintenanceImportPlan(<opaque>)")
    }
}

/// Sealed, non-cloneable proof of one durable Phase-2 authority acquisition.
/// Constructible only from a control-minted, fully validated acquisition row
/// through control's private producer token. The retained `owner_id` is the
/// frozen advisory owner identity from the acquisition row — deliberately a
/// different namespace than the maintenance plan's own witness-lease owner —
/// so the importer gate binds through the row commitment, which covers every
/// acquisition field. There is no durable resumed-local-admission marker; the
/// acquisition row this plan seals was mintable only against the retired
/// advisory controller run, the strongest durable proxy for the fully settled
/// advisory terminal.
pub(crate) struct Phase2AcquiredAuthorityPlan {
    user_id: String,
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    owner_id: ObjectId,
    acquisition_fence_authority: String,
    acquisition_commitment: [u8; 32],
}

impl Phase2AcquiredAuthorityPlan {
    pub(crate) fn from_acquisition(
        _token: crate::cp::control_store::Phase2AuthorityPersistenceContext,
        user_id: &str,
        row: &crate::cp::control_store::Phase2AuthorityAcquisition,
    ) -> Result<Self, MaintenanceImportError> {
        let fence_authority = row.acquisition_fence_authority();
        if user_id.is_empty()
            || zero(row.archive_id().as_bytes())
            || zero(row.owner_id().as_bytes())
            || zero(&row.commitment())
            || fence_authority.len() != 72
            || !fence_authority.starts_with("archive_")
            || !fence_authority[8..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || row.stage() != crate::cp::control_store::Phase2AcquisitionStage::Phase2Acquired
        {
            return Err(MaintenanceImportError::Corrupt);
        }
        Ok(Self {
            user_id: user_id.to_owned(),
            archive_id: row.archive_id(),
            operation_id: row.maintenance_operation_id(),
            owner_id: row.owner_id(),
            acquisition_fence_authority: fence_authority.to_owned(),
            acquisition_commitment: row.commitment(),
        })
    }
}

impl fmt::Debug for Phase2AcquiredAuthorityPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Phase2AcquiredAuthorityPlan(<opaque>)")
    }
}

pub(crate) struct MaintenanceStorePlanView {
    pub(crate) user_id: String,
    pub(crate) archive_id: ArchiveId,
    pub(crate) operation_id: MaintenanceImportOperationId,
    pub(crate) owner_id: ObjectId,
    pub(crate) attempt: u32,
    pub(crate) attempt_id: crate::archive_v3_shadow_session::ShadowAttemptId,
    pub(crate) fence_authority: String,
    pub(crate) operation_commitment: [u8; 32],
}

#[derive(PartialEq, Eq)]
pub(crate) struct MaintenanceImportRecord {
    stage: MaintenanceImportStage,
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    owner_id: ObjectId,
    attempt: u32,
    attempt_id: crate::archive_v3_shadow_session::ShadowAttemptId,
    next_artifact_ordinal: u32,
    operation_commitment: [u8; 32],
    tentative: Option<crate::store::MaintenanceTentativeSource>,
    source: Option<MaintenanceSourceBinding>,
    witness_bytes: Option<Box<[u8]>>,
    shadow_candidate: Option<Box<[u8]>>,
    parity_commitment: Option<[u8; 32]>,
    authoritative_candidate: Option<Box<[u8]>>,
}

impl fmt::Debug for MaintenanceImportRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaintenanceImportRecord(<opaque>)")
    }
}

impl MaintenanceImportRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control_persistence(
        _token: crate::cp::control_store::MaintenancePersistenceContext,
        stage: MaintenanceImportStage,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        owner_id: ObjectId,
        attempt: u32,
        attempt_id: crate::archive_v3_shadow_session::ShadowAttemptId,
        next_artifact_ordinal: u32,
        operation_commitment: [u8; 32],
        tentative: Option<crate::store::MaintenanceTentativeSource>,
        source: Option<MaintenanceSourceBinding>,
        witness_bytes: Option<Vec<u8>>,
        shadow_candidate: Option<Vec<u8>>,
        parity_commitment: Option<[u8; 32]>,
        authoritative_candidate: Option<Vec<u8>>,
    ) -> Result<Self, MaintenanceImportError> {
        if attempt == 0
            || attempt > MAX_MAINTENANCE_IMPORT_ATTEMPTS
            || zero(archive_id.as_bytes())
            || zero(owner_id.as_bytes())
            || zero(attempt_id.as_bytes())
            || usize::try_from(next_artifact_ordinal)
                .ok()
                .is_none_or(|value| {
                    value > crate::archive_v3_operation::MAX_SHADOW_OBJECTS_PER_ATTEMPT
                })
            || zero(&operation_commitment)
            || witness_bytes.as_ref().is_some_and(|bytes| bytes.is_empty())
            || shadow_candidate
                .as_ref()
                .is_some_and(|bytes| bytes.is_empty())
            || authoritative_candidate
                .as_ref()
                .is_some_and(|bytes| bytes.is_empty())
            || parity_commitment.as_ref().is_some_and(zero)
            || (stage != MaintenanceImportStage::ManualRequired
                && (((stage == MaintenanceImportStage::Prepared) != tentative.is_none())
                    || (matches!(
                        stage,
                        MaintenanceImportStage::Prepared | MaintenanceImportStage::Fencing
                    ) != source.is_none())
                    || (matches!(
                        stage,
                        MaintenanceImportStage::Prepared
                            | MaintenanceImportStage::Fencing
                            | MaintenanceImportStage::LegacyPinned
                    ) != witness_bytes.is_none())
                    || (matches!(
                        stage,
                        MaintenanceImportStage::Prepared
                            | MaintenanceImportStage::Fencing
                            | MaintenanceImportStage::LegacyPinned
                    ) && shadow_candidate.is_some())
                    || (matches!(
                        stage,
                        MaintenanceImportStage::ShadowSendUnknown
                            | MaintenanceImportStage::ShadowWal
                            | MaintenanceImportStage::ParityVerified
                            | MaintenanceImportStage::AuthoritativeUploading
                            | MaintenanceImportStage::AuthoritativeSendUnknown
                            | MaintenanceImportStage::WalAuthoritative
                    ) && shadow_candidate.is_none())
                    || (matches!(
                        stage,
                        MaintenanceImportStage::Prepared
                            | MaintenanceImportStage::Fencing
                            | MaintenanceImportStage::LegacyPinned
                            | MaintenanceImportStage::ShadowUploading
                            | MaintenanceImportStage::ShadowSendUnknown
                            | MaintenanceImportStage::ShadowWal
                    ) && parity_commitment.is_some())
                    || (matches!(
                        stage,
                        MaintenanceImportStage::ParityVerified
                            | MaintenanceImportStage::AuthoritativeUploading
                            | MaintenanceImportStage::AuthoritativeSendUnknown
                            | MaintenanceImportStage::WalAuthoritative
                    ) && parity_commitment.is_none())
                    || (matches!(
                        stage,
                        MaintenanceImportStage::Prepared
                            | MaintenanceImportStage::Fencing
                            | MaintenanceImportStage::LegacyPinned
                            | MaintenanceImportStage::ShadowUploading
                            | MaintenanceImportStage::ShadowSendUnknown
                            | MaintenanceImportStage::ShadowWal
                            | MaintenanceImportStage::ParityVerified
                    ) && authoritative_candidate.is_some())
                    || (matches!(
                        stage,
                        MaintenanceImportStage::AuthoritativeUploading
                            | MaintenanceImportStage::AuthoritativeSendUnknown
                            | MaintenanceImportStage::WalAuthoritative
                    ) && authoritative_candidate.is_none())))
            || (stage == MaintenanceImportStage::ManualRequired
                && ((authoritative_candidate.is_some() && parity_commitment.is_none())
                    || (parity_commitment.is_some() && shadow_candidate.is_none())
                    || (shadow_candidate.is_some() && witness_bytes.is_none())
                    || (witness_bytes.is_some() && source.is_none())
                    || (source.is_some() && tentative.is_none())))
        {
            return Err(MaintenanceImportError::Corrupt);
        }
        if let Some(tentative) = tentative {
            if tentative.base_generation < 0
                || tentative.plaintext_len == 0
                || !tentative.plaintext_len.is_multiple_of(4096)
                || tentative.plaintext_len > crate::archive_v3::MAX_DATABASE_BYTES
                || zero(&tentative.plaintext_hash)
                || zero(&tentative.wrapped_dek_commitment)
                || source.is_some_and(|source| {
                    source.generation <= tentative.base_generation
                        || source.plaintext_hash != tentative.plaintext_hash
                        || source.plaintext_len != tentative.plaintext_len
                        || source.sqlite_schema_version != tentative.sqlite_schema_version
                        || source.wrapped_dek_commitment != tentative.wrapped_dek_commitment
                })
            {
                return Err(MaintenanceImportError::Corrupt);
            }
        }
        if let Some(bytes) = witness_bytes.as_ref() {
            let record =
                WitnessRecord::decode(bytes).map_err(|_| MaintenanceImportError::Corrupt)?;
            let expected_migration = match stage {
                MaintenanceImportStage::ShadowUploading
                | MaintenanceImportStage::ShadowSendUnknown => MigrationState::Legacy,
                MaintenanceImportStage::ShadowWal
                | MaintenanceImportStage::ParityVerified
                | MaintenanceImportStage::AuthoritativeUploading
                | MaintenanceImportStage::AuthoritativeSendUnknown => MigrationState::ShadowWal,
                MaintenanceImportStage::WalAuthoritative => MigrationState::WalAuthoritative,
                MaintenanceImportStage::ManualRequired if authoritative_candidate.is_some() => {
                    MigrationState::ShadowWal
                }
                MaintenanceImportStage::ManualRequired => MigrationState::Legacy,
                MaintenanceImportStage::Prepared
                | MaintenanceImportStage::Fencing
                | MaintenanceImportStage::LegacyPinned => {
                    return Err(MaintenanceImportError::Corrupt)
                }
            };
            if record.archive_id() != archive_id
                || record.deletion() != crate::archive_v3_witness::DeletionState::Active
                || record.migration() != expected_migration
            {
                return Err(MaintenanceImportError::Corrupt);
            }
        }
        if let Some(bytes) = shadow_candidate.as_ref() {
            let candidate =
                WitnessRecord::decode(bytes).map_err(|_| MaintenanceImportError::Corrupt)?;
            if candidate.archive_id() != archive_id
                || candidate.deletion() != crate::archive_v3_witness::DeletionState::Active
                || candidate.migration() != MigrationState::ShadowWal
            {
                return Err(MaintenanceImportError::Corrupt);
            }
        }
        if let Some(bytes) = authoritative_candidate.as_ref() {
            let candidate =
                WitnessRecord::decode(bytes).map_err(|_| MaintenanceImportError::Corrupt)?;
            if candidate.archive_id() != archive_id
                || candidate.deletion() != crate::archive_v3_witness::DeletionState::Active
                || candidate.migration() != MigrationState::WalAuthoritative
            {
                return Err(MaintenanceImportError::Corrupt);
            }
        }
        Ok(Self {
            stage,
            archive_id,
            operation_id,
            owner_id,
            attempt,
            attempt_id,
            next_artifact_ordinal,
            operation_commitment,
            tentative,
            source,
            witness_bytes: witness_bytes.map(Vec::into_boxed_slice),
            shadow_candidate: shadow_candidate.map(Vec::into_boxed_slice),
            parity_commitment,
            authoritative_candidate: authoritative_candidate.map(Vec::into_boxed_slice),
        })
    }

    pub(crate) const fn stage(&self) -> MaintenanceImportStage {
        self.stage
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn operation_id(&self) -> MaintenanceImportOperationId {
        self.operation_id
    }

    pub(crate) const fn source(&self) -> Option<MaintenanceSourceBinding> {
        self.source
    }

    pub(crate) const fn attempt_id(&self) -> crate::archive_v3_shadow_session::ShadowAttemptId {
        self.attempt_id
    }

    pub(crate) const fn next_artifact_ordinal(&self) -> u32 {
        self.next_artifact_ordinal
    }

    pub(crate) const fn owner_id_for_control(
        &self,
        _token: crate::cp::control_store::MaintenancePersistenceContext,
    ) -> ObjectId {
        self.owner_id
    }

    /// Encrypted-Control-only authentication for the Phase-1 owner reserve
    /// and bind transactions. The expected record must be the exact released
    /// ShadowWal successor of this immutable parity terminal.
    pub(crate) fn authenticate_advisory_owner_terminal(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        operation_id: MaintenanceImportOperationId,
        expected: &WitnessRecord,
    ) -> Result<(), MaintenanceImportError> {
        if self.operation_id != operation_id {
            return Err(MaintenanceImportError::Conflict);
        }
        validate_advisory_parity_evidence(
            self,
            self.source.ok_or(MaintenanceImportError::Corrupt)?,
            expected,
        )
    }

    pub(crate) fn witnessed_record(&self) -> Result<Option<WitnessRecord>, MaintenanceImportError> {
        self.witness_bytes
            .as_deref()
            .map(WitnessRecord::decode)
            .transpose()
            .map_err(|_| MaintenanceImportError::Corrupt)
    }

    fn shadow_candidate_record(&self) -> Result<Option<WitnessRecord>, MaintenanceImportError> {
        self.shadow_candidate
            .as_deref()
            .map(WitnessRecord::decode)
            .transpose()
            .map_err(|_| MaintenanceImportError::Corrupt)
    }

    fn authoritative_candidate_record(
        &self,
    ) -> Result<Option<WitnessRecord>, MaintenanceImportError> {
        self.authoritative_candidate
            .as_deref()
            .map(WitnessRecord::decode)
            .transpose()
            .map_err(|_| MaintenanceImportError::Corrupt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum MaintenanceImportError {
    #[error("maintenance import authority is unavailable")]
    Unavailable,
    #[error("maintenance import authority conflicts")]
    Conflict,
    #[error("maintenance import durable state is corrupt")]
    Corrupt,
    #[error("maintenance import requires exact reconciliation")]
    OutcomeUnknown,
    #[error("maintenance import parity did not match")]
    ParityMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintenanceWitnessCommitError {
    Rejected,
    DefinitelyFailed,
    OutcomeUnknown,
}

/// Non-cloneable exact migration candidate. It can only be built by applying
/// the authenticated RootAdvance to the freshly read witness in the local
/// witness state machine; control consumes its sealed bytes before send.
pub(crate) struct PreparedMaintenanceMigration {
    expected_current_hash: [u8; 32],
    candidate: Box<[u8]>,
    next: MigrationState,
}

impl PreparedMaintenanceMigration {
    pub(crate) fn from_authenticated_advance(
        current: &WitnessRecord,
        advance: &RootAdvance,
        next: MigrationState,
    ) -> Result<Self, MaintenanceImportError> {
        if !matches!(
            (current.migration(), next),
            (MigrationState::Legacy, MigrationState::ShadowWal)
                | (MigrationState::ShadowWal, MigrationState::WalAuthoritative)
        ) {
            return Err(MaintenanceImportError::Conflict);
        }
        let candidate = current
            .exact_migration_candidate(advance, next)
            .map_err(|_| MaintenanceImportError::Conflict)?
            .encode()
            .to_vec();
        Ok(Self {
            expected_current_hash: Sha256::digest(current.encode()).into(),
            candidate: candidate.into_boxed_slice(),
            next,
        })
    }

    pub(crate) fn control_view(
        self,
        _token: crate::cp::control_store::MaintenancePersistenceContext,
    ) -> PreparedMaintenanceMigrationControlView {
        PreparedMaintenanceMigrationControlView {
            expected_current_hash: self.expected_current_hash,
            candidate: self.candidate.into_vec(),
            next: self.next,
        }
    }
}

pub(crate) struct PreparedMaintenanceMigrationControlView {
    pub(crate) expected_current_hash: [u8; 32],
    pub(crate) candidate: Vec<u8>,
    pub(crate) next: MigrationState,
}

impl fmt::Debug for PreparedMaintenanceMigration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedMaintenanceMigration(<opaque>)")
    }
}

/// Exact witness boundary used only by this inactive importer. Implementors
/// may not return raw transports or accept a caller-created recovery root.
#[async_trait]
pub(crate) trait MaintenanceImportWitnessProvider: Send + Sync {
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
    ) -> Result<(), MaintenanceWitnessCommitError>;

    async fn release_advisory_lease_unresolved(
        &self,
        retained: WitnessRecord,
        owner: ObjectId,
    ) -> Result<(), MaintenanceWitnessCommitError>;

    async fn advance_migration_unresolved(
        &self,
        expected: WitnessRecord,
        candidate: WitnessRecord,
        advance: RootAdvance,
        next: MigrationState,
    ) -> Result<(), MaintenanceWitnessCommitError>;
}

/// Durable state boundary. A concrete ControlStore implementation must use
/// cancellation-safe owned-handle writes for every mutating method.
#[async_trait]
pub(crate) trait MaintenanceImportPersistence: ShadowObjectInventory + Send + Sync {
    fn as_shadow_inventory(&self) -> &dyn ShadowObjectInventory;

    async fn load_exact(
        &self,
        operation_id: MaintenanceImportOperationId,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn ensure_advisory_release_absent(
        &self,
        operation_id: MaintenanceImportOperationId,
    ) -> Result<(), MaintenanceImportError>;

    async fn persist_fencing(
        &self,
        operation_id: MaintenanceImportOperationId,
        tentative: crate::store::MaintenanceTentativeSource,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn persist_fencing_rebase(
        &self,
        operation_id: MaintenanceImportOperationId,
        previous: crate::store::MaintenanceTentativeSource,
        replacement: crate::store::MaintenanceTentativeSource,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn persist_pinned_source(
        &self,
        operation_id: MaintenanceImportOperationId,
        source: MaintenanceSourceBinding,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn persist_witness_and_lease(
        &self,
        operation_id: MaintenanceImportOperationId,
        source: MaintenanceSourceBinding,
        witness: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    /// Before a root candidate exists, a crash-left partial randomized upload
    /// is never replayed with replacement bytes. Control either returns the
    /// empty current attempt or atomically retains it as superseded and mints
    /// the next bounded attempt.
    async fn prepare_shadow_upload_attempt(
        &self,
        operation_id: MaintenanceImportOperationId,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn prepare_authoritative_upload_attempt(
        &self,
        operation_id: MaintenanceImportOperationId,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn persist_renewed_lease(
        &self,
        operation_id: MaintenanceImportOperationId,
        expected_stage: MaintenanceImportStage,
        previous: &WitnessRecord,
        renewed: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn persist_reacquired_lease(
        &self,
        operation_id: MaintenanceImportOperationId,
        expected_stage: MaintenanceImportStage,
        previous: &WitnessRecord,
        reacquired: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    /// Persist the Phase-2 witness-lease succession from the settled advisory
    /// terminal. Control revalidates the exact succession (or its restart
    /// lineage) and binds the fresh-basis hash to the durable Phase-2
    /// acquisition row before any retained witness fact changes.
    async fn persist_phase2_succeeded_lease(
        &self,
        operation_id: MaintenanceImportOperationId,
        expected_stage: MaintenanceImportStage,
        previous: &WitnessRecord,
        basis: Option<&WitnessRecord>,
        succeeded: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn persist_manual_required(
        &self,
        operation_id: MaintenanceImportOperationId,
        expected_stage: MaintenanceImportStage,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn abort_pre_owner(
        &self,
        operation_id: MaintenanceImportOperationId,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn persist_candidate_before_send(
        &self,
        operation_id: MaintenanceImportOperationId,
        from: MaintenanceImportStage,
        candidate: PreparedMaintenanceMigration,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn persist_send_unknown(
        &self,
        operation_id: MaintenanceImportOperationId,
        from: MaintenanceImportStage,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn reconcile_exact_witness(
        &self,
        operation_id: MaintenanceImportOperationId,
        expected_stage: MaintenanceImportStage,
        observed: &WitnessRecord,
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;

    async fn persist_parity_verified(
        &self,
        operation_id: MaintenanceImportOperationId,
        source: MaintenanceSourceBinding,
        exact_shadow_witness: &WitnessRecord,
        parity_commitment: [u8; 32],
    ) -> Result<MaintenanceImportRecord, MaintenanceImportError>;
}

/// Inert runtime-owned importer. Construction and fields are private; the
/// sealed runtime is its only producer and no method is reachable from main.
pub(crate) struct SingleArchiveMaintenanceImporter {
    archive_id: ArchiveId,
    archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
    runtime_token: crate::archive_v3_shadow_runtime::MaintenanceRuntimeContext,
    control: Arc<crate::cp::control_store::ControlStore>,
    store: Arc<crate::store::Store>,
    plan: AuthenticatedMaintenanceImportPlan,
    /// `Some` only for the acquisition-gated Phase-2 door. When set, the
    /// advisory release-absence predicate is replaced by presence-and-exact-
    /// match of the durable acquisition row, `run_phase2` is the only
    /// permitted entry, and the advisory target is unreachable.
    phase2_acquisition: Option<Phase2AcquiredAuthorityPlan>,
}

/// Type-separated Phase-1 owner. It can stop only at independently verified
/// ShadowWal and has no method that can request the WalAuthoritative
/// transition.
pub(crate) struct SingleArchiveAdvisoryShadowImporter {
    inner: SingleArchiveMaintenanceImporter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaintenanceImportTarget {
    AdvisoryShadow,
    WalAuthoritative,
}

enum CompletedMaintenanceImport {
    Advisory(Box<CompletedAdvisoryShadowHandoff>),
    WalAuthoritative(Box<CompletedMaintenanceWalHandoff>),
}

impl SingleArchiveMaintenanceImporter {
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated maintenance tuple; grouping would obscure exact binding"
    )]
    pub(crate) fn from_sealed_runtime(
        token: crate::archive_v3_shadow_runtime::MaintenanceRuntimeContext,
        archive_id: ArchiveId,
        archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
        runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
        control: Arc<crate::cp::control_store::ControlStore>,
        store: Arc<crate::store::Store>,
        plan: AuthenticatedMaintenanceImportPlan,
    ) -> Result<Self, MaintenanceImportError> {
        if plan.archive_id != archive_id || runtime.maintenance_witness(&token).is_none() {
            return Err(MaintenanceImportError::Conflict);
        }
        Ok(Self {
            archive_id,
            archive_binding,
            runtime,
            runtime_token: token,
            control,
            store,
            plan,
            phase2_acquisition: None,
        })
    }

    /// Acquisition-gated Phase-2 constructor. The importer runs with the
    /// ORIGINAL maintenance plan identity (same operation, witness-lease
    /// owner, and attempt continue R2), but every advisory release-absence
    /// gate is replaced by presence-and-exact-match of the sealed acquisition,
    /// which must bind the exact same user, archive, and operation. The
    /// acquisition's advisory owner identity is a different namespace than
    /// the plan's witness-lease owner, so owner binding is enforced through
    /// the acquisition row commitment at the gate rather than here.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit authenticated maintenance tuple; grouping would obscure exact binding"
    )]
    pub(crate) fn from_sealed_runtime_with_phase2(
        token: crate::archive_v3_shadow_runtime::MaintenanceRuntimeContext,
        archive_id: ArchiveId,
        archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
        runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
        control: Arc<crate::cp::control_store::ControlStore>,
        store: Arc<crate::store::Store>,
        plan: AuthenticatedMaintenanceImportPlan,
        acquisition: Phase2AcquiredAuthorityPlan,
    ) -> Result<Self, MaintenanceImportError> {
        if acquisition.user_id != plan.user_id
            || acquisition.archive_id != plan.archive_id
            || acquisition.operation_id.as_bytes() != plan.operation_id.as_bytes()
        {
            return Err(MaintenanceImportError::Conflict);
        }
        let mut importer = Self::from_sealed_runtime(
            token,
            archive_id,
            archive_binding,
            runtime,
            control,
            store,
            plan,
        )?;
        importer.phase2_acquisition = Some(acquisition);
        Ok(importer)
    }

    #[cfg(test)]
    pub(crate) fn from_test_components<W>(
        archive_id: ArchiveId,
        objects: Arc<dyn ImmutableObjectBackend>,
        registries: Arc<dyn ExactKeyRegistryProvider>,
        witness: Arc<W>,
        control: Arc<crate::cp::control_store::ControlStore>,
        store: Arc<crate::store::Store>,
        plan: AuthenticatedMaintenanceImportPlan,
    ) -> Result<Self, MaintenanceImportError>
    where
        W: MaintenanceImportWitnessProvider
            + crate::archive_v3_advisory_owner::AdvisoryOwnerWitnessProvider
            + 'static,
    {
        if plan.archive_id != archive_id {
            return Err(MaintenanceImportError::Conflict);
        }
        let runtime =
            crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle::from_maintenance_test_components(
                objects,
                registries,
                witness,
            );
        Ok(Self {
            archive_id,
            archive_binding:
                crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding::from_control_store(
                    crate::cp::control_store::ArchiveBinding::for_runtime_test(archive_id),
                ),
            runtime,
            runtime_token: crate::archive_v3_shadow_runtime::MaintenanceRuntimeContext::for_test(),
            control,
            store,
            plan,
            phase2_acquisition: None,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_test_components_with_phase2<W>(
        archive_id: ArchiveId,
        objects: Arc<dyn ImmutableObjectBackend>,
        registries: Arc<dyn ExactKeyRegistryProvider>,
        witness: Arc<W>,
        control: Arc<crate::cp::control_store::ControlStore>,
        store: Arc<crate::store::Store>,
        plan: AuthenticatedMaintenanceImportPlan,
        acquisition: Phase2AcquiredAuthorityPlan,
    ) -> Result<Self, MaintenanceImportError>
    where
        W: MaintenanceImportWitnessProvider
            + crate::archive_v3_advisory_owner::AdvisoryOwnerWitnessProvider
            + 'static,
    {
        if acquisition.user_id != plan.user_id
            || acquisition.archive_id != plan.archive_id
            || acquisition.operation_id.as_bytes() != plan.operation_id.as_bytes()
        {
            return Err(MaintenanceImportError::Conflict);
        }
        let mut importer = Self::from_test_components(
            archive_id, objects, registries, witness, control, store, plan,
        )?;
        importer.phase2_acquisition = Some(acquisition);
        Ok(importer)
    }

    /// Abort a pre-owner maintenance import operation: validates Store state,
    /// reconciles GCS provider marker deletion to fresh NotFound, durably transitions
    /// Control maintenance import stage to ManualRequired, and restores Store legacy gates.
    pub(crate) async fn abort_pre_owner(
        store: &Arc<crate::store::Store>,
        control: &Arc<crate::cp::control_store::ControlStore>,
        user_id: &str,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        fence_authority: &str,
    ) -> Result<(), MaintenanceImportError> {
        let admission = store
            .preflight_pre_owner_advisory_abort(
                MaintenanceCoordinatorContext(()),
                user_id,
                archive_id,
                operation_id,
                fence_authority,
            )
            .await
            .map_err(|_| MaintenanceImportError::Conflict)?;
        control.abort_pre_owner(operation_id).await?;
        let restored = store
            .restore_pre_owner_advisory_local_admission(
                MaintenanceCoordinatorContext(()),
                admission,
            )
            .await
            .map_err(|_| MaintenanceImportError::Conflict)?;
        let _ = restored
            .authenticate(MaintenanceCoordinatorContext(()), archive_id, operation_id)
            .map_err(|_| MaintenanceImportError::Conflict)?;
        Ok(())
    }

    /// Run the complete offline import in one owned task. Dropping the caller
    /// does not detach a witness send or plaintext scratch owner; the task
    /// retains both until a durable stage or cleanup. This advisory-fenced
    /// door refuses a Phase-2-constructed importer so the two doors never mix.
    pub(crate) async fn run(
        self,
    ) -> Result<CompletedMaintenanceWalHandoff, MaintenanceImportError> {
        if self.phase2_acquisition.is_some() {
            return Err(MaintenanceImportError::Conflict);
        }
        let completed =
            tokio::spawn(self.run_owned(MaintenanceImportTarget::WalAuthoritative, None))
                .await
                .map_err(|_| MaintenanceImportError::Unavailable)??;
        match completed {
            CompletedMaintenanceImport::WalAuthoritative(handoff) => Ok(*handoff),
            CompletedMaintenanceImport::Advisory(_) => Err(MaintenanceImportError::Corrupt),
        }
    }

    /// Acquisition-gated Phase-2 door. It mirrors [`Self::run`] exactly —
    /// same owned task, same `WalAuthoritative` target, same predicates —
    /// except that inside `run_owned` the two advisory release-absence gates
    /// are replaced by presence-and-exact-match of the durable Phase-2
    /// acquisition row (pre-lock and in-lock). It is the only entry permitted
    /// for a Phase-2-constructed importer and refuses every other importer.
    pub(crate) async fn run_phase2(
        self,
    ) -> Result<CompletedMaintenanceWalHandoff, MaintenanceImportError> {
        if self.phase2_acquisition.is_none() {
            return Err(MaintenanceImportError::Conflict);
        }
        let completed =
            tokio::spawn(self.run_owned(MaintenanceImportTarget::WalAuthoritative, None))
                .await
                .map_err(|_| MaintenanceImportError::Unavailable)??;
        match completed {
            CompletedMaintenanceImport::WalAuthoritative(handoff) => Ok(*handoff),
            CompletedMaintenanceImport::Advisory(_) => Err(MaintenanceImportError::Corrupt),
        }
    }

    async fn run_owned(
        self,
        target: MaintenanceImportTarget,
        existing_admission: Option<crate::store::ArchiveMaintenanceAdmission>,
    ) -> Result<CompletedMaintenanceImport, MaintenanceImportError> {
        let Self {
            archive_id,
            archive_binding,
            runtime,
            runtime_token,
            control,
            store,
            plan,
            phase2_acquisition,
        } = self;
        let objects = runtime.maintenance_objects_owned(&runtime_token);
        let registries = runtime.maintenance_registries(&runtime_token);
        let witness = Arc::clone(
            runtime
                .maintenance_witness(&runtime_token)
                .ok_or(MaintenanceImportError::Unavailable)?,
        );
        let persistence: Arc<dyn MaintenanceImportPersistence> = control.clone();
        let operation_id = plan.operation_id;
        let owner_id = plan.owner_id;
        let request_fingerprint = plan.operation_commitment;
        let session_id = ShadowSessionId::for_operation(*operation_id.as_bytes())
            .map_err(|_| MaintenanceImportError::Corrupt)?;
        let mut record = persistence.load_exact(operation_id).await?;
        // Under a Phase-2 acquisition, presence-and-exact-match of the durable
        // acquisition row replaces the advisory release-absence predicate at
        // BOTH gate sites; every other predicate is unchanged. A Phase-2
        // importer can only ever drive the WalAuthoritative target.
        match &phase2_acquisition {
            Some(acquisition) => {
                if target != MaintenanceImportTarget::WalAuthoritative {
                    return Err(MaintenanceImportError::Conflict);
                }
                ensure_phase2_acquisition_intact(control.as_ref(), acquisition).await?;
            }
            None => {
                persistence
                    .ensure_advisory_release_absent(operation_id)
                    .await?;
            }
        }
        if record.stage == MaintenanceImportStage::ManualRequired {
            return Err(MaintenanceImportError::Conflict);
        }
        if target == MaintenanceImportTarget::AdvisoryShadow
            && matches!(
                record.stage,
                MaintenanceImportStage::AuthoritativeUploading
                    | MaintenanceImportStage::AuthoritativeSendUnknown
                    | MaintenanceImportStage::WalAuthoritative
            )
        {
            return Err(MaintenanceImportError::Conflict);
        }

        let admission = match existing_admission {
            Some(admission) => admission,
            None => store
                .acquire_archive_maintenance_admission(MaintenanceCoordinatorContext(()), plan)
                .await
                .map_err(|_| MaintenanceImportError::Unavailable)?,
        };
        // Pair this final Control check with Store's per-user lifecycle lock,
        // before either local admission gate is changed. The inactive release
        // executor takes the same lock before preparing its durable row and
        // keeps it through local resume, so a stale waiter cannot recreate the
        // marker or leave Store reblocked after terminal release. Under a
        // Phase-2 acquisition the same in-lock slot re-reads and byte-compares
        // the durable acquisition row instead.
        match &phase2_acquisition {
            Some(_acquisition) => {}
            None => {
                persistence
                    .ensure_advisory_release_absent(operation_id)
                    .await?;
            }
        }
        let mut transition = admission.begin().await;
        let pinned = if matches!(
            record.stage,
            MaintenanceImportStage::Prepared | MaintenanceImportStage::Fencing
        ) {
            let observed = transition
                .tentative_source()
                .await
                .map_err(|_| MaintenanceImportError::Unavailable)?;
            let mut tentative = if record.stage == MaintenanceImportStage::Prepared {
                record = persistence.persist_fencing(operation_id, observed).await?;
                observed
            } else {
                let durable = record.tentative.ok_or(MaintenanceImportError::Corrupt)?;
                if observed != durable {
                    record = persistence
                        .persist_fencing_rebase(operation_id, durable, observed)
                        .await?;
                    observed
                } else {
                    durable
                }
            };
            if record.stage != MaintenanceImportStage::Fencing {
                return Err(MaintenanceImportError::Conflict);
            }
            let pinned = loop {
                match transition
                    .fence_and_pin(tentative)
                    .await
                    .map_err(|_| MaintenanceImportError::Conflict)?
                {
                    crate::store::MaintenanceFenceAndPin::Pinned(pinned) => break pinned,
                    crate::store::MaintenanceFenceAndPin::Rebase {
                        transition: retained,
                        source,
                    } => {
                        persistence
                            .persist_fencing_rebase(operation_id, tentative, source)
                            .await?;
                        tentative = source;
                        transition = retained;
                    }
                }
            };
            record = persistence
                .persist_pinned_source(operation_id, pinned.source_binding())
                .await?;
            pinned
        } else {
            let source = record.source().ok_or(MaintenanceImportError::Corrupt)?;
            transition
                .recover_pinned(source)
                .await
                .map_err(|_| MaintenanceImportError::Conflict)?
        };

        let source = pinned.source_binding();
        let mut current = match record.stage {
            MaintenanceImportStage::LegacyPinned => {
                let current = witness
                    .read_current_exact(archive_id)
                    .await
                    .map_err(|_| MaintenanceImportError::Unavailable)?;
                require_active_migration(&current, archive_id, MigrationState::Legacy)?;
                let cipher = resolve_witness_cipher(&current, archive_id, registries).await?;
                authenticate_current_root(objects.as_ref(), cipher.as_ref(), &current).await?;
                let lease = witness
                    .acquire_lease_exact(&current, owner_id, MAINTENANCE_LEASE_TICKS)
                    .await
                    .map_err(|_| MaintenanceImportError::Unavailable)?;
                let leased = witness
                    .read_current_exact(archive_id)
                    .await
                    .map_err(|_| MaintenanceImportError::Unavailable)?;
                require_active_migration(&leased, archive_id, MigrationState::Legacy)?;
                if !leased.authorizes_lease(lease) {
                    return Err(MaintenanceImportError::Conflict);
                }
                record = persistence
                    .persist_witness_and_lease(operation_id, source, &leased, lease)
                    .await?;
                leased
            }
            _ => record
                .witnessed_record()?
                .ok_or(MaintenanceImportError::Corrupt)?,
        };

        if record.stage == MaintenanceImportStage::ShadowUploading
            && record.shadow_candidate_record()?.is_none()
        {
            let observed = witness
                .read_current_exact(archive_id)
                .await
                .map_err(|_| MaintenanceImportError::Unavailable)?;
            require_active_migration(&observed, archive_id, MigrationState::Legacy)?;
            let (renewed, renewed_record) = renew_exact_maintenance_lease(
                witness.as_ref(),
                persistence.as_ref(),
                operation_id,
                MaintenanceImportStage::ShadowUploading,
                owner_id,
                current,
                observed,
            )
            .await?;
            current = renewed;
            record = renewed_record;
            let cipher = resolve_witness_cipher(&current, archive_id, registries).await?;
            authenticate_current_root(objects.as_ref(), cipher.as_ref(), &current).await?;
            let lease = current
                .exact_active_lease_for_owner(owner_id)
                .map_err(|_| MaintenanceImportError::Conflict)?;
            let binding = ShadowSessionBinding::from_maintenance_witness(
                MaintenanceZeroWalBindingContext(()),
                &current,
                lease,
                *operation_id.as_bytes(),
                request_fingerprint,
                0,
                0,
                0,
            )
            .map_err(|_| MaintenanceImportError::Corrupt)?;
            let recovery_staging = ShadowObjectStaging::from_maintenance_attempt(
                MaintenanceStagingContext(()),
                persistence.as_shadow_inventory(),
                session_id,
                record.attempt_id(),
                binding,
                record.next_artifact_ordinal(),
            )
            .map_err(|_| MaintenanceImportError::Corrupt)?;
            reconcile_reserved_shadow_objects(objects.as_ref(), &recovery_staging)
                .await
                .map_err(|_| MaintenanceImportError::Unavailable)?;
            record = persistence
                .prepare_shadow_upload_attempt(operation_id)
                .await?;
            let staging = ShadowObjectStaging::from_maintenance_attempt(
                MaintenanceStagingContext(()),
                persistence.as_shadow_inventory(),
                session_id,
                record.attempt_id(),
                binding,
                record.next_artifact_ordinal(),
            )
            .map_err(|_| MaintenanceImportError::Corrupt)?;
            let mut checkpoint_source = MaintenanceCheckpointSource::from_pinned(&pinned)
                .map_err(|_| MaintenanceImportError::Corrupt)?;
            let checkpoint = upload_checkpoint(
                objects.as_ref(),
                cipher.as_ref(),
                archive_id,
                current.database_epoch(),
                &mut checkpoint_source,
                staging.clone(),
            )
            .await
            .map_err(|_| MaintenanceImportError::Unavailable)?;
            validate_checkpoint_source(&checkpoint, source)?;
            let advance = build_zero_wal_candidate(
                objects.as_ref(),
                cipher.as_ref(),
                &current,
                lease,
                &checkpoint,
                &staging,
            )
            .await?;
            let prepared = PreparedMaintenanceMigration::from_authenticated_advance(
                &current,
                &advance,
                MigrationState::ShadowWal,
            )?;
            record = persistence
                .persist_candidate_before_send(
                    operation_id,
                    MaintenanceImportStage::ShadowUploading,
                    prepared,
                )
                .await?;
        }
        if record.stage == MaintenanceImportStage::ShadowUploading {
            record = persistence
                .persist_send_unknown(operation_id, MaintenanceImportStage::ShadowUploading)
                .await?;
        }
        if record.stage == MaintenanceImportStage::ShadowSendUnknown {
            record = resume_retained_send(
                Arc::clone(&witness),
                Arc::clone(&persistence),
                operation_id,
                record,
                owner_id,
                MigrationState::ShadowWal,
                MaintenanceImportStage::ShadowSendUnknown,
                archive_id,
            )
            .await?;
        }
        if record.stage == MaintenanceImportStage::AuthoritativeUploading {
            record = persistence
                .persist_send_unknown(operation_id, MaintenanceImportStage::AuthoritativeUploading)
                .await?;
        }
        if record.stage == MaintenanceImportStage::AuthoritativeSendUnknown {
            record = resume_retained_send(
                Arc::clone(&witness),
                Arc::clone(&persistence),
                operation_id,
                record,
                owner_id,
                MigrationState::WalAuthoritative,
                MaintenanceImportStage::AuthoritativeSendUnknown,
                archive_id,
            )
            .await?;
        }
        if target == MaintenanceImportTarget::AdvisoryShadow
            && record.stage == MaintenanceImportStage::ParityVerified
        {
            return finish_advisory_import(
                &record,
                persistence.as_ref(),
                witness.as_ref(),
                owner_id,
                archive_id,
                source,
                pinned,
                runtime,
                archive_binding,
                control,
            )
            .await
            .map(|handoff| CompletedMaintenanceImport::Advisory(Box::new(handoff)));
        }
        if record.stage == MaintenanceImportStage::WalAuthoritative {
            return finish_offline_import(
                &record,
                persistence.as_ref(),
                witness.as_ref(),
                owner_id,
                archive_id,
                source,
                pinned,
                runtime,
                archive_binding,
                control,
            )
            .await
            .map(|handoff| CompletedMaintenanceImport::WalAuthoritative(Box::new(handoff)));
        }

        current = witness
            .read_current_exact(archive_id)
            .await
            .map_err(|_| MaintenanceImportError::Unavailable)?;
        require_active_migration(&current, archive_id, MigrationState::ShadowWal)?;
        if !matches!(
            record.stage,
            MaintenanceImportStage::ShadowWal | MaintenanceImportStage::ParityVerified
        ) {
            return Err(MaintenanceImportError::Corrupt);
        }
        let durable_witness = record
            .witnessed_record()?
            .ok_or(MaintenanceImportError::Corrupt)?;
        // Under a Phase-2 acquisition the durable maintenance lease lineage
        // resumes only through the succession from the settled advisory
        // terminal; the plain renewal/reacquire ladder cannot apply across
        // the advisory owner's era and is never consulted here.
        let (renewed, renewed_record) = match &phase2_acquisition {
            Some(_) => {
                succeed_phase2_maintenance_lease(
                    witness.as_ref(),
                    persistence.as_ref(),
                    operation_id,
                    record.stage,
                    owner_id,
                    durable_witness,
                    current,
                )
                .await?
            }
            None => {
                renew_exact_maintenance_lease(
                    witness.as_ref(),
                    persistence.as_ref(),
                    operation_id,
                    record.stage,
                    owner_id,
                    durable_witness,
                    current,
                )
                .await?
            }
        };
        current = renewed;
        record = renewed_record;
        let cipher = resolve_witness_cipher(&current, archive_id, registries).await?;
        let recovery = RecoveryRoot::from_exact_active_record(&current)
            .map_err(|_| MaintenanceImportError::Corrupt)?;
        let recovered = recover_owned_maintenance_staging(
            recovery,
            Arc::clone(&objects),
            Arc::clone(&cipher),
            archive_id,
        )
        .await
        .map_err(|_| MaintenanceImportError::Corrupt)?;
        validate_checkpoint_source(recovered.checkpoint(), source)?;
        let checkpoint = recovered.checkpoint().clone();

        if record.stage == MaintenanceImportStage::ShadowWal {
            let (primary, shadow) = prepare_full_parity(&pinned, &recovered)?;
            let parity_digest = verify_full_parity(primary, shadow).await?;
            pinned
                .exact_generation_revalidation()
                .verify()
                .await
                .map_err(|_| MaintenanceImportError::Conflict)?;
            let fresh = witness
                .read_current_exact(archive_id)
                .await
                .map_err(|_| MaintenanceImportError::Unavailable)?;
            if fresh != current {
                return Err(MaintenanceImportError::Conflict);
            }
            let parity = maintenance_parity_commitment(source, parity_digest)?;
            record = persistence
                .persist_parity_verified(operation_id, source, &fresh, parity)
                .await?;
        }

        if record.stage != MaintenanceImportStage::ParityVerified {
            return Err(MaintenanceImportError::Corrupt);
        }
        if target == MaintenanceImportTarget::AdvisoryShadow {
            return finish_advisory_import(
                &record,
                persistence.as_ref(),
                witness.as_ref(),
                owner_id,
                archive_id,
                source,
                pinned,
                runtime,
                archive_binding,
                control,
            )
            .await
            .map(|handoff| CompletedMaintenanceImport::Advisory(Box::new(handoff)));
        }
        let renewed = witness
            .read_current_exact(archive_id)
            .await
            .map_err(|_| MaintenanceImportError::Unavailable)?;
        let durable_witness = record
            .witnessed_record()?
            .ok_or(MaintenanceImportError::Corrupt)?;
        let (current, renewed_record) = renew_exact_maintenance_lease(
            witness.as_ref(),
            persistence.as_ref(),
            operation_id,
            MaintenanceImportStage::ParityVerified,
            owner_id,
            durable_witness,
            renewed,
        )
        .await?;
        if renewed_record.stage() != MaintenanceImportStage::ParityVerified {
            return Err(MaintenanceImportError::Corrupt);
        }
        require_active_migration(&current, archive_id, MigrationState::ShadowWal)?;
        let lease = current
            .exact_active_lease_for_owner(owner_id)
            .map_err(|_| MaintenanceImportError::Conflict)?;
        let authoritative_binding = ShadowSessionBinding::from_maintenance_witness(
            MaintenanceZeroWalBindingContext(()),
            &current,
            lease,
            *operation_id.as_bytes(),
            request_fingerprint,
            0,
            0,
            0,
        )
        .map_err(|_| MaintenanceImportError::Corrupt)?;
        record = persistence
            .prepare_authoritative_upload_attempt(operation_id)
            .await?;
        let recovery_staging = ShadowObjectStaging::from_maintenance_attempt(
            MaintenanceStagingContext(()),
            persistence.as_shadow_inventory(),
            session_id,
            record.attempt_id(),
            authoritative_binding,
            record.next_artifact_ordinal(),
        )
        .map_err(|_| MaintenanceImportError::Corrupt)?;
        reconcile_reserved_shadow_objects(objects.as_ref(), &recovery_staging)
            .await
            .map_err(|_| MaintenanceImportError::Unavailable)?;
        let authoritative_staging = ShadowObjectStaging::from_maintenance_attempt(
            MaintenanceStagingContext(()),
            persistence.as_shadow_inventory(),
            session_id,
            record.attempt_id(),
            authoritative_binding,
            record.next_artifact_ordinal(),
        )
        .map_err(|_| MaintenanceImportError::Corrupt)?;
        let advance = build_zero_wal_candidate(
            objects.as_ref(),
            cipher.as_ref(),
            &current,
            lease,
            &checkpoint,
            &authoritative_staging,
        )
        .await?;
        let prepared = PreparedMaintenanceMigration::from_authenticated_advance(
            &current,
            &advance,
            MigrationState::WalAuthoritative,
        )?;
        persistence
            .persist_candidate_before_send(
                operation_id,
                MaintenanceImportStage::ParityVerified,
                prepared,
            )
            .await?;
        record = persistence
            .persist_send_unknown(operation_id, MaintenanceImportStage::AuthoritativeUploading)
            .await?;
        record = resume_retained_send(
            Arc::clone(&witness),
            Arc::clone(&persistence),
            operation_id,
            record,
            owner_id,
            MigrationState::WalAuthoritative,
            MaintenanceImportStage::AuthoritativeSendUnknown,
            archive_id,
        )
        .await?;
        if record.stage != MaintenanceImportStage::WalAuthoritative {
            return Err(MaintenanceImportError::OutcomeUnknown);
        }
        finish_offline_import(
            &record,
            persistence.as_ref(),
            witness.as_ref(),
            owner_id,
            archive_id,
            source,
            pinned,
            runtime,
            archive_binding,
            control,
        )
        .await
        .map(|handoff| CompletedMaintenanceImport::WalAuthoritative(Box::new(handoff)))
    }
}

/// Phase-2 replacement for the advisory release-absence predicate: the
/// durable acquisition row must exist, byte-match the sealed acquisition
/// (commitment equality covers every acquisition field), and rest at
/// `Phase2Acquired`. Anything else — absence, a different mint, or a
/// `ManualRequired` fence — fails closed.
async fn ensure_phase2_acquisition_intact(
    control: &crate::cp::control_store::ControlStore,
    acquisition: &Phase2AcquiredAuthorityPlan,
) -> Result<(), MaintenanceImportError> {
    let retained = control
        .load_phase2_authority_acquisition(acquisition.archive_id)
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?
        .ok_or(MaintenanceImportError::Conflict)?;
    if retained.commitment() != acquisition.acquisition_commitment
        || retained.stage() != crate::cp::control_store::Phase2AcquisitionStage::Phase2Acquired
        || retained.archive_id() != acquisition.archive_id
        || retained.maintenance_operation_id().as_bytes() != acquisition.operation_id.as_bytes()
        || retained.acquisition_fence_authority() != acquisition.acquisition_fence_authority
    {
        return Err(MaintenanceImportError::Conflict);
    }
    Ok(())
}

impl SingleArchiveAdvisoryShadowImporter {
    pub(crate) fn from_maintenance_importer(inner: SingleArchiveMaintenanceImporter) -> Self {
        Self { inner }
    }

    pub(crate) fn plan(&self) -> &AuthenticatedMaintenanceImportPlan {
        &self.inner.plan
    }

    pub(crate) fn fence_authority(&self) -> &str {
        &self.inner.plan.fence_authority
    }

    /// Observe the tentative source database size under the user lifecycle lock
    /// and return a consuming preflight token retaining the exact admission lock.
    pub(crate) async fn preflight(
        self,
    ) -> Result<(u64, SingleArchivePreflightedShadowImporter), MaintenanceImportError> {
        let admission = self
            .inner
            .store
            .acquire_archive_maintenance_admission(
                MaintenanceCoordinatorContext(()),
                self.inner.plan.clone(),
            )
            .await
            .map_err(|_| MaintenanceImportError::Unavailable)?;
        let database_bytes = admission
            .observe_source_database_bytes()
            .await
            .map_err(|_| MaintenanceImportError::Unavailable)?;
        Ok((
            database_bytes,
            SingleArchivePreflightedShadowImporter {
                inner: self.inner,
                admission,
                database_bytes,
            },
        ))
    }

    /// Run through the complete Phase-1 advisory shadow importer flow.
    pub(crate) async fn run(
        self,
    ) -> Result<CompletedAdvisoryShadowHandoff, MaintenanceImportError> {
        let (_bytes, preflighted) = self.preflight().await?;
        preflighted.run().await
    }
}

/// Non-cloneable consuming preflight token retaining the exact lifecycle/actor lock
/// and measured database geometry. It transfers the held admission directly into the
/// importer task without dropping or reacquiring the guard.
pub(crate) struct SingleArchivePreflightedShadowImporter {
    inner: SingleArchiveMaintenanceImporter,
    admission: crate::store::ArchiveMaintenanceAdmission,
    database_bytes: u64,
}

impl SingleArchivePreflightedShadowImporter {
    pub(crate) fn database_bytes(&self) -> u64 {
        self.database_bytes
    }

    pub(crate) fn plan(&self) -> &AuthenticatedMaintenanceImportPlan {
        &self.inner.plan
    }

    pub(crate) fn fence_authority(&self) -> &str {
        &self.inner.plan.fence_authority
    }

    /// Run only through the Phase-1 advisory terminal using the continuously retained
    /// preflight admission.
    pub(crate) async fn run(
        self,
    ) -> Result<CompletedAdvisoryShadowHandoff, MaintenanceImportError> {
        let Self {
            inner,
            admission,
            database_bytes: _,
        } = self;
        let completed =
            tokio::spawn(inner.run_owned(MaintenanceImportTarget::AdvisoryShadow, Some(admission)))
                .await
                .map_err(|_| MaintenanceImportError::Unavailable)??;
        match completed {
            CompletedMaintenanceImport::Advisory(handoff) => Ok(*handoff),
            CompletedMaintenanceImport::WalAuthoritative(_) => Err(MaintenanceImportError::Corrupt),
        }
    }

    /// Abort the pre-owner import: drops the retained admission guard and executes
    /// the authenticated store and control pre-owner abort with the authentic fence authority.
    pub(crate) async fn abort_pre_owner(self) -> Result<(), MaintenanceImportError> {
        let fence_auth = self.inner.plan.fence_authority.clone();
        let archive_id = self.inner.plan.archive_id;
        let operation_id = self.inner.plan.operation_id;
        let admission = self
            .admission
            .into_pre_owner_abort_admission(&fence_auth)
            .await
            .map_err(|_| MaintenanceImportError::Conflict)?;
        self.inner.control.abort_pre_owner(operation_id).await?;
        let restored = self
            .inner
            .store
            .restore_pre_owner_advisory_local_admission(
                MaintenanceCoordinatorContext(()),
                admission,
            )
            .await
            .map_err(|_| MaintenanceImportError::Conflict)?;
        let _ = restored
            .authenticate(MaintenanceCoordinatorContext(()), archive_id, operation_id)
            .map_err(|_| MaintenanceImportError::Conflict)?;
        Ok(())
    }
}

/// Non-cloneable Phase-1 terminal handoff. It proves the exact legacy source
/// and independently recovered ShadowWal root matched before the maintenance
/// lease was released. It carries no Store fence, serving policy,
/// acknowledgement, route, or WalAuthoritative conversion.
pub(crate) struct CompletedAdvisoryShadowHandoff {
    _runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
    _terminal_witness: WitnessRecord,
    _archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    _parity: CompletedAdvisoryShadowParityEvidence,
    _control: Arc<crate::cp::control_store::ControlStore>,
    _store_capture_target: crate::store::StoreAdvisoryCaptureTarget,
}

impl CompletedAdvisoryShadowHandoff {
    #[allow(dead_code)]
    pub(crate) fn test_terminal_witness(&self) -> &WitnessRecord {
        &self._terminal_witness
    }

    #[allow(dead_code)]
    pub(crate) fn measured_database_bytes(&self) -> u64 {
        self._parity
            .terminal_control
            .source
            .as_ref()
            .map(|s| s.plaintext_len)
            .unwrap_or(0)
    }
}

/// Consuming Phase-1 view obtainable only with the advisory-owner module's
/// private runtime token. It never contains a Store fence or authority
/// conversion.
pub(crate) struct CompletedAdvisoryShadowHandoffView {
    pub(crate) runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
    pub(crate) terminal_witness: WitnessRecord,
    pub(crate) archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    pub(crate) parity: CompletedAdvisoryShadowParityEvidence,
    pub(crate) control: Arc<crate::cp::control_store::ControlStore>,
    pub(crate) store_capture_target: crate::store::StoreAdvisoryCaptureTarget,
}

/// Opaque proof retained only by the advisory handoff. The future live
/// shadow owner must re-read this exact Control row and witness before it can
/// obtain any capture or publication capability.
pub(crate) struct CompletedAdvisoryShadowParityEvidence {
    terminal_control: MaintenanceImportRecord,
}

impl CompletedAdvisoryShadowParityEvidence {
    fn from_terminal(
        terminal_control: MaintenanceImportRecord,
        source: MaintenanceSourceBinding,
        terminal_witness: &WitnessRecord,
    ) -> Result<Self, MaintenanceImportError> {
        validate_advisory_parity_evidence(&terminal_control, source, terminal_witness)?;
        Ok(Self { terminal_control })
    }

    pub(crate) const fn operation_id_for_advisory_owner(
        &self,
        _token: crate::archive_v3_advisory_owner::AdvisoryOwnerRuntimeContext,
    ) -> MaintenanceImportOperationId {
        self.terminal_control.operation_id
    }

    pub(crate) fn reauthenticate_for_advisory_owner(
        &self,
        _token: crate::archive_v3_advisory_owner::AdvisoryOwnerRuntimeContext,
        observed: &MaintenanceImportRecord,
        terminal_witness: &WitnessRecord,
    ) -> Result<(), MaintenanceImportError> {
        if observed != &self.terminal_control {
            return Err(MaintenanceImportError::Conflict);
        }
        validate_advisory_parity_evidence(
            &self.terminal_control,
            self.terminal_control
                .source()
                .ok_or(MaintenanceImportError::Corrupt)?,
            terminal_witness,
        )
    }
}

impl CompletedAdvisoryShadowHandoff {
    pub(crate) fn into_advisory_owner(
        self,
        _token: crate::archive_v3_advisory_owner::AdvisoryOwnerRuntimeContext,
    ) -> CompletedAdvisoryShadowHandoffView {
        CompletedAdvisoryShadowHandoffView {
            runtime: self._runtime,
            terminal_witness: self._terminal_witness,
            archive_binding: self._archive_binding,
            parity: self._parity,
            control: self._control,
            store_capture_target: self._store_capture_target,
        }
    }
}

impl fmt::Debug for CompletedAdvisoryShadowHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletedAdvisoryShadowHandoff(<advisory>)")
    }
}

impl fmt::Debug for CompletedAdvisoryShadowParityEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletedAdvisoryShadowParityEvidence(<opaque>)")
    }
}

/// Non-cloneable offline handoff. Each value exposes one consuming view and
/// retains the complete sealed provider owner, exact terminal witness,
/// encrypted Control handle, and Store's long-lived admission fence. Terminal
/// restart may mint another value; durable global owner serialization belongs
/// to the WAL worker. There are no field getters; only the WAL-owner module can
/// obtain the view by presenting its private Store-owner token.
pub(crate) struct CompletedMaintenanceWalHandoff {
    runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
    terminal_witness: WitnessRecord,
    archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    parity: CompletedMaintenanceParityEvidence,
    control: Arc<crate::cp::control_store::ControlStore>,
    store_fence: Option<crate::store::StoreWalAuthorityFence>,
}

pub(crate) struct CompletedMaintenanceWalHandoffView {
    pub(crate) runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
    pub(crate) terminal_witness: WitnessRecord,
    pub(crate) archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    pub(crate) parity: CompletedMaintenanceParityEvidence,
    pub(crate) control: Arc<crate::cp::control_store::ControlStore>,
    pub(crate) store_fence: Option<crate::store::StoreWalAuthorityFence>,
}

/// Non-cloneable proof that the offline maintenance transition reached its
/// exact terminal Control row only after full independent legacy/shadow
/// parity. The WAL launcher can re-read and authenticate that exact row, but
/// cannot mint or detach the parity commitment.
pub(crate) struct CompletedMaintenanceParityEvidence {
    terminal_control: MaintenanceImportRecord,
}

impl CompletedMaintenanceParityEvidence {
    fn from_terminal(
        terminal_control: MaintenanceImportRecord,
        source: MaintenanceSourceBinding,
        terminal_witness: &WitnessRecord,
    ) -> Result<Self, MaintenanceImportError> {
        validate_terminal_parity_evidence(&terminal_control, source, terminal_witness)?;
        Ok(Self { terminal_control })
    }

    pub(crate) const fn operation_id_for_wal_owner(
        &self,
        _token: crate::archive_v3_wal_owner::WalOwnerStoreContext,
    ) -> MaintenanceImportOperationId {
        self.terminal_control.operation_id
    }

    pub(crate) fn reauthenticate_for_wal_owner(
        &self,
        _token: crate::archive_v3_wal_owner::WalOwnerStoreContext,
        observed: &MaintenanceImportRecord,
        terminal_witness: &WitnessRecord,
    ) -> Result<(), MaintenanceImportError> {
        if observed != &self.terminal_control {
            return Err(MaintenanceImportError::Conflict);
        }
        let source = self
            .terminal_control
            .source()
            .ok_or(MaintenanceImportError::Corrupt)?;
        validate_terminal_parity_evidence(&self.terminal_control, source, terminal_witness)
    }
}

impl fmt::Debug for CompletedMaintenanceParityEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletedMaintenanceParityEvidence(<opaque>)")
    }
}

impl CompletedMaintenanceWalHandoff {
    /// Reconstruct the WAL-owner handoff from durable state alone, for a
    /// serving process that restarts after the cutover. The exact durable
    /// WalAuthoritative terminal row supplies the retained terminal witness
    /// and re-mints the parity evidence through the same validation the
    /// terminal path used; the publisher then performs its own live-witness
    /// owner reserve/renew/reacquire with lost-response adoption. No Store
    /// fence transfers on restart: the startup-installed per-user selection
    /// carries the fence's guarantees durably, and the legacy generation
    /// stays pinned by the durable row and the permanent provider marker.
    pub(crate) async fn reconstruct_from_durable(
        runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
        archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
        control: Arc<crate::cp::control_store::ControlStore>,
        operation_id: MaintenanceImportOperationId,
    ) -> Result<Self, MaintenanceImportError> {
        let persistence: &dyn MaintenanceImportPersistence = control.as_ref();
        let terminal_control = persistence.load_exact(operation_id).await?;
        if terminal_control.stage() != MaintenanceImportStage::WalAuthoritative {
            return Err(MaintenanceImportError::Conflict);
        }
        let source = terminal_control
            .source()
            .ok_or(MaintenanceImportError::Corrupt)?;
        let retained_terminal = terminal_control
            .witnessed_record()?
            .ok_or(MaintenanceImportError::Corrupt)?;
        // The durable row retains the still-leased terminal; every evidence
        // consumer requires its canonical release successor, exactly as the
        // in-run path passed the provider's released record.
        let terminal_witness = retained_terminal
            .derived_maintenance_terminal_release(terminal_control.owner_id)
            .map_err(|_| MaintenanceImportError::Corrupt)?;
        let parity = CompletedMaintenanceParityEvidence::from_terminal(
            terminal_control,
            source,
            &terminal_witness,
        )?;
        Ok(Self {
            runtime,
            terminal_witness,
            archive_binding,
            parity,
            control,
            store_fence: None,
        })
    }

    pub(crate) fn into_wal_owner(
        self,
        _token: crate::archive_v3_wal_owner::WalOwnerStoreContext,
    ) -> CompletedMaintenanceWalHandoffView {
        CompletedMaintenanceWalHandoffView {
            runtime: self.runtime,
            terminal_witness: self.terminal_witness,
            archive_binding: self.archive_binding,
            parity: self.parity,
            control: self.control,
            store_fence: self.store_fence,
        }
    }
}

impl fmt::Debug for CompletedMaintenanceWalHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletedMaintenanceWalHandoff(<offline>)")
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit authenticated maintenance tuple; grouping would obscure exact binding"
)]
async fn resume_retained_send(
    witness: Arc<dyn MaintenanceImportWitnessProvider>,
    persistence: Arc<dyn MaintenanceImportPersistence>,
    operation_id: MaintenanceImportOperationId,
    retained: MaintenanceImportRecord,
    owner_id: ObjectId,
    migration: MigrationState,
    stage: MaintenanceImportStage,
    archive_id: ArchiveId,
) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
    if retained.stage != stage {
        return Err(MaintenanceImportError::Corrupt);
    }
    let candidate = match migration {
        MigrationState::ShadowWal => retained.shadow_candidate_record()?,
        MigrationState::WalAuthoritative => retained.authoritative_candidate_record()?,
        _ => None,
    }
    .ok_or(MaintenanceImportError::Corrupt)?;
    let expected = retained
        .witnessed_record()?
        .ok_or(MaintenanceImportError::Corrupt)?;
    let observed = witness
        .read_current_exact(archive_id)
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?;
    if observed == candidate {
        return persistence
            .reconcile_exact_witness(operation_id, stage, &observed)
            .await;
    }
    if observed != expected {
        persistence
            .persist_manual_required(operation_id, stage)
            .await?;
        return Err(MaintenanceImportError::Conflict);
    }
    if witness
        .validate_exact_lease(&expected, owner_id)
        .await
        .is_err()
    {
        persistence
            .persist_manual_required(operation_id, stage)
            .await?;
        return Err(MaintenanceImportError::Conflict);
    }
    let advance = match RootAdvance::from_retained_migration_candidate(
        MaintenanceWitnessRecoveryContext(()),
        &observed,
        &candidate,
        owner_id,
        migration,
    ) {
        Ok(advance) => advance,
        Err(_) => {
            persistence
                .persist_manual_required(operation_id, stage)
                .await?;
            return Err(MaintenanceImportError::Conflict);
        }
    };
    let owned_witness = Arc::clone(&witness);
    let send_expected = expected.clone();
    let send_candidate = candidate.clone();
    let outcome = tokio::spawn(async move {
        owned_witness
            .advance_migration_unresolved(send_expected, send_candidate, advance, migration)
            .await
    })
    .await
    .map_err(|_| MaintenanceImportError::OutcomeUnknown)?;
    let observed = witness
        .read_current_exact(archive_id)
        .await
        .map_err(|_| MaintenanceImportError::OutcomeUnknown)?;
    if observed == candidate {
        return persistence
            .reconcile_exact_witness(operation_id, stage, &observed)
            .await;
    }
    if observed != expected {
        persistence
            .persist_manual_required(operation_id, stage)
            .await?;
        return Err(MaintenanceImportError::Conflict);
    }
    match outcome {
        Err(MaintenanceWitnessCommitError::Rejected) => Err(MaintenanceImportError::Conflict),
        Err(MaintenanceWitnessCommitError::DefinitelyFailed) => {
            Err(MaintenanceImportError::Unavailable)
        }
        Err(MaintenanceWitnessCommitError::OutcomeUnknown) | Ok(_) => {
            Err(MaintenanceImportError::OutcomeUnknown)
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit authenticated terminal handoff tuple; grouping would obscure exact binding"
)]
async fn finish_advisory_import(
    expected_durable: &MaintenanceImportRecord,
    persistence: &dyn MaintenanceImportPersistence,
    witness: &dyn MaintenanceImportWitnessProvider,
    owner_id: ObjectId,
    archive_id: ArchiveId,
    source: MaintenanceSourceBinding,
    pinned: crate::store::PinnedLegacySnapshot,
    runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
    archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    control: Arc<crate::cp::control_store::ControlStore>,
) -> Result<CompletedAdvisoryShadowHandoff, MaintenanceImportError> {
    let durable = persistence
        .load_exact(expected_durable.operation_id)
        .await?;
    validate_exact_advisory_control(expected_durable, &durable, source)?;
    let released =
        authenticate_and_release_advisory_witness(&durable, witness, owner_id, archive_id).await?;
    pinned
        .exact_generation_revalidation()
        .verify()
        .await
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let exact_durable = persistence
        .load_exact(expected_durable.operation_id)
        .await?;
    validate_exact_advisory_control(&durable, &exact_durable, source)?;
    let parity =
        CompletedAdvisoryShadowParityEvidence::from_terminal(exact_durable, source, &released)?;
    // The target retains only a private exact Store/user/archive/import
    // binding. Minting it scrubs DB/WAL/SHM and drops the owned maintenance
    // guards; the Store/barrier blocked state and permanent provider fence
    // remain fail-closed. The later inactive release executor can use this
    // target only for its one exact provider marker; it still cannot unblock
    // Store or install capture. Unlike the authoritative handoff, Phase 1
    // transfers no long-lived guard or general Store surface.
    let store_capture_target = pinned
        .into_advisory_capture_target(MaintenanceCoordinatorContext(()), source)
        .map_err(|_| MaintenanceImportError::Conflict)?;
    Ok(CompletedAdvisoryShadowHandoff {
        _runtime: runtime,
        _terminal_witness: released,
        _archive_binding: archive_binding,
        _parity: parity,
        _control: control,
        _store_capture_target: store_capture_target,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit authenticated terminal handoff tuple; grouping would obscure exact binding"
)]
async fn finish_offline_import(
    expected_durable: &MaintenanceImportRecord,
    persistence: &dyn MaintenanceImportPersistence,
    witness: &dyn MaintenanceImportWitnessProvider,
    owner_id: ObjectId,
    archive_id: ArchiveId,
    source: MaintenanceSourceBinding,
    pinned: crate::store::PinnedLegacySnapshot,
    runtime: crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle,
    archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    control: Arc<crate::cp::control_store::ControlStore>,
) -> Result<CompletedMaintenanceWalHandoff, MaintenanceImportError> {
    let durable = persistence
        .load_exact(expected_durable.operation_id)
        .await?;
    validate_exact_terminal_control(expected_durable, &durable, source)?;
    let released =
        authenticate_and_release_terminal_witness(&durable, witness, owner_id, archive_id).await?;
    pinned
        .exact_generation_revalidation()
        .verify()
        .await
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let exact_durable = persistence
        .load_exact(expected_durable.operation_id)
        .await?;
    validate_exact_terminal_control(&durable, &exact_durable, source)?;
    let store_fence = pinned
        .into_wal_authority_fence(MaintenanceCoordinatorContext(()), source)
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let parity =
        CompletedMaintenanceParityEvidence::from_terminal(exact_durable, source, &released)?;
    Ok(CompletedMaintenanceWalHandoff {
        runtime,
        terminal_witness: released,
        archive_binding,
        parity,
        control,
        store_fence: Some(store_fence),
    })
}

fn validate_advisory_parity_evidence(
    terminal_control: &MaintenanceImportRecord,
    source: MaintenanceSourceBinding,
    terminal_witness: &WitnessRecord,
) -> Result<(), MaintenanceImportError> {
    if terminal_control.stage() != MaintenanceImportStage::ParityVerified
        || terminal_control.source() != Some(source)
        || terminal_control.parity_commitment.is_none()
        || terminal_control.authoritative_candidate_record()?.is_some()
        || terminal_witness.archive_id() != terminal_control.archive_id
        || terminal_witness.deletion() != DeletionState::Active
        || terminal_witness.migration() != MigrationState::ShadowWal
    {
        return Err(MaintenanceImportError::Corrupt);
    }
    let retained_terminal = terminal_control
        .witnessed_record()?
        .ok_or(MaintenanceImportError::Corrupt)?;
    if terminal_witness
        .exact_maintenance_advisory_or_release_from(&retained_terminal, terminal_control.owner_id)
        .map_err(|_| MaintenanceImportError::Conflict)?
    {
        return Err(MaintenanceImportError::Conflict);
    }
    let retained_candidate = terminal_control
        .shadow_candidate_record()?
        .ok_or(MaintenanceImportError::Corrupt)?;
    let retained_root = RecoveryRoot::from_exact_active_record(&retained_candidate)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    let terminal_root = RecoveryRoot::from_exact_active_record(terminal_witness)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    if terminal_root != retained_root {
        return Err(MaintenanceImportError::Conflict);
    }
    Ok(())
}

fn validate_exact_advisory_control(
    expected: &MaintenanceImportRecord,
    observed: &MaintenanceImportRecord,
    source: MaintenanceSourceBinding,
) -> Result<(), MaintenanceImportError> {
    if observed != expected
        || observed.stage() != MaintenanceImportStage::ParityVerified
        || observed.source() != Some(source)
        || observed.parity_commitment.is_none()
        || observed.authoritative_candidate_record()?.is_some()
    {
        return Err(MaintenanceImportError::Conflict);
    }
    Ok(())
}

async fn authenticate_and_release_advisory_witness(
    durable: &MaintenanceImportRecord,
    witness: &dyn MaintenanceImportWitnessProvider,
    owner_id: ObjectId,
    archive_id: ArchiveId,
) -> Result<WitnessRecord, MaintenanceImportError> {
    if durable.stage() != MaintenanceImportStage::ParityVerified
        || durable.parity_commitment.is_none()
        || durable.authoritative_candidate_record()?.is_some()
    {
        return Err(MaintenanceImportError::Corrupt);
    }
    let retained_terminal = durable
        .witnessed_record()?
        .ok_or(MaintenanceImportError::Corrupt)?;
    let retained_candidate = durable
        .shadow_candidate_record()?
        .ok_or(MaintenanceImportError::Corrupt)?;
    let retained_root = RecoveryRoot::from_exact_active_record(&retained_candidate)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    let terminal = witness
        .read_current_exact(archive_id)
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?;
    require_active_migration(&terminal, archive_id, MigrationState::ShadowWal)?;
    let terminal_requires_release = terminal
        .exact_maintenance_advisory_or_release_from(&retained_terminal, owner_id)
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let terminal_root = RecoveryRoot::from_exact_active_record(&terminal)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    if terminal_root != retained_root {
        return Err(MaintenanceImportError::Conflict);
    }
    let release_outcome = if terminal_requires_release {
        Some(
            witness
                .release_advisory_lease_unresolved(retained_terminal.clone(), owner_id)
                .await,
        )
    } else {
        None
    };
    let released = witness
        .read_current_exact(archive_id)
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?;
    require_active_migration(&released, archive_id, MigrationState::ShadowWal)?;
    let released_requires_release = released
        .exact_maintenance_advisory_or_release_from(&retained_terminal, owner_id)
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let released_root = RecoveryRoot::from_exact_active_record(&released)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    if released_root != retained_root {
        return Err(MaintenanceImportError::Conflict);
    }
    if released_requires_release {
        return Err(match release_outcome {
            Some(Err(MaintenanceWitnessCommitError::DefinitelyFailed)) => {
                MaintenanceImportError::Unavailable
            }
            Some(Err(MaintenanceWitnessCommitError::OutcomeUnknown)) | Some(Ok(())) => {
                MaintenanceImportError::OutcomeUnknown
            }
            Some(Err(MaintenanceWitnessCommitError::Rejected)) | None => {
                MaintenanceImportError::Conflict
            }
        });
    }
    Ok(released)
}

fn validate_terminal_parity_evidence(
    terminal_control: &MaintenanceImportRecord,
    source: MaintenanceSourceBinding,
    terminal_witness: &WitnessRecord,
) -> Result<(), MaintenanceImportError> {
    if terminal_control.stage() != MaintenanceImportStage::WalAuthoritative
        || terminal_control.source() != Some(source)
        || terminal_control.parity_commitment.is_none()
        || terminal_witness.archive_id() != terminal_control.archive_id
        || terminal_witness.deletion() != DeletionState::Active
        || terminal_witness.migration() != MigrationState::WalAuthoritative
    {
        return Err(MaintenanceImportError::Corrupt);
    }
    let retained_terminal = terminal_control
        .witnessed_record()?
        .ok_or(MaintenanceImportError::Corrupt)?;
    if terminal_witness
        .exact_maintenance_terminal_or_release_from(&retained_terminal, terminal_control.owner_id)
        .map_err(|_| MaintenanceImportError::Conflict)?
    {
        return Err(MaintenanceImportError::Conflict);
    }
    let retained_candidate = terminal_control
        .authoritative_candidate_record()?
        .ok_or(MaintenanceImportError::Corrupt)?;
    let retained_root = RecoveryRoot::from_exact_wal_authoritative_record(&retained_candidate)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    let terminal_root = RecoveryRoot::from_exact_wal_authoritative_record(terminal_witness)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    if terminal_root != retained_root {
        return Err(MaintenanceImportError::Conflict);
    }
    Ok(())
}

fn validate_exact_terminal_control(
    expected: &MaintenanceImportRecord,
    observed: &MaintenanceImportRecord,
    source: MaintenanceSourceBinding,
) -> Result<(), MaintenanceImportError> {
    if observed != expected
        || observed.stage() != MaintenanceImportStage::WalAuthoritative
        || observed.source() != Some(source)
    {
        return Err(MaintenanceImportError::Conflict);
    }
    Ok(())
}

async fn authenticate_and_release_terminal_witness(
    durable: &MaintenanceImportRecord,
    witness: &dyn MaintenanceImportWitnessProvider,
    owner_id: ObjectId,
    archive_id: ArchiveId,
) -> Result<WitnessRecord, MaintenanceImportError> {
    if durable.stage() != MaintenanceImportStage::WalAuthoritative {
        return Err(MaintenanceImportError::Corrupt);
    }
    let retained_terminal = durable
        .witnessed_record()?
        .ok_or(MaintenanceImportError::Corrupt)?;
    let retained_candidate = durable
        .authoritative_candidate_record()?
        .ok_or(MaintenanceImportError::Corrupt)?;
    let retained_root = RecoveryRoot::from_exact_wal_authoritative_record(&retained_candidate)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    let terminal = witness
        .read_current_exact(archive_id)
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?;
    require_active_migration(&terminal, archive_id, MigrationState::WalAuthoritative)?;
    let terminal_requires_release = terminal
        .exact_maintenance_terminal_or_release_from(&retained_terminal, owner_id)
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let terminal_root = RecoveryRoot::from_exact_wal_authoritative_record(&terminal)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    if terminal_root != retained_root {
        return Err(MaintenanceImportError::Conflict);
    }
    let release_outcome = if terminal_requires_release {
        Some(
            witness
                .release_terminal_lease_unresolved(retained_terminal.clone(), owner_id)
                .await,
        )
    } else {
        None
    };
    let released = witness
        .read_current_exact(archive_id)
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?;
    require_active_migration(&released, archive_id, MigrationState::WalAuthoritative)?;
    let released_requires_release = released
        .exact_maintenance_terminal_or_release_from(&retained_terminal, owner_id)
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let released_root = RecoveryRoot::from_exact_wal_authoritative_record(&released)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    if released_root != retained_root {
        return Err(MaintenanceImportError::Conflict);
    }
    if released_requires_release {
        return Err(match release_outcome {
            Some(Err(MaintenanceWitnessCommitError::DefinitelyFailed)) => {
                MaintenanceImportError::Unavailable
            }
            Some(Err(MaintenanceWitnessCommitError::OutcomeUnknown)) | Some(Ok(())) => {
                MaintenanceImportError::OutcomeUnknown
            }
            Some(Err(MaintenanceWitnessCommitError::Rejected)) | None => {
                MaintenanceImportError::Conflict
            }
        });
    }
    Ok(released)
}

async fn renew_exact_maintenance_lease(
    witness: &dyn MaintenanceImportWitnessProvider,
    persistence: &dyn MaintenanceImportPersistence,
    operation_id: MaintenanceImportOperationId,
    stage: MaintenanceImportStage,
    owner_id: ObjectId,
    mut durable: WitnessRecord,
    mut observed: WitnessRecord,
) -> Result<(WitnessRecord, MaintenanceImportRecord), MaintenanceImportError> {
    if observed != durable {
        if let Ok(adopted_lease) = observed.exact_maintenance_renewal_from(&durable, owner_id) {
            persistence
                .persist_renewed_lease(operation_id, stage, &durable, &observed, adopted_lease)
                .await?;
            durable = observed.clone();
        } else if let Ok(adopted_lease) =
            observed.exact_maintenance_reacquire_from(&durable, owner_id)
        {
            let record = persistence
                .persist_reacquired_lease(operation_id, stage, &durable, &observed, adopted_lease)
                .await?;
            return Ok((observed, record));
        } else {
            return Err(MaintenanceImportError::Conflict);
        }
    }
    let previous_lease = observed
        .exact_active_lease_for_owner(owner_id)
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let lease = match witness
        .renew_lease_exact(previous_lease, MAINTENANCE_LEASE_TICKS)
        .await
    {
        Ok(lease) => lease,
        Err(WitnessError::Fenced) => {
            let fresh = witness
                .read_current_exact(observed.archive_id())
                .await
                .map_err(|_| MaintenanceImportError::Unavailable)?;
            return reacquire_exact_maintenance_lease(
                witness,
                persistence,
                operation_id,
                stage,
                owner_id,
                durable,
                fresh,
            )
            .await;
        }
        Err(_) => return Err(MaintenanceImportError::Unavailable),
    };
    observed = witness
        .read_current_exact(observed.archive_id())
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?;
    if observed
        .exact_maintenance_renewal_from(&durable, owner_id)
        .is_err()
        || !observed.authorizes_lease(lease)
    {
        return Err(MaintenanceImportError::Conflict);
    }
    let record = persistence
        .persist_renewed_lease(operation_id, stage, &durable, &observed, lease)
        .await?;
    Ok((observed, record))
}

/// Phase-2-only witness-lease succession from the settled advisory owner.
/// Under the acquisition-gated door, the maintenance owner acquires the exact
/// unleased advisory terminal its durable Phase-2 acquisition was minted
/// over; encrypted Control refuses the persist unless the fresh basis hashes
/// to that acquisition's terminal witness hash. A restart between the
/// provider acquire and the durable persist re-adopts only the exact leased
/// successor of the identical archive graph. Every refusal is fail-closed:
/// the plain renewal/reacquire ladder is never consulted under Phase 2.
#[allow(clippy::too_many_arguments)]
async fn succeed_phase2_maintenance_lease(
    witness: &dyn MaintenanceImportWitnessProvider,
    persistence: &dyn MaintenanceImportPersistence,
    operation_id: MaintenanceImportOperationId,
    stage: MaintenanceImportStage,
    owner_id: ObjectId,
    durable: WitnessRecord,
    observed: WitnessRecord,
) -> Result<(WitnessRecord, MaintenanceImportRecord), MaintenanceImportError> {
    if observed.exact_active_lease_for_owner(owner_id).is_ok() {
        let lease = observed
            .exact_phase2_succession_lineage_from(&durable, owner_id)
            .map_err(|_| MaintenanceImportError::Conflict)?;
        let record = persistence
            .persist_phase2_succeeded_lease(operation_id, stage, &durable, None, &observed, lease)
            .await?;
        return Ok((observed, record));
    }
    if !observed.is_exact_phase2_succession_basis_of(&durable, owner_id) {
        return Err(MaintenanceImportError::Conflict);
    }
    let lease = witness
        .acquire_lease_exact(&observed, owner_id, MAINTENANCE_LEASE_TICKS)
        .await
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let succeeded = witness
        .read_current_exact(observed.archive_id())
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?;
    let exact = succeeded
        .exact_phase2_succession_from(&observed, owner_id)
        .map_err(|_| MaintenanceImportError::Conflict)?;
    if exact != lease {
        return Err(MaintenanceImportError::Conflict);
    }
    let record = persistence
        .persist_phase2_succeeded_lease(
            operation_id,
            stage,
            &durable,
            Some(&observed),
            &succeeded,
            lease,
        )
        .await?;
    Ok((succeeded, record))
}

#[allow(clippy::too_many_arguments)]
async fn reacquire_exact_maintenance_lease(
    witness: &dyn MaintenanceImportWitnessProvider,
    persistence: &dyn MaintenanceImportPersistence,
    operation_id: MaintenanceImportOperationId,
    stage: MaintenanceImportStage,
    owner_id: ObjectId,
    durable: WitnessRecord,
    observed: WitnessRecord,
) -> Result<(WitnessRecord, MaintenanceImportRecord), MaintenanceImportError> {
    if let Ok(adopted_lease) = observed.exact_maintenance_reacquire_from(&durable, owner_id) {
        let record = persistence
            .persist_reacquired_lease(operation_id, stage, &durable, &observed, adopted_lease)
            .await?;
        return Ok((observed, record));
    }
    if observed != durable {
        return Err(MaintenanceImportError::Conflict);
    }
    let lease = witness
        .acquire_lease_exact(&observed, owner_id, MAINTENANCE_LEASE_TICKS)
        .await
        .map_err(|_| MaintenanceImportError::Conflict)?;
    let reacquired = witness
        .read_current_exact(observed.archive_id())
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?;
    if reacquired
        .exact_maintenance_reacquire_from(&durable, owner_id)
        .is_err()
        || !reacquired.authorizes_lease(lease)
    {
        return Err(MaintenanceImportError::Conflict);
    }
    let record = persistence
        .persist_reacquired_lease(operation_id, stage, &durable, &reacquired, lease)
        .await?;
    Ok((reacquired, record))
}

fn require_active_migration(
    record: &WitnessRecord,
    archive_id: ArchiveId,
    expected: MigrationState,
) -> Result<(), MaintenanceImportError> {
    if record.archive_id() != archive_id
        || record.deletion() != DeletionState::Active
        || record.migration() != expected
    {
        return Err(MaintenanceImportError::Conflict);
    }
    Ok(())
}

async fn resolve_witness_cipher(
    record: &WitnessRecord,
    archive_id: ArchiveId,
    registries: &dyn ExactKeyRegistryProvider,
) -> Result<Arc<VerifiedArchiveCipher>, MaintenanceImportError> {
    require_active_migration(record, archive_id, record.migration())?;
    let registry = record.registry();
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
        registries,
    )
    .await
    .map(Arc::new)
    .map_err(|_| MaintenanceImportError::Corrupt)
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

async fn authenticate_current_root(
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    record: &WitnessRecord,
) -> Result<ArchiveRoot, MaintenanceImportError> {
    let commitment = record.root();
    let reference = commitment.root();
    let parent = commitment.parent().map(|parent| ParentReference {
        object_id: parent.object_id(),
        envelope_hash: parent.ciphertext_hash(),
    });
    let context = ObjectContext::new(
        record.archive_id(),
        commitment.database_epoch(),
        commitment.key_epoch(),
        ObjectRole::RootV3,
        LogicalLocation::Root {
            root_seq: reference.sequence(),
        },
        reference.object_id(),
        parent,
    )
    .map_err(|_| MaintenanceImportError::Corrupt)?;
    let envelope = backend
        .get(&context.object_key())
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?
        .ok_or(MaintenanceImportError::Corrupt)?;
    if envelope.hash() != reference.ciphertext_hash() {
        return Err(MaintenanceImportError::Corrupt);
    }
    let plaintext = cipher
        .open(&context, &envelope)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    let root = ArchiveRoot::decode(&plaintext).map_err(|_| MaintenanceImportError::Corrupt)?;
    root.validate_for_context(&context)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    if root.owner_fencing_epoch != commitment.owner_fencing_epoch() {
        return Err(MaintenanceImportError::Corrupt);
    }
    Ok(root)
}

async fn build_zero_wal_candidate(
    backend: &dyn ImmutableObjectBackend,
    cipher: &VerifiedArchiveCipher,
    current: &WitnessRecord,
    lease: WitnessLease,
    checkpoint: &UploadedCheckpoint,
    staging: &ShadowObjectStaging<'_>,
) -> Result<RootAdvance, MaintenanceImportError> {
    let expected = current.root();
    let root_seq = expected
        .root()
        .sequence()
        .checked_add(1)
        .ok_or(MaintenanceImportError::Corrupt)?;
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
    .map_err(|_| MaintenanceImportError::Corrupt)?;
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
            &root.encode().map_err(|_| MaintenanceImportError::Corrupt)?,
        )
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    staging
        .create_and_readback(backend, &context, envelope)
        .await
        .map_err(|_| MaintenanceImportError::Unavailable)?;
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
    .map_err(|_| MaintenanceImportError::Corrupt)
}

fn validate_checkpoint_source(
    checkpoint: &UploadedCheckpoint,
    source: MaintenanceSourceBinding,
) -> Result<(), MaintenanceImportError> {
    if checkpoint.logical_file_length() != source.plaintext_len
        || checkpoint.database_plaintext_hash() != source.plaintext_hash
        || checkpoint.user_schema_version() != source.sqlite_schema_version
    {
        return Err(MaintenanceImportError::Corrupt);
    }
    Ok(())
}

fn prepare_full_parity(
    source: &crate::store::PinnedLegacySnapshot,
    recovered: &crate::archive_v3_shadow_wal::RecoveredMaintenanceStaging,
) -> Result<(PrivateStagedSqliteCopy, PrivateStagedSqliteCopy), MaintenanceImportError> {
    let primary = PrivateStagedSqliteCopy::from_pinned_maintenance_source(source)
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    let shadow = PrivateStagedSqliteCopy::from_owned_maintenance_recovery(recovered.owned())
        .map_err(|_| MaintenanceImportError::Corrupt)?;
    Ok((primary, shadow))
}

async fn verify_full_parity(
    primary: PrivateStagedSqliteCopy,
    shadow: PrivateStagedSqliteCopy,
) -> Result<[u8; 32], MaintenanceImportError> {
    tokio::task::spawn_blocking(move || {
        let cancelled = AtomicBool::new(false);
        let control =
            ShadowParityRunControl::new(Instant::now() + Duration::from_secs(300), &cancelled);
        match ShadowParityVerifier::compare_staged_copies(&primary, &shadow, &control) {
            Ok(ShadowParityResult::Match(digests)) => Ok(digests.maintenance_commitment()),
            Ok(ShadowParityResult::Mismatch(_)) => Err(MaintenanceImportError::ParityMismatch),
            Err(_) => Err(MaintenanceImportError::Unavailable),
        }
    })
    .await
    .map_err(|_| MaintenanceImportError::Unavailable)?
}

impl fmt::Debug for SingleArchiveMaintenanceImporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleArchiveMaintenanceImporter(<inactive>)")
    }
}

fn operation_commitment_for(
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    owner_id: ObjectId,
    fence_authority: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(IMPORT_OPERATION_DOMAIN);
    hasher.update(archive_id.as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(owner_id.as_bytes());
    hasher.update((fence_authority.len() as u32).to_be_bytes());
    hasher.update(fence_authority.as_bytes());
    hasher.finalize().into()
}

pub(crate) fn operation_commitment_for_control(
    _token: crate::cp::control_store::MaintenancePersistenceContext,
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    owner_id: ObjectId,
    fence_authority: &str,
) -> [u8; 32] {
    operation_commitment_for(archive_id, operation_id, owner_id, fence_authority)
}

pub(crate) fn maintenance_parity_commitment(
    source: MaintenanceSourceBinding,
    shadow_digest: [u8; 32],
) -> Result<[u8; 32], MaintenanceImportError> {
    if zero(&shadow_digest) {
        return Err(MaintenanceImportError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(IMPORT_PARITY_DOMAIN);
    hasher.update(source.commitment);
    hasher.update(shadow_digest);
    Ok(hasher.finalize().into())
}

const fn zero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{atomic::AtomicUsize, Mutex};

    use crate::{
        archive_v3::{
            resolve_archive_cipher, ArchiveDek, ArchiveV3Error, DatabaseEpoch,
            InMemoryImmutableBackend, KeyEpoch, KeyRegistryPlaintext,
        },
        archive_v3_operation::{RecordOutcome, ShadowObjectFacts, ShadowObjectInventoryPage},
        archive_v3_shadow_checkpoint::ShadowObjectInventoryError,
        archive_v3_shadow_session::ShadowAttemptId,
        archive_v3_witness::{
            InMemoryWitness, KeyRegistryReference, MigrationState, RootCommitment, RootReference,
            Witness, WitnessBootstrap, WitnessError, WitnessLease,
        },
    };
    use sha2::{Digest, Sha256};

    pub(crate) struct TestRegistry {
        pub(crate) object_id: ObjectId,
        pub(crate) wrapped: Vec<u8>,
        pub(crate) plaintext: Vec<u8>,
    }

    #[async_trait]
    impl ExactKeyRegistryProvider for TestRegistry {
        async fn read_exact_wrapped(
            &self,
            _context: &KeyRegistryContext,
            object_id: ObjectId,
            destination: &mut [u8],
        ) -> std::result::Result<usize, ArchiveV3Error> {
            if object_id != self.object_id {
                return Err(ArchiveV3Error::InvalidContext);
            }
            if self.wrapped.len() <= destination.len() {
                destination[..self.wrapped.len()].copy_from_slice(&self.wrapped);
            }
            Ok(self.wrapped.len())
        }

        async fn kms_unwrap_exact(
            &self,
            _context: &KeyRegistryContext,
            wrapped: &[u8],
            destination: &mut [u8],
        ) -> std::result::Result<usize, ArchiveV3Error> {
            if wrapped != self.wrapped {
                return Err(ArchiveV3Error::InvalidContext);
            }
            if self.plaintext.len() <= destination.len() {
                destination[..self.plaintext.len()].copy_from_slice(&self.plaintext);
            }
            Ok(self.plaintext.len())
        }
    }

    pub(crate) struct InMemoryMaintenanceWitness {
        pub(crate) inner: InMemoryWitness,
        pub(crate) advisory_acquires: std::sync::atomic::AtomicUsize,
        pub(crate) advisory_maintains: std::sync::atomic::AtomicUsize,
        pub(crate) advisory_outcome_unknown_once: std::sync::atomic::AtomicBool,
        pub(crate) advisory_maintain_outcome_unknown_once: std::sync::atomic::AtomicBool,
    }

    impl InMemoryMaintenanceWitness {
        pub(crate) fn new(inner: InMemoryWitness) -> Self {
            Self {
                inner,
                advisory_acquires: std::sync::atomic::AtomicUsize::new(0),
                advisory_maintains: std::sync::atomic::AtomicUsize::new(0),
                advisory_outcome_unknown_once: std::sync::atomic::AtomicBool::new(false),
                advisory_maintain_outcome_unknown_once: std::sync::atomic::AtomicBool::new(false),
            }
        }

        pub(crate) fn with_advisory_outcome_unknown(inner: InMemoryWitness) -> Self {
            Self {
                inner,
                advisory_acquires: std::sync::atomic::AtomicUsize::new(0),
                advisory_maintains: std::sync::atomic::AtomicUsize::new(0),
                advisory_outcome_unknown_once: std::sync::atomic::AtomicBool::new(true),
                advisory_maintain_outcome_unknown_once: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    #[async_trait]
    impl MaintenanceImportWitnessProvider for InMemoryMaintenanceWitness {
        async fn read_current_exact(
            &self,
            archive_id: ArchiveId,
        ) -> Result<WitnessRecord, WitnessError> {
            self.inner
                .read_current(archive_id)?
                .ok_or(WitnessError::MissingArchive)
        }

        async fn acquire_lease_exact(
            &self,
            record: &WitnessRecord,
            owner: ObjectId,
            duration_ticks: u64,
        ) -> Result<WitnessLease, WitnessError> {
            self.inner.acquire_lease(
                record.archive_id(),
                record.database_epoch(),
                record.registry().key_epoch(),
                owner,
                duration_ticks,
            )
        }

        async fn validate_exact_lease(
            &self,
            record: &WitnessRecord,
            owner: ObjectId,
        ) -> Result<WitnessLease, WitnessError> {
            let current = self
                .inner
                .read_current(record.archive_id())?
                .ok_or(WitnessError::MissingArchive)?;
            if current != *record {
                return Err(WitnessError::Fenced);
            }
            current.exact_active_lease_for_owner(owner)
        }

        async fn renew_lease_exact(
            &self,
            lease: WitnessLease,
            duration_ticks: u64,
        ) -> Result<WitnessLease, WitnessError> {
            self.inner.renew_lease(lease, duration_ticks)
        }

        async fn release_terminal_lease_unresolved(
            &self,
            retained: WitnessRecord,
            owner: ObjectId,
        ) -> Result<(), MaintenanceWitnessCommitError> {
            self.inner
                .release_exact_maintenance_terminal(&retained, owner)
                .map(|_| ())
                .map_err(|_| MaintenanceWitnessCommitError::Rejected)
        }

        async fn release_advisory_lease_unresolved(
            &self,
            retained: WitnessRecord,
            owner: ObjectId,
        ) -> Result<(), MaintenanceWitnessCommitError> {
            self.inner
                .release_exact_maintenance_advisory(&retained, owner)
                .map(|_| ())
                .map_err(|_| MaintenanceWitnessCommitError::Rejected)
        }

        async fn advance_migration_unresolved(
            &self,
            expected: WitnessRecord,
            candidate: WitnessRecord,
            advance: RootAdvance,
            next: MigrationState,
        ) -> Result<(), MaintenanceWitnessCommitError> {
            let current = self
                .inner
                .read_current(expected.archive_id())
                .map_err(|_| MaintenanceWitnessCommitError::Rejected)?
                .ok_or(MaintenanceWitnessCommitError::Rejected)?;
            if current != expected
                || !expected
                    .exact_migration_candidate(&advance, next)
                    .is_ok_and(|exact| exact == candidate)
            {
                return Err(MaintenanceWitnessCommitError::Rejected);
            }
            let receipt = self
                .inner
                .advance_exact_retained_migration_for_test(advance, next, &candidate)
                .map_err(|_| MaintenanceWitnessCommitError::Rejected)?;
            if receipt.record() != &candidate {
                return Err(MaintenanceWitnessCommitError::Rejected);
            }
            Ok(())
        }
    }

    #[async_trait]
    impl crate::archive_v3_advisory_owner::AdvisoryOwnerWitnessProvider for InMemoryMaintenanceWitness {
        async fn read_current_exact(
            &self,
            archive_id: ArchiveId,
        ) -> Result<WitnessRecord, WitnessError> {
            self.inner
                .read_current(archive_id)?
                .ok_or(WitnessError::MissingArchive)
        }

        async fn acquire_owner_lease(
            &self,
            expected: &WitnessRecord,
            owner: crate::archive_v3_advisory_owner::AdvisoryOwnerId,
            duration_ticks: u64,
        ) -> std::result::Result<
            (WitnessRecord, WitnessLease),
            crate::archive_v3_advisory_owner::AdvisoryOwnerCommitError,
        > {
            let value = self
                .inner
                .acquire_exact_advisory_owner_lease(
                    expected,
                    ObjectId::from_bytes(*owner.as_bytes()),
                    duration_ticks,
                )
                .map_err(|_| {
                    crate::archive_v3_advisory_owner::AdvisoryOwnerCommitError::Rejected
                })?;
            self.advisory_acquires
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self
                .advisory_outcome_unknown_once
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                Err(crate::archive_v3_advisory_owner::AdvisoryOwnerCommitError::OutcomeUnknown)
            } else {
                Ok(value)
            }
        }

        async fn maintain_owner_lease(
            &self,
            previous: &WitnessRecord,
            owner: crate::archive_v3_advisory_owner::AdvisoryOwnerId,
            duration_ticks: u64,
        ) -> std::result::Result<
            (WitnessRecord, WitnessLease),
            crate::archive_v3_advisory_owner::AdvisoryOwnerCommitError,
        > {
            let value = self
                .inner
                .maintain_exact_advisory_owner_lease(
                    previous,
                    ObjectId::from_bytes(*owner.as_bytes()),
                    duration_ticks,
                )
                .map_err(|_| {
                    crate::archive_v3_advisory_owner::AdvisoryOwnerCommitError::Rejected
                })?;
            self.advisory_maintains
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self
                .advisory_maintain_outcome_unknown_once
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                Err(crate::archive_v3_advisory_owner::AdvisoryOwnerCommitError::OutcomeUnknown)
            } else {
                Ok(value)
            }
        }

        async fn reacquire_owner_lease(
            &self,
            previous: &WitnessRecord,
            owner: crate::archive_v3_advisory_owner::AdvisoryOwnerId,
            duration_ticks: u64,
        ) -> std::result::Result<
            (WitnessRecord, WitnessLease),
            crate::archive_v3_advisory_owner::AdvisoryOwnerCommitError,
        > {
            self.inner
                .reacquire_exact_advisory_owner_lease(
                    previous,
                    ObjectId::from_bytes(*owner.as_bytes()),
                    duration_ticks,
                )
                .map_err(|_| crate::archive_v3_advisory_owner::AdvisoryOwnerCommitError::Rejected)
        }
    }

    fn source(
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
    ) -> MaintenanceSourceBinding {
        MaintenanceSourceBinding::from_pinned(
            archive_id,
            operation_id,
            2,
            [0x31; 32],
            4096,
            0,
            [0x32; 32],
        )
        .unwrap()
    }

    struct MigrationFixture {
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        owner_id: ObjectId,
        current: WitnessRecord,
        candidate: WitnessRecord,
        source: MaintenanceSourceBinding,
    }

    fn migration_fixture() -> MigrationFixture {
        let archive_id = ArchiveId::from_bytes([1; 16]);
        let database_epoch = DatabaseEpoch::from_bytes([2; 16]);
        let key_epoch = KeyEpoch::from_bytes([3; 16]);
        let registry =
            KeyRegistryReference::new(key_epoch, 0, ObjectId::from_bytes([4; 16]), [5; 32]);
        let genesis = RootCommitment::genesis(
            database_epoch,
            key_epoch,
            RootReference::new(0, ObjectId::from_bytes([6; 16]), [7; 32]),
        );
        let witness = InMemoryWitness::new();
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                genesis,
                registry,
            ))
            .unwrap();
        let owner_id = ObjectId::from_bytes([8; 16]);
        let lease = witness
            .acquire_lease(archive_id, database_epoch, key_epoch, owner_id, 900)
            .unwrap();
        let current = witness.read_current(archive_id).unwrap().unwrap();
        let candidate_commitment = current
            .with_candidate_root_for_test(
                RootReference::new(1, ObjectId::from_bytes([9; 16]), [10; 32]),
                lease.fencing_epoch(),
            )
            .root();
        let advance = RootAdvance::new(lease, current.root(), registry, candidate_commitment);
        let candidate = current
            .exact_migration_candidate(&advance, MigrationState::ShadowWal)
            .unwrap();
        let operation_id = MaintenanceImportOperationId::from_control(
            crate::cp::control_store::MaintenancePersistenceContext::for_test(),
            [11; 16],
        )
        .unwrap();
        MigrationFixture {
            archive_id,
            operation_id,
            owner_id,
            source: source(archive_id, operation_id),
            current,
            candidate,
        }
    }

    fn record(
        fixture: &MigrationFixture,
        stage: MaintenanceImportStage,
        witnessed: &WitnessRecord,
    ) -> MaintenanceImportRecord {
        MaintenanceImportRecord::from_control_persistence(
            crate::cp::control_store::MaintenancePersistenceContext::for_test(),
            stage,
            fixture.archive_id,
            fixture.operation_id,
            fixture.owner_id,
            1,
            ShadowAttemptId::from_bytes([12; 16]),
            1,
            [13; 32],
            Some(crate::store::MaintenanceTentativeSource {
                base_generation: 1,
                plaintext_hash: [0x31; 32],
                plaintext_len: 4096,
                sqlite_schema_version: 0,
                wrapped_dek_commitment: [0x32; 32],
            }),
            Some(fixture.source),
            Some(witnessed.encode().to_vec()),
            Some(fixture.candidate.encode().to_vec()),
            None,
            None,
        )
        .unwrap()
    }

    fn terminal_record(
        fixture: &MigrationFixture,
        terminal: &WitnessRecord,
    ) -> MaintenanceImportRecord {
        MaintenanceImportRecord::from_control_persistence(
            crate::cp::control_store::MaintenancePersistenceContext::for_test(),
            MaintenanceImportStage::WalAuthoritative,
            fixture.archive_id,
            fixture.operation_id,
            fixture.owner_id,
            2,
            ShadowAttemptId::from_bytes([14; 16]),
            1,
            [13; 32],
            Some(crate::store::MaintenanceTentativeSource {
                base_generation: 1,
                plaintext_hash: [0x31; 32],
                plaintext_len: 4096,
                sqlite_schema_version: 0,
                wrapped_dek_commitment: [0x32; 32],
            }),
            Some(fixture.source),
            Some(terminal.encode().to_vec()),
            Some(fixture.candidate.encode().to_vec()),
            Some([0x45; 32]),
            Some(terminal.encode().to_vec()),
        )
        .unwrap()
    }

    fn advisory_record(fixture: &MigrationFixture) -> MaintenanceImportRecord {
        MaintenanceImportRecord::from_control_persistence(
            crate::cp::control_store::MaintenancePersistenceContext::for_test(),
            MaintenanceImportStage::ParityVerified,
            fixture.archive_id,
            fixture.operation_id,
            fixture.owner_id,
            1,
            ShadowAttemptId::from_bytes([12; 16]),
            1,
            [13; 32],
            Some(crate::store::MaintenanceTentativeSource {
                base_generation: 1,
                plaintext_hash: [0x31; 32],
                plaintext_len: 4096,
                sqlite_schema_version: 0,
                wrapped_dek_commitment: [0x32; 32],
            }),
            Some(fixture.source),
            Some(fixture.candidate.encode().to_vec()),
            Some(fixture.candidate.encode().to_vec()),
            Some([0x45; 32]),
            None,
        )
        .unwrap()
    }

    #[derive(Clone, Copy)]
    enum SendBehavior {
        CommitThenUnknown,
        DefinitelyFailed,
    }

    struct FakeWitness {
        current: Mutex<WitnessRecord>,
        reads: AtomicUsize,
        revokes: AtomicUsize,
        sends: AtomicUsize,
        behavior: SendBehavior,
        revoke_succeeds: bool,
    }

    #[async_trait]
    impl MaintenanceImportWitnessProvider for FakeWitness {
        async fn read_current_exact(
            &self,
            _archive_id: ArchiveId,
        ) -> Result<WitnessRecord, WitnessError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.current.lock().unwrap().clone())
        }

        async fn acquire_lease_exact(
            &self,
            _record: &WitnessRecord,
            _owner: ObjectId,
            _duration_ticks: u64,
        ) -> Result<WitnessLease, WitnessError> {
            Err(WitnessError::Unavailable)
        }

        async fn validate_exact_lease(
            &self,
            record: &WitnessRecord,
            owner: ObjectId,
        ) -> Result<WitnessLease, WitnessError> {
            let current = self.current.lock().unwrap();
            if *current != *record {
                return Err(WitnessError::Fenced);
            }
            current.exact_active_lease_for_owner(owner)
        }

        async fn renew_lease_exact(
            &self,
            _lease: WitnessLease,
            _duration_ticks: u64,
        ) -> Result<WitnessLease, WitnessError> {
            Err(WitnessError::Unavailable)
        }

        async fn release_terminal_lease_unresolved(
            &self,
            retained: WitnessRecord,
            owner: ObjectId,
        ) -> Result<(), MaintenanceWitnessCommitError> {
            self.revokes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.revoke_succeeds {
                let current = self.current.lock().unwrap().clone();
                let local = InMemoryWitness::from_provider_record_at_tick(
                    Some(current.encode()),
                    retained.last_server_tick().saturating_add(1),
                )
                .unwrap();
                *self.current.lock().unwrap() = local
                    .release_exact_maintenance_terminal(&retained, owner)
                    .unwrap();
                return Err(MaintenanceWitnessCommitError::OutcomeUnknown);
            }
            Err(MaintenanceWitnessCommitError::DefinitelyFailed)
        }

        async fn release_advisory_lease_unresolved(
            &self,
            retained: WitnessRecord,
            owner: ObjectId,
        ) -> Result<(), MaintenanceWitnessCommitError> {
            self.revokes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.revoke_succeeds {
                let current = self.current.lock().unwrap().clone();
                let local = InMemoryWitness::from_provider_record_at_tick(
                    Some(current.encode()),
                    retained.last_server_tick().saturating_add(1),
                )
                .unwrap();
                *self.current.lock().unwrap() = local
                    .release_exact_maintenance_advisory(&retained, owner)
                    .unwrap();
                return Err(MaintenanceWitnessCommitError::OutcomeUnknown);
            }
            Err(MaintenanceWitnessCommitError::DefinitelyFailed)
        }

        async fn advance_migration_unresolved(
            &self,
            expected: WitnessRecord,
            candidate: WitnessRecord,
            advance: RootAdvance,
            next: MigrationState,
        ) -> Result<(), MaintenanceWitnessCommitError> {
            self.sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let current = self.current.lock().unwrap().clone();
            if current != expected
                || !expected
                    .exact_migration_candidate(&advance, next)
                    .is_ok_and(|exact| exact == candidate)
            {
                return Err(MaintenanceWitnessCommitError::Rejected);
            }
            match self.behavior {
                SendBehavior::CommitThenUnknown => {
                    *self.current.lock().unwrap() = candidate;
                    Err(MaintenanceWitnessCommitError::OutcomeUnknown)
                }
                SendBehavior::DefinitelyFailed => {
                    Err(MaintenanceWitnessCommitError::DefinitelyFailed)
                }
            }
        }
    }

    struct FakePersistence {
        fixture: MigrationFixture,
        reconciles: AtomicUsize,
        manuals: AtomicUsize,
        renewals: AtomicUsize,
        reacquires: AtomicUsize,
    }

    #[async_trait]
    impl ShadowObjectInventory for FakePersistence {
        async fn reserve_exact(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _facts: ShadowObjectFacts,
        ) -> Result<RecordOutcome, ShadowObjectInventoryError> {
            Err(ShadowObjectInventoryError::Unavailable)
        }

        async fn mark_materialized_exact(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _facts: ShadowObjectFacts,
        ) -> Result<RecordOutcome, ShadowObjectInventoryError> {
            Err(ShadowObjectInventoryError::Unavailable)
        }

        async fn load_exact_attempt_page(
            &self,
            _session_id: ShadowSessionId,
            _attempt_id: ShadowAttemptId,
            _binding: ShadowSessionBinding,
            _after_ordinal: Option<u32>,
        ) -> Result<ShadowObjectInventoryPage, ShadowObjectInventoryError> {
            Ok(ShadowObjectInventoryPage::empty())
        }
    }

    #[async_trait]
    impl MaintenanceImportPersistence for FakePersistence {
        fn as_shadow_inventory(&self) -> &dyn ShadowObjectInventory {
            self
        }

        async fn load_exact(
            &self,
            _operation_id: MaintenanceImportOperationId,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }

        async fn ensure_advisory_release_absent(
            &self,
            _operation_id: MaintenanceImportOperationId,
        ) -> Result<(), MaintenanceImportError> {
            Ok(())
        }

        async fn persist_fencing(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _tentative: crate::store::MaintenanceTentativeSource,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }

        async fn persist_fencing_rebase(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _previous: crate::store::MaintenanceTentativeSource,
            _replacement: crate::store::MaintenanceTentativeSource,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }

        async fn persist_pinned_source(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _source: MaintenanceSourceBinding,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }

        async fn persist_witness_and_lease(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _source: MaintenanceSourceBinding,
            _witness: &WitnessRecord,
            _lease: WitnessLease,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }

        async fn prepare_shadow_upload_attempt(
            &self,
            _operation_id: MaintenanceImportOperationId,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }

        async fn prepare_authoritative_upload_attempt(
            &self,
            _operation_id: MaintenanceImportOperationId,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }

        async fn persist_renewed_lease(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _expected_stage: MaintenanceImportStage,
            _previous: &WitnessRecord,
            renewed: &WitnessRecord,
            _lease: WitnessLease,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            self.renewals
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(record(&self.fixture, _expected_stage, renewed))
        }

        async fn persist_reacquired_lease(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _expected_stage: MaintenanceImportStage,
            _previous: &WitnessRecord,
            reacquired: &WitnessRecord,
            _lease: WitnessLease,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            self.reacquires
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(record(&self.fixture, _expected_stage, reacquired))
        }

        async fn persist_phase2_succeeded_lease(
            &self,
            _operation_id: MaintenanceImportOperationId,
            expected_stage: MaintenanceImportStage,
            _previous: &WitnessRecord,
            _basis: Option<&WitnessRecord>,
            succeeded: &WitnessRecord,
            _lease: WitnessLease,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            self.reacquires
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(record(&self.fixture, expected_stage, succeeded))
        }

        async fn persist_manual_required(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _expected_stage: MaintenanceImportStage,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            self.manuals
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(record(
                &self.fixture,
                MaintenanceImportStage::ManualRequired,
                &self.fixture.current,
            ))
        }

        async fn abort_pre_owner(
            &self,
            _operation_id: MaintenanceImportOperationId,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            self.manuals
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(record(
                &self.fixture,
                MaintenanceImportStage::ManualRequired,
                &self.fixture.current,
            ))
        }

        async fn persist_candidate_before_send(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _from: MaintenanceImportStage,
            _candidate: PreparedMaintenanceMigration,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }

        async fn persist_send_unknown(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _from: MaintenanceImportStage,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }

        async fn reconcile_exact_witness(
            &self,
            _operation_id: MaintenanceImportOperationId,
            expected_stage: MaintenanceImportStage,
            observed: &WitnessRecord,
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            self.reconciles
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let next = match expected_stage {
                MaintenanceImportStage::ShadowSendUnknown => MaintenanceImportStage::ShadowWal,
                MaintenanceImportStage::AuthoritativeSendUnknown => {
                    MaintenanceImportStage::WalAuthoritative
                }
                _ => return Err(MaintenanceImportError::Conflict),
            };
            Ok(record(&self.fixture, next, observed))
        }

        async fn persist_parity_verified(
            &self,
            _operation_id: MaintenanceImportOperationId,
            _source: MaintenanceSourceBinding,
            _exact_shadow_witness: &WitnessRecord,
            _parity_commitment: [u8; 32],
        ) -> Result<MaintenanceImportRecord, MaintenanceImportError> {
            Err(MaintenanceImportError::Unavailable)
        }
    }

    fn persistence(fixture: MigrationFixture) -> Arc<FakePersistence> {
        Arc::new(FakePersistence {
            fixture,
            reconciles: AtomicUsize::new(0),
            manuals: AtomicUsize::new(0),
            renewals: AtomicUsize::new(0),
            reacquires: AtomicUsize::new(0),
        })
    }

    #[tokio::test]
    async fn restart_adopts_committed_higher_fence_as_reacquire_not_renewal() {
        let fixture = migration_fixture();
        let observed = fixture.current.reacquired_maintenance_lease_for_test();
        let witness = FakeWitness {
            current: Mutex::new(observed.clone()),
            reads: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            behavior: SendBehavior::DefinitelyFailed,
            revoke_succeeds: false,
        };
        let persistence = persistence(fixture);
        let (adopted, record) = renew_exact_maintenance_lease(
            &witness,
            persistence.as_ref(),
            persistence.fixture.operation_id,
            MaintenanceImportStage::ShadowUploading,
            persistence.fixture.owner_id,
            persistence.fixture.current.clone(),
            observed.clone(),
        )
        .await
        .unwrap();
        assert!(adopted == observed);
        assert_eq!(record.stage(), MaintenanceImportStage::ShadowUploading);
        assert_eq!(
            persistence
                .reacquires
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            persistence
                .renewals
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn retained_send_reconciles_exact_existing_without_resend() {
        let fixture = migration_fixture();
        let retained = record(
            &fixture,
            MaintenanceImportStage::ShadowSendUnknown,
            &fixture.current,
        );
        let witness = Arc::new(FakeWitness {
            current: Mutex::new(fixture.candidate.clone()),
            reads: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            behavior: SendBehavior::DefinitelyFailed,
            revoke_succeeds: false,
        });
        let persistence = persistence(fixture);
        let result = resume_retained_send(
            witness.clone(),
            persistence.clone(),
            persistence.fixture.operation_id,
            retained,
            persistence.fixture.owner_id,
            MigrationState::ShadowWal,
            MaintenanceImportStage::ShadowSendUnknown,
            persistence.fixture.archive_id,
        )
        .await
        .unwrap();
        assert_eq!(result.stage(), MaintenanceImportStage::ShadowWal);
        assert_eq!(witness.sends.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            persistence
                .reconciles
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn lost_send_settles_only_from_exact_candidate_readback() {
        let fixture = migration_fixture();
        let retained = record(
            &fixture,
            MaintenanceImportStage::ShadowSendUnknown,
            &fixture.current,
        );
        let witness = Arc::new(FakeWitness {
            current: Mutex::new(fixture.current.clone()),
            reads: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            behavior: SendBehavior::CommitThenUnknown,
            revoke_succeeds: false,
        });
        let persistence = persistence(fixture);
        let result = resume_retained_send(
            witness.clone(),
            persistence.clone(),
            persistence.fixture.operation_id,
            retained,
            persistence.fixture.owner_id,
            MigrationState::ShadowWal,
            MaintenanceImportStage::ShadowSendUnknown,
            persistence.fixture.archive_id,
        )
        .await
        .unwrap();
        assert_eq!(result.stage(), MaintenanceImportStage::ShadowWal);
        assert_eq!(witness.sends.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn alternate_witness_poisons_operation_before_any_send() {
        let fixture = migration_fixture();
        let retained = record(
            &fixture,
            MaintenanceImportStage::ShadowSendUnknown,
            &fixture.current,
        );
        let alternate = fixture
            .current
            .with_archive_id_for_test(ArchiveId::from_bytes([99; 16]));
        let witness = Arc::new(FakeWitness {
            current: Mutex::new(alternate),
            reads: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            behavior: SendBehavior::DefinitelyFailed,
            revoke_succeeds: false,
        });
        let persistence = persistence(fixture);
        assert_eq!(
            resume_retained_send(
                witness.clone(),
                persistence.clone(),
                persistence.fixture.operation_id,
                retained,
                persistence.fixture.owner_id,
                MigrationState::ShadowWal,
                MaintenanceImportStage::ShadowSendUnknown,
                persistence.fixture.archive_id,
            )
            .await,
            Err(MaintenanceImportError::Conflict)
        );
        assert_eq!(witness.sends.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            persistence
                .manuals
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn terminal_handoff_requires_fresh_exact_release_and_accepts_lost_revoke_response() {
        let fixture = migration_fixture();
        let terminal = fixture
            .candidate
            .with_migration_for_test(MigrationState::WalAuthoritative);
        let durable = terminal_record(&fixture, &terminal);
        let failed = FakeWitness {
            current: Mutex::new(terminal.clone()),
            reads: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            behavior: SendBehavior::DefinitelyFailed,
            revoke_succeeds: false,
        };
        assert!(matches!(
            authenticate_and_release_terminal_witness(
                &durable,
                &failed,
                fixture.owner_id,
                fixture.archive_id,
            )
            .await,
            Err(MaintenanceImportError::Unavailable)
        ));
        assert_eq!(failed.revokes.load(std::sync::atomic::Ordering::SeqCst), 1);

        // A lost commit response is accepted only through the fresh exact
        // no-active-lease read immediately afterward.
        let lost_success = FakeWitness {
            current: Mutex::new(terminal),
            reads: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            behavior: SendBehavior::DefinitelyFailed,
            revoke_succeeds: true,
        };
        let released = authenticate_and_release_terminal_witness(
            &durable,
            &lost_success,
            fixture.owner_id,
            fixture.archive_id,
        )
        .await
        .unwrap();
        assert!(!released.has_exact_active_wal_owner_lease());
        assert_eq!(
            lost_success
                .revokes
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        let reads_before = lost_success.reads.load(std::sync::atomic::Ordering::SeqCst);
        let reopened = authenticate_and_release_terminal_witness(
            &durable,
            &lost_success,
            fixture.owner_id,
            fixture.archive_id,
        )
        .await
        .unwrap();
        assert!(reopened == released);
        assert_eq!(
            lost_success
                .revokes
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            lost_success.reads.load(std::sync::atomic::Ordering::SeqCst),
            reads_before + 2
        );

        let alternate = released.with_archive_id_for_test(ArchiveId::from_bytes([0xee; 16]));
        *lost_success.current.lock().unwrap() = alternate;
        assert!(matches!(
            authenticate_and_release_terminal_witness(
                &durable,
                &lost_success,
                fixture.owner_id,
                fixture.archive_id,
            )
            .await,
            Err(MaintenanceImportError::Conflict)
        ));
    }

    #[tokio::test]
    async fn advisory_handoff_releases_only_exact_shadow_wal_and_reopens_without_resend() {
        let fixture = migration_fixture();
        let durable = advisory_record(&fixture);
        assert!(validate_exact_advisory_control(&durable, &durable, fixture.source).is_ok());

        let failed = FakeWitness {
            current: Mutex::new(fixture.candidate.clone()),
            reads: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            behavior: SendBehavior::DefinitelyFailed,
            revoke_succeeds: false,
        };
        assert!(matches!(
            authenticate_and_release_advisory_witness(
                &durable,
                &failed,
                fixture.owner_id,
                fixture.archive_id,
            )
            .await,
            Err(MaintenanceImportError::Unavailable)
        ));
        assert_eq!(failed.revokes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(failed.sends.load(std::sync::atomic::Ordering::SeqCst), 0);

        // A lost release response is resolved only by the exact fresh
        // no-owner ShadowWal record. Reopen observes that same terminal and
        // performs no second mutation.
        let lost_success = FakeWitness {
            current: Mutex::new(fixture.candidate.clone()),
            reads: AtomicUsize::new(0),
            revokes: AtomicUsize::new(0),
            sends: AtomicUsize::new(0),
            behavior: SendBehavior::DefinitelyFailed,
            revoke_succeeds: true,
        };
        let released = authenticate_and_release_advisory_witness(
            &durable,
            &lost_success,
            fixture.owner_id,
            fixture.archive_id,
        )
        .await
        .unwrap();
        assert_eq!(released.migration(), MigrationState::ShadowWal);
        assert!(!released
            .exact_maintenance_advisory_or_release_from(&fixture.candidate, fixture.owner_id)
            .unwrap());
        assert!(validate_advisory_parity_evidence(&durable, fixture.source, &released).is_ok());
        let reads_before = lost_success.reads.load(std::sync::atomic::Ordering::SeqCst);
        let reopened = authenticate_and_release_advisory_witness(
            &durable,
            &lost_success,
            fixture.owner_id,
            fixture.archive_id,
        )
        .await
        .unwrap();
        assert_eq!(reopened, released);
        assert_eq!(
            lost_success
                .revokes
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            lost_success.reads.load(std::sync::atomic::Ordering::SeqCst),
            reads_before + 2
        );
        assert_eq!(
            lost_success.sends.load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        // Type/state separation is bidirectional: an advisory terminal is not
        // an authority terminal and an authority record is not releasable by
        // the advisory predicate.
        assert!(released
            .exact_maintenance_terminal_or_release_from(&fixture.candidate, fixture.owner_id)
            .is_err());
        let authoritative = fixture
            .candidate
            .with_migration_for_test(MigrationState::WalAuthoritative);
        assert!(authoritative
            .exact_maintenance_advisory_or_release_from(&fixture.candidate, fixture.owner_id)
            .is_err());
    }

    #[test]
    fn source_and_parity_commitments_are_exact_and_schema_zero_is_valid() {
        let fixture = migration_fixture();
        let first = fixture.source;
        let same = source(fixture.archive_id, fixture.operation_id);
        let other = MaintenanceSourceBinding::from_pinned(
            fixture.archive_id,
            fixture.operation_id,
            3,
            [0x31; 32],
            4096,
            0,
            [0x32; 32],
        )
        .unwrap();
        assert_eq!(first, same);
        assert_ne!(first, other);
        assert_eq!(
            maintenance_parity_commitment(first, [0x41; 32]).unwrap(),
            maintenance_parity_commitment(same, [0x41; 32]).unwrap()
        );
        assert_ne!(
            maintenance_parity_commitment(first, [0x41; 32]).unwrap(),
            maintenance_parity_commitment(first, [0x42; 32]).unwrap()
        );
        assert_eq!(
            maintenance_parity_commitment(first, [0; 32]),
            Err(MaintenanceImportError::Corrupt)
        );
    }

    #[test]
    fn persisted_witness_migration_is_exact_for_each_durable_stage() {
        let fixture = migration_fixture();
        let terminal = fixture
            .candidate
            .with_migration_for_test(MigrationState::WalAuthoritative);
        let build = |stage, witnessed: &WitnessRecord, authoritative: Option<&WitnessRecord>| {
            MaintenanceImportRecord::from_control_persistence(
                crate::cp::control_store::MaintenancePersistenceContext::for_test(),
                stage,
                fixture.archive_id,
                fixture.operation_id,
                fixture.owner_id,
                1,
                ShadowAttemptId::from_bytes([12; 16]),
                1,
                [13; 32],
                Some(crate::store::MaintenanceTentativeSource {
                    base_generation: 1,
                    plaintext_hash: [0x31; 32],
                    plaintext_len: 4096,
                    sqlite_schema_version: 0,
                    wrapped_dek_commitment: [0x32; 32],
                }),
                Some(fixture.source),
                Some(witnessed.encode().to_vec()),
                Some(fixture.candidate.encode().to_vec()),
                authoritative.map(|_| [0x45; 32]),
                authoritative.map(|record| record.encode().to_vec()),
            )
        };

        assert!(build(MaintenanceImportStage::ShadowWal, &fixture.candidate, None).is_ok());
        assert!(build(
            MaintenanceImportStage::WalAuthoritative,
            &terminal,
            Some(&terminal)
        )
        .is_ok());
        assert_eq!(
            build(
                MaintenanceImportStage::WalAuthoritative,
                &fixture.candidate,
                Some(&terminal)
            ),
            Err(MaintenanceImportError::Corrupt)
        );
        assert!(build(
            MaintenanceImportStage::ManualRequired,
            &fixture.current,
            None
        )
        .is_ok());
        assert!(build(
            MaintenanceImportStage::ManualRequired,
            &fixture.candidate,
            Some(&terminal)
        )
        .is_ok());
        assert_eq!(
            build(
                MaintenanceImportStage::ManualRequired,
                &terminal,
                Some(&terminal)
            ),
            Err(MaintenanceImportError::Corrupt)
        );
    }

    #[test]
    fn terminal_control_reload_rejects_stale_stage_source_or_full_row() {
        let fixture = migration_fixture();
        let terminal = fixture
            .candidate
            .with_migration_for_test(MigrationState::WalAuthoritative);
        let exact = terminal_record(&fixture, &terminal);
        assert!(validate_exact_terminal_control(&exact, &exact, fixture.source).is_ok());

        let stale_stage = record(
            &fixture,
            MaintenanceImportStage::ShadowWal,
            &fixture.candidate,
        );
        assert!(matches!(
            validate_exact_terminal_control(&exact, &stale_stage, fixture.source),
            Err(MaintenanceImportError::Conflict)
        ));
        let other_source = MaintenanceSourceBinding::from_pinned(
            fixture.archive_id,
            fixture.operation_id,
            3,
            [0x31; 32],
            4096,
            0,
            [0x32; 32],
        )
        .unwrap();
        assert!(matches!(
            validate_exact_terminal_control(&exact, &exact, other_source),
            Err(MaintenanceImportError::Conflict)
        ));
    }

    #[derive(Clone, Copy)]
    enum AdvisoryTerminalTestMode {
        ComparisonReplay,
        AbortCancellation,
        AbortRestartRecovery,
        ReleasedAbort,
        ReleasedAbortCancellation,
        ReleasedAbortRestartRecovery,
        ReleasedAbortLostPrepareResponse,
        ReleasedAbortWinsResumeRace,
        ReleasedResumeWinsAbortRace,
    }

    async fn run_real_sqlite_import_stops_advisory_reopens_and_fences_authority(
        terminal_mode: AdvisoryTerminalTestMode,
    ) {
        use crate::{
            cp::control_store::ControlStore,
            error::EnclaveError,
            store::{tests::FakeGcs, tests::FakeKms, GcsClient, Store},
        };

        let control_gcs = Arc::new(FakeGcs::new());
        let control = Arc::new(ControlStore::new(Arc::new(FakeKms), control_gcs.clone()));
        let user = control
            .upsert_user("maintenance-import-e2e", "maintenance@example.com")
            .await
            .unwrap();
        let plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let archive_id = plan.archive_id;
        let owner_id = plan.owner_id;
        let operation_id = plan.operation_id;

        let legacy_gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(Arc::new(FakeKms), legacy_gcs.clone()));
        store
            .with_user(&user.id, |connection| {
                connection.execute(
                    "INSERT INTO app_metadata(key,value) VALUES('maintenance-e2e','exact')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(&user.id).await.unwrap();

        let database_epoch = DatabaseEpoch::from_bytes([0x72; 16]);
        let key_epoch = KeyEpoch::from_bytes([0x73; 16]);
        let registry_object_id = ObjectId::from_bytes([0x74; 16]);
        let wrapped = b"maintenance-registry-envelope".to_vec();
        let registry_context = KeyRegistryContext::new(archive_id, KeyKind::Archive, key_epoch);
        let plaintext = KeyRegistryPlaintext::encode_archive(
            &registry_context,
            &ArchiveDek::from_bytes([0x75; 32]),
        )
        .unwrap()
        .to_vec();
        let registries = Arc::new(TestRegistry {
            object_id: registry_object_id,
            wrapped: wrapped.clone(),
            plaintext,
        });
        let cipher = resolve_archive_cipher(
            &registry_context,
            registry_object_id,
            Sha256::digest(&wrapped).into(),
            registries.as_ref(),
        )
        .await
        .unwrap();
        let backend = Arc::new(InMemoryImmutableBackend::new());
        let initial_root_id = ObjectId::from_bytes([0x76; 16]);
        let initial_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            initial_root_id,
            None,
        )
        .unwrap();
        let initial_root = ArchiveRoot {
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
        let initial_envelope = cipher
            .seal(&initial_context, &initial_root.encode().unwrap())
            .unwrap();
        backend
            .create_if_absent(initial_context.object_key(), initial_envelope.clone())
            .await
            .unwrap();
        let witness = InMemoryWitness::with_incrementing_clock_for_test(1);
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(
                    database_epoch,
                    key_epoch,
                    RootReference::new(0, initial_root_id, initial_envelope.hash()),
                ),
                KeyRegistryReference::new(
                    key_epoch,
                    0,
                    registry_object_id,
                    Sha256::digest(&wrapped).into(),
                ),
            ))
            .unwrap();
        let witness = Arc::new(InMemoryMaintenanceWitness::with_advisory_outcome_unknown(
            witness,
        ));
        let objects: Arc<dyn ImmutableObjectBackend> = backend;
        let registry_provider: Arc<dyn ExactKeyRegistryProvider> = registries;
        let importer = SingleArchiveMaintenanceImporter::from_test_components(
            archive_id,
            Arc::clone(&objects),
            Arc::clone(&registry_provider),
            witness.clone(),
            Arc::clone(&control),
            Arc::clone(&store),
            plan,
        )
        .unwrap();
        let advisory = SingleArchiveAdvisoryShadowImporter::from_maintenance_importer(importer)
            .run()
            .await
            .unwrap();
        assert_eq!(
            format!("{advisory:?}"),
            "CompletedAdvisoryShadowHandoff(<advisory>)"
        );
        assert_eq!(
            advisory._terminal_witness.migration(),
            MigrationState::ShadowWal
        );
        assert_eq!(advisory._terminal_witness.root().root().sequence(), 1);
        assert!(advisory
            ._terminal_witness
            .exact_active_lease_for_owner(owner_id)
            .is_err());
        assert_eq!(
            advisory._parity.terminal_control.stage(),
            MaintenanceImportStage::ParityVerified
        );
        // The advisory handoff drops its owned Store guards but deliberately
        // retains fail-closed Store/barrier state and the permanent provider
        // fence. An advisory restart reacquires and revalidates the exact
        // legacy source, observes the already-released witness, and remints no
        // serving or release authority.
        // Obtain three restart handoffs before any is allowed to acquire the
        // later live advisory owner; this models restart/lost-local-result
        // recovery without rerunning maintenance after the marker is absent.
        let restart_plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let restart = SingleArchiveAdvisoryShadowImporter::from_maintenance_importer(
            SingleArchiveMaintenanceImporter::from_test_components(
                archive_id,
                Arc::clone(&objects),
                Arc::clone(&registry_provider),
                witness.clone(),
                Arc::clone(&control),
                Arc::clone(&store),
                restart_plan,
            )
            .unwrap(),
        )
        .run()
        .await
        .unwrap();
        let stale_authority_plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let release_restart_plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let release_restart = SingleArchiveAdvisoryShadowImporter::from_maintenance_importer(
            SingleArchiveMaintenanceImporter::from_test_components(
                archive_id,
                Arc::clone(&objects),
                Arc::clone(&registry_provider),
                witness.clone(),
                Arc::clone(&control),
                Arc::clone(&store),
                release_restart_plan,
            )
            .unwrap(),
        )
        .run()
        .await
        .unwrap();
        let resume_restart_plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let mut resume_restart = Some(
            SingleArchiveAdvisoryShadowImporter::from_maintenance_importer(
                SingleArchiveMaintenanceImporter::from_test_components(
                    archive_id,
                    Arc::clone(&objects),
                    Arc::clone(&registry_provider),
                    witness.clone(),
                    Arc::clone(&control),
                    Arc::clone(&store),
                    resume_restart_plan,
                )
                .unwrap(),
            )
            .run()
            .await
            .unwrap(),
        );
        let race_restart_plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let mut race_restart = Some(
            SingleArchiveAdvisoryShadowImporter::from_maintenance_importer(
                SingleArchiveMaintenanceImporter::from_test_components(
                    archive_id,
                    Arc::clone(&objects),
                    Arc::clone(&registry_provider),
                    witness.clone(),
                    Arc::clone(&control),
                    Arc::clone(&store),
                    race_restart_plan,
                )
                .unwrap(),
            )
            .run()
            .await
            .unwrap(),
        );
        assert_eq!(
            restart._terminal_witness.migration(),
            MigrationState::ShadowWal
        );
        assert_eq!(restart._terminal_witness.root().root().sequence(), 1);
        assert!(restart
            ._terminal_witness
            .exact_active_lease_for_owner(owner_id)
            .is_err());
        let canary = control
            .authorize_advisory_canary_for_test(
                operation_id,
                &advisory._terminal_witness,
                [0xa1; 32],
                [0xa2; 32],
            )
            .await
            .unwrap();
        let mut first_owner =
            crate::archive_v3_advisory_owner::start_advisory_owner_for_test(advisory, canary)
                .await
                .unwrap();
        assert_eq!(
            format!("{first_owner:?}"),
            "SingleArchiveAdvisoryOwner(<inactive>)"
        );
        assert!(first_owner.has_exact_capture_target(&user.id, archive_id, operation_id));
        assert!(first_owner.may_heartbeat());
        let first_bound = witness.read_current_exact(archive_id).await.unwrap();
        assert_eq!(first_bound.migration(), MigrationState::ShadowWal);
        assert!(first_bound.exact_active_lease_for_owner(owner_id).is_err());
        first_owner.maintain_lease().await.unwrap();
        let heartbeated = witness.read_current_exact(archive_id).await.unwrap();
        assert!(heartbeated.last_server_tick() > first_bound.last_server_tick());
        assert_eq!(heartbeated.root(), first_bound.root());
        assert_eq!(heartbeated.migration(), MigrationState::ShadowWal);

        // Reopening from the second parity-certified handoff exact-loads the
        // durable bound row. It must not advance the witness fence or issue a
        // second owner acquisition.
        let reopened_canary = control
            .load_advisory_canary_for_test(operation_id)
            .await
            .unwrap();
        let reopened_owner = crate::archive_v3_advisory_owner::start_advisory_owner_for_test(
            restart,
            reopened_canary,
        )
        .await
        .unwrap();
        assert!(!reopened_owner.may_heartbeat());
        assert!(reopened_owner.has_exact_capture_target(&user.id, archive_id, operation_id));
        assert_eq!(
            witness.read_current_exact(archive_id).await.unwrap(),
            heartbeated
        );
        assert_eq!(
            witness
                .advisory_acquires
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            witness
                .advisory_maintains
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        first_owner.maintain_lease().await.unwrap();
        let second_heartbeat = witness.read_current_exact(archive_id).await.unwrap();
        assert!(second_heartbeat.last_server_tick() > heartbeated.last_server_tick());
        assert!(matches!(
            reopened_owner.release_legacy_fence().await,
            Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
        ));
        let marker_name = store.identity_rebind_fence_object_name(&user.id).unwrap();
        let marker_generation = legacy_gcs
            .get_object(&marker_name)
            .await
            .unwrap()
            .generation;
        legacy_gcs.reset_operation_counts();
        legacy_gcs.fail_next_get(EnclaveError::NotFound);
        assert!(matches!(
            first_owner.mark_advisory_fence_delete_started().await,
            Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
        ));
        assert_eq!(legacy_gcs.operation_counts(), (0, 0));
        first_owner
            .mark_advisory_fence_delete_started()
            .await
            .unwrap();
        let marker_metadata =
            legacy_gcs.replace_live_wrapped_dek(&marker_name, "substituted-marker-metadata");
        legacy_gcs.reset_operation_counts();
        assert!(matches!(
            first_owner
                .reconcile_advisory_fence_absence_for_test()
                .await,
            Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
        ));
        assert_eq!(legacy_gcs.operation_counts(), (0, 0));
        assert_eq!(
            legacy_gcs.replace_live_wrapped_dek(&marker_name, &marker_metadata),
            "substituted-marker-metadata"
        );
        let replacement_generation = marker_generation.checked_add(1).unwrap();
        assert_eq!(
            legacy_gcs.replace_live_generation(&marker_name, replacement_generation),
            marker_generation
        );
        legacy_gcs.reset_operation_counts();
        assert!(matches!(
            first_owner
                .reconcile_advisory_fence_absence_for_test()
                .await,
            Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
        ));
        assert_eq!(legacy_gcs.operation_counts(), (0, 0));
        assert_eq!(
            legacy_gcs.replace_live_generation(&marker_name, marker_generation),
            replacement_generation
        );

        // With retained DeleteStarted, even when the exact provider deletion
        // commits but its response is lost, a fresh exact-name read alone
        // authorizes the terminal Control transition.
        legacy_gcs.reset_operation_counts();
        legacy_gcs.fail_next_generation_delete_after_commit(&marker_name, marker_generation);
        let released_owner = first_owner.release_legacy_fence().await.unwrap();
        assert!(released_owner.is_released());
        assert!(released_owner.has_exact_capture_target(&user.id, archive_id, operation_id));
        assert!(matches!(
            legacy_gcs.get_object(&marker_name).await,
            Err(EnclaveError::NotFound)
        ));
        assert_eq!(legacy_gcs.operation_counts(), (0, 1));
        // Provider release alone is never local serving authority.
        assert!(matches!(
            store.with_user(&user.id, |_| Ok(())).await,
            Err(EnclaveError::Auth(_))
        ));
        drop(released_owner);

        // Reopen exact-loads the terminal Control row and performs no second
        // marker read, delete, list, or owner-witness mutation.
        legacy_gcs.reset_operation_counts();
        let live_gets_before_reopen = legacy_gcs.live_get_count();
        let release_canary = control
            .load_advisory_canary_for_test(operation_id)
            .await
            .unwrap();
        let release_reopened = crate::archive_v3_advisory_owner::start_advisory_owner_for_test(
            release_restart,
            release_canary,
        )
        .await
        .unwrap()
        .release_legacy_fence()
        .await
        .unwrap();
        assert!(release_reopened.is_released());
        assert_eq!(legacy_gcs.operation_counts(), (0, 0));
        assert_eq!(legacy_gcs.live_get_count(), live_gets_before_reopen);
        assert!(matches!(
            store.with_user(&user.id, |_| Ok(())).await,
            Err(EnclaveError::Auth(_))
        ));
        witness
            .inner
            .replace_current_for_test(
                second_heartbeat.with_deletion_for_test(DeletionState::Tombstoned),
            )
            .unwrap();
        assert!(matches!(
            release_reopened.resume_local_admission().await,
            Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
        ));
        assert!(matches!(
            store.with_user(&user.id, |_| Ok(())).await,
            Err(EnclaveError::Auth(_))
        ));
        witness
            .inner
            .replace_current_for_test(second_heartbeat.clone())
            .unwrap();

        if matches!(
            terminal_mode,
            AdvisoryTerminalTestMode::ReleasedAbort
                | AdvisoryTerminalTestMode::ReleasedAbortCancellation
                | AdvisoryTerminalTestMode::ReleasedAbortRestartRecovery
                | AdvisoryTerminalTestMode::ReleasedAbortLostPrepareResponse
                | AdvisoryTerminalTestMode::ReleasedAbortWinsResumeRace
                | AdvisoryTerminalTestMode::ReleasedResumeWinsAbortRace
        ) {
            let canary = control
                .load_advisory_canary_for_test(operation_id)
                .await
                .unwrap();
            let released = crate::archive_v3_advisory_owner::start_advisory_owner_for_test(
                resume_restart.take().unwrap(),
                canary,
            )
            .await
            .unwrap()
            .release_legacy_fence()
            .await
            .unwrap();
            let rival = if matches!(
                terminal_mode,
                AdvisoryTerminalTestMode::ReleasedAbortWinsResumeRace
                    | AdvisoryTerminalTestMode::ReleasedResumeWinsAbortRace
            ) {
                let rival_canary = control
                    .load_advisory_canary_for_test(operation_id)
                    .await
                    .unwrap();
                Some(
                    crate::archive_v3_advisory_owner::start_advisory_owner_for_test(
                        race_restart.take().unwrap(),
                        rival_canary,
                    )
                    .await
                    .unwrap(),
                )
            } else {
                None
            };
            legacy_gcs.reset_operation_counts();
            if matches!(
                terminal_mode,
                AdvisoryTerminalTestMode::ReleasedAbortWinsResumeRace
            ) {
                let stale_resume = tokio::spawn(async move {
                    rival
                        .unwrap()
                        .release_legacy_fence()
                        .await?
                        .resume_local_admission()
                        .await
                        .map(|_| ())
                });
                tokio::task::yield_now().await;
                assert!(!stale_resume.is_finished());
                released
                    .prepare_released_abort_for_restart_test()
                    .await
                    .unwrap();
                assert!(
                    stale_resume.await.unwrap().is_err(),
                    "durable Prepared abort must fence a stale resume"
                );
                assert!(matches!(
                    store.with_user(&user.id, |_| Ok(())).await,
                    Err(EnclaveError::Auth(_))
                ));
                drop(store);
                let restarted = Arc::new(Store::new(Arc::new(FakeKms), legacy_gcs.clone()));
                assert_eq!(
                    crate::archive_v3_advisory_owner::reconcile_prepared_abort_for_test(
                        Arc::clone(&control),
                        Arc::clone(&restarted),
                        operation_id,
                    )
                    .await
                    .unwrap(),
                    crate::archive_v3_advisory_owner::AdvisoryAbortStage::Aborted
                );
                restarted.with_user(&user.id, |_| Ok(())).await.unwrap();
                assert_eq!(legacy_gcs.operation_counts(), (0, 0));
                return;
            } else if matches!(
                terminal_mode,
                AdvisoryTerminalTestMode::ReleasedResumeWinsAbortRace
            ) {
                let stale_abort = tokio::spawn(async move {
                    rival
                        .unwrap()
                        .release_legacy_fence()
                        .await?
                        .abort_released_for_test(
                            crate::archive_v3_advisory_owner::AdvisoryAbortReason::StopRequested,
                        )
                        .await
                        .map(|_| ())
                });
                tokio::task::yield_now().await;
                assert!(!stale_abort.is_finished());
                let resumed = released.resume_local_admission().await.unwrap();
                assert!(
                    stale_abort.await.unwrap().is_err(),
                    "installed capture must fence a stale released abort"
                );
                assert_eq!(
                    control
                        .advisory_abort_stage_for_test(operation_id)
                        .await
                        .unwrap(),
                    None,
                    "losing released abort must not write Control"
                );
                let aborted = resumed
                    .abort_for_test(
                        crate::archive_v3_advisory_owner::AdvisoryAbortReason::StopRequested,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    aborted.stage_for_test(),
                    crate::archive_v3_advisory_owner::AdvisoryAbortStage::Aborted
                );
            } else if matches!(
                terminal_mode,
                AdvisoryTerminalTestMode::ReleasedAbortRestartRecovery
            ) {
                released
                    .prepare_released_abort_for_restart_test()
                    .await
                    .unwrap();
                assert_eq!(
                    control
                        .advisory_abort_stage_for_test(operation_id)
                        .await
                        .unwrap(),
                    Some(crate::archive_v3_advisory_owner::AdvisoryAbortStage::Prepared)
                );
                assert!(matches!(
                    store.with_user(&user.id, |_| Ok(())).await,
                    Err(EnclaveError::Auth(_))
                ));
                drop(store);
                let restarted = Arc::new(Store::new(Arc::new(FakeKms), legacy_gcs.clone()));
                assert_eq!(
                    crate::archive_v3_advisory_owner::reconcile_prepared_abort_for_test(
                        Arc::clone(&control),
                        Arc::clone(&restarted),
                        operation_id,
                    )
                    .await
                    .unwrap(),
                    crate::archive_v3_advisory_owner::AdvisoryAbortStage::Aborted
                );
                restarted.with_user(&user.id, |_| Ok(())).await.unwrap();
                assert_eq!(legacy_gcs.operation_counts(), (0, 0));
                return;
            } else if matches!(
                terminal_mode,
                AdvisoryTerminalTestMode::ReleasedAbortCancellation
            ) {
                control
                    .set_advisory_abort_finalize_fault_for_test(true)
                    .await
                    .unwrap();
                let caller = tokio::spawn(async move {
                    released
                        .abort_released_for_test(
                            crate::archive_v3_advisory_owner::AdvisoryAbortReason::StopRequested,
                        )
                        .await
                });
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        if control
                            .advisory_abort_stage_for_test(operation_id)
                            .await
                            .unwrap()
                            == Some(crate::archive_v3_advisory_owner::AdvisoryAbortStage::Prepared)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("released abort must durably prepare before local restoration");
                caller.abort();
                let _ = caller.await;
                control
                    .set_advisory_abort_finalize_fault_for_test(false)
                    .await
                    .unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        if control
                            .advisory_abort_stage_for_test(operation_id)
                            .await
                            .unwrap()
                            == Some(crate::archive_v3_advisory_owner::AdvisoryAbortStage::Aborted)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("caller cancellation must not strand released abort Prepared");
            } else {
                if matches!(
                    terminal_mode,
                    AdvisoryTerminalTestMode::ReleasedAbortLostPrepareResponse
                ) {
                    control_gcs.fail_next_put_after_commit(EnclaveError::Gcs(
                        "lost released-abort prepare response".into(),
                    ));
                }
                let aborted = released
                    .abort_released_for_test(
                        crate::archive_v3_advisory_owner::AdvisoryAbortReason::StopRequested,
                    )
                    .await
                    .unwrap();
                assert!(aborted.is_aborted());
                assert!(aborted.retained_local_restoration());
            }
            assert_eq!(legacy_gcs.operation_counts(), (0, 0));
            store
                .with_user(&user.id, |connection| {
                    connection.execute(
                        "INSERT OR REPLACE INTO app_metadata(key,value) VALUES(?1,?2)",
                        ["released-abort", "legacy-open-without-capture"],
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
            let content_lease = store.acquire_content_write(&user.id).await.unwrap();
            drop(content_lease);
            assert!(matches!(
                control
                    .prepare_archive_v3_maintenance_import(&user.id)
                    .await,
                Err(EnclaveError::Conflict(_))
            ));
            return;
        }

        let resume_canary = control
            .load_advisory_canary_for_test(operation_id)
            .await
            .unwrap();
        let resumed_owner = Arc::new(
            crate::archive_v3_advisory_owner::start_advisory_owner_for_test(
                resume_restart.take().unwrap(),
                resume_canary,
            )
            .await
            .unwrap()
            .release_legacy_fence()
            .await
            .unwrap()
            .resume_local_admission()
            .await
            .unwrap(),
        );
        assert!(resumed_owner.has_exact_resumed_target(&user.id, archive_id, operation_id));
        assert_eq!(legacy_gcs.operation_counts(), (0, 0));
        assert_eq!(legacy_gcs.live_get_count(), live_gets_before_reopen);
        let content_lease = store.acquire_content_write(&user.id).await.unwrap();
        drop(content_lease);
        store
            .with_user(&user.id, |connection| {
                connection.execute(
                    "INSERT OR REPLACE INTO app_metadata(key,value) VALUES(?1,?2)",
                    ["advisory-capture", "exact-user"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let exact_capture_count = resumed_owner
            .captured_commit_count_for_test()
            .await
            .expect("resumed exact user must open through capture VFS");
        assert!(exact_capture_count > 0);
        store
            .with_user("advisory-capture-unselected", |connection| {
                connection.execute(
                    "INSERT INTO app_metadata(key,value) VALUES(?1,?2)",
                    ["advisory-capture", "unselected-user"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            resumed_owner.captured_commit_count_for_test().await,
            Some(exact_capture_count),
            "an unrelated user must never enter the advisory capture stream"
        );
        let capture_drain = resumed_owner.begin_capture_drain_for_test().await.unwrap();
        assert_eq!(
            capture_drain.captured_commit_count_for_test(),
            exact_capture_count
        );
        assert_eq!(
            capture_drain
                .snapshot_metadata_value_for_test("advisory-capture")
                .as_deref(),
            Some("exact-user")
        );
        assert_eq!(
            resumed_owner.captured_commit_count_for_test().await,
            Some(0)
        );
        assert!(resumed_owner.begin_capture_drain_for_test().await.is_err());
        store
            .with_user(&user.id, |connection| {
                connection.execute(
                    "INSERT INTO app_metadata(key,value) VALUES(?1,?2)",
                    ["advisory-capture-later", "exact-user"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let later_capture_count = resumed_owner
            .captured_commit_count_for_test()
            .await
            .expect("later exact-user commit remains in the live capture stream");
        assert!(later_capture_count > 0);
        assert_eq!(
            capture_drain.snapshot_metadata_value_for_test("advisory-capture-later"),
            None,
            "the read transaction must remain pinned before later exact-user commits"
        );
        drop(capture_drain);
        assert_eq!(
            resumed_owner.captured_commit_count_for_test().await,
            Some(exact_capture_count + later_capture_count),
            "cancellation restores only the selected prefix ahead of later commits"
        );

        witness
            .inner
            .replace_current_for_test(
                second_heartbeat.with_deletion_for_test(DeletionState::Tombstoned),
            )
            .unwrap();
        assert!(resumed_owner
            .compare_captured_prefix_for_test()
            .await
            .is_err());
        assert_eq!(
            resumed_owner.captured_commit_count_for_test().await,
            Some(exact_capture_count + later_capture_count),
            "a pre-comparison witness change cannot detach the prefix"
        );
        witness
            .inner
            .replace_current_for_test(second_heartbeat.clone())
            .unwrap();

        let retained_release_commitment = control
            .replace_advisory_release_commitment_for_test(archive_id, [0x91; 32])
            .await
            .unwrap();
        assert!(resumed_owner
            .compare_captured_prefix_for_test()
            .await
            .is_err());
        control
            .replace_advisory_release_commitment_for_test(archive_id, retained_release_commitment)
            .await
            .unwrap();
        let retained_source_commitment = control
            .replace_maintenance_source_commitment_for_test(operation_id, [0x92; 32])
            .await
            .unwrap();
        assert!(resumed_owner
            .compare_captured_prefix_for_test()
            .await
            .is_err());
        control
            .replace_maintenance_source_commitment_for_test(
                operation_id,
                retained_source_commitment,
            )
            .await
            .unwrap();

        let post_boundary_stall = Arc::new(crate::store::AdvisoryComparisonStall::new());
        let post_boundary_task = tokio::spawn({
            let resumed_owner = Arc::clone(&resumed_owner);
            let stall = Arc::clone(&post_boundary_stall);
            async move {
                resumed_owner
                    .compare_captured_prefix_with_stall_for_test(stall)
                    .await
            }
        });
        post_boundary_stall.wait_until_entered().await;
        witness
            .inner
            .replace_current_for_test(
                second_heartbeat.with_deletion_for_test(DeletionState::Tombstoned),
            )
            .unwrap();
        post_boundary_stall.release();
        assert!(post_boundary_task.await.unwrap().is_err());
        assert_eq!(
            resumed_owner.captured_commit_count_for_test().await,
            Some(exact_capture_count + later_capture_count),
            "a post-comparison witness change must fail after atomic restoration"
        );
        witness
            .inner
            .replace_current_for_test(second_heartbeat.clone())
            .unwrap();

        let post_release_stall = Arc::new(crate::store::AdvisoryComparisonStall::new());
        let post_release_task = tokio::spawn({
            let resumed_owner = Arc::clone(&resumed_owner);
            let stall = Arc::clone(&post_release_stall);
            async move {
                resumed_owner
                    .compare_captured_prefix_with_stall_for_test(stall)
                    .await
            }
        });
        post_release_stall.wait_until_entered().await;
        let retained_release_commitment = control
            .replace_advisory_release_commitment_for_test(archive_id, [0x93; 32])
            .await
            .unwrap();
        post_release_stall.release();
        assert!(post_release_task.await.unwrap().is_err());
        control
            .replace_advisory_release_commitment_for_test(archive_id, retained_release_commitment)
            .await
            .unwrap();

        let post_source_stall = Arc::new(crate::store::AdvisoryComparisonStall::new());
        let post_source_task = tokio::spawn({
            let resumed_owner = Arc::clone(&resumed_owner);
            let stall = Arc::clone(&post_source_stall);
            async move {
                resumed_owner
                    .compare_captured_prefix_with_stall_for_test(stall)
                    .await
            }
        });
        post_source_stall.wait_until_entered().await;
        let retained_source_commitment = control
            .replace_maintenance_source_commitment_for_test(operation_id, [0x94; 32])
            .await
            .unwrap();
        post_source_stall.release();
        assert!(post_source_task.await.unwrap().is_err());
        control
            .replace_maintenance_source_commitment_for_test(
                operation_id,
                retained_source_commitment,
            )
            .await
            .unwrap();
        assert_eq!(
            resumed_owner.captured_commit_count_for_test().await,
            Some(exact_capture_count + later_capture_count),
            "post-boundary Control changes must fail only after atomic restoration"
        );

        let cancellation_stall = Arc::new(crate::store::AdvisoryComparisonStall::new());
        let cancelled_task = tokio::spawn({
            let resumed_owner = Arc::clone(&resumed_owner);
            let stall = Arc::clone(&cancellation_stall);
            async move {
                resumed_owner
                    .compare_captured_prefix_with_stall_for_test(stall)
                    .await
            }
        });
        cancellation_stall.wait_until_entered().await;
        cancelled_task.abort();
        cancellation_stall.release();
        let _ = cancelled_task.await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if resumed_owner.captured_commit_count_for_test().await
                    == Some(exact_capture_count + later_capture_count)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the cancellation-owned worker must eventually restore the prefix");

        resumed_owner
            .write_uncaptured_metadata_for_test("advisory-uncaptured", "outside-capture-vfs")
            .await
            .unwrap();
        assert!(resumed_owner
            .compare_captured_prefix_for_test()
            .await
            .is_err());
        assert_eq!(
            resumed_owner.captured_commit_count_for_test().await,
            Some(exact_capture_count + later_capture_count),
            "a parity mismatch cannot settle or lose the selected prefix"
        );
        let store = match terminal_mode {
            AdvisoryTerminalTestMode::AbortCancellation => {
                let resumed_owner = Arc::try_unwrap(resumed_owner)
                    .expect("comparison tasks released the sole owner reference");
                control
                    .set_advisory_abort_finalize_fault_for_test(true)
                    .await
                    .unwrap();
                let abort_started = Arc::new(tokio::sync::Semaphore::new(0));
                let abort_caller = tokio::spawn({
                    let abort_started = Arc::clone(&abort_started);
                    async move {
                        resumed_owner
                            .abort_with_started_for_test(
                                crate::archive_v3_advisory_owner::AdvisoryAbortReason::ComparisonMismatch,
                                abort_started,
                            )
                            .await
                    }
                });
                abort_started
                    .acquire()
                    .await
                    .expect("abort owner start semaphore remains open")
                    .forget();
                abort_caller.abort();
                let _ = abort_caller.await;
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        if control
                            .advisory_abort_stage_for_test(operation_id)
                            .await
                            .unwrap()
                            == Some(crate::archive_v3_advisory_owner::AdvisoryAbortStage::Prepared)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("a failed final readback must retain the durable Prepared terminal");
                control
                    .set_advisory_abort_finalize_fault_for_test(false)
                    .await
                    .unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        if control
                            .advisory_abort_stage_for_test(operation_id)
                            .await
                            .unwrap()
                            == Some(crate::archive_v3_advisory_owner::AdvisoryAbortStage::Aborted)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("caller cancellation must not interrupt the owned abort terminal");
                store
            }
            AdvisoryTerminalTestMode::AbortRestartRecovery => {
                let resumed_owner = Arc::try_unwrap(resumed_owner)
                    .expect("comparison tasks released the sole owner reference");
                resumed_owner
                    .prepare_abort_for_restart_test(
                        crate::archive_v3_advisory_owner::AdvisoryAbortReason::ComparisonMismatch,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    control
                        .advisory_abort_stage_for_test(operation_id)
                        .await
                        .unwrap(),
                    Some(crate::archive_v3_advisory_owner::AdvisoryAbortStage::Prepared)
                );
                assert!(
                    crate::archive_v3_advisory_owner::reconcile_prepared_abort_for_test(
                        Arc::clone(&control),
                        Arc::clone(&store),
                        operation_id,
                    )
                    .await
                    .is_err(),
                    "restart reconciliation must not accept a still-live capture selector"
                );
                drop(store);
                let restarted = Arc::new(Store::new(Arc::new(FakeKms), legacy_gcs.clone()));
                let wrong_operation = MaintenanceImportOperationId::from_control(
                    crate::cp::control_store::MaintenancePersistenceContext::for_test(),
                    [0xf1; 16],
                )
                .unwrap();
                assert!(
                    crate::archive_v3_advisory_owner::prove_prepared_abort_absence_for_test(
                        Arc::clone(&control),
                        Arc::clone(&restarted),
                        wrong_operation,
                    )
                    .await
                    .is_err()
                );

                let retained_source = control
                    .replace_maintenance_source_commitment_for_test(operation_id, [0xf2; 32])
                    .await
                    .unwrap();
                assert!(
                    crate::archive_v3_advisory_owner::prove_prepared_abort_absence_for_test(
                        Arc::clone(&control),
                        Arc::clone(&restarted),
                        operation_id,
                    )
                    .await
                    .is_err()
                );
                control
                    .replace_maintenance_source_commitment_for_test(operation_id, retained_source)
                    .await
                    .unwrap();

                let retained_parity = control
                    .replace_maintenance_parity_commitment_for_test(operation_id, [0xf3; 32])
                    .await
                    .unwrap();
                assert!(
                    crate::archive_v3_advisory_owner::prove_prepared_abort_absence_for_test(
                        Arc::clone(&control),
                        Arc::clone(&restarted),
                        operation_id,
                    )
                    .await
                    .is_err()
                );
                control
                    .replace_maintenance_parity_commitment_for_test(operation_id, retained_parity)
                    .await
                    .unwrap();

                let retained_binding = control
                    .replace_archive_binding_state_for_test(archive_id, "tombstoned")
                    .await
                    .unwrap();
                assert!(
                    crate::archive_v3_advisory_owner::prove_prepared_abort_absence_for_test(
                        Arc::clone(&control),
                        Arc::clone(&restarted),
                        operation_id,
                    )
                    .await
                    .is_err()
                );
                control
                    .replace_archive_binding_state_for_test(archive_id, &retained_binding)
                    .await
                    .unwrap();

                crate::archive_v3_advisory_owner::prove_prepared_abort_absence_for_test(
                    Arc::clone(&control),
                    Arc::clone(&restarted),
                    operation_id,
                )
                .await
                .unwrap();
                restarted.with_user(&user.id, |_| Ok(())).await.unwrap();
                crate::archive_v3_advisory_owner::prove_prepared_abort_absence_for_test(
                    Arc::clone(&control),
                    Arc::clone(&restarted),
                    operation_id,
                )
                .await
                .unwrap();
                let active_write = restarted.acquire_content_write(&user.id).await.unwrap();
                assert!(
                    crate::archive_v3_advisory_owner::prove_prepared_abort_absence_for_test(
                        Arc::clone(&control),
                        Arc::clone(&restarted),
                        operation_id,
                    )
                    .await
                    .is_err(),
                    "an active legacy write must prevent local-absence proof minting"
                );
                drop(active_write);
                control
                    .set_advisory_abort_finalize_fault_for_test(true)
                    .await
                    .unwrap();
                assert!(crate::archive_v3_advisory_owner::finalize_prepared_abort_recovery_once_for_test(
                    Arc::clone(&control),
                    Arc::clone(&restarted),
                    operation_id,
                )
                .await
                .is_err());
                assert_eq!(
                    control
                        .advisory_abort_stage_for_test(operation_id)
                        .await
                        .unwrap(),
                    Some(crate::archive_v3_advisory_owner::AdvisoryAbortStage::Prepared),
                    "late recovery readback corruption must roll back to Prepared"
                );
                control
                    .set_advisory_abort_finalize_fault_for_test(false)
                    .await
                    .unwrap();
                control
                    .set_advisory_abort_recovery_admission_fault_for_test(true)
                    .await
                    .unwrap();
                assert!(crate::archive_v3_advisory_owner::finalize_prepared_abort_recovery_once_for_test(
                    Arc::clone(&control),
                    Arc::clone(&restarted),
                    operation_id,
                )
                .await
                .is_err());
                assert_eq!(
                    control
                        .advisory_abort_stage_for_test(operation_id)
                        .await
                        .unwrap(),
                    Some(crate::archive_v3_advisory_owner::AdvisoryAbortStage::Prepared),
                    "late admission rearm must roll back the abort CAS"
                );
                control
                    .set_advisory_abort_recovery_admission_fault_for_test(false)
                    .await
                    .unwrap();
                let recovery_guard = restarted.lock_user_lifecycle(&user.id).await.unwrap();
                let recovery_started = Arc::new(tokio::sync::Semaphore::new(0));
                let recovery_caller = tokio::spawn({
                    let control = Arc::clone(&control);
                    let restarted = Arc::clone(&restarted);
                    let recovery_started = Arc::clone(&recovery_started);
                    async move {
                        crate::archive_v3_advisory_owner::reconcile_prepared_abort_with_started_for_test(
                            control,
                            restarted,
                            operation_id,
                            recovery_started,
                        )
                        .await
                    }
                });
                recovery_started
                    .acquire()
                    .await
                    .expect("restart recovery semaphore remains open")
                    .forget();
                recovery_caller.abort();
                let _ = recovery_caller.await;
                drop(recovery_guard);
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        if control
                            .advisory_abort_stage_for_test(operation_id)
                            .await
                            .unwrap()
                            == Some(crate::archive_v3_advisory_owner::AdvisoryAbortStage::Aborted)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("caller cancellation must not interrupt restart reconciliation");
                assert_eq!(
                    crate::archive_v3_advisory_owner::reconcile_prepared_abort_for_test(
                        Arc::clone(&control),
                        Arc::clone(&restarted),
                        operation_id,
                    )
                    .await
                    .unwrap(),
                    crate::archive_v3_advisory_owner::AdvisoryAbortStage::Aborted,
                    "exact Aborted replay must perform no second Store mutation"
                );
                restarted
            }
            AdvisoryTerminalTestMode::ComparisonReplay => {
                resumed_owner
                    .delete_uncaptured_metadata_for_test("advisory-uncaptured")
                    .await
                    .unwrap();
                resumed_owner
                    .persist_comparison_without_retirement_for_test()
                    .await
                    .unwrap();
                let resumed_owner = Arc::try_unwrap(resumed_owner)
                    .expect("comparison tasks released the sole owner reference");
                let settled_owner = resumed_owner.settle_comparison_for_test().await.unwrap();
                assert_eq!(
                    format!("{settled_owner:?}"),
                    "SettledSingleArchiveAdvisoryOwner(<inactive>)"
                );
                assert!(settled_owner.capture_is_retired_for_test().await);
                settled_owner
                    .reconcile_capture_retirement_for_test()
                    .await
                    .unwrap();
                store
            }
            AdvisoryTerminalTestMode::ReleasedAbort => unreachable!("handled before resume"),
            AdvisoryTerminalTestMode::ReleasedAbortCancellation => {
                unreachable!("handled before resume")
            }
            AdvisoryTerminalTestMode::ReleasedAbortRestartRecovery => {
                unreachable!("handled before resume")
            }
            AdvisoryTerminalTestMode::ReleasedAbortLostPrepareResponse => {
                unreachable!("handled before resume")
            }
            AdvisoryTerminalTestMode::ReleasedAbortWinsResumeRace => {
                unreachable!("handled before resume")
            }
            AdvisoryTerminalTestMode::ReleasedResumeWinsAbortRace => {
                unreachable!("handled before resume")
            }
        };
        store
            .with_user(&user.id, |connection| {
                connection.execute(
                    "INSERT OR REPLACE INTO app_metadata(key,value) VALUES(?1,?2)",
                    ["advisory-after-retirement", "legacy-still-authoritative"],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        // Selecting the later authority importer against a completed advisory
        // terminal fails closed. A separately reviewed Phase-2 transition
        // must define how it acquires new authority; the advisory type cannot
        // silently continue into R2. Its rejection also cannot re-close either
        // local gate after the exact terminal resume.
        let authority = SingleArchiveMaintenanceImporter::from_test_components(
            archive_id,
            Arc::clone(&objects),
            Arc::clone(&registry_provider),
            witness.clone(),
            Arc::clone(&control),
            Arc::clone(&store),
            stale_authority_plan,
        )
        .unwrap()
        .run()
        .await;
        assert!(matches!(authority, Err(MaintenanceImportError::Conflict)));
        store.with_user(&user.id, |_| Ok(())).await.unwrap();
        let content_lease = store.acquire_content_write(&user.id).await.unwrap();
        drop(content_lease);
        assert!(matches!(
            control
                .prepare_archive_v3_maintenance_import(&user.id)
                .await,
            Err(EnclaveError::Conflict(_))
        ));
        assert!(matches!(
            legacy_gcs.get_object(&marker_name).await,
            Err(EnclaveError::NotFound)
        ));
    }

    fn run_advisory_terminal_test(mode: AdvisoryTerminalTestMode) {
        std::thread::Builder::new()
            .name("advisory-terminal-e2e".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(
                        run_real_sqlite_import_stops_advisory_reopens_and_fences_authority(mode),
                    );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn real_sqlite_import_stops_advisory_reopens_and_fences_authority() {
        run_advisory_terminal_test(AdvisoryTerminalTestMode::ComparisonReplay);
    }

    #[test]
    fn real_sqlite_advisory_mismatch_abort_survives_caller_cancellation() {
        run_advisory_terminal_test(AdvisoryTerminalTestMode::AbortCancellation);
    }

    #[test]
    fn real_sqlite_prepared_abort_reconciles_after_process_local_state_is_lost() {
        run_advisory_terminal_test(AdvisoryTerminalTestMode::AbortRestartRecovery);
    }

    #[test]
    fn real_sqlite_released_abort_reopens_without_capture_or_provider_io() {
        run_advisory_terminal_test(AdvisoryTerminalTestMode::ReleasedAbort);
    }

    #[test]
    fn real_sqlite_released_abort_survives_caller_cancellation() {
        run_advisory_terminal_test(AdvisoryTerminalTestMode::ReleasedAbortCancellation);
    }

    #[test]
    fn real_sqlite_released_prepared_abort_reconciles_after_restart() {
        run_advisory_terminal_test(AdvisoryTerminalTestMode::ReleasedAbortRestartRecovery);
    }

    #[test]
    fn real_sqlite_released_abort_reconciles_lost_prepare_response() {
        run_advisory_terminal_test(AdvisoryTerminalTestMode::ReleasedAbortLostPrepareResponse);
    }

    #[test]
    fn real_sqlite_released_abort_wins_against_stale_resume() {
        run_advisory_terminal_test(AdvisoryTerminalTestMode::ReleasedAbortWinsResumeRace);
    }

    #[test]
    fn real_sqlite_released_resume_wins_against_stale_abort() {
        run_advisory_terminal_test(AdvisoryTerminalTestMode::ReleasedResumeWinsAbortRace);
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Phase2FixtureMode {
        /// Stop with the advisory owner bound but the release, comparison,
        /// and controller retirement still absent.
        BoundOnly,
        /// Drive the full advisory terminal: released at revision 3, settled
        /// comparison, retired controller run.
        Settled,
    }

    struct Phase2AcquisitionFixture {
        control: Arc<crate::cp::control_store::ControlStore>,
        store: Arc<crate::store::Store>,
        objects: Arc<dyn ImmutableObjectBackend>,
        registries: Arc<dyn ExactKeyRegistryProvider>,
        witness: Arc<InMemoryMaintenanceWitness>,
        user_id: String,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        authority_plan: AuthenticatedMaintenanceImportPlan,
        maintenance_fence: String,
        scope_id: [u8; 16],
        clock_ticks: Arc<std::sync::atomic::AtomicU64>,
    }

    /// Real-sqlite advisory fixture for the Phase-2 acquisition transition.
    /// It mirrors the full advisory harness through owner binding and, in
    /// `Settled` mode, drives release, local resume, one captured commit,
    /// comparison settlement, and the durable controller-run retirement whose
    /// row is the acquisition's strongest durable settled-terminal proxy.
    async fn phase2_acquisition_fixture(mode: Phase2FixtureMode) -> Phase2AcquisitionFixture {
        use crate::{
            cp::control_store::ControlStore,
            store::{tests::FakeGcs, tests::FakeKms, Store},
        };

        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let user = control
            .upsert_user("phase2-acquisition-e2e", "phase2@example.com")
            .await
            .unwrap();
        let plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let archive_id = plan.plan_archive_id();
        let operation_id = plan.plan_operation_id();
        // The controller run must be prepared and eligible while the import
        // row still rests at its `prepared` stage.
        control
            .prepare_advisory_controller_run(
                [0x5a; 16],
                &user.id,
                archive_id,
                operation_id,
                [0x5b; 16],
                [0x5c; 32],
            )
            .await
            .unwrap();
        control
            .advance_advisory_controller_eligible(operation_id, 1000, 2000, 1_000_000)
            .await
            .unwrap();

        let legacy_gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(Arc::new(FakeKms), legacy_gcs));
        store
            .with_user(&user.id, |connection| {
                connection.execute(
                    "INSERT INTO app_metadata(key,value) VALUES('phase2-e2e','exact')",
                    [],
                )?;
                connection.execute(
                    "INSERT INTO capture_sessions
                     (id,device_id,install_id,started_at,last_event_at,schema_version)
                     VALUES('phase2-session','phase2-device','phase2-install',
                            '2026-08-19T10:00:00Z','2026-08-19T10:05:00Z',1)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(&user.id).await.unwrap();

        let database_epoch = DatabaseEpoch::from_bytes([0x72; 16]);
        let key_epoch = KeyEpoch::from_bytes([0x73; 16]);
        let registry_object_id = ObjectId::from_bytes([0x74; 16]);
        let wrapped = b"maintenance-registry-envelope".to_vec();
        let registry_context = KeyRegistryContext::new(archive_id, KeyKind::Archive, key_epoch);
        let plaintext = KeyRegistryPlaintext::encode_archive(
            &registry_context,
            &ArchiveDek::from_bytes([0x75; 32]),
        )
        .unwrap()
        .to_vec();
        let registries = Arc::new(TestRegistry {
            object_id: registry_object_id,
            wrapped: wrapped.clone(),
            plaintext,
        });
        let cipher = resolve_archive_cipher(
            &registry_context,
            registry_object_id,
            Sha256::digest(&wrapped).into(),
            registries.as_ref(),
        )
        .await
        .unwrap();
        let backend = Arc::new(InMemoryImmutableBackend::new());
        let initial_root_id = ObjectId::from_bytes([0x76; 16]);
        let initial_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            initial_root_id,
            None,
        )
        .unwrap();
        let initial_root = ArchiveRoot {
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
        let initial_envelope = cipher
            .seal(&initial_context, &initial_root.encode().unwrap())
            .unwrap();
        backend
            .create_if_absent(initial_context.object_key(), initial_envelope.clone())
            .await
            .unwrap();
        let (witness, clock_ticks) = InMemoryWitness::with_shared_incrementing_clock_for_test(1);
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(
                    database_epoch,
                    key_epoch,
                    RootReference::new(0, initial_root_id, initial_envelope.hash()),
                ),
                KeyRegistryReference::new(
                    key_epoch,
                    0,
                    registry_object_id,
                    Sha256::digest(&wrapped).into(),
                ),
            ))
            .unwrap();
        let witness = Arc::new(InMemoryMaintenanceWitness::new(witness));
        let objects: Arc<dyn ImmutableObjectBackend> = backend;
        let registry_provider: Arc<dyn ExactKeyRegistryProvider> = registries;

        let importer = SingleArchiveMaintenanceImporter::from_test_components(
            archive_id,
            Arc::clone(&objects),
            Arc::clone(&registry_provider),
            witness.clone(),
            Arc::clone(&control),
            Arc::clone(&store),
            plan,
        )
        .unwrap();
        let advisory = SingleArchiveAdvisoryShadowImporter::from_maintenance_importer(importer)
            .run()
            .await
            .unwrap();
        // Re-adopt the retained maintenance plan before release permanently
        // fences the advisory door; this is the exact original operation
        // identity the Phase-2 continuation runs with.
        let authority_plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let maintenance_fence = authority_plan.fence_authority().to_owned();

        let canary = control
            .authorize_advisory_canary_for_test(
                operation_id,
                &advisory._terminal_witness,
                [0xa1; 32],
                [0xa2; 32],
            )
            .await
            .unwrap();
        let scope_id = canary.scope_id();
        let owner =
            crate::archive_v3_advisory_owner::start_advisory_owner_for_test(advisory, canary)
                .await
                .unwrap();
        let owner_id_bytes = owner.owner_id_for_test();
        control
            .advance_advisory_controller_imported(operation_id)
            .await
            .unwrap();
        control
            .advance_advisory_controller_authorized(operation_id, scope_id)
            .await
            .unwrap();
        if mode == Phase2FixtureMode::BoundOnly {
            drop(owner);
        } else {
            let released = owner.release_legacy_fence().await.unwrap();
            control
                .advance_advisory_controller_owner_admitted(operation_id, owner_id_bytes)
                .await
                .unwrap();
            let resumed = released.resume_local_admission().await.unwrap();
            store
                .with_user(&user.id, |connection| {
                    connection.execute(
                        "INSERT INTO app_metadata(key,value) VALUES('phase2-capture','exact-user')",
                        [],
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
            let settled = resumed.settle_comparison_for_test().await.unwrap();
            drop(settled);
            let settlement = control
                .load_retained_advisory_comparison_exact(archive_id)
                .await
                .unwrap()
                .unwrap();
            control
                .advance_advisory_controller_retired(operation_id, settlement.evidence_commitment())
                .await
                .unwrap();
        }
        Phase2AcquisitionFixture {
            control,
            store,
            objects,
            registries: registry_provider,
            witness,
            user_id: user.id,
            archive_id,
            operation_id,
            authority_plan,
            maintenance_fence,
            scope_id,
            clock_ticks,
        }
    }

    async fn phase2_terminal_witness_hash(fixture: &Phase2AcquisitionFixture) -> [u8; 32] {
        let current = fixture
            .witness
            .read_current_exact(fixture.archive_id)
            .await
            .unwrap();
        Sha256::digest(current.encode()).into()
    }

    /// Build a Phase-2 statement whose facts are copied from the REAL durable
    /// maintenance-import row (the source and parity commitments are read via
    /// the retaining replace helpers).
    async fn phase2_statement_from_durable(
        fixture: &Phase2AcquisitionFixture,
        terminal_witness_hash: [u8; 32],
    ) -> crate::archive_v3_advisory_owner::ParsedPhase2Statement {
        let source_commitment = fixture
            .control
            .replace_maintenance_source_commitment_for_test(fixture.operation_id, [0xf9; 32])
            .await
            .unwrap();
        fixture
            .control
            .replace_maintenance_source_commitment_for_test(fixture.operation_id, source_commitment)
            .await
            .unwrap();
        let parity_commitment = fixture
            .control
            .replace_maintenance_parity_commitment_for_test(fixture.operation_id, [0xfa; 32])
            .await
            .unwrap();
        fixture
            .control
            .replace_maintenance_parity_commitment_for_test(fixture.operation_id, parity_commitment)
            .await
            .unwrap();
        crate::archive_v3_advisory_owner::ParsedPhase2Statement {
            scope_id: fixture.scope_id,
            user_id_commitment: crate::archive_v3_advisory_owner::scope_user_commitment(
                &fixture.scope_id,
                &fixture.user_id,
            )
            .unwrap(),
            archive_id: fixture.archive_id,
            operation_id: *fixture.operation_id.as_bytes(),
            operation_commitment: fixture.authority_plan.plan_operation_commitment(),
            source_commitment,
            parity_commitment,
            terminal_witness_hash,
            release_image_digest: [0xd7; 32],
        }
    }

    fn phase2_authorization(
        statement: crate::archive_v3_advisory_owner::ParsedPhase2Statement,
        evidence_commitment: [u8; 32],
    ) -> crate::archive_v3_advisory_owner::VerifiedPhase2AuthorityAuthorization {
        let admission = crate::archive_v3_advisory_owner::ParsedPhase2Admission {
            enabled_mutation_set_commitment: [0x31; 32],
            deployment_target_commitment: [0x32; 32],
            maintenance_window_id: [0x33; 16],
            deployment_revision_commitment: [0x34; 32],
            challenge_commitment: [0x35; 32],
            monitoring_policy_commitment: [0x36; 32],
            rollback_policy_commitment: [0x37; 32],
        };
        crate::archive_v3_advisory_owner::VerifiedPhase2AuthorityAuthorization::mint_for_test(
            statement,
            admission,
            evidence_commitment,
        )
    }

    async fn run_phase2_acquisition_succeeds_and_is_idempotent() {
        let fixture = phase2_acquisition_fixture(Phase2FixtureMode::Settled).await;
        let witness_hash = phase2_terminal_witness_hash(&fixture).await;
        let statement = phase2_statement_from_durable(&fixture, witness_hash).await;
        let authorization = phase2_authorization(statement, [0xe1; 32]);
        let (plan, acquisition) = crate::archive_v3_advisory_owner::acquire_phase2_authority(
            fixture.control.as_ref(),
            fixture.store.as_ref(),
            fixture.witness.as_ref(),
            &fixture.user_id,
            &authorization,
        )
        .await
        .unwrap();
        assert_eq!(format!("{plan:?}"), "Phase2AcquiredAuthorityPlan(<opaque>)");
        assert_eq!(
            format!("{acquisition:?}"),
            "Phase2AuthorityAcquisition(<opaque>)"
        );
        let fence = acquisition.acquisition_fence_authority().to_owned();
        assert_eq!(fence.len(), 72);
        assert!(fence.starts_with("archive_"));
        assert!(fence[8..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert_ne!(
            fence, fixture.maintenance_fence,
            "the acquisition fence must be fresh, never the maintenance fence"
        );
        assert_eq!(acquisition.terminal_witness_hash(), witness_hash);

        // A replayed identical authorization re-adopts the existing row.
        let (replayed, created) = fixture
            .control
            .acquire_phase2_authority(&fixture.user_id, authorization.acquisition_evidence())
            .await
            .unwrap();
        assert!(!created);
        assert!(replayed == acquisition);
        let (_replayed_plan, driver_replayed) =
            crate::archive_v3_advisory_owner::acquire_phase2_authority(
                fixture.control.as_ref(),
                fixture.store.as_ref(),
                fixture.witness.as_ref(),
                &fixture.user_id,
                &authorization,
            )
            .await
            .unwrap();
        assert!(driver_replayed == acquisition);

        // The durable row survives full readback validation.
        let loaded = fixture
            .control
            .load_phase2_authority_acquisition(fixture.archive_id)
            .await
            .unwrap()
            .unwrap();
        assert!(loaded == acquisition);
    }

    async fn run_phase2_acquisition_refuses_missing_or_wrong_facts() {
        // A bound advisory owner without release, comparison, or retirement
        // cannot acquire even through the honest driver.
        {
            let fixture = phase2_acquisition_fixture(Phase2FixtureMode::BoundOnly).await;
            let witness_hash = phase2_terminal_witness_hash(&fixture).await;
            let statement = phase2_statement_from_durable(&fixture, witness_hash).await;
            let authorization = phase2_authorization(statement, [0xe1; 32]);
            assert!(matches!(
                crate::archive_v3_advisory_owner::acquire_phase2_authority(
                    fixture.control.as_ref(),
                    fixture.store.as_ref(),
                    fixture.witness.as_ref(),
                    &fixture.user_id,
                    &authorization,
                )
                .await,
                Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
            ));
        }
        // Against the fully settled terminal, a wrong terminal witness hash
        // and a wrong operation commitment refuse, a correct authorization
        // succeeds, and a DIFFERENT later authorization is permanently fenced.
        {
            let fixture = phase2_acquisition_fixture(Phase2FixtureMode::Settled).await;
            let witness_hash = phase2_terminal_witness_hash(&fixture).await;
            let wrong_hash_statement = phase2_statement_from_durable(&fixture, [0x77; 32]).await;
            assert!(matches!(
                crate::archive_v3_advisory_owner::acquire_phase2_authority(
                    fixture.control.as_ref(),
                    fixture.store.as_ref(),
                    fixture.witness.as_ref(),
                    &fixture.user_id,
                    &phase2_authorization(wrong_hash_statement, [0xe1; 32]),
                )
                .await,
                Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
            ));
            let mut wrong_operation = phase2_statement_from_durable(&fixture, witness_hash).await;
            wrong_operation.operation_commitment = [0x66; 32];
            assert!(matches!(
                crate::archive_v3_advisory_owner::acquire_phase2_authority(
                    fixture.control.as_ref(),
                    fixture.store.as_ref(),
                    fixture.witness.as_ref(),
                    &fixture.user_id,
                    &phase2_authorization(wrong_operation, [0xe1; 32]),
                )
                .await,
                Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
            ));
            // The durable scope/user binding refuses a statement for a
            // different canary scope, and (separately) a statement whose
            // user commitment does not match the acquiring user under the
            // real scope.
            let mut wrong_scope = phase2_statement_from_durable(&fixture, witness_hash).await;
            wrong_scope.scope_id = [0x5c; 16];
            wrong_scope.user_id_commitment =
                crate::archive_v3_advisory_owner::scope_user_commitment(
                    &wrong_scope.scope_id,
                    &fixture.user_id,
                )
                .unwrap();
            assert!(matches!(
                crate::archive_v3_advisory_owner::acquire_phase2_authority(
                    fixture.control.as_ref(),
                    fixture.store.as_ref(),
                    fixture.witness.as_ref(),
                    &fixture.user_id,
                    &phase2_authorization(wrong_scope, [0xe1; 32]),
                )
                .await,
                Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
            ));
            let mut wrong_user = phase2_statement_from_durable(&fixture, witness_hash).await;
            wrong_user.user_id_commitment = [0x5d; 32];
            assert!(matches!(
                crate::archive_v3_advisory_owner::acquire_phase2_authority(
                    fixture.control.as_ref(),
                    fixture.store.as_ref(),
                    fixture.witness.as_ref(),
                    &fixture.user_id,
                    &phase2_authorization(wrong_user, [0xe1; 32]),
                )
                .await,
                Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
            ));
            let good = phase2_statement_from_durable(&fixture, witness_hash).await;
            crate::archive_v3_advisory_owner::acquire_phase2_authority(
                fixture.control.as_ref(),
                fixture.store.as_ref(),
                fixture.witness.as_ref(),
                &fixture.user_id,
                &phase2_authorization(good, [0xe1; 32]),
            )
            .await
            .unwrap();
            let different = phase2_statement_from_durable(&fixture, witness_hash).await;
            assert!(matches!(
                crate::archive_v3_advisory_owner::acquire_phase2_authority(
                    fixture.control.as_ref(),
                    fixture.store.as_ref(),
                    fixture.witness.as_ref(),
                    &fixture.user_id,
                    &phase2_authorization(different, [0xe2; 32]),
                )
                .await,
                Err(crate::archive_v3_advisory_owner::AdvisoryOwnerError::Conflict)
            ));
        }
    }

    async fn run_phase2_gated_importer_replaces_absence_predicate() {
        let fixture = phase2_acquisition_fixture(Phase2FixtureMode::Settled).await;
        let witness_hash = phase2_terminal_witness_hash(&fixture).await;
        let statement = phase2_statement_from_durable(&fixture, witness_hash).await;
        let authorization = phase2_authorization(statement, [0xe1; 32]);
        let (_plan, acquisition) = crate::archive_v3_advisory_owner::acquire_phase2_authority(
            fixture.control.as_ref(),
            fixture.store.as_ref(),
            fixture.witness.as_ref(),
            &fixture.user_id,
            &authorization,
        )
        .await
        .unwrap();
        let sealed_plan = || {
            // The test token and the row-vouched token are interchangeable
            // producers of the same sealed plan.
            Phase2AcquiredAuthorityPlan::from_acquisition(
                crate::cp::control_store::Phase2AuthorityPersistenceContext::for_test(),
                &fixture.user_id,
                &acquisition,
            )
            .unwrap()
        };

        // (a) The advisory-fenced run() refuses a Phase-2-constructed importer.
        let importer = SingleArchiveMaintenanceImporter::from_test_components_with_phase2(
            fixture.archive_id,
            Arc::clone(&fixture.objects),
            Arc::clone(&fixture.registries),
            fixture.witness.clone(),
            Arc::clone(&fixture.control),
            Arc::clone(&fixture.store),
            fixture.authority_plan.clone(),
            sealed_plan(),
        )
        .unwrap();
        assert!(matches!(
            importer.run().await,
            Err(MaintenanceImportError::Conflict)
        ));

        // (b) run_phase2 refuses a non-Phase-2 importer.
        let importer = SingleArchiveMaintenanceImporter::from_test_components(
            fixture.archive_id,
            Arc::clone(&fixture.objects),
            Arc::clone(&fixture.registries),
            fixture.witness.clone(),
            Arc::clone(&fixture.control),
            Arc::clone(&fixture.store),
            fixture.authority_plan.clone(),
        )
        .unwrap();
        assert!(matches!(
            importer.run_phase2().await,
            Err(MaintenanceImportError::Conflict)
        ));

        // The plain advisory-fenced authority door remains permanently fenced
        // after release, exactly as before this slice.
        let importer = SingleArchiveMaintenanceImporter::from_test_components(
            fixture.archive_id,
            Arc::clone(&fixture.objects),
            Arc::clone(&fixture.registries),
            fixture.witness.clone(),
            Arc::clone(&fixture.control),
            Arc::clone(&fixture.store),
            fixture.authority_plan.clone(),
        )
        .unwrap();
        assert!(matches!(
            importer.run().await,
            Err(MaintenanceImportError::Conflict)
        ));

        // (c) A tampered (deleted) acquisition fails closed at the pre-lock
        // gate: presence-and-exact-match replaces absence.
        let sealed = sealed_plan();
        fixture
            .control
            .delete_phase2_authority_acquisition_for_test(fixture.archive_id)
            .await
            .unwrap();
        let importer = SingleArchiveMaintenanceImporter::from_test_components_with_phase2(
            fixture.archive_id,
            Arc::clone(&fixture.objects),
            Arc::clone(&fixture.registries),
            fixture.witness.clone(),
            Arc::clone(&fixture.control),
            Arc::clone(&fixture.store),
            fixture.authority_plan.clone(),
            sealed,
        )
        .unwrap();
        assert!(matches!(
            importer.run_phase2().await,
            Err(MaintenanceImportError::Conflict)
        ));
        // The tampered refusal fired at the pre-lock gate: no Store
        // maintenance admission was taken, so the settled exact-user legacy
        // gates remain open.
        fixture
            .store
            .with_user(&fixture.user_id, |_| Ok(()))
            .await
            .unwrap();

        // (d) With the acquisition restored (a fresh mint over the same
        // settled terminal), run_phase2 crosses BOTH former Conflict gates
        // (pre-lock and in-lock), takes the Store maintenance admission —
        // which fail-closed re-blocks the exact-user legacy gates — and
        // revalidates the pinned legacy source. It then stops at the
        // witness-lease succession because the settled advisory owner's
        // lease has not expired at the provider's trusted clock; the
        // full-terminal test below jumps trusted time past the TTL and
        // completes the continuation.
        let (_plan, reacquired) = crate::archive_v3_advisory_owner::acquire_phase2_authority(
            fixture.control.as_ref(),
            fixture.store.as_ref(),
            fixture.witness.as_ref(),
            &fixture.user_id,
            &authorization,
        )
        .await
        .unwrap();
        let sealed = Phase2AcquiredAuthorityPlan::from_acquisition(
            reacquired.persistence_context(),
            &fixture.user_id,
            &reacquired,
        )
        .unwrap();
        let importer = SingleArchiveMaintenanceImporter::from_test_components_with_phase2(
            fixture.archive_id,
            Arc::clone(&fixture.objects),
            Arc::clone(&fixture.registries),
            fixture.witness.clone(),
            Arc::clone(&fixture.control),
            Arc::clone(&fixture.store),
            fixture.authority_plan.clone(),
            sealed,
        )
        .unwrap();
        assert!(matches!(
            importer.run_phase2().await,
            Err(MaintenanceImportError::Conflict)
        ));
        // Unlike the tampered pre-lock refusal above, the intact acquisition
        // provably crossed both gates into the Store admission: the local
        // legacy gates are re-blocked fail-closed.
        assert!(matches!(
            fixture.store.with_user(&fixture.user_id, |_| Ok(())).await,
            Err(crate::error::EnclaveError::Auth(_))
        ));
        assert!(fixture
            .store
            .acquire_content_write(&fixture.user_id)
            .await
            .is_err());
    }

    /// The control-side basis binding: if the live witness moved after the
    /// acquisition was minted (here: an intruding owner leased and expired
    /// across the settled terminal), the succession's fresh basis no longer
    /// hashes to the acquisition's terminal witness hash and the continuation
    /// refuses — the moved archive can never be imported under an authority
    /// minted over a different terminal.
    async fn run_phase2_succession_refuses_a_moved_witness() {
        let fixture = phase2_acquisition_fixture(Phase2FixtureMode::Settled).await;
        let witness_hash = phase2_terminal_witness_hash(&fixture).await;
        let statement = phase2_statement_from_durable(&fixture, witness_hash).await;
        let authorization = phase2_authorization(statement, [0xe1; 32]);
        let (_plan, acquisition) = crate::archive_v3_advisory_owner::acquire_phase2_authority(
            fixture.control.as_ref(),
            fixture.store.as_ref(),
            fixture.witness.as_ref(),
            &fixture.user_id,
            &authorization,
        )
        .await
        .unwrap();
        let sealed = Phase2AcquiredAuthorityPlan::from_acquisition(
            acquisition.persistence_context(),
            &fixture.user_id,
            &acquisition,
        )
        .unwrap();
        // Move the witness after the mint: an intruder leases the settled
        // terminal once its advisory TTL expires, then that lease expires
        // too, so the driver-side acquire succeeds over a basis whose bytes
        // differ from the acquisition's frozen terminal.
        fixture
            .clock_ticks
            .store(1_000_000, std::sync::atomic::Ordering::SeqCst);
        let current = fixture
            .witness
            .read_current_exact(fixture.archive_id)
            .await
            .unwrap();
        fixture
            .witness
            .inner
            .acquire_lease(
                fixture.archive_id,
                current.database_epoch(),
                current.registry().key_epoch(),
                ObjectId::from_bytes([0x99; 16]),
                10,
            )
            .unwrap();
        fixture
            .clock_ticks
            .store(2_000_000, std::sync::atomic::Ordering::SeqCst);
        let importer = SingleArchiveMaintenanceImporter::from_test_components_with_phase2(
            fixture.archive_id,
            Arc::clone(&fixture.objects),
            Arc::clone(&fixture.registries),
            fixture.witness.clone(),
            Arc::clone(&fixture.control),
            Arc::clone(&fixture.store),
            fixture.authority_plan.clone(),
            sealed,
        )
        .unwrap();
        assert!(matches!(
            importer.run_phase2().await,
            Err(MaintenanceImportError::Conflict)
        ));
        // The refusal left the durable authority untouched: the acquisition
        // row is intact and the import row never left its settled stage.
        let retained = fixture
            .control
            .load_phase2_authority_acquisition(fixture.archive_id)
            .await
            .unwrap();
        assert!(retained.is_some());
        let terminal = fixture
            .witness
            .read_current_exact(fixture.archive_id)
            .await
            .unwrap();
        assert_eq!(terminal.migration(), MigrationState::ShadowWal);
    }

    /// Full Phase-2 continuation to the `WalAuthoritative` terminal: the
    /// acquisition gates, Store admission, and pinned-source revalidation
    /// pass, the maintenance owner succeeds the settled advisory owner's
    /// expired witness lease through `succeed_phase2_maintenance_lease`
    /// (trusted time jumped past the settled owner's TTL, exactly like the
    /// operator's real cutover waits it out), and the R2 continuation then
    /// drives the witness to its durable `WalAuthoritative` terminal.
    async fn run_phase2_full_terminal_after_lease_succession() {
        let fixture = phase2_acquisition_fixture(Phase2FixtureMode::Settled).await;
        let witness_hash = phase2_terminal_witness_hash(&fixture).await;
        let statement = phase2_statement_from_durable(&fixture, witness_hash).await;
        let authorization = phase2_authorization(statement, [0xe1; 32]);
        let (_plan, acquisition) = crate::archive_v3_advisory_owner::acquire_phase2_authority(
            fixture.control.as_ref(),
            fixture.store.as_ref(),
            fixture.witness.as_ref(),
            &fixture.user_id,
            &authorization,
        )
        .await
        .unwrap();
        let sealed = Phase2AcquiredAuthorityPlan::from_acquisition(
            acquisition.persistence_context(),
            &fixture.user_id,
            &acquisition,
        )
        .unwrap();
        // The settled advisory owner's witness lease must expire at the
        // provider's trusted clock before the succession can acquire; jump
        // trusted time past it, exactly like the operator's real cutover
        // waits out the settled owner's TTL.
        fixture
            .clock_ticks
            .store(1_000_000, std::sync::atomic::Ordering::SeqCst);
        let handoff = SingleArchiveMaintenanceImporter::from_test_components_with_phase2(
            fixture.archive_id,
            Arc::clone(&fixture.objects),
            Arc::clone(&fixture.registries),
            fixture.witness.clone(),
            Arc::clone(&fixture.control),
            Arc::clone(&fixture.store),
            fixture.authority_plan.clone(),
            sealed,
        )
        .unwrap()
        .run_phase2()
        .await
        .unwrap();
        assert_eq!(
            format!("{handoff:?}"),
            "CompletedMaintenanceWalHandoff(<offline>)"
        );
        let run_terminal_witness = handoff.terminal_witness.clone();
        let run_operation_id = handoff.parity.operation_id_for_wal_owner(
            crate::archive_v3_wal_owner::WalOwnerStoreContext::for_test(),
        );
        drop(handoff);
        let terminal = fixture
            .witness
            .read_current_exact(fixture.archive_id)
            .await
            .unwrap();
        assert_eq!(terminal.migration(), MigrationState::WalAuthoritative);

        // Restart: the in-run handoff is gone. Reconstruct it from durable
        // state alone with a fresh runtime, launch the serving authority
        // through the real publisher owner-acquisition against the live
        // Control and witness, and prove the recovered authoritative
        // database serves settled reads — including the exact pre-import
        // capture row — through the settled-only read surface.
        let restart_runtime =
            crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle::from_maintenance_test_components(
                Arc::clone(&fixture.objects),
                Arc::clone(&fixture.registries),
                fixture.witness.clone(),
            );
        let restart_binding =
            crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding::from_control_store(
                crate::cp::control_store::ArchiveBinding::for_runtime_test(fixture.archive_id),
            );
        let reconstructed = CompletedMaintenanceWalHandoff::reconstruct_from_durable(
            restart_runtime,
            restart_binding,
            Arc::clone(&fixture.control),
            fixture.operation_id,
        )
        .await
        .unwrap();
        // The durable reconstruction carries no Store fence (startup-installed
        // selections replace it across restarts) and reproduces the in-run
        // handoff's evidence byte-exactly: the same released terminal witness
        // and the same maintenance operation identity, revalidated through
        // the identical terminal-parity checks the run used.
        assert!(reconstructed.store_fence.is_none());
        // Identical released terminal modulo trusted time: the derivation
        // preserves the retained row's tick while the in-run release read the
        // provider clock at release time.
        assert_eq!(
            reconstructed.terminal_witness.root(),
            run_terminal_witness.root()
        );
        assert_eq!(
            reconstructed.terminal_witness.migration(),
            MigrationState::WalAuthoritative
        );
        assert!(reconstructed
            .terminal_witness
            .exact_active_lease_for_owner(ObjectId::from_bytes([0x5d; 16]))
            .is_err());
        assert!(
            reconstructed.terminal_witness.last_server_tick()
                <= run_terminal_witness.last_server_tick()
        );
        assert_eq!(
            reconstructed.parity.operation_id_for_wal_owner(
                crate::archive_v3_wal_owner::WalOwnerStoreContext::for_test()
            ),
            run_operation_id
        );

        // First full launch through the REAL publisher: reconstruct again
        // with a publisher-capable runtime over the shared protocol-faithful
        // Firestore fake, seeded byte-exactly with the derived released
        // terminal the handoff carries (the publisher requires the live
        // record to equal it before the first owner acquire). The launch
        // drives owner reservation, the durable send marker, the fake-CAS
        // lease acquire, and the lane recovery of the authoritative
        // database, and the settled-only read then serves the exact row the
        // pinned legacy generation carried into the archive (the later
        // capture-window write stayed a dirty local fact by design).
        let terminal_row = MaintenanceImportPersistence::load_exact(
            fixture.control.as_ref(),
            fixture.operation_id,
        )
        .await
        .unwrap();
        let seed = terminal_row
            .witnessed_record()
            .unwrap()
            .unwrap()
            .derived_maintenance_terminal_release(terminal_row.owner_id)
            .unwrap();
        let transport = Arc::new(
            crate::archive_v3_firestore_witness::test_transport::FakeTransport::new(
                Some(seed.encode()),
                [],
            ),
        );
        let firestore = Arc::new(
            crate::archive_v3_firestore_shadow::FirestoreShadowWitness::from_witness_for_test(
                Arc::new(
                    crate::archive_v3_firestore_witness::test_transport::witness_over_fake(
                        Arc::clone(&transport),
                    ),
                ),
            ),
        );
        let launch_runtime =
            crate::archive_v3_shadow_runtime::ArchiveV3ShadowRuntimeBundle::from_publisher_test_components(
                Arc::clone(&fixture.objects),
                Arc::clone(&fixture.registries),
                fixture.witness.clone(),
                firestore,
            );
        let launch_binding =
            crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding::from_control_store(
                crate::cp::control_store::ArchiveBinding::for_runtime_test(fixture.archive_id),
            );
        let launch_handoff = CompletedMaintenanceWalHandoff::reconstruct_from_durable(
            launch_runtime,
            launch_binding,
            Arc::clone(&fixture.control),
            fixture.operation_id,
        )
        .await
        .unwrap();
        let serving = Arc::new(
            crate::archive_v3_wal_owner::SingleArchiveWalServingAuthority::launch(launch_handoff)
                .await
                .unwrap(),
        );
        let captured = serving
            .read(|connection| {
                let value: String = connection.query_row(
                    "SELECT value FROM app_metadata WHERE key='phase2-e2e'",
                    [],
                    |row| row.get(0),
                )?;
                Ok(value)
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(captured, "exact");

        // The Store's own routed read serves the lane for the selected user
        // — the production read API end-to-end over WAL-authoritative data —
        // while every legacy-path read refuses rather than serving the stale
        // snapshot.
        fixture
            .store
            .install_wal_authority_persistence(
                crate::cp::control_store::WalAuthoritativePersistenceSelection::for_test(
                    &fixture.user_id,
                    fixture.archive_id,
                ),
            )
            .unwrap();
        fixture
            .store
            .install_wal_serving_authority(&fixture.user_id, Arc::clone(&serving))
            .unwrap();
        let routed: String = fixture
            .store
            .wal_authoritative_read(&fixture.user_id, |connection| {
                Ok(connection.query_row(
                    "SELECT value FROM app_metadata WHERE key='phase2-e2e'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(routed, "exact");
        assert!(fixture
            .store
            .with_user(&fixture.user_id, |_| Ok(()))
            .await
            .is_err());

        // Domain routing (media capture-session-finish): the sealed plan
        // settles through the launched authority via the Store's submit
        // surface — acknowledged only after witness settlement — an
        // identical second submit replays the exact retained outcome, the
        // routed read observes the settled end, and a plan for an absent
        // session refuses as a retryable Conflict.
        let finish = crate::cp::media::wal::CaptureSessionFinishPlan::new_for_wal_e2e(
            "phase2-session".to_owned(),
        )
        .unwrap();
        let prepared =
            crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(finish).unwrap();
        let outcome = fixture
            .store
            .wal_authoritative_submit(&fixture.user_id, prepared)
            .await
            .unwrap();
        let ended_at = outcome.ended_at_for_wal_e2e().to_owned();
        assert!(!ended_at.is_empty());
        let replay = crate::cp::media::wal::CaptureSessionFinishPlan::new_for_wal_e2e(
            "phase2-session".to_owned(),
        )
        .unwrap();
        let prepared =
            crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(replay).unwrap();
        let replayed = fixture
            .store
            .wal_authoritative_submit(&fixture.user_id, prepared)
            .await
            .unwrap();
        assert_eq!(replayed.ended_at_for_wal_e2e(), ended_at);
        let observed: Option<String> = fixture
            .store
            .wal_authoritative_read(&fixture.user_id, |conn| {
                use rusqlite::OptionalExtension as _;
                Ok(conn
                    .query_row(
                        "SELECT ended_at FROM capture_sessions WHERE id='phase2-session'",
                        [],
                        |row| row.get(0),
                    )
                    .optional()?)
            })
            .await
            .unwrap();
        assert_eq!(observed.as_deref(), Some(ended_at.as_str()));
        let absent = crate::cp::media::wal::CaptureSessionFinishPlan::new_for_wal_e2e(
            "phase2-missing".to_owned(),
        )
        .unwrap();
        let prepared =
            crate::archive_v3_wal_idempotency::PreparedLogicalMutation::prepare(absent).unwrap();
        assert!(matches!(
            fixture
                .store
                .wal_authoritative_submit(&fixture.user_id, prepared)
                .await,
            Err(crate::error::EnclaveError::Conflict(_))
        ));
    }

    #[test]
    fn phase2_succession_refuses_a_moved_witness() {
        std::thread::Builder::new()
            .name("phase2-moved-witness-e2e".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run_phase2_succession_refuses_a_moved_witness());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn phase2_run_reaches_wal_authoritative_after_lease_succession() {
        std::thread::Builder::new()
            .name("phase2-terminal-e2e".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run_phase2_full_terminal_after_lease_succession());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn phase2_acquisition_succeeds_only_from_fully_settled_terminal_and_is_idempotent() {
        std::thread::Builder::new()
            .name("phase2-acquisition-e2e".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run_phase2_acquisition_succeeds_and_is_idempotent());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn phase2_acquisition_refuses_missing_or_wrong_facts() {
        std::thread::Builder::new()
            .name("phase2-refusal-e2e".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run_phase2_acquisition_refuses_missing_or_wrong_facts());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn phase2_gated_importer_replaces_absence_predicate_exactly() {
        std::thread::Builder::new()
            .name("phase2-gate-e2e".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run_phase2_gated_importer_replaces_absence_predicate());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[tokio::test]
    async fn real_sqlite_pre_owner_abort_cleans_marker_and_restores_legacy_access() {
        use crate::{
            cp::control_store::ControlStore,
            store::{tests::FakeGcs, tests::FakeKms, GcsClient, Store},
        };

        let control_gcs = Arc::new(FakeGcs::new());
        let control = Arc::new(ControlStore::new(Arc::new(FakeKms), control_gcs.clone()));
        let user = control
            .upsert_user("pre-owner-e2e", "preowner@example.com")
            .await
            .unwrap();
        let plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let (_, archive_id, operation_id, fence_authority) = plan.components_for_test();
        let fence_authority = fence_authority.to_string();

        let legacy_gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(Arc::new(FakeKms), legacy_gcs.clone()));
        store
            .with_user(&user.id, |connection| {
                connection.execute(
                    "INSERT INTO screenshots (captured_at, ocr_text) VALUES (?1, ?2)",
                    ["2026-08-13T12:00:00Z", "pre-owner-legacy-data"],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(&user.id).await.unwrap();

        // 1. Begin maintenance and fence
        let admission = store
            .acquire_archive_maintenance_admission(MaintenanceCoordinatorContext::for_test(), plan)
            .await
            .unwrap();
        let mut transition = admission.begin().await;
        let tentative = transition.tentative_source().await.unwrap();
        let _ = control
            .persist_fencing(operation_id, tentative)
            .await
            .unwrap();
        let pinned = match transition.fence_and_pin(tentative).await.unwrap() {
            crate::store::MaintenanceFenceAndPin::Pinned(pinned) => pinned,
            _ => panic!("unexpected rebase"),
        };
        let _ = control
            .persist_pinned_source(operation_id, pinned.source_binding())
            .await
            .unwrap();
        drop(pinned);

        // Marker exists on GCS and Store gates are blocked
        let marker_name = store.identity_rebind_fence_object_name(&user.id).unwrap();
        assert!(legacy_gcs.get_object(&marker_name).await.is_ok());
        assert!(store.with_user(&user.id, |_| Ok(())).await.is_err());

        // 2. Perform pre-owner abort
        SingleArchiveMaintenanceImporter::abort_pre_owner(
            &store,
            &control,
            &user.id,
            archive_id,
            operation_id,
            &fence_authority,
        )
        .await
        .unwrap();

        // 3. Verify marker is deleted from GCS and Store gates are unblocked
        assert!(matches!(
            legacy_gcs.get_object(&marker_name).await,
            Err(crate::error::EnclaveError::NotFound)
        ));
        store
            .with_user(&user.id, |connection| {
                connection.execute(
                    "INSERT INTO app_metadata(key,value) VALUES('pre-owner-aborted','clean')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let write_lease = store.acquire_content_write(&user.id).await.unwrap();
        drop(write_lease);
    }

    #[tokio::test]
    async fn real_sqlite_authority_import_still_reaches_two_exact_roots_offline() {
        use crate::{
            cp::control_store::ControlStore,
            store::{tests::FakeGcs, tests::FakeKms, Store},
        };

        let control = Arc::new(ControlStore::new(
            Arc::new(FakeKms),
            Arc::new(FakeGcs::new()),
        ));
        let user = control
            .upsert_user("maintenance-authority-e2e", "authority@example.com")
            .await
            .unwrap();
        let plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let archive_id = plan.archive_id;
        let owner_id = plan.owner_id;

        let legacy_gcs = Arc::new(FakeGcs::new());
        let store = Arc::new(Store::new(Arc::new(FakeKms), legacy_gcs));
        store
            .with_user(&user.id, |connection| {
                connection.execute(
                    "INSERT INTO app_metadata(key,value) VALUES('authority-e2e','exact')",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store.save_user(&user.id).await.unwrap();

        let database_epoch = DatabaseEpoch::from_bytes([0x82; 16]);
        let key_epoch = KeyEpoch::from_bytes([0x83; 16]);
        let registry_object_id = ObjectId::from_bytes([0x84; 16]);
        let wrapped = b"authority-registry-envelope".to_vec();
        let registry_context = KeyRegistryContext::new(archive_id, KeyKind::Archive, key_epoch);
        let plaintext = KeyRegistryPlaintext::encode_archive(
            &registry_context,
            &ArchiveDek::from_bytes([0x85; 32]),
        )
        .unwrap()
        .to_vec();
        let registries = Arc::new(TestRegistry {
            object_id: registry_object_id,
            wrapped: wrapped.clone(),
            plaintext,
        });
        let cipher = resolve_archive_cipher(
            &registry_context,
            registry_object_id,
            Sha256::digest(&wrapped).into(),
            registries.as_ref(),
        )
        .await
        .unwrap();
        let backend = Arc::new(InMemoryImmutableBackend::new());
        let initial_root_id = ObjectId::from_bytes([0x86; 16]);
        let initial_context = ObjectContext::new(
            archive_id,
            database_epoch,
            key_epoch,
            ObjectRole::RootV3,
            LogicalLocation::Root { root_seq: 0 },
            initial_root_id,
            None,
        )
        .unwrap();
        let initial_root = ArchiveRoot {
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
        let initial_envelope = cipher
            .seal(&initial_context, &initial_root.encode().unwrap())
            .unwrap();
        backend
            .create_if_absent(initial_context.object_key(), initial_envelope.clone())
            .await
            .unwrap();
        let witness = InMemoryWitness::with_incrementing_clock_for_test(1);
        witness
            .bootstrap(WitnessBootstrap::new(
                archive_id,
                database_epoch,
                RootCommitment::genesis(
                    database_epoch,
                    key_epoch,
                    RootReference::new(0, initial_root_id, initial_envelope.hash()),
                ),
                KeyRegistryReference::new(
                    key_epoch,
                    0,
                    registry_object_id,
                    Sha256::digest(&wrapped).into(),
                ),
            ))
            .unwrap();
        let witness = Arc::new(InMemoryMaintenanceWitness::new(witness));
        let objects: Arc<dyn ImmutableObjectBackend> = backend;
        let registry_provider: Arc<dyn ExactKeyRegistryProvider> = registries;
        let handoff = SingleArchiveMaintenanceImporter::from_test_components(
            archive_id,
            Arc::clone(&objects),
            Arc::clone(&registry_provider),
            witness.clone(),
            Arc::clone(&control),
            Arc::clone(&store),
            plan,
        )
        .unwrap()
        .run()
        .await
        .unwrap();
        assert!(handoff
            .store_fence
            .as_ref()
            .unwrap()
            .scratch_family_absent_for_test());
        let terminal = witness.read_current_exact(archive_id).await.unwrap();
        assert_eq!(terminal.migration(), MigrationState::WalAuthoritative);
        assert_eq!(terminal.root().root().sequence(), 2);
        assert_eq!(terminal.root().parent().unwrap().sequence(), 1);
        assert!(terminal.exact_active_lease_for_owner(owner_id).is_err());

        let blocked_plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let blocked = store.acquire_archive_maintenance_admission(
            MaintenanceCoordinatorContext::for_test(),
            blocked_plan,
        );
        assert!(tokio::time::timeout(Duration::from_millis(25), blocked)
            .await
            .is_err());

        drop(handoff);
        let restart_plan = control
            .prepare_archive_v3_maintenance_import(&user.id)
            .await
            .unwrap();
        let restart = SingleArchiveMaintenanceImporter::from_test_components(
            archive_id,
            objects,
            registry_provider,
            witness.clone(),
            control,
            store,
            restart_plan,
        )
        .unwrap()
        .run()
        .await
        .unwrap();
        assert!(restart
            .store_fence
            .as_ref()
            .unwrap()
            .scratch_family_absent_for_test());
        assert!(witness
            .read_current_exact(archive_id)
            .await
            .unwrap()
            .exact_active_lease_for_owner(owner_id)
            .is_err());
        let owner_view =
            restart.into_wal_owner(crate::archive_v3_wal_owner::WalOwnerStoreContext::for_test());
        let retained_terminal = MaintenanceImportPersistence::load_exact(
            owner_view.control.as_ref(),
            owner_view.parity.operation_id_for_wal_owner(
                crate::archive_v3_wal_owner::WalOwnerStoreContext::for_test(),
            ),
        )
        .await
        .unwrap();
        owner_view
            .parity
            .reauthenticate_for_wal_owner(
                crate::archive_v3_wal_owner::WalOwnerStoreContext::for_test(),
                &retained_terminal,
                &owner_view.terminal_witness,
            )
            .unwrap();
        assert_eq!(
            owner_view.terminal_witness.migration(),
            MigrationState::WalAuthoritative
        );
        assert!(owner_view
            .store_fence
            .as_ref()
            .unwrap()
            .scratch_family_absent_for_test());
    }

    #[test]
    fn maintenance_surface_is_inactive_redacted_and_has_no_delete_or_list() {
        let source = include_str!("archive_v3_maintenance_import.rs");
        let runtime = include_str!("archive_v3_shadow_runtime.rs");
        let main = include_str!("main.rs");
        for forbidden in [
            concat!("impl Clone", " for AuthenticatedMaintenanceImportPlan"),
            concat!("impl Clone", " for CompletedMaintenanceWalHandoff"),
            concat!("impl Copy", " for CompletedMaintenanceWalHandoff"),
            concat!("impl Clone", " for CompletedAdvisoryShadowHandoff"),
            concat!("impl Copy", " for CompletedAdvisoryShadowHandoff"),
            concat!("pub(crate) fn user_", "id"),
            concat!("pub(crate) fn archive_", "id"),
            concat!("pub(crate) fn terminal_", "witness"),
            concat!("pub(crate) fn provider", "s"),
            concat!("delete_", "exact"),
            concat!("enumer", "ate("),
            concat!("list_", "objects"),
            concat!("WalLogical", "Only"),
            concat!("std::env", "::"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
        for forbidden in [
            concat!("SingleArchiveMaintenance", "Importer"),
            concat!("prepare_archive_v3_maintenance", "_import"),
            concat!("into_maintenance", "_importer"),
        ] {
            assert!(!main.contains(forbidden), "production wiring: {forbidden}");
        }
        assert!(source.contains(concat!("tokio::spawn(self.run_", "owned(")));
        assert!(source.contains(concat!("MaintenanceImportTarget::Advisory", "Shadow")));
        // Deliberate ADR-0022 Phase-2 sibling pin: WalAuthoritative may be
        // selected by exactly the two known run_owned spawn expressions — the
        // advisory-fenced run() and the acquisition-gated run_phase2(). A
        // third selection site requires deliberately updating this count.
        assert_eq!(
            source
                .matches(concat!(
                    "run_owned(MaintenanceImportTarget::Wal",
                    "Authoritative"
                ))
                .count(),
            2
        );
        assert!(source.contains(concat!("release_advisory_lease_", "unresolved")));
        assert!(source.contains(concat!("exact_maintenance_advisory_or_", "release_from")));
        assert!(source.contains(concat!("into_wal_", "owner(")));
        assert!(source.contains(concat!("WalOwnerStore", "Context")));
        assert_eq!(
            source
                .matches(concat!(
                    "persistence\n        .load_exact(expected_durable.",
                    "operation_id)\n        .await?"
                ))
                .count(),
            4
        );
        assert!(source.contains(concat!("exact_maintenance_terminal_or_", "release_from")));
        assert!(source.contains(concat!("release_terminal_lease_", "unresolved")));
        assert!(source.contains(concat!("into_wal_authority_", "fence")));
        assert!(source.contains(concat!("ShadowParityVerifier::compare_", "staged_copies")));
        assert!(source.contains(concat!("MigrationState::Wal", "Authoritative")));
        assert!(!runtime.contains(concat!("impl Clone for ArchiveV3ShadowRuntime", "Bundle")));
        assert!(runtime.contains(concat!("_token: &MaintenanceRuntime", "Context")));
        assert!(runtime.contains(concat!("fn maintenance_objects_", "owned(")));
        assert!(!runtime.contains(concat!("pub(crate) fn ", "objects(")));
        assert!(source.contains(concat!("Arc::clone(&", "objects)")));
        assert_eq!(source.matches(concat!("fn into_wal_", "owner(")).count(), 1);
    }
}
