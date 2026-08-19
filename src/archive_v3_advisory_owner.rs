#![allow(
    dead_code,
    reason = "inactive ADR-0022 Phase-1 advisory owner is compiled before Store/startup wiring"
)]

//! Inactive, Phase-1-only owner lease lifecycle for one advisory `ShadowWal`
//! archive. The state machine authenticates the parity-certified maintenance
//! handoff and one exact operator-selected canary capability, atomically
//! consumes that scope while reserving one random owner, records `SendStarted` before the
//! initial witness transaction, and adopts only exact one-step acquisition,
//! heartbeat, or post-expiry reacquire successors. It is deliberately separate
//! from the `WalAuthoritative` publisher. It retains one sealed exact-user
//! Store target and exposes no root, object, cipher, acknowledgement, route,
//! task, configuration, or serving capability. A separate inactive
//! release path lets only that target observe and delete its one permanent
//! marker after Control durably freezes the owner. Provider confirmation leaves
//! local gates closed; a second consuming terminal transition freshly
//! reauthenticates witness and Control state before atomically installing one
//! exact-user capture selection and reopening both gates together. The opaque
//! result retains no database operation. The resumed owner can select only an
//! opaque cancellation-safe capture prefix; it cannot inspect or settle it.
//! Its private comparison child may durably consume only a successful opaque
//! result into a one-shot Control terminal, never a Store drain or user result.
//! A separate abort child records Control intent before either exact capture
//! retirement or released-gate restoration and finalizes only from an opaque
//! Store proof. A separate private worker can reconcile an unfinished abort only from exact Control state and
//! read-only absence on the controller-owned Store; neither path is wired.

mod abort;
mod abort_reconcile;
mod attestation_challenge;
mod canary;
mod canary_trust;
mod comparison;
mod controller;
mod live_window_observer;
mod monitoring_policy;
mod phase2_acquisition;
mod phase2_authority;
pub(crate) mod solo_entry;
mod telemetry;
mod window;
pub(crate) use abort::{
    AdvisoryAbortLocus, AdvisoryAbortReason, AdvisoryAbortRecoveryState, AdvisoryAbortStage,
    AdvisoryAbortTerminal, PreparedAdvisoryAbortRecovery,
};
pub(crate) use canary::AdvisoryCanaryScope;
#[allow(
    unused_imports,
    reason = "inactive canary verifier remains unwired until activation review"
)]
pub(crate) use canary_trust::{
    scope_user_commitment, verify_pinned_advisory_canary_authorization,
    VerifiedAdvisoryCanaryAuthorization,
};
pub(crate) use comparison::{AdvisoryComparisonEvidence, AdvisoryComparisonSettlement};
#[allow(
    unused_imports,
    reason = "inactive phase2 acquisition driver remains unwired until activation review"
)]
pub(crate) use phase2_acquisition::acquire_phase2_authority;
#[allow(
    unused_imports,
    reason = "inactive phase2 authority admission remains unwired until activation review"
)]
pub(crate) use phase2_authority::{
    verify_pinned_phase2_authority, Phase2AuthorityAcquisitionEvidence,
    VerifiedPhase2AuthorityAuthorization,
};
#[cfg(test)]
pub(crate) use phase2_authority::{ParsedPhase2Admission, ParsedPhase2Statement};

#[derive(Clone, Copy)]
pub(crate) struct AdvisoryAbortContext(());

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    archive_v3::ArchiveId,
    archive_v3_maintenance_import::{
        CompletedAdvisoryShadowHandoff, CompletedAdvisoryShadowHandoffView,
        MaintenanceImportOperationId, MaintenanceImportPersistence,
    },
    archive_v3_witness::{
        DeletionState, MigrationState, WitnessError, WitnessLease, WitnessRecord,
    },
};

const ADVISORY_OWNER_FORMAT_V1: u16 = 1;
const ADVISORY_OWNER_LEASE_TICKS: u64 = 300;
const ADVISORY_OWNER_COMMITMENT_DOMAIN: &[u8] = b"kioku/archive-v3/advisory-shadow-owner/v1\0";
const ADVISORY_RELEASE_FORMAT_V1: u16 = 1;
const ADVISORY_RELEASE_COMMITMENT_DOMAIN: &[u8] = b"kioku/archive-v3/advisory-release/v1\0";
const ADVISORY_FENCE_AUTHORITY_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-release/fence-authority/v1\0";
const ADVISORY_FENCE_NAME_DOMAIN: &[u8] = b"kioku/archive-v3/advisory-release/fence-name/v1\0";
const ADVISORY_FENCE_OBSERVATION_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-release/fence-observation/v1\0";
const ADVISORY_FENCE_ABSENCE_DOMAIN: &[u8] =
    b"kioku/archive-v3/advisory-release/fence-absence/v1\0";
const ADVISORY_FENCE_METADATA: &str = "kioku-identity-rebind-fence-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum AdvisoryOwnerError {
    #[error("advisory owner authority conflicts")]
    Conflict,
    #[error("advisory owner state is corrupt")]
    Corrupt,
    #[error("advisory owner persistence is unavailable")]
    Persistence,
    #[error("advisory owner witness is unavailable")]
    Publication,
}

pub(crate) type Result<T> = std::result::Result<T, AdvisoryOwnerError>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdvisoryOwnerId([u8; 16]);

impl AdvisoryOwnerId {
    pub(crate) fn random_for_control(
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> Result<Self> {
        for _ in 0..16 {
            let mut value = [0; 16];
            OsRng.fill_bytes(&mut value);
            if value != [0; 16] {
                return Ok(Self(value));
            }
        }
        Err(AdvisoryOwnerError::Persistence)
    }

    pub(crate) fn from_control_bytes(
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        value: [u8; 16],
    ) -> Result<Self> {
        (value != [0; 16])
            .then_some(Self(value))
            .ok_or(AdvisoryOwnerError::Corrupt)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for AdvisoryOwnerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdvisoryOwnerId(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum AdvisoryOwnerStage {
    Reserved = 1,
    SendStarted = 2,
    Bound = 3,
    ManualRequired = 4,
}

/// Durable comparison-only reservation. It cannot call the witness provider.
pub(crate) struct AdvisoryOwnerReservation {
    operation_id: MaintenanceImportOperationId,
    owner_id: AdvisoryOwnerId,
    expected: WitnessRecord,
    revision: u64,
    stage: AdvisoryOwnerStage,
    commitment: [u8; 32],
}

impl AdvisoryOwnerReservation {
    pub(crate) fn new_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        operation_id: MaintenanceImportOperationId,
        owner_id: AdvisoryOwnerId,
        expected: WitnessRecord,
    ) -> Result<Self> {
        let commitment = advisory_owner_commitment(
            operation_id,
            owner_id,
            &expected,
            1,
            AdvisoryOwnerStage::Reserved,
            None,
            None,
        );
        Self::from_control(
            token,
            operation_id,
            owner_id,
            expected,
            1,
            AdvisoryOwnerStage::Reserved,
            (None, None),
            commitment,
        )
    }

    pub(crate) fn send_started_for_control(
        &self,
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> Result<Self> {
        if self.stage != AdvisoryOwnerStage::Reserved {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(AdvisoryOwnerError::Corrupt)?;
        let commitment = advisory_owner_commitment(
            self.operation_id,
            self.owner_id,
            &self.expected,
            revision,
            AdvisoryOwnerStage::SendStarted,
            None,
            None,
        );
        Self::from_control(
            token,
            self.operation_id,
            self.owner_id,
            self.expected.clone(),
            revision,
            AdvisoryOwnerStage::SendStarted,
            (None, None),
            commitment,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control(
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        operation_id: MaintenanceImportOperationId,
        owner_id: AdvisoryOwnerId,
        expected: WitnessRecord,
        revision: u64,
        stage: AdvisoryOwnerStage,
        lineage: (Option<&WitnessRecord>, Option<&WitnessRecord>),
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        let (predecessor, observed) = lineage;
        let valid_lineage = match (predecessor, observed) {
            (None, None) => stage != AdvisoryOwnerStage::Bound,
            (Some(predecessor), Some(observed)) => {
                stage == AdvisoryOwnerStage::Bound
                    && if predecessor == &expected {
                        observed
                            .exact_advisory_owner_acquire_from(predecessor, owner_id.as_bytes())
                            .is_ok()
                    } else {
                        observed
                            .exact_advisory_owner_heartbeat_from(predecessor, owner_id.as_bytes())
                            .or_else(|_| {
                                observed.exact_advisory_owner_reacquire_from(
                                    predecessor,
                                    owner_id.as_bytes(),
                                )
                            })
                            .is_ok()
                    }
            }
            _ => false,
        };
        if revision == 0
            || expected.deletion() != DeletionState::Active
            || expected.migration() != MigrationState::ShadowWal
            || !expected.is_exact_unleased_advisory_terminal()
            || !valid_lineage
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        let commitment = advisory_owner_commitment(
            operation_id,
            owner_id,
            &expected,
            revision,
            stage,
            predecessor,
            observed,
        );
        if commitment == [0; 32] || commitment != persisted_commitment {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            operation_id,
            owner_id,
            expected,
            revision,
            stage,
            commitment,
        })
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> (
        MaintenanceImportOperationId,
        AdvisoryOwnerId,
        &WitnessRecord,
        u64,
        AdvisoryOwnerStage,
        [u8; 32],
    ) {
        (
            self.operation_id,
            self.owner_id,
            &self.expected,
            self.revision,
            self.stage,
            self.commitment,
        )
    }

    pub(crate) const fn operation_id(&self) -> MaintenanceImportOperationId {
        self.operation_id
    }

    pub(crate) const fn owner_id(&self) -> AdvisoryOwnerId {
        self.owner_id
    }

    pub(crate) const fn stage(&self) -> AdvisoryOwnerStage {
        self.stage
    }
}

impl fmt::Debug for AdvisoryOwnerReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdvisoryOwnerReservation(<opaque>)")
    }
}

/// Non-cloneable exact advisory owner lease. It can be advanced only through
/// the private same-owner lifecycle path and grants no root mutation.
pub(crate) struct BoundAdvisoryOwner {
    operation_id: MaintenanceImportOperationId,
    owner_id: AdvisoryOwnerId,
    expected: WitnessRecord,
    predecessor: WitnessRecord,
    observed: WitnessRecord,
    lease: WitnessLease,
    revision: u64,
    commitment: [u8; 32],
}

impl BoundAdvisoryOwner {
    pub(crate) fn bind_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        reservation: &AdvisoryOwnerReservation,
        observed: WitnessRecord,
        lease: WitnessLease,
    ) -> Result<Self> {
        if reservation.stage != AdvisoryOwnerStage::SendStarted
            || observed
                .exact_advisory_owner_acquire_from(
                    &reservation.expected,
                    reservation.owner_id.as_bytes(),
                )
                .ok()
                != Some(lease)
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let revision = reservation
            .revision
            .checked_add(1)
            .ok_or(AdvisoryOwnerError::Corrupt)?;
        let commitment = advisory_owner_commitment(
            reservation.operation_id,
            reservation.owner_id,
            &reservation.expected,
            revision,
            AdvisoryOwnerStage::Bound,
            Some(&reservation.expected),
            Some(&observed),
        );
        Self::from_control_persisted(
            token,
            reservation.operation_id,
            reservation.owner_id,
            reservation.expected.clone(),
            reservation.expected.clone(),
            observed,
            revision,
            commitment,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control_persisted(
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        operation_id: MaintenanceImportOperationId,
        owner_id: AdvisoryOwnerId,
        expected: WitnessRecord,
        predecessor: WitnessRecord,
        observed: WitnessRecord,
        revision: u64,
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        if !expected.is_exact_unleased_advisory_terminal() {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        let lease = if predecessor == expected {
            observed.exact_advisory_owner_acquire_from(&predecessor, owner_id.as_bytes())
        } else {
            observed
                .exact_advisory_owner_heartbeat_from(&predecessor, owner_id.as_bytes())
                .or_else(|_| {
                    observed.exact_advisory_owner_reacquire_from(&predecessor, owner_id.as_bytes())
                })
        }
        .map_err(|_| AdvisoryOwnerError::Conflict)?;
        let commitment = advisory_owner_commitment(
            operation_id,
            owner_id,
            &expected,
            revision,
            AdvisoryOwnerStage::Bound,
            Some(&predecessor),
            Some(&observed),
        );
        if revision == 0 || commitment == [0; 32] || commitment != persisted_commitment {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            operation_id,
            owner_id,
            expected,
            predecessor,
            observed,
            lease,
            revision,
            commitment,
        })
    }

    pub(crate) fn successor_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        retained: &Self,
        predecessor: WitnessRecord,
        observed: WitnessRecord,
        lease: WitnessLease,
    ) -> Result<Self> {
        if predecessor != retained.observed
            || (observed
                .exact_advisory_owner_heartbeat_from(&predecessor, retained.owner_id.as_bytes())
                .ok()
                != Some(lease)
                && observed
                    .exact_advisory_owner_reacquire_from(&predecessor, retained.owner_id.as_bytes())
                    .ok()
                    != Some(lease))
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let revision = retained
            .revision
            .checked_add(1)
            .ok_or(AdvisoryOwnerError::Corrupt)?;
        let commitment = advisory_owner_commitment(
            retained.operation_id,
            retained.owner_id,
            &retained.expected,
            revision,
            AdvisoryOwnerStage::Bound,
            Some(&predecessor),
            Some(&observed),
        );
        Self::from_control_persisted(
            token,
            retained.operation_id,
            retained.owner_id,
            retained.expected.clone(),
            predecessor,
            observed,
            revision,
            commitment,
        )
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> (
        MaintenanceImportOperationId,
        AdvisoryOwnerId,
        &WitnessRecord,
        &WitnessRecord,
        &WitnessRecord,
        WitnessLease,
        u64,
        [u8; 32],
    ) {
        (
            self.operation_id,
            self.owner_id,
            &self.expected,
            &self.predecessor,
            &self.observed,
            self.lease,
            self.revision,
            self.commitment,
        )
    }

    const fn owner_id(&self) -> AdvisoryOwnerId {
        self.owner_id
    }

    fn observed(&self) -> &WitnessRecord {
        &self.observed
    }
}

impl fmt::Debug for BoundAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundAdvisoryOwner(<opaque>)")
    }
}

/// Durable end-of-advisory protocol. `Prepared` freezes the exact advisory
/// owner binding, `DeleteStarted` records the exact provider-marker generation
/// before any future delete, and `Released` accepts only a Store-minted exact-
/// name absence proof. None of these states can call Store or a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum AdvisoryReleaseStage {
    Prepared = 1,
    DeleteStarted = 2,
    Released = 3,
}

/// Minimal authenticated state exposed only to Store through its private
/// maintenance token. Store learns no owner or witness fields; it receives
/// only the stage and exact generation needed for its one named marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdvisoryReleaseStoreStage {
    Prepared,
    DeleteStarted { marker_generation: u64 },
    Released,
}

type AdvisoryReleaseMarkerTuple = (
    Option<[u8; 32]>,
    Option<u64>,
    Option<[u8; 32]>,
    Option<[u8; 32]>,
);

type AdvisoryFenceObservationControlView = (
    ArchiveId,
    MaintenanceImportOperationId,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    u64,
    [u8; 32],
);

/// Opaque exact release row. It is deliberately non-cloneable: future Store
/// release work must retain the one authenticated value supplied by Control.
#[derive(PartialEq, Eq)]
pub(crate) struct AdvisoryRelease {
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    owner_id: AdvisoryOwnerId,
    owner_witness: WitnessRecord,
    owner_revision: u64,
    owner_commitment: [u8; 32],
    fence_authority_commitment: [u8; 32],
    revision: u64,
    stage: AdvisoryReleaseStage,
    marker_name_commitment: Option<[u8; 32]>,
    marker_generation: Option<u64>,
    marker_observation_commitment: Option<[u8; 32]>,
    absence_commitment: Option<[u8; 32]>,
    commitment: [u8; 32],
}

#[derive(PartialEq, Eq)]
pub(crate) struct AdvisoryReleaseControlView<'a> {
    pub(crate) archive_id: ArchiveId,
    pub(crate) operation_id: MaintenanceImportOperationId,
    pub(crate) owner_id: AdvisoryOwnerId,
    pub(crate) owner_witness: &'a WitnessRecord,
    pub(crate) owner_revision: u64,
    pub(crate) owner_commitment: [u8; 32],
    pub(crate) fence_authority_commitment: [u8; 32],
    pub(crate) revision: u64,
    pub(crate) stage: AdvisoryReleaseStage,
    pub(crate) marker_name_commitment: Option<[u8; 32]>,
    pub(crate) marker_generation: Option<u64>,
    pub(crate) marker_observation_commitment: Option<[u8; 32]>,
    pub(crate) absence_commitment: Option<[u8; 32]>,
    pub(crate) commitment: [u8; 32],
}

impl AdvisoryRelease {
    pub(crate) fn prepared_for_control(
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        owner: &BoundAdvisoryOwner,
        fence_authority: &str,
    ) -> Result<Self> {
        if !valid_advisory_fence_authority(fence_authority) {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        let (operation_id, owner_id, _, _, observed, _, owner_revision, owner_commitment) =
            owner.control_view(token);
        let archive_id = observed.archive_id();
        let fence_authority_commitment =
            advisory_fence_authority_commitment(archive_id, operation_id, fence_authority);
        let commitment = advisory_release_commitment(
            archive_id,
            operation_id,
            owner_id,
            observed,
            owner_revision,
            owner_commitment,
            fence_authority_commitment,
            1,
            AdvisoryReleaseStage::Prepared,
            None,
            None,
            None,
            None,
        );
        Self::from_control(
            token,
            archive_id,
            operation_id,
            owner_id,
            observed.clone(),
            owner_revision,
            owner_commitment,
            fence_authority_commitment,
            1,
            AdvisoryReleaseStage::Prepared,
            (None, None, None, None),
            commitment,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control(
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        owner_id: AdvisoryOwnerId,
        owner_witness: WitnessRecord,
        owner_revision: u64,
        owner_commitment: [u8; 32],
        fence_authority_commitment: [u8; 32],
        revision: u64,
        stage: AdvisoryReleaseStage,
        marker: AdvisoryReleaseMarkerTuple,
        persisted_commitment: [u8; 32],
    ) -> Result<Self> {
        let (
            marker_name_commitment,
            marker_generation,
            marker_observation_commitment,
            absence_commitment,
        ) = marker;
        let valid_stage = match stage {
            AdvisoryReleaseStage::Prepared => {
                revision == 1
                    && marker_name_commitment.is_none()
                    && marker_generation.is_none()
                    && marker_observation_commitment.is_none()
                    && absence_commitment.is_none()
            }
            AdvisoryReleaseStage::DeleteStarted => {
                revision == 2
                    && marker_name_commitment.is_some()
                    && marker_generation.is_some_and(|generation| generation > 0)
                    && marker_observation_commitment.is_some()
                    && absence_commitment.is_none()
            }
            AdvisoryReleaseStage::Released => {
                revision == 3
                    && marker_name_commitment.is_some()
                    && marker_generation.is_some_and(|generation| generation > 0)
                    && marker_observation_commitment.is_some()
                    && absence_commitment.is_some()
            }
        };
        if !valid_stage
            || archive_id != owner_witness.archive_id()
            || owner_witness.deletion() != DeletionState::Active
            || owner_witness.migration() != MigrationState::ShadowWal
            || owner_revision == 0
            || owner_commitment == [0; 32]
            || fence_authority_commitment == [0; 32]
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        let prepared_commitment = advisory_release_commitment(
            archive_id,
            operation_id,
            owner_id,
            &owner_witness,
            owner_revision,
            owner_commitment,
            fence_authority_commitment,
            1,
            AdvisoryReleaseStage::Prepared,
            None,
            None,
            None,
            None,
        );
        if let (Some(name), Some(generation), Some(observation)) = (
            marker_name_commitment,
            marker_generation,
            marker_observation_commitment,
        ) {
            if observation
                != advisory_fence_observation_commitment(
                    archive_id,
                    operation_id,
                    prepared_commitment,
                    fence_authority_commitment,
                    name,
                    generation,
                )
            {
                return Err(AdvisoryOwnerError::Corrupt);
            }
            if let Some(absence) = absence_commitment {
                let delete_started_commitment = advisory_release_commitment(
                    archive_id,
                    operation_id,
                    owner_id,
                    &owner_witness,
                    owner_revision,
                    owner_commitment,
                    fence_authority_commitment,
                    2,
                    AdvisoryReleaseStage::DeleteStarted,
                    Some(name),
                    Some(generation),
                    Some(observation),
                    None,
                );
                if absence
                    != advisory_fence_absence_commitment(
                        archive_id,
                        operation_id,
                        delete_started_commitment,
                        name,
                        generation,
                    )
                {
                    return Err(AdvisoryOwnerError::Corrupt);
                }
            }
        }
        let commitment = advisory_release_commitment(
            archive_id,
            operation_id,
            owner_id,
            &owner_witness,
            owner_revision,
            owner_commitment,
            fence_authority_commitment,
            revision,
            stage,
            marker_name_commitment,
            marker_generation,
            marker_observation_commitment,
            absence_commitment,
        );
        if commitment == [0; 32] || commitment != persisted_commitment {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            archive_id,
            operation_id,
            owner_id,
            owner_witness,
            owner_revision,
            owner_commitment,
            fence_authority_commitment,
            revision,
            stage,
            marker_name_commitment,
            marker_generation,
            marker_observation_commitment,
            absence_commitment,
            commitment,
        })
    }

    pub(crate) fn delete_started_for_control(
        &self,
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        observation: &AdvisoryFenceObservation,
    ) -> Result<Self> {
        let observation_view = observation.control_view(token);
        if self.stage != AdvisoryReleaseStage::Prepared
            || observation_view.0 != self.archive_id
            || observation_view.1 != self.operation_id
            || observation_view.2 != self.commitment
            || observation_view.3 != self.fence_authority_commitment
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let commitment = advisory_release_commitment(
            self.archive_id,
            self.operation_id,
            self.owner_id,
            &self.owner_witness,
            self.owner_revision,
            self.owner_commitment,
            self.fence_authority_commitment,
            2,
            AdvisoryReleaseStage::DeleteStarted,
            Some(observation_view.4),
            Some(observation_view.5),
            Some(observation_view.6),
            None,
        );
        Self::from_control(
            token,
            self.archive_id,
            self.operation_id,
            self.owner_id,
            self.owner_witness.clone(),
            self.owner_revision,
            self.owner_commitment,
            self.fence_authority_commitment,
            2,
            AdvisoryReleaseStage::DeleteStarted,
            (
                Some(observation_view.4),
                Some(observation_view.5),
                Some(observation_view.6),
                None,
            ),
            commitment,
        )
    }

    pub(crate) fn released_for_control(
        &self,
        token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
        absence: &AdvisoryFenceAbsence,
    ) -> Result<Self> {
        let absence_view = absence.control_view(token);
        if self.stage != AdvisoryReleaseStage::DeleteStarted
            || absence_view.0 != self.archive_id
            || absence_view.1 != self.operation_id
            || absence_view.2 != self.commitment
            || Some(absence_view.3) != self.marker_name_commitment
            || Some(absence_view.4) != self.marker_generation
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let commitment = advisory_release_commitment(
            self.archive_id,
            self.operation_id,
            self.owner_id,
            &self.owner_witness,
            self.owner_revision,
            self.owner_commitment,
            self.fence_authority_commitment,
            3,
            AdvisoryReleaseStage::Released,
            self.marker_name_commitment,
            self.marker_generation,
            self.marker_observation_commitment,
            Some(absence_view.5),
        );
        Self::from_control(
            token,
            self.archive_id,
            self.operation_id,
            self.owner_id,
            self.owner_witness.clone(),
            self.owner_revision,
            self.owner_commitment,
            self.fence_authority_commitment,
            3,
            AdvisoryReleaseStage::Released,
            (
                self.marker_name_commitment,
                self.marker_generation,
                self.marker_observation_commitment,
                Some(absence_view.5),
            ),
            commitment,
        )
    }

    pub(crate) fn control_view(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> AdvisoryReleaseControlView<'_> {
        AdvisoryReleaseControlView {
            archive_id: self.archive_id,
            operation_id: self.operation_id,
            owner_id: self.owner_id,
            owner_witness: &self.owner_witness,
            owner_revision: self.owner_revision,
            owner_commitment: self.owner_commitment,
            fence_authority_commitment: self.fence_authority_commitment,
            revision: self.revision,
            stage: self.stage,
            marker_name_commitment: self.marker_name_commitment,
            marker_generation: self.marker_generation,
            marker_observation_commitment: self.marker_observation_commitment,
            absence_commitment: self.absence_commitment,
            commitment: self.commitment,
        }
    }

    pub(crate) const fn operation_id(&self) -> MaintenanceImportOperationId {
        self.operation_id
    }

    pub(crate) const fn stage(&self) -> AdvisoryReleaseStage {
        self.stage
    }

    pub(crate) fn authenticate_store_target(
        &self,
        _token: crate::store::StoreMaintenanceContext,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
        marker_name: &str,
        fence_authority: &str,
    ) -> Result<AdvisoryReleaseStoreStage> {
        if self.archive_id != archive_id
            || self.operation_id != operation_id
            || !crate::store::is_canonical_identity_rebind_fence_object_name(marker_name)
            || !valid_advisory_fence_authority(fence_authority)
            || advisory_fence_authority_commitment(archive_id, operation_id, fence_authority)
                != self.fence_authority_commitment
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let marker_name_commitment =
            advisory_fence_name_commitment(archive_id, operation_id, marker_name);
        match self.stage {
            AdvisoryReleaseStage::Prepared => Ok(AdvisoryReleaseStoreStage::Prepared),
            AdvisoryReleaseStage::DeleteStarted => {
                if self.marker_name_commitment != Some(marker_name_commitment) {
                    return Err(AdvisoryOwnerError::Conflict);
                }
                Ok(AdvisoryReleaseStoreStage::DeleteStarted {
                    marker_generation: self.marker_generation.ok_or(AdvisoryOwnerError::Corrupt)?,
                })
            }
            AdvisoryReleaseStage::Released => {
                if self.marker_name_commitment != Some(marker_name_commitment) {
                    return Err(AdvisoryOwnerError::Conflict);
                }
                Ok(AdvisoryReleaseStoreStage::Released)
            }
        }
    }

    pub(crate) fn commitment_for_store(
        &self,
        _token: crate::store::StoreMaintenanceContext,
    ) -> [u8; 32] {
        self.commitment
    }
}

impl fmt::Debug for AdvisoryRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdvisoryRelease(<opaque>)")
    }
}

/// Exact live marker facts. The only production constructor requires Store's
/// private maintenance token; Control cannot infer or fabricate an observation.
pub(crate) struct AdvisoryFenceObservation {
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    prepared_release_commitment: [u8; 32],
    fence_authority_commitment: [u8; 32],
    marker_name_commitment: [u8; 32],
    marker_generation: u64,
    commitment: [u8; 32],
}

impl AdvisoryFenceObservation {
    pub(crate) fn from_store(
        _token: crate::store::StoreMaintenanceContext,
        prepared: &AdvisoryRelease,
        marker_name: &str,
        fence_authority: &str,
        marker_metadata: &str,
        marker_generation: i64,
    ) -> Result<Self> {
        Self::from_exact_facts(
            prepared,
            marker_name,
            fence_authority,
            marker_metadata,
            marker_generation,
        )
    }

    fn from_exact_facts(
        prepared: &AdvisoryRelease,
        marker_name: &str,
        fence_authority: &str,
        marker_metadata: &str,
        marker_generation: i64,
    ) -> Result<Self> {
        if prepared.stage != AdvisoryReleaseStage::Prepared
            || !crate::store::is_canonical_identity_rebind_fence_object_name(marker_name)
            || !valid_advisory_fence_authority(fence_authority)
            || marker_metadata != ADVISORY_FENCE_METADATA
            || advisory_fence_authority_commitment(
                prepared.archive_id,
                prepared.operation_id,
                fence_authority,
            ) != prepared.fence_authority_commitment
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let marker_generation = u64::try_from(marker_generation)
            .ok()
            .filter(|generation| *generation > 0)
            .ok_or(AdvisoryOwnerError::Corrupt)?;
        let marker_name_commitment =
            advisory_fence_name_commitment(prepared.archive_id, prepared.operation_id, marker_name);
        let commitment = advisory_fence_observation_commitment(
            prepared.archive_id,
            prepared.operation_id,
            prepared.commitment,
            prepared.fence_authority_commitment,
            marker_name_commitment,
            marker_generation,
        );
        Ok(Self {
            archive_id: prepared.archive_id,
            operation_id: prepared.operation_id,
            prepared_release_commitment: prepared.commitment,
            fence_authority_commitment: prepared.fence_authority_commitment,
            marker_name_commitment,
            marker_generation,
            commitment,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        prepared: &AdvisoryRelease,
        marker_name: &str,
        fence_authority: &str,
        marker_metadata: &str,
        marker_generation: i64,
    ) -> Result<Self> {
        Self::from_exact_facts(
            prepared,
            marker_name,
            fence_authority,
            marker_metadata,
            marker_generation,
        )
    }

    fn control_view(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> AdvisoryFenceObservationControlView {
        (
            self.archive_id,
            self.operation_id,
            self.prepared_release_commitment,
            self.fence_authority_commitment,
            self.marker_name_commitment,
            self.marker_generation,
            self.commitment,
        )
    }
}

impl fmt::Debug for AdvisoryFenceObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdvisoryFenceObservation(<opaque>)")
    }
}

/// Exact-name provider absence after the durable deletion marker. Like the
/// observation, this can be minted in production only inside Store.
pub(crate) struct AdvisoryFenceAbsence {
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    delete_started_commitment: [u8; 32],
    marker_name_commitment: [u8; 32],
    marker_generation: u64,
    commitment: [u8; 32],
}

impl AdvisoryFenceAbsence {
    pub(crate) fn from_store(
        _token: crate::store::StoreMaintenanceContext,
        delete_started: &AdvisoryRelease,
        marker_name: &str,
    ) -> Result<Self> {
        Self::from_exact_facts(delete_started, marker_name)
    }

    fn from_exact_facts(delete_started: &AdvisoryRelease, marker_name: &str) -> Result<Self> {
        let marker_name_commitment = advisory_fence_name_commitment(
            delete_started.archive_id,
            delete_started.operation_id,
            marker_name,
        );
        if delete_started.stage != AdvisoryReleaseStage::DeleteStarted
            || !crate::store::is_canonical_identity_rebind_fence_object_name(marker_name)
            || Some(marker_name_commitment) != delete_started.marker_name_commitment
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let marker_generation = delete_started
            .marker_generation
            .ok_or(AdvisoryOwnerError::Corrupt)?;
        let commitment = advisory_fence_absence_commitment(
            delete_started.archive_id,
            delete_started.operation_id,
            delete_started.commitment,
            marker_name_commitment,
            marker_generation,
        );
        Ok(Self {
            archive_id: delete_started.archive_id,
            operation_id: delete_started.operation_id,
            delete_started_commitment: delete_started.commitment,
            marker_name_commitment,
            marker_generation,
            commitment,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(delete_started: &AdvisoryRelease, marker_name: &str) -> Result<Self> {
        Self::from_exact_facts(delete_started, marker_name)
    }

    fn control_view(
        &self,
        _token: crate::cp::control_store::AdvisoryOwnerPersistenceContext,
    ) -> (
        ArchiveId,
        MaintenanceImportOperationId,
        [u8; 32],
        [u8; 32],
        u64,
        [u8; 32],
    ) {
        (
            self.archive_id,
            self.operation_id,
            self.delete_started_commitment,
            self.marker_name_commitment,
            self.marker_generation,
            self.commitment,
        )
    }
}

impl fmt::Debug for AdvisoryFenceAbsence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdvisoryFenceAbsence(<opaque>)")
    }
}

fn valid_advisory_fence_authority(authority: &str) -> bool {
    authority.len() == 72
        && authority.starts_with("archive_")
        && authority[8..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(crate) fn advisory_fence_authority_commitment(
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    authority: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ADVISORY_FENCE_AUTHORITY_DOMAIN);
    hasher.update(archive_id.as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update((authority.len() as u32).to_be_bytes());
    hasher.update(authority.as_bytes());
    hasher.finalize().into()
}

fn advisory_fence_name_commitment(
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    marker_name: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ADVISORY_FENCE_NAME_DOMAIN);
    hasher.update(archive_id.as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update((marker_name.len() as u32).to_be_bytes());
    hasher.update(marker_name.as_bytes());
    hasher.finalize().into()
}

fn advisory_fence_observation_commitment(
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    prepared_release_commitment: [u8; 32],
    fence_authority_commitment: [u8; 32],
    marker_name_commitment: [u8; 32],
    marker_generation: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ADVISORY_FENCE_OBSERVATION_DOMAIN);
    hasher.update(archive_id.as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(prepared_release_commitment);
    hasher.update(fence_authority_commitment);
    hasher.update(marker_name_commitment);
    hasher.update(marker_generation.to_be_bytes());
    hasher.finalize().into()
}

fn advisory_fence_absence_commitment(
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    delete_started_commitment: [u8; 32],
    marker_name_commitment: [u8; 32],
    marker_generation: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ADVISORY_FENCE_ABSENCE_DOMAIN);
    hasher.update(archive_id.as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(delete_started_commitment);
    hasher.update(marker_name_commitment);
    hasher.update(marker_generation.to_be_bytes());
    hasher.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn advisory_release_commitment(
    archive_id: ArchiveId,
    operation_id: MaintenanceImportOperationId,
    owner_id: AdvisoryOwnerId,
    owner_witness: &WitnessRecord,
    owner_revision: u64,
    owner_commitment: [u8; 32],
    fence_authority_commitment: [u8; 32],
    revision: u64,
    stage: AdvisoryReleaseStage,
    marker_name_commitment: Option<[u8; 32]>,
    marker_generation: Option<u64>,
    marker_observation_commitment: Option<[u8; 32]>,
    absence_commitment: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ADVISORY_RELEASE_COMMITMENT_DOMAIN);
    hasher.update(ADVISORY_RELEASE_FORMAT_V1.to_be_bytes());
    hasher.update(archive_id.as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(owner_id.as_bytes());
    hasher.update(owner_witness.encode());
    hasher.update(owner_revision.to_be_bytes());
    hasher.update(owner_commitment);
    hasher.update(fence_authority_commitment);
    hasher.update(revision.to_be_bytes());
    hasher.update([stage as u8]);
    for commitment in [
        marker_name_commitment,
        marker_observation_commitment,
        absence_commitment,
    ] {
        if let Some(commitment) = commitment {
            hasher.update([1]);
            hasher.update(commitment);
        } else {
            hasher.update([0]);
        }
    }
    if let Some(generation) = marker_generation {
        hasher.update([1]);
        hasher.update(generation.to_be_bytes());
    } else {
        hasher.update([0]);
    }
    hasher.finalize().into()
}

fn advisory_owner_commitment(
    operation_id: MaintenanceImportOperationId,
    owner_id: AdvisoryOwnerId,
    expected: &WitnessRecord,
    revision: u64,
    stage: AdvisoryOwnerStage,
    predecessor: Option<&WitnessRecord>,
    observed: Option<&WitnessRecord>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ADVISORY_OWNER_COMMITMENT_DOMAIN);
    hasher.update(ADVISORY_OWNER_FORMAT_V1.to_be_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(owner_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    hasher.update([stage as u8]);
    hasher.update(expected.encode());
    if let Some(predecessor) = predecessor {
        hasher.update([1]);
        hasher.update(predecessor.encode());
    } else {
        hasher.update([0]);
    }
    if let Some(observed) = observed {
        hasher.update([1]);
        hasher.update(observed.encode());
    } else {
        hasher.update([0]);
    }
    hasher.finalize().into()
}

#[async_trait]
pub(crate) trait AdvisoryOwnerControl: Send + Sync {
    async fn reserve_advisory_owner_with_canary(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        canary: &AdvisoryCanaryScope,
        operation_id: MaintenanceImportOperationId,
        expected: &WitnessRecord,
    ) -> Result<AdvisoryOwnerReservation>;

    async fn mark_advisory_owner_send_started(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        reserved: &AdvisoryOwnerReservation,
    ) -> Result<AdvisoryOwnerReservation>;

    async fn bind_advisory_owner(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        reserved: &AdvisoryOwnerReservation,
        observed: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<BoundAdvisoryOwner>;

    async fn load_bound_advisory_owner(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        operation_id: MaintenanceImportOperationId,
        observed: &WitnessRecord,
    ) -> Result<BoundAdvisoryOwner>;

    async fn load_retained_advisory_owner(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        operation_id: MaintenanceImportOperationId,
    ) -> Result<BoundAdvisoryOwner>;

    async fn persist_advisory_owner_successor(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        previous: &WitnessRecord,
        observed: &WitnessRecord,
        lease: WitnessLease,
    ) -> Result<BoundAdvisoryOwner>;

    async fn prepare_advisory_release(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        owner: &BoundAdvisoryOwner,
    ) -> Result<AdvisoryRelease>;

    async fn load_advisory_release(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        owner: &BoundAdvisoryOwner,
    ) -> Result<Option<AdvisoryRelease>>;

    async fn mark_advisory_fence_delete_started(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        prepared: &AdvisoryRelease,
        observation: &AdvisoryFenceObservation,
    ) -> Result<AdvisoryRelease>;

    async fn mark_advisory_fence_released(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        delete_started: &AdvisoryRelease,
        absence: &AdvisoryFenceAbsence,
    ) -> Result<AdvisoryRelease>;

    async fn settle_advisory_comparison(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        owner: &BoundAdvisoryOwner,
        release: &AdvisoryRelease,
        evidence: AdvisoryComparisonEvidence,
    ) -> Result<AdvisoryComparisonSettlement>;

    async fn load_advisory_comparison(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        owner: &BoundAdvisoryOwner,
        release: &AdvisoryRelease,
    ) -> Result<Option<AdvisoryComparisonSettlement>>;

    async fn prepare_advisory_abort(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        owner: &BoundAdvisoryOwner,
        release: &AdvisoryRelease,
        reason: AdvisoryAbortReason,
    ) -> Result<AdvisoryAbortTerminal>;

    async fn prepare_released_advisory_abort(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        owner: &BoundAdvisoryOwner,
        release: &AdvisoryRelease,
        admission: &crate::store::StoreReleasedAbortAdmission,
    ) -> Result<AdvisoryAbortTerminal>;

    async fn load_advisory_abort(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        owner: &BoundAdvisoryOwner,
        release: &AdvisoryRelease,
    ) -> Result<Option<AdvisoryAbortTerminal>>;

    async fn load_advisory_abort_recovery(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    ) -> Result<Option<AdvisoryAbortRecoveryState>>;

    async fn finalize_advisory_abort(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        prepared: &AdvisoryAbortTerminal,
        retired: &crate::store::StoreAdvisoryCaptureRetired,
    ) -> Result<AdvisoryAbortTerminal>;

    async fn finalize_released_advisory_abort(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        prepared: &AdvisoryAbortTerminal,
        restored: &crate::store::StoreReleasedAbortRestored,
    ) -> Result<AdvisoryAbortTerminal>;

    async fn finalize_advisory_abort_recovery(
        &self,
        token: AdvisoryOwnerRuntimeContext,
        recovery: &PreparedAdvisoryAbortRecovery,
        absence: &crate::store::StorePreparedAdvisoryAbortAbsent,
    ) -> Result<AdvisoryAbortTerminal>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdvisoryOwnerCommitError {
    Rejected,
    DefinitelyFailed,
    OutcomeUnknown,
}

#[async_trait]
pub(crate) trait AdvisoryOwnerWitnessProvider: Send + Sync {
    async fn read_current_exact(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<WitnessRecord, WitnessError>;

    async fn acquire_owner_lease(
        &self,
        expected: &WitnessRecord,
        owner: AdvisoryOwnerId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), AdvisoryOwnerCommitError>;

    async fn maintain_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: AdvisoryOwnerId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), AdvisoryOwnerCommitError>;

    async fn reacquire_owner_lease(
        &self,
        previous: &WitnessRecord,
        owner: AdvisoryOwnerId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), AdvisoryOwnerCommitError>;
}

/// Token available only inside this module. It prevents the provider bundle
/// and advisory handoff from being consumed by a sibling production caller.
#[derive(Clone, Copy)]
pub(crate) struct AdvisoryOwnerRuntimeContext(());

/// Token constructible only by this owner and its private comparison child.
/// It gates exact recovery, local replay, and opaque evidence extraction
/// without exposing any underlying provider or SQLite capability.
#[derive(Clone, Copy)]
pub(crate) struct AdvisoryComparisonContext(());

/// Opaque owner capability. It intentionally has no operation method in this
/// slice; owning it proves only that Control and the exact ShadowWal witness
/// agree on one initial advisory lease.
struct SingleArchiveAdvisoryOwner {
    _runtime: crate::archive_v3_shadow_runtime::AdvisoryOwnerRuntimeOwner,
    _control: Arc<crate::cp::control_store::ControlStore>,
    _archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    _parity: crate::archive_v3_maintenance_import::CompletedAdvisoryShadowParityEvidence,
    _capture_target: crate::store::StoreAdvisoryCaptureTarget,
    _bound: BoundAdvisoryOwner,
    may_heartbeat: bool,
}

/// Terminal inactive owner after the permanent Store marker is proven absent.
/// The original owner remains nested and unreachable so no lease maintenance
/// can race or resume after release. Its Store target still retains every
/// process-local block for the separately reviewed unblock/capture phase.
struct ReleasedSingleArchiveAdvisoryOwner {
    _owner: SingleArchiveAdvisoryOwner,
    _release: AdvisoryRelease,
    _release_lifecycle_guard: crate::store::StoreAdvisoryReleaseLifecycle,
}

/// Terminal inactive owner after the exact provider and both process-local
/// legacy fences are released. The nested owner remains unreachable, and the
/// Store result retains only the installed exact-user capture registry and has
/// no connection, comparison, settlement, acknowledgement, or serving API.
pub(crate) struct LocallyResumedSingleArchiveAdvisoryOwner {
    _owner: SingleArchiveAdvisoryOwner,
    _release: AdvisoryRelease,
    _resumed_target: crate::store::StoreAdvisoryResumedTarget,
}

/// One-shot inactive Phase-1 comparison terminal. The exact successful
/// comparison is durable in Control and restart-loadable, and the exact Store
/// capture is retired before construction, while the nested owner and target
/// are unreachable. It has no acknowledgement, publication, provider, route,
/// or authority-conversion operation.
pub(crate) struct SettledSingleArchiveAdvisoryOwner {
    _owner: LocallyResumedSingleArchiveAdvisoryOwner,
    _settlement: AdvisoryComparisonSettlement,
    _retired: crate::store::StoreAdvisoryCaptureRetired,
}

/// Terminal inactive owner after a resumed-canary stop or comparison mismatch
/// is durable and the exact Store capture has been retired. It carries no
/// restart, acknowledgement, provider, route, or authority-conversion API.
pub(crate) struct AbortedSingleArchiveAdvisoryOwner {
    _owner: LocallyResumedSingleArchiveAdvisoryOwner,
    _abort: AdvisoryAbortTerminal,
    _retired: crate::store::StoreAdvisoryCaptureRetired,
}

/// Terminal inactive owner after a stop at the released-before-local-resume
/// boundary. The paired legacy gates are open without advisory capture, and
/// the exact abort is durable. It exposes no provider, acknowledgement,
/// restart, route, or authority-conversion operation.
pub(crate) struct AbortedReleasedSingleArchiveAdvisoryOwner {
    _owner: SingleArchiveAdvisoryOwner,
    _release: AdvisoryRelease,
    _abort: AdvisoryAbortTerminal,
    _local_restored: Option<crate::store::StoreReleasedAbortRestored>,
}

impl SingleArchiveAdvisoryOwner {
    pub(crate) const fn operation_id(&self) -> MaintenanceImportOperationId {
        self._bound.operation_id
    }

    pub(crate) const fn owner_id(&self) -> AdvisoryOwnerId {
        self._bound.owner_id
    }

    async fn start(
        handoff: CompletedAdvisoryShadowHandoff,
        canary: AdvisoryCanaryScope,
    ) -> Result<Self> {
        let CompletedAdvisoryShadowHandoffView {
            runtime,
            terminal_witness,
            archive_binding,
            parity,
            control,
            store_capture_target,
        } = handoff.into_advisory_owner(AdvisoryOwnerRuntimeContext(()));
        let operation_id = parity.operation_id_for_advisory_owner(AdvisoryOwnerRuntimeContext(()));
        let terminal_control =
            MaintenanceImportPersistence::load_exact(control.as_ref(), operation_id)
                .await
                .map_err(|_| AdvisoryOwnerError::Conflict)?;
        parity
            .reauthenticate_for_advisory_owner(
                AdvisoryOwnerRuntimeContext(()),
                &terminal_control,
                &terminal_witness,
            )
            .map_err(|_| AdvisoryOwnerError::Conflict)?;
        let reserved = control
            .reserve_advisory_owner_with_canary(
                AdvisoryOwnerRuntimeContext(()),
                &canary,
                operation_id,
                &terminal_witness,
            )
            .await?;
        let runtime = runtime
            .into_advisory_owner(AdvisoryOwnerRuntimeContext(()))
            .map_err(|_| AdvisoryOwnerError::Publication)?;
        let (bound, may_heartbeat) = if reserved.stage() == AdvisoryOwnerStage::Bound {
            let retained = control
                .load_retained_advisory_owner(AdvisoryOwnerRuntimeContext(()), operation_id)
                .await?;
            let current = runtime
                .read_advisory_owner_current_exact(
                    &AdvisoryOwnerRuntimeContext(()),
                    terminal_witness.archive_id(),
                )
                .await
                .map_err(|_| AdvisoryOwnerError::Publication)?;
            if current == *retained.observed() {
                (retained, false)
            } else {
                let lease = current
                    .exact_advisory_owner_heartbeat_from(
                        retained.observed(),
                        retained.owner_id().as_bytes(),
                    )
                    .or_else(|_| {
                        current.exact_advisory_owner_reacquire_from(
                            retained.observed(),
                            retained.owner_id().as_bytes(),
                        )
                    })
                    .map_err(|_| AdvisoryOwnerError::Conflict)?;
                let bound = control
                    .persist_advisory_owner_successor(
                        AdvisoryOwnerRuntimeContext(()),
                        retained.observed(),
                        &current,
                        lease,
                    )
                    .await?;
                (bound, false)
            }
        } else {
            let reserved = control
                .mark_advisory_owner_send_started(AdvisoryOwnerRuntimeContext(()), &reserved)
                .await?;
            let current = runtime
                .read_advisory_owner_current_exact(
                    &AdvisoryOwnerRuntimeContext(()),
                    terminal_witness.archive_id(),
                )
                .await
                .map_err(|_| AdvisoryOwnerError::Publication)?;
            let (observed, lease) = if let Ok(lease) = current.exact_advisory_owner_acquire_from(
                &terminal_witness,
                reserved.owner_id().as_bytes(),
            ) {
                (current, lease)
            } else {
                if current != terminal_witness {
                    return Err(AdvisoryOwnerError::Conflict);
                }
                match runtime
                    .acquire_advisory_owner_lease_unresolved(
                        &AdvisoryOwnerRuntimeContext(()),
                        terminal_witness.clone(),
                        reserved.owner_id(),
                        ADVISORY_OWNER_LEASE_TICKS,
                    )
                    .await
                {
                    Ok(value) => value,
                    Err(AdvisoryOwnerCommitError::OutcomeUnknown) => {
                        let observed = runtime
                            .read_advisory_owner_current_exact(
                                &AdvisoryOwnerRuntimeContext(()),
                                terminal_witness.archive_id(),
                            )
                            .await
                            .map_err(|_| AdvisoryOwnerError::Publication)?;
                        let lease = observed
                            .exact_advisory_owner_acquire_from(
                                &terminal_witness,
                                reserved.owner_id().as_bytes(),
                            )
                            .map_err(|_| AdvisoryOwnerError::Publication)?;
                        (observed, lease)
                    }
                    Err(AdvisoryOwnerCommitError::Rejected) => {
                        return Err(AdvisoryOwnerError::Conflict)
                    }
                    Err(AdvisoryOwnerCommitError::DefinitelyFailed) => {
                        return Err(AdvisoryOwnerError::Publication)
                    }
                }
            };
            let bound = control
                .bind_advisory_owner(AdvisoryOwnerRuntimeContext(()), &reserved, &observed, lease)
                .await?;
            (bound, true)
        };
        Ok(Self {
            _runtime: runtime,
            _control: control,
            _archive_binding: archive_binding,
            _parity: parity,
            _capture_target: store_capture_target,
            _bound: bound,
            may_heartbeat,
        })
    }

    /// Maintain only the already-bound advisory lease. Same-fence heartbeat
    /// and post-expiry higher-fence reacquire are the only accepted provider
    /// outcomes; restart recovery adopts the same exact one-step successor.
    async fn maintain_lease(&mut self) -> Result<()> {
        let previous = self._bound.observed().clone();
        let owner = self._bound.owner_id();
        let mut observed = self
            ._runtime
            .read_advisory_owner_current_exact(
                &AdvisoryOwnerRuntimeContext(()),
                previous.archive_id(),
            )
            .await
            .map_err(|_| AdvisoryOwnerError::Publication)?;
        let provider_transition_started = observed == previous;
        if provider_transition_started {
            let transition = if self.may_heartbeat {
                self._runtime
                    .maintain_advisory_owner_lease_unresolved(
                        &AdvisoryOwnerRuntimeContext(()),
                        previous.clone(),
                        owner,
                        ADVISORY_OWNER_LEASE_TICKS,
                    )
                    .await
            } else {
                self._runtime
                    .reacquire_advisory_owner_lease_unresolved(
                        &AdvisoryOwnerRuntimeContext(()),
                        previous.clone(),
                        owner,
                        ADVISORY_OWNER_LEASE_TICKS,
                    )
                    .await
            };
            match transition {
                Ok((next, _)) => observed = next,
                Err(AdvisoryOwnerCommitError::OutcomeUnknown) => {
                    observed = self
                        ._runtime
                        .read_advisory_owner_current_exact(
                            &AdvisoryOwnerRuntimeContext(()),
                            previous.archive_id(),
                        )
                        .await
                        .map_err(|_| AdvisoryOwnerError::Publication)?;
                }
                Err(AdvisoryOwnerCommitError::Rejected) => {
                    return Err(AdvisoryOwnerError::Conflict)
                }
                Err(AdvisoryOwnerCommitError::DefinitelyFailed) => {
                    return Err(AdvisoryOwnerError::Publication)
                }
            }
        }
        if observed == previous {
            return if self.may_heartbeat {
                Ok(())
            } else {
                Err(AdvisoryOwnerError::Conflict)
            };
        }
        let lease = observed
            .exact_advisory_owner_heartbeat_from(&previous, owner.as_bytes())
            .or_else(|_| observed.exact_advisory_owner_reacquire_from(&previous, owner.as_bytes()))
            .map_err(|_| AdvisoryOwnerError::Conflict)?;
        self._bound = self
            ._control
            .persist_advisory_owner_successor(
                AdvisoryOwnerRuntimeContext(()),
                &previous,
                &observed,
                lease,
            )
            .await?;
        if !provider_transition_started {
            self.may_heartbeat = false;
            return Err(AdvisoryOwnerError::Conflict);
        }
        if !self.may_heartbeat {
            if observed
                .exact_advisory_owner_reacquire_from(&previous, owner.as_bytes())
                .is_err()
            {
                return Err(AdvisoryOwnerError::Conflict);
            }
            self.may_heartbeat = true;
        }
        Ok(())
    }

    /// Consume the owner before beginning irreversible release. Control is
    /// always advanced to `DeleteStarted` before Store receives exact-delete
    /// authority; a restart exact-loads the retained stage and reconciles only
    /// exact-name absence. No local Store admission gate is reopened here.
    async fn release_legacy_fence(self) -> Result<ReleasedSingleArchiveAdvisoryOwner> {
        let release_lifecycle_guard = self
            ._capture_target
            .acquire_advisory_release_lifecycle()
            .await
            .map_err(map_advisory_store_error)?;
        let current = self
            ._runtime
            .read_advisory_owner_current_exact(
                &AdvisoryOwnerRuntimeContext(()),
                self._bound.observed().archive_id(),
            )
            .await
            .map_err(|_| AdvisoryOwnerError::Publication)?;
        if current != *self._bound.observed() {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let mut release = match self
            ._control
            .load_advisory_release(AdvisoryOwnerRuntimeContext(()), &self._bound)
            .await?
        {
            Some(retained) => retained,
            None => {
                self._control
                    .prepare_advisory_release(AdvisoryOwnerRuntimeContext(()), &self._bound)
                    .await?
            }
        };
        loop {
            release = match release.stage {
                AdvisoryReleaseStage::Prepared => {
                    let observation = self
                        ._capture_target
                        .observe_advisory_fence(&release)
                        .await
                        .map_err(map_advisory_store_error)?;
                    self._control
                        .mark_advisory_fence_delete_started(
                            AdvisoryOwnerRuntimeContext(()),
                            &release,
                            &observation,
                        )
                        .await?
                }
                AdvisoryReleaseStage::DeleteStarted => {
                    let absence = self
                        ._capture_target
                        .reconcile_advisory_fence_absence(&release)
                        .await
                        .map_err(map_advisory_store_error)?;
                    self._control
                        .mark_advisory_fence_released(
                            AdvisoryOwnerRuntimeContext(()),
                            &release,
                            &absence,
                        )
                        .await?
                }
                AdvisoryReleaseStage::Released => break,
            };
        }
        Ok(ReleasedSingleArchiveAdvisoryOwner {
            _owner: self,
            _release: release,
            _release_lifecycle_guard: release_lifecycle_guard,
        })
    }
}

impl ReleasedSingleArchiveAdvisoryOwner {
    pub(crate) const fn operation_id(&self) -> MaintenanceImportOperationId {
        self._release.operation_id
    }

    pub(crate) const fn marker_generation(&self) -> i64 {
        match self._release.marker_generation {
            Some(generation) => generation as i64,
            None => 0,
        }
    }

    async fn reauthenticate_boundary(&self) -> Result<()> {
        let current = self
            ._owner
            ._runtime
            .read_advisory_owner_current_exact(
                &AdvisoryOwnerRuntimeContext(()),
                self._owner._bound.observed().archive_id(),
            )
            .await
            .map_err(|_| AdvisoryOwnerError::Publication)?;
        if current != *self._owner._bound.observed() {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let retained = self
            ._owner
            ._control
            .load_advisory_release(AdvisoryOwnerRuntimeContext(()), &self._owner._bound)
            .await?
            .ok_or(AdvisoryOwnerError::Conflict)?;
        if retained.stage != AdvisoryReleaseStage::Released || retained != self._release {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(())
    }

    /// Consume the provider-terminal owner into a process-local resumed
    /// state. A fresh exact witness and Control release read are required
    /// while the same Store lifecycle gate remains continuously owned.
    async fn resume_local_admission(self) -> Result<LocallyResumedSingleArchiveAdvisoryOwner> {
        self.reauthenticate_boundary().await?;
        if self
            ._owner
            ._control
            .load_advisory_abort(
                AdvisoryOwnerRuntimeContext(()),
                &self._owner._bound,
                &self._release,
            )
            .await?
            .is_some()
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let Self {
            _owner: owner,
            _release: release,
            _release_lifecycle_guard: lifecycle,
        } = self;
        let resumed_target = owner
            ._capture_target
            .resume_advisory_local_admission(&release, lifecycle)
            .await
            .map_err(map_advisory_store_error)?;
        Ok(LocallyResumedSingleArchiveAdvisoryOwner {
            _owner: owner,
            _release: release,
            _resumed_target: resumed_target,
        })
    }

    /// Consume a provider-released owner into a durable stop terminal without
    /// ever installing capture. Control records `Prepared` before the paired
    /// local legacy gates reopen. Caller cancellation cannot cancel the owned
    /// transition, and only persistence errors are retried after local work.
    pub(super) async fn abort_before_local_resume(
        self,
        reason: AdvisoryAbortReason,
    ) -> Result<AbortedReleasedSingleArchiveAdvisoryOwner> {
        tokio::spawn(async move { self.abort_before_local_resume_owned(reason).await })
            .await
            .map_err(|_| AdvisoryOwnerError::Publication)?
    }

    async fn abort_before_local_resume_owned(
        self,
        reason: AdvisoryAbortReason,
    ) -> Result<AbortedReleasedSingleArchiveAdvisoryOwner> {
        if reason != AdvisoryAbortReason::StopRequested {
            return Err(AdvisoryOwnerError::Conflict);
        }
        self.reauthenticate_boundary().await?;
        let retained = self
            ._owner
            ._control
            .load_advisory_abort(
                AdvisoryOwnerRuntimeContext(()),
                &self._owner._bound,
                &self._release,
            )
            .await?;
        if let Some(retained) = retained {
            if retained.locus() != AdvisoryAbortLocus::ReleasedBeforeResume
                || retained.reason() != reason
                || retained.stage() != AdvisoryAbortStage::Aborted
            {
                return Err(AdvisoryOwnerError::Conflict);
            }
            self.reauthenticate_boundary().await?;
            let Self {
                _owner,
                _release,
                _release_lifecycle_guard: _,
            } = self;
            return Ok(AbortedReleasedSingleArchiveAdvisoryOwner {
                _owner,
                _release,
                _abort: retained,
                _local_restored: None,
            });
        }
        let Self {
            _owner: owner,
            _release: release,
            _release_lifecycle_guard: lifecycle,
        } = self;
        let admission = owner
            ._capture_target
            .preflight_released_advisory_abort(&release, lifecycle)
            .await
            .map_err(map_advisory_store_error)?;
        let prepared = loop {
            match owner
                ._control
                .prepare_released_advisory_abort(
                    AdvisoryOwnerRuntimeContext(()),
                    &owner._bound,
                    &release,
                    &admission,
                )
                .await
            {
                Ok(prepared) => break prepared,
                Err(AdvisoryOwnerError::Persistence) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        };
        if prepared.locus() != AdvisoryAbortLocus::ReleasedBeforeResume
            || prepared.reason() != reason
            || prepared.stage() != AdvisoryAbortStage::Prepared
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let restored = owner
            ._capture_target
            .restore_released_advisory_local_admission_without_capture(&prepared, admission)
            .await
            .map_err(map_advisory_store_error)?;
        let terminal = loop {
            match owner
                ._control
                .finalize_released_advisory_abort(
                    AdvisoryOwnerRuntimeContext(()),
                    &prepared,
                    &restored,
                )
                .await
            {
                Ok(terminal) => break terminal,
                Err(AdvisoryOwnerError::Persistence) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        };
        let current = owner
            ._runtime
            .read_advisory_owner_current_exact(
                &AdvisoryOwnerRuntimeContext(()),
                owner._bound.observed().archive_id(),
            )
            .await
            .map_err(|_| AdvisoryOwnerError::Publication)?;
        if current != *owner._bound.observed() {
            return Err(AdvisoryOwnerError::Conflict);
        }
        let retained_release = owner
            ._control
            .load_advisory_release(AdvisoryOwnerRuntimeContext(()), &owner._bound)
            .await?
            .ok_or(AdvisoryOwnerError::Conflict)?;
        if retained_release != release || retained_release.stage != AdvisoryReleaseStage::Released {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(AbortedReleasedSingleArchiveAdvisoryOwner {
            _owner: owner,
            _release: release,
            _abort: terminal,
            _local_restored: Some(restored),
        })
    }
}

impl LocallyResumedSingleArchiveAdvisoryOwner {
    pub(crate) const fn operation_id(&self) -> MaintenanceImportOperationId {
        self._release.operation_id
    }

    pub(crate) const fn owner_id(&self) -> AdvisoryOwnerId {
        self._owner.owner_id()
    }

    /// Borrow the terminal owner to pin the exact legacy read snapshot and
    /// select its queued capture prefix. The returned Store value is opaque
    /// and cancellation restores the prefix; replay, comparison, and
    /// settlement are intentionally absent here.
    async fn begin_capture_drain(&self) -> Result<crate::store::StoreAdvisoryCapturedDrain> {
        self._resumed_target
            .begin_advisory_capture_drain()
            .await
            .map_err(map_advisory_store_error)
    }

    /// Run the owner-private, read-only advisory comparison. The returned
    /// evidence is content-free and cannot settle the captured prefix.
    async fn compare_captured_prefix(&self) -> Result<comparison::AdvisoryComparisonEvidence> {
        comparison::compare_captured_prefix(self).await
    }

    /// Consume the one-shot advisory owner into an exact durable comparison
    /// terminal. A retained row is exact-loaded before any new local work, so
    /// lost Control responses and owner restarts never run a second comparison.
    pub(super) async fn settle_comparison(self) -> Result<AdvisorySettlementOutcome> {
        comparison::reauthenticate_boundary(&self).await?;
        if let Some(retained_abort) = self
            ._owner
            ._control
            .load_advisory_abort(
                AdvisoryOwnerRuntimeContext(()),
                &self._owner._bound,
                &self._release,
            )
            .await?
        {
            if retained_abort.stage() == AdvisoryAbortStage::Aborted {
                let aborted = self.abort_resumed_owned(retained_abort.reason()).await?;
                return Ok(AdvisorySettlementOutcome::Aborted(aborted));
            }
            return Err(AdvisoryOwnerError::Conflict);
        }
        let settlement = match self
            ._owner
            ._control
            .load_advisory_comparison(
                AdvisoryOwnerRuntimeContext(()),
                &self._owner._bound,
                &self._release,
            )
            .await?
        {
            Some(retained) => retained,
            None => {
                let evidence = match self.compare_captured_prefix().await {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        let abort_reason = if matches!(
                            error,
                            AdvisoryOwnerError::Conflict | AdvisoryOwnerError::Corrupt
                        ) {
                            AdvisoryAbortReason::ComparisonMismatch
                        } else {
                            AdvisoryAbortReason::StopRequested
                        };
                        let aborted = self.abort_resumed_owned(abort_reason).await?;
                        return Ok(AdvisorySettlementOutcome::Aborted(aborted));
                    }
                };
                self._owner
                    ._control
                    .settle_advisory_comparison(
                        AdvisoryOwnerRuntimeContext(()),
                        &self._owner._bound,
                        &self._release,
                        evidence,
                    )
                    .await?
            }
        };
        comparison::reauthenticate_boundary(&self).await?;
        let retired = self
            ._resumed_target
            .retire_advisory_capture(&settlement)
            .await
            .map_err(map_advisory_store_error)?;
        comparison::reauthenticate_boundary(&self).await?;
        Ok(AdvisorySettlementOutcome::Settled(
            SettledSingleArchiveAdvisoryOwner {
                _owner: self,
                _settlement: settlement,
                _retired: retired,
            },
        ))
    }

    /// Consume a locally resumed canary into a durable stop terminal. Control
    /// records the exact predecessor before the owned Store retirement task;
    /// only the opaque exact-target proof can advance it to `Aborted`.
    pub(super) async fn abort_resumed(
        self,
        reason: AdvisoryAbortReason,
    ) -> Result<AbortedSingleArchiveAdvisoryOwner> {
        tokio::spawn(async move { self.abort_resumed_owned(reason).await })
            .await
            .map_err(|_| AdvisoryOwnerError::Publication)?
    }

    async fn abort_resumed_owned(
        self,
        reason: AdvisoryAbortReason,
    ) -> Result<AbortedSingleArchiveAdvisoryOwner> {
        comparison::reauthenticate_boundary(&self).await?;
        let retained = self
            ._owner
            ._control
            .load_advisory_abort(
                AdvisoryOwnerRuntimeContext(()),
                &self._owner._bound,
                &self._release,
            )
            .await?;
        let prepared = match retained {
            Some(retained) => {
                if retained.reason() != reason {
                    return Err(AdvisoryOwnerError::Conflict);
                }
                retained
            }
            None => {
                self._owner
                    ._control
                    .prepare_advisory_abort(
                        AdvisoryOwnerRuntimeContext(()),
                        &self._owner._bound,
                        &self._release,
                        reason,
                    )
                    .await?
            }
        };
        let prepared_stage = prepared.stage();
        let retired = loop {
            match self
                ._resumed_target
                .retire_advisory_capture_for_abort(&prepared)
                .await
                .map_err(map_advisory_store_error)
            {
                Ok(retired) => break retired,
                Err(AdvisoryOwnerError::Publication) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        };
        let terminal = if prepared_stage == AdvisoryAbortStage::Aborted {
            prepared
        } else {
            loop {
                match self
                    ._owner
                    ._control
                    .finalize_advisory_abort(AdvisoryOwnerRuntimeContext(()), &prepared, &retired)
                    .await
                {
                    Ok(terminal) => break terminal,
                    Err(AdvisoryOwnerError::Persistence) => {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        comparison::reauthenticate_boundary(&self).await?;
        Ok(AbortedSingleArchiveAdvisoryOwner {
            _owner: self,
            _abort: terminal,
            _retired: retired,
        })
    }
}

fn map_advisory_store_error(error: crate::error::EnclaveError) -> AdvisoryOwnerError {
    match error {
        crate::error::EnclaveError::Auth(_)
        | crate::error::EnclaveError::Conflict(_)
        | crate::error::EnclaveError::InvalidRequest(_) => AdvisoryOwnerError::Conflict,
        _ => AdvisoryOwnerError::Publication,
    }
}

impl fmt::Debug for SingleArchiveAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleArchiveAdvisoryOwner(<inactive>)")
    }
}

impl fmt::Debug for ReleasedSingleArchiveAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReleasedSingleArchiveAdvisoryOwner(<inactive>)")
    }
}

impl fmt::Debug for LocallyResumedSingleArchiveAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocallyResumedSingleArchiveAdvisoryOwner(<inactive>)")
    }
}

/// Typed terminal capability returned by comparison settlement.
pub(crate) enum AdvisorySettlementOutcome {
    Settled(SettledSingleArchiveAdvisoryOwner),
    Aborted(AbortedSingleArchiveAdvisoryOwner),
}

impl SettledSingleArchiveAdvisoryOwner {
    pub(crate) const fn operation_id(&self) -> MaintenanceImportOperationId {
        self._settlement.operation_id()
    }

    pub(crate) const fn evidence_commitment(&self) -> [u8; 32] {
        self._settlement.evidence_commitment()
    }

    pub(crate) const fn settlement_commitment(&self) -> [u8; 32] {
        self._settlement.commitment()
    }
}

impl AbortedSingleArchiveAdvisoryOwner {
    pub(crate) const fn operation_id(&self) -> MaintenanceImportOperationId {
        self._abort.operation_id()
    }

    pub(crate) const fn reason(&self) -> AdvisoryAbortReason {
        self._abort.reason()
    }
}

impl fmt::Debug for SettledSingleArchiveAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SettledSingleArchiveAdvisoryOwner(<inactive>)")
    }
}

impl fmt::Debug for AbortedSingleArchiveAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AbortedSingleArchiveAdvisoryOwner(<inactive>)")
    }
}

impl fmt::Debug for AbortedReleasedSingleArchiveAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AbortedReleasedSingleArchiveAdvisoryOwner(<inactive>)")
    }
}

#[cfg(test)]
pub(crate) struct AdvisoryOwnerTestHandle(SingleArchiveAdvisoryOwner);

#[cfg(test)]
pub(crate) struct ReleasedAdvisoryOwnerTestHandle(ReleasedSingleArchiveAdvisoryOwner);

#[cfg(test)]
pub(crate) struct LocallyResumedAdvisoryOwnerTestHandle(LocallyResumedSingleArchiveAdvisoryOwner);

#[cfg(test)]
pub(crate) struct SettledAdvisoryOwnerTestHandle(SettledSingleArchiveAdvisoryOwner);

#[cfg(test)]
pub(crate) struct AbortedAdvisoryOwnerTestHandle(AbortedSingleArchiveAdvisoryOwner);

#[cfg(test)]
pub(crate) struct AbortedReleasedAdvisoryOwnerTestHandle(AbortedReleasedSingleArchiveAdvisoryOwner);

#[cfg(test)]
impl AdvisoryOwnerTestHandle {
    pub(crate) async fn maintain_lease(&mut self) -> Result<()> {
        self.0.maintain_lease().await
    }

    pub(crate) fn owner_id_for_test(&self) -> [u8; 16] {
        *self.0.owner_id().as_bytes()
    }

    pub(crate) const fn may_heartbeat(&self) -> bool {
        self.0.may_heartbeat
    }

    pub(crate) fn has_exact_capture_target(
        &self,
        user_id: &str,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
    ) -> bool {
        self.0
            ._capture_target
            .exact_identity_for_test(user_id, archive_id, operation_id)
    }

    pub(crate) async fn release_legacy_fence(self) -> Result<ReleasedAdvisoryOwnerTestHandle> {
        self.0
            .release_legacy_fence()
            .await
            .map(ReleasedAdvisoryOwnerTestHandle)
    }

    pub(crate) async fn mark_advisory_fence_delete_started(&self) -> Result<()> {
        let release = match self
            .0
            ._control
            .load_advisory_release(AdvisoryOwnerRuntimeContext(()), &self.0._bound)
            .await?
        {
            Some(retained) => retained,
            None => {
                self.0
                    ._control
                    .prepare_advisory_release(AdvisoryOwnerRuntimeContext(()), &self.0._bound)
                    .await?
            }
        };
        match release.stage {
            AdvisoryReleaseStage::Prepared => {
                let observation = self
                    .0
                    ._capture_target
                    .observe_advisory_fence(&release)
                    .await
                    .map_err(map_advisory_store_error)?;
                let next = self
                    .0
                    ._control
                    .mark_advisory_fence_delete_started(
                        AdvisoryOwnerRuntimeContext(()),
                        &release,
                        &observation,
                    )
                    .await?;
                (next.stage == AdvisoryReleaseStage::DeleteStarted)
                    .then_some(())
                    .ok_or(AdvisoryOwnerError::Corrupt)
            }
            AdvisoryReleaseStage::DeleteStarted => Ok(()),
            AdvisoryReleaseStage::Released => Err(AdvisoryOwnerError::Conflict),
        }
    }

    pub(crate) async fn reconcile_advisory_fence_absence_for_test(&self) -> Result<()> {
        let release = self
            .0
            ._control
            .load_advisory_release(AdvisoryOwnerRuntimeContext(()), &self.0._bound)
            .await?
            .ok_or(AdvisoryOwnerError::Conflict)?;
        if release.stage != AdvisoryReleaseStage::DeleteStarted {
            return Err(AdvisoryOwnerError::Conflict);
        }
        self.0
            ._capture_target
            .reconcile_advisory_fence_absence(&release)
            .await
            .map(|_| ())
            .map_err(map_advisory_store_error)
    }
}

#[cfg(test)]
impl ReleasedAdvisoryOwnerTestHandle {
    pub(crate) fn has_exact_capture_target(
        &self,
        user_id: &str,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
    ) -> bool {
        self.0
            ._owner
            ._capture_target
            .exact_identity_for_test(user_id, archive_id, operation_id)
    }

    pub(crate) fn is_released(&self) -> bool {
        self.0._release.stage == AdvisoryReleaseStage::Released
    }

    pub(crate) async fn resume_local_admission(
        self,
    ) -> Result<LocallyResumedAdvisoryOwnerTestHandle> {
        self.0
            .resume_local_admission()
            .await
            .map(LocallyResumedAdvisoryOwnerTestHandle)
    }

    pub(crate) async fn abort_released_for_test(
        self,
        reason: AdvisoryAbortReason,
    ) -> Result<AbortedReleasedAdvisoryOwnerTestHandle> {
        self.0
            .abort_before_local_resume(reason)
            .await
            .map(AbortedReleasedAdvisoryOwnerTestHandle)
    }

    pub(crate) async fn prepare_released_abort_for_restart_test(self) -> Result<()> {
        self.0.reauthenticate_boundary().await?;
        let ReleasedSingleArchiveAdvisoryOwner {
            _owner: owner,
            _release: release,
            _release_lifecycle_guard: lifecycle,
        } = self.0;
        let admission = owner
            ._capture_target
            .preflight_released_advisory_abort(&release, lifecycle)
            .await
            .map_err(map_advisory_store_error)?;
        let prepared = owner
            ._control
            .prepare_released_advisory_abort(
                AdvisoryOwnerRuntimeContext(()),
                &owner._bound,
                &release,
                &admission,
            )
            .await?;
        if prepared.locus() != AdvisoryAbortLocus::ReleasedBeforeResume
            || prepared.stage() != AdvisoryAbortStage::Prepared
        {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(())
    }
}

#[cfg(test)]
impl LocallyResumedAdvisoryOwnerTestHandle {
    pub(crate) fn has_exact_resumed_target(
        &self,
        user_id: &str,
        archive_id: ArchiveId,
        operation_id: MaintenanceImportOperationId,
    ) -> bool {
        self.0
            ._resumed_target
            .exact_identity_for_test(user_id, archive_id, operation_id)
    }

    pub(crate) async fn captured_commit_count_for_test(&self) -> Option<usize> {
        self.0
            ._resumed_target
            .captured_commit_count_for_test()
            .await
    }

    pub(crate) async fn begin_capture_drain_for_test(
        &self,
    ) -> Result<crate::store::StoreAdvisoryCapturedDrain> {
        self.0.begin_capture_drain().await
    }

    pub(crate) async fn compare_captured_prefix_for_test(&self) -> Result<String> {
        self.0
            .compare_captured_prefix()
            .await
            .map(|evidence| format!("{evidence:?}"))
    }

    pub(crate) async fn compare_captured_prefix_with_stall_for_test(
        &self,
        stall: Arc<crate::store::AdvisoryComparisonStall>,
    ) -> Result<String> {
        comparison::compare_captured_prefix_with_stall(&self.0, stall)
            .await
            .map(|evidence| format!("{evidence:?}"))
    }

    pub(crate) async fn write_uncaptured_metadata_for_test(
        &self,
        key: &str,
        value: &str,
    ) -> crate::error::Result<()> {
        self.0
            ._resumed_target
            .write_uncaptured_metadata_for_test(key, value)
            .await
    }

    pub(crate) async fn delete_uncaptured_metadata_for_test(
        &self,
        key: &str,
    ) -> crate::error::Result<()> {
        self.0
            ._resumed_target
            .delete_uncaptured_metadata_for_test(key)
            .await
    }

    pub(crate) async fn settle_comparison_for_test(self) -> Result<SettledAdvisoryOwnerTestHandle> {
        match self.0.settle_comparison().await? {
            AdvisorySettlementOutcome::Settled(settled) => {
                Ok(SettledAdvisoryOwnerTestHandle(settled))
            }
            AdvisorySettlementOutcome::Aborted(_) => Err(AdvisoryOwnerError::Conflict),
        }
    }

    pub(crate) async fn settle_comparison_outcome_for_test(
        self,
    ) -> Result<AdvisorySettlementOutcome> {
        self.0.settle_comparison().await
    }

    pub(crate) async fn persist_comparison_without_retirement_for_test(&self) -> Result<()> {
        let evidence = self.0.compare_captured_prefix().await?;
        self.0
            ._owner
            ._control
            .settle_advisory_comparison(
                AdvisoryOwnerRuntimeContext(()),
                &self.0._owner._bound,
                &self.0._release,
                evidence,
            )
            .await
            .map(|_| ())
    }

    pub(crate) async fn abort_for_test(
        self,
        reason: AdvisoryAbortReason,
    ) -> Result<AbortedAdvisoryOwnerTestHandle> {
        self.0
            .abort_resumed(reason)
            .await
            .map(AbortedAdvisoryOwnerTestHandle)
    }

    pub(crate) fn into_inner(self) -> LocallyResumedSingleArchiveAdvisoryOwner {
        self.0
    }

    pub(crate) async fn prepare_abort_for_restart_test(
        self,
        reason: AdvisoryAbortReason,
    ) -> Result<()> {
        comparison::reauthenticate_boundary(&self.0).await?;
        let retained = self
            .0
            ._owner
            ._control
            .load_advisory_abort(
                AdvisoryOwnerRuntimeContext(()),
                &self.0._owner._bound,
                &self.0._release,
            )
            .await?;
        let prepared = match retained {
            Some(retained) => retained,
            None => {
                self.0
                    ._owner
                    ._control
                    .prepare_advisory_abort(
                        AdvisoryOwnerRuntimeContext(()),
                        &self.0._owner._bound,
                        &self.0._release,
                        reason,
                    )
                    .await?
            }
        };
        if prepared.stage() != AdvisoryAbortStage::Prepared || prepared.reason() != reason {
            return Err(AdvisoryOwnerError::Conflict);
        }
        Ok(())
    }

    pub(crate) async fn abort_with_started_for_test(
        self,
        reason: AdvisoryAbortReason,
        started: Arc<tokio::sync::Semaphore>,
    ) -> Result<AbortedAdvisoryOwnerTestHandle> {
        let task = tokio::spawn(async move { self.0.abort_resumed_owned(reason).await });
        started.add_permits(1);
        task.await
            .map_err(|_| AdvisoryOwnerError::Publication)?
            .map(AbortedAdvisoryOwnerTestHandle)
    }
}

#[cfg(test)]
pub(crate) async fn reconcile_prepared_abort_for_test(
    control: Arc<crate::cp::control_store::ControlStore>,
    store: Arc<crate::store::Store>,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
) -> Result<AdvisoryAbortStage> {
    let control: Arc<dyn AdvisoryOwnerControl> = control;
    abort_reconcile::reconcile_prepared_abort(control, store, operation_id)
        .await
        .map(|terminal| terminal.stage())
}

#[cfg(test)]
pub(crate) async fn prove_prepared_abort_absence_for_test(
    control: Arc<crate::cp::control_store::ControlStore>,
    store: Arc<crate::store::Store>,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
) -> Result<()> {
    let recovery = control
        .load_advisory_abort_recovery(AdvisoryOwnerRuntimeContext(()), operation_id)
        .await?
        .ok_or(AdvisoryOwnerError::Conflict)?;
    let AdvisoryAbortRecoveryState::Prepared(recovery) = recovery else {
        return Err(AdvisoryOwnerError::Conflict);
    };
    store
        .prove_prepared_advisory_abort_local_absence(&recovery)
        .await
        .map(|_| ())
        .map_err(map_advisory_store_error)
}

#[cfg(test)]
pub(crate) async fn finalize_prepared_abort_recovery_once_for_test(
    control: Arc<crate::cp::control_store::ControlStore>,
    store: Arc<crate::store::Store>,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
) -> Result<AdvisoryAbortStage> {
    let recovery = control
        .load_advisory_abort_recovery(AdvisoryOwnerRuntimeContext(()), operation_id)
        .await?
        .ok_or(AdvisoryOwnerError::Conflict)?;
    let AdvisoryAbortRecoveryState::Prepared(recovery) = recovery else {
        return Err(AdvisoryOwnerError::Conflict);
    };
    let absence = store
        .prove_prepared_advisory_abort_local_absence(&recovery)
        .await
        .map_err(map_advisory_store_error)?;
    control
        .finalize_advisory_abort_recovery(AdvisoryOwnerRuntimeContext(()), &recovery, &absence)
        .await
        .map(|terminal| terminal.stage())
}

#[cfg(test)]
pub(crate) async fn reconcile_prepared_abort_with_started_for_test(
    control: Arc<crate::cp::control_store::ControlStore>,
    store: Arc<crate::store::Store>,
    operation_id: crate::archive_v3_maintenance_import::MaintenanceImportOperationId,
    started: Arc<tokio::sync::Semaphore>,
) -> Result<AdvisoryAbortStage> {
    let control: Arc<dyn AdvisoryOwnerControl> = control;
    abort_reconcile::reconcile_prepared_abort_with_started(control, store, operation_id, started)
        .await
        .map(|terminal| terminal.stage())
}

#[cfg(test)]
impl fmt::Debug for AdvisoryOwnerTestHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
impl fmt::Debug for ReleasedAdvisoryOwnerTestHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
impl fmt::Debug for LocallyResumedAdvisoryOwnerTestHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
impl fmt::Debug for SettledAdvisoryOwnerTestHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
impl fmt::Debug for AbortedAdvisoryOwnerTestHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
impl AbortedReleasedAdvisoryOwnerTestHandle {
    pub(crate) fn is_aborted(&self) -> bool {
        self.0._abort.stage() == AdvisoryAbortStage::Aborted
    }

    pub(crate) fn retained_local_restoration(&self) -> bool {
        self.0._local_restored.is_some()
    }
}

#[cfg(test)]
impl fmt::Debug for AbortedReleasedAdvisoryOwnerTestHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
impl SettledAdvisoryOwnerTestHandle {
    pub(crate) async fn capture_is_retired_for_test(&self) -> bool {
        self.0
            ._owner
            ._resumed_target
            .captured_commit_count_for_test()
            .await
            .is_none()
    }

    pub(crate) async fn reconcile_capture_retirement_for_test(&self) -> Result<()> {
        self.0
            ._owner
            ._resumed_target
            .retire_advisory_capture(&self.0._settlement)
            .await
            .map(|_| ())
            .map_err(map_advisory_store_error)
    }
}

#[cfg(test)]
impl AbortedAdvisoryOwnerTestHandle {
    pub(crate) async fn capture_is_retired_for_test(&self) -> bool {
        self.0
            ._owner
            ._resumed_target
            .captured_commit_count_for_test()
            .await
            .is_none()
    }

    pub(crate) fn stage_for_test(&self) -> AdvisoryAbortStage {
        self.0._abort.stage()
    }

    pub(crate) async fn reconcile_capture_retirement_for_test(&self) -> Result<()> {
        self.0
            ._owner
            ._resumed_target
            .retire_advisory_capture_for_abort(&self.0._abort)
            .await
            .map(|_| ())
            .map_err(map_advisory_store_error)
    }
}

#[cfg(test)]
pub(crate) async fn start_advisory_owner_for_test(
    handoff: CompletedAdvisoryShadowHandoff,
    canary: AdvisoryCanaryScope,
) -> Result<AdvisoryOwnerTestHandle> {
    SingleArchiveAdvisoryOwner::start(handoff, canary)
        .await
        .map(AdvisoryOwnerTestHandle)
}
