#![allow(
    dead_code,
    reason = "inactive ADR-0022 Phase-1 advisory owner is compiled before Store/startup wiring"
)]

//! Inactive, Phase-1-only owner bootstrap for one advisory `ShadowWal`
//! archive. The state machine authenticates the parity-certified maintenance
//! handoff, durably reserves one random owner, records `SendStarted` before the
//! witness transaction, and adopts only the exact lost-response successor.
//! It is deliberately separate from the `WalAuthoritative` publisher and
//! exposes no Store, capture, object, cipher, acknowledgement, route, task,
//! configuration, or serving capability.

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
        if revision == 0
            || expected.deletion() != DeletionState::Active
            || expected.migration() != MigrationState::ShadowWal
            || !expected.is_exact_unleased_advisory_terminal()
            || predecessor.is_some() != observed.is_some()
            || (stage == AdvisoryOwnerStage::Bound) != observed.is_some()
            || observed.is_some_and(|value| {
                predecessor != Some(&expected)
                    || value
                        .exact_advisory_owner_acquire_from(&expected, owner_id.as_bytes())
                        .is_err()
            })
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

    const fn owner_id(&self) -> AdvisoryOwnerId {
        self.owner_id
    }

    const fn stage(&self) -> AdvisoryOwnerStage {
        self.stage
    }
}

impl fmt::Debug for AdvisoryOwnerReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdvisoryOwnerReservation(<opaque>)")
    }
}

/// Non-cloneable exact initial advisory owner lease. No renewal or root
/// mutation method exists in this slice.
pub(crate) struct BoundAdvisoryOwner {
    operation_id: MaintenanceImportOperationId,
    owner_id: AdvisoryOwnerId,
    expected: WitnessRecord,
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
        let lease = observed
            .exact_advisory_owner_acquire_from(&predecessor, owner_id.as_bytes())
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
        if predecessor != expected
            || revision == 0
            || commitment == [0; 32]
            || commitment != persisted_commitment
        {
            return Err(AdvisoryOwnerError::Corrupt);
        }
        Ok(Self {
            operation_id,
            owner_id,
            expected,
            observed,
            lease,
            revision,
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
        &WitnessRecord,
        WitnessLease,
        u64,
        [u8; 32],
    ) {
        (
            self.operation_id,
            self.owner_id,
            &self.expected,
            &self.observed,
            self.lease,
            self.revision,
            self.commitment,
        )
    }
}

impl fmt::Debug for BoundAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundAdvisoryOwner(<opaque>)")
    }
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
    async fn reserve_advisory_owner(
        &self,
        token: AdvisoryOwnerRuntimeContext,
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
}

/// Token available only inside this module. It prevents the provider bundle
/// and advisory handoff from being consumed by a sibling production caller.
#[derive(Clone, Copy)]
pub(crate) struct AdvisoryOwnerRuntimeContext(());

/// Opaque owner capability. It intentionally has no operation method in this
/// slice; owning it proves only that Control and the exact ShadowWal witness
/// agree on one initial advisory lease.
struct SingleArchiveAdvisoryOwner {
    _runtime: crate::archive_v3_shadow_runtime::AdvisoryOwnerRuntimeOwner,
    _control: Arc<crate::cp::control_store::ControlStore>,
    _archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    _parity: crate::archive_v3_maintenance_import::CompletedAdvisoryShadowParityEvidence,
    _bound: BoundAdvisoryOwner,
}

impl SingleArchiveAdvisoryOwner {
    async fn start(handoff: CompletedAdvisoryShadowHandoff) -> Result<Self> {
        let CompletedAdvisoryShadowHandoffView {
            runtime,
            terminal_witness,
            archive_binding,
            parity,
            control,
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
        let runtime = runtime
            .into_advisory_owner(AdvisoryOwnerRuntimeContext(()))
            .map_err(|_| AdvisoryOwnerError::Publication)?;
        let reserved = control
            .reserve_advisory_owner(
                AdvisoryOwnerRuntimeContext(()),
                operation_id,
                &terminal_witness,
            )
            .await?;
        let bound = if reserved.stage() == AdvisoryOwnerStage::Bound {
            let current = runtime
                .read_advisory_owner_current_exact(
                    &AdvisoryOwnerRuntimeContext(()),
                    terminal_witness.archive_id(),
                )
                .await
                .map_err(|_| AdvisoryOwnerError::Publication)?;
            control
                .load_bound_advisory_owner(AdvisoryOwnerRuntimeContext(()), operation_id, &current)
                .await?
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
            control
                .bind_advisory_owner(AdvisoryOwnerRuntimeContext(()), &reserved, &observed, lease)
                .await?
        };
        Ok(Self {
            _runtime: runtime,
            _control: control,
            _archive_binding: archive_binding,
            _parity: parity,
            _bound: bound,
        })
    }
}

impl fmt::Debug for SingleArchiveAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleArchiveAdvisoryOwner(<inactive>)")
    }
}

#[cfg(test)]
pub(crate) async fn start_advisory_owner_for_test(
    handoff: CompletedAdvisoryShadowHandoff,
) -> Result<impl fmt::Debug> {
    SingleArchiveAdvisoryOwner::start(handoff).await
}
