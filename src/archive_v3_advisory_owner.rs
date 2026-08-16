#![allow(
    dead_code,
    reason = "inactive ADR-0022 Phase-1 advisory owner is compiled before Store/startup wiring"
)]

//! Inactive, Phase-1-only owner lease lifecycle for one advisory `ShadowWal`
//! archive. The state machine authenticates the parity-certified maintenance
//! handoff, durably reserves one random owner, records `SendStarted` before the
//! initial witness transaction, and adopts only exact one-step acquisition,
//! heartbeat, or post-expiry reacquire successors. It is deliberately separate
//! from the `WalAuthoritative` publisher and exposes no Store, capture, root,
//! object, cipher, acknowledgement, route, task, configuration, or serving
//! capability.

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

/// Opaque owner capability. It intentionally has no operation method in this
/// slice; owning it proves only that Control and the exact ShadowWal witness
/// agree on one initial advisory lease.
struct SingleArchiveAdvisoryOwner {
    _runtime: crate::archive_v3_shadow_runtime::AdvisoryOwnerRuntimeOwner,
    _control: Arc<crate::cp::control_store::ControlStore>,
    _archive_binding: crate::archive_v3_shadow_runtime::DurableSingleArchiveBinding,
    _parity: crate::archive_v3_maintenance_import::CompletedAdvisoryShadowParityEvidence,
    _bound: BoundAdvisoryOwner,
    may_heartbeat: bool,
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
}

impl fmt::Debug for SingleArchiveAdvisoryOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SingleArchiveAdvisoryOwner(<inactive>)")
    }
}

#[cfg(test)]
pub(crate) struct AdvisoryOwnerTestHandle(SingleArchiveAdvisoryOwner);

#[cfg(test)]
impl AdvisoryOwnerTestHandle {
    pub(crate) async fn maintain_lease(&mut self) -> Result<()> {
        self.0.maintain_lease().await
    }

    pub(crate) const fn may_heartbeat(&self) -> bool {
        self.0.may_heartbeat
    }
}

#[cfg(test)]
impl fmt::Debug for AdvisoryOwnerTestHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
pub(crate) async fn start_advisory_owner_for_test(
    handoff: CompletedAdvisoryShadowHandoff,
) -> Result<AdvisoryOwnerTestHandle> {
    SingleArchiveAdvisoryOwner::start(handoff)
        .await
        .map(AdvisoryOwnerTestHandle)
}
