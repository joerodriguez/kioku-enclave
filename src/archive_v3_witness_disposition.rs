#![allow(
    dead_code,
    reason = "inactive ADR-0022 pre-witness disposition capability is compiled and fake-tested before authority wiring"
)]

//! Capability-only resolution for an archive deleted before its first witness
//! was durably established.
//!
//! Encrypted control state is consulted before the injected exact-name witness
//! reader. Missing, unsupported, active, or inconsistent control state cannot
//! cause witness I/O. A definite absence proof exists only for an enrolled v1
//! protocol that deletion atomically closed before send started and for which
//! a fresh exact read still observes no document.

use crate::{
    archive_v3::{ArchiveId, ObjectId},
    archive_v3_lifecycle::{BootstrapAttemptId, LifecycleError},
    archive_v3_witness::WitnessRecord,
};
use async_trait::async_trait;
use sha2::Digest;
use std::fmt;
use thiserror::Error;

/// Fully authenticated, content-free control snapshot. Only the encrypted
/// control producer can construct it outside tests.
pub(crate) struct ClosedWitnessProtocol {
    archive_id: ArchiveId,
    attempt_id: BootstrapAttemptId,
    deletion_fence: ObjectId,
    lifecycle_revision: u64,
    expected_record: Option<Box<[u8]>>,
    expected_hash: Option<[u8; 32]>,
    expected_len: Option<u32>,
    admission_revision: Option<u64>,
    protocol_version: u16,
    protocol_commitment: [u8; 32],
    phase: ClosedWitnessPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClosedWitnessPhase {
    ClosedUnsent,
    ClosedStarted,
    AbsenceConfirmed,
    PresentExact,
    ManualRequired,
}

impl ClosedWitnessProtocol {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_control_snapshot(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        archive_id: ArchiveId,
        attempt_id: BootstrapAttemptId,
        deletion_fence: ObjectId,
        lifecycle_revision: u64,
        expected_record: Option<Vec<u8>>,
        expected_hash: Option<[u8; 32]>,
        expected_len: Option<u32>,
        admission_revision: Option<u64>,
        protocol_version: u16,
        protocol_commitment: [u8; 32],
        phase: ClosedWitnessPhase,
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            archive_id,
            attempt_id,
            deletion_fence,
            lifecycle_revision,
            expected_record,
            expected_hash,
            expected_len,
            admission_revision,
            protocol_version,
            protocol_commitment,
            phase,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test(
        archive_id: ArchiveId,
        attempt_id: BootstrapAttemptId,
        deletion_fence: ObjectId,
        lifecycle_revision: u64,
        expected_record: Option<Vec<u8>>,
        expected_hash: Option<[u8; 32]>,
        expected_len: Option<u32>,
        admission_revision: Option<u64>,
        protocol_version: u16,
        protocol_commitment: [u8; 32],
        phase: ClosedWitnessPhase,
    ) -> Result<Self, LifecycleError> {
        Self::validated(
            archive_id,
            attempt_id,
            deletion_fence,
            lifecycle_revision,
            expected_record,
            expected_hash,
            expected_len,
            admission_revision,
            protocol_version,
            protocol_commitment,
            phase,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn validated(
        archive_id: ArchiveId,
        attempt_id: BootstrapAttemptId,
        deletion_fence: ObjectId,
        lifecycle_revision: u64,
        expected_record: Option<Vec<u8>>,
        expected_hash: Option<[u8; 32]>,
        expected_len: Option<u32>,
        admission_revision: Option<u64>,
        protocol_version: u16,
        protocol_commitment: [u8; 32],
        phase: ClosedWitnessPhase,
    ) -> Result<Self, LifecycleError> {
        let expected_tuple_valid = match (&expected_record, expected_hash, expected_len) {
            (None, None, None) => true,
            (Some(bytes), Some(hash), Some(len)) => {
                !bytes.is_empty()
                    && usize::try_from(len).ok() == Some(bytes.len())
                    && <[u8; 32]>::from(sha2::Sha256::digest(bytes)) == hash
            }
            _ => false,
        };
        let admission_valid = admission_revision.is_none() || expected_hash.is_some();
        let phase_valid = match phase {
            ClosedWitnessPhase::ClosedUnsent => true,
            ClosedWitnessPhase::ClosedStarted | ClosedWitnessPhase::PresentExact => {
                expected_hash.is_some() && admission_revision.is_some()
            }
            ClosedWitnessPhase::AbsenceConfirmed => admission_revision.is_none(),
            // Started/manual recovery retains its admission. A contradictory
            // witness observed after a definitely-unsent/confirmed-absent
            // state is instead durably poisoned with no admission.
            ClosedWitnessPhase::ManualRequired => true,
        };
        if archive_id.as_bytes() == &[0; 16]
            || deletion_fence.as_bytes() == &[0; 16]
            || lifecycle_revision == 0
            || protocol_version == 0
            || protocol_commitment == [0; 32]
            || !expected_tuple_valid
            || !admission_valid
            || !phase_valid
        {
            return Err(LifecycleError::Corrupt);
        }
        Ok(Self {
            archive_id,
            attempt_id,
            deletion_fence,
            lifecycle_revision,
            expected_record: expected_record.map(Vec::into_boxed_slice),
            expected_hash,
            expected_len,
            admission_revision,
            protocol_version,
            protocol_commitment,
            phase,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn attempt_id(&self) -> BootstrapAttemptId {
        self.attempt_id
    }

    pub(crate) const fn deletion_fence(&self) -> ObjectId {
        self.deletion_fence
    }

    pub(crate) const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    pub(crate) fn expected_record(&self) -> Option<&[u8]> {
        self.expected_record.as_deref()
    }

    pub(crate) const fn expected_hash(&self) -> Option<[u8; 32]> {
        self.expected_hash
    }

    pub(crate) const fn expected_len(&self) -> Option<u32> {
        self.expected_len
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn admission_revision(&self) -> Option<u64> {
        self.admission_revision
    }

    pub(crate) const fn protocol_commitment(&self) -> [u8; 32] {
        self.protocol_commitment
    }

    pub(crate) const fn phase(&self) -> ClosedWitnessPhase {
        self.phase
    }
}

impl fmt::Debug for ClosedWitnessProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClosedWitnessProtocol(<opaque>)")
    }
}

pub(crate) enum PreWitnessControlState {
    Participating(ClosedWitnessProtocol),
    NotParticipating,
    UnsupportedManual,
}

/// One-shot proof that the coordinator obtained `None` from the injected
/// exact-name witness reader for this exact authenticated control snapshot.
/// Only this module can construct it; encrypted control consumes it.
pub(crate) struct ExactNoneObservation {
    snapshot: ClosedWitnessProtocol,
}

impl ExactNoneObservation {
    fn from_exact_read(snapshot: ClosedWitnessProtocol) -> Self {
        Self { snapshot }
    }

    pub(crate) fn into_control_snapshot(self) -> ClosedWitnessProtocol {
        self.snapshot
    }
}

impl fmt::Debug for ExactNoneObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactNoneObservation(<opaque>)")
    }
}

impl fmt::Debug for PreWitnessControlState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Participating(_) => formatter.write_str("Participating(<opaque>)"),
            Self::NotParticipating => formatter.write_str("NotParticipating"),
            Self::UnsupportedManual => formatter.write_str("UnsupportedManual"),
        }
    }
}

/// Non-cloneable proof of one fresh exact absent read and a matching
/// full-state encrypted-control CAS.
pub(crate) struct AuthenticatedPreWitnessAbsence {
    archive_id: ArchiveId,
    attempt_id: BootstrapAttemptId,
    deletion_fence: ObjectId,
    lifecycle_revision: u64,
    expected_hash: Option<[u8; 32]>,
    expected_len: Option<u32>,
    protocol_version: u16,
    admission_revision: Option<u64>,
    protocol_commitment: [u8; 32],
}

impl AuthenticatedPreWitnessAbsence {
    pub(crate) fn from_control_cas(
        _producer: &crate::cp::control_store::LifecyclePersistenceContext,
        snapshot: &ClosedWitnessProtocol,
        resulting_revision: u64,
        resulting_commitment: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if resulting_revision <= snapshot.lifecycle_revision || resulting_commitment == [0; 32] {
            return Err(LifecycleError::Corrupt);
        }
        Ok(Self {
            archive_id: snapshot.archive_id,
            attempt_id: snapshot.attempt_id,
            deletion_fence: snapshot.deletion_fence,
            lifecycle_revision: resulting_revision,
            expected_hash: snapshot.expected_hash,
            expected_len: snapshot.expected_len,
            protocol_version: snapshot.protocol_version,
            admission_revision: snapshot.admission_revision,
            protocol_commitment: resulting_commitment,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        snapshot: &ClosedWitnessProtocol,
        resulting_commitment: [u8; 32],
    ) -> Result<Self, LifecycleError> {
        if resulting_commitment == [0; 32] {
            return Err(LifecycleError::Corrupt);
        }
        Ok(Self {
            archive_id: snapshot.archive_id,
            attempt_id: snapshot.attempt_id,
            deletion_fence: snapshot.deletion_fence,
            lifecycle_revision: snapshot.lifecycle_revision.saturating_add(1),
            expected_hash: snapshot.expected_hash,
            expected_len: snapshot.expected_len,
            protocol_version: snapshot.protocol_version,
            admission_revision: snapshot.admission_revision,
            protocol_commitment: resulting_commitment,
        })
    }

    pub(crate) const fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub(crate) const fn deletion_fence(&self) -> ObjectId {
        self.deletion_fence
    }
}

impl fmt::Debug for AuthenticatedPreWitnessAbsence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPreWitnessAbsence(<opaque>)")
    }
}

pub(crate) enum PreWitnessDisposition {
    ConfirmedAbsent(AuthenticatedPreWitnessAbsence),
    WitnessPresent,
    ManualRequired,
    NotParticipating,
}

impl fmt::Debug for PreWitnessDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfirmedAbsent(_) => formatter.write_str("ConfirmedAbsent(<opaque>)"),
            Self::WitnessPresent => formatter.write_str("WitnessPresent"),
            Self::ManualRequired => formatter.write_str("ManualRequired"),
            Self::NotParticipating => formatter.write_str("NotParticipating"),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum PreWitnessDispositionError {
    #[error("pre-witness control authority rejected the request")]
    Control,
    #[error("exact witness read is unavailable")]
    WitnessRead,
    #[error("persisted pre-witness protocol is corrupt")]
    Corrupt,
}

#[async_trait]
pub(crate) trait PreWitnessDispositionControl: Send + Sync {
    async fn authenticate_closed_protocol(
        &self,
        archive_id: ArchiveId,
        deletion_fence: ObjectId,
    ) -> Result<PreWitnessControlState, LifecycleError>;

    async fn confirm_absence(
        &self,
        observation: ExactNoneObservation,
    ) -> Result<AuthenticatedPreWitnessAbsence, LifecycleError>;

    async fn record_present_exact(
        &self,
        snapshot: &ClosedWitnessProtocol,
    ) -> Result<(), LifecycleError>;

    async fn require_manual(&self, snapshot: &ClosedWitnessProtocol) -> Result<(), LifecycleError>;
}

#[async_trait]
pub(crate) trait ExactPreWitnessReader: Send + Sync {
    async fn read_exact_witness(
        &self,
        archive_id: ArchiveId,
    ) -> Result<ExactPreWitnessObservation, PreWitnessDispositionError>;
}

pub(crate) enum ExactPreWitnessObservation {
    Absent,
    Present(Box<WitnessRecord>),
    /// The exact-name provider response proves that a document exists, but
    /// its name/shape/record is not the sole canonical witness encoding.
    DefinitelyPresentInvalid,
}

pub(crate) async fn resolve_pre_witness_disposition(
    archive_id: ArchiveId,
    deletion_fence: ObjectId,
    control: &dyn PreWitnessDispositionControl,
    witness: &dyn ExactPreWitnessReader,
) -> Result<PreWitnessDisposition, PreWitnessDispositionError> {
    let snapshot = match control
        .authenticate_closed_protocol(archive_id, deletion_fence)
        .await
        .map_err(|_| PreWitnessDispositionError::Control)?
    {
        PreWitnessControlState::NotParticipating => {
            return Ok(PreWitnessDisposition::NotParticipating)
        }
        PreWitnessControlState::UnsupportedManual => {
            return Ok(PreWitnessDisposition::ManualRequired)
        }
        PreWitnessControlState::Participating(snapshot) => snapshot,
    };
    let observed = witness.read_exact_witness(archive_id).await?;
    if matches!(
        &observed,
        ExactPreWitnessObservation::DefinitelyPresentInvalid
    ) {
        control
            .require_manual(&snapshot)
            .await
            .map_err(|_| PreWitnessDispositionError::Control)?;
        return Ok(PreWitnessDisposition::ManualRequired);
    }
    let exact = match &observed {
        ExactPreWitnessObservation::Present(record) => {
            let encoded = record.encode();
            snapshot
                .expected_record()
                .is_some_and(|expected| expected == encoded.as_slice())
        }
        ExactPreWitnessObservation::Absent
        | ExactPreWitnessObservation::DefinitelyPresentInvalid => false,
    };
    if exact {
        match snapshot.phase() {
            ClosedWitnessPhase::ClosedStarted | ClosedWitnessPhase::PresentExact => {
                control
                    .record_present_exact(&snapshot)
                    .await
                    .map_err(|_| PreWitnessDispositionError::Control)?;
                return Ok(PreWitnessDisposition::WitnessPresent);
            }
            ClosedWitnessPhase::ManualRequired if snapshot.admission_revision().is_some() => {
                control
                    .record_present_exact(&snapshot)
                    .await
                    .map_err(|_| PreWitnessDispositionError::Control)?;
                return Ok(PreWitnessDisposition::WitnessPresent);
            }
            ClosedWitnessPhase::ClosedUnsent
            | ClosedWitnessPhase::AbsenceConfirmed
            | ClosedWitnessPhase::ManualRequired => {}
        }
    }
    if matches!(&observed, ExactPreWitnessObservation::Present(_)) {
        if matches!(
            snapshot.phase(),
            ClosedWitnessPhase::ClosedUnsent
                | ClosedWitnessPhase::AbsenceConfirmed
                | ClosedWitnessPhase::ClosedStarted
                | ClosedWitnessPhase::ManualRequired
        ) {
            control
                .require_manual(&snapshot)
                .await
                .map_err(|_| PreWitnessDispositionError::Control)?;
        }
        return Ok(PreWitnessDisposition::ManualRequired);
    }
    match snapshot.phase() {
        ClosedWitnessPhase::ClosedUnsent | ClosedWitnessPhase::AbsenceConfirmed => control
            .confirm_absence(ExactNoneObservation::from_exact_read(snapshot))
            .await
            .map(PreWitnessDisposition::ConfirmedAbsent)
            .map_err(|_| PreWitnessDispositionError::Control),
        ClosedWitnessPhase::ClosedStarted | ClosedWitnessPhase::ManualRequired => {
            control
                .require_manual(&snapshot)
                .await
                .map_err(|_| PreWitnessDispositionError::Control)?;
            Ok(PreWitnessDisposition::ManualRequired)
        }
        ClosedWitnessPhase::PresentExact => Err(PreWitnessDispositionError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive_v3::{DatabaseEpoch, KeyEpoch},
        archive_v3_witness::{
            KeyRegistryReference, RootCommitment, RootReference, WitnessBootstrap,
        },
    };
    use sha2::{Digest, Sha256};
    use std::sync::Mutex;

    fn id(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn record() -> WitnessRecord {
        let database_epoch = DatabaseEpoch::from_bytes(id(2));
        let key_epoch = KeyEpoch::from_bytes(id(3));
        let bootstrap = WitnessBootstrap::new(
            ArchiveId::from_bytes(id(1)),
            database_epoch,
            RootCommitment::genesis(
                database_epoch,
                key_epoch,
                RootReference::new(0, ObjectId::from_bytes(id(4)), hash(5)),
            ),
            KeyRegistryReference::new(key_epoch, 0, ObjectId::from_bytes(id(6)), hash(7)),
        );
        WitnessRecord::decode(&bootstrap.expected_initial_record_bytes().unwrap()).unwrap()
    }

    #[derive(Clone, Copy)]
    enum ControlMode {
        Participating(ClosedWitnessPhase),
        NotParticipating,
        Unsupported,
        Reject,
    }

    struct FakeControl {
        mode: ControlMode,
        absence: Mutex<usize>,
        present: Mutex<usize>,
        manual: Mutex<usize>,
    }

    impl FakeControl {
        fn new(mode: ControlMode) -> Self {
            Self {
                mode,
                absence: Mutex::new(0),
                present: Mutex::new(0),
                manual: Mutex::new(0),
            }
        }

        fn snapshot(phase: ClosedWitnessPhase) -> ClosedWitnessProtocol {
            let encoded = record().encode().to_vec();
            let admission_revision = (phase != ClosedWitnessPhase::AbsenceConfirmed).then_some(9);
            ClosedWitnessProtocol::for_test(
                ArchiveId::from_bytes(id(1)),
                BootstrapAttemptId::from_bytes(id(8)).unwrap(),
                ObjectId::from_bytes(id(9)),
                11,
                Some(encoded.clone()),
                Some(Sha256::digest(&encoded).into()),
                Some(u32::try_from(encoded.len()).unwrap()),
                admission_revision,
                1,
                hash(10),
                phase,
            )
            .unwrap()
        }
    }

    #[async_trait]
    impl PreWitnessDispositionControl for FakeControl {
        async fn authenticate_closed_protocol(
            &self,
            _archive_id: ArchiveId,
            _deletion_fence: ObjectId,
        ) -> Result<PreWitnessControlState, LifecycleError> {
            match self.mode {
                ControlMode::Participating(phase) => {
                    Ok(PreWitnessControlState::Participating(Self::snapshot(phase)))
                }
                ControlMode::NotParticipating => Ok(PreWitnessControlState::NotParticipating),
                ControlMode::Unsupported => Ok(PreWitnessControlState::UnsupportedManual),
                ControlMode::Reject => Err(LifecycleError::InvalidState),
            }
        }

        async fn confirm_absence(
            &self,
            observation: ExactNoneObservation,
        ) -> Result<AuthenticatedPreWitnessAbsence, LifecycleError> {
            *self.absence.lock().unwrap() += 1;
            let snapshot = observation.into_control_snapshot();
            AuthenticatedPreWitnessAbsence::for_test(&snapshot, hash(11))
        }

        async fn record_present_exact(
            &self,
            _snapshot: &ClosedWitnessProtocol,
        ) -> Result<(), LifecycleError> {
            *self.present.lock().unwrap() += 1;
            Ok(())
        }

        async fn require_manual(
            &self,
            _snapshot: &ClosedWitnessProtocol,
        ) -> Result<(), LifecycleError> {
            *self.manual.lock().unwrap() += 1;
            Ok(())
        }
    }

    struct FakeReader {
        result: Mutex<Option<Result<ExactPreWitnessObservation, PreWitnessDispositionError>>>,
        reads: Mutex<usize>,
    }

    #[async_trait]
    impl ExactPreWitnessReader for FakeReader {
        async fn read_exact_witness(
            &self,
            _archive_id: ArchiveId,
        ) -> Result<ExactPreWitnessObservation, PreWitnessDispositionError> {
            *self.reads.lock().unwrap() += 1;
            self.result.lock().unwrap().take().unwrap()
        }
    }

    fn reader(
        result: Result<ExactPreWitnessObservation, PreWitnessDispositionError>,
    ) -> FakeReader {
        FakeReader {
            result: Mutex::new(Some(result)),
            reads: Mutex::new(0),
        }
    }

    #[tokio::test]
    async fn closed_unsent_fresh_none_mints_only_private_absence() {
        let control =
            FakeControl::new(ControlMode::Participating(ClosedWitnessPhase::ClosedUnsent));
        let absent_reader = reader(Ok(ExactPreWitnessObservation::Absent));
        let result = resolve_pre_witness_disposition(
            ArchiveId::from_bytes(id(1)),
            ObjectId::from_bytes(id(9)),
            &control,
            &absent_reader,
        )
        .await
        .unwrap();
        assert!(matches!(result, PreWitnessDisposition::ConfirmedAbsent(_)));
        assert_eq!(*control.absence.lock().unwrap(), 1);
        assert_eq!(*absent_reader.reads.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn started_none_is_manual_but_later_exact_is_present() {
        let control = FakeControl::new(ControlMode::Participating(
            ClosedWitnessPhase::ClosedStarted,
        ));
        let absent_reader = reader(Ok(ExactPreWitnessObservation::Absent));
        assert!(matches!(
            resolve_pre_witness_disposition(
                ArchiveId::from_bytes(id(1)),
                ObjectId::from_bytes(id(9)),
                &control,
                &absent_reader,
            )
            .await
            .unwrap(),
            PreWitnessDisposition::ManualRequired
        ));
        assert_eq!(*control.manual.lock().unwrap(), 1);

        let control = FakeControl::new(ControlMode::Participating(
            ClosedWitnessPhase::ManualRequired,
        ));
        let exact_reader = reader(Ok(ExactPreWitnessObservation::Present(Box::new(record()))));
        assert!(matches!(
            resolve_pre_witness_disposition(
                ArchiveId::from_bytes(id(1)),
                ObjectId::from_bytes(id(9)),
                &control,
                &exact_reader,
            )
            .await
            .unwrap(),
            PreWitnessDisposition::WitnessPresent
        ));
        assert_eq!(*control.present.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn invalid_or_unsupported_control_performs_zero_witness_io() {
        for (mode, expected_error) in [
            (ControlMode::Reject, true),
            (ControlMode::Unsupported, false),
            (ControlMode::NotParticipating, false),
        ] {
            let control = FakeControl::new(mode);
            let reader = reader(Ok(ExactPreWitnessObservation::Absent));
            let result = resolve_pre_witness_disposition(
                ArchiveId::from_bytes(id(1)),
                ObjectId::from_bytes(id(9)),
                &control,
                &reader,
            )
            .await;
            assert_eq!(result.is_err(), expected_error);
            assert_eq!(*reader.reads.lock().unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn read_error_never_transitions_control() {
        let control =
            FakeControl::new(ControlMode::Participating(ClosedWitnessPhase::ClosedUnsent));
        let reader = reader(Err(PreWitnessDispositionError::WitnessRead));
        assert!(matches!(
            resolve_pre_witness_disposition(
                ArchiveId::from_bytes(id(1)),
                ObjectId::from_bytes(id(9)),
                &control,
                &reader,
            )
            .await,
            Err(PreWitnessDispositionError::WitnessRead)
        ));
        assert_eq!(*control.absence.lock().unwrap(), 0);
        assert_eq!(*control.manual.lock().unwrap(), 0);
        assert_eq!(*control.present.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn any_present_or_present_invalid_after_unsent_or_absent_persists_manual() {
        for (phase, observation) in [
            (
                ClosedWitnessPhase::ClosedUnsent,
                ExactPreWitnessObservation::Present(Box::new(record())),
            ),
            (
                ClosedWitnessPhase::ClosedUnsent,
                ExactPreWitnessObservation::Present(Box::new(record().tombstoned_for_test())),
            ),
            (
                ClosedWitnessPhase::AbsenceConfirmed,
                ExactPreWitnessObservation::DefinitelyPresentInvalid,
            ),
        ] {
            let control = FakeControl::new(ControlMode::Participating(phase));
            let reader = reader(Ok(observation));
            assert!(matches!(
                resolve_pre_witness_disposition(
                    ArchiveId::from_bytes(id(1)),
                    ObjectId::from_bytes(id(9)),
                    &control,
                    &reader,
                )
                .await
                .unwrap(),
                PreWitnessDisposition::ManualRequired
            ));
            assert_eq!(*control.manual.lock().unwrap(), 1);
            assert_eq!(*control.absence.lock().unwrap(), 0);
        }
    }

    #[test]
    fn capability_surface_has_no_runtime_wiring() {
        let runtime = concat!(
            include_str!("main.rs"),
            include_str!("store.rs"),
            include_str!("cp/mod.rs"),
            include_str!("cp/sync.rs"),
            include_str!("archive_v3_inventory_coordinator.rs"),
            include_str!("archive_v3_deletion.rs"),
        );
        for forbidden in [
            "resolve_pre_witness_disposition(",
            "AuthenticatedPreWitnessAbsence",
            ".authenticate_closed_protocol(",
            ".confirm_absence(",
            "create_witness_if_absent(",
        ] {
            assert!(!runtime.contains(forbidden), "{forbidden}");
        }
        let disposition_source = include_str!("archive_v3_witness_disposition.rs");
        assert!(disposition_source
            .contains("confirm_absence(ExactNoneObservation::from_exact_read(snapshot))"));
        let raw_snapshot_bypass = concat!("confirm_absence(", "&snapshot)");
        assert!(!disposition_source.contains(raw_snapshot_bypass));
        let visible_none_factory = concat!("pub(crate) fn ", "from_exact_read");
        assert!(!disposition_source.contains(visible_none_factory));
        let control_source = include_str!("cp/control_store.rs");
        assert!(!control_source.contains("pub(crate) async fn confirm_pre_witness_absence"));
    }
}
