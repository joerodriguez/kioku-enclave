#![allow(
    dead_code,
    reason = "inactive ADR-0022 Firestore witness boundary is compiled and unit-tested before runtime wiring"
)]

//! Inactive ADR-0022 Firestore witness adapter.
//!
//! This is a provider-neutral transaction boundary, not a Firestore client or
//! production authority.  It is deliberately not wired to credentials from
//! metadata, Store, VFS, routes, deployment flags, or write authority.  The
//! only persisted field is `r`, containing the exact fixed-size
//! [`WitnessRecord`] codec bytes.  A future concrete HTTP transport must use a
//! narrowly-scoped bearer-token provider and preserve these transaction and
//! compare-and-set semantics.

use crate::{
    archive_v3::{ArchiveId, DatabaseEpoch, KeyEpoch, ObjectId},
    archive_v3_firestore_probe::{
        singleton_document_suffix, FirestoreProbeAttemptId, FirestoreProbeOutcome,
        FirestoreProbeRecord, PROBE_RECORD_BYTES,
    },
    archive_v3_lifecycle::{
        ActiveCreateAdmission, WitnessCreateDispatchLedger, WitnessSendStarted,
    },
    archive_v3_witness::{
        DeletionAdvance, DeletionRecovery, DeletionStageProof, DeletionState,
        DeletionWorkerCredential, InMemoryWitness, RecoveryRoot, RootAdvance, TombstoneReceipt,
        Witness, WitnessBootstrap, WitnessError, WitnessLease, WitnessReceipt, WitnessRecord,
        WITNESS_RECORD_BYTES,
    },
    archive_v3_witness_disposition::{
        ExactPreWitnessObservation, ExactPreWitnessReader, PreWitnessDispositionError,
    },
    legacy_gcm::ExactLegacyWitness,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

const MAX_ABORTED_ATTEMPTS: usize = 3;
const WITNESS_COLLECTION: &str = "archive_witness_v3";
const MAX_BEARER_TOKEN_BYTES: usize = 16_384;
const MAX_TRANSACTION_BYTES: usize = 1_024;
const MAX_FIRESTORE_TIMESTAMP_BYTES: usize = 30;
pub(crate) const MAX_BATCH_GET_RESPONSE_BYTES: usize = 4_096;
const WITNESS_RECORD_BASE64_BYTES: usize = 4 * WITNESS_RECORD_BYTES.div_ceil(3);
const ARCHIVE_WITNESS_WIF_AUDIENCE_PREFIX: &str = "//iam.googleapis.com/projects/";
const ARCHIVE_WITNESS_WIF_AUDIENCE_SUFFIX: &str =
    "/locations/global/workloadIdentityPools/archive-witness-attest/providers/archive-witness";

/// Redacted result from the provider boundary.  It intentionally contains no
/// HTTP body, URI, bearer token, document name, or provider diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FirestoreWitnessTransportError {
    Unavailable,
    Aborted,
    PreconditionFailed,
    /// A commit may have been accepted but the response was unavailable.
    OutcomeUnknown,
    /// The Firestore endpoint/database was not found. A missing witness
    /// document is represented only by a successful `batchGet` `missing`
    /// result and must never be mapped from an HTTP 404.
    EndpointNotFound,
    TooLarge,
    Protocol,
    /// A strict exact-name response included a `found` document, but its
    /// document name/field set/encoding was noncanonical. This is permanent
    /// presence evidence for pre-witness disposition, never retryable absence.
    DefinitelyPresentInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_witness::{KeyRegistryReference, RootCommitment, RootReference};
    use std::{collections::VecDeque, sync::Mutex};

    const TIME: &str = "2026-01-02T03:04:05.123Z";
    const CREATE_TIME: &str = "2026-01-02T03:04:04.999Z";
    const WIF_AUDIENCE: &str = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/archive-witness-attest/providers/archive-witness";

    struct StaticToken(Mutex<Vec<String>>);
    #[async_trait::async_trait]
    impl FirestoreWitnessBearerTokenProvider for StaticToken {
        async fn bearer_token(
            &self,
            expected_audience: &str,
        ) -> std::result::Result<FirestoreWitnessBearerToken, FirestoreWitnessTransportError>
        {
            self.0.lock().unwrap().push(expected_audience.to_owned());
            FirestoreWitnessBearerToken::new("narrow-test-token")
        }
    }

    struct FailingToken;
    #[async_trait::async_trait]
    impl FirestoreWitnessBearerTokenProvider for FailingToken {
        async fn bearer_token(
            &self,
            _expected_audience: &str,
        ) -> std::result::Result<FirestoreWitnessBearerToken, FirestoreWitnessTransportError>
        {
            Err(FirestoreWitnessTransportError::Unavailable)
        }
    }

    struct FakeDispatch {
        marks: Mutex<usize>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl WitnessCreateDispatchLedger for FakeDispatch {
        async fn mark_witness_send_started(
            &self,
            admission: &ActiveCreateAdmission,
        ) -> std::result::Result<WitnessSendStarted, crate::archive_v3_lifecycle::LifecycleError>
        {
            *self.marks.lock().unwrap() += 1;
            if self.fail {
                return Err(crate::archive_v3_lifecycle::LifecycleError::Unavailable);
            }
            WitnessSendStarted::for_test(admission, [88; 32])
        }
    }

    #[derive(Clone, Copy)]
    enum CommitOutcome {
        Ok,
        Aborted,
        LostResponse,
        DelayedLostResponse,
        CompetingWrite,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FailureStage {
        Begin,
        BatchGet,
    }
    struct FakeState {
        record: Option<[u8; WITNESS_RECORD_BYTES]>,
        update_time: Option<String>,
        outcomes: VecDeque<CommitOutcome>,
        commits: usize,
        requests: Vec<Value>,
        time: String,
        failure: Option<FailureStage>,
        delayed_record: Option<[u8; WITNESS_RECORD_BYTES]>,
    }
    struct FakeTransport(Mutex<FakeState>);
    impl FakeTransport {
        fn new(
            record: Option<[u8; WITNESS_RECORD_BYTES]>,
            outcomes: impl IntoIterator<Item = CommitOutcome>,
        ) -> Self {
            Self(Mutex::new(FakeState {
                record,
                update_time: record.map(|_| TIME.to_owned()),
                outcomes: outcomes.into_iter().collect(),
                commits: 0,
                requests: Vec::new(),
                time: TIME.to_owned(),
                failure: None,
                delayed_record: None,
            }))
        }
        fn push_outcome(&self, outcome: CommitOutcome) {
            self.0.lock().unwrap().outcomes.push_back(outcome);
        }
        fn fail_next(&self, stage: FailureStage) {
            self.0.lock().unwrap().failure = Some(stage);
        }
        fn read(state: &FakeState) -> FirestoreWitnessRead {
            let read_time = FirestoreTimestamp::parse(&state.time).unwrap();
            FirestoreWitnessRead {
                record: state.record,
                update_time: state
                    .update_time
                    .as_deref()
                    .map(|time| FirestoreTimestamp::parse(time).unwrap()),
                trusted_tick: read_time.trusted_tick,
                read_time,
            }
        }
    }
    #[async_trait::async_trait]
    impl FirestoreWitnessTransport for FakeTransport {
        async fn begin_read_write(
            &self,
            _bearer: &str,
            request: Value,
        ) -> std::result::Result<FirestoreTransaction, FirestoreWitnessTransportError> {
            let mut state = self.0.lock().unwrap();
            state.requests.push(request);
            if state.failure == Some(FailureStage::Begin) {
                state.failure = None;
                return Err(FirestoreWitnessTransportError::Unavailable);
            }
            FirestoreTransaction::new(b"tx")
        }
        async fn batch_get_exact(
            &self,
            _bearer: &str,
            _tx: &FirestoreTransaction,
            request: Value,
        ) -> std::result::Result<FirestoreWitnessRead, FirestoreWitnessTransportError> {
            let mut state = self.0.lock().unwrap();
            state.requests.push(request);
            if state.failure == Some(FailureStage::BatchGet) {
                state.failure = None;
                return Err(FirestoreWitnessTransportError::Unavailable);
            }
            Ok(Self::read(&state))
        }
        async fn read_exact(
            &self,
            _bearer: &str,
            request: Value,
        ) -> std::result::Result<FirestoreWitnessRead, FirestoreWitnessTransportError> {
            let mut state = self.0.lock().unwrap();
            state.requests.push(request);
            Ok(Self::read(&state))
        }
        async fn commit_full_record(
            &self,
            _bearer: &str,
            _tx: &FirestoreTransaction,
            request: Value,
        ) -> std::result::Result<(), FirestoreWitnessTransportError> {
            let mut state = self.0.lock().unwrap();
            state.commits += 1;
            if let Some(delayed) = state.delayed_record.take() {
                state.record = Some(delayed);
                state.update_time = Some(TIME.to_owned());
            }
            match (state.record.as_ref(), state.update_time.as_deref()) {
                (None, None)
                    if request["writes"][0]["currentDocument"] == json!({"exists": false}) => {}
                (Some(_), Some(update_time))
                    if request["writes"][0]["currentDocument"]
                        == json!({"updateTime": update_time}) => {}
                (None, None) | (Some(_), Some(_)) => {
                    return Err(FirestoreWitnessTransportError::PreconditionFailed)
                }
                _ => return Err(FirestoreWitnessTransportError::Protocol),
            }
            state.requests.push(request.clone());
            let encoded = request["writes"][0]["update"]["fields"]["r"]["bytesValue"]
                .as_str()
                .ok_or(FirestoreWitnessTransportError::Protocol)?;
            if encoded.len() != WITNESS_RECORD_BASE64_BYTES {
                return Err(FirestoreWitnessTransportError::Protocol);
            }
            let mut record = [0; WITNESS_RECORD_BYTES];
            if STANDARD
                .decode_slice(encoded, &mut record)
                .map_err(|_| FirestoreWitnessTransportError::Protocol)?
                != WITNESS_RECORD_BYTES
            {
                return Err(FirestoreWitnessTransportError::Protocol);
            }
            let outcome = state.outcomes.pop_front().unwrap_or(CommitOutcome::Ok);
            if matches!(outcome, CommitOutcome::CompetingWrite) {
                state.update_time = Some("2026-01-02T03:04:05.998Z".to_owned());
                return Err(FirestoreWitnessTransportError::PreconditionFailed);
            }
            if matches!(outcome, CommitOutcome::Ok | CommitOutcome::LostResponse) {
                state.record = Some(record);
                state.update_time = Some(format!("2026-01-02T03:04:05.{:03}Z", state.commits));
            }
            match outcome {
                CommitOutcome::Ok => Ok(()),
                CommitOutcome::Aborted => Err(FirestoreWitnessTransportError::Aborted),
                CommitOutcome::LostResponse => Err(FirestoreWitnessTransportError::OutcomeUnknown),
                CommitOutcome::DelayedLostResponse => {
                    state.delayed_record = Some(record);
                    Err(FirestoreWitnessTransportError::OutcomeUnknown)
                }
                CommitOutcome::CompetingWrite => unreachable!("handled above"),
            }
        }
    }

    fn id(byte: u8) -> [u8; 16] {
        [byte; 16]
    }
    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    fn bootstrap() -> WitnessBootstrap {
        let epoch = DatabaseEpoch::from_bytes(id(2));
        let key_epoch = KeyEpoch::from_bytes(id(3));
        WitnessBootstrap::new(
            ArchiveId::from_bytes(id(1)),
            epoch,
            RootCommitment::genesis(
                epoch,
                key_epoch,
                RootReference::new(0, ObjectId::from_bytes(id(4)), hash(5)),
            ),
            KeyRegistryReference::new(key_epoch, 0, ObjectId::from_bytes(id(6)), hash(7)),
        )
    }
    fn witness(transport: Arc<FakeTransport>) -> FirestoreWitness {
        FirestoreWitness::new(
            FirestoreWitnessConfig::new("project-1", "123456789", "witness-db").unwrap(),
            Arc::new(StaticToken(Mutex::new(Vec::new()))),
            transport,
        )
        .unwrap()
    }

    fn witness_admission() -> ActiveCreateAdmission {
        let bootstrap = bootstrap();
        ActiveCreateAdmission::for_test(
            bootstrap.archive_id(),
            crate::archive_v3_lifecycle::BootstrapAttemptId::from_bytes([8; 16]).unwrap(),
            9,
            2,
            Sha256::digest(bootstrap.expected_initial_record_bytes().unwrap()).into(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn commit_started_bootstrap_marks_once_and_resolves_aborted_or_lost_response() {
        for outcomes in [
            vec![CommitOutcome::Aborted, CommitOutcome::Ok],
            vec![CommitOutcome::LostResponse],
        ] {
            let transport = Arc::new(FakeTransport::new(None, outcomes));
            let adapter = witness(transport.clone());
            let dispatch = FakeDispatch {
                marks: Mutex::new(0),
                fail: false,
            };
            let result = adapter
                .bootstrap_commit_started(&witness_admission(), &dispatch, bootstrap())
                .await
                .unwrap();
            assert_eq!(
                result.encode(),
                bootstrap().expected_initial_record_bytes().unwrap()
            );
            assert_eq!(*dispatch.marks.lock().unwrap(), 1);
            assert!(transport.0.lock().unwrap().commits >= 1);
        }
    }

    #[tokio::test]
    async fn maintenance_migration_commits_control_retained_bytes_across_read_tick_drift() {
        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
        let adapter = witness(transport.clone());
        let initial = adapter.bootstrap_async(bootstrap()).await.unwrap();
        let owner = ObjectId::from_bytes(id(8));
        let lease = adapter
            .acquire_lease_async(
                initial.archive_id(),
                initial.database_epoch(),
                initial.registry().key_epoch(),
                owner,
                60,
            )
            .await
            .unwrap();
        let expected = adapter
            .read_current_async(initial.archive_id())
            .await
            .unwrap()
            .unwrap();
        let candidate_root = RootCommitment::candidate_for_test(
            expected.database_epoch(),
            expected.registry().key_epoch(),
            lease.fencing_epoch(),
            expected.root().root(),
            RootReference::new(1, ObjectId::from_bytes(id(9)), hash(10)),
        );
        let advance = RootAdvance::new(lease, expected.root(), expected.registry(), candidate_root);
        let candidate = expected
            .exact_migration_candidate(
                &advance,
                crate::archive_v3_witness::MigrationState::ShadowWal,
            )
            .unwrap();
        transport.0.lock().unwrap().time = "2026-01-02T03:04:06.123Z".to_owned();
        assert!(adapter
            .advance_exact_migration_candidate_unresolved_async(
                expected,
                candidate.clone(),
                advance,
                crate::archive_v3_witness::MigrationState::ShadowWal,
            )
            .await
            .is_ok());
        assert_eq!(transport.0.lock().unwrap().record, Some(candidate.encode()));
    }

    #[tokio::test]
    async fn maintenance_terminal_release_handles_expiry_and_rejects_higher_fence() {
        let trusted_tick = firestore_read_time_tick(TIME).unwrap();
        let local = InMemoryWitness::from_provider_record_at_tick(None, trusted_tick).unwrap();
        let initial = local.bootstrap_at_tick(bootstrap(), trusted_tick).unwrap();
        let owner = ObjectId::from_bytes(id(8));
        local
            .acquire_lease(
                initial.archive_id(),
                initial.database_epoch(),
                initial.registry().key_epoch(),
                owner,
                60,
            )
            .unwrap();
        let retained = local
            .read_current(initial.archive_id())
            .unwrap()
            .unwrap()
            .with_migration_for_test(crate::archive_v3_witness::MigrationState::WalAuthoritative);

        for time in [
            "2026-01-02T03:05:04.123Z",
            "2026-01-02T03:05:05.123Z",
            "2026-01-02T03:05:06.123Z",
        ] {
            let transport = Arc::new(FakeTransport::new(
                Some(retained.encode()),
                [CommitOutcome::Ok],
            ));
            transport.0.lock().unwrap().time = time.to_owned();
            let adapter = witness(transport.clone());
            assert!(adapter
                .release_exact_maintenance_terminal_unresolved_async(retained.clone(), owner,)
                .await
                .is_ok());
            let released =
                WitnessRecord::decode(&transport.0.lock().unwrap().record.expect("release record"))
                    .unwrap();
            assert!(!released
                .exact_maintenance_terminal_or_release_from(&retained, owner)
                .unwrap());
        }

        let lost = Arc::new(FakeTransport::new(
            Some(retained.encode()),
            [CommitOutcome::LostResponse],
        ));
        lost.0.lock().unwrap().time = "2026-01-02T03:05:06.123Z".to_owned();
        assert!(matches!(
            witness(lost.clone())
                .release_exact_maintenance_terminal_unresolved_async(retained.clone(), owner)
                .await,
            Err(FirestoreWitnessCommitError::OutcomeUnknown)
        ));
        let released =
            WitnessRecord::decode(&lost.0.lock().unwrap().record.expect("lost release record"))
                .unwrap();
        assert!(!released
            .exact_maintenance_terminal_or_release_from(&retained, owner)
            .unwrap());

        let same_owner_reacquired = retained.reacquired_maintenance_lease_for_test();
        let same_owner_reacquire = Arc::new(FakeTransport::new(
            Some(same_owner_reacquired.encode()),
            [CommitOutcome::Ok],
        ));
        same_owner_reacquire.0.lock().unwrap().time = "2026-01-02T03:05:06.123Z".to_owned();
        assert!(matches!(
            witness(same_owner_reacquire.clone())
                .release_exact_maintenance_terminal_unresolved_async(retained.clone(), owner)
                .await,
            Err(FirestoreWitnessCommitError::Rejected(_))
        ));
        assert_eq!(same_owner_reacquire.0.lock().unwrap().commits, 0);

        let reacquired_local = InMemoryWitness::from_provider_record_at_tick(
            Some(retained.encode()),
            retained
                .exact_active_lease_for_owner(owner)
                .unwrap()
                .expires_at_tick(),
        )
        .unwrap();
        let competing_lease = reacquired_local
            .acquire_lease(
                retained.archive_id(),
                retained.database_epoch(),
                retained.registry().key_epoch(),
                ObjectId::from_bytes(id(15)),
                60,
            )
            .unwrap();
        reacquired_local.revoke_lease(competing_lease).unwrap();
        let competing_released = reacquired_local
            .read_current(retained.archive_id())
            .unwrap()
            .unwrap();
        let competing = Arc::new(FakeTransport::new(
            Some(competing_released.encode()),
            [CommitOutcome::Ok],
        ));
        competing.0.lock().unwrap().time = "2026-01-02T03:05:06.123Z".to_owned();
        assert!(matches!(
            witness(competing.clone())
                .release_exact_maintenance_terminal_unresolved_async(retained, owner)
                .await,
            Err(FirestoreWitnessCommitError::Rejected(_))
        ));
        assert_eq!(competing.0.lock().unwrap().commits, 0);
    }

    #[tokio::test]
    async fn maintenance_advisory_release_is_shadow_only_and_reconciles_lost_response() {
        let trusted_tick = firestore_read_time_tick(TIME).unwrap();
        let local = InMemoryWitness::from_provider_record_at_tick(None, trusted_tick).unwrap();
        let initial = local.bootstrap_at_tick(bootstrap(), trusted_tick).unwrap();
        let owner = ObjectId::from_bytes(id(8));
        local
            .acquire_lease(
                initial.archive_id(),
                initial.database_epoch(),
                initial.registry().key_epoch(),
                owner,
                60,
            )
            .unwrap();
        let retained = local
            .read_current(initial.archive_id())
            .unwrap()
            .unwrap()
            .with_migration_for_test(crate::archive_v3_witness::MigrationState::ShadowWal);

        let lost = Arc::new(FakeTransport::new(
            Some(retained.encode()),
            [CommitOutcome::LostResponse],
        ));
        lost.0.lock().unwrap().time = "2026-01-02T03:05:06.123Z".to_owned();
        assert!(matches!(
            witness(lost.clone())
                .release_exact_maintenance_advisory_unresolved_async(retained.clone(), owner)
                .await,
            Err(FirestoreWitnessCommitError::OutcomeUnknown)
        ));
        let released = WitnessRecord::decode(
            &lost
                .0
                .lock()
                .unwrap()
                .record
                .expect("lost advisory release"),
        )
        .unwrap();
        assert_eq!(
            released.migration(),
            crate::archive_v3_witness::MigrationState::ShadowWal
        );
        assert!(!released
            .exact_maintenance_advisory_or_release_from(&retained, owner)
            .unwrap());
        assert!(released
            .exact_maintenance_terminal_or_release_from(&retained, owner)
            .is_err());

        let higher_fence = retained.reacquired_maintenance_lease_for_test();
        let rejected = Arc::new(FakeTransport::new(
            Some(higher_fence.encode()),
            [CommitOutcome::Ok],
        ));
        rejected.0.lock().unwrap().time = "2026-01-02T03:05:06.123Z".to_owned();
        assert!(matches!(
            witness(rejected.clone())
                .release_exact_maintenance_advisory_unresolved_async(retained, owner)
                .await,
            Err(FirestoreWitnessCommitError::Rejected(_))
        ));
        assert_eq!(rejected.0.lock().unwrap().commits, 0);
    }

    #[tokio::test]
    async fn wal_owner_root_advance_authenticates_the_firestore_provider_tick() {
        let trusted_tick = firestore_read_time_tick(TIME).unwrap();
        let local = InMemoryWitness::from_provider_record_at_tick(None, trusted_tick).unwrap();
        let initial = local.bootstrap_at_tick(bootstrap(), trusted_tick).unwrap();
        let owner = ObjectId::from_bytes(id(8));
        let lease = local
            .acquire_lease(
                initial.archive_id(),
                initial.database_epoch(),
                initial.registry().key_epoch(),
                owner,
                60,
            )
            .unwrap();
        let legacy = local.read_current(initial.archive_id()).unwrap().unwrap();
        let shadow_root = RootCommitment::candidate_for_test(
            legacy.database_epoch(),
            legacy.registry().key_epoch(),
            lease.fencing_epoch(),
            legacy.root().root(),
            RootReference::new(1, ObjectId::from_bytes(id(9)), hash(10)),
        );
        let shadow = local
            .advance_migration(
                RootAdvance::new(lease, legacy.root(), legacy.registry(), shadow_root),
                crate::archive_v3_witness::MigrationState::ShadowWal,
            )
            .unwrap();
        let authoritative_root = RootCommitment::candidate_for_test(
            shadow.record().database_epoch(),
            shadow.record().registry().key_epoch(),
            lease.fencing_epoch(),
            shadow.record().root().root(),
            RootReference::new(2, ObjectId::from_bytes(id(11)), hash(12)),
        );
        let authoritative = local
            .advance_migration(
                RootAdvance::new(
                    lease,
                    shadow.record().root(),
                    shadow.record().registry(),
                    authoritative_root,
                ),
                crate::archive_v3_witness::MigrationState::WalAuthoritative,
            )
            .unwrap();
        let candidate_root = RootCommitment::candidate_for_test(
            authoritative.record().database_epoch(),
            authoritative.record().registry().key_epoch(),
            lease.fencing_epoch(),
            authoritative.record().root().root(),
            RootReference::new(3, ObjectId::from_bytes(id(13)), hash(14)),
        );
        let retained =
            crate::archive_v3_witness::AuthenticatedWalRootAdvance::from_expected_witness(
                crate::archive_v3_wal_owner::WalWitnessAdvanceContext::for_test(),
                authoritative.record(),
                candidate_root,
            )
            .unwrap();

        let transport = Arc::new(FakeTransport::new(
            Some(authoritative.record().encode()),
            [CommitOutcome::Ok],
        ));
        transport.0.lock().unwrap().time = "2026-01-02T03:04:06.123Z".to_owned();
        let adapter = witness(transport);
        let observed = adapter
            .compare_and_advance_exact_wal_owner_root_unresolved_async(
                authoritative.record().clone(),
                retained.provider_advance(
                    crate::archive_v3_wal_owner::WalWitnessAdvanceContext::for_test(),
                ),
            )
            .await;
        assert!(observed.is_ok());
        let observed = observed.ok().expect("checked exact witness advance");
        assert!(observed.record().last_server_tick() > authoritative.record().last_server_tick());
        assert!(retained.validate_observed(observed.record()).is_ok());

        let tampered = authoritative.record().with_next_fencing_epoch_for_test(99);
        let rejected = Arc::new(FakeTransport::new(
            Some(tampered.encode()),
            [CommitOutcome::Ok],
        ));
        rejected.0.lock().unwrap().time = "2026-01-02T03:04:06.123Z".to_owned();
        assert!(matches!(
            witness(rejected.clone())
                .compare_and_advance_exact_wal_owner_root_unresolved_async(
                    authoritative.record().clone(),
                    retained.provider_advance(
                        crate::archive_v3_wal_owner::WalWitnessAdvanceContext::for_test(),
                    ),
                )
                .await,
            Err(FirestoreWitnessCommitError::Rejected(_))
        ));
        assert_eq!(rejected.0.lock().unwrap().commits, 0);
    }

    #[tokio::test]
    async fn wal_owner_acquire_preserves_ambiguity_and_authenticates_firestore_tick() {
        let trusted_tick = firestore_read_time_tick(TIME).unwrap();
        let local = InMemoryWitness::from_provider_record_at_tick(None, trusted_tick).unwrap();
        let initial = local.bootstrap_at_tick(bootstrap(), trusted_tick).unwrap();
        let importer = ObjectId::from_bytes(id(8));
        local
            .acquire_lease(
                initial.archive_id(),
                initial.database_epoch(),
                initial.registry().key_epoch(),
                importer,
                60,
            )
            .unwrap();
        let released = local
            .read_current(initial.archive_id())
            .unwrap()
            .unwrap()
            .released_wal_owner_for_test();
        let owner = ObjectId::from_bytes(id(31));

        let transport = Arc::new(FakeTransport::new(
            Some(released.encode()),
            [CommitOutcome::Ok],
        ));
        transport.0.lock().unwrap().time = "2026-01-02T03:04:06.123Z".to_owned();
        let acquired = witness(transport)
            .acquire_exact_wal_owner_lease_unresolved_async(released.clone(), owner, 60)
            .await;
        assert!(acquired.is_ok());
        let (observed, lease) = acquired.ok().unwrap();
        assert!(observed.last_server_tick() > released.last_server_tick());
        assert_eq!(
            observed
                .exact_wal_owner_acquire_from(&released, owner.as_bytes())
                .unwrap(),
            lease
        );

        let renewing = Arc::new(FakeTransport::new(
            Some(observed.encode()),
            [CommitOutcome::Ok],
        ));
        renewing.0.lock().unwrap().time = "2026-01-02T03:04:07.123Z".to_owned();
        let renewed = witness(renewing)
            .renew_exact_wal_owner_lease_unresolved_async(observed.clone(), lease, 120)
            .await;
        assert!(renewed.is_ok());
        let (renewed, renewed_lease) = renewed.ok().unwrap();
        assert_eq!(
            renewed
                .exact_wal_owner_renewal_from(&observed, owner.as_bytes())
                .unwrap(),
            renewed_lease
        );

        let changed_current = observed.with_next_fencing_epoch_for_test(99);
        let stale = Arc::new(FakeTransport::new(
            Some(changed_current.encode()),
            [CommitOutcome::Ok],
        ));
        stale.0.lock().unwrap().time = "2026-01-02T03:04:07.123Z".to_owned();
        assert!(matches!(
            witness(stale.clone())
                .renew_exact_wal_owner_lease_unresolved_async(observed.clone(), lease, 120)
                .await,
            Err(FirestoreWitnessCommitError::Rejected(_))
        ));
        assert_eq!(stale.0.lock().unwrap().commits, 0);

        let reacquiring = Arc::new(FakeTransport::new(
            Some(observed.encode()),
            [CommitOutcome::Ok],
        ));
        reacquiring.0.lock().unwrap().time = "2026-01-02T03:06:00.123Z".to_owned();
        let reacquired = witness(reacquiring)
            .reacquire_exact_wal_owner_lease_unresolved_async(observed.clone(), owner, 60)
            .await;
        assert!(reacquired.is_ok());
        let (reacquired, reacquired_lease) = reacquired.ok().unwrap();
        assert_eq!(
            reacquired
                .exact_wal_owner_reacquire_from(&observed, owner.as_bytes())
                .unwrap(),
            reacquired_lease
        );

        let lost = Arc::new(FakeTransport::new(
            Some(released.encode()),
            [CommitOutcome::LostResponse],
        ));
        lost.0.lock().unwrap().time = "2026-01-02T03:04:06.123Z".to_owned();
        assert!(matches!(
            witness(lost.clone())
                .acquire_exact_wal_owner_lease_unresolved_async(released.clone(), owner, 60)
                .await,
            Err(FirestoreWitnessCommitError::OutcomeUnknown)
        ));
        let committed = WitnessRecord::decode(&lost.0.lock().unwrap().record.unwrap()).unwrap();
        assert!(committed
            .exact_wal_owner_acquire_from(&released, owner.as_bytes())
            .is_ok());

        let alternate = released.with_next_fencing_epoch_for_test(99);
        let rejected = Arc::new(FakeTransport::new(
            Some(released.encode()),
            [CommitOutcome::Ok],
        ));
        assert!(matches!(
            witness(rejected.clone())
                .acquire_exact_wal_owner_lease_unresolved_async(alternate, owner, 60)
                .await,
            Err(FirestoreWitnessCommitError::Rejected(_))
        ));
        assert_eq!(rejected.0.lock().unwrap().commits, 0);
    }

    #[tokio::test]
    async fn advisory_owner_acquire_preserves_ambiguity_and_shadow_wal_boundary() {
        let trusted_tick = firestore_read_time_tick(TIME).unwrap();
        let local = InMemoryWitness::from_provider_record_at_tick(None, trusted_tick).unwrap();
        let initial = local.bootstrap_at_tick(bootstrap(), trusted_tick).unwrap();
        let importer = ObjectId::from_bytes(id(8));
        local
            .acquire_lease(
                initial.archive_id(),
                initial.database_epoch(),
                initial.registry().key_epoch(),
                importer,
                60,
            )
            .unwrap();
        let retained = local
            .read_current(initial.archive_id())
            .unwrap()
            .unwrap()
            .with_migration_for_test(crate::archive_v3_witness::MigrationState::ShadowWal);
        let release = InMemoryWitness::from_provider_record_at_tick(
            Some(retained.encode()),
            retained.last_server_tick() + 1,
        )
        .unwrap();
        let released = release
            .release_exact_maintenance_advisory(&retained, importer)
            .unwrap();
        let owner = ObjectId::from_bytes(id(32));

        let lost = Arc::new(FakeTransport::new(
            Some(released.encode()),
            [CommitOutcome::LostResponse],
        ));
        lost.0.lock().unwrap().time = "2026-01-02T03:04:06.123Z".to_owned();
        assert!(matches!(
            witness(lost.clone())
                .acquire_exact_advisory_owner_lease_unresolved_async(released.clone(), owner, 60,)
                .await,
            Err(FirestoreWitnessCommitError::OutcomeUnknown)
        ));
        let committed = WitnessRecord::decode(&lost.0.lock().unwrap().record.unwrap()).unwrap();
        assert!(committed
            .exact_advisory_owner_acquire_from(&released, owner.as_bytes())
            .is_ok());

        let authoritative = released
            .with_migration_for_test(crate::archive_v3_witness::MigrationState::WalAuthoritative);
        let rejected = Arc::new(FakeTransport::new(
            Some(authoritative.encode()),
            [CommitOutcome::Ok],
        ));
        rejected.0.lock().unwrap().time = "2026-01-02T03:04:07.123Z".to_owned();
        assert!(matches!(
            witness(rejected.clone())
                .acquire_exact_advisory_owner_lease_unresolved_async(authoritative, owner, 60)
                .await,
            Err(FirestoreWitnessCommitError::Rejected(_))
        ));
        assert_eq!(rejected.0.lock().unwrap().commits, 0);
    }

    #[tokio::test]
    async fn commit_started_bootstrap_pre_marker_failures_are_definitely_unsent() {
        let transport = Arc::new(FakeTransport::new(None, []));
        transport.fail_next(FailureStage::BatchGet);
        let adapter = witness(transport.clone());
        let dispatch = FakeDispatch {
            marks: Mutex::new(0),
            fail: false,
        };
        assert!(matches!(
            adapter
                .bootstrap_commit_started(&witness_admission(), &dispatch, bootstrap())
                .await,
            Err(FirestoreWitnessBootstrapError::DefinitelyUnsent(_))
        ));
        assert_eq!(*dispatch.marks.lock().unwrap(), 0);
        assert_eq!(transport.0.lock().unwrap().commits, 0);

        let dispatch = FakeDispatch {
            marks: Mutex::new(0),
            fail: true,
        };
        assert!(matches!(
            adapter
                .bootstrap_commit_started(&witness_admission(), &dispatch, bootstrap())
                .await,
            Err(FirestoreWitnessBootstrapError::DefinitelyUnsent(_))
        ));
        assert_eq!(*dispatch.marks.lock().unwrap(), 1);
        assert_eq!(transport.0.lock().unwrap().commits, 0);
    }

    #[tokio::test]
    async fn delayed_first_create_then_second_precondition_resolves_by_fresh_exact_read() {
        let transport = Arc::new(FakeTransport::new(
            None,
            [CommitOutcome::DelayedLostResponse, CommitOutcome::Ok],
        ));
        let adapter = witness(transport.clone());
        let dispatch = FakeDispatch {
            marks: Mutex::new(0),
            fail: false,
        };
        let record = adapter
            .bootstrap_commit_started(&witness_admission(), &dispatch, bootstrap())
            .await
            .unwrap();
        assert_eq!(
            record.encode(),
            bootstrap().expected_initial_record_bytes().unwrap()
        );
        assert_eq!(*dispatch.marks.lock().unwrap(), 1);
        assert_eq!(transport.0.lock().unwrap().commits, 2);
    }

    #[tokio::test]
    async fn exact_pre_witness_reader_classifies_malformed_found_as_definite_presence() {
        let transport = Arc::new(FakeTransport::new(Some([0xff; WITNESS_RECORD_BYTES]), []));
        let adapter = witness(transport);
        assert!(matches!(
            adapter
                .read_exact_witness(ArchiveId::from_bytes(id(1)))
                .await
                .unwrap(),
            ExactPreWitnessObservation::DefinitelyPresentInvalid
        ));
    }

    #[test]
    fn strict_codec_and_emulator_request_shapes() {
        let namespace = FirestoreWitnessNamespace::new("project-1", "witness-db").unwrap();
        let document = namespace.document(ArchiveId::from_bytes(id(1)));
        assert_eq!(document, "projects/project-1/databases/witness-db/documents/archive_witness_v3/01010101010101010101010101010101");
        let transaction = FirestoreTransaction::new(b"tx").unwrap();
        assert_eq!(begin_request_json(), json!({"options": {"readWrite": {}}}));
        assert_eq!(
            batch_get_request_json(&document, Some(&transaction)),
            json!({"documents": [document], "transaction": "dHg="})
        );
        let encoded = [9; WITNESS_RECORD_BYTES];
        let commit = commit_request_json(&document, &transaction, &encoded, Some(TIME));
        assert_eq!(commit["writes"][0]["update"]["name"], document);
        assert_eq!(commit["writes"][0]["currentDocument"]["updateTime"], TIME);
        let response = json!({"found": {"name": document, "createTime": CREATE_TIME, "updateTime": TIME, "fields": {"r": {"bytesValue": STANDARD.encode(encoded)}}}, "readTime": TIME});
        assert_eq!(
            parse_batch_get_response(&response, &document)
                .unwrap()
                .record
                .unwrap(),
            encoded
        );
        let malformed = json!({"found": {"name": document, "createTime": CREATE_TIME, "updateTime": TIME, "fields": {"r": {"bytesValue": ""}, "extra": {}}}, "readTime": TIME});
        assert_eq!(
            parse_batch_get_response(&malformed, &document),
            Err(FirestoreWitnessTransportError::Protocol)
        );
        let malformed_stream = serde_json::to_vec(&malformed).unwrap();
        assert_eq!(
            parse_exact_batch_get_stream([malformed_stream.as_slice()], &document),
            Err(FirestoreWitnessTransportError::DefinitelyPresentInvalid)
        );
        for invalid_found in [
            json!({"found": {"name": format!("{document}-wrong"), "createTime": CREATE_TIME, "updateTime": TIME, "fields": {"r": {"bytesValue": STANDARD.encode(encoded)}}}, "readTime": TIME}),
            json!({"found": {"name": document, "createTime": CREATE_TIME, "updateTime": TIME, "fields": {"wrong": {"bytesValue": STANDARD.encode(encoded)}}}, "readTime": TIME}),
            json!({"found": {"name": document, "createTime": CREATE_TIME, "updateTime": TIME, "fields": {"r": {"bytesValue": STANDARD.encode(encoded)}}, "extra": true}, "readTime": TIME}),
        ] {
            let invalid = serde_json::to_vec(&invalid_found).unwrap();
            assert_eq!(
                parse_exact_batch_get_stream([invalid.as_slice()], &document),
                Err(FirestoreWitnessTransportError::DefinitelyPresentInvalid)
            );
        }
    }

    #[test]
    fn namespace_audience_and_secret_material_are_strictly_bounded() {
        for database in [
            "(default)",
            "abc",
            "1archive",
            "archive-",
            "archive_Witness",
            "123e4567-e89b-12d3-a456-426614174000",
        ] {
            assert_eq!(
                FirestoreWitnessNamespace::new("project-1", database),
                Err(WitnessError::Malformed),
                "{database}"
            );
        }
        assert!(FirestoreWitnessNamespace::new("project-1", "archive-witness-2").is_ok());
        for project in [
            "1roject",
            "project-",
            "project-id-that-is-longer-than-thirty-characters",
        ] {
            assert_eq!(
                FirestoreWitnessNamespace::new(project, "witness-db"),
                Err(WitnessError::Malformed),
                "{project}"
            );
        }
        assert!(FirestoreWitnessAudience::new(WIF_AUDIENCE).is_ok());
        assert!(FirestoreWitnessAudience::new(
            "//iam.googleapis.com/projects/0123/locations/global/workloadIdentityPools/archive-witness-attest/providers/archive-witness"
        )
        .is_err());
        assert!(FirestoreWitnessAudience::new(
            "//iam.googleapis.com/projects/project-id/locations/global/workloadIdentityPools/archive-witness-attest/providers/archive-witness"
        )
        .is_err());
        assert!(FirestoreWitnessAudience::new(
            "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/other/providers/archive-witness"
        )
        .is_err());
        assert!(FirestoreWitnessBearerToken::new("").is_err());
        assert!(FirestoreWitnessBearerToken::new("contains\"quote").is_err());
        assert!(FirestoreWitnessBearerToken::new("contains\\backslash").is_err());
        assert!(FirestoreWitnessBearerToken::new(&"x".repeat(MAX_BEARER_TOKEN_BYTES + 1)).is_err());
        assert!(FirestoreTransaction::new(&[]).is_err());
        assert!(FirestoreTransaction::new(&vec![0; MAX_TRANSACTION_BYTES + 1]).is_err());
        let config = FirestoreWitnessConfig::new("project-1", "123456789", "witness-db").unwrap();
        assert_eq!(
            config.namespace.document(ArchiveId::from_bytes(id(1))),
            "projects/project-1/databases/witness-db/documents/archive_witness_v3/01010101010101010101010101010101"
        );
        assert_eq!(config.provider_audience.as_str(), WIF_AUDIENCE);
    }

    #[test]
    fn batch_get_is_exact_bounded_and_timestamp_validated() {
        let document = FirestoreWitnessNamespace::new("project-1", "witness-db")
            .unwrap()
            .document(ArchiveId::from_bytes(id(1)));
        let encoded = STANDARD.encode([9; WITNESS_RECORD_BYTES]);
        let response = json!({"found": {"name": document, "createTime": CREATE_TIME, "updateTime": TIME, "fields": {"r": {"bytesValue": encoded}}}, "readTime": TIME});
        let response = serde_json::to_vec(&response).unwrap();
        assert!(parse_exact_batch_get_stream([response.as_slice()], &document).is_ok());
        assert_eq!(
            parse_exact_batch_get_stream(Vec::<&[u8]>::new(), &document),
            Err(FirestoreWitnessTransportError::Protocol)
        );
        assert_eq!(
            parse_exact_batch_get_stream([response.as_slice(), response.as_slice()], &document),
            Err(FirestoreWitnessTransportError::DefinitelyPresentInvalid)
        );
        assert_eq!(
            parse_exact_batch_get_stream(
                [vec![b' '; MAX_BATCH_GET_RESPONSE_BYTES + 1].as_slice()],
                &document
            ),
            Err(FirestoreWitnessTransportError::TooLarge)
        );
        let bad_update = json!({"found": {"name": document, "createTime": CREATE_TIME, "updateTime": "2026-01-02T03:04:06Z", "fields": {"r": {"bytesValue": STANDARD.encode([9; WITNESS_RECORD_BYTES])}}}, "readTime": TIME});
        assert_eq!(
            parse_batch_get_response(&bad_update, &document),
            Err(FirestoreWitnessTransportError::Protocol)
        );
        let long_read_time = format!("2026-01-02T03:04:05.{}Z", "1".repeat(10));
        assert!(FirestoreTimestamp::parse(&long_read_time).is_err());
        let bad_create = json!({"found": {"name": document, "createTime": "2026-01-02T03:04:05.124Z", "updateTime": TIME, "fields": {"r": {"bytesValue": STANDARD.encode([9; WITNESS_RECORD_BYTES])}}}, "readTime": TIME});
        assert_eq!(
            parse_batch_get_response(&bad_create, &document),
            Err(FirestoreWitnessTransportError::Protocol)
        );
        let no_create_time = json!({"found": {"name": document, "updateTime": TIME, "fields": {"r": {"bytesValue": STANDARD.encode([9; WITNESS_RECORD_BYTES])}}}, "readTime": TIME});
        assert!(parse_batch_get_response(&no_create_time, &document).is_ok());
        let unexpected_instead_of_create = json!({"found": {"name": document, "unexpected": CREATE_TIME, "updateTime": TIME, "fields": {"r": {"bytesValue": STANDARD.encode([9; WITNESS_RECORD_BYTES])}}}, "readTime": TIME});
        assert_eq!(
            parse_batch_get_response(&unexpected_instead_of_create, &document),
            Err(FirestoreWitnessTransportError::Protocol)
        );
        let wrong_length = json!({"found": {"name": document, "createTime": CREATE_TIME, "updateTime": TIME, "fields": {"r": {"bytesValue": "A".repeat(WITNESS_RECORD_BASE64_BYTES - 1)}}}, "readTime": TIME});
        assert_eq!(
            parse_batch_get_response(&wrong_length, &document),
            Err(FirestoreWitnessTransportError::Protocol)
        );
        assert!(valid_firestore_precondition_timestamp(
            "2026-01-02T03:04:05.123456Z"
        ));
        assert!(valid_firestore_precondition_timestamp(
            "2026-01-02T03:04:05.123456000Z"
        ));
        assert!(!valid_firestore_precondition_timestamp(
            "2026-01-02T03:04:05.123456789Z"
        ));
        assert!(!valid_firestore_precondition_timestamp(
            "2026-01-02T03:04:05.123456+00:00"
        ));
    }

    #[tokio::test]
    async fn bootstrap_race_and_update_precondition_are_not_overwritten() {
        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
        let adapter = witness(transport.clone());
        let record = adapter.bootstrap_async(bootstrap()).await.unwrap();
        adapter
            .acquire_lease_async(
                record.archive_id(),
                record.database_epoch(),
                record.registry().key_epoch(),
                ObjectId::from_bytes(id(8)),
                10,
            )
            .await
            .unwrap();
        assert_eq!(
            adapter.bootstrap_async(bootstrap()).await,
            Err(WitnessError::AlreadyExists)
        );
        let state = transport.0.lock().unwrap();
        let commits: Vec<_> = state
            .requests
            .iter()
            .filter(|value| value.get("writes").is_some())
            .collect();
        assert_eq!(commits[0]["writes"][0]["currentDocument"]["exists"], false);
        assert_eq!(
            commits[1]["writes"][0]["currentDocument"]["updateTime"],
            "2026-01-02T03:04:05.001Z"
        );
        assert_eq!(record.archive_id(), ArchiveId::from_bytes(id(1)));
    }

    #[tokio::test]
    async fn aborted_retries_are_bounded_and_lost_response_is_resolved_exactly() {
        let transport = Arc::new(FakeTransport::new(
            None,
            [
                CommitOutcome::Aborted,
                CommitOutcome::Aborted,
                CommitOutcome::Aborted,
            ],
        ));
        assert_eq!(
            witness(transport.clone())
                .bootstrap_async(bootstrap())
                .await,
            Err(WitnessError::Unavailable)
        );
        assert_eq!(transport.0.lock().unwrap().commits, MAX_ABORTED_ATTEMPTS);
        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::LostResponse]));
        let record = witness(transport.clone())
            .bootstrap_async(bootstrap())
            .await
            .unwrap();
        assert_eq!(
            transport
                .0
                .lock()
                .unwrap()
                .record
                .as_ref()
                .map(|bytes| bytes.as_slice()),
            Some(record.encode().as_slice())
        );
    }

    #[tokio::test]
    async fn coordinator_path_preserves_lost_commit_response_without_internal_reread() {
        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
        let adapter = witness(transport.clone());
        let record = adapter.bootstrap_async(bootstrap()).await.unwrap();
        transport.push_outcome(CommitOutcome::LostResponse);
        let outcome = adapter
            .update_unresolved(record.archive_id(), |local| {
                local.acquire_lease(
                    record.archive_id(),
                    record.database_epoch(),
                    record.registry().key_epoch(),
                    ObjectId::from_bytes(id(8)),
                    10,
                )
            })
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            FirestoreUpdateOutcome::OutcomeUnknown { .. }
        ));
        // Begin + transactional batch-get + commit only: the unresolved path
        // does not issue the ordinary adapter's fourth exact readback.
        let state = transport.0.lock().unwrap();
        assert_eq!(state.commits, 2);
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|request| request.get("documents").is_some())
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn unresolved_failures_are_not_misclassified_as_definite_rejections() {
        for stage in [FailureStage::Begin, FailureStage::BatchGet] {
            let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
            let adapter = witness(transport.clone());
            let record = adapter.bootstrap_async(bootstrap()).await.unwrap();
            transport.fail_next(stage);
            assert!(matches!(
                adapter
                    .update_unresolved(record.archive_id(), |_| Ok(()))
                    .await,
                Err(FirestoreUpdateError::Failed(WitnessError::Unavailable))
            ));
            assert_eq!(transport.0.lock().unwrap().commits, 1);
        }

        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
        let record = witness(transport.clone())
            .bootstrap_async(bootstrap())
            .await
            .unwrap();
        let adapter = FirestoreWitness::new(
            FirestoreWitnessConfig::new("project-1", "123456789", "witness-db").unwrap(),
            Arc::new(FailingToken),
            transport.clone(),
        )
        .unwrap();
        assert!(matches!(
            adapter
                .update_unresolved(record.archive_id(), |_| Ok(()))
                .await,
            Err(FirestoreUpdateError::Failed(WitnessError::Unavailable))
        ));
        assert_eq!(transport.0.lock().unwrap().commits, 1);

        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
        let adapter = witness(transport.clone());
        let record = adapter.bootstrap_async(bootstrap()).await.unwrap();
        transport.push_outcome(CommitOutcome::CompetingWrite);
        assert!(matches!(
            adapter
                .update_unresolved(record.archive_id(), |local| {
                    local.acquire_lease(
                        record.archive_id(),
                        record.database_epoch(),
                        record.registry().key_epoch(),
                        ObjectId::from_bytes(id(8)),
                        10,
                    )
                })
                .await,
            Err(FirestoreUpdateError::Rejected(WitnessError::CompareFailed))
        ));
    }

    #[tokio::test]
    async fn trusted_clock_regression_and_redaction_fail_closed() {
        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
        let adapter = witness(transport.clone());
        let record = adapter.bootstrap_async(bootstrap()).await.unwrap();
        transport.0.lock().unwrap().time = "2020-01-01T00:00:00Z".to_owned();
        assert_eq!(
            adapter.read_current_async(record.archive_id()).await,
            Err(WitnessError::Clock)
        );
        assert_eq!(format!("{adapter:?}"), "FirestoreWitness(<inactive>)");
        assert!(!format!("{:?}", FirestoreTransaction::new(b"secret").unwrap()).contains("secret"));
    }

    #[tokio::test]
    async fn competing_write_update_time_precondition_cannot_be_overwritten() {
        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
        let adapter = witness(transport.clone());
        let record = adapter.bootstrap_async(bootstrap()).await.unwrap();
        transport.push_outcome(CommitOutcome::CompetingWrite);
        assert_eq!(
            adapter
                .acquire_lease_async(
                    record.archive_id(),
                    record.database_epoch(),
                    record.registry().key_epoch(),
                    ObjectId::from_bytes(id(8)),
                    10,
                )
                .await,
            Err(WitnessError::CompareFailed)
        );
        let state = transport.0.lock().unwrap();
        assert_eq!(state.record, Some(record.encode()));
        assert_eq!(
            state.update_time.as_deref(),
            Some("2026-01-02T03:04:05.998Z")
        );
    }

    #[tokio::test]
    async fn every_token_request_receives_the_dedicated_wif_audience() {
        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
        let tokens = Arc::new(StaticToken(Mutex::new(Vec::new())));
        let adapter = FirestoreWitness::new(
            FirestoreWitnessConfig::new("project-1", "123456789", "witness-db").unwrap(),
            tokens.clone(),
            transport,
        )
        .unwrap();
        let record = adapter.bootstrap_async(bootstrap()).await.unwrap();
        adapter
            .read_current_async(record.archive_id())
            .await
            .unwrap();
        let audiences = tokens.0.lock().unwrap();
        assert!(audiences.len() >= 2);
        assert!(audiences.iter().all(|audience| audience == WIF_AUDIENCE));
    }

    #[tokio::test]
    async fn legacy_exact_read_uses_async_firestore_transport_under_tokio() {
        let transport = Arc::new(FakeTransport::new(None, [CommitOutcome::Ok]));
        let adapter = witness(transport);
        let record = adapter.bootstrap_async(bootstrap()).await.unwrap();
        let observed =
            crate::legacy_gcm::ExactLegacyWitness::read_exact_legacy(&adapter, record.archive_id())
                .await
                .unwrap();
        assert_eq!(observed, record);
    }

    struct FakeProbeState {
        record: Option<[u8; PROBE_RECORD_BYTES]>,
        update_time: Option<String>,
        commits: usize,
        outcomes: VecDeque<FirestoreWitnessTransportError>,
        preconditions: Vec<Value>,
        apply_unknown: bool,
    }

    struct FakeProbeTransport(Mutex<FakeProbeState>);

    impl FakeProbeTransport {
        fn new(outcomes: impl IntoIterator<Item = FirestoreWitnessTransportError>) -> Self {
            Self(Mutex::new(FakeProbeState {
                record: None,
                update_time: None,
                commits: 0,
                outcomes: outcomes.into_iter().collect(),
                preconditions: Vec::new(),
                apply_unknown: false,
            }))
        }

        fn read(state: &FakeProbeState) -> FirestoreProbeRead {
            FirestoreProbeRead {
                record: state.record,
                update_time: state
                    .update_time
                    .as_deref()
                    .map(|value| FirestoreTimestamp::parse(value).unwrap()),
                read_time: FirestoreTimestamp::parse(TIME).unwrap(),
            }
        }
    }

    #[async_trait::async_trait]
    impl FirestoreProbeTransport for FakeProbeTransport {
        async fn begin_probe_transaction(
            &self,
            _bearer_token: &str,
            request_json: Value,
        ) -> std::result::Result<FirestoreTransaction, FirestoreWitnessTransportError> {
            assert_eq!(request_json, begin_request_json());
            FirestoreTransaction::new(b"probe-tx")
        }

        async fn batch_get_probe(
            &self,
            _bearer_token: &str,
            _transaction: &FirestoreTransaction,
            _request_json: Value,
        ) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError> {
            Ok(Self::read(&self.0.lock().unwrap()))
        }

        async fn read_probe(
            &self,
            _bearer_token: &str,
            _request_json: Value,
        ) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError> {
            Ok(Self::read(&self.0.lock().unwrap()))
        }

        async fn commit_probe_record(
            &self,
            _bearer_token: &str,
            _transaction: &FirestoreTransaction,
            request_json: Value,
        ) -> std::result::Result<(), FirestoreWitnessTransportError> {
            let mut state = self.0.lock().unwrap();
            state.commits += 1;
            state
                .preconditions
                .push(request_json["writes"][0]["currentDocument"].clone());
            let encoded = request_json["writes"][0]["update"]["fields"]["r"]["bytesValue"]
                .as_str()
                .unwrap();
            let decoded = STANDARD.decode(encoded).unwrap();
            let mut record = [0; PROBE_RECORD_BYTES];
            record.copy_from_slice(&decoded);
            let outcome = state.outcomes.pop_front();
            if outcome.is_none()
                || outcome == Some(FirestoreWitnessTransportError::OutcomeUnknown)
                    && state.apply_unknown
            {
                state.record = Some(record);
                state.update_time = Some(TIME.to_owned());
            }
            match outcome {
                None => Ok(()),
                Some(error) => Err(error),
            }
        }
    }

    fn probe(transport: Arc<FakeProbeTransport>) -> FirestoreTransportProbe {
        FirestoreTransportProbe::new(
            FirestoreWitnessConfig::new("project-1", "123456789", "witness-db").unwrap(),
            Arc::new(StaticToken(Mutex::new(Vec::new()))),
            transport,
        )
    }

    #[tokio::test]
    async fn probe_create_then_exact_update_use_provider_preconditions() {
        let transport = Arc::new(FakeProbeTransport::new([]));
        assert_eq!(
            probe(transport.clone()).run_once().await,
            FirestoreProbeOutcome::Confirmed
        );
        assert_eq!(
            probe(transport.clone()).run_once().await,
            FirestoreProbeOutcome::Confirmed
        );
        let state = transport.0.lock().unwrap();
        assert_eq!(state.preconditions[0], json!({"exists": false}));
        assert_eq!(state.preconditions[1], json!({"updateTime": TIME}));
        assert_eq!(
            FirestoreProbeRecord::decode(&state.record.unwrap())
                .unwrap()
                .generation(),
            2
        );
    }

    #[tokio::test]
    async fn probe_aborted_retries_are_bounded_and_stale_is_definitive() {
        let transport = Arc::new(FakeProbeTransport::new([
            FirestoreWitnessTransportError::Aborted,
            FirestoreWitnessTransportError::Aborted,
            FirestoreWitnessTransportError::Aborted,
        ]));
        assert_eq!(
            probe(transport.clone()).run_once().await,
            FirestoreProbeOutcome::Failed
        );
        assert_eq!(transport.0.lock().unwrap().commits, MAX_ABORTED_ATTEMPTS);

        let transport = Arc::new(FakeProbeTransport::new([
            FirestoreWitnessTransportError::PreconditionFailed,
        ]));
        assert_eq!(
            probe(transport).run_once().await,
            FirestoreProbeOutcome::Stale
        );
    }

    #[tokio::test]
    async fn probe_ambiguity_confirms_only_the_exact_attempt_and_generation() {
        let transport = Arc::new(FakeProbeTransport::new([
            FirestoreWitnessTransportError::OutcomeUnknown,
        ]));
        transport.0.lock().unwrap().apply_unknown = true;
        assert_eq!(
            probe(transport).run_once().await,
            FirestoreProbeOutcome::Confirmed
        );

        let transport = Arc::new(FakeProbeTransport::new([
            FirestoreWitnessTransportError::OutcomeUnknown,
        ]));
        assert_eq!(
            probe(transport).run_once().await,
            FirestoreProbeOutcome::OutcomeUnknown
        );
    }

    #[test]
    fn probe_batch_get_rejects_malformed_oversized_and_multiple_results() {
        let namespace = FirestoreWitnessNamespace::new("project-1", "witness-db").unwrap();
        let document = namespace.probe_document();
        let record = FirestoreProbeRecord::first(FirestoreProbeAttemptId::from_test_bytes([3; 32]));
        let valid = serde_json::to_vec(&json!({
            "found": {"name": document, "updateTime": TIME, "fields": {"r": {"bytesValue": STANDARD.encode(record.encode())}}},
            "readTime": TIME
        }))
        .unwrap();
        assert!(parse_exact_probe_batch_get_stream([valid.as_slice()], &document).is_ok());
        assert_eq!(
            parse_exact_probe_batch_get_stream([valid.as_slice(), valid.as_slice()], &document)
                .map(|_| ()),
            Err(FirestoreWitnessTransportError::Protocol)
        );
        assert_eq!(
            parse_exact_probe_batch_get_stream(
                [vec![b'x'; MAX_BATCH_GET_RESPONSE_BYTES + 1].as_slice()],
                &document
            )
            .map(|_| ()),
            Err(FirestoreWitnessTransportError::TooLarge)
        );
        let mut malformed: Value = serde_json::from_slice(&valid).unwrap();
        malformed["found"]["fields"]["extra"] = json!({"integerValue": "1"});
        let malformed = serde_json::to_vec(&malformed).unwrap();
        assert_eq!(
            parse_exact_probe_batch_get_stream([malformed.as_slice()], &document).map(|_| ()),
            Err(FirestoreWitnessTransportError::Protocol)
        );
    }

    struct PendingToken {
        entered: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl FirestoreWitnessBearerTokenProvider for PendingToken {
        async fn bearer_token(
            &self,
            _expected_audience: &str,
        ) -> std::result::Result<FirestoreWitnessBearerToken, FirestoreWitnessTransportError>
        {
            self.entered.notify_one();
            std::future::pending().await
        }
    }

    #[derive(Clone, Copy)]
    enum PendingProbeStage {
        Read,
        Commit,
    }

    struct PendingProbeTransport {
        stage: PendingProbeStage,
        entered: Arc<tokio::sync::Notify>,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl FirestoreProbeTransport for PendingProbeTransport {
        async fn begin_probe_transaction(
            &self,
            _bearer_token: &str,
            _request_json: Value,
        ) -> std::result::Result<FirestoreTransaction, FirestoreWitnessTransportError> {
            FirestoreTransaction::new(b"pending-tx")
        }

        async fn batch_get_probe(
            &self,
            _bearer_token: &str,
            _transaction: &FirestoreTransaction,
            _request_json: Value,
        ) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if matches!(self.stage, PendingProbeStage::Read) {
                self.entered.notify_one();
                return std::future::pending().await;
            }
            Ok(FirestoreProbeRead {
                record: None,
                update_time: None,
                read_time: FirestoreTimestamp::parse(TIME).unwrap(),
            })
        }

        async fn read_probe(
            &self,
            _bearer_token: &str,
            _request_json: Value,
        ) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError> {
            unreachable!("ambiguity reconciliation is not used")
        }

        async fn commit_probe_record(
            &self,
            _bearer_token: &str,
            _transaction: &FirestoreTransaction,
            _request_json: Value,
        ) -> std::result::Result<(), FirestoreWitnessTransportError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.entered.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancellation_at_auth_read_or_commit_has_no_detached_retry() {
        let config =
            || FirestoreWitnessConfig::new("project-1", "123456789", "witness-db").unwrap();

        let entered = Arc::new(tokio::sync::Notify::new());
        let transport = Arc::new(FakeProbeTransport::new([]));
        let probe = Arc::new(FirestoreTransportProbe::new(
            config(),
            Arc::new(PendingToken {
                entered: Arc::clone(&entered),
            }),
            transport.clone(),
        ));
        let task = tokio::spawn({
            let probe = Arc::clone(&probe);
            async move { probe.run_once().await }
        });
        entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(transport.0.lock().unwrap().commits, 0);

        for stage in [PendingProbeStage::Read, PendingProbeStage::Commit] {
            let entered = Arc::new(tokio::sync::Notify::new());
            let transport = Arc::new(PendingProbeTransport {
                stage,
                entered: Arc::clone(&entered),
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let probe = Arc::new(FirestoreTransportProbe::new(
                config(),
                Arc::new(StaticToken(Mutex::new(Vec::new()))),
                transport.clone(),
            ));
            let task = tokio::spawn({
                let probe = Arc::clone(&probe);
                async move { probe.run_once().await }
            });
            entered.notified().await;
            let calls = transport.calls.load(std::sync::atomic::Ordering::SeqCst);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            tokio::task::yield_now().await;
            assert_eq!(
                transport.calls.load(std::sync::atomic::Ordering::SeqCst),
                calls
            );
        }
    }
}

/// Exact, dedicated WIF provider resource accepted by this inactive adapter.
/// It is an STS bearer-token audience, never a public verifier audience.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FirestoreWitnessAudience(String);
impl FirestoreWitnessAudience {
    pub(crate) fn new(value: &str) -> std::result::Result<Self, WitnessError> {
        let Some(project_number) = value
            .strip_prefix(ARCHIVE_WITNESS_WIF_AUDIENCE_PREFIX)
            .and_then(|rest| rest.strip_suffix(ARCHIVE_WITNESS_WIF_AUDIENCE_SUFFIX))
        else {
            return Err(WitnessError::Malformed);
        };
        if !(1..=20).contains(&project_number.len())
            || project_number.starts_with('0')
            || !project_number.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(WitnessError::Malformed);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for FirestoreWitnessAudience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreWitnessAudience(<redacted>)")
    }
}

/// Opaque, bounded bearer-token material. It has no `Display`/derived `Debug`
/// implementation so it cannot accidentally reach logs.
pub(crate) struct FirestoreWitnessBearerToken {
    bytes: Zeroizing<[u8; MAX_BEARER_TOKEN_BYTES]>,
    len: usize,
}
impl FirestoreWitnessBearerToken {
    pub(crate) fn new(value: &str) -> std::result::Result<Self, FirestoreWitnessTransportError> {
        if value.is_empty()
            || value.len() > MAX_BEARER_TOKEN_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
        {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let mut bytes = Zeroizing::new([0; MAX_BEARER_TOKEN_BYTES]);
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            len: value.len(),
        })
    }

    fn as_str(&self) -> &str {
        // `new` copied only valid bytes from a Rust `str`.
        std::str::from_utf8(&self.bytes[..self.len]).expect("validated bearer token")
    }

    pub(crate) fn duplicate(&self) -> Self {
        // The source is a bounded, UTF-8 token constructed by `new`.
        Self::new(self.as_str()).expect("duplicate validated bearer token")
    }
}
impl fmt::Debug for FirestoreWitnessBearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreWitnessBearerToken(<opaque>)")
    }
}

/// Opaque, bounded Firestore transaction token. It has no `Display`/derived
/// `Debug` implementation so it cannot accidentally reach logs.
pub(crate) struct FirestoreTransaction {
    bytes: Zeroizing<[u8; MAX_TRANSACTION_BYTES]>,
    len: usize,
}
impl FirestoreTransaction {
    pub(crate) fn new(bytes: &[u8]) -> std::result::Result<Self, FirestoreWitnessTransportError> {
        if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let mut bounded = Zeroizing::new([0; MAX_TRANSACTION_BYTES]);
        bounded[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: bounded,
            len: bytes.len(),
        })
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl fmt::Debug for FirestoreTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreTransaction(<opaque>)")
    }
}

/// A bounded canonical Firestore timestamp and its strict UTC-second parsing.
#[derive(Clone, PartialEq, Eq)]
struct FirestoreTimestamp {
    bytes: [u8; MAX_FIRESTORE_TIMESTAMP_BYTES],
    len: usize,
    trusted_tick: u64,
    subsecond_nanos: u32,
}
impl FirestoreTimestamp {
    fn parse(value: &str) -> std::result::Result<Self, WitnessError> {
        if value.len() > MAX_FIRESTORE_TIMESTAMP_BYTES {
            return Err(WitnessError::Clock);
        }
        let trusted_tick = firestore_read_time_tick(value)?;
        let suffix = &value[19..value.len() - 1];
        let subsecond_nanos = if suffix.is_empty() {
            0
        } else {
            let digits = suffix[1..]
                .parse::<u32>()
                .map_err(|_| WitnessError::Clock)?;
            match suffix.len() {
                4 => digits * 1_000_000,
                7 => digits * 1_000,
                10 => digits,
                _ => return Err(WitnessError::Clock),
            }
        };
        let mut bytes = [0; MAX_FIRESTORE_TIMESTAMP_BYTES];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            len: value.len(),
            trusted_tick,
            subsecond_nanos,
        })
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("validated timestamp")
    }

    fn is_after(&self, other: &Self) -> bool {
        (self.trusted_tick, self.subsecond_nanos) > (other.trusted_tick, other.subsecond_nanos)
    }
}

/// Validates the bounded canonical Firestore UTC timestamp grammar shared by
/// the provider-neutral adapter and its concrete REST transport.
pub(crate) fn valid_firestore_timestamp(value: &str) -> bool {
    FirestoreTimestamp::parse(value).is_ok()
}

/// Validates Firestore's update-time precondition requirement: a canonical
/// UTC timestamp whose nanoseconds are aligned to whole microseconds.
pub(crate) fn valid_firestore_precondition_timestamp(value: &str) -> bool {
    FirestoreTimestamp::parse(value).is_ok_and(|timestamp| timestamp.subsecond_nanos % 1_000 == 0)
}

/// Compares two already canonical provider timestamps without exposing their
/// contents or allowing a separate, weaker parser in the HTTP transport.
pub(crate) fn firestore_timestamp_not_after(left: &str, right: &str) -> bool {
    match (
        FirestoreTimestamp::parse(left),
        FirestoreTimestamp::parse(right),
    ) {
        (Ok(left), Ok(right)) => !left.is_after(&right),
        _ => false,
    }
}
impl fmt::Debug for FirestoreTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreTimestamp(<redacted>)")
    }
}

/// The only document payload the adapter accepts. `read_time` is the exact
/// Firestore server readTime and `trusted_tick` is derived from it. A concrete
/// transport must use [`parse_exact_batch_get_stream`] for every batch-get.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FirestoreWitnessRead {
    record: Option<[u8; WITNESS_RECORD_BYTES]>,
    update_time: Option<FirestoreTimestamp>,
    read_time: FirestoreTimestamp,
    trusted_tick: u64,
}
impl fmt::Debug for FirestoreWitnessRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreWitnessRead(<redacted>)")
    }
}

/// Narrow token boundary.  It deliberately has no metadata-server default;
/// runtime wiring must provide a digest-bound workload identity token source and
/// mint a token for the supplied, dedicated provider-resource audience.
#[async_trait::async_trait]
pub(crate) trait FirestoreWitnessBearerTokenProvider: Send + Sync {
    async fn bearer_token(
        &self,
        expected_audience: &str,
    ) -> std::result::Result<FirestoreWitnessBearerToken, FirestoreWitnessTransportError>;
}

/// Provider-neutral Firestore REST boundary. Implementations issue only
/// `beginTransaction(readWrite)`, exact `batchGet`, and full-document
/// `commit`; they must never list, query, delete, or add fields to the record.
/// For `batchGet`, they must cap the complete response array at
/// [`MAX_BATCH_GET_RESPONSE_BYTES`] before deserializing it and call
/// [`parse_exact_batch_get_stream`] with its sole object so exactly one
/// response is accepted.
#[async_trait::async_trait]
pub(crate) trait FirestoreWitnessTransport: Send + Sync {
    async fn begin_read_write(
        &self,
        bearer_token: &str,
        request_json: Value,
    ) -> std::result::Result<FirestoreTransaction, FirestoreWitnessTransportError>;
    async fn batch_get_exact(
        &self,
        bearer_token: &str,
        transaction: &FirestoreTransaction,
        request_json: Value,
    ) -> std::result::Result<FirestoreWitnessRead, FirestoreWitnessTransportError>;
    async fn read_exact(
        &self,
        bearer_token: &str,
        request_json: Value,
    ) -> std::result::Result<FirestoreWitnessRead, FirestoreWitnessTransportError>;
    async fn commit_full_record(
        &self,
        bearer_token: &str,
        transaction: &FirestoreTransaction,
        request_json: Value,
    ) -> std::result::Result<(), FirestoreWitnessTransportError>;
}

/// Probe-only REST boundary. It is deliberately separate from canonical
/// archive witness semantics and accepts only the fixed singleton request
/// shapes constructed below.
#[async_trait::async_trait]
pub(crate) trait FirestoreProbeTransport: Send + Sync {
    async fn begin_probe_transaction(
        &self,
        bearer_token: &str,
        request_json: Value,
    ) -> std::result::Result<FirestoreTransaction, FirestoreWitnessTransportError>;
    async fn batch_get_probe(
        &self,
        bearer_token: &str,
        transaction: &FirestoreTransaction,
        request_json: Value,
    ) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError>;
    async fn read_probe(
        &self,
        bearer_token: &str,
        request_json: Value,
    ) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError>;
    async fn commit_probe_record(
        &self,
        bearer_token: &str,
        transaction: &FirestoreTransaction,
        request_json: Value,
    ) -> std::result::Result<(), FirestoreWitnessTransportError>;
}

/// Exact singleton read result. All fields remain private; the concrete HTTP
/// transport can construct it only through the strict parser in this module.
pub(crate) struct FirestoreProbeRead {
    record: Option<[u8; PROBE_RECORD_BYTES]>,
    update_time: Option<FirestoreTimestamp>,
    read_time: FirestoreTimestamp,
}

impl fmt::Debug for FirestoreProbeRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirestoreProbeRead(<redacted>)")
    }
}

/// One construction boundary collects the Firestore namespace and numeric WIF
/// provider project and derives the exact audience rather than accepting it as
/// independent runtime configuration. A future concrete runtime must source
/// this pair from one image-baked deployment identity; Terraform IAM remains
/// responsible for proving that the provider principal can access only this
/// exact named database.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FirestoreWitnessConfig {
    namespace: FirestoreWitnessNamespace,
    provider_audience: FirestoreWitnessAudience,
}
impl FirestoreWitnessConfig {
    pub(crate) fn new(
        project: &str,
        project_number: &str,
        database: &str,
    ) -> std::result::Result<Self, WitnessError> {
        let namespace = FirestoreWitnessNamespace::new(project, database)?;
        let provider_audience = FirestoreWitnessAudience::new(&format!(
            "{ARCHIVE_WITNESS_WIF_AUDIENCE_PREFIX}{project_number}{ARCHIVE_WITNESS_WIF_AUDIENCE_SUFFIX}"
        ))?;
        Ok(Self {
            namespace,
            provider_audience,
        })
    }

    /// Return the already-validated namespace as a typed value.  The concrete
    /// composition seam uses this instead of accepting an independently
    /// configurable project/database selector.
    pub(crate) fn namespace(&self) -> FirestoreWitnessNamespace {
        self.namespace.clone()
    }

    /// Return the audience derived from the same deployment identity as the
    /// namespace.  Callers cannot substitute a raw audience string.
    pub(crate) fn provider_audience(&self) -> FirestoreWitnessAudience {
        self.provider_audience.clone()
    }
}
impl fmt::Debug for FirestoreWitnessConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreWitnessConfig(<opaque>)")
    }
}

/// Fixed project/database selector. It only constructs the one legal
/// document name for an opaque archive ID.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FirestoreWitnessNamespace {
    project: String,
    database: String,
}
impl FirestoreWitnessNamespace {
    pub(crate) fn new(project: &str, database: &str) -> std::result::Result<Self, WitnessError> {
        let valid_project = (6..=30).contains(&project.len())
            && project
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_lowercase)
            && project
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && project
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        let valid_database = (4..=63).contains(&database.len())
            && database
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_lowercase)
            && database
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && database
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !is_uuid_like(database);
        if !valid_project || !valid_database {
            return Err(WitnessError::Malformed);
        }
        Ok(Self {
            project: project.to_owned(),
            database: database.to_owned(),
        })
    }

    fn document(&self, archive_id: ArchiveId) -> String {
        let mut encoded = String::with_capacity(32);
        for byte in archive_id.as_bytes() {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        format!(
            "projects/{}/databases/{}/documents/{WITNESS_COLLECTION}/{encoded}",
            self.project, self.database
        )
    }

    /// The immutable Firestore database resource used by the concrete
    /// transport. This is deliberately not a general collection or document
    /// selector.
    pub(crate) fn database_resource(&self) -> String {
        format!("projects/{}/databases/{}", self.project, self.database)
    }

    /// The sole non-authoritative probe document. There is no caller-selected
    /// collection or document component.
    pub(crate) fn probe_document(&self) -> String {
        format!(
            "projects/{}/databases/{}/documents/{}",
            self.project,
            self.database,
            singleton_document_suffix()
        )
    }

    pub(crate) fn is_probe_document(&self, document: &str) -> bool {
        document == self.probe_document()
    }

    /// Checks the only legal document family without exposing the project or
    /// database components separately to a transport implementation.
    pub(crate) fn is_canonical_document(&self, document: &str) -> bool {
        let prefix = format!(
            "projects/{}/databases/{}/documents/{WITNESS_COLLECTION}/",
            self.project, self.database
        );
        let Some(archive_id) = document.strip_prefix(&prefix) else {
            return false;
        };
        archive_id.len() == 32 && archive_id.bytes().all(is_lower_hex_byte)
    }
}

const fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

/// Firestore named databases reject UUID-shaped IDs even though their
/// individual characters otherwise fit the named-database grammar.
fn is_uuid_like(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| value.as_bytes()[index] == b'-')
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_alphanumeric())
}
impl fmt::Debug for FirestoreWitnessNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreWitnessNamespace(<opaque>)")
    }
}

/// Builds the exact emulator-compatible REST JSON shapes.  These helpers are
/// intentionally separate from HTTP so request formation can be unit tested
/// without credentials or a live provider.
fn begin_request_json() -> Value {
    json!({"options": {"readWrite": {}}})
}
fn batch_get_request_json(document: &str, transaction: Option<&FirestoreTransaction>) -> Value {
    let mut request = json!({"documents": [document]});
    if let Some(transaction) = transaction {
        request["transaction"] = Value::String(STANDARD.encode(transaction.bytes()));
    }
    request
}
fn commit_request_json(
    document: &str,
    transaction: &FirestoreTransaction,
    encoded: &[u8; WITNESS_RECORD_BYTES],
    update_time: Option<&str>,
) -> Value {
    let precondition = match update_time {
        Some(update_time) => json!({"updateTime": update_time}),
        None => json!({"exists": false}),
    };
    json!({
        "transaction": STANDARD.encode(transaction.bytes()),
        "writes": [{
            "update": {"name": document, "fields": {"r": {"bytesValue": STANDARD.encode(encoded)}}},
            "currentDocument": precondition
        }]
    })
}

fn map_transport(error: FirestoreWitnessTransportError) -> WitnessError {
    match error {
        FirestoreWitnessTransportError::PreconditionFailed => WitnessError::CompareFailed,
        FirestoreWitnessTransportError::EndpointNotFound => WitnessError::Unavailable,
        FirestoreWitnessTransportError::TooLarge | FirestoreWitnessTransportError::Protocol => {
            WitnessError::Corrupt
        }
        FirestoreWitnessTransportError::DefinitelyPresentInvalid => WitnessError::Corrupt,
        FirestoreWitnessTransportError::Unavailable
        | FirestoreWitnessTransportError::Aborted
        | FirestoreWitnessTransportError::OutcomeUnknown => WitnessError::Unavailable,
    }
}

fn decode_read(
    read: &FirestoreWitnessRead,
    archive_id: ArchiveId,
) -> std::result::Result<Option<[u8; WITNESS_RECORD_BYTES]>, WitnessError> {
    if read.read_time.trusted_tick != read.trusted_tick
        || firestore_read_time_tick(read.read_time.as_str())? != read.trusted_tick
    {
        return Err(WitnessError::Clock);
    }
    match (&read.record, &read.update_time) {
        (None, None) => Ok(None),
        (Some(bytes), Some(update_time)) if !update_time.is_after(&read.read_time) => {
            if firestore_read_time_tick(update_time.as_str())? != update_time.trusted_tick {
                return Err(WitnessError::Clock);
            }
            let decoded = WitnessRecord::decode(bytes)?;
            if decoded.archive_id() != archive_id {
                return Err(WitnessError::Corrupt);
            }
            if read.trusted_tick < decoded.last_server_tick() {
                return Err(WitnessError::Clock);
            }
            Ok(Some(*bytes))
        }
        (Some(_), Some(_)) => Err(WitnessError::Clock),
        _ => Err(WitnessError::Corrupt),
    }
}

/// Strictly decodes one already size-bounded JSON object from Firestore's
/// `batchGet` response array. The expected document prevents a substituted
/// name from becoming an authority record. The outer exact parser preserves
/// rejected `found` evidence so it can never become evidence of absence.
fn parse_batch_get_response(
    value: &Value,
    expected_document: &str,
) -> std::result::Result<FirestoreWitnessRead, FirestoreWitnessTransportError> {
    let object = value
        .as_object()
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    if object.len() != 2 {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let read_time = object
        .get("readTime")
        .and_then(Value::as_str)
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    let read_time = FirestoreTimestamp::parse(read_time)
        .map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    let trusted_tick = read_time.trusted_tick;
    let found = object.get("found");
    let missing = object.get("missing");
    if found.is_some() == missing.is_some() {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    if let Some(missing) = missing {
        if missing.as_str() != Some(expected_document) || object.len() != 2 {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        return Ok(FirestoreWitnessRead {
            record: None,
            update_time: None,
            read_time,
            trusted_tick,
        });
    }
    let found = found
        .and_then(Value::as_object)
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    if found.get("name").and_then(Value::as_str) != Some(expected_document) {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    if !matches!(found.len(), 3 | 4) {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let update_time = found
        .get("updateTime")
        .and_then(Value::as_str)
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    let update_time = FirestoreTimestamp::parse(update_time)
        .map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    let create_time = match found.get("createTime") {
        None if found.len() == 3 => None,
        Some(Value::String(create_time)) if found.len() == 4 => Some(
            FirestoreTimestamp::parse(create_time)
                .map_err(|_| FirestoreWitnessTransportError::Protocol)?,
        ),
        _ => return Err(FirestoreWitnessTransportError::Protocol),
    };
    if create_time
        .as_ref()
        .is_some_and(|create_time| create_time.is_after(&update_time))
        || update_time.is_after(&read_time)
    {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let fields = found
        .get("fields")
        .and_then(Value::as_object)
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    if fields.len() != 1 {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let encoded = fields
        .get("r")
        .and_then(Value::as_object)
        .and_then(|field| (field.len() == 1).then_some(field))
        .and_then(|field| field.get("bytesValue"))
        .and_then(Value::as_str)
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    if encoded.len() != WITNESS_RECORD_BASE64_BYTES {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let mut record = [0; WITNESS_RECORD_BYTES];
    let decoded_len = STANDARD
        .decode_slice(encoded, &mut record)
        .map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    if decoded_len != WITNESS_RECORD_BYTES {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    Ok(FirestoreWitnessRead {
        record: Some(record),
        update_time: Some(update_time),
        read_time,
        trusted_tick,
    })
}

/// Parses exactly one size-bounded batch-get response object. A concrete HTTP
/// transport must cap the complete JSON response array before deserializing
/// it, require exactly one object, then pass that object here. Empty responses
/// are protocol failures; rejected multi-object responses preserve definite
/// presence when a `found` document was included.
pub(crate) fn parse_exact_batch_get_stream<'a>(
    responses: impl IntoIterator<Item = &'a [u8]>,
    expected_document: &str,
) -> std::result::Result<FirestoreWitnessRead, FirestoreWitnessTransportError> {
    let mut responses = responses.into_iter();
    let response = responses
        .next()
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    if response.len() > MAX_BATCH_GET_RESPONSE_BYTES {
        return Err(FirestoreWitnessTransportError::TooLarge);
    }
    let response: Value =
        serde_json::from_slice(response).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    let parsed = parse_batch_get_response(&response, expected_document).map_err(|error| {
        if response.get("found").is_some() {
            FirestoreWitnessTransportError::DefinitelyPresentInvalid
        } else {
            error
        }
    })?;
    if responses.next().is_some() {
        return Err(if parsed.record.is_some() {
            FirestoreWitnessTransportError::DefinitelyPresentInvalid
        } else {
            FirestoreWitnessTransportError::Protocol
        });
    }
    Ok(parsed)
}

fn probe_batch_get_request_json(
    document: &str,
    transaction: Option<&FirestoreTransaction>,
) -> Value {
    batch_get_request_json(document, transaction)
}

fn probe_commit_request_json(
    document: &str,
    transaction: &FirestoreTransaction,
    encoded: &[u8; PROBE_RECORD_BYTES],
    update_time: Option<&str>,
) -> Value {
    let precondition = match update_time {
        Some(update_time) => json!({"updateTime": update_time}),
        None => json!({"exists": false}),
    };
    json!({
        "transaction": STANDARD.encode(transaction.bytes()),
        "writes": [{
            "update": {"name": document, "fields": {"r": {"bytesValue": STANDARD.encode(encoded)}}},
            "currentDocument": precondition
        }]
    })
}

/// Parse exactly one bounded Firestore `batchGet` object for the singleton
/// probe. This codec is independent of and cannot decode a canonical witness.
pub(crate) fn parse_exact_probe_batch_get_stream<'a>(
    responses: impl IntoIterator<Item = &'a [u8]>,
    expected_document: &str,
) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError> {
    let mut responses = responses.into_iter();
    let bytes = responses
        .next()
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    if bytes.len() > MAX_BATCH_GET_RESPONSE_BYTES {
        return Err(FirestoreWitnessTransportError::TooLarge);
    }
    if responses.next().is_some() {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    let object = value
        .as_object()
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    if object.len() != 2 {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let read_time = object
        .get("readTime")
        .and_then(Value::as_str)
        .ok_or(FirestoreWitnessTransportError::Protocol)
        .and_then(|value| {
            FirestoreTimestamp::parse(value).map_err(|_| FirestoreWitnessTransportError::Protocol)
        })?;
    match (object.get("found"), object.get("missing")) {
        (None, Some(Value::String(missing))) if missing == expected_document => {
            Ok(FirestoreProbeRead {
                record: None,
                update_time: None,
                read_time,
            })
        }
        (Some(Value::Object(found)), None) => {
            if !matches!(found.len(), 3 | 4)
                || found.get("name").and_then(Value::as_str) != Some(expected_document)
            {
                return Err(FirestoreWitnessTransportError::Protocol);
            }
            let update_time = found
                .get("updateTime")
                .and_then(Value::as_str)
                .ok_or(FirestoreWitnessTransportError::Protocol)
                .and_then(|value| {
                    FirestoreTimestamp::parse(value)
                        .map_err(|_| FirestoreWitnessTransportError::Protocol)
                })?;
            let create_time = match found.get("createTime") {
                None if found.len() == 3 => None,
                Some(Value::String(value)) if found.len() == 4 => Some(
                    FirestoreTimestamp::parse(value)
                        .map_err(|_| FirestoreWitnessTransportError::Protocol)?,
                ),
                _ => return Err(FirestoreWitnessTransportError::Protocol),
            };
            if update_time.is_after(&read_time)
                || create_time
                    .as_ref()
                    .is_some_and(|value| value.is_after(&update_time))
            {
                return Err(FirestoreWitnessTransportError::Protocol);
            }
            let fields = found
                .get("fields")
                .and_then(Value::as_object)
                .filter(|fields| fields.len() == 1)
                .ok_or(FirestoreWitnessTransportError::Protocol)?;
            let encoded = fields
                .get("r")
                .and_then(Value::as_object)
                .filter(|field| field.len() == 1)
                .and_then(|field| field.get("bytesValue"))
                .and_then(Value::as_str)
                .ok_or(FirestoreWitnessTransportError::Protocol)?;
            let decoded = STANDARD
                .decode(encoded)
                .map_err(|_| FirestoreWitnessTransportError::Protocol)?;
            if decoded.len() != PROBE_RECORD_BYTES || STANDARD.encode(&decoded) != encoded {
                return Err(FirestoreWitnessTransportError::Protocol);
            }
            let mut record = [0; PROBE_RECORD_BYTES];
            record.copy_from_slice(&decoded);
            FirestoreProbeRecord::decode(&record)
                .ok_or(FirestoreWitnessTransportError::Protocol)?;
            Ok(FirestoreProbeRead {
                record: Some(record),
                update_time: Some(update_time),
                read_time,
            })
        }
        _ => Err(FirestoreWitnessTransportError::Protocol),
    }
}

/// One-shot, non-authoritative probe over the process's Tokio runtime. It owns
/// no runtime and launches no tasks; cancellation drops the in-flight future,
/// so no detached retry can survive any auth/read/commit await point.
pub(crate) struct FirestoreTransportProbe {
    namespace: FirestoreWitnessNamespace,
    provider_audience: FirestoreWitnessAudience,
    tokens: Arc<dyn FirestoreWitnessBearerTokenProvider>,
    transport: Arc<dyn FirestoreProbeTransport>,
}

impl FirestoreTransportProbe {
    pub(crate) fn new(
        config: FirestoreWitnessConfig,
        tokens: Arc<dyn FirestoreWitnessBearerTokenProvider>,
        transport: Arc<dyn FirestoreProbeTransport>,
    ) -> Self {
        Self {
            namespace: config.namespace,
            provider_audience: config.provider_audience,
            tokens,
            transport,
        }
    }

    async fn token(
        &self,
    ) -> std::result::Result<FirestoreWitnessBearerToken, FirestoreWitnessTransportError> {
        self.tokens
            .bearer_token(self.provider_audience.as_str())
            .await
    }

    pub(crate) async fn run_once(&self) -> FirestoreProbeOutcome {
        let attempt_id = FirestoreProbeAttemptId::random();
        let document = self.namespace.probe_document();
        for retry in 0..MAX_ABORTED_ATTEMPTS {
            let token = match self.token().await {
                Ok(token) => token,
                Err(_) => return FirestoreProbeOutcome::Failed,
            };
            let transaction = match self
                .transport
                .begin_probe_transaction(token.as_str(), begin_request_json())
                .await
            {
                Ok(transaction) => transaction,
                Err(_) => return FirestoreProbeOutcome::Failed,
            };
            let read = match self
                .transport
                .batch_get_probe(
                    token.as_str(),
                    &transaction,
                    probe_batch_get_request_json(&document, Some(&transaction)),
                )
                .await
            {
                Ok(read) => read,
                Err(_) => return FirestoreProbeOutcome::Failed,
            };
            let current = match read.record {
                None if read.update_time.is_none() => None,
                Some(bytes) if read.update_time.is_some() => {
                    match FirestoreProbeRecord::decode(&bytes) {
                        Some(record) => Some(record),
                        None => return FirestoreProbeOutcome::Failed,
                    }
                }
                _ => return FirestoreProbeOutcome::Failed,
            };
            let candidate = match current {
                Some(record) => match record.next(attempt_id) {
                    Some(next) => next,
                    None => return FirestoreProbeOutcome::Failed,
                },
                None => FirestoreProbeRecord::first(attempt_id),
            };
            let commit = self
                .transport
                .commit_probe_record(
                    token.as_str(),
                    &transaction,
                    probe_commit_request_json(
                        &document,
                        &transaction,
                        &candidate.encode(),
                        read.update_time.as_ref().map(FirestoreTimestamp::as_str),
                    ),
                )
                .await;
            match commit {
                Ok(()) => return FirestoreProbeOutcome::Confirmed,
                Err(FirestoreWitnessTransportError::Aborted)
                    if retry + 1 < MAX_ABORTED_ATTEMPTS =>
                {
                    continue;
                }
                Err(FirestoreWitnessTransportError::PreconditionFailed) => {
                    return FirestoreProbeOutcome::Stale;
                }
                Err(FirestoreWitnessTransportError::OutcomeUnknown) => {
                    let token = match self.token().await {
                        Ok(token) => token,
                        Err(_) => return FirestoreProbeOutcome::OutcomeUnknown,
                    };
                    let observed = self
                        .transport
                        .read_probe(
                            token.as_str(),
                            probe_batch_get_request_json(&document, None),
                        )
                        .await;
                    return match observed
                        .ok()
                        .and_then(|read| read.record)
                        .and_then(|bytes| FirestoreProbeRecord::decode(&bytes))
                    {
                        Some(record)
                            if record.attempt_id() == attempt_id
                                && record.generation() == candidate.generation() =>
                        {
                            FirestoreProbeOutcome::Confirmed
                        }
                        _ => FirestoreProbeOutcome::OutcomeUnknown,
                    };
                }
                Err(_) => return FirestoreProbeOutcome::Failed,
            }
        }
        FirestoreProbeOutcome::Failed
    }
}

impl fmt::Debug for FirestoreTransportProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirestoreTransportProbe(<redacted>)")
    }
}

/// Parses canonical UTC Firestore timestamps to whole seconds. A provider
/// transport must preserve the original string and this result as a pair.
fn firestore_read_time_tick(value: &str) -> std::result::Result<u64, WitnessError> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || !value.ends_with('Z')
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return Err(WitnessError::Clock);
    }
    let number = |start, len| -> std::result::Result<i64, WitnessError> {
        let part = bytes.get(start..start + len).ok_or(WitnessError::Clock)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return Err(WitnessError::Clock);
        }
        std::str::from_utf8(part)
            .map_err(|_| WitnessError::Clock)?
            .parse()
            .map_err(|_| WitnessError::Clock)
    };
    let year = number(0, 4)?;
    let month = number(5, 2)?;
    let day = number(8, 2)?;
    let hour = number(11, 2)?;
    let minute = number(14, 2)?;
    let second = number(17, 2)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(WitnessError::Clock);
    }
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return Err(WitnessError::Clock),
    };
    if day > days_in_month {
        return Err(WitnessError::Clock);
    }
    let suffix = &value[19..value.len() - 1];
    if !suffix.is_empty()
        && (!matches!(suffix.len(), 4 | 7 | 10)
            || !suffix.starts_with('.')
            || !suffix[1..].bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(WitnessError::Clock);
    }
    // Howard Hinnant's civil-date conversion, with Unix epoch offset.
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days
        .checked_mul(86_400)
        .and_then(|v| v.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or(WitnessError::Clock)?;
    u64::try_from(seconds).map_err(|_| WitnessError::Clock)
}

/// Inactive concrete witness. Async methods are the real adapter surface;
/// the existing synchronous [`Witness`] trait is supported only through a
/// private runtime for compatibility with the currently-inactive contract.
pub(crate) struct FirestoreWitness {
    namespace: FirestoreWitnessNamespace,
    provider_audience: FirestoreWitnessAudience,
    tokens: Arc<dyn FirestoreWitnessBearerTokenProvider>,
    transport: Arc<dyn FirestoreWitnessTransport>,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

/// A compare-and-advance result whose provider response may have been lost.
/// The shadow coordinator must retain that distinction so it can return an
/// exact opaque reconciliation handle instead of treating ambiguity as a
/// definitive CAS rejection.
pub(crate) enum FirestoreWitnessCommitError {
    /// The candidate was definitively rejected by the local exact-state
    /// comparison or the provider's transaction precondition.
    Rejected(WitnessError),
    /// No commit was accepted, but this is not evidence that the retained
    /// candidate is stale (for example token, begin, or batch-get failure).
    Failed(WitnessError),
    OutcomeUnknown,
}

/// Phase-precise initial witness create outcome. `DefinitelyUnsent` is
/// returned only before the durable send-start marker exists. Once it exists,
/// every transport failure remains `OutcomeUnknown` until an exact read
/// resolves the retained candidate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FirestoreWitnessBootstrapError {
    DefinitelyUnsent(WitnessError),
    Rejected(WitnessError),
    OutcomeUnknown,
}

#[derive(Debug)]
enum FirestoreUpdateError {
    Rejected(WitnessError),
    Failed(WitnessError),
}

impl FirestoreUpdateError {
    const fn into_witness(self) -> WitnessError {
        match self {
            Self::Rejected(error) | Self::Failed(error) => error,
        }
    }
}

enum FirestoreUpdateOutcome<T> {
    Committed(T),
    OutcomeUnknown {
        output: T,
        encoded: Box<[u8; WITNESS_RECORD_BYTES]>,
    },
}

impl FirestoreWitness {
    pub(crate) fn new(
        config: FirestoreWitnessConfig,
        tokens: Arc<dyn FirestoreWitnessBearerTokenProvider>,
        transport: Arc<dyn FirestoreWitnessTransport>,
    ) -> std::result::Result<Self, WitnessError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| WitnessError::Unavailable)?;
        Ok(Self {
            namespace: config.namespace,
            provider_audience: config.provider_audience,
            tokens,
            transport,
            runtime: Mutex::new(Some(runtime)),
        })
    }

    async fn token(&self) -> std::result::Result<FirestoreWitnessBearerToken, WitnessError> {
        self.tokens
            .bearer_token(self.provider_audience.as_str())
            .await
            .map_err(map_transport)
    }
    async fn fresh_record(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<(FirestoreWitnessRead, Option<[u8; WITNESS_RECORD_BYTES]>), WitnessError>
    {
        let token = self.token().await?;
        let document = self.namespace.document(archive_id);
        let read = self
            .transport
            .read_exact(token.as_str(), batch_get_request_json(&document, None))
            .await
            .map_err(map_transport)?;
        let record = decode_read(&read, archive_id)?;
        Ok((read, record))
    }
    async fn update_unresolved<T, F>(
        &self,
        archive_id: ArchiveId,
        apply: F,
    ) -> std::result::Result<FirestoreUpdateOutcome<T>, FirestoreUpdateError>
    where
        F: Fn(&InMemoryWitness) -> std::result::Result<T, WitnessError>,
    {
        let document = self.namespace.document(archive_id);
        for attempt in 0..MAX_ABORTED_ATTEMPTS {
            let token = self.token().await.map_err(FirestoreUpdateError::Failed)?;
            let transaction = self
                .transport
                .begin_read_write(token.as_str(), begin_request_json())
                .await
                .map_err(map_transport)
                .map_err(FirestoreUpdateError::Failed)?;
            let read = self
                .transport
                .batch_get_exact(
                    token.as_str(),
                    &transaction,
                    batch_get_request_json(&document, Some(&transaction)),
                )
                .await
                .map_err(map_transport)
                .map_err(FirestoreUpdateError::Failed)?;
            let current = decode_read(&read, archive_id)
                .map_err(FirestoreUpdateError::Failed)?
                .ok_or(FirestoreUpdateError::Failed(WitnessError::MissingArchive))?;
            let local =
                InMemoryWitness::from_provider_record_at_tick(Some(current), read.trusted_tick)
                    .map_err(FirestoreUpdateError::Failed)?;
            let output = apply(&local).map_err(FirestoreUpdateError::Rejected)?;
            let next = local
                .read_current(archive_id)
                .map_err(FirestoreUpdateError::Failed)?
                .ok_or(FirestoreUpdateError::Failed(WitnessError::Synchronization))?;
            let encoded = next.encode();
            let commit = commit_request_json(
                &document,
                &transaction,
                &encoded,
                read.update_time.as_ref().map(FirestoreTimestamp::as_str),
            );
            match self
                .transport
                .commit_full_record(token.as_str(), &transaction, commit)
                .await
            {
                Ok(()) => return Ok(FirestoreUpdateOutcome::Committed(output)),
                Err(FirestoreWitnessTransportError::Aborted)
                    if attempt + 1 < MAX_ABORTED_ATTEMPTS =>
                {
                    continue
                }
                Err(FirestoreWitnessTransportError::OutcomeUnknown) => {
                    return Ok(FirestoreUpdateOutcome::OutcomeUnknown {
                        output,
                        encoded: Box::new(encoded),
                    });
                }
                Err(FirestoreWitnessTransportError::PreconditionFailed) => {
                    return Err(FirestoreUpdateError::Rejected(WitnessError::CompareFailed));
                }
                Err(error) => {
                    return Err(FirestoreUpdateError::Failed(map_transport(error)));
                }
            }
        }
        Err(FirestoreUpdateError::Failed(WitnessError::Unavailable))
    }

    async fn update<T, F>(
        &self,
        archive_id: ArchiveId,
        apply: F,
    ) -> std::result::Result<T, WitnessError>
    where
        F: Fn(&InMemoryWitness) -> std::result::Result<T, WitnessError>,
    {
        match self
            .update_unresolved(archive_id, apply)
            .await
            .map_err(FirestoreUpdateError::into_witness)?
        {
            FirestoreUpdateOutcome::Committed(output) => Ok(output),
            FirestoreUpdateOutcome::OutcomeUnknown { output, encoded } => {
                let (_, observed) = self.fresh_record(archive_id).await?;
                if observed
                    .as_ref()
                    .is_some_and(|bytes| bytes == encoded.as_ref())
                {
                    Ok(output)
                } else {
                    Err(WitnessError::CompareFailed)
                }
            }
        }
    }
    async fn commit_initial_witness(
        &self,
        token: &FirestoreWitnessBearerToken,
        transaction: &FirestoreTransaction,
        document: &str,
        admission: &ActiveCreateAdmission,
        send_started: &WitnessSendStarted,
        encoded: &[u8; WITNESS_RECORD_BYTES],
    ) -> std::result::Result<(), FirestoreWitnessBootstrapError> {
        if admission.archive_id() != send_started.archive_id()
            || admission.attempt_id() != send_started.attempt_id()
            || admission.revision() != send_started.admission_revision()
            || admission.artifact_ordinal() != 2
            || admission.artifact_hash() != send_started.expected_hash()
            || <[u8; 32]>::from(Sha256::digest(encoded)) != admission.artifact_hash()
        {
            return Err(FirestoreWitnessBootstrapError::Rejected(
                WitnessError::CompareFailed,
            ));
        }
        // At this point the transport request may be accepted before any
        // response is available. Apart from a definitive precondition
        // rejection, all provider/transport outcomes are ambiguous.
        match self
            .transport
            .commit_full_record(
                token.as_str(),
                transaction,
                commit_request_json(document, transaction, encoded, None),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(FirestoreWitnessTransportError::PreconditionFailed) => {
                // A prior response-ambiguous attempt may have committed
                // between this transaction's exact read and its create
                // precondition. Only a fresh exact read can distinguish that
                // success from a competing document. Absence or read failure
                // remains ambiguous once send-start is durable.
                match self.fresh_record(admission.archive_id()).await {
                    Ok((_, Some(observed))) if observed == *encoded => Ok(()),
                    Ok((_, Some(_))) => Err(FirestoreWitnessBootstrapError::Rejected(
                        WitnessError::AlreadyExists,
                    )),
                    Ok((_, None)) | Err(_) => Err(FirestoreWitnessBootstrapError::OutcomeUnknown),
                }
            }
            Err(_) => Err(FirestoreWitnessBootstrapError::OutcomeUnknown),
        }
    }

    pub(crate) async fn bootstrap_commit_started<D>(
        &self,
        admission: &ActiveCreateAdmission,
        dispatch: &D,
        bootstrap: WitnessBootstrap,
    ) -> std::result::Result<WitnessRecord, FirestoreWitnessBootstrapError>
    where
        D: WitnessCreateDispatchLedger + ?Sized,
    {
        let archive_id = bootstrap.archive_id();
        if admission.archive_id() != archive_id || admission.artifact_ordinal() != 2 {
            return Err(FirestoreWitnessBootstrapError::Rejected(
                WitnessError::CompareFailed,
            ));
        }
        let document = self.namespace.document(archive_id);
        let mut send_started = None;
        for attempt in 0..MAX_ABORTED_ATTEMPTS {
            let token = match self.token().await {
                Ok(token) => token,
                Err(error) if send_started.is_none() => {
                    return Err(FirestoreWitnessBootstrapError::DefinitelyUnsent(error))
                }
                Err(_) => return Err(FirestoreWitnessBootstrapError::OutcomeUnknown),
            };
            let transaction = match self
                .transport
                .begin_read_write(token.as_str(), begin_request_json())
                .await
            {
                Ok(transaction) => transaction,
                Err(error) if send_started.is_none() => {
                    return Err(FirestoreWitnessBootstrapError::DefinitelyUnsent(
                        map_transport(error),
                    ))
                }
                Err(_) => return Err(FirestoreWitnessBootstrapError::OutcomeUnknown),
            };
            let read = match self
                .transport
                .batch_get_exact(
                    token.as_str(),
                    &transaction,
                    batch_get_request_json(&document, Some(&transaction)),
                )
                .await
            {
                Ok(read) => read,
                Err(error) if send_started.is_none() => {
                    return Err(FirestoreWitnessBootstrapError::DefinitelyUnsent(
                        map_transport(error),
                    ))
                }
                Err(_) => return Err(FirestoreWitnessBootstrapError::OutcomeUnknown),
            };
            let existing = decode_read(&read, archive_id).map_err(|error| {
                if send_started.is_none() {
                    FirestoreWitnessBootstrapError::DefinitelyUnsent(error)
                } else {
                    FirestoreWitnessBootstrapError::OutcomeUnknown
                }
            })?;
            let encoded = bootstrap.expected_initial_record_bytes().map_err(|error| {
                if send_started.is_none() {
                    FirestoreWitnessBootstrapError::DefinitelyUnsent(error)
                } else {
                    FirestoreWitnessBootstrapError::OutcomeUnknown
                }
            })?;
            if let Some(existing) = existing {
                let record = WitnessRecord::decode(&existing)
                    .map_err(FirestoreWitnessBootstrapError::Rejected)?;
                let candidate = WitnessRecord::decode(&encoded)
                    .map_err(FirestoreWitnessBootstrapError::Rejected)?;
                return if record == candidate && send_started.is_some() {
                    Ok(record)
                } else {
                    Err(FirestoreWitnessBootstrapError::Rejected(
                        WitnessError::AlreadyExists,
                    ))
                };
            }
            let record = WitnessRecord::decode(&encoded)
                .map_err(FirestoreWitnessBootstrapError::DefinitelyUnsent)?;
            if <[u8; 32]>::from(Sha256::digest(encoded)) != admission.artifact_hash() {
                return Err(FirestoreWitnessBootstrapError::Rejected(
                    WitnessError::CompareFailed,
                ));
            }
            if send_started.is_none() {
                send_started = Some(
                    dispatch
                        .mark_witness_send_started(admission)
                        .await
                        .map_err(|_| {
                            FirestoreWitnessBootstrapError::DefinitelyUnsent(
                                WitnessError::CompareFailed,
                            )
                        })?,
                );
            }
            match self
                .commit_initial_witness(
                    &token,
                    &transaction,
                    &document,
                    admission,
                    send_started.as_ref().expect("set before commit"),
                    &encoded,
                )
                .await
            {
                Ok(()) => return Ok(record),
                Err(FirestoreWitnessBootstrapError::OutcomeUnknown)
                    if attempt + 1 < MAX_ABORTED_ATTEMPTS =>
                {
                    // Only an exact transaction reread may resolve whether an
                    // ABORTED/ambiguous attempt created the candidate. The
                    // durable marker is intentionally retained across retry.
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(FirestoreWitnessBootstrapError::OutcomeUnknown)
    }

    #[cfg(test)]
    pub(crate) async fn bootstrap_async(
        &self,
        bootstrap: WitnessBootstrap,
    ) -> std::result::Result<WitnessRecord, WitnessError> {
        let archive_id = bootstrap.archive_id();
        let document = self.namespace.document(archive_id);
        for attempt in 0..MAX_ABORTED_ATTEMPTS {
            let token = self.token().await?;
            let transaction = self
                .transport
                .begin_read_write(token.as_str(), begin_request_json())
                .await
                .map_err(map_transport)?;
            let read = self
                .transport
                .batch_get_exact(
                    token.as_str(),
                    &transaction,
                    batch_get_request_json(&document, Some(&transaction)),
                )
                .await
                .map_err(map_transport)?;
            if decode_read(&read, archive_id)?.is_some() {
                return Err(WitnessError::AlreadyExists);
            }
            let local = InMemoryWitness::from_provider_record_at_tick(None, read.trusted_tick)?;
            let record = local.bootstrap_at_tick(bootstrap.clone(), read.trusted_tick)?;
            let encoded = record.encode();
            match self
                .transport
                .commit_full_record(
                    token.as_str(),
                    &transaction,
                    commit_request_json(&document, &transaction, &encoded, None),
                )
                .await
            {
                Ok(()) => return Ok(record),
                Err(FirestoreWitnessTransportError::Aborted)
                    if attempt + 1 < MAX_ABORTED_ATTEMPTS =>
                {
                    continue
                }
                Err(FirestoreWitnessTransportError::OutcomeUnknown) => {
                    let (_, observed) = self.fresh_record(archive_id).await?;
                    if observed.as_ref().is_some_and(|bytes| bytes == &encoded) {
                        return Ok(record);
                    }
                    return Err(WitnessError::AlreadyExists);
                }
                Err(error) => return Err(map_transport(error)),
            }
        }
        Err(WitnessError::Unavailable)
    }
    pub(crate) async fn read_current_async(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<Option<WitnessRecord>, WitnessError> {
        let (_, record) = self.fresh_record(archive_id).await?;
        record
            .map(|bytes| WitnessRecord::decode(&bytes))
            .transpose()
    }

    /// Authenticate exact stored bytes while evaluating their lease against
    /// this read's trusted provider tick. The refreshed local record is never
    /// returned or persisted, preserving byte-exact send reconciliation.
    pub(crate) async fn validate_exact_maintenance_lease_async(
        &self,
        expected: &WitnessRecord,
        owner: crate::archive_v3::ObjectId,
    ) -> std::result::Result<WitnessLease, WitnessError> {
        let (read, record) = self.fresh_record(expected.archive_id()).await?;
        let encoded = record.ok_or(WitnessError::MissingArchive)?;
        if encoded != expected.encode() {
            return Err(WitnessError::Fenced);
        }
        let local =
            InMemoryWitness::from_provider_record_at_tick(Some(encoded), read.trusted_tick)?;
        let refreshed = local
            .read_current(expected.archive_id())?
            .ok_or(WitnessError::MissingArchive)?;
        refreshed.exact_active_lease_for_owner(owner)
    }
    pub(crate) async fn recovery_root_async(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<RecoveryRoot, WitnessError> {
        let (read, record) = self.fresh_record(archive_id).await?;
        let local = InMemoryWitness::from_provider_record_at_tick(record, read.trusted_tick)?;
        local.recovery_root(archive_id)
    }
    pub(crate) async fn acquire_lease_async(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> std::result::Result<WitnessLease, WitnessError> {
        self.update(archive_id, |local| {
            local.acquire_lease(archive_id, database_epoch, key_epoch, owner, duration_ticks)
        })
        .await
    }

    /// Owner-publisher-only exact acquire. Commit ambiguity is deliberately
    /// returned unresolved; encrypted Control owns the reserved owner ID and
    /// settles it only from a fresh exact witness reread.
    pub(crate) async fn acquire_exact_wal_owner_lease_unresolved_async(
        &self,
        expected: WitnessRecord,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        let outcome = self
            .update_unresolved(expected.archive_id(), |local| {
                local.acquire_exact_wal_owner_lease(&expected, owner, duration_ticks)
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(value) => Ok(value),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }

    /// Phase-1 advisory-owner-only exact acquire. Commit ambiguity remains
    /// unresolved so encrypted Control can adopt only the exact fresh
    /// `ShadowWal` successor under its durable owner ID.
    pub(crate) async fn acquire_exact_advisory_owner_lease_unresolved_async(
        &self,
        expected: WitnessRecord,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        let outcome = self
            .update_unresolved(expected.archive_id(), |local| {
                local.acquire_exact_advisory_owner_lease(&expected, owner, duration_ticks)
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(value) => Ok(value),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }

    pub(crate) async fn reacquire_exact_wal_owner_lease_unresolved_async(
        &self,
        previous: WitnessRecord,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        let outcome = self
            .update_unresolved(previous.archive_id(), |local| {
                local.reacquire_exact_wal_owner_lease(&previous, owner, duration_ticks)
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(value) => Ok(value),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }

    pub(crate) async fn renew_exact_wal_owner_lease_unresolved_async(
        &self,
        retained: WitnessRecord,
        lease: WitnessLease,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        let outcome = self
            .update_unresolved(retained.archive_id(), |local| {
                let current = local
                    .read_current(retained.archive_id())?
                    .ok_or(WitnessError::MissingArchive)?;
                if current != retained {
                    return Err(WitnessError::CompareFailed);
                }
                let renewed = local.renew_lease(lease, duration_ticks)?;
                let observed = local
                    .read_current(retained.archive_id())?
                    .ok_or(WitnessError::MissingArchive)?;
                Ok((observed, renewed))
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(value) => Ok(value),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }

    /// WAL-owner heartbeat/reacquire transaction. The provider transaction
    /// tick decides whether to retain/renew the current fence or reacquire at
    /// the next fence; response ambiguity remains unresolved for exact fresh
    /// readback adoption by encrypted Control.
    pub(crate) async fn maintain_exact_wal_owner_lease_unresolved_async(
        &self,
        retained: WitnessRecord,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> std::result::Result<(WitnessRecord, WitnessLease), FirestoreWitnessCommitError> {
        let outcome = self
            .update_unresolved(retained.archive_id(), |local| {
                local.maintain_exact_wal_owner_lease(&retained, owner, duration_ticks)
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(value) => Ok(value),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }
    pub(crate) async fn renew_lease_async(
        &self,
        lease: WitnessLease,
        duration_ticks: u64,
    ) -> std::result::Result<WitnessLease, WitnessError> {
        self.update(lease.archive_id(), |local| {
            local.renew_lease(lease, duration_ticks)
        })
        .await
    }
    pub(crate) async fn revoke_lease_async(
        &self,
        lease: WitnessLease,
    ) -> std::result::Result<(), WitnessError> {
        self.update(lease.archive_id(), |local| local.revoke_lease(lease))
            .await
    }

    /// Maintenance-terminal-only owner release. The transaction read's
    /// trusted tick authenticates the full retained WalAuthoritative R2 tuple
    /// and may clear the importer owner even exactly at or after lease expiry.
    /// Commit ambiguity is preserved for caller-owned exact reread.
    pub(crate) async fn release_exact_maintenance_terminal_unresolved_async(
        &self,
        retained: WitnessRecord,
        owner: ObjectId,
    ) -> std::result::Result<(), FirestoreWitnessCommitError> {
        let outcome = self
            .update_unresolved(retained.archive_id(), |local| {
                local.release_exact_maintenance_terminal(&retained, owner)
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(_) => Ok(()),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }

    /// Phase-1 advisory-only owner release. The transaction read's trusted
    /// tick authenticates the full retained ShadowWal tuple and may clear
    /// only that importer owner. Commit ambiguity remains caller-owned and is
    /// reconciled by an exact witness reread.
    pub(crate) async fn release_exact_maintenance_advisory_unresolved_async(
        &self,
        retained: WitnessRecord,
        owner: ObjectId,
    ) -> std::result::Result<(), FirestoreWitnessCommitError> {
        let outcome = self
            .update_unresolved(retained.archive_id(), |local| {
                local.release_exact_maintenance_advisory(&retained, owner)
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(_) => Ok(()),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }

    pub(crate) async fn compare_and_advance_root_async(
        &self,
        advance: RootAdvance,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.update(advance.archive_id(), |local| {
            local.compare_and_advance_root(advance.clone())
        })
        .await
    }

    /// Coordinator-only variant that deliberately does not resolve a lost
    /// commit response internally.  The coordinator owns the exact candidate
    /// and expected parent needed to build a durable reconciliation handle.
    pub(crate) async fn compare_and_advance_root_unresolved_async(
        &self,
        advance: RootAdvance,
    ) -> std::result::Result<WitnessReceipt, FirestoreWitnessCommitError> {
        let outcome = self
            .update_unresolved(advance.archive_id(), |local| {
                local.compare_and_advance_root(advance.clone())
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(receipt) => Ok(receipt),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }

    /// Publisher-only root advance. The full retained witness is compared
    /// before Firestore's transaction tick is applied, so a tuple change that
    /// happens to preserve the root/registry/lease projection cannot mutate.
    pub(crate) async fn compare_and_advance_exact_wal_owner_root_unresolved_async(
        &self,
        expected: WitnessRecord,
        advance: RootAdvance,
    ) -> std::result::Result<WitnessReceipt, FirestoreWitnessCommitError> {
        if expected.archive_id() != advance.archive_id() {
            return Err(FirestoreWitnessCommitError::Rejected(
                WitnessError::CompareFailed,
            ));
        }
        let outcome = self
            .update_unresolved(expected.archive_id(), |local| {
                let current = local
                    .read_current(expected.archive_id())?
                    .ok_or(WitnessError::MissingArchive)?;
                if current != expected {
                    return Err(WitnessError::CompareFailed);
                }
                local.compare_and_advance_root(advance.clone())
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(receipt) => Ok(receipt),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }
    pub(crate) async fn advance_migration_async(
        &self,
        advance: RootAdvance,
        next: crate::archive_v3_witness::MigrationState,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.update(advance.archive_id(), |local| {
            local.advance_migration(advance.clone(), next)
        })
        .await
    }

    /// Maintenance-only unresolved migration CAS. Once the exact candidate is
    /// durable, a lost provider response must remain distinguishable from a
    /// definitive rejection so restart can reconcile only that candidate.
    pub(crate) async fn advance_migration_unresolved_async(
        &self,
        advance: RootAdvance,
        next: crate::archive_v3_witness::MigrationState,
    ) -> std::result::Result<WitnessReceipt, FirestoreWitnessCommitError> {
        let outcome = self
            .update_unresolved(advance.archive_id(), |local| {
                local.advance_migration(advance.clone(), next)
            })
            .await
            .map_err(|error| match error {
                FirestoreUpdateError::Rejected(error) => {
                    FirestoreWitnessCommitError::Rejected(error)
                }
                FirestoreUpdateError::Failed(error) => FirestoreWitnessCommitError::Failed(error),
            })?;
        match outcome {
            FirestoreUpdateOutcome::Committed(receipt) => Ok(receipt),
            FirestoreUpdateOutcome::OutcomeUnknown { .. } => {
                Err(FirestoreWitnessCommitError::OutcomeUnknown)
            }
        }
    }

    /// Commit only the byte-exact maintenance candidate that encrypted control
    /// retained before send. The fresh transaction read is used to authenticate
    /// the exact current bytes and lease at its trusted tick, but it must never
    /// rewrite the candidate's retained server-tick field on retry.
    pub(crate) async fn advance_exact_migration_candidate_unresolved_async(
        &self,
        expected: WitnessRecord,
        candidate: WitnessRecord,
        advance: RootAdvance,
        next: crate::archive_v3_witness::MigrationState,
    ) -> std::result::Result<(), FirestoreWitnessCommitError> {
        if !expected
            .exact_migration_candidate(&advance, next)
            .is_ok_and(|exact| exact == candidate)
        {
            return Err(FirestoreWitnessCommitError::Rejected(
                WitnessError::InvalidTransition,
            ));
        }
        let expected_encoded = expected.encode();
        let candidate_encoded = candidate.encode();
        let document = self.namespace.document(expected.archive_id());
        for attempt in 0..MAX_ABORTED_ATTEMPTS {
            let token = self
                .token()
                .await
                .map_err(FirestoreWitnessCommitError::Failed)?;
            let transaction = self
                .transport
                .begin_read_write(token.as_str(), begin_request_json())
                .await
                .map_err(map_transport)
                .map_err(FirestoreWitnessCommitError::Failed)?;
            let read = self
                .transport
                .batch_get_exact(
                    token.as_str(),
                    &transaction,
                    batch_get_request_json(&document, Some(&transaction)),
                )
                .await
                .map_err(map_transport)
                .map_err(FirestoreWitnessCommitError::Failed)?;
            let current = decode_read(&read, expected.archive_id())
                .map_err(FirestoreWitnessCommitError::Failed)?
                .ok_or(FirestoreWitnessCommitError::Failed(
                    WitnessError::MissingArchive,
                ))?;
            if current == candidate_encoded {
                return Ok(());
            }
            if current != expected_encoded {
                return Err(FirestoreWitnessCommitError::Rejected(
                    WitnessError::CompareFailed,
                ));
            }
            let local =
                InMemoryWitness::from_provider_record_at_tick(Some(current), read.trusted_tick)
                    .map_err(FirestoreWitnessCommitError::Failed)?;
            let receipt = local
                .advance_migration(advance.clone(), next)
                .map_err(FirestoreWitnessCommitError::Rejected)?;
            if !receipt
                .record()
                .matches_retained_maintenance_candidate(&candidate)
            {
                return Err(FirestoreWitnessCommitError::Rejected(
                    WitnessError::InvalidTransition,
                ));
            }
            let commit = commit_request_json(
                &document,
                &transaction,
                &candidate_encoded,
                read.update_time.as_ref().map(FirestoreTimestamp::as_str),
            );
            match self
                .transport
                .commit_full_record(token.as_str(), &transaction, commit)
                .await
            {
                Ok(()) => return Ok(()),
                Err(FirestoreWitnessTransportError::Aborted)
                    if attempt + 1 < MAX_ABORTED_ATTEMPTS =>
                {
                    continue
                }
                Err(FirestoreWitnessTransportError::OutcomeUnknown)
                | Err(FirestoreWitnessTransportError::PreconditionFailed)
                | Err(FirestoreWitnessTransportError::Aborted) => {
                    return Err(FirestoreWitnessCommitError::OutcomeUnknown)
                }
                Err(error) => {
                    return Err(FirestoreWitnessCommitError::Failed(map_transport(error)))
                }
            }
        }
        Err(FirestoreWitnessCommitError::Failed(
            WitnessError::Unavailable,
        ))
    }
    pub(crate) async fn rotate_key_registry_async(
        &self,
        advance: RootAdvance,
        next: crate::archive_v3_witness::KeyRegistryReference,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.update(advance.archive_id(), |local| {
            local.rotate_key_registry(advance.clone(), next)
        })
        .await
    }
    pub(crate) async fn cut_over_database_epoch_async(
        &self,
        advance: RootAdvance,
        next: DatabaseEpoch,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.update(advance.archive_id(), |local| {
            local.cut_over_database_epoch(advance.clone(), next)
        })
        .await
    }
    #[cfg(test)]
    pub(crate) async fn tombstone_async(
        &self,
        advance: RootAdvance,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> std::result::Result<TombstoneReceipt, WitnessError> {
        self.update(advance.archive_id(), |local| {
            local.tombstone(advance.clone(), credential, proof)
        })
        .await
    }
    pub(crate) async fn tombstone_current_async(
        &self,
        advance: crate::archive_v3_witness::TombstoneAdvance,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> std::result::Result<TombstoneReceipt, WitnessError> {
        self.update(advance.archive_id(), |local| {
            local.tombstone_current(advance.clone(), credential, proof)
        })
        .await
    }
    pub(crate) async fn resume_deletion_async(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> std::result::Result<DeletionRecovery, WitnessError> {
        self.update(archive_id, |local| {
            local.resume_deletion(archive_id, credential)
        })
        .await
    }
    pub(crate) async fn verify_physical_completion_async(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> std::result::Result<DeletionRecovery, WitnessError> {
        self.update(archive_id, |local| {
            local.verify_physical_completion(archive_id, credential, proof)
        })
        .await
    }
    pub(crate) async fn advance_deletion_async(
        &self,
        advance: DeletionAdvance,
        next: DeletionState,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.update(advance.archive_id(), |local| {
            local.advance_deletion(advance.clone(), next, credential, proof)
        })
        .await
    }
    fn blocking<T>(
        &self,
        future: impl std::future::Future<Output = std::result::Result<T, WitnessError>>,
    ) -> std::result::Result<T, WitnessError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(WitnessError::Unavailable);
        }
        self.runtime
            .lock()
            .map_err(|_| WitnessError::Synchronization)?
            .as_mut()
            .ok_or(WitnessError::Unavailable)?
            .block_on(future)
    }
}
impl Drop for FirestoreWitness {
    fn drop(&mut self) {
        // Async unit tests and future async callers may release this inactive
        // compatibility wrapper on a Tokio worker.  Explicit background
        // shutdown avoids Tokio's blocking-on-drop panic without changing the
        // async adapter surface.
        if let Ok(slot) = self.runtime.get_mut() {
            if let Some(runtime) = slot.take() {
                runtime.shutdown_background();
            }
        }
    }
}
impl fmt::Debug for FirestoreWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreWitness(<inactive>)")
    }
}

#[async_trait::async_trait]
impl ExactLegacyWitness for FirestoreWitness {
    async fn read_exact_legacy(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<WitnessRecord, WitnessError> {
        self.read_current_async(archive_id)
            .await?
            .ok_or(WitnessError::MissingArchive)
    }
}

#[async_trait::async_trait]
impl ExactPreWitnessReader for FirestoreWitness {
    async fn read_exact_witness(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<ExactPreWitnessObservation, PreWitnessDispositionError> {
        let token = self
            .token()
            .await
            .map_err(|_| PreWitnessDispositionError::WitnessRead)?;
        let document = self.namespace.document(archive_id);
        let read = match self
            .transport
            .read_exact(token.as_str(), batch_get_request_json(&document, None))
            .await
        {
            Ok(read) => read,
            Err(FirestoreWitnessTransportError::DefinitelyPresentInvalid) => {
                return Ok(ExactPreWitnessObservation::DefinitelyPresentInvalid)
            }
            Err(_) => return Err(PreWitnessDispositionError::WitnessRead),
        };
        match (&read.record, &read.update_time) {
            (None, None) => decode_read(&read, archive_id)
                .map(|_| ExactPreWitnessObservation::Absent)
                .map_err(|_| PreWitnessDispositionError::Corrupt),
            (Some(_), Some(_)) => match decode_read(&read, archive_id) {
                Ok(Some(bytes)) => match WitnessRecord::decode(&bytes) {
                    Ok(record) => Ok(ExactPreWitnessObservation::Present(Box::new(record))),
                    Err(_) => Ok(ExactPreWitnessObservation::DefinitelyPresentInvalid),
                },
                Ok(None) | Err(_) => Ok(ExactPreWitnessObservation::DefinitelyPresentInvalid),
            },
            // Private transport implementations can only construct a read
            // through strict parsing; nevertheless, fail closed as definite
            // presence if either found-side field survived alone.
            (Some(_), None) | (None, Some(_)) => {
                Ok(ExactPreWitnessObservation::DefinitelyPresentInvalid)
            }
        }
    }
}

impl Witness for FirestoreWitness {
    fn read_current(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<Option<WitnessRecord>, WitnessError> {
        self.blocking(self.read_current_async(archive_id))
    }
    fn recovery_root(
        &self,
        archive_id: ArchiveId,
    ) -> std::result::Result<RecoveryRoot, WitnessError> {
        self.blocking(self.recovery_root_async(archive_id))
    }
    fn acquire_lease(
        &self,
        archive_id: ArchiveId,
        database_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
        owner: ObjectId,
        duration_ticks: u64,
    ) -> std::result::Result<WitnessLease, WitnessError> {
        self.blocking(self.acquire_lease_async(
            archive_id,
            database_epoch,
            key_epoch,
            owner,
            duration_ticks,
        ))
    }
    fn renew_lease(
        &self,
        lease: WitnessLease,
        duration_ticks: u64,
    ) -> std::result::Result<WitnessLease, WitnessError> {
        self.blocking(self.renew_lease_async(lease, duration_ticks))
    }
    fn revoke_lease(&self, lease: WitnessLease) -> std::result::Result<(), WitnessError> {
        self.blocking(self.revoke_lease_async(lease))
    }
    fn compare_and_advance_root(
        &self,
        advance: RootAdvance,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.blocking(self.compare_and_advance_root_async(advance))
    }
    fn advance_migration(
        &self,
        advance: RootAdvance,
        next: crate::archive_v3_witness::MigrationState,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.blocking(self.advance_migration_async(advance, next))
    }
    fn rotate_key_registry(
        &self,
        advance: RootAdvance,
        next: crate::archive_v3_witness::KeyRegistryReference,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.blocking(self.rotate_key_registry_async(advance, next))
    }
    fn cut_over_database_epoch(
        &self,
        advance: RootAdvance,
        next: DatabaseEpoch,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.blocking(self.cut_over_database_epoch_async(advance, next))
    }
    #[cfg(test)]
    fn tombstone(
        &self,
        advance: RootAdvance,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> std::result::Result<TombstoneReceipt, WitnessError> {
        self.blocking(self.tombstone_async(advance, credential, proof))
    }
    fn tombstone_current(
        &self,
        advance: crate::archive_v3_witness::TombstoneAdvance,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> std::result::Result<TombstoneReceipt, WitnessError> {
        self.blocking(self.tombstone_current_async(advance, credential, proof))
    }
    fn resume_deletion(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
    ) -> std::result::Result<DeletionRecovery, WitnessError> {
        self.blocking(self.resume_deletion_async(archive_id, credential))
    }
    fn verify_physical_completion(
        &self,
        archive_id: ArchiveId,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> std::result::Result<DeletionRecovery, WitnessError> {
        self.blocking(self.verify_physical_completion_async(archive_id, credential, proof))
    }
    fn advance_deletion(
        &self,
        advance: DeletionAdvance,
        next: DeletionState,
        credential: &DeletionWorkerCredential,
        proof: &DeletionStageProof,
    ) -> std::result::Result<WitnessReceipt, WitnessError> {
        self.blocking(self.advance_deletion_async(advance, next, credential, proof))
    }
}
