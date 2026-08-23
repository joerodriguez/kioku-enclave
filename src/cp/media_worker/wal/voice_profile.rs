//! Selected voice-profile assignment and deterministic representative repair.
//!
//! This is a provider-free ADR-0022 A-domain.  The owner observes exactly one
//! bounded item through the routed archive read, prepares one fixed logical
//! mutation, and submits it without giving the WAL executor a clock, random-id
//! source, Store handle, model, launcher, or retry authority.  Pending samples
//! are matched against the complete bounded competing profile set.  Every row
//! that can affect the decision is committed; allocator IDs and mutation time
//! are caller-fixed.  Historical unversioned profiles and assignments are
//! repaired before new assignments, so a current sample never depends on an
//! implicit schema backfill.

use rusqlite::{params, types::ValueRef, Connection, OptionalExtension, Transaction};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    archive_v3_wal_idempotency::{
        stable_operation_source, DomainLedgerBounds, LogicalMutationResult,
        PreparedLogicalMutation, WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan,
        WalLogicalOperationId, WalOperationKind, WalReplayResult,
    },
    cp::{isotime, voice_memory, voice_quality},
};

type Result<T> = std::result::Result<T, WalIdempotencyError>;

const REQUEST_V1: u16 = 1;
const PROFILE_BACKFILL_SUBTYPE: &[u8] = b"adr-0022-voice-profile-backfill-v1";
const ASSIGNMENT_BACKFILL_SUBTYPE: &[u8] = b"adr-0022-voice-assignment-backfill-v1";
const SAMPLE_ASSIGNMENT_SUBTYPE: &[u8] = b"adr-0022-voice-sample-assignment-v1";
const PROFILE_RECONCILE_SUBTYPE: &[u8] = b"adr-0022-voice-profile-reconcile-v1";
const PROPOSAL_REFUSAL_SUBTYPE: &[u8] = b"adr-0022-voice-lineage-action-refusal-v1";
const EPISODE_STATUS_SUBTYPE: &[u8] = b"adr-0022-voice-episode-status-v1";
const PERSON_IDENTITY_SUBTYPE: &[u8] = b"adr-0022-person-self-identification-v1";
const MAX_PROFILES: usize = 32;
const MAX_PROFILE_SAMPLES: usize = 100;
const MAX_OBSERVATION_SOURCES: i64 = 128;
const MAX_OBSERVATION_SAMPLES: i64 = 128;
const MAX_EMBEDDING_BYTES: usize = 4 * 256;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_TEXT_BYTES: usize = 8_192;
const MAX_TRANSCRIPT_BYTES: usize = 4 * crate::cp::media::MAX_TEXT_LEN;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_voice_profile_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_voice_profile_operations";
const STATE_TABLE: &str = "archive_v3_wal_voice_profile_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllocatorPins {
    profiles: i64,
    revisions: i64,
    assignments: i64,
    representatives: i64,
}

impl AllocatorPins {
    fn next_profile(self) -> Option<i64> {
        self.profiles.checked_add(1)
    }
    fn next_revision(self) -> Option<i64> {
        self.revisions.checked_add(1)
    }
    fn next_assignment(self) -> Option<i64> {
        self.assignments.checked_add(1)
    }
    fn next_representative(self) -> Option<i64> {
        self.representatives.checked_add(1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProfileBackfillEvidence {
    profile_id: i64,
    snapshot: [u8; 32],
    pins: AllocatorPins,
    disposition: BackfillDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackfillDisposition {
    Insert { revision_id: i64 },
    Quarantine,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AssignmentBackfillEvidence {
    sample_id: i64,
    profile_id: i64,
    snapshot: [u8; 32],
    pins: AllocatorPins,
    assignment_id: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SampleAssignmentEvidence {
    sample_id: i64,
    snapshot: [u8; 32],
    pins: AllocatorPins,
    decision: AssignmentDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProfileReconcileEvidence {
    profile_id: i64,
    snapshot: [u8; 32],
    pins: AllocatorPins,
    decision: ReconcileDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ReconcileDecision {
    Update(ProfileUpdate),
    Quarantine {
        revision_id: Option<i64>,
        predecessor_revision_id: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProposalRefusalEvidence {
    proposal_id: i64,
    snapshot: [u8; 32],
    predecessor_state: String,
    target_state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EpisodeStatusEvidence {
    episode_id: i64,
    snapshot: [u8; 32],
    predecessor_status: String,
    target_status: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PersonAllocatorPins {
    people: i64,
    name_claims: i64,
    facts: i64,
    bindings: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FactWrite {
    id: i64,
    predicate: String,
    value: String,
    literal_evidence: String,
    supersedes_id: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PersonIdentityDecision {
    Reject,
    Bind {
        person_id: i64,
        create_person: bool,
        name_claim_id: i64,
        binding_id: i64,
        supersedes_binding_id: Option<i64>,
        binding_evidence_count: i64,
        profile_id: i64,
        active_revision_id: i64,
        observation_id: i64,
        cluster_id: i64,
        normalized_name: String,
        facts: Vec<FactWrite>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PersonIdentityEvidence {
    evidence_id: i64,
    snapshot: [u8; 32],
    pins: PersonAllocatorPins,
    claimed_name: String,
    evidence_json: String,
    confidence_millionths: u32,
    source_event_id: String,
    observed_at: String,
    decision: PersonIdentityDecision,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentityEnvelope {
    schema_version: u8,
    turn_id: String,
    literal_evidence: String,
    facts: Vec<StoredIdentityFact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentityFact {
    predicate: String,
    value: String,
    evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AssignmentDecision {
    Reject {
        similarity: Option<u32>,
        margin: Option<u32>,
    },
    Existing {
        profile_id: i64,
        assignment_id: i64,
        accepted: bool,
        outlier: bool,
        similarity: u32,
        margin: u32,
        update: Option<ProfileUpdate>,
    },
    New {
        profile_id: i64,
        assignment_id: i64,
        revision_id: i64,
        representative_id: i64,
        person_id: Option<i64>,
        centroid: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProfileUpdate {
    centroid: Vec<u8>,
    sample_count: i64,
    medoid_sample_id: i64,
    status: String,
    revision_id: i64,
    predecessor_revision_id: i64,
    representative_id: i64,
    representative_exists: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum WorkEvidence {
    ProfileBackfill(ProfileBackfillEvidence),
    AssignmentBackfill(AssignmentBackfillEvidence),
    SampleAssignment(SampleAssignmentEvidence),
    ProfileReconcile(ProfileReconcileEvidence),
    PersonIdentity(PersonIdentityEvidence),
    ProposalRefusal(ProposalRefusalEvidence),
    EpisodeStatus(EpisodeStatusEvidence),
}

impl WorkEvidence {
    fn subtype(&self) -> &'static [u8] {
        match self {
            Self::ProfileBackfill(_) => PROFILE_BACKFILL_SUBTYPE,
            Self::AssignmentBackfill(_) => ASSIGNMENT_BACKFILL_SUBTYPE,
            Self::SampleAssignment(_) => SAMPLE_ASSIGNMENT_SUBTYPE,
            Self::ProfileReconcile(_) => PROFILE_RECONCILE_SUBTYPE,
            Self::PersonIdentity(_) => PERSON_IDENTITY_SUBTYPE,
            Self::ProposalRefusal(_) => PROPOSAL_REFUSAL_SUBTYPE,
            Self::EpisodeStatus(_) => EPISODE_STATUS_SUBTYPE,
        }
    }

    fn stable_id(&self) -> i64 {
        match self {
            Self::ProfileBackfill(value) => value.profile_id,
            Self::AssignmentBackfill(value) => value.sample_id,
            Self::SampleAssignment(value) => value.sample_id,
            Self::ProfileReconcile(value) => value.profile_id,
            Self::PersonIdentity(value) => value.evidence_id,
            Self::ProposalRefusal(value) => value.proposal_id,
            Self::EpisodeStatus(value) => value.episode_id,
        }
    }

    fn snapshot(&self) -> [u8; 32] {
        match self {
            Self::ProfileBackfill(value) => value.snapshot,
            Self::AssignmentBackfill(value) => value.snapshot,
            Self::SampleAssignment(value) => value.snapshot,
            Self::ProfileReconcile(value) => value.snapshot,
            Self::PersonIdentity(value) => value.snapshot,
            Self::ProposalRefusal(value) => value.snapshot,
            Self::EpisodeStatus(value) => value.snapshot,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) enum VoiceProfileScan {
    Idle,
    ClockDeferred,
    Work(Box<VoiceProfileEvidence>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct VoiceProfileEvidence {
    account_id: String,
    observed_at: String,
    work: WorkEvidence,
}

pub(crate) struct VoiceProfilePlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    committed_at: String,
    evidence: VoiceProfileEvidence,
}

impl std::fmt::Debug for VoiceProfilePlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VoiceProfilePlan(<opaque>)")
    }
}

impl VoiceProfilePlan {
    pub(in crate::cp::media_worker) fn new(
        account_id: String,
        evidence: VoiceProfileEvidence,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        validate_timestamp(&committed_at)?;
        validate_timestamp(&evidence.observed_at)?;
        if account_id != evidence.account_id || committed_at < evidence.observed_at {
            return Err(WalIdempotencyError::Precondition);
        }
        validate_evidence(&evidence)?;
        let id = evidence.work.stable_id().to_be_bytes();
        let snapshot = evidence.work.snapshot();
        let source = stable_operation_source(
            evidence.work.subtype(),
            &[account_id.as_bytes(), &id, &snapshot],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::VoiceProfile, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            committed_at,
            evidence,
        })
    }
}

pub(crate) struct VoiceProfileLedger;

impl WalLogicalDomainPlan for VoiceProfilePlan {
    type Ledger = VoiceProfileLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::VoiceProfile
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut output = Zeroizing::new(Vec::with_capacity(4 * 1024));
        output.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_string(&mut output, &self.account_id)?;
        encode_string(&mut output, &self.committed_at)?;
        encode_string(&mut output, &self.evidence.observed_at)?;
        encode_work(&mut output, &self.evidence.work)?;
        Ok(output)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        let fresh = reobserve(transaction, &self.evidence)?;
        if fresh != self.evidence {
            return Err(WalIdempotencyError::Precondition);
        }
        match &self.evidence.work {
            WorkEvidence::ProfileBackfill(value) => {
                apply_profile_backfill(transaction, value, &self.committed_at)?
            }
            WorkEvidence::AssignmentBackfill(value) => {
                apply_assignment_backfill(transaction, value, &self.committed_at)?
            }
            WorkEvidence::SampleAssignment(value) => {
                apply_sample_assignment(transaction, value, &self.committed_at)?
            }
            WorkEvidence::ProfileReconcile(value) => {
                apply_profile_reconcile(transaction, value, &self.committed_at)?
            }
            WorkEvidence::PersonIdentity(value) => {
                apply_person_identity(transaction, value, &self.committed_at)?
            }
            WorkEvidence::ProposalRefusal(value) => {
                apply_proposal_refusal(transaction, value, &self.committed_at)?
            }
            WorkEvidence::EpisodeStatus(value) => {
                apply_episode_status(transaction, value, &self.committed_at)?
            }
        }
        Ok(WalReplayResult::unit())
    }

    fn validate_replay(&self, result: &WalReplayResult) -> Result<()> {
        match result {
            WalReplayResult::UnitApplied => Ok(()),
            WalReplayResult::CanonicalResponse(_) => Err(WalIdempotencyError::ResultUnsupported),
        }
    }

    fn decode_output(&self, result: &WalReplayResult) -> Result<Self::Output> {
        self.validate_replay(result)
    }
}

pub(in crate::cp::media_worker) fn observe_next(
    connection: &Connection,
    account_id: &str,
    observed_at: &str,
) -> Result<VoiceProfileScan> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    validate_timestamp(observed_at)?;
    ensure_source_schema(connection)?;
    let pins = read_allocator_pins(connection)?;

    if let Some(profile_id) = connection
        .query_row(
            "SELECT profile.id FROM voice_profiles profile
             WHERE profile.status<>'quarantined' AND NOT EXISTS (
               SELECT 1 FROM voice_profile_revisions revision
               WHERE revision.profile_id=profile.id)
             ORDER BY profile.id LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
    {
        return load_profile_backfill(connection, account_id, observed_at, profile_id, pins);
    }

    if let Some((sample_id, profile_id)) = connection
        .query_row(
            "SELECT sample.id,sample.voice_profile_id FROM voice_samples sample
             WHERE sample.voice_profile_id IS NOT NULL AND sample.accepted<>-1
               AND NOT EXISTS (
                 SELECT 1 FROM voice_sample_profile_assignments assignment
                 WHERE assignment.sample_id=sample.id)
             ORDER BY sample.id LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
    {
        return load_assignment_backfill(
            connection,
            account_id,
            observed_at,
            sample_id,
            profile_id,
            pins,
        );
    }

    // Repair or quarantine historical profile topology before a pending
    // sample is allowed to observe it as a matching candidate.
    if let Some(profile_id) = next_reconcile_profile(connection)? {
        return load_profile_reconcile(connection, account_id, observed_at, profile_id, pins);
    }

    let sample_id = connection
        .query_row(
            "SELECT id FROM voice_samples WHERE accepted=-1 ORDER BY id LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(sample_id) = sample_id else {
        if let Some(evidence_id) = next_person_identity(connection)? {
            return load_person_identity(connection, account_id, observed_at, evidence_id);
        }
        if let Some(proposal_id) = connection
            .query_row(
                "SELECT id FROM voice_profile_proposals
                 WHERE state IN ('approved','revert_requested') ORDER BY id LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
        {
            return load_proposal_refusal(connection, account_id, observed_at, proposal_id);
        }
        if let Some(episode_id) = next_episode_status(connection)? {
            return load_episode_status(connection, account_id, observed_at, episode_id);
        }
        return Ok(VoiceProfileScan::Idle);
    };
    load_sample_assignment(connection, account_id, observed_at, sample_id, pins)
}

fn reobserve(
    connection: &Connection,
    evidence: &VoiceProfileEvidence,
) -> Result<VoiceProfileEvidence> {
    let scan = match &evidence.work {
        WorkEvidence::ProfileBackfill(value) => load_profile_backfill(
            connection,
            &evidence.account_id,
            &evidence.observed_at,
            value.profile_id,
            value.pins,
        )?,
        WorkEvidence::AssignmentBackfill(value) => load_assignment_backfill(
            connection,
            &evidence.account_id,
            &evidence.observed_at,
            value.sample_id,
            value.profile_id,
            value.pins,
        )?,
        WorkEvidence::SampleAssignment(value) => load_sample_assignment(
            connection,
            &evidence.account_id,
            &evidence.observed_at,
            value.sample_id,
            value.pins,
        )?,
        WorkEvidence::ProfileReconcile(value) => load_profile_reconcile(
            connection,
            &evidence.account_id,
            &evidence.observed_at,
            value.profile_id,
            value.pins,
        )?,
        WorkEvidence::PersonIdentity(value) => load_person_identity(
            connection,
            &evidence.account_id,
            &evidence.observed_at,
            value.evidence_id,
        )?,
        WorkEvidence::ProposalRefusal(value) => load_proposal_refusal(
            connection,
            &evidence.account_id,
            &evidence.observed_at,
            value.proposal_id,
        )?,
        WorkEvidence::EpisodeStatus(value) => load_episode_status(
            connection,
            &evidence.account_id,
            &evidence.observed_at,
            value.episode_id,
        )?,
    };
    match scan {
        VoiceProfileScan::Work(value) => Ok(*value),
        VoiceProfileScan::Idle | VoiceProfileScan::ClockDeferred => {
            Err(WalIdempotencyError::Precondition)
        }
    }
}

fn load_profile_backfill(
    connection: &Connection,
    account_id: &str,
    observed_at: &str,
    profile_id: i64,
    pins: AllocatorPins,
) -> Result<VoiceProfileScan> {
    let timestamps = connection
        .query_row(
            "SELECT created_at,updated_at FROM voice_profiles WHERE id=?1",
            [profile_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some((created_at, updated_at)) = timestamps else {
        return Ok(VoiceProfileScan::Idle);
    };
    if timestamp_after(&created_at, observed_at) || timestamp_after(&updated_at, observed_at) {
        return Ok(VoiceProfileScan::ClockDeferred);
    }
    let snapshot = profile_backfill_snapshot(connection, profile_id)?;
    let valid = valid_timestamp(&created_at)
        && valid_timestamp(&updated_at)
        && pins.next_revision().is_some();
    let disposition = if valid {
        BackfillDisposition::Insert {
            revision_id: pins.next_revision().ok_or(WalIdempotencyError::Limit)?,
        }
    } else {
        BackfillDisposition::Quarantine
    };
    Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
        account_id: account_id.to_owned(),
        observed_at: observed_at.to_owned(),
        work: WorkEvidence::ProfileBackfill(ProfileBackfillEvidence {
            profile_id,
            snapshot,
            pins,
            disposition,
        }),
    })))
}

fn load_assignment_backfill(
    connection: &Connection,
    account_id: &str,
    observed_at: &str,
    sample_id: i64,
    profile_id: i64,
    pins: AllocatorPins,
) -> Result<VoiceProfileScan> {
    let created_at = connection
        .query_row(
            "SELECT created_at FROM voice_samples WHERE id=?1 AND voice_profile_id=?2",
            params![sample_id, profile_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(created_at) = created_at else {
        return Ok(VoiceProfileScan::Idle);
    };
    if timestamp_after(&created_at, observed_at) {
        return Ok(VoiceProfileScan::ClockDeferred);
    }
    let snapshot = assignment_backfill_snapshot(connection, sample_id, profile_id)?;
    let target_exists = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM voice_profiles WHERE id=?1 AND status<>'quarantined')",
            [profile_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let assignment_id = (valid_timestamp(&created_at) && target_exists)
        .then(|| pins.next_assignment())
        .flatten();
    Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
        account_id: account_id.to_owned(),
        observed_at: observed_at.to_owned(),
        work: WorkEvidence::AssignmentBackfill(AssignmentBackfillEvidence {
            sample_id,
            profile_id,
            snapshot,
            pins,
            assignment_id,
        }),
    })))
}

#[derive(Clone)]
struct PendingSample {
    id: i64,
    observation_id: i64,
    person_id: Option<i64>,
    embedding_space: String,
    channel_domain: String,
    embedding: Vec<u8>,
    scorer_version: i64,
    eligibility: String,
    created_at: String,
    embedding_job_id: Option<i64>,
    embedding_job_state: Option<String>,
}

#[derive(Clone)]
struct CandidateProfile {
    id: i64,
    person_id: Option<i64>,
    centroid: Vec<u8>,
    active_revision_id: Option<i64>,
    active_revision_created_at: Option<String>,
    active_revision_count: i64,
    created_at: String,
    updated_at: String,
}

fn load_sample_assignment(
    connection: &Connection,
    account_id: &str,
    observed_at: &str,
    sample_id: i64,
    pins: AllocatorPins,
) -> Result<VoiceProfileScan> {
    let sample = connection
        .query_row(
            "SELECT sample.id,sample.speaker_observation_id,observation.person_id,
                    sample.embedding_space,sample.channel_domain,sample.embedding,
                    sample.scorer_version,sample.eligibility,sample.created_at,
                    sample.embedding_job_id,job.state
             FROM voice_samples sample
             JOIN speaker_observations observation ON observation.id=sample.speaker_observation_id
             LEFT JOIN voice_embedding_jobs job ON job.id=sample.embedding_job_id
             WHERE sample.id=?1 AND sample.accepted=-1",
            [sample_id],
            |row| {
                Ok(PendingSample {
                    id: row.get(0)?,
                    observation_id: row.get(1)?,
                    person_id: row.get(2)?,
                    embedding_space: row.get(3)?,
                    channel_domain: row.get(4)?,
                    embedding: row.get(5)?,
                    scorer_version: row.get(6)?,
                    eligibility: row.get(7)?,
                    created_at: row.get(8)?,
                    embedding_job_id: row.get(9)?,
                    embedding_job_state: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some(sample) = sample else {
        return Ok(VoiceProfileScan::Idle);
    };
    if timestamp_after(&sample.created_at, observed_at) {
        return Ok(VoiceProfileScan::ClockDeferred);
    }
    let decision = match derive_assignment(connection, &sample, pins, observed_at) {
        Ok(decision) => decision,
        Err(WalIdempotencyError::Precondition) => return Ok(VoiceProfileScan::ClockDeferred),
        Err(error) => return Err(error),
    };
    let snapshot = sample_assignment_snapshot(connection, &sample, &decision)?;
    Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
        account_id: account_id.to_owned(),
        observed_at: observed_at.to_owned(),
        work: WorkEvidence::SampleAssignment(SampleAssignmentEvidence {
            sample_id,
            snapshot,
            pins,
            decision,
        }),
    })))
}

fn derive_assignment(
    connection: &Connection,
    sample: &PendingSample,
    pins: AllocatorPins,
    observed_at: &str,
) -> Result<AssignmentDecision> {
    if !valid_timestamp(&sample.created_at)
        || sample.embedding_space != voice_memory::EMBEDDING_SPACE
        || sample.scorer_version != voice_quality::SCORER_VERSION
        || !matches!(sample.eligibility.as_str(), "enroll" | "match_only")
        || sample.embedding_job_id.is_none()
        || sample.embedding_job_state.as_deref() != Some("ready")
    {
        return Ok(AssignmentDecision::Reject {
            similarity: None,
            margin: None,
        });
    }
    if let Some(person_id) = sample.person_id {
        let person_exists = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM people WHERE id=?1)",
                [person_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if !person_exists {
            return Ok(AssignmentDecision::Reject {
                similarity: None,
                margin: None,
            });
        }
    }
    let candidate = match decode_embedding(&sample.embedding) {
        Some(value) => value,
        None => {
            return Ok(AssignmentDecision::Reject {
                similarity: None,
                margin: None,
            })
        }
    };
    let mut statement = connection
        .prepare(
            "SELECT profile.id,profile.person_id,profile.centroid,
                    (SELECT revision.id FROM voice_profile_revisions revision
                     WHERE revision.profile_id=profile.id AND revision.active=1),
                    (SELECT revision.created_at FROM voice_profile_revisions revision
                     WHERE revision.profile_id=profile.id AND revision.active=1),
                    (SELECT COUNT(*) FROM (
                       SELECT 1 FROM voice_profile_revisions revision
                       WHERE revision.profile_id=profile.id AND revision.active=1
                         AND revision.status NOT IN ('quarantined','superseded','split')
                       LIMIT 2)),
                    profile.created_at,profile.updated_at
             FROM voice_profiles profile
             WHERE profile.embedding_space=?1 AND profile.channel_domain=?2
               AND profile.scorer_version=?3 AND profile.status<>'quarantined'
               AND NOT EXISTS (
                 SELECT 1 FROM voice_profile_revisions terminal
                 WHERE terminal.profile_id=profile.id AND terminal.active=1
                   AND terminal.status IN ('quarantined','superseded','split'))
             ORDER BY profile.id LIMIT ?4",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let profiles = statement
        .query_map(
            params![
                sample.embedding_space,
                sample.channel_domain,
                sample.scorer_version,
                i64::try_from(MAX_PROFILES + 1).map_err(|_| WalIdempotencyError::Limit)?
            ],
            |row| {
                Ok(CandidateProfile {
                    id: row.get(0)?,
                    person_id: row.get(1)?,
                    centroid: row.get(2)?,
                    active_revision_id: row.get(3)?,
                    active_revision_created_at: row.get(4)?,
                    active_revision_count: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if profiles.len() > MAX_PROFILES {
        return Ok(AssignmentDecision::Reject {
            similarity: None,
            margin: None,
        });
    }
    if profiles.iter().any(|profile| {
        !valid_timestamp(&profile.created_at)
            || !valid_timestamp(&profile.updated_at)
            || profile
                .active_revision_created_at
                .as_deref()
                .is_some_and(|value| !valid_timestamp(value))
            || profile.active_revision_count != 1
    }) {
        return Ok(AssignmentDecision::Reject {
            similarity: None,
            margin: None,
        });
    }
    if profiles.iter().any(|profile| {
        timestamp_after(&profile.created_at, observed_at)
            || timestamp_after(&profile.updated_at, observed_at)
    }) {
        return Err(WalIdempotencyError::Precondition);
    }
    let mut scored = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let Some(centroid) = decode_embedding(&profile.centroid) else {
            return Ok(AssignmentDecision::Reject {
                similarity: None,
                margin: None,
            });
        };
        let score = voice_quality::cosine(&candidate, &centroid);
        if !score.is_finite() {
            return Ok(AssignmentDecision::Reject {
                similarity: None,
                margin: None,
            });
        }
        scored.push((profile, score));
    }
    scored.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.id.cmp(&right.0.id))
    });
    let best = scored.first();
    let second = scored.get(1).map_or(-1.0, |item| item.1);
    let best_score = best.map(|item| item.1);
    let margin = best_score.map(|score| score - second);
    let identity_compatible = best.is_none_or(|(profile, _)| {
        sample
            .person_id
            .is_none_or(|person_id| profile.person_id.is_none_or(|value| value == person_id))
    });
    let clear_match = best.is_some_and(|(_, score)| {
        identity_compatible
            && *score >= voice_memory::MATCH_THRESHOLD
            && *score - second >= voice_memory::MIN_DECISION_MARGIN
    });
    if clear_match {
        let Some((profile, score)) = best else {
            return Err(WalIdempotencyError::Precondition);
        };
        if profile
            .active_revision_created_at
            .as_deref()
            .is_some_and(|value| timestamp_after(value, observed_at))
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let representative_timestamps = connection
            .query_row(
                "SELECT created_at,updated_at FROM voice_profile_representatives
                 WHERE profile_id=?1 AND channel_domain=?2",
                params![profile.id, sample.channel_domain],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if representative_timestamps.is_some_and(|(created_at, updated_at)| {
            timestamp_after(&created_at, observed_at) || timestamp_after(&updated_at, observed_at)
        }) {
            return Err(WalIdempotencyError::Precondition);
        }
        let Some(assignment_id) = pins.next_assignment() else {
            return Ok(AssignmentDecision::Reject {
                similarity: best_score.map(f32::to_bits),
                margin: margin.map(f32::to_bits),
            });
        };
        if sample.eligibility == "match_only" {
            return Ok(AssignmentDecision::Existing {
                profile_id: profile.id,
                assignment_id,
                accepted: true,
                outlier: false,
                similarity: score.to_bits(),
                margin: (*score - second).to_bits(),
                update: None,
            });
        }
        let Some(predecessor_revision_id) = profile.active_revision_id else {
            return Ok(AssignmentDecision::Reject {
                similarity: Some(score.to_bits()),
                margin: Some((*score - second).to_bits()),
            });
        };
        let rows =
            match load_profile_sample_embeddings(connection, profile.id, &sample.channel_domain) {
                Ok(rows) => rows,
                Err(WalIdempotencyError::Malformed | WalIdempotencyError::Limit) => {
                    return Ok(AssignmentDecision::Reject {
                        similarity: Some(score.to_bits()),
                        margin: Some((*score - second).to_bits()),
                    })
                }
                Err(error) => return Err(error),
            };
        if rows.len() > MAX_PROFILE_SAMPLES {
            return Ok(AssignmentDecision::Reject {
                similarity: Some(score.to_bits()),
                margin: Some((*score - second).to_bits()),
            });
        }
        let existing = rows
            .iter()
            .map(|(_, embedding)| embedding.clone())
            .collect::<Vec<_>>();
        let outlier = match voice_quality::is_profile_outlier(&existing, &candidate) {
            Ok(value) => value,
            Err(_) => {
                return Ok(AssignmentDecision::Reject {
                    similarity: Some(score.to_bits()),
                    margin: Some((*score - second).to_bits()),
                })
            }
        };
        if outlier {
            return Ok(AssignmentDecision::Existing {
                profile_id: profile.id,
                assignment_id,
                accepted: false,
                outlier: true,
                similarity: score.to_bits(),
                margin: (*score - second).to_bits(),
                update: None,
            });
        }
        let Some(revision_id) = pins.next_revision() else {
            return Ok(AssignmentDecision::Reject {
                similarity: Some(score.to_bits()),
                margin: Some((*score - second).to_bits()),
            });
        };
        let mut ids = rows.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let mut vectors = existing;
        ids.push(sample.id);
        vectors.push(candidate.clone());
        let representative = match voice_quality::robust_representative(&vectors) {
            Ok(value) => value,
            Err(_) => {
                return Ok(AssignmentDecision::Reject {
                    similarity: Some(score.to_bits()),
                    margin: Some((*score - second).to_bits()),
                })
            }
        };
        let representative_row = connection
            .query_row(
                "SELECT id FROM voice_profile_representatives
                 WHERE profile_id=?1 AND channel_domain=?2",
                params![profile.id, sample.channel_domain],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let (representative_id, representative_exists) = match representative_row {
            Some(id) if id > 0 => (id, true),
            Some(_) => {
                return Ok(AssignmentDecision::Reject {
                    similarity: Some(score.to_bits()),
                    margin: Some((*score - second).to_bits()),
                })
            }
            None => match pins.next_representative() {
                Some(id) => (id, false),
                None => {
                    return Ok(AssignmentDecision::Reject {
                        similarity: Some(score.to_bits()),
                        margin: Some((*score - second).to_bits()),
                    })
                }
            },
        };
        let effective = i64::try_from(vectors.len() - representative.excluded_indices.len())
            .map_err(|_| WalIdempotencyError::Limit)?;
        let medoid_sample_id = ids[representative.medoid_index];
        return Ok(AssignmentDecision::Existing {
            profile_id: profile.id,
            assignment_id,
            accepted: true,
            outlier: false,
            similarity: score.to_bits(),
            margin: (*score - second).to_bits(),
            update: Some(ProfileUpdate {
                centroid: encode_embedding(&representative.centroid),
                sample_count: effective,
                medoid_sample_id,
                status: if effective >= 3 {
                    "stable"
                } else {
                    "tentative"
                }
                .into(),
                revision_id,
                predecessor_revision_id,
                representative_id,
                representative_exists,
            }),
        });
    }
    if sample.eligibility == "enroll"
        && (sample.person_id.is_some()
            || best_score.is_none_or(|score| score < voice_memory::NEW_PROFILE_THRESHOLD))
    {
        let ids = (
            pins.next_profile(),
            pins.next_assignment(),
            pins.next_revision(),
            pins.next_representative(),
        );
        if let (Some(profile_id), Some(assignment_id), Some(revision_id), Some(representative_id)) =
            ids
        {
            let label = format!("Voice {profile_id}");
            let label_exists = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM voice_profiles WHERE label=?1)",
                    [label],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if label_exists {
                return Ok(AssignmentDecision::Reject {
                    similarity: best_score.map(f32::to_bits),
                    margin: margin.map(f32::to_bits),
                });
            }
            return Ok(AssignmentDecision::New {
                profile_id,
                assignment_id,
                revision_id,
                representative_id,
                person_id: sample.person_id,
                centroid: sample.embedding.clone(),
            });
        }
    }
    Ok(AssignmentDecision::Reject {
        similarity: best_score.map(f32::to_bits),
        margin: margin.map(f32::to_bits),
    })
}

fn load_profile_sample_embeddings(
    connection: &Connection,
    profile_id: i64,
    expected_domain: &str,
) -> Result<Vec<(i64, Vec<f32>)>> {
    let mut statement = connection
        .prepare(
            "SELECT sample.id,typeof(sample.embedding),sample.embedding,
                    typeof(sample.channel_domain),CAST(sample.channel_domain AS TEXT)
             FROM voice_samples sample
             JOIN voice_sample_profile_assignments assignment ON assignment.sample_id=sample.id
             WHERE assignment.profile_id=?1 AND assignment.active=1
               AND sample.accepted=1 AND sample.eligibility='enroll' AND sample.outlier=0
               AND sample.scorer_version=?2
             ORDER BY sample.id LIMIT ?3",
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let rows = statement
        .query_map(
            params![
                profile_id,
                voice_quality::SCORER_VERSION,
                i64::try_from(MAX_PROFILE_SAMPLES + 1).map_err(|_| WalIdempotencyError::Limit)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, rusqlite::types::Value>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    rows.into_iter()
        .map(|(id, embedding_kind, embedding, domain_kind, domain)| {
            if domain_kind != "text" || domain != expected_domain || embedding_kind != "blob" {
                return Err(WalIdempotencyError::Malformed);
            }
            let rusqlite::types::Value::Blob(embedding) = embedding else {
                return Err(WalIdempotencyError::Malformed);
            };
            decode_embedding(&embedding)
                .map(|vector| (id, vector))
                .ok_or(WalIdempotencyError::Malformed)
        })
        .collect()
}

fn next_reconcile_profile(connection: &Connection) -> Result<Option<i64>> {
    connection
        .query_row(
            "SELECT profile.id FROM voice_profiles profile
             WHERE profile.status<>'quarantined'
               AND EXISTS (
                 SELECT 1 FROM voice_profile_revisions any_revision
                 WHERE any_revision.profile_id=profile.id)
               AND (
                 (SELECT COUNT(*) FROM (
                    SELECT 1 FROM voice_profile_revisions active_revision
                    WHERE active_revision.profile_id=profile.id
                      AND active_revision.active=1
                      AND active_revision.status NOT IN ('quarantined','superseded','split')
                    LIMIT 2))<>1
                 OR profile.scorer_version<>?1
                 OR profile.representative_kind<>'medoid_trimmed_centroid'
                 OR length(profile.channel_domain)=0
                 OR length(profile.channel_domain)>?2
                 OR profile.embedding_space<>?3
                 OR typeof(profile.centroid)<>'blob'
                 OR length(profile.centroid)<>?4
                 OR typeof(profile.sample_count)<>'integer'
                 OR profile.sample_count<1 OR profile.sample_count>?6
                 OR profile.person_id IS NOT NULL AND NOT EXISTS (
                   SELECT 1 FROM people person WHERE person.id=profile.person_id)
                 OR profile.medoid_sample_id IS NULL OR NOT EXISTS (
                   SELECT 1 FROM voice_samples medoid WHERE medoid.id=profile.medoid_sample_id)
                 OR length(profile.created_at)=0 OR length(profile.created_at)>64
                 OR strftime('%Y-%m-%dT%H:%M:%fZ',profile.created_at) IS NULL
                 OR length(profile.updated_at)=0 OR length(profile.updated_at)>64
                 OR strftime('%Y-%m-%dT%H:%M:%fZ',profile.updated_at) IS NULL
                 OR EXISTS (
                   SELECT 1 FROM voice_profile_revisions active_revision
                   WHERE active_revision.profile_id=profile.id AND active_revision.active=1
                     AND (length(active_revision.created_at)=0
                       OR length(active_revision.created_at)>64
                       OR strftime('%Y-%m-%dT%H:%M:%fZ',active_revision.created_at) IS NULL))
                 OR (SELECT COUNT(*) FROM (
                   SELECT 1 FROM voice_profile_representatives representative
                   WHERE representative.profile_id=profile.id
                     AND representative.channel_domain=profile.channel_domain
                   LIMIT 2))<>1
                 OR EXISTS (
                   SELECT 1 FROM voice_profile_representatives representative
                   WHERE representative.profile_id=profile.id
                     AND (representative.channel_domain<>profile.channel_domain
                       OR representative.scorer_version<>?1
                       OR typeof(representative.centroid)<>'blob'
                       OR length(representative.centroid)<>?4
                       OR typeof(representative.sample_count)<>'integer'
                       OR representative.sample_count<1 OR representative.sample_count>?6
                       OR representative.medoid_sample_id IS NULL
                       OR length(representative.created_at)=0
                       OR length(representative.created_at)>64
                       OR strftime('%Y-%m-%dT%H:%M:%fZ',representative.created_at) IS NULL
                       OR length(representative.updated_at)=0
                       OR length(representative.updated_at)>64
                       OR strftime('%Y-%m-%dT%H:%M:%fZ',representative.updated_at) IS NULL))
                 OR (SELECT COUNT(*) FROM (
                   SELECT 1 FROM voice_samples sample
                   JOIN voice_sample_profile_assignments assignment
                     ON assignment.sample_id=sample.id
                   WHERE assignment.profile_id=profile.id AND assignment.active=1
                     AND sample.accepted=1 AND sample.eligibility='enroll'
                     AND sample.outlier=0 AND sample.scorer_version=?1
                   LIMIT ?5)) NOT BETWEEN 1 AND ?6
                 OR EXISTS (
                   SELECT 1 FROM voice_samples sample
                   JOIN voice_sample_profile_assignments assignment
                     ON assignment.sample_id=sample.id
                   WHERE assignment.profile_id=profile.id AND assignment.active=1
                     AND sample.accepted=1 AND sample.eligibility='enroll'
                     AND sample.outlier=0
                     AND (sample.scorer_version<>?1
                       OR sample.channel_domain<>profile.channel_domain
                       OR typeof(sample.embedding)<>'blob'
                       OR length(sample.embedding)<>?4))
               )
             ORDER BY profile.id LIMIT 1",
            params![
                voice_quality::SCORER_VERSION,
                512_i64,
                voice_memory::EMBEDDING_SPACE,
                i64::try_from(MAX_EMBEDDING_BYTES).map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(MAX_PROFILE_SAMPLES + 1).map_err(|_| WalIdempotencyError::Limit)?,
                i64::try_from(MAX_PROFILE_SAMPLES).map_err(|_| WalIdempotencyError::Limit)?,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_profile_reconcile(
    connection: &Connection,
    account_id: &str,
    observed_at: &str,
    profile_id: i64,
    pins: AllocatorPins,
) -> Result<VoiceProfileScan> {
    let row = connection
        .query_row(
            "SELECT profile.channel_domain,profile.created_at,profile.updated_at,
                    (SELECT revision.id FROM voice_profile_revisions revision
                     WHERE revision.profile_id=profile.id AND revision.active=1
                       AND revision.status NOT IN ('quarantined','superseded','split')
                     ORDER BY revision.id LIMIT 1),
                    (SELECT revision.created_at FROM voice_profile_revisions revision
                     WHERE revision.profile_id=profile.id AND revision.active=1
                       AND revision.status NOT IN ('quarantined','superseded','split')
                     ORDER BY revision.id LIMIT 1),
                    (SELECT COUNT(*) FROM (
                       SELECT 1 FROM voice_profile_revisions revision
                       WHERE revision.profile_id=profile.id AND revision.active=1
                         AND revision.status NOT IN ('quarantined','superseded','split')
                       LIMIT 2)),
                    (profile.embedding_space=?2
                     AND (profile.person_id IS NULL OR EXISTS (
                       SELECT 1 FROM people person WHERE person.id=profile.person_id))
                     AND NOT EXISTS (
                       SELECT 1 FROM voice_profile_representatives representative
                       WHERE representative.profile_id=profile.id
                         AND representative.channel_domain<>profile.channel_domain))
             FROM voice_profiles profile
             WHERE profile.id=?1 AND profile.status<>'quarantined'",
            params![profile_id, voice_memory::EMBEDDING_SPACE,],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some((
        domain,
        created_at,
        updated_at,
        predecessor_revision_id,
        revision_created_at,
        active_revision_count,
        metadata_valid,
    )) = row
    else {
        return Ok(VoiceProfileScan::Idle);
    };
    if timestamp_after(&created_at, observed_at)
        || timestamp_after(&updated_at, observed_at)
        || revision_created_at
            .as_deref()
            .is_some_and(|value| timestamp_after(value, observed_at))
    {
        return Ok(VoiceProfileScan::ClockDeferred);
    }
    let snapshot = profile_reconcile_snapshot(connection, profile_id)?;
    let representative_rows = {
        let mut statement = connection
            .prepare(
                "SELECT id,created_at,updated_at FROM voice_profile_representatives
                 WHERE profile_id=?1 AND channel_domain=?2 ORDER BY id LIMIT 2",
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let rows = statement
            .query_map(params![profile_id, domain], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        rows
    };
    if representative_rows
        .iter()
        .any(|(_, created_at, updated_at)| {
            timestamp_after(created_at, observed_at) || timestamp_after(updated_at, observed_at)
        })
    {
        return Ok(VoiceProfileScan::ClockDeferred);
    }
    let predecessor_revision_id = predecessor_revision_id.unwrap_or(0);
    let malformed_topology = active_revision_count != 1
        || !metadata_valid
        || predecessor_revision_id <= 0
        || domain.is_empty()
        || domain.len() > 512
        || !valid_timestamp(&created_at)
        || !valid_timestamp(&updated_at)
        || revision_created_at
            .as_deref()
            .is_none_or(|value| !valid_timestamp(value))
        || representative_rows.len() > 1
        || representative_rows
            .iter()
            .any(|(id, created_at, updated_at)| {
                *id <= 0 || !valid_timestamp(created_at) || !valid_timestamp(updated_at)
            });
    let wrong_domain = connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM voice_samples sample
               JOIN voice_sample_profile_assignments assignment ON assignment.sample_id=sample.id
               WHERE assignment.profile_id=?1 AND assignment.active=1
                 AND sample.accepted=1 AND sample.eligibility='enroll' AND sample.outlier=0
                 AND sample.channel_domain<>?2)",
            params![profile_id, domain],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let samples = match load_profile_sample_embeddings(connection, profile_id, &domain) {
        Ok(samples) => samples,
        Err(WalIdempotencyError::Malformed | WalIdempotencyError::Limit) => Vec::new(),
        Err(error) => return Err(error),
    };
    let decision = if malformed_topology {
        // Do not append a revision on top of a missing/ambiguous predecessor.
        // The exact snapshot still authenticates the terminal profile update.
        ReconcileDecision::Quarantine {
            revision_id: None,
            predecessor_revision_id,
        }
    } else if wrong_domain || samples.is_empty() || samples.len() > MAX_PROFILE_SAMPLES {
        ReconcileDecision::Quarantine {
            revision_id: pins.next_revision(),
            predecessor_revision_id,
        }
    } else {
        let ids = samples.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let vectors = samples
            .iter()
            .map(|(_, embedding)| embedding.clone())
            .collect::<Vec<_>>();
        let representative = match voice_quality::robust_representative(&vectors) {
            Ok(value) => value,
            Err(_) => {
                return Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
                    account_id: account_id.to_owned(),
                    observed_at: observed_at.to_owned(),
                    work: WorkEvidence::ProfileReconcile(ProfileReconcileEvidence {
                        profile_id,
                        snapshot,
                        pins,
                        decision: ReconcileDecision::Quarantine {
                            revision_id: pins.next_revision(),
                            predecessor_revision_id,
                        },
                    }),
                })));
            }
        };
        let count = i64::try_from(vectors.len() - representative.excluded_indices.len())
            .map_err(|_| WalIdempotencyError::Limit)?;
        let (representative_id, representative_exists) = match representative_rows.first() {
            Some((id, _, _)) => (*id, true),
            None => {
                let Some(representative_id) = pins.next_representative() else {
                    return Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
                        account_id: account_id.to_owned(),
                        observed_at: observed_at.to_owned(),
                        work: WorkEvidence::ProfileReconcile(ProfileReconcileEvidence {
                            profile_id,
                            snapshot,
                            pins,
                            decision: ReconcileDecision::Quarantine {
                                revision_id: pins.next_revision(),
                                predecessor_revision_id,
                            },
                        }),
                    })));
                };
                (representative_id, false)
            }
        };
        let Some(revision_id) = pins.next_revision() else {
            return Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
                account_id: account_id.to_owned(),
                observed_at: observed_at.to_owned(),
                work: WorkEvidence::ProfileReconcile(ProfileReconcileEvidence {
                    profile_id,
                    snapshot,
                    pins,
                    decision: ReconcileDecision::Quarantine {
                        revision_id: None,
                        predecessor_revision_id,
                    },
                }),
            })));
        };
        ReconcileDecision::Update(ProfileUpdate {
            centroid: encode_embedding(&representative.centroid),
            sample_count: count,
            medoid_sample_id: ids[representative.medoid_index],
            status: if count >= 3 { "stable" } else { "tentative" }.into(),
            revision_id,
            predecessor_revision_id,
            representative_id,
            representative_exists,
        })
    };
    Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
        account_id: account_id.to_owned(),
        observed_at: observed_at.to_owned(),
        work: WorkEvidence::ProfileReconcile(ProfileReconcileEvidence {
            profile_id,
            snapshot,
            pins,
            decision,
        }),
    })))
}

fn next_person_identity(connection: &Connection) -> Result<Option<i64>> {
    connection
        .query_row(
            "SELECT id FROM identity_evidence
             WHERE kind='audio_self_identification' AND status='proposed'
               AND person_id IS NULL
             ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_person_identity(
    connection: &Connection,
    account_id: &str,
    horizon: &str,
    evidence_id: i64,
) -> Result<VoiceProfileScan> {
    let Some((
        evidence_profile_id,
        source_event_id,
        observed_at,
        observation_id,
        evidence_cluster_id,
        claimed_name,
        evidence_json,
        evidence_json_len,
        score,
        created_at,
    )) = connection
        .query_row(
            "SELECT voice_profile_id,source_event_id,observed_at,speaker_observation_id,
                    speaker_cluster_id,claimed_name,
                    CASE WHEN length(CAST(evidence_json AS BLOB))<=?2
                         THEN evidence_json END,
                    length(CAST(evidence_json AS BLOB)),score,created_at
             FROM identity_evidence
             WHERE id=?1 AND person_id IS NULL AND kind='audio_self_identification'
               AND status='proposed'",
            params![evidence_id, MAX_TEXT_BYTES as i64],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<f64>>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
    else {
        return Ok(VoiceProfileScan::Idle);
    };
    let source_event_id = source_event_id.unwrap_or_default();
    let observed_at = observed_at.unwrap_or_default();
    let observation_id = observation_id.unwrap_or(-1);
    let claimed_name = claimed_name.unwrap_or_default();
    let evidence_json = evidence_json.unwrap_or_default();
    if timestamp_after(&created_at, horizon) || timestamp_after(&observed_at, horizon) {
        return Ok(VoiceProfileScan::ClockDeferred);
    }

    let profiles = connection
        .prepare(
            "SELECT DISTINCT assignment.profile_id
             FROM voice_samples sample
             JOIN voice_sample_profile_assignments assignment
               ON assignment.sample_id=sample.id AND assignment.active=1
             WHERE sample.speaker_observation_id=?1 AND sample.accepted=1
             ORDER BY assignment.profile_id LIMIT 2",
        )
        .and_then(|mut statement| {
            statement
                .query_map([observation_id], |row| row.get::<_, i64>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if profiles.is_empty() {
        let still_pending = connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM voice_embedding_jobs
                   WHERE speaker_observation_id=?1
                     AND state IN ('pending','processing','retry_wait'))
                 OR EXISTS(
                   SELECT 1 FROM voice_samples
                   WHERE speaker_observation_id=?1 AND accepted=-1)",
                [observation_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if still_pending {
            return Ok(VoiceProfileScan::Idle);
        }
    }
    let profile_id = profiles.first().copied().unwrap_or(-1);
    let pins = read_person_allocator_pins(connection)?;
    let (source_count, sample_count, active_assignment_count) = connection
        .query_row(
            "SELECT
               (SELECT COUNT(*) FROM speaker_observation_sources
                WHERE speaker_observation_id=?1),
               (SELECT COUNT(*) FROM voice_samples
                WHERE speaker_observation_id=?1),
               (SELECT COUNT(*) FROM voice_sample_profile_assignments assignment
                JOIN voice_samples sample ON sample.id=assignment.sample_id
                WHERE sample.speaker_observation_id=?1 AND assignment.active=1)",
            [observation_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let envelope = serde_json::from_str::<StoredIdentityEnvelope>(&evidence_json).ok();
    let normalized_name = normalize_person_name(&claimed_name);
    let confidence_millionths = score
        .filter(|value| value.is_finite() && (0.90..=1.0).contains(value))
        .map(|value| (value * 1_000_000.0).round() as u32)
        .filter(|value| (900_000..=1_000_000).contains(value));
    let basic_valid = evidence_id > 0
        && evidence_profile_id.is_none()
        && evidence_cluster_id.is_none()
        && observation_id > 0
        && profiles.len() == 1
        && (1..=MAX_OBSERVATION_SOURCES).contains(&source_count)
        && (1..=MAX_OBSERVATION_SAMPLES).contains(&sample_count)
        && (1..=MAX_OBSERVATION_SAMPLES).contains(&active_assignment_count)
        && !source_event_id.is_empty()
        && source_event_id.len() <= 128
        && valid_timestamp(&observed_at)
        && valid_timestamp(&created_at)
        && !claimed_name.trim().is_empty()
        && claimed_name.len() <= 256
        && !claimed_name.contains('\0')
        && !normalized_name.is_empty()
        && confidence_millionths.is_some()
        && (0..=MAX_TEXT_BYTES as i64).contains(&evidence_json_len)
        && envelope.as_ref().is_some_and(|value| {
            value.schema_version == 1
                && !value.turn_id.is_empty()
                && value.turn_id.len() <= 128
                && !value.literal_evidence.trim().is_empty()
                && value.literal_evidence.len() <= 2_000
                && !value.literal_evidence.contains('\0')
                && value.facts.len() <= 20
        });

    let snapshot = person_identity_snapshot(connection, evidence_id, observation_id, profile_id)?;
    let mut decision = PersonIdentityDecision::Reject;
    if basic_valid {
        let profile = connection
            .query_row(
                "SELECT person_id,status,created_at,updated_at
                 FROM voice_profiles WHERE id=?1",
                [profile_id],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let revisions = connection
            .prepare(
                "SELECT id,person_id,created_at FROM voice_profile_revisions
                 WHERE profile_id=?1 AND active=1
                   AND status NOT IN ('quarantined','superseded','split')
                 ORDER BY id LIMIT 2",
            )
            .and_then(|mut statement| {
                statement
                    .query_map([profile_id], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()
            })
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let observation = connection
            .query_row(
                "SELECT person_id,cluster_id,event_id,turn_id,started_at,ended_at,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN transcript_text END,
                        length(CAST(transcript_text AS BLOB)),direct_evidence_id
                 FROM speaker_observations WHERE id=?1",
                params![observation_id, MAX_TRANSCRIPT_BYTES as i64],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if let (
            Some((profile_person, status, profile_created, profile_updated)),
            [revision],
            Some((
                observation_person,
                Some(cluster_id),
                event_id,
                turn_id,
                started_at,
                observation_ended,
                transcript_text,
                transcript_bytes,
                direct_evidence_id,
            )),
        ) = (profile, revisions.as_slice(), observation)
        {
            if [
                profile_created.as_str(),
                profile_updated.as_str(),
                revision.2.as_str(),
                started_at.as_str(),
                observation_ended.as_str(),
            ]
            .iter()
            .any(|value| timestamp_after(value, horizon))
            {
                return Ok(VoiceProfileScan::ClockDeferred);
            }
            let envelope = envelope.as_ref().ok_or(WalIdempotencyError::Malformed)?;
            let transcript_text = transcript_text.unwrap_or_default();
            let topology_valid = status != "quarantined"
                && revision.1 == profile_person
                && event_id == source_event_id
                && turn_id == envelope.turn_id
                && observed_at == started_at
                && direct_evidence_id.is_none()
                && (0..=MAX_TRANSCRIPT_BYTES as i64).contains(&transcript_bytes)
                && !transcript_text.is_empty()
                && transcript_text.contains(envelope.literal_evidence.as_str())
                && envelope.literal_evidence.contains(claimed_name.trim())
                && envelope
                    .facts
                    .iter()
                    .all(|fact| transcript_text.contains(fact.evidence.as_str()))
                && observation_person.is_none_or(|person| Some(person) == profile_person);
            if topology_valid {
                let cluster_valid = connection
                    .query_row(
                        "SELECT person_id,voice_profile_id,attribution_state,
                                created_at,updated_at
                         FROM speaker_clusters WHERE id=?1",
                        [cluster_id],
                        |row| {
                            Ok((
                                row.get::<_, Option<i64>>(0)?,
                                row.get::<_, Option<i64>>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, String>(4)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                let create_person = profile_person.is_none();
                let person_id = match profile_person {
                    Some(value) => value,
                    None => pins.people.checked_add(1).unwrap_or(-1),
                };
                let person_predecessor = if create_person {
                    None
                } else {
                    connection
                        .query_row(
                            "SELECT display_name,normalized_name,status,created_at,updated_at,kind
                             FROM people WHERE id=?1",
                            [person_id],
                            |row| {
                                Ok((
                                    row.get::<_, Option<String>>(0)?,
                                    row.get::<_, Option<String>>(1)?,
                                    row.get::<_, String>(2)?,
                                    row.get::<_, String>(3)?,
                                    row.get::<_, String>(4)?,
                                    row.get::<_, String>(5)?,
                                ))
                            },
                        )
                        .optional()
                        .map_err(|_| WalIdempotencyError::Unavailable)?
                };
                let accepted_names = connection
                    .prepare(
                        "SELECT normalized_name,observed_at,created_at FROM person_name_claims
                         WHERE person_id=?1 AND status='accepted'
                         ORDER BY id LIMIT 101",
                    )
                    .and_then(|mut statement| {
                        statement
                            .query_map([person_id], |row| {
                                Ok((
                                    row.get::<_, String>(0)?,
                                    row.get::<_, String>(1)?,
                                    row.get::<_, String>(2)?,
                                ))
                            })?
                            .collect::<std::result::Result<Vec<_>, _>>()
                    })
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                let names_compatible = accepted_names.len() <= 100
                    && (accepted_names.is_empty()
                        || accepted_names
                            .iter()
                            .all(|value| value.0 == normalized_name));
                let bindings = connection
                    .prepare(
                        "SELECT id,person_id,evidence_count,confidence,created_at,updated_at
                         FROM profile_identity_bindings
                         WHERE voice_profile_id=?1 AND active=1 AND state='accepted'
                         ORDER BY id LIMIT 2",
                    )
                    .and_then(|mut statement| {
                        statement
                            .query_map([profile_id], |row| {
                                Ok((
                                    row.get::<_, i64>(0)?,
                                    row.get::<_, i64>(1)?,
                                    row.get::<_, i64>(2)?,
                                    row.get::<_, f64>(3)?,
                                    row.get::<_, String>(4)?,
                                    row.get::<_, String>(5)?,
                                ))
                            })?
                            .collect::<std::result::Result<Vec<_>, _>>()
                    })
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                let binding_predecessor = match bindings.as_slice() {
                    [] => Some((None, 1)),
                    [(id, bound_person, count, confidence, _, _)]
                        if *bound_person == person_id
                            && *count > 0
                            && confidence.is_finite()
                            && (0.0..=1.0).contains(confidence) =>
                    {
                        count.checked_add(1).map(|next| (Some(*id), next))
                    }
                    _ => None,
                };
                let active_fact_times = connection
                    .prepare(
                        "SELECT observed_at,created_at FROM person_facts
                         WHERE person_id=?1 AND status='active'
                         ORDER BY id LIMIT 101",
                    )
                    .and_then(|mut statement| {
                        statement
                            .query_map([person_id], |row| {
                                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                            })?
                            .collect::<std::result::Result<Vec<_>, _>>()
                    })
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                let sample_times = connection
                    .prepare(
                        "SELECT created_at FROM voice_samples
                         WHERE speaker_observation_id=?1 ORDER BY id LIMIT 129",
                    )
                    .and_then(|mut statement| {
                        statement
                            .query_map([observation_id], |row| row.get::<_, String>(0))?
                            .collect::<std::result::Result<Vec<_>, _>>()
                    })
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                let assignment_times = connection
                    .prepare(
                        "SELECT assignment.created_at
                         FROM voice_sample_profile_assignments assignment
                         JOIN voice_samples sample ON sample.id=assignment.sample_id
                         WHERE sample.speaker_observation_id=?1 AND assignment.active=1
                         ORDER BY assignment.id LIMIT 129",
                    )
                    .and_then(|mut statement| {
                        statement
                            .query_map([observation_id], |row| row.get::<_, String>(0))?
                            .collect::<std::result::Result<Vec<_>, _>>()
                    })
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                let mut predecessor_timestamps = vec![
                    profile_created.clone(),
                    profile_updated.clone(),
                    revision.2.clone(),
                    started_at.clone(),
                    observation_ended.clone(),
                ];
                predecessor_timestamps.extend(sample_times);
                predecessor_timestamps.extend(assignment_times);
                if let Some((_, _, _, cluster_created, cluster_updated)) = &cluster_valid {
                    predecessor_timestamps.push(cluster_created.clone());
                    predecessor_timestamps.push(cluster_updated.clone());
                }
                if let Some((_, _, _, person_created, person_updated, _)) = &person_predecessor {
                    predecessor_timestamps.push(person_created.clone());
                    predecessor_timestamps.push(person_updated.clone());
                }
                predecessor_timestamps.extend(
                    accepted_names
                        .iter()
                        .flat_map(|value| [value.1.clone(), value.2.clone()]),
                );
                predecessor_timestamps.extend(
                    bindings
                        .iter()
                        .flat_map(|value| [value.4.clone(), value.5.clone()]),
                );
                predecessor_timestamps.extend(
                    active_fact_times
                        .iter()
                        .flat_map(|value| [value.0.clone(), value.1.clone()]),
                );
                if predecessor_timestamps
                    .iter()
                    .any(|value| timestamp_after(value, horizon))
                {
                    return Ok(VoiceProfileScan::ClockDeferred);
                }
                let predecessor_timestamps_valid = predecessor_timestamps
                    .iter()
                    .all(|value| valid_timestamp(value));
                let person_valid = if create_person {
                    person_id > 0
                } else {
                    person_predecessor.as_ref().is_some_and(|value| {
                        let display_compatible = value.0.as_deref().is_none_or(|display| {
                            display.trim().is_empty()
                                || normalize_person_name(display) == normalized_name
                        });
                        let normalized_compatible = value.1.as_deref().is_none_or(|stored| {
                            stored.trim().is_empty() || stored == normalized_name
                        });
                        value.2 == "identified"
                            && value.5 == "person"
                            && display_compatible
                            && normalized_compatible
                    })
                };
                let facts = build_fact_writes(connection, person_id, pins.facts, &envelope.facts)?;
                if let (
                    Some((cluster_person, cluster_profile, cluster_state, _, _)),
                    Some((supersedes_binding_id, binding_evidence_count)),
                    Some(binding_id),
                    Some(name_claim_id),
                    Some(facts),
                ) = (
                    cluster_valid,
                    binding_predecessor,
                    pins.bindings.checked_add(1),
                    pins.name_claims.checked_add(1),
                    facts,
                ) {
                    if person_valid
                        && predecessor_timestamps_valid
                        && names_compatible
                        && active_fact_times.len() <= 100
                        && cluster_person.is_none_or(|value| value == person_id)
                        && cluster_profile.is_none_or(|value| value == profile_id)
                        && matches!(
                            cluster_state.as_str(),
                            "request_local" | "anonymous_profile" | "person_bound"
                        )
                    {
                        decision = PersonIdentityDecision::Bind {
                            person_id,
                            create_person,
                            name_claim_id,
                            binding_id,
                            supersedes_binding_id,
                            binding_evidence_count,
                            profile_id,
                            active_revision_id: revision.0,
                            observation_id,
                            cluster_id,
                            normalized_name,
                            facts,
                        };
                    }
                }
            }
        }
    }
    Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
        account_id: account_id.to_owned(),
        observed_at: horizon.to_owned(),
        work: WorkEvidence::PersonIdentity(PersonIdentityEvidence {
            evidence_id,
            snapshot,
            pins,
            claimed_name,
            evidence_json,
            confidence_millionths: confidence_millionths.unwrap_or(0),
            source_event_id,
            observed_at,
            decision,
        }),
    })))
}

fn normalize_person_name(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn build_fact_writes(
    connection: &Connection,
    person_id: i64,
    initial_pin: i64,
    facts: &[StoredIdentityFact],
) -> Result<Option<Vec<FactWrite>>> {
    let mut output = Vec::new();
    let mut temporal = std::collections::HashSet::new();
    for fact in facts {
        if !matches!(
            fact.predicate.as_str(),
            "role"
                | "organization"
                | "relationship"
                | "preference"
                | "responsibility"
                | "contact"
                | "location"
                | "other"
        ) || fact.value.trim().is_empty()
            || fact.value.len() > 2_000
            || fact.value.contains('\0')
            || fact.evidence.trim().is_empty()
            || fact.evidence.len() > 2_000
            || fact.evidence.contains('\0')
        {
            return Ok(None);
        }
        let singleton = matches!(
            fact.predicate.as_str(),
            "role" | "organization" | "location"
        );
        if singleton && !temporal.insert(fact.predicate.as_str()) {
            return Ok(None);
        }
        let exact = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM person_facts
                 WHERE person_id=?1 AND predicate=?2 AND lower(value)=lower(?3)
                   AND status='active')",
                params![person_id, fact.predicate, fact.value],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if exact {
            continue;
        }
        let supersedes_id = if singleton {
            connection
                .query_row(
                    "SELECT id FROM person_facts
                     WHERE person_id=?1 AND predicate=?2 AND status='active'
                     ORDER BY COALESCE(observed_at,created_at) DESC,id DESC LIMIT 1",
                    params![person_id, fact.predicate],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| WalIdempotencyError::Unavailable)?
        } else {
            None
        };
        let id = initial_pin
            .checked_add(1)
            .and_then(|base| base.checked_add(i64::try_from(output.len()).ok()?));
        let Some(id) = id else { return Ok(None) };
        output.push(FactWrite {
            id,
            predicate: fact.predicate.clone(),
            value: fact.value.clone(),
            literal_evidence: fact.evidence.clone(),
            supersedes_id,
        });
    }
    Ok(Some(output))
}

fn load_proposal_refusal(
    connection: &Connection,
    account_id: &str,
    observed_at: &str,
    proposal_id: i64,
) -> Result<VoiceProfileScan> {
    let row = connection
        .query_row(
            "SELECT state,created_at,updated_at FROM voice_profile_proposals WHERE id=?1",
            [proposal_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some((state, created_at, updated_at)) = row else {
        return Ok(VoiceProfileScan::Idle);
    };
    if timestamp_after(&created_at, observed_at) || timestamp_after(&updated_at, observed_at) {
        return Ok(VoiceProfileScan::ClockDeferred);
    }
    let target = match state.as_str() {
        "approved" => "rejected",
        "revert_requested" => "applied",
        _ => return Ok(VoiceProfileScan::Idle),
    };
    let snapshot = digest_queries(
        connection,
        &[(
            b"proposal".as_slice(),
            "SELECT id,state,created_at,updated_at
             FROM voice_profile_proposals WHERE id=?1 ORDER BY id",
            vec![SqlArg::Integer(proposal_id)],
        )],
    )?;
    Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
        account_id: account_id.to_owned(),
        observed_at: observed_at.to_owned(),
        work: WorkEvidence::ProposalRefusal(ProposalRefusalEvidence {
            proposal_id,
            snapshot,
            predecessor_state: state,
            target_state: target.into(),
        }),
    })))
}

fn next_episode_status(connection: &Connection) -> Result<Option<i64>> {
    connection
        .query_row(
            "SELECT episode.id FROM episodes episode
             WHERE episode.speaker_processing_status <> CASE
               WHEN EXISTS (
                 SELECT 1 FROM episode_members member
                 JOIN utterances utterance ON utterance.id=member.record_id
                   AND member.record_type='utterance'
                 JOIN voice_embedding_jobs job
                   ON job.speaker_observation_id=utterance.speaker_observation_id
                 WHERE member.episode_id=episode.id
                   AND job.state IN ('pending','processing','retry_wait')) THEN 'pending'
               WHEN EXISTS (
                 SELECT 1 FROM episode_members member
                 JOIN utterances utterance ON utterance.id=member.record_id
                   AND member.record_type='utterance'
                 JOIN voice_embedding_jobs job
                   ON job.speaker_observation_id=utterance.speaker_observation_id
                 WHERE member.episode_id=episode.id AND job.state='failed') THEN 'degraded'
               ELSE 'ready' END
             ORDER BY episode.id LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)
}

fn load_episode_status(
    connection: &Connection,
    account_id: &str,
    observed_at: &str,
    episode_id: i64,
) -> Result<VoiceProfileScan> {
    let row = connection
        .query_row(
            "SELECT episode.speaker_processing_status,
                    COALESCE(episode.updated_at,episode.created_at,episode.started_at),
                    EXISTS(
                      SELECT 1 FROM episode_members member
                      JOIN utterances utterance ON utterance.id=member.record_id
                        AND member.record_type='utterance'
                      JOIN voice_embedding_jobs job
                        ON job.speaker_observation_id=utterance.speaker_observation_id
                      WHERE member.episode_id=episode.id
                        AND job.state IN ('pending','processing','retry_wait')),
                    EXISTS(
                      SELECT 1 FROM episode_members member
                      JOIN utterances utterance ON utterance.id=member.record_id
                        AND member.record_type='utterance'
                      JOIN voice_embedding_jobs job
                        ON job.speaker_observation_id=utterance.speaker_observation_id
                      WHERE member.episode_id=episode.id AND job.state='failed')
             FROM episodes episode WHERE episode.id=?1",
            [episode_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let Some((predecessor, updated_at, pending, failed)) = row else {
        return Ok(VoiceProfileScan::Idle);
    };
    if timestamp_after(&updated_at, observed_at) {
        return Ok(VoiceProfileScan::ClockDeferred);
    }
    let target = if pending {
        "pending"
    } else if failed {
        "degraded"
    } else {
        "ready"
    };
    if predecessor == target {
        return Ok(VoiceProfileScan::Idle);
    }
    let snapshot = digest_queries(
        connection,
        &[
            (
                b"episode".as_slice(),
                "SELECT id,speaker_processing_status,updated_at,created_at,started_at
                 FROM episodes WHERE id=?1 ORDER BY id",
                vec![SqlArg::Integer(episode_id)],
            ),
            (
                b"derived".as_slice(),
                "SELECT
                   SUM(CASE WHEN job.state IN ('pending','processing','retry_wait') THEN 1 ELSE 0 END),
                   SUM(CASE WHEN job.state='failed' THEN 1 ELSE 0 END)
                 FROM episode_members member
                 JOIN utterances utterance ON utterance.id=member.record_id
                   AND member.record_type='utterance'
                 JOIN voice_embedding_jobs job
                   ON job.speaker_observation_id=utterance.speaker_observation_id
                 WHERE member.episode_id=?1",
                vec![SqlArg::Integer(episode_id)],
            ),
        ],
    )?;
    Ok(VoiceProfileScan::Work(Box::new(VoiceProfileEvidence {
        account_id: account_id.to_owned(),
        observed_at: observed_at.to_owned(),
        work: WorkEvidence::EpisodeStatus(EpisodeStatusEvidence {
            episode_id,
            snapshot,
            predecessor_status: predecessor,
            target_status: target.into(),
        }),
    })))
}

fn profile_reconcile_snapshot(connection: &Connection, profile_id: i64) -> Result<[u8; 32]> {
    digest_queries(
        connection,
        &[
            (
                b"profile".as_slice(),
                "SELECT id,person_id,embedding_space,channel_domain,centroid,sample_count,
                        scorer_version,representative_kind,medoid_sample_id,status,
                        created_at,updated_at
                 FROM voice_profiles WHERE id=?1 ORDER BY id",
                vec![SqlArg::Integer(profile_id)],
            ),
            (
                b"revisions".as_slice(),
                "SELECT id,profile_id,status,scorer_version,active,created_at
                 FROM voice_profile_revisions
                 WHERE profile_id=?1 AND active=1 ORDER BY id LIMIT 2",
                vec![SqlArg::Integer(profile_id)],
            ),
            (
                b"assignments".as_slice(),
                "SELECT assignment.id,assignment.sample_id,assignment.profile_id,assignment.active,
                        sample.id,sample.channel_domain,sample.embedding,sample.scorer_version,
                        sample.eligibility,sample.outlier,sample.accepted,sample.created_at
                 FROM voice_sample_profile_assignments assignment
                 JOIN voice_samples sample ON sample.id=assignment.sample_id
                 WHERE assignment.profile_id=?1 AND assignment.active=1
                   AND sample.accepted=1 AND sample.eligibility='enroll' AND sample.outlier=0
                 ORDER BY sample.id LIMIT 101",
                vec![SqlArg::Integer(profile_id)],
            ),
            (
                b"representatives".as_slice(),
                "SELECT id,profile_id,channel_domain,scorer_version,created_at,updated_at
                 FROM voice_profile_representatives
                 WHERE profile_id=?1 ORDER BY id LIMIT 33",
                vec![SqlArg::Integer(profile_id)],
            ),
        ],
    )
}

fn apply_profile_backfill(
    transaction: &Transaction<'_>,
    evidence: &ProfileBackfillEvidence,
    committed_at: &str,
) -> Result<()> {
    match evidence.disposition {
        BackfillDisposition::Insert { revision_id } => {
            transaction
                .execute(
                    "INSERT INTO voice_profile_revisions
                     (id,profile_id,status,derivation_version,scorer_version,
                      representative_kind,centroid,sample_count,medoid_sample_id,
                      person_id,reason_code,active,created_at)
                     SELECT ?1,id,status,1,scorer_version,representative_kind,centroid,
                            sample_count,medoid_sample_id,person_id,'schema_backfill',1,?2
                     FROM voice_profiles WHERE id=?3 AND NOT EXISTS (
                       SELECT 1 FROM voice_profile_revisions WHERE profile_id=?3)",
                    params![revision_id, committed_at, evidence.profile_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
        }
        BackfillDisposition::Quarantine => {
            transaction
                .execute(
                    "UPDATE voice_profiles SET status='quarantined',person_id=NULL,updated_at=?1
                     WHERE id=?2 AND status<>'quarantined'",
                    params![committed_at, evidence.profile_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
        }
    }
    let after = read_allocator_pins(transaction)?;
    let mut expected = evidence.pins;
    if let BackfillDisposition::Insert { revision_id } = evidence.disposition {
        expected.revisions = revision_id;
    }
    if after != expected {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn apply_assignment_backfill(
    transaction: &Transaction<'_>,
    evidence: &AssignmentBackfillEvidence,
    committed_at: &str,
) -> Result<()> {
    if let Some(assignment_id) = evidence.assignment_id {
        transaction
            .execute(
                "INSERT INTO voice_sample_profile_assignments
                 (id,sample_id,profile_id,active,created_at) VALUES (?1,?2,?3,1,?4)",
                params![
                    assignment_id,
                    evidence.sample_id,
                    evidence.profile_id,
                    committed_at
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)
            .and_then(require_one)?;
    } else {
        transaction
            .execute(
                "UPDATE voice_samples SET voice_profile_id=NULL,accepted=0,outlier=0,
                 similarity=NULL,decision_margin=NULL WHERE id=?1 AND voice_profile_id=?2",
                params![evidence.sample_id, evidence.profile_id],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)
            .and_then(require_one)?;
    }
    let after = read_allocator_pins(transaction)?;
    let mut expected = evidence.pins;
    if let Some(assignment_id) = evidence.assignment_id {
        expected.assignments = assignment_id;
    }
    if after != expected {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn apply_sample_assignment(
    transaction: &Transaction<'_>,
    evidence: &SampleAssignmentEvidence,
    committed_at: &str,
) -> Result<()> {
    match &evidence.decision {
        AssignmentDecision::Reject { similarity, margin } => {
            update_sample(
                transaction,
                evidence.sample_id,
                None,
                false,
                false,
                *similarity,
                *margin,
            )?;
        }
        AssignmentDecision::Existing {
            profile_id,
            assignment_id,
            accepted,
            outlier,
            similarity,
            margin,
            update,
        } => {
            update_sample(
                transaction,
                evidence.sample_id,
                Some(*profile_id),
                *accepted,
                *outlier,
                Some(*similarity),
                Some(*margin),
            )?;
            insert_assignment(
                transaction,
                *assignment_id,
                evidence.sample_id,
                *profile_id,
                committed_at,
            )?;
            if let Some(update) = update {
                transaction
                    .execute(
                        "UPDATE voice_profile_revisions SET active=0
                         WHERE id=?1 AND profile_id=?2 AND active=1",
                        params![update.predecessor_revision_id, profile_id],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)
                    .and_then(require_one)?;
                transaction
                    .execute(
                        "UPDATE voice_profiles SET centroid=?1,sample_count=?2,
                         scorer_version=?3,representative_kind='medoid_trimmed_centroid',
                         medoid_sample_id=?4,status=?5,updated_at=?6 WHERE id=?7",
                        params![
                            update.centroid,
                            update.sample_count,
                            voice_quality::SCORER_VERSION,
                            update.medoid_sample_id,
                            update.status,
                            committed_at,
                            profile_id
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)
                    .and_then(require_one)?;
                transaction
                    .execute(
                        "INSERT INTO voice_profile_revisions
                         (id,profile_id,status,derivation_version,scorer_version,
                          representative_kind,centroid,sample_count,medoid_sample_id,
                          person_id,predecessor_revision_id,reason_code,active,created_at)
                         SELECT ?1,id,status,1,scorer_version,representative_kind,centroid,
                                sample_count,medoid_sample_id,person_id,?2,
                                'representative_recomputed',1,?3
                         FROM voice_profiles WHERE id=?4",
                        params![
                            update.revision_id,
                            update.predecessor_revision_id,
                            committed_at,
                            profile_id
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)
                    .and_then(require_one)?;
                upsert_representative(transaction, update, *profile_id, committed_at)?;
            }
        }
        AssignmentDecision::New {
            profile_id,
            assignment_id,
            revision_id,
            representative_id,
            person_id,
            centroid,
        } => {
            transaction
                .execute(
                    "INSERT INTO voice_profiles
                     (id,person_id,label,embedding_space,channel_domain,centroid,sample_count,
                      scorer_version,representative_kind,medoid_sample_id,status,created_at,updated_at)
                     SELECT ?1,?2,?3,embedding_space,channel_domain,?4,1,scorer_version,
                            'medoid_trimmed_centroid',id,'tentative',?5,?5
                     FROM voice_samples WHERE id=?6 AND accepted=-1",
                    params![
                        profile_id,
                        person_id,
                        format!("Voice {profile_id}"),
                        centroid,
                        committed_at,
                        evidence.sample_id
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            // The SELECT above cannot use the sample id as medoid before the
            // sample update; it nevertheless is the exact fixed sample id.
            transaction
                .execute(
                    "UPDATE voice_profiles SET medoid_sample_id=?1 WHERE id=?2",
                    params![evidence.sample_id, profile_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            update_sample(
                transaction,
                evidence.sample_id,
                Some(*profile_id),
                true,
                false,
                None,
                None,
            )?;
            insert_assignment(
                transaction,
                *assignment_id,
                evidence.sample_id,
                *profile_id,
                committed_at,
            )?;
            transaction
                .execute(
                    "INSERT INTO voice_profile_revisions
                     (id,profile_id,status,derivation_version,scorer_version,
                      representative_kind,centroid,sample_count,medoid_sample_id,
                      person_id,reason_code,active,created_at)
                     SELECT ?1,id,status,1,scorer_version,representative_kind,centroid,
                            sample_count,medoid_sample_id,person_id,'sample_assigned',1,?2
                     FROM voice_profiles WHERE id=?3",
                    params![revision_id, committed_at, profile_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            transaction
                .execute(
                    "INSERT INTO voice_profile_representatives
                     (id,profile_id,channel_domain,centroid,sample_count,medoid_sample_id,
                      scorer_version,created_at,updated_at)
                     SELECT ?1,?2,channel_domain,centroid,1,?3,scorer_version,?4,?4
                     FROM voice_profiles WHERE id=?2",
                    params![
                        representative_id,
                        profile_id,
                        evidence.sample_id,
                        committed_at
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
        }
    }
    assert_allocator_poststate(transaction, evidence.pins, &evidence.decision)?;
    Ok(())
}

fn apply_profile_reconcile(
    transaction: &Transaction<'_>,
    evidence: &ProfileReconcileEvidence,
    committed_at: &str,
) -> Result<()> {
    match &evidence.decision {
        ReconcileDecision::Update(update) => {
            transaction
                .execute(
                    "UPDATE voice_profile_revisions SET active=0
                     WHERE id=?1 AND profile_id=?2 AND active=1",
                    params![update.predecessor_revision_id, evidence.profile_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            transaction
                .execute(
                    "UPDATE voice_profiles SET centroid=?1,sample_count=?2,scorer_version=?3,
                     representative_kind='medoid_trimmed_centroid',medoid_sample_id=?4,
                     status=?5,updated_at=?6 WHERE id=?7 AND status<>'quarantined'",
                    params![
                        update.centroid,
                        update.sample_count,
                        voice_quality::SCORER_VERSION,
                        update.medoid_sample_id,
                        update.status,
                        committed_at,
                        evidence.profile_id
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            transaction
                .execute(
                    "INSERT INTO voice_profile_revisions
                     (id,profile_id,status,derivation_version,scorer_version,
                      representative_kind,centroid,sample_count,medoid_sample_id,person_id,
                      predecessor_revision_id,reason_code,active,created_at)
                     SELECT ?1,id,status,1,scorer_version,representative_kind,centroid,
                            sample_count,medoid_sample_id,person_id,?2,
                            'bounded_reconciliation',1,?3
                     FROM voice_profiles WHERE id=?4",
                    params![
                        update.revision_id,
                        update.predecessor_revision_id,
                        committed_at,
                        evidence.profile_id
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            upsert_representative(transaction, update, evidence.profile_id, committed_at)?;
        }
        ReconcileDecision::Quarantine {
            revision_id,
            predecessor_revision_id,
        } => {
            transaction
                .execute(
                    "UPDATE voice_profiles SET status='quarantined',sample_count=0,
                     medoid_sample_id=NULL,person_id=NULL,updated_at=?1
                     WHERE id=?2 AND status<>'quarantined'",
                    params![committed_at, evidence.profile_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            if let Some(revision_id) = revision_id {
                transaction
                    .execute(
                        "UPDATE voice_profile_revisions SET active=0
                         WHERE id=?1 AND profile_id=?2 AND active=1",
                        params![predecessor_revision_id, evidence.profile_id],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)
                    .and_then(require_one)?;
                transaction
                    .execute(
                        "INSERT INTO voice_profile_revisions
                         (id,profile_id,status,derivation_version,scorer_version,
                          representative_kind,centroid,sample_count,medoid_sample_id,person_id,
                          predecessor_revision_id,reason_code,active,created_at)
                         SELECT ?1,id,'quarantined',1,scorer_version,representative_kind,
                                centroid,0,NULL,NULL,?2,'bounded_reconciliation',1,?3
                         FROM voice_profiles WHERE id=?4",
                        params![
                            revision_id,
                            predecessor_revision_id,
                            committed_at,
                            evidence.profile_id
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)
                    .and_then(require_one)?;
            } else {
                // An exhausted allocator or malformed active-revision topology
                // must not leave this profile claimable forever. Preserve row
                // identities and terminalize every active overlay in place; no
                // new SQLite integer is minted or overflowed. The complete
                // predecessor set was committed and reobserved before writes.
                transaction
                    .execute(
                        "UPDATE voice_profile_revisions SET status='quarantined',
                         sample_count=0,medoid_sample_id=NULL,person_id=NULL
                         WHERE profile_id=?1 AND active=1",
                        [evidence.profile_id],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                let survives = transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM voice_profile_revisions
                         WHERE profile_id=?1 AND active=1 AND status<>'quarantined')",
                        [evidence.profile_id],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if survives {
                    return Err(WalIdempotencyError::Corrupt);
                }
            }
        }
    }
    assert_reconcile_allocator_poststate(transaction, evidence)?;
    Ok(())
}

fn apply_person_identity(
    transaction: &Transaction<'_>,
    evidence: &PersonIdentityEvidence,
    committed_at: &str,
) -> Result<()> {
    match &evidence.decision {
        PersonIdentityDecision::Reject => {
            transaction
                .execute(
                    "UPDATE identity_evidence SET status='rejected'
                     WHERE id=?1 AND person_id IS NULL
                       AND kind='audio_self_identification' AND status='proposed'",
                    [evidence.evidence_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
        }
        PersonIdentityDecision::Bind {
            person_id,
            create_person,
            name_claim_id,
            binding_id,
            supersedes_binding_id,
            binding_evidence_count,
            profile_id,
            active_revision_id,
            observation_id,
            cluster_id,
            normalized_name,
            facts,
        } => {
            if *create_person {
                transaction
                    .execute(
                        "INSERT INTO people
                         (id,display_name,normalized_name,status,created_at,updated_at)
                         VALUES (?1,?2,NULL,'identified',?3,?3)",
                        params![person_id, evidence.claimed_name.trim(), committed_at],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)
                    .and_then(require_one)?;
            }
            transaction
                .execute(
                    "INSERT INTO person_name_claims
                     (id,person_id,name,normalized_name,source_event_id,
                      speaker_observation_id,observed_at,evidence_kind,evidence_json,
                      confidence,status,created_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,'audio_self_identification',
                             ?8,?9,'accepted',?10)",
                    params![
                        name_claim_id,
                        person_id,
                        evidence.claimed_name.trim(),
                        normalized_name,
                        evidence.source_event_id,
                        observation_id,
                        evidence.observed_at,
                        evidence.evidence_json,
                        f64::from(evidence.confidence_millionths) / 1_000_000.0,
                        committed_at,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            transaction
                .execute(
                    "UPDATE identity_evidence
                     SET person_id=?1,voice_profile_id=?2,speaker_cluster_id=?3,status='accepted'
                     WHERE id=?4 AND person_id IS NULL AND voice_profile_id IS NULL
                       AND speaker_cluster_id IS NULL
                       AND kind='audio_self_identification' AND status='proposed'",
                    params![person_id, profile_id, cluster_id, evidence.evidence_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            transaction
                .execute(
                    "UPDATE speaker_observations SET person_id=?1,direct_evidence_id=?2
                     WHERE id=?3 AND (person_id IS NULL OR person_id=?1)
                       AND direct_evidence_id IS NULL AND cluster_id=?4",
                    params![person_id, evidence.evidence_id, observation_id, cluster_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            transaction
                .execute(
                    "UPDATE speaker_clusters SET person_id=?1,voice_profile_id=?2,
                     attribution_state='person_bound',updated_at=?3
                     WHERE id=?4 AND (person_id IS NULL OR person_id=?1)
                       AND (voice_profile_id IS NULL OR voice_profile_id=?2)
                       AND attribution_state IN ('request_local','anonymous_profile','person_bound')",
                    params![person_id, profile_id, committed_at, cluster_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            transaction
                .execute(
                    "UPDATE voice_profiles SET person_id=?1,updated_at=?2
                     WHERE id=?3 AND (person_id IS NULL OR person_id=?1)
                       AND status<>'quarantined'",
                    params![person_id, committed_at, profile_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            transaction
                .execute(
                    "UPDATE voice_profile_revisions SET person_id=?1
                     WHERE id=?2 AND profile_id=?3 AND active=1
                       AND (person_id IS NULL OR person_id=?1)",
                    params![person_id, active_revision_id, profile_id],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            if let Some(previous) = supersedes_binding_id {
                transaction
                    .execute(
                        "UPDATE profile_identity_bindings SET active=0,updated_at=?1
                         WHERE id=?2 AND voice_profile_id=?3 AND person_id=?4
                           AND evidence_count=?5 AND state='accepted' AND active=1",
                        params![
                            committed_at,
                            previous,
                            profile_id,
                            person_id,
                            binding_evidence_count - 1,
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)
                    .and_then(require_one)?;
            }
            transaction
                .execute(
                    "INSERT INTO profile_identity_bindings
                     (id,voice_profile_id,person_id,evidence_count,confidence,state,
                      derivation_version,evidence_json,supersedes_id,created_at,updated_at,
                      active,operation_id,conflicts_with_id)
                     VALUES (?1,?2,?3,?4,?5,'accepted',2,?6,?7,?8,?8,1,?9,NULL)",
                    params![
                        binding_id,
                        profile_id,
                        person_id,
                        binding_evidence_count,
                        f64::from(evidence.confidence_millionths) / 1_000_000.0,
                        json!({
                            "kind": "audio_self_identification",
                            "identity_evidence_id": evidence.evidence_id,
                            "speaker_observation_id": observation_id,
                        })
                        .to_string(),
                        supersedes_binding_id,
                        committed_at,
                        format!("adr0022:self-identification:{}", evidence.evidence_id),
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            for fact in facts {
                if let Some(previous) = fact.supersedes_id {
                    transaction
                        .execute(
                            "UPDATE person_facts SET status='superseded'
                             WHERE id=?1 AND person_id=?2 AND status='active'",
                            params![previous, person_id],
                        )
                        .map_err(|_| WalIdempotencyError::Unavailable)
                        .and_then(require_one)?;
                }
                transaction
                    .execute(
                        "INSERT INTO person_facts
                         (id,person_id,predicate,value,evidence_json,derivation_version,status,
                          supersedes_id,source_event_id,speaker_observation_id,observed_at,
                          literal_evidence,confidence,created_at)
                         VALUES (?1,?2,?3,?4,?5,2,'active',?6,?7,?8,?9,?10,?11,?12)",
                        params![
                            fact.id,
                            person_id,
                            fact.predicate,
                            fact.value,
                            json!({
                                "identity_evidence_id": evidence.evidence_id,
                                "literal_evidence": fact.literal_evidence,
                            })
                            .to_string(),
                            fact.supersedes_id,
                            evidence.source_event_id,
                            observation_id,
                            evidence.observed_at,
                            fact.literal_evidence,
                            f64::from(evidence.confidence_millionths) / 1_000_000.0,
                            committed_at,
                        ],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)
                    .and_then(require_one)?;
            }
        }
    }
    assert_person_allocator_poststate(transaction, evidence)?;
    assert_person_identity_poststate(transaction, evidence, committed_at)?;
    Ok(())
}

fn apply_proposal_refusal(
    transaction: &Transaction<'_>,
    evidence: &ProposalRefusalEvidence,
    committed_at: &str,
) -> Result<()> {
    transaction
        .execute(
            "UPDATE voice_profile_proposals SET state=?1,updated_at=?2
             WHERE id=?3 AND state=?4",
            params![
                evidence.target_state,
                committed_at,
                evidence.proposal_id,
                evidence.predecessor_state
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
        .and_then(require_one)
}

fn apply_episode_status(
    transaction: &Transaction<'_>,
    evidence: &EpisodeStatusEvidence,
    committed_at: &str,
) -> Result<()> {
    transaction
        .execute(
            "UPDATE episodes SET speaker_processing_status=?1,updated_at=?2
             WHERE id=?3 AND speaker_processing_status=?4",
            params![
                evidence.target_status,
                committed_at,
                evidence.episode_id,
                evidence.predecessor_status
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
        .and_then(require_one)
}

fn assert_reconcile_allocator_poststate(
    connection: &Connection,
    evidence: &ProfileReconcileEvidence,
) -> Result<()> {
    let after = read_allocator_pins(connection)?;
    let mut expected = evidence.pins;
    match &evidence.decision {
        ReconcileDecision::Update(update) => {
            expected.revisions = update.revision_id;
            if !update.representative_exists {
                expected.representatives = update.representative_id;
            }
        }
        ReconcileDecision::Quarantine {
            revision_id: Some(revision_id),
            ..
        } => expected.revisions = *revision_id,
        ReconcileDecision::Quarantine {
            revision_id: None, ..
        } => {}
    }
    (after == expected)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

fn update_sample(
    transaction: &Transaction<'_>,
    sample_id: i64,
    profile_id: Option<i64>,
    accepted: bool,
    outlier: bool,
    similarity: Option<u32>,
    margin: Option<u32>,
) -> Result<()> {
    let similarity = similarity.map(|bits| f64::from(f32::from_bits(bits)));
    let margin = margin.map(|bits| f64::from(f32::from_bits(bits)));
    transaction
        .execute(
            "UPDATE voice_samples SET voice_profile_id=?1,accepted=?2,outlier=?3,
             similarity=?4,decision_margin=?5 WHERE id=?6 AND accepted=-1",
            params![
                profile_id,
                i64::from(accepted),
                i64::from(outlier),
                similarity,
                margin,
                sample_id
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
        .and_then(require_one)
}

fn insert_assignment(
    transaction: &Transaction<'_>,
    assignment_id: i64,
    sample_id: i64,
    profile_id: i64,
    committed_at: &str,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO voice_sample_profile_assignments
             (id,sample_id,profile_id,active,created_at) VALUES (?1,?2,?3,1,?4)",
            params![assignment_id, sample_id, profile_id, committed_at],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)
        .and_then(require_one)
}

fn upsert_representative(
    transaction: &Transaction<'_>,
    update: &ProfileUpdate,
    profile_id: i64,
    committed_at: &str,
) -> Result<()> {
    if update.representative_exists {
        transaction
            .execute(
                "UPDATE voice_profile_representatives SET centroid=?1,sample_count=?2,
                 medoid_sample_id=?3,scorer_version=?4,updated_at=?5
                 WHERE id=?6 AND profile_id=?7",
                params![
                    update.centroid,
                    update.sample_count,
                    update.medoid_sample_id,
                    voice_quality::SCORER_VERSION,
                    committed_at,
                    update.representative_id,
                    profile_id
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)
            .and_then(require_one)
    } else {
        transaction
            .execute(
                "INSERT INTO voice_profile_representatives
                 (id,profile_id,channel_domain,centroid,sample_count,medoid_sample_id,
                  scorer_version,created_at,updated_at)
                 SELECT ?1,id,channel_domain,?2,?3,?4,?5,?6,?6
                 FROM voice_profiles WHERE id=?7",
                params![
                    update.representative_id,
                    update.centroid,
                    update.sample_count,
                    update.medoid_sample_id,
                    voice_quality::SCORER_VERSION,
                    committed_at,
                    profile_id
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)
            .and_then(require_one)
    }
}

fn profile_backfill_snapshot(connection: &Connection, profile_id: i64) -> Result<[u8; 32]> {
    digest_queries(
        connection,
        &[
            (
                b"profile".as_slice(),
                "SELECT id,person_id,embedding_space,channel_domain,centroid,sample_count,
                        scorer_version,representative_kind,medoid_sample_id,status,
                        created_at,updated_at
                 FROM voice_profiles WHERE id=?1 ORDER BY id",
                vec![SqlArg::Integer(profile_id)],
            ),
            (
                b"revisions".as_slice(),
                "SELECT id,profile_id,status,active,created_at
                 FROM voice_profile_revisions WHERE profile_id=?1 ORDER BY id",
                vec![SqlArg::Integer(profile_id)],
            ),
        ],
    )
}

fn assignment_backfill_snapshot(
    connection: &Connection,
    sample_id: i64,
    profile_id: i64,
) -> Result<[u8; 32]> {
    digest_queries(
        connection,
        &[
            (
                b"sample".as_slice(),
                "SELECT id,voice_profile_id,accepted,outlier,similarity,decision_margin,created_at
                 FROM voice_samples WHERE id=?1 ORDER BY id",
                vec![SqlArg::Integer(sample_id)],
            ),
            (
                b"profile".as_slice(),
                "SELECT id,status FROM voice_profiles WHERE id=?1 ORDER BY id",
                vec![SqlArg::Integer(profile_id)],
            ),
            (
                b"assignments".as_slice(),
                "SELECT id,sample_id,profile_id,active
                 FROM voice_sample_profile_assignments WHERE sample_id=?1 ORDER BY id",
                vec![SqlArg::Integer(sample_id)],
            ),
        ],
    )
}

fn sample_assignment_snapshot(
    connection: &Connection,
    sample: &PendingSample,
    decision: &AssignmentDecision,
) -> Result<[u8; 32]> {
    let target_profile = match decision {
        AssignmentDecision::Existing { profile_id, .. } => *profile_id,
        AssignmentDecision::Reject { .. } | AssignmentDecision::New { .. } => -1,
    };
    digest_queries(
        connection,
        &[
            (
                b"sample".as_slice(),
                "SELECT id,speaker_observation_id,voice_profile_id,embedding_space,
                        channel_domain,embedding,scorer_version,eligibility,outlier,
                        similarity,decision_margin,accepted,embedding_job_id,created_at
                 FROM voice_samples WHERE id=?1 ORDER BY id",
                vec![SqlArg::Integer(sample.id)],
            ),
            (
                b"observation".as_slice(),
                "SELECT id,person_id FROM speaker_observations WHERE id=?1 ORDER BY id",
                vec![SqlArg::Integer(sample.observation_id)],
            ),
            (
                b"profiles".as_slice(),
                "SELECT profile.id,profile.person_id,profile.embedding_space,
                        profile.channel_domain,profile.centroid,profile.scorer_version,
                        profile.status,profile.created_at,profile.updated_at
                 FROM voice_profiles profile
                 WHERE profile.embedding_space=?1 AND profile.channel_domain=?2
                   AND profile.scorer_version=?3 AND profile.status<>'quarantined'
                   AND NOT EXISTS (
                     SELECT 1 FROM voice_profile_revisions terminal
                     WHERE terminal.profile_id=profile.id AND terminal.active=1
                       AND terminal.status IN ('quarantined','superseded','split'))
                 ORDER BY id LIMIT 33",
                vec![
                    SqlArg::Text(sample.embedding_space.clone()),
                    SqlArg::Text(sample.channel_domain.clone()),
                    SqlArg::Integer(sample.scorer_version),
                ],
            ),
            (
                b"revisions".as_slice(),
                "SELECT revision.id,revision.profile_id,revision.status,
                        revision.active,revision.created_at
                 FROM voice_profile_revisions revision
                 JOIN voice_profiles profile ON profile.id=revision.profile_id
                 WHERE profile.embedding_space=?1 AND profile.channel_domain=?2
                   AND profile.scorer_version=?3 AND profile.status<>'quarantined'
                   AND revision.active=1
                   AND revision.status NOT IN ('quarantined','superseded','split')
                 ORDER BY profile.id LIMIT 33",
                vec![
                    SqlArg::Text(sample.embedding_space.clone()),
                    SqlArg::Text(sample.channel_domain.clone()),
                    SqlArg::Integer(sample.scorer_version),
                ],
            ),
            (
                b"profile_samples".as_slice(),
                "SELECT assignment.id,assignment.sample_id,assignment.profile_id,assignment.active,
                        member.id,member.channel_domain,member.embedding,member.scorer_version,
                        member.eligibility,member.outlier,member.accepted,member.created_at
                 FROM voice_sample_profile_assignments assignment
                 JOIN voice_samples member ON member.id=assignment.sample_id
                 WHERE assignment.profile_id=?1 AND assignment.active=1
                   AND member.accepted=1 AND member.eligibility='enroll'
                   AND member.outlier=0 AND member.scorer_version=?2
                 ORDER BY member.id LIMIT 101",
                vec![
                    SqlArg::Integer(target_profile),
                    SqlArg::Integer(voice_quality::SCORER_VERSION),
                ],
            ),
            (
                b"representatives".as_slice(),
                "SELECT id,profile_id,channel_domain,scorer_version,created_at,updated_at
                 FROM voice_profile_representatives
                 WHERE profile_id=?1 ORDER BY id LIMIT 33",
                vec![SqlArg::Integer(target_profile)],
            ),
            (
                b"embedding_job".as_slice(),
                "SELECT id,speaker_observation_id,state,updated_at
                 FROM voice_embedding_jobs WHERE id=?1 ORDER BY id",
                vec![SqlArg::Integer(sample.embedding_job_id.unwrap_or(-1))],
            ),
        ],
    )
}

fn person_identity_snapshot(
    connection: &Connection,
    evidence_id: i64,
    observation_id: i64,
    profile_id: i64,
) -> Result<[u8; 32]> {
    digest_queries(
        connection,
        &[
            (
                b"identity".as_slice(),
                "SELECT id,person_id,voice_profile_id,source_event_id,observed_at,
                        speaker_observation_id,speaker_cluster_id,kind,claimed_name,
                        CASE WHEN length(CAST(evidence_json AS BLOB))<=?2
                             THEN evidence_json END,
                        length(CAST(evidence_json AS BLOB)),score,status,created_at
                 FROM identity_evidence WHERE id=?1 ORDER BY id",
                vec![
                    SqlArg::Integer(evidence_id),
                    SqlArg::Integer(MAX_TEXT_BYTES as i64),
                ],
            ),
            (
                b"observation".as_slice(),
                "SELECT id,person_id,event_id,turn_id,speaker_local_id,started_at,ended_at,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),1,8192) END,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),8193,8192) END,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),16385,8192) END,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),24577,8192) END,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),32769,8192) END,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),40961,8192) END,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),49153,8192) END,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),57345,8192) END,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),65537,8192) END,
                        CASE WHEN length(CAST(transcript_text AS BLOB))<=?2
                             THEN substr(CAST(transcript_text AS BLOB),73729,8192) END,
                        length(CAST(transcript_text AS BLOB)),language,overlap,
                        voice_eligibility,
                        CASE WHEN length(CAST(voice_diagnostics_json AS BLOB))<=?3
                             THEN voice_diagnostics_json END,
                        length(CAST(voice_diagnostics_json AS BLOB)),cluster_id,
                        direct_evidence_id
                 FROM speaker_observations WHERE id=?1 ORDER BY id",
                vec![
                    SqlArg::Integer(observation_id),
                    SqlArg::Integer(MAX_TRANSCRIPT_BYTES as i64),
                    SqlArg::Integer(MAX_TEXT_BYTES as i64),
                ],
            ),
            (
                b"sources".as_slice(),
                "SELECT speaker_observation_id,event_id,window_start_ms,window_end_ms,
                        event_start_ms,event_end_ms
                 FROM speaker_observation_sources
                 WHERE speaker_observation_id=?1
                 ORDER BY event_id,window_start_ms LIMIT 129",
                vec![SqlArg::Integer(observation_id)],
            ),
            (
                b"samples".as_slice(),
                "SELECT sample.id,sample.speaker_observation_id,sample.voice_profile_id,
                        sample.embedding_space,sample.channel_domain,
                        CASE WHEN length(sample.embedding)<=?2 THEN sample.embedding END,
                        length(sample.embedding),sample.quality_score,
                        CASE WHEN length(CAST(sample.diagnostics_json AS BLOB))<=?3
                             THEN sample.diagnostics_json END,
                        length(CAST(sample.diagnostics_json AS BLOB)),sample.quality_version,
                        sample.scorer_version,sample.eligibility,sample.duration_ms,
                        sample.speech_ratio,sample.snr_proxy_db,sample.clipping_ratio,
                        sample.silence_ratio,sample.embedding_norm,sample.outlier,
                        sample.similarity,sample.decision_margin,sample.accepted,
                        sample.embedding_job_id,sample.created_at
                 FROM voice_samples sample
                 WHERE sample.speaker_observation_id=?1
                 ORDER BY sample.id LIMIT 129",
                vec![
                    SqlArg::Integer(observation_id),
                    SqlArg::Integer(MAX_EMBEDDING_BYTES as i64),
                    SqlArg::Integer(MAX_TEXT_BYTES as i64),
                ],
            ),
            (
                b"assignments".as_slice(),
                "SELECT assignment.id,assignment.sample_id,assignment.profile_id,
                        assignment.proposal_id,assignment.predecessor_assignment_id,
                        assignment.active,assignment.created_at
                 FROM voice_sample_profile_assignments assignment
                 JOIN voice_samples sample ON sample.id=assignment.sample_id
                 WHERE sample.speaker_observation_id=?1 AND assignment.active=1
                 ORDER BY assignment.id LIMIT 129",
                vec![SqlArg::Integer(observation_id)],
            ),
            (
                b"profile".as_slice(),
                "SELECT id,person_id,label,embedding_space,channel_domain,
                        CASE WHEN length(centroid)<=?2 THEN centroid END,length(centroid),
                        sample_count,scorer_version,representative_kind,medoid_sample_id,
                        status,created_at,updated_at
                 FROM voice_profiles WHERE id=?1 ORDER BY id",
                vec![
                    SqlArg::Integer(profile_id),
                    SqlArg::Integer(MAX_EMBEDDING_BYTES as i64),
                ],
            ),
            (
                b"revisions".as_slice(),
                "SELECT id,profile_id,status,derivation_version,scorer_version,
                        representative_kind,
                        CASE WHEN length(centroid)<=?2 THEN centroid END,length(centroid),
                        sample_count,medoid_sample_id,person_id,proposal_id,
                        predecessor_revision_id,reason_code,active,created_at
                 FROM voice_profile_revisions
                 WHERE profile_id=?1 AND active=1 ORDER BY id LIMIT 2",
                vec![
                    SqlArg::Integer(profile_id),
                    SqlArg::Integer(MAX_EMBEDDING_BYTES as i64),
                ],
            ),
            (
                b"people".as_slice(),
                "SELECT person.id,person.display_name,person.normalized_name,person.status,
                        person.created_at,person.updated_at,person.kind
                 FROM people person JOIN voice_profiles profile ON profile.person_id=person.id
                 WHERE profile.id=?1 ORDER BY person.id",
                vec![SqlArg::Integer(profile_id)],
            ),
            (
                b"claims".as_slice(),
                "SELECT claim.id,claim.person_id,claim.name,claim.normalized_name,
                        claim.normalized_email,
                        claim.source_event_id,claim.speaker_observation_id,claim.observed_at,
                        claim.evidence_kind,claim.evidence_json,claim.confidence,claim.status,
                        claim.supersedes_id,claim.created_at
                 FROM person_name_claims claim
                 JOIN voice_profiles profile ON profile.person_id=claim.person_id
                 WHERE profile.id=?1 AND claim.status='accepted'
                 ORDER BY claim.id LIMIT 101",
                vec![SqlArg::Integer(profile_id)],
            ),
            (
                b"facts".as_slice(),
                "SELECT fact.id,fact.person_id,fact.predicate,fact.value,fact.evidence_json,
                        fact.derivation_version,fact.status,
                        fact.supersedes_id,fact.source_event_id,fact.speaker_observation_id,
                        fact.observed_at,fact.literal_evidence,fact.confidence,
                        fact.conflicts_with_id,fact.created_at
                 FROM person_facts fact
                 JOIN voice_profiles profile ON profile.person_id=fact.person_id
                 WHERE profile.id=?1 AND fact.status='active'
                 ORDER BY fact.id LIMIT 101",
                vec![SqlArg::Integer(profile_id)],
            ),
            (
                b"bindings".as_slice(),
                "SELECT id,voice_profile_id,person_id,evidence_count,confidence,state,
                        derivation_version,evidence_json,supersedes_id,created_at,updated_at,
                        active,operation_id,conflicts_with_id
                 FROM profile_identity_bindings
                 WHERE voice_profile_id=?1 AND active=1
                 ORDER BY id LIMIT 2",
                vec![SqlArg::Integer(profile_id)],
            ),
            (
                b"clusters".as_slice(),
                "SELECT cluster.id,cluster.work_unit_id,cluster.speaker_local_id,
                        cluster.voice_profile_id,cluster.person_id,
                        cluster.attribution_state,cluster.created_at,cluster.updated_at
                 FROM speaker_clusters cluster JOIN speaker_observations observation
                   ON observation.cluster_id=cluster.id
                 WHERE observation.id=?1 ORDER BY cluster.id",
                vec![SqlArg::Integer(observation_id)],
            ),
        ],
    )
}

#[derive(Clone)]
enum SqlArg {
    Integer(i64),
    Text(String),
}

fn digest_queries(
    connection: &Connection,
    queries: &[(&[u8], &str, Vec<SqlArg>)],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"kioku:voice-profile-evidence:v1\0");
    let mut total_rows = 0_usize;
    let mut total_bytes = 0_usize;
    for (label, sql, args) in queries {
        hasher.update((label.len() as u32).to_be_bytes());
        hasher.update(label);
        let mut statement = connection
            .prepare(sql)
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let values = args
            .iter()
            .map(|arg| match arg {
                SqlArg::Integer(value) => rusqlite::types::Value::Integer(*value),
                SqlArg::Text(value) => rusqlite::types::Value::Text(value.clone()),
            })
            .collect::<Vec<_>>();
        let mut rows = statement
            .query(rusqlite::params_from_iter(values))
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let mut query_rows = 0_u32;
        while let Some(row) = rows.next().map_err(|_| WalIdempotencyError::Unavailable)? {
            total_rows = total_rows
                .checked_add(1)
                .ok_or(WalIdempotencyError::Limit)?;
            if total_rows > 4_096 {
                return Err(WalIdempotencyError::Limit);
            }
            query_rows = query_rows
                .checked_add(1)
                .ok_or(WalIdempotencyError::Limit)?;
            hasher.update(query_rows.to_be_bytes());
            for index in 0..row.as_ref().column_count() {
                let value = row
                    .get_ref(index)
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                hash_value(&mut hasher, value, &mut total_bytes)?;
            }
        }
        hasher.update(query_rows.to_be_bytes());
    }
    Ok(hasher.finalize().into())
}

fn hash_value(hasher: &mut Sha256, value: ValueRef<'_>, total_bytes: &mut usize) -> Result<()> {
    match value {
        ValueRef::Null => hasher.update([0]),
        ValueRef::Integer(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        ValueRef::Real(value) => {
            hasher.update([2]);
            hasher.update(value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => {
            *total_bytes = total_bytes
                .checked_add(value.len())
                .ok_or(WalIdempotencyError::Limit)?;
            if value.len() > MAX_TEXT_BYTES || *total_bytes > 4 * 1024 * 1024 {
                return Err(WalIdempotencyError::Limit);
            }
            hasher.update([3]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        ValueRef::Blob(value) => {
            *total_bytes = total_bytes
                .checked_add(value.len())
                .ok_or(WalIdempotencyError::Limit)?;
            if value.len() > MAX_TEXT_BYTES || *total_bytes > 4 * 1024 * 1024 {
                return Err(WalIdempotencyError::Limit);
            }
            hasher.update([4]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
    }
    Ok(())
}

fn read_allocator_pins(connection: &Connection) -> Result<AllocatorPins> {
    Ok(AllocatorPins {
        profiles: read_allocator_pin(connection, "voice_profiles")?,
        revisions: read_allocator_pin(connection, "voice_profile_revisions")?,
        assignments: read_allocator_pin(connection, "voice_sample_profile_assignments")?,
        representatives: read_allocator_pin(connection, "voice_profile_representatives")?,
    })
}

fn read_person_allocator_pins(connection: &Connection) -> Result<PersonAllocatorPins> {
    for table in [
        "people",
        "person_name_claims",
        "person_facts",
        "profile_identity_bindings",
    ] {
        let sql = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .ok_or(WalIdempotencyError::Unavailable)?;
        if !sql.to_ascii_uppercase().contains("AUTOINCREMENT") {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    Ok(PersonAllocatorPins {
        people: read_allocator_pin(connection, "people")?,
        name_claims: read_allocator_pin(connection, "person_name_claims")?,
        facts: read_allocator_pin(connection, "person_facts")?,
        bindings: read_allocator_pin(connection, "profile_identity_bindings")?,
    })
}

fn read_allocator_pin(connection: &Connection, table: &str) -> Result<i64> {
    let value = connection
        .query_row(
            "SELECT typeof(seq),CAST(seq AS TEXT) FROM sqlite_sequence WHERE name=?1",
            [table],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match value {
        None => Ok(0),
        Some((kind, value)) if kind == "integer" => Ok(value
            .parse::<i64>()
            .ok()
            .filter(|value| *value >= 0)
            .unwrap_or(i64::MAX)),
        Some(_) => Ok(i64::MAX),
    }
}

fn assert_allocator_poststate(
    connection: &Connection,
    before: AllocatorPins,
    decision: &AssignmentDecision,
) -> Result<()> {
    let after = read_allocator_pins(connection)?;
    let mut expected = before;
    match decision {
        AssignmentDecision::Reject { .. } => {}
        AssignmentDecision::Existing { update, .. } => {
            expected.assignments = before.next_assignment().ok_or(WalIdempotencyError::Limit)?;
            if let Some(update) = update {
                expected.revisions = update.revision_id;
                if !update.representative_exists {
                    expected.representatives = update.representative_id;
                }
            }
        }
        AssignmentDecision::New {
            profile_id,
            assignment_id,
            revision_id,
            representative_id,
            ..
        } => {
            expected.profiles = *profile_id;
            expected.assignments = *assignment_id;
            expected.revisions = *revision_id;
            expected.representatives = *representative_id;
        }
    }
    (after == expected)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

fn assert_person_allocator_poststate(
    connection: &Connection,
    evidence: &PersonIdentityEvidence,
) -> Result<()> {
    let after = read_person_allocator_pins(connection)?;
    let mut expected = evidence.pins;
    match &evidence.decision {
        PersonIdentityDecision::Reject => {}
        PersonIdentityDecision::Bind {
            person_id,
            create_person,
            name_claim_id,
            binding_id,
            facts,
            ..
        } => {
            if *create_person {
                expected.people = *person_id;
            }
            expected.name_claims = *name_claim_id;
            if let Some(fact) = facts.last() {
                expected.facts = fact.id;
            }
            expected.bindings = *binding_id;
        }
    }
    (after == expected)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

fn assert_person_identity_poststate(
    connection: &Connection,
    evidence: &PersonIdentityEvidence,
    committed_at: &str,
) -> Result<()> {
    match &evidence.decision {
        PersonIdentityDecision::Reject => {
            let rejected = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM identity_evidence
                     WHERE id=?1 AND person_id IS NULL
                       AND kind='audio_self_identification' AND status='rejected')",
                    [evidence.evidence_id],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            rejected.then_some(()).ok_or(WalIdempotencyError::Corrupt)
        }
        PersonIdentityDecision::Bind {
            person_id,
            create_person,
            name_claim_id,
            binding_id,
            supersedes_binding_id,
            binding_evidence_count,
            profile_id,
            active_revision_id,
            observation_id,
            cluster_id,
            normalized_name,
            facts,
            ..
        } => {
            let confidence = f64::from(evidence.confidence_millionths) / 1_000_000.0;
            let exact_identity = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM identity_evidence
                     WHERE id=?1 AND person_id=?2 AND voice_profile_id=?3
                       AND speaker_observation_id=?4 AND speaker_cluster_id=?5
                       AND source_event_id=?6 AND observed_at=?7
                       AND kind='audio_self_identification' AND claimed_name=?8
                       AND evidence_json=?9 AND score=?10 AND status='accepted')",
                    params![
                        evidence.evidence_id,
                        person_id,
                        profile_id,
                        observation_id,
                        cluster_id,
                        evidence.source_event_id,
                        evidence.observed_at,
                        evidence.claimed_name,
                        evidence.evidence_json,
                        confidence,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let exact_observation = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM speaker_observations
                     WHERE id=?1 AND person_id=?2 AND direct_evidence_id=?3 AND cluster_id=?4)",
                    params![observation_id, person_id, evidence.evidence_id, cluster_id],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let exact_cluster = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM speaker_clusters
                     WHERE id=?1 AND person_id=?2 AND voice_profile_id=?3
                       AND attribution_state='person_bound' AND updated_at=?4)",
                    params![cluster_id, person_id, profile_id, committed_at],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let exact_profile = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM voice_profiles
                     WHERE id=?1 AND person_id=?2 AND updated_at=?3 AND status<>'quarantined')",
                    params![profile_id, person_id, committed_at],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let exact_revision = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM voice_profile_revisions
                     WHERE id=?1 AND profile_id=?2 AND person_id=?3 AND active=1)",
                    params![active_revision_id, profile_id, person_id],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let exact_person = if *create_person {
                connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM people
                         WHERE id=?1 AND display_name=?2 AND normalized_name IS NULL
                           AND status='identified' AND kind='person'
                           AND created_at=?3 AND updated_at=?3)",
                        params![person_id, evidence.claimed_name.trim(), committed_at],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?
            } else {
                connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM people
                         WHERE id=?1 AND status='identified')",
                        [person_id],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?
            };
            let exact_name = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM person_name_claims
                     WHERE id=?1 AND person_id=?2 AND name=?3 AND normalized_name=?4
                       AND normalized_email IS NULL AND source_event_id=?5
                       AND speaker_observation_id=?6 AND observed_at=?7
                       AND evidence_kind='audio_self_identification' AND evidence_json=?8
                       AND confidence=?9 AND status='accepted' AND supersedes_id IS NULL
                       AND created_at=?10)",
                    params![
                        name_claim_id,
                        person_id,
                        evidence.claimed_name.trim(),
                        normalized_name,
                        evidence.source_event_id,
                        observation_id,
                        evidence.observed_at,
                        evidence.evidence_json,
                        confidence,
                        committed_at,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let operation_id = format!("adr0022:self-identification:{}", evidence.evidence_id);
            let binding_json = json!({
                "kind": "audio_self_identification",
                "identity_evidence_id": evidence.evidence_id,
                "speaker_observation_id": observation_id,
            })
            .to_string();
            let exact_binding = connection
                .query_row(
                    "SELECT person_id,evidence_count,confidence,state,derivation_version,
                            evidence_json,supersedes_id,created_at,updated_at,active,
                            operation_id,conflicts_with_id
                     FROM profile_identity_bindings
                     WHERE id=?1 AND voice_profile_id=?2",
                    params![binding_id, profile_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, f64>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, Option<i64>>(6)?,
                            row.get::<_, String>(7)?,
                            row.get::<_, String>(8)?,
                            row.get::<_, i64>(9)?,
                            row.get::<_, Option<String>>(10)?,
                            row.get::<_, Option<i64>>(11)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| WalIdempotencyError::Unavailable)?
                .is_some_and(
                    |(
                        person,
                        count,
                        stored_confidence,
                        state,
                        derivation,
                        stored_json,
                        supersedes,
                        created,
                        updated,
                        active,
                        operation,
                        conflicts,
                    )| {
                        person == *person_id
                            && count == *binding_evidence_count
                            && stored_confidence.to_bits() == confidence.to_bits()
                            && state == "accepted"
                            && derivation == 2
                            && stored_json == binding_json
                            && supersedes == *supersedes_binding_id
                            && created == committed_at
                            && updated == committed_at
                            && active == 1
                            && operation.as_deref() == Some(operation_id.as_str())
                            && conflicts.is_none()
                    },
                );
            let one_active_binding = connection
                .query_row(
                    "SELECT COUNT(*)=1 FROM profile_identity_bindings
                     WHERE voice_profile_id=?1 AND active=1 AND state='accepted'
                       AND id=?2 AND person_id=?3",
                    params![profile_id, binding_id, person_id],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            let predecessor_inactive = match supersedes_binding_id {
                None => true,
                Some(previous) => connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM profile_identity_bindings
                         WHERE id=?1 AND active=0)",
                        [previous],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?,
            };
            let exact_facts = facts.iter().try_fold(true, |all_exact, fact| {
                let exact = connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM person_facts
                         WHERE id=?1 AND person_id=?2 AND predicate=?3 AND value=?4
                           AND evidence_json=?5 AND derivation_version=2
                           AND status='active' AND supersedes_id IS ?6
                           AND source_event_id=?7 AND speaker_observation_id=?8
                           AND observed_at=?9 AND literal_evidence=?10 AND confidence=?11
                           AND conflicts_with_id IS NULL AND created_at=?12)",
                        params![
                            fact.id,
                            person_id,
                            fact.predicate,
                            fact.value,
                            json!({
                                "identity_evidence_id": evidence.evidence_id,
                                "literal_evidence": fact.literal_evidence,
                            })
                            .to_string(),
                            fact.supersedes_id,
                            evidence.source_event_id,
                            observation_id,
                            evidence.observed_at,
                            fact.literal_evidence,
                            confidence,
                            committed_at,
                        ],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                Ok::<bool, WalIdempotencyError>(all_exact && exact)
            })?;
            (exact_identity
                && exact_observation
                && exact_cluster
                && exact_profile
                && exact_revision
                && exact_person
                && exact_name
                && exact_binding
                && one_active_binding
                && predecessor_inactive
                && exact_facts)
                .then_some(())
                .ok_or(WalIdempotencyError::Corrupt)
        }
    }
}

fn ensure_source_schema(connection: &Connection) -> Result<()> {
    for table in [
        "voice_profiles",
        "voice_profile_revisions",
        "voice_sample_profile_assignments",
        "voice_profile_representatives",
    ] {
        let sql = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?
            .ok_or(WalIdempotencyError::Unavailable)?;
        if !sql.to_ascii_uppercase().contains("AUTOINCREMENT") {
            return Err(WalIdempotencyError::Precondition);
        }
    }
    Ok(())
}

fn validate_evidence(evidence: &VoiceProfileEvidence) -> Result<()> {
    crate::store::validate_user_id(&evidence.account_id)
        .map_err(|_| WalIdempotencyError::Malformed)?;
    validate_timestamp(&evidence.observed_at)?;
    let id = evidence.work.stable_id();
    if id <= 0 || evidence.work.snapshot() == [0; 32] {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    valid_timestamp(value)
        .then_some(())
        .ok_or(WalIdempotencyError::Malformed)
}

fn valid_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TIMESTAMP_BYTES
        && isotime::parse_epoch_millis(value)
            .is_some_and(|millis| isotime::format_epoch_millis(millis) == value)
}

fn timestamp_after(value: &str, horizon: &str) -> bool {
    valid_timestamp(value) && value > horizon
}

fn decode_embedding(value: &[u8]) -> Option<Vec<f32>> {
    if value.len() != MAX_EMBEDDING_BYTES {
        return None;
    }
    let vector = value
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect::<Vec<_>>();
    vector
        .iter()
        .all(|value| value.is_finite())
        .then_some(vector)
}

fn encode_embedding(value: &[f32]) -> Vec<u8> {
    value.iter().flat_map(|value| value.to_le_bytes()).collect()
}

fn require_one(changed: usize) -> Result<()> {
    (changed == 1)
        .then_some(())
        .ok_or(WalIdempotencyError::Precondition)
}

fn encode_work(output: &mut Vec<u8>, work: &WorkEvidence) -> Result<()> {
    output.extend_from_slice(work.subtype());
    output.extend_from_slice(&work.stable_id().to_be_bytes());
    output.extend_from_slice(&work.snapshot());
    match work {
        WorkEvidence::ProfileBackfill(value) => {
            encode_pins(output, value.pins);
            match value.disposition {
                BackfillDisposition::Insert { revision_id } => {
                    output.push(1);
                    output.extend_from_slice(&revision_id.to_be_bytes());
                }
                BackfillDisposition::Quarantine => output.push(2),
            }
        }
        WorkEvidence::AssignmentBackfill(value) => {
            encode_pins(output, value.pins);
            output.extend_from_slice(&value.profile_id.to_be_bytes());
            encode_optional_i64(output, value.assignment_id);
        }
        WorkEvidence::SampleAssignment(value) => {
            encode_pins(output, value.pins);
            encode_decision(output, &value.decision)?;
        }
        WorkEvidence::ProfileReconcile(value) => {
            encode_pins(output, value.pins);
            encode_reconcile_decision(output, &value.decision)?;
        }
        WorkEvidence::PersonIdentity(value) => {
            encode_person_pins(output, value.pins);
            encode_string(output, &value.claimed_name)?;
            encode_string(output, &value.evidence_json)?;
            output.extend_from_slice(&value.confidence_millionths.to_be_bytes());
            encode_string(output, &value.source_event_id)?;
            encode_string(output, &value.observed_at)?;
            encode_person_identity_decision(output, &value.decision)?;
        }
        WorkEvidence::ProposalRefusal(value) => {
            encode_string(output, &value.predecessor_state)?;
            encode_string(output, &value.target_state)?;
        }
        WorkEvidence::EpisodeStatus(value) => {
            encode_string(output, &value.predecessor_status)?;
            encode_string(output, &value.target_status)?;
        }
    }
    Ok(())
}

fn encode_pins(output: &mut Vec<u8>, pins: AllocatorPins) {
    output.extend_from_slice(&pins.profiles.to_be_bytes());
    output.extend_from_slice(&pins.revisions.to_be_bytes());
    output.extend_from_slice(&pins.assignments.to_be_bytes());
    output.extend_from_slice(&pins.representatives.to_be_bytes());
}

fn encode_person_pins(output: &mut Vec<u8>, pins: PersonAllocatorPins) {
    output.extend_from_slice(&pins.people.to_be_bytes());
    output.extend_from_slice(&pins.name_claims.to_be_bytes());
    output.extend_from_slice(&pins.facts.to_be_bytes());
    output.extend_from_slice(&pins.bindings.to_be_bytes());
}

fn encode_person_identity_decision(
    output: &mut Vec<u8>,
    decision: &PersonIdentityDecision,
) -> Result<()> {
    match decision {
        PersonIdentityDecision::Reject => output.push(0),
        PersonIdentityDecision::Bind {
            person_id,
            create_person,
            name_claim_id,
            binding_id,
            supersedes_binding_id,
            binding_evidence_count,
            profile_id,
            active_revision_id,
            observation_id,
            cluster_id,
            normalized_name,
            facts,
        } => {
            output.push(1);
            output.extend_from_slice(&person_id.to_be_bytes());
            output.push(u8::from(*create_person));
            output.extend_from_slice(&name_claim_id.to_be_bytes());
            output.extend_from_slice(&binding_id.to_be_bytes());
            encode_optional_i64(output, *supersedes_binding_id);
            output.extend_from_slice(&binding_evidence_count.to_be_bytes());
            output.extend_from_slice(&profile_id.to_be_bytes());
            output.extend_from_slice(&active_revision_id.to_be_bytes());
            output.extend_from_slice(&observation_id.to_be_bytes());
            output.extend_from_slice(&cluster_id.to_be_bytes());
            encode_string(output, normalized_name)?;
            let count = u32::try_from(facts.len()).map_err(|_| WalIdempotencyError::Limit)?;
            output.extend_from_slice(&count.to_be_bytes());
            for fact in facts {
                output.extend_from_slice(&fact.id.to_be_bytes());
                encode_string(output, &fact.predicate)?;
                encode_string(output, &fact.value)?;
                encode_string(output, &fact.literal_evidence)?;
                encode_optional_i64(output, fact.supersedes_id);
            }
        }
    }
    Ok(())
}

fn encode_decision(output: &mut Vec<u8>, decision: &AssignmentDecision) -> Result<()> {
    match decision {
        AssignmentDecision::Reject { similarity, margin } => {
            output.push(0);
            encode_optional_u32(output, *similarity);
            encode_optional_u32(output, *margin);
        }
        AssignmentDecision::Existing {
            profile_id,
            assignment_id,
            accepted,
            outlier,
            similarity,
            margin,
            update,
        } => {
            output.push(1);
            output.extend_from_slice(&profile_id.to_be_bytes());
            output.extend_from_slice(&assignment_id.to_be_bytes());
            output.push(u8::from(*accepted));
            output.push(u8::from(*outlier));
            output.extend_from_slice(&similarity.to_be_bytes());
            output.extend_from_slice(&margin.to_be_bytes());
            match update {
                None => output.push(0),
                Some(update) => {
                    output.push(1);
                    encode_bytes(output, &update.centroid)?;
                    output.extend_from_slice(&update.sample_count.to_be_bytes());
                    output.extend_from_slice(&update.medoid_sample_id.to_be_bytes());
                    encode_string(output, &update.status)?;
                    output.extend_from_slice(&update.revision_id.to_be_bytes());
                    output.extend_from_slice(&update.predecessor_revision_id.to_be_bytes());
                    output.extend_from_slice(&update.representative_id.to_be_bytes());
                    output.push(u8::from(update.representative_exists));
                }
            }
        }
        AssignmentDecision::New {
            profile_id,
            assignment_id,
            revision_id,
            representative_id,
            person_id,
            centroid,
        } => {
            output.push(2);
            output.extend_from_slice(&profile_id.to_be_bytes());
            output.extend_from_slice(&assignment_id.to_be_bytes());
            output.extend_from_slice(&revision_id.to_be_bytes());
            output.extend_from_slice(&representative_id.to_be_bytes());
            encode_optional_i64(output, *person_id);
            encode_bytes(output, centroid)?;
        }
    }
    Ok(())
}

fn encode_reconcile_decision(output: &mut Vec<u8>, decision: &ReconcileDecision) -> Result<()> {
    match decision {
        ReconcileDecision::Update(update) => {
            output.push(1);
            encode_profile_update(output, update)?;
        }
        ReconcileDecision::Quarantine {
            revision_id,
            predecessor_revision_id,
        } => {
            output.push(2);
            encode_optional_i64(output, *revision_id);
            output.extend_from_slice(&predecessor_revision_id.to_be_bytes());
        }
    }
    Ok(())
}

fn encode_profile_update(output: &mut Vec<u8>, update: &ProfileUpdate) -> Result<()> {
    encode_bytes(output, &update.centroid)?;
    output.extend_from_slice(&update.sample_count.to_be_bytes());
    output.extend_from_slice(&update.medoid_sample_id.to_be_bytes());
    encode_string(output, &update.status)?;
    output.extend_from_slice(&update.revision_id.to_be_bytes());
    output.extend_from_slice(&update.predecessor_revision_id.to_be_bytes());
    output.extend_from_slice(&update.representative_id.to_be_bytes());
    output.push(u8::from(update.representative_exists));
    Ok(())
}

fn encode_optional_i64(output: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn encode_optional_u32(output: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    encode_bytes(output, value.as_bytes())
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| WalIdempotencyError::Limit)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

impl WalLogicalDomainLedger<VoiceProfilePlan> for VoiceProfileLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<VoiceProfilePlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,result_bytes,
                        result_commitment FROM archive_v3_wal_voice_profile_operations
                 WHERE operation_id=?1",
                [prepared.operation_id_for_owner().as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let Some((format, codec, fingerprint, encoded, commitment)) = row else {
            return Ok(None);
        };
        let kind = WalOperationKind::VoiceProfile;
        if format != i64::from(WalOperationKind::format_version())
            || codec != i64::from(kind.codec_version())
            || fingerprint.as_slice()
                != prepared
                    .request_fingerprint_for_owner()
                    .as_bytes()
                    .as_slice()
            || commitment.len() != 32
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        let result = WalReplayResult::decode(kind, &encoded)?;
        if commitment.as_slice() != result.commitment(kind)?.as_slice() {
            return Err(WalIdempotencyError::Corrupt);
        }
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        Ok(Some(result))
    }

    fn resolve_or_apply(
        transaction: &Transaction<'_>,
        prepared: &PreparedLogicalMutation<VoiceProfilePlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (rows, bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(rows, bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let kind = WalOperationKind::VoiceProfile;
        let encoded = result.encode(kind)?;
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_voice_profile_operations
                 (operation_id,format_version,codec_version,request_fingerprint,result_bytes,
                  result_commitment) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    prepared.operation_id_for_owner().as_bytes().as_slice(),
                    i64::from(WalOperationKind::format_version()),
                    i64::from(kind.codec_version()),
                    prepared
                        .request_fingerprint_for_owner()
                        .as_bytes()
                        .as_slice(),
                    encoded.as_slice(),
                    commitment.as_slice(),
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)
            .and_then(require_one)?;
        transaction
            .execute(
                "UPDATE archive_v3_wal_voice_profile_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(rows),
                    i64::try_from(bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)
            .and_then(require_one)?;
        let stored = Self::lookup(transaction, prepared)?.ok_or(WalIdempotencyError::Corrupt)?;
        if stored != result {
            return Err(WalIdempotencyError::Corrupt);
        }
        Ok(LogicalMutationResult::Applied(result))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerSchemaState {
    Absent,
    Present,
}

fn require_kind(prepared: &PreparedLogicalMutation<VoiceProfilePlan>) -> Result<()> {
    (prepared.kind_for_owner() == WalOperationKind::VoiceProfile)
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN (?1,?2,?3)",
            params![SCHEMA_TABLE, LEDGER_TABLE, STATE_TABLE],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match count {
        0 => Ok(LedgerSchemaState::Absent),
        3 => Ok(LedgerSchemaState::Present),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn ensure_schema(transaction: &Transaction<'_>) -> Result<()> {
    match schema_state(transaction)? {
        LedgerSchemaState::Present => validate_schema_marker(transaction),
        LedgerSchemaState::Absent => {
            transaction
                .execute_batch(
                    "CREATE TABLE archive_v3_wal_voice_profile_schema (
                       singleton INTEGER PRIMARY KEY CHECK (singleton=1),
                       format_version INTEGER NOT NULL CHECK(format_version>0),
                       codec_version INTEGER NOT NULL CHECK(codec_version>0)
                     );
                     CREATE TABLE archive_v3_wal_voice_profile_operations (
                       operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=16),
                       format_version INTEGER NOT NULL CHECK(format_version>0),
                       codec_version INTEGER NOT NULL CHECK(codec_version>0),
                       request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
                       result_bytes BLOB NOT NULL CHECK(length(result_bytes)=9),
                       result_commitment BLOB NOT NULL CHECK(length(result_commitment)=32)
                     );
                     CREATE TABLE archive_v3_wal_voice_profile_state (
                       singleton INTEGER PRIMARY KEY CHECK (singleton=1),
                       row_count INTEGER NOT NULL CHECK(row_count>=0),
                       result_bytes INTEGER NOT NULL CHECK(result_bytes>=0)
                     );",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            transaction
                .execute(
                    "INSERT INTO archive_v3_wal_voice_profile_schema
                     (singleton,format_version,codec_version) VALUES (1,?1,?2)",
                    params![
                        i64::from(WalOperationKind::format_version()),
                        i64::from(WalOperationKind::VoiceProfile.codec_version())
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            transaction
                .execute(
                    "INSERT INTO archive_v3_wal_voice_profile_state
                     (singleton,row_count,result_bytes) VALUES (1,0,0)",
                    [],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)
                .and_then(require_one)?;
            validate_schema_marker(transaction)
        }
    }
}

fn validate_schema_marker(connection: &Connection) -> Result<()> {
    let marker = connection
        .query_row(
            "SELECT format_version,codec_version FROM archive_v3_wal_voice_profile_schema
             WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    (marker
        == (
            i64::from(WalOperationKind::format_version()),
            i64::from(WalOperationKind::VoiceProfile.codec_version()),
        ))
        .then_some(())
        .ok_or(WalIdempotencyError::Corrupt)
}

fn load_ledger_state(connection: &Connection) -> Result<(u32, u64)> {
    let (rows, bytes) = connection
        .query_row(
            "SELECT row_count,result_bytes FROM archive_v3_wal_voice_profile_state
             WHERE singleton=1 AND typeof(row_count)='integer'
               AND typeof(result_bytes)='integer'",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    Ok((
        u32::try_from(rows).map_err(|_| WalIdempotencyError::Corrupt)?,
        u64::try_from(bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const AT: &str = "2026-08-22T12:00:00.000Z";

    fn fixture() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        crate::cp::media::init_schema(&connection).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        connection
    }

    fn embedding(seed: f32) -> Vec<u8> {
        (0..256)
            .flat_map(|index| {
                let value = if index == 0 { seed } else { 0.0 };
                value.to_le_bytes()
            })
            .collect()
    }

    fn basis_embedding(index: usize) -> Vec<u8> {
        (0..256)
            .flat_map(|candidate| {
                let value = if candidate == index { 1.0_f32 } else { 0.0 };
                value.to_le_bytes()
            })
            .collect()
    }

    fn seed_complete_profile(connection: &Connection, ordinal: i64) {
        let profile_id = 10_000 + ordinal;
        let observation_id = 20_000 + ordinal;
        let sample_id = 30_000 + ordinal;
        let revision_id = 40_000 + ordinal;
        let assignment_id = 50_000 + ordinal;
        let representative_id = 60_000 + ordinal;
        let vector = basis_embedding(usize::try_from(ordinal).unwrap() % 256);
        connection
            .execute(
                "INSERT INTO speaker_observations
                 (id,event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,overlap)
                 VALUES (?1,?2,?3,'speaker','2026-08-22T11:59:55.000Z',
                         '2026-08-22T11:59:56.000Z','bounded',0)",
                params![
                    observation_id,
                    format!("profile-event-{ordinal}"),
                    format!("profile-turn-{ordinal}")
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_samples
                 (id,speaker_observation_id,embedding_space,channel_domain,embedding,
                  quality_score,diagnostics_json,quality_version,scorer_version,eligibility,
                  duration_ms,speech_ratio,snr_proxy_db,clipping_ratio,silence_ratio,
                  embedding_norm,outlier,accepted,created_at)
                 VALUES (?1,?2,?3,'audio:system:microphone',?4,0.9,'{}',1,2,'enroll',
                         4000,0.9,18.0,0.0,0.1,1.0,0,1,'2026-08-22T11:59:57.000Z')",
                params![
                    sample_id,
                    observation_id,
                    voice_memory::EMBEDDING_SPACE,
                    vector
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_profiles
                 (id,label,embedding_space,channel_domain,centroid,sample_count,scorer_version,
                  representative_kind,medoid_sample_id,status,created_at,updated_at)
                 VALUES (?1,?2,?3,'audio:system:microphone',?4,1,2,
                         'medoid_trimmed_centroid',?5,'tentative',?6,?6)",
                params![
                    profile_id,
                    format!("Seeded voice {ordinal}"),
                    voice_memory::EMBEDDING_SPACE,
                    vector,
                    sample_id,
                    "2026-08-22T11:59:57.000Z"
                ],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE voice_samples SET voice_profile_id=?1 WHERE id=?2",
                params![profile_id, sample_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_sample_profile_assignments
                 (id,sample_id,profile_id,active,created_at) VALUES (?1,?2,?3,1,?4)",
                params![
                    assignment_id,
                    sample_id,
                    profile_id,
                    "2026-08-22T11:59:57.000Z"
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_profile_revisions
                 (id,profile_id,status,derivation_version,scorer_version,representative_kind,
                  centroid,sample_count,medoid_sample_id,reason_code,active,created_at)
                 VALUES (?1,?2,'tentative',1,2,'medoid_trimmed_centroid',?3,1,?4,
                         'sample_assigned',1,?5)",
                params![
                    revision_id,
                    profile_id,
                    vector,
                    sample_id,
                    "2026-08-22T11:59:57.000Z"
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_profile_representatives
                 (id,profile_id,channel_domain,centroid,sample_count,medoid_sample_id,
                  scorer_version,created_at,updated_at)
                 VALUES (?1,?2,'audio:system:microphone',?3,1,?4,2,?5,?5)",
                params![
                    representative_id,
                    profile_id,
                    vector,
                    sample_id,
                    "2026-08-22T11:59:57.000Z"
                ],
            )
            .unwrap();
    }

    fn seed_pending(connection: &Connection, id: i64, created_at: &str, seed: f32) {
        connection
            .execute(
                "INSERT INTO speaker_observations
                 (id,event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,overlap)
                 VALUES (?1,?2,?3,'speaker-1','2026-08-22T11:59:55.000Z',
                         '2026-08-22T11:59:56.000Z','bounded transcript',0)",
                params![id, format!("event-{id}"), format!("turn-{id}")],
            )
            .unwrap();
        let job_id = 1_000 + id;
        connection
            .execute(
                "INSERT INTO voice_embedding_jobs
                 (id,speaker_observation_id,embedding_space,processor_version,quality_version,
                  scorer_version,state,attempt_count,created_at,updated_at)
                 VALUES (?1,?2,?3,1,1,2,'ready',1,?4,?4)",
                params![job_id, id, voice_memory::EMBEDDING_SPACE, created_at],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_samples
                 (id,speaker_observation_id,voice_profile_id,embedding_space,channel_domain,
                  embedding,quality_score,diagnostics_json,quality_version,scorer_version,
                  eligibility,duration_ms,speech_ratio,snr_proxy_db,clipping_ratio,silence_ratio,
                  embedding_norm,outlier,similarity,decision_margin,accepted,embedding_job_id,
                  created_at)
                 VALUES (?1,?1,NULL,?2,'audio:system:microphone',?3,0.9,'{}',1,2,
                         'enroll',4000,0.9,18.0,0.0,0.1,1.0,0,NULL,NULL,-1,?4,?5)",
                params![
                    id,
                    voice_memory::EMBEDDING_SPACE,
                    embedding(seed),
                    job_id,
                    created_at
                ],
            )
            .unwrap();
    }

    fn execute(
        connection: &mut Connection,
        evidence: VoiceProfileEvidence,
    ) -> Result<LogicalMutationDisposition> {
        let plan = VoiceProfilePlan::new(ACCOUNT.to_owned(), evidence, AT.to_owned())?;
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|value| value.disposition())
    }

    fn work(connection: &Connection, at: &str) -> VoiceProfileEvidence {
        match observe_next(connection, ACCOUNT, at).unwrap() {
            VoiceProfileScan::Work(value) => *value,
            other => panic!("expected work, got {other:?}"),
        }
    }

    #[test]
    fn new_profile_and_existing_match_are_exact_and_replayable() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let first = work(&connection, AT);
        assert_eq!(
            execute(&mut connection, first.clone()).unwrap(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            execute(&mut connection, first).unwrap(),
            LogicalMutationDisposition::Replayed
        );
        let profile_id: i64 = connection
            .query_row(
                "SELECT voice_profile_id FROM voice_samples WHERE id=1 AND accepted=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(profile_id > 0);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM voice_profile_revisions WHERE profile_id=?1 AND active=1",
                    [profile_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );

        seed_pending(&connection, 2, "2026-08-22T11:59:59.000Z", 1.0);
        let mut second = work(&connection, AT);
        if matches!(second.work, WorkEvidence::ProfileReconcile(_)) {
            execute(&mut connection, second).unwrap();
            second = work(&connection, AT);
        }
        assert_eq!(
            execute(&mut connection, second).unwrap(),
            LogicalMutationDisposition::Applied
        );
        let second_profile: i64 = connection
            .query_row(
                "SELECT voice_profile_id FROM voice_samples WHERE id=2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(second_profile, profile_id);
        assert_eq!(
            connection
                .query_row(
                    "SELECT sample_count FROM voice_profiles WHERE id=?1",
                    [profile_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn backward_clock_defers_without_mutation() {
        let connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T12:00:01.000Z", 1.0);
        assert_eq!(
            observe_next(&connection, ACCOUNT, AT).unwrap(),
            VoiceProfileScan::ClockDeferred
        );
        assert_eq!(
            connection
                .query_row("SELECT accepted FROM voice_samples WHERE id=1", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            -1
        );
    }

    #[test]
    fn changed_sample_refuses_before_any_profile_write() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let evidence = work(&connection, AT);
        connection
            .execute(
                "UPDATE voice_samples SET eligibility='match_only' WHERE id=1",
                [],
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, evidence).unwrap_err(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_profiles", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn missing_or_nonready_embedding_job_is_rejected_and_releases_the_lane() {
        for state in [None, Some("pending")] {
            let mut connection = fixture();
            seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
            seed_pending(&connection, 2, "2026-08-22T11:59:59.000Z", 1.0);
            match state {
                None => {
                    connection
                        .execute("DELETE FROM voice_embedding_jobs WHERE id=1001", [])
                        .unwrap();
                }
                Some(state) => {
                    connection
                        .execute(
                            "UPDATE voice_embedding_jobs SET state=?1 WHERE id=1001",
                            [state],
                        )
                        .unwrap();
                }
            }
            let poisoned = work(&connection, AT);
            assert!(matches!(
                poisoned.work,
                WorkEvidence::SampleAssignment(SampleAssignmentEvidence {
                    decision: AssignmentDecision::Reject { .. },
                    ..
                })
            ));
            execute(&mut connection, poisoned).unwrap();
            assert_eq!(
                connection
                    .query_row("SELECT accepted FROM voice_samples WHERE id=1", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                0
            );
            let successor = work(&connection, AT);
            assert!(matches!(
                successor.work,
                WorkEvidence::SampleAssignment(SampleAssignmentEvidence { sample_id: 2, .. })
            ));
        }
    }

    #[test]
    fn stale_profile_is_repaired_before_a_new_sample_can_match_it() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let initial = work(&connection, AT);
        execute(&mut connection, initial).unwrap();
        let profile_id: i64 = connection
            .query_row(
                "SELECT voice_profile_id FROM voice_samples WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute(
                "UPDATE voice_profiles SET scorer_version=1 WHERE id=?1",
                [profile_id],
            )
            .unwrap();
        seed_pending(&connection, 2, "2026-08-22T11:59:59.000Z", 1.0);
        let repair = work(&connection, AT);
        assert!(matches!(repair.work, WorkEvidence::ProfileReconcile(_)));
        execute(&mut connection, repair).unwrap();
        assert!(matches!(
            work(&connection, AT).work,
            WorkEvidence::SampleAssignment(SampleAssignmentEvidence { sample_id: 2, .. })
        ));
    }

    #[test]
    fn future_representative_clock_defers_without_charging_profile_or_sample() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let initial = work(&connection, AT);
        execute(&mut connection, initial).unwrap();
        let profile_id: i64 = connection
            .query_row(
                "SELECT voice_profile_id FROM voice_samples WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute(
                "UPDATE voice_profiles SET scorer_version=1 WHERE id=?1",
                [profile_id],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE voice_profile_representatives SET updated_at=?1 WHERE profile_id=?2",
                params!["2026-08-22T12:00:01.000Z", profile_id],
            )
            .unwrap();
        assert_eq!(
            observe_next(&connection, ACCOUNT, AT).unwrap(),
            VoiceProfileScan::ClockDeferred
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT scorer_version FROM voice_profiles WHERE id=?1",
                    [profile_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn real_allocator_state_rejects_without_overflow_or_sqlite_coercion() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        connection
            .execute(
                "DELETE FROM sqlite_sequence WHERE name='voice_profiles'",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sqlite_sequence(name,seq) VALUES ('voice_profiles',1.5)",
                [],
            )
            .unwrap();
        let evidence = work(&connection, AT);
        execute(&mut connection, evidence).unwrap();
        let (accepted, sequence_kind): (i64, String) = connection
            .query_row(
                "SELECT accepted,(SELECT typeof(seq) FROM sqlite_sequence
                 WHERE name='voice_profiles') FROM voice_samples WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((accepted, sequence_kind.as_str()), (0, "real"));
    }

    #[test]
    fn thirty_third_candidate_is_bounded_provider_free_poison() {
        let mut connection = fixture();
        for ordinal in 0..33 {
            seed_complete_profile(&connection, ordinal);
        }
        seed_pending(&connection, 1, "2026-08-22T11:59:59.000Z", 1.0);
        let evidence = work(&connection, AT);
        assert!(matches!(
            evidence.work,
            WorkEvidence::SampleAssignment(SampleAssignmentEvidence {
                decision: AssignmentDecision::Reject { .. },
                ..
            })
        ));
        execute(&mut connection, evidence).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT accepted FROM voice_samples WHERE id=1", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_profiles", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            33
        );
    }

    #[test]
    fn changed_candidate_rolls_back_before_sample_or_profile_mutation() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let initial = work(&connection, AT);
        execute(&mut connection, initial).unwrap();
        seed_pending(&connection, 2, "2026-08-22T11:59:59.000Z", 1.0);
        let evidence = work(&connection, AT);
        connection
            .execute(
                "UPDATE voice_profiles SET centroid=?1 WHERE id=(
                   SELECT voice_profile_id FROM voice_samples WHERE id=1)",
                [basis_embedding(2)],
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, evidence).unwrap_err(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            connection
                .query_row("SELECT accepted FROM voice_samples WHERE id=2", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            -1
        );
    }

    #[test]
    fn partial_ledger_schema_refuses_before_domain_mutation() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let evidence = work(&connection, AT);
        connection
            .execute_batch(
                "CREATE TABLE archive_v3_wal_voice_profile_schema (
                   singleton INTEGER PRIMARY KEY,
                   format_version INTEGER NOT NULL,
                   codec_version INTEGER NOT NULL
                 );",
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, evidence).unwrap_err(),
            WalIdempotencyError::Corrupt
        );
        assert_eq!(
            connection
                .query_row("SELECT accepted FROM voice_samples WHERE id=1", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            -1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_profiles", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn ledger_capacity_refuses_before_sample_or_profile_mutation() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let initial = work(&connection, AT);
        execute(&mut connection, initial).unwrap();
        seed_pending(&connection, 2, "2026-08-22T11:59:59.000Z", 1.0);
        let evidence = work(&connection, AT);
        connection
            .execute(
                "UPDATE archive_v3_wal_voice_profile_state SET row_count=?1 WHERE singleton=1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, evidence).unwrap_err(),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            connection
                .query_row("SELECT accepted FROM voice_samples WHERE id=2", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            -1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_profiles", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
    }

    #[test]
    fn late_ledger_failure_rolls_back_every_profile_write() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let initial = work(&connection, AT);
        execute(&mut connection, initial).unwrap();
        seed_pending(&connection, 2, "2026-08-22T11:59:59.000Z", 1.0);
        let evidence = work(&connection, AT);
        connection
            .execute_batch(
                "CREATE TRIGGER reject_voice_profile_ledger
                 BEFORE INSERT ON archive_v3_wal_voice_profile_operations
                 BEGIN SELECT RAISE(ABORT,'ledger unavailable'); END;",
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, evidence).unwrap_err(),
            WalIdempotencyError::Unavailable
        );
        assert_eq!(
            connection
                .query_row("SELECT accepted FROM voice_samples WHERE id=2", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            -1
        );
        assert_eq!(
            connection
                .query_row("SELECT sample_count FROM voice_profiles", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM voice_sample_profile_assignments",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn exhausted_allocator_rejects_sample_without_sql_overflow() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        connection
            .execute(
                "DELETE FROM sqlite_sequence WHERE name='voice_profiles'",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sqlite_sequence(name,seq) VALUES ('voice_profiles',?1)",
                [i64::MAX],
            )
            .unwrap();
        let evidence = work(&connection, AT);
        assert_eq!(
            execute(&mut connection, evidence).unwrap(),
            LogicalMutationDisposition::Applied
        );
        let (accepted, kind): (i64, String) = connection
            .query_row(
                "SELECT accepted,typeof(accepted) FROM voice_samples WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((accepted, kind.as_str()), (0, "integer"));
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_profiles", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn historical_lineage_backfills_before_sample_assignment() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let first = work(&connection, AT);
        execute(&mut connection, first).unwrap();
        let profile_id: i64 = connection
            .query_row(
                "SELECT voice_profile_id FROM voice_samples WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute(
                "DELETE FROM voice_sample_profile_assignments WHERE sample_id=1",
                [],
            )
            .unwrap();
        connection
            .execute(
                "DELETE FROM voice_profile_revisions WHERE profile_id=?1",
                [profile_id],
            )
            .unwrap();

        let profile_backfill = work(&connection, AT);
        assert!(matches!(
            profile_backfill.work,
            WorkEvidence::ProfileBackfill(_)
        ));
        execute(&mut connection, profile_backfill).unwrap();
        let assignment_backfill = work(&connection, AT);
        assert!(matches!(
            assignment_backfill.work,
            WorkEvidence::AssignmentBackfill(_)
        ));
        execute(&mut connection, assignment_backfill).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM voice_profile_revisions WHERE profile_id=?1 AND active=1",
                    [profile_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM voice_sample_profile_assignments WHERE sample_id=1 AND active=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn stale_profile_reconciles_and_empty_profile_quarantines() {
        let mut connection = fixture();
        seed_pending(&connection, 1, "2026-08-22T11:59:58.000Z", 1.0);
        let first = work(&connection, AT);
        execute(&mut connection, first).unwrap();
        let profile_id: i64 = connection
            .query_row(
                "SELECT voice_profile_id FROM voice_samples WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute(
                "UPDATE voice_profiles SET scorer_version=1 WHERE id=?1",
                [profile_id],
            )
            .unwrap();
        let reconcile = work(&connection, AT);
        assert!(matches!(reconcile.work, WorkEvidence::ProfileReconcile(_)));
        execute(&mut connection, reconcile).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT scorer_version FROM voice_profiles WHERE id=?1",
                    [profile_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            voice_quality::SCORER_VERSION
        );

        connection
            .execute("UPDATE voice_samples SET accepted=0 WHERE id=1", [])
            .unwrap();
        connection
            .execute(
                "UPDATE voice_profile_representatives SET scorer_version=1 WHERE profile_id=?1",
                [profile_id],
            )
            .unwrap();
        let quarantine = work(&connection, AT);
        execute(&mut connection, quarantine).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM voice_profiles WHERE id=?1",
                    [profile_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "quarantined"
        );
    }

    #[test]
    fn imported_lineage_action_is_refused_without_applying_topology() {
        let mut connection = fixture();
        connection
            .execute(
                "INSERT INTO voice_profile_proposals
                 (proposal_key,kind,state,scorer_version,derivation_version,reason_code,
                  created_at,updated_at)
                 VALUES ('proposal-1','merge','approved',2,1,'calibrated',?1,?1)",
                ["2026-08-22T11:59:58.000Z"],
            )
            .unwrap();
        let evidence = work(&connection, AT);
        assert!(matches!(evidence.work, WorkEvidence::ProposalRefusal(_)));
        execute(&mut connection, evidence).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT state FROM voice_profile_proposals WHERE proposal_key='proposal-1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "rejected"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_profiles", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn episode_status_is_derived_one_exact_episode_at_a_time() {
        let mut connection = fixture();
        connection
            .execute(
                "INSERT INTO speaker_observations
                 (id,event_id,turn_id,speaker_local_id,started_at,ended_at,transcript_text,overlap)
                 VALUES (1,'event-1','turn-1','speaker-1',?1,?1,'text',0)",
                ["2026-08-22T11:59:58.000Z"],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_embedding_jobs
                 (id,speaker_observation_id,embedding_space,processor_version,quality_version,
                  scorer_version,state,attempt_count,created_at,updated_at)
                 VALUES (1,1,?1,1,1,2,'failed',3,?2,?2)",
                params![voice_memory::EMBEDDING_SPACE, "2026-08-22T11:59:58.000Z"],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO utterances
                 (id,audio_segment_id,text,source_key,speaker_observation_id)
                 VALUES (1,1,'text','cloud-v2:event-1:turn-1',1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO episodes
                 (id,started_at,ended_at,speaker_processing_status,created_at,updated_at)
                 VALUES (1,?1,?1,'ready',?1,?1)",
                ["2026-08-22T11:59:58.000Z"],
            )
            .unwrap();
        connection
            .execute("INSERT INTO episode_members VALUES (1,1,'utterance')", [])
            .unwrap();
        let evidence = work(&connection, AT);
        assert!(matches!(evidence.work, WorkEvidence::EpisodeStatus(_)));
        execute(&mut connection, evidence).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT speaker_processing_status FROM episodes WHERE id=1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "degraded"
        );
    }

    fn seed_literal_self_identity(connection: &Connection, evidence_json: &str) {
        seed_complete_profile(connection, 1);
        connection
            .execute(
                "INSERT INTO speaker_observation_sources
                 (speaker_observation_id,event_id,window_start_ms,window_end_ms,
                  event_start_ms,event_end_ms)
                 VALUES (20001,'profile-event-1',0,1000,0,1000)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO speaker_clusters
                 (id,work_unit_id,speaker_local_id,attribution_state,created_at,updated_at)
                 VALUES (1,'work-identity','speaker','anonymous_profile',?1,?1)",
                ["2026-08-22T11:59:57.000Z"],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE speaker_observations
                 SET cluster_id=1,
                     transcript_text='I''m Alice Example, and I work as an engineer'
                 WHERE id=20001",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO identity_evidence
                 (person_id,voice_profile_id,source_event_id,observed_at,
                  speaker_observation_id,kind,claimed_name,evidence_json,score,status,created_at)
                 VALUES (NULL,NULL,'profile-event-1','2026-08-22T11:59:55.000Z',20001,
                         'audio_self_identification','  Alice Example  ',?1,0.99,'proposed',?2)",
                params![evidence_json, "2026-08-22T11:59:58.000Z"],
            )
            .unwrap();
    }

    #[test]
    fn literal_self_identity_creates_one_exact_person_and_replays() {
        let mut connection = fixture();
        seed_literal_self_identity(
            &connection,
            r#"{"schema_version":1,"turn_id":"profile-turn-1","literal_evidence":"I'm Alice Example","facts":[{"predicate":"role","value":"Engineer","evidence":"I work as an engineer"}]}"#,
        );
        let evidence = work(&connection, AT);
        assert!(matches!(
            evidence.work,
            WorkEvidence::PersonIdentity(PersonIdentityEvidence {
                decision: PersonIdentityDecision::Bind { .. },
                ..
            })
        ));
        assert_eq!(
            execute(&mut connection, evidence.clone()).unwrap(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            execute(&mut connection, evidence).unwrap(),
            LogicalMutationDisposition::Replayed
        );
        let person_id = connection
            .query_row(
                "SELECT id FROM people WHERE display_name='Alice Example' AND status='identified'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert!(person_id > 0);
        let bound: (i64, i64, String) = connection
            .query_row(
                "SELECT person_id,voice_profile_id,status FROM identity_evidence WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(bound, (person_id, 10001, "accepted".into()));
        for sql in [
            "SELECT COUNT(*) FROM person_name_claims WHERE person_id=?1 AND normalized_name='alice example' AND status='accepted'",
            "SELECT COUNT(*) FROM person_facts WHERE person_id=?1 AND predicate='role' AND value='Engineer' AND status='active'",
            "SELECT COUNT(*) FROM profile_identity_bindings WHERE person_id=?1 AND voice_profile_id=10001 AND state='accepted' AND active=1 AND evidence_count=1 AND operation_id='adr0022:self-identification:1'",
            "SELECT COUNT(*) FROM voice_profiles WHERE id=10001 AND person_id=?1",
            "SELECT COUNT(*) FROM voice_profile_revisions WHERE profile_id=10001 AND person_id=?1 AND active=1",
            "SELECT COUNT(*) FROM speaker_observations WHERE id=20001 AND person_id=?1 AND direct_evidence_id=1",
            "SELECT COUNT(*) FROM speaker_clusters WHERE id=1 AND person_id=?1 AND voice_profile_id=10001 AND attribution_state='person_bound'",
        ] {
            assert_eq!(
                connection
                    .query_row(sql, [person_id], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1,
                "missing person-bound postcondition: {sql}"
            );
        }
        assert!(matches!(
            observe_next(&connection, ACCOUNT, AT).unwrap(),
            VoiceProfileScan::Idle
        ));
    }

    #[test]
    fn legal_multibyte_transcript_is_committed_in_bounded_exact_chunks() {
        let mut connection = fixture();
        seed_literal_self_identity(
            &connection,
            r#"{"schema_version":1,"turn_id":"profile-turn-1","literal_evidence":"I'm Alice Example","facts":[]}"#,
        );
        let transcript = format!("I'm Alice Example {}", "界".repeat(19_000));
        assert!(transcript.len() > MAX_TEXT_BYTES);
        assert!(transcript.len() <= MAX_TRANSCRIPT_BYTES);
        connection
            .execute(
                "UPDATE speaker_observations SET transcript_text=?1 WHERE id=20001",
                [transcript],
            )
            .unwrap();
        let evidence = work(&connection, AT);
        assert!(matches!(
            evidence.work,
            WorkEvidence::PersonIdentity(PersonIdentityEvidence {
                decision: PersonIdentityDecision::Bind { .. },
                ..
            })
        ));
        execute(&mut connection, evidence).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM identity_evidence WHERE id=1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "accepted"
        );
    }

    #[test]
    fn repeated_literal_identity_supersedes_one_active_binding_exactly() {
        let mut connection = fixture();
        seed_literal_self_identity(
            &connection,
            r#"{"schema_version":1,"turn_id":"profile-turn-1","literal_evidence":"I'm Alice Example","facts":[]}"#,
        );
        let first = work(&connection, AT);
        execute(&mut connection, first).unwrap();
        let person_id = connection
            .query_row(
                "SELECT id FROM people WHERE display_name='Alice Example'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO speaker_clusters
                 (id,work_unit_id,speaker_local_id,voice_profile_id,person_id,
                  attribution_state,created_at,updated_at)
                 VALUES (2,'work-identity-2','speaker',10001,?1,'person_bound',?2,?2)",
                params![person_id, "2026-08-22T11:59:57.000Z"],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO speaker_observations
                 (id,person_id,event_id,turn_id,speaker_local_id,started_at,ended_at,
                  transcript_text,overlap,cluster_id)
                 VALUES (20002,NULL,'profile-event-2','profile-turn-2','speaker',?1,?2,
                         'I''m Alice Example',0,2)",
                params!["2026-08-22T11:59:56.000Z", "2026-08-22T11:59:57.000Z"],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_samples
                 (id,speaker_observation_id,voice_profile_id,embedding_space,channel_domain,
                  embedding,quality_score,scorer_version,eligibility,outlier,accepted,created_at)
                 SELECT 30002,20002,10001,embedding_space,channel_domain,embedding,
                        quality_score,scorer_version,eligibility,outlier,1,created_at
                 FROM voice_samples WHERE id=30001",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO speaker_observation_sources
                 (speaker_observation_id,event_id,window_start_ms,window_end_ms,
                  event_start_ms,event_end_ms)
                 VALUES (20002,'profile-event-2',0,1000,0,1000)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO voice_sample_profile_assignments
                 (id,sample_id,profile_id,active,created_at)
                 VALUES (50002,30002,10001,1,?1)",
                ["2026-08-22T11:59:57.000Z"],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO identity_evidence
                 (person_id,voice_profile_id,source_event_id,observed_at,
                  speaker_observation_id,kind,claimed_name,evidence_json,score,status,created_at)
                 VALUES (NULL,NULL,'profile-event-2','2026-08-22T11:59:56.000Z',20002,
                         'audio_self_identification','Alice Example',?1,0.98,'proposed',?2)",
                params![
                    r#"{"schema_version":1,"turn_id":"profile-turn-2","literal_evidence":"I'm Alice Example","facts":[]}"#,
                    "2026-08-22T11:59:58.000Z"
                ],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE profile_identity_bindings
                 SET created_at=?1,updated_at=?1 WHERE voice_profile_id=10001 AND active=1",
                ["2026-08-22T12:00:01.000Z"],
            )
            .unwrap();
        assert!(matches!(
            observe_next(&connection, ACCOUNT, AT).unwrap(),
            VoiceProfileScan::ClockDeferred
        ));
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM identity_evidence WHERE id=2",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "proposed"
        );
        connection
            .execute(
                "UPDATE profile_identity_bindings
                 SET created_at=?1,updated_at=?1 WHERE voice_profile_id=10001 AND active=1",
                [AT],
            )
            .unwrap();
        let second = work(&connection, AT);
        assert!(matches!(
            second.work,
            WorkEvidence::PersonIdentity(PersonIdentityEvidence {
                decision: PersonIdentityDecision::Bind {
                    supersedes_binding_id: Some(_),
                    binding_evidence_count: 2,
                    ..
                },
                ..
            })
        ));
        execute(&mut connection, second).unwrap();
        let rows = connection
            .prepare(
                "SELECT id,evidence_count,active,supersedes_id
                 FROM profile_identity_bindings WHERE voice_profile_id=10001 ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows, vec![(1, 1, 0, None), (2, 2, 1, Some(1))]);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM identity_evidence
                     WHERE status='accepted' AND person_id=?1 AND voice_profile_id=10001",
                    [person_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn malformed_or_stale_identity_never_partially_binds_a_person() {
        let mut malformed = fixture();
        seed_literal_self_identity(
            &malformed,
            r#"{"schema_version":9,"turn_id":"profile-turn-1","literal_evidence":"I'm Alice","facts":[]}"#,
        );
        let refusal = work(&malformed, AT);
        assert!(matches!(
            refusal.work,
            WorkEvidence::PersonIdentity(PersonIdentityEvidence {
                decision: PersonIdentityDecision::Reject,
                ..
            })
        ));
        execute(&mut malformed, refusal).unwrap();
        assert_eq!(
            malformed
                .query_row(
                    "SELECT status FROM identity_evidence WHERE id=1",
                    [],
                    |row| { row.get::<_, String>(0) }
                )
                .unwrap(),
            "rejected"
        );
        assert_eq!(
            malformed
                .query_row(
                    "SELECT COUNT(*) FROM people WHERE display_name='Alice Example'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        let mut nonliteral = fixture();
        seed_literal_self_identity(
            &nonliteral,
            r#"{"schema_version":1,"turn_id":"profile-turn-1","literal_evidence":"A third party introduced Alice Example","facts":[]}"#,
        );
        let refusal = work(&nonliteral, AT);
        assert!(matches!(
            refusal.work,
            WorkEvidence::PersonIdentity(PersonIdentityEvidence {
                decision: PersonIdentityDecision::Reject,
                ..
            })
        ));
        execute(&mut nonliteral, refusal).unwrap();
        assert_eq!(
            nonliteral
                .query_row(
                    "SELECT COUNT(*) FROM people WHERE display_name='Alice Example'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        let mut stale = fixture();
        seed_literal_self_identity(
            &stale,
            r#"{"schema_version":1,"turn_id":"profile-turn-1","literal_evidence":"I'm Alice Example","facts":[]}"#,
        );
        let evidence = work(&stale, AT);
        stale
            .execute(
                "UPDATE voice_profiles SET label='changed after observation' WHERE id=10001",
                [],
            )
            .unwrap();
        assert_eq!(
            execute(&mut stale, evidence).unwrap_err(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            stale
                .query_row(
                    "SELECT status FROM identity_evidence WHERE id=1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "proposed"
        );
        assert_eq!(
            stale
                .query_row(
                    "SELECT COUNT(*) FROM people WHERE display_name='Alice Example'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }
}
