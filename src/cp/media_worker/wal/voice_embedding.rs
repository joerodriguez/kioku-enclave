//! Exact selected-account voice-embedding claim and result plans.
//!
//! The owner first observes one bounded due job and its complete canonical
//! source topology through the WAL read authority. `VoiceEmbeddingPlan::claim`
//! re-runs that observation and either claims the exact row with a checked
//! attempt increment or settles deterministic poison without provider work.
//! After the owner reads only the carried current generations, authenticates
//! them under the installed media DEK, and runs the in-enclave model, the
//! result plan reauthenticates the claim and source topology before recording
//! a retry/terminal/quality outcome or one explicit-ID pending sample.
//!
//! Profile matching is deliberately not part of this boundary. A successful
//! sample is stored with `accepted=-1`, the durable marker for the separately
//! sealed profile-assignment owner. This plan cannot allocate a profile,
//! identity, person, wall clock, provider, Store handle, or retry task.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive_v3_wal_idempotency::{
    stable_operation_source, DomainLedgerBounds, LogicalMutationResult, PreparedLogicalMutation,
    WalIdempotencyError, WalLogicalDomainLedger, WalLogicalDomainPlan, WalLogicalOperationId,
    WalOperationKind, WalReplayResult,
};

const REQUEST_V1: u16 = 1;
const CLAIM_SUBTYPE: &[u8] = b"adr-0022-voice-embedding-claim-v1";
const RESULT_SUBTYPE: &[u8] = b"adr-0022-voice-embedding-result-v1";
const BACKFILL_SUBTYPE: &[u8] = b"adr-0022-voice-embedding-job-backfill-v1";
const EMBEDDING_SPACE: &str = "wespeaker-resnet34-lm-v1";
const PROCESSOR_VERSION: i64 = 1;
const QUALITY_VERSION: i64 = 1;
const MAX_ATTEMPTS: i64 = 3;
const MAX_SOURCES: usize = 128;
const MAX_EXISTING_SAMPLES: usize = 128;
const MAX_ID_BYTES: usize = 128;
const MAX_KEY_BYTES: usize = 512;
const MAX_MIME_BYTES: usize = 128;
const MAX_DOMAIN_BYTES: usize = 512;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_ERROR_BYTES: usize = 128;
const MAX_WRAPPED_DEK_BYTES: usize = 8 * 1024;
const MAX_DIAGNOSTICS_BYTES: usize = 16 * 1024;
const EMBEDDING_DIMENSION: usize = 256;
const EMBEDDING_BYTES: usize = EMBEDDING_DIMENSION * 4;
const ENCODED_UNIT_RESULT_BYTES: usize = 9;
const SCHEMA_TABLE: &str = "archive_v3_wal_voice_embedding_schema";
const LEDGER_TABLE: &str = "archive_v3_wal_voice_embedding_operations";
const STATE_TABLE: &str = "archive_v3_wal_voice_embedding_state";
const MAX_ROWS: u32 = 1_048_576;
const MAX_RESULT_BYTES: u64 = 32 * 1024 * 1024;
const BOUNDS: DomainLedgerBounds = DomainLedgerBounds::new(MAX_ROWS, MAX_RESULT_BYTES);

type Result<T> = std::result::Result<T, WalIdempotencyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct JobRow {
    id: i64,
    speaker_observation_id: i64,
    embedding_space: String,
    processor_version: i64,
    quality_version: i64,
    scorer_version: i64,
    state: String,
    lease_owner: Option<String>,
    lease_token: Option<String>,
    lease_until: Option<String>,
    attempt_count: i64,
    next_attempt_at: Option<String>,
    error_code: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservationRow {
    id: i64,
    person_id: Option<i64>,
    event_id: String,
    turn_id: String,
    speaker_local_id: String,
    started_at: String,
    ended_at: String,
    transcript_length: u32,
    transcript_commitment: [u8; 32],
    language: Option<String>,
    overlap: bool,
    prior_eligibility: Option<String>,
    prior_diagnostics_length: u32,
    prior_diagnostics_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExistingSampleRow {
    id: i64,
    speaker_observation_id: i64,
    embedding_job_id: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VoiceSampleSequencePin {
    table_sql_length: u32,
    table_sql_commitment: [u8; 32],
    autoincrement: bool,
    storage_type: String,
    value: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct VoiceJobBackfillEvidence {
    account_id: String,
    observation: ObservationRow,
    sample_count: usize,
    job_count: usize,
    job_sequence: VoiceSampleSequencePin,
}

impl VoiceSampleSequencePin {
    fn next_id(&self) -> Option<i64> {
        if !self.autoincrement || !matches!(self.storage_type.as_str(), "absent" | "integer") {
            return None;
        }
        let value = match self.storage_type.as_str() {
            "absent" if self.value.is_none() => 0,
            "integer" => self.value?,
            _ => return None,
        };
        value.checked_add(1).filter(|next| *next > 0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct VoiceEmbeddingSource {
    event_id: String,
    window_start_ms: i64,
    window_end_ms: i64,
    event_start_ms: i64,
    event_end_ms: i64,
    stream_kind: String,
    audio_role: Option<String>,
    audio_route: Option<String>,
    object_key: String,
    object_generation: Option<i64>,
    object_backend: Option<String>,
    sha256: String,
    byte_length: i64,
    mime_type: String,
    processing_state: String,
    deleted_at: Option<String>,
}

impl VoiceEmbeddingSource {
    #[cfg(test)]
    pub(in crate::cp::media_worker) fn for_test(
        object_key: String,
        generation: i64,
        sha256: String,
        byte_length: i64,
    ) -> Self {
        Self {
            event_id: "event-voice-source".into(),
            window_start_ms: 0,
            window_end_ms: 1_000,
            event_start_ms: 0,
            event_end_ms: 1_000,
            stream_kind: "mic".into(),
            audio_role: None,
            audio_route: None,
            object_key,
            object_generation: Some(generation),
            object_backend: Some("current".into()),
            sha256,
            byte_length,
            mime_type: "audio/wav".into(),
            processing_state: "ready".into(),
            deleted_at: None,
        }
    }

    pub(in crate::cp::media_worker) fn object_key(&self) -> &str {
        &self.object_key
    }

    pub(in crate::cp::media_worker) fn generation(&self) -> Option<i64> {
        self.object_generation
    }

    pub(in crate::cp::media_worker) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(in crate::cp::media_worker) fn byte_length(&self) -> i64 {
        self.byte_length
    }

    pub(in crate::cp::media_worker) fn mime_type(&self) -> &str {
        &self.mime_type
    }

    pub(in crate::cp::media_worker) fn event_offsets(&self) -> (i64, i64) {
        (self.event_start_ms, self.event_end_ms)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) enum VoiceClaimDisposition {
    Authorized,
    ExistingSample,
    ClockDeferred,
    Terminal(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cp::media_worker) struct VoiceEmbeddingEvidence {
    account_id: String,
    observed_at: String,
    job: JobRow,
    observation: Option<ObservationRow>,
    sources: Vec<VoiceEmbeddingSource>,
    raw_source_count: usize,
    existing_samples: Vec<ExistingSampleRow>,
    existing_sample_overflow: bool,
    sample_sequence: VoiceSampleSequencePin,
    wrapped_media_dek: Option<String>,
}

impl VoiceEmbeddingEvidence {
    pub(in crate::cp::media_worker) fn job_id(&self) -> i64 {
        self.job.id
    }

    pub(in crate::cp::media_worker) fn observation_id(&self) -> i64 {
        self.job.speaker_observation_id
    }

    pub(in crate::cp::media_worker) fn overlap(&self) -> bool {
        self.observation.as_ref().is_some_and(|row| row.overlap)
    }

    pub(in crate::cp::media_worker) fn person_id(&self) -> Option<i64> {
        self.observation.as_ref().and_then(|row| row.person_id)
    }

    pub(in crate::cp::media_worker) fn sources(&self) -> &[VoiceEmbeddingSource] {
        &self.sources
    }

    pub(in crate::cp::media_worker) fn wrapped_media_dek(&self) -> Option<&str> {
        self.wrapped_media_dek.as_deref()
    }

    pub(in crate::cp::media_worker) fn next_attempt_count(&self) -> Option<i64> {
        self.job.attempt_count.checked_add(1)
    }

    pub(in crate::cp::media_worker) fn sample_sequence_pin(&self) -> Option<i64> {
        self.sample_sequence.next_id()?.checked_sub(1)
    }

    pub(in crate::cp::media_worker) fn acoustic_domain(&self) -> String {
        self.sources.first().map_or_else(String::new, |source| {
            match (&source.audio_role, &source.audio_route) {
                (None, None) => source.stream_kind.clone(),
                (role, route) => format!(
                    "{}:{}:{}",
                    source.stream_kind,
                    role.as_deref().unwrap_or_default(),
                    route.as_deref().unwrap_or_default()
                ),
            }
        })
    }

    pub(in crate::cp::media_worker) fn disposition(&self) -> VoiceClaimDisposition {
        if self.job.id <= 0
            || self.job.speaker_observation_id <= 0
            || self.job.embedding_space != EMBEDDING_SPACE
            || self.job.processor_version != PROCESSOR_VERSION
            || self.job.quality_version != QUALITY_VERSION
            || self.job.scorer_version <= 0
            || self.job.attempt_count < 0
            || self.job.attempt_count >= MAX_ATTEMPTS
            || !valid_job_strings(&self.job)
        {
            return VoiceClaimDisposition::Terminal("ERR_JOB_MALFORMED");
        }
        // A row observed under a rolled-back enclave wall clock is not
        // durable poison. Leave it byte-for-byte untouched until the clock
        // catches up; never charge or terminalize otherwise healthy work.
        if self.job.created_at > self.observed_at || self.job.updated_at > self.observed_at {
            return VoiceClaimDisposition::ClockDeferred;
        }
        if self.existing_sample_overflow {
            return VoiceClaimDisposition::Terminal("ERR_SAMPLE_TOPOLOGY");
        }
        let Some(observation) = &self.observation else {
            return VoiceClaimDisposition::Terminal("ERR_OBSERVATION_NOT_FOUND");
        };
        if !valid_observation(observation) {
            return VoiceClaimDisposition::Terminal("ERR_OBSERVATION_MALFORMED");
        }
        if self.existing_samples.iter().any(|sample| {
            sample.id <= 0
                || sample.speaker_observation_id != observation.id
                || sample.embedding_job_id.is_some_and(|value| value <= 0)
        }) {
            return VoiceClaimDisposition::Terminal("ERR_SAMPLE_TOPOLOGY");
        }
        if self.existing_samples.len() > 1 {
            return VoiceClaimDisposition::Terminal("ERR_SAMPLE_TOPOLOGY");
        }
        if self.existing_samples.len() == 1 {
            return VoiceClaimDisposition::ExistingSample;
        }
        if self.sample_sequence.next_id().is_none() {
            return VoiceClaimDisposition::Terminal("ERR_SAMPLE_CAPACITY");
        }
        if self.raw_source_count == 0 {
            return VoiceClaimDisposition::Terminal("ERR_NO_SOURCES_RECORDED");
        }
        if self.raw_source_count > MAX_SOURCES || self.sources.len() != self.raw_source_count {
            return VoiceClaimDisposition::Terminal("ERR_SOURCE_TOPOLOGY");
        }
        if self
            .sources
            .iter()
            .any(|source| source.processing_state == "pruned" || source.deleted_at.is_some())
        {
            return VoiceClaimDisposition::Terminal("ERR_MEDIA_PRUNED");
        }
        if self.sources.iter().any(|source| {
            !valid_source(&self.account_id, source)
                || source.object_backend.as_deref() != Some("current")
                || source.object_generation.is_none_or(|value| value <= 0)
        }) {
            return VoiceClaimDisposition::Terminal("ERR_SOURCE_MALFORMED");
        }
        if self.sources.windows(2).any(|pair| {
            pair[0].window_start_ms >= pair[1].window_start_ms
                || pair[0].window_end_ms > pair[1].window_start_ms
        }) {
            return VoiceClaimDisposition::Terminal("ERR_SOURCE_TOPOLOGY");
        }
        if self
            .wrapped_media_dek
            .as_ref()
            .is_none_or(|value| value.is_empty() || value.len() > MAX_WRAPPED_DEK_BYTES)
        {
            return VoiceClaimDisposition::Terminal("ERR_MEDIA_DEK_MISSING");
        }
        VoiceClaimDisposition::Authorized
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(in crate::cp::media_worker) struct VoiceSamplePayload {
    vector_bytes: Vec<u8>,
    diagnostics_json: String,
    eligibility: String,
    duration_ms: i64,
    speech_ratio: f64,
    snr_proxy_db: f64,
    clipping_ratio: f64,
    silence_ratio: f64,
    embedding_norm: f64,
    acoustic_domain: String,
}

impl VoiceSamplePayload {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn new(
        vector_bytes: Vec<u8>,
        diagnostics_json: String,
        eligibility: String,
        duration_ms: i64,
        speech_ratio: f64,
        snr_proxy_db: f64,
        clipping_ratio: f64,
        silence_ratio: f64,
        embedding_norm: f64,
        acoustic_domain: String,
    ) -> Result<Self> {
        let value = Self {
            vector_bytes,
            diagnostics_json,
            eligibility,
            duration_ms,
            speech_ratio,
            snr_proxy_db,
            clipping_ratio,
            silence_ratio,
            embedding_norm,
            acoustic_domain,
        };
        validate_sample(&value)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(in crate::cp::media_worker) enum VoiceEmbeddingOutcome {
    Sample {
        payload: VoiceSamplePayload,
        sequence_pin: i64,
    },
    QualityRejected {
        diagnostics_json: String,
        eligibility: String,
    },
    Retry {
        error_code: String,
        retry_at: String,
    },
    Terminal {
        error_code: String,
    },
}

#[derive(Clone)]
enum VoiceEmbeddingAction {
    BackfillJob {
        evidence: VoiceJobBackfillEvidence,
        committed_at: String,
    },
    Claim {
        evidence: VoiceEmbeddingEvidence,
        lease_token: String,
        leased_at: String,
        lease_until: String,
    },
    Settle {
        evidence: VoiceEmbeddingEvidence,
        lease_token: String,
        leased_at: String,
        lease_until: String,
        settled_at: String,
        outcome: VoiceEmbeddingOutcome,
    },
}

pub(crate) struct VoiceEmbeddingPlan {
    operation_id: WalLogicalOperationId,
    account_id: String,
    action: VoiceEmbeddingAction,
}

impl VoiceEmbeddingPlan {
    pub(in crate::cp::media_worker) fn backfill_job(
        account_id: String,
        evidence: VoiceJobBackfillEvidence,
        committed_at: String,
    ) -> Result<Self> {
        crate::store::validate_user_id(&account_id).map_err(|_| WalIdempotencyError::Malformed)?;
        validate_timestamp(&committed_at)?;
        if account_id != evidence.account_id
            || evidence.observation.id <= 0
            || evidence.sample_count != 0
            || evidence.job_count != 0
            || committed_at < evidence.observation.started_at
            || committed_at < evidence.observation.ended_at
            || evidence.job_sequence.next_id().is_none()
        {
            return Err(WalIdempotencyError::Precondition);
        }
        let source = stable_operation_source(
            BACKFILL_SUBTYPE,
            &[
                account_id.as_bytes(),
                &evidence.observation.id.to_be_bytes(),
            ],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::VoiceEmbedding, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            action: VoiceEmbeddingAction::BackfillJob {
                evidence,
                committed_at,
            },
        })
    }

    pub(in crate::cp::media_worker) fn claim(
        account_id: String,
        evidence: VoiceEmbeddingEvidence,
        lease_token: String,
        leased_at: String,
        lease_until: String,
    ) -> Result<Self> {
        validate_common(
            &account_id,
            &evidence,
            &lease_token,
            &leased_at,
            &lease_until,
        )?;
        if account_id != evidence.account_id {
            return Err(WalIdempotencyError::Malformed);
        }
        if evidence.disposition() == VoiceClaimDisposition::ClockDeferred {
            return Err(WalIdempotencyError::Precondition);
        }
        let source = stable_operation_source(
            CLAIM_SUBTYPE,
            &[
                account_id.as_bytes(),
                &evidence.job.id.to_be_bytes(),
                &evidence.job.attempt_count.to_be_bytes(),
                lease_token.as_bytes(),
            ],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::VoiceEmbedding, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            action: VoiceEmbeddingAction::Claim {
                evidence,
                lease_token,
                leased_at,
                lease_until,
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::cp::media_worker) fn settle(
        account_id: String,
        evidence: VoiceEmbeddingEvidence,
        lease_token: String,
        leased_at: String,
        lease_until: String,
        settled_at: String,
        outcome: VoiceEmbeddingOutcome,
    ) -> Result<Self> {
        validate_common(
            &account_id,
            &evidence,
            &lease_token,
            &leased_at,
            &lease_until,
        )?;
        validate_timestamp(&settled_at)?;
        if account_id != evidence.account_id
            || evidence.disposition() != VoiceClaimDisposition::Authorized
            || settled_at < leased_at
            || matches!(
                &outcome,
                VoiceEmbeddingOutcome::Retry { retry_at, .. } if retry_at <= &settled_at
            )
        {
            return Err(WalIdempotencyError::Precondition);
        }
        validate_outcome(&outcome, evidence.next_attempt_count())?;
        let outcome_commitment = outcome_commitment(&outcome)?;
        let source = stable_operation_source(
            RESULT_SUBTYPE,
            &[
                account_id.as_bytes(),
                &evidence.job.id.to_be_bytes(),
                lease_token.as_bytes(),
                &outcome_commitment,
            ],
        )?;
        let operation_id =
            WalLogicalOperationId::from_stable_source(WalOperationKind::VoiceEmbedding, &source)?;
        Ok(Self {
            operation_id,
            account_id,
            action: VoiceEmbeddingAction::Settle {
                evidence,
                lease_token,
                leased_at,
                lease_until,
                settled_at,
                outcome,
            },
        })
    }
}

pub(crate) struct VoiceEmbeddingLedger;

impl WalLogicalDomainPlan for VoiceEmbeddingPlan {
    type Ledger = VoiceEmbeddingLedger;
    type Output = ();

    fn kind(&self) -> WalOperationKind {
        WalOperationKind::VoiceEmbedding
    }

    fn operation_id(&self) -> WalLogicalOperationId {
        self.operation_id
    }

    fn canonical_request(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = Zeroizing::new(Vec::with_capacity(64 * 1024));
        request.extend_from_slice(&REQUEST_V1.to_be_bytes());
        encode_string(&mut request, &self.account_id)?;
        match &self.action {
            VoiceEmbeddingAction::BackfillJob {
                evidence,
                committed_at,
            } => {
                request.push(0);
                encode_bytes(&mut request, BACKFILL_SUBTYPE)?;
                encode_backfill_evidence(&mut request, evidence)?;
                encode_string(&mut request, committed_at)?;
            }
            VoiceEmbeddingAction::Claim {
                evidence,
                lease_token,
                leased_at,
                lease_until,
            } => {
                request.push(1);
                encode_bytes(&mut request, CLAIM_SUBTYPE)?;
                encode_evidence(&mut request, evidence)?;
                encode_string(&mut request, lease_token)?;
                encode_string(&mut request, leased_at)?;
                encode_string(&mut request, lease_until)?;
            }
            VoiceEmbeddingAction::Settle {
                evidence,
                lease_token,
                leased_at,
                lease_until,
                settled_at,
                outcome,
            } => {
                request.push(2);
                encode_bytes(&mut request, RESULT_SUBTYPE)?;
                encode_evidence(&mut request, evidence)?;
                encode_string(&mut request, lease_token)?;
                encode_string(&mut request, leased_at)?;
                encode_string(&mut request, lease_until)?;
                encode_string(&mut request, settled_at)?;
                encode_outcome(&mut request, outcome)?;
            }
        }
        Ok(request)
    }

    fn apply(&self, transaction: &Transaction<'_>) -> Result<WalReplayResult> {
        match &self.action {
            VoiceEmbeddingAction::BackfillJob {
                evidence,
                committed_at,
            } => apply_job_backfill(transaction, evidence, committed_at)?,
            VoiceEmbeddingAction::Claim {
                evidence,
                lease_token,
                leased_at,
                lease_until,
            } => apply_claim(transaction, evidence, lease_token, leased_at, lease_until)?,
            VoiceEmbeddingAction::Settle {
                evidence,
                lease_token,
                leased_at,
                lease_until,
                settled_at,
                outcome,
            } => apply_settlement(
                transaction,
                evidence,
                lease_token,
                leased_at,
                lease_until,
                settled_at,
                outcome,
            )?,
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
    now: &str,
) -> rusqlite::Result<Option<VoiceEmbeddingEvidence>> {
    let job = connection
        .query_row(
            "SELECT id,speaker_observation_id,embedding_space,processor_version,quality_version,
                    scorer_version,state,lease_owner,lease_token,lease_until,attempt_count,
                    next_attempt_at,error_code,created_at,updated_at
             FROM voice_embedding_jobs
             WHERE (state IN ('pending','retry_wait') AND (
                       next_attempt_at IS NULL OR next_attempt_at<=?1 OR length(next_attempt_at)>64
                       OR strftime('%Y-%m-%dT%H:%M:%fZ',next_attempt_at) IS NULL))
                OR (state='processing' AND (
                       lease_until IS NULL OR lease_until<?1 OR length(lease_until)>64
                       OR strftime('%Y-%m-%dT%H:%M:%fZ',lease_until) IS NULL))
             ORDER BY id LIMIT 1",
            [now],
            read_job,
        )
        .optional()?;
    job.map(|job| load_evidence(connection, account_id, now, job))
        .transpose()
}

/// Enumerates one historical observation written by the live v1 transcript
/// contract before atomic embedding-job handoff existed. This is bounded to
/// one row and carries the exact observation plus both absence counts and the
/// allocator predecessor; `apply` rereads every fact before inserting.
pub(in crate::cp::media_worker) fn observe_next_job_backfill(
    connection: &Connection,
    account_id: &str,
) -> rusqlite::Result<Option<VoiceJobBackfillEvidence>> {
    let observation_id = connection
        .query_row(
            "SELECT o.id FROM speaker_observations o
             WHERE COALESCE(o.overlap,0)=0
               AND NOT EXISTS (
                       SELECT 1 FROM voice_samples s WHERE s.speaker_observation_id=o.id)
               AND NOT EXISTS (
                       SELECT 1 FROM voice_embedding_jobs j WHERE j.speaker_observation_id=o.id)
               AND EXISTS (
                       SELECT 1 FROM speaker_observation_sources source
                       WHERE source.speaker_observation_id=o.id)
             ORDER BY o.id LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    observation_id
        .map(|observation_id| load_job_backfill_evidence(connection, account_id, observation_id))
        .transpose()
}

fn load_job_backfill_evidence(
    connection: &Connection,
    account_id: &str,
    observation_id: i64,
) -> rusqlite::Result<VoiceJobBackfillEvidence> {
    let observation = connection.query_row(
        "SELECT id,person_id,event_id,turn_id,speaker_local_id,started_at,ended_at,
                transcript_text,language,overlap,voice_eligibility,voice_diagnostics_json
         FROM speaker_observations WHERE id=?1",
        [observation_id],
        read_observation,
    )?;
    let sample_count = bounded_child_count(
        connection,
        "voice_samples",
        "speaker_observation_id",
        observation_id,
    )?;
    let job_count = bounded_child_count(
        connection,
        "voice_embedding_jobs",
        "speaker_observation_id",
        observation_id,
    )?;
    Ok(VoiceJobBackfillEvidence {
        account_id: account_id.to_owned(),
        observation,
        sample_count,
        job_count,
        job_sequence: load_sequence_pin(connection, "voice_embedding_jobs")?,
    })
}

fn is_job_backfill_candidate(
    connection: &Connection,
    observation_id: i64,
) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM speaker_observations o
             WHERE o.id=?1 AND COALESCE(o.overlap,0)=0
               AND NOT EXISTS (
                       SELECT 1 FROM voice_samples s WHERE s.speaker_observation_id=o.id)
               AND NOT EXISTS (
                       SELECT 1 FROM voice_embedding_jobs j WHERE j.speaker_observation_id=o.id)
               AND EXISTS (
                       SELECT 1 FROM speaker_observation_sources source
                       WHERE source.speaker_observation_id=o.id))",
        [observation_id],
        |row| row.get(0),
    )
}

fn bounded_child_count(
    connection: &Connection,
    table: &str,
    column: &str,
    observation_id: i64,
) -> rusqlite::Result<usize> {
    if !matches!(table, "voice_samples" | "voice_embedding_jobs")
        || column != "speaker_observation_id"
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let sql = format!("SELECT COUNT(*) FROM (SELECT 1 FROM {table} WHERE {column}=?1 LIMIT 2)");
    let count = connection.query_row(&sql, [observation_id], |row| row.get::<_, i64>(0))?;
    usize::try_from(count).map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(in crate::cp::media_worker) fn voice_sample_sequence_pin(
    connection: &Connection,
) -> rusqlite::Result<i64> {
    load_voice_sample_sequence_pin(connection)?
        .next_id()
        .and_then(|value| value.checked_sub(1))
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn load_evidence(
    connection: &Connection,
    account_id: &str,
    observed_at: &str,
    job: JobRow,
) -> rusqlite::Result<VoiceEmbeddingEvidence> {
    let observation = connection
        .query_row(
            "SELECT id,person_id,event_id,turn_id,speaker_local_id,started_at,ended_at,
                    transcript_text,language,overlap,voice_eligibility,voice_diagnostics_json
             FROM speaker_observations WHERE id=?1",
            [job.speaker_observation_id],
            read_observation,
        )
        .optional()?;

    // Count the raw association topology independently of its children.
    // The bounded count makes an absent capture/media child observable
    // instead of silently dropping that interval through the joins below.
    let raw_source_count = connection.query_row(
        "SELECT COUNT(*) FROM (
             SELECT 1 FROM speaker_observation_sources
             WHERE speaker_observation_id=?1 LIMIT ?2
         )",
        params![job.speaker_observation_id, (MAX_SOURCES + 1) as i64],
        |row| row.get::<_, i64>(0),
    )?;
    let raw_source_count =
        usize::try_from(raw_source_count).map_err(|_| rusqlite::Error::InvalidQuery)?;

    let mut statement = connection.prepare(
        "SELECT source.event_id,source.window_start_ms,source.window_end_ms,
                source.event_start_ms,source.event_end_ms,event.stream_kind,event.audio_role,
                event.audio_route,media.object_key,media.object_generation,media.object_backend,
                media.sha256,media.byte_length,media.mime_type,media.processing_state,media.deleted_at
         FROM speaker_observation_sources source
         JOIN capture_events event ON event.event_id=source.event_id
         JOIN media_objects media ON media.event_id=source.event_id
         WHERE source.speaker_observation_id=?1
         ORDER BY source.window_start_ms,source.event_id LIMIT ?2",
    )?;
    let sources = statement
        .query_map(
            params![job.speaker_observation_id, (MAX_SOURCES + 1) as i64],
            |row| {
                Ok(VoiceEmbeddingSource {
                    event_id: row.get(0)?,
                    window_start_ms: row.get(1)?,
                    window_end_ms: row.get(2)?,
                    event_start_ms: row.get(3)?,
                    event_end_ms: row.get(4)?,
                    stream_kind: row.get(5)?,
                    audio_role: row.get(6)?,
                    audio_route: row.get(7)?,
                    object_key: row.get(8)?,
                    object_generation: row.get(9)?,
                    object_backend: row.get(10)?,
                    sha256: row.get(11)?,
                    byte_length: row.get(12)?,
                    mime_type: row.get(13)?,
                    processing_state: row.get(14)?,
                    deleted_at: row.get(15)?,
                })
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut samples_statement = connection.prepare(
        "SELECT id,speaker_observation_id,embedding_job_id
         FROM voice_samples WHERE speaker_observation_id=?1 ORDER BY id LIMIT ?2",
    )?;
    let existing_samples = samples_statement
        .query_map(
            params![
                job.speaker_observation_id,
                (MAX_EXISTING_SAMPLES + 1) as i64
            ],
            |row| {
                Ok(ExistingSampleRow {
                    id: row.get(0)?,
                    speaker_observation_id: row.get(1)?,
                    embedding_job_id: row.get(2)?,
                })
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let existing_sample_overflow = existing_samples.len() > MAX_EXISTING_SAMPLES;
    let sample_sequence = load_voice_sample_sequence_pin(connection)?;

    let wrapped_media_dek = connection
        .query_row(
            "SELECT value FROM app_metadata WHERE key='wrapped_media_dek'",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();

    Ok(VoiceEmbeddingEvidence {
        account_id: account_id.to_owned(),
        observed_at: observed_at.to_owned(),
        job,
        observation,
        sources,
        raw_source_count,
        existing_samples,
        existing_sample_overflow,
        sample_sequence,
        wrapped_media_dek,
    })
}

fn load_voice_sample_sequence_pin(
    connection: &Connection,
) -> rusqlite::Result<VoiceSampleSequencePin> {
    load_sequence_pin(connection, "voice_samples")
}

fn load_sequence_pin(
    connection: &Connection,
    table: &str,
) -> rusqlite::Result<VoiceSampleSequencePin> {
    if !matches!(table, "voice_samples" | "voice_embedding_jobs") {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let table_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
        .unwrap_or_default();
    let sequence_table_present = connection.query_row(
        "SELECT COUNT(*)>0 FROM sqlite_schema WHERE type='table' AND name='sqlite_sequence'",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    let sequence = if sequence_table_present {
        connection
            .query_row(
                "SELECT typeof(seq),CASE WHEN typeof(seq)='integer' THEN seq ELSE NULL END
                 FROM sqlite_sequence WHERE name=?1",
                [table],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .optional()?
    } else {
        Some(("missing".to_owned(), None))
    };
    let (storage_type, value) = sequence.unwrap_or_else(|| ("absent".to_owned(), None));
    Ok(VoiceSampleSequencePin {
        table_sql_length: u32::try_from(table_sql.len())
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        table_sql_commitment: Sha256::digest(table_sql.as_bytes()).into(),
        autoincrement: table_sql.to_ascii_uppercase().contains("AUTOINCREMENT"),
        storage_type,
        value,
    })
}

fn read_observation(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObservationRow> {
    let transcript = row.get::<_, String>(7)?;
    let diagnostics = row.get::<_, Option<String>>(11)?;
    Ok(ObservationRow {
        id: row.get(0)?,
        person_id: row.get(1)?,
        event_id: row.get(2)?,
        turn_id: row.get(3)?,
        speaker_local_id: row.get(4)?,
        started_at: row.get(5)?,
        ended_at: row.get(6)?,
        transcript_length: u32::try_from(transcript.len())
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        transcript_commitment: Sha256::digest(transcript.as_bytes()).into(),
        language: row.get(8)?,
        overlap: row.get::<_, i64>(9)? != 0,
        prior_eligibility: row.get(10)?,
        prior_diagnostics_length: u32::try_from(diagnostics.as_deref().map_or(0, str::len))
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        prior_diagnostics_commitment: Sha256::digest(
            diagnostics.as_deref().unwrap_or_default().as_bytes(),
        )
        .into(),
    })
}

fn read_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRow> {
    Ok(JobRow {
        id: row.get(0)?,
        speaker_observation_id: row.get(1)?,
        embedding_space: row.get(2)?,
        processor_version: row.get(3)?,
        quality_version: row.get(4)?,
        scorer_version: row.get(5)?,
        state: row.get(6)?,
        lease_owner: row.get(7)?,
        lease_token: row.get(8)?,
        lease_until: row.get(9)?,
        attempt_count: row.get(10)?,
        next_attempt_at: row.get(11)?,
        error_code: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

fn apply_job_backfill(
    transaction: &Transaction<'_>,
    evidence: &VoiceJobBackfillEvidence,
    committed_at: &str,
) -> Result<()> {
    let current =
        load_job_backfill_evidence(transaction, &evidence.account_id, evidence.observation.id)
            .map_err(|_| WalIdempotencyError::Unavailable)?;
    if &current != evidence
        || current.sample_count != 0
        || current.job_count != 0
        || !is_job_backfill_candidate(transaction, evidence.observation.id)
            .map_err(|_| WalIdempotencyError::Unavailable)?
    {
        return Err(WalIdempotencyError::Precondition);
    }
    let job_id = evidence
        .job_sequence
        .next_id()
        .ok_or(WalIdempotencyError::Limit)?;
    let inserted = transaction
        .execute(
            "INSERT INTO voice_embedding_jobs
             (id,speaker_observation_id,embedding_space,processor_version,quality_version,
              scorer_version,state,lease_owner,lease_token,lease_until,attempt_count,
              next_attempt_at,error_code,created_at,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,'pending',NULL,NULL,NULL,0,NULL,NULL,?7,?7)",
            params![
                job_id,
                evidence.observation.id,
                EMBEDDING_SPACE,
                PROCESSOR_VERSION,
                QUALITY_VERSION,
                crate::cp::voice_quality::SCORER_VERSION,
                committed_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if inserted != 1 || transaction.last_insert_rowid() != job_id {
        return Err(WalIdempotencyError::Corrupt);
    }
    let stored = transaction
        .query_row(
            "SELECT id,speaker_observation_id,embedding_space,processor_version,quality_version,
                    scorer_version,state,lease_owner,lease_token,lease_until,attempt_count,
                    next_attempt_at,error_code,created_at,updated_at
             FROM voice_embedding_jobs WHERE id=?1",
            [job_id],
            read_job,
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    let expected = JobRow {
        id: job_id,
        speaker_observation_id: evidence.observation.id,
        embedding_space: EMBEDDING_SPACE.to_owned(),
        processor_version: PROCESSOR_VERSION,
        quality_version: QUALITY_VERSION,
        scorer_version: crate::cp::voice_quality::SCORER_VERSION,
        state: "pending".to_owned(),
        lease_owner: None,
        lease_token: None,
        lease_until: None,
        attempt_count: 0,
        next_attempt_at: None,
        error_code: None,
        created_at: committed_at.to_owned(),
        updated_at: committed_at.to_owned(),
    };
    if stored != expected {
        return Err(WalIdempotencyError::Corrupt);
    }
    let stored_sequence = load_sequence_pin(transaction, "voice_embedding_jobs")
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if stored_sequence.table_sql_length != evidence.job_sequence.table_sql_length
        || stored_sequence.table_sql_commitment != evidence.job_sequence.table_sql_commitment
        || stored_sequence.autoincrement != evidence.job_sequence.autoincrement
        || stored_sequence.storage_type != "integer"
        || stored_sequence.value != Some(job_id)
    {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn apply_claim(
    transaction: &Transaction<'_>,
    evidence: &VoiceEmbeddingEvidence,
    lease_token: &str,
    leased_at: &str,
    lease_until: &str,
) -> Result<()> {
    let current = observe_next(transaction, &evidence.account_id, leased_at)
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
    if &current != evidence || current.disposition() != evidence.disposition() {
        return Err(WalIdempotencyError::Precondition);
    }
    match evidence.disposition() {
        VoiceClaimDisposition::Authorized => {
            let next_attempt = evidence
                .job
                .attempt_count
                .checked_add(1)
                .filter(|value| *value <= MAX_ATTEMPTS)
                .ok_or(WalIdempotencyError::Limit)?;
            let changed = transaction
                .execute(
                    "UPDATE voice_embedding_jobs
                     SET state='processing',lease_owner='media_worker',lease_token=?1,
                         lease_until=?2,attempt_count=?3,updated_at=?4
                     WHERE id=?5 AND state=?6 AND attempt_count=?7 AND updated_at=?8
                       AND lease_owner IS ?9 AND lease_token IS ?10 AND lease_until IS ?11
                       AND next_attempt_at IS ?12 AND error_code IS ?13
                       AND typeof(attempt_count)='integer' AND attempt_count<?14",
                    params![
                        lease_token,
                        lease_until,
                        next_attempt,
                        leased_at,
                        evidence.job.id,
                        evidence.job.state,
                        evidence.job.attempt_count,
                        evidence.job.updated_at,
                        evidence.job.lease_owner,
                        evidence.job.lease_token,
                        evidence.job.lease_until,
                        evidence.job.next_attempt_at,
                        evidence.job.error_code,
                        MAX_ATTEMPTS,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if changed != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
        }
        VoiceClaimDisposition::ExistingSample => {
            let [sample] = evidence.existing_samples.as_slice() else {
                return Err(WalIdempotencyError::Corrupt);
            };
            if sample.embedding_job_id.is_none() {
                let changed = transaction
                    .execute(
                        "UPDATE voice_samples SET embedding_job_id=?1
                         WHERE id=?2 AND speaker_observation_id=?3
                           AND embedding_job_id IS NULL",
                        params![evidence.job.id, sample.id, sample.speaker_observation_id],
                    )
                    .map_err(|_| WalIdempotencyError::Unavailable)?;
                if changed != 1 {
                    return Err(WalIdempotencyError::Corrupt);
                }
            }
            settle_job_without_claim(transaction, evidence, "ready", None, leased_at)?;
        }
        VoiceClaimDisposition::ClockDeferred => {
            return Err(WalIdempotencyError::Precondition);
        }
        VoiceClaimDisposition::Terminal(error_code) => {
            settle_job_without_claim(transaction, evidence, "failed", Some(error_code), leased_at)?;
        }
    }
    Ok(())
}

fn settle_job_without_claim(
    transaction: &Transaction<'_>,
    evidence: &VoiceEmbeddingEvidence,
    target_state: &str,
    error_code: Option<&str>,
    settled_at: &str,
) -> Result<()> {
    let changed = transaction
        .execute(
            "UPDATE voice_embedding_jobs
             SET state=?1,lease_owner=NULL,lease_token=NULL,lease_until=NULL,
                 next_attempt_at=NULL,error_code=?2,updated_at=?3
             WHERE id=?4 AND state=?5 AND attempt_count=?6 AND updated_at=?7
               AND lease_owner IS ?8 AND lease_token IS ?9 AND lease_until IS ?10
               AND next_attempt_at IS ?11 AND error_code IS ?12",
            params![
                target_state,
                error_code,
                settled_at,
                evidence.job.id,
                evidence.job.state,
                evidence.job.attempt_count,
                evidence.job.updated_at,
                evidence.job.lease_owner,
                evidence.job.lease_token,
                evidence.job.lease_until,
                evidence.job.next_attempt_at,
                evidence.job.error_code,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_settlement(
    transaction: &Transaction<'_>,
    evidence: &VoiceEmbeddingEvidence,
    lease_token: &str,
    leased_at: &str,
    lease_until: &str,
    settled_at: &str,
    outcome: &VoiceEmbeddingOutcome,
) -> Result<()> {
    let current_job = transaction
        .query_row(
            "SELECT id,speaker_observation_id,embedding_space,processor_version,quality_version,
                    scorer_version,state,lease_owner,lease_token,lease_until,attempt_count,
                    next_attempt_at,error_code,created_at,updated_at
             FROM voice_embedding_jobs WHERE id=?1",
            [evidence.job.id],
            read_job,
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Precondition)?;
    let mut expected = evidence.job.clone();
    expected.state = "processing".into();
    expected.lease_owner = Some("media_worker".into());
    expected.lease_token = Some(lease_token.into());
    expected.lease_until = Some(lease_until.into());
    expected.attempt_count = expected
        .attempt_count
        .checked_add(1)
        .ok_or(WalIdempotencyError::Limit)?;
    expected.updated_at = leased_at.into();
    if current_job != expected {
        return Err(WalIdempotencyError::Precondition);
    }
    let current_evidence = load_evidence(
        transaction,
        &evidence.account_id,
        &evidence.observed_at,
        current_job.clone(),
    )
    .map_err(|_| WalIdempotencyError::Unavailable)?;
    if current_evidence.observation != evidence.observation
        || current_evidence.sources != evidence.sources
        || current_evidence.raw_source_count != evidence.raw_source_count
        || current_evidence.existing_samples != evidence.existing_samples
        || current_evidence.existing_sample_overflow != evidence.existing_sample_overflow
        || current_evidence.sample_sequence != evidence.sample_sequence
        || current_evidence.wrapped_media_dek != evidence.wrapped_media_dek
    {
        return Err(WalIdempotencyError::Precondition);
    }

    match outcome {
        VoiceEmbeddingOutcome::Sample {
            payload,
            sequence_pin,
        } => {
            if !evidence.existing_samples.is_empty() {
                return Err(WalIdempotencyError::Precondition);
            }
            let Some(observed_pin) = evidence.sample_sequence_pin() else {
                return Err(WalIdempotencyError::Precondition);
            };
            if observed_pin != *sequence_pin {
                return Err(WalIdempotencyError::Precondition);
            }
            let sample_id = sequence_pin
                .checked_add(1)
                .ok_or(WalIdempotencyError::Limit)?;
            let observation = evidence
                .observation
                .as_ref()
                .ok_or(WalIdempotencyError::Precondition)?;
            let inserted = transaction
                .execute(
                    "INSERT INTO voice_samples
                     (id,speaker_observation_id,voice_profile_id,embedding_space,channel_domain,
                      embedding,quality_score,diagnostics_json,quality_version,scorer_version,
                      eligibility,duration_ms,speech_ratio,snr_proxy_db,clipping_ratio,silence_ratio,
                      embedding_norm,outlier,similarity,decision_margin,accepted,embedding_job_id,
                      created_at)
                     VALUES (?1,?2,NULL,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,
                             ?16,0,NULL,NULL,-1,?17,?18)",
                    params![
                        sample_id,
                        observation.id,
                        EMBEDDING_SPACE,
                        payload.acoustic_domain,
                        payload.vector_bytes,
                        payload.speech_ratio * (1.0 - payload.clipping_ratio),
                        payload.diagnostics_json,
                        QUALITY_VERSION,
                        evidence.job.scorer_version,
                        payload.eligibility,
                        payload.duration_ms,
                        payload.speech_ratio,
                        payload.snr_proxy_db,
                        payload.clipping_ratio,
                        payload.silence_ratio,
                        payload.embedding_norm,
                        evidence.job.id,
                        settled_at,
                    ],
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if inserted != 1 {
                return Err(WalIdempotencyError::Corrupt);
            }
            let stored_pin = voice_sample_sequence_pin(transaction)
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            if stored_pin != sample_id {
                return Err(WalIdempotencyError::Corrupt);
            }
            update_observation(
                transaction,
                observation,
                &payload.eligibility,
                &payload.diagnostics_json,
            )?;
            settle_claimed_job(transaction, &current_job, "ready", None, None, settled_at)?;
        }
        VoiceEmbeddingOutcome::QualityRejected {
            diagnostics_json,
            eligibility,
        } => {
            let observation = evidence
                .observation
                .as_ref()
                .ok_or(WalIdempotencyError::Precondition)?;
            update_observation(transaction, observation, eligibility, diagnostics_json)?;
            settle_claimed_job(
                transaction,
                &current_job,
                "ready",
                Some("QUALITY_REJECTED"),
                None,
                settled_at,
            )?;
        }
        VoiceEmbeddingOutcome::Retry {
            error_code,
            retry_at,
        } => {
            let (state, next) = if current_job.attempt_count >= MAX_ATTEMPTS {
                ("failed", None)
            } else {
                ("retry_wait", Some(retry_at.as_str()))
            };
            settle_claimed_job(
                transaction,
                &current_job,
                state,
                Some(error_code),
                next,
                settled_at,
            )?;
        }
        VoiceEmbeddingOutcome::Terminal { error_code } => {
            settle_claimed_job(
                transaction,
                &current_job,
                "failed",
                Some(error_code),
                None,
                settled_at,
            )?;
        }
    }
    Ok(())
}

fn update_observation(
    transaction: &Transaction<'_>,
    observation: &ObservationRow,
    eligibility: &str,
    diagnostics_json: &str,
) -> Result<()> {
    let current = transaction
        .query_row(
            "SELECT transcript_text,voice_eligibility,voice_diagnostics_json
             FROM speaker_observations WHERE id=?1",
            [observation.id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if u32::try_from(current.0.len()).ok() != Some(observation.transcript_length)
        || <[u8; 32]>::from(Sha256::digest(current.0.as_bytes()))
            != observation.transcript_commitment
        || current.1 != observation.prior_eligibility
        || u32::try_from(current.2.as_deref().map_or(0, str::len)).ok()
            != Some(observation.prior_diagnostics_length)
        || <[u8; 32]>::from(Sha256::digest(
            current.2.as_deref().unwrap_or_default().as_bytes(),
        )) != observation.prior_diagnostics_commitment
    {
        return Err(WalIdempotencyError::Precondition);
    }
    let changed = transaction
        .execute(
            "UPDATE speaker_observations SET voice_eligibility=?1,voice_diagnostics_json=?2
             WHERE id=?3 AND voice_eligibility IS ?4 AND voice_diagnostics_json IS ?5",
            params![
                eligibility,
                diagnostics_json,
                observation.id,
                observation.prior_eligibility,
                current.2,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn settle_claimed_job(
    transaction: &Transaction<'_>,
    current: &JobRow,
    state: &str,
    error_code: Option<&str>,
    retry_at: Option<&str>,
    settled_at: &str,
) -> Result<()> {
    let changed = transaction
        .execute(
            "UPDATE voice_embedding_jobs
             SET state=?1,lease_owner=NULL,lease_token=NULL,lease_until=NULL,
                 next_attempt_at=?2,error_code=?3,updated_at=?4
             WHERE id=?5 AND state='processing' AND lease_owner IS ?6 AND lease_token IS ?7
               AND lease_until IS ?8 AND attempt_count=?9 AND next_attempt_at IS ?10
               AND error_code IS ?11 AND updated_at=?12",
            params![
                state,
                retry_at,
                error_code,
                settled_at,
                current.id,
                current.lease_owner,
                current.lease_token,
                current.lease_until,
                current.attempt_count,
                current.next_attempt_at,
                current.error_code,
                current.updated_at,
            ],
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    if changed != 1 {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

impl WalLogicalDomainLedger<VoiceEmbeddingPlan> for VoiceEmbeddingLedger {
    fn lookup(
        connection: &Connection,
        prepared: &PreparedLogicalMutation<VoiceEmbeddingPlan>,
    ) -> Result<Option<WalReplayResult>> {
        require_kind(prepared)?;
        if schema_state(connection)? == LedgerSchemaState::Absent {
            return Ok(None);
        }
        validate_schema_marker(connection)?;
        let row = connection
            .query_row(
                "SELECT format_version,codec_version,request_fingerprint,result_bytes,
                        result_commitment
                 FROM archive_v3_wal_voice_embedding_operations WHERE operation_id=?1",
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
        let kind = WalOperationKind::VoiceEmbedding;
        if format != i64::from(WalOperationKind::format_version())
            || codec != i64::from(kind.codec_version())
            || fingerprint.len() != 32
            || commitment.len() != 32
        {
            return Err(WalIdempotencyError::Corrupt);
        }
        if fingerprint.as_slice()
            != prepared
                .request_fingerprint_for_owner()
                .as_bytes()
                .as_slice()
        {
            return Err(WalIdempotencyError::FingerprintConflict);
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
        prepared: &PreparedLogicalMutation<VoiceEmbeddingPlan>,
    ) -> Result<LogicalMutationResult> {
        require_kind(prepared)?;
        ensure_schema(transaction)?;
        if let Some(result) = Self::lookup(transaction, prepared)? {
            return Ok(LogicalMutationResult::Replayed(result));
        }
        let (row_count, result_bytes) = load_ledger_state(transaction)?;
        BOUNDS.admit(row_count, result_bytes, ENCODED_UNIT_RESULT_BYTES)?;
        let kind = WalOperationKind::VoiceEmbedding;
        let result = prepared.plan_for_domain_ledger().apply(transaction)?;
        prepared.plan_for_domain_ledger().validate_replay(&result)?;
        let encoded = result.encode(kind)?;
        if encoded.len() != ENCODED_UNIT_RESULT_BYTES {
            return Err(WalIdempotencyError::Corrupt);
        }
        let commitment = result.commitment(kind)?;
        transaction
            .execute(
                "INSERT INTO archive_v3_wal_voice_embedding_operations
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
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE archive_v3_wal_voice_embedding_state
                 SET row_count=row_count+1,result_bytes=result_bytes+?1
                 WHERE singleton=1 AND row_count=?2 AND result_bytes=?3",
                params![
                    i64::try_from(encoded.len()).map_err(|_| WalIdempotencyError::Limit)?,
                    i64::from(row_count),
                    i64::try_from(result_bytes).map_err(|_| WalIdempotencyError::Corrupt)?,
                ],
            )
            .map_err(|_| WalIdempotencyError::Unavailable)?;
        if changed != 1 {
            return Err(WalIdempotencyError::Corrupt);
        }
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

fn require_kind(prepared: &PreparedLogicalMutation<VoiceEmbeddingPlan>) -> Result<()> {
    if prepared.kind_for_owner() != WalOperationKind::VoiceEmbedding {
        return Err(WalIdempotencyError::Corrupt);
    }
    Ok(())
}

fn schema_state(connection: &Connection) -> Result<LedgerSchemaState> {
    let present = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN (?1,?2,?3)",
            params![SCHEMA_TABLE, LEDGER_TABLE, STATE_TABLE],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match present {
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
                    "CREATE TABLE archive_v3_wal_voice_embedding_schema (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1)
                     ) STRICT;
                     CREATE TABLE archive_v3_wal_voice_embedding_operations (
                        operation_id BLOB PRIMARY KEY NOT NULL,
                        format_version INTEGER NOT NULL CHECK(format_version=1),
                        codec_version INTEGER NOT NULL CHECK(codec_version=1),
                        request_fingerprint BLOB NOT NULL,
                        result_bytes BLOB NOT NULL,
                        result_commitment BLOB NOT NULL,
                        CHECK(length(operation_id)=16 AND operation_id<>zeroblob(16)),
                        CHECK(length(request_fingerprint)=32 AND request_fingerprint<>zeroblob(32)),
                        CHECK(length(result_bytes)=9),
                        CHECK(length(result_commitment)=32 AND result_commitment<>zeroblob(32))
                     ) STRICT, WITHOUT ROWID;
                     CREATE TABLE archive_v3_wal_voice_embedding_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                        row_count INTEGER NOT NULL CHECK(row_count>=0),
                        result_bytes INTEGER NOT NULL CHECK(result_bytes>=0)
                     ) STRICT;
                     INSERT INTO archive_v3_wal_voice_embedding_schema VALUES (1,1,1);
                     INSERT INTO archive_v3_wal_voice_embedding_state VALUES (1,0,0);",
                )
                .map_err(|_| WalIdempotencyError::Unavailable)?;
            validate_schema_marker(transaction)
        }
    }
}

fn validate_schema_marker(connection: &Connection) -> Result<()> {
    let marker = connection
        .query_row(
            "SELECT format_version,codec_version FROM archive_v3_wal_voice_embedding_schema
             WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?;
    match marker {
        Some((1, 1)) => Ok(()),
        _ => Err(WalIdempotencyError::Corrupt),
    }
}

fn load_ledger_state(connection: &Connection) -> Result<(u32, u64)> {
    let state = connection
        .query_row(
            "SELECT row_count,result_bytes FROM archive_v3_wal_voice_embedding_state
             WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| WalIdempotencyError::Unavailable)?
        .ok_or(WalIdempotencyError::Corrupt)?;
    Ok((
        u32::try_from(state.0).map_err(|_| WalIdempotencyError::Corrupt)?,
        u64::try_from(state.1).map_err(|_| WalIdempotencyError::Corrupt)?,
    ))
}

fn validate_common(
    account_id: &str,
    evidence: &VoiceEmbeddingEvidence,
    lease_token: &str,
    leased_at: &str,
    lease_until: &str,
) -> Result<()> {
    crate::store::validate_user_id(account_id).map_err(|_| WalIdempotencyError::Malformed)?;
    if lease_token.is_empty() || lease_token.len() > MAX_ID_BYTES {
        return Err(WalIdempotencyError::Malformed);
    }
    validate_timestamp(leased_at)?;
    validate_timestamp(lease_until)?;
    validate_timestamp(&evidence.observed_at)?;
    if lease_until <= leased_at || evidence.observed_at != leased_at {
        return Err(WalIdempotencyError::Malformed);
    }
    if evidence.sources.len() > MAX_SOURCES + 1
        || evidence.raw_source_count > MAX_SOURCES + 1
        || evidence.existing_samples.len() > MAX_EXISTING_SAMPLES + 1
    {
        return Err(WalIdempotencyError::Limit);
    }
    Ok(())
}

fn validate_outcome(outcome: &VoiceEmbeddingOutcome, attempt: Option<i64>) -> Result<()> {
    let attempt = attempt.ok_or(WalIdempotencyError::Limit)?;
    if !(1..=MAX_ATTEMPTS).contains(&attempt) {
        return Err(WalIdempotencyError::Malformed);
    }
    match outcome {
        VoiceEmbeddingOutcome::Sample {
            payload,
            sequence_pin,
        } => {
            validate_sample(payload)?;
            if *sequence_pin < 0 || *sequence_pin == i64::MAX {
                return Err(WalIdempotencyError::Limit);
            }
        }
        VoiceEmbeddingOutcome::QualityRejected {
            diagnostics_json,
            eligibility,
        } => validate_diagnostics(diagnostics_json, eligibility)?,
        VoiceEmbeddingOutcome::Retry {
            error_code,
            retry_at,
        } => {
            validate_error(error_code)?;
            validate_timestamp(retry_at)?;
        }
        VoiceEmbeddingOutcome::Terminal { error_code } => validate_error(error_code)?,
    }
    Ok(())
}

fn validate_sample(sample: &VoiceSamplePayload) -> Result<()> {
    if sample.vector_bytes.len() != EMBEDDING_BYTES
        || sample.duration_ms <= 0
        || sample.acoustic_domain.is_empty()
        || sample.acoustic_domain.len() > MAX_DOMAIN_BYTES
        || ![
            sample.speech_ratio,
            sample.snr_proxy_db,
            sample.clipping_ratio,
            sample.silence_ratio,
            sample.embedding_norm,
        ]
        .iter()
        .all(|value| value.is_finite())
        || sample.embedding_norm <= 0.0
    {
        return Err(WalIdempotencyError::Malformed);
    }
    if sample
        .vector_bytes
        .chunks_exact(4)
        .any(|chunk| !f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]).is_finite())
    {
        return Err(WalIdempotencyError::Malformed);
    }
    validate_diagnostics(&sample.diagnostics_json, &sample.eligibility)
}

fn validate_diagnostics(diagnostics: &str, eligibility: &str) -> Result<()> {
    if diagnostics.is_empty()
        || diagnostics.len() > MAX_DIAGNOSTICS_BYTES
        || eligibility.is_empty()
        || eligibility.len() > 64
        || serde_json::from_str::<serde_json::Value>(diagnostics).is_err()
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn validate_error(error: &str) -> Result<()> {
    if error.is_empty()
        || error.len() > MAX_ERROR_BYTES
        || !error
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn valid_job_strings(job: &JobRow) -> bool {
    let bounded = |value: &str, cap: usize| !value.is_empty() && value.len() <= cap;
    bounded(&job.embedding_space, MAX_ID_BYTES)
        && bounded(&job.state, 32)
        && job
            .lease_owner
            .as_deref()
            .is_none_or(|value| bounded(value, MAX_ID_BYTES))
        && job
            .lease_token
            .as_deref()
            .is_none_or(|value| bounded(value, MAX_ID_BYTES))
        && job
            .lease_until
            .as_deref()
            .is_none_or(|value| validate_timestamp(value).is_ok())
        && job
            .next_attempt_at
            .as_deref()
            .is_none_or(|value| validate_timestamp(value).is_ok())
        && job
            .error_code
            .as_deref()
            .is_none_or(|value| validate_error(value).is_ok())
        && validate_timestamp(&job.created_at).is_ok()
        && validate_timestamp(&job.updated_at).is_ok()
}

fn valid_observation(row: &ObservationRow) -> bool {
    row.id > 0
        && row.person_id.is_none_or(|value| value > 0)
        && !row.event_id.is_empty()
        && row.event_id.len() <= MAX_ID_BYTES
        && !row.turn_id.is_empty()
        && row.turn_id.len() <= MAX_ID_BYTES
        && !row.speaker_local_id.is_empty()
        && row.speaker_local_id.len() <= MAX_ID_BYTES
        && validate_timestamp(&row.started_at).is_ok()
        && validate_timestamp(&row.ended_at).is_ok()
        && row.started_at <= row.ended_at
        && row.transcript_commitment != [0; 32]
        && row
            .language
            .as_deref()
            .is_none_or(|value| value.len() <= 64)
        && row
            .prior_eligibility
            .as_deref()
            .is_none_or(|value| value.len() <= 64)
}

fn valid_source(account_id: &str, source: &VoiceEmbeddingSource) -> bool {
    let prefix = format!("raw/{account_id}/");
    let window_duration = source.window_end_ms.checked_sub(source.window_start_ms);
    let event_duration = source.event_end_ms.checked_sub(source.event_start_ms);
    !source.event_id.is_empty()
        && source.event_id.len() <= MAX_ID_BYTES
        && source.window_start_ms >= 0
        && source.window_end_ms > source.window_start_ms
        && source.window_end_ms <= super::super::media_planner::MAX_AUDIO_WINDOW_MS
        && source.event_start_ms >= 0
        && source.event_end_ms > source.event_start_ms
        && source.event_end_ms <= super::super::media_planner::MAX_AUDIO_WINDOW_MS
        && window_duration == event_duration
        && !source.stream_kind.is_empty()
        && source.stream_kind.len() <= 64
        && source
            .audio_role
            .as_deref()
            .is_none_or(|value| value.len() <= 64)
        && source
            .audio_route
            .as_deref()
            .is_none_or(|value| value.len() <= 128)
        && source.object_key.starts_with(&prefix)
        && source.object_key.len() <= MAX_KEY_BYTES
        && source.sha256.len() == 64
        && source.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        && (1..=20 * 1024 * 1024).contains(&source.byte_length)
        && !source.mime_type.is_empty()
        && source.mime_type.len() <= MAX_MIME_BYTES
        && matches!(source.processing_state.as_str(), "ready" | "processing")
}

fn validate_timestamp(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TIMESTAMP_BYTES
        || crate::cp::isotime::parse_epoch_millis(value)
            .is_none_or(|millis| crate::cp::isotime::format_epoch_millis(millis) != value)
    {
        return Err(WalIdempotencyError::Malformed);
    }
    Ok(())
}

fn outcome_commitment(outcome: &VoiceEmbeddingOutcome) -> Result<[u8; 32]> {
    let mut encoded = Vec::new();
    encode_outcome(&mut encoded, outcome)?;
    Ok(Sha256::digest(&encoded).into())
}

fn encode_backfill_evidence(
    output: &mut Vec<u8>,
    evidence: &VoiceJobBackfillEvidence,
) -> Result<()> {
    encode_string(output, &evidence.account_id)?;
    encode_observation(output, &evidence.observation)?;
    encode_len(output, evidence.sample_count)?;
    encode_len(output, evidence.job_count)?;
    encode_sequence_pin(output, &evidence.job_sequence)
}

fn encode_evidence(output: &mut Vec<u8>, evidence: &VoiceEmbeddingEvidence) -> Result<()> {
    encode_string(output, &evidence.account_id)?;
    encode_string(output, &evidence.observed_at)?;
    encode_job(output, &evidence.job)?;
    match &evidence.observation {
        Some(row) => {
            output.push(1);
            encode_observation(output, row)?;
        }
        None => output.push(0),
    }
    encode_len(output, evidence.sources.len())?;
    encode_len(output, evidence.raw_source_count)?;
    for source in &evidence.sources {
        encode_source(output, source)?;
    }
    encode_len(output, evidence.existing_samples.len())?;
    for sample in &evidence.existing_samples {
        output.extend_from_slice(&sample.id.to_be_bytes());
        output.extend_from_slice(&sample.speaker_observation_id.to_be_bytes());
        encode_optional_i64(output, sample.embedding_job_id);
    }
    output.push(u8::from(evidence.existing_sample_overflow));
    encode_sequence_pin(output, &evidence.sample_sequence)?;
    match &evidence.wrapped_media_dek {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(
                &u32::try_from(value.len())
                    .map_err(|_| WalIdempotencyError::Limit)?
                    .to_be_bytes(),
            );
            output.extend_from_slice(&<[u8; 32]>::from(Sha256::digest(value.as_bytes())));
        }
        None => output.push(0),
    }
    Ok(())
}

fn encode_observation(output: &mut Vec<u8>, row: &ObservationRow) -> Result<()> {
    output.extend_from_slice(&row.id.to_be_bytes());
    encode_optional_i64(output, row.person_id);
    encode_text_commitment(output, &row.event_id)?;
    encode_text_commitment(output, &row.turn_id)?;
    encode_text_commitment(output, &row.speaker_local_id)?;
    encode_text_commitment(output, &row.started_at)?;
    encode_text_commitment(output, &row.ended_at)?;
    output.extend_from_slice(&row.transcript_length.to_be_bytes());
    output.extend_from_slice(&row.transcript_commitment);
    encode_optional_text_commitment(output, row.language.as_deref())?;
    output.push(u8::from(row.overlap));
    encode_optional_text_commitment(output, row.prior_eligibility.as_deref())?;
    output.extend_from_slice(&row.prior_diagnostics_length.to_be_bytes());
    output.extend_from_slice(&row.prior_diagnostics_commitment);
    Ok(())
}

fn encode_sequence_pin(output: &mut Vec<u8>, pin: &VoiceSampleSequencePin) -> Result<()> {
    output.extend_from_slice(&pin.table_sql_length.to_be_bytes());
    output.extend_from_slice(&pin.table_sql_commitment);
    output.push(u8::from(pin.autoincrement));
    encode_text_commitment(output, &pin.storage_type)?;
    encode_optional_i64(output, pin.value);
    Ok(())
}

fn encode_job(output: &mut Vec<u8>, job: &JobRow) -> Result<()> {
    output.extend_from_slice(&job.id.to_be_bytes());
    output.extend_from_slice(&job.speaker_observation_id.to_be_bytes());
    encode_text_commitment(output, &job.embedding_space)?;
    output.extend_from_slice(&job.processor_version.to_be_bytes());
    output.extend_from_slice(&job.quality_version.to_be_bytes());
    output.extend_from_slice(&job.scorer_version.to_be_bytes());
    encode_text_commitment(output, &job.state)?;
    encode_optional_text_commitment(output, job.lease_owner.as_deref())?;
    encode_optional_text_commitment(output, job.lease_token.as_deref())?;
    encode_optional_text_commitment(output, job.lease_until.as_deref())?;
    output.extend_from_slice(&job.attempt_count.to_be_bytes());
    encode_optional_text_commitment(output, job.next_attempt_at.as_deref())?;
    encode_optional_text_commitment(output, job.error_code.as_deref())?;
    encode_text_commitment(output, &job.created_at)?;
    encode_text_commitment(output, &job.updated_at)
}

fn encode_source(output: &mut Vec<u8>, source: &VoiceEmbeddingSource) -> Result<()> {
    encode_text_commitment(output, &source.event_id)?;
    for value in [
        source.window_start_ms,
        source.window_end_ms,
        source.event_start_ms,
        source.event_end_ms,
    ] {
        output.extend_from_slice(&value.to_be_bytes());
    }
    encode_text_commitment(output, &source.stream_kind)?;
    encode_optional_text_commitment(output, source.audio_role.as_deref())?;
    encode_optional_text_commitment(output, source.audio_route.as_deref())?;
    encode_text_commitment(output, &source.object_key)?;
    encode_optional_i64(output, source.object_generation);
    encode_optional_text_commitment(output, source.object_backend.as_deref())?;
    encode_text_commitment(output, &source.sha256)?;
    output.extend_from_slice(&source.byte_length.to_be_bytes());
    encode_text_commitment(output, &source.mime_type)?;
    encode_text_commitment(output, &source.processing_state)?;
    encode_optional_text_commitment(output, source.deleted_at.as_deref())
}

fn encode_outcome(output: &mut Vec<u8>, outcome: &VoiceEmbeddingOutcome) -> Result<()> {
    match outcome {
        VoiceEmbeddingOutcome::Sample {
            payload,
            sequence_pin,
        } => {
            output.push(1);
            encode_bytes(output, &payload.vector_bytes)?;
            encode_string(output, &payload.diagnostics_json)?;
            encode_string(output, &payload.eligibility)?;
            output.extend_from_slice(&payload.duration_ms.to_be_bytes());
            for value in [
                payload.speech_ratio,
                payload.snr_proxy_db,
                payload.clipping_ratio,
                payload.silence_ratio,
                payload.embedding_norm,
            ] {
                output.extend_from_slice(&value.to_bits().to_be_bytes());
            }
            encode_string(output, &payload.acoustic_domain)?;
            output.extend_from_slice(&sequence_pin.to_be_bytes());
        }
        VoiceEmbeddingOutcome::QualityRejected {
            diagnostics_json,
            eligibility,
        } => {
            output.push(2);
            encode_string(output, diagnostics_json)?;
            encode_string(output, eligibility)?;
        }
        VoiceEmbeddingOutcome::Retry {
            error_code,
            retry_at,
        } => {
            output.push(3);
            encode_string(output, error_code)?;
            encode_string(output, retry_at)?;
        }
        VoiceEmbeddingOutcome::Terminal { error_code } => {
            output.push(4);
            encode_string(output, error_code)?;
        }
    }
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

fn encode_optional_string(output: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        Some(value) => {
            output.push(1);
            encode_string(output, value)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

fn encode_optional_text_commitment(output: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        Some(value) => {
            output.push(1);
            encode_text_commitment(output, value)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

fn encode_text_commitment(output: &mut Vec<u8>, value: &str) -> Result<()> {
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&<[u8; 32]>::from(Sha256::digest(value.as_bytes())));
    Ok(())
}

fn encode_len(output: &mut Vec<u8>, value: usize) -> Result<()> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| WalIdempotencyError::Limit)?
            .to_be_bytes(),
    );
    Ok(())
}

fn encode_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    encode_bytes(output, value.as_bytes())
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    encode_len(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_wal_idempotency::{
        execute_prepared_for_owner, LogicalMutationDisposition,
    };

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const OBSERVED_AT: &str = "2026-08-22T12:00:00.000Z";
    const LEASE_UNTIL: &str = "2026-08-22T12:05:00.000Z";
    const SETTLED_AT: &str = "2026-08-22T12:00:05.000Z";
    const RETRY_AT: &str = "2026-08-22T12:01:05.000Z";
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn install_schema(connection: &Connection) {
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE app_metadata (key TEXT PRIMARY KEY,value TEXT);
                 CREATE TABLE capture_events (
                    event_id TEXT PRIMARY KEY,stream_kind TEXT NOT NULL,
                    audio_role TEXT,audio_route TEXT
                 );
                 CREATE TABLE media_objects (
                    event_id TEXT PRIMARY KEY,object_key TEXT NOT NULL,
                    object_generation INTEGER,object_backend TEXT,sha256 TEXT NOT NULL,
                    byte_length INTEGER NOT NULL,mime_type TEXT NOT NULL,
                    processing_state TEXT NOT NULL,deleted_at TEXT
                 );
                 CREATE TABLE speaker_observations (
                    id INTEGER PRIMARY KEY,person_id INTEGER,event_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,speaker_local_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,ended_at TEXT NOT NULL,
                    transcript_text TEXT NOT NULL,language TEXT,overlap INTEGER NOT NULL,
                    voice_eligibility TEXT,voice_diagnostics_json TEXT
                 );
                 CREATE TABLE speaker_observation_sources (
                    speaker_observation_id INTEGER NOT NULL,event_id TEXT NOT NULL,
                    window_start_ms INTEGER NOT NULL,window_end_ms INTEGER NOT NULL,
                    event_start_ms INTEGER NOT NULL,event_end_ms INTEGER NOT NULL,
                    PRIMARY KEY(speaker_observation_id,event_id,window_start_ms)
                 );
                 CREATE TABLE voice_embedding_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    speaker_observation_id INTEGER NOT NULL,
                    embedding_space TEXT NOT NULL,processor_version INTEGER NOT NULL,
                    quality_version INTEGER NOT NULL,scorer_version INTEGER NOT NULL,
                    state TEXT NOT NULL,lease_owner TEXT,lease_token TEXT,lease_until TEXT,
                    attempt_count INTEGER NOT NULL,next_attempt_at TEXT,error_code TEXT,
                    created_at TEXT NOT NULL,updated_at TEXT NOT NULL
                 );
                 CREATE UNIQUE INDEX idx_voice_embedding_jobs_identity
                 ON voice_embedding_jobs(
                    speaker_observation_id,embedding_space,processor_version,
                    quality_version,scorer_version);
                 CREATE TABLE voice_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    speaker_observation_id INTEGER NOT NULL,voice_profile_id INTEGER,
                    embedding_space TEXT NOT NULL,channel_domain TEXT NOT NULL,
                    embedding BLOB NOT NULL,quality_score REAL NOT NULL,
                    diagnostics_json TEXT NOT NULL,quality_version INTEGER NOT NULL,
                    scorer_version INTEGER NOT NULL,eligibility TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,speech_ratio REAL NOT NULL,
                    snr_proxy_db REAL NOT NULL,clipping_ratio REAL NOT NULL,
                    silence_ratio REAL NOT NULL,embedding_norm REAL NOT NULL,
                    outlier INTEGER NOT NULL,similarity REAL,decision_margin REAL,
                    accepted INTEGER NOT NULL,embedding_job_id INTEGER,created_at TEXT NOT NULL
                 );
                 CREATE UNIQUE INDEX idx_voice_samples_job
                 ON voice_samples(embedding_job_id)
                 WHERE embedding_job_id IS NOT NULL;",
            )
            .unwrap();
    }

    fn seed_observation_without_job(connection: &Connection, id: i64, event: &str) {
        connection
            .execute(
                "INSERT INTO capture_events VALUES (?1,'audio','system','microphone')",
                [event],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO media_objects VALUES
                 (?1,?2,1,'current',?3,4096,'audio/wav','ready',NULL)",
                params![event, format!("raw/{ACCOUNT}/{event}.enc"), "a".repeat(64)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO speaker_observations VALUES
                 (?1,NULL,?2,?3,'speaker-1',?4,?5,'bounded transcript','en',0,NULL,NULL)",
                params![
                    id,
                    event,
                    format!("turn-{id}"),
                    "2026-08-22T11:59:50.000Z",
                    "2026-08-22T11:59:51.000Z"
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO speaker_observation_sources VALUES (?1,?2,0,1000,0,1000)",
                params![id, event],
            )
            .unwrap();
    }

    fn seed_observation(connection: &Connection, id: i64, event: &str) {
        seed_observation_without_job(connection, id, event);
        connection
            .execute(
                "INSERT INTO voice_embedding_jobs
                 (id,speaker_observation_id,embedding_space,processor_version,quality_version,
                  scorer_version,state,attempt_count,created_at,updated_at)
                 VALUES (?1,?1,?2,1,1,2,'pending',0,?3,?3)",
                params![id, EMBEDDING_SPACE, "2026-08-22T11:59:55.000Z"],
            )
            .unwrap();
    }

    fn fixture(two_jobs: bool) -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        install_schema(&connection);
        connection
            .execute(
                "INSERT INTO app_metadata VALUES ('wrapped_media_dek','wrapped-v2')",
                [],
            )
            .unwrap();
        seed_observation(&connection, 1, "event-1");
        if two_jobs {
            seed_observation(&connection, 2, "event-2");
        }
        connection
    }

    fn observe(connection: &Connection, at: &str) -> VoiceEmbeddingEvidence {
        observe_next(connection, ACCOUNT, at).unwrap().unwrap()
    }

    fn execute(
        connection: &mut Connection,
        plan: VoiceEmbeddingPlan,
    ) -> Result<LogicalMutationDisposition> {
        let prepared = PreparedLogicalMutation::prepare(plan)?;
        execute_prepared_for_owner(connection, prepared).map(|result| result.disposition())
    }

    fn claim(evidence: VoiceEmbeddingEvidence, at: &str, until: &str) -> VoiceEmbeddingPlan {
        VoiceEmbeddingPlan::claim(
            ACCOUNT.to_owned(),
            evidence,
            TOKEN.to_owned(),
            at.to_owned(),
            until.to_owned(),
        )
        .unwrap()
    }

    fn sample_payload() -> VoiceSamplePayload {
        VoiceSamplePayload::new(
            (0..EMBEDDING_DIMENSION)
                .flat_map(|index| ((index + 1) as f32 / 256.0).to_le_bytes())
                .collect(),
            r#"{"decision":"enroll"}"#.to_owned(),
            "enroll".to_owned(),
            1_000,
            0.9,
            18.0,
            0.01,
            0.05,
            1.0,
            "audio:system:microphone".to_owned(),
        )
        .unwrap()
    }

    fn sample_row(connection: &Connection, observation_id: i64, job_id: Option<i64>) {
        connection
            .execute(
                "INSERT INTO voice_samples
                 (speaker_observation_id,voice_profile_id,embedding_space,channel_domain,
                  embedding,quality_score,diagnostics_json,quality_version,scorer_version,
                  eligibility,duration_ms,speech_ratio,snr_proxy_db,clipping_ratio,silence_ratio,
                  embedding_norm,outlier,similarity,decision_margin,accepted,embedding_job_id,
                  created_at)
                 VALUES (?1,NULL,?2,'audio',?3,0.8,'{}',1,2,'enroll',1000,0.9,18.0,
                         0.01,0.05,1.0,0,NULL,NULL,1,?4,?5)",
                params![
                    observation_id,
                    EMBEDDING_SPACE,
                    vec![0_u8; EMBEDDING_BYTES],
                    job_id,
                    SETTLED_AT
                ],
            )
            .unwrap();
    }

    #[test]
    fn historical_v1_observation_job_backfill_is_exact_replayable_and_policy_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive.db");
        let mut evidence = {
            let mut connection = Connection::open(&path).unwrap();
            install_schema(&connection);
            // This is the exact durable output shape of the production v1
            // transcript family: the observation and its projected source
            // exist, while neither a voice sample nor an embedding job does.
            // Do not obtain the fixture by deleting a v2 job; doing so would
            // let this compatibility proof drift away from the deployed v1
            // predecessor it is responsible for repairing.
            seed_observation_without_job(&connection, 1, "event-1");
            let evidence = observe_next_job_backfill(&connection, ACCOUNT)
                .unwrap()
                .unwrap();
            assert_eq!(evidence.sample_count, 0);
            assert_eq!(evidence.job_count, 0);
            assert_eq!(evidence.job_sequence.next_id(), Some(1));
            assert_eq!(
                execute(
                    &mut connection,
                    VoiceEmbeddingPlan::backfill_job(
                        ACCOUNT.to_owned(),
                        evidence.clone(),
                        OBSERVED_AT.to_owned(),
                    )
                    .unwrap(),
                )
                .unwrap(),
                LogicalMutationDisposition::Applied
            );
            assert!(observe_next_job_backfill(&connection, ACCOUNT)
                .unwrap()
                .is_none());
            evidence
        };

        let mut reopened = Connection::open(&path).unwrap();
        assert_eq!(
            execute(
                &mut reopened,
                VoiceEmbeddingPlan::backfill_job(
                    ACCOUNT.to_owned(),
                    evidence.clone(),
                    OBSERVED_AT.to_owned(),
                )
                .unwrap(),
            )
            .unwrap(),
            LogicalMutationDisposition::Replayed
        );
        assert_eq!(
            reopened
                .query_row(
                    "SELECT id,speaker_observation_id,state,attempt_count,typeof(id),
                            typeof(attempt_count),created_at
                     FROM voice_embedding_jobs",
                    [],
                    |row| Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    )),
                )
                .unwrap(),
            (
                1,
                1,
                "pending".to_owned(),
                0,
                "integer".to_owned(),
                "integer".to_owned(),
                OBSERVED_AT.to_owned(),
            )
        );
        reopened
            .execute(
                "UPDATE voice_embedding_jobs SET state='ready'
                 WHERE speaker_observation_id=1",
                [],
            )
            .unwrap();

        // A stale exact transcript predecessor cannot be used to insert a
        // second job, and intentional policy abstentions remain absent.
        evidence.observation.transcript_commitment = [7; 32];
        let stale =
            VoiceEmbeddingPlan::backfill_job(ACCOUNT.to_owned(), evidence, OBSERVED_AT.to_owned())
                .unwrap();
        assert_eq!(
            execute(&mut reopened, stale).unwrap_err(),
            WalIdempotencyError::FingerprintConflict
        );

        seed_observation(&reopened, 3, "event-3");
        reopened
            .execute("DELETE FROM voice_embedding_jobs WHERE id=3", [])
            .unwrap();
        reopened
            .execute("UPDATE speaker_observations SET overlap=1 WHERE id=3", [])
            .unwrap();
        assert!(observe_next_job_backfill(&reopened, ACCOUNT)
            .unwrap()
            .is_none());

        seed_observation(&reopened, 4, "event-4");
        reopened
            .execute("DELETE FROM voice_embedding_jobs WHERE id=4", [])
            .unwrap();
        let pruned_media = observe_next_job_backfill(&reopened, ACCOUNT)
            .unwrap()
            .unwrap();
        reopened
            .execute(
                "UPDATE media_objects SET processing_state='pruned' WHERE event_id='event-4'",
                [],
            )
            .unwrap();
        assert_eq!(
            execute(
                &mut reopened,
                VoiceEmbeddingPlan::backfill_job(
                    ACCOUNT.to_owned(),
                    pruned_media,
                    OBSERVED_AT.to_owned(),
                )
                .unwrap(),
            )
            .unwrap(),
            LogicalMutationDisposition::Applied
        );
        let pruned_job = observe(&reopened, OBSERVED_AT);
        assert_eq!(
            pruned_job.disposition(),
            VoiceClaimDisposition::Terminal("ERR_MEDIA_PRUNED")
        );
        assert_eq!(
            execute(&mut reopened, claim(pruned_job, OBSERVED_AT, LEASE_UNTIL),).unwrap(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            reopened
                .query_row(
                    "SELECT state,error_code,attempt_count
                     FROM voice_embedding_jobs WHERE speaker_observation_id=4",
                    [],
                    |row| Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    )),
                )
                .unwrap(),
            ("failed".to_owned(), Some("ERR_MEDIA_PRUNED".to_owned()), 0)
        );
    }

    #[test]
    fn exact_claim_and_sample_settlement_replay_without_allocating_inside_apply() {
        let mut connection = fixture(false);
        let evidence = observe(&connection, OBSERVED_AT);
        assert_eq!(evidence.disposition(), VoiceClaimDisposition::Authorized);
        assert_eq!(evidence.sample_sequence_pin(), Some(0));
        assert_eq!(
            execute(
                &mut connection,
                claim(evidence.clone(), OBSERVED_AT, LEASE_UNTIL),
            )
            .unwrap(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            execute(
                &mut connection,
                claim(evidence.clone(), OBSERVED_AT, LEASE_UNTIL),
            )
            .unwrap(),
            LogicalMutationDisposition::Replayed
        );
        let claim_state: (String, i64, String) = connection
            .query_row(
                "SELECT state,attempt_count,typeof(attempt_count) FROM voice_embedding_jobs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            claim_state,
            ("processing".to_owned(), 1, "integer".to_owned())
        );

        assert_eq!(
            execute(
                &mut connection,
                VoiceEmbeddingPlan::settle(
                    ACCOUNT.to_owned(),
                    evidence.clone(),
                    TOKEN.to_owned(),
                    OBSERVED_AT.to_owned(),
                    LEASE_UNTIL.to_owned(),
                    SETTLED_AT.to_owned(),
                    VoiceEmbeddingOutcome::Sample {
                        payload: sample_payload(),
                        sequence_pin: 0,
                    },
                )
                .unwrap(),
            )
            .unwrap(),
            LogicalMutationDisposition::Applied
        );
        assert_eq!(
            execute(
                &mut connection,
                VoiceEmbeddingPlan::settle(
                    ACCOUNT.to_owned(),
                    evidence,
                    TOKEN.to_owned(),
                    OBSERVED_AT.to_owned(),
                    LEASE_UNTIL.to_owned(),
                    SETTLED_AT.to_owned(),
                    VoiceEmbeddingOutcome::Sample {
                        payload: sample_payload(),
                        sequence_pin: 0,
                    },
                )
                .unwrap(),
            )
            .unwrap(),
            LogicalMutationDisposition::Replayed
        );
        let sample: (i64, i64, i64, i64, String) = connection
            .query_row(
                "SELECT id,accepted,embedding_job_id,length(embedding),typeof(id)
                 FROM voice_samples",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            sample,
            (1, -1, 1, EMBEDDING_BYTES as i64, "integer".to_owned())
        );
        assert_eq!(
            connection
                .query_row("SELECT state FROM voice_embedding_jobs", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .unwrap(),
            "ready"
        );
    }

    #[test]
    fn stale_source_or_allocator_evidence_rolls_back_the_entire_result() {
        let mut connection = fixture(false);
        let evidence = observe(&connection, OBSERVED_AT);
        execute(
            &mut connection,
            claim(evidence.clone(), OBSERVED_AT, LEASE_UNTIL),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE media_objects SET sha256=?1 WHERE event_id='event-1'",
                ["b".repeat(64)],
            )
            .unwrap();
        let stale = VoiceEmbeddingPlan::settle(
            ACCOUNT.to_owned(),
            evidence.clone(),
            TOKEN.to_owned(),
            OBSERVED_AT.to_owned(),
            LEASE_UNTIL.to_owned(),
            SETTLED_AT.to_owned(),
            VoiceEmbeddingOutcome::Sample {
                payload: sample_payload(),
                sequence_pin: 0,
            },
        )
        .unwrap();
        assert_eq!(
            execute(&mut connection, stale).unwrap_err(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_samples", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT state FROM voice_embedding_jobs", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .unwrap(),
            "processing"
        );
    }

    #[test]
    fn malformed_attempt_allocator_and_oversized_rows_settle_before_provider_work() {
        for (label, poison_sql) in [
            (
                "negative attempt",
                "UPDATE voice_embedding_jobs SET attempt_count=-1 WHERE id=1",
            ),
            (
                "attempt cap",
                "UPDATE voice_embedding_jobs SET attempt_count=3 WHERE id=1",
            ),
            (
                "attempt max",
                "UPDATE voice_embedding_jobs SET attempt_count=9223372036854775807 WHERE id=1",
            ),
        ] {
            let mut connection = fixture(true);
            connection.execute(poison_sql, []).unwrap();
            let evidence = observe(&connection, OBSERVED_AT);
            assert!(matches!(
                evidence.disposition(),
                VoiceClaimDisposition::Terminal("ERR_JOB_MALFORMED")
            ));
            execute(&mut connection, claim(evidence, OBSERVED_AT, LEASE_UNTIL))
                .unwrap_or_else(|error| panic!("{label}: {error:?}"));
            let stored: (String, String) = connection
                .query_row(
                    "SELECT state,typeof(attempt_count) FROM voice_embedding_jobs WHERE id=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                stored,
                ("failed".to_owned(), "integer".to_owned()),
                "{label}"
            );
            assert_eq!(observe(&connection, OBSERVED_AT).job_id(), 2, "{label}");
        }

        let mut connection = fixture(true);
        connection
            .execute(
                "UPDATE voice_embedding_jobs SET error_code=?1 WHERE id=1",
                ["x".repeat(1_100_000)],
            )
            .unwrap();
        let evidence = observe(&connection, OBSERVED_AT);
        let prepared = PreparedLogicalMutation::prepare(claim(evidence, OBSERVED_AT, LEASE_UNTIL))
            .expect("raw poisoned fields travel only through fixed-size commitments");
        execute_prepared_for_owner(&mut connection, prepared).unwrap();
        assert_eq!(observe(&connection, OBSERVED_AT).job_id(), 2);

        let mut connection = fixture(true);
        connection
            .execute(
                "INSERT INTO sqlite_sequence(name,seq) VALUES ('voice_samples',9223372036854775807)",
                [],
            )
            .unwrap();
        let evidence = observe(&connection, OBSERVED_AT);
        assert_eq!(
            evidence.disposition(),
            VoiceClaimDisposition::Terminal("ERR_SAMPLE_CAPACITY")
        );
        execute(&mut connection, claim(evidence, OBSERVED_AT, LEASE_UNTIL)).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT typeof(seq) FROM sqlite_sequence WHERE name='voice_samples'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "integer"
        );
        assert_eq!(observe(&connection, OBSERVED_AT).job_id(), 2);
    }

    #[test]
    fn existing_sample_link_is_exact_and_stale_evidence_cannot_overwrite_it() {
        let mut connection = fixture(false);
        sample_row(&connection, 1, None);
        let evidence = observe(&connection, OBSERVED_AT);
        assert_eq!(
            evidence.disposition(),
            VoiceClaimDisposition::ExistingSample
        );
        connection
            .execute(
                "UPDATE voice_samples SET embedding_job_id=99 WHERE id=1",
                [],
            )
            .unwrap();
        assert_eq!(
            execute(&mut connection, claim(evidence, OBSERVED_AT, LEASE_UNTIL)).unwrap_err(),
            WalIdempotencyError::Precondition
        );
        assert_eq!(
            connection
                .query_row("SELECT state FROM voice_embedding_jobs", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .unwrap(),
            "pending"
        );
        let fresh = observe(&connection, OBSERVED_AT);
        execute(&mut connection, claim(fresh, OBSERVED_AT, LEASE_UNTIL)).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT embedding_job_id FROM voice_samples", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            99
        );
    }

    #[test]
    fn multiple_existing_samples_terminalize_without_unique_index_wedge() {
        let mut connection = fixture(true);
        sample_row(&connection, 1, None);
        sample_row(&connection, 1, None);
        let evidence = observe(&connection, OBSERVED_AT);
        assert_eq!(
            evidence.disposition(),
            VoiceClaimDisposition::Terminal("ERR_SAMPLE_TOPOLOGY")
        );
        execute(&mut connection, claim(evidence, OBSERVED_AT, LEASE_UNTIL)).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT state,error_code,attempt_count FROM voice_embedding_jobs WHERE id=1",
                    [],
                    |row| Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?
                    )),
                )
                .unwrap(),
            ("failed".to_owned(), "ERR_SAMPLE_TOPOLOGY".to_owned(), 0)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM voice_samples WHERE embedding_job_id IS NOT NULL",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(observe(&connection, OBSERVED_AT).job_id(), 2);
    }

    #[test]
    fn backward_clock_defers_without_mutating_or_charging_the_job() {
        let connection = fixture(true);
        connection
            .execute(
                "UPDATE voice_embedding_jobs
                 SET created_at='2026-08-22T12:01:00.000Z',updated_at='2026-08-22T12:01:00.000Z'
                 WHERE id=1",
                [],
            )
            .unwrap();
        let evidence = observe(&connection, OBSERVED_AT);
        assert_eq!(evidence.disposition(), VoiceClaimDisposition::ClockDeferred);
        let error = match VoiceEmbeddingPlan::claim(
            ACCOUNT.to_owned(),
            evidence,
            TOKEN.to_owned(),
            OBSERVED_AT.to_owned(),
            LEASE_UNTIL.to_owned(),
        ) {
            Ok(_) => panic!("clock-deferred evidence unexpectedly constructed a claim"),
            Err(error) => error,
        };
        assert_eq!(error, WalIdempotencyError::Precondition);
        assert_eq!(
            connection
                .query_row(
                    "SELECT state,attempt_count,error_code,updated_at
                     FROM voice_embedding_jobs WHERE id=1",
                    [],
                    |row| Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?
                    )),
                )
                .unwrap(),
            (
                "pending".to_owned(),
                0,
                None,
                "2026-08-22T12:01:00.000Z".to_owned(),
            )
        );
    }

    #[test]
    fn missing_source_child_terminalizes_without_partial_embedding_topology() {
        let mut connection = fixture(true);
        connection
            .execute("DELETE FROM media_objects WHERE event_id='event-1'", [])
            .unwrap();
        let evidence = observe(&connection, OBSERVED_AT);
        assert_eq!(evidence.raw_source_count, 1);
        assert!(evidence.sources().is_empty());
        assert_eq!(
            evidence.disposition(),
            VoiceClaimDisposition::Terminal("ERR_SOURCE_TOPOLOGY")
        );
        execute(&mut connection, claim(evidence, OBSERVED_AT, LEASE_UNTIL)).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT state,error_code,attempt_count FROM voice_embedding_jobs WHERE id=1",
                    [],
                    |row| Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?
                    )),
                )
                .unwrap(),
            ("failed".to_owned(), "ERR_SOURCE_TOPOLOGY".to_owned(), 0)
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_samples", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(observe(&connection, OBSERVED_AT).job_id(), 2);
    }

    #[test]
    fn retry_ladder_is_checked_and_the_third_provider_failure_is_terminal() {
        let mut connection = fixture(false);
        let mut observed_at = OBSERVED_AT.to_owned();
        for attempt in 1..=MAX_ATTEMPTS {
            let evidence = observe(&connection, &observed_at);
            let lease_until = crate::cp::isotime::add_seconds(&observed_at, 300.0);
            execute(
                &mut connection,
                claim(evidence.clone(), &observed_at, &lease_until),
            )
            .unwrap();
            let settled_at = crate::cp::isotime::add_seconds(&observed_at, 5.0);
            let retry_at = crate::cp::isotime::add_seconds(&settled_at, 60.0);
            execute(
                &mut connection,
                VoiceEmbeddingPlan::settle(
                    ACCOUNT.to_owned(),
                    evidence,
                    TOKEN.to_owned(),
                    observed_at.clone(),
                    lease_until,
                    settled_at,
                    VoiceEmbeddingOutcome::Retry {
                        error_code: "ERR_INFERENCE".to_owned(),
                        retry_at: retry_at.clone(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
            let stored: (String, i64, String) = connection
                .query_row(
                    "SELECT state,attempt_count,typeof(attempt_count) FROM voice_embedding_jobs",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(stored.1, attempt);
            assert_eq!(stored.2, "integer");
            assert_eq!(
                stored.0,
                if attempt == MAX_ATTEMPTS {
                    "failed"
                } else {
                    "retry_wait"
                }
            );
            observed_at = retry_at;
        }
        assert!(observe_next(&connection, ACCOUNT, &observed_at)
            .unwrap()
            .is_none());
    }

    #[test]
    fn ledger_capacity_refuses_before_a_result_mutates_domain_rows() {
        let mut connection = fixture(false);
        let evidence = observe(&connection, OBSERVED_AT);
        execute(
            &mut connection,
            claim(evidence.clone(), OBSERVED_AT, LEASE_UNTIL),
        )
        .unwrap();
        connection
            .execute(
                "UPDATE archive_v3_wal_voice_embedding_state SET row_count=?1 WHERE singleton=1",
                [i64::from(MAX_ROWS)],
            )
            .unwrap();
        let plan = VoiceEmbeddingPlan::settle(
            ACCOUNT.to_owned(),
            evidence,
            TOKEN.to_owned(),
            OBSERVED_AT.to_owned(),
            LEASE_UNTIL.to_owned(),
            SETTLED_AT.to_owned(),
            VoiceEmbeddingOutcome::QualityRejected {
                diagnostics_json: r#"{"decision":"no_embedding"}"#.to_owned(),
                eligibility: "no_embedding".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            execute(&mut connection, plan).unwrap_err(),
            WalIdempotencyError::Limit
        );
        assert_eq!(
            connection
                .query_row("SELECT state FROM voice_embedding_jobs", [], |row| row
                    .get::<_, String>(
                    0
                ))
                .unwrap(),
            "processing"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM voice_samples", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
